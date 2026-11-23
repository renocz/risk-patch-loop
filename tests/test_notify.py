"""Notifications: confirmed delivery, retries, one message per key, secret handling, webhook destination checks."""
import json
import os
import tempfile
import threading
import time
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, HTTPServer

from rpl import notify

EV = {"key": "fix:app-1:CVE-2026-0001:2.4.1", "text": "app-1 has a fix pending"}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = self.tmp.name

    def secret(self, name, value="s3cr3t-value", mode=0o600):
        p = os.path.join(self.d, name)
        with open(p, "w") as f:
            f.write(value + "\n")
        os.chmod(p, mode)
        return p

    def cfg(self, channels, **extra):
        c = {"state_dir": os.path.join(self.d, "state"), "notifications": dict({"channels": channels}, **extra)}
        return c

    def state(self, cfg):
        return json.load(open(os.path.join(cfg["state_dir"], "notifs.json")))


class Delivery(Base):
    def hook(self, **kw):
        return dict({"type": "webhook", "url": "https://hooks.example.test/x"}, **kw)

    def test_2xx_marks_delivered_and_second_call_sends_nothing(self):
        sent = []
        poster = lambda url, body, headers, allow: sent.append(url) or 200
        cfg = self.cfg([self.hook()])
        self.assertEqual(notify.deliver([EV], cfg, poster)["delivered"], [EV["key"]])
        self.assertEqual(notify.deliver([EV], cfg, poster)["delivered"], [])
        self.assertEqual(len(sent), 1)

    def test_failure_keeps_the_event_queued_and_retries(self):
        codes = iter([500, 200])
        poster = lambda *a: next(codes)
        cfg = self.cfg([self.hook()])
        self.assertEqual(notify.deliver([EV], cfg, poster)["queued"], [EV["key"]])
        self.assertFalse(self.state(cfg)[EV["key"]]["delivered"])
        self.assertIn("HTTP 500", self.state(cfg)[EV["key"]]["last_error"])
        later = lambda: __import__("time").time() + notify.RETRY_BASE_S + 1                  # after the retry delay
        self.assertEqual(notify.deliver([EV], cfg, poster, later)["delivered"], [EV["key"]])

    def test_redirect_status_is_not_a_delivery(self):
        self.assertEqual(notify.deliver([EV], self.cfg([self.hook()]), lambda *a: 302)["queued"], [EV["key"]])

    def test_two_channels_need_both_to_confirm(self):
        codes = {"https://a.example.test/": 200, "https://b.example.test/": 500}
        poster = lambda url, *a: codes[url]
        cfg = self.cfg([self.hook(url="https://a.example.test/"), self.hook(url="https://b.example.test/")])
        self.assertEqual(notify.deliver([EV], cfg, poster)["queued"], [EV["key"]])

    def test_attempts_are_capped_and_visible(self):
        cfg = self.cfg([self.hook()], max_attempts=2)
        poster = lambda *a: 500
        for i in range(2):
            notify.deliver([EV], cfg, poster, lambda: 1000.0 + i * notify.RETRY_CAP_S)
        self.assertEqual(notify.deliver([EV], cfg, poster, lambda: 1000.0 + 2 * notify.RETRY_CAP_S)["given_up"], [EV["key"]])
        self.assertEqual(self.state(cfg)[EV["key"]]["tries"], 2)

    def test_no_channel_is_a_queued_error_not_a_silent_success(self):
        res = notify.deliver([EV], self.cfg([]), lambda *a: 200)
        self.assertEqual(res["queued"], [EV["key"]])

    def test_unknown_channel_type_is_queued(self):
        self.assertEqual(notify.deliver([EV], self.cfg([{"type": "carrier-pigeon"}]), lambda *a: 200)["queued"], [EV["key"]])

    def test_another_version_is_another_message(self):
        sent = []
        poster = lambda *a: sent.append(1) or 200
        cfg = self.cfg([self.hook()])
        notify.deliver([EV, dict(EV, key=EV["key"].replace("2.4.1", "2.4.2"))], cfg, poster)
        self.assertEqual(len(sent), 2)


class Secrets(Base):
    def test_loose_permissions_are_refused_without_printing_the_value(self):
        p = self.secret("tok", mode=0o644)
        with self.assertRaises(notify.NotifyError) as cm:
            notify.read_secret(p)
        self.assertNotIn("s3cr3t-value", str(cm.exception))

    def test_missing_and_empty_files(self):
        with self.assertRaises(notify.NotifyError):
            notify.read_secret(os.path.join(self.d, "nope"))
        with self.assertRaises(notify.NotifyError):
            notify.read_secret(self.secret("empty", value=""))

    def test_secret_never_reaches_the_state_file_or_errors(self):
        tok = self.secret("tg", value="123456:abcdef")
        cfg = self.cfg([{"type": "telegram", "token_file": tok, "chat_id": "42"}])

        def boom(url, *a):
            raise ConnectionError("failed to reach " + url)          # the URL carries the token
        notify.deliver([EV], cfg, boom)
        raw = open(os.path.join(cfg["state_dir"], "notifs.json")).read()
        self.assertNotIn("abcdef", raw)
        self.assertIn("ConnectionError", raw)

    def test_webhook_secret_is_sent_as_bearer_header(self):
        seen = {}
        cfg = self.cfg([{"type": "webhook", "url": "https://hooks.example.test/x", "secret_file": self.secret("h")}])
        notify.deliver([EV], cfg, lambda url, body, headers, allow: seen.update(headers) or 200)
        self.assertEqual(seen["Authorization"], "Bearer s3cr3t-value")


class Destination(Base):
    def test_private_loopback_and_link_local_are_refused_after_resolution(self):
        for ip in ("10.0.0.5", "127.0.0.1", "169.254.169.254", "192.168.50.1", "::1", "fe80::1"):
            with self.assertRaises(notify.NotifyError, msg=ip):
                notify.post("https://hooks.example.test/x", b"{}", {}, resolver=lambda h, p, ip=ip: [ip])

    def test_one_private_address_among_public_ones_refuses(self):
        with self.assertRaises(notify.NotifyError):
            notify.post("https://hooks.example.test/x", b"{}", {}, resolver=lambda h, p: ["93.184.216.34", "10.0.0.5"])

    def test_plain_http_is_refused_by_default(self):
        with self.assertRaises(notify.NotifyError):
            notify.post("http://hooks.example.test/x", b"{}", {}, resolver=lambda h, p: ["93.184.216.34"])

    def test_unresolvable_host_is_an_error(self):
        def nope(h, p):
            raise OSError("no such host")
        with self.assertRaises(notify.NotifyError):
            notify.post("https://hooks.example.test/x", b"{}", {}, resolver=nope)

    def test_it_connects_to_the_address_it_checked_and_does_not_follow_redirects(self):
        hits = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                hits.append((self.path, self.headers.get("Host")))
                self.send_response(302)
                self.send_header("Location", "http://other.example.test/")
                self.send_header("Content-Length", "0")
                self.end_headers()

        srv = HTTPServer(("127.0.0.1", 0), H)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close(), t.join(5)))
        port = srv.server_address[1]
        status = notify.post(f"http://hooks.example.test:{port}/p?q=1", b"{}", {}, allow_private=True, resolver=lambda h, p: ["127.0.0.1"])
        self.assertEqual(status, 302)
        self.assertEqual(hits, [("/p?q=1", f"hooks.example.test:{port}")])


class Backoff(Base):
    """A failed event is retried after a delay that grows with elapsed time, not on every run: a timer every minute must not use up
    `max_attempts` in twenty minutes."""

    def setUp(self):
        super().setUp()
        self.posts = []
        self.code = 500
        self.poster = lambda url, body, headers, allow: self.posts.append(url) or self.code
        self.cfg_ = self.cfg([{"type": "webhook", "url": "https://hooks.example.test/x"}])

    def go(self, t, **kw):
        return notify.deliver([EV], dict(self.cfg_, **kw), self.poster, lambda: t)

    def test_a_retry_before_the_delay_sends_nothing_and_stays_queued(self):
        self.go(1000.0)
        res = self.go(1000.0 + 10)
        self.assertEqual((len(self.posts), res["queued"]), (1, [EV["key"]]))
        self.assertEqual(self.state(self.cfg_)[EV["key"]]["tries"], 1)       # a held event is not a try

    def test_after_the_delay_it_is_sent_again(self):
        self.go(1000.0)
        self.go(1000.0 + notify.RETRY_BASE_S)
        self.assertEqual(len(self.posts), 2)

    def test_the_delay_doubles_with_each_failure(self):
        t = 1000.0
        self.go(t)
        t += notify.RETRY_BASE_S
        self.go(t)                                                           # second failure: next wait is twice the base
        self.go(t + 2 * notify.RETRY_BASE_S - 1)
        self.assertEqual(len(self.posts), 2)
        self.go(t + 2 * notify.RETRY_BASE_S)
        self.assertEqual(len(self.posts), 3)

    def test_the_delay_has_a_ceiling(self):
        t = 1000.0
        for _ in range(12):
            self.go(t)
            t += notify.RETRY_CAP_S
        self.assertEqual(len(self.posts), 12)                                # never more than the cap between two tries

    def test_the_next_try_is_visible_in_the_state_file(self):
        self.go(1000.0)
        self.assertEqual(self.state(self.cfg_)[EV["key"]]["next_try"], 1000.0 + notify.RETRY_BASE_S)

    def test_a_next_try_far_in_the_future_is_not_trusted(self):
        self.go(1000.0)
        self.go(1000.0 - 10 * 3600)                                          # the clock went back by ten hours
        self.assertEqual(len(self.posts), 2)

    def test_a_minute_timer_does_not_give_up_after_twenty_minutes(self):
        t = 1000.0
        for _ in range(60):
            res = self.go(t)
            t += 60
        self.assertEqual(res["given_up"], [])
        self.assertLess(len(self.posts), 20)

    def test_an_hourly_timer_gets_one_try_per_run_for_about_twenty_hours(self):
        t, sends = 1000.0, []
        for run in range(1, 26):
            res = self.go(t)
            if res["given_up"]:
                sends.append(run)
                break
            t += 3600
        self.assertEqual((sends, len(self.posts)), ([21], 20))               # 20 tries on runs 1..20, given up on run 21

    def test_the_cap_on_attempts_still_applies(self):
        t = 1000.0
        for _ in range(30):
            res = self.go(t, notifications={"channels": self.cfg_["notifications"]["channels"], "max_attempts": 3})
            t += notify.RETRY_CAP_S
        self.assertEqual((res["given_up"], len(self.posts)), ([EV["key"]], 3))

    def test_a_delivery_after_a_wait_clears_the_wait(self):
        self.go(1000.0)
        self.code = 200
        self.assertEqual(self.go(1000.0 + notify.RETRY_BASE_S)["delivered"], [EV["key"]])
        self.assertNotIn("next_try", self.state(self.cfg_)[EV["key"]])


class Concurrency(Base):
    """Several processes write notifs.json (`rpl watch` every minute, `rpl notify`, the group apply). A run must not erase what another
    run recorded while it was sending: losing a `queued` or `delivered` mark loses an alert or sends it twice for ever."""

    def setUp(self):
        super().setUp()
        self.cfg_ = self.cfg([{"type": "webhook", "url": "https://hooks.example.test/x"}])
        self.other = dict(EV, key="fix:app-2:CVE-2026-0002:1.0.0")

    def test_a_run_that_overlaps_another_does_not_erase_its_state(self):
        def during_the_send(url, body, headers, allow):
            notify.deliver([self.other], self.cfg_, lambda *a: 200)          # another process delivers its own event meanwhile
            return 500
        notify.deliver([EV], self.cfg_, during_the_send)
        state = self.state(self.cfg_)
        self.assertTrue(state[self.other["key"]]["delivered"], "the other run's delivery mark was erased")
        self.assertFalse(state[EV["key"]]["delivered"])
        self.assertEqual(state[EV["key"]]["tries"], 1)

    def test_two_overlapping_failures_both_stay_queued(self):
        def during_the_send(url, body, headers, allow):
            notify.deliver([self.other], self.cfg_, lambda *a: 500)
            return 500
        notify.deliver([EV], self.cfg_, during_the_send)
        state = self.state(self.cfg_)
        self.assertEqual(sorted(state), sorted([EV["key"], self.other["key"]]))
        self.assertTrue(all(v["tries"] == 1 and not v["delivered"] for v in state.values()))

    def test_a_lock_that_cannot_be_taken_never_stops_an_alert(self):
        fcntl = __import__("fcntl")
        os.makedirs(self.cfg_["state_dir"], exist_ok=True)
        path = os.path.join(self.cfg_["state_dir"], "notifs.json.lock")
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)                                       # held by "another process" for the whole test
        notify.LOCK_WAIT_S, old = 0.2, notify.LOCK_WAIT_S
        self.addCleanup(setattr, notify, "LOCK_WAIT_S", old)
        res = notify.deliver([EV], self.cfg_, lambda *a: 200)
        self.assertEqual(res["delivered"], [EV["key"]])
        self.assertTrue(self.state(self.cfg_)[EV["key"]]["delivered"])

    def test_a_state_update_waits_for_the_lock_held_by_another_process(self):
        fcntl = __import__("fcntl")
        os.makedirs(self.cfg_["state_dir"], exist_ok=True)
        lock_path = os.path.join(self.cfg_["state_dir"], "notifs.json.lock")
        taken, hold_s = threading.Event(), 0.4

        def holder():
            fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            taken.set()
            time.sleep(hold_s)
            os.close(fd)

        t = threading.Thread(target=holder)
        t.start()
        self.addCleanup(t.join)
        self.assertTrue(taken.wait(5))
        start = time.monotonic()
        notify._commit(os.path.join(self.cfg_["state_dir"], "notifs.json"), "k", {"delivered": True, "tries": 1})
        self.assertGreaterEqual(time.monotonic() - start, hold_s * 0.6, "the update did not wait for the lock")

    def test_the_state_file_is_owner_only_whatever_the_umask(self):
        """notifs.json holds container and image names and the last error of each channel: owner-only like the journal and the lock."""
        old = os.umask(0o022)                                                # a common umask: files would be created 0644
        self.addCleanup(os.umask, old)
        notify.deliver([EV], self.cfg_, lambda *a: 500)
        path = os.path.join(self.cfg_["state_dir"], "notifs.json")
        self.assertEqual(os.stat(path).st_mode & 0o077, 0)

    def test_an_existing_world_readable_state_file_is_tightened_at_the_next_write(self):
        os.makedirs(self.cfg_["state_dir"], exist_ok=True)
        path = os.path.join(self.cfg_["state_dir"], "notifs.json")
        with open(path, "w") as f:
            json.dump({}, f)
        os.chmod(path, 0o644)
        notify.deliver([EV], self.cfg_, lambda *a: 200)
        self.assertEqual(os.stat(path).st_mode & 0o077, 0)

    def test_a_leftover_temporary_file_with_loose_rights_does_not_leak_into_the_state_file(self):
        os.makedirs(self.cfg_["state_dir"], exist_ok=True)
        leftover = os.path.join(self.cfg_["state_dir"], f"notifs.json.{os.getpid()}.tmp")
        with open(leftover, "w") as f:
            f.write("{}")
        os.chmod(leftover, 0o666)                                            # left by an earlier crashed run of this very pid
        notify.deliver([EV], self.cfg_, lambda *a: 200)
        self.assertEqual(os.stat(os.path.join(self.cfg_["state_dir"], "notifs.json")).st_mode & 0o077, 0)

    def test_the_lock_file_is_owner_only(self):
        notify.deliver([EV], self.cfg_, lambda *a: 200)
        mode = os.stat(os.path.join(self.cfg_["state_dir"], "notifs.json.lock")).st_mode & 0o777
        self.assertEqual(mode & 0o077, 0)

    def test_a_malformed_entry_is_replaced_not_a_crash(self):
        os.makedirs(self.cfg_["state_dir"], exist_ok=True)
        with open(os.path.join(self.cfg_["state_dir"], "notifs.json"), "w") as f:
            json.dump({EV["key"]: {"unexpected": 1}, self.other["key"]: "text"}, f)
        res = notify.deliver([EV, self.other], self.cfg_, lambda *a: 200)
        self.assertEqual(sorted(res["delivered"]), sorted([EV["key"], self.other["key"]]))     # a duplicate is better than a lost alert

    def test_the_state_file_keeps_every_key_after_many_runs(self):
        for i in range(5):
            notify.deliver([dict(EV, key=f"k{i}")], self.cfg_, lambda *a: 200)
        self.assertEqual(len(self.state(self.cfg_)), 5)


class FileStamp(Base):
    def test_the_stamp_follows_the_content_not_only_the_modification_second(self):
        path = os.path.join(self.d, "f.json")
        stamps = []
        for content in ("a", "b", "bb"):
            with open(path, "w") as f:
                f.write(content)
            os.utime(path, (1_700_000_000, 1_700_000_000))
            stamps.append(notify.file_stamp(path))
        self.assertEqual(len(set(stamps)), 3)

    def test_the_same_content_gives_the_same_stamp(self):
        path = os.path.join(self.d, "f.json")
        with open(path, "w") as f:
            f.write("a")
        self.assertEqual(notify.file_stamp(path), notify.file_stamp(path))

    def test_a_file_that_cannot_be_read_or_does_not_exist_still_gets_a_stamp(self):
        self.assertEqual(notify.file_stamp(os.path.join(self.d, "missing.json")), "unknown")
        path = os.path.join(self.d, "f.json")
        with open(path, "w") as f:
            f.write("a")
        with mock.patch("builtins.open", side_effect=PermissionError(13, "denied")):
            self.assertRegex(notify.file_stamp(path), r"^\d+$")             # falls back to the modification time in nanoseconds


class RetryAfter(Base):
    """A 429 or 503 that says when to come back: the next try is not earlier than that (never later than the ceiling)."""

    def server(self, status, headers):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", "0")
                self.end_headers()

        srv = HTTPServer(("127.0.0.1", 0), H)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close(), t.join(5)))
        return f"http://hooks.example.test:{srv.server_address[1]}/p"

    def post(self, status, headers):
        return notify.post(self.server(status, headers), b"{}", {}, allow_private=True, resolver=lambda h, p: ["127.0.0.1"])

    def test_post_returns_the_status_with_the_retry_after_seconds(self):
        res = self.post(429, {"Retry-After": "120"})
        self.assertEqual(res, 429)
        self.assertEqual(res.retry_after, 120)

    def test_a_date_or_garbage_or_nothing_gives_no_hint(self):
        for headers in ({"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}, {"Retry-After": "soon"}, {"Retry-After": "-5"}, {}):
            with self.subTest(headers=headers):
                self.assertIsNone(self.post(503, headers).retry_after)

    def test_a_success_keeps_working_as_a_plain_status(self):
        self.assertEqual(self.post(200, {}), 200)

    def deliver_with(self, *statuses, cfg_extra=None):
        channels = [{"type": "webhook", "url": f"https://h{i}.example.test/x"} for i in range(len(statuses))]
        answers = {c["url"]: st for c, st in zip(channels, statuses)}
        cfg = self.cfg(channels)
        notify.deliver([EV], cfg, lambda url, body, headers, allow: answers[url], lambda: 1000.0)
        return self.state(cfg)[EV["key"]]

    def status(self, code, retry_after):
        s = notify.Status(code)
        s.retry_after = retry_after
        return s

    def test_a_longer_retry_after_than_the_calendar_wins(self):
        self.assertEqual(self.deliver_with(self.status(429, 300))["next_try"], 1000.0 + 300)

    def test_a_shorter_one_does_not_shorten_the_calendar(self):
        self.assertEqual(self.deliver_with(self.status(429, 5))["next_try"], 1000.0 + notify.RETRY_BASE_S)

    def test_an_absurd_one_is_capped_at_the_ceiling(self):
        self.assertEqual(self.deliver_with(self.status(503, 10 ** 9))["next_try"], 1000.0 + notify.RETRY_CAP_S)

    def test_with_two_failing_channels_the_longest_hint_counts(self):
        self.assertEqual(self.deliver_with(self.status(429, 200), self.status(429, 100))["next_try"], 1000.0 + 200)     # the longer one is first: the last one must not win

    def test_a_channel_that_succeeded_does_not_set_the_wait(self):
        st = self.deliver_with(self.status(200, 900), self.status(500, None))
        self.assertEqual(st["next_try"], 1000.0 + notify.RETRY_BASE_S)

    def test_a_plain_integer_status_still_works(self):
        self.assertEqual(self.deliver_with(500)["next_try"], 1000.0 + notify.RETRY_BASE_S)


class Timeouts(Base):
    n = 0

    def calls(self, channel):
        seen = []
        Timeouts.n += 1                                                      # a new key each time: one message per key, also across subtests
        notify.deliver([dict(EV, key=f"k{Timeouts.n}")], self.cfg([channel]), lambda *a, **kw: seen.append(kw) or 200)
        return seen

    def test_without_a_setting_the_poster_is_called_as_before(self):
        self.assertEqual(self.calls({"type": "webhook", "url": "https://h.example.test/x"}), [{}])

    def test_a_channel_timeout_is_passed_to_the_poster(self):
        self.assertEqual(self.calls({"type": "webhook", "url": "https://h.example.test/x", "timeout_s": 3}), [{"timeout": 3.0}])

    def test_telegram_gets_it_too(self):
        secret = self.secret("tg.token")
        got = self.calls({"type": "telegram", "token_file": secret, "chat_id": "1", "timeout_s": 4})
        self.assertEqual(got, [{"timeout": 4.0}])

    def test_a_silly_value_is_ignored_or_clamped(self):
        for value, expected in (("abc", {}), (-1, {}), (0, {}), (True, {}), (1000, {"timeout": 60.0})):
            with self.subTest(value=value):
                self.assertEqual(self.calls({"type": "webhook", "url": "https://h.example.test/x", "timeout_s": value}), [expected])


class RunBudget(Base):
    """A run must not outlast its timer: when the time spent sending reaches the budget, the remaining events wait for the next run."""

    def setUp(self):
        super().setUp()
        self.clock = [1000.0]
        self.sent = []

        def poster(url, body, headers, allow, **kw):
            self.sent.append(json.loads(body)["text"])
            self.clock[0] += 20                                              # a slow channel
            return 200
        self.poster = poster

    def run_(self, n, **notif):
        events = [dict(EV, key=f"k{i}", text=f"t{i}") for i in range(n)]
        cfg = self.cfg([{"type": "webhook", "url": "https://h.example.test/x"}], **notif)
        return notify.deliver(events, cfg, self.poster, lambda: self.clock[0])

    def test_events_after_the_budget_wait_for_the_next_run(self):
        res = self.run_(4, run_budget_s=30)
        self.assertEqual(self.sent, ["t0", "t1"])
        self.assertEqual((res["delivered"], res["queued"]), (["k0", "k1"], ["k2", "k3"]))

    def test_a_held_event_is_not_a_try_and_goes_next_time(self):
        self.run_(4, run_budget_s=30)
        res = self.run_(4, run_budget_s=30)
        self.assertEqual(self.sent, ["t0", "t1", "t2", "t3"])
        self.assertEqual(res["delivered"], ["k2", "k3"])

    def critical(self, i):
        return dict(EV, key=f"c{i}", text=f"critical{i}", critical=True)

    def info(self, i):
        return dict(EV, key=f"k{i}", text=f"info{i}")

    def go(self, events, **notif):
        cfg = self.cfg([{"type": "webhook", "url": "https://h.example.test/x"}], **notif)
        return notify.deliver(events, cfg, self.poster, lambda: self.clock[0])

    def test_a_critical_event_goes_first_whatever_its_place(self):
        self.go([self.info(0), self.info(1), self.critical(0)], run_budget_s=30)
        self.assertEqual(self.sent[0], "critical0")

    def test_slow_ordinary_events_cannot_starve_a_critical_one(self):
        """Five "updated" messages at 14 s a call would use the 45 s budget before a CHECK BY HAND placed after them."""
        self.poster = lambda url, body, headers, allow, **kw: (self.sent.append(json.loads(body)["text"]), self.clock.__setitem__(0, self.clock[0] + 14), 200)[2]
        res = self.go([self.info(i) for i in range(5)] + [self.critical(0)])
        self.assertIn("c0", res["delivered"])
        self.assertEqual(self.sent[0], "critical0")
        self.assertEqual(len(res["delivered"]) + len(res["queued"]), 6)

    def test_the_budget_never_holds_a_critical_event(self):
        res = self.go([self.critical(0), self.critical(1), self.critical(2), self.info(0)], run_budget_s=30)     # 20 s a call
        self.assertEqual(res["delivered"], ["c0", "c1", "c2"])
        self.assertEqual(res["queued"], ["k0"])

    def test_saturated_runs_in_a_row_still_send_the_critical_one_at_once(self):
        for run in range(3):
            events = [self.info(10 * run + i) for i in range(5)] + [self.critical(run)]
            res = self.go(events, run_budget_s=30)
            self.assertIn(f"c{run}", res["delivered"])

    def test_without_a_flag_nothing_changes_the_order(self):
        self.go([self.info(0), self.info(1), self.info(2)], run_budget_s=1000)
        self.assertEqual(self.sent, ["info0", "info1", "info2"])

    def test_the_default_budget_is_under_a_minute(self):
        self.assertLess(notify.RUN_BUDGET_S, 60)

    def test_no_budget_problem_when_sends_are_fast(self):
        self.poster = lambda url, body, headers, allow, **kw: 200
        self.assertEqual(len(self.run_(10)["delivered"]), 10)


class NightlyMissing(unittest.TestCase):
    def test_recent_run_gives_nothing(self):
        self.assertIsNone(notify.missing_run(1000.0, 1000.0 + 3600 * 20))

    def test_old_run_gives_an_event_keyed_on_that_run(self):
        ev = notify.missing_run(1000.0, 1000.0 + 3600 * 40)
        self.assertEqual(ev["key"], "nightly-missing:1000")

    def test_never_run_gives_an_event(self):
        self.assertEqual(notify.missing_run(None, 5.0)["key"], "nightly-missing:never")


if __name__ == "__main__":
    unittest.main()
