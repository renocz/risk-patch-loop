"""Notifications: confirmed delivery, retries, one message per key, secret handling, webhook destination checks."""
import json
import os
import tempfile
import threading
import unittest
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
        self.assertEqual(notify.deliver([EV], cfg, poster)["delivered"], [EV["key"]])

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
        for _ in range(2):
            notify.deliver([EV], cfg, poster)
        self.assertEqual(notify.deliver([EV], cfg, poster)["given_up"], [EV["key"]])
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
