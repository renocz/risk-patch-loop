"""rpl notify: the command that collects events from the other modules' state and hands them to rpl.notify.deliver. Doubles only."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from rpl import events, notify

NOW = 1_800_000_000.0
H = 3600


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = os.path.join(self.tmp.name, "state")
        os.makedirs(self.state)
        self.posts = []
        self.code = 200
        self.now = NOW
        self.cfg = {"state_dir": self.state, "notifications": {"channels": [{"type": "webhook", "url": "https://hooks.example.test/x"}]}}
        self.nightly_ok()                                  # most tests are about something else

    def poster(self, url, body, headers, allow):
        self.posts.append(json.loads(body)["text"])
        return self.code

    def put(self, name, data):
        with open(os.path.join(self.state, name), "w") as f:
            f.write(data if isinstance(data, str) else json.dumps(data))

    def nightly_ok(self, ago=H):
        self.put("nightly.json", {"ts": NOW - ago, "status": "ok"})

    def inventory(self, *names):
        self.put("inventory.json", {n: {"image": n + ":1", "level": "internal"} for n in names})

    def keys(self):
        return [e["key"] for e in events.collect(self.cfg, lambda: NOW)]

    def run_cmd(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = events.run(self.cfg, self.poster, lambda: self.now)
        return rc, out.getvalue()


class Nightly(Base):
    def test_a_recent_ok_run_gives_nothing(self):
        self.assertEqual(self.keys(), [])

    def test_a_run_never_recorded_is_reported(self):
        os.remove(os.path.join(self.state, "nightly.json"))
        self.assertEqual(self.keys(), ["nightly-missing:never"])

    def test_a_stale_run_is_reported_with_the_key_of_notify_missing_run(self):
        self.nightly_ok(ago=40 * H)
        self.assertEqual(self.keys(), [f"nightly-missing:{int(NOW - 40 * H)}"])

    def test_a_failed_run_is_reported_with_its_reason(self):
        self.put("nightly.json", {"ts": NOW - H, "status": "failed", "reason": "scan UNRELIABLE: KEV list unavailable"})
        evs = events.collect(self.cfg, lambda: NOW)
        self.assertEqual([e["key"] for e in evs], [f"nightly-failed:{int(NOW - H)}"])
        self.assertIn("KEV list unavailable", evs[0]["text"])

    def test_a_record_that_cannot_be_read_is_missing_not_ok(self):
        self.put("nightly.json", "{broken")
        self.assertTrue(any(k.startswith("error:nightly.json") for k in self.keys()))

    def test_a_record_with_another_status_is_not_ok(self):
        self.put("nightly.json", {"ts": NOW - H, "status": "fine"})
        self.assertTrue(any(k.startswith("error:nightly.json") for k in self.keys()))

    def test_record_writes_what_collect_reads(self):
        os.remove(os.path.join(self.state, "nightly.json"))
        events.record(self.cfg, "failed", "scan crashed", lambda: NOW)
        self.assertEqual(self.keys(), [f"nightly-failed:{int(NOW)}"])
        events.record(self.cfg, "ok", "", lambda: NOW + 60)
        self.assertEqual(events.collect(dict(self.cfg), lambda: NOW + 120), [])

    def test_a_long_reason_is_cut_with_a_visible_mark(self):
        events.record(self.cfg, "failed", "x" * 900, lambda: NOW)
        text = events.collect(self.cfg, lambda: NOW)[0]["text"]
        self.assertIn("\u2026", text)                      # the reader must see that something was cut
        self.assertLess(len(text), 400)

    def test_a_short_reason_is_not_marked(self):
        events.record(self.cfg, "failed", "scan crashed", lambda: NOW)
        self.assertNotIn("\u2026", events.collect(self.cfg, lambda: NOW)[0]["text"])

    def test_record_refuses_an_unknown_status(self):
        with self.assertRaises(ValueError):
            events.record(self.cfg, "fine", "", lambda: NOW)


class PatchResults(Base):
    def patches(self, *results, ago=H):
        self.put("patches.json", [{"ts": NOW - ago - i, "service": "app-1", "from": "img:1", "to": "img:2", "result": r} for i, r in enumerate(results)])

    def test_each_recent_result_is_an_event(self):
        self.patches("ok", "rollback ok")
        evs = events.collect(self.cfg, lambda: NOW)
        self.assertEqual(len(evs), 2)
        self.assertIn("app-1", evs[0]["text"])
        self.assertIn("img:2", evs[0]["text"])

    def test_a_failure_to_roll_back_says_check_by_hand(self):
        self.patches("rollback FAILED: CHECK BY HAND")
        self.assertIn("CHECK BY HAND", events.collect(self.cfg, lambda: NOW)[0]["text"])

    def test_old_results_are_not_replayed(self):
        self.patches("ok", ago=5 * 86400)
        self.assertEqual(self.keys(), [])

    def test_a_journal_that_cannot_be_read_is_an_error_event(self):
        self.put("patches.json", "{broken")
        self.assertTrue(any(k.startswith("error:patches.json") for k in self.keys()))

    def test_an_entry_without_a_usable_time_is_an_error_not_a_crash(self):
        self.put("patches.json", [{"service": "app-1", "result": "ok"}])
        self.assertTrue(any(k.startswith("error:patches.json") for k in self.keys()))

    def test_no_patch_journal_is_not_an_error(self):
        self.assertEqual(self.keys(), [])


class Exclusions(Base):
    def files(self, verdict="COMPLETE", reason="service 'app-1' is not in patch-apps.json (health route and database to describe)"):
        self.put("proposals.json", {"ts": NOW - H, "proposals": [], "not_proposed": [{"image": "img:1", "reason": reason}]})
        self.put("fixcheck.json", {"ts": NOW - H, "images": [{"image": "img:1", "verdict": verdict, "candidate": "2"}]})

    def test_an_excluded_image_with_a_proven_fix_is_reported(self):
        self.files()
        evs = events.collect(self.cfg, lambda: NOW)
        self.assertEqual([e["key"] for e in evs], ["excluded:img:1:2"])
        self.assertIn("patch-apps.json", evs[0]["text"])

    def test_an_image_without_a_proven_fix_is_not(self):
        self.files(verdict="NO NEWER VERSION", reason="no proven fix (NO NEWER VERSION)")
        self.assertEqual(self.keys(), [])

    def test_a_new_candidate_is_a_new_message(self):
        self.files()
        first = self.keys()
        self.put("fixcheck.json", {"ts": NOW, "images": [{"image": "img:1", "verdict": "COMPLETE", "candidate": "3"}]})
        self.assertNotEqual(self.keys(), first)

    def test_an_image_that_is_already_up_to_date_is_not_a_pending_fix(self):
        self.files(reason="already at the registry digest")
        self.assertEqual(self.keys(), [])

    def test_a_group_member_is_reported(self):
        self.files(reason="member of an update group (VPN container or service sharing a network namespace): dedicated procedure")
        self.assertEqual(self.keys(), ["excluded:img:1:2"])

    def test_unreadable_proposals_are_an_error_event(self):
        self.put("proposals.json", "{broken")
        self.assertTrue(any(k.startswith("error:proposals.json") for k in self.keys()))

    def test_unreadable_fix_check_is_an_error_event(self):
        self.put("proposals.json", {"ts": NOW, "proposals": [], "not_proposed": [{"image": "img:1", "reason": "x"}]})
        self.put("fixcheck.json", "{broken")
        self.assertTrue(any(k.startswith("error:fixcheck.json") for k in self.keys()))


class NewApplications(Base):
    def test_the_first_run_records_a_baseline_and_says_nothing(self):
        self.inventory("app-1", "app-2")
        self.assertEqual(self.keys(), [])
        rc, out = self.run_cmd()
        self.assertEqual(rc, 0)
        self.assertIn("baseline", out)

    def test_an_application_that_appears_later_is_reported_once_delivered(self):
        self.inventory("app-1")
        self.run_cmd()
        self.inventory("app-1", "app-2")
        self.assertEqual(self.keys(), ["new-app:app-2"])
        self.run_cmd()
        self.assertEqual(len(self.posts), 1)
        self.assertIn("app-2", self.posts[0])
        self.assertEqual(self.keys(), [])                  # delivered: now known

    def test_an_application_whose_message_was_not_delivered_stays_new(self):
        self.inventory("app-1")
        self.run_cmd()
        self.inventory("app-1", "app-2")
        self.code = 500
        self.run_cmd()
        self.assertEqual(self.keys(), ["new-app:app-2"])
        self.code = 200
        self.now += notify.RETRY_BASE_S + 1                 # the retry delay has passed
        self.run_cmd()
        self.assertEqual(self.posts[-1], self.posts[0])
        self.assertEqual(self.keys(), [])

    def test_without_a_channel_nothing_is_marked_as_known(self):
        self.inventory("app-1")
        self.run_cmd()
        self.inventory("app-1", "app-2")
        self.cfg["notifications"] = {}
        self.run_cmd()
        self.assertEqual(self.keys(), ["new-app:app-2"])

    def test_a_removed_application_is_not_an_event(self):
        self.inventory("app-1", "app-2")
        self.run_cmd()
        self.inventory("app-1")
        self.assertEqual(self.keys(), [])

    def test_a_removed_then_returning_application_is_not_new_again(self):
        self.inventory("app-1")
        self.run_cmd()
        self.inventory("app-1", "app-2")
        self.run_cmd()
        self.inventory("app-1")
        self.run_cmd()
        self.inventory("app-1", "app-2")
        self.assertEqual(self.keys(), [])

    def test_two_different_broken_files_in_the_same_second_are_two_error_events(self):
        path = os.path.join(self.state, "inventory.json")
        keys = set()
        for content in ("{broken", "[1]", "[2]"):
            self.put("inventory.json", content)
            os.utime(path, (1_700_000_000, 1_700_000_000))
            keys |= {k for k in self.keys() if k.startswith("error:inventory.json")}
        self.assertEqual(len(keys), 3)

    def test_an_unreadable_inventory_is_an_error_event_and_keeps_the_baseline(self):
        self.inventory("app-1")
        self.run_cmd()
        self.put("inventory.json", "{broken")
        self.assertTrue(any(k.startswith("error:inventory.json") for k in self.keys()))
        self.inventory("app-1")
        self.assertEqual(self.keys(), [])


class Delivery(Base):
    def test_everything_goes_through_deliver_once_per_key(self):
        os.remove(os.path.join(self.state, "nightly.json"))
        self.assertEqual(self.run_cmd()[0], 0)
        self.assertEqual(self.run_cmd()[0], 0)
        self.assertEqual(len(self.posts), 1)

    def test_a_delivery_that_fails_gives_a_nonzero_exit_and_is_retried(self):
        os.remove(os.path.join(self.state, "nightly.json"))
        self.code = 500
        self.assertEqual(self.run_cmd()[0], 1)
        self.code = 200
        self.assertEqual(self.run_cmd()[0], 1)              # still inside the retry delay: nothing sent, still not delivered
        self.assertEqual(len(self.posts), 1)
        self.now += notify.RETRY_BASE_S + 1
        self.assertEqual(self.run_cmd()[0], 0)
        self.assertEqual(len(self.posts), 2)

    def test_the_events_are_printed_even_without_a_channel(self):
        os.remove(os.path.join(self.state, "nightly.json"))
        self.cfg["notifications"] = {}
        rc, out = self.run_cmd()
        self.assertEqual(rc, 1)
        self.assertIn("never completed", out)

    def test_nothing_to_say_posts_nothing(self):
        self.assertEqual(self.run_cmd(), (0, "no event\n"))
        self.assertEqual(self.posts, [])

    def test_unexpected_value_types_are_reported_not_crashed_on(self):
        self.put("patches.json", [{"ts": NOW - H, "service": {"x": 1}, "result": ["y"]}])
        self.assertTrue(self.keys())


class Priority(Base):
    """What must reach a human even when a slow channel has used the run's time budget is marked critical; the rest waits for the next run."""

    def flags(self):
        return {e["key"].split(":")[0]: bool(e.get("critical")) for e in events.collect(self.cfg, lambda: NOW)}

    def test_a_missing_or_failed_nightly_run_is_critical(self):
        os.remove(os.path.join(self.state, "nightly.json"))
        self.assertEqual(self.flags(), {"nightly-missing": True})
        self.put("nightly.json", {"ts": NOW - H, "status": "failed", "reason": "x"})
        self.assertEqual(self.flags(), {"nightly-failed": True})
        self.put("nightly.json", {"ts": NOW - 40 * H, "status": "ok"})                      # a record that is too old
        self.assertEqual(self.flags(), {"nightly-missing": True})

    def test_an_unreadable_state_file_is_critical(self):
        self.put("patches.json", "{broken")
        self.assertEqual(self.flags(), {"error": True})

    def test_a_patch_that_needs_a_human_is_critical_and_one_that_worked_is_not(self):
        self.put("patches.json", [{"ts": NOW - H, "service": "a", "from": "i:1", "to": "i:2", "result": "ok"},
                                  {"ts": NOW - H - 1, "service": "b", "from": "i:1", "to": "i:2", "result": "rollback FAILED: CHECK BY HAND"},
                                  {"ts": NOW - H - 2, "service": "c", "from": "i:1", "to": "i:2", "result": "aborted: CHECK BY HAND"},
                                  {"ts": NOW - H - 3, "service": "d", "from": "i:1", "to": "i:2", "result": "rollback ok"}])
        got = {e["key"].split(":")[1]: bool(e.get("critical")) for e in events.collect(self.cfg, lambda: NOW)}
        self.assertEqual(got, {"a": False, "b": True, "c": True, "d": False})

    def test_a_new_application_and_an_exclusion_are_not_critical(self):
        self.inventory("app-1")
        events.run(self.cfg, self.poster, lambda: NOW)
        self.inventory("app-1", "app-2")
        self.put("proposals.json", {"ts": NOW - H, "proposals": [], "not_proposed": [{"image": "img:1", "reason": "x"}]})
        self.put("fixcheck.json", {"ts": NOW - H, "images": [{"image": "img:1", "verdict": "COMPLETE", "candidate": "2"}]})
        evs = events.collect(self.cfg, lambda: NOW)
        self.assertEqual(sorted(e["key"].split(":")[0] for e in evs), ["excluded", "new-app"])
        self.assertFalse(any(e.get("critical") for e in evs))


class Robustness(Base):
    def test_a_source_that_crashes_becomes_an_error_event_and_the_others_still_run(self):
        def boom(cfg, now):
            raise KeyError("x")
        os.remove(os.path.join(self.state, "nightly.json"))
        with mock.patch.object(events, "SOURCES", (("patches.json", boom), ("nightly.json", events.nightly_events))):
            keys = self.keys()
        self.assertTrue(any(k.startswith("error:patches.json") for k in keys))
        self.assertIn("nightly-missing:never", keys)


class Command(unittest.TestCase):
    def test_the_command_is_registered(self):
        from rpl import __main__ as cli
        self.assertEqual(cli.COMMANDS["notify"], "events")

    def test_rpl_watch_does_not_depend_on_the_collector_or_the_group_apply(self):
        import ast
        import inspect
        from rpl import watch
        imported = set()
        for node in ast.walk(ast.parse(inspect.getsource(watch))):
            if isinstance(node, ast.ImportFrom) and node.level:
                imported |= {a.name for a in node.names}
        self.assertEqual(imported & {"events", "groupapply", "patch"}, set())          # it must stand alone: config, notify and the message module only


if __name__ == "__main__":
    unittest.main()
