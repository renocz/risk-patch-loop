"""rpl watch: the independent check for a group apply that never recorded a result. Doubles only: no network, no Docker."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from rpl import groupapply, watch

NOW = 1_800_000_000.0


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = os.path.join(self.tmp.name, "state")
        os.makedirs(self.state)
        self.posts = []
        self.cfg = {"state_dir": self.state, "notifications": {"channels": [{"type": "webhook", "url": "https://hooks.example.test/x"}]}}

    def poster(self, url, body, headers, allow):
        self.posts.append(json.loads(body)["text"])
        return 200

    def journal(self, entries):
        with open(os.path.join(self.state, watch.JOURNAL), "w") as f:
            json.dump(entries, f)

    def entry(self, id="proj-vpn-1-20261122-010203", result=None, ts=NOW - 7200, state="changing", **extra):
        e = {"id": id, "ts": ts, "result": result, "state": state, "plan": {"parent": "proj-vpn-1"}}
        e.update(extra)
        return e

    def run_watch(self, cfg=None):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = watch.run(cfg or self.cfg, self.poster, lambda: NOW)
        return rc, out.getvalue()


class Unfinished(Base):
    def test_an_entry_without_result_is_reported_and_delivered(self):
        self.journal([self.entry()])
        rc, out = self.run_watch()
        self.assertEqual(rc, 1)
        self.assertEqual(len(self.posts), 1)
        for text in (self.posts[0], out):
            self.assertIn("proj-vpn-1", text)
            self.assertIn("changing", text)
            self.assertIn("--resume", text)

    def test_finished_entries_say_nothing(self):
        self.journal([self.entry(result="ok"), self.entry(id="b", result="rollback ok")])
        rc, _ = self.run_watch()
        self.assertEqual((rc, self.posts), (0, []))

    def test_a_failed_rollback_is_not_this_checks_business(self):
        self.journal([self.entry(result="rollback FAILED: CHECK BY HAND")])       # it has a result, and the apply printed it
        self.assertEqual(self.run_watch()[0], 0)

    def test_missing_journal_is_clean(self):
        self.assertEqual(self.run_watch()[0], 0)

    def test_one_message_per_entry_but_the_exit_code_stays_nonzero(self):
        self.journal([self.entry()])
        self.assertEqual(self.run_watch()[0], 1)
        self.assertEqual(self.run_watch()[0], 1)
        self.assertEqual(len(self.posts), 1)

    def test_two_open_entries_give_two_messages(self):
        self.journal([self.entry(id="a"), self.entry(id="b")])
        self.run_watch()
        self.assertEqual(len(self.posts), 2)

    def test_an_entry_without_a_result_key_counts_as_unfinished(self):
        e = self.entry()
        del e["result"]
        self.journal([e])
        self.assertEqual(self.run_watch()[0], 1)

    def test_it_sees_what_the_group_apply_really_writes(self):
        cfg = dict(self.cfg, backup_dir=os.path.join(self.tmp.name, "b"))
        entry = self.entry()
        groupapply._record(cfg, entry)
        self.assertEqual(self.run_watch(cfg)[0], 1)
        groupapply._record(cfg, entry, result="ok")
        self.assertEqual(self.run_watch(cfg)[0], 0)

    def test_the_journal_name_is_the_one_the_group_apply_uses(self):
        self.assertEqual(watch.JOURNAL, groupapply.JOURNAL)

    def test_no_other_state_file_is_needed(self):
        self.journal([self.entry()])
        self.assertEqual(os.listdir(self.state), [watch.JOURNAL])           # no nightly record, findings or proposals
        self.assertEqual(self.run_watch()[0], 1)


class Grace(Base):
    def test_a_recent_entry_may_be_an_apply_in_progress(self):
        self.journal([self.entry(ts=NOW - 600)])
        self.assertEqual(self.run_watch()[0], 0)

    def test_an_old_entry_is_reported(self):
        self.journal([self.entry(ts=NOW - 3 * 3600)])
        self.assertEqual(self.run_watch()[0], 1)

    def test_the_grace_is_configurable(self):
        self.journal([self.entry(ts=NOW - 600)])
        self.assertEqual(self.run_watch(dict(self.cfg, group_unfinished_grace_minutes=5))[0], 1)

    def test_a_timestamp_that_cannot_be_trusted_is_reported(self):
        for ts in (None, "yesterday", NOW + 10 * 86400):                    # missing, not a number, far in the future
            with self.subTest(ts=ts):
                self.journal([self.entry(ts=ts)])
                self.assertEqual(self.run_watch()[0], 1)


class Unreadable(Base):
    def test_a_journal_that_cannot_be_parsed_is_never_ok(self):
        with open(os.path.join(self.state, watch.JOURNAL), "w") as f:
            f.write("{not json")
        rc, out = self.run_watch()
        self.assertEqual(rc, 2)
        self.assertEqual(len(self.posts), 1)
        self.assertIn("cannot be read", out)

    def test_a_journal_that_is_not_a_list_is_never_ok(self):
        self.journal({"result": None})                                     # groupapply would read it as "no entries"
        self.assertEqual(self.run_watch()[0], 2)

    def test_an_entry_that_is_not_an_object_is_never_ok(self):
        self.journal(["x"])
        self.assertEqual(self.run_watch()[0], 2)

    def test_a_journal_that_cannot_be_opened_is_never_ok(self):
        self.journal([])
        with mock.patch("builtins.open", side_effect=PermissionError(13, "denied")):
            rc, _ = self.run_watch()
        self.assertEqual(rc, 2)


class Permissions(Base):
    def test_a_journal_another_account_wrote_says_so(self):
        self.journal([self.entry()])
        with mock.patch("builtins.open", side_effect=PermissionError(13, "denied")):
            rc, out = self.run_watch()
        self.assertEqual(rc, 2)
        self.assertIn("PermissionError", out)
        self.assertIn("account that runs `rpl group`", out)     # the journal is mode 0600: the timer must run as the account that applies


class Delivery(Base):
    def test_without_a_channel_the_alert_is_still_printed_and_the_exit_code_set(self):
        self.journal([self.entry()])
        rc, out = self.run_watch({"state_dir": self.state})
        self.assertEqual(rc, 1)
        self.assertIn("proj-vpn-1", out)

    def test_a_delivery_that_blows_up_does_not_change_the_result(self):
        self.journal([self.entry()])
        with mock.patch("rpl.notify.deliver", side_effect=RuntimeError("boom")):
            rc, out = self.run_watch()
        self.assertEqual(rc, 1)
        self.assertIn("proj-vpn-1", out)
        self.assertIn("RuntimeError", out)

    def test_a_refused_delivery_stays_queued_and_is_sent_on_the_next_run(self):
        self.journal([self.entry()])
        codes = iter([500, 200])
        self.poster = lambda url, body, headers, allow: next(codes)
        self.run_watch()
        self.run_watch()
        with open(os.path.join(self.state, "notifs.json")) as f:
            state = json.load(f)
        self.assertTrue(all(v["delivered"] for v in state.values()))


class Command(unittest.TestCase):
    def test_the_command_is_registered(self):
        from rpl import __main__ as cli
        self.assertEqual(cli.COMMANDS["watch"], "watch")


if __name__ == "__main__":
    unittest.main()
