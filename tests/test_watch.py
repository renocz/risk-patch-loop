"""rpl watch: the independent check for a group apply that never recorded a result. Doubles only: no network, no Docker."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from rpl import groupapply, notify, watch

NOW = 1_800_000_000.0


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = os.path.join(self.tmp.name, "state")
        os.makedirs(self.state)
        self.posts = []
        self.now = NOW
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
            rc = watch.run(cfg or self.cfg, self.poster, lambda: self.now)
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

    def test_two_different_damaged_journals_in_the_same_second_give_two_messages(self):
        path = os.path.join(self.state, watch.JOURNAL)
        for content in ("{not json", '["x"]', "[1]", "[2]"):                  # the last two have the same size
            with open(path, "w") as f:
                f.write(content)
            os.utime(path, (1_700_000_000, 1_700_000_000))                    # the same modification second, every time
            self.run_watch()
        self.assertEqual(len(self.posts), 4, "a different damaged file is a different message")

    def test_the_same_damaged_journal_is_told_once(self):
        path = os.path.join(self.state, watch.JOURNAL)
        with open(path, "w") as f:
            f.write("{not json")
        self.run_watch()
        self.run_watch()
        self.assertEqual(len(self.posts), 1)

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


class FailedRollback(Base):
    """A rollback that failed (CHECK BY HAND) is an open incident for as long as its backup exists: the purge never deletes that backup, so a
    human deleting it, once the services are repaired, is the acknowledgement. `rpl watch` re-presents it on every run, so a first delivery that
    failed (the group apply gives its message to `deliver` once) is retried, and it uses the group apply's own key, so a delivered one is not sent
    twice."""

    def failed(self, id="proj-vpn-1-20261120-000000", backup="present", **extra):
        path = os.path.join(self.tmp.name, "backups", "group-" + id)
        if backup == "present":
            os.makedirs(path)
        e = self.entry(id=id, result="rollback FAILED: CHECK BY HAND", ts=extra.pop("ts", NOW - 100), state="rolled-back")
        e["backup_root"] = path
        e.update(extra)
        return e

    def test_a_failed_rollback_with_its_backup_still_there_is_reported_at_once(self):
        e = self.failed()                                              # recent: the grace is for an apply in progress, this one is over
        self.journal([e])
        rc, out = self.run_watch()
        self.assertEqual(rc, 1)
        self.assertEqual(len(self.posts), 1)
        for text in (self.posts[0], out):
            self.assertIn("proj-vpn-1", text)
            self.assertIn(e["backup_root"], text)
            self.assertIn("rollback", text)

    def test_deleting_the_backup_closes_the_incident(self):
        e = self.failed()
        self.journal([e])
        self.assertEqual(self.run_watch()[0], 1)
        os.rmdir(e["backup_root"])
        self.posts.clear()
        self.assertEqual(self.run_watch(), (0, ""))
        self.assertEqual(self.posts, [])

    def test_it_is_reported_however_old_it_is(self):
        self.journal([self.failed(ts=NOW - 400 * 86400)])
        self.assertEqual(self.run_watch()[0], 1)

    def test_a_failed_rollback_without_a_usable_backup_path_is_reported(self):
        for backup_root in (None, "", 3):
            with self.subTest(backup_root=backup_root):
                e = self.failed(backup="absent")
                e["backup_root"] = backup_root
                self.journal([e])
                self.assertEqual(self.run_watch()[0], 1)

    def test_a_rollback_that_succeeded_and_a_success_are_not_incidents(self):
        self.journal([self.entry(id="a", result="rollback ok"), self.entry(id="b", result="ok")])
        self.assertEqual(self.run_watch()[0], 0)

    def test_two_incidents_give_two_messages(self):
        self.journal([self.failed(id="a"), self.entry(id="b")])        # one failed rollback, one apply that never finished
        rc, _ = self.run_watch()
        self.assertEqual((rc, len(self.posts)), (1, 2))

    def test_the_alert_is_printed_on_every_run_but_sent_once(self):
        self.journal([self.failed()])
        first, second = self.run_watch(), self.run_watch()
        self.assertEqual((first[0], second[0]), (1, 1))
        self.assertIn("ALERT", second[1])
        self.assertEqual(len(self.posts), 1)

    def test_it_reads_the_journal_and_the_backup_path_and_nothing_else(self):
        self.journal([self.failed()])
        self.assertEqual(sorted(os.listdir(self.state)), [watch.JOURNAL])
        self.assertEqual(self.run_watch()[0], 1)

    def group_apply_tells(self, entry, code):
        """Run the group apply's own message for this failed rollback, through the real `notify.deliver`; the channel is a double."""
        sent = []
        channel = mock.patch.dict(groupapply.notify.CHANNELS, {"webhook": lambda ch, text, poster: sent.append(text) or code})
        with channel, mock.patch.object(groupapply, "_rollback", return_value=["dl: could not be restored"]), \
                contextlib.redirect_stdout(io.StringIO()):
            groupapply._finish_rollback(dict(entry, result=None), self.cfg, None, "a control failed")
        return sent

    def test_it_uses_the_key_of_the_group_apply_message(self):
        e = self.failed()
        answer = {"delivered": [], "queued": [], "given_up": []}
        with mock.patch.object(groupapply.notify, "deliver", return_value=answer) as deliver, \
                mock.patch.object(groupapply, "_rollback", return_value=["dl: could not be restored"]), contextlib.redirect_stdout(io.StringIO()):
            groupapply._finish_rollback(dict(e, result=None), self.cfg, None, "a control failed")
        key_of_the_group_apply = deliver.call_args[0][0][0]["key"]
        self.journal([e])
        self.assertEqual([ev["key"] for ev in watch.events(watch.check(self.cfg, lambda: NOW), self.cfg)], [key_of_the_group_apply])

    def test_a_message_the_group_apply_already_delivered_is_not_sent_again(self):
        e = self.failed()
        self.assertEqual(len(self.group_apply_tells(e, 200)), 1)
        self.journal([e])
        rc, _ = self.run_watch()
        self.assertEqual((rc, self.posts), (1, []))                    # still an open incident, but already told

    def test_a_message_the_group_apply_could_not_deliver_is_retried_by_watch(self):
        e = self.failed()
        self.assertEqual(len(self.group_apply_tells(e, 500)), 1)       # the channel was down when the rollback failed
        self.journal([e])
        self.now = NOW + notify.RETRY_CAP_S                            # well after the retry delay
        self.run_watch()
        self.assertEqual(len(self.posts), 1)
        self.run_watch()
        self.assertEqual(len(self.posts), 1)                           # and then once


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
        self.now += notify.RETRY_BASE_S + 1                 # the retry delay has passed
        self.run_watch()
        with open(os.path.join(self.state, "notifs.json")) as f:
            state = json.load(f)
        self.assertTrue(all(v["delivered"] for v in state.values()))


class Key(unittest.TestCase):
    def test_the_key_format_is_fixed_because_it_is_stored_in_notifs_json(self):
        self.assertEqual(watch.group_key("proj-vpn-1-20261120-000000", "rollback-failed"), "group:proj-vpn-1-20261120-000000:rollback-failed")
        self.assertEqual(watch.group_key("a", "ok"), "group:a:ok")


class Command(unittest.TestCase):
    def test_the_command_is_registered(self):
        from rpl import __main__ as cli
        self.assertEqual(cli.COMMANDS["watch"], "watch")


if __name__ == "__main__":
    unittest.main()
