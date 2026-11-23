"""The notification messages of a group apply: keys and texts, shared by the group apply, `rpl watch` and `rpl notify`."""
import unittest

from rpl import groupmsg


class Keys(unittest.TestCase):
    def test_the_key_format_is_fixed_because_it_is_stored_in_notifs_json(self):
        self.assertEqual(groupmsg.group_key("proj-vpn-1-20261120-000000", "rollback-failed"), "group:proj-vpn-1-20261120-000000:rollback-failed")
        self.assertEqual(groupmsg.group_key("a", "ok"), "group:a:ok")
        self.assertEqual(groupmsg.group_key("a", "rolled-back"), "group:a:rolled-back")


class Texts(unittest.TestCase):
    def test_the_success_text_lists_the_members_that_got_a_new_image(self):
        members = [{"service": "vpn", "to": "img:2"}, {"service": "idx", "to": None}, {"service": "dl", "to": "img:3"}]
        self.assertEqual(groupmsg.text("proj-vpn-1", "ok", members=members), "rpl: group proj-vpn-1 updated: vpn -> img:2, dl -> img:3")

    def test_the_rollback_texts_carry_the_reason(self):
        self.assertEqual(groupmsg.text("p", "rolled-back", "a control failed"), "rpl: group p: the update failed (a control failed) and was rolled back.")
        self.assertEqual(groupmsg.text("p", "rollback-failed", "a control failed"),
                         "rpl: group p: the update failed (a control failed) AND the rollback failed. Check by hand.")

    def test_an_unknown_outcome_is_an_error(self):
        with self.assertRaises(ValueError):
            groupmsg.text("p", "fine")

    def test_the_module_imports_nothing_from_rpl(self):
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(groupmsg))
        self.assertEqual([n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))], [])        # `rpl watch` must stand alone


if __name__ == "__main__":
    unittest.main()
