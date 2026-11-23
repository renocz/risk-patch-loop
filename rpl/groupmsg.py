"""The notification messages of a group apply: their keys and their texts, in ONE place.

`rpl group` (rpl/groupapply.py) gives each message to `rpl.notify` once, when the apply ends. `rpl watch` (a failed rollback) and `rpl notify`
(the "updated" and "rolled back" results) produce the same messages again from the journal, so a message whose first delivery failed is retried;
because the key and the text are built here for all three, `rpl.notify`, which sends one message per key, sends a given message once, whoever
gives it first.

This module imports nothing from the other modules of rpl: `rpl watch` must stand alone.
"""


def group_key(entry_id, outcome):
    """The notification key of a group apply: one per apply (its journal entry id) and outcome ("ok", "rolled-back", "rollback-failed")."""
    return f"group:{entry_id}:{outcome}"


def text(parent, outcome, why="", members=()):
    """The text of the message of one outcome. `members` is the plan's list of {"service", "to"}."""
    if outcome == "ok":
        return f"rpl: group {parent} updated: " + ", ".join(f"{m['service']} -> {m['to']}" for m in members if m.get("to"))
    if outcome == "rolled-back":
        return f"rpl: group {parent}: the update failed ({why}) and was rolled back."
    if outcome == "rollback-failed":
        return f"rpl: group {parent}: the update failed ({why}) AND the rollback failed. Check by hand."
    raise ValueError("unknown outcome " + repr(outcome))
