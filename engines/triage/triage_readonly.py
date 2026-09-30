"""Is this command a read?

Lives in its own module with no app imports so it can be tested directly. That matters:
an earlier version of this guard banned the `execute` and `request` verbs
wholesale, which silently refused three of FortiOS's own signalled checks and made every
Fortinet diagnosis conclude nothing. A guard that blocks valid reads fails as quietly as
one that permits writes, so it needs its own tests against the real catalog.
"""
from __future__ import annotations

#: Read-only guard. This guard is the only thing between a bad catalog entry and a
#: config change, so it fails closed.
#:
#: Prefixes that are never a read: config mode, writes, resets.
_WRITE_PREFIX = (
    "config", "conf t", "configure", "no ", "set ", "unset ", "delete ", "commit",
    "write", "copy ", "reload", "clear ", "erase", "rename ", "move ",
)

#: FortiOS and JunOS put READ-ONLY operations behind `execute` and `request` too —
#: `execute date`, `execute ping`, `execute log display`, `request pfe statistics`. A
#: blanket ban on those verbs (which is what shipped) refused three of FortiOS's own
#: signalled checks and killed every Fortinet diagnosis. So the destructive operations
#: are named instead, and screened on EVERY command regardless of its leading verb.
_DESTRUCTIVE_OP = (
    "reboot", "shutdown", "restart", "factoryreset", "formatlogdisk", "format ",
    "restore", "halt", "poweroff", "zeroize", "upgrade", "firmware", "usb-disk",
    "request system", "backup",
)


#: Verbs that only ever read on every platform we carry. A destructive word appearing
#: as their ARGUMENT is a topic, not an action — `show system reboot` lists scheduled
#: reboots and is the one command in the catalog the unanchored screen wrongly refused.
_READ_VERB = ("show ", "get ", "display ", "monitor ")


def _is_read_only(command: str) -> bool:
    """True when `command` cannot change or disrupt the device.

    Deliberately conservative: anything not provably a read is refused. A refusal
    costs one skipped check, whereas a false pass runs a config change on customer kit.
    """
    c = " ".join(command.strip().lower().split())
    if not c:
        return False
    if any(c.startswith(w) for w in _WRITE_PREFIX):
        return False
    if any(c.startswith(v) for v in _READ_VERB):
        return True
    return not any(op in c for op in _DESTRUCTIVE_OP)
