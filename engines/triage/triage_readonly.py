from __future__ import annotations

_WRITE_PREFIX = (
    "config", "conf t", "configure", "no ", "set ", "unset ", "delete ", "commit",
    "write", "copy ", "reload", "clear ", "erase", "rename ", "move ",
)

_DESTRUCTIVE_OP = (
    "reboot", "shutdown", "restart", "factoryreset", "formatlogdisk", "format ",
    "restore", "halt", "poweroff", "zeroize", "upgrade", "firmware", "usb-disk",
    "request system", "backup",
)


_READ_VERB = ("show ", "get ", "display ", "monitor ")


def _is_read_only(command: str) -> bool:
    c = " ".join(command.strip().lower().split())
    if not c:
        return False
    if any(c.startswith(w) for w in _WRITE_PREFIX):
        return False
    if any(c.startswith(v) for v in _READ_VERB):
        return True
    return not any(op in c for op in _DESTRUCTIVE_OP)
