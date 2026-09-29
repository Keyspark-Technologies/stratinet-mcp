import re
from collections.abc import Iterator

MARKERS = (
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r'File "[^"]+", line \d+'),
    re.compile(r"/app/"),
    re.compile(r"\b[A-Z][A-Z0-9_]*_URL="),
    re.compile(r"<[A-Za-z_][\w.]* object at 0x[0-9a-fA-F]+>"),
    re.compile(r"\b[A-Z][A-Za-z]*(?:Error|Exception)\("),
)

PRIVATE_IP = re.compile(r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b")


class InternalMarkerError(Exception):
    pass


def assert_no_internal_markers(payload: object, *, check_private_ips: bool = True) -> None:
    patterns = MARKERS + (PRIVATE_IP,) if check_private_ips else MARKERS
    for text in _strings(payload):
        for pattern in patterns:
            if pattern.search(text):
                raise InternalMarkerError(pattern.pattern)


def _strings(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)
