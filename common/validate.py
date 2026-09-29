from collections.abc import Iterable, Mapping
from typing import Any


class ToolInputError(Exception):
    def __init__(
        self,
        code: str,
        message: str = "",
        supported: list[str] | None = None,
        field: str | None = None,
    ):
        super().__init__(code)
        self.code = code
        self.message = message
        self.supported = supported
        self.field = field


def check_fields(
    arguments: Mapping[str, Any], required: Iterable[str] = (), optional: Iterable[str] = ()
) -> None:
    required = tuple(required)
    allowed = set(required) | set(optional)
    for name in sorted(arguments):
        if name not in allowed:
            raise ToolInputError("unknown_field", field=name)
    for name in required:
        if name not in arguments:
            raise ToolInputError("missing_field", field=name)
