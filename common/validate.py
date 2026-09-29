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


MAX_OUTPUTS = 8
MAX_OUTPUT_BYTES = 64 * 1024
MAX_OUTPUTS_TOTAL_BYTES = 256 * 1024


def check_enum(value: Any, allowed: Iterable[str], field: str) -> str:
    allowed = set(allowed)
    if not isinstance(value, str) or value not in allowed:
        raise ToolInputError(
            f"unsupported_{field}",
            f"{field} must be one of the supported values",
            supported=sorted(allowed),
            field=field,
        )
    return value


def _size(text: Any) -> int:
    if isinstance(text, bytes):
        return len(text)
    return len(str(text).encode("utf-8"))


def check_size(text: Any, max_bytes: int, field: str) -> Any:
    if text is not None and _size(text) > max_bytes:
        raise ToolInputError("input_too_large", f"{field} exceeds {max_bytes} bytes", field=field)
    return text


def check_outputs(outputs: Any) -> list:
    if not isinstance(outputs, list | tuple):
        raise ToolInputError("invalid_value", "outputs must be a list", field="outputs")
    if len(outputs) > MAX_OUTPUTS:
        raise ToolInputError("input_too_large", f"at most {MAX_OUTPUTS} outputs", field="outputs")
    total = 0
    for i, out in enumerate(outputs):
        n = _size(out)
        if n > MAX_OUTPUT_BYTES:
            raise ToolInputError(
                "input_too_large", f"output {i} exceeds {MAX_OUTPUT_BYTES} bytes", field="outputs"
            )
        total += n
    if total > MAX_OUTPUTS_TOTAL_BYTES:
        raise ToolInputError(
            "input_too_large",
            f"outputs exceed {MAX_OUTPUTS_TOTAL_BYTES} bytes in total",
            field="outputs",
        )
    return list(outputs)
