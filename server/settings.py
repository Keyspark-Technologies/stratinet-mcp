import os
from collections.abc import Mapping
from dataclasses import dataclass

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


class SettingsError(ValueError):
    pass


@dataclass(frozen=True)
class Settings:
    port: int
    log_level: str
    allowed_hosts: tuple[str, ...]

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> "Settings":
        return cls(
            port=_port(env.get("PORT", "8000")),
            log_level=_log_level(env.get("LOG_LEVEL", "INFO")),
            allowed_hosts=_allowed_hosts(env.get("ALLOWED_HOSTS", "localhost:*,127.0.0.1:*")),
        )


def _port(raw: str) -> int:
    if not raw.isdigit() or not 1 <= int(raw) <= 65535:
        raise SettingsError("PORT must be a number from 1 to 65535")
    return int(raw)


def _log_level(raw: str) -> str:
    level = raw.strip().upper()
    if level not in LOG_LEVELS:
        raise SettingsError(f"LOG_LEVEL must be one of {', '.join(LOG_LEVELS)}")
    return level


def _allowed_hosts(raw: str) -> tuple[str, ...]:
    hosts = tuple(h.strip() for h in raw.split(",") if h.strip())
    if not hosts:
        raise SettingsError("ALLOWED_HOSTS must list at least one host")
    return hosts
