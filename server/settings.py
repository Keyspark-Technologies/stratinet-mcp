import os
import re
from collections.abc import Mapping
from dataclasses import dataclass

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
AUTH_MODES = ("api_key", "disabled")
MAX_KEY_CACHE_SECONDS = 60
MAX_TOOL_TIMEOUT_SECONDS = 600
TABLE_NAME = re.compile(r"[A-Za-z0-9_.-]{3,255}")
REGION = re.compile(r"[a-z]{2}(-[a-z]+)+-[0-9]{1,2}")
SECONDS = re.compile(r"[0-9]{1,6}(\.[0-9]{1,3})?")
WHOLE = re.compile(r"[0-9]{1,8}")


class SettingsError(ValueError):
    pass


@dataclass(frozen=True)
class AuthSettings:
    keys_table: str
    usage_table: str
    region: str
    per_minute: int
    per_day: int
    cache_seconds: int


@dataclass(frozen=True)
class Settings:
    port: int
    log_level: str
    allowed_hosts: tuple[str, ...]
    auth: AuthSettings | None
    tool_timeout_seconds: float = 30.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> "Settings":
        return cls(
            port=_port(env.get("PORT", "8000")),
            log_level=_log_level(env.get("LOG_LEVEL", "INFO")),
            allowed_hosts=_allowed_hosts(env.get("ALLOWED_HOSTS", "localhost:*,127.0.0.1:*")),
            auth=_auth(env),
            tool_timeout_seconds=_timeout(env.get("TOOL_TIMEOUT_SECONDS", "30")),
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


def _auth(env: Mapping[str, str]) -> AuthSettings | None:
    mode = env.get("AUTH_MODE", "api_key").strip().lower()
    if mode not in AUTH_MODES:
        raise SettingsError(f"AUTH_MODE must be one of {', '.join(AUTH_MODES)}")
    if mode == "disabled":
        return None
    per_minute = _count(env.get("RATE_LIMIT_PER_MINUTE", "60"), "RATE_LIMIT_PER_MINUTE")
    per_day = _count(env.get("RATE_LIMIT_PER_DAY", "5000"), "RATE_LIMIT_PER_DAY")
    if per_day < per_minute:
        raise SettingsError("RATE_LIMIT_PER_DAY must be at least RATE_LIMIT_PER_MINUTE")
    return AuthSettings(
        keys_table=_table(env.get("API_KEYS_TABLE", ""), "API_KEYS_TABLE"),
        usage_table=_table(env.get("USAGE_TABLE", ""), "USAGE_TABLE"),
        region=_region(env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION") or ""),
        per_minute=per_minute,
        per_day=per_day,
        cache_seconds=_cache_seconds(env.get("API_KEY_CACHE_SECONDS", "60")),
    )


def _table(raw: str, name: str) -> str:
    table = raw.strip()
    if not TABLE_NAME.fullmatch(table):
        raise SettingsError(f"{name} must name a DynamoDB table when AUTH_MODE is api_key")
    return table


def _region(raw: str) -> str:
    region = raw.strip()
    if not REGION.fullmatch(region):
        raise SettingsError("AWS_REGION must name an AWS region when AUTH_MODE is api_key")
    return region


def _count(raw: str, name: str) -> int:
    raw = raw.strip()
    if not WHOLE.fullmatch(raw) or not 1 <= int(raw) <= 10_000_000:
        raise SettingsError(f"{name} must be a number from 1 to 10000000")
    return int(raw)


def _cache_seconds(raw: str) -> int:
    raw = raw.strip()
    if not WHOLE.fullmatch(raw) or int(raw) > MAX_KEY_CACHE_SECONDS:
        raise SettingsError(
            f"API_KEY_CACHE_SECONDS must be a number from 0 to {MAX_KEY_CACHE_SECONDS}"
        )
    return int(raw)


def _timeout(raw: str) -> float:
    raw = raw.strip()
    if not SECONDS.fullmatch(raw) or not 0 < float(raw) <= MAX_TOOL_TIMEOUT_SECONDS:
        raise SettingsError(
            f"TOOL_TIMEOUT_SECONDS must be a number above 0 and at most {MAX_TOOL_TIMEOUT_SECONDS}"
        )
    return float(raw)
