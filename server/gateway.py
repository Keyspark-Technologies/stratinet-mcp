import asyncio
import contextvars
import hashlib
import json
import logging
import re
import time
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from server.errors import http_error_payload
from server.settings import MAX_KEY_CACHE_SECONDS, AuthSettings

logger = logging.getLogger(__name__)

OPEN_PATHS = frozenset({"/healthz"})
ACTIVE = "active"
USAGE_TTL_SECONDS = 2 * 24 * 60 * 60
LOG_PREFIX_CHARS = 8
MAX_CACHED_KEYS = 10_000
GATEWAY_WORKERS = 16
BEARER = re.compile(r"[Bb][Ee][Aa][Rr][Ee][Rr] ([A-Za-z0-9_-]{16,256})")


class KeyStore(Protocol):
    def key_status(self, key_hash: str) -> str | None: ...

    def count_call(self, key_hash: str, window: str, limit: int, expires_at: int) -> bool: ...


@dataclass(frozen=True)
class Window:
    name: str
    seconds: int
    limit: int


class DynamoKeyStore:
    def __init__(self, auth: AuthSettings, client: Any = None) -> None:
        if client is None:
            import boto3
            from boto3.session import Config

            client = boto3.client(
                "dynamodb",
                region_name=auth.region,
                config=Config(
                    connect_timeout=2,
                    read_timeout=2,
                    retries={"max_attempts": 2, "mode": "standard"},
                ),
            )
        self._client = client
        self._keys_table = auth.keys_table
        self._usage_table = auth.usage_table

    def key_status(self, key_hash: str) -> str | None:
        item = self._client.get_item(
            TableName=self._keys_table,
            Key={"key_hash": {"S": key_hash}},
            ProjectionExpression="#status",
            ExpressionAttributeNames={"#status": "status"},
        ).get("Item")
        if not item:
            return None
        return (item.get("status") or {}).get("S")

    def count_call(self, key_hash: str, window: str, limit: int, expires_at: int) -> bool:
        try:
            self._client.update_item(
                TableName=self._usage_table,
                Key={"key_hash": {"S": key_hash}, "window": {"S": window}},
                UpdateExpression="ADD calls :one SET expires_at = :expires_at",
                ConditionExpression="attribute_not_exists(calls) OR calls < :limit",
                ExpressionAttributeValues={
                    ":one": {"N": "1"},
                    ":limit": {"N": str(limit)},
                    ":expires_at": {"N": str(expires_at)},
                },
            )
        except self._client.exceptions.ConditionalCheckFailedException:
            return False
        return True


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("ascii")).hexdigest()


def bearer_key(scope: dict) -> str | None:
    values = [v for k, v in scope.get("headers") or () if k.lower() == b"authorization"]
    if len(values) != 1:
        return None
    try:
        header = values[0].decode("ascii")
    except UnicodeDecodeError:
        return None
    match = BEARER.fullmatch(header)
    return match.group(1) if match else None


class Gateway:
    def __init__(
        self,
        app: Callable,
        auth: AuthSettings,
        store: KeyStore,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.app = app
        self.store = store
        self.clock = clock
        self.monotonic = monotonic
        self.cache_seconds = min(auth.cache_seconds, MAX_KEY_CACHE_SECONDS)
        self.windows = (
            Window("minute", 60, auth.per_minute),
            Window("day", 24 * 60 * 60, auth.per_day),
        )
        self._cache: OrderedDict[str, tuple[float, bool]] = OrderedDict()
        self._executor = ThreadPoolExecutor(GATEWAY_WORKERS, thread_name_prefix="gateway")

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] == "lifespan" or (
            scope["type"] == "http" and scope.get("path") in OPEN_PATHS
        ):
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            await send({"type": "websocket.close", "code": 1008})
            return
        key = bearer_key(scope)
        if key is None:
            logger.info("request refused: no valid authorization header")
            await _refuse(send, 401, "unauthorized")
            return
        prefix = key[:LOG_PREFIX_CHARS]
        key_hash = hash_key(key)
        try:
            active = await self._is_active(key_hash)
            retry_after = None
            if active:
                retry_after = await self._off_loop(self._count, key_hash)
        except Exception as exc:
            logger.error("api key check failed for key %s: %s", prefix, type(exc).__name__)
            await _refuse(send, 503, "unavailable")
            return
        if not active:
            logger.info("request refused: api key %s is not active", prefix)
            await _refuse(send, 401, "unauthorized")
            return
        if retry_after is not None:
            logger.info("request refused: api key %s is over its rate limit", prefix)
            await _refuse(send, 429, "rate_limited", [(b"retry-after", str(retry_after).encode())])
            return
        await self.app(scope, receive, send)

    async def _is_active(self, key_hash: str) -> bool:
        now = self.monotonic()
        cached = self._cache.get(key_hash)
        if cached is not None and cached[0] > now:
            return cached[1]
        active = await self._off_loop(self.store.key_status, key_hash) == ACTIVE
        if self.cache_seconds > 0:
            self._cache[key_hash] = (now + self.cache_seconds, active)
            self._cache.move_to_end(key_hash)
            while len(self._cache) > MAX_CACHED_KEYS:
                self._cache.popitem(last=False)
        return active

    async def _off_loop(self, call: Callable, *args: Any) -> Any:
        return await asyncio.get_running_loop().run_in_executor(
            self._executor, contextvars.copy_context().run, call, *args
        )

    def _count(self, key_hash: str) -> int | None:
        now = self.clock()
        for window in self.windows:
            start = int(now // window.seconds) * window.seconds
            if not self.store.count_call(
                key_hash, _window_id(window, start), window.limit, start + USAGE_TTL_SECONDS
            ):
                return max(1, int(start + window.seconds - now))
        return None


def _window_id(window: Window, start: int) -> str:
    stamp = datetime.fromtimestamp(start, UTC)
    if window.name == "day":
        return f"day#{stamp:%Y-%m-%d}"
    return f"minute#{stamp:%Y-%m-%dT%H:%M}"


async def _refuse(
    send: Callable, status: int, code: str, extra: list[tuple[bytes, bytes]] | None = None
) -> None:
    body = json.dumps(http_error_payload(code)).encode()
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
        *(extra or []),
    ]
    if status == 401:
        headers.append((b"www-authenticate", b"Bearer"))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})
