"""Redis blob store for async scan source payloads (keeps Celery args small)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import redis

SOURCE_KEY_PREFIX = "analyzer:scan:source:"


def source_key(scan_id: str) -> str:
    return f"{SOURCE_KEY_PREFIX}{scan_id}"


def store_scan_source(
    redis_client: redis.Redis,
    scan_id: str,
    source_code: str,
    ttl_seconds: int,
) -> None:
    redis_client.setex(source_key(scan_id), ttl_seconds, source_code)


def load_scan_source(redis_client: redis.Redis, scan_id: str) -> str | None:
    raw = redis_client.get(source_key(scan_id))
    if raw is None:
        return None
    if isinstance(raw, bytes):
        return raw.decode()
    return str(raw)


def delete_scan_source(redis_client: redis.Redis, scan_id: str) -> None:
    redis_client.delete(source_key(scan_id))
