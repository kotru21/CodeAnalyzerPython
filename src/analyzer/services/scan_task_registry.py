"""Redis mapping from API scan_id to Celery task id for async poll."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import redis as redis_lib

KEY_PREFIX = "analyzer:scan_task:"


def registry_key(scan_id: str) -> str:
    return f"{KEY_PREFIX}{scan_id}"


def register_scan_task(
    redis_client: redis_lib.Redis, scan_id: str, task_id: str, ttl_seconds: int
) -> None:
    redis_client.setex(registry_key(scan_id), ttl_seconds, task_id)


def get_task_id(redis_client: redis_lib.Redis, scan_id: str) -> str | None:
    raw = redis_client.get(registry_key(scan_id))
    if raw is None:
        return None
    if isinstance(raw, bytes):
        return raw.decode()
    return str(raw)
