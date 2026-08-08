"""Simple Redis fixed-window rate limiting."""

from __future__ import annotations

from typing import Annotated

import redis
from fastapi import Depends, Header, HTTPException, Request

from analyzer.api.dependencies import get_redis_client, require_api_key
from analyzer.config import Settings, get_settings

# Atomic INCR + EXPIRE on first hit (avoid orphan keys without TTL).
_INCR_EXPIRE_LUA = """
local c = redis.call('INCR', KEYS[1])
if c == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return c
"""


def _client_key(
    request: Request,
    api_key: str | None,
    *,
    trust_x_forwarded_for: bool,
) -> str:
    if api_key:
        return f"key:{api_key[:16]}"
    if trust_x_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return f"ip:{forwarded.split(',')[0].strip()}"
    client = request.client
    host = client.host if client else "unknown"
    return f"ip:{host}"


def rate_limit_analyze(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    redis_client: Annotated[redis.Redis, Depends(get_redis_client)],
    _: Annotated[None, Depends(require_api_key)],
    x_api_key: Annotated[str | None, Header()] = None,
) -> None:
    limit = settings.rate_limit_per_minute
    path = request.url.path
    if path.endswith("/analyze/sync") or path.endswith("/bundle/sync"):
        sync_cap = settings.rate_limit_sync_per_minute
        if limit <= 0:
            limit = sync_cap
        elif sync_cap > 0:
            limit = min(limit, sync_cap)
    if limit <= 0:
        return

    bucket = _client_key(
        request,
        x_api_key,
        trust_x_forwarded_for=settings.trust_x_forwarded_for,
    )
    redis_key = f"analyzer:ratelimit:{bucket}:{path}"
    try:
        count_raw = redis_client.eval(_INCR_EXPIRE_LUA, 1, redis_key, 60)
        count = int(count_raw)  # type: ignore[arg-type]
        if count > limit:
            raise HTTPException(status_code=429, detail="rate limit exceeded")
    except redis.RedisError as e:
        raise HTTPException(status_code=503, detail="redis unavailable") from e
