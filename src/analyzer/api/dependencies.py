import hmac
from functools import lru_cache
from typing import Annotated

import redis
from fastapi import Depends, Header, HTTPException

from analyzer.config import Settings, get_settings
from analyzer.core.orchestrator import Orchestrator
from analyzer.knowledge.cwe_database import CWEDatabase


@lru_cache(maxsize=1)
def get_cwe_db() -> CWEDatabase:
    settings = get_settings()
    db = CWEDatabase()
    if settings.cwe_xml_path.exists():
        db.load(settings.cwe_xml_path)
    return db


def get_orchestrator() -> Orchestrator:
    settings = get_settings()
    cwe_db = get_cwe_db()
    return Orchestrator(settings=settings, cwe_db=cwe_db)


@lru_cache(maxsize=1)
def get_redis_client() -> redis.Redis:
    return redis.Redis.from_url(get_settings().redis_url, decode_responses=True)


def require_api_key(
    settings: Annotated[Settings, Depends(get_settings)],
    x_api_key: Annotated[str | None, Header()] = None,
) -> None:
    """Require X-API-Key when configured, or whenever not in debug mode."""
    expected = settings.api_key
    if not expected:
        if settings.debug:
            return
        raise HTTPException(
            status_code=401,
            detail="ANALYZER_API_KEY is required (set key or ANALYZER_DEBUG=true)",
        )
    provided = x_api_key or ""
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="invalid or missing API key")
