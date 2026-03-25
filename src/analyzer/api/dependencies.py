from functools import lru_cache

import redis

from analyzer.config import get_settings
from analyzer.core.orchestrator import Orchestrator
from analyzer.knowledge.cwe_database import CWEDatabase


@lru_cache(maxsize=1)
def _get_cwe_db() -> CWEDatabase:
    settings = get_settings()
    db = CWEDatabase()
    if settings.cwe_xml_path.exists():
        db.load(settings.cwe_xml_path)
    return db


def get_orchestrator() -> Orchestrator:
    settings = get_settings()
    cwe_db = _get_cwe_db()
    return Orchestrator(settings=settings, cwe_db=cwe_db)


@lru_cache(maxsize=1)
def get_redis_client() -> redis.Redis:
    return redis.Redis.from_url(get_settings().redis_url, decode_responses=True)
