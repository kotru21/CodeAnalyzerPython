import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Self

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    # Compose secrets (POSTGRES_*, REDIS_*) may sit in the same .env; ignore extras.
    model_config = SettingsConfigDict(
        env_prefix="ANALYZER_",
        env_file=".env",
        extra="ignore",
    )

    app_name: str = "Analyzer Service"
    app_version: str = "0.1.0"
    debug: bool = False

    database_url: str = "postgresql://analyzer:analyzer@localhost:5432/analyzer"
    redis_url: str = "redis://localhost:6379/0"

    cwe_xml_path: Path = _PROJECT_ROOT / "data" / "cwec_v4.19.1.xml"

    max_sync_source_bytes: int = 50_000
    max_source_bytes: int = 5_000_000

    # Wall-clock budget for analyze_sync (rules + optional taint). None = no limit.
    analysis_budget_ms: int | None = None
    # Default budget applied to async Celery scans when request/config has none.
    async_analysis_budget_ms: int = 120_000

    # Shared secret; required unless debug=True. When set, require X-API-Key.
    api_key: str | None = None

    celery_soft_time_limit_seconds: int = 180
    celery_time_limit_seconds: int = 240

    max_bundle_files: int = 32
    max_bundle_total_bytes: int = 524_288

    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    scan_task_registry_ttl_seconds: int = 604_800
    cors_origins: list[str] = []
    sarif_information_uri: str | None = None

    # Rate limits (Redis); 0 disables.
    rate_limit_per_minute: int = 60
    rate_limit_sync_per_minute: int = 20

    # When False, SQL *.query sinks match any receiver (legacy noisy mode).
    sql_sink_allowlist: bool = True

    # Experimental: ThreadPool rule execution sharing one tree-sitter Tree.
    # Keep False in production until concurrency is validated (not process-safe).
    parallel_rules: bool = False
    parallel_rules_workers: int = 4

    # Honor X-Forwarded-For for rate-limit buckets only when behind a trusted proxy.
    trust_x_forwarded_for: bool = False

    # Mark pending/running scans failed if updated_at older than this (seconds).
    # Default None → celery_time_limit_seconds + 60 (set in model_validator).
    scan_stale_after_seconds: int | None = None

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Any) -> list[str]:
        if v is None or v == "":
            return []
        if isinstance(v, list):
            return [str(x) for x in v]
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
            except json.JSONDecodeError:
                return [s.strip() for s in v.split(",") if s.strip()]
            else:
                if isinstance(parsed, list):
                    return [str(x) for x in parsed]
                return [str(parsed)]
        return []

    @model_validator(mode="after")
    def reject_cors_wildcard(self) -> Self:
        if "*" in self.cors_origins:
            msg = "cors_origins must not contain '*' (incompatible with allow_credentials)"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def default_stale_after_celery_limit(self) -> Self:
        """Stale timeout must cover Celery hard time limit (+ buffer for persist)."""
        minimum = self.celery_time_limit_seconds + 60
        if self.scan_stale_after_seconds is None or self.scan_stale_after_seconds < minimum:
            self.scan_stale_after_seconds = minimum
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
