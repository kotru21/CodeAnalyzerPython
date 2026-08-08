import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Self

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ANALYZER_", env_file=".env")

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

    # Shared secret; when set, require X-API-Key on analyze/results/rules.
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


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
