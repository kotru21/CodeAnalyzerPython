from pathlib import Path
from functools import lru_cache

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

    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
