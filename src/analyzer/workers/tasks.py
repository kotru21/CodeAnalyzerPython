# mypy: disable-error-code="import-untyped,no-untyped-def,untyped-decorator"
from celery import Celery

from analyzer.config import get_settings

settings = get_settings()

celery_app = Celery(
    "analyzer",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    result_expires=604_800,
)


@celery_app.task(name="analyzer.run_async_scan", bind=True, max_retries=2)
def run_async_scan(
    self,  # noqa: ANN001
    source_code: str,
    file_path: str,
    scan_id: str,
    config: dict | None = None,  # type: ignore[type-arg]
) -> dict:  # type: ignore[type-arg]
    from uuid import UUID

    from analyzer.api.dependencies import get_orchestrator
    from analyzer.api.schemas import AnalyzeRequest, ScanConfig

    scan_config = ScanConfig(**(config or {}))
    request = AnalyzeRequest(
        source_code=source_code,
        file_path=file_path,
        config=scan_config,
        scan_id=UUID(scan_id),
    )

    orchestrator = get_orchestrator()
    result = orchestrator.analyze_sync(request)

    return result.model_dump(mode="json")
