# mypy: disable-error-code="import-untyped,no-untyped-def,untyped-decorator"
from __future__ import annotations

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
    task_soft_time_limit=settings.celery_soft_time_limit_seconds,
    task_time_limit=settings.celery_time_limit_seconds,
)


@celery_app.task(name="analyzer.run_async_scan", bind=True)
def run_async_scan(
    self,  # noqa: ANN001
    source_code: str,
    file_path: str,
    scan_id: str,
    config: dict | None = None,  # type: ignore[type-arg]
) -> dict:  # type: ignore[type-arg]
    from uuid import UUID

    from analyzer.api.dependencies import get_cwe_db, get_orchestrator
    from analyzer.api.schemas import AnalyzeRequest, ScanConfig
    from analyzer.config import get_settings as _get_settings
    from analyzer.core.orchestrator import Orchestrator

    scan_config = ScanConfig(**(config or {}))
    request = AnalyzeRequest(
        source_code=source_code,
        file_path=file_path,
        config=scan_config,
        scan_id=UUID(scan_id),
    )

    worker_settings = _get_settings()
    if worker_settings.analysis_budget_ms is None and worker_settings.async_analysis_budget_ms > 0:
        orch_settings = worker_settings.model_copy(
            update={"analysis_budget_ms": worker_settings.async_analysis_budget_ms}
        )
        try:
            cwe = get_cwe_db()
        except Exception:  # noqa: BLE001
            cwe = None
        orchestrator = Orchestrator(settings=orch_settings, cwe_db=cwe)
    else:
        orchestrator = get_orchestrator()

    result = orchestrator.analyze_sync(request)
    return result.model_dump(mode="json")
