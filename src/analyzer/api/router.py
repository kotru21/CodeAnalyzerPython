import logging
from typing import Annotated
from uuid import UUID, uuid4

import redis
from celery.result import AsyncResult
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from analyzer.api.dependencies import get_orchestrator, get_redis_client, require_api_key
from analyzer.api.schemas import (
    AnalyzeBundleRequest,
    AnalyzeRequest,
    AnalyzeResponse,
    AsyncAnalyzeResponse,
    HealthResponse,
    RuleInfo,
)
from analyzer.config import Settings, get_settings
from analyzer.core.orchestrator import Orchestrator
from analyzer.export.sarif import build_sarif_log
from analyzer.rules.registry import get_all_rules, get_rules_for_language
from analyzer.services.scan_task_registry import get_task_id, register_scan_task
from analyzer.workers.tasks import celery_app, run_async_scan

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")


@router.post("/analyze/sync", response_model=None)
def analyze_sync(
    request: AnalyzeRequest,
    orchestrator: Annotated[Orchestrator, Depends(get_orchestrator)],
    settings: Annotated[Settings, Depends(get_settings)],
    _: Annotated[None, Depends(require_api_key)],
) -> AnalyzeResponse | JSONResponse:
    if len(request.source_code.encode()) > settings.max_sync_source_bytes:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Source too large for sync analysis. "
                f"Max: {settings.max_sync_source_bytes} bytes. Use /analyze/async."
            ),
        )
    try:
        result = orchestrator.analyze_sync(request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    if request.response_format == "sarif":
        doc = build_sarif_log(
            result,
            tool_name=settings.app_name,
            tool_version=settings.app_version,
            information_uri=settings.sarif_information_uri,
        )
        return JSONResponse(content=doc, media_type="application/sarif+json")
    return result


@router.post("/analyze/bundle/sync", response_model=None)
def analyze_bundle_sync(
    request: AnalyzeBundleRequest,
    orchestrator: Annotated[Orchestrator, Depends(get_orchestrator)],
    settings: Annotated[Settings, Depends(get_settings)],
    _: Annotated[None, Depends(require_api_key)],
) -> AnalyzeResponse | JSONResponse:
    nfiles = len(request.files)
    if nfiles > settings.max_bundle_files:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Too many files in bundle (max {settings.max_bundle_files}). "
                "Reduce the number of entries or raise ANALYZER_MAX_BUNDLE_FILES."
            ),
        )
    total_bytes = sum(len(s.encode("utf-8")) for s in request.files.values())
    if total_bytes > settings.max_bundle_total_bytes:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Bundle too large ({total_bytes} bytes). "
                f"Max: {settings.max_bundle_total_bytes}. "
                "Raise ANALYZER_MAX_BUNDLE_TOTAL_BYTES if needed."
            ),
        )
    try:
        result = orchestrator.analyze_bundle_sync(request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    if request.response_format == "sarif":
        doc = build_sarif_log(
            result,
            tool_name=settings.app_name,
            tool_version=settings.app_version,
            information_uri=settings.sarif_information_uri,
        )
        return JSONResponse(content=doc, media_type="application/sarif+json")
    return result


@router.get("/rules", response_model=list[RuleInfo])
def list_rules(
    _: Annotated[None, Depends(require_api_key)],
    language: str | None = None,
) -> list[RuleInfo]:
    rules = get_rules_for_language(language) if language else get_all_rules()
    return [
        RuleInfo(
            rule_id=r.meta().rule_id,
            title=r.meta().title,
            severity=r.meta().severity,
            confidence=r.meta().confidence,
            cwe_id=r.meta().cwe_id,
            owasp=r.meta().owasp,
            description=r.meta().description,
        )
        for r in rules
    ]


@router.post("/analyze/async", response_model=AsyncAnalyzeResponse)
def analyze_async(
    request: AnalyzeRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    redis_client: Annotated[redis.Redis, Depends(get_redis_client)],
    _: Annotated[None, Depends(require_api_key)],
) -> AsyncAnalyzeResponse:
    if len(request.source_code.encode()) > settings.max_source_bytes:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Source too large for async analysis. "
                f"Max: {settings.max_source_bytes} bytes."
            ),
        )
    scan_id = str(uuid4())
    config = request.config.model_dump(mode="json")

    task = None
    try:
        task = run_async_scan.delay(
            source_code=request.source_code,
            file_path=request.file_path,
            scan_id=scan_id,
            config=config,
        )
        register_scan_task(
            redis_client,
            scan_id,
            task.id,
            settings.scan_task_registry_ttl_seconds,
        )
    except redis.RedisError as e:
        if task is not None:
            try:
                AsyncResult(task.id, app=celery_app).revoke(terminate=False)
            except Exception:  # noqa: BLE001
                _logger.exception("failed to revoke orphan celery task %s", task.id)
        raise HTTPException(status_code=503, detail="redis unavailable") from e
    return AsyncAnalyzeResponse(
        task_id=task.id,
        scan_id=UUID(scan_id),
        status="queued",
        poll_url=f"/api/v1/results/{scan_id}",
    )


@router.get("/results/{scan_id}")
def get_results(
    scan_id: str,
    redis_client: Annotated[redis.Redis, Depends(get_redis_client)],
    _: Annotated[None, Depends(require_api_key)],
) -> dict:  # type: ignore[type-arg]
    try:
        UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="unknown scan_id") from None
    try:
        task_id = get_task_id(redis_client, scan_id)
    except redis.RedisError as e:
        raise HTTPException(status_code=503, detail="redis unavailable") from e
    if not task_id:
        raise HTTPException(status_code=404, detail="unknown scan_id")

    ar = AsyncResult(task_id, app=celery_app)
    state = ar.state
    if state in ("PENDING", "STARTED", "RETRY"):
        return {"status": "pending", "scan_id": scan_id}
    if state == "SUCCESS":
        payload = ar.result
        if not isinstance(payload, dict):
            return {
                "status": "failed",
                "scan_id": scan_id,
                "error": "invalid task result",
            }
        out = dict(payload)
        out["status"] = "completed"
        return out
    if ar.info is not None:
        _logger.warning("async scan %s failed: %s", scan_id, ar.info)
    return {"status": "failed", "scan_id": scan_id, "error": "task failed"}


@router.get("/health", response_model=HealthResponse)
async def health(settings: Annotated[Settings, Depends(get_settings)]) -> HealthResponse:
    return HealthResponse(
        status="healthy",
        version=settings.app_version,
        rules_loaded=len(get_all_rules()),
    )
