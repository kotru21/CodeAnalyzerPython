import logging
from typing import Annotated, Literal
from uuid import UUID, uuid4

import redis
from celery.result import AsyncResult
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from analyzer.api.dependencies import get_orchestrator, get_redis_client, require_api_key
from analyzer.api.rate_limit import rate_limit_analyze
from analyzer.api.schemas import (
    AnalyzeBundleRequest,
    AnalyzeRequest,
    AnalyzeResponse,
    AsyncAnalyzeResponse,
    HealthResponse,
    RuleInfo,
)
from analyzer.config import Settings, get_settings
from analyzer.core.language_detect import detect_language
from analyzer.core.orchestrator import Orchestrator
from analyzer.export.sarif import build_sarif_log
from analyzer.models.base import get_session_factory
from analyzer.rules.registry import get_all_rules, get_rules_for_language
from analyzer.services.scan_repository import (
    create_scan,
    fail_stale_scan,
    get_scan,
    mark_failed,
    save_analyze_response,
    scan_to_result_dict,
)
from analyzer.services.scan_source_store import store_scan_source
from analyzer.services.scan_task_registry import register_scan_task
from analyzer.utils.hash import md5_fingerprint
from analyzer.workers.tasks import celery_app, run_async_scan

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")


def _persist_response(result: AnalyzeResponse) -> None:
    factory = get_session_factory()
    session = factory()
    try:
        save_analyze_response(session, result)
    except Exception:  # noqa: BLE001
        _logger.exception("failed to persist scan %s", result.scan_id)
        session.rollback()
    finally:
        session.close()


@router.post("/analyze/sync", response_model=None)
def analyze_sync(
    request: AnalyzeRequest,
    orchestrator: Annotated[Orchestrator, Depends(get_orchestrator)],
    settings: Annotated[Settings, Depends(get_settings)],
    _: Annotated[None, Depends(rate_limit_analyze)],
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
    _persist_response(result)
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
    _: Annotated[None, Depends(rate_limit_analyze)],
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
    _persist_response(result)
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
    _: Annotated[None, Depends(rate_limit_analyze)],
) -> AsyncAnalyzeResponse:
    if len(request.source_code.encode()) > settings.max_source_bytes:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Source too large for async analysis. Max: {settings.max_source_bytes} bytes."
            ),
        )
    scan_id = str(uuid4())
    config = request.config.model_dump(mode="json")
    language = request.language or detect_language(request.file_path)
    source_hash = md5_fingerprint(request.source_code)

    factory = get_session_factory()
    session = factory()
    try:
        create_scan(
            session,
            scan_id=scan_id,
            language=language,
            source_hash=source_hash,
            status="pending",
        )
    except Exception as e:  # noqa: BLE001
        session.rollback()
        _logger.exception("failed to create scan row")
        raise HTTPException(status_code=503, detail="database unavailable") from e
    finally:
        session.close()

    task = None
    try:
        store_scan_source(
            redis_client,
            scan_id,
            request.source_code,
            settings.scan_task_registry_ttl_seconds,
        )
        # Pass source_code for rolling upgrades with older workers that ignore Redis.
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
    except Exception as e:  # noqa: BLE001 — broker/redis/encode failures
        if task is not None:
            try:
                AsyncResult(task.id, app=celery_app).revoke(terminate=False)
            except Exception:  # noqa: BLE001
                _logger.exception("failed to revoke orphan celery task %s", task.id)
        factory = get_session_factory()
        session = factory()
        try:
            err_code = "redis_unavailable" if isinstance(e, redis.RedisError) else "enqueue_failed"
            mark_failed(
                session,
                scan_id,
                error_message=str(e) or "enqueue failed",
                error_code=err_code,
            )
        finally:
            session.close()
        detail = "redis unavailable" if isinstance(e, redis.RedisError) else "enqueue failed"
        raise HTTPException(status_code=503, detail=detail) from e
    return AsyncAnalyzeResponse(
        task_id=task.id,
        scan_id=UUID(scan_id),
        # Keep legacy "queued" for API clients; DB row stays "pending".
        status="queued",
        poll_url=f"/api/v1/results/{scan_id}",
    )


@router.get("/results/{scan_id}")
def get_results(
    scan_id: str,
    settings: Annotated[Settings, Depends(get_settings)],
    _: Annotated[None, Depends(require_api_key)],
) -> dict:  # type: ignore[type-arg]
    try:
        UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="unknown scan_id") from None

    factory = get_session_factory()
    session = factory()
    try:
        stale_after = settings.scan_stale_after_seconds or (settings.celery_time_limit_seconds + 60)
        fail_stale_scan(session, scan_id, older_than_seconds=stale_after)
        scan = get_scan(session, scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="unknown scan_id")
        return scan_to_result_dict(session, scan)
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        _logger.exception("failed to load scan %s", scan_id)
        raise HTTPException(status_code=503, detail="database unavailable") from e
    finally:
        session.close()


@router.get("/health", response_model=HealthResponse)
def health(settings: Annotated[Settings, Depends(get_settings)]) -> HealthResponse:
    db_status: Literal["ok", "unavailable"] = "ok"
    try:
        from sqlalchemy import text

        factory = get_session_factory()
        session = factory()
        try:
            session.execute(text("SELECT 1"))
        finally:
            session.close()
    except Exception:  # noqa: BLE001
        db_status = "unavailable"
    return HealthResponse(
        status="healthy" if db_status == "ok" else "degraded",
        version=settings.app_version,
        rules_loaded=len(get_all_rules()),
        database=db_status,
    )
