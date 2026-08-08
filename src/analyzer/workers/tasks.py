# mypy: disable-error-code="import-untyped,no-untyped-def,untyped-decorator"
from __future__ import annotations

import logging
import time
from typing import Any

from celery import Celery
from sqlalchemy.exc import SQLAlchemyError

from analyzer.config import Settings, get_settings

_logger = logging.getLogger(__name__)

# Retryable infra errors — do not mark scan failed until final attempt.
_RETRYABLE = (ConnectionError, TimeoutError, OSError, SQLAlchemyError)

celery_app = Celery("analyzer")

_MAX_RETRIES = 3
_PERSIST_ATTEMPTS = 3


def configure_celery(settings: Settings | None = None) -> Celery:
    """Apply broker/backend and task limits from Settings (safe to call more than once)."""
    s = settings if settings is not None else get_settings()
    celery_app.conf.update(
        broker_url=s.celery_broker_url,
        result_backend=s.celery_result_backend,
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        result_expires=604_800,
        task_soft_time_limit=s.celery_soft_time_limit_seconds,
        task_time_limit=s.celery_time_limit_seconds,
        task_acks_late=True,
        task_reject_on_worker_lost=True,
    )
    return celery_app


configure_celery()


@celery_app.task(
    name="analyzer.run_async_scan",
    bind=True,
    autoretry_for=_RETRYABLE,
    retry_backoff=True,
    retry_kwargs={"max_retries": _MAX_RETRIES},
)
def run_async_scan(
    self,  # noqa: ANN001
    source_code: str | None = None,
    file_path: str = "untitled.js",
    scan_id: str = "",
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run async scan. Prefer loading source from Redis when source_code is omitted."""
    from uuid import UUID

    import redis as redis_lib

    from analyzer.api.dependencies import get_cwe_db, get_orchestrator
    from analyzer.api.schemas import AnalyzeRequest, AnalyzeResponse, ScanConfig
    from analyzer.config import get_settings as _get_settings
    from analyzer.core.orchestrator import Orchestrator
    from analyzer.models.base import get_session_factory
    from analyzer.services.scan_repository import (
        mark_failed,
        mark_running,
        save_analyze_response,
        touch_scan,
    )
    from analyzer.services.scan_source_store import delete_scan_source, load_scan_source

    worker_settings = _get_settings()
    factory = get_session_factory()
    max_retries = int(getattr(self, "max_retries", None) or _MAX_RETRIES)

    def _is_final_attempt() -> bool:
        return int(getattr(self.request, "retries", 0) or 0) >= max_retries

    def _db_mark_failed(msg: str, code: str) -> None:
        session = factory()
        try:
            mark_failed(session, scan_id, error_message=msg, error_code=code)
        except Exception:  # noqa: BLE001
            _logger.exception("failed to mark scan %s failed", scan_id)
        finally:
            session.close()

    def _mark_failed_if_final(msg: str, code: str) -> None:
        if _is_final_attempt():
            _db_mark_failed(msg, code)
        else:
            _logger.warning(
                "scan %s attempt %s failed (%s); leaving status for retry",
                scan_id,
                self.request.retries,
                code,
            )

    def _heartbeat() -> None:
        session = factory()
        try:
            touch_scan(session, scan_id)
        except Exception:  # noqa: BLE001
            _logger.debug("heartbeat failed for scan %s", scan_id, exc_info=True)
        finally:
            session.close()

    session = factory()
    try:
        if not mark_running(session, scan_id):
            _logger.info("scan %s not runnable (missing or terminal); skipping", scan_id)
            return {"status": "skipped", "scan_id": scan_id}
    except Exception:  # noqa: BLE001
        _logger.exception("failed to mark scan running")
    finally:
        session.close()

    try:
        # Prefer Redis blob (smaller broker payload); fall back to task arg for old APIs.
        code = None
        redis_client = redis_lib.Redis.from_url(worker_settings.redis_url, decode_responses=True)
        try:
            code = load_scan_source(redis_client, scan_id)
        except Exception:  # noqa: BLE001
            _logger.warning("redis source load failed for %s; trying task arg", scan_id)
        if code is None:
            code = source_code
        if code is None:
            msg = "source not found"
            _db_mark_failed(msg, "source_missing")
            raise ValueError(msg)

        scan_config = ScanConfig(**(config or {}))
        request = AnalyzeRequest(
            source_code=code,
            file_path=file_path,
            config=scan_config,
            scan_id=UUID(scan_id),
        )

        if (
            worker_settings.analysis_budget_ms is None
            and worker_settings.async_analysis_budget_ms > 0
        ):
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

        _heartbeat()
        result: AnalyzeResponse = orchestrator.analyze_sync(request)
        _heartbeat()

        # Persist with local retries; leave status running on failure so Celery can retry.
        last_err: Exception | None = None
        for attempt in range(_PERSIST_ATTEMPTS):
            session = factory()
            try:
                save_analyze_response(session, result)
                last_err = None
                break
            except SQLAlchemyError as e:
                last_err = e
                _logger.warning(
                    "persist attempt %s/%s failed for scan %s: %s",
                    attempt + 1,
                    _PERSIST_ATTEMPTS,
                    scan_id,
                    e,
                )
                session.rollback()
            finally:
                session.close()
            if attempt + 1 < _PERSIST_ATTEMPTS:
                time.sleep(0.5 * (2**attempt))
        if last_err is not None:
            _mark_failed_if_final(str(last_err), "database_error")
            raise last_err

        try:
            redis_client = redis_lib.Redis.from_url(
                worker_settings.redis_url, decode_responses=True
            )
            delete_scan_source(redis_client, scan_id)
        except Exception:  # noqa: BLE001
            _logger.warning("failed to delete source blob for %s", scan_id)

        return result.model_dump(mode="json")
    except _RETRYABLE as e:
        code = "database_error" if isinstance(e, SQLAlchemyError) else "task_failed"
        _mark_failed_if_final(str(e), code)
        raise
    except Exception as e:
        # Non-retryable: terminal failure.
        _db_mark_failed(str(e), "task_failed")
        raise
