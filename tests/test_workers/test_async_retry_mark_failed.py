"""Worker only marks failed on final Celery retry attempt."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch
from uuid import UUID

import pytest
from celery.exceptions import Retry
from sqlalchemy.exc import OperationalError

from analyzer.api.schemas import AnalyzeResponse, ScanStats
from analyzer.config import get_settings
from analyzer.models.base import Base, get_engine, get_session_factory, reset_engine
from analyzer.services.scan_repository import create_scan, get_scan
from analyzer.workers.tasks import celery_app, run_async_scan


@pytest.fixture
def sqlite_db(monkeypatch: pytest.MonkeyPatch, tmp_path):
    monkeypatch.setenv("ANALYZER_DATABASE_URL", f"sqlite:///{tmp_path / 'worker.db'}")
    get_settings.cache_clear()
    reset_engine()
    engine = get_engine()
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)
    reset_engine()
    get_settings.cache_clear()


def test_persist_failure_does_not_mark_failed_before_final_retry(
    sqlite_db, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_id = "11111111-2222-3333-4444-555555555555"
    session = get_session_factory()()
    try:
        create_scan(session, scan_id=scan_id, status="pending")
    finally:
        session.close()

    fake_redis = MagicMock()
    fake_redis.get.return_value = "const x = 1;"
    monkeypatch.setattr("redis.Redis.from_url", lambda *_a, **_k: fake_redis)

    celery_app.conf.task_always_eager = True
    celery_app.conf.task_eager_propagates = True
    try:
        with (
            patch("analyzer.workers.tasks._PERSIST_ATTEMPTS", 1),
            patch(
                "analyzer.services.scan_repository.save_analyze_response",
                side_effect=OperationalError("stmt", {}, Exception("boom")),
            ),
            patch("analyzer.api.dependencies.get_orchestrator") as mock_orch,
            patch.object(run_async_scan, "max_retries", 3),
        ):
            mock_orch.return_value.analyze_sync.return_value = AnalyzeResponse(
                scan_id=UUID(scan_id),
                status="completed",
                language="javascript",
                stats=ScanStats(),
                findings=[],
                created_at=datetime.now(UTC),
            )
            # retries=0 → Celery schedules Retry (not final); must not mark failed.
            with pytest.raises((OperationalError, Retry)):
                run_async_scan.apply(
                    kwargs={
                        "source_code": None,
                        "file_path": "app.js",
                        "scan_id": scan_id,
                        "config": {},
                    }
                ).get()
    finally:
        celery_app.conf.task_always_eager = False

    session = get_session_factory()()
    try:
        scan = get_scan(session, scan_id)
        assert scan is not None
        assert scan.status != "failed"
    finally:
        session.close()
