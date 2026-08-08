from datetime import UTC, datetime
from uuid import UUID

import pytest

from analyzer.api.schemas import AnalyzeResponse, ScanStats
from analyzer.config import get_settings
from analyzer.models.base import Base, get_engine, get_session_factory, reset_engine
from analyzer.services.scan_repository import (
    create_scan,
    get_scan,
    mark_running,
    save_analyze_response,
)


@pytest.fixture
def sqlite_db(monkeypatch: pytest.MonkeyPatch, tmp_path):
    monkeypatch.setenv("ANALYZER_DATABASE_URL", f"sqlite:///{tmp_path / 'guard.db'}")
    get_settings.cache_clear()
    reset_engine()
    engine = get_engine()
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)
    reset_engine()
    get_settings.cache_clear()


def test_mark_running_does_not_resurrect_completed(sqlite_db) -> None:
    sid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    session = get_session_factory()()
    try:
        create_scan(session, scan_id=sid, status="pending")
        save_analyze_response(
            session,
            AnalyzeResponse(
                scan_id=UUID(sid),
                status="completed",
                language="javascript",
                stats=ScanStats(),
                findings=[],
                created_at=datetime.now(UTC),
            ),
        )
        assert mark_running(session, sid) is False
        scan = get_scan(session, sid)
        assert scan is not None
        assert scan.status == "completed"
    finally:
        session.close()
