from datetime import UTC, datetime, timedelta

import pytest

from analyzer.config import get_settings
from analyzer.models.base import Base, get_engine, get_session_factory, reset_engine
from analyzer.services.scan_repository import create_scan, fail_stale_scans, get_scan


@pytest.fixture
def sqlite_db(monkeypatch: pytest.MonkeyPatch, tmp_path):
    monkeypatch.setenv("ANALYZER_DATABASE_URL", f"sqlite:///{tmp_path / 'stale.db'}")
    get_settings.cache_clear()
    reset_engine()
    engine = get_engine()
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)
    reset_engine()
    get_settings.cache_clear()


def test_fail_stale_scans_marks_old_running(sqlite_db) -> None:
    session = get_session_factory()()
    try:
        create_scan(session, scan_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", status="running")
        scan = get_scan(session, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        assert scan is not None
        scan.updated_at = datetime.now(UTC) - timedelta(seconds=3600)
        session.commit()
        n = fail_stale_scans(session, older_than_seconds=300)
        assert n == 1
        scan = get_scan(session, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        assert scan is not None
        assert scan.status == "failed"
        assert scan.error_code == "scan_stale"
    finally:
        session.close()
