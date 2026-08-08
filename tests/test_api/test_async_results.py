from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from analyzer.api.dependencies import get_redis_client
from analyzer.api.schemas import AnalyzeResponse, ScanStats
from analyzer.config import Settings, get_settings
from analyzer.main import create_app
from analyzer.models.base import Base, get_engine, get_session_factory, reset_engine
from analyzer.services.scan_repository import create_scan, mark_failed, save_analyze_response


@pytest.fixture
def sqlite_db(monkeypatch: pytest.MonkeyPatch, tmp_path):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("ANALYZER_DATABASE_URL", f"sqlite:///{db_path}")
    get_settings.cache_clear()
    reset_engine()
    engine = get_engine()
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)
    reset_engine()
    get_settings.cache_clear()


@pytest.fixture
async def client_with_redis(mock_redis: MagicMock, sqlite_db):
    app = create_app()
    app.dependency_overrides[get_redis_client] = lambda: mock_redis
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.fixture
def mock_redis() -> MagicMock:
    return MagicMock()


class TestGetResults:
    async def test_unknown_scan_returns_404(self, client_with_redis: AsyncClient):
        sid = str(uuid4())
        resp = await client_with_redis.get(f"/api/v1/results/{sid}")
        assert resp.status_code == 404

    async def test_invalid_uuid_returns_404(self, client_with_redis: AsyncClient):
        resp = await client_with_redis.get("/api/v1/results/not-a-uuid")
        assert resp.status_code == 404

    async def test_pending_state(self, client_with_redis: AsyncClient):
        sid = str(uuid4())
        session = get_session_factory()()
        try:
            create_scan(session, scan_id=sid, status="pending")
        finally:
            session.close()

        resp = await client_with_redis.get(f"/api/v1/results/{sid}")
        assert resp.status_code == 200
        assert resp.json() == {"status": "pending", "scan_id": sid}

    async def test_success_from_db(self, client_with_redis: AsyncClient):
        sid = uuid4()
        session = get_session_factory()()
        try:
            create_scan(session, scan_id=str(sid), status="pending")
            save_analyze_response(
                session,
                AnalyzeResponse(
                    scan_id=sid,
                    status="completed",
                    language="javascript",
                    stats=ScanStats(total_findings=0),
                    findings=[],
                    created_at=datetime.now(UTC),
                ),
            )
        finally:
            session.close()

        resp = await client_with_redis.get(f"/api/v1/results/{sid}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "completed"
        assert body["findings"] == []

    async def test_failure_returns_error(self, client_with_redis: AsyncClient):
        sid = str(uuid4())
        session = get_session_factory()()
        try:
            create_scan(session, scan_id=sid, status="pending")
            mark_failed(session, sid, error_message="worker blew up", error_code="task_failed")
        finally:
            session.close()

        resp = await client_with_redis.get(f"/api/v1/results/{sid}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "failed"
        assert body["error"] == "worker blew up"
        assert body["error_code"] == "task_failed"


class TestAsyncEnqueueLimits:
    async def test_async_rejects_oversized_source(
        self, client_with_redis: AsyncClient, mock_redis: MagicMock
    ):
        get_settings.cache_clear()
        app = client_with_redis._transport.app  # type: ignore[attr-defined]
        small = Settings(max_source_bytes=100, debug=True, rate_limit_per_minute=0)
        app.dependency_overrides[get_settings] = lambda: small
        try:
            resp = await client_with_redis.post(
                "/api/v1/analyze/async",
                json={
                    "source_code": "x" * 200,
                    "file_path": "big.js",
                },
            )
            assert resp.status_code == 413
        finally:
            app.dependency_overrides.pop(get_settings, None)
            get_settings.cache_clear()
