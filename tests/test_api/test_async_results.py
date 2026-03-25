from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from analyzer.api.dependencies import get_redis_client
from analyzer.main import create_app


@pytest.fixture
async def client_with_redis(mock_redis: MagicMock):
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
    async def test_unknown_scan_returns_404(
        self, client_with_redis: AsyncClient, mock_redis: MagicMock
    ):
        mock_redis.get.return_value = None
        sid = str(uuid4())
        resp = await client_with_redis.get(f"/api/v1/results/{sid}")
        assert resp.status_code == 404

    async def test_invalid_uuid_returns_404(self, client_with_redis: AsyncClient):
        resp = await client_with_redis.get("/api/v1/results/not-a-uuid")
        assert resp.status_code == 404

    async def test_pending_state(self, client_with_redis: AsyncClient, mock_redis: MagicMock):
        sid = str(uuid4())
        mock_redis.get.return_value = "celery-task-id"

        mock_ar = MagicMock()
        mock_ar.state = "PENDING"

        with patch("analyzer.api.router.AsyncResult", return_value=mock_ar):
            resp = await client_with_redis.get(f"/api/v1/results/{sid}")
        assert resp.status_code == 200
        assert resp.json() == {"status": "pending", "scan_id": sid}

    async def test_success_merges_completed(
        self, client_with_redis: AsyncClient, mock_redis: MagicMock
    ):
        sid = str(uuid4())
        mock_redis.get.return_value = "celery-task-id"

        mock_ar = MagicMock()
        mock_ar.state = "SUCCESS"
        mock_ar.result = {"findings": [], "language": "javascript"}

        with patch("analyzer.api.router.AsyncResult", return_value=mock_ar):
            resp = await client_with_redis.get(f"/api/v1/results/{sid}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "completed"
        assert body["findings"] == []

    async def test_failure_returns_error(
        self, client_with_redis: AsyncClient, mock_redis: MagicMock
    ):
        sid = str(uuid4())
        mock_redis.get.return_value = "celery-task-id"

        mock_ar = MagicMock()
        mock_ar.state = "FAILURE"
        mock_ar.info = Exception("worker blew up")

        with patch("analyzer.api.router.AsyncResult", return_value=mock_ar):
            resp = await client_with_redis.get(f"/api/v1/results/{sid}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "failed"
        assert "error" in body
