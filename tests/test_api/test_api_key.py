import pytest
from httpx import ASGITransport, AsyncClient

from analyzer.api.dependencies import get_settings
from analyzer.config import Settings
from analyzer.main import create_app


@pytest.fixture
async def client_with_api_key():
    get_settings.cache_clear()
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: Settings(api_key="secret-key")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()
    get_settings.cache_clear()


class TestApiKeyAuth:
    async def test_health_public_without_key(self, client_with_api_key: AsyncClient):
        resp = await client_with_api_key.get("/api/v1/health")
        assert resp.status_code == 200

    async def test_rules_requires_key(self, client_with_api_key: AsyncClient):
        resp = await client_with_api_key.get("/api/v1/rules")
        assert resp.status_code == 401

    async def test_analyze_with_valid_key(self, client_with_api_key: AsyncClient):
        resp = await client_with_api_key.post(
            "/api/v1/analyze/sync",
            headers={"X-API-Key": "secret-key"},
            json={"source_code": "const x = 1;\n", "file_path": "a.js"},
        )
        assert resp.status_code == 200

    async def test_analyze_rejects_bad_key(self, client_with_api_key: AsyncClient):
        resp = await client_with_api_key.post(
            "/api/v1/analyze/sync",
            headers={"X-API-Key": "wrong"},
            json={"source_code": "const x = 1;\n", "file_path": "a.js"},
        )
        assert resp.status_code == 401
