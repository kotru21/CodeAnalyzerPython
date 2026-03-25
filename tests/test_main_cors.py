import pytest
from fastapi.testclient import TestClient

from analyzer.config import get_settings
from analyzer.main import create_app


@pytest.fixture
def clear_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_cors_header_when_origins_configured(
    monkeypatch: pytest.MonkeyPatch, clear_settings_cache: None
) -> None:
    monkeypatch.setenv("ANALYZER_CORS_ORIGINS", '["http://localhost:5173"]')
    app = create_app()
    client = TestClient(app)
    r = client.get("/api/v1/health", headers={"Origin": "http://localhost:5173"})
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_no_cors_when_origins_empty(
    monkeypatch: pytest.MonkeyPatch, clear_settings_cache: None
) -> None:
    monkeypatch.delenv("ANALYZER_CORS_ORIGINS", raising=False)
    app = create_app()
    client = TestClient(app)
    r = client.get("/api/v1/health", headers={"Origin": "http://localhost:5173"})
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") is None
