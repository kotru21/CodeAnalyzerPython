"""End-to-end-ish async path: enqueue → Redis source → eager worker → DB poll."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from analyzer.api.dependencies import get_redis_client
from analyzer.config import Settings, get_settings
from analyzer.main import create_app
from analyzer.models.base import Base, get_engine, get_session_factory, reset_engine
from analyzer.services.scan_repository import get_scan
from analyzer.workers.tasks import celery_app, configure_celery


@pytest.fixture
def sqlite_db(monkeypatch: pytest.MonkeyPatch, tmp_path):
    db_path = tmp_path / "async_int.db"
    monkeypatch.setenv("ANALYZER_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("ANALYZER_DEBUG", "true")
    monkeypatch.setenv("ANALYZER_RATE_LIMIT_PER_MINUTE", "0")
    get_settings.cache_clear()
    reset_engine()
    engine = get_engine()
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)
    reset_engine()
    get_settings.cache_clear()


@pytest.fixture
def fake_redis() -> MagicMock:
    store: dict[str, str] = {}

    r = MagicMock()

    def setex(key: str, _ttl: int, value: str) -> None:
        store[key] = value

    def get(key: str) -> str | None:
        return store.get(key)

    def delete(key: str) -> int:
        return 1 if store.pop(key, None) is not None else 0

    def incr(key: str) -> int:
        store[key] = str(int(store.get(key, "0")) + 1)
        return int(store[key])

    def expire(_key: str, _ttl: int) -> None:
        return None

    def eval(_script: str, _numkeys: int, key: str, _ttl: int) -> int:
        return incr(key)

    r.setex.side_effect = setex
    r.get.side_effect = get
    r.delete.side_effect = delete
    r.incr.side_effect = incr
    r.expire.side_effect = expire
    r.eval.side_effect = eval
    r._store = store  # type: ignore[attr-defined]
    return r


@pytest.fixture
async def client(sqlite_db, fake_redis: MagicMock, monkeypatch: pytest.MonkeyPatch):
    # Eager Celery so delay() runs in-process.
    celery_app.conf.task_always_eager = True
    celery_app.conf.task_eager_propagates = True
    configure_celery(Settings(debug=True, rate_limit_per_minute=0))

    # Worker loads Redis via from_url — patch to fake.
    monkeypatch.setattr(
        "redis.Redis.from_url",
        lambda *_a, **_k: fake_redis,
    )

    app = create_app()
    app.dependency_overrides[get_redis_client] = lambda: fake_redis
    app.dependency_overrides[get_settings] = lambda: Settings(
        debug=True,
        rate_limit_per_minute=0,
        rate_limit_sync_per_minute=0,
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()
    celery_app.conf.task_always_eager = False


@pytest.mark.asyncio
async def test_async_enqueue_worker_persist_poll(client: AsyncClient, fake_redis: MagicMock):
    resp = await client.post(
        "/api/v1/analyze/async",
        json={
            "source_code": "db.query(`SELECT ${req.query.id}`);",
            "file_path": "app.js",
            "config": {"enable_taint": True},
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "queued"
    scan_id = body["scan_id"]

    # Source was stored then deleted after successful worker persist.
    source_keys = [k for k in fake_redis._store if "scan:source:" in k]
    assert source_keys == [] or all(fake_redis._store.get(k) is None for k in source_keys)

    poll = await client.get(f"/api/v1/results/{scan_id}")
    assert poll.status_code == 200
    result = poll.json()
    assert result["status"] in ("completed", "partial")
    assert "findings" in result
    assert result["stats"]["files_scanned"] >= 1
    assert isinstance(result.get("failed_rules"), list)

    session = get_session_factory()()
    try:
        scan = get_scan(session, scan_id)
        assert scan is not None
        assert scan.status in ("completed", "partial")
    finally:
        session.close()


@pytest.mark.asyncio
async def test_rate_limit_429(sqlite_db, fake_redis: MagicMock, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("redis.Redis.from_url", lambda *_a, **_k: fake_redis)
    app = create_app()
    app.dependency_overrides[get_redis_client] = lambda: fake_redis
    app.dependency_overrides[get_settings] = lambda: Settings(
        debug=True,
        rate_limit_per_minute=1,
        rate_limit_sync_per_minute=1,
        api_key="k",
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        headers = {"X-API-Key": "k"}
        r1 = await ac.post(
            "/api/v1/analyze/sync",
            headers=headers,
            json={"source_code": "const x = 1;\n", "file_path": "a.js"},
        )
        r2 = await ac.post(
            "/api/v1/analyze/sync",
            headers=headers,
            json={"source_code": "const x = 2;\n", "file_path": "a.js"},
        )
    app.dependency_overrides.clear()
    assert r1.status_code == 200
    assert r2.status_code == 429
