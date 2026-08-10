"""Explicit unknown language values are rejected instead of silently scanned as JS."""

from fastapi.testclient import TestClient

from analyzer.main import create_app


def _client() -> TestClient:
    return TestClient(create_app())


def test_sync_unknown_language_rejected() -> None:
    client = _client()
    resp = client.post(
        "/api/v1/analyze/sync",
        json={"source_code": "eval(x);", "file_path": "app.js", "language": "python"},
    )
    assert resp.status_code == 422
    assert "python" in resp.text


def test_sync_unknown_language_cobol_rejected() -> None:
    client = _client()
    resp = client.post(
        "/api/v1/analyze/sync",
        json={"source_code": "eval(x);", "file_path": "app.js", "language": "cobol"},
    )
    assert resp.status_code == 422


def test_bundle_unknown_language_rejected() -> None:
    client = _client()
    resp = client.post(
        "/api/v1/analyze/bundle/sync",
        json={"files": {"app.js": "eval(x);"}, "language": "python"},
    )
    assert resp.status_code == 422


def test_supported_languages_accepted() -> None:
    client = _client()
    for lang in ("javascript", "typescript", "jsx", "tsx"):
        resp = client.post(
            "/api/v1/analyze/sync",
            json={"source_code": "const x = 1;", "file_path": "app.js", "language": lang},
        )
        assert resp.status_code == 200, lang


def test_omitted_language_still_autodetects() -> None:
    client = _client()
    resp = client.post(
        "/api/v1/analyze/sync",
        json={"source_code": "const x = 1;", "file_path": "app.ts"},
    )
    assert resp.status_code == 200
    assert resp.json()["language"] == "typescript"
