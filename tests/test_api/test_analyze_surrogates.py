"""Lone-surrogate payloads must not 500: sanitize and keep scanning."""

import pytest
from fastapi.testclient import TestClient

from analyzer.api.schemas import AnalyzeBundleRequest, AnalyzeRequest
from analyzer.main import create_app


class TestModelSanitizesSurrogates:
    def test_analyze_request_python_mode(self) -> None:
        req = AnalyzeRequest.model_validate(
            {"source_code": "const s = '\ud800';", "file_path": "s.js"}
        )
        assert req.source_code == "const s = '\ufffd';"

    def test_bundle_request_python_mode(self) -> None:
        req = AnalyzeBundleRequest.model_validate({"files": {"a.js": "x = '\ud800';"}})
        assert req.files == {"a.js": "x = '\ufffd';"}

    def test_empty_bundle_still_rejected(self) -> None:
        with pytest.raises(ValueError, match="at least one entry"):
            AnalyzeBundleRequest.model_validate({"files": {}})

    def test_bundle_rejects_paths_that_collide_after_sanitization(self) -> None:
        surrogate_path = "a" + chr(0xD800) + ".js"
        replacement_path = "a" + chr(0xFFFD) + ".js"
        with pytest.raises(ValueError, match="collide after sanitization"):
            AnalyzeBundleRequest.model_validate(
                {
                    "files": {
                        surrogate_path: "const x = 1;",
                        replacement_path: "eval(req.query.x);",
                    }
                }
            )


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def _post_raw(client: TestClient, url: str, body: bytes):
    return client.post(url, content=body, headers={"content-type": "application/json"})


def test_sync_analyze_lone_surrogate_returns_200(client: TestClient) -> None:
    body = b'{"source_code": "const s = \'\\ud800\';", "file_path": "s.js"}'
    resp = _post_raw(client, "/api/v1/analyze/sync", body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    assert data["language"] == "javascript"
    assert isinstance(data["findings"], list)
    assert data["stats"]["files_scanned"] == 1


def test_sync_analyze_lone_surrogate_still_detects(client: TestClient) -> None:
    body = (
        b'{"source_code": "const s = \'\\ud800\'; eval(req.query.x);", '
        b'"file_path": "s.js", "config": {"enable_taint": false}}'
    )
    resp = _post_raw(client, "/api/v1/analyze/sync", body)
    assert resp.status_code == 200
    rule_ids = {f["rule_id"] for f in resp.json()["findings"]}
    assert "JS-CMD-001" in rule_ids


def test_bundle_analyze_lone_surrogate_returns_200(client: TestClient) -> None:
    body = (
        b'{"files": {"app.js": "const s = \'\\ud800\';", "util.js": "eval(location.hash);"}, '
        b'"config": {"enable_taint": false}}'
    )
    resp = _post_raw(client, "/api/v1/analyze/bundle/sync", body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["stats"]["files_scanned"] == 2
    assert any(f["rule_id"] == "JS-CMD-001" for f in data["findings"])
