"""config.rule_ids must filter taint findings the same as AST findings."""

from fastapi.testclient import TestClient

from analyzer.main import create_app


def _client() -> TestClient:
    return TestClient(create_app())


def test_sync_rule_ids_filter_applies_to_taint_findings() -> None:
    client = _client()
    resp = client.post(
        "/api/v1/analyze/sync",
        json={
            "source_code": "app.get('/x', (req, res) => { eval(req.query.x); });",
            "file_path": "app.js",
            "config": {"rule_ids": ["JS-NOPE-999"]},
        },
    )
    assert resp.status_code == 200
    findings = resp.json()["findings"]
    assert findings == []
    assert all(f["rule_id"] == "JS-NOPE-999" for f in findings)


def test_sync_rule_ids_filter_keeps_requested_taint_rule() -> None:
    client = _client()
    resp = client.post(
        "/api/v1/analyze/sync",
        json={
            "source_code": "app.get('/x', (req, res) => { eval(req.query.x); });",
            "file_path": "app.js",
            "config": {"rule_ids": ["JS-CMD-001"]},
        },
    )
    assert resp.status_code == 200
    findings = resp.json()["findings"]
    assert findings
    assert {f["rule_id"] for f in findings} == {"JS-CMD-001"}


def test_bundle_rule_ids_filter_applies_to_taint_findings() -> None:
    client = _client()
    resp = client.post(
        "/api/v1/analyze/bundle/sync",
        json={
            "files": {"app.js": "app.get('/x', (req, res) => { eval(req.query.x); });"},
            "config": {"rule_ids": ["JS-NOPE-999"]},
        },
    )
    assert resp.status_code == 200
    assert resp.json()["findings"] == []
