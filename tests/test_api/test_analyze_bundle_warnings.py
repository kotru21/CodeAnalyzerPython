"""Bundle endpoint surfaces skipped (unsupported) files via warnings."""

from fastapi.testclient import TestClient

from analyzer.main import create_app


def test_bundle_with_unsupported_file_returns_200_with_warnings() -> None:
    client = TestClient(create_app())
    resp = client.post(
        "/api/v1/analyze/bundle/sync",
        json={
            "files": {
                "app.js": "app.get('/x', (req, res) => { eval(req.query.x); });",
                "cfg.json": '{"key": "value"}',
            },
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    assert any(f["rule_id"] == "JS-CMD-001" for f in data["findings"])
    assert data["stats"]["files_scanned"] == 1
    assert any("cfg.json" in w for w in data["warnings"])


def test_bundle_all_supported_has_empty_warnings() -> None:
    client = TestClient(create_app())
    resp = client.post(
        "/api/v1/analyze/bundle/sync",
        json={"files": {"app.js": "const x = 1;"}},
    )
    assert resp.status_code == 200
    assert resp.json()["warnings"] == []


def test_bundle_with_no_supported_files_returns_400() -> None:
    client = TestClient(create_app())
    resp = client.post(
        "/api/v1/analyze/bundle/sync",
        json={"files": {"helper.py": "print(1)", "cfg.json": "{}"}},
    )

    assert resp.status_code == 400
    assert "no analyzable files" in resp.json()["detail"]
