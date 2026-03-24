import pytest
from httpx import ASGITransport, AsyncClient

from analyzer.main import app


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestHealthEndpoint:
    async def test_health_returns_ok(self, client: AsyncClient):
        resp = await client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["rules_loaded"] > 0


class TestRulesEndpoint:
    async def test_list_all_rules(self, client: AsyncClient):
        resp = await client.get("/api/v1/rules")
        assert resp.status_code == 200
        rules = resp.json()
        assert len(rules) >= 12

    async def test_filter_by_language(self, client: AsyncClient):
        resp = await client.get("/api/v1/rules?language=javascript")
        assert resp.status_code == 200
        rules = resp.json()
        assert all(r["rule_id"].startswith("JS-") for r in rules)


class TestAnalyzeSyncEndpoint:
    async def test_analyze_vulnerable_code(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/analyze/sync",
            json={
                "source_code": """
const { exec } = require('child_process');
app.get('/run', (req, res) => {
    exec(`ls ${req.query.dir}`);
});
""",
                "file_path": "app.js",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["language"] == "javascript"
        assert data["stats"]["total_findings"] > 0
        assert any(f["rule_id"] == "JS-CMD-001" for f in data["findings"])

    async def test_analyze_safe_code(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/analyze/sync",
            json={
                "source_code": "const x = 1 + 2;\nconsole.log(x);\n",
                "file_path": "safe.js",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["stats"]["total_findings"] == 0

    async def test_analyze_empty_code_rejected(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/analyze/sync",
            json={"source_code": "", "file_path": "empty.js"},
        )
        assert resp.status_code == 422

    async def test_response_contains_cwe_info(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/analyze/sync",
            json={
                "source_code": "const password = 'SuperSecret123!';",
                "file_path": "config.js",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        if data["stats"]["total_findings"] > 0:
            finding = data["findings"][0]
            assert "CWE-" in finding["cwe_id"]
            assert finding["owasp_category"] != ""
