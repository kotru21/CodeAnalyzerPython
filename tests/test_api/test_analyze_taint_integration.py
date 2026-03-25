import pytest
from httpx import ASGITransport, AsyncClient

from analyzer.main import app


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestAnalyzeTaintIntegration:
    async def test_interprocedural_taint_surfaces_sql_rule(self, client: AsyncClient) -> None:
        source = """
function run(q) {
  db.query(q);
}
app.get('/', (req, res) => {
  run(req.body);
});
"""
        resp = await client.post(
            "/api/v1/analyze/sync",
            json={
                "source_code": source,
                "file_path": "routes.js",
                "config": {"enable_taint": True},
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["stats"]["total_findings"] >= 1
        assert any(f["rule_id"] == "JS-SQL-001" for f in data["findings"])
