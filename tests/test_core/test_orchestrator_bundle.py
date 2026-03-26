"""Multi-file bundle analysis with merged function index for taint."""

from analyzer.api.schemas import AnalyzeBundleRequest, ScanConfig
from analyzer.config import Settings
from analyzer.core.orchestrator import Orchestrator


def test_bundle_merged_fn_index_cross_file_taint() -> None:
    """Helpers in lib.js; app.js uses o.runQuery + buildSql resolved via merged fn_index."""
    lib = """
function runQuery(dbConn, sqlText) {
  dbConn.query(sqlText);
}
function buildSql(userId) {
  return `DELETE FROM sessions WHERE uid = '${userId}'`;
}
"""
    app = """
const db = {};
const o = {};
app.get('/x', (req, res) => {
  const uid = req.params.id;
  const sql = buildSql(uid);
  o.runQuery(db, sql);
});
"""
    orch = Orchestrator(settings=Settings(), cwe_db=None)
    req = AnalyzeBundleRequest(
        files={"app/routes.js": app, "lib/helpers.js": lib},
        config=ScanConfig(enable_taint=True),
    )
    resp = orch.analyze_bundle_sync(req)
    sql_findings = [f for f in resp.findings if f.rule_id == "JS-SQL-001"]
    assert sql_findings, "expected SQL taint via cross-file merged fn_index + return taint"
    paths = {f.file_path for f in sql_findings}
    assert "app/routes.js" in paths


def test_bundle_finds_nosql_spread_case() -> None:
    code = """app.post('/s', (req, res) => {
  const q = { ...req.body, limit: 10 };
  users.find(q);
});
"""
    orch = Orchestrator(settings=Settings(), cwe_db=None)
    req = AnalyzeBundleRequest(
        files={"app.js": code},
        config=ScanConfig(enable_taint=False),
    )
    resp = orch.analyze_bundle_sync(req)
    assert any(f.rule_id == "JS-NOSQL-001" for f in resp.findings)
