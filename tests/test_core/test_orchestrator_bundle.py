"""Multi-file bundle analysis with per-file + import fn_index for taint."""

from analyzer.api.schemas import AnalyzeBundleRequest, ScanConfig
from analyzer.config import Settings
from analyzer.core.orchestrator import Orchestrator


def test_bundle_import_fn_index_cross_file_taint() -> None:
    """Helpers exported from lib; app requires them (no global name merge)."""
    lib = """
function runQuery(dbConn, sqlText) {
  dbConn.query(sqlText);
}
function buildSql(userId) {
  return `DELETE FROM sessions WHERE uid = '${userId}'`;
}
module.exports = { runQuery, buildSql };
"""
    app = """
const { runQuery, buildSql } = require('../lib/helpers');
const db = {};
app.get('/x', (req, res) => {
  const uid = req.params.id;
  const sql = buildSql(uid);
  runQuery(db, sql);
});
"""
    orch = Orchestrator(settings=Settings(), cwe_db=None)
    req = AnalyzeBundleRequest(
        files={"app/routes.js": app, "lib/helpers.js": lib},
        config=ScanConfig(enable_taint=True),
    )
    resp = orch.analyze_bundle_sync(req)
    sql_findings = [f for f in resp.findings if f.rule_id == "JS-SQL-001"]
    assert sql_findings, "expected SQL taint via import-resolved fn_index + return taint"
    paths = {f.file_path for f in sql_findings}
    assert "app/routes.js" in paths


def test_bundle_same_name_functions_do_not_collide() -> None:
    """Unrelated files both define queryUser; only the imported one runs."""
    evil = """
function queryUser(sql) {
  db.query(sql);
}
module.exports = { queryUser };
"""
    safe = """
function queryUser(id) {
  return id;
}
module.exports = { queryUser };
"""
    app = """
const { queryUser } = require('./safe');
app.get('/x', (req, res) => {
  const x = queryUser(req.body.q);
  res.send(x);
});
"""
    orch = Orchestrator(settings=Settings(), cwe_db=None)
    resp = orch.analyze_bundle_sync(
        AnalyzeBundleRequest(
            files={"evil.js": evil, "safe.js": safe, "app.js": app},
            config=ScanConfig(enable_taint=True),
        )
    )
    high_sql = [
        f for f in resp.findings if f.rule_id == "JS-SQL-001" and f.confidence.value == "high"
    ]
    assert not high_sql, "must not execute evil.js queryUser via name collision"


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
