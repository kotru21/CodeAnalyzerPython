"""Legacy smoke tests; see also test_taint_sources_sinks_matrix and test_taint_interprocedural."""

from analyzer.api.schemas import AnalyzeRequest, ScanConfig
from analyzer.config import Settings
from analyzer.core.orchestrator import Orchestrator
from analyzer.taint.tracker import TaintTracker
from tests.conftest import make_js_context


class TestTaintTracker:
    def test_direct_source_to_sink(self):
        code = """
app.get('/users', (req, res) => {
    db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
});
"""
        ctx = make_js_context(code)
        tracker = TaintTracker()
        flows = tracker.analyze(ctx)
        assert len(flows) > 0
        assert any(f.sink_method == "query" for f in flows)

    def test_propagation_through_variable(self):
        code = """
app.get('/users', (req, res) => {
    const id = req.params.id;
    db.query(`SELECT * FROM users WHERE id = ${id}`);
});
"""
        ctx = make_js_context(code)
        tracker = TaintTracker()
        flows = tracker.analyze(ctx)
        assert len(flows) > 0

    def test_sanitized_no_finding(self):
        code = """
app.get('/users', (req, res) => {
    const id = parseInt(req.params.id);
    db.query(`SELECT * FROM users WHERE id = ${id}`);
});
"""
        ctx = make_js_context(code)
        tracker = TaintTracker()
        flows = tracker.analyze(ctx)
        assert len(flows) == 0

    def test_multi_step_propagation(self):
        code = """
app.post('/search', (req, res) => {
    const input = req.body.search;
    const query = 'SELECT * FROM items WHERE name = \\'' + input + '\\'';
    db.query(query);
});
"""
        ctx = make_js_context(code)
        tracker = TaintTracker()
        flows = tracker.analyze(ctx)
        assert len(flows) > 0

    def test_reassignment_clears_taint(self) -> None:
        code = """
app.get('/x', (req, res) => {
  let q = req.body.q;
  q = 'SELECT 1';
  db.query(q);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert not any(f.sink_method == "query" for f in flows)

    def test_knex_raw_taint_maps_to_sql_rule(self) -> None:
        code = """
app.get('/x', (req, res) => {
  knex.raw(req.query.q);
});
"""
        orch = Orchestrator(Settings())
        resp = orch.analyze_sync(
            AnalyzeRequest(
                source_code=code,
                file_path="app.js",
                config=ScanConfig(enable_taint=True),
            )
        )
        assert any(
            f.rule_id == "JS-SQL-001" and f.confidence.value == "high"
            for f in resp.findings
        )

    def test_res_send_taint_maps_to_xss_003(self) -> None:
        code = """
app.get('/x', (req, res) => {
  res.send(req.query.msg);
});
"""
        orch = Orchestrator(Settings())
        resp = orch.analyze_sync(
            AnalyzeRequest(
                source_code=code,
                file_path="app.js",
                config=ScanConfig(enable_taint=True),
            )
        )
        assert any(
            f.rule_id == "JS-XSS-003" and f.confidence.value == "high"
            for f in resp.findings
        )
