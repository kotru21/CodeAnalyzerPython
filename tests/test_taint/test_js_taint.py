import pytest

from tests.conftest import make_js_context
from analyzer.taint.tracker import TaintTracker


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
