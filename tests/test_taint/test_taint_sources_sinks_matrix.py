"""Matrix tests for taint sources/sinks (plan Task 1–2)."""

import pytest

from analyzer.taint.tracker import TaintTracker
from tests.conftest import make_js_context
from tests.test_taint.taint_assertions import assert_any_flow, assert_no_flow_with_sink


class TestTaintSourcesSinksMatrix:
    def test_multer_files__positive__query_template(self) -> None:
        code = """
app.post('/up', (req, res) => {
    db.query(`INSERT INTO x VALUES ('${req.files[0].name}')`);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="query", source_substr="req.files")

    def test_multer_file__positive__readfile_path(self) -> None:
        code = """
app.post('/up', (req, res) => {
    fs.readFileSync('/data/' + req.file.path);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="readFileSync", source_substr="req.file")

    def test_prisma__positive__query_raw_template(self) -> None:
        code = """
app.get('/x', (req, res) => {
    prisma.$queryRaw`SELECT * FROM u WHERE id = ${req.body.id}`;
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="$queryRaw", source_substr="req.body")

    def test_prisma__positive__execute_raw_template(self) -> None:
        code = """
app.get('/x', (req, res) => {
    prisma.$executeRaw`DELETE FROM t WHERE x = ${req.query.x}`;
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="$executeRaw", source_substr="req.query")

    def test_prisma__negative__static_query_raw(self) -> None:
        code = """
app.get('/x', (req, res) => {
    prisma.$queryRaw`SELECT 1`;
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_no_flow_with_sink(flows, "$queryRaw")

    def test_express_cookies__positive__exec_template(self) -> None:
        code = """
const { exec } = require('child_process');
app.get('/x', (req, res) => {
    exec(`echo ${req.cookies.sess}`);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="exec", source_substr="req.cookies")

    def test_sanitizer__positive__encode_uri_does_not_sanitize_sql(self) -> None:
        code = """
app.get('/x', (req, res) => {
    const x = encodeURIComponent(req.body.name);
    db.query(`SELECT * FROM u WHERE n = '${x}'`);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="query", source_substr="req.body")

    def test_pg_placeholder__negative__taint_only_values_array(self) -> None:
        code = """
app.get('/u', (req, res) => {
  db.query('SELECT * FROM users WHERE id = $1', [req.query.id]);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_no_flow_with_sink(flows, "query")

    def test_concat_in_first_arg__positive__still_flows(self) -> None:
        code = """
app.get('/u', (req, res) => {
  db.query('SELECT * FROM u WHERE id = ' + req.query.id, []);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="query", source_substr="req.query")

    def test_qmark_placeholder__negative__taint_only_values(self) -> None:
        code = """
app.get('/u', (req, res) => {
  db.query('SELECT * FROM users WHERE id = ?', [req.body.x]);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_no_flow_with_sink(flows, "query")

    @pytest.mark.skip(reason="pool.execute sink optional in plan row 8")
    def test_mysql_pool_execute__optional__skipped(self) -> None:
        pass
