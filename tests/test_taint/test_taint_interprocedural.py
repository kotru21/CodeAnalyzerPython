"""Limited same-file inter-procedural taint (plan Task 3–4)."""

from analyzer.taint.tracker import TaintTracker
from tests.conftest import make_js_context
from tests.test_taint.taint_assertions import assert_any_flow


class TestTaintInterprocedural:
    def test_hoisted_function__positive__param_to_query(self) -> None:
        code = """
function run(q) {
  db.query(q);
}
app.get('/', (req, res) => {
  run(req.body);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="query", source_substr="req.body")

    def test_const_arrow__positive__param_to_query(self) -> None:
        code = """
const run = (q) => {
  db.query(q);
};
app.get('/', (req, res) => {
  run(req.body);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="query", source_substr="req.body")

    def test_two_params__positive__second_tainted(self) -> None:
        code = """
function run(a, b) {
  db.query(b);
}
app.get('/', (req, res) => {
  run(1, req.body.x);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="query", source_substr="req.body")

    def test_param_only_callee__positive__minimal_caller(self) -> None:
        code = """
function sinkQuery(sql) {
  db.query(sql);
}
app.post('/', (req, res) => {
  sinkQuery(req.body.q);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="query", source_substr="req.body")

    def test_static_arg__negative__no_flow(self) -> None:
        code = """
function run(q) {
  db.query(q);
}
run('static');
app.get('/', (req, res) => { res.end('ok'); });
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert not any(f.sink_method == "query" for f in flows)

    def test_method_call__positive__member_callee_resolves_top_level_fn(self) -> None:
        code = """
function run(q) {
  db.query(q);
}
const o = {};
app.get('/', (req, res) => {
  o.run(req.body);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="query", source_substr="req.body")

    def test_object_literal_method__negative__not_in_fn_index(self) -> None:
        """Method shorthand on object literals is not indexed; only declaration/const fn."""
        code = """
const o = {
  run(x) { db.query(x); },
};
app.get('/', (req, res) => {
  o.run(req.body);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert not any(f.sink_method == "query" for f in flows)

    def test_recursive__positive__bounded_depth(self) -> None:
        code = """
function f(n, x) {
  if (n > 0) return f(n - 1, x);
  db.query(x);
}
app.get('/', (req, res) => {
  f(2, req.body.a);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="query", source_substr="req.body")

    def test_sanitized_arg__negative__parse_int_wrap(self) -> None:
        code = """
function run(q) {
  db.query(q);
}
app.get('/', (req, res) => {
  run(parseInt(req.query.x));
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert not any(f.sink_method == "query" for f in flows)

    def test_regression__intra_propagation_still_works(self) -> None:
        code = """
app.get('/users', (req, res) => {
    const id = req.params.id;
    db.query(`SELECT * FROM users WHERE id = ${id}`);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="query")

    def test_function_expression_var__positive(self) -> None:
        code = """
const run = function(q) {
  db.query(q);
};
app.get('/', (req, res) => {
  run(req.query.q);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="query", source_substr="req.query")

    def test_optional_chaining__positive__req_body_to_query(self) -> None:
        code = """
app.get('/', (req, res) => {
  db.query(req?.body?.x);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="query", source_substr="req.body")

    def test_optional_chaining_sink__positive__db_optional_query(self) -> None:
        code = """
app.get('/', (req, res) => {
  db?.query(req.body);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="query", source_substr="req.body")

    def test_intermediate_var_template__positive__sql_med_shape(self) -> None:
        code = """
app.get('/u', (req, res) => {
  const sort = req.body.order;
  const q = `SELECT * FROM t ORDER BY ${sort}`;
  db.query(q);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="query", source_substr="req.body")
