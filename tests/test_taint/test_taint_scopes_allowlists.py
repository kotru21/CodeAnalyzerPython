"""Regression tests for function scopes and sink allowlists."""

from analyzer.taint.tracker import TaintTracker
from tests.conftest import make_js_context


def test_param_shadow_does_not_inherit_outer_taint() -> None:
    code = """
const q = req.params.id;
runQuery('SELECT 1');
function runQuery(q) {
  db.query(q);
}
"""
    flows = TaintTracker().analyze(make_js_context(code))
    assert not any(f.sink_method == "query" for f in flows)


def test_interproc_still_propagates_tainted_arg() -> None:
    code = """
function runQuery(q) {
  db.query(q);
}
const q = req.params.id;
runQuery(q);
"""
    flows = TaintTracker().analyze(make_js_context(code))
    assert any(f.source == "req.params" and f.sink_method == "query" for f in flows)


def test_array_find_is_not_nosql_sink() -> None:
    code = "const x = items.find(req.body);"
    flows = TaintTracker().analyze(make_js_context(code))
    assert not any(f.sink_method == "find" for f in flows)


def test_collection_find_is_nosql_sink() -> None:
    code = "collection.find({ name: req.body.name });"
    flows = TaintTracker().analyze(make_js_context(code))
    assert any(f.sink_method == "find" and f.source == "req.body" for f in flows)


def test_unknown_receiver_query_not_sql_when_allowlist() -> None:
    code = "cache.query(req.query.q);"
    flows = TaintTracker(sql_sink_allowlist=True).analyze(make_js_context(code))
    assert not any(f.sink_method == "query" for f in flows)


def test_db_query_still_sql_sink() -> None:
    code = "db.query(req.query.q);"
    flows = TaintTracker(sql_sink_allowlist=True).analyze(make_js_context(code))
    assert any(f.sink_method == "query" for f in flows)
