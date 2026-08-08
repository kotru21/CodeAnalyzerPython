"""Path-sensitive if/else taint regressions."""

from analyzer.taint.tracker import TaintTracker
from tests.conftest import make_js_context


def test_sanitized_then_branch_no_flow_else_still_flows() -> None:
    code = """
let q = req.query.id;
if (ok) {
  q = parseInt(q);
  db.query(q);
} else {
  db.query(q);
}
"""
    flows = TaintTracker().analyze(make_js_context(code))
    # Else branch must still report; then branch should not (type_cast → sql).
    assert any(f.sink_method == "query" and f.source == "req.query" for f in flows)
    # Exactly one flow expected from the else arm (line with unsanitized q).
    assert len([f for f in flows if f.sink_method == "query"]) == 1
