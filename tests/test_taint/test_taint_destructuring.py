from analyzer.taint.patterns import bind_pattern_from_source
from analyzer.taint.tracker import TaintTracker
from tests.conftest import make_js_context
from tests.test_taint.taint_assertions import assert_any_flow


def test_bind_object_shorthand():
    tainted: dict[str, str] = {}
    code = "const { id } = req.params;"
    ctx = make_js_context(code)
    decl = _first_var_declarator(ctx.root_node)
    bind_pattern_from_source(decl.child_by_field_name("name"), "req.params", tainted)
    assert tainted == {"id": "req.params"}


def test_bind_object_rename():
    tainted: dict[str, str] = {}
    code = "const { userId: id } = req.body;"
    ctx = make_js_context(code)
    decl = _first_var_declarator(ctx.root_node)
    bind_pattern_from_source(decl.child_by_field_name("name"), "req.body", tainted)
    assert tainted == {"id": "req.body"}


def test_bind_array_element():
    tainted: dict[str, str] = {}
    code = "const [first] = req.query.items;"
    ctx = make_js_context(code)
    decl = _first_var_declarator(ctx.root_node)
    bind_pattern_from_source(decl.child_by_field_name("name"), "req.query.items", tainted)
    assert tainted == {"first": "req.query.items"}


def test_destructure_to_sql_sink():
    code = """
app.get('/u', (req, res) => {
  const { id } = req.params;
  db.query(`SELECT * FROM users WHERE id = ${id}`);
});
"""
    flows = TaintTracker().analyze(make_js_context(code))
    assert_any_flow(flows, sink_method="query", source_substr="req.params")


def _first_var_declarator(root):
    stack = [root]
    while stack:
        n = stack.pop()
        if n.type == "variable_declarator":
            return n
        stack.extend(reversed(n.children))
    raise AssertionError("no variable_declarator")
