from analyzer.taint.sanitizers import sanitizer_categories_for_call
from analyzer.taint.tracker import TaintTracker
from tests.conftest import make_js_context


def test_escape_sanitizes_xss_not_sql():
    cats = sanitizer_categories_for_call("validator.escape")
    assert "xss" in cats
    assert "sql" not in cats


def test_parseint_does_not_sanitize_xss_template():
    code = """
app.get('/x', (req, res) => {
  const id = parseInt(req.query.x, 10);
  res.send(`<div>${id}</div>`);
});
"""
    flows = TaintTracker().analyze(make_js_context(code))
    assert any(f.sink_method == "send" for f in flows)


def test_dompurify_blocks_xss_flow():
    code = """
app.get('/x', (req, res) => {
  const html = DOMPurify.sanitize(req.body.html);
  res.send(html);
});
"""
    flows = TaintTracker().analyze(make_js_context(code))
    assert not any(f.sink_method == "send" for f in flows)
