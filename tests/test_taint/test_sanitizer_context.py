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


def test_path_resolve_does_not_sanitize_traversal():
    code = """
const path = require('path');
app.get('/x', (req, res) => {
  const p = path.resolve(req.query.f);
  fs.readFile(p);
});
"""
    flows = TaintTracker().analyze(make_js_context(code))
    assert any(f.sink_method == "readFile" for f in flows)


def test_encode_uri_component_does_not_sanitize_xss():
    code = """
app.get('/x', (req, res) => {
  el.innerHTML = encodeURIComponent(req.query.x);
});
"""
    flows = TaintTracker().analyze(make_js_context(code))
    assert any(f.sink_method == "innerHTML" for f in flows)


def test_bare_sanitize_substring_does_not_block_sql():
    # Unknown wrappers are not sanitizers; taint still visible in sink args.
    code = """
app.get('/x', (req, res) => {
  db.query(mysanitize(req.body.q));
});
"""
    flows = TaintTracker().analyze(make_js_context(code))
    assert any(f.sink_method == "query" for f in flows)


def test_innerhtml_assignment_taint_confirmed():
    code = """
app.get('/x', (req, res) => {
  el.innerHTML = req.query.x;
});
"""
    flows = TaintTracker().analyze(make_js_context(code))
    assert any(f.sink_method == "innerHTML" for f in flows)


def test_await_propagates_taint():
    code = """
app.get('/x', async (req, res) => {
  const q = await Promise.resolve(req.body.q);
  db.query(q);
});
"""
    flows = TaintTracker().analyze(make_js_context(code))
    assert any(f.sink_method == "query" for f in flows)


def test_string_wrapper_propagates_taint():
    code = """
app.get('/x', (req, res) => {
  const q = String(req.body.q);
  db.query(q);
});
"""
    flows = TaintTracker().analyze(make_js_context(code))
    assert any(f.sink_method == "query" for f in flows)
