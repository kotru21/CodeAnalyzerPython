"""NoSQL and generic HTTP method sinks (plan Task 7)."""

from analyzer.api.schemas import AnalyzeBundleRequest, ScanConfig
from analyzer.config import Settings
from analyzer.core.orchestrator import Orchestrator
from analyzer.taint.tracker import TaintTracker
from tests.conftest import make_js_context
from tests.test_taint.taint_assertions import assert_any_flow

NOSQL_HARD = """function runFind(model, query) {
  model.find(query);
}
app.get('/z', (req, res) => {
  runFind(users, req.query.filter);
});"""

SSRF_HARD = """function pull(url) {
  return axios.get(url);
}
app.get('/x', (req, res) => {
  pull(req.query.u);
});"""


def test_nosql_hard_interprocedural_flow() -> None:
    flows = TaintTracker().analyze(make_js_context(NOSQL_HARD))
    assert_any_flow(flows, sink_method="find", source_substr="req.query")


def test_ssrf_hard_interprocedural_flow() -> None:
    flows = TaintTracker().analyze(make_js_context(SSRF_HARD))
    assert_any_flow(flows, sink_method="get", source_substr="req.query")


def test_orchestrator_detects_nosql_hard() -> None:
    orch = Orchestrator(Settings())
    resp = orch.analyze_bundle_sync(
        AnalyzeBundleRequest(
            files={"app.js": NOSQL_HARD},
            config=ScanConfig(enable_taint=True),
        )
    )
    assert any(f.rule_id == "JS-NOSQL-001" for f in resp.findings)


def test_orchestrator_detects_ssrf_hard() -> None:
    orch = Orchestrator(Settings())
    resp = orch.analyze_bundle_sync(
        AnalyzeBundleRequest(files={"app.js": SSRF_HARD}, config=ScanConfig())
    )
    assert any(f.rule_id == "JS-SSRF-001" for f in resp.findings)


def test_map_get_is_not_ssrf_sink() -> None:
    code = """app.get('/x', (req, res) => {
  const m = new Map();
  const v = m.get(req.query.k);
  res.send(v);
});
"""
    flows = TaintTracker().analyze(make_js_context(code))
    assert not any(f.sink_method == "get" for f in flows)


def test_headers_get_is_not_ssrf_sink() -> None:
    code = """app.get('/x', (req, res) => {
  const h = headers.get(req.query.name);
  res.send(h);
});
"""
    flows = TaintTracker().analyze(make_js_context(code))
    assert not any(f.sink_method == "get" for f in flows)


def test_generic_client_get_is_not_ssrf_sink() -> None:
    code = """app.get('/x', (req, res) => {
  client.get(req.query.u);
});
"""
    flows = TaintTracker().analyze(make_js_context(code))
    assert not any(f.sink_method == "get" for f in flows)


def test_axios_delete_maps_to_ssrf_rule() -> None:
    code = """app.get('/x', (req, res) => {
  axios.delete(req.query.u);
});
"""
    orch = Orchestrator(Settings())
    resp = orch.analyze_bundle_sync(
        AnalyzeBundleRequest(files={"app.js": code}, config=ScanConfig(enable_taint=True))
    )
    assert any(f.rule_id == "JS-SSRF-001" and f.confidence.value == "high" for f in resp.findings)
