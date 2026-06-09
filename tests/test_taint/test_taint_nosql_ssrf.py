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

SSRF_HARD = """function pull(client, url) {
  return client.get(url);
}
app.get('/x', (req, res) => {
  pull(axios, req.query.u);
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
