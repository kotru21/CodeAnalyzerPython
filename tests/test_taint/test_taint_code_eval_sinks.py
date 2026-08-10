"""Code-evaluation sinks: new Function(...) and string-arg setTimeout/setInterval."""

from analyzer.api.schemas import AnalyzeRequest, ScanConfig
from analyzer.config import Settings
from analyzer.core.orchestrator import Orchestrator
from analyzer.taint.tracker import TaintTracker
from tests.conftest import make_js_context
from tests.test_taint.taint_assertions import assert_any_flow, assert_no_flow_with_sink


class TestCodeEvalSinks:
    def test_new_function__positive__tainted_arg(self) -> None:
        code = """
app.get('/x', (req, res) => {
  new Function(req.query.x);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="Function", source_substr="req.query")

    def test_new_function__positive__concat_arg(self) -> None:
        code = """
app.get('/x', (req, res) => {
  new Function('return ' + req.body.snippet);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="Function", source_substr="req.body")

    def test_new_function__negative__literal_arg(self) -> None:
        code = """
app.get('/x', (req, res) => {
  new Function('return 1');
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_no_flow_with_sink(flows, "Function")

    def test_set_timeout__positive__tainted_string_first_arg(self) -> None:
        code = """
app.get('/x', (req, res) => {
  const code = req.body.snippet;
  setTimeout(code, 100);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="setTimeout", source_substr="req.body")

    def test_set_interval__positive__tainted_string_first_arg(self) -> None:
        code = """
app.get('/x', (req, res) => {
  setInterval(req.query.cb, 1000);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_any_flow(flows, sink_method="setInterval", source_substr="req.query")

    def test_set_timeout__negative__literal_string(self) -> None:
        code = """
app.get('/x', (req, res) => {
  setTimeout('console.log(1)', 100);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_no_flow_with_sink(flows, "setTimeout")

    def test_set_timeout__negative__function_arg(self) -> None:
        code = """
app.get('/x', (req, res) => {
  setTimeout(() => { res.end('ok'); }, 100);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_no_flow_with_sink(flows, "setTimeout")

    def test_set_timeout__negative__tainted_delay_only(self) -> None:
        """Only the first arg is evaluated as code; a tainted delay is not RCE."""
        code = """
app.get('/x', (req, res) => {
  setTimeout(() => res.end('ok'), req.query.delay);
});
"""
        flows = TaintTracker().analyze(make_js_context(code))
        assert_no_flow_with_sink(flows, "setTimeout")

    def test_new_function__maps_to_cmd_rule_high_confidence(self) -> None:
        code = """
app.get('/x', (req, res) => {
  new Function(req.query.x);
});
"""
        orch = Orchestrator(Settings())
        resp = orch.analyze_sync(
            AnalyzeRequest(
                source_code=code,
                file_path="app.js",
                config=ScanConfig(enable_taint=True),
            )
        )
        assert any(
            f.rule_id == "JS-CMD-001" and f.confidence.value == "high" for f in resp.findings
        )

    def test_set_timeout__maps_to_cmd_rule_high_confidence(self) -> None:
        code = """
app.get('/x', (req, res) => {
  setTimeout(req.query.x, 100);
});
"""
        orch = Orchestrator(Settings())
        resp = orch.analyze_sync(
            AnalyzeRequest(
                source_code=code,
                file_path="app.js",
                config=ScanConfig(enable_taint=True),
            )
        )
        assert any(
            f.rule_id == "JS-CMD-001" and f.confidence.value == "high" for f in resp.findings
        )

    def test_set_timeout__negative__literal_no_cmd_finding(self) -> None:
        code = """
app.get('/x', (req, res) => {
  setTimeout('console.log(1)', 100);
});
"""
        orch = Orchestrator(Settings())
        resp = orch.analyze_sync(
            AnalyzeRequest(
                source_code=code,
                file_path="app.js",
                config=ScanConfig(enable_taint=True),
            )
        )
        assert not any(f.rule_id == "JS-CMD-001" for f in resp.findings)
