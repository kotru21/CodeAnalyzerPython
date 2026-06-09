from analyzer.api.schemas import AnalyzeRequest, ScanConfig
from analyzer.config import Settings
from analyzer.core.orchestrator import Orchestrator
from analyzer.core.severity import Confidence


def test_ssrf_without_taint_is_low_confidence():
    code = "const url = config.endpoint; fetch(url);"
    orch = Orchestrator(Settings())
    resp = orch.analyze_sync(
        AnalyzeRequest(
            source_code=code,
            file_path="app.js",
            config=ScanConfig(enable_taint=False),
        )
    )
    ssrf_findings = [f for f in resp.findings if f.rule_id == "JS-SSRF-001"]
    assert len(ssrf_findings) == 1
    assert ssrf_findings[0].confidence == Confidence.LOW


def test_ssrf_with_taint_is_high_confidence():
    code = "fetch(req.query.url);"
    orch = Orchestrator(Settings())
    resp = orch.analyze_sync(
        AnalyzeRequest(
            source_code=code,
            file_path="app.js",
            config=ScanConfig(enable_taint=True),
        )
    )
    ssrf_findings = [f for f in resp.findings if f.rule_id == "JS-SSRF-001"]
    assert len(ssrf_findings) == 1
    assert ssrf_findings[0].confidence == Confidence.HIGH
