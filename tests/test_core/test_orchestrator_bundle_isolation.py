"""Bundle per-file isolation: unsupported files are skipped with warnings."""

import pytest

from analyzer.api.schemas import AnalyzeBundleRequest, ScanConfig
from analyzer.config import Settings
from analyzer.core.orchestrator import Orchestrator

_VULN_JS = "app.get('/x', (req, res) => { eval(req.query.x); });"


def _make_orch() -> Orchestrator:
    return Orchestrator(settings=Settings(), cwe_db=None)


def test_mixed_bundle_skips_unsupported_file() -> None:
    orch = _make_orch()
    resp = orch.analyze_bundle_sync(
        AnalyzeBundleRequest(
            files={"app.js": _VULN_JS, "helper.py": "print('hello')"},
            config=ScanConfig(enable_taint=False),
        )
    )
    assert resp.status == "completed"
    assert any(f.rule_id == "JS-CMD-001" for f in resp.findings)
    assert resp.stats.files_scanned == 1
    assert len(resp.warnings) == 1
    assert "helper.py" in resp.warnings[0]


def test_json_file_skipped_but_still_required_as_module() -> None:
    """require('./cfg.json') is idiomatic: skip analysis, keep module resolution."""
    app_js = """const cfg = require('./cfg.json');
app.get('/x', (req, res) => { eval(req.query.x); });
"""
    orch = _make_orch()
    resp = orch.analyze_bundle_sync(
        AnalyzeBundleRequest(
            files={"app.js": app_js, "cfg.json": '{"key": "value"}'},
            config=ScanConfig(enable_taint=True),
        )
    )
    assert resp.status == "completed"
    assert any(f.rule_id == "JS-CMD-001" for f in resp.findings)
    assert any("cfg.json" in w for w in resp.warnings)


def test_all_files_unsupported_is_rejected() -> None:
    orch = _make_orch()
    with pytest.raises(ValueError, match="no analyzable files"):
        orch.analyze_bundle_sync(
            AnalyzeBundleRequest(files={"helper.py": "print(1)", "cfg.json": "{}"})
        )


def test_empty_bundle_raises_clear_value_error() -> None:
    orch = _make_orch()
    req = AnalyzeBundleRequest.model_construct(files={})
    with pytest.raises(ValueError, match="at least one entry"):
        orch.analyze_bundle_sync(req)
