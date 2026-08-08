"""Wall-clock budget for analyze_sync (between rules; taint skipped if exceeded)."""

from unittest.mock import patch

from analyzer.api.schemas import AnalyzeRequest, ScanConfig
from analyzer.config import Settings
from analyzer.core.orchestrator import Orchestrator


def test_analyze_sync_time_budget_stops_before_second_rule() -> None:
    settings = Settings(analysis_budget_ms=10)
    orch = Orchestrator(settings=settings, cwe_db=None)
    request = AnalyzeRequest(
        source_code="const x = 1;",
        file_path="a.js",
        config=ScanConfig(enable_taint=True),
    )

    from analyzer.rules.registry import get_rules_for_language

    real_rules = get_rules_for_language("javascript")
    r1 = real_rules[0]
    r2 = real_rules[1]

    with (
        patch(
            "analyzer.core.orchestrator.time.monotonic",
            side_effect=[0.0, 0.0001, 0.02, 0.02, 0.02],
        ),
        patch(
            "analyzer.core.orchestrator.get_rules_for_language",
            return_value=[r1, r2],
        ),
    ):
        resp = orch.analyze_sync(request)

    assert resp.stats.time_budget_exceeded is True
    assert resp.status == "partial"


def test_analyze_sync_no_budget_flag_when_unlimited() -> None:
    settings = Settings(analysis_budget_ms=None)
    orch = Orchestrator(settings=settings, cwe_db=None)
    request = AnalyzeRequest(
        source_code="const x = 1;",
        file_path="a.js",
        config=ScanConfig(enable_taint=False),
    )
    resp = orch.analyze_sync(request)
    assert resp.stats.time_budget_exceeded is False
