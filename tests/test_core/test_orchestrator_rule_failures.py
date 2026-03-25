from unittest.mock import patch

from analyzer.api.schemas import AnalyzeRequest, ScanConfig
from analyzer.config import get_settings
from analyzer.core.orchestrator import Orchestrator


def test_analyze_sync_records_failed_rule_ids() -> None:
    settings = get_settings()
    orch = Orchestrator(settings=settings, cwe_db=None)
    request = AnalyzeRequest(
        source_code="const x = 1;",
        file_path="a.js",
        config=ScanConfig(enable_taint=False),
    )

    from analyzer.rules.registry import get_rules_for_language

    real_rules = get_rules_for_language("javascript")
    victim = next(r for r in real_rules if r.meta().rule_id == "JS-SQL-001")

    def boom(ctx):  # noqa: ANN001
        raise RuntimeError("simulated")

    with (
        patch.object(victim.__class__, "run", side_effect=boom),
        patch(
            "analyzer.core.orchestrator.get_rules_for_language",
            return_value=[victim],
        ),
    ):
        resp = orch.analyze_sync(request)

    assert "JS-SQL-001" in resp.failed_rules
