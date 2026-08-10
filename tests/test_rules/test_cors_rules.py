"""JS-CORS-001/002: wildcard origin with/without credentials."""

import pytest

from analyzer.rules.registry import get_all_rules, reset_registry
from tests.conftest import make_js_context

CORS_CASES = [
    {
        "id": "wildcard-with-credentials",
        "code": """
const cors = require('cors');
app.use(cors({ origin: '*', credentials: true }));
""",
        "expected": {"JS-CORS-001"},
        "absent": {"JS-CORS-002"},
    },
    {
        "id": "wildcard-without-credentials",
        "code": """
const cors = require('cors');
app.use(cors({ origin: '*' }));
""",
        "expected": {"JS-CORS-002"},
        "absent": {"JS-CORS-001"},
    },
    {
        "id": "wildcard-credentials-false",
        "code": "app.use(cors({ origin: '*', credentials: false }));",
        "expected": {"JS-CORS-002"},
        "absent": {"JS-CORS-001"},
    },
    {
        "id": "safe-origin-list",
        "code": "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));",
        "expected": set(),
        "absent": {"JS-CORS-001", "JS-CORS-002"},
    },
    {
        "id": "safe-static-origin",
        "code": "app.use(cors({ origin: 'https://app.example.com' }));",
        "expected": set(),
        "absent": {"JS-CORS-001", "JS-CORS-002"},
    },
    {
        "id": "member-expression-cors-call",
        "code": "app.use(mw.cors({ origin: '*', credentials: true }));",
        "expected": {"JS-CORS-001"},
        "absent": {"JS-CORS-002"},
    },
    {
        "id": "reflected-origin-with-credentials",
        "code": "app.use(cors({ origin: true, credentials: true }));",
        "expected": {"JS-CORS-001"},
        "absent": {"JS-CORS-002"},
    },
    {
        "id": "default-origin-with-credentials",
        "code": "app.use(cors({ credentials: true }));",
        "expected": {"JS-CORS-001"},
        "absent": {"JS-CORS-002"},
    },
    {
        "id": "no-options-object",
        "code": "app.use(cors());",
        "expected": {"JS-CORS-002"},
        "absent": {"JS-CORS-001"},
    },
]


@pytest.fixture(autouse=True)
def _reset():
    reset_registry()
    yield
    reset_registry()


class TestCorsRules:
    @pytest.mark.parametrize("case", CORS_CASES, ids=[c["id"] for c in CORS_CASES])
    def test_cors(self, case: dict) -> None:
        ctx = make_js_context(case["code"])
        rule_ids = {"JS-CORS-001", "JS-CORS-002"}
        rules = [r for r in get_all_rules() if r.meta().rule_id in rule_ids]
        assert len(rules) == 2
        found = {r.meta().rule_id for r in rules for f in [r.run(ctx)] if f}
        assert case["expected"] <= found, f"Missing detection for {case['id']}"
        assert case["absent"].isdisjoint(found), f"Unexpected finding for {case['id']}"

    def test_severity_levels(self) -> None:
        rules = {r.meta().rule_id: r.meta() for r in get_all_rules()}
        assert rules["JS-CORS-001"].severity.value == "high"
        assert rules["JS-CORS-002"].severity.value == "low"

    def test_column_uses_characters_after_non_ascii_text(self) -> None:
        source = "const " + chr(233) * 2 + " = 1; app.use(cors({ origin: '*' }));"
        ctx = make_js_context(source)
        rule = next(r for r in get_all_rules() if r.meta().rule_id == "JS-CORS-002")

        finding = rule.run(ctx)[0]

        assert finding.column == source.index("cors")
