"""JS-SEC-001: credential-format values must flag even without secret-like names."""

import pytest

from analyzer.rules.registry import get_all_rules, reset_registry
from tests.conftest import make_js_context

VALUE_CASES = [
    {
        "id": "aws-access-key-innocuous-name",
        "code": 'const key = "AKIAIOSFODNN7EXAMPLE";',
        "should_detect": True,
    },
    {
        "id": "aws-access-key-object-property",
        "code": 'const cfg = { accessKey: "AKIAIOSFODNN7EXAMPLE" };',
        "should_detect": True,
    },
    {
        "id": "pem-private-key",
        "code": 'const pem = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEow...";',
        "should_detect": True,
    },
    {
        "id": "pem-plain-private-key",
        "code": 'const pem = "-----BEGIN PRIVATE KEY-----";',
        "should_detect": True,
    },
    {
        "id": "github-pat",
        "code": 'const t = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12";',
        "should_detect": True,
    },
    {
        "id": "github-oauth-token",
        "code": 'const t = "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12";',
        "should_detect": True,
    },
    {
        "id": "slack-bot-token",
        "code": 'const s = "xoxb-123456789012-abcdefghijkl";',
        "should_detect": True,
    },
    {
        "id": "aws-lowercase-lookalike-not-flagged",
        "code": 'const key = "akiaiosfodnn7example";',
        "should_detect": False,
    },
    {
        "id": "prose-mentioning-akia-not-flagged",
        "code": 'const doc = "AWS keys look like AKIA followed by 16 chars";',
        "should_detect": False,
    },
    {
        "id": "short-string-not-flagged",
        "code": 'const key = "abc";',
        "should_detect": False,
    },
    {
        "id": "normal-words-not-flagged",
        "code": 'const greeting = "hello world";',
        "should_detect": False,
    },
    {
        "id": "name-based-match-still-works",
        "code": 'const password = "SuperSecret123!";',
        "should_detect": True,
    },
    {
        "id": "placeholder-still-ignored",
        "code": 'const password = "changeme";',
        "should_detect": False,
    },
]


@pytest.fixture(autouse=True)
def _reset():
    reset_registry()
    yield
    reset_registry()


class TestHardcodedSecretsValuePatterns:
    @pytest.mark.parametrize("case", VALUE_CASES, ids=[c["id"] for c in VALUE_CASES])
    def test_value_patterns(self, case: dict) -> None:
        ctx = make_js_context(case["code"])
        rule = next(r for r in get_all_rules() if r.meta().rule_id == "JS-SEC-001")
        findings = rule.run(ctx)
        if case["should_detect"]:
            assert findings, f"Expected detection for {case['id']}"
        else:
            assert findings == [], f"False positive for {case['id']}"

    def test_detected_secret_is_redacted_from_snippet(self) -> None:
        secret = "AKIAIOSFODNN7EXAMPLE"
        ctx = make_js_context(f'const value = "{secret}";')
        rule = next(r for r in get_all_rules() if r.meta().rule_id == "JS-SEC-001")

        finding = rule.run(ctx)[0]

        assert secret not in finding.code_snippet
        assert "[REDACTED]" in finding.code_snippet
