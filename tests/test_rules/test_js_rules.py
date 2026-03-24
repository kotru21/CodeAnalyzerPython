import pytest

from tests.conftest import make_js_context
from analyzer.rules.registry import get_all_rules, reset_registry


SQLI_CASES = [
    {
        "id": "sqli-template-literal-in-query",
        "code": """
const express = require('express');
const app = express();
app.get('/users', (req, res) => {
    const id = req.params.id;
    db.query(`SELECT * FROM users WHERE id = ${id}`);
});
""",
        "should_detect": True,
        "rule_id": "JS-SQL-001",
    },
    {
        "id": "sqli-string-concat-in-query",
        "code": """
app.post('/login', (req, res) => {
    const username = req.body.username;
    pool.query("SELECT * FROM users WHERE name = '" + username + "'");
});
""",
        "should_detect": True,
        "rule_id": "JS-SQL-001",
    },
    {
        "id": "sqli-safe-parameterized",
        "code": """
app.get('/users', (req, res) => {
    db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
});
""",
        "should_detect": False,
        "rule_id": "JS-SQL-001",
    },
]


@pytest.fixture(autouse=True)
def _reset():
    reset_registry()
    yield
    reset_registry()


class TestSQLInjectionRule:
    @pytest.mark.parametrize("case", SQLI_CASES, ids=[c["id"] for c in SQLI_CASES])
    def test_sql_injection(self, case: dict):
        ctx = make_js_context(case["code"])
        rules = get_all_rules()
        rule = next(r for r in rules if r.meta().rule_id == case["rule_id"])
        findings = rule.run(ctx)
        if case["should_detect"]:
            assert len(findings) > 0, f"Expected detection for {case['id']}"
        else:
            assert len(findings) == 0, f"False positive for {case['id']}"
