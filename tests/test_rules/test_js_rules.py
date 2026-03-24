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


XSS_CASES = [
    {
        "id": "xss-innerhtml-assignment",
        "code": """
app.get('/page', (req, res) => {
    const el = document.getElementById('output');
    el.innerHTML = req.query.input;
});
""",
        "should_detect": True,
        "rule_id": "JS-XSS-001",
    },
    {
        "id": "xss-document-write",
        "code": """
app.get('/page', (req, res) => {
    document.write(req.query.input);
});
""",
        "should_detect": True,
        "rule_id": "JS-XSS-001",
    },
    {
        "id": "xss-safe-textcontent",
        "code": """
app.get('/page', (req, res) => {
    const el = document.getElementById('output');
    el.textContent = req.query.input;
});
""",
        "should_detect": False,
        "rule_id": "JS-XSS-001",
    },
    {
        "id": "xss-dangerously-set-innerhtml",
        "code": """
function UserProfile({ data }) {
    return <div dangerouslySetInnerHTML={{__html: data.bio}} />;
}
""",
        "should_detect": True,
        "rule_id": "JS-XSS-002",
    },
    {
        "id": "xss-safe-jsx-expression",
        "code": """
function UserProfile({ data }) {
    return <div>{data.bio}</div>;
}
""",
        "should_detect": False,
        "rule_id": "JS-XSS-002",
    },
]


class TestXSSRule:
    @pytest.mark.parametrize("case", XSS_CASES, ids=[c["id"] for c in XSS_CASES])
    def test_xss(self, case: dict):
        ctx = make_js_context(case["code"])
        rules = get_all_rules()
        rule = next(r for r in rules if r.meta().rule_id == case["rule_id"])
        findings = rule.run(ctx)
        if case["should_detect"]:
            assert len(findings) > 0, f"Expected detection for {case['id']}"
        else:
            assert len(findings) == 0, f"False positive for {case['id']}"


CMDI_CASES = [
    {
        "id": "cmdi-exec-template-literal",
        "code": """
const { exec } = require('child_process');
app.get('/run', (req, res) => {
    exec(`ls ${req.query.dir}`);
});
""",
        "should_detect": True,
        "rule_id": "JS-CMD-001",
    },
    {
        "id": "cmdi-eval-variable",
        "code": """
app.post('/calc', (req, res) => {
    const expr = req.body.expression;
    eval(expr);
});
""",
        "should_detect": True,
        "rule_id": "JS-CMD-001",
    },
    {
        "id": "cmdi-safe-static-exec",
        "code": """
const { execSync } = require('child_process');
const output = execSync('ls -la');
""",
        "should_detect": False,
        "rule_id": "JS-CMD-001",
    },
]


class TestCommandInjectionRule:
    @pytest.mark.parametrize("case", CMDI_CASES, ids=[c["id"] for c in CMDI_CASES])
    def test_command_injection(self, case: dict):
        ctx = make_js_context(case["code"])
        rules = get_all_rules()
        rule = next(r for r in rules if r.meta().rule_id == case["rule_id"])
        findings = rule.run(ctx)
        if case["should_detect"]:
            assert len(findings) > 0, f"Expected detection for {case['id']}"
        else:
            assert len(findings) == 0, f"False positive for {case['id']}"
