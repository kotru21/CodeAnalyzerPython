import pytest

from analyzer.rules.registry import get_all_rules, reset_registry
from tests.conftest import make_js_context

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
    {
        "id": "xss-res-send-dynamic",
        "code": """
app.get('/x', (req, res) => {
    res.send(req.query.msg);
});
""",
        "should_detect": True,
        "rule_id": "JS-XSS-003",
    },
    {
        "id": "xss-socket-send-not-response-xss",
        "code": """
socket.send(req.query.msg);
""",
        "should_detect": False,
        "rule_id": "JS-XSS-003",
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


# --- Phase 4 Rules ---

PROTO_CASES = [
    {
        "id": "proto-recursive-merge-unsafe",
        "code": """
function merge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object') {
            target[key] = target[key] || {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}
""",
        "should_detect": True,
        "rule_id": "JS-PROTO-001",
    },
    {
        "id": "proto-bracket-assignment-dynamic-key",
        "code": """
app.post('/config', (req, res) => {
    const obj = {};
    obj[req.body.key] = req.body.value;
});
""",
        "should_detect": True,
        "rule_id": "JS-PROTO-001",
    },
    {
        "id": "proto-safe-object-create-null",
        "code": """
function safeMerge(target, source) {
    const result = Object.create(null);
    for (const key of Object.keys(source)) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
        result[key] = source[key];
    }
    return result;
}
""",
        "should_detect": False,
        "rule_id": "JS-PROTO-001",
    },
]


class TestPrototypePollutionRule:
    @pytest.mark.parametrize("case", PROTO_CASES, ids=[c["id"] for c in PROTO_CASES])
    def test_prototype_pollution(self, case: dict):
        ctx = make_js_context(case["code"])
        rules = get_all_rules()
        matching = [r for r in rules if r.meta().rule_id == case["rule_id"]]
        assert len(matching) == 1
        findings = matching[0].run(ctx)
        if case["should_detect"]:
            assert len(findings) > 0, f"Expected detection for {case['id']}"
        else:
            assert len(findings) == 0, f"False positive for {case['id']}"


PATH_CASES = [
    {
        "id": "path-readfile-user-input",
        "code": """
const fs = require('fs');
app.get('/file', (req, res) => {
    const filePath = req.query.path;
    fs.readFile(filePath, 'utf8', (err, data) => {
        res.send(data);
    });
});
""",
        "should_detect": True,
        "rule_id": "JS-PATH-001",
    },
    {
        "id": "path-readfile-concat",
        "code": """
app.get('/download', (req, res) => {
    fs.readFileSync('./uploads/' + req.params.filename);
});
""",
        "should_detect": True,
        "rule_id": "JS-PATH-001",
    },
    {
        "id": "path-safe-static-path",
        "code": """
const fs = require('fs');
const data = fs.readFileSync('./config/settings.json', 'utf8');
""",
        "should_detect": False,
        "rule_id": "JS-PATH-001",
    },
]


class TestPathTraversalRule:
    @pytest.mark.parametrize("case", PATH_CASES, ids=[c["id"] for c in PATH_CASES])
    def test_path_traversal(self, case: dict):
        ctx = make_js_context(case["code"])
        rules = get_all_rules()
        matching = [r for r in rules if r.meta().rule_id == case["rule_id"]]
        assert len(matching) == 1
        findings = matching[0].run(ctx)
        if case["should_detect"]:
            assert len(findings) > 0, f"Expected detection for {case['id']}"
        else:
            assert len(findings) == 0, f"False positive for {case['id']}"


SECRETS_CASES = [
    {
        "id": "secrets-password-string",
        "code": """
const password = "SuperSecret123!";
const dbConfig = { host: 'localhost', password: 'admin123' };
""",
        "should_detect": True,
        "rule_id": "JS-SEC-001",
    },
    {
        "id": "secrets-api-key",
        "code": """
const API_KEY = "sk-1234567890abcdef";
""",
        "should_detect": True,
        "rule_id": "JS-SEC-001",
    },
    {
        "id": "secrets-safe-env-var",
        "code": """
const password = process.env.DB_PASSWORD;
const apiKey = process.env.API_KEY;
""",
        "should_detect": False,
        "rule_id": "JS-SEC-001",
    },
]


class TestHardcodedSecretsRule:
    @pytest.mark.parametrize("case", SECRETS_CASES, ids=[c["id"] for c in SECRETS_CASES])
    def test_hardcoded_secrets(self, case: dict):
        ctx = make_js_context(case["code"])
        rules = get_all_rules()
        matching = [r for r in rules if r.meta().rule_id == case["rule_id"]]
        assert len(matching) == 1
        findings = matching[0].run(ctx)
        if case["should_detect"]:
            assert len(findings) > 0, f"Expected detection for {case['id']}"
        else:
            assert len(findings) == 0, f"False positive for {case['id']}"


DESER_CASES = [
    {
        "id": "deser-node-serialize",
        "code": """
const serialize = require('node-serialize');
app.post('/data', (req, res) => {
    const obj = serialize.unserialize(req.body.data);
    res.json(obj);
});
""",
        "should_detect": True,
        "rule_id": "JS-DES-001",
    },
    {
        "id": "deser-eval-buffer",
        "code": """
const payload = Buffer.from(req.body.encoded, 'base64').toString();
eval(payload);
""",
        "should_detect": True,
        "rule_id": "JS-DES-001",
    },
    {
        "id": "deser-safe-json-parse-validated",
        "code": """
const data = JSON.parse(req.body.json);
const validated = schema.validate(data);
""",
        "should_detect": False,
        "rule_id": "JS-DES-001",
    },
]


class TestInsecureDeserializationRule:
    @pytest.mark.parametrize("case", DESER_CASES, ids=[c["id"] for c in DESER_CASES])
    def test_insecure_deserialization(self, case: dict):
        ctx = make_js_context(case["code"])
        rules = get_all_rules()
        matching = [r for r in rules if r.meta().rule_id == case["rule_id"]]
        assert len(matching) == 1
        findings = matching[0].run(ctx)
        if case["should_detect"]:
            assert len(findings) > 0, f"Expected detection for {case['id']}"
        else:
            assert len(findings) == 0, f"False positive for {case['id']}"


CRYPTO_CASES = [
    {
        "id": "crypto-md5-hash",
        "code": """
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');
""",
        "should_detect": True,
        "rule_id": "JS-CRYPTO-001",
    },
    {
        "id": "crypto-math-random",
        "code": """
function generateToken() {
    return Math.random().toString(36).substr(2);
}
""",
        "should_detect": True,
        "rule_id": "JS-CRYPTO-001",
    },
    {
        "id": "crypto-safe-sha256",
        "code": """
const crypto = require('crypto');
const hash = crypto.createHash('sha256').update(data).digest('hex');
const id = crypto.randomUUID();
""",
        "should_detect": False,
        "rule_id": "JS-CRYPTO-001",
    },
]


class TestWeakCryptoRule:
    @pytest.mark.parametrize("case", CRYPTO_CASES, ids=[c["id"] for c in CRYPTO_CASES])
    def test_weak_crypto(self, case: dict):
        ctx = make_js_context(case["code"])
        rules = get_all_rules()
        matching = [r for r in rules if r.meta().rule_id == case["rule_id"]]
        assert len(matching) == 1
        findings = matching[0].run(ctx)
        if case["should_detect"]:
            assert len(findings) > 0, f"Expected detection for {case['id']}"
        else:
            assert len(findings) == 0, f"False positive for {case['id']}"


REDIRECT_CASES = [
    {
        "id": "redirect-req-query-url",
        "code": """
app.get('/redirect', (req, res) => {
    res.redirect(req.query.url);
});
""",
        "should_detect": True,
        "rule_id": "JS-REDIRECT-001",
    },
    {
        "id": "redirect-req-params",
        "code": """
app.get('/go/:target', (req, res) => {
    res.redirect(req.params.target);
});
""",
        "should_detect": True,
        "rule_id": "JS-REDIRECT-001",
    },
    {
        "id": "redirect-safe-static",
        "code": """
app.get('/home', (req, res) => {
    res.redirect('/dashboard');
});
""",
        "should_detect": False,
        "rule_id": "JS-REDIRECT-001",
    },
]


class TestOpenRedirectRule:
    @pytest.mark.parametrize("case", REDIRECT_CASES, ids=[c["id"] for c in REDIRECT_CASES])
    def test_open_redirect(self, case: dict):
        ctx = make_js_context(case["code"])
        rules = get_all_rules()
        matching = [r for r in rules if r.meta().rule_id == case["rule_id"]]
        assert len(matching) == 1
        findings = matching[0].run(ctx)
        if case["should_detect"]:
            assert len(findings) > 0, f"Expected detection for {case['id']}"
        else:
            assert len(findings) == 0, f"False positive for {case['id']}"


NOSQL_CASES = [
    {
        "id": "nosql-find-req-body",
        "code": """
app.post('/users/search', (req, res) => {
    db.collection('users').find(req.body);
});
""",
        "should_detect": True,
        "rule_id": "JS-NOSQL-001",
    },
    {
        "id": "nosql-where-operator",
        "code": """
app.get('/users', (req, res) => {
    db.collection('users').find({ $where: req.query.filter });
});
""",
        "should_detect": True,
        "rule_id": "JS-NOSQL-001",
    },
    {
        "id": "nosql-safe-specific-fields",
        "code": """
app.get('/users', (req, res) => {
    db.collection('users').find({ name: req.query.name, active: true });
});
""",
        "should_detect": False,
        "rule_id": "JS-NOSQL-001",
    },
]


class TestNoSQLInjectionRule:
    @pytest.mark.parametrize("case", NOSQL_CASES, ids=[c["id"] for c in NOSQL_CASES])
    def test_nosql_injection(self, case: dict):
        ctx = make_js_context(case["code"])
        rules = get_all_rules()
        matching = [r for r in rules if r.meta().rule_id == case["rule_id"]]
        assert len(matching) == 1
        findings = matching[0].run(ctx)
        if case["should_detect"]:
            assert len(findings) > 0, f"Expected detection for {case['id']}"
        else:
            assert len(findings) == 0, f"False positive for {case['id']}"


SSRF_CASES = [
    {
        "id": "ssrf-fetch-user-url",
        "code": """
app.get('/proxy', async (req, res) => {
    const response = await fetch(req.query.url);
    const data = await response.text();
    res.send(data);
});
""",
        "should_detect": True,
        "rule_id": "JS-SSRF-001",
    },
    {
        "id": "ssrf-axios-user-url",
        "code": """
app.post('/webhook', async (req, res) => {
    const result = await axios.get(req.body.callback_url);
    res.json(result.data);
});
""",
        "should_detect": True,
        "rule_id": "JS-SSRF-001",
    },
    {
        "id": "ssrf-safe-hardcoded-url",
        "code": """
const response = await fetch('https://api.example.com/data');
""",
        "should_detect": False,
        "rule_id": "JS-SSRF-001",
    },
]


class TestSSRFRule:
    @pytest.mark.parametrize("case", SSRF_CASES, ids=[c["id"] for c in SSRF_CASES])
    def test_ssrf(self, case: dict):
        ctx = make_js_context(case["code"])
        rules = get_all_rules()
        matching = [r for r in rules if r.meta().rule_id == case["rule_id"]]
        assert len(matching) == 1
        findings = matching[0].run(ctx)
        if case["should_detect"]:
            assert len(findings) > 0, f"Expected detection for {case['id']}"
        else:
            assert len(findings) == 0, f"False positive for {case['id']}"


REDOS_CASES = [
    {
        "id": "redos-evil-regex",
        "code": """
app.post('/search', (req, res) => {
    const pattern = new RegExp(req.body.pattern);
    const match = pattern.test(data);
});
""",
        "should_detect": True,
        "rule_id": "JS-REDOS-001",
    },
    {
        "id": "redos-safe-static-regex",
        "code": r"""
const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const valid = emailRegex.test(email);
""",
        "should_detect": False,
        "rule_id": "JS-REDOS-001",
    },
]


class TestRegexDOSRule:
    @pytest.mark.parametrize("case", REDOS_CASES, ids=[c["id"] for c in REDOS_CASES])
    def test_redos(self, case: dict):
        ctx = make_js_context(case["code"])
        rules = get_all_rules()
        matching = [r for r in rules if r.meta().rule_id == case["rule_id"]]
        assert len(matching) == 1
        findings = matching[0].run(ctx)
        if case["should_detect"]:
            assert len(findings) > 0, f"Expected detection for {case['id']}"
        else:
            assert len(findings) == 0, f"False positive for {case['id']}"


JWT_CASES = [
    {
        "id": "jwt-algorithm-none",
        "code": """
const jwt = require('jsonwebtoken');
app.post('/login', (req, res) => {
    const token = jwt.sign({ userId: req.body.id }, 'secret', { algorithm: 'none' });
    res.json({ token });
});
""",
        "should_detect": True,
        "rule_id": "JS-JWT-001",
    },
    {
        "id": "jwt-alg-none-jsonwebtoken",
        "code": """
const jsonwebtoken = require('jsonwebtoken');
const token = jsonwebtoken.sign({ id: 1 }, 'key', { alg: "none" });
""",
        "should_detect": True,
        "rule_id": "JS-JWT-001",
    },
    {
        "id": "jwt-safe-hs256",
        "code": """
const jwt = require('jsonwebtoken');
const token = jwt.sign({ id: 1 }, 'secret', { algorithm: 'HS256' });
""",
        "should_detect": False,
        "rule_id": "JS-JWT-001",
    },
]


class TestJWTRule:
    @pytest.mark.parametrize("case", JWT_CASES, ids=[c["id"] for c in JWT_CASES])
    def test_jwt(self, case: dict):
        ctx = make_js_context(case["code"])
        rules = get_all_rules()
        matching = [r for r in rules if r.meta().rule_id == case["rule_id"]]
        assert len(matching) == 1
        findings = matching[0].run(ctx)
        if case["should_detect"]:
            assert len(findings) > 0, f"Expected detection for {case['id']}"
        else:
            assert len(findings) == 0, f"False positive for {case['id']}"


COOKIE_CASES = [
    {
        "id": "cookie-httponly-false",
        "code": """
app.get('/session', (req, res) => {
    res.cookie('sessionId', req.query.id, { httpOnly: false, secure: true });
});
""",
        "should_detect": True,
        "rule_id": "JS-COOKIE-001",
    },
    {
        "id": "cookie-httponly-true",
        "code": """
app.get('/session', (req, res) => {
    res.cookie('sessionId', req.query.id, { httpOnly: true, secure: true });
});
""",
        "should_detect": False,
        "rule_id": "JS-COOKIE-001",
    },
    {
        "id": "cookie-no-httponly-option",
        "code": """
app.get('/session', (req, res) => {
    res.cookie('sessionId', req.query.id, { secure: true });
});
""",
        "should_detect": False,
        "rule_id": "JS-COOKIE-001",
    },
]


class TestInsecureCookiesRule:
    @pytest.mark.parametrize("case", COOKIE_CASES, ids=[c["id"] for c in COOKIE_CASES])
    def test_insecure_cookies(self, case: dict):
        ctx = make_js_context(case["code"])
        rules = get_all_rules()
        matching = [r for r in rules if r.meta().rule_id == case["rule_id"]]
        assert len(matching) == 1
        findings = matching[0].run(ctx)
        if case["should_detect"]:
            assert len(findings) > 0, f"Expected detection for {case['id']}"
        else:
            assert len(findings) == 0, f"False positive for {case['id']}"
