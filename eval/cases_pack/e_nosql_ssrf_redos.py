from eval.cases_pack._util import mk


def cases_nosql_ssrf_redos() -> list[dict]:
    return [
        mk(
            "NOSQL-EASY-VULN-01",
            "JS-NOSQL-001",
            "easy",
            "vulnerable",
            "app.js",
            "users.find(req.body);",
            "CWE-943",
            "find с req.body",
        ),
        mk(
            "NOSQL-EASY-SAFE-01",
            "JS-NOSQL-001",
            "easy",
            "safe",
            "app.js",
            "users.find({ name: 'alice' });",
            None,
            "Статический запрос",
        ),
        mk(
            "NOSQL-MED-VULN-01",
            "JS-NOSQL-001",
            "medium",
            "vulnerable",
            "app.js",
            """app.post('/q', (req, res) => {
  const q = req.body;
  db.items.find(q);
});""",
            "CWE-943",
            "Промежуточная переменная",
        ),
        mk(
            "NOSQL-MED-SAFE-01",
            "JS-NOSQL-001",
            "medium",
            "safe",
            "app.js",
            """app.post('/q', (req, res) => {
  const id = req.body.id;
  db.items.find({ _id: id });
});""",
            None,
            "Только поле id",
        ),
        mk(
            "NOSQL-HARD-VULN-01",
            "JS-NOSQL-001",
            "hard",
            "vulnerable",
            "app.js",
            """function runFind(model, query) {
  model.find(query);
}
app.get('/z', (req, res) => {
  runFind(users, req.query.filter);
});""",
            "CWE-943",
            "Inter-procedural find",
        ),
        mk(
            "NOSQL-HARD-SAFE-01",
            "JS-NOSQL-001",
            "hard",
            "safe",
            "app.js",
            """function runFind(model, query) {
  model.find(query);
}
app.get('/z', (req, res) => {
  runFind(users, { status: 'open' });
});""",
            None,
            "Константный фильтр",
        ),
        mk(
            "SSRF-EASY-VULN-01",
            "JS-SSRF-001",
            "easy",
            "vulnerable",
            "app.js",
            "fetch(req.query.url);",
            "CWE-918",
            "fetch с URL из query",
        ),
        mk(
            "SSRF-EASY-SAFE-01",
            "JS-SSRF-001",
            "easy",
            "safe",
            "app.js",
            "fetch('https://example.com/api');",
            None,
            "Константный URL",
        ),
        mk(
            "SSRF-MED-VULN-01",
            "JS-SSRF-001",
            "medium",
            "vulnerable",
            "app.js",
            """app.get('/p', (req, res) => {
  const target = req.body.endpoint;
  axios.get(target);
});""",
            "CWE-918",
            "axios.get",
        ),
        mk(
            "SSRF-MED-SAFE-01",
            "JS-SSRF-001",
            "medium",
            "safe",
            "app.js",
            """app.get('/p', (req, res) => {
  axios.get('https://api.example.com/v1/status');
});""",
            None,
            "Фиксированный endpoint",
        ),
        mk(
            "SSRF-HARD-VULN-01",
            "JS-SSRF-001",
            "hard",
            "vulnerable",
            "app.js",
            """function pull(client, url) {
  return client.get(url);
}
app.get('/x', (req, res) => {
  pull(axios, req.query.u);
});""",
            "CWE-918",
            "Inter-procedural HTTP",
        ),
        mk(
            "SSRF-HARD-SAFE-01",
            "JS-SSRF-001",
            "hard",
            "safe",
            "app.js",
            """function pull(client, url) {
  return client.get(url);
}
app.get('/x', (req, res) => {
  pull(axios, 'https://example.com');
});""",
            None,
            "Константный URL в helper",
        ),
        mk(
            "REDOS-EASY-VULN-01",
            "JS-REDOS-001",
            "easy",
            "vulnerable",
            "app.js",
            "new RegExp(req.query.pat);",
            "CWE-1333",
            "RegExp из пользователя",
        ),
        mk(
            "REDOS-EASY-SAFE-01",
            "JS-REDOS-001",
            "easy",
            "safe",
            "app.js",
            "new RegExp('^[a-z0-9]+$');",
            None,
            "Статический паттерн",
        ),
        mk(
            "REDOS-MED-VULN-01",
            "JS-REDOS-001",
            "medium",
            "vulnerable",
            "app.js",
            """app.get('/r', (req, res) => {
  const p = req.body.regex;
  const re = new RegExp(p);
  re.test('abc');
});""",
            "CWE-1333",
            "Паттерн из body",
        ),
        mk(
            "REDOS-MED-SAFE-01",
            "JS-REDOS-001",
            "medium",
            "safe",
            "app.js",
            """app.get('/r', (req, res) => {
  const re = new RegExp('^\\\\d+$');
  re.test(req.body.s);
});""",
            None,
            "Статический regex, пользователь только в test()",
        ),
        mk(
            "REDOS-HARD-VULN-01",
            "JS-REDOS-001",
            "hard",
            "vulnerable",
            "app.js",
            """function buildRe(src) {
  return new RegExp(src);
}
app.get('/t', (req, res) => {
  buildRe(req.query.r);
});""",
            "CWE-1333",
            "Helper new RegExp",
        ),
        mk(
            "REDOS-HARD-SAFE-01",
            "JS-REDOS-001",
            "hard",
            "safe",
            "app.js",
            """function buildRe() {
  return new RegExp('abc');
}
app.get('/t', (req, res) => {
  buildRe();
});""",
            None,
            "Без пользовательского ввода в RegExp",
        ),
    ]
