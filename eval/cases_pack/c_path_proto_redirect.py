from eval.cases_pack._util import mk


def cases_path_proto_redirect() -> list[dict]:
    return [
        mk(
            "PATH-EASY-VULN-01",
            "JS-PATH-001",
            "easy",
            "vulnerable",
            "app.js",
            "const fs = require('fs');\nfs.readFileSync(`./data/${req.query.name}`);",
            "CWE-22",
            "Путь из шаблонной строки",
        ),
        mk(
            "PATH-EASY-SAFE-01",
            "JS-PATH-001",
            "easy",
            "safe",
            "app.js",
            "const fs = require('fs');\nfs.readFileSync('/var/app/readme.txt');",
            None,
            "Константный путь",
        ),
        mk(
            "PATH-MED-VULN-01",
            "JS-PATH-001",
            "medium",
            "vulnerable",
            "app.js",
            """const fs = require('fs');
app.get('/f', (req, res) => {
  const base = './uploads/';
  const name = req.body.filename;
  const p = base + name;
  fs.readFileSync(p);
});""",
            "CWE-22",
            "Конкатенация пути",
        ),
        mk(
            "PATH-MED-SAFE-01",
            "JS-PATH-001",
            "medium",
            "safe",
            "app.js",
            """const fs = require('fs');
const ALLOW = new Set(['a.txt', 'b.txt']);
app.get('/f', (req, res) => {
  const name = req.query.n;
  if (!ALLOW.has(name)) return;
  fs.readFileSync('/var/safe/' + name);
});""",
            None,
            "Allowlist имён (код всё ещё может быть спорным для анализатора)",
        ),
        mk(
            "PATH-HARD-VULN-01",
            "JS-PATH-001",
            "hard",
            "vulnerable",
            "app.js",
            """const fs = require('fs');
function load(pathStr) {
  fs.readFileSync(pathStr);
}
function buildPath(seg) {
  return `/tmp/${seg}`;
}
app.get('/p', (req, res) => {
  load(buildPath(req.query.s));
});""",
            "CWE-22",
            "Inter-procedural путь",
        ),
        mk(
            "PATH-HARD-SAFE-01",
            "JS-PATH-001",
            "hard",
            "safe",
            "app.js",
            """const fs = require('fs');
function load(pathStr) {
  fs.readFileSync(pathStr);
}
app.get('/p', (req, res) => {
  load('/etc/hostname');
});""",
            None,
            "Только константа до sink",
        ),
        mk(
            "PROTO-EASY-VULN-01",
            "JS-PROTO-001",
            "easy",
            "vulnerable",
            "app.js",
            """const target = {};
const src = payload;
for (const k in src) {
  target[k] = src[k];
}""",
            "CWE-1321",
            "for-in merge без фильтра опасных ключей",
        ),
        mk(
            "PROTO-EASY-SAFE-01",
            "JS-PROTO-001",
            "easy",
            "safe",
            "app.js",
            """const target = {};
for (const k in src) {
  if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
  target[k] = src[k];
}""",
            None,
            "Явный фильтр ключей",
        ),
        mk(
            "PROTO-MED-VULN-01",
            "JS-PROTO-001",
            "medium",
            "vulnerable",
            "app.js",
            """app.post('/m', (req, res) => {
  const body = req.body;
  const out = {};
  for (const key in body) {
    out[key] = body[key];
  }
});""",
            "CWE-1321",
            "Слияние req.body",
        ),
        mk(
            "PROTO-MED-SAFE-01",
            "JS-PROTO-001",
            "medium",
            "safe",
            "app.js",
            """app.post('/m', (req, res) => {
  const body = req.body;
  const out = Object.create(null);
  for (const key of Object.keys(body)) {
    if (['__proto__', 'constructor', 'prototype'].includes(key)) continue;
    out[key] = body[key];
  }
});""",
            None,
            "Object.create(null) и фильтр",
        ),
        mk(
            "PROTO-HARD-VULN-01",
            "JS-PROTO-001",
            "hard",
            "vulnerable",
            "app.js",
            """function merge(dst, src) {
  for (const k in src) {
    dst[k] = src[k];
  }
}
app.get('/x', (req, res) => {
  const o = {};
  merge(o, req.query);
});""",
            "CWE-1321",
            "Helper merge",
        ),
        mk(
            "PROTO-HARD-SAFE-01",
            "JS-PROTO-001",
            "hard",
            "safe",
            "app.js",
            """function safeMerge(dst, src) {
  for (const k of Object.keys(src)) {
    if (k === '__proto__') continue;
    dst[k] = src[k];
  }
}
app.get('/x', (req, res) => {
  safeMerge({}, { a: 1 });
});""",
            None,
            "Безопасный merge без пользовательского объекта целиком",
        ),
        mk(
            "REDIR-EASY-VULN-01",
            "JS-REDIRECT-001",
            "easy",
            "vulnerable",
            "app.js",
            "res.redirect(req.query.next);",
            "CWE-601",
            "Редирект на пользовательский URL",
        ),
        mk(
            "REDIR-EASY-SAFE-01",
            "JS-REDIRECT-001",
            "easy",
            "safe",
            "app.js",
            "res.redirect('/dashboard');",
            None,
            "Константный путь",
        ),
        mk(
            "REDIR-MED-VULN-01",
            "JS-REDIRECT-001",
            "medium",
            "vulnerable",
            "app.js",
            """app.get('/go', (req, res) => {
  const u = req.body.url;
  if (u) {
    res.redirect(u);
  }
});""",
            "CWE-601",
            "redirect из req.body",
        ),
        mk(
            "REDIR-MED-SAFE-01",
            "JS-REDIRECT-001",
            "medium",
            "safe",
            "app.js",
            """app.get('/go', (req, res) => {
  const page = req.query.p;
  const map = { home: '/home', about: '/about' };
  res.redirect(map[page] || '/home');
});""",
            None,
            "Только относительные пути из словаря",
        ),
        mk(
            "REDIR-HARD-VULN-01",
            "JS-REDIRECT-001",
            "hard",
            "vulnerable",
            "app.js",
            """function sendRedirect(res, loc) {
  res.redirect(loc);
}
app.get('/x', (req, res) => {
  sendRedirect(res, req.query.to);
});""",
            "CWE-601",
            "Inter-procedural redirect",
        ),
        mk(
            "REDIR-HARD-SAFE-01",
            "JS-REDIRECT-001",
            "hard",
            "safe",
            "app.js",
            """function sendRedirect(res, loc) {
  res.redirect(loc);
}
app.get('/x', (req, res) => {
  sendRedirect(res, '/ok');
});""",
            None,
            "Константа в helper",
        ),
    ]
