from eval.cases_pack._util import mk


def cases_special() -> list[dict]:
    return [
        mk(
            "SPECIAL-TAINT-INTERPROC-SQL",
            "JS-SQL-001",
            "hard",
            "vulnerable",
            "app.js",
            """function runQuery(q) {
  db.query(q);
}
app.get('/', (req, res) => {
  runQuery(`SELECT * FROM t WHERE x = '${req.body.name}'`);
});""",
            "CWE-89",
            "Классический same-file bare id (README-пример)",
            tags=["special:taint-interproc"],
        ),
        mk(
            "SPECIAL-TAINT-BOUNDARY-OBJMETHOD",
            "JS-SQL-001",
            "hard",
            "vulnerable",
            "app.js",
            """const svc = {
  run(q) {
    db.query(`SELECT 1 WHERE z = '${q}'`);
  },
};
app.get('/x', (req, res) => {
  svc.run(req.query.id);
});""",
            "CWE-89",
            ("Вызов obj.method(req): ограничение taint; AST может всё ещё дать finding"),
            tags=["special:taint-boundary"],
        ),
        mk(
            "SPECIAL-TS-SQL",
            "JS-SQL-001",
            "medium",
            "vulnerable",
            "routes.ts",
            """import type { Request, Response } from 'express';
export function h(req: Request, res: Response): void {
  const id: string = String(req.query.id);
  db.query(`SELECT * FROM users WHERE id = '${id}'`);
}""",
            "CWE-89",
            "Тот же SQL-паттерн в TypeScript",
            tags=["special:typescript"],
        ),
        mk(
            "SPECIAL-MULTI-VULN",
            "MULTI",
            "hard",
            "vulnerable",
            "app.js",
            """const { exec } = require('child_process');
app.get('/bad', (req, res) => {
  db.query(`SELECT * FROM u WHERE id = ${req.query.a}`);
  exec(`echo ${req.query.b}`);
  fetch(req.query.c);
});""",
            None,
            "Три разных класса в одном файле",
            expected_rule_ids=["JS-SQL-001", "JS-CMD-001", "JS-SSRF-001"],
            tags=["special:multi-vuln"],
        ),
        mk(
            "SPECIAL-LARGE-SAFE",
            "JS-SQL-001",
            "hard",
            "safe",
            "app.js",
            """const crypto = require('crypto');
function add(a, b) {
  return a + b;
}
function hash(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}
const x = add(1, 2);
const y = hash('hello');
const z = JSON.stringify({ a: 1, b: 2 });
console.log(x, y, z);
function greet(name) {
  return `Hello, ${name}`;
}
module.exports = { add, hash, greet };
const items = [1, 2, 3].map((n) => n * 2);
const sum = items.reduce((a, b) => a + b, 0);
const obj = { ...{ k: 1 }, m: 2 };
const keys = Object.keys(obj);
if (keys.length > 0) {
  console.log(keys[0]);
}
const p = new Promise((resolve) => resolve(1));
p.then((v) => v + 1);
async function af() {
  return 42;
}
void af();
""",
            None,
            "Длинный фрагмент без уязвимых sink'ов (ожидается 0 findings)",
            tags=["special:large-safe"],
        ),
        mk(
            "SPECIAL-EDGE-DESTRUCT",
            "JS-SQL-001",
            "medium",
            "vulnerable",
            "app.js",
            """app.get('/d', (req, res) => {
  const { id } = req.params;
  db.query(`SELECT * FROM t WHERE id = '${id}'`);
});""",
            "CWE-89",
            "Деструктуризация req.params",
            tags=["special:edge-taint"],
        ),
        mk(
            "SPECIAL-EDGE-SPREAD",
            "JS-NOSQL-001",
            "medium",
            "vulnerable",
            "app.js",
            """app.post('/s', (req, res) => {
  const q = { ...req.body, limit: 10 };
  users.find(q);
});""",
            "CWE-943",
            "spread req.body в объект запроса",
            tags=["special:edge-taint"],
        ),
        mk(
            "SPECIAL-EDGE-OPTIONAL",
            "JS-SSRF-001",
            "medium",
            "vulnerable",
            "app.js",
            "fetch(req?.query?.url);",
            "CWE-918",
            "optional chaining на req",
            tags=["special:edge-taint"],
        ),
        mk(
            "SPECIAL-DUP-LINE-SQL",
            "JS-SQL-001",
            "easy",
            "vulnerable",
            "app.js",
            "db.query(`SELECT * FROM u WHERE id = ${req.query.id}`);",
            "CWE-89",
            "Одна строка — ожидается возможный дубль AST+taint (наблюдение)",
            tags=["special:duplicate-observe"],
            notes_expected_count=2,
        ),
    ]
