from eval.cases_pack._util import mk


def cases_sql_cmd() -> list[dict]:
    return [
        mk(
            "SQL-EASY-VULN-01",
            "JS-SQL-001",
            "easy",
            "vulnerable",
            "app.js",
            "db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);",
            "CWE-89",
            "Прямой SQL-шаблон с req.query",
            notes_expected_count=2,
        ),
        mk(
            "SQL-EASY-SAFE-01",
            "JS-SQL-001",
            "easy",
            "safe",
            "app.js",
            "db.query('SELECT * FROM users WHERE id = $1', [req.query.id]);",
            None,
            "Параметризованный запрос",
        ),
        mk(
            "SQL-MED-VULN-01",
            "JS-SQL-001",
            "medium",
            "vulnerable",
            "app.js",
            """app.get('/u', (req, res) => {
  const sort = req.body.order;
  const q = `SELECT * FROM t ORDER BY ${sort}`;
  db.query(q);
});""",
            "CWE-89",
            "Промежуточные переменные и шаблонная строка",
        ),
        mk(
            "SQL-MED-SAFE-01",
            "JS-SQL-001",
            "medium",
            "safe",
            "app.js",
            """app.get('/u', (req, res) => {
  const id = req.query.id;
  db.query('SELECT * FROM users WHERE id = $1', [id]);
});""",
            None,
            "Конкатенация только в параметрах prepared",
        ),
        mk(
            "SQL-HARD-VULN-01",
            "JS-SQL-001",
            "hard",
            "vulnerable",
            "app.js",
            """function runQuery(dbConn, sqlText) {
  dbConn.query(sqlText);
}
function buildSql(userId) {
  return `DELETE FROM sessions WHERE uid = '${userId}'`;
}
app.get('/x', (req, res) => {
  const uid = req.params.id;
  const sql = buildSql(uid);
  runQuery(db, sql);
});""",
            "CWE-89",
            "Same-file inter-procedural bare id к sink",
        ),
        mk(
            "SQL-HARD-SAFE-01",
            "JS-SQL-001",
            "hard",
            "safe",
            "app.js",
            """function runQuery(dbConn, text, params) {
  dbConn.query(text, params);
}
app.get('/x', (req, res) => {
  const id = req.query.id;
  runQuery(db, 'SELECT 1 WHERE id = $1', [id]);
});""",
            None,
            "Inter-procedural с параметризованным запросом",
        ),
        mk(
            "CMD-EASY-VULN-01",
            "JS-CMD-001",
            "easy",
            "vulnerable",
            "app.js",
            "const { exec } = require('child_process');\nexec(`ls ${req.query.dir}`);",
            "CWE-78",
            "exec + template с пользователем",
            notes_expected_count=2,
        ),
        mk(
            "CMD-EASY-SAFE-01",
            "JS-CMD-001",
            "easy",
            "safe",
            "app.js",
            (
                "const { execFile } = require('child_process');\n"
                "execFile('/bin/ls', ['/tmp'], () => {});"
            ),
            None,
            "execFile с массивом аргументов",
        ),
        mk(
            "CMD-MED-VULN-01",
            "JS-CMD-001",
            "medium",
            "vulnerable",
            "app.js",
            """const { exec } = require('child_process');
app.get('/r', (req, res) => {
  const arg = req.body.cmd;
  let c = 'echo ok';
  if (req.query.debug) {
    c = `sh -c ${arg}`;
  }
  exec(c);
});""",
            "CWE-78",
            "Условие и промежуточная строка команды",
        ),
        mk(
            "CMD-MED-SAFE-01",
            "JS-CMD-001",
            "medium",
            "safe",
            "app.js",
            """const { execFile } = require('child_process');
app.get('/r', (req, res) => {
  const safe = '/usr/bin/true';
  execFile(safe, [], () => {});
});""",
            None,
            "Только константные пути",
        ),
        mk(
            "CMD-HARD-VULN-01",
            "JS-CMD-001",
            "hard",
            "vulnerable",
            "app.js",
            """const { exec } = require('child_process');
function runCmd(shellLine) {
  exec(shellLine);
}
function buildLine(u) {
  return `grep ${u} /etc/passwd`;
}
app.get('/s', (req, res) => {
  const line = buildLine(req.query.u);
  runCmd(line);
});""",
            "CWE-78",
            "Цепочка функций same-file",
        ),
        mk(
            "CMD-HARD-SAFE-01",
            "JS-CMD-001",
            "hard",
            "safe",
            "app.js",
            """const { execFile } = require('child_process');
function runBin(path, args) {
  execFile(path, args, () => {});
}
app.get('/s', (req, res) => {
  runBin('/bin/echo', ['static']);
});""",
            None,
            "execFile через helper",
        ),
    ]
