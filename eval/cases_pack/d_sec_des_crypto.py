from eval.cases_pack._util import mk


def cases_sec_des_crypto() -> list[dict]:
    return [
        mk(
            "SEC-EASY-VULN-01",
            "JS-SEC-001",
            "easy",
            "vulnerable",
            "config.js",
            "const apiKey = 'HARDCODED_BENCHMARK_SECRET_NOT_A_REAL_VENDOR_KEY';",
            "CWE-798",
            "Хардкод ключа",
        ),
        mk(
            "SEC-EASY-SAFE-01",
            "JS-SEC-001",
            "easy",
            "safe",
            "config.js",
            "const apiKey = process.env.API_KEY;",
            None,
            "Секрет из окружения",
        ),
        mk(
            "SEC-MED-VULN-01",
            "JS-SEC-001",
            "medium",
            "vulnerable",
            "config.js",
            """const cfg = {
  password: 'MyVerySecretPassword2024!',
  host: 'db.local',
};""",
            "CWE-798",
            "Секрет в объекте",
        ),
        mk(
            "SEC-MED-SAFE-01",
            "JS-SEC-001",
            "medium",
            "safe",
            "config.js",
            """const cfg = {
  password: process.env.DB_PASSWORD,
  host: 'db.local',
};""",
            None,
            "Пароль из env",
        ),
        mk(
            "SEC-HARD-VULN-01",
            "JS-SEC-001",
            "hard",
            "vulnerable",
            "config.js",
            """function loadSecrets() {
  const token = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789';
  return token;
}
module.exports = { loadSecrets };""",
            "CWE-798",
            "Секрет внутри функции",
        ),
        mk(
            "SEC-HARD-SAFE-01",
            "JS-SEC-001",
            "hard",
            "safe",
            "config.js",
            """function loadSecrets() {
  return process.env.GITHUB_TOKEN;
}
module.exports = { loadSecrets };""",
            None,
            "Токен только из env",
        ),
        mk(
            "DES-EASY-VULN-01",
            "JS-DES-001",
            "easy",
            "vulnerable",
            "app.js",
            "eval(Buffer.from(req.body.payload, 'base64').toString());",
            "CWE-502",
            "eval над декодированным буфером",
        ),
        mk(
            "DES-EASY-SAFE-01",
            "JS-DES-001",
            "easy",
            "safe",
            "app.js",
            "const x = JSON.parse('{\"a\":1}');",
            None,
            "JSON.parse литерала",
        ),
        mk(
            "DES-MED-VULN-01",
            "JS-DES-001",
            "medium",
            "vulnerable",
            "app.js",
            """app.post('/x', (req, res) => {
  const raw = req.body.data;
  eval(Buffer.from(raw, 'base64').toString());
});""",
            "CWE-502",
            "req.body в eval/Buffer",
        ),
        mk(
            "DES-MED-SAFE-01",
            "JS-DES-001",
            "medium",
            "safe",
            "app.js",
            """app.post('/x', (req, res) => {
  const raw = req.body.json;
  const obj = JSON.parse(raw);
  res.json(obj);
});""",
            None,
            "JSON.parse без eval",
        ),
        mk(
            "DES-HARD-VULN-01",
            "JS-DES-001",
            "hard",
            "vulnerable",
            "app.js",
            """function runUserCode(buf) {
  eval(Buffer.from(buf, 'hex').toString());
}
app.get('/y', (req, res) => {
  runUserCode(req.query.q);
});""",
            "CWE-502",
            "Inter-procedural eval+Buffer",
        ),
        mk(
            "DES-HARD-SAFE-01",
            "JS-DES-001",
            "hard",
            "safe",
            "app.js",
            """function parseJson(s) {
  return JSON.parse(s);
}
app.get('/y', (req, res) => {
  parseJson('{}');
});""",
            None,
            "Только статический JSON",
        ),
        mk(
            "CRYPTO-EASY-VULN-01",
            "JS-CRYPTO-001",
            "easy",
            "vulnerable",
            "app.js",
            (
                "const crypto = require('crypto');\n"
                "crypto.createHash('md5').update('x').digest('hex');"
            ),
            "CWE-327",
            "MD5",
        ),
        mk(
            "CRYPTO-EASY-SAFE-01",
            "JS-CRYPTO-001",
            "easy",
            "safe",
            "app.js",
            (
                "const crypto = require('crypto');\n"
                "crypto.createHash('sha256').update('x').digest('hex');"
            ),
            None,
            "SHA-256",
        ),
        mk(
            "CRYPTO-MED-VULN-01",
            "JS-CRYPTO-001",
            "medium",
            "vulnerable",
            "app.js",
            """const crypto = require('crypto');
app.get('/t', (req, res) => {
  const h = crypto.createHash('sha1');
  h.update(req.query.s);
  res.send(h.digest('hex'));
});""",
            "CWE-327",
            "SHA1",
        ),
        mk(
            "CRYPTO-MED-SAFE-01",
            "JS-CRYPTO-001",
            "medium",
            "safe",
            "app.js",
            """const crypto = require('crypto');
app.get('/t', (req, res) => {
  const h = crypto.createHash('sha512');
  h.update(req.query.s);
  res.send(h.digest('hex'));
});""",
            None,
            "SHA-512",
        ),
        mk(
            "CRYPTO-HARD-VULN-01",
            "JS-CRYPTO-001",
            "hard",
            "vulnerable",
            "app.js",
            """const crypto = require('crypto');
function makeCipher() {
  return crypto.createCipheriv('des-ede3-cbc', Buffer.alloc(24), Buffer.alloc(8));
}
makeCipher();""",
            "CWE-327",
            "3DES",
        ),
        mk(
            "CRYPTO-HARD-SAFE-01",
            "JS-CRYPTO-001",
            "hard",
            "safe",
            "app.js",
            """const crypto = require('crypto');
function token() {
  return crypto.randomBytes(16).toString('hex');
}
token();""",
            None,
            "randomBytes",
        ),
    ]
