from eval.cases_pack._util import mk


def cases_jwt_cookies() -> list[dict]:
    return [
        mk(
            "JWT-EASY-VULN-01",
            "JS-JWT-001",
            "easy",
            "vulnerable",
            "app.js",
            (
                "const jwt = require('jsonwebtoken');\n"
                "jwt.sign({ id: 1 }, 'secret', { algorithm: 'none' });"
            ),
            "CWE-347",
            "JWT algorithm none",
        ),
        mk(
            "JWT-EASY-SAFE-01",
            "JS-JWT-001",
            "easy",
            "safe",
            "app.js",
            (
                "const jwt = require('jsonwebtoken');\n"
                "jwt.sign({ id: 1 }, 'secret', { algorithm: 'HS256' });"
            ),
            None,
            "JWT algorithm HS256",
        ),
        mk(
            "COOKIE-EASY-VULN-01",
            "JS-COOKIE-001",
            "easy",
            "vulnerable",
            "app.js",
            "res.cookie('sid', 'abc', { httpOnly: false });",
            "CWE-1004",
            "Cookie httpOnly false",
        ),
        mk(
            "COOKIE-EASY-SAFE-01",
            "JS-COOKIE-001",
            "easy",
            "safe",
            "app.js",
            "res.cookie('sid', 'abc', { httpOnly: true });",
            None,
            "Cookie httpOnly true",
        ),
    ]
