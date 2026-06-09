from dataclasses import dataclass


@dataclass(frozen=True)
class TaintSource:
    pattern: str
    framework: str
    description: str


@dataclass(frozen=True)
class TaintSink:
    pattern: str
    category: str
    description: str


EXPRESS_SOURCES: list[TaintSource] = [
    TaintSource("req.params", "express", "URL path parameters"),
    TaintSource("req.query", "express", "URL query parameters"),
    TaintSource("req.body", "express", "Request body"),
    TaintSource("req.headers", "express", "Request headers"),
    TaintSource("req.cookies", "express", "Request cookies"),
    TaintSource("req.files", "express", "Multer multi-file uploads"),
    TaintSource("req.file", "express", "Multer single-file upload"),
]

KOA_SOURCES: list[TaintSource] = [
    TaintSource("ctx.request.body", "koa", "Request body"),
    TaintSource("ctx.params", "koa", "URL parameters"),
    TaintSource("ctx.query", "koa", "Query string"),
    TaintSource("ctx.request.query", "koa", "Query string"),
]

FASTIFY_SOURCES: list[TaintSource] = [
    TaintSource("request.params", "fastify", "URL parameters"),
    TaintSource("request.query", "fastify", "Query string"),
    TaintSource("request.body", "fastify", "Request body"),
]

GENERIC_SOURCES: list[TaintSource] = [
    TaintSource("process.argv", "node", "Command line arguments"),
    TaintSource("process.env", "node", "Environment variables (partial taint)"),
]

ALL_SOURCES: list[TaintSource] = EXPRESS_SOURCES + KOA_SOURCES + FASTIFY_SOURCES + GENERIC_SOURCES

SOURCE_PATTERNS: frozenset[str] = frozenset(s.pattern for s in ALL_SOURCES)

WEAK_SOURCE_PATTERNS: frozenset[str] = frozenset({"process.env"})


def is_weak_source(pattern: str) -> bool:
    return pattern in WEAK_SOURCE_PATTERNS


SQL_SINKS: list[TaintSink] = [
    TaintSink("db.query", "sql", "Database query"),
    TaintSink("pool.query", "sql", "Database pool query"),
    TaintSink("connection.query", "sql", "Database connection query"),
    TaintSink("sequelize.query", "sql", "Sequelize raw query"),
    TaintSink("knex.raw", "sql", "Knex raw query"),
    TaintSink("prisma.$queryRaw", "sql", "Prisma raw query (tagged template / call)"),
    TaintSink("prisma.$executeRaw", "sql", "Prisma raw execute"),
]

COMMAND_SINKS: list[TaintSink] = [
    TaintSink("exec", "command", "OS command execution"),
    TaintSink("execSync", "command", "Synchronous OS command"),
    TaintSink("eval", "command", "Dynamic code evaluation"),
]

XSS_SINKS: list[TaintSink] = [
    TaintSink("innerHTML", "xss", "DOM innerHTML assignment"),
    TaintSink("outerHTML", "xss", "DOM outerHTML assignment"),
    TaintSink("document.write", "xss", "Document write"),
    TaintSink("res.send", "xss", "Express response send"),
]

FS_SINKS: list[TaintSink] = [
    TaintSink("fs.readFile", "path", "File system read"),
    TaintSink("fs.readFileSync", "path", "Synchronous file read"),
    TaintSink("fs.writeFile", "path", "File system write"),
    TaintSink("fs.writeFileSync", "path", "Synchronous file write"),
]

HTTP_SINKS: list[TaintSink] = [
    TaintSink("fetch", "ssrf", "HTTP fetch request"),
    TaintSink("axios.get", "ssrf", "Axios GET request"),
    TaintSink("axios.post", "ssrf", "Axios POST request"),
    TaintSink("http.get", "ssrf", "HTTP GET request"),
    TaintSink("http.request", "ssrf", "HTTP request"),
]

REDIRECT_SINKS: list[TaintSink] = [
    TaintSink("res.redirect", "redirect", "Express redirect"),
]

ALL_SINKS: list[TaintSink] = (
    SQL_SINKS + COMMAND_SINKS + XSS_SINKS + FS_SINKS + HTTP_SINKS + REDIRECT_SINKS
)

SINK_METHODS: frozenset[str] = frozenset(s.pattern.split(".")[-1] for s in ALL_SINKS)

SINK_IDENTIFIERS: frozenset[str] = frozenset(s.pattern for s in ALL_SINKS if "." not in s.pattern)

SINK_MEMBER_PATTERNS: frozenset[str] = frozenset(s.pattern for s in ALL_SINKS if "." in s.pattern)

# Any `receiver.query(...)` / `.$queryRaw` / etc. (covers `dbConn.query` and similar).
SQL_SINK_METHOD_NAMES: frozenset[str] = frozenset(
    s.pattern.split(".")[-1] for s in SQL_SINKS if "." in s.pattern
)

COMMAND_SINK_METHOD_NAMES: frozenset[str] = frozenset(s.pattern for s in COMMAND_SINKS)
