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

NEXT_SOURCES: list[TaintSource] = [
    TaintSource("searchParams", "nextjs", "Next.js App Router searchParams"),
    TaintSource("props.searchParams", "nextjs", "Next.js page searchParams prop"),
]

ALL_SOURCES: list[TaintSource] = (
    EXPRESS_SOURCES + KOA_SOURCES + FASTIFY_SOURCES + GENERIC_SOURCES + NEXT_SOURCES
)

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
    TaintSink("prisma.$queryRawUnsafe", "sql", "Prisma unsafe raw query"),
    TaintSink("prisma.$executeRawUnsafe", "sql", "Prisma unsafe raw execute"),
]

COMMAND_SINKS: list[TaintSink] = [
    TaintSink("exec", "command", "OS command execution"),
    TaintSink("execSync", "command", "Synchronous OS command"),
    TaintSink("eval", "command", "Dynamic code evaluation"),
    TaintSink("Function", "command", "Function constructor (dynamic code evaluation)"),
    TaintSink("setTimeout", "command", "setTimeout with string callback (code evaluation)"),
    TaintSink("setInterval", "command", "setInterval with string callback (code evaluation)"),
]

# Only the first arg of timer sinks is evaluated as code; later args are delay/options.
TIMER_STRING_ARG_SINKS: frozenset[str] = frozenset({"setTimeout", "setInterval"})

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

NOSQL_SINK_METHODS: frozenset[str] = frozenset(
    {
        "find",
        "findOne",
        "findOneAndUpdate",
        "updateOne",
        "deleteOne",
        "aggregate",
    }
)

HTTP_METHOD_SINKS: frozenset[str] = frozenset(
    {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "request",
    }
)

# Only well-known HTTP client receivers (avoid Map.get, headers.get, generic client/api).
HTTP_RECEIVER_ALLOWLIST: frozenset[str] = frozenset(
    {
        "axios",
        "http",
        "https",
        "fetch",
        "request",
        "got",
        "superagent",
        "httpClient",
        "undici",
        "needle",
    }
)

# DB / ORM receivers for SQL method sinks (*.query, etc.).
SQL_RECEIVER_ALLOWLIST: frozenset[str] = frozenset(
    {
        "db",
        "dbConn",
        "pool",
        "connection",
        "conn",
        "client",
        "sequelize",
        "knex",
        "prisma",
        "pg",
        "mysql",
        "mysql2",
        "sqlite",
        "database",
        "sql",
    }
)

# Mongo / ODM-style receivers for NoSQL method sinks (avoid Array.prototype.find).
NOSQL_RECEIVER_ALLOWLIST: frozenset[str] = frozenset(
    {
        "collection",
        "col",
        "model",
        "Model",
        "db",
        "mongo",
        "mongodb",
        "mongoose",
        "users",
        "User",
        "docs",
        "documents",
    }
)
