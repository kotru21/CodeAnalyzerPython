# Analyzer Service

Static vulnerability analyzer for JavaScript/TypeScript code. Parses JS/TS via tree-sitter, runs AST-based rules + intra-procedural taint analysis, enriches findings with CWE data.

## Quick Start

### Local Development

```bash
pip install -e ".[dev]"
uvicorn analyzer.main:app --reload --port 8000
```

### Docker

```bash
docker-compose up --build
```

### Run Tests

```bash
pytest tests/ -v
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/analyze/sync` | Synchronous analysis (< 50 KB) |
| POST | `/api/v1/analyze/async` | Async analysis via Celery |
| GET | `/api/v1/results/{scan_id}` | Get scan results |
| GET | `/api/v1/rules` | List available rules |
| GET | `/api/v1/health` | Health check |

## Example

```bash
curl -X POST http://localhost:8000/api/v1/analyze/sync \
  -H "Content-Type: application/json" \
  -d '{
    "source_code": "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);",
    "file_path": "app.js"
  }'
```

## Rules

| Rule ID | Vulnerability | Severity |
|---------|--------------|----------|
| JS-SQL-001 | SQL Injection | CRITICAL |
| JS-CMD-001 | Command Injection | CRITICAL |
| JS-XSS-001 | Reflected XSS | HIGH |
| JS-XSS-002 | dangerouslySetInnerHTML | HIGH |
| JS-PATH-001 | Path Traversal | HIGH |
| JS-PROTO-001 | Prototype Pollution | HIGH |
| JS-SEC-001 | Hardcoded Secrets | HIGH |
| JS-DES-001 | Insecure Deserialization | HIGH |
| JS-NOSQL-001 | NoSQL Injection | HIGH |
| JS-SSRF-001 | SSRF | HIGH |
| JS-CRYPTO-001 | Weak Cryptography | MEDIUM |
| JS-REDIRECT-001 | Open Redirect | MEDIUM |
| JS-REDOS-001 | Regular Expression DoS | MEDIUM |

## Architecture

```
src/analyzer/
├── api/            # FastAPI router, schemas, dependencies
├── core/           # Orchestrator, language detection, severity
├── knowledge/      # CWE database + mapping
├── models/         # SQLAlchemy ORM models (Scan, Finding)
├── parsers/        # tree-sitter JS/TS parsers
├── rules/          # 13 AST-based vulnerability rules
├── taint/          # Intra-procedural taint tracker
├── utils/          # Hashing helpers
└── workers/        # Celery async tasks
```

## Configuration

All settings can be overridden via environment variables with the `ANALYZER_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `ANALYZER_DATABASE_URL` | `postgresql://analyzer:analyzer@localhost:5432/analyzer` | PostgreSQL connection |
| `ANALYZER_REDIS_URL` | `redis://localhost:6379/0` | Redis connection |
| `ANALYZER_CELERY_BROKER_URL` | `redis://localhost:6379/1` | Celery broker |
| `ANALYZER_CELERY_RESULT_BACKEND` | `redis://localhost:6379/2` | Celery results |
| `ANALYZER_MAX_SYNC_SOURCE_BYTES` | `50000` | Max source size for sync endpoint |

## License

MIT
