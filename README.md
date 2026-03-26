# Analyzer Service

Static vulnerability analyzer for JavaScript/TypeScript code. Parses JS/TS via tree-sitter, runs AST-based rules + taint analysis (intra-procedural and **limited same-file inter-procedural** calls), enriches findings with CWE data.

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
| POST | `/api/v1/analyze/sync` | Synchronous analysis (< 50 KB); JSON or SARIF (see below) |
| POST | `/api/v1/analyze/async` | Async analysis via Celery; poll `GET /results/{scan_id}` |
| GET | `/api/v1/results/{scan_id}` | Async status: `pending`, or completed body (same shape as sync JSON), or `failed` |
| GET | `/api/v1/rules` | List available rules |
| GET | `/api/v1/health` | Health check |

### Sync response formats

- Default JSON: same `AnalyzeResponse` as before, plus **`failed_rules`**: rule IDs whose `run()` raised (other rules still execute).
- SARIF: set `"response_format": "sarif"` on the request. Response **`Content-Type: application/sarif+json`** (SARIF 2.1.0 log). OpenAPI documents the JSON branch only; SARIF is described here.

### Async polling

1. `POST /api/v1/analyze/async` returns `scan_id` and `poll_url`.
2. `GET /api/v1/results/{scan_id}`:
   - **404** if the `scan_id` is unknown or not a UUID.
   - **200** `{ "status": "pending", "scan_id": "..." }` while the Celery task is queued/running.
   - **200** completed: same fields as sync JSON (including `findings`, `stats`, …) with **`"status": "completed"`**.
   - **200** `{ "status": "failed", "scan_id": "...", "error": "..." }` on task failure.
   - **503** if Redis is unavailable.

## Example request

```bash
curl -X POST http://localhost:8000/api/v1/analyze/sync \
  -H "Content-Type: application/json" \
  -d '{
    "source_code": "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);",
    "file_path": "app.js",
    "config": { "enable_taint": true }
  }'
```

## Example code snippets and scanner output

All examples assume `POST /api/v1/analyze/sync` with `Content-Type: application/json` and `"config": { "enable_taint": true }` unless noted. Responses are abbreviated (same `scan_id`/`created_at` shape as real API).

### 1. SQL injection (template literal + user input)

**Input `source_code`:**

```javascript
app.get('/users', (req, res) => {
  db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
});
```

**Typical output:** `stats.total_findings` is **2** for the same line — once from the **AST rule** (`JS-SQL-001`) and once from **taint** (`req.params` → `query`). Both are `severity: critical`, `rule_id: "JS-SQL-001"`, `cwe_id: "CWE-89"`. Descriptions may be enriched from the local CWE XML if configured.

```json
{
  "status": "completed",
  "language": "javascript",
  "stats": {
    "total_findings": 2,
    "critical": 2,
    "files_scanned": 1
  },
  "findings": [
    {
      "rule_id": "JS-SQL-001",
      "title": "SQL Injection via template literal or string concatenation",
      "severity": "critical",
      "line_start": 2,
      "code_snippet": "  db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);",
      "cwe_id": "CWE-89"
    }
  ],
  "failed_rules": []
}
```

*(Second finding is structurally similar; consider deduplication in the client if one report per line is enough.)*

### 2. Command injection

**Input `source_code`:**

```javascript
const { exec } = require('child_process');
app.get('/run', (req, res) => {
  exec(`ls ${req.query.dir}`);
});
```

**Typical output:** `JS-CMD-001`, `CWE-78`, again often **2** hits on the same line (rule + taint).

### 3. Clean code (no issues)

**Input `source_code`:**

```javascript
const x = 1 + 2;
console.log(x);
```

**Typical output:**

```json
{
  "status": "completed",
  "language": "javascript",
  "stats": { "total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0 },
  "findings": [],
  "failed_rules": []
}
```

### 4. Same-file inter-procedural taint (helper function)

**Input `source_code`:**

```javascript
function runQuery(q) {
  db.query(q);
}
app.get('/', (req, res) => {
  runQuery(req.body);
});
```

**Typical output:** at least one **`JS-SQL-001`** finding on the `db.query` line, driven by taint through the `runQuery` parameter (with `enable_taint: true`).

## Rules

| Rule ID | Vulnerability | Severity |
|---------|---------------|----------|
| JS-SQL-001 | SQL Injection | CRITICAL |
| JS-XSS-001 | Reflected XSS | HIGH |
| JS-XSS-002 | dangerouslySetInnerHTML | HIGH |
| JS-CMD-001 | Command Injection | CRITICAL |
| JS-PATH-001 | Path Traversal | HIGH |
| JS-PROTO-001 | Prototype Pollution | HIGH |
| JS-SEC-001 | Hardcoded Secrets | HIGH |
| JS-DES-001 | Insecure Deserialization | HIGH |
| JS-CRYPTO-001 | Weak Cryptography | MEDIUM |
| JS-REDIRECT-001 | Open Redirect | MEDIUM |
| JS-NOSQL-001 | NoSQL Injection | HIGH |
| JS-SSRF-001 | SSRF | HIGH |
| JS-REDOS-001 | ReDoS | MEDIUM |

## Taint analysis

- **Sources:** Express-style `req.*` (including Multer `req.file` / `req.files`), Koa, Fastify, `process.*`, etc. — see `src/analyzer/taint/sources_sinks.py`.
- **Sinks:** SQL (`db.query`, Prisma `$queryRaw` / `$executeRaw`, …), `exec`/`eval`, `fs.*`, redirects, etc.
- **Parameterized SQL:** for calls like `db.query('… $1 …', [values])`, taint only in the values argument is treated as binding, not as SQL text injection (see `tracker.py`).
- **Same-file inter-procedural:** if the callee is a bare identifier (`run(x)`), the analyzer binds taint from actual arguments into the callee’s parameters and re-walks that function body (depth capped at `MAX_INTERPROC_DEPTH` in `tracker.py`, default 5). **Not supported:** `obj.method()`, optional chaining, cross-file calls.
- **Pattern overlap:** longer `req.*` patterns are preferred (e.g. `req.files` over `req.file`) when both match.
- **Tests:** `tests/test_taint/test_taint_sources_sinks_matrix.py`, `tests/test_taint/test_taint_interprocedural.py`, `tests/test_taint/test_js_taint.py`.

## Evaluation benchmark

Single-file HTTP benchmark for precision/recall style scoring (see `docs/superpowers/plans/2026-03-26-analyzer-effectiveness-evaluation.md`).

1. Regenerate the JSON catalog after editing Python case definitions: `py -3 -m eval.build_cases`
2. Start the stack: `docker compose up --build` (needs API on port 8000 and, for async checks, the `worker` service)
3. Run sync scans and write `eval/results/report.md` plus raw JSON: `py -3 -m eval.cli run --base-url http://localhost:8000` (or `py -3 -m eval.run_evaluation …`, same flags)
4. Optional multi-backend compare (Semgrep + HTTP analyzer): `py -3 -m eval.cli compare --base-url http://localhost:8000` (needs Semgrep on PATH and entries in `eval/catalog/rule_map.yaml`, or pass `--semgrep-config <path>`). This writes `eval/results/compare_summary.json`. When both the HTTP analyzer and Semgrep backends run, each non-skipped row can include **`line_overlap`**: greedy line-level pairing between the two tools under the **equivalence mapping** in `rule_map.yaml` (`equivalence_rules` lists which Semgrep `check_id` strings are in scope per analyzer `rule_id`, with optional top-level `line_slop` for near matches). Treat these fields as **mapping-dependent agreement**, not ground-truth security labels. For catalog cases with **`type: safe`**, `line_overlap.analyzer_lines` is always empty by design; non-empty Semgrep lines there are a benchmark signal only, not an automatic false-positive verdict.
5. SARIF smoke: `py -3 -m eval.sarif_smoke --base-url http://localhost:8000`
6. Async vs sync comparison: `py -3 -m eval.async_compare --base-url http://localhost:8000`
7. **Semgrep cross-check (optional):** clone [semgrep-rules](https://github.com/semgrep/semgrep-rules), install the [Semgrep CLI](https://semgrep.dev/docs/getting-started/), then run `scripts/semgrep_corpus_compare.py` (see module docstring). Point `--corpus` at e.g. `semgrep-rules/javascript`; for **NodeGoat**, use the same script with `--corpus` set to the cloned app source and a JS rule pack as `--semgrep-config`.

### Semgrep-rules `javascript/` snapshot (reference)

Recorded on one machine for **orientation only**: Semgrep and this service use different rule sets and severities, so totals are **not** precision/recall against a shared ground truth.

| Item | Value |
|------|--------|
| **Corpus** | [semgrep-rules](https://github.com/semgrep/semgrep-rules) path `javascript/`, shallow clone **`28db38e`** |
| **Files** | 174 (`.js` / `.jsx` / `.ts` / `.tsx` under that tree) |
| **Semgrep** | CLI **1.156.0**, `--config` = same `javascript/` tree, **897** result rows (matches) |
| **This analyzer** | API **0.1.0**, **13** rules, taint on, **215** findings summed over the same files (single-file `POST /api/v1/analyze/sync` per file) |
| **Per-file overlap** | **50** files where both tools had ≥1 finding; **124** Semgrep-only; **0** analyzer-only |
| **HTTP errors** | **0** |
| **Raw output** | `eval/results/semgrep_compare.json` (gitignored; regenerate with the script) |

`eval/results/*.json` and `report.md` are gitignored; committed sources live under `eval/catalog/` and `eval/cases_pack/`.

## Architecture

```
src/analyzer/
├── api/           # FastAPI router, schemas, dependencies
├── core/          # Orchestrator, language detection, severity
├── export/        # SARIF log builder
├── knowledge/     # CWE database + rule taxonomy helpers
├── models/        # SQLAlchemy ORM models (Scan, Finding)
├── parsers/       # tree-sitter JS/TS parsers
├── rules/         # AST-based vulnerability rules
├── services/      # Redis scan_id → Celery task registry
├── taint/         # Taint tracker (sources/sinks + limited inter-procedural)
├── utils/         # Hashing utilities
└── workers/       # Celery async scan tasks
```

## Configuration

Environment variables (prefix `ANALYZER_`):

| Variable | Default | Description |
|----------|---------|-------------|
| `ANALYZER_DATABASE_URL` | `postgresql://analyzer:analyzer@localhost:5432/analyzer` | PostgreSQL connection |
| `ANALYZER_REDIS_URL` | `redis://localhost:6379/0` | Redis connection |
| `ANALYZER_CELERY_BROKER_URL` | `redis://localhost:6379/1` | Celery broker |
| `ANALYZER_CELERY_RESULT_BACKEND` | `redis://localhost:6379/2` | Celery result store |
| `ANALYZER_MAX_SYNC_SOURCE_BYTES` | `50000` | Max size for sync endpoint |
| `ANALYZER_DEBUG` | `false` | Debug mode |
| `ANALYZER_SCAN_TASK_REGISTRY_TTL_SECONDS` | `604800` | Redis TTL for async `scan_id` → task id mapping |
| `ANALYZER_CORS_ORIGINS` | `[]` | JSON array of allowed browser origins (e.g. `["http://localhost:5173"]`); must not include `*` |
| `ANALYZER_SARIF_INFORMATION_URI` | (unset) | Optional `informationUri` in SARIF `tool.driver` |
