# Analyzer Service

[![Eval Catalog](https://github.com/kotru21/CodeAnalyzerPython/actions/workflows/eval.yml/badge.svg)](https://github.com/kotru21/CodeAnalyzerPython/actions/workflows/eval.yml)
[![Python](https://img.shields.io/badge/python-3.12%2B%20%7C%20CI%2FDocker%203.14-blue?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.141+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Celery](https://img.shields.io/badge/Celery-Redis%20broker-37B24D?logo=celery&logoColor=white)](https://docs.celeryq.dev/)
[![Ruff](https://img.shields.io/badge/linter-ruff-D7FF64?logo=ruff&logoColor=black)](https://docs.astral.sh/ruff/)
[![mypy](https://img.shields.io/badge/types-mypy-blue)](https://mypy-lang.org/)

Static vulnerability analyzer for JavaScript/TypeScript code. Parses JS/TS via tree-sitter, runs AST-based rules + taint analysis (intra-procedural and **limited same-file inter-procedural** calls), enriches findings with CWE data.

## Quick Start

### Local Development

Requires Python **3.12+** (`requires-python`). CI and Docker images use **3.14**.

```bash
pip install -e ".[dev]"
uvicorn analyzer.main:app --reload --port 8000
```

### Docker

```bash
cp .env.example .env   # set strong POSTGRES_PASSWORD / REDIS_PASSWORD / ANALYZER_API_KEY (non-empty)
docker compose up --build
```

Postgres and Redis are **not** published to the host (internal Docker network only). Compose **requires** a non-empty `ANALYZER_API_KEY` (`${ANALYZER_API_KEY:?…}` fails if empty). Send `X-API-Key` on analyze/results/rules. Local open mode without compose: `ANALYZER_DEBUG=true` and unset key for uvicorn/pytest.

### Run Tests

```bash
pytest tests/ -v
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/analyze/sync` | Synchronous analysis (< 50 KB); JSON or SARIF (see below) |
| POST | `/api/v1/analyze/bundle/sync` | Multi-file JSON body (`files` map); relative import fn index (+ optional `tsconfig_paths`); caps via `ANALYZER_MAX_BUNDLE_*` |
| POST | `/api/v1/analyze/async` | Async analysis via Celery; poll `GET /results/{scan_id}` |
| GET | `/api/v1/results/{scan_id}` | Async status from Postgres: `pending`/`running`, or completed/`partial` body, or `failed` |
| GET | `/api/v1/rules` | List available rules |
| GET | `/api/v1/health` | Health check |

### Sync response formats

- Default JSON: same `AnalyzeResponse` as before, plus **`failed_rules`**: rule IDs whose `run()` raised (other rules still execute).
- SARIF: set `"response_format": "sarif"` on the request. Response **`Content-Type: application/sarif+json`** (SARIF 2.1.0 log). OpenAPI documents the JSON branch only; SARIF is described here.

### Async polling

1. `POST /api/v1/analyze/async` returns `scan_id`, `poll_url`, and **`status: "queued"`** (legacy client value). The DB row is `pending` until the worker sets `running` / a terminal status. Source is stored in Redis and also passed in the task args for rolling upgrades.
2. `GET /api/v1/results/{scan_id}` (Postgres is source of truth):
   - **404** if the `scan_id` is unknown or not a UUID.
   - **200** `{ "status": "pending"|"running", "scan_id": "..." }` while queued/running.
   - **200** completed/`partial`: same fields as sync JSON (`findings`, `stats`, …). `partial` means the wall-clock analysis budget was hit.
   - **200** `{ "status": "failed", "scan_id": "...", "error": "...", "error_code": "..." }` on failure.
   - **503** if the database is unavailable.

## Example request

```bash
curl -X POST http://localhost:8000/api/v1/analyze/sync \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $ANALYZER_API_KEY" \
  -d '{
    "source_code": "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);",
    "file_path": "app.js",
    "config": { "enable_taint": true }
  }'
```

Omit `X-API-Key` only when `ANALYZER_DEBUG=true` and `ANALYZER_API_KEY` is unset (local pytest / open local uvicorn). Non-debug mode requires a key.

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
| JS-XSS-001 | Reflected XSS (DOM) | HIGH |
| JS-XSS-002 | dangerouslySetInnerHTML | HIGH |
| JS-XSS-003 | Reflected XSS (response send) | HIGH |
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
- **Same-file inter-procedural:** taint is bound from call arguments into the callee’s parameters when the callee resolves to an indexed function—either a bare identifier (`run(x)`) or a **member call** whose **property name** matches a same-file top-level or `const`/`var` function (`o.run(x)` → `function run` / `const run = …`). Depth is capped at `MAX_INTERPROC_DEPTH` in `tracker.py` (default 5). **Optional chaining** (`req?.body`, `db?.query`) is normalized for source/sink pattern matching. **Return taint:** `const x = foo()` walks `foo`’s body and uses the first `return` expression to mark `x` tainted when arguments carry taint (same depth cap). **Template literals:** `${...}` inside templates is analyzed via `template_substitution` nodes. **Object spread:** `{ ...req.body }` is treated as tainted when the spread operand matches request-source patterns. **SQL sinks:** `receiver.query(...)` when receiver is on the SQL allowlist (`db`, `pool`, `dbConn`, …); `ANALYZER_SQL_SINK_ALLOWLIST=false` restores any-receiver mode. **Multi-file (bundle API):** per-file function index plus resolved relative `require`/`import` (and `index.js` / optional `tsconfig_paths`); not a full merge of every bundle path. **Not supported:** object-literal method shorthand unless indexed; unresolved package imports outside the `files` map.
- **Pattern overlap:** longer `req.*` patterns are preferred (e.g. `req.files` over `req.file`) when both match.
- **Tests:** `tests/test_taint/test_taint_sources_sinks_matrix.py`, `tests/test_taint/test_taint_interprocedural.py`, `tests/test_taint/test_js_taint.py`.

## Evaluation benchmark

Single-file HTTP benchmark for precision/recall style scoring (see `docs/superpowers/plans/2026-03-26-analyzer-effectiveness-evaluation.md`).

### Internal catalog dataset (`eval/cases_pack` → `eval/catalog/cases.json`)

This is a **project-owned** set of small synthetic snippets (one “file” per `test_id`), maintained in **`eval/cases_pack/`** and exported to **`eval/catalog/cases.json`** via `eval.build_cases`. Labels (`type: vulnerable|safe`, expected rule/CWE) are **for this repo only**.

**Role:** **regression and development**—track TP/TN/FN/FP against those labels, and (with `eval.cli compare`) check **line_overlap** vs Semgrep on the **same** snippets. It is **not** a standalone, citable real-world benchmark.

### External tree run (`corpus_paper_eval`) — Semgrep agreement, not gold labels

**Second evaluation track:** scan a **directory tree** you choose (JS/TS files) with Semgrep and the HTTP analyzer, then summarize **line-level agreement** in `corpus_eval_summary.json`. There is **no** project TP/FN oracle here—only counts like matched lines vs Semgrep under **Policy A/B** (see `docs/superpowers/specs/2026-03-26-external-js-ts-corpus-semgrep-design.md`).

The repo often uses a clone of **[semgrep-rules](https://github.com/semgrep/semgrep-rules) `javascript/`** as a **convenience corpus** (mostly rule examples and test snippets—not a CVE-labeled benchmark). For a thesis/paper, point `--corpus` at a **frozen, citable** snapshot instead.

1. Regenerate the JSON catalog after editing Python case definitions: `py -3 -m eval.build_cases`
2. Start the stack: `docker compose up --build` (needs API on port 8000 and, for async checks, the `worker` service)
3. Run sync scans and write `eval/results/report.md` plus raw JSON: `py -3 -m eval.cli run --base-url http://localhost:8000`
4. Optional multi-backend compare (Semgrep + HTTP analyzer): `py -3 -m eval.cli compare --base-url http://localhost:8000` (needs Semgrep on PATH and entries in `eval/catalog/rule_map.yaml`, or pass `--semgrep-config <path>`). This writes `eval/results/compare_summary.json`. When both the HTTP analyzer and Semgrep backends run, each non-skipped row can include **`line_overlap`**: greedy line-level pairing between the two tools under the **equivalence mapping** in `rule_map.yaml` (`equivalence_rules` lists which Semgrep `check_id` strings are in scope per analyzer `rule_id`, with optional top-level `line_slop` for near matches). Treat these fields as **mapping-dependent agreement**, not ground-truth security labels. For catalog cases with **`type: safe`**, `line_overlap.analyzer_lines` is always empty by design; non-empty Semgrep lines there are a benchmark signal only, not an automatic false-positive verdict.
5. **External tree vs Semgrep (optional, large corpora):** `scripts/corpus_paper_eval.py` — Semgrep once + analyzer per file → `corpus_eval_summary.json` with line-level agreement. Use for [semgrep-rules](https://github.com/semgrep/semgrep-rules) trees (e.g. `javascript/`), **NodeGoat**, or a frozen paper snapshot. Needs Semgrep on PATH, API up, and `--semgrep-config`. **Policy A** requires non-empty `equivalence_rules` in `eval/catalog/rule_map.yaml`; **Policy B** is a broad baseline (all checks vs all analyzer findings). Design: `docs/superpowers/specs/2026-03-26-external-js-ts-corpus-semgrep-design.md`. Example: `py -3 scripts/corpus_paper_eval.py --corpus path/to/snapshot --semgrep-config path/to/rules --policy b --analyzer http://localhost:8000`. **File universe (MVP):** extension filter only; record `file_universe_rule` from the JSON in methods. If the same Semgrep `check_id` appears in multiple Policy A buckets, totals can double-count—keep allowlists disjoint for interpretable numbers.

### CSV GitHub dataset (`dataset_paper_eval`)

**Third track (paper-friendly file list):** a CSV with a **`full_repo_path`** column (GitHub blob URLs). The script downloads each unique file from **`raw.githubusercontent.com`** at the commit in the URL, writes a tree under **`--materialize-root`**, writes **`materialization_manifest.json`** (per-file SHA-256), then runs the **same** Semgrep + HTTP analyzer line-overlap summary as **`corpus_paper_eval`** (default output **`eval/results/dataset_eval_summary.json`**).

- **Rate limits:** unauthenticated GitHub HTTP requests are capped (on the order of tens per hour per IP). Large datasets may hit throttling; optional authenticated fetch via `GITHUB_TOKEN` can be added later.
- **Methods text:** file versions are fixed by each blob URL’s commit; the manifest records content hashes for reproducibility.

Example:

`py -3 scripts/dataset_paper_eval.py --csv path/to/JavaScriptVulnerability.csv --materialize-root .vendor/js-vuln-dataset --semgrep-config .vendor/semgrep-rules/javascript --policy b --analyzer http://127.0.0.1:8001`

### Reproducing the catalog benchmark

1. Install project test/runtime deps (e.g. `uv sync` or your usual env); install [Semgrep CLI](https://semgrep.dev/docs/getting-started/) and ensure `semgrep` is on `PATH`.
2. Start the API (step 2 above). Use the same base URL in all commands (e.g. `http://127.0.0.1:8000`).
3. `py -3 -m eval.build_cases` whenever you change `eval/cases_pack/`.
4. **Analyzer vs catalog (gold labels):**  
   `py -3 -m eval.cli run --base-url http://127.0.0.1:8000`  
   → `eval/results/report.md` and `eval/results/raw/<test_id>.json`.
5. **Analyzer vs Semgrep (same catalog snippets):** clone rules once, then compare:  
   `git clone --depth 1 https://github.com/semgrep/semgrep-rules.git .vendor/semgrep-rules`  
   `py -3 -m eval.cli compare --base-url http://127.0.0.1:8000 --semgrep-config .vendor/semgrep-rules/javascript --output-dir eval/results`  
   → `eval/results/compare_summary.json` and `eval/results/raw/<test_id>.semgrep.json`.  
   `eval/catalog/rule_map.yaml` must list Semgrep `check_id` strings under `equivalence_rules` for meaningful `line_overlap` (see step 4 in the list above).

**Pinning (papers / regression reports):** record `semgrep --version`, analyzer/API version (e.g. OpenAPI or release tag), git commit of this repo, commit of `semgrep-rules` (or archive hash), and the exact `eval.cli` / `corpus_paper_eval.py` / `dataset_paper_eval.py` command line (for dataset runs, also `materialization_manifest.manifest_sha256` in the output JSON).

### Reading the outputs

| Artifact | What it means |
|----------|----------------|
| **`eval/results/report.md`** | Produced by `eval.cli run`. Per-case **TP / TN / FN / FP** vs the **catalog** (`eval/catalog/cases.json`: `type`, `rule_id`, `expected_cwe`, etc.). Summary counts and per-rule stats are in the same report. This is **not** Semgrep agreement. |
| **`eval/results/raw/<test_id>.json`** | Raw HTTP JSON from `/api/v1/analyze/sync` for that case. |
| **`eval/results/compare_summary.json`** | From `eval.cli compare`. Each row has catalog `outcome` plus `by_backend` counts. **`line_overlap`** is greedy line pairing between analyzer and Semgrep after filtering Semgrep by `equivalence_rules` in `rule_map.yaml`—**mapping-dependent**, not ground truth. On **`type: safe`** cases, `line_overlap.analyzer_lines` is always empty by design. |
| **`eval/results/raw/<test_id>.semgrep.json`** | Semgrep JSON for that synthetic file (debugging `check_id` / lines). |
| **`eval/results/corpus_eval_summary.json`** | From `scripts/corpus_paper_eval.py` on a real tree; fields described in `docs/superpowers/specs/2026-03-26-external-js-ts-corpus-semgrep-design.md` §7. |
| **`eval/results/dataset_eval_summary.json`** | From `scripts/dataset_paper_eval.py`; same overlap fields as the corpus summary plus `dataset_csv` and `materialization_manifest` (`path`, `manifest_sha256`). |

`eval/results/*.json` and `report.md` are gitignored; committed sources live under `eval/catalog/` and `eval/cases_pack/`.

### Current catalog compare vs Semgrep

**In-process catalog gate (CI):** `run_catalog_inprocess(load_catalog())` — current gold outcomes **TP 52 / TN 37 / FN 0 / FP 7** (refreshed **2026-08-08**, includes `h_realworld` Nest/Next snippets). CI fails if `FN > 0` or `FP > 10`.

Historical Semgrep **`eval.cli compare`** numbers (HTTP vs Semgrep line overlap on the same catalog) from **2026-03-26** are outdated relative to the in-process gate; re-run compare locally to refresh Semgrep agreement stats (`compare_summary.json` is gitignored).

### Current `corpus_paper_eval` run (example: `semgrep-rules` `javascript/`)

Example **external-tree** run: **Policy B** (all analyzer findings vs all in-scope Semgrep hits on the same files). **`corpus_eval_summary.json` is gitignored**—re-run to refresh.

| Item | Value |
|------|------:|
| **Corpus** | `.vendor/semgrep-rules/javascript` (174 `.js`/`.jsx`/`.ts`/`.tsx` files, `walk:rglob_ext=…`) |
| **Rules commit** | `28db38e6376df4995dac96f41984cc5690549553` |
| **Semgrep** | CLI **1.156.0**, `--config` = same `javascript/` tree |
| **Command** | `py -3 scripts/corpus_paper_eval.py --corpus .vendor/semgrep-rules/javascript --semgrep-config .vendor/semgrep-rules/javascript --policy b --analyzer http://127.0.0.1:8001` (plus `--out` / `--corpus-id` as you prefer; URL must match your running API) |
| **`semgrep_findings_total`** (counted rows with string `check_id` + line) | **868** |
| **`analyzer_findings_total`** | **219** |
| **`matched_line_pairs`** | **116** |
| **`analyzer_only_lines`** | **76** |
| **`semgrep_only_lines`** | **613** |

These numbers are **Semgrep agreement under Policy B**, not precision/recall vs a labeled dataset. Older ad-hoc **per-file** “both tools ≥1 hit” stats are deprecated in favor of the line-level JSON above.

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
| `ANALYZER_DATABASE_URL` | `postgresql://analyzer:analyzer@localhost:5432/analyzer` | PostgreSQL connection (compose uses `POSTGRES_PASSWORD`) |
| `ANALYZER_REDIS_URL` | `redis://localhost:6379/0` | Redis connection (compose uses password URL) |
| `ANALYZER_CELERY_BROKER_URL` | `redis://localhost:6379/1` | Celery broker |
| `ANALYZER_CELERY_RESULT_BACKEND` | `redis://localhost:6379/2` | Celery result store |
| `ANALYZER_API_KEY` | (unset) | Required unless `ANALYZER_DEBUG=true`; compose needs a non-empty value (`cp .env.example .env` then change the placeholder) |
| `ANALYZER_RATE_LIMIT_PER_MINUTE` | `60` | Redis rate limit for analyze endpoints (0 disables) |
| `ANALYZER_RATE_LIMIT_SYNC_PER_MINUTE` | `20` | Tighter cap for sync/bundle analyze |
| `ANALYZER_TRUST_X_FORWARDED_FOR` | `false` | When true, rate-limit IP bucket may use `X-Forwarded-For` (only behind a trusted proxy) |
| `ANALYZER_SCAN_STALE_AFTER_SECONDS` | `celery_time_limit+60` | Pending/running scans older than this are marked `failed` on poll (floored to Celery hard limit + 60s) |
| `ANALYZER_PARALLEL_RULES` | `false` | **Experimental** — ThreadPool rule runs sharing one parse tree; keep off in production |
| `ANALYZER_SQL_SINK_ALLOWLIST` | `true` | When true, SQL `*.query` sinks require a known DB receiver |
| `ANALYZER_MAX_SOURCE_BYTES` | `5000000` | Max size for async analyze enqueue |
| `ANALYZER_MAX_SYNC_SOURCE_BYTES` | `50000` | Max size for sync endpoint |
| `ANALYZER_ANALYSIS_BUDGET_MS` | (unset) | Optional wall-clock limit (ms) for sync analysis: stops before further rules and skips taint if exceeded; `stats.time_budget_exceeded` is set |
| `ANALYZER_MAX_BUNDLE_FILES` | `32` | Max entries in `analyze/bundle/sync` `files` map |
| `ANALYZER_MAX_BUNDLE_TOTAL_BYTES` | `524288` | Max total UTF-8 size of all bundle sources |
| `ANALYZER_DEBUG` | `false` | Debug mode |
| `ANALYZER_SCAN_TASK_REGISTRY_TTL_SECONDS` | `604800` | Redis TTL for async `scan_id` → task id mapping |
| `ANALYZER_CORS_ORIGINS` | `[]` | JSON array of allowed browser origins (e.g. `["http://localhost:5173"]`); must not include `*` |
| `ANALYZER_SARIF_INFORMATION_URI` | (unset) | Optional `informationUri` in SARIF `tool.driver` |
