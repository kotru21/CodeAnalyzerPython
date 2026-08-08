# Task 2 Report: Docker smoke script

**Status:** DONE  
**Date:** 2026-08-08  
**Agent:** subagent (Task 2 of 6 — CI reliability/quality)

---

## Summary

Created `scripts/ci_docker_smoke.sh` — a bash CI smoke script that builds the Docker image, runs Alembic migrations, starts the API with `--network host`, and polls `/api/v1/health` until `status=healthy` and `database=ok`. Implemented Task 4 Option A Redis URL branching so empty `REDIS_PASSWORD` works with unauthenticated GHA Redis services. File written with LF line endings. No commit per human constraint.

---

## Changes Implemented

### File created

- `scripts/ci_docker_smoke.sh` (new, 75 lines, LF endings verified — 0 CR bytes)

### Key interfaces

| Variable | Default | Notes |
|----------|---------|-------|
| `IMAGE` | `analyzer-ci:local` | Built and used for migrate + API |
| `POSTGRES_USER` | `analyzer` | |
| `POSTGRES_PASSWORD` | `ci-postgres` | |
| `POSTGRES_DB` | `analyzer` | |
| `REDIS_PASSWORD` | *(empty if unset)* | `${REDIS_PASSWORD-}` — no default |
| `ANALYZER_API_KEY` | `ci-smoke-key` | via `API_KEY` |

### Redis URL branch (Task 4 Option A)

```bash
REDIS_PASSWORD="${REDIS_PASSWORD-}"
if [[ -n "${REDIS_PASSWORD}" ]]; then
  REDIS_URL="redis://:${REDIS_PASSWORD}@127.0.0.1:6379/0"
  # ... broker/result with password
else
  REDIS_URL="redis://127.0.0.1:6379/0"
  # ... broker/result without password
fi
```

When `REDIS_PASSWORD` is unset or empty (GHA docker job), URLs omit auth. When set (e.g. local compose with `--requirepass`), password URLs are used.

### Script flow

1. `docker build -t "${IMAGE}" .`
2. `docker run --rm --network host … alembic upgrade head`
3. `docker run -d --network host …` (API)
4. Poll `curl -fsS http://127.0.0.1:8000/api/v1/health` up to 30×2s
5. `grep -E` for `"status" … "healthy"` and `"database" … "ok"`
6. `trap cleanup EXIT` — logs container and removes on exit

### Step 4: Commit

**Skipped** — human constraint: do not commit.

---

## Verification

### Step 2: LF line endings

**Command:**

```powershell
$bytes = [System.IO.File]::ReadAllBytes("scripts/ci_docker_smoke.sh")
($bytes | Where-Object { $_ -eq 13 } | Measure-Object).Count
```

**Result:** CR count = 0 (pure LF).

### Step 3: Local dry-run

**Skipped** — Docker Desktop is available (v29.6.2) but Postgres (127.0.0.1:5432) and Redis (127.0.0.1:6379) are not listening on the host. Compose stack does not publish those ports. Full validation deferred to Task 4 GHA docker job.

### Bash syntax check

`bash -n` unavailable on this Windows host (WSL/bash path issues). Script follows brief structure; syntax is standard bash with `set -euo pipefail`.

---

## Self-Review

### Correctness

- Matches task brief: build → migrate → health grep flow preserved.
- Human override applied: `REDIS_PASSWORD="${REDIS_PASSWORD-}"` with if/else URL branch instead of hardcoded password default.
- Postgres defaults unchanged (`analyzer` / `ci-postgres` / `analyzer`).
- Rate limits disabled for smoke (`ANALYZER_RATE_LIMIT_*=0`).
- `--network host` on both migrate and API runs (required for GHA Linux service containers on localhost).
- Health check uses robust `grep -E` with optional whitespace (not fragile `jq` dependency).
- Cleanup trap ensures container removal and log capture on failure.

### Scope

- Only `scripts/ci_docker_smoke.sh` created; no workflow YAML, no pyproject changes, no commit.

### Minor deviation from brief template

- Removed two no-op `grep -q` lines from the brief's health loop (results were discarded before `status_ok` assignment). Behavior unchanged; loop logic is cleaner.

---

## Concerns / Notes

1. **No local end-to-end run** — smoke not exercised until Task 4 wires GHA services + job.
2. **`--network host` is Linux-only** — correct for `ubuntu-latest`; will not work on Windows/macOS Docker Desktop for local runs.
3. **Port 8000 conflict** — if another process binds 8000 during smoke, health poll will fail; acceptable for CI ephemeral runners.
4. **Executable bit** — git may record `100644` on Windows checkout; CI runs via `bash scripts/ci_docker_smoke.sh` so execute bit is not required.
5. **Local compose mismatch** — compose Redis uses password; local dry-run would need `REDIS_PASSWORD=changeme` (or matching `.env`) plus published PG/Redis ports — not set up on this host.

---

## Git State

```
?? scripts/ci_docker_smoke.sh
```

Untracked new file only; no commit, no staging per instructions.

---

## Interfaces Produced (for downstream tasks)

| Interface | Value |
|-----------|-------|
| Smoke script path | `scripts/ci_docker_smoke.sh` |
| Image tag | `analyzer-ci:local` (overridable via `IMAGE`) |
| Success criteria | exit 0 iff migrate OK + health JSON has `status=healthy`, `database=ok` |
| Redis empty-password | supported via `REDIS_PASSWORD=""` or unset |

---

## Commands for Human / CI Verification

```bash
# On ubuntu-latest with PG/Redis service containers (Task 4):
export IMAGE=analyzer-ci:local
export POSTGRES_PASSWORD=ci-postgres
export REDIS_PASSWORD=""
export ANALYZER_API_KEY=ci-smoke-key
bash scripts/ci_docker_smoke.sh
```

Expected: exit 0, `==> docker smoke OK`.
