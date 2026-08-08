# Task 4 Report: Docker job in `ci.yml`

**Status:** DONE  
**Date:** 2026-08-08  
**Agent:** subagent (Task 4 of 6 — CI reliability/quality)

---

## Summary

Appended the canonical `docker` job to `.github/workflows/ci.yml` (Option A: unauthenticated Redis service + empty `REDIS_PASSWORD`). Confirmed `scripts/ci_docker_smoke.sh` already implements the empty-password Redis URL branch from Task 2. No smoke-script edits required. No commit created per human constraint.

---

## Changes Implemented

### Modified

- `.github/workflows/ci.yml` — added `docker` job after `eval`:
  - Service containers: `postgres:17-alpine` (user/db/password aligned with smoke script defaults), `redis:8-alpine` (no `--requirepass`, health `redis-cli ping`)
  - Steps: checkout, `docker/setup-buildx-action@v3`, `bash scripts/ci_docker_smoke.sh`
  - Job env: `IMAGE=analyzer-ci:local`, `POSTGRES_PASSWORD=ci-postgres`, `REDIS_PASSWORD=""`, `ANALYZER_API_KEY=ci-smoke-key`

### Verified unchanged (Task 2)

- `scripts/ci_docker_smoke.sh` — `REDIS_PASSWORD="${REDIS_PASSWORD-}"` and conditional URL construction (lines 10–22); `--network host` for Linux GHA; alembic + health poll unchanged.

### Not done (per scope)

- Step 3 push/PR + green GHA run — human follow-up (agent cannot push)
- Step 4 commit — skipped

---

## Self-Review

| Check | Result |
|-------|--------|
| YAML matches plan Option A canonical form | Yes |
| Postgres env matches script defaults (`analyzer` / `ci-postgres` / `analyzer`) | Yes |
| Redis: no password in service; smoke uses passwordless URLs when `REDIS_PASSWORD` empty | Yes |
| Existing `quality` / `test` / `eval` jobs untouched | Yes |
| `docker/setup-buildx-action@v3` present before build | Yes |

**Risks / follow-ups**

1. **GHA not exercised here** — Docker smoke requires push/PR to GitHub; expect migrate OK + `/api/v1/health` healthy within ~60s on `ubuntu-latest`.
2. **`--network host`** — required for container → `127.0.0.1` service ports; Linux GHA only (correct runner).
3. **Build time** — raw `docker build` in script (no GHA cache); acceptable for v1 per plan YAGNI note.

---

## Verification

| Check | Result |
|-------|--------|
| Smoke script empty-password branch | Present (lines 10–22) |
| Local Docker smoke run | Not run (environment-dependent) |
| GHA `docker` job green | Pending human push/PR |

---

## Commit

**Skipped** — human constraint: do not commit.
