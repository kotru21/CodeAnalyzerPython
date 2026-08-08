# Task 3 Report: Multi-job workflow `ci.yml` (quality / test / eval)

**Status:** DONE  
**Date:** 2026-08-08  
**Agent:** subagent (Task 3 of 6 — CI reliability/quality)

---

## Summary

Created `.github/workflows/ci.yml` with three parallel jobs (`quality`, `test`, `eval`) matching the brief. Expanded ruff scope to `src tests eval` revealed 27 lint issues and 31 format diffs; fixed with auto-fix (including `--unsafe-fixes` for TCH import moves) plus three manual edits. All three CI job commands pass locally on Python 3.14. pip-audit reports no known vulnerabilities. No commit created per human constraint.

---

## Changes Implemented

### Created

- `.github/workflows/ci.yml` — `quality` (ruff check/format + mypy), `test` (pip-audit + pytest w/ coverage), `eval` (in-process catalog with FN=0 / FP≤10 gates). No docker job (Task 4).

### Modified (ruff lint/format only — no logic refactors)

**Manual fixes (3):**

| File | Fix |
|------|-----|
| `eval/finding_match.py` | Renamed unused loop vars `f` → `_f` (B007) |
| `eval/line_overlap.py` | Shortened docstring to satisfy line-length 100 (E501) |

**Auto-fixed (42 files, 31 reformatted):**

- `ruff check --fix` — import sort (I001), duplicate import merge
- `ruff check --fix --unsafe-fixes` — TCH rules: moved type-only imports into `TYPE_CHECKING` blocks across `eval/` and `tests/eval/`
- `ruff format` — whitespace/line-wrap normalization across `src`, `tests`, `eval`

No changes to `pyproject.toml` ruff config; no `.pip-audit-ignore` needed.

### Not touched (per scope)

- `.github/workflows/eval.yml` — delete in Task 5
- Docker job — Task 4
- Step 4 commit — skipped

---

## Verification

### quality job

| Command | Exit | Result |
|---------|------|--------|
| `py -3.14 -m ruff check src tests eval` | 0 | All checks passed |
| `py -3.14 -m ruff format --check src tests eval` | 0 | 161 files already formatted |
| `py -3.14 -m mypy src/analyzer` | 0 | Success: no issues found in 64 source files |

### test job

| Command | Exit | Result |
|---------|------|--------|
| `py -3.14 -m pip_audit` | 0 | No known vulnerabilities found |
| `py -3.14 -m pytest tests/ -q --cov=src/analyzer --cov-report=term-missing` | 0 | 239 passed, 1 skipped; **84.11%** coverage (fail_under 84 met) |

**pip-audit note:** `analyzer-service (0.1.0)` skipped (local editable, not on PyPI) — expected.

### eval job

| Command | Exit | Result |
|---------|------|--------|
| In-process catalog script (same as ci.yml) | 0 | `{"counts": {"TP": 52, "FP": 7, "TN": 37, "FN": 0, "ERROR": 0}, "precision": 0.881, "recall": 1.0, "f1": 0.937}` |

FN=0 and FP=7 (≤10 budget) — gates pass.

---

## Self-Review

### ci.yml fidelity

- Matches brief YAML exactly (triggers, concurrency, Python 3.14, three jobs, eval inline script).
- Uses `actions/checkout@v7` and `actions/setup-python@v7` as specified.
- Coverage gate relies on `[tool.coverage.report] fail_under = 84` from Task 1 (no duplicate `--cov-fail-under`).

### Ruff scope expansion

- Prior CI likely checked `src` only; adding `tests eval` surfaced pre-existing style debt.
- TCH unsafe fixes are safe: only moved imports used exclusively in annotations; runtime `Path(...)` usage retained at module level where needed.
- Largest diffs (`sources_sinks.py`, `tracker.py`, `orchestrator.py`) are import/format only — verified by passing full pytest + eval.

### Risks / follow-ups

1. **Large formatting diff** — 43 files touched; mostly mechanical. Reviewers should focus on the 3 manual edits + `ci.yml`.
2. **eval.yml overlap** — both workflows will run until Task 5 deletes `eval.yml`; duplicate eval on PRs until then.
3. **SQLite ResourceWarnings** in pytest output — pre-existing, not introduced by this task.
4. **Windows vs Linux** — eval heredoc (`python - <<'PY'`) is bash-only; correct for `ubuntu-latest` runners.

### Commit

**Skipped** — human constraint: do not commit.

---

## Files for human review (priority)

1. `.github/workflows/ci.yml` (new)
2. `eval/finding_match.py`, `eval/line_overlap.py` (manual)
3. Remaining diffs: confirm import-only / format-only
