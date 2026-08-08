# Task 1 Report: Dev deps + coverage ratchet in pyproject

**Status:** DONE  
**Date:** 2026-08-08  
**Agent:** subagent (Task 1 of 6 — CI reliability/quality)

---

## Summary

Updated `pyproject.toml` to add `pip-audit` and `pre-commit` to dev optional dependencies and configured coverage reporting with an 84% floor. Verified the gate passes at current coverage and correctly fails when raised to 99%. No commit created per human constraint.

---

## Changes Implemented

### File modified

- `pyproject.toml` (only file touched)

### Step 1: Dev dependencies

Added to `[project.optional-dependencies] dev`:

```toml
"pip-audit>=2.9",
"pre-commit>=4.0",
```

### Step 1: Coverage configuration

Added after `[tool.pytest.ini_options]`:

```toml
[tool.coverage.run]
source = ["analyzer"]
branch = false

[tool.coverage.report]
fail_under = 84
show_missing = true
```

### Step 4: Commit

**Skipped** — human constraint: do not commit.

---

## Verification

### Step 2: Install and coverage gate at 84

**Command:**

```powershell
py -3.14 -m pip install -e ".[dev]"
py -3.14 -m pytest tests/ -q --cov=src/analyzer --cov-report=term-missing
```

**Results:**

| Check | Result |
|-------|--------|
| `pip install -e ".[dev]"` | Exit 0 — `pip-audit` 2.10.1, `pre-commit` 4.6.1 installed |
| pytest exit code | 0 |
| Tests | 239 passed, 1 skipped |
| Total coverage | **84.11%** |
| fail_under message | `Required test coverage of 84.0% reached. Total coverage: 84.11%` |

### Step 3: Sanity check (fail_under = 99)

Temporarily set `fail_under = 99`, re-ran pytest, then restored `fail_under = 84`.

**Results:**

| Check | Result |
|-------|--------|
| pytest exit code | 1 |
| Failure message | `ERROR: Coverage failure: total of 84 is less than fail-under=99` |
| Secondary message | `FAIL Required test coverage of 99.0% not reached. Total coverage: 84.11%` |
| Tests still pass | 239 passed, 1 skipped (failure is coverage-only) |
| Restored | `fail_under = 84` confirmed in working tree |

---

## Self-Review

### Correctness

- Dev extras match task brief exactly (versions and package names).
- Coverage tables match brief (`source = ["analyzer"]`, `branch = false`, `fail_under = 84`, `show_missing = true`).
- Placement after `[tool.pytest.ini_options]` aligns with brief and existing tool-table layout.
- No unrelated files modified.

### Coverage behavior

- `[tool.coverage.run] source = ["analyzer"]` works with existing `pythonpath = ["src", "."]` in pytest config.
- CLI flag `--cov=src/analyzer` is consistent with package layout under `src/analyzer/`.
- Gate is functional: passes at 84, fails at 99.

### Scope

- Task scope respected: pyproject-only change, no CI workflows, no pre-commit config file (later tasks).

---

## Concerns / Notes

1. **Tight margin:** Total coverage is 84.11% — only ~0.11% above the floor. Small regressions could fail CI once wired in Task 2+.
2. **Low-coverage modules (informational):** Largest gaps include `taint/module_graph.py` (52%), `models/base.py` (64%), `main.py` (70%), `api/router.py` (73%). Not blocking for this task.
3. **Pre-existing test warnings:** ResourceWarnings for unclosed SQLite connections during teardown; unrelated to this change.
4. **Local PATH:** `pip-audit` / `pre-commit` scripts installed under user Scripts dir with PATH warnings on this Windows host; does not affect `py -3.14 -m` invocation.

---

## Git State

```
 M pyproject.toml
```

Unstaged modification only; no commit, no staging per instructions.

---

## Interfaces Produced (for downstream tasks)

| Interface | Value |
|-----------|-------|
| `[tool.coverage.report] fail_under` | `84` |
| Dev extras | includes `pip-audit>=2.9`, `pre-commit>=4.0` |

---

## Commands for Human Verification

```powershell
cd d:\GitRepositories\CodeAnalyzerPython
py -3.14 -m pip install -e ".[dev]"
py -3.14 -m pytest tests/ -q --cov=src/analyzer --cov-report=term-missing
```

Expected: exit 0, TOTAL ≥ 84%.
