# Task 5 Report: Retire eval.yml, pre-commit, README

**Status:** Complete  
**Commits:** none (per instructions)

## Summary

Retired standalone `.github/workflows/eval.yml`; catalog eval now runs only as the `eval` job in `ci.yml`. Added `.pre-commit-config.yaml` mirroring CI **quality** + **test** jobs. Updated README badge, Pre-commit section, CI jobs table, and catalog gate wording.

## Changes

| File | Action |
|------|--------|
| `.github/workflows/eval.yml` | Deleted |
| `.pre-commit-config.yaml` | Created |
| `README.md` | CI badge, Pre-commit + CI jobs sections, eval gate label |
| `.gitignore` | Unchanged — `docs/superpowers/specs/` and `plans/` ignores kept |

## Pre-commit config

- **Ruff** pinned to `v0.16.2` (matches `py -3.14 -m ruff --version` → 0.16.2).
- Used `files: ^(src|tests|eval)/` without extra `args` — adding `--force-exclude` duplicated the hook default and failed.
- Local hooks use `python -m …` so tools resolve when Scripts/venv bin is not on PATH (Windows); same pattern works on Linux/macOS with active venv.
- Hooks: ruff check, ruff format, mypy, pip-audit, pytest + 84% coverage floor.
- Catalog eval and Docker smoke remain CI-only.

## Verification

```text
py -3.14 -m pre_commit install
py -3.14 -m pre_commit run --all-files
→ All 5 hooks Passed
```

First successful run may have auto-formatted tracked Python under `src/`, `tests/`, `eval/` via the ruff-format hook (expected pre-commit behavior).

## Self-review

- [x] `eval.yml` removed from filesystem
- [x] Single CI badge in README
- [x] Pre-commit docs match brief
- [x] CI jobs table documents all four jobs
- [x] Catalog gate text references CI `eval` job, not `eval.yml`
- [x] `.gitignore` specs/plans ignores preserved
- [x] No commit, no push

## Concerns / follow-ups

1. **`pyproject.toml` comment** still mentions `eval.yml` (line 57) — harmless stale comment; update in a later cleanup if desired.
2. **Ruff format collateral** — `pre-commit run --all-files` may have reformatted many files from prior tasks; review those diffs when staging the full CI branch.
3. **`python -m` vs bare CLI** — brief showed bare `mypy`/`pytest`/`pip-audit`; `python -m` chosen for PATH portability on Windows without venv activation.
4. **Branch protection** — README documents requiring all four CI checks; must be configured manually on GitHub.

## Out of scope (unchanged)

- `ci.yml`, `pyproject.toml`, `scripts/ci_docker_smoke.sh` — delivered in earlier tasks; not modified in Task 5 except incidental ruff format from hook run.
