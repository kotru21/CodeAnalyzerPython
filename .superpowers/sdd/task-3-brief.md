### Task 3: Multi-job workflow `ci.yml` (quality / test / eval)

**Files:**
- Create: `.github/workflows/ci.yml` (jobs `quality`, `test`, `eval` first; docker job in Task 4)
- Modify later: delete `eval.yml` in Task 5

**Interfaces:**
- Consumes: `pyproject.toml` fail_under and pip-audit from Task 1
- Produces: three required jobs green on PR

- [ ] **Step 1: Write `.github/workflows/ci.yml` with quality, test, eval**

```yaml
name: CI

on:
  push:
    branches: [main, master]
  pull_request:

concurrency:
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.14"
          cache: pip
      - run: pip install -e ".[dev]"
      - name: Ruff check
        run: ruff check src tests eval
      - name: Ruff format
        run: ruff format --check src tests eval
      - name: Mypy
        run: mypy src/analyzer

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.14"
          cache: pip
      - run: pip install -e ".[dev]"
      - name: pip-audit
        run: pip-audit
      - name: Pytest
        run: pytest tests/ -q --cov=src/analyzer --cov-report=term-missing

  eval:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.14"
          cache: pip
      - run: pip install -e ".[dev]"
      - name: In-process catalog eval
        run: |
          python - <<'PY'
          import json
          from eval.catalog_loader import load_catalog
          from eval.catalog_runner import run_catalog_inprocess
          from eval.metrics import global_counts, precision_recall_f1
          rows = run_catalog_inprocess(load_catalog())
          counts = global_counts(rows)
          p, r, f1 = precision_recall_f1(counts["TP"], counts["FP"], counts["FN"])
          print(json.dumps({"counts": counts, "precision": p, "recall": r, "f1": f1}))
          assert counts["FN"] == 0, f"FN regression: {counts['FN']}"
          assert counts["FP"] <= 10, f"FP budget exceeded: {counts['FP']}"
          PY
```

Note: pytest picks up `[tool.coverage.report] fail_under = 84` from Task 1; no need to duplicate `--cov-fail-under` unless you want belt-and-suspenders.

- [ ] **Step 2: Fix any ruff format/check failures on `tests` / `eval` revealed by expanded scope**

Run locally:

```bash
py -3.14 -m ruff check src tests eval
py -3.14 -m ruff format --check src tests eval
```

If format fails: `py -3.14 -m ruff format src tests eval`, then re-check. Fix lint issues with minimal edits (no drive-by refactors).

- [ ] **Step 3: Run pip-audit locally and record outcome**

```bash
py -3.14 -m pip_audit
```

If it fails on a CVE with no fix: add a narrow `.pip-audit-ignore` or `pip-audit --ignore-vuln <id>` **only for that id**, and document the reason in the PR/commit body. Do not disable pip-audit.

- [ ] **Step 4: Commit (only if human asks)**

```bash
git add .github/workflows/ci.yml
git commit -m "$(cat <<'EOF'
ci: add parallel quality, test, and catalog jobs

EOF
)"
```

---
