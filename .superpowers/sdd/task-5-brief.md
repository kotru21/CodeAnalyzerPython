### Task 5: Retire `eval.yml`, pre-commit, README

**Files:**
- Delete: `.github/workflows/eval.yml`
- Create: `.pre-commit-config.yaml`
- Modify: `README.md` (badge + CI / pre-commit docs)
- Modify: `.gitignore` — ensure `docs/superpowers/specs/` present (already)

**Interfaces:**
- Consumes: same commands as quality + test jobs
- Produces: local pre-commit parity; single CI badge

- [ ] **Step 1: Delete `.github/workflows/eval.yml`**

```bash
git rm .github/workflows/eval.yml
```

- [ ] **Step 2: Create `.pre-commit-config.yaml`**

```yaml
# Mirrors CI jobs quality + test. Catalog eval and Docker smoke stay CI-only.
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.16.2
    hooks:
      - id: ruff
        args: [check, src, tests, eval, --force-exclude]
      - id: ruff-format
        args: [src, tests, eval, --force-exclude]

  - repo: local
    hooks:
      - id: mypy
        name: mypy
        entry: mypy src/analyzer
        language: system
        pass_filenames: false
        types: [python]
      - id: pip-audit
        name: pip-audit
        entry: pip-audit
        language: system
        pass_filenames: false
      - id: pytest-cov
        name: pytest with coverage ratchet
        entry: pytest tests/ -q --cov=src/analyzer --cov-report=term-missing
        language: system
        pass_filenames: false
        stages: [pre-commit]
```

Pin `rev` to the ruff version resolved in the local env (`py -3.14 -m ruff --version`). Re-check ruff-pre-commit args: if `args: [check, src, ...]` conflicts with how the hook invokes ruff, use:

```yaml
      - id: ruff
        args: [--force-exclude]
        files: ^(src|tests|eval)/
      - id: ruff-format
        args: [--force-exclude]
        files: ^(src|tests|eval)/
```

- [ ] **Step 3: Install and run pre-commit**

```bash
py -3.14 -m pip install -e ".[dev]"
pre-commit install
pre-commit run --all-files
```

Expected: all hooks pass (or fix format/lint first).

- [ ] **Step 4: Update README badge and docs**

Replace the Eval Catalog badge line:

```markdown
[![CI](https://github.com/kotru21/CodeAnalyzerPython/actions/workflows/ci.yml/badge.svg)](https://github.com/kotru21/CodeAnalyzerPython/actions/workflows/ci.yml)
```

After the “Run Tests” section, add:

```markdown
### Pre-commit

```bash
pip install -e ".[dev]"
pre-commit install
pre-commit run --all-files
```

Hooks mirror CI **quality** + **test** (ruff, format, mypy, pip-audit, pytest + 84% coverage floor). Catalog eval and Docker smoke run only in GitHub Actions.

### CI jobs

| Job | What it runs |
|-----|----------------|
| `quality` | `ruff check` / `ruff format --check` on `src` `tests` `eval`; `mypy src/analyzer` |
| `test` | `pip-audit`; `pytest` with coverage fail-under 84% |
| `eval` | In-process catalog gate (`FN == 0`, `FP <= 10`) |
| `docker` | Image build, `alembic upgrade head`, `GET /api/v1/health` vs Postgres+Redis |

Enable branch protection on `main` to require all four checks.
```

Also update the README sentence that says “In-process catalog gate (CI)” if it still points at `eval.yml` by name — keep budgets text, change workflow name to CI.

- [ ] **Step 5: Commit (only if human asks)**

```bash
git add .github/workflows/ci.yml .pre-commit-config.yaml README.md pyproject.toml scripts/ci_docker_smoke.sh .gitignore
git rm -f .github/workflows/eval.yml
git commit -m "$(cat <<'EOF'
ci: parallel required gates, pre-commit, and Docker smoke

EOF
)"
```

---
