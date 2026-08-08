### Task 1: Dev deps + coverage ratchet in pyproject

**Files:**
- Modify: `pyproject.toml`
- Test: run pytest with fail-under (no new test file)

**Interfaces:**
- Consumes: none
- Produces: `[tool.coverage.report] fail_under = 84`; dev extras include `pip-audit` and `pre-commit`

- [ ] **Step 1: Add coverage fail_under and dev dependencies**

In `pyproject.toml`, update `[project.optional-dependencies] dev` to include:

```toml
dev = [
    "pyyaml>=6.0.3",
    "pytest>=9.0",
    "pytest-asyncio>=1.0",
    "pytest-cov>=7.0",
    "ruff>=0.16",
    "mypy>=2.0",
    "pip-audit>=2.9",
    "pre-commit>=4.0",
]
```

Add after `[tool.pytest.ini_options]` (or near other tool tables):

```toml
[tool.coverage.run]
source = ["analyzer"]
branch = false

[tool.coverage.report]
fail_under = 84
show_missing = true
```

- [ ] **Step 2: Reinstall and verify coverage gate passes at 84**

Run:

```bash
py -3.14 -m pip install -e ".[dev]"
py -3.14 -m pytest tests/ -q --cov=src/analyzer --cov-report=term-missing
```

Expected: exit code 0; TOTAL around 84%+; no fail_under error.

- [ ] **Step 3: Verify fail_under would trip if lowered incorrectly (optional sanity)**

Temporarily set `fail_under = 99`, run the same pytest command, confirm non-zero exit mentioning fail-under / coverage, then restore `fail_under = 84`.

- [ ] **Step 4: Commit (only if human asks)**

```bash
git add pyproject.toml
git commit -m "$(cat <<'EOF'
chore(ci): add pip-audit/pre-commit deps and 84% coverage floor

EOF
)"
```

---
