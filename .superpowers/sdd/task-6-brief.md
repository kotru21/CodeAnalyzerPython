### Task 6: End-to-end verification

**Files:** none new — validation only

- [ ] **Step 1: Local full quality+test parity**

```bash
py -3.14 -m ruff check src tests eval
py -3.14 -m ruff format --check src tests eval
py -3.14 -m mypy src/analyzer
py -3.14 -m pip_audit
py -3.14 -m pytest tests/ -q --cov=src/analyzer --cov-report=term-missing
py -3.14 -c "from eval.catalog_loader import load_catalog; from eval.catalog_runner import run_catalog_inprocess; from eval.metrics import global_counts; c=global_counts(run_catalog_inprocess(load_catalog())); assert c['FN']==0 and c['FP']<=10; print(c)"
```

Expected: all exit 0.

- [ ] **Step 2: Confirm on GitHub that all four jobs are green**

Open Actions for the PR/push; `quality`, `test`, `eval`, `docker` all success.

- [ ] **Step 3: Negative check (optional, on a throwaway branch)**

Introduce a deliberate `ruff format` break in one file, push, confirm `quality` fails, revert.

- [ ] **Step 4: Document branch protection for the human**

Human action (Settings → Branches): require status checks `quality`, `test`, `eval`, `docker` on `main`. Not automatable without admin token.

---

## Spec coverage checklist (self-review)

| Spec requirement | Task |
|------------------|------|
| Parallel jobs quality/test/eval/docker | 3, 4 |
| Ruff on src/tests/eval + format check | 3, 5 |
| mypy src/analyzer | 3, 5 |
| pip-audit blocking | 1, 3, 5 |
| Coverage ratchet (floor current) → 84% | 1 |
| Catalog FN=0 FP≤10 | 3 |
| Docker build + migrate + health vs PG/Redis | 2, 4 |
| Pre-commit ≈ quality+test incl. pytest | 5 |
| No CD / no Trivy / no matrix | Global Constraints |
| README badge + docs | 5 |
| Retire eval.yml | 5 |
| Caching pip | 3 (`cache: pip`) |
| Branch protection documented | 5, 6 |

## Placeholder / consistency notes

- Redis in CI: **no password** (service simplicity); compose locally still uses password — smoke script supports both via `REDIS_PASSWORD`.
- Coverage number **84** locked from local run 2026-08-08 (`TOTAL ... 84%`); if CI measures slightly lower, set `fail_under` to the CI floor and note it in the commit.
- ruff-pre-commit `rev` must match installed major.minor; adjust pin when bumping ruff.
