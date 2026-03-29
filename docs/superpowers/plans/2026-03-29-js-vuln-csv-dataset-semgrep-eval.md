# JS vulnerability CSV dataset vs Semgrep — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automate the same line-level analyzer-vs-Semgrep agreement workflow as `scripts/corpus_paper_eval.py`, but where the file universe comes from a CSV (e.g. `JavaScriptVulnerability.csv`) with GitHub blob URLs, producing a reproducible summary JSON suitable for the paper.

**Architecture:** (1) Parse CSV rows and derive a stable tree under a materialization root: one directory per unique `(owner, repo, commit)` and repo-relative paths preserved, files fetched over HTTPS from `raw.githubusercontent.com` (no full git clone required for MVP). (2) Reuse existing overlap stack: `run_semgrep_json_configs` → `overlap_for_file_bucket` / `aggregate_overlap_payloads` with the same `rule_map` and policy A/B as the corpus script. (3) Refactor the corpus script’s core loop into a small library module so both entrypoints stay DRY.

**Tech stack:** Python 3.12+, `httpx`, existing `eval/` modules, Semgrep CLI, running analyzer HTTP API (same as corpus eval).

**Related spec:** None on disk for this feature; behavioral parity with `scripts/corpus_paper_eval.py` and `eval/corpus_agreement.py`. Original corpus design referenced from README: `docs/superpowers/specs/2026-03-26-external-js-ts-corpus-semgrep-design.md` (path may vary).

---

## File map

| File | Responsibility |
|------|----------------|
| `eval/dataset_github.py` | Parse `full_repo_path` blob URLs → `(owner, repo, sha, path_in_repo)`; build raw GitHub URL; normalize CSV numeric strings (European thousands separators in `line`/`endline`). |
| `eval/dataset_materialize.py` | From parsed rows: unique file keys, concurrent-safe download via `httpx`, write `materialize_root/<snapshot_id>/...`, emit `materialization_manifest.json` (urls, sha256, row count). |
| `eval/corpus_paper_runner.py` | Extracted from `scripts/corpus_paper_eval.py`: given resolved corpus root + configs + rule_map + policy + analyzer URL → Semgrep JSON, per-file HTTP analyzer calls, aggregated summary dict (same keys as today’s output). |
| `scripts/corpus_paper_eval.py` | Thin CLI: argparse → call `corpus_paper_runner.run_paper_eval` → write JSON (behavior unchanged). |
| `scripts/dataset_paper_eval.py` | CLI: `--csv`, `--materialize-root`, optional `--refresh-materialize`, then call materializer then `run_paper_eval` on materialize root. |
| `tests/eval/test_dataset_github.py` | URL + int normalization tests. |
| `tests/eval/test_dataset_materialize.py` | Manifest dedupe + mocked HTTP downloads. |
| `tests/eval/test_corpus_paper_runner.py` | Mock Semgrep + mock httpx; assert summary shape and overlap math for 1–2 files. |
| `README.md` | Short subsection: dataset eval command, pinning manifest hash, caveat on GitHub rate limits. |

---

### Task 1: `eval/dataset_github.py` (parse URL + numeric columns)

**Files:**
- Create: `eval/dataset_github.py`
- Test: `tests/eval/test_dataset_github.py`

- [ ] **Step 1: Write failing tests**

```python
import pytest

from eval.dataset_github import parse_github_blob_url, parse_csv_int


def test_parse_blob_url_typical() -> None:
    u = "https://github.com/angular/angular.js/blob/f6aa1c55616b34215f562e0445e436210860ef04/src/ng/compile.js"
    assert parse_github_blob_url(u) == (
        "angular",
        "angular.js",
        "f6aa1c55616b34215f562e0445e436210860ef04",
        "src/ng/compile.js",
    )


def test_raw_url() -> None:
    from eval.dataset_github import github_blob_to_raw_url

    blob = "https://github.com/angular/angular.js/blob/abc123/src/ng/compile.js"
    assert github_blob_to_raw_url(blob) == (
        "https://raw.githubusercontent.com/angular/angular.js/abc123/src/ng/compile.js"
    )


def test_parse_csv_int_plain() -> None:
    assert parse_csv_int("942") == 942


def test_parse_csv_int_european_thousands() -> None:
    # Dataset exports may use dot as thousands separator
    assert parse_csv_int("1.200") == 1200
```

- [ ] **Step 2: Run test — expect failures**

Run: `pytest tests/eval/test_dataset_github.py -v`

Expected: import/attribute errors.

- [ ] **Step 3: Minimal implementation**

```python
from __future__ import annotations

import re
from urllib.parse import urlparse


def parse_github_blob_url(blob_url: str) -> tuple[str, str, str, str]:
    """
    Parse https://github.com/{owner}/{repo}/blob/{sha}/{path}
    Returns (owner, repo, full_sha, path_in_repo posix).
    """
    p = urlparse(blob_url.strip())
    if p.netloc not in ("github.com", "www.github.com"):
        raise ValueError(f"not a github.com URL: {blob_url!r}")
    parts = [x for x in p.path.split("/") if x]
    # parts: owner, repo, blob, sha, ...
    if len(parts) < 5 or parts[2] != "blob":
        raise ValueError(f"not a blob URL: {blob_url!r}")
    owner, repo, _, sha, *rest = parts
    path_in_repo = "/".join(rest)
    if not path_in_repo:
        raise ValueError(f"missing path in blob URL: {blob_url!r}")
    return owner, repo, sha, path_in_repo


def github_blob_to_raw_url(blob_url: str) -> str:
    owner, repo, sha, path_in_repo = parse_github_blob_url(blob_url)
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path_in_repo}"


_THOUSANDS_RE = re.compile(r"^\d{1,3}(\.\d{3})+$")


def parse_csv_int(s: str) -> int:
    t = s.strip().replace(",", ".") if "," in s else s.strip()
    if _THOUSANDS_RE.match(t):
        return int(t.replace(".", ""))
    return int(float(t.replace(",", ".")))
```

- [ ] **Step 4: Run tests — expect PASS**

Run: `pytest tests/eval/test_dataset_github.py -v`

- [ ] **Step 5: Commit**

```bash
git add eval/dataset_github.py tests/eval/test_dataset_github.py
git commit -m "feat(eval): parse GitHub blob URLs and CSV ints for dataset materialize"
```

---

### Task 2: `eval/dataset_materialize.py` (HTTPS materialization + manifest)

**Files:**
- Create: `eval/dataset_materialize.py`
- Test: `tests/eval/test_dataset_materialize.py`

**Behavior:**
- Input: iterable of rows with at least `full_repo_path` (and optionally `path` for cross-check).
- For each unique `(owner, repo, sha, path_in_repo)`: `snapshot_id = f"{owner}_{repo}_{sha[:12]}"` (sanitize `/` etc. in repo name to `_`).
- Destination: `materialize_root / snapshot_id / path_in_repo` (Path with parents).
- Skip download if file exists and `--no-refresh` (default); with `--refresh-materialize`, overwrite.
- `materialization_manifest.json`: `{ "files": [ { "blob_url", "raw_url", "relpath", "sha256", "bytes" } ], "csv_path", "row_count" }` where `relpath` is relative to `materialize_root` as POSIX (same as Semgrep will see).

- [ ] **Step 1: Write failing test** (mock `httpx.Client.get` to return fixed bytes; assert file written + manifest).

- [ ] **Step 2: Run pytest — FAIL**

- [ ] **Step 3: Implement** `materialize_dataset_csv(csv_path: Path, materialize_root: Path, *, refresh: bool = False) -> Path` returning path to manifest.

Use `hashlib.sha256` for content hash. Handle HTTP 404: collect errors and fail with a clear report listing missing files (common when commit is abbreviated incorrectly — use full SHA from URL).

- [ ] **Step 4: pytest PASS**

- [ ] **Step 5: Commit** `feat(eval): materialize JS vuln CSV via raw GitHub URLs`

---

### Task 3: Extract `eval/corpus_paper_runner.py`

**Files:**
- Create: `eval/corpus_paper_runner.py`
- Modify: `scripts/corpus_paper_eval.py` (delegate to runner)
- Test: `tests/eval/test_corpus_paper_runner.py`

**Function signature (illustrative):**

```python
def run_paper_eval(
    *,
    corpus: Path,
    configs: list[Path],
    rule_map: RuleMap,
    policy: Literal["a", "b"],
    file_mode: Literal["walk", "git"],
    analyzer_base: str,
    max_files: int,
    semgrep_timeout: int,
) -> dict[str, Any]:
    """Returns the summary dict currently built in corpus_paper_eval.main (before write)."""
```

Move: relpath listing, `run_semgrep_json_configs`, httpx loop, totals, per-bucket aggregation, assembly of `summary` — from `scripts/corpus_paper_eval.py` lines ~140–295 into this module. Keep `POLICY_B_NOTE` and `_environment_fields` either in runner or shared small constant module; avoid circular imports.

- [ ] **Step 1: Write test** with `tmp_path` corpus of two tiny `.js` files, `monkeypatch` `run_semgrep_json_configs` to return synthetic results, `monkeypatch` `httpx.Client.post` to return analyzer JSON with findings — assert `matched_line_pairs` etc.

- [ ] **Step 2: pytest FAIL**

- [ ] **Step 3: Implement extract + thin script**

- [ ] **Step 4: Manual smoke:** run existing README example for `corpus_paper_eval` if environment allows; else rely on test.

- [ ] **Step 5: Commit** `refactor(eval): extract corpus paper eval runner for reuse`

---

### Task 4: `scripts/dataset_paper_eval.py`

**Files:**
- Create: `scripts/dataset_paper_eval.py`
- Modify: `README.md` (one paragraph + example command)

**CLI mirrors corpus script where possible:**

- `--csv` (required)
- `--materialize-root` (required directory; created if missing)
- `--refresh-materialize` (flag)
- `--semgrep-config` (repeatable), `--rule-map`, `--policy`, `--analyzer`, `--out` (default `eval/results/dataset_eval_summary.json`), `--max-files`, `--semgrep-timeout`, analyzer identity flags, `environment-*`, `--dataset-id` (analogous to `--corpus-id`)

**Summary JSON extensions** (add fields, do not remove corpus fields):

- `dataset_csv`: absolute path string
- `materialization_manifest`: path + `manifest_sha256` of the manifest file
- `file_universe_rule`: e.g. `dataset_csv:JavaScriptVulnerability.csv+github_raw_fetch`
- Drop or empty `corpus_snapshot_hash` unless user passes `--dataset-snapshot-hash` (document as optional content hash of CSV file)

Flow:

1. Resolve paths, load CSV with stdlib `csv.DictReader` (utf-8-sig).
2. `materialize_dataset_csv(...)` 
3. `relpaths = list_js_ts_relpaths_walk(materialize_root)` — ensures only `.js`/`.ts`/… under tree.
4. `summary = run_paper_eval(corpus=materialize_root, ...)` then merge extra fields + write.

- [ ] **Step 1: Integration test** optional: `@pytest.mark.integration` that skips without `DATASET_CSV_EVAL=1`, runs materializer against one row fixture CSV pointing to a tiny public file — keep off CI by default.

- [ ] **Step 2: Implement CLI**

- [ ] **Step 3: Commit** `feat(scripts): dataset_paper_eval for CSV-driven Semgrep agreement`

---

### Task 5: Docs + paper hygiene

- [ ] **README:** Document GitHub rate limiting (unauthenticated ~60/hr/IP); recommend `GITHUB_TOKEN` env if you add optional `Authorization` header in materializer in a follow-up.
- [ ] **Paper methods one-liner:** "File versions fixed by commit SHA in CSV; content fetched from `raw.githubusercontent.com`; manifest records SHA-256 per file."

- [ ] **Commit** `docs: dataset_paper_eval usage and reproducibility notes`

---

## Plan review loop

After implementation, optionally dispatch **plan-document-reviewer** with:

- Plan path: `docs/superpowers/plans/2026-03-29-js-vuln-csv-dataset-semgrep-eval.md`
- Spec path: *none — parity with existing corpus eval behavior; cite README + `eval/corpus_agreement.py`*

Fix at most three review rounds, then escalate to the human.

---

## Optional follow-ups (out of scope unless requested)

- **Function-scoped metrics:** use CSV `line`/`endline` and `Vuln` to tag whether analyzer/Semgrep lines fall inside labeled functions (separate JSON section `by_csv_row`).
- **Git fallback** when raw URL 404 (submodule path or LFS).
- **Auth:** `httpx` headers from `GITHUB_TOKEN` for higher rate limits.

---

## Execution handoff

**Plan complete and saved to `docs/superpowers/plans/2026-03-29-js-vuln-csv-dataset-semgrep-eval.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach do you want?**
