# External corpus: Semgrep agreement (paper eval) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One CLI-driven pipeline that scans a frozen local JS/TS tree with Semgrep and the HTTP analyzer, computes per-file, per-bucket line overlap (Policy A or B), and writes `corpus_eval_summary.json` with reproducibility metadata per `docs/superpowers/specs/2026-03-26-external-js-ts-corpus-semgrep-design.md`.

**Architecture:** Add small pure modules under `eval/` for deterministic file listing, path-normalized Semgrep line extraction, and aggregation atop existing `eval/line_overlap.py` (`build_line_overlap_payload`, `greedy_match_lines`). Replace ad-hoc file-level-only reporting in `scripts/semgrep_corpus_compare.py` by delegating to the new library **or** add a parallel script `scripts/corpus_paper_eval.py` that is the supported entry point for papers (keep old script as thin wrapper or deprecate in README—implementation choice in Task 7). No changes to catalog `classify_outcome` or `eval.cli compare` behavior.

**Tech stack:** Python 3.x, existing `httpx`, `eval.backends.semgrep_subprocess.run_semgrep_json_configs`, `eval.rule_map.load_rule_map`, `yaml` (already used).

**Spec:** @docs/superpowers/specs/2026-03-26-external-js-ts-corpus-semgrep-design.md

---

## File structure (planned)

| File | Responsibility |
|------|----------------|
| `eval/corpus_paths.py` | Deterministic JS/TS path lists: `walk` (rglob + sort) vs optional `git ls-files`. |
| `eval/corpus_semgrep_normalize.py` | Map Semgrep JSON `path` strings to corpus-relative POSIX paths; extract lines per `(relpath, allowed_check_ids)`. |
| `eval/corpus_agreement.py` | Build per `(relpath, bucket)` overlap payloads; aggregate global counts; Policy A / B bucket definitions from `RuleMap`. |
| `eval/corpus_repro.py` | SHA-256 for config paths, `semgrep --version` subprocess, optional fields for analyzer invoke string. |
| `scripts/corpus_paper_eval.py` | argparse, orchestration: list files → semgrep once → analyzer per file → write summary JSON. |
| `tests/eval/test_corpus_paths.py` | Temp dirs + git fixture for path listing. |
| `tests/eval/test_corpus_semgrep_normalize.py` | Synthetic Semgrep results + path normalization. |
| `tests/eval/test_corpus_agreement.py` | End-to-end aggregation on synthetic findings/results (no Semgrep). |
| `tests/eval/test_corpus_repro.py` | SHA-256 and optional mocked Semgrep version. |
| `README.md` | Paper corpus eval subsection + pointer from `semgrep_corpus_compare.py` (single task owns all README edits). |

**§4 file-universe MVP:** Implement **extension-filtered** `walk` and `git ls-files` only. **Deferred** (document in README + `file_universe_rule` string): honoring `.gitignore` beyond `git ls-files`, max file bytes, and binary detection. The summary must state `file_universe_rule: "walk:rglob_ext=.js,.jsx,.ts,.tsx"` (or `git:ls-files+ext filter`) so the paper matches what was run.

---

### Task 1: File universe (`eval/corpus_paths.py`)

**Files:**
- Create: `eval/corpus_paths.py`
- Test: `tests/eval/test_corpus_paths.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/eval/test_corpus_paths.py
from pathlib import Path

from eval.corpus_paths import list_js_ts_relpaths_walk


def test_walk_collects_sorted_unique_relpaths(tmp_path: Path) -> None:
    (tmp_path / "a.ts").write_text("//", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.js").write_text("", encoding="utf-8")
    (tmp_path / "skip.txt").write_text("", encoding="utf-8")
    out = list_js_ts_relpaths_walk(tmp_path)
    assert out == ["a.ts", "sub/b.js"]  # sorted lexicographically as POSIX strings
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/eval/test_corpus_paths.py::test_walk_collects_sorted_unique_relpaths -v`

Expected: FAIL (import or missing function).

- [ ] **Step 3: Implement**

```python
# eval/corpus_paths.py
from __future__ import annotations

from pathlib import Path

DEFAULT_JS_TS_EXTENSIONS = frozenset({"js", "jsx", "ts", "tsx"})


def _to_posix_relpath(corpus_root: Path, file_path: Path) -> str:
    rel = file_path.resolve().relative_to(corpus_root.resolve())
    return rel.as_posix()


def list_js_ts_relpaths_walk(
    corpus_root: Path,
    *,
    extensions: frozenset[str] | None = None,
) -> list[str]:
    root = corpus_root.resolve()
    ext = extensions if extensions is not None else DEFAULT_JS_TS_EXTENSIONS
    found: list[str] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lstrip(".").lower() not in ext:
            continue
        found.append(_to_posix_relpath(root, p))
    return sorted(set(found))


def list_js_ts_relpaths_git(
    corpus_root: Path,
    *,
    extensions: frozenset[str] | None = None,
) -> list[str]:
    import subprocess

    root = corpus_root.resolve()
    ext = extensions if extensions is not None else DEFAULT_JS_TS_EXTENSIONS
    proc = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        check=False,
        text=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "git ls-files failed; use walk mode or run from a git checkout"
        )
    raw = proc.stdout.split(b"\0")
    out: list[str] = []
    for b in raw:
        if not b:
            continue
        rel = b.decode("utf-8", errors="replace").replace("\\", "/")
        suf = Path(rel).suffix.lstrip(".").lower()
        if suf not in ext:
            continue
        p = (root / rel).resolve()
        if not p.is_file():
            continue
        out.append(Path(rel).as_posix())
    return sorted(set(out))
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/eval/test_corpus_paths.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add eval/corpus_paths.py tests/eval/test_corpus_paths.py
git commit -m "feat(eval): deterministic JS/TS corpus path listing"
```

---

### Task 2: Semgrep path normalization and line extraction

**Files:**
- Create: `eval/corpus_semgrep_normalize.py`
- Modify: `eval/line_overlap.py` (only if you prefer a one-liner re-export; otherwise keep all corpus-specific logic in `corpus_semgrep_normalize.py`)
- Test: `tests/eval/test_corpus_semgrep_normalize.py`

- [ ] **Step 1: Write failing tests**

Assert that for `corpus_root = /tmp/corpus` and Semgrep result `path` equal to `str(/tmp/corpus/sub/x.js)`, `relpath` resolves to `sub/x.js` and lines with allowed `check_id` are collected.

Include tests: `allowed_check_ids=frozenset()` → no lines; `allowed_check_ids=None` → all matching paths’ lines.

- [ ] **Step 2: Run pytest → FAIL**

- [ ] **Step 3: Implement** `semgrep_result_relpath(corpus_root: Path, result_path: str | None) -> str | None` and `integer_lines_from_semgrep_for_relpath(..., target_relpath: str, allowed_check_ids: frozenset[str] | None) -> list[int]`: when `allowed_check_ids is None`, include **all** `check_id` values (Policy B); when `frozenset()`, include none. Path matching: normalize to `relative_to(corpus_root.resolve()).as_posix()` when under corpus; otherwise skip.

- [ ] **Step 4: pytest PASS**

- [ ] **Step 5: Commit** `feat(eval): Semgrep results normalized to corpus relpaths`

---

### Task 3: Policy A/B buckets and aggregation

**Files:**
- Create: `eval/corpus_agreement.py`
- Test: `tests/eval/test_corpus_agreement.py`

- [ ] **Step 1: Write tests**

1. **Policy A:** `RuleMap` with `equivalence_rules` for two analyzer rule ids; synthetic analyzer findings and semgrep results for one file → two buckets, correct `matched_lines` counts when lines align with `line_slop=0`.

2. **Policy B:** Single logical bucket: all analyzer findings (any `rule_id`), all semgrep results (any `check_id`) for that file—verify totals.

3. **Aggregation:** Sum `len(matched_lines)`, `len(analyzer_only_lines)`, `len(semgrep_only_lines)` across multiple `(relpath, bucket)` payloads matches hand-calculated totals.

- [ ] **Step 2: Implement**

  - `def buckets_for_policy(policy: Literal["a","b"], rule_map: RuleMap) -> list[str]:`  
    - `a`: sorted keys of `rule_map.equivalence_rules` with non-empty check-id lists.  
    - `b`: `["ALL_MAPPED"]` only.

  - **Policy a:** For bucket `rid`, Semgrep lines = `integer_lines_from_semgrep_for_relpath(..., allowed_check_ids=frozenset(rule_map.equivalence_rules[rid]))`; analyzer lines = `integer_lines_from_analyzer_findings(..., allowed_rule_ids=frozenset({rid}))`.

  - **Policy b:** Semgrep lines = `integer_lines_from_semgrep_for_relpath(..., allowed_check_ids=None)`; analyzer lines = all findings with valid lines (`allowed_rule_ids` = frozenset of every `rule_id` seen in that file’s findings, or extract lines without filtering by rule—same effect). Summary JSON includes `policy_b_note` string as in Task 5. **No** requirement that `equivalence_rules` be non-empty for Policy B.

  - `def overlap_for_file_bucket(...) -> dict:` build `build_line_overlap_payload(line_slop=..., analyzer_lines=..., semgrep_lines_in_map=...)`.

  - `def aggregate_overlap_payloads(payloads: list[dict]) -> dict[str, int]:` keys `matched_line_pairs`, `analyzer_only_lines`, `semgrep_only_lines` = **global** sums of list lengths.

- [ ] **Step 3: pytest PASS**

- [ ] **Step 4: Commit** `feat(eval): corpus line overlap per bucket and aggregates`

---

### Task 4: Reproducibility helpers

**Files:**
- Create: `eval/corpus_repro.py`
- Test: `tests/eval/test_corpus_repro.py`

- [ ] **Step 1: Write failing tests** — assert `sha256_file` on a temp file with known bytes matches a precomputed SHA-256; use `monkeypatch` to stub `subprocess.run` for `semgrep_cli_version()` returning a fixed stdout line.

- [ ] **Step 2: Run pytest → FAIL**

- [ ] **Step 3: Implement** `sha256_file(path: Path) -> str`, `config_bundle_hashes(paths: list[Path]) -> dict[str, str]` (basename → sha256), `semgrep_cli_version() -> str` via `subprocess.run([semgrep_executable(), "--version"], ...)` first line of stdout.

- [ ] **Step 4: pytest PASS**

- [ ] **Step 5: Commit** `feat(eval): reproducibility metadata for corpus eval`

---

### Task 5: CLI script `scripts/corpus_paper_eval.py` + README

**Files:**
- Create: `scripts/corpus_paper_eval.py`
- Modify: `README.md` (eval / benchmark section); `scripts/semgrep_corpus_compare.py` docstring (one-line pointer)

- [ ] **Step 1: argparse**

  - `--corpus` (required `Path`)
  - `--semgrep-config` (required `Path`, or allow repeat `--semgrep-config`; pass list to `run_semgrep_json_configs`)
  - `--rule-map` default `eval/catalog/rule_map.yaml` (repo-relative from cwd or resolve via `eval.catalog_loader.repo_root()`)
  - `--policy` choices `a`, `b`
  - `--file-mode` choices `walk`, `git` (default `walk`)
  - `--analyzer` default `http://localhost:8000`
  - `--out` default `eval/results/corpus_eval_summary.json`
  - `--corpus-id` optional string (default: corpus dir name or full path string)
  - `--corpus-snapshot-hash` optional (default: empty; user passes git commit for paper)
  - `--analyzer-invoke` optional string recorded verbatim in JSON (e.g. `POST .../analyze/sync`)
  - `--analyzer-git-commit` optional string (or `--analyzer-version` optional string): at least **one** should be documented for §7; if both omitted, emit `analyzer_version: null` and `analyzer_git_commit: null` plus `analyzer_identity_note: "not provided; pass --analyzer-git-commit for paper"`
  - `--environment-note` optional string
  - `--environment-out-of-scope` `store_true`: if set, JSON **must** include `"environment_out_of_scope": true` and **must not** require `environment_note`. If **not** set and `--environment-note` is absent, emit `"environment_out_of_scope": true` and `"environment_note": null` (explicit §7-valid default: environment not pinned). If `--environment-note` is set, emit `environment_note` and `environment_out_of_scope: false`.
  - `--max-files` int default 0 (unlimited)

- [ ] **Step 2: Orchestration**

  1. Resolve repo root (reuse `eval.catalog_loader.repo_root`).
  2. Load rule map; `line_slop = rule_map.line_slop`.
  3. List files via `list_js_ts_relpaths_*`.
  4. `run_semgrep_json_configs(configs, corpus, timeout_sec=...)`.
  5. Build `results_by_relpath: dict[str, list[dict]]` by bucketing raw Semgrep `results` using `corpus_semgrep_normalize.semgrep_result_relpath`.
  6. `httpx.Client`: for each relpath, read file, POST like `scripts/semgrep_corpus_compare._analyze_file`, collect findings.
  7. For each `(relpath, bucket)` compute overlap; append to list; optional `per_unit` detail array (YAGNI: include only if `--verbose-json` flag added; default summary only + optional `top_analyzer_only_files` truncated—defer to keep JSON small unless spec requires; **MVP: global counts + `buckets` list with per-bucket totals only**, not every file).

  Clarification for MVP output shape: include `aggregate` global counts plus `by_bucket: { bucket: { matched_line_pairs, ... } }` without per-file matrix to keep file size sane for large corpora; add `--per-file` flag later if needed (out of scope for first PR).

- [ ] **Step 3: Write summary JSON (§7 checklist)** — required keys:

  - `files_scanned` = number of files successfully submitted to analyzer (or listed, if analyzer errors counted separately—**define:** `files_scanned` = len(path list after `--max-files`); `files_with_js_ts` = same as `files_scanned` for this MVP since list is JS/TS-only).
  - `analyzer_findings_total` = sum of finding counts **after** bucket policy (sum over files of counts included in overlap inputs—document: for Policy A, sum per-file findings whose `rule_id` is in any bucket; for Policy B, sum all findings).
  - `semgrep_findings_total` = count of Semgrep `results` entries **after** path normalization and policy (Policy A: only results whose `check_id` is allowed for at least one bucket when attributing—**MVP:** count all results under corpus with `check_id` matching any bucket’s allowlist for policy `a`; for policy `b`, count all results for listed files).
  - `matched_line_pairs`, `analyzer_only_lines`, `semgrep_only_lines` = **global** sums from `aggregate_overlap_payloads`.
  - Plus: `corpus_id`, `corpus_snapshot_hash`, `file_universe_rule`, `analyzer_invoke`, `analyzer_version` / `analyzer_git_commit` (nullable + note), `semgrep_version`, `semgrep_config_paths`, `semgrep_config_sha256`, `semgrep_cli_argv`, `environment_note`, `environment_out_of_scope`.

- [ ] **Step 4: Gate on pytest only** — optional manual smoke on dev machine is **non-gating**; mark Task 5 done when unit tests pass.

- [ ] **Step 5: README** — add bullet for `corpus_paper_eval.py` (spec link, disclaimer, §4 MVP limitation on file universe, example command); add one-line pointer in `semgrep_corpus_compare.py` docstring.

- [ ] **Step 6: Commit** `feat(scripts): corpus_paper_eval for Semgrep agreement summary`

---

### Task 6: Optional integration hook (skipped in CI by default)

**Files:**
- Optional: `tests/eval/test_corpus_paper_eval_integration.py` with `@pytest.mark.skipif(not os.environ.get("SEMGREP_INTEGRATION"), reason="...")`.

- [ ] **Step 1:** **YAGNI default: omit.** Document `SEMGREP_INTEGRATION` in README only if an integration test is added later.

---

## Testing commands (full suite)

```bash
pytest tests/eval/test_corpus_paths.py tests/eval/test_corpus_semgrep_normalize.py tests/eval/test_corpus_agreement.py tests/eval/test_corpus_repro.py -v
```

## Plan review

After implementation, run ruff/pyright if the repo uses them on touched files.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-03-26-external-corpus-semgrep-agreement.md`. Two execution options:

**1. Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks, fast iteration (@superpowers:subagent-driven-development).

**2. Inline Execution** — execute tasks in this session using checkpoints (@superpowers:executing-plans).

**Which approach?**
