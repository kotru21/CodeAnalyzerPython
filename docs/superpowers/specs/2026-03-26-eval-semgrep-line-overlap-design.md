# Eval catalog: Semgrep line overlap and rule equivalence

**Status:** Approved for implementation (spec review 2026-03-26)  
**Scope:** Phase A — catalog `eval.cli compare` only. Phase B (corpus / sidecar) is out of scope for this spec except a short forward-looking note.

---

## 1. Problem

Comparing this analyzer to Semgrep using only **per-file or per-case finding counts** does not show **where** tools agree. There is no objective shared TP/FN at line level across two different rule sets without an explicit **equivalence model**. This spec defines a **project-owned** model: allowed Semgrep `check_id`s per analyzer `rule_id`, optional per-`test_id` overrides later, and **line slop** for near matches.

---

## 2. Goals and non-goals

**Goals**

- For each non-`SKIP` catalog case, after `compare`, emit **structured line-level overlap** between analyzer findings and Semgrep findings **after** filtering Semgrep by the equivalence map.
- Keep the model **explainable** in docs: metrics are “agreement under our mapping,” not ground-truth security labels.
- Unit-test the matching logic without requiring Semgrep in CI.

**Non-goals**

- Claim universal precision/recall vs Semgrep.
- Phase B: arbitrary corpus trees without labels (see §8).
- Changing `classify_outcome` / gold TP-FN for the analyzer-only `report.md` in this work (overlap is additive to `compare` output).

---

## 3. Equivalence data

### 3.1 Primary: extend rule map YAML

Extend `eval/catalog/rule_map.yaml` (or a dedicated file merged at load time — implementation detail) with:

- `version` (unchanged convention).
- `line_slop: int` — default `0`; match lines `a` and `b` if `abs(a - b) <= line_slop` when both are integers.
- `rules.<analyzer_rule_id>.semgrep_check_ids: [string, ...]` — Semgrep rule identifiers to treat as **in scope** for that analyzer rule. **MVP:** **exact string match** only (`entry == check_id`). Prefix / glob wildcards are reserved for a later version unless explicitly added behind a feature flag.

Empty list for a rule means “no Semgrep rules considered equivalent” (Semgrep findings do not contribute to overlap for cases using that analyzer rule).

### 3.2 Secondary (later hook): overrides by `test_id`

Reserve structure for optional `overrides.<test_id>.semgrep_check_ids` (same list semantics) when rule-level mapping is insufficient. **MVP may ship with parser accepting but ignoring overrides** if not implemented day one; spec requires code paths to remain pluggable.

### 3.3 Loading

Reuse / extend `eval/rule_map.py` to expose:

- Resolved allowlist of `check_id` patterns for a given case (union over `case["rule_id"]` and `case.get("expected_rule_ids")`, same spirit as `collect_semgrep_configs_for_cases`).

---

## 4. Which analyzer findings enter the comparison

**Default policy (MVP):**

- **Vulnerable** cases: include analyzer findings whose `rule_id` is in `{case["rule_id"]} ∪ expected_rule_ids` (if present). Ignore other analyzer findings for overlap (reduces noise from unrelated rules on small snippets). These contribute to `analyzer_lines` in §6.
- **Safe** cases: **`analyzer_lines` is always empty** for overlap (do not include analyzer findings, even if rule_id matches). Semgrep side still filtered by the case’s rule mapping into `semgrep_lines_in_map`. Rationale: overlap is defined as “agreement on signaled lines under mapping”; for safe snippets we only surface whether Semgrep fires in-map.

Interpretation in README: safe case + non-empty `semgrep_lines_in_map` is a **benchmark signal**, not an automatic FP label.

Implementations may add a flag `--overlap-policy` later (e.g. include all analyzer findings on safe cases); MVP = policy above.

---

## 5. Semgrep findings input

Use per-case Semgrep results already produced by batch scan (`results` filtered to paths matching that case’s `test_id` stem). Each item contributes `(check_id, line)` if `check_id` is allowed after §3.

---

## 6. Output shape

Add to `compare_summary.json` **per row** (for non-SKIP cases) a field `line_overlap` (name fixed in implementation), roughly:

```json
{
  "line_slop_used": 0,
  "analyzer_lines": [3, 5],
  "semgrep_lines_in_map": [3],
  "matched_lines": [[3, 3]],
  "analyzer_only_lines": [5],
  "semgrep_only_lines": []
}
```

- **Input hygiene:** Findings with missing / non-integer `line` are **excluded** from line sets and from matching (both tools).
- **Duplicates:** Before matching, **deduplicate** integer line numbers per side (set semantics for matching; output `analyzer_lines` / `semgrep_lines_in_map` as sorted unique lists).
- `matched_lines`: pairs `[analyzer_line, semgrep_line]`. **MVP pairing algorithm:** sort unique `analyzer_lines` ascending; sort unique `semgrep_lines_in_map` ascending; **greedy:** for each analyzer line `a` in order, assign the **smallest** still-unmatched Semgrep line `s` such that `abs(a - s) <= line_slop`; each `s` used at most once. Unmatched lines go to `analyzer_only_lines` / `semgrep_only_lines`.
- Omit or null `line_overlap` for `SKIP` rows.

Optional aggregate section at top of file: counts of cases with `len(matched_lines) > 0`, etc.

---

## 7. Integration point

After `run_catalog` builds rows with `by_backend`, a pure function `compute_line_overlaps(rows, cases_by_id, rule_map)` enriches rows. Called from `eval/cli.py` `execute_compare` before writing JSON.

Dependencies: raw Semgrep `results` per case must remain addressable — today `by_backend.semgrep` stores `finding_count` and raw lives under `eval/results/raw/<test_id>.semgrep.json`; overlap step may re-read raw or attach normalized lists during catalog run (implementation choice; prefer **no second Semgrep run**).

---

## 8. Phase B (corpus) — forward note only

For `scripts/corpus_paper_eval.py` and successors: line-level comparison on arbitrary trees is covered by `docs/superpowers/specs/2026-03-26-external-js-ts-corpus-semgrep-design.md`. Optional oracle metrics still need sidecar labels. No further design in this document.

---

## 9. Testing

- Table-driven tests: given two synthetic finding lists + YAML fragment → expected sets and pairs.
- Edge: empty allowlist, `line_slop` 0 vs 2, multi-rule `expected_rule_ids`, missing lines (`null`).

---

## 10. Documentation

- README eval section: one short paragraph on what `line_overlap` means and that it is **mapping-dependent**.
- Do not use “Made with Cursor” or tool marketing strings in committed docs.

---

## 11. Open implementation choices (non-blocking)

- Min-cost matching (e.g. Hungarian) as an alternative to greedy — optional later; MVP is greedy per §6.
- Whether to embed `line_overlap` inside `compare_summary.json` vs sibling file (default: **inside** same object for one artifact).
