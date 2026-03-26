# Scanner high-priority upgrades — implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans task-by-task. Steps use `- [ ]` checkboxes.

**Goal:** Raise analysis fidelity and perceived “readiness” for thesis work: stronger **same-file taint** (calls currently blocked), **optional chaining**, a **minimal multi-file** path, **targeted new rules** from FN evidence, and **predictable** runtime behavior—without boiling the ocean into full commercial SAST.

**Architecture:** Changes stay centered on `analyzer.core.orchestrator.Orchestrator`, `analyzer.taint.tracker.TaintTracker`, and optionally a thin **multi-file front** (new request shape + import resolution stub) that still produces the same `AnalyzeResponse` finding schema.

**Tech stack:** Existing tree-sitter JS/TS stack, FastAPI, pytest.

**Context:** README today documents bare-identifier interproc only (`run(x)`); `member_expression` callees are excluded in `_maybe_analyze_callee_interproc` (`func.type != "identifier"`).

---

## File map (planned touchpoints)

| Area | Files |
|------|--------|
| Taint interproc | `src/analyzer/taint/tracker.py`, `tests/test_taint/test_taint_interprocedural.py` |
| Optional chaining | `src/analyzer/taint/tracker.py`, `_extract_source`, `_find_tainted_in_arg`, tests |
| Multi-file MVP | `src/analyzer/api/schemas.py`, `src/analyzer/api/router.py`, `src/analyzer/core/orchestrator.py` (or new `multi_analyze.py`), tests |
| Time budget | `src/analyzer/core/orchestrator.py`, `src/analyzer/config.py`, tests |
| Rules | `src/analyzer/rules/javascript/*.py`, `eval/cases_pack` + catalog for regression |
| Docs | `README.md` (limitations / new endpoint) |

---

## Phase 1 — Taint: `obj.method()` same-file interprocedural

**Problem:** `_maybe_analyze_callee_interproc` returns early when `function` is not an `identifier`, so `foo(bar)` is analyzed but `obj.foo(bar)` is not.

**Design (MVP):**

- When `function` is `member_expression`, take **property** identifier as **callee name** (e.g. `x.run` → `run`).
- Look up `run` in existing `fn_index` (same as today).
- **Document ambiguity:** two functions named `run` in file—index already last-wins per `_index_functions`; member call uses same rule as today for name collisions.
- **Out of scope for MVP:** dispatch on receiver type, `super.run`, computed property names.

**Tasks**

- [ ] **Step 1:** Add failing tests in `tests/test_taint/test_taint_interprocedural.py`: e.g. `const o = { run: function(y) { sink(y); } };` style or `function run(q) { exec(q); }` called as `obj.run(req.query.x)` with appropriate source—minimal repro matching tree-sitter shape.
- [ ] **Step 2:** Extend `_maybe_analyze_callee_interproc` to handle `member_expression` → property name lookup; keep depth and sanitizer behavior identical to identifier path.
- [ ] **Step 3:** Run `pytest tests/test_taint/test_taint_interprocedural.py -v` and full `pytest tests/test_taint/ -v`.
- [ ] **Step 4:** Update README taint bullet to state **member call** support and remaining gaps (`?.`, cross-file).
- [ ] **Step 5:** Commit `feat(taint): same-file interproc for member_expression callees`.

---

## Phase 2 — Taint: optional chaining (`?.`)

**Problem:** Optional chaining changes AST shape; taint may not propagate through `member_expression` / `call_expression` wrapped in optional chain nodes.

**Design (MVP):**

- Identify tree-sitter node types used for optional chaining in JS grammar (often nested `member_expression` with different field names or parent `optional_chain` depending on grammar version—**verify in fixture parse**).
- In `_extract_source` and `_find_tainted_in_arg`, recurse into optional-chain children so `req?.query` still matches `req.query` patterns where safe.
- Tests: `req?.query` → sink patterns already covered for non-optional.

**Tasks**

- [ ] **Step 1:** Add parse snippet test or use existing parser helper to print node types for `a?.b` and `req?.query?.x`.
- [ ] **Step 2:** Implement propagation; add `tests/test_taint/test_optional_chain.py` (or extend matrix).
- [ ] **Step 3:** `pytest tests/test_taint/ -v`; update README one line.
- [ ] **Step 4:** Commit `feat(taint): optional chaining for source/sink taint paths`.

---

## Phase 3 — Multi-file MVP (bounded)

**Problem:** Single `source_code` string cannot model import taint across files—limits realism vs “project scanner.”

**Design (choose one track—recommend A for thesis clarity):**

| Track | Description | Trade-off |
|-------|-------------|-----------|
| **A. Bundle request (recommended)** | New endpoint e.g. `POST /api/v1/analyze/bundle` with JSON `{ "files": { "rel/path.js": "..." }, "entry": "main.js" }` (max N files, max total bytes). Build per-file `AnalysisContext`, resolve **static** `require("./a")` / `import x from "./a"` to concatenate or cross-index taint—**MVP:** only re-export taint for explicitly listed files; no node_modules. | Clear API story for dissertation “limited project mode”; more code. |
| **B. CLI-only bundle** | `py -m analyzer.scan_bundle path/` reads disk, no new HTTP surface. | Faster to ship; weaker demo for API-first thesis. |

**MVP scope (Track A):**

- Cap: e.g. 32 files, 512 KiB total (config-driven).
- Parse imports; build map `relPath → source`.
- **Phase 3a:** Run current single-file analysis on **entry** only but **inline** or **preface** imported file sources as comments—too hacky; **prefer 3b**.
- **Phase 3b:** For each file, run taint with **shared** `fn_index` merged across all files (same global function name still ambiguous—document). **No** cross-file calls unless callee file also defines the function and name resolves—defer true cross-file call graph to Phase 3c if timeboxed.

**Tasks (3b minimum)**

- [ ] **Step 1:** Spec exact JSON schema in `schemas.py` + OpenAPI-friendly models.
- [ ] **Step 2:** Implement `merge_fn_index` across parsed trees; single `TaintTracker` pass per file or unified walk—pick simplest that passes tests.
- [ ] **Step 3:** Test: `a.js` defines `function sinkData(q){...}`, `b.js` `import { sinkData } from './a.js'` and passes tainted arg—**if import resolution too large**, reduce to `require` only for MVP.
- [ ] **Step 4:** Document limitations in README; commit `feat(api): analyze bundle MVP`.

---

## Phase 4 — Rules driven by FN / gaps

**Process (not one-shot):**

- [ ] Run `eval.cli compare` + catalog `report.md`; list **FN** by `rule_id`.
- [ ] For top 2–3 FNs, add minimal `cases_pack` regression + rule fix in `src/analyzer/rules/javascript/`.
- [ ] Re-run catalog; ensure no FP explosion on `TN` cases.

**Tasks**

- [ ] **Step 1:** Export FN list (script or manual table) from latest `compare_summary.json` / `report.md`.
- [ ] **Step 2:** Pick one CWE/rule cluster; implement; commit per rule cluster.

---

## Phase 5 — Stability and predictability

**Design:**

- Add **wall-clock budget** to `Orchestrator.analyze_sync` (e.g. `settings.analysis_budget_ms`), default generous (e.g. 60_000); on exceed, return partial results with `status` or add `stats.truncated_reason` / extend `failed_rules` with synthetic sentinel—**prefer** completing with `stats.analysis_timeout_ms` and empty extra findings rather than 500.
- Log slow rules in debug mode (optional).

**Tasks**

- [ ] **Step 1:** Failing test: infinite-loop-ish pattern or mock slow rule—use budget 50ms with tiny rule stub.
- [ ] **Step 2:** Implement budget check between rule batches / taint phases (document where hook lives).
- [ ] **Step 3:** Config + README; commit `feat(core): analysis time budget`.

---

## Verification commands

```bash
pytest tests/test_taint/ -v
pytest tests/ -q --tb=no   # or full suite before merge
```

---

## Suggested order (thesis impact / risk)

1. Phase 1 (member callee) — **high signal**, localized code.  
2. Phase 2 (optional chaining) — **medium**, grammar-sensitive.  
3. Phase 5 (time budget) — **low risk**, helps large `corpus_paper_eval` honesty.  
4. Phase 4 (FN rules) — **ongoing**, parallel to above.  
5. Phase 3 (bundle) — **largest**; start only after Phase 1–2 stable or scope to Track B if time-constrained.

---

## After this plan

Optional formal spec: `docs/superpowers/specs/2026-03-26-taint-and-bundle-design.md` if Phases 1–3 need committee/reviewer sign-off. Otherwise proceed with **writing-plans**-style execution per phase above.
