# External JS/TS corpus: citable dataset vs Semgrep baseline

**Status:** Draft — user approved design intent 2026-03-26; revised after internal spec review (methodology / reproducibility)  
**Related:** `2026-03-26-eval-semgrep-line-overlap-design.md` (line-level overlap mechanics on the **project catalog**). That document’s Phase B note targets **line-level evaluation against an oracle / labels**; *this* spec targets **analyzer–Semgrep agreement** at lines and does **not** require vulnerability labels (sidecar metadata is only for stratification or optional supervised metrics in §6).

---

## 1. Problem

The in-repo benchmark catalog (`eval/catalog/cases.json`) is useful for regression testing but is **not** a standard academic dataset. For a thesis or paper you need a **citable, frozen snapshot** of real or research JS/TS code, a **reproducible Semgrep configuration**, and a **single clear summary**: where your analyzer agrees with Semgrep at line granularity and where it diverges—so you know what to improve next.

---

## 2. Goals and non-goals

**Goals**

- Evaluate **only JS/TS** artifacts from an **externally citable** source (peer-reviewed dataset paper + released artifact, or a derivative subset with an explicit selection protocol and primary citations such as CVE/GitHub Advisory).
- Run **Semgrep** (pinned version) and **this analyzer** on the **same file set**, then compute **line-level agreement** using the same conceptual model as catalog overlap: filter Semgrep by an **equivalence policy** (see §5), optional `line_slop`, dedupe, greedy pairing.
- Emit **one machine-readable summary** suitable for tables in the paper: counts of matched lines, analyzer-only lines, Semgrep-only lines, aggregated over the corpus (and optionally per CWE / per rule family if sidecar metadata exists).
- Document **reproducibility** symmetrically for **both** tools: Semgrep CLI version; **analyzer** release or git commit, build/API config, and invocation (e.g. base URL + endpoint or batch driver flags); exact Semgrep `--config` arguments; corpus snapshot id (commit, archive checksum, date). Field-level checklist: §7; pipeline and environment bounds: §4.

**Non-goals**

- Replace Juliet / OWASP Benchmark as the “main” citation—they are not JS/TS-first; this track explicitly targets **JS/TS citable corpora**.
- Treat Semgrep as ground truth: agreement metrics are **“agreement under stated rule policy,”** not universal security correctness.
- Mandate a single named dataset in this spec: the **choice** of corpus is left to the author but must satisfy §3.

---

## 3. Dataset eligibility (for the paper)

A corpus is acceptable for this design if **all** hold:

1. **Citable provenance:** primary reference is a **published** work (DOI) **or** an official database (e.g. advisory/CVE) plus a **documented** filtering protocol in your paper.
2. **JS/TS subset:** evaluation is restricted to `.js`, `.jsx`, `.ts`, `.tsx` (exact extensions configurable; non-matching files excluded from metrics).
3. **Frozen snapshot:** a fixed revision or archive; no “live HEAD” without a recorded commit hash.
4. **Ethics / licensing:** license and redistribution constraints stated in the paper; snapshot hosted or cited per publisher requirements.

**Examples of corpus classes** (illustrative, not exclusive): research vulnerability corpora that include JS/TS slices; CVE-derived JS/TS subsets with frozen clone list; smaller released benchmarks explicitly tied to a publication.

---

## 4. Pipeline (logical)

1. **Prepare snapshot** — checkout or unpack corpus; record identifier and checksums.
2. **Build the file universe** — one deterministic rule, recorded in the paper and in the summary JSON, e.g. `git ls-files` at snapshot commit filtered by extension, or a rooted walk with explicit ignore patterns (`.gitignore`, max file size, binary skip). Include exact extension set (default `.js`, `.jsx`, `.ts`, `.tsx`). Two independent runs must produce the **same** path list.
3. **Run Semgrep** once over that list (batch mode preferred for performance), with fixed configs.
4. **Run the analyzer** on the same paths (existing HTTP API or batch driver—implementation detail).
5. **Normalize findings** to `(path, rule_or_check_id, line)` per tool.
6. **Apply equivalence policy** (§5) so only Semgrep rules “in scope” for each **comparison bucket** are counted.
7. **Line overlap** — within each bucket, reuse catalog semantics for dedupe, optional slop, and greedy pairing (see §5.1 for bucket definition). Emit per-bucket payloads, then aggregate.
8. **Aggregate** — global and (if metadata exists) stratified counts for the paper.

Steps 2–8 should be invokable as **one documented command** or script entry point in the repo (exact CLI is an implementation-plan detail). The reproducibility appendix should state whether **environment** is pinned (e.g. Docker image digest, OS, Semgrep install method) or explicitly left **out of scope**—avoid claiming full reproducibility without stating bounds.

---

## 5. Equivalence policy for an external corpus

Unlike catalog cases, there is no per-`test_id` `rule_id` in the dataset JSON. The spec requires **one explicit policy**, chosen and justified in the paper:

- **Policy A (strict):** map analyzer `rule_id` / CWE families to **explicit** Semgrep `check_id` allowlists (same idea as `rule_map.yaml`), and report overlap **per analyzer rule** or per CWE bucket using sidecar metadata if available.
- **Policy B (exploratory):** union of Semgrep rules from a **named, frozen** registry pack—**must** be labeled in the paper as a broad baseline. Minimum reproducibility requirements: exact pack identifier; **vendored or cached** rule files committed or archived with **SHA-256**; recorded literal `--config` arguments (no reliance on live registry without a lock). Specify how “JS/TS” applies to rules (e.g. Semgrep’s rule `languages` field vs scan `--lang` vs file extension filter).

Default recommendation for a **defensible** paper: **Policy A** where metadata allows; **Policy B** only as a secondary column.

### 5.1 Which findings enter line sets (differs from catalog “safe” cases)

The catalog overlap spec intentionally clears **analyzer** lines on **safe** snippets while still surfacing in-map Semgrep lines. A **tree corpus** has no per-file `type: safe|vulnerable` in the same sense.

**External corpus default:** for each **comparison bucket** (e.g. one analyzer `rule_id` under Policy A), include **all analyzer findings whose `rule_id` matches that bucket**. Semgrep lines are those with `check_id` allowed for that bucket after the map. Overlap is computed **per file path** within the bucket: greedy pairing runs on the integer line sets for that `(path, bucket)` (not globally across files). Implementations must **not** blindly reuse catalog “safe case ⇒ empty analyzer lines” for corpus files.

If the paper uses a single global bucket (Policy B), use one bucket key such as `ALL_MAPPED` and the same per-file pairing.

### 5.2 Matching granularity (summary)

**Unit of pairing:** each **(relative_path, bucket)** pair gets its own dedupe → slop → greedy pairing. **Aggregation** sums counts across all `(path, bucket)` units unless the paper defines a different roll-up.

---

## 6. Optional: metrics vs dataset labels

If the citable corpus provides **vulnerable / safe** labels (or line ranges):

- Report **standard** metrics vs those labels (e.g. precision/recall/F1 at line or file level—exact definition fixed in the paper).
- Still report **Semgrep agreement** as a separate column so readers see both **oracle-from-dataset** and **agreement-with-baseline**.

If labels are weak or absent, the paper relies on **Semgrep agreement + qualitative analysis** of `analyzer_only` and `semgrep_only` buckets, with clear limitation statements.

---

## 7. Outputs for the paper

Minimum summary object (conceptual):

- `corpus_id`, `corpus_snapshot_hash`, `file_universe_rule` (e.g. `git_ls_files` + extension list + ignores)
- `analyzer_version` or `analyzer_git_commit`, `analyzer_invoke` (e.g. API URL + route or CLI)
- `semgrep_version`, `semgrep_config_paths`, `semgrep_config_sha256` (per vendored file or bundle), `semgrep_cli_argv` (literal `--config` args)
- `environment_note` (e.g. Docker digest + OS) or explicit `environment_out_of_scope: true`
- `files_scanned`, `files_with_js_ts`
- `analyzer_findings_total`, `semgrep_findings_total` (after policy filter)
- `matched_line_pairs`, `analyzer_only_lines`, `semgrep_only_lines` (counts; optionally per-file top contributors)
- Optional: stratification keys (`cwe`, `rule_id`, project id)

Human-facing: one **table** (global + optional by-category) and **reproducibility appendix** listing versions and hashes.

---

## 8. Relation to existing code

- **Reuse:** `eval/line_overlap.py` matching logic; Semgrep batch scanning patterns from `eval/backends/semgrep_batch.py`; JSON shapes from Semgrep CLI.
- **New / extended:** corpus scanner (file list, sidecar metadata), aggregation layer, CLI or script dedicated to **external tree** (distinct from `eval.cli compare` which is catalog-oriented).
- The existing catalog `compare` path remains for **internal regression**; the paper’s primary evaluation points to the **external snapshot** workflow.

---

## 9. Testing

- Unit tests: overlap + policy filtering on **synthetic** two-tool JSON payloads (no Semgrep in CI).
- Smoke: optional marked integration test skipped unless `SEMGREP_INTEGRATION=1` and corpus fixture present.

---

## 10. Documentation

- Short section in project docs: how to obtain the corpus, pin versions, run the paper evaluation, and interpret “agreement vs Semgrep.”
- Explicit disclaimer: metrics are **mapping- and policy-dependent**.

---

## 11. Open choices (implementation plan)

- Sidecar format for per-file CWE or expected lines (JSONL vs extended catalog schema).
- Whether per-file results live beside `compare_summary.json` or in a dedicated `corpus_eval_summary.json`.
- Hungarian vs greedy matching: catalog spec allows greedy MVP; corpus track may follow the same unless research reasons dictate otherwise.
