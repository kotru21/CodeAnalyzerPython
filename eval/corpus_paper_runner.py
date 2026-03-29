from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Literal

import httpx

from eval.backends.semgrep_subprocess import run_semgrep_json_configs
from eval.corpus_agreement import (
    aggregate_overlap_payloads,
    buckets_for_policy,
    overlap_for_file_bucket,
)
from eval.corpus_paths import (
    DEFAULT_JS_TS_EXTENSIONS,
    list_js_ts_relpaths_git,
    list_js_ts_relpaths_walk,
)
from eval.corpus_repro import config_bundle_hashes, semgrep_cli_version
from eval.corpus_semgrep_normalize import semgrep_result_relpath
from eval.rule_map import RuleMap

POLICY_B_NOTE = (
    "check_id filter: none (all Semgrep results per file under given --semgrep-config)"
)


def _environment_fields(
    note: str | None, out_of_scope_flag: bool
) -> tuple[str | None, bool]:
    if out_of_scope_flag:
        return note, True
    if note:
        return note, False
    return None, True


def run_paper_eval(
    *,
    corpus: Path,
    configs: list[Path],
    rule_map: RuleMap,
    policy: Literal["a", "b"],
    file_mode: Literal["walk", "git"],
    analyzer_base: str,
    max_files: int = 0,
    semgrep_timeout: int = 3600,
    corpus_id: str = "",
    corpus_snapshot_hash: str = "",
    analyzer_invoke: str = "",
    analyzer_version: str = "",
    analyzer_git_commit: str = "",
    environment_note: str = "",
    environment_out_of_scope: bool = False,
    file_universe_rule: str | None = None,
    relpaths_override: list[str] | None = None,
) -> dict[str, Any]:
    """
    Run Semgrep on ``corpus``, call analyzer HTTP API per JS/TS file, return summary dict
    (same shape as ``corpus_eval_summary.json``).

    If ``relpaths_override`` is set, scan exactly those paths (POSIX rel to corpus) instead
    of listing via walk/git. If ``file_universe_rule`` is set, it is stored in the summary;
    otherwise it is derived from ``file_mode``.
    """
    corpus = corpus.resolve()
    if file_mode == "walk":
        relpaths = (
            list_js_ts_relpaths_walk(corpus)
            if relpaths_override is None
            else list(relpaths_override)
        )
        fur = file_universe_rule or (
            "walk:rglob_ext=" + ",".join(sorted(DEFAULT_JS_TS_EXTENSIONS))
        )
    else:
        relpaths = (
            list_js_ts_relpaths_git(corpus)
            if relpaths_override is None
            else list(relpaths_override)
        )
        fur = file_universe_rule or (
            "git:ls-files+ext_filter=" + ",".join(sorted(DEFAULT_JS_TS_EXTENSIONS))
        )

    if max_files > 0:
        relpaths = relpaths[:max_files]

    buckets = buckets_for_policy(policy, rule_map)
    raw = run_semgrep_json_configs(configs, corpus, timeout_sec=semgrep_timeout)
    all_results = [r for r in raw.get("results") or [] if isinstance(r, dict)]
    files_set = set(relpaths)

    def semgrep_findings_total() -> int:
        if policy == "a":
            allow: set[str] | None = set()
            for b in buckets:
                allow.update(rule_map.equivalence_rules.get(b, ()))
        else:
            allow = None
        n = 0
        for r in all_results:
            if not isinstance(r, dict):
                continue
            check = r.get("check_id") or r.get("rule_id")
            if not isinstance(check, str):
                continue
            if allow is not None and check not in allow:
                continue
            rp = semgrep_result_relpath(
                corpus, str(r.get("path")) if r.get("path") else None
            )
            if rp not in files_set:
                continue
            start = r.get("start")
            if not isinstance(start, dict) or not isinstance(start.get("line"), int):
                continue
            n += 1
        return n

    findings_by_rel: dict[str, list[Any]] = {}
    base = analyzer_base.rstrip("/")
    url = f"{base}/api/v1/analyze/sync"

    with httpx.Client() as client:
        for rel in relpaths:
            abs_path = (corpus / rel).resolve()
            try:
                abs_path.relative_to(corpus.resolve())
            except ValueError:
                print(f"SKIP (outside corpus): {rel}", file=sys.stderr)
                findings_by_rel[rel] = []
                continue
            body = {
                "source_code": abs_path.read_text(encoding="utf-8", errors="replace"),
                "file_path": abs_path.name,
                "config": {"enable_taint": True},
            }
            try:
                r = client.post(url, json=body, timeout=120.0)
                r.raise_for_status()
                data = r.json()
            except (httpx.HTTPError, ValueError, OSError) as e:
                print(f"ERROR {rel}: {e}", file=sys.stderr)
                findings_by_rel[rel] = []
                continue
            findings = data.get("findings") if isinstance(data, dict) else []
            findings_by_rel[rel] = findings if isinstance(findings, list) else []

    def analyzer_findings_total() -> int:
        total = 0
        for rel in relpaths:
            findings = findings_by_rel.get(rel, [])
            if policy == "b":
                total += sum(1 for f in findings if isinstance(f, dict))
            else:
                for f in findings:
                    if isinstance(f, dict) and f.get("rule_id") in buckets:
                        total += 1
        return total

    sg_total = semgrep_findings_total()
    an_total = analyzer_findings_total()

    per_bucket_payloads: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rel in relpaths:
        findings = [f for f in findings_by_rel.get(rel, []) if isinstance(f, dict)]
        for bucket in buckets:
            payload = overlap_for_file_bucket(
                line_slop=rule_map.line_slop,
                policy=policy,
                bucket=bucket,
                rule_map=rule_map,
                analyzer_findings=findings,
                semgrep_results_full=all_results,
                corpus_root=corpus,
                relpath=rel,
            )
            per_bucket_payloads[bucket].append(payload)

    flat_payloads = [p for lst in per_bucket_payloads.values() for p in lst]
    agg = aggregate_overlap_payloads(flat_payloads)
    by_bucket = {
        b: aggregate_overlap_payloads(lst) for b, lst in per_bucket_payloads.items()
    }

    hashes = config_bundle_hashes(configs)
    semgrep_argv = ["scan", "--json", "--quiet"]
    for c in configs:
        semgrep_argv.extend(["--config", str(c)])
    semgrep_argv.append(str(corpus))

    env_note = environment_note.strip() or None
    env_note, env_oos = _environment_fields(env_note, environment_out_of_scope)

    av = analyzer_version.strip() or None
    ag = analyzer_git_commit.strip() or None
    invoke = analyzer_invoke.strip() or f"POST {url}"

    return {
        "corpus_id": corpus_id.strip() or corpus.name,
        "corpus_snapshot_hash": corpus_snapshot_hash.strip(),
        "file_universe_rule": fur,
        "policy": policy,
        "policy_b_note": (
            POLICY_B_NOTE + " Analyzer lines only include findings with string rule_id."
            if policy == "b"
            else None
        ),
        "analyzer_invoke": invoke,
        "analyzer_version": av,
        "analyzer_git_commit": ag,
        "analyzer_identity_note": (
            None
            if (av or ag)
            else "not provided; pass --analyzer-git-commit or --analyzer-version for paper"
        ),
        "semgrep_version": semgrep_cli_version(),
        "semgrep_config_paths": [str(c) for c in configs],
        "semgrep_config_sha256": hashes,
        "semgrep_cli_argv": semgrep_argv,
        "environment_note": env_note,
        "environment_out_of_scope": env_oos,
        "files_scanned": len(relpaths),
        "files_with_js_ts": len(relpaths),
        "analyzer_findings_total": an_total,
        "semgrep_findings_total": sg_total,
        "matched_line_pairs": agg["matched_line_pairs"],
        "analyzer_only_lines": agg["analyzer_only_lines"],
        "semgrep_only_lines": agg["semgrep_only_lines"],
        "aggregate": agg,
        "by_bucket": by_bucket,
    }
