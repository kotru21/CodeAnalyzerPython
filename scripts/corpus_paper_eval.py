#!/usr/bin/env python3
"""
External JS/TS tree: run Semgrep + HTTP analyzer, emit line-overlap summary JSON.

See ``docs/superpowers/specs/2026-03-26-external-js-ts-corpus-semgrep-design.md``.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import httpx  # noqa: E402

from eval.backends.semgrep_subprocess import run_semgrep_json_configs  # noqa: E402
from eval.catalog_loader import repo_root  # noqa: E402
from eval.corpus_agreement import (  # noqa: E402
    aggregate_overlap_payloads,
    buckets_for_policy,
    overlap_for_file_bucket,
)
from eval.corpus_paths import (  # noqa: E402
    DEFAULT_JS_TS_EXTENSIONS,
    list_js_ts_relpaths_git,
    list_js_ts_relpaths_walk,
)
from eval.corpus_repro import config_bundle_hashes, semgrep_cli_version  # noqa: E402
from eval.corpus_semgrep_normalize import semgrep_result_relpath  # noqa: E402
from eval.rule_map import load_rule_map  # noqa: E402

POLICY_B_NOTE = (
    "check_id filter: none (all Semgrep results per file under given --semgrep-config)"
)


def _environment_fields(
    note: str | None, out_of_scope_flag: bool
) -> tuple[str | None, bool]:
    """§7: explicit note and/or environment_out_of_scope."""
    if out_of_scope_flag:
        return note, True
    if note:
        return note, False
    return None, True


def main() -> int:
    root = repo_root()
    p = argparse.ArgumentParser(
        description="Paper eval: JS/TS corpus vs Semgrep line agreement"
    )
    p.add_argument("--corpus", type=Path, required=True, help="Corpus root directory")
    p.add_argument(
        "--semgrep-config",
        type=Path,
        action="append",
        required=True,
        metavar="PATH",
        help="Semgrep --config (repeatable)",
    )
    p.add_argument(
        "--rule-map",
        type=Path,
        default=Path("eval/catalog/rule_map.yaml"),
        help="YAML with equivalence_rules and line_slop",
    )
    p.add_argument(
        "--policy",
        choices=("a", "b"),
        required=True,
        help="A: per-bucket from equivalence_rules; B: all checks / all analyzer rules",
    )
    p.add_argument(
        "--file-mode",
        choices=("walk", "git"),
        default="walk",
        help="walk: rglob by extension; git: git ls-files under corpus",
    )
    p.add_argument("--analyzer", default="http://localhost:8000", help="Analyzer base URL")
    p.add_argument(
        "--out",
        type=Path,
        default=Path("eval/results/corpus_eval_summary.json"),
    )
    p.add_argument("--corpus-id", default="", help="Identifier for summary JSON")
    p.add_argument(
        "--corpus-snapshot-hash",
        default="",
        help="Frozen snapshot id (e.g. git commit) for the paper",
    )
    p.add_argument(
        "--analyzer-invoke",
        default="",
        help="Recorded verbatim (default: POST .../analyze/sync)",
    )
    p.add_argument("--analyzer-version", default="", help="Analyzer release string")
    p.add_argument("--analyzer-git-commit", default="", help="Analyzer git SHA")
    p.add_argument("--environment-note", default="", help="Pinned environment description")
    p.add_argument(
        "--environment-out-of-scope",
        action="store_true",
        help="Force environment_out_of_scope true in JSON",
    )
    p.add_argument("--max-files", type=int, default=0, help="Cap files (0 = all)")
    p.add_argument(
        "--semgrep-timeout",
        type=int,
        default=3600,
        metavar="SEC",
        help="Subprocess timeout for Semgrep",
    )
    args = p.parse_args()

    corpus = args.corpus.resolve()
    if not corpus.is_dir():
        print(f"--corpus is not a directory: {corpus}", file=sys.stderr)
        return 1

    configs = [(c if c.is_absolute() else root / c).resolve() for c in args.semgrep_config]
    rule_map_path = (
        args.rule_map if args.rule_map.is_absolute() else root / args.rule_map
    ).resolve()
    rule_map = load_rule_map(rule_map_path)
    buckets = buckets_for_policy(args.policy, rule_map)
    if args.policy == "a" and not buckets:
        print(
            "Policy A needs at least one non-empty equivalence_rules entry in the rule map.",
            file=sys.stderr,
        )
        return 2

    if args.file_mode == "walk":
        relpaths = list_js_ts_relpaths_walk(corpus)
        fur = "walk:rglob_ext=" + ",".join(sorted(DEFAULT_JS_TS_EXTENSIONS))
    else:
        relpaths = list_js_ts_relpaths_git(corpus)
        fur = "git:ls-files+ext_filter=" + ",".join(sorted(DEFAULT_JS_TS_EXTENSIONS))

    if args.max_files > 0:
        relpaths = relpaths[: args.max_files]

    raw = run_semgrep_json_configs(configs, corpus, timeout_sec=args.semgrep_timeout)
    all_results = [r for r in raw.get("results") or [] if isinstance(r, dict)]
    files_set = set(relpaths)

    def semgrep_findings_total() -> int:
        if args.policy == "b":
            n = 0
            for r in all_results:
                rp = semgrep_result_relpath(
                    corpus, str(r.get("path")) if r.get("path") else None
                )
                if rp in files_set:
                    n += 1
            return n
        allow = set()
        for b in buckets:
            allow.update(rule_map.equivalence_rules.get(b, ()))
        n = 0
        for r in all_results:
            check = r.get("check_id") or r.get("rule_id")
            if not isinstance(check, str) or check not in allow:
                continue
            rp = semgrep_result_relpath(
                corpus, str(r.get("path")) if r.get("path") else None
            )
            if rp in files_set:
                n += 1
        return n

    findings_by_rel: dict[str, list[Any]] = {}
    base = args.analyzer.rstrip("/")
    url = f"{base}/api/v1/analyze/sync"

    with httpx.Client() as client:
        for rel in relpaths:
            abs_path = (corpus / rel).resolve()
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
            if args.policy == "b":
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
                policy=args.policy,
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

    env_note = args.environment_note.strip() or None
    env_note, env_oos = _environment_fields(env_note, args.environment_out_of_scope)

    av = args.analyzer_version.strip() or None
    ag = args.analyzer_git_commit.strip() or None
    invoke = args.analyzer_invoke.strip() or f"POST {url}"

    summary: dict[str, Any] = {
        "corpus_id": args.corpus_id.strip() or corpus.name,
        "corpus_snapshot_hash": args.corpus_snapshot_hash.strip(),
        "file_universe_rule": fur,
        "policy": args.policy,
        "policy_b_note": POLICY_B_NOTE if args.policy == "b" else None,
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

    out_path = args.out if args.out.is_absolute() else (root / args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
