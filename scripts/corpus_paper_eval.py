#!/usr/bin/env python3
"""
External JS/TS tree: run Semgrep + HTTP analyzer, emit line-overlap summary JSON.

See ``docs/superpowers/specs/2026-03-26-external-js-ts-corpus-semgrep-design.md``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from eval.catalog_loader import repo_root  # noqa: E402
from eval.corpus_agreement import buckets_for_policy  # noqa: E402
from eval.corpus_paper_runner import run_paper_eval  # noqa: E402
from eval.rule_map import load_rule_map  # noqa: E402


def _agreement_fn_count(summary: dict) -> int | None:
    """False negatives for line-level Semgrep agreement (if present in summary)."""
    agreement = summary.get("agreement_summary")
    if isinstance(agreement, dict):
        fn = agreement.get("FN")
        if isinstance(fn, int):
            return fn
    if "semgrep_only_lines" in summary:
        return int(summary["semgrep_only_lines"])
    return None


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
    p.add_argument(
        "--fail-on-fn",
        action="store_true",
        help=(
            "Exit 3 when line-agreement false negatives are > 0. Uses "
            "agreement_summary.FN when present, otherwise semgrep_only_lines "
            "(Semgrep lines not matched by the analyzer)."
        ),
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

    summary = run_paper_eval(
        corpus=corpus,
        configs=configs,
        rule_map=rule_map,
        policy=args.policy,
        file_mode=args.file_mode,
        analyzer_base=args.analyzer,
        max_files=args.max_files,
        semgrep_timeout=args.semgrep_timeout,
        corpus_id=args.corpus_id,
        corpus_snapshot_hash=args.corpus_snapshot_hash,
        analyzer_invoke=args.analyzer_invoke,
        analyzer_version=args.analyzer_version,
        analyzer_git_commit=args.analyzer_git_commit,
        environment_note=args.environment_note,
        environment_out_of_scope=args.environment_out_of_scope,
    )

    out_path = args.out if args.out.is_absolute() else (root / args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {out_path}")

    if args.fail_on_fn:
        fn_count = _agreement_fn_count(summary)
        if fn_count is None:
            print(
                "--fail-on-fn: no agreement FN field in summary; skipping gate",
                file=sys.stderr,
            )
        elif fn_count > 0:
            print(
                f"--fail-on-fn: agreement FN count {fn_count} > 0",
                file=sys.stderr,
            )
            return 3

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
