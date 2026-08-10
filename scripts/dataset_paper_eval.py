#!/usr/bin/env python3
"""
CSV with GitHub blob URLs: materialize files from raw.githubusercontent.com, then run the
same Semgrep + HTTP analyzer line-overlap summary as ``corpus_paper_eval``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from eval.catalog_loader import repo_root  # noqa: E402
from eval.corpus_agreement import buckets_for_policy  # noqa: E402
from eval.corpus_paper_runner import run_paper_eval  # noqa: E402
from eval.corpus_paths import list_js_ts_relpaths_walk  # noqa: E402
from eval.dataset_materialize import materialize_dataset_csv  # noqa: E402
from eval.rule_map import load_rule_map  # noqa: E402


def main() -> int:
    root = repo_root()
    p = argparse.ArgumentParser(
        description="Paper eval: CSV-listed GitHub JS/TS files vs Semgrep line agreement"
    )
    p.add_argument("--csv", type=Path, required=True, help="Dataset CSV (column full_repo_path)")
    p.add_argument(
        "--materialize-root",
        type=Path,
        required=True,
        help="Directory to download snapshot files into",
    )
    p.add_argument(
        "--refresh-materialize",
        action="store_true",
        help="Re-download files even if they already exist",
    )
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
    p.add_argument("--analyzer", default="http://localhost:8000", help="Analyzer base URL")
    p.add_argument(
        "--out",
        type=Path,
        default=Path("eval/results/dataset_eval_summary.json"),
    )
    p.add_argument(
        "--dataset-id",
        default="",
        help="Identifier for summary JSON (default: CSV stem)",
    )
    p.add_argument(
        "--dataset-snapshot-hash",
        default="",
        help="Optional hash or id for the CSV snapshot (stored in corpus_snapshot_hash)",
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
    p.add_argument("--max-files", type=int, default=0, help="Cap files after materialize (0 = all)")
    p.add_argument(
        "--semgrep-timeout",
        type=int,
        default=3600,
        metavar="SEC",
        help="Subprocess timeout for Semgrep",
    )
    args = p.parse_args()

    csv_path = (args.csv if args.csv.is_absolute() else root / args.csv).resolve()
    if not csv_path.is_file():
        print(f"--csv is not a file: {csv_path}", file=sys.stderr)
        return 1

    materialize_root = (
        args.materialize_root
        if args.materialize_root.is_absolute()
        else root / args.materialize_root
    ).resolve()

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

    try:
        manifest_path = materialize_dataset_csv(
            csv_path,
            materialize_root,
            refresh=args.refresh_materialize,
        )
    except (OSError, RuntimeError, ValueError) as e:
        print(f"Materialization failed: {e}", file=sys.stderr)
        return 3

    relpaths = list_js_ts_relpaths_walk(materialize_root)
    if args.max_files > 0:
        relpaths = relpaths[: args.max_files]

    fur = f"dataset_csv:{csv_path.name}+github_raw_fetch"
    corpus_id = args.dataset_id.strip() or csv_path.stem

    summary = run_paper_eval(
        corpus=materialize_root,
        configs=configs,
        rule_map=rule_map,
        policy=args.policy,
        file_mode="walk",
        analyzer_base=args.analyzer,
        max_files=0,
        semgrep_timeout=args.semgrep_timeout,
        corpus_id=corpus_id,
        corpus_snapshot_hash=args.dataset_snapshot_hash,
        analyzer_invoke=args.analyzer_invoke,
        analyzer_version=args.analyzer_version,
        analyzer_git_commit=args.analyzer_git_commit,
        environment_note=args.environment_note,
        environment_out_of_scope=args.environment_out_of_scope,
        file_universe_rule=fur,
        relpaths_override=relpaths,
    )

    manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    summary["dataset_csv"] = str(csv_path)
    summary["materialization_manifest"] = {
        "path": str(manifest_path.resolve()),
        "manifest_sha256": manifest_sha256,
    }

    out_path = args.out if args.out.is_absolute() else (root / args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
