from __future__ import annotations

import argparse
import json
import sys
from argparse import Namespace
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from eval.backends.http_analyzer import HttpAnalyzerBackend
from eval.backends.semgrep_case import SemgrepCaseBackend
from eval.catalog_loader import load_cases, repo_root
from eval.catalog_runner import run_catalog
from eval.compare_enrich import enrich_rows_with_line_overlap
from eval.rule_map import collect_semgrep_configs_for_cases, load_rule_map

if TYPE_CHECKING:
    from collections.abc import Sequence


def build_run_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run benchmark cases against analyzer HTTP API")
    p.add_argument("--base-url", default="http://localhost:8000")
    p.add_argument("--catalog", default="eval/catalog/cases.json")
    p.add_argument("--output-dir", default="eval/results")
    return p


def execute_run(args: Namespace) -> int:
    root = repo_root()
    catalog_path = root / args.catalog
    out_dir = root / args.output_dir
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    cases = load_cases(catalog_path)
    with httpx.Client() as client:
        backends = [HttpAnalyzerBackend(client, args.base_url)]
        run_catalog(
            cases=cases,
            backends=backends,
            raw_dir=raw_dir,
            write_report=True,
            out_dir=out_dir,
            catalog_dir=catalog_path.parent,
        )
    print(f"Wrote {out_dir / 'report.md'} and {len(cases)} raw responses under {raw_dir}")
    return 0


def _parse_backends(spec: str) -> list[str]:
    return [x.strip() for x in spec.split(",") if x.strip()]


def execute_compare(args: Namespace) -> int:
    root = repo_root()
    catalog_path = root / args.catalog
    out_dir = root / args.output_dir
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    cases = load_cases(catalog_path)
    if getattr(args, "limit", 0) and args.limit > 0:
        cases = cases[: args.limit]
    names = _parse_backends(args.backends)
    if not names:
        print("No backends given.", file=sys.stderr)
        return 1

    for n in names:
        if n not in ("analyzer_http", "semgrep"):
            print(f"Unknown backend: {n}", file=sys.stderr)
            return 1

    semgrep_configs: list[Path] | None = None
    if "semgrep" in names:
        if args.semgrep_config:
            cfg = Path(args.semgrep_config)
            semgrep_configs = [cfg.resolve() if cfg.is_absolute() else (root / cfg).resolve()]
        else:
            rule_map_path = root / args.rule_map
            rm = load_rule_map(rule_map_path)
            semgrep_configs = collect_semgrep_configs_for_cases(cases, rm, root)

    backends = []
    with httpx.Client() as client:
        for n in names:
            if n == "analyzer_http":
                backends.append(HttpAnalyzerBackend(client, args.base_url))
            else:
                assert semgrep_configs is not None
                backends.append(SemgrepCaseBackend(semgrep_configs))

        rows = run_catalog(
            cases=cases,
            backends=backends,
            raw_dir=raw_dir,
            write_report=False,
            out_dir=out_dir,
            catalog_dir=catalog_path.parent,
        )

    backend_names = [b.name for b in backends]
    if "analyzer_http" in backend_names and "semgrep" in backend_names:
        rule_map_overlap = load_rule_map(root / args.rule_map)
        enrich_rows_with_line_overlap(
            rows,
            cases,
            rule_map_overlap,
            raw_dir,
            backends_have_semgrep_and_http=True,
        )

    summary = {
        "catalog": str(catalog_path),
        "backends": [b.name for b in backends],
        "rows": rows,
    }
    out_path = out_dir / "compare_summary.json"
    out_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {out_path}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="eval.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="HTTP analyzer vs catalog (writes report.md)")
    run_p.add_argument("--base-url", default="http://localhost:8000")
    run_p.add_argument("--catalog", default="eval/catalog/cases.json")
    run_p.add_argument("--output-dir", default="eval/results")

    cmp_p = sub.add_parser("compare", help="Multi-backend compare (writes compare_summary.json)")
    cmp_p.add_argument("--base-url", default="http://localhost:8000")
    cmp_p.add_argument("--catalog", default="eval/catalog/cases.json")
    cmp_p.add_argument("--output-dir", default="eval/results")
    cmp_p.add_argument(
        "--rule-map",
        default="eval/catalog/rule_map.yaml",
        help="YAML map of analyzer rule_id -> semgrep configs (when --semgrep-config omitted)",
    )
    cmp_p.add_argument(
        "--backends",
        default="analyzer_http,semgrep",
        help="Comma-separated: analyzer_http, semgrep",
    )
    cmp_p.add_argument(
        "--semgrep-config",
        default="",
        help="Single Semgrep --config path (repo-relative); overrides rule map union",
    )
    cmp_p.add_argument(
        "--limit",
        type=int,
        default=0,
        metavar="N",
        help="Only first N catalog cases (0 = all)",
    )

    args = parser.parse_args(argv)
    if args.command == "run":
        return execute_run(args)
    if args.command == "compare":
        return execute_compare(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
