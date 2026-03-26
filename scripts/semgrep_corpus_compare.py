#!/usr/bin/env python3
"""
Compare Semgrep vs this analyzer on the same local file tree (e.g. semgrep-rules).

For **line-level overlap**, reproducibility fields, and paper-oriented summaries, prefer ``scripts/corpus_paper_eval.py``.

Setup
-----
1. Clone rules (one-time), e.g. next to the repo::

     git clone --depth 1 https://github.com/semgrep/semgrep-rules.git .vendor/semgrep-rules

2. Install Semgrep CLI: ``pip install semgrep`` or see semgrep.dev docs.

3. Run the analyzer (Docker or ``uvicorn``).

Example
-------
.. code-block:: text

   py -3 scripts/semgrep_corpus_compare.py ^
     --corpus .vendor/semgrep-rules/javascript ^
     --semgrep-config .vendor/semgrep-rules/javascript ^
     --analyzer http://localhost:8000 ^
     --out eval/results/semgrep_compare.json

Semgrep loads all YAML under ``--semgrep-config`` and scans ``--corpus``. The analyzer
is called with each ``.js`` / ``.jsx`` / ``.ts`` / ``.tsx`` file as a single-file scan.

NodeGoat: clone OWASP/NodeGoat, point ``--corpus`` and ``--semgrep-config`` at a rules
pack (e.g. ``p/javascript`` or a local ``javascript`` folder from semgrep-rules); expect
many cross-file flows — compare file-level counts, not line-perfect TP/FN without a map.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from eval.backends.semgrep_subprocess import run_semgrep_json  # noqa: E402


def _collect_sources(root: Path, extensions: frozenset[str]) -> list[Path]:
    out: list[Path] = []
    for ext in extensions:
        out.extend(root.rglob(f"*.{ext}"))
    return sorted(p.resolve() for p in out if p.is_file())


def _semgrep_counts_by_path(data: dict) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in data.get("results") or []:
        p = r.get("path")
        if not p:
            continue
        key = str(Path(p).resolve())
        counts[key] = counts.get(key, 0) + 1
    return counts


def _analyze_file(client, base: str, path: Path) -> dict:
    url = f"{base.rstrip('/')}/api/v1/analyze/sync"
    body = {
        "source_code": path.read_text(encoding="utf-8", errors="replace"),
        "file_path": path.name,
        "config": {"enable_taint": True},
    }
    r = client.post(url, json=body, timeout=120.0)
    r.raise_for_status()
    return r.json()


def main() -> int:
    ap = argparse.ArgumentParser(description="Semgrep vs analyzer corpus compare")
    ap.add_argument(
        "--corpus",
        type=Path,
        required=True,
        help="Root directory to scan (e.g. semgrep-rules/javascript)",
    )
    ap.add_argument(
        "--semgrep-config",
        type=Path,
        required=True,
        help="Semgrep --config path (folder of rules or a .yaml file)",
    )
    ap.add_argument(
        "--analyzer",
        default="http://localhost:8000",
        help="Analyzer base URL",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("eval/results/semgrep_compare.json"),
    )
    ap.add_argument(
        "--max-files",
        type=int,
        default=0,
        help="Limit files (0 = no limit); useful for dry runs",
    )
    args = ap.parse_args()

    try:
        import httpx
    except ImportError as e:
        print("Install httpx: pip install httpx", file=sys.stderr)
        raise SystemExit(1) from e

    corpus = args.corpus.resolve()
    if not corpus.is_dir():
        print(f"--corpus is not a directory: {corpus}", file=sys.stderr)
        return 1

    exts = frozenset({"js", "jsx", "ts", "tsx"})
    files = _collect_sources(corpus, exts)
    if args.max_files > 0:
        files = files[: args.max_files]

    if not files:
        print("No source files found under corpus.", file=sys.stderr)
        return 1

    print(f"Semgrep: tree {corpus}, config={args.semgrep_config} …")
    sg = run_semgrep_json(args.semgrep_config.resolve(), corpus, timeout_sec=3600)
    sg_counts = _semgrep_counts_by_path(sg)

    rows: list[dict] = []
    print(f"Analyzer: {args.analyzer} …")
    with httpx.Client() as client:
        for i, path in enumerate(files):
            key = str(path)
            sg_n = sg_counts.get(key, 0)
            try:
                data = _analyze_file(client, args.analyzer, path)
                an_n = int((data.get("stats") or {}).get("total_findings", 0))
            except Exception as e:
                rows.append(
                    {
                        "path": key,
                        "semgrep_findings": sg_n,
                        "analyzer_findings": None,
                        "error": str(e),
                    }
                )
            else:
                rows.append(
                    {
                        "path": key,
                        "semgrep_findings": sg_n,
                        "analyzer_findings": an_n,
                        "error": None,
                    }
                )
            if (i + 1) % 50 == 0:
                print(f"  … {i + 1}/{len(files)}")

    summary = {
        "corpus": str(corpus),
        "semgrep_config": str(args.semgrep_config),
        "analyzer": args.analyzer,
        "files": len(files),
        "semgrep_total": sum(sg_counts.values()),
        "analyzer_total": sum(
            r["analyzer_findings"] for r in rows if r["analyzer_findings"] is not None
        ),
        "rows": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
