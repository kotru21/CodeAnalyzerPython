from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from eval.catalog_loader import load_rule_ids, should_skip_main
from eval.classify import classify_outcome
from eval.report_md import render_report

if TYPE_CHECKING:
    from pathlib import Path

    from eval.backends.base import ScanBackend


def _raw_basename(test_id: str, backend_name: str) -> str:
    if backend_name == "analyzer_http":
        return f"{test_id}.json"
    return f"{test_id}.{backend_name}.json"


def run_catalog(
    *,
    cases: list[dict[str, Any]],
    backends: list[ScanBackend],
    raw_dir: Path,
    write_report: bool = False,
    out_dir: Path | None = None,
    catalog_dir: Path | None = None,
) -> list[dict[str, Any]]:
    multi = len(backends) > 1
    rows: list[dict[str, Any]] = []

    for case in cases:
        tid = case["test_id"]
        if should_skip_main(case):
            rows.append(
                {
                    "test_id": tid,
                    "rule_id": case.get("rule_id"),
                    "difficulty": case.get("difficulty"),
                    "type": case.get("type"),
                    "actual_findings": "—",
                    "outcome": "SKIP",
                    "notes": "skipped (sarif/async tag)",
                    "multi_case": bool(case.get("expected_rule_ids")),
                }
            )
            continue

        by_backend: dict[str, Any] = {}
        analyzer_data: dict[str, Any] | None = None
        analyzer_err: str | None = None

        for b in backends:
            res = b.scan_case(case)
            raw_name = _raw_basename(tid, b.name)
            raw_path = raw_dir / raw_name
            if res.ok:
                raw_path.write_text(
                    json.dumps(res.raw, indent=2, default=str),
                    encoding="utf-8",
                )
            else:
                raw_path.write_text(
                    json.dumps({"error": res.error}, indent=2),
                    encoding="utf-8",
                )

            rel = raw_name
            if out_dir is not None:
                try:
                    rel = str(raw_path.relative_to(out_dir)).replace("\\", "/")
                except ValueError:
                    rel = raw_name

            if multi:
                by_backend[b.name] = {
                    "ok": res.ok,
                    "error": res.error,
                    "raw_relpath": rel,
                    "finding_count": len(res.findings),
                }

            if b.name == "analyzer_http":
                if res.ok:
                    analyzer_data = res.raw
                else:
                    analyzer_err = res.error

        has_analyzer = any(b.name == "analyzer_http" for b in backends)
        if has_analyzer:
            if analyzer_data is not None:
                outcome = classify_outcome(case, analyzer_data)
                stats = analyzer_data.get("stats") or {}
                total = stats.get(
                    "total_findings", len(analyzer_data.get("findings") or [])
                )
            else:
                outcome = "ERROR"
                total = "—"
            notes = ""
            if analyzer_err:
                notes = analyzer_err[:200]
            nec = case.get("notes_expected_count")
            if nec is not None and isinstance(total, int):
                notes = (notes + f" expected_count~{nec} actual={total}").strip()
        else:
            outcome = "ERROR"
            total = "—"
            notes = "no analyzer_http backend"

        row: dict[str, Any] = {
            "test_id": tid,
            "rule_id": case.get("rule_id"),
            "difficulty": case.get("difficulty"),
            "type": case.get("type"),
            "actual_findings": total,
            "outcome": outcome,
            "notes": notes,
            "multi_case": bool(case.get("expected_rule_ids")),
        }
        if multi:
            row["by_backend"] = by_backend
        rows.append(row)

    if write_report and out_dir is not None and catalog_dir is not None:
        metric_rows = [r for r in rows if r.get("outcome") != "SKIP"]
        rule_ids = load_rule_ids(catalog_dir)
        md = render_report(metric_rows, rule_ids)
        (out_dir / "report.md").write_text(md, encoding="utf-8")

    return rows
