from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from analyzer.api.schemas import AnalyzeRequest, ScanConfig
from analyzer.config import Settings
from analyzer.core.orchestrator import Orchestrator

from eval.catalog_loader import load_rule_ids, should_skip_main
from eval.classify import classify_outcome
from eval.finding_match import (
    classify_case_findings,
    expand_rows_for_metrics,
    primary_outcome,
)
from eval.report_md import render_report

from eval.backends.semgrep_batch import batch_scan_semgrep
from eval.backends.semgrep_case import SemgrepCaseBackend

if TYPE_CHECKING:
    from pathlib import Path

    from eval.backends.base import ScanBackend


def run_catalog_inprocess(
    cases: list[dict[str, Any]],
    *,
    settings: Settings | None = None,
) -> list[dict[str, Any]]:
    """Run catalog cases via Orchestrator.analyze_sync (no HTTP)."""
    orch = Orchestrator(settings=settings or Settings(), cwe_db=None)
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

        scan_config = ScanConfig(**(case.get("config") or {"enable_taint": True}))
        request = AnalyzeRequest(
            source_code=case["source_code"],
            file_path=case["file_path"],
            config=scan_config,
        )

        analyzer_err: str | None = None
        analyzer_data: dict[str, Any] | None = None
        try:
            response = orch.analyze_sync(request)
            analyzer_data = response.model_dump(mode="json")
        except Exception as e:  # noqa: BLE001
            analyzer_err = str(e)

        finding_outcomes: list[str] | None = None
        if analyzer_data is not None:
            if case.get("expected_findings") is not None:
                finding_outcomes = classify_case_findings(case, analyzer_data)
                outcome = primary_outcome(finding_outcomes)
            else:
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
        if finding_outcomes:
            notes = (
                notes + f" finding_outcomes={','.join(finding_outcomes)}"
            ).strip()

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
        if finding_outcomes is not None:
            row["finding_outcomes"] = finding_outcomes
        rows.append(row)

    return rows


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

    semgrep_backend = next((b for b in backends if b.name == "semgrep"), None)
    semgrep_by_tid: dict[str, Any] = {}
    if isinstance(semgrep_backend, SemgrepCaseBackend):
        active = [c for c in cases if not should_skip_main(c)]
        # One Semgrep process for the whole catalog (vs N runs per case).
        batch_timeout = max(semgrep_backend.timeout_sec, 600)
        semgrep_by_tid = batch_scan_semgrep(
            active,
            semgrep_backend.config_paths,
            timeout_sec=batch_timeout,
        )

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
            if (
                b.name == "semgrep"
                and isinstance(semgrep_backend, SemgrepCaseBackend)
                and tid in semgrep_by_tid
            ):
                res = semgrep_by_tid[tid]
            else:
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
        finding_outcomes: list[str] | None = None
        if has_analyzer:
            if analyzer_data is not None:
                if case.get("expected_findings") is not None:
                    finding_outcomes = classify_case_findings(case, analyzer_data)
                    outcome = primary_outcome(finding_outcomes)
                else:
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
            if finding_outcomes:
                notes = (
                    notes + f" finding_outcomes={','.join(finding_outcomes)}"
                ).strip()
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
        if finding_outcomes is not None:
            row["finding_outcomes"] = finding_outcomes
        if multi:
            row["by_backend"] = by_backend
        rows.append(row)

    if write_report and out_dir is not None and catalog_dir is not None:
        metric_rows = expand_rows_for_metrics(
            [r for r in rows if r.get("outcome") != "SKIP"]
        )
        rule_ids = load_rule_ids(catalog_dir)
        md = render_report(metric_rows, rule_ids)
        (out_dir / "report.md").write_text(md, encoding="utf-8")

    return rows
