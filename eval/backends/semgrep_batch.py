from __future__ import annotations

import tempfile
from pathlib import Path, PurePath
from typing import Any

from eval.backends.semgrep_subprocess import (
    findings_from_semgrep_json,
    run_semgrep_json_configs,
)
from eval.scan_types import BackendScanResult


def _suffix_for_case(case: dict[str, Any]) -> str:
    fp = case.get("file_path") or "snippet.js"
    suf = PurePath(str(fp)).suffix
    return suf if suf else ".js"


def batch_scan_semgrep(
    cases: list[dict[str, Any]],
    config_paths: list[Path],
    *,
    timeout_sec: int = 900,
) -> dict[str, BackendScanResult]:
    """Run Semgrep once over all case sources (one file per test_id)."""
    existing = [p for p in config_paths if p.is_file() or p.is_dir()]
    if not existing:
        err = BackendScanResult(
            ok=False,
            error="no semgrep config paths",
            raw={},
            findings=[],
        )
        return {str(c["test_id"]): err for c in cases}

    if not cases:
        return {}

    try:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for case in cases:
                tid = str(case["test_id"])
                path = root / f"{tid}{_suffix_for_case(case)}"
                path.write_text(case.get("source_code") or "", encoding="utf-8")
            raw = run_semgrep_json_configs(
                existing, root, timeout_sec=timeout_sec
            )
    except (OSError, RuntimeError, FileNotFoundError) as e:
        err_res = BackendScanResult(
            ok=False,
            error=str(e),
            raw={},
            findings=[],
        )
        return {str(c["test_id"]): err_res for c in cases}

    by_tid: dict[str, list[Any]] = {}
    for r in raw.get("results") or []:
        if not isinstance(r, dict):
            continue
        p = r.get("path")
        if not p:
            continue
        stem = Path(str(p)).stem
        by_tid.setdefault(stem, []).append(r)

    errs = raw.get("errors", [])
    out: dict[str, BackendScanResult] = {}
    for case in cases:
        tid = str(case["test_id"])
        sub_raw: dict[str, Any] = {
            "results": by_tid.get(tid, []),
            "errors": errs if isinstance(errs, list) else [],
        }
        findings = findings_from_semgrep_json(sub_raw)
        out[tid] = BackendScanResult(
            ok=True,
            error=None,
            raw=sub_raw,
            findings=findings,
        )
    return out
