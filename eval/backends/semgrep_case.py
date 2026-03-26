from __future__ import annotations

import tempfile
from pathlib import Path, PurePath
from typing import Any

from eval.backends.semgrep_subprocess import (
    findings_from_semgrep_json,
    run_semgrep_json_configs,
)
from eval.scan_types import BackendScanResult


def _safe_basename(file_path: str) -> str:
    name = PurePath(file_path).name
    if not name or name == "." or name == "..":
        return "snippet.js"
    return name


class SemgrepCaseBackend:
    name = "semgrep"

    def __init__(
        self,
        config_paths: list[Path],
        *,
        timeout_sec: int = 240,
    ) -> None:
        self._config_paths = config_paths
        self._timeout_sec = timeout_sec

    def scan_case(self, case: dict[str, Any]) -> BackendScanResult:
        existing = [p for p in self._config_paths if p.is_file() or p.is_dir()]
        if not existing:
            return BackendScanResult(
                ok=False,
                error="no semgrep config paths",
                raw={},
                findings=[],
            )
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                fname = _safe_basename(str(case.get("file_path") or "snippet.js"))
                fpath = root / fname
                fpath.write_text(case.get("source_code") or "", encoding="utf-8")
                raw = run_semgrep_json_configs(
                    existing, root, timeout_sec=self._timeout_sec
                )
        except (OSError, RuntimeError, FileNotFoundError) as e:
            return BackendScanResult(
                ok=False,
                error=str(e),
                raw={},
                findings=[],
            )
        findings = findings_from_semgrep_json(raw)
        return BackendScanResult(
            ok=True,
            error=None,
            raw=raw,
            findings=findings,
        )
