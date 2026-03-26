from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from eval.scan_types import NormalizedFinding


def semgrep_executable() -> str:
    found = shutil.which("semgrep")
    if found:
        return found
    parent = Path(sys.executable).resolve().parent
    for cand in (
        parent / "Scripts" / "semgrep.exe",
        parent / "Scripts" / "semgrep",
        parent / "semgrep",
    ):
        if cand.is_file():
            return str(cand)
    raise FileNotFoundError(
        "semgrep not found (install: pip install semgrep, or add Scripts to PATH)"
    )


def run_semgrep_json(
    config: Path,
    scan_root: Path,
    *,
    timeout_sec: int = 3600,
) -> dict[str, Any]:
    return run_semgrep_json_configs([config], scan_root, timeout_sec=timeout_sec)


def run_semgrep_json_configs(
    configs: list[Path],
    scan_root: Path,
    *,
    timeout_sec: int = 3600,
) -> dict[str, Any]:
    existing = [c.resolve() for c in configs if c.is_file() or c.is_dir()]
    if not existing:
        raise FileNotFoundError("no existing semgrep --config paths")
    cmd: list[str] = [semgrep_executable(), "scan", "--json", "--quiet"]
    for c in existing:
        cmd.extend(["--config", str(c)])
    cmd.append(str(scan_root.resolve()))
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
        timeout=timeout_sec,
    )
    if proc.returncode not in (0, 1):
        err = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"semgrep exited {proc.returncode}: {err[:2000]}")
    return json.loads(proc.stdout or "{}")


def findings_from_semgrep_json(data: dict[str, Any]) -> list[NormalizedFinding]:
    out: list[NormalizedFinding] = []
    for r in data.get("results") or []:
        if not isinstance(r, dict):
            continue
        check = r.get("check_id") or r.get("rule_id")
        if not isinstance(check, str):
            continue
        path = r.get("path")
        start = r.get("start") if isinstance(r.get("start"), dict) else {}
        line = start.get("line") if isinstance(start, dict) else None
        ln = int(line) if isinstance(line, int) else None
        out.append(
            NormalizedFinding(
                rule_id=check,
                line=ln,
                path=str(path) if path else None,
            )
        )
    return out
