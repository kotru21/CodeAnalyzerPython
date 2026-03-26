from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from eval.backends.semgrep_subprocess import semgrep_executable


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def config_bundle_hashes(paths: list[Path]) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in paths:
        r = p.resolve()
        if r.is_file():
            out[r.name] = sha256_file(r)
        elif r.is_dir():
            for f in sorted(r.rglob("*.yml")) + sorted(r.rglob("*.yaml")):
                if f.is_file():
                    key = str(f.relative_to(r)).replace("\\", "/")
                    out[key] = sha256_file(f)
    return out


def semgrep_cli_version() -> str:
    proc = subprocess.run(
        [semgrep_executable(), "--version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
        shell=False,
    )
    out = (proc.stdout or proc.stderr or "").strip().splitlines()
    return (out[0] if out else "unknown").strip()
