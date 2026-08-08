from __future__ import annotations

import hashlib
import subprocess
from typing import TYPE_CHECKING

from eval.backends.semgrep_subprocess import semgrep_executable

if TYPE_CHECKING:
    from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def config_bundle_hashes(paths: list[Path]) -> dict[str, str]:
    """Keys are unique per resolved path (avoids basename collisions)."""
    out: dict[str, str] = {}
    for p in paths:
        r = p.resolve()
        if r.is_file():
            out[str(r).replace("\\", "/")] = sha256_file(r)
        elif r.is_dir():
            for f in sorted(set(r.rglob("*.yml")).union(r.rglob("*.yaml"))):
                if f.is_file():
                    key = str(f.resolve()).replace("\\", "/")
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
