from __future__ import annotations

import subprocess
import sys


def test_cli_run_help() -> None:
    r = subprocess.run(
        [sys.executable, "-m", "eval.cli", "run", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0
    assert "--base-url" in r.stdout
