"""Measure parse-cache benefit on a synthetic 32-file bundle.

Usage:
  PYTHONPATH=src;. python scripts/bench_bundle_parse.py
"""

from __future__ import annotations

import time

from analyzer.api.schemas import AnalyzeBundleRequest, ScanConfig
from analyzer.config import Settings
from analyzer.core.orchestrator import Orchestrator


def _bundle(n: int = 32) -> dict[str, str]:
    files: dict[str, str] = {}
    for i in range(n):
        files[f"f{i}.js"] = f"const x{i} = req.query.a;\ndb.query(`SELECT ${{x{i}}}`);\n"
    return files


def main() -> None:
    files = _bundle()
    req = AnalyzeBundleRequest(files=files, config=ScanConfig(enable_taint=True))
    orch = Orchestrator(Settings())
    t0 = time.perf_counter()
    orch.analyze_bundle_sync(req)
    t1 = time.perf_counter()
    # Second run identical content — cache is per-scan, so rebuild orch scan.
    # Document sequential baseline duration for the 32-file bundle.
    print(f"bundle_files={len(files)} duration_ms={(t1 - t0) * 1000:.1f}")
    print("note: ScanParseCache is per-scan; benefit is re-parse avoidance within one scan.")


if __name__ == "__main__":
    main()
