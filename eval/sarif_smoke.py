#!/usr/bin/env python3
"""POST a few sync scans with response_format=sarif and validate minimal SARIF 2.1.0 shape."""

from __future__ import annotations

import argparse
import json
import sys

import httpx

SAMPLES = [
    {
        "source_code": "const x = 1;",
        "file_path": "a.js",
        "config": {"enable_taint": False},
        "response_format": "sarif",
    },
    {
        "source_code": "db.query(`SELECT 1 WHERE x = ${req.query.id}`);",
        "file_path": "b.js",
        "config": {"enable_taint": True},
        "response_format": "sarif",
    },
    {
        "source_code": "console.log('ok');",
        "file_path": "c.ts",
        "config": {"enable_taint": True},
        "response_format": "sarif",
    },
]


def _check_sarif(body: dict) -> list[str]:
    errs: list[str] = []
    if body.get("version") != "2.1.0":
        errs.append(f"expected version 2.1.0, got {body.get('version')}")
    runs = body.get("runs")
    if not isinstance(runs, list) or not runs:
        errs.append("missing runs[]")
        return errs
    run0 = runs[0]
    tool = run0.get("tool")
    if not isinstance(tool, dict) or "driver" not in tool:
        errs.append("missing runs[0].tool.driver")
    if "results" not in run0:
        errs.append("missing runs[0].results")
    return errs


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--base-url", default="http://localhost:8000")
    args = p.parse_args()
    url = f"{args.base_url.rstrip('/')}/api/v1/analyze/sync"
    failed = False
    with httpx.Client() as client:
        for i, body in enumerate(SAMPLES):
            r = client.post(url, json=body, timeout=60.0)
            ct = r.headers.get("content-type", "")
            if r.status_code != 200:
                print(f"sample {i}: HTTP {r.status_code} {r.text[:300]}")
                failed = True
                continue
            if "sarif" not in ct:
                print(f"sample {i}: unexpected Content-Type {ct!r}")
                failed = True
            try:
                data = r.json()
            except json.JSONDecodeError as e:
                print(f"sample {i}: invalid JSON {e}")
                failed = True
                continue
            errs = _check_sarif(data)
            if errs:
                print(f"sample {i}: " + "; ".join(errs))
                failed = True
            else:
                print(f"sample {i}: OK")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
