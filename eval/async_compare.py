#!/usr/bin/env python3
"""Compare findings from /analyze/sync vs /analyze/async + poll for one payload."""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any

import httpx


def _finding_keys(data: dict[str, Any]) -> set[tuple[str, str, int]]:
    out: set[tuple[str, str, int]] = set()
    for f in data.get("findings") or []:
        if not isinstance(f, dict):
            continue
        rid = str(f.get("rule_id", ""))
        cwe = str(f.get("cwe_id", ""))
        line = int(f.get("line_start", 0))
        out.add((rid, cwe, line))
    return out


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--base-url", default="http://localhost:8000")
    p.add_argument("--timeout", type=float, default=120.0)
    args = p.parse_args()
    base = args.base_url.rstrip("/")

    body = {
        "source_code": "const { exec } = require('child_process');\nexec(`echo ${req.query.x}`);\n",
        "file_path": "async_cmp.js",
        "config": {"enable_taint": True},
    }

    with httpx.Client() as client:
        sr = client.post(f"{base}/api/v1/analyze/sync", json=body, timeout=60.0)
        if sr.status_code != 200:
            print(f"sync HTTP {sr.status_code}: {sr.text[:500]}")
            return 1
        sync_data = sr.json()

        ar = client.post(f"{base}/api/v1/analyze/async", json=body, timeout=30.0)
        if ar.status_code != 200:
            print(f"async HTTP {ar.status_code}: {ar.text[:500]}")
            return 1
        async_meta = ar.json()
        scan_id = async_meta.get("scan_id")
        if not scan_id:
            print("no scan_id in async response")
            return 1

        deadline = time.monotonic() + args.timeout
        async_data: dict | None = None
        while time.monotonic() < deadline:
            gr = client.get(f"{base}/api/v1/results/{scan_id}", timeout=30.0)
            if gr.status_code != 200:
                print(f"poll HTTP {gr.status_code}: {gr.text[:300]}")
                return 1
            payload = gr.json()
            st = payload.get("status")
            if st == "completed":
                async_data = payload
                break
            if st == "failed":
                print(f"async failed: {payload.get('error')}")
                return 1
            time.sleep(1.0)

        if async_data is None:
            print("timeout waiting for async results")
            return 1

    a = _finding_keys(sync_data)
    b = _finding_keys(async_data)
    if a != b:
        print("Mismatch:")
        print(" sync only:", a - b)
        print(" async only:", b - a)
        print("sync json:", json.dumps(sync_data, indent=2, default=str)[:2000])
        print("async json:", json.dumps(async_data, indent=2, default=str)[:2000])
        return 1
    print("OK: finding keys match between sync and async")
    return 0


if __name__ == "__main__":
    sys.exit(main())
