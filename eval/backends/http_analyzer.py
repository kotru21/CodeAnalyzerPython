from __future__ import annotations

import json
from typing import Any

import httpx

from eval.scan_types import BackendScanResult, analyzer_response_to_result


class HttpAnalyzerBackend:
    name = "analyzer_http"

    def __init__(self, client: httpx.Client, base_url: str) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")

    def scan_case(self, case: dict[str, Any]) -> BackendScanResult:
        url = f"{self._base_url}/api/v1/analyze/sync"
        body = {
            "source_code": case["source_code"],
            "file_path": case["file_path"],
            "config": case.get("config") or {"enable_taint": True},
        }
        try:
            r = self._client.post(url, json=body, timeout=120.0)
        except httpx.RequestError as e:
            return analyzer_response_to_result(None, str(e))
        if r.status_code != 200:
            return analyzer_response_to_result(None, f"HTTP {r.status_code}: {r.text[:500]}")
        try:
            data = r.json()
        except json.JSONDecodeError as e:
            return analyzer_response_to_result(None, str(e))
        if not isinstance(data, dict):
            return analyzer_response_to_result(None, "response JSON is not an object")
        return analyzer_response_to_result(data, None)
