from __future__ import annotations

import httpx
from eval.backends.http_analyzer import HttpAnalyzerBackend


def test_http_backend_ok() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = {
            "findings": [{"rule_id": "JS-XSS-001", "line": 1}],
            "stats": {"total_findings": 1},
        }
        return httpx.Response(200, json=body)

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    backend = HttpAnalyzerBackend(client=client, base_url="http://test")
    case = {
        "source_code": "void 0",
        "file_path": "a.js",
        "config": {"enable_taint": True},
    }
    res = backend.scan_case(case)
    assert res.ok
    assert res.findings[0].rule_id == "JS-XSS-001"
