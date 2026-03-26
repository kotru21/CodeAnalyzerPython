from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from eval.scan_types import BackendScanResult


class ScanBackend(Protocol):
    name: str

    def scan_case(self, case: dict[str, Any]) -> BackendScanResult: ...
