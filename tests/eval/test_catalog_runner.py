from __future__ import annotations

from typing import TYPE_CHECKING

from eval.catalog_runner import run_catalog
from eval.scan_types import BackendScanResult

if TYPE_CHECKING:
    from pathlib import Path


class _FakeHttpBackend:
    name = "analyzer_http"

    def scan_case(self, case: dict) -> BackendScanResult:
        return BackendScanResult(
            ok=True,
            error=None,
            raw={"findings": [], "stats": {"total_findings": 0}},
            findings=[],
        )


def test_skip_sarif_tag(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    cases = [
        {
            "test_id": "S1",
            "rule_id": "JS-X",
            "difficulty": "easy",
            "type": "safe",
            "tags": ["special:sarif"],
        }
    ]
    rows = run_catalog(
        cases=cases,
        backends=[_FakeHttpBackend()],
        raw_dir=raw_dir,
        write_report=False,
        out_dir=out_dir,
    )
    assert len(rows) == 1
    assert rows[0]["outcome"] == "SKIP"
    assert not (raw_dir / "S1.json").exists()


def test_fake_http_writes_raw_and_tn(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    catalog_dir = tmp_path / "cat"
    catalog_dir.mkdir()
    (catalog_dir / "rule_cwe_map.json").write_text('{"JS-X": ["CWE-79"]}', encoding="utf-8")

    cases = [
        {
            "test_id": "T1",
            "rule_id": "JS-X",
            "difficulty": "easy",
            "type": "safe",
        }
    ]
    rows = run_catalog(
        cases=cases,
        backends=[_FakeHttpBackend()],
        raw_dir=raw_dir,
        write_report=True,
        out_dir=out_dir,
        catalog_dir=catalog_dir,
    )
    assert rows[0]["outcome"] == "TN"
    assert (raw_dir / "T1.json").exists()
    assert (out_dir / "report.md").exists()
