from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from eval.corpus_repro import config_bundle_hashes, semgrep_cli_version, sha256_file


def test_sha256_file_known_content(tmp_path: Path) -> None:
    p = tmp_path / "x.bin"
    data = b"hello-worm"
    p.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    assert sha256_file(p) == expected


def test_semgrep_cli_version_monkeypatch(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd: list[str], **kwargs: object) -> object:
        class R:
            returncode = 0
            stdout = "1.2.3-test\n"
            stderr = ""

        return R()

    monkeypatch.setattr("eval.corpus_repro.subprocess.run", fake_run)
    monkeypatch.setattr(
        "eval.corpus_repro.semgrep_executable", lambda: "semgrep-fake"
    )
    assert semgrep_cli_version() == "1.2.3-test"


def test_config_bundle_hashes_single_file(tmp_path: Path) -> None:
    f = tmp_path / "rules.yaml"
    f.write_text("rules: []\n", encoding="utf-8")
    h = config_bundle_hashes([f])
    keys = list(h.keys())
    assert len(keys) == 1
    assert keys[0].endswith("rules.yaml")
    assert len(h[keys[0]]) == 64
