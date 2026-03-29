import json
from pathlib import Path

import pytest

from eval.dataset_materialize import materialize_dataset_csv


class _FakeResponse:
    def __init__(self, content: bytes, status: int = 200) -> None:
        self.content = content
        self.status_code = status

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeClient:
    def __init__(self, *args: object, **kwargs: object) -> None:
        kwargs.pop("follow_redirects", None)
        kwargs.pop("timeout", None)
        self._content = kwargs.pop("_test_content", b"export const x = 1;\n")

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def get(self, url: str) -> _FakeResponse:
        return _FakeResponse(self._content, 200)


def test_materialize_writes_file_and_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    csv_path = tmp_path / "d.csv"
    csv_path.write_text(
        "full_repo_path,path\n"
        "https://github.com/o/r/blob/abcdef1234567890abcdef1234567890ab/p/f.js,p/f.js\n",
        encoding="utf-8",
    )
    root = tmp_path / "mat"
    monkeypatch.setattr(
        "eval.dataset_materialize.httpx.Client",
        lambda *a, **k: _FakeClient(*a, **k),
    )
    manifest_path = materialize_dataset_csv(csv_path, root, refresh=False)
    assert manifest_path == root / "materialization_manifest.json"
    rel_file = "o_r_abcdef123456/p/f.js"
    f = root / rel_file
    assert f.is_file()
    assert f.read_bytes() == b"export const x = 1;\n"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert data["row_count"] == 1
    assert len(data["files"]) == 1
    assert data["files"][0]["relpath"] == rel_file


def test_materialize_404_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    csv_path = tmp_path / "d.csv"
    csv_path.write_text(
        "full_repo_path\n"
        "https://github.com/o/r/blob/abcdef1234567890abcdef1234567890ab/missing.js\n",
        encoding="utf-8",
    )

    class _Client404(_FakeClient):
        def get(self, url: str) -> _FakeResponse:
            return _FakeResponse(b"", 404)

    monkeypatch.setattr(
        "eval.dataset_materialize.httpx.Client",
        lambda *a, **k: _Client404(*a, **k),
    )
    with pytest.raises(RuntimeError, match="404"):
        materialize_dataset_csv(csv_path, tmp_path / "mat", refresh=False)
