import io
import zipfile
from pathlib import Path

import pytest

from analyzer.utils.file_handler import extract_zip


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_extract_zip_ok(tmp_path: Path) -> None:
    out = extract_zip(_zip_bytes({"a.js": b"const x = 1;"}), tmp_path)
    assert (out / "a.js").read_text(encoding="utf-8") == "const x = 1;"


def test_extract_zip_blocks_slip(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="zip slip"):
        extract_zip(_zip_bytes({"../evil.js": b"x"}), tmp_path)
