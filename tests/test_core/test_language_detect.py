import pytest

from analyzer.core.language_detect import detect_language


def test_detect_js() -> None:
    assert detect_language("app.js") == "javascript"


def test_detect_ts() -> None:
    assert detect_language("mod.ts") == "typescript"


def test_reject_unknown_extension() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        detect_language("notes.txt")
