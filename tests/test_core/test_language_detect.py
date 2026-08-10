import pytest

from analyzer.core.language_detect import detect_language


def test_detect_js() -> None:
    assert detect_language("app.js") == "javascript"


def test_detect_ts() -> None:
    assert detect_language("mod.ts") == "typescript"


def test_reject_unknown_extension() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        detect_language("notes.txt")


def test_reject_dotfile_includes_path_in_message() -> None:
    with pytest.raises(ValueError) as exc_info:
        detect_language(".js")
    assert ".js" in str(exc_info.value)
    assert "(none)" in str(exc_info.value)


def test_reject_unknown_extension_includes_path() -> None:
    with pytest.raises(ValueError, match=r"notes\.txt"):
        detect_language("notes.txt")
