from pathlib import Path

_EXTENSION_MAP: dict[str, str] = {
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "jsx",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "tsx",
}

SUPPORTED_LANGUAGES: frozenset[str] = frozenset(_EXTENSION_MAP.values())


def detect_language(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    lang = _EXTENSION_MAP.get(ext)
    if lang is None:
        msg = f"unsupported file extension for analysis: {ext or '(none)'} (path: {file_path!r})"
        raise ValueError(msg)
    return lang
