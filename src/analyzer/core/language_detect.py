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


def detect_language(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    lang = _EXTENSION_MAP.get(ext)
    if lang is None:
        msg = f"unsupported file extension for analysis: {ext or '(none)'}"
        raise ValueError(msg)
    return lang
