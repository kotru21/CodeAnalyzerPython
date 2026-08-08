from __future__ import annotations

import subprocess
from pathlib import Path

DEFAULT_JS_TS_EXTENSIONS = frozenset({"js", "jsx", "ts", "tsx"})


def _to_posix_relpath(corpus_root: Path, file_path: Path) -> str:
    rel = file_path.resolve().relative_to(corpus_root.resolve())
    return rel.as_posix()


def list_js_ts_relpaths_walk(
    corpus_root: Path,
    *,
    extensions: frozenset[str] | None = None,
) -> list[str]:
    root = corpus_root.resolve()
    ext = extensions if extensions is not None else DEFAULT_JS_TS_EXTENSIONS
    found: list[str] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lstrip(".").lower() not in ext:
            continue
        found.append(_to_posix_relpath(root, p))
    return sorted(set(found))


def list_js_ts_relpaths_git(
    corpus_root: Path,
    *,
    extensions: frozenset[str] | None = None,
) -> list[str]:
    root = corpus_root.resolve()
    ext = extensions if extensions is not None else DEFAULT_JS_TS_EXTENSIONS
    proc = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        check=False,
        text=False,
    )
    if proc.returncode != 0:
        raise RuntimeError("git ls-files failed; use walk mode or run from a git checkout")
    raw = proc.stdout.split(b"\0")
    out: list[str] = []
    for b in raw:
        if not b:
            continue
        rel = b.decode("utf-8", errors="replace").replace("\\", "/")
        suf = Path(rel).suffix.lstrip(".").lower()
        if suf not in ext:
            continue
        p = (root / rel).resolve()
        try:
            p.relative_to(root)
        except ValueError:
            continue
        if not p.is_file():
            continue
        out.append(Path(rel).as_posix())
    return sorted(set(out))
