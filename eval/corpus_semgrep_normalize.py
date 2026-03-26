from __future__ import annotations

from pathlib import Path
from typing import Any


def semgrep_result_relpath(corpus_root: Path, result_path: str | None) -> str | None:
    """Map Semgrep JSON result path to corpus-relative POSIX path, or None if outside corpus."""
    if not result_path or not isinstance(result_path, str):
        return None
    root = corpus_root.resolve()
    try:
        abs_p = Path(result_path).resolve()
        rel = abs_p.relative_to(root)
    except (OSError, ValueError, RuntimeError):
        return None
    return rel.as_posix()


def integer_lines_from_semgrep_for_relpath(
    results: list[dict[str, Any]],
    corpus_root: Path,
    target_relpath: str,
    allowed_check_ids: frozenset[str] | None,
) -> list[int]:
    """
    Lines from Semgrep results for one corpus file.

    * ``allowed_check_ids is None`` — include every result whose path matches (Policy B).
    * ``allowed_check_ids == frozenset()`` — include none.
    * Otherwise — filter by ``check_id`` membership.
    """
    lines: set[int] = set()
    target = Path(target_relpath).as_posix()
    for r in results:
        if not isinstance(r, dict):
            continue
        check = r.get("check_id") or r.get("rule_id")
        if allowed_check_ids is not None:
            if not isinstance(check, str) or check not in allowed_check_ids:
                continue
        elif not isinstance(check, str):
            continue
        rp = semgrep_result_relpath(corpus_root, str(r.get("path")) if r.get("path") else None)
        if rp != target:
            continue
        start = r.get("start")
        if not isinstance(start, dict):
            continue
        line = start.get("line")
        if not isinstance(line, int):
            continue
        lines.add(line)
    return sorted(lines)
