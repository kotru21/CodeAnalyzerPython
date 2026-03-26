from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SKIP_TAGS = frozenset({"special:sarif", "special:async"})


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def load_cases(catalog_path: Path) -> list[dict[str, Any]]:
    data = json.loads(catalog_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("catalog must be a JSON array")
    return data


def load_rule_ids(catalog_dir: Path) -> list[str]:
    m = json.loads((catalog_dir / "rule_cwe_map.json").read_text(encoding="utf-8"))
    if not isinstance(m, dict):
        raise ValueError("rule_cwe_map must be a JSON object")
    return sorted(m.keys())


def should_skip_main(case: dict[str, Any]) -> bool:
    tags = case.get("tags") or []
    try:
        return bool(SKIP_TAGS.intersection(tags))
    except TypeError:
        return False
