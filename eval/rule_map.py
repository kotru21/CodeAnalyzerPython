from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class RuleMap:
    version: int
    rules: dict[str, list[str]]


def load_rule_map(path: Path) -> RuleMap:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("rule map root must be a mapping")
    version = int(raw.get("version", 1))
    rules_raw = raw.get("rules") or {}
    if not isinstance(rules_raw, dict):
        raise ValueError("rules must be a mapping")
    rules: dict[str, list[str]] = {}
    for k, v in rules_raw.items():
        if not isinstance(k, str):
            continue
        if isinstance(v, str):
            rules[k] = [v]
        elif isinstance(v, list) and all(isinstance(x, str) for x in v):
            rules[k] = list(v)
    return RuleMap(version=version, rules=rules)


def get_semgrep_configs_for_rule(
    rule_map: RuleMap, rule_id: str, repo_root: Path
) -> list[Path]:
    paths = rule_map.rules.get(rule_id, [])
    out: list[Path] = []
    for p in paths:
        q = Path(p)
        out.append(q if q.is_absolute() else (repo_root / q).resolve())
    return out


def _rule_ids_for_case(case: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    rid = case.get("rule_id")
    if isinstance(rid, str):
        ids.append(rid)
    exp = case.get("expected_rule_ids")
    if isinstance(exp, list):
        for x in exp:
            if isinstance(x, str):
                ids.append(x)
    return ids


def collect_semgrep_configs_for_cases(
    cases: list[dict[str, Any]], rule_map: RuleMap, repo_root: Path
) -> list[Path]:
    seen: set[str] = set()
    ordered: list[Path] = []
    for case in cases:
        for rid in _rule_ids_for_case(case):
            for p in get_semgrep_configs_for_rule(rule_map, rid, repo_root):
                key = str(p.resolve())
                if key not in seen:
                    seen.add(key)
                    ordered.append(p)
    ordered.sort(key=lambda p: str(p))
    return ordered
