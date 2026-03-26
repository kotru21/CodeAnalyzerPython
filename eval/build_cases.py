#!/usr/bin/env python3
"""Regenerate eval/catalog/cases.json from Python definitions."""

import json
from pathlib import Path

from eval.cases_pack import all_cases


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    out = root / "eval" / "catalog" / "cases.json"
    cases = all_cases()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(cases, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {len(cases)} cases to {out}")


if __name__ == "__main__":
    main()
