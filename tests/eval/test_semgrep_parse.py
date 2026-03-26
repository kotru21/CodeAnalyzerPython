from __future__ import annotations

import json
from pathlib import Path

from eval.backends.semgrep_subprocess import findings_from_semgrep_json


def test_one_result() -> None:
    data = json.loads(
        (Path(__file__).parent / "fixtures" / "semgrep_minimal.json").read_text(encoding="utf-8")
    )
    fs = findings_from_semgrep_json(data)
    assert len(fs) == 1
    assert fs[0].rule_id == "javascript.lang.security.test-rule"
    assert fs[0].line == 7
