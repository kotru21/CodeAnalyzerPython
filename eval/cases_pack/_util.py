DEFAULT_CONFIG: dict = {"enable_taint": True}


def mk(
    test_id: str,
    rule_id: str,
    difficulty: str,
    typ: str,
    file_path: str,
    source_code: str,
    expected_cwe: str | None,
    description: str,
    *,
    config: dict | None = None,
    tags: list[str] | None = None,
    expected_rule_ids: list[str] | None = None,
    notes_expected_count: int | None = None,
) -> dict:
    row: dict = {
        "test_id": test_id,
        "rule_id": rule_id,
        "difficulty": difficulty,
        "type": typ,
        "file_path": file_path,
        "source_code": source_code,
        "config": {**DEFAULT_CONFIG, **(config or {})},
        "expected_cwe": expected_cwe,
        "description": description,
    }
    if tags:
        row["tags"] = tags
    if expected_rule_ids is not None:
        row["expected_rule_ids"] = expected_rule_ids
    if notes_expected_count is not None:
        row["notes_expected_count"] = notes_expected_count
    return row
