from __future__ import annotations

from eval.catalog_runner import run_catalog_inprocess


def test_run_catalog_inprocess_returns_rows() -> None:
    cases = [
        {
            "test_id": "T-INPROC-01",
            "rule_id": "JS-SQL-001",
            "difficulty": "easy",
            "type": "safe",
            "file_path": "app.js",
            "source_code": "db.query('SELECT 1');",
            "config": {"enable_taint": True},
        },
        {
            "test_id": "T-INPROC-02",
            "rule_id": "JS-SQL-001",
            "difficulty": "easy",
            "type": "vulnerable",
            "file_path": "app.js",
            "source_code": "db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);",
            "config": {"enable_taint": True},
            "expected_cwe": "CWE-89",
        },
    ]
    rows = run_catalog_inprocess(cases)
    assert len(rows) == 2
    assert rows[0]["test_id"] == "T-INPROC-01"
    assert rows[0]["rule_id"] == "JS-SQL-001"
    assert rows[0]["outcome"] in ("TN", "FP", "ERROR")
    assert rows[1]["test_id"] == "T-INPROC-02"
    assert rows[1]["outcome"] in ("TP", "FN", "ERROR")
