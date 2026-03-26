from eval.classify import aggregate_by_rule, classify_outcome


def test_vulnerable_tp_when_rule_matches() -> None:
    case = {"type": "vulnerable", "rule_id": "JS-CMD-001", "expected_cwe": "CWE-78"}
    response = {
        "stats": {"total_findings": 2},
        "findings": [
            {"rule_id": "JS-CMD-001", "cwe_id": "CWE-78"},
            {"rule_id": "JS-CMD-001", "cwe_id": "CWE-78"},
        ],
    }
    assert classify_outcome(case, response) == "TP"


def test_safe_tn() -> None:
    case = {"type": "safe", "rule_id": "JS-SQL-001"}
    response = {"stats": {"total_findings": 0}, "findings": []}
    assert classify_outcome(case, response) == "TN"


def test_safe_fp_on_any_finding() -> None:
    case = {"type": "safe", "rule_id": "JS-SQL-001"}
    response = {
        "stats": {"total_findings": 1},
        "findings": [{"rule_id": "JS-XSS-001", "cwe_id": "CWE-79"}],
    }
    assert classify_outcome(case, response) == "FP"


def test_fn_wrong_cwe_when_expected() -> None:
    case = {"type": "vulnerable", "rule_id": "JS-SQL-001", "expected_cwe": "CWE-89"}
    response = {
        "stats": {"total_findings": 1},
        "findings": [{"rule_id": "JS-SQL-001", "cwe_id": "CWE-999"}],
    }
    assert classify_outcome(case, response) == "FN"


def test_vulnerable_expected_rule_ids_all_present() -> None:
    case = {
        "type": "vulnerable",
        "rule_id": "MULTI",
        "expected_rule_ids": ["JS-A", "JS-B"],
        "expected_cwe": None,
    }
    response = {
        "stats": {"total_findings": 2},
        "findings": [
            {"rule_id": "JS-A", "cwe_id": "CWE-1"},
            {"rule_id": "JS-B", "cwe_id": "CWE-2"},
        ],
    }
    assert classify_outcome(case, response) == "TP"


def test_vulnerable_expected_rule_ids_missing_one() -> None:
    case = {
        "type": "vulnerable",
        "rule_id": "MULTI",
        "expected_rule_ids": ["JS-A", "JS-B"],
    }
    response = {
        "stats": {"total_findings": 1},
        "findings": [{"rule_id": "JS-A", "cwe_id": "CWE-1"}],
    }
    assert classify_outcome(case, response) == "FN"


def test_error_on_none_response() -> None:
    case = {"type": "vulnerable", "rule_id": "JS-SQL-001", "expected_cwe": "CWE-89"}
    assert classify_outcome(case, None) == "ERROR"


def test_aggregate_by_rule() -> None:
    rows = [
        {"rule_id": "JS-SQL-001", "outcome": "TP"},
        {"rule_id": "JS-SQL-001", "outcome": "FN"},
        {"rule_id": "JS-SQL-001", "outcome": "ERROR"},
    ]
    agg = aggregate_by_rule(rows)
    assert agg["JS-SQL-001"]["TP"] == 1
    assert agg["JS-SQL-001"]["FN"] == 1
    assert agg["JS-SQL-001"]["ERROR"] == 1
