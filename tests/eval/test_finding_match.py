from eval.finding_match import classify_case_findings, finding_matches_expected


def test_line_tolerance_match() -> None:
    finding = {"rule_id": "JS-SQL-001", "line_start": 5, "cwe_id": "CWE-89"}
    expected = {"rule_id": "JS-SQL-001", "line": 4, "cwe_id": "CWE-89"}
    assert finding_matches_expected(finding, expected, line_tolerance=1)


def test_safe_case_counts_unexpected_fp_per_finding() -> None:
    case = {
        "type": "safe",
        "rule_id": "JS-SQL-001",
        "expected_findings": [],
    }
    response = {
        "findings": [
            {"rule_id": "JS-XSS-001", "line_start": 1, "cwe_id": "CWE-79"},
            {"rule_id": "JS-PATH-001", "line_start": 2, "cwe_id": "CWE-22"},
        ]
    }
    outcomes = classify_case_findings(case, response)
    assert outcomes.count("FP") == 2
    assert outcomes.count("TN") == 0


def test_vulnerable_extra_finding_is_fp() -> None:
    case = {
        "type": "vulnerable",
        "rule_id": "JS-CMD-001",
        "expected_findings": [{"rule_id": "JS-CMD-001", "line": 3}],
    }
    response = {
        "findings": [
            {"rule_id": "JS-CMD-001", "line_start": 3, "cwe_id": "CWE-78"},
            {"rule_id": "JS-PATH-001", "line_start": 3, "cwe_id": "CWE-22"},
        ]
    }
    outcomes = classify_case_findings(case, response)
    assert "TP" in outcomes
    assert "FP" in outcomes
