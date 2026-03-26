from eval.metrics import false_positive_rate, global_counts, precision_recall_f1


def test_precision_recall_f1() -> None:
    p, r, f1 = precision_recall_f1(tp=2, fp=1, fn=1)
    assert abs(p - 2 / 3) < 1e-6
    assert abs(r - 2 / 3) < 1e-6
    assert f1 > 0


def test_fpr() -> None:
    assert false_positive_rate(1, 3) == 0.25


def test_global_counts() -> None:
    rows = [
        {"outcome": "TP"},
        {"outcome": "FP"},
        {"outcome": "TN"},
        {"outcome": "FN"},
        {"outcome": "ERROR"},
    ]
    g = global_counts(rows)
    assert g == {"TP": 1, "FP": 1, "TN": 1, "FN": 1, "ERROR": 1}
