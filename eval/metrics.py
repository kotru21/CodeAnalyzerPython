from __future__ import annotations


def precision_recall_f1(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        0.0
        if precision + recall == 0
        else 2 * precision * recall / (precision + recall)
    )
    return precision, recall, f1


def false_positive_rate(fp: int, tn: int) -> float:
    return fp / (fp + tn) if (fp + tn) > 0 else 0.0


def compute_counts(rows: list[dict]) -> dict[str, dict[str, int]]:
    """Alias-style: rule_id -> outcome counts."""
    from eval.classify import aggregate_by_rule

    return aggregate_by_rule(rows)


def global_counts(rows: list[dict]) -> dict[str, int]:
    acc = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "ERROR": 0}
    for row in rows:
        o = row.get("outcome")
        if o in acc:
            acc[o] += 1
    return acc
