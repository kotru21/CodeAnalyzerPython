from __future__ import annotations

from eval.metrics import false_positive_rate, global_counts, precision_recall_f1


def render_report(
    rows: list[dict],
    rule_ids_ordered: list[str],
) -> str:
    lines: list[str] = [
        "# Analyzer evaluation report",
        "",
        "## Per-test results",
        "",
        "| test_id | rule_id | difficulty | type | actual_findings | outcome | notes |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        notes = r.get("notes") or ""
        tid = r.get("test_id", "")
        rid = r.get("rule_id", "")
        diff = r.get("difficulty", "")
        typ = r.get("type", "")
        af = r.get("actual_findings", "")
        oc = r.get("outcome", "")
        lines.append(f"| {tid} | {rid} | {diff} | {typ} | {af} | {oc} | {notes} |")

    lines.extend(["", "## Per-rule metrics", "", _per_rule_table(rows, rule_ids_ordered), ""])

    g = global_counts(rows)
    tp, fp, tn, fn = g["TP"], g["FP"], g["TN"], g["FN"]
    p, rec, f1 = precision_recall_f1(tp, fp, fn)
    fpr = false_positive_rate(fp, tn)

    lines.extend(
        [
            "## Global metrics",
            "",
            f"- TP={tp} FP={fp} TN={tn} FN={fn} ERROR={g['ERROR']}",
            f"- Precision={p:.4f} Recall={rec:.4f} F1={f1:.4f} FPR={fpr:.4f}",
            "",
            "## Rules by recall (worst first)",
            "",
            _rules_by_recall(rows, rule_ids_ordered),
            "",
            "## FN patterns (fill manually)",
            "",
            "_Список пропущенных паттернов с примерами из raw JSON._",
            "",
            "## FP patterns (fill manually)",
            "",
            "_Ложные срабатывания на safe-кейсах._",
            "",
            "## Recommendations (fill manually)",
            "",
            "_Приоритизированные доработки правил и taint._",
            "",
        ]
    )
    return "\n".join(lines)


def _subset_for_rule(rows: list[dict], rule_id: str) -> list[dict]:
    return [
        r
        for r in rows
        if r.get("rule_id") == rule_id
        and not r.get("multi_case")
        and r.get("outcome") in ("TP", "FP", "TN", "FN")
    ]


def _per_rule_table(rows: list[dict], rule_ids: list[str]) -> str:
    hdr = (
        "| rule_id | TP | FP | TN | FN | Precision | Recall | F1 | FPR |"
        "\n|---|---:|---:|---:|---:|---:|---:|---:|---:|"
    )
    body: list[str] = []
    for rid in rule_ids:
        sub = _subset_for_rule(rows, rid)
        tp = sum(1 for r in sub if r.get("outcome") == "TP")
        fp = sum(1 for r in sub if r.get("outcome") == "FP")
        tn = sum(1 for r in sub if r.get("outcome") == "TN")
        fn = sum(1 for r in sub if r.get("outcome") == "FN")
        p, rec, f1 = precision_recall_f1(tp, fp, fn)
        fpr = false_positive_rate(fp, tn)
        body.append(
            f"| {rid} | {tp} | {fp} | {tn} | {fn} | {p:.4f} | {rec:.4f} | {f1:.4f} | {fpr:.4f} |"
        )
    return hdr + "\n" + "\n".join(body)


def _rules_by_recall(rows: list[dict], rule_ids: list[str]) -> str:
    scored: list[tuple[str, float, int, int]] = []
    for rid in rule_ids:
        sub = _subset_for_rule(rows, rid)
        tp = sum(1 for r in sub if r.get("outcome") == "TP")
        fn = sum(1 for r in sub if r.get("outcome") == "FN")
        _, rec, _ = precision_recall_f1(tp, 0, fn)  # recall only
        scored.append((rid, rec, tp, fn))
    scored.sort(key=lambda x: (x[1], x[3]))  # low recall, high fn first
    lines = ["| rule_id | recall | TP | FN |", "|---|---:|---:|---:|"]
    for rid, rec, tp, fn in scored:
        lines.append(f"| {rid} | {rec:.4f} | {tp} | {fn} |")
    return "\n".join(lines)
