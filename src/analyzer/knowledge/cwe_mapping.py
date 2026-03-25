"""Taxonomy helpers derived from registered rule metadata (single source of truth)."""


def build_rule_taxonomy() -> dict[str, dict[str, str]]:
    from analyzer.rules.registry import get_all_rules

    cwe: dict[str, str] = {}
    owasp: dict[str, str] = {}
    for rule in get_all_rules():
        meta = rule.meta()
        cwe[meta.rule_id] = meta.cwe_id
        owasp[meta.rule_id] = meta.owasp
    return {"cwe": cwe, "owasp": owasp}
