from analyzer.knowledge.cwe_mapping import build_rule_taxonomy
from analyzer.rules.registry import get_all_rules


def test_taxonomy_matches_rule_meta() -> None:
    taxonomy = build_rule_taxonomy()
    for rule in get_all_rules():
        meta = rule.meta()
        assert taxonomy["cwe"][meta.rule_id] == meta.cwe_id
        assert taxonomy["owasp"][meta.rule_id] == meta.owasp
