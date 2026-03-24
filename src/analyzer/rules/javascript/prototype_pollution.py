from tree_sitter import Node

from analyzer.core.severity import Confidence, Severity
from analyzer.rules.base import AnalysisContext, BaseRule, RawFinding, RuleMeta

_DANGEROUS_KEYS = frozenset({"__proto__", "constructor", "prototype"})


class PrototypePollutionRule(BaseRule):
    def meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id="JS-PROTO-001",
            title="Prototype Pollution via recursive merge or dynamic key assignment",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            cwe_id="CWE-1321",
            owasp="A03:2021 Injection",
            description=(
                "Object properties are set using user-controlled keys without "
                "filtering __proto__, constructor, or prototype, enabling prototype pollution."
            ),
            remediation=(
                "Use Object.create(null) for target objects, filter dangerous keys "
                "(__proto__, constructor, prototype), or use Map instead of plain objects."
            ),
        )

    def run(self, context: AnalysisContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        self._walk(context.root_node, context, findings)
        return findings

    def _walk(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        if node.type == "for_in_statement":
            self._check_for_in_merge(node, ctx, findings)
        elif node.type == "assignment_expression":
            self._check_dynamic_bracket_assign(node, ctx, findings)
        for child in node.children:
            self._walk(child, ctx, findings)

    def _check_for_in_merge(
        self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]
    ) -> None:
        source_text = node.text.decode() if node.text else ""
        has_bracket_assign = "[" in source_text and "]" in source_text and "=" in source_text
        guards_proto = any(dk in source_text for dk in _DANGEROUS_KEYS)
        if has_bracket_assign and not guards_proto:
            findings.append(self._make_finding(node, ctx))

    def _check_dynamic_bracket_assign(
        self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]
    ) -> None:
        left = node.child_by_field_name("left")
        if left is None or left.type != "subscript_expression":
            return
        index = left.child_by_field_name("index")
        if index is None:
            return
        if index.type == "string":
            return
        if index.type == "member_expression":
            index_text = index.text.decode() if index.text else ""
            if any(s in index_text for s in ("req.", "request.", "ctx.")):
                findings.append(self._make_finding(node, ctx))

    def _make_finding(self, node: Node, ctx: AnalysisContext) -> RawFinding:
        return RawFinding(
            rule_id=self.meta().rule_id,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            column=node.start_point[1],
            code_snippet=self._snippet(ctx, node.start_point[0] + 1),
        )
