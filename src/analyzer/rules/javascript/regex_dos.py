from tree_sitter import Node

from analyzer.core.severity import Confidence, Severity
from analyzer.rules.base import AnalysisContext, BaseRule, RawFinding, RuleMeta


class RegexDOSRule(BaseRule):
    def meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id="JS-REDOS-001",
            title="Regular Expression Denial of Service (ReDoS)",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            cwe_id="CWE-1333",
            owasp="A06:2021 Vulnerable and Outdated Components",
            description=(
                "A regular expression is constructed from user input, which can "
                "lead to catastrophic backtracking and denial of service."
            ),
            remediation=(
                "Use a static regex or validate/sanitize user input before "
                "constructing RegExp. Consider using re2 for safe regex."
            ),
        )

    def run(self, context: AnalysisContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        self._walk(context.root_node, context, findings)
        return findings

    def _walk(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        if node.type == "new_expression":
            self._check_new_regexp(node, ctx, findings)
        for child in node.children:
            self._walk(child, ctx, findings)

    def _check_new_regexp(
        self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]
    ) -> None:
        constructor = node.child_by_field_name("constructor")
        args = node.child_by_field_name("arguments")
        if constructor is None or args is None:
            return
        name = constructor.text.decode() if constructor.text else ""
        if name != "RegExp":
            return
        first_arg = next((c for c in args.children if c.is_named), None)
        if first_arg is None or first_arg.type == "string":
            return
        findings.append(
            RawFinding(
                rule_id=self.meta().rule_id,
                line_start=node.start_point[0] + 1,
                line_end=node.end_point[0] + 1,
                column=node.start_point[1],
                code_snippet=self._snippet(ctx, node.start_point[0] + 1),
            )
        )
