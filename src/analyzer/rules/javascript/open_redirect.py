from tree_sitter import Node

from analyzer.core.severity import Confidence, Severity
from analyzer.rules.base import AnalysisContext, BaseRule, RawFinding, RuleMeta


class OpenRedirectRule(BaseRule):
    def meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id="JS-REDIRECT-001",
            title="Open Redirect via user-controlled URL",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            cwe_id="CWE-601",
            owasp="A01:2021 Broken Access Control",
            description=(
                "The redirect destination is taken directly from user input "
                "without validation against an allowlist."
            ),
            remediation=(
                "Validate redirect URLs against a whitelist of allowed domains, "
                "or use relative paths only."
            ),
        )

    def run(self, context: AnalysisContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        self._walk(context.root_node, context, findings)
        return findings

    def _walk(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        if node.type == "call_expression":
            self._check_redirect(node, ctx, findings)
        for child in node.children:
            self._walk(child, ctx, findings)

    def _check_redirect(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func is None or args is None or func.type != "member_expression":
            return
        prop = func.child_by_field_name("property")
        if prop is None:
            return
        if (prop.text.decode() if prop.text else "") != "redirect":
            return

        first_arg = next((c for c in args.children if c.is_named), None)
        if first_arg is None or first_arg.type == "string":
            return
        if first_arg.type == "number":
            first_arg = next((c for c in args.children if c.is_named and c != first_arg), None)
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
