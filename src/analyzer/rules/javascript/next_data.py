"""Next.js App Router data-path heuristics (searchParams → redirect/fetch)."""

from tree_sitter import Node

from analyzer.core.severity import Confidence, Severity
from analyzer.rules.base import AnalysisContext, BaseRule, RawFinding, RuleMeta


class NextSearchParamsRule(BaseRule):
    def meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id="JS-NEXT-001",
            title="Next.js searchParams used in redirect or outbound request",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            cwe_id="CWE-601",
            owasp="A01:2021 Broken Access Control",
            description=(
                "User-controlled Next.js searchParams flow into redirect() or fetch() "
                "without host allowlisting."
            ),
            remediation=(
                "Validate searchParams against an allowlist before redirect/fetch. "
                "Prefer relative redirects only."
            ),
        )

    def run(self, context: AnalysisContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        self._walk(context.root_node, context, findings)
        return findings

    def _walk(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        if node.type == "call_expression":
            self._check(node, ctx, findings)
        for child in node.children:
            self._walk(child, ctx, findings)

    def _check(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func is None or args is None:
            return
        name = ""
        if func.type == "identifier" and func.text:
            name = func.text.decode()
        elif func.type == "member_expression":
            prop = func.child_by_field_name("property")
            if prop is not None and prop.text:
                name = prop.text.decode()
        if name not in ("redirect", "fetch", "permanentRedirect"):
            return
        arg_text = args.text.decode() if args.text else ""
        if "searchParams" not in arg_text:
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
