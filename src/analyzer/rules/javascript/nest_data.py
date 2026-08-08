"""NestJS controller data-path heuristics (@Query/@Param/@Body near raw SQL)."""

from tree_sitter import Node

from analyzer.core.severity import Confidence, Severity
from analyzer.rules.base import AnalysisContext, BaseRule, RawFinding, RuleMeta

_DECORATORS = ("Query", "Param", "Body")


class NestRawQueryRule(BaseRule):
    def meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id="JS-NEST-001",
            title="NestJS request decorator near raw SQL template",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            cwe_id="CWE-89",
            owasp="A03:2021 Injection",
            description=(
                "A NestJS handler uses @Query/@Param/@Body and a template-literal "
                "SQL call in the same function — likely unsanitized input in SQL."
            ),
            remediation=(
                "Use parameterized queries / QueryBuilder / repository methods; "
                "never interpolate decorator parameters into SQL strings."
            ),
        )

    def run(self, context: AnalysisContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        self._walk(context.root_node, context, findings)
        return findings

    def _walk(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        if node.type in (
            "function_declaration",
            "method_definition",
            "arrow_function",
            "function_expression",
        ):
            self._check_fn(node, ctx, findings)
        for child in node.children:
            self._walk(child, ctx, findings)

    def _check_fn(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        text = node.text.decode() if node.text else ""
        has_decorator = any(f"@{d}" in text or f"@{d}(" in text for d in _DECORATORS)
        if not has_decorator:
            return
        if ".query(" not in text and ".$queryRaw" not in text:
            return
        if "`" not in text or "${" not in text:
            return
        # Report at the function start line (heuristic).
        findings.append(
            RawFinding(
                rule_id=self.meta().rule_id,
                line_start=node.start_point[0] + 1,
                line_end=node.end_point[0] + 1,
                column=node.start_point[1],
                code_snippet=self._snippet(ctx, node.start_point[0] + 1),
            )
        )
