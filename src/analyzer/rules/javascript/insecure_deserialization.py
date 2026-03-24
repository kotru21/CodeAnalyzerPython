from tree_sitter import Node

from analyzer.core.severity import Confidence, Severity
from analyzer.rules.base import AnalysisContext, BaseRule, RawFinding, RuleMeta

_DANGEROUS_METHODS = frozenset({"unserialize", "deserialize"})


class InsecureDeserializationRule(BaseRule):
    def meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id="JS-DES-001",
            title="Insecure Deserialization",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe_id="CWE-502",
            owasp="A08:2021 Software and Data Integrity Failures",
            description=(
                "User input is passed to an unsafe deserialization function "
                "like node-serialize unserialize or eval(Buffer.from(...)), "
                "allowing arbitrary code execution."
            ),
            remediation=(
                "Use JSON.parse() with schema validation instead of "
                "node-serialize. Never eval() deserialized data."
            ),
        )

    def run(self, context: AnalysisContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        self._walk(context.root_node, context, findings)
        return findings

    def _walk(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        if node.type == "call_expression":
            self._check_call(node, ctx, findings)
        for child in node.children:
            self._walk(child, ctx, findings)

    def _check_call(
        self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]
    ) -> None:
        func = node.child_by_field_name("function")
        if func is None:
            return

        method = self._get_method_name(func)
        if method in _DANGEROUS_METHODS:
            findings.append(self._make_finding(node, ctx))
            return

        if method == "eval":
            args = node.child_by_field_name("arguments")
            if args is None:
                return
            if self._has_buffer_from(args):
                findings.append(self._make_finding(node, ctx))
                return
            first_arg = next((c for c in args.children if c.is_named), None)
            if first_arg and first_arg.type == "identifier":
                if "Buffer.from" in ctx.source_code:
                    findings.append(self._make_finding(node, ctx))

    @staticmethod
    def _has_buffer_from(args_node: Node) -> bool:
        text = args_node.text.decode() if args_node.text else ""
        return "Buffer.from" in text

    @staticmethod
    def _get_method_name(func_node: Node) -> str:
        if func_node.type == "identifier":
            return func_node.text.decode() if func_node.text else ""
        if func_node.type == "member_expression":
            prop = func_node.child_by_field_name("property")
            return (prop.text.decode() if prop.text else "") if prop else ""
        return ""

    def _make_finding(self, node: Node, ctx: AnalysisContext) -> RawFinding:
        return RawFinding(
            rule_id=self.meta().rule_id,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            column=node.start_point[1],
            code_snippet=self._snippet(ctx, node.start_point[0] + 1),
        )
