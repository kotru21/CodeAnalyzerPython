from tree_sitter import Node

from analyzer.rules.base import AnalysisContext, BaseRule, RawFinding, RuleMeta
from analyzer.core.severity import Confidence, Severity

_QUERY_METHODS = frozenset({"query", "raw", "execute", "$queryRaw", "$executeRaw"})


class SQLInjectionRule(BaseRule):
    def meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id="JS-SQL-001",
            title="SQL Injection via template literal or string concatenation",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            cwe_id="CWE-89",
            owasp="A03:2021 Injection",
            description=(
                "User-controllable input is interpolated directly into an SQL query "
                "string via template literal or string concatenation, enabling SQL injection."
            ),
            remediation=(
                "Use parameterized queries or prepared statements. "
                "Example: db.query('SELECT * FROM users WHERE id = $1', [id])"
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

    def _check_call(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func is None or args is None:
            return
        method_name = self._extract_method_name(func)
        if method_name not in _QUERY_METHODS:
            return
        for arg in args.children:
            if arg.type == "template_string" and self._has_substitution(arg):
                findings.append(self._make_finding(node, ctx))
                return
            if arg.type == "binary_expression" and self._is_string_concat(arg):
                findings.append(self._make_finding(node, ctx))
                return

    @staticmethod
    def _extract_method_name(func_node: Node) -> str:
        if func_node.type == "member_expression":
            prop = func_node.child_by_field_name("property")
            if prop is not None:
                return prop.text.decode() if prop.text else ""
        if func_node.type == "identifier":
            return func_node.text.decode() if func_node.text else ""
        return ""

    @staticmethod
    def _has_substitution(template_node: Node) -> bool:
        return any(c.type == "template_substitution" for c in template_node.children)

    @staticmethod
    def _is_string_concat(node: Node) -> bool:
        if node.type != "binary_expression":
            return False
        children_types = [c.type for c in node.children]
        if "+" not in children_types:
            return False
        return any(
            c.type in ("string", "template_string")
            or (c.type == "binary_expression" and SQLInjectionRule._is_string_concat(c))
            for c in node.children
        )

    def _make_finding(self, node: Node, ctx: AnalysisContext) -> RawFinding:
        return RawFinding(
            rule_id=self.meta().rule_id,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            column=node.start_point[1],
            code_snippet=self._snippet(ctx, node.start_point[0] + 1),
        )
