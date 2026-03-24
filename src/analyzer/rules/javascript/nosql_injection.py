from tree_sitter import Node

from analyzer.core.severity import Confidence, Severity
from analyzer.rules.base import AnalysisContext, BaseRule, RawFinding, RuleMeta

_MONGO_METHODS = frozenset({
    "find", "findOne", "findOneAndUpdate", "findOneAndDelete",
    "updateOne", "updateMany", "deleteOne", "deleteMany",
    "aggregate", "count", "countDocuments",
})
_DANGEROUS_OPERATORS = frozenset({"$where", "$regex", "$expr"})


class NoSQLInjectionRule(BaseRule):
    def meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id="JS-NOSQL-001",
            title="NoSQL Injection via unvalidated query object",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe_id="CWE-943",
            owasp="A03:2021 Injection",
            description=(
                "User input is passed directly as a MongoDB query object or "
                "contains dangerous operators ($where, $regex) from user input."
            ),
            remediation=(
                "Extract specific fields from user input instead of passing "
                "req.body directly. Sanitize or validate that values don't "
                "contain MongoDB operators."
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
        args = node.child_by_field_name("arguments")
        if func is None or args is None:
            return
        method = self._get_method_name(func)
        if method not in _MONGO_METHODS:
            return

        first_arg = next((c for c in args.children if c.is_named), None)
        if first_arg is None:
            return

        if first_arg.type == "member_expression":
            text = first_arg.text.decode() if first_arg.text else ""
            if any(s in text for s in ("req.body", "req.query", "request.body")):
                findings.append(self._make_finding(node, ctx))
                return

        if first_arg.type == "object":
            for child in first_arg.children:
                if child.type == "pair":
                    key = child.child_by_field_name("key")
                    if key:
                        key_text = key.text.decode() if key.text else ""
                        key_text = key_text.strip("\"'`")
                        if key_text in _DANGEROUS_OPERATORS:
                            findings.append(self._make_finding(node, ctx))
                            return

    @staticmethod
    def _get_method_name(func_node: Node) -> str:
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
