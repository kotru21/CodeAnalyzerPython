from tree_sitter import Node

from analyzer.core.severity import Confidence, Severity
from analyzer.rules.base import AnalysisContext, BaseRule, RawFinding, RuleMeta

_UNSAFE_QUERY_SUBSTR = (
    "req.body",
    "req.query",
    "req.params",
    "request.body",
    "request.query",
    "request.params",
    "ctx.request.body",
    "ctx.query",
)


def _norm(n: Node) -> str:
    t = n.text.decode() if n.text else ""
    return t.replace("?.", ".")


def _value_marks_unsafe_spread_or_request(val: Node) -> bool:
    s = _norm(val)
    if any(u in s for u in _UNSAFE_QUERY_SUBSTR):
        return True
    if val.type == "object":
        for ch in val.children:
            if ch.type != "spread_element":
                continue
            for c in ch.children:
                if c.is_named and any(u in _norm(c) for u in _UNSAFE_QUERY_SUBSTR):
                    return True
    return False


def _binding_before_call_is_unsafe(root: Node, call_node: Node, ident: str) -> bool:
    call_b = call_node.start_byte
    best: tuple[int, Node] | None = None

    def visit(n: Node) -> None:
        nonlocal best
        if n.type == "variable_declarator":
            vn = n.child_by_field_name("name")
            vv = n.child_by_field_name("value")
            if (
                vn is not None
                and vn.type == "identifier"
                and vv is not None
                and n.start_byte < call_b
            ):
                nm = vn.text.decode() if vn.text else ""
                if nm == ident:
                    if best is None or n.start_byte > best[0]:
                        best = (n.start_byte, vv)
        for c in n.children:
            visit(c)

    visit(root)
    if best is None:
        return False
    return _value_marks_unsafe_spread_or_request(best[1])


_MONGO_METHODS = frozenset(
    {
        "find",
        "findOne",
        "findOneAndUpdate",
        "findOneAndDelete",
        "updateOne",
        "updateMany",
        "deleteOne",
        "deleteMany",
        "aggregate",
        "count",
        "countDocuments",
    }
)
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

    def _check_call(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
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

        if first_arg.type == "identifier":
            iname = first_arg.text.decode() if first_arg.text else ""
            if iname and _binding_before_call_is_unsafe(ctx.root_node, node, iname):
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
