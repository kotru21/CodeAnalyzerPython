from tree_sitter import Node

from analyzer.core.severity import Confidence, Severity
from analyzer.rules.base import AnalysisContext, BaseRule, RawFinding, RuleMeta


class InsecureCookiesRule(BaseRule):
    def meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id="JS-COOKIE-001",
            title="Cookie set without httpOnly flag",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            cwe_id="CWE-1004",
            owasp="A05:2021 Security Misconfiguration",
            description=(
                "res.cookie() is called with httpOnly explicitly set to false, "
                "allowing client-side scripts to access the cookie."
            ),
            remediation=(
                "Set httpOnly: true (the default in many frameworks) to prevent "
                "JavaScript access to sensitive cookies."
            ),
        )

    def run(self, context: AnalysisContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        self._walk(context.root_node, context, findings)
        return findings

    def _walk(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        if node.type == "call_expression":
            self._check_cookie(node, ctx, findings)
        for child in node.children:
            self._walk(child, ctx, findings)

    def _check_cookie(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func is None or args is None or not self._is_res_cookie_call(func):
            return

        for arg in args.children:
            if not arg.is_named or arg.type != "object":
                continue
            if _object_has_httponly_false(arg):
                findings.append(self._make_finding(node, ctx))
                return

    @staticmethod
    def _is_res_cookie_call(func: Node) -> bool:
        if func.type != "member_expression":
            return False
        obj = func.child_by_field_name("object")
        prop = func.child_by_field_name("property")
        if obj is None or prop is None:
            return False
        obj_name = obj.text.decode() if obj.text else ""
        method = prop.text.decode() if prop.text else ""
        return method == "cookie" and obj_name == "res"

    def _make_finding(self, node: Node, ctx: AnalysisContext) -> RawFinding:
        return RawFinding(
            rule_id=self.meta().rule_id,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            column=node.start_point[1],
            code_snippet=self._snippet(ctx, node.start_point[0] + 1),
        )


def _object_has_httponly_false(obj_node: Node) -> bool:
    for child in obj_node.children:
        if child.type != "pair":
            continue
        key = child.child_by_field_name("key")
        value = child.child_by_field_name("value")
        if key is None or value is None:
            continue
        key_text = key.text.decode() if key.text else ""
        key_text = key_text.strip("\"'`")
        if key_text != "httpOnly":
            continue
        if value.type == "false":
            return True
    return False
