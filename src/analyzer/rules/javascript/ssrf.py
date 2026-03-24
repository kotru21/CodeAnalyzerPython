from tree_sitter import Node

from analyzer.core.severity import Confidence, Severity
from analyzer.rules.base import AnalysisContext, BaseRule, RawFinding, RuleMeta

_HTTP_FUNCTIONS = frozenset({"fetch", "got", "request"})
_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "request"})
_HTTP_OBJECTS = frozenset({"axios", "http", "https", "got", "request", "superagent"})


class SSRFRule(BaseRule):
    def meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id="JS-SSRF-001",
            title="Server-Side Request Forgery via user-controlled URL",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe_id="CWE-918",
            owasp="A10:2021 Server-Side Request Forgery",
            description=(
                "An HTTP request is made with a URL derived from user input "
                "without validation, enabling SSRF attacks against internal services."
            ),
            remediation=(
                "Validate URLs against an allowlist of permitted hosts/schemes. "
                "Block requests to private IP ranges (127.0.0.0/8, 10.0.0.0/8, etc.)."
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

        is_http_call = False

        if func.type == "identifier":
            name = func.text.decode() if func.text else ""
            is_http_call = name in _HTTP_FUNCTIONS

        elif func.type == "member_expression":
            obj = func.child_by_field_name("object")
            prop = func.child_by_field_name("property")
            if obj and prop:
                obj_name = obj.text.decode() if obj.text else ""
                method = prop.text.decode() if prop.text else ""
                is_http_call = obj_name in _HTTP_OBJECTS and method in _HTTP_METHODS

        if not is_http_call:
            return

        first_arg = next((c for c in args.children if c.is_named), None)
        if first_arg is None:
            return
        if first_arg.type == "string":
            return
        if first_arg.type == "template_string" and not any(
            c.type == "template_substitution" for c in first_arg.children
        ):
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
