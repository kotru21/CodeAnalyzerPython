from tree_sitter import Node

from analyzer.core.severity import Confidence, Severity
from analyzer.rules.base import AnalysisContext, BaseRule, RawFinding, RuleMeta

_JWT_OBJECTS = frozenset({"jwt", "jsonwebtoken"})
_NONE_ALG_KEYS = frozenset({"algorithm", "alg"})


class JWTIssuesRule(BaseRule):
    def meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id="JS-JWT-001",
            title="JWT signed with algorithm 'none'",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe_id="CWE-347",
            owasp="A02:2021 Cryptographic Failures",
            description=(
                "jwt.sign() or jsonwebtoken.sign() is called with algorithm "
                "set to 'none', which disables signature verification."
            ),
            remediation=(
                "Use a strong signing algorithm such as HS256 or RS256. "
                "Never allow 'none' as the algorithm."
            ),
        )

    def run(self, context: AnalysisContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        self._walk(context.root_node, context, findings)
        return findings

    def _walk(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        if node.type == "call_expression":
            self._check_sign(node, ctx, findings)
        for child in node.children:
            self._walk(child, ctx, findings)

    def _check_sign(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func is None or args is None or not self._is_jwt_sign_call(func):
            return

        for arg in args.children:
            if not arg.is_named or arg.type != "object":
                continue
            if _object_has_none_algorithm(arg):
                findings.append(self._make_finding(node, ctx))
                return

    @staticmethod
    def _is_jwt_sign_call(func: Node) -> bool:
        if func.type != "member_expression":
            return False
        obj = func.child_by_field_name("object")
        prop = func.child_by_field_name("property")
        if obj is None or prop is None:
            return False
        obj_name = obj.text.decode() if obj.text else ""
        method = prop.text.decode() if prop.text else ""
        return method == "sign" and obj_name in _JWT_OBJECTS

    def _make_finding(self, node: Node, ctx: AnalysisContext) -> RawFinding:
        return RawFinding(
            rule_id=self.meta().rule_id,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            column=node.start_point[1],
            code_snippet=self._snippet(ctx, node.start_point[0] + 1),
        )


def _object_has_none_algorithm(obj_node: Node) -> bool:
    for child in obj_node.children:
        if child.type != "pair":
            continue
        key = child.child_by_field_name("key")
        value = child.child_by_field_name("value")
        if key is None or value is None:
            continue
        key_text = key.text.decode() if key.text else ""
        key_text = key_text.strip("\"'`")
        if key_text not in _NONE_ALG_KEYS:
            continue
        if value.type == "string":
            val_text = value.text.decode().strip("\"'`").lower() if value.text else ""
            if val_text == "none":
                return True
    return False
