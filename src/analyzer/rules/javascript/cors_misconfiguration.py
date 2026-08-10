from tree_sitter import Node

from analyzer.core.severity import Confidence, Severity
from analyzer.rules.base import AnalysisContext, BaseRule, RawFinding, RuleMeta


def _is_cors_callable(func: Node) -> bool:
    if func.type == "identifier":
        return func.text.decode() == "cors" if func.text else False
    if func.type == "member_expression":
        prop = func.child_by_field_name("property")
        return prop is not None and prop.text is not None and prop.text.decode() == "cors"
    return False


def _cors_wildcard_credentials(call: Node) -> bool | None:
    """None: not a wildcard-origin cors() call; else True when credentials: true."""
    func = call.child_by_field_name("function")
    args = call.child_by_field_name("arguments")
    if func is None or args is None or not _is_cors_callable(func):
        return None
    named_args = [arg for arg in args.children if arg.is_named]
    if not named_args:
        return False
    for arg in named_args:
        if arg.type != "object":
            return None
        wildcard = True
        credentials = False
        for pair in arg.children:
            if pair.type != "pair":
                continue
            key = pair.child_by_field_name("key")
            value = pair.child_by_field_name("value")
            if key is None or value is None or not key.text:
                continue
            key_text = key.text.decode().strip("\"'`")
            if key_text == "origin":
                wildcard = value.type == "true" or (
                    value.type == "string"
                    and value.text is not None
                    and value.text.decode().strip("\"'`") == "*"
                )
            elif key_text == "credentials":
                credentials = value.type == "true"
        if wildcard:
            return credentials
    return None


def _character_column(line: str, byte_column: int) -> int:
    prefix = line.encode("utf-8")[:byte_column]
    return len(prefix.decode("utf-8"))


def _make_finding(rule_id: str, node: Node, ctx: AnalysisContext) -> RawFinding:
    idx = node.start_point[0]
    snippet = ctx.lines[idx] if 0 <= idx < len(ctx.lines) else ""
    return RawFinding(
        rule_id=rule_id,
        line_start=node.start_point[0] + 1,
        line_end=node.end_point[0] + 1,
        column=_character_column(snippet, node.start_point[1]),
        code_snippet=snippet,
    )


class CorsWildcardCredentialsRule(BaseRule):
    def meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id="JS-CORS-001",
            title="CORS wildcard origin combined with credentials",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe_id="CWE-942",
            owasp="A05:2021 Security Misconfiguration",
            description=(
                "cors() allows an arbitrary origin together with credentials. "
                "Reflected origins can expose authenticated responses cross-origin; "
                "a literal '*' is rejected by browsers and signals a broken policy."
            ),
            remediation=(
                "Use an explicit origin allowlist when credentials are enabled, "
                "e.g. cors({ origin: ['https://app.example.com'], credentials: true })."
            ),
        )

    def run(self, context: AnalysisContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        self._walk(context.root_node, context, findings)
        return findings

    def _walk(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        if node.type == "call_expression" and _cors_wildcard_credentials(node) is True:
            findings.append(_make_finding(self.meta().rule_id, node, ctx))
        for child in node.children:
            self._walk(child, ctx, findings)


class CorsWildcardOriginRule(BaseRule):
    def meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id="JS-CORS-002",
            title="CORS wildcard origin",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            cwe_id="CWE-942",
            owasp="A05:2021 Security Misconfiguration",
            description=(
                "cors() allows any origin ('*'). Without credentials this only "
                "exposes public data, but it disables same-origin protections "
                "for the endpoint."
            ),
            remediation=(
                "Restrict origins to an explicit allowlist, "
                "e.g. cors({ origin: ['https://app.example.com'] })."
            ),
        )

    def run(self, context: AnalysisContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        self._walk(context.root_node, context, findings)
        return findings

    def _walk(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        if node.type == "call_expression" and _cors_wildcard_credentials(node) is False:
            findings.append(_make_finding(self.meta().rule_id, node, ctx))
        for child in node.children:
            self._walk(child, ctx, findings)
