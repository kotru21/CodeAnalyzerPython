from tree_sitter import Node

from analyzer.rules.base import AnalysisContext, BaseRule, RawFinding, RuleMeta
from analyzer.core.severity import Confidence, Severity

_DANGEROUS_PROPS = frozenset({"innerHTML", "outerHTML"})
_WRITE_METHODS = frozenset({"write", "writeln"})


class ReflectedXSSRule(BaseRule):
    def meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id="JS-XSS-001",
            title="Reflected XSS via innerHTML or document.write",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            cwe_id="CWE-79",
            owasp="A03:2021 Injection",
            description=(
                "User input is assigned to innerHTML/outerHTML or passed to "
                "document.write/writeln, enabling cross-site scripting."
            ),
            remediation=(
                "Use textContent instead of innerHTML, or sanitize input with "
                "a library such as DOMPurify before insertion."
            ),
        )

    def run(self, context: AnalysisContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        self._walk(context.root_node, context, findings)
        return findings

    def _walk(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        if node.type == "assignment_expression":
            self._check_assignment(node, ctx, findings)
        elif node.type == "call_expression":
            self._check_document_write(node, ctx, findings)
        for child in node.children:
            self._walk(child, ctx, findings)

    def _check_assignment(
        self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]
    ) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        if left.type != "member_expression":
            return
        prop = left.child_by_field_name("property")
        if prop is None:
            return
        prop_name = prop.text.decode() if prop.text else ""
        if prop_name not in _DANGEROUS_PROPS:
            return
        if right.type == "string":
            return
        findings.append(self._make_finding(node, ctx))

    def _check_document_write(
        self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]
    ) -> None:
        func = node.child_by_field_name("function")
        if func is None or func.type != "member_expression":
            return
        obj = func.child_by_field_name("object")
        prop = func.child_by_field_name("property")
        if obj is None or prop is None:
            return
        obj_name = obj.text.decode() if obj.text else ""
        prop_name = prop.text.decode() if prop.text else ""
        if obj_name == "document" and prop_name in _WRITE_METHODS:
            findings.append(self._make_finding(node, ctx))

    def _make_finding(self, node: Node, ctx: AnalysisContext) -> RawFinding:
        return RawFinding(
            rule_id=self.meta().rule_id,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            column=node.start_point[1],
            code_snippet=self._snippet(ctx, node.start_point[0] + 1),
        )


class DangerouslySetInnerHTMLRule(BaseRule):
    def meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id="JS-XSS-002",
            title="XSS via dangerouslySetInnerHTML",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe_id="CWE-79",
            owasp="A03:2021 Injection",
            description=(
                "dangerouslySetInnerHTML injects raw HTML into the DOM, bypassing "
                "React's built-in XSS protection."
            ),
            remediation=(
                "Avoid dangerouslySetInnerHTML. If HTML rendering is required, "
                "sanitize input with DOMPurify before passing it."
            ),
        )

    def run(self, context: AnalysisContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        self._walk(context.root_node, context, findings)
        return findings

    def _walk(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        if node.type == "jsx_attribute":
            self._check_jsx_attr(node, ctx, findings)
        for child in node.children:
            self._walk(child, ctx, findings)

    def _check_jsx_attr(
        self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]
    ) -> None:
        for child in node.children:
            if child.type == "property_identifier":
                name = child.text.decode() if child.text else ""
                if name == "dangerouslySetInnerHTML":
                    findings.append(
                        RawFinding(
                            rule_id=self.meta().rule_id,
                            line_start=node.start_point[0] + 1,
                            line_end=node.end_point[0] + 1,
                            column=node.start_point[1],
                            code_snippet=self._snippet(ctx, node.start_point[0] + 1),
                        )
                    )
                    return
