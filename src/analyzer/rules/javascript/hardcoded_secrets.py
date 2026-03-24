import re

from tree_sitter import Node

from analyzer.core.severity import Confidence, Severity
from analyzer.rules.base import AnalysisContext, BaseRule, RawFinding, RuleMeta

_SECRET_PATTERN = re.compile(
    r"(password|passwd|secret|api_?key|apikey|token|auth|credential|private_?key)",
    re.IGNORECASE,
)

_PROP_SECRET_PATTERN = re.compile(
    r"^(password|passwd|secret|api_?key|apikey|token|auth_?token|private_?key)$",
    re.IGNORECASE,
)


class HardcodedSecretsRule(BaseRule):
    def meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id="JS-SEC-001",
            title="Hardcoded secret or credential",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            cwe_id="CWE-798",
            owasp="A07:2021 Identification and Authentication Failures",
            description=(
                "A variable or property with a secret-like name is assigned a "
                "hardcoded string literal, exposing credentials in source code."
            ),
            remediation=(
                "Store secrets in environment variables or a secrets manager. "
                "Example: const password = process.env.DB_PASSWORD"
            ),
        )

    def run(self, context: AnalysisContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        self._walk(context.root_node, context, findings)
        return findings

    def _walk(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        if node.type == "variable_declarator":
            self._check_variable(node, ctx, findings)
        elif node.type == "pair":
            self._check_object_property(node, ctx, findings)
        elif node.type == "assignment_expression":
            self._check_assignment(node, ctx, findings)
        for child in node.children:
            self._walk(child, ctx, findings)

    def _check_variable(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node is None or value_node is None:
            return
        var_name = name_node.text.decode() if name_node.text else ""
        if not _SECRET_PATTERN.search(var_name):
            return
        if value_node.type == "string" and self._is_real_secret(value_node):
            findings.append(self._make_finding(node, ctx))

    def _check_object_property(
        self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]
    ) -> None:
        key_node = node.child_by_field_name("key")
        value_node = node.child_by_field_name("value")
        if key_node is None or value_node is None:
            return
        key_text = key_node.text.decode() if key_node.text else ""
        if not _PROP_SECRET_PATTERN.search(key_text):
            return
        if value_node.type == "string" and self._is_real_secret(value_node):
            findings.append(self._make_finding(node, ctx))

    def _check_assignment(
        self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]
    ) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        left_text = left.text.decode() if left.text else ""
        if not _SECRET_PATTERN.search(left_text):
            return
        if right.type == "string" and self._is_real_secret(right):
            findings.append(self._make_finding(node, ctx))

    @staticmethod
    def _is_real_secret(string_node: Node) -> bool:
        raw = string_node.text.decode() if string_node.text else ""
        value = raw.strip("\"'`")
        return len(value) > 3 and value.lower() not in (
            "",
            "null",
            "none",
            "undefined",
            "todo",
            "changeme",
            "xxx",
        )

    def _make_finding(self, node: Node, ctx: AnalysisContext) -> RawFinding:
        return RawFinding(
            rule_id=self.meta().rule_id,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            column=node.start_point[1],
            code_snippet=self._snippet(ctx, node.start_point[0] + 1),
        )
