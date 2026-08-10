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

# High-precision credential formats; flagged regardless of the variable name.
_SECRET_VALUE_PATTERN = re.compile(
    r"AKIA[0-9A-Z]{16}"  # AWS Access Key ID
    r"|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"  # PEM private key
    r"|\bgh[po]_[A-Za-z0-9]{20,}"  # GitHub PAT / OAuth token
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}"  # Slack token
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
                "hardcoded string literal, or a string literal matches a known "
                "credential format (AWS key id, PEM private key, GitHub/Slack "
                "token), exposing credentials in source code."
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
            self._check_variable(node, findings)
        elif node.type == "pair":
            self._check_object_property(node, findings)
        elif node.type == "assignment_expression":
            self._check_assignment(node, findings)
        for child in node.children:
            self._walk(child, ctx, findings)

    def _check_variable(self, node: Node, findings: list[RawFinding]) -> None:
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node is None or value_node is None:
            return
        var_name = name_node.text.decode() if name_node.text else ""
        name_suspicious = _SECRET_PATTERN.search(var_name) is not None
        if self._is_flagged_value(value_node, name_suspicious):
            findings.append(self._make_finding(node))

    def _check_object_property(self, node: Node, findings: list[RawFinding]) -> None:
        key_node = node.child_by_field_name("key")
        value_node = node.child_by_field_name("value")
        if key_node is None or value_node is None:
            return
        key_text = key_node.text.decode() if key_node.text else ""
        name_suspicious = _PROP_SECRET_PATTERN.search(key_text) is not None
        if self._is_flagged_value(value_node, name_suspicious):
            findings.append(self._make_finding(node))

    def _check_assignment(self, node: Node, findings: list[RawFinding]) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        left_text = left.text.decode() if left.text else ""
        name_suspicious = _SECRET_PATTERN.search(left_text) is not None
        if self._is_flagged_value(right, name_suspicious):
            findings.append(self._make_finding(node))

    def _is_flagged_value(self, value_node: Node, name_suspicious: bool) -> bool:
        if value_node.type != "string":
            return False
        if self._has_secret_value(value_node):
            return True
        return name_suspicious and self._is_real_secret(value_node)

    @staticmethod
    def _has_secret_value(string_node: Node) -> bool:
        raw = string_node.text.decode() if string_node.text else ""
        return _SECRET_VALUE_PATTERN.search(raw.strip("\"'`")) is not None

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

    def _make_finding(self, node: Node) -> RawFinding:
        return RawFinding(
            rule_id=self.meta().rule_id,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            column=node.start_point[1],
            code_snippet=self._redacted_snippet(node),
        )

    @staticmethod
    def _redacted_snippet(node: Node) -> str:
        for field_name in ("name", "key", "left"):
            target = node.child_by_field_name(field_name)
            if target is not None and target.text:
                return f"{target.text.decode()} = [REDACTED]"
        return "[REDACTED]"
