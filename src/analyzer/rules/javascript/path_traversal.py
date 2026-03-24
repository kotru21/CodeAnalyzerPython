from tree_sitter import Node

from analyzer.core.severity import Confidence, Severity
from analyzer.rules.base import AnalysisContext, BaseRule, RawFinding, RuleMeta

_FS_METHODS = frozenset({
    "readFile", "readFileSync", "writeFile", "writeFileSync",
    "access", "accessSync", "createReadStream", "createWriteStream",
    "unlink", "unlinkSync", "rmdir", "rmdirSync",
})


class PathTraversalRule(BaseRule):
    def meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id="JS-PATH-001",
            title="Path Traversal via user-controlled file path",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe_id="CWE-22",
            owasp="A01:2021 Broken Access Control",
            description=(
                "A file system operation uses a path derived from user input "
                "without proper validation, enabling directory traversal attacks."
            ),
            remediation=(
                "Use path.resolve() and verify the result starts with the intended "
                "base directory. Example: path.resolve(baseDir, userInput).startsWith(baseDir)"
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
        method_name = self._get_method_name(func)
        if method_name not in _FS_METHODS:
            return
        first_arg = next((c for c in args.children if c.is_named), None)
        if first_arg is None:
            return
        if first_arg.type == "string":
            return
        if first_arg.type == "template_string":
            if not any(c.type == "template_substitution" for c in first_arg.children):
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

    @staticmethod
    def _get_method_name(func_node: Node) -> str:
        if func_node.type == "member_expression":
            prop = func_node.child_by_field_name("property")
            return (prop.text.decode() if prop.text else "") if prop else ""
        return ""
