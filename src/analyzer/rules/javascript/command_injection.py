from tree_sitter import Node

from analyzer.rules.base import AnalysisContext, BaseRule, RawFinding, RuleMeta
from analyzer.core.severity import Confidence, Severity

_EXEC_FUNCTIONS = frozenset({
    "exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync",
})


class CommandInjectionRule(BaseRule):
    def meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id="JS-CMD-001",
            title="Command Injection via exec/eval",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            cwe_id="CWE-78",
            owasp="A03:2021 Injection",
            description=(
                "User-controllable input is passed to exec, execSync, or eval, "
                "allowing arbitrary command or code execution."
            ),
            remediation=(
                "Avoid exec/eval with user input. Use execFile with an argument array, "
                "or use a safe parser instead of eval."
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

        func_name = self._extract_func_name(func)

        if func_name == "eval":
            self._check_eval(node, args, ctx, findings)
        elif func_name in _EXEC_FUNCTIONS:
            self._check_exec(node, args, ctx, findings)

    def _check_eval(
        self, node: Node, args: Node, ctx: AnalysisContext, findings: list[RawFinding]
    ) -> None:
        real_args = [c for c in args.children if c.type not in ("(", ")", ",")]
        if not real_args:
            return
        first_arg = real_args[0]
        if first_arg.type == "string":
            return
        findings.append(self._make_finding(node, ctx))

    def _check_exec(
        self, node: Node, args: Node, ctx: AnalysisContext, findings: list[RawFinding]
    ) -> None:
        real_args = [c for c in args.children if c.type not in ("(", ")", ",")]
        if not real_args:
            return
        first_arg = real_args[0]
        if first_arg.type == "template_string" and self._has_substitution(first_arg):
            findings.append(self._make_finding(node, ctx))
        elif first_arg.type in ("identifier", "member_expression", "binary_expression"):
            findings.append(self._make_finding(node, ctx))

    @staticmethod
    def _extract_func_name(func_node: Node) -> str:
        if func_node.type == "identifier":
            return func_node.text.decode() if func_node.text else ""
        if func_node.type == "member_expression":
            prop = func_node.child_by_field_name("property")
            if prop is not None:
                return prop.text.decode() if prop.text else ""
        return ""

    @staticmethod
    def _has_substitution(template_node: Node) -> bool:
        return any(c.type == "template_substitution" for c in template_node.children)

    def _make_finding(self, node: Node, ctx: AnalysisContext) -> RawFinding:
        return RawFinding(
            rule_id=self.meta().rule_id,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            column=node.start_point[1],
            code_snippet=self._snippet(ctx, node.start_point[0] + 1),
        )
