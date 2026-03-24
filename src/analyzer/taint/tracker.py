from dataclasses import dataclass, field
from tree_sitter import Node

from analyzer.rules.base import AnalysisContext
from analyzer.taint.sanitizers import SANITIZER_NAMES
from analyzer.taint.sources_sinks import (
    SOURCE_PATTERNS,
    SINK_IDENTIFIERS,
    SINK_MEMBER_PATTERNS,
    SINK_METHODS,
)


@dataclass
class TaintFlow:
    source: str
    sink_method: str
    source_line: int
    sink_line: int
    variable_chain: list[str] = field(default_factory=list)


class TaintTracker:
    """Intra-procedural taint tracker operating on tree-sitter AST."""

    def analyze(self, context: AnalysisContext) -> list[TaintFlow]:
        tainted_vars: dict[str, str] = {}
        sanitized_vars: set[str] = set()
        flows: list[TaintFlow] = []

        self._collect_taint_info(
            context.root_node, tainted_vars, sanitized_vars, flows, context
        )
        return flows

    def _collect_taint_info(
        self,
        node: Node,
        tainted: dict[str, str],
        sanitized: set[str],
        flows: list[TaintFlow],
        ctx: AnalysisContext,
    ) -> None:
        if node.type == "variable_declarator":
            self._handle_var_decl(node, tainted, sanitized)
        elif node.type == "assignment_expression":
            self._handle_assignment(node, tainted, sanitized)
        elif node.type == "call_expression":
            self._check_sink(node, tainted, sanitized, flows, ctx)

        for child in node.children:
            self._collect_taint_info(child, tainted, sanitized, flows, ctx)

    def _handle_var_decl(
        self, node: Node, tainted: dict[str, str], sanitized: set[str]
    ) -> None:
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node is None or value_node is None:
            return
        var_name = name_node.text.decode() if name_node.text else ""
        if not var_name:
            return

        if self._is_sanitizer_call(value_node):
            sanitized.add(var_name)
            return

        source = self._extract_source(value_node, tainted)
        if source:
            tainted[var_name] = source

    def _handle_assignment(
        self, node: Node, tainted: dict[str, str], sanitized: set[str]
    ) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        var_name = left.text.decode() if left.text else ""
        if not var_name:
            return

        if self._is_sanitizer_call(right):
            sanitized.add(var_name)
            return

        source = self._extract_source(right, tainted)
        if source:
            tainted[var_name] = source

    def _extract_source(self, node: Node, tainted: dict[str, str]) -> str | None:
        text = node.text.decode() if node.text else ""

        for pattern in SOURCE_PATTERNS:
            if pattern in text:
                return pattern

        if node.type == "identifier" and text in tainted:
            return tainted[text]

        if node.type in ("binary_expression", "template_string"):
            for child in node.children:
                result = self._extract_source(child, tainted)
                if result:
                    return result

        if node.type == "member_expression":
            obj_text = text
            for pattern in SOURCE_PATTERNS:
                if obj_text.startswith(pattern):
                    return pattern

        return None

    def _check_sink(
        self,
        node: Node,
        tainted: dict[str, str],
        sanitized: set[str],
        flows: list[TaintFlow],
        ctx: AnalysisContext,
    ) -> None:
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func is None or args is None:
            return

        method = self._get_sink_method(func)
        if not self._is_known_sink(func, method):
            return

        for arg in args.children:
            if not arg.is_named:
                continue
            taint_source = self._find_tainted_in_arg(arg, tainted, sanitized)
            if taint_source:
                flows.append(
                    TaintFlow(
                        source=taint_source,
                        sink_method=method,
                        source_line=node.start_point[0] + 1,
                        sink_line=node.start_point[0] + 1,
                    )
                )
                return

    def _find_tainted_in_arg(
        self, node: Node, tainted: dict[str, str], sanitized: set[str]
    ) -> str | None:
        text = node.text.decode() if node.text else ""

        if node.type == "identifier":
            if text in sanitized:
                return None
            if text in tainted:
                return tainted[text]

        for pattern in SOURCE_PATTERNS:
            if pattern in text:
                return pattern

        for child in node.children:
            result = self._find_tainted_in_arg(child, tainted, sanitized)
            if result:
                return result

        return None

    @staticmethod
    def _is_known_sink(func_node: Node, method: str) -> bool:
        if func_node.type == "identifier":
            return method in SINK_IDENTIFIERS
        if func_node.type == "member_expression":
            full_text = func_node.text.decode() if func_node.text else ""
            return full_text in SINK_MEMBER_PATTERNS
        return False

    @staticmethod
    def _is_sanitizer_call(node: Node) -> bool:
        if node.type != "call_expression":
            return False
        func = node.child_by_field_name("function")
        if func is None:
            return False
        func_text = func.text.decode() if func.text else ""
        func_name = func_text.split(".")[-1] if "." in func_text else func_text
        return func_name in SANITIZER_NAMES

    @staticmethod
    def _get_sink_method(func_node: Node) -> str:
        if func_node.type == "identifier":
            return func_node.text.decode() if func_node.text else ""
        if func_node.type == "member_expression":
            prop = func_node.child_by_field_name("property")
            return (prop.text.decode() if prop.text else "") if prop else ""
        return ""
