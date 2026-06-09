from dataclasses import dataclass, field

from tree_sitter import Node

from analyzer.rules.base import AnalysisContext
from analyzer.taint.patterns import bind_pattern_from_source
from analyzer.taint.sanitizers import (
    is_parameterized_query,
    sanitizer_categories_cover_sink,
    sanitizer_categories_for_call,
)
from analyzer.taint.source_match import find_matching_source
from analyzer.taint.sources_sinks import (
    COMMAND_SINK_METHOD_NAMES,
    SINK_IDENTIFIERS,
    SINK_MEMBER_PATTERNS,
    SQL_SINK_METHOD_NAMES,
    is_weak_source,
)

MAX_INTERPROC_DEPTH = 5


def _normalize_optional_access(text: str) -> str:
    """Map `a?.b` to `a.b` so SOURCE/SINK substring checks match optional chaining."""
    return text.replace("?.", ".")


def _interproc_callee_name(func: Node) -> str | None:
    if func.type == "identifier":
        t = func.text.decode() if func.text else ""
        return t or None
    if func.type == "member_expression":
        prop = func.child_by_field_name("property")
        if prop is None:
            return None
        t = prop.text.decode() if prop.text else ""
        return t or None
    return None


# db.query('... $1 ...', values): taint only in values is binding, not SQLi text.
_SQL_PLACEHOLDER_MULTIARG_METHODS: frozenset[str] = frozenset({"query"})


def _string_literal_text(node: Node) -> str | None:
    """Raw source slice for a string literal (includes quotes); None if not a string node."""
    if node.type != "string":
        return None
    return node.text.decode() if node.text else None


@dataclass
class TaintFlow:
    source: str
    sink_method: str
    source_line: int
    sink_line: int
    variable_chain: list[str] = field(default_factory=list)


def _formal_param_identifiers(params_node: Node) -> list[str]:
    names: list[str] = []
    for child in params_node.children:
        if child.type == "identifier":
            t = child.text.decode() if child.text else ""
            if t:
                names.append(t)
        elif child.type in ("required_parameter", "optional_parameter"):
            pat = child.child_by_field_name("pattern")
            if pat is not None and pat.type == "identifier":
                t = pat.text.decode() if pat.text else ""
                if t:
                    names.append(t)
    return names


def _params_from_function_node(fn_node: Node) -> list[str]:
    params = fn_node.child_by_field_name("parameters")
    if params is None:
        return []
    if params.type == "identifier":
        t = params.text.decode() if params.text else ""
        return [t] if t else []
    if params.type == "formal_parameters":
        return _formal_param_identifiers(params)
    return []


def _index_functions(root: Node) -> dict[str, tuple[list[str], Node]]:
    index: dict[str, tuple[list[str], Node]] = {}

    def visit(node: Node) -> None:
        if node.type == "function_declaration":
            name = node.child_by_field_name("name")
            body = node.child_by_field_name("body")
            if name is not None and name.type == "identifier" and body is not None:
                nm = name.text.decode() if name.text else ""
                if nm:
                    index[nm] = (_params_from_function_node(node), body)
        elif node.type == "variable_declarator":
            vn = node.child_by_field_name("name")
            val = node.child_by_field_name("value")
            if (
                vn is not None
                and vn.type == "identifier"
                and val is not None
                and val.type in ("arrow_function", "function_expression")
            ):
                body = val.child_by_field_name("body")
                if body is not None:
                    nm = vn.text.decode() if vn.text else ""
                    if nm:
                        index[nm] = (_params_from_function_node(val), body)
        for c in node.children:
            visit(c)

    visit(root)
    return index


def merge_fn_index_from_roots(roots: list[Node]) -> dict[str, tuple[list[str], Node]]:
    merged: dict[str, tuple[list[str], Node]] = {}
    for root in roots:
        merged.update(_index_functions(root))
    return merged


def _positional_arguments(args_node: Node | None) -> list[Node]:
    if args_node is None:
        return []
    if args_node.type == "template_string":
        return [args_node]
    return [c for c in args_node.children if c.is_named]


class TaintTracker:
    """Taint tracker on tree-sitter AST: intra- and limited same-file inter-procedural."""

    def analyze(
        self,
        context: AnalysisContext,
        fn_index: dict[str, tuple[list[str], Node]] | None = None,
    ) -> list[TaintFlow]:
        tainted_vars: dict[str, str] = {}
        sanitized_vars: dict[str, frozenset[str]] = {}
        flows: list[TaintFlow] = []
        idx = fn_index if fn_index is not None else _index_functions(context.root_node)

        self._collect_taint_info(
            context.root_node,
            tainted_vars,
            sanitized_vars,
            flows,
            context,
            idx,
            0,
        )
        return flows

    def _collect_taint_info(
        self,
        node: Node,
        tainted: dict[str, str],
        sanitized: dict[str, frozenset[str]],
        flows: list[TaintFlow],
        ctx: AnalysisContext,
        fn_index: dict[str, tuple[list[str], Node]],
        depth: int,
    ) -> None:
        if node.type == "variable_declarator":
            self._handle_var_decl(
                node, tainted, sanitized, flows, ctx, fn_index, depth
            )
        elif node.type == "assignment_expression":
            self._handle_assignment(
                node, tainted, sanitized, flows, ctx, fn_index, depth
            )
        elif node.type == "call_expression":
            self._check_sink(node, tainted, sanitized, flows, ctx)
            self._maybe_analyze_callee_interproc(
                node, tainted, sanitized, flows, ctx, fn_index, depth
            )

        for child in node.children:
            self._collect_taint_info(
                child, tainted, sanitized, flows, ctx, fn_index, depth
            )

    def _maybe_analyze_callee_interproc(
        self,
        node: Node,
        tainted: dict[str, str],
        sanitized: dict[str, frozenset[str]],
        flows: list[TaintFlow],
        ctx: AnalysisContext,
        fn_index: dict[str, tuple[list[str], Node]],
        depth: int,
    ) -> None:
        if depth >= MAX_INTERPROC_DEPTH:
            return
        func = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")
        if func is None:
            return
        fname = _interproc_callee_name(func)
        if not fname or fname not in fn_index:
            return
        params, body = fn_index[fname]
        if not params:
            return
        arg_nodes = _positional_arguments(args_node)
        bindings: dict[str, str] = {}
        san_child = dict(sanitized)
        for i, pname in enumerate(params):
            if i >= len(arg_nodes):
                break
            arg = arg_nodes[i]
            sanitizer_cats = self._is_sanitizer_call(arg)
            if sanitizer_cats:
                san_child[pname] = sanitizer_cats
                inner = self._sanitizer_first_arg(arg)
                if inner is not None:
                    src = self._find_tainted_in_arg(inner, tainted, sanitized)
                    if src:
                        bindings[pname] = src
                continue
            src = self._find_tainted_in_arg(arg, tainted, sanitized)
            if src:
                bindings[pname] = src
        if not bindings:
            return
        merged = {**tainted, **bindings}
        self._collect_taint_info(
            body, merged, san_child, flows, ctx, fn_index, depth + 1
        )

    def _interproc_call_return_source(
        self,
        call_node: Node,
        tainted: dict[str, str],
        sanitized: dict[str, frozenset[str]],
        flows: list[TaintFlow],
        ctx: AnalysisContext,
        fn_index: dict[str, tuple[list[str], Node]],
        depth: int,
    ) -> str | None:
        if depth >= MAX_INTERPROC_DEPTH:
            return None
        func = call_node.child_by_field_name("function")
        args_node = call_node.child_by_field_name("arguments")
        if func is None:
            return None
        fname = _interproc_callee_name(func)
        if not fname or fname not in fn_index:
            return None
        params, body = fn_index[fname]
        arg_nodes = _positional_arguments(args_node)
        bindings: dict[str, str] = {}
        san_child = dict(sanitized)
        for i, pname in enumerate(params):
            if i >= len(arg_nodes):
                break
            arg = arg_nodes[i]
            sanitizer_cats = self._is_sanitizer_call(arg)
            if sanitizer_cats:
                san_child[pname] = sanitizer_cats
                inner = self._sanitizer_first_arg(arg)
                if inner is not None:
                    src = self._find_tainted_in_arg(inner, tainted, sanitized)
                    if src:
                        bindings[pname] = src
                continue
            src = self._find_tainted_in_arg(arg, tainted, sanitized)
            if src:
                bindings[pname] = src
        merged = {**tainted, **bindings}
        self._collect_taint_info(
            body, merged, san_child, flows, ctx, fn_index, depth + 1
        )
        return self._return_expression_taint(body, merged, san_child)

    @staticmethod
    def _return_expression_taint(
        body: Node, tainted: dict[str, str], sanitized: dict[str, frozenset[str]]
    ) -> str | None:
        def visit(n: Node) -> str | None:
            if n.type == "return_statement":
                for ch in n.children:
                    if not ch.is_named:
                        continue
                    r = TaintTracker._extract_source_static(ch, tainted)
                    if r:
                        return r
                    r2 = TaintTracker._find_tainted_in_arg_static(ch, tainted, sanitized)
                    if r2:
                        return r2
            for c in n.children:
                got = visit(c)
                if got:
                    return got
            return None

        return visit(body)

    @staticmethod
    def _extract_source_static(node: Node, tainted: dict[str, str]) -> str | None:
        tr = TaintTracker()
        return tr._extract_source(node, tainted)

    @staticmethod
    def _find_tainted_in_arg_static(
        node: Node,
        tainted: dict[str, str],
        sanitized: dict[str, frozenset[str]],
        sink_method: str | None = None,
    ) -> str | None:
        tr = TaintTracker()
        return tr._find_tainted_in_arg(node, tainted, sanitized, sink_method)

    def _handle_var_decl(
        self,
        node: Node,
        tainted: dict[str, str],
        sanitized: dict[str, frozenset[str]],
        flows: list[TaintFlow],
        ctx: AnalysisContext,
        fn_index: dict[str, tuple[list[str], Node]],
        depth: int,
    ) -> None:
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node is None or value_node is None:
            return
        var_name = name_node.text.decode() if name_node.text else ""
        if not var_name:
            return

        sanitizer_cats = self._is_sanitizer_call(value_node)
        if sanitizer_cats:
            sanitized[var_name] = sanitizer_cats
            inner = self._sanitizer_first_arg(value_node)
            if inner is not None:
                src = self._find_tainted_in_arg(inner, tainted, sanitized)
                if src:
                    tainted[var_name] = src
            return

        if value_node.type == "call_expression":
            ret = self._interproc_call_return_source(
                value_node, tainted, sanitized, flows, ctx, fn_index, depth
            )
            if ret:
                tainted[var_name] = ret
                return

        source = self._extract_source(value_node, tainted)
        if source:
            if name_node.type == "identifier":
                tainted[var_name] = source
            else:
                bind_pattern_from_source(name_node, source, tainted)
            return

    def _handle_assignment(
        self,
        node: Node,
        tainted: dict[str, str],
        sanitized: dict[str, frozenset[str]],
        flows: list[TaintFlow],
        ctx: AnalysisContext,
        fn_index: dict[str, tuple[list[str], Node]],
        depth: int,
    ) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        var_name = left.text.decode() if left.text else ""
        if not var_name:
            return

        sanitizer_cats = self._is_sanitizer_call(right)
        if sanitizer_cats:
            sanitized[var_name] = sanitizer_cats
            inner = self._sanitizer_first_arg(right)
            if inner is not None:
                src = self._find_tainted_in_arg(inner, tainted, sanitized)
                if src:
                    tainted[var_name] = src
            return

        if right.type == "call_expression":
            ret = self._interproc_call_return_source(
                right, tainted, sanitized, flows, ctx, fn_index, depth
            )
            if ret:
                tainted[var_name] = ret
                return

        source = self._extract_source(right, tainted)
        if source:
            tainted[var_name] = source

    def _extract_source(self, node: Node, tainted: dict[str, str]) -> str | None:
        if node.type in ("identifier", "member_expression"):
            match = find_matching_source(node)
            if match:
                return match

        text = node.text.decode() if node.text else ""

        if node.type == "identifier" and text in tainted:
            return tainted[text]

        if node.type == "template_substitution":
            for child in node.children:
                if not child.is_named:
                    continue
                result = self._extract_source(child, tainted)
                if result:
                    return result
            return None

        if node.type in ("binary_expression", "template_string"):
            for child in node.children:
                result = self._extract_source(child, tainted)
                if result:
                    return result

        if node.type == "object":
            for child in node.children:
                if child.type == "spread_element":
                    for c in child.children:
                        if c.is_named:
                            result = self._extract_source(c, tainted)
                            if result:
                                return result

        return None

    @staticmethod
    def _should_report_flow(taint_source: str, sink_method: str) -> bool:
        if is_weak_source(taint_source) and sink_method not in COMMAND_SINK_METHOD_NAMES:
            return False
        return True

    def _check_sink(
        self,
        node: Node,
        tainted: dict[str, str],
        sanitized: dict[str, frozenset[str]],
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

        pos_args = _positional_arguments(args)
        if (
            len(pos_args) >= 2
            and method in _SQL_PLACEHOLDER_MULTIARG_METHODS
        ):
            first = pos_args[0]
            lit = _string_literal_text(first)
            if lit is not None and is_parameterized_query(lit):
                taint_in_first = self._find_tainted_in_arg(
                    first, tainted, sanitized, method
                )
                if taint_in_first and self._should_report_flow(
                    taint_in_first, method
                ):
                    line = node.start_point[0] + 1
                    flows.append(
                        TaintFlow(
                            source=taint_in_first,
                            sink_method=method,
                            source_line=line,
                            sink_line=line,
                        )
                    )
                return

        for arg in pos_args:
            taint_source = self._find_tainted_in_arg(arg, tainted, sanitized, method)
            if taint_source and self._should_report_flow(taint_source, method):
                line = node.start_point[0] + 1
                flows.append(
                    TaintFlow(
                        source=taint_source,
                        sink_method=method,
                        source_line=line,
                        sink_line=line,
                    )
                )
                return

    def _find_tainted_in_arg(
        self,
        node: Node,
        tainted: dict[str, str],
        sanitized: dict[str, frozenset[str]],
        sink_method: str | None = None,
    ) -> str | None:
        text = node.text.decode() if node.text else ""

        if node.type == "identifier":
            if text in sanitized and sink_method is not None:
                if sanitizer_categories_cover_sink(sanitized[text], sink_method):
                    return None
            if text in tainted:
                return tainted[text]

        if node.type in ("identifier", "member_expression"):
            match = find_matching_source(node)
            if match:
                return match

        for child in node.children:
            result = self._find_tainted_in_arg(
                child, tainted, sanitized, sink_method
            )
            if result:
                return result

        return None

    @staticmethod
    def _sanitizer_first_arg(call_node: Node) -> Node | None:
        args = call_node.child_by_field_name("arguments")
        if args is None:
            return None
        pos = _positional_arguments(args)
        return pos[0] if pos else None

    @staticmethod
    def _is_known_sink(func_node: Node, method: str) -> bool:
        if func_node.type == "identifier":
            return method in SINK_IDENTIFIERS
        if func_node.type == "member_expression":
            full_text = func_node.text.decode() if func_node.text else ""
            norm = _normalize_optional_access(full_text)
            if full_text in SINK_MEMBER_PATTERNS or norm in SINK_MEMBER_PATTERNS:
                return True
            return method in SQL_SINK_METHOD_NAMES
        return False

    @staticmethod
    def _is_sanitizer_call(node: Node) -> frozenset[str] | None:
        if node.type != "call_expression":
            return None
        func = node.child_by_field_name("function")
        if func is None:
            return None
        func_text = func.text.decode() if func.text else ""
        cats = sanitizer_categories_for_call(func_text)
        return cats if cats else None

    @staticmethod
    def _get_sink_method(func_node: Node) -> str:
        if func_node.type == "identifier":
            return func_node.text.decode() if func_node.text else ""
        if func_node.type == "member_expression":
            prop = func_node.child_by_field_name("property")
            return (prop.text.decode() if prop.text else "") if prop else ""
        return ""
