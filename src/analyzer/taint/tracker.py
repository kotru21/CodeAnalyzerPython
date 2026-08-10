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
    HTTP_METHOD_SINKS,
    HTTP_RECEIVER_ALLOWLIST,
    NOSQL_RECEIVER_ALLOWLIST,
    NOSQL_SINK_METHODS,
    SINK_IDENTIFIERS,
    SINK_MEMBER_PATTERNS,
    SQL_RECEIVER_ALLOWLIST,
    SQL_SINK_METHOD_NAMES,
    is_weak_source,
)

_FUNCTION_NODE_TYPES = frozenset({"function_declaration", "arrow_function", "function_expression"})

MAX_INTERPROC_DEPTH = 5

# Only these wrappers propagate taint from args when interproc does not resolve.
_TRANSPARENT_WRAPPERS: frozenset[str] = frozenset(
    {
        "String",
        "Boolean",
        "encodeURIComponent",
        "encodeURI",
        "decodeURIComponent",
        "decodeURI",
        "path.resolve",
        "path.normalize",
        "path.join",
        "path.basename",
        "path.dirname",
        "Promise.resolve",
    }
)


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
    # File containing the sink node; None when it is the analyzed file itself.
    sink_file: str | None = None


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


def _identifier_text(node: Node | None) -> str | None:
    if node is None or node.type not in ("identifier", "property_identifier"):
        return None
    text = node.text.decode() if node.text else ""
    return text or None


def is_module_exports_member(node: Node) -> bool:
    """True for a `module.exports` member expression."""
    return (
        node.type == "member_expression"
        and _identifier_text(node.child_by_field_name("object")) == "module"
        and _identifier_text(node.child_by_field_name("property")) == "exports"
    )


def export_assignment_name(left: Node) -> str | None:
    """Property name for `exports.foo` / `module.exports.foo` assignment targets."""
    if left.type != "member_expression":
        return None
    obj = left.child_by_field_name("object")
    prop = _identifier_text(left.child_by_field_name("property"))
    if obj is None or prop is None:
        return None
    if _identifier_text(obj) == "exports" or is_module_exports_member(obj):
        return prop
    return None


def _index_exports_object(
    obj: Node,
    index: dict[str, tuple[list[str], Node, str | None]],
    file_path: str | None,
) -> None:
    """Index `module.exports = { foo() {}, bar: function() {}, baz: () => {} }` members."""
    for child in obj.children:
        fn_node: Node | None = None
        name: str | None = None
        if child.type == "method_definition":
            name = _identifier_text(child.child_by_field_name("name"))
            fn_node = child
        elif child.type == "pair":
            value = child.child_by_field_name("value")
            if value is not None and value.type in ("arrow_function", "function_expression"):
                name = _identifier_text(child.child_by_field_name("key"))
                fn_node = value
        if name is None or fn_node is None:
            continue
        body = fn_node.child_by_field_name("body")
        if body is not None:
            index[name] = (_params_from_function_node(fn_node), body, file_path)


def _index_export_assignment(
    node: Node,
    index: dict[str, tuple[list[str], Node, str | None]],
    file_path: str | None,
) -> None:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return
    if right.type in ("arrow_function", "function_expression"):
        name = export_assignment_name(left)
        body = right.child_by_field_name("body")
        if name and body is not None:
            index[name] = (_params_from_function_node(right), body, file_path)
    elif right.type == "object" and is_module_exports_member(left):
        _index_exports_object(right, index, file_path)


def _index_functions(
    root: Node, file_path: str | None = None, *, include_exports: bool = False
) -> dict[str, tuple[list[str], Node, str | None]]:
    index: dict[str, tuple[list[str], Node, str | None]] = {}

    def visit(node: Node) -> None:
        if node.type == "function_declaration":
            name = node.child_by_field_name("name")
            body = node.child_by_field_name("body")
            if name is not None and name.type == "identifier" and body is not None:
                nm = name.text.decode() if name.text else ""
                if nm:
                    index[nm] = (_params_from_function_node(node), body, file_path)
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
                        index[nm] = (_params_from_function_node(val), body, file_path)
        elif node.type == "assignment_expression" and include_exports:
            _index_export_assignment(node, index, file_path)
        for c in node.children:
            visit(c)

    visit(root)
    return index


def merge_fn_index_from_roots(
    roots: list[Node], file_path: str | None = None
) -> dict[str, tuple[list[str], Node, str | None]]:
    # include_exports: used by the bundle path (module_graph) so CommonJS
    # export-assigned functions resolve cross-file; single-file analyze() keeps
    # the default and is unchanged.
    merged: dict[str, tuple[list[str], Node, str | None]] = {}
    for root in roots:
        merged.update(_index_functions(root, file_path, include_exports=True))
    return merged


def _positional_arguments(args_node: Node | None) -> list[Node]:
    if args_node is None:
        return []
    if args_node.type == "template_string":
        return [args_node]
    return [c for c in args_node.children if c.is_named]


class TaintTracker:
    """Taint tracker on tree-sitter AST: intra- and limited same-file inter-procedural."""

    def __init__(self, *, sql_sink_allowlist: bool = True) -> None:
        self._sql_sink_allowlist = sql_sink_allowlist
        self._interproc_cache: set[tuple[str, int, tuple[tuple[str, str], ...]]] = set()

    def analyze(
        self,
        context: AnalysisContext,
        fn_index: dict[str, tuple[list[str], Node, str | None]] | None = None,
    ) -> list[TaintFlow]:
        tainted_vars: dict[str, str] = {}
        sanitized_vars: dict[str, frozenset[str]] = {}
        flows: list[TaintFlow] = []
        idx = fn_index if fn_index is not None else _index_functions(context.root_node)
        self._interproc_cache.clear()

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
        fn_index: dict[str, tuple[list[str], Node, str | None]],
        depth: int,
    ) -> None:
        # Nested functions get a fresh scope: formals shadow outer taint.
        if node.type in _FUNCTION_NODE_TYPES:
            params = _params_from_function_node(node)
            body = node.child_by_field_name("body")
            local_tainted = {k: v for k, v in tainted.items() if k not in params}
            local_san = {k: v for k, v in sanitized.items() if k not in params}
            if body is not None:
                self._collect_taint_info(
                    body, local_tainted, local_san, flows, ctx, fn_index, depth
                )
            for child in node.children:
                if child is body or child.type in (
                    "formal_parameters",
                    "statement_block",
                ):
                    continue
                # Arrow expression body already handled via body field.
                if child is body:
                    continue
                self._collect_taint_info(
                    child, local_tainted, local_san, flows, ctx, fn_index, depth
                )
            return

        # Path-sensitive if/else: analyze branches on separate scope copies.
        if node.type == "if_statement":
            cond = node.child_by_field_name("condition")
            cons = node.child_by_field_name("consequence")
            alt = node.child_by_field_name("alternative")
            if cond is not None:
                self._collect_taint_info(cond, tainted, sanitized, flows, ctx, fn_index, depth)
            then_t, then_s = dict(tainted), dict(sanitized)
            if cons is not None:
                self._collect_taint_info(cons, then_t, then_s, flows, ctx, fn_index, depth)
            else_t, else_s = dict(tainted), dict(sanitized)
            if alt is not None:
                self._collect_taint_info(alt, else_t, else_s, flows, ctx, fn_index, depth)
            self._join_scopes(tainted, sanitized, then_t, then_s, else_t, else_s, alt is None)
            return

        if node.type == "variable_declarator":
            self._handle_var_decl(node, tainted, sanitized, flows, ctx, fn_index, depth)
        elif node.type == "assignment_expression":
            self._handle_assignment(node, tainted, sanitized, flows, ctx, fn_index, depth)
            self._check_assignment_sink(node, tainted, sanitized, flows, ctx)
        elif node.type == "call_expression":
            self._check_sink(node, tainted, sanitized, flows, ctx)
            self._analyze_callee_interproc(node, tainted, sanitized, flows, ctx, fn_index, depth)

        for child in node.children:
            self._collect_taint_info(child, tainted, sanitized, flows, ctx, fn_index, depth)

    @staticmethod
    def _join_scopes(
        out_tainted: dict[str, str],
        out_sanitized: dict[str, frozenset[str]],
        then_t: dict[str, str],
        then_s: dict[str, frozenset[str]],
        else_t: dict[str, str],
        else_s: dict[str, frozenset[str]],
        else_is_fallthrough: bool,
    ) -> None:
        """Conservative join after if/else: taint if either path keeps it."""
        keys = set(then_t) | set(else_t) | set(out_tainted)
        new_t: dict[str, str] = {}
        for k in keys:
            in_then = k in then_t
            in_else = k in else_t
            if in_then and in_else:
                new_t[k] = then_t[k]
            elif in_then and else_is_fallthrough:
                # May skip then → keep pre-if taint if any, else then-only is uncertain.
                if k in out_tainted:
                    new_t[k] = out_tainted[k]
                else:
                    new_t[k] = then_t[k]
            elif in_then or in_else:
                new_t[k] = then_t[k] if in_then else else_t[k]
        out_tainted.clear()
        out_tainted.update(new_t)

        san_keys = set(then_s) | set(else_s)
        new_s: dict[str, frozenset[str]] = {}
        for k in san_keys:
            if k in then_s and k in else_s:
                new_s[k] = then_s[k] & else_s[k]
                if not new_s[k]:
                    new_s.pop(k, None)
            elif k in then_s and else_is_fallthrough and k in out_sanitized:
                new_s[k] = then_s[k] & out_sanitized[k]
                if not new_s[k]:
                    new_s.pop(k, None)
        out_sanitized.clear()
        out_sanitized.update(new_s)

    def _bindings_for_call(
        self,
        call_node: Node,
        tainted: dict[str, str],
        sanitized: dict[str, frozenset[str]],
        fn_index: dict[str, tuple[list[str], Node, str | None]],
    ) -> tuple[str, Node, str | None, dict[str, str], dict[str, frozenset[str]]] | None:
        func = call_node.child_by_field_name("function")
        args_node = call_node.child_by_field_name("arguments")
        if func is None:
            return None
        fname = _interproc_callee_name(func)
        if not fname or fname not in fn_index:
            return None
        params, body, callee_file = fn_index[fname]
        arg_nodes = _positional_arguments(args_node)
        bindings: dict[str, str] = {}
        san_child: dict[str, frozenset[str]] = {}
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
        return fname, body, callee_file, bindings, san_child

    def _analyze_callee_interproc(
        self,
        node: Node,
        tainted: dict[str, str],
        sanitized: dict[str, frozenset[str]],
        flows: list[TaintFlow],
        ctx: AnalysisContext,
        fn_index: dict[str, tuple[list[str], Node, str | None]],
        depth: int,
        *,
        require_bindings: bool = True,
    ) -> str | None:
        """Walk callee body with param bindings only (no ambient outer taint)."""
        if depth >= MAX_INTERPROC_DEPTH:
            return None
        resolved = self._bindings_for_call(node, tainted, sanitized, fn_index)
        if resolved is None:
            return None
        fname, body, callee_file, bindings, san_child = resolved
        if require_bindings and not bindings:
            return None
        sig = tuple(sorted(bindings.items()))
        cache_key = (fname, depth, sig)
        if cache_key in self._interproc_cache:
            return self._return_expression_taint(body, dict(bindings), san_child)
        self._interproc_cache.add(cache_key)
        # Do not inherit ambient outer taint into the callee.
        flows_before = len(flows)
        self._collect_taint_info(body, dict(bindings), san_child, flows, ctx, fn_index, depth + 1)
        if callee_file is not None:
            # Sinks found inside an imported callee belong to the callee's file.
            for flow in flows[flows_before:]:
                if flow.sink_file is None:
                    flow.sink_file = callee_file
        return self._return_expression_taint(body, dict(bindings), san_child)

    def _interproc_call_return_source(
        self,
        call_node: Node,
        tainted: dict[str, str],
        sanitized: dict[str, frozenset[str]],
        flows: list[TaintFlow],
        ctx: AnalysisContext,
        fn_index: dict[str, tuple[list[str], Node, str | None]],
        depth: int,
    ) -> str | None:
        return self._analyze_callee_interproc(
            call_node,
            tainted,
            sanitized,
            flows,
            ctx,
            fn_index,
            depth,
            require_bindings=False,
        )

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
        fn_index: dict[str, tuple[list[str], Node, str | None]],
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
        if name_node.type == "identifier":
            tainted.pop(var_name, None)
            sanitized.pop(var_name, None)

    def _handle_assignment(
        self,
        node: Node,
        tainted: dict[str, str],
        sanitized: dict[str, frozenset[str]],
        flows: list[TaintFlow],
        ctx: AnalysisContext,
        fn_index: dict[str, tuple[list[str], Node, str | None]],
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
        elif left.type == "identifier":
            tainted.pop(var_name, None)
            sanitized.pop(var_name, None)

    def _extract_source(self, node: Node, tainted: dict[str, str]) -> str | None:
        if node.type in ("identifier", "member_expression"):
            match = find_matching_source(node)
            if match:
                return match

        text = node.text.decode() if node.text else ""

        if node.type == "identifier" and text in tainted:
            return tainted[text]

        if node.type == "await_expression":
            for child in node.children:
                if child.is_named:
                    return self._extract_source(child, tainted)
            return None

        if node.type == "ternary_expression":
            for field in ("consequence", "alternative"):
                ch = node.child_by_field_name(field)
                if ch is not None:
                    result = self._extract_source(ch, tainted)
                    if result:
                        return result
            return None

        if node.type == "call_expression":
            func = node.child_by_field_name("function")
            func_text = ""
            if func is not None and func.text:
                func_text = _normalize_optional_access(func.text.decode())
            if func_text not in _TRANSPARENT_WRAPPERS:
                return None
            args = node.child_by_field_name("arguments")
            if args is not None:
                for arg in _positional_arguments(args):
                    result = self._extract_source(arg, tainted)
                    if result:
                        return result
            return None

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
        return not (is_weak_source(taint_source) and sink_method not in COMMAND_SINK_METHOD_NAMES)

    def _check_assignment_sink(
        self,
        node: Node,
        tainted: dict[str, str],
        sanitized: dict[str, frozenset[str]],
        flows: list[TaintFlow],
        ctx: AnalysisContext,
    ) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None or left.type != "member_expression":
            return
        prop = left.child_by_field_name("property")
        if prop is None:
            return
        prop_name = prop.text.decode() if prop.text else ""
        if prop_name not in ("innerHTML", "outerHTML"):
            return
        taint_source = self._find_tainted_in_arg(right, tainted, sanitized, prop_name)
        if taint_source and self._should_report_flow(taint_source, prop_name):
            line = node.start_point[0] + 1
            flows.append(
                TaintFlow(
                    source=taint_source,
                    sink_method=prop_name,
                    source_line=line,
                    sink_line=line,
                )
            )

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
        if len(pos_args) >= 2 and method in _SQL_PLACEHOLDER_MULTIARG_METHODS:
            first = pos_args[0]
            taint_in_first = self._find_tainted_in_arg(first, tainted, sanitized, method)
            lit = _string_literal_text(first)
            # Parameterized / bound style: SQL text arg not tainted; values may be.
            if taint_in_first is None and (
                lit is None or is_parameterized_query(lit) or first.type == "identifier"
            ):
                return
            if lit is not None and is_parameterized_query(lit):
                if taint_in_first and self._should_report_flow(taint_in_first, method):
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
            if (
                text in sanitized
                and sink_method is not None
                and sanitizer_categories_cover_sink(sanitized[text], sink_method)
            ):
                return None
            if text in tainted:
                return tainted[text]

        if node.type in ("identifier", "member_expression"):
            match = find_matching_source(node)
            if match:
                return match

        for child in node.children:
            result = self._find_tainted_in_arg(child, tainted, sanitized, sink_method)
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

    def _receiver_identifier(self, func_node: Node) -> str | None:
        obj = func_node.child_by_field_name("object")
        if obj is None:
            return None
        if obj.type == "identifier":
            return obj.text.decode() if obj.text else None
        # collection.find / db.users.find — use property of nested member as receiver hint
        if obj.type == "member_expression":
            prop = obj.child_by_field_name("property")
            if prop is not None and prop.type in ("identifier", "property_identifier"):
                return prop.text.decode() if prop.text else None
        return None

    def _is_known_sink(self, func_node: Node, method: str) -> bool:
        if func_node.type == "identifier":
            return method in SINK_IDENTIFIERS
        if func_node.type == "member_expression":
            full_text = func_node.text.decode() if func_node.text else ""
            norm = _normalize_optional_access(full_text)
            if full_text in SINK_MEMBER_PATTERNS or norm in SINK_MEMBER_PATTERNS:
                return True
            receiver = self._receiver_identifier(func_node)
            if method in SQL_SINK_METHOD_NAMES:
                if not self._sql_sink_allowlist:
                    return True
                return receiver is not None and receiver in SQL_RECEIVER_ALLOWLIST
            if method in NOSQL_SINK_METHODS:
                return receiver is not None and receiver in NOSQL_RECEIVER_ALLOWLIST
            if method in HTTP_METHOD_SINKS:
                return receiver is not None and receiver in HTTP_RECEIVER_ALLOWLIST
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
