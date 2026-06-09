from __future__ import annotations

import posixpath
import re
from collections.abc import Mapping, Sequence

from tree_sitter import Node

from analyzer.rules.base import AnalysisContext
from analyzer.taint.tracker import merge_fn_index_from_roots

_REQUIRE_RE = re.compile(r"""require\(\s*['"](\./[^'"]+|\.\./[^'"]+)['"]\s*\)""")
_IMPORT_RE = re.compile(r"""from\s+['"](\./[^'"]+|\.\./[^'"]+)['"]""")


def parse_relative_imports(source: str) -> list[str]:
    paths: list[str] = []
    for m in _REQUIRE_RE.finditer(source):
        paths.append(m.group(1))
    for m in _IMPORT_RE.finditer(source):
        paths.append(m.group(1))
    return paths


def resolve_relative(base_path: str, rel: str) -> str:
    base = posixpath.dirname(base_path)
    joined = posixpath.normpath(posixpath.join(base, rel))
    if not joined.endswith((".js", ".ts", ".mjs", ".cjs")):
        for ext in (".js", ".ts", ".mjs", ".cjs"):
            candidate = joined + ext
            if candidate:
                return candidate
        return joined + ".js"
    return joined


def _ident_text(node: Node | None) -> str | None:
    if node is None:
        return None
    if node.type not in ("identifier", "property_identifier"):
        return None
    t = node.text.decode() if node.text else ""
    return t or None


def _is_module_exports(left: Node) -> bool:
    if left.type != "member_expression":
        return False
    obj = left.child_by_field_name("object")
    prop = left.child_by_field_name("property")
    return _ident_text(obj) == "module" and _ident_text(prop) == "exports"


def _exports_property_name(left: Node) -> str | None:
    if left.type != "member_expression":
        return None
    obj = left.child_by_field_name("object")
    prop = left.child_by_field_name("property")
    if _ident_text(obj) != "exports":
        return None
    return _ident_text(prop)


def _binding_from_export_value(value: Node | None) -> str | None:
    if value is None:
        return None
    if value.type == "identifier":
        return _ident_text(value)
    if value.type in ("function_expression", "arrow_function"):
        return None
    return None


def _collect_object_exports(obj: Node, bindings: dict[str, str]) -> None:
    for child in obj.children:
        if child.type == "shorthand_property_identifier":
            name = child.text.decode() if child.text else ""
            if name:
                bindings[name] = name
        elif child.type == "pair":
            key = child.child_by_field_name("key")
            value = child.child_by_field_name("value")
            key_text: str | None = None
            if key is not None:
                if key.type == "property_identifier":
                    key_text = _ident_text(key)
                elif key.type == "string":
                    raw = key.text.decode() if key.text else ""
                    key_text = raw.strip("'\"") if raw else None
            fn_name = _binding_from_export_value(value)
            if key_text and fn_name:
                bindings[key_text] = fn_name


def exported_bindings(root: Node) -> dict[str, str]:
    """Map exported name -> defining function name in same file (minimal)."""
    bindings: dict[str, str] = {}

    def visit(node: Node) -> None:
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None:
                if _is_module_exports(left) and right.type == "object":
                    _collect_object_exports(right, bindings)
                export_name = _exports_property_name(left)
                if export_name is not None:
                    fn_name = _binding_from_export_value(right)
                    if fn_name:
                        bindings[export_name] = fn_name
        for child in node.children:
            visit(child)

    visit(root)
    return bindings


def _match_bundle_path(files: Mapping[str, str], base_path: str, rel: str) -> str | None:
    candidate = resolve_relative(base_path, rel)
    if candidate in files:
        return candidate
    stem = candidate
    for ext in (".js", ".ts", ".mjs", ".cjs"):
        if stem.endswith(ext):
            stem = stem[: -len(ext)]
            break
    for path in files:
        if path == stem or path == candidate:
            return path
        path_stem = path
        for ext in (".js", ".ts", ".mjs", ".cjs"):
            if path_stem.endswith(ext):
                path_stem = path_stem[: -len(ext)]
                break
        if path_stem == stem:
            return path
    return None


def build_per_file_fn_index(
    contexts: Sequence[AnalysisContext],
    merged_idx: dict[str, tuple[list[str], Node]],
    files: Mapping[str, str],
) -> dict[str, dict[str, tuple[list[str], Node]]]:
    """Per consumer file: merged fn_index plus resolved require/import exports."""
    by_path = {ctx.file_path: ctx for ctx in contexts}
    file_indices = {
        path: merge_fn_index_from_roots([ctx.root_node])
        for path, ctx in by_path.items()
    }

    result: dict[str, dict[str, tuple[list[str], Node]]] = {}
    for ctx in contexts:
        idx = dict(merged_idx)
        for rel in parse_relative_imports(ctx.source_code):
            dep_path = _match_bundle_path(files, ctx.file_path, rel)
            if dep_path is None:
                continue
            dep_ctx = by_path.get(dep_path)
            if dep_ctx is None:
                continue
            exports = exported_bindings(dep_ctx.root_node)
            dep_idx = file_indices[dep_path]
            for export_name, fn_name in exports.items():
                if fn_name in dep_idx:
                    idx[export_name] = dep_idx[fn_name]
        result[ctx.file_path] = idx
    return result
