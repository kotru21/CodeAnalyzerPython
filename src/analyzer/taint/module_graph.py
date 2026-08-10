from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from analyzer.taint.tracker import (
    export_assignment_name,
    index_direct_export_functions,
    is_module_exports_member,
    merge_fn_index_from_roots,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from tree_sitter import Node

    from analyzer.rules.base import AnalysisContext

_REQUIRE_RE = re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)""")
_IMPORT_RE = re.compile(r"""(?:from\s+['"]([^'"]+)['"]|import\s+['"]([^'"]+)['"])""")
_EXPORT_FROM_RE = re.compile(r"""export\s+(?:\*|\{[^}]+\})\s+from\s+['"]([^'"]+)['"]""")
_MODULE_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")


@dataclass(frozen=True)
class ImportBinding:
    specifier: str
    local_name: str
    exported_name: str
    namespace: bool = False


def parse_relative_imports(source: str) -> list[str]:
    """Legacy regex extractor; superseded by import_paths_from_root (AST-based)."""
    paths: list[str] = []
    for m in _REQUIRE_RE.finditer(source):
        paths.append(m.group(1))
    for m in _IMPORT_RE.finditer(source):
        paths.append(m.group(1) or m.group(2))
    for m in _EXPORT_FROM_RE.finditer(source):
        paths.append(m.group(1))
    return paths


def _string_literal_value(node: Node | None) -> str | None:
    """Raw text of a string literal without surrounding quotes (escapes preserved)."""
    if node is None or node.type != "string":
        return None
    raw = node.text.decode() if node.text else ""
    if len(raw) >= 2 and raw[0] in ("'", '"') and raw[-1] == raw[0]:
        return raw[1:-1]
    return None


def import_paths_from_root(root: Node) -> list[str]:
    """Import/require specifiers via AST; unlike regexes, comments and string
    literals never produce phantom specifiers."""
    paths: list[str] = []

    def visit(node: Node) -> None:
        if node.type in ("import_statement", "export_statement"):
            spec = _string_literal_value(node.child_by_field_name("source"))
            if spec:
                paths.append(spec)
        elif node.type == "call_expression":
            func = node.child_by_field_name("function")
            if (
                func is not None
                and func.type == "identifier"
                and func.text is not None
                and func.text.decode() == "require"
            ):
                args = node.child_by_field_name("arguments")
                named = [c for c in args.children if c.is_named] if args is not None else []
                spec = _string_literal_value(named[0]) if named else None
                if spec:
                    paths.append(spec)
        for child in node.children:
            visit(child)

    visit(root)
    return paths


def _require_specifier(node: Node | None) -> str | None:
    if node is None or node.type != "call_expression":
        return None
    func = node.child_by_field_name("function")
    if _ident_text(func) != "require":
        return None
    args = node.child_by_field_name("arguments")
    named = [child for child in args.children if child.is_named] if args is not None else []
    return _string_literal_value(named[0]) if named else None


def _esm_import_bindings(node: Node, specifier: str) -> list[ImportBinding]:
    bindings: list[ImportBinding] = []
    clause = next((child for child in node.children if child.type == "import_clause"), None)
    if clause is None:
        return bindings
    for child in clause.children:
        if child.type == "identifier":
            local = _ident_text(child)
            if local:
                bindings.append(ImportBinding(specifier, local, "default"))
        elif child.type == "namespace_import":
            local_node = next(
                (part for part in child.children if part.type == "identifier"), None
            )
            local = _ident_text(local_node)
            if local:
                bindings.append(ImportBinding(specifier, local, "*", namespace=True))
        elif child.type == "named_imports":
            for imported in child.children:
                if imported.type != "import_specifier":
                    continue
                exported = _ident_text(imported.child_by_field_name("name"))
                local = _ident_text(imported.child_by_field_name("alias")) or exported
                if local and exported:
                    bindings.append(ImportBinding(specifier, local, exported))
    return bindings


def _commonjs_import_bindings(node: Node, specifier: str) -> list[ImportBinding]:
    name = node.child_by_field_name("name")
    if name is None:
        return []
    if name.type == "identifier":
        local = _ident_text(name)
        return [ImportBinding(specifier, local, "*", namespace=True)] if local else []
    if name.type != "object_pattern":
        return []
    bindings: list[ImportBinding] = []
    for child in name.children:
        if child.type == "shorthand_property_identifier_pattern":
            local = child.text.decode() if child.text else ""
            if local:
                bindings.append(ImportBinding(specifier, local, local))
        elif child.type == "pair_pattern":
            exported = _ident_text(child.child_by_field_name("key"))
            local = _ident_text(child.child_by_field_name("value"))
            if local and exported:
                bindings.append(ImportBinding(specifier, local, exported))
    return bindings


def import_bindings_from_root(root: Node) -> list[ImportBinding]:
    bindings: list[ImportBinding] = []

    def visit(node: Node) -> None:
        if node.type == "import_statement":
            specifier = _string_literal_value(node.child_by_field_name("source"))
            if specifier:
                bindings.extend(_esm_import_bindings(node, specifier))
        elif node.type == "variable_declarator":
            specifier = _require_specifier(node.child_by_field_name("value"))
            if specifier:
                bindings.extend(_commonjs_import_bindings(node, specifier))
        for child in node.children:
            visit(child)

    visit(root)
    return bindings


def resolve_relative(base_path: str, rel: str) -> str:
    base = posixpath.dirname(base_path)
    joined = posixpath.normpath(posixpath.join(base, rel))
    return joined


def apply_tsconfig_paths(spec: str, paths_map: Mapping[str, list[str]]) -> str | None:
    """Resolve TypeScript path aliases (first matching pattern → first target)."""
    for pattern, targets in paths_map.items():
        if not targets:
            continue
        if pattern.endswith("/*"):
            alias_prefix = pattern[:-1]  # '@app/'
            if spec.startswith(alias_prefix):
                rest = spec[len(alias_prefix) :]
                target = targets[0]
                if target.endswith("/*"):
                    return target[:-1] + rest
                return posixpath.join(target, rest).replace("\\", "/")
        elif spec == pattern:
            return targets[0]
    return None


def _ident_text(node: Node | None) -> str | None:
    if node is None:
        return None
    if node.type not in ("identifier", "property_identifier"):
        return None
    t = node.text.decode() if node.text else ""
    return t or None


def _binding_from_export_value(value: Node | None) -> str | None:
    if value is None:
        return None
    if value.type == "identifier":
        return _ident_text(value)
    if value.type in ("function_expression", "arrow_function"):
        return None
    return None


def _collect_object_exports(
    obj: Node, bindings: dict[str, str], *, namespace: str | None = None
) -> None:
    for child in obj.children:
        if child.type == "shorthand_property_identifier":
            name = child.text.decode() if child.text else ""
            if name:
                exported_name = f"{namespace}.{name}" if namespace else name
                bindings[exported_name] = name
        elif child.type == "method_definition":
            # { foo(...) {...} }: anonymous in scope, indexed under the key name
            method_name = _ident_text(child.child_by_field_name("name"))
            if method_name:
                exported_name = f"{namespace}.{method_name}" if namespace else method_name
                bindings[exported_name] = method_name
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
            if (
                key_text
                and value is not None
                and value.type in ("function_expression", "arrow_function")
            ):
                exported_name = f"{namespace}.{key_text}" if namespace else key_text
                bindings[exported_name] = key_text
                continue
            fn_name = _binding_from_export_value(value)
            if key_text and fn_name:
                exported_name = f"{namespace}.{key_text}" if namespace else key_text
                bindings[exported_name] = fn_name


def exported_bindings(root: Node) -> dict[str, str]:
    """Map exported name -> defining function name in same file."""
    bindings: dict[str, str] = {}

    def visit(node: Node) -> None:
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None:
                if is_module_exports_member(left) and right.type == "object":
                    _collect_object_exports(right, bindings)
                elif is_module_exports_member(left) and right.type == "identifier":
                    name = _ident_text(right)
                    if name:
                        bindings["default"] = name
                elif right.type == "object" and export_assignment_name(left) is not None:
                    namespace = export_assignment_name(left)
                    _collect_object_exports(right, bindings, namespace=namespace)
                export_name = export_assignment_name(left)
                if export_name is not None:
                    if right.type in ("function_expression", "arrow_function"):
                        # Anonymous fn is indexed under the export name itself.
                        bindings[export_name] = export_name
                    else:
                        fn_name = _binding_from_export_value(right)
                        if fn_name:
                            bindings[export_name] = fn_name
        elif node.type == "export_statement":
            # export function foo() {} / export const foo = ...
            for child in node.children:
                if child.type == "function_declaration":
                    fname_node = child.child_by_field_name("name")
                    nm = _ident_text(fname_node)
                    if nm:
                        bindings[nm] = nm
                elif child.type == "lexical_declaration":
                    for decl in child.children:
                        if decl.type != "variable_declarator":
                            continue
                        vn = decl.child_by_field_name("name")
                        nm = _ident_text(vn)
                        if nm:
                            bindings[nm] = nm
                elif child.type == "export_clause":
                    for spec in child.children:
                        if spec.type != "export_specifier":
                            continue
                        spec_name = spec.child_by_field_name("name")
                        alias = spec.child_by_field_name("alias")
                        src = _ident_text(spec_name)
                        dst = _ident_text(alias) or src
                        if src and dst:
                            bindings[dst] = src
                elif child.type == "identifier" and _ident_text(child):
                    # export default foo
                    nm = _ident_text(child)
                    if nm:
                        bindings["default"] = nm
        for child in node.children:
            visit(child)

    visit(root)
    return bindings


def _package_main_from_json(text: str) -> str | None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    exports = data.get("exports")
    if isinstance(exports, str):
        return exports.lstrip("./")
    if isinstance(exports, dict):
        main_exp = exports.get(".")
        if isinstance(main_exp, str):
            return main_exp.lstrip("./")
        if isinstance(main_exp, dict):
            for key in ("import", "require", "default"):
                val = main_exp.get(key)
                if isinstance(val, str):
                    return val.lstrip("./")
    main = data.get("main")
    if isinstance(main, str):
        return main.lstrip("./")
    return "index.js"


def _match_bundle_path(
    files: Mapping[str, str],
    base_path: str,
    rel: str,
    *,
    tsconfig_paths: Mapping[str, list[str]] | None = None,
) -> str | None:
    # Windows-style separators ('.\\lib\\db') normalize to posix before resolution.
    spec = rel.replace("\\", "/")
    alias_mapped = False
    if tsconfig_paths and not (spec.startswith("./") or spec.startswith("../")):
        mapped = apply_tsconfig_paths(spec, tsconfig_paths)
        if mapped is not None:
            spec = mapped if mapped.startswith(".") else "./" + mapped
            alias_mapped = True

    # package-like: "lib/utils" → try as relative from base, then package.json
    if not (spec.startswith("./") or spec.startswith("../") or spec.startswith("/")):
        # Treat as relative to bundle root
        pkg_json = f"{spec}/package.json"
        if pkg_json in files:
            main = _package_main_from_json(files[pkg_json]) or "index.js"
            candidate = posixpath.normpath(f"{spec}/{main}")
            hit = _exact_or_index(files, candidate)
            if hit:
                return hit
        hit = _exact_or_index(files, spec)
        if hit:
            return hit
        return None

    # baseUrl semantics: alias targets are relative to the bundle root,
    # not to the importing file's directory.
    candidate = resolve_relative("" if alias_mapped else base_path, spec)
    hit = _exact_or_index(files, candidate)
    if hit:
        return hit
    # directory import → index.js
    stem = candidate
    for ext in _MODULE_EXTENSIONS:
        if stem.endswith(ext):
            stem = stem[: -len(ext)]
            break
    for index_name in tuple(f"index{ext}" for ext in _MODULE_EXTENSIONS):
        idx_path = f"{stem}/{index_name}"
        if idx_path in files:
            return idx_path
    return None


def _exact_or_index(files: Mapping[str, str], candidate: str) -> str | None:
    if candidate in files:
        return candidate
    stem = candidate
    for ext in _MODULE_EXTENSIONS:
        if stem.endswith(ext):
            stem = stem[: -len(ext)]
            break
    for path in files:
        if path in (stem, candidate):
            return path
        path_stem = path
        for ext in _MODULE_EXTENSIONS:
            if path_stem.endswith(ext):
                path_stem = path_stem[: -len(ext)]
                break
        if path_stem == stem:
            return path
    for index_name in tuple(f"index{ext}" for ext in _MODULE_EXTENSIONS):
        idx = f"{stem}/{index_name}"
        if idx in files:
            return idx
    return None


def build_per_file_fn_index(
    contexts: Sequence[AnalysisContext],
    files: Mapping[str, str],
    *,
    tsconfig_paths: Mapping[str, list[str]] | None = None,
) -> dict[str, dict[str, tuple[list[str], Node, str | None]]]:
    """Per consumer file: local fn_index plus resolved require/import exports."""
    by_path = {ctx.file_path: ctx for ctx in contexts}
    file_indices = {
        path: merge_fn_index_from_roots([ctx.root_node], file_path=path)
        for path, ctx in by_path.items()
    }
    direct_export_indices = {
        path: index_direct_export_functions(ctx.root_node, file_path=path)
        for path, ctx in by_path.items()
    }
    file_exports = {path: exported_bindings(ctx.root_node) for path, ctx in by_path.items()}

    def resolved_export_entries(
        dep_path: str,
    ) -> dict[str, tuple[list[str], Node, str | None]]:
        dep_ctx = by_path[dep_path]
        entries: dict[str, tuple[list[str], Node, str | None]] = {}
        for exported_name, function_name in file_exports[dep_path].items():
            entry = direct_export_indices[dep_path].get(exported_name)
            if entry is None:
                entry = file_indices[dep_path].get(function_name)
            if entry is not None:
                entries[exported_name] = entry
        if "export" not in dep_ctx.source_code:
            return entries
        for re_rel in import_paths_from_root(dep_ctx.root_node):
            re_path = _match_bundle_path(files, dep_path, re_rel, tsconfig_paths=tsconfig_paths)
            if re_path is None or re_path not in file_exports:
                continue
            for exported_name, function_name in file_exports[re_path].items():
                entry = direct_export_indices[re_path].get(exported_name)
                if entry is None:
                    entry = file_indices[re_path].get(function_name)
                if entry is not None:
                    entries.setdefault(exported_name, entry)
        return entries

    result: dict[str, dict[str, tuple[list[str], Node, str | None]]] = {}
    for ctx in contexts:
        idx = dict(file_indices[ctx.file_path])
        for binding in import_bindings_from_root(ctx.root_node):
            dep_path = _match_bundle_path(
                files,
                ctx.file_path,
                binding.specifier,
                tsconfig_paths=tsconfig_paths,
            )
            if dep_path is None:
                continue
            if dep_path not in by_path:
                continue
            entries = resolved_export_entries(dep_path)
            if binding.namespace:
                for exported_name, entry in entries.items():
                    idx.setdefault(f"{binding.local_name}.{exported_name}", entry)
                continue
            bound_entry = entries.get(binding.exported_name)
            if bound_entry is not None:
                idx.setdefault(binding.local_name, bound_entry)
            namespace_prefix = f"{binding.exported_name}."
            for exported_name, nested_entry in entries.items():
                if exported_name.startswith(namespace_prefix):
                    suffix = exported_name[len(binding.exported_name) :]
                    idx.setdefault(f"{binding.local_name}{suffix}", nested_entry)
        result[ctx.file_path] = idx
    return result
