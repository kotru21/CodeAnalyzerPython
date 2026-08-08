from __future__ import annotations

import json
import posixpath
import re
from typing import TYPE_CHECKING

from analyzer.taint.tracker import merge_fn_index_from_roots

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from tree_sitter import Node

    from analyzer.rules.base import AnalysisContext

_REQUIRE_RE = re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)""")
_IMPORT_RE = re.compile(
    r"""(?:from\s+['"]([^'"]+)['"]|import\s+['"]([^'"]+)['"])"""
)
_EXPORT_FROM_RE = re.compile(
    r"""export\s+(?:\*|\{[^}]+\})\s+from\s+['"]([^'"]+)['"]"""
)


def parse_relative_imports(source: str) -> list[str]:
    paths: list[str] = []
    for m in _REQUIRE_RE.finditer(source):
        paths.append(m.group(1))
    for m in _IMPORT_RE.finditer(source):
        paths.append(m.group(1) or m.group(2))
    for m in _EXPORT_FROM_RE.finditer(source):
        paths.append(m.group(1))
    return paths


def resolve_relative(base_path: str, rel: str) -> str:
    base = posixpath.dirname(base_path)
    joined = posixpath.normpath(posixpath.join(base, rel))
    if not joined.endswith((".js", ".ts", ".mjs", ".cjs", ".json")):
        for ext in (".js", ".ts", ".mjs", ".cjs"):
            candidate = joined + ext
            if candidate:
                return candidate
        return joined + ".js"
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
    """Map exported name -> defining function name in same file."""
    bindings: dict[str, str] = {}

    def visit(node: Node) -> None:
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None:
                if _is_module_exports(left) and right.type == "object":
                    _collect_object_exports(right, bindings)
                elif _is_module_exports(left) and right.type == "identifier":
                    name = _ident_text(right)
                    if name:
                        bindings["default"] = name
                export_name = _exports_property_name(left)
                if export_name is not None:
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
    spec = rel
    if tsconfig_paths and not (spec.startswith("./") or spec.startswith("../")):
        mapped = apply_tsconfig_paths(spec, tsconfig_paths)
        if mapped is not None:
            spec = mapped if mapped.startswith(".") else "./" + mapped

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

    candidate = resolve_relative(base_path, spec)
    hit = _exact_or_index(files, candidate)
    if hit:
        return hit
    # directory import → index.js
    stem = candidate
    for ext in (".js", ".ts", ".mjs", ".cjs"):
        if stem.endswith(ext):
            stem = stem[: -len(ext)]
            break
    for index_name in ("index.js", "index.ts", "index.mjs", "index.cjs"):
        idx_path = f"{stem}/{index_name}"
        if idx_path in files:
            return idx_path
    return None


def _exact_or_index(files: Mapping[str, str], candidate: str) -> str | None:
    if candidate in files:
        return candidate
    stem = candidate
    for ext in (".js", ".ts", ".mjs", ".cjs"):
        if stem.endswith(ext):
            stem = stem[: -len(ext)]
            break
    for path in files:
        if path in (stem, candidate):
            return path
        path_stem = path
        for ext in (".js", ".ts", ".mjs", ".cjs"):
            if path_stem.endswith(ext):
                path_stem = path_stem[: -len(ext)]
                break
        if path_stem == stem:
            return path
    for index_name in ("index.js", "index.ts", "index.mjs", "index.cjs"):
        idx = f"{stem}/{index_name}"
        if idx in files:
            return idx
    return None


def build_per_file_fn_index(
    contexts: Sequence[AnalysisContext],
    files: Mapping[str, str],
    *,
    tsconfig_paths: Mapping[str, list[str]] | None = None,
) -> dict[str, dict[str, tuple[list[str], Node]]]:
    """Per consumer file: local fn_index plus resolved require/import exports."""
    by_path = {ctx.file_path: ctx for ctx in contexts}
    file_indices = {
        path: merge_fn_index_from_roots([ctx.root_node])
        for path, ctx in by_path.items()
    }
    file_exports = {
        path: exported_bindings(ctx.root_node) for path, ctx in by_path.items()
    }

    result: dict[str, dict[str, tuple[list[str], Node]]] = {}
    for ctx in contexts:
        idx = dict(file_indices[ctx.file_path])
        for rel in parse_relative_imports(ctx.source_code):
            dep_path = _match_bundle_path(
                files, ctx.file_path, rel, tsconfig_paths=tsconfig_paths
            )
            if dep_path is None:
                continue
            dep_ctx = by_path.get(dep_path)
            if dep_ctx is None:
                continue
            exports = dict(file_exports[dep_path])
            # Re-export: export { foo } from './other'
            for re_rel in parse_relative_imports(dep_ctx.source_code):
                if "export" not in dep_ctx.source_code:
                    break
                re_path = _match_bundle_path(
                    files, dep_path, re_rel, tsconfig_paths=tsconfig_paths
                )
                if re_path is None or re_path not in file_exports:
                    continue
                for en, fn in file_exports[re_path].items():
                    exports.setdefault(en, fn)
            dep_idx = file_indices[dep_path]
            # Also pull function bodies from re-export targets
            for en, fn_name in list(exports.items()):
                if fn_name in dep_idx:
                    idx[en] = dep_idx[fn_name]
                    continue
                # resolve fn_name from re-exported module index
                for re_rel in parse_relative_imports(dep_ctx.source_code):
                    re_path = _match_bundle_path(
                        files, dep_path, re_rel, tsconfig_paths=tsconfig_paths
                    )
                    if re_path and fn_name in file_indices.get(re_path, {}):
                        idx[en] = file_indices[re_path][fn_name]
                        break
        result[ctx.file_path] = idx
    return result
