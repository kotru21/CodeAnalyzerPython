from tree_sitter import Node

from analyzer.taint.sources_sinks import SOURCE_PATTERNS


def member_chain_parts(node: Node) -> list[str] | None:
    if node.type == "identifier":
        t = node.text.decode() if node.text else ""
        return [t] if t else None
    if node.type == "member_expression":
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        if obj is None or prop is None:
            return None
        base = member_chain_parts(obj)
        seg = prop.text.decode() if prop.text else ""
        if base is None or not seg:
            return None
        return base + [seg]
    return None


def chain_to_dotted(parts: list[str]) -> str:
    return ".".join(parts)


def matches_taint_source(node: Node, pattern: str) -> bool:
    parts = member_chain_parts(node)
    if parts is None:
        text = node.text.decode() if node.text else ""
        norm = text.replace("?.", ".")
        return norm == pattern
    dotted = chain_to_dotted(parts)
    if dotted == pattern:
        return True
    return bool(dotted.startswith(pattern + "."))


def find_matching_source(node: Node) -> str | None:
    for pattern in sorted(SOURCE_PATTERNS, key=len, reverse=True):
        if matches_taint_source(node, pattern):
            return pattern
    return None
