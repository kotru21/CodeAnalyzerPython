from tree_sitter import Node


def _node_text(node: Node) -> str:
    return node.text.decode() if node.text else ""


def bind_pattern_from_source(
    pattern_node: Node | None, source: str, tainted: dict[str, str]
) -> None:
    """Bind destructuring pattern identifiers to a taint source label."""
    if pattern_node is None:
        return
    if pattern_node.type == "identifier":
        name = _node_text(pattern_node)
        if name:
            tainted[name] = source
        return
    if pattern_node.type == "object_pattern":
        for child in pattern_node.children:
            if child.type == "shorthand_property_identifier_pattern":
                key = _node_text(child)
                if key:
                    tainted[key] = source
            elif child.type == "pair_pattern":
                value = child.child_by_field_name("value")
                if value is not None:
                    bind_pattern_from_source(value, source, tainted)
        return
    if pattern_node.type == "array_pattern":
        for child in pattern_node.children:
            if child.type in ("identifier", "object_pattern", "array_pattern"):
                bind_pattern_from_source(child, source, tainted)
            elif child.type == "assignment_pattern":
                left = child.child_by_field_name("left")
                bind_pattern_from_source(left, source, tainted)
