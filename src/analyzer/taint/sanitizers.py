from dataclasses import dataclass

from analyzer.taint.sources_sinks import ALL_SINKS


@dataclass(frozen=True)
class Sanitizer:
    pattern: str
    category: str
    description: str


# Exact callee match only (no substring / generic cross-category sanitizers).
SANITIZERS: list[Sanitizer] = [
    Sanitizer("validator.escape", "xss", "validator.js escape function"),
    Sanitizer("DOMPurify.sanitize", "xss", "DOMPurify sanitization"),
    Sanitizer("he.encode", "xss", "he HTML encode"),
    Sanitizer("xss", "xss", "xss library filter"),
    Sanitizer("parseInt", "type_cast", "Parse to integer (strips non-numeric)"),
    Sanitizer("Number", "type_cast", "Cast to number"),
    Sanitizer("path.normalize", "path", "Normalize filesystem path"),
    Sanitizer("path.basename", "path", "Strip directory from path"),
]

SANITIZER_NAMES: frozenset[str] = frozenset(s.pattern.split(".")[-1] for s in SANITIZERS)

SANITIZER_BY_PATTERN: dict[str, str] = {s.pattern: s.category for s in SANITIZERS}

SINK_CATEGORY_BY_METHOD: dict[str, str] = {
    s.pattern.split(".")[-1]: s.category for s in ALL_SINKS
}
# NoSQL methods are not in ALL_SINKS patterns as dotted names.
for _nosql_m in ("find", "findOne", "findOneAndUpdate", "updateOne", "deleteOne", "aggregate"):
    SINK_CATEGORY_BY_METHOD.setdefault(_nosql_m, "nosql")

PARAMETERIZED_PATTERNS: frozenset[str] = frozenset(
    {
        "$1",
        "$2",
        "$3",
        "?",
        ":id",
        ":name",
    }
)


def is_sanitizer_call(func_text: str) -> bool:
    return bool(sanitizer_categories_for_call(func_text))


def sanitizer_categories_for_call(func_text: str) -> frozenset[str]:
    """Return categories only when func_text exactly matches a known sanitizer pattern."""
    cat = SANITIZER_BY_PATTERN.get(func_text)
    if cat is None:
        return frozenset()
    return frozenset({cat})


def _categories_cover_sink_category(cats: frozenset[str], sink_category: str) -> bool:
    if sink_category in cats:
        return True
    return bool("type_cast" in cats and sink_category == "sql")


def sanitizer_applies_to_sink(func_text: str, sink_method: str) -> bool:
    cats = sanitizer_categories_for_call(func_text)
    if not cats:
        return False
    sink_category = SINK_CATEGORY_BY_METHOD.get(sink_method)
    if sink_category is None:
        return False
    return _categories_cover_sink_category(cats, sink_category)


def sanitizer_categories_cover_sink(
    sanitizer_cats: frozenset[str], sink_method: str
) -> bool:
    sink_category = SINK_CATEGORY_BY_METHOD.get(sink_method)
    if sink_category is None:
        return False
    return _categories_cover_sink_category(sanitizer_cats, sink_category)


def is_parameterized_query(query_text: str) -> bool:
    return any(p in query_text for p in PARAMETERIZED_PATTERNS)
