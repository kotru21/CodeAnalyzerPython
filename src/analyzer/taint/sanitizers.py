from dataclasses import dataclass

from analyzer.taint.sources_sinks import ALL_SINKS


@dataclass(frozen=True)
class Sanitizer:
    pattern: str
    category: str
    description: str


SANITIZERS: list[Sanitizer] = [
    Sanitizer("validator.escape", "xss", "validator.js escape function"),
    Sanitizer("DOMPurify.sanitize", "xss", "DOMPurify sanitization"),
    Sanitizer("encodeURIComponent", "xss", "URI component encoding"),
    Sanitizer("encodeURI", "xss", "URI encoding"),
    Sanitizer("escape", "xss", "Generic escape function"),
    Sanitizer("sanitize", "generic", "Generic sanitize function"),
    Sanitizer("parseInt", "type_cast", "Parse to integer (strips non-numeric)"),
    Sanitizer("Number", "type_cast", "Cast to number"),
    Sanitizer("path.resolve", "path", "Resolve to absolute path"),
    Sanitizer("path.normalize", "path", "Normalize path"),
    Sanitizer("path.basename", "path", "Extract basename"),
]

SANITIZER_NAMES: frozenset[str] = frozenset(s.pattern.split(".")[-1] for s in SANITIZERS)

SANITIZER_BY_PATTERN: dict[str, str] = {s.pattern: s.category for s in SANITIZERS}

SINK_CATEGORY_BY_METHOD: dict[str, str] = {
    s.pattern.split(".")[-1]: s.category for s in ALL_SINKS
}

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
    cats: set[str] = set()
    for pattern, category in SANITIZER_BY_PATTERN.items():
        if pattern in func_text:
            cats.add(category)
    return frozenset(cats)


def _categories_cover_sink_category(cats: frozenset[str], sink_category: str) -> bool:
    if "generic" in cats:
        return True
    if sink_category in cats:
        return True
    if "type_cast" in cats and sink_category == "sql":
        return True
    return False


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
