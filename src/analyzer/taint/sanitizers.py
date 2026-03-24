from dataclasses import dataclass


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

SANITIZER_NAMES: frozenset[str] = frozenset(
    s.pattern.split(".")[-1] for s in SANITIZERS
)

PARAMETERIZED_PATTERNS: frozenset[str] = frozenset({
    "$1", "$2", "$3", "?", ":id", ":name",
})


def is_sanitizer_call(func_text: str) -> bool:
    for sanitizer in SANITIZERS:
        if sanitizer.pattern in func_text:
            return True
    return False


def is_parameterized_query(query_text: str) -> bool:
    return any(p in query_text for p in PARAMETERIZED_PATTERNS)
