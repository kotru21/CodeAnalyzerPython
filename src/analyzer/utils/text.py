"""Sanitization for user-supplied source text.

JSON payloads may contain lone UTF-16 surrogates (e.g. ``\\ud800``), which are
valid ``str`` but not encodable to UTF-8. A scanner must not crash on them:
replace them with U+FFFD and keep scanning.
"""

_REPLACEMENT = "\ufffd"  # U+FFFD REPLACEMENT CHARACTER
_HIGH_START = 0xD800
_HIGH_END = 0xDBFF
_LOW_START = 0xDC00
_LOW_END = 0xDFFF


def sanitize_lone_surrogates(text: str) -> str:
    """Combine UTF-16 surrogate pairs and replace unpaired code units."""
    result: list[str] = []
    index = 0
    while index < len(text):
        code = ord(text[index])
        if _HIGH_START <= code <= _HIGH_END:
            if index + 1 < len(text):
                low = ord(text[index + 1])
                if _LOW_START <= low <= _LOW_END:
                    scalar = 0x10000 + ((code - _HIGH_START) << 10) + (low - _LOW_START)
                    result.append(chr(scalar))
                    index += 2
                    continue
            result.append(_REPLACEMENT)
        elif _LOW_START <= code <= _LOW_END:
            result.append(_REPLACEMENT)
        else:
            result.append(text[index])
        index += 1
    return "".join(result)


def encode_utf8_safe(text: str) -> bytes:
    """UTF-8 encode that never raises on lone surrogates."""
    return sanitize_lone_surrogates(text).encode("utf-8")
