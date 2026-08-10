import hashlib

from analyzer.utils.text import encode_utf8_safe


def sha256_digest(content: str) -> str:
    return hashlib.sha256(encode_utf8_safe(content)).hexdigest()


def md5_fingerprint(*parts: str) -> str:
    combined = ":".join(parts)
    return hashlib.md5(encode_utf8_safe(combined)).hexdigest()
