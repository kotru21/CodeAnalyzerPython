import hashlib


def sha256_digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def md5_fingerprint(*parts: str) -> str:
    combined = ":".join(parts)
    return hashlib.md5(combined.encode("utf-8")).hexdigest()
