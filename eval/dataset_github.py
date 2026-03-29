from __future__ import annotations

import re
from urllib.parse import urlparse


def parse_github_blob_url(blob_url: str) -> tuple[str, str, str, str]:
    """
    Parse https://github.com/{owner}/{repo}/blob/{sha}/{path}

    Returns (owner, repo, full_sha, path_in_repo posix).
    """
    p = urlparse(blob_url.strip())
    if p.netloc not in ("github.com", "www.github.com"):
        raise ValueError(f"not a github.com URL: {blob_url!r}")
    parts = [x for x in p.path.split("/") if x]
    if len(parts) < 5 or parts[2] != "blob":
        raise ValueError(f"not a blob URL: {blob_url!r}")
    owner, repo, _, sha, *rest = parts
    path_in_repo = "/".join(rest)
    if not path_in_repo:
        raise ValueError(f"missing path in blob URL: {blob_url!r}")
    return owner, repo, sha, path_in_repo


def github_blob_to_raw_url(blob_url: str) -> str:
    owner, repo, sha, path_in_repo = parse_github_blob_url(blob_url)
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path_in_repo}"


_THOUSANDS_RE = re.compile(r"^\d{1,3}(\.\d{3})+$")


def parse_csv_int(s: str) -> int:
    t = s.strip().replace(",", ".") if "," in s else s.strip()
    if _THOUSANDS_RE.match(t):
        return int(t.replace(".", ""))
    return int(float(t.replace(",", ".")))
