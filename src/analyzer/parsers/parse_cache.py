"""Per-scan parse-tree cache keyed by (path, content_hash)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from analyzer.utils.hash import sha256_digest

if TYPE_CHECKING:
    from tree_sitter import Tree


@dataclass
class CachedParse:
    tree: Tree
    language: str


class ScanParseCache:
    def __init__(self) -> None:
        self._store: dict[tuple[str, str], CachedParse] = {}

    def get(self, path: str, source: str) -> CachedParse | None:
        return self._store.get((path, sha256_digest(source)))

    def put(self, path: str, source: str, tree: Tree, language: str) -> CachedParse:
        key = (path, sha256_digest(source))
        entry = CachedParse(tree=tree, language=language)
        self._store[key] = entry
        return entry
