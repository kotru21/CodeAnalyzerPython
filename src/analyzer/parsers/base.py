from typing import Protocol

from tree_sitter import Tree


class CodeParser(Protocol):
    def parse(self, source_code: str) -> Tree: ...

    @property
    def language_name(self) -> str: ...
