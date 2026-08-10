import tree_sitter_typescript as tsts
from tree_sitter import Language, Parser, Tree

from analyzer.utils.text import encode_utf8_safe

TS_LANGUAGE = Language(tsts.language_typescript())
TSX_LANGUAGE = Language(tsts.language_tsx())


class TypeScriptParser:
    def __init__(self, tsx: bool = False) -> None:
        lang = TSX_LANGUAGE if tsx else TS_LANGUAGE
        self._parser = Parser(lang)
        self._tsx = tsx

    def parse(self, source_code: str) -> Tree:
        return self._parser.parse(encode_utf8_safe(source_code))

    @property
    def language_name(self) -> str:
        return "tsx" if self._tsx else "typescript"

    @property
    def language(self) -> Language:
        return TSX_LANGUAGE if self._tsx else TS_LANGUAGE
