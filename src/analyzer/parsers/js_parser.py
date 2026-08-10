import tree_sitter_javascript as tsjs
from tree_sitter import Language, Parser, Tree

from analyzer.utils.text import encode_utf8_safe

JS_LANGUAGE = Language(tsjs.language())


class JavaScriptParser:
    def __init__(self) -> None:
        self._parser = Parser(JS_LANGUAGE)

    def parse(self, source_code: str) -> Tree:
        return self._parser.parse(encode_utf8_safe(source_code))

    @property
    def language_name(self) -> str:
        return "javascript"

    @property
    def language(self) -> Language:
        return JS_LANGUAGE
