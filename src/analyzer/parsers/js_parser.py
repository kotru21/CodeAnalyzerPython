import tree_sitter_javascript as tsjs
from tree_sitter import Language, Parser, Tree

JS_LANGUAGE = Language(tsjs.language())


class JavaScriptParser:
    def __init__(self) -> None:
        self._parser = Parser(JS_LANGUAGE)

    def parse(self, source_code: str) -> Tree:
        return self._parser.parse(source_code.encode("utf-8"))

    @property
    def language_name(self) -> str:
        return "javascript"

    @property
    def language(self) -> Language:
        return JS_LANGUAGE
