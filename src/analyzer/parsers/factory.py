from analyzer.core.language_detect import detect_language
from analyzer.parsers.base import CodeParser
from analyzer.parsers.js_parser import JavaScriptParser
from analyzer.parsers.ts_parser import TypeScriptParser

_JS_PARSER = JavaScriptParser()
_TS_PARSER = TypeScriptParser(tsx=False)
_TSX_PARSER = TypeScriptParser(tsx=True)


def get_parser(language: str | None = None, file_path: str = "untitled.js") -> CodeParser:
    lang = language or detect_language(file_path)
    match lang:
        case "javascript" | "jsx":
            return _JS_PARSER
        case "typescript":
            return _TS_PARSER
        case "tsx":
            return _TSX_PARSER
        case _:
            return _JS_PARSER
