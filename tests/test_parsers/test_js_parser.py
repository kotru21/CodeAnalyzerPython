import pytest

from analyzer.parsers.factory import get_parser
from analyzer.parsers.js_parser import JavaScriptParser
from analyzer.parsers.ts_parser import TypeScriptParser


class TestJavaScriptParser:
    def test_parse_simple_variable(self, js_parser: JavaScriptParser):
        tree = js_parser.parse("const x = 1;")
        assert tree.root_node.type == "program"
        assert tree.root_node.child_count >= 1

    def test_parse_es6_arrow_function(self, js_parser: JavaScriptParser):
        code = "const add = (a, b) => a + b;"
        tree = js_parser.parse(code)
        assert tree.root_node.type == "program"
        assert not tree.root_node.has_error

    def test_parse_async_await(self, js_parser: JavaScriptParser):
        code = """
async function fetchData() {
    const res = await fetch('/api');
    return res.json();
}
"""
        tree = js_parser.parse(code)
        assert not tree.root_node.has_error

    def test_parse_optional_chaining(self, js_parser: JavaScriptParser):
        code = "const name = user?.profile?.name;"
        tree = js_parser.parse(code)
        assert not tree.root_node.has_error

    def test_parse_nullish_coalescing(self, js_parser: JavaScriptParser):
        code = "const val = a ?? b;"
        tree = js_parser.parse(code)
        assert not tree.root_node.has_error

    def test_parse_template_literal(self, js_parser: JavaScriptParser):
        code = "const msg = `Hello ${name}`;"
        tree = js_parser.parse(code)
        assert not tree.root_node.has_error

    def test_parse_destructuring(self, js_parser: JavaScriptParser):
        code = "const { a, b: c, ...rest } = obj;"
        tree = js_parser.parse(code)
        assert not tree.root_node.has_error

    def test_parse_invalid_syntax_no_crash(self, js_parser: JavaScriptParser):
        code = "function ( { if else"
        tree = js_parser.parse(code)
        assert tree.root_node.type == "program"
        assert tree.root_node.has_error


class TestTypeScriptParser:
    def test_parse_typed_variable(self, ts_parser: TypeScriptParser):
        tree = ts_parser.parse("const x: number = 1;")
        assert tree.root_node.type == "program"
        assert not tree.root_node.has_error

    def test_parse_interface(self, ts_parser: TypeScriptParser):
        code = "interface User { name: string; age: number; }"
        tree = ts_parser.parse(code)
        assert not tree.root_node.has_error

    def test_parse_generic(self, ts_parser: TypeScriptParser):
        code = "function identity<T>(arg: T): T { return arg; }"
        tree = ts_parser.parse(code)
        assert not tree.root_node.has_error


class TestTSXParser:
    def test_parse_jsx_element(self, tsx_parser: TypeScriptParser):
        code = "const el = <div className='test'>Hello</div>;"
        tree = tsx_parser.parse(code)
        assert not tree.root_node.has_error


class TestParserFactory:
    @pytest.mark.parametrize(
        ("file_path", "expected_lang"),
        [
            ("app.js", "javascript"),
            ("app.ts", "typescript"),
            ("app.tsx", "tsx"),
            ("app.mjs", "javascript"),
        ],
    )
    def test_factory_returns_correct_parser(self, file_path: str, expected_lang: str):
        parser = get_parser(file_path=file_path)
        assert parser.language_name == expected_lang
