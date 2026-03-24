import pytest

from analyzer.parsers.js_parser import JavaScriptParser
from analyzer.parsers.ts_parser import TypeScriptParser
from analyzer.rules.base import AnalysisContext


@pytest.fixture
def js_parser() -> JavaScriptParser:
    return JavaScriptParser()


@pytest.fixture
def ts_parser() -> TypeScriptParser:
    return TypeScriptParser()


@pytest.fixture
def tsx_parser() -> TypeScriptParser:
    return TypeScriptParser(tsx=True)


def make_js_context(source_code: str, file_path: str = "test.js") -> AnalysisContext:
    parser = JavaScriptParser()
    tree = parser.parse(source_code)
    return AnalysisContext(
        source_code=source_code,
        file_path=file_path,
        tree=tree,
        root_node=tree.root_node,
        lines=source_code.splitlines(),
        language="javascript",
    )
