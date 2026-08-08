import pytest

from analyzer.config import get_settings
from analyzer.parsers.js_parser import JavaScriptParser
from analyzer.parsers.ts_parser import TypeScriptParser
from analyzer.rules.base import AnalysisContext


@pytest.fixture(autouse=True)
def _analyzer_debug_for_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    """Allow create_app lifespan without ANALYZER_API_KEY in unit tests."""
    monkeypatch.setenv("ANALYZER_DEBUG", "true")
    monkeypatch.setenv("ANALYZER_RATE_LIMIT_PER_MINUTE", "0")
    monkeypatch.setenv("ANALYZER_RATE_LIMIT_SYNC_PER_MINUTE", "0")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


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
