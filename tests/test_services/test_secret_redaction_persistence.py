import pytest

from analyzer.api.schemas import AnalyzeRequest, ScanConfig
from analyzer.config import Settings, get_settings
from analyzer.core.orchestrator import Orchestrator
from analyzer.models.base import Base, get_engine, get_session_factory, reset_engine
from analyzer.services.scan_repository import get_findings, save_analyze_response


@pytest.fixture
def sqlite_db(monkeypatch: pytest.MonkeyPatch, tmp_path):
    monkeypatch.setenv("ANALYZER_DATABASE_URL", f"sqlite:///{tmp_path / 'redaction.db'}")
    get_settings.cache_clear()
    reset_engine()
    engine = get_engine()
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)
    reset_engine()
    get_settings.cache_clear()


def test_persisted_secret_finding_contains_only_redacted_snippet(sqlite_db) -> None:
    secret = "AKIAIOSFODNN7EXAMPLE"
    response = Orchestrator(Settings()).analyze_sync(
        AnalyzeRequest(
            source_code=f'const value = "{secret}";',
            file_path="config.js",
            config=ScanConfig(enable_taint=False),
        )
    )
    session = get_session_factory()()
    try:
        save_analyze_response(session, response)
        stored = get_findings(session, str(response.scan_id))
    finally:
        session.close()

    assert len(stored) == 1
    assert secret not in stored[0].code_snippet
    assert "[REDACTED]" in stored[0].code_snippet
