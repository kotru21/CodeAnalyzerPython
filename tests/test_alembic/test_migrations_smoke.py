"""Smoke-test Alembic upgrades against an isolated SQLite DB."""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


@pytest.fixture
def alembic_sqlite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db_path = tmp_path / "alembic.db"
    url = f"sqlite:///{db_path}"
    monkeypatch.setenv("ANALYZER_DATABASE_URL", url)
    # Clear settings cache so alembic env sees the URL.
    from analyzer.config import get_settings

    get_settings.cache_clear()
    return db_path


def test_alembic_upgrade_head_creates_scans_and_findings(alembic_sqlite: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "alembic"))
    command.upgrade(cfg, "head")

    engine = create_engine(f"sqlite:///{alembic_sqlite}")
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    assert "scans" in tables
    assert "findings" in tables
    cols = {c["name"] for c in insp.get_columns("scans")}
    assert "files_scanned" in cols
    assert "failed_rules_json" in cols
    with engine.connect() as conn:
        conn.execute(text("SELECT id, status FROM scans LIMIT 0"))
        conn.execute(text("SELECT id, scan_id FROM findings LIMIT 0"))
