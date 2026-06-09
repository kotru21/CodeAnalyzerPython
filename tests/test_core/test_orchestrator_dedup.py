from analyzer.api.schemas import AnalyzeRequest, ScanConfig
from analyzer.config import Settings
from analyzer.core.orchestrator import Orchestrator
from analyzer.core.severity import Confidence


def test_rule_and_taint_same_line_merged_to_one_finding():
    code = """
app.get('/users', (req, res) => {
    db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
});
"""
    orch = Orchestrator(Settings())
    resp = orch.analyze_sync(
        AnalyzeRequest(
            source_code=code,
            file_path="app.js",
            config=ScanConfig(enable_taint=True),
        )
    )
    sql_findings = [f for f in resp.findings if f.rule_id == "JS-SQL-001"]
    assert len(sql_findings) == 1
    assert sql_findings[0].confidence == Confidence.HIGH
