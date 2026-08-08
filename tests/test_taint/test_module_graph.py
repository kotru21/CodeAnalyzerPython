from analyzer.api.schemas import AnalyzeBundleRequest, ScanConfig
from analyzer.config import Settings
from analyzer.core.orchestrator import Orchestrator

HELPER = """
function queryDb(sql) {
  db.query(sql);
}
module.exports = { queryDb };
"""

APP = """
const { queryDb } = require('./db');
app.get('/x', (req, res) => {
  queryDb(req.body.q);
});
"""


def test_bundle_resolves_require_export() -> None:
    orch = Orchestrator(Settings())
    resp = orch.analyze_bundle_sync(
        AnalyzeBundleRequest(
            files={"db.js": HELPER, "app.js": APP},
            config=ScanConfig(enable_taint=True),
        )
    )
    assert any(f.rule_id == "JS-SQL-001" and f.confidence.value == "high" for f in resp.findings)
