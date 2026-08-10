"""Local function definitions must shadow same-named imported/exported bindings."""

from analyzer.api.schemas import AnalyzeBundleRequest, AnalyzeRequest, ScanConfig
from analyzer.config import Settings
from analyzer.core.orchestrator import Orchestrator
from analyzer.taint.module_graph import build_per_file_fn_index
from analyzer.taint.tracker import TaintTracker, merge_fn_index_from_roots
from tests.conftest import make_js_context

DB = """
exports.helper = function(x) { db.query(x); };
"""

APP = """
function helper(x) { return x; }
const db = require('./db');
app.get('/x', (req, res) => {
  helper(req.query.x);
});
"""

SAME_FILE = """
function helper(x) { return x; }
module.exports.helper = function(x) { db.query(x); };
app.get('/x', (req, res) => {
  helper(req.query.x);
});
"""


def test_local_fn_shadows_imported_export__no_cross_file_fp() -> None:
    orch = Orchestrator(Settings())
    resp = orch.analyze_bundle_sync(
        AnalyzeBundleRequest(
            files={"app.js": APP, "db.js": DB},
            config=ScanConfig(enable_taint=True),
        )
    )
    assert not any(f.rule_id == "JS-SQL-001" for f in resp.findings)


def test_local_fn_entry_wins_in_per_file_index() -> None:
    files = {"app.js": APP, "db.js": DB}
    contexts = [make_js_context(APP, "app.js"), make_js_context(DB, "db.js")]
    idx = build_per_file_fn_index(contexts, files)
    entry = idx["app.js"]["helper"]
    # (params, body, defining file): the local declaration, not db.js's export.
    assert entry[2] == "app.js"


def test_export_assignment_does_not_clobber_local__bundle_index() -> None:
    ctx = make_js_context(SAME_FILE, "mod.js")
    idx = merge_fn_index_from_roots([ctx.root_node], file_path="mod.js")
    flows = TaintTracker().analyze(ctx, fn_index=idx)
    assert not any(f.sink_method == "query" for f in flows)


def test_export_assignment_not_indexed__single_file() -> None:
    flows = TaintTracker().analyze(make_js_context(SAME_FILE, "mod.js"))
    assert not any(f.sink_method == "query" for f in flows)


def test_sync_and_bundle_agree_on_same_file() -> None:
    orch = Orchestrator(Settings())
    sync_resp = orch.analyze_sync(
        AnalyzeRequest(
            source_code=SAME_FILE,
            file_path="mod.js",
            config=ScanConfig(enable_taint=True),
        )
    )
    bundle_resp = orch.analyze_bundle_sync(
        AnalyzeBundleRequest(
            files={"mod.js": SAME_FILE},
            config=ScanConfig(enable_taint=True),
        )
    )
    assert not any(f.rule_id == "JS-SQL-001" for f in sync_resp.findings)
    assert not any(f.rule_id == "JS-SQL-001" for f in bundle_resp.findings)


def test_importer_uses_export_assignment_not_same_named_local() -> None:
    files = {
        "db.js": (
            "function helper(x) { return x; } "
            "module.exports.helper = function(x) { db.query(x); };"
        ),
        "app.js": (
            "const { helper } = require('./db'); "
            "app.get('/x', (req, res) => helper(req.query.x));"
        ),
    }
    response = Orchestrator(Settings()).analyze_bundle_sync(
        AnalyzeBundleRequest(files=files, config=ScanConfig(enable_taint=True))
    )

    assert any(
        f.rule_id == "JS-SQL-001" and f.file_path == "db.js" for f in response.findings
    )
