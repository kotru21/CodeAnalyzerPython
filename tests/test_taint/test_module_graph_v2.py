"""Module graph v2: index.js, package main, tsconfig paths, named exports."""

from analyzer.api.schemas import AnalyzeBundleRequest, ScanConfig
from analyzer.config import Settings
from analyzer.core.orchestrator import Orchestrator
from analyzer.parsers.js_parser import JavaScriptParser
from analyzer.rules.base import AnalysisContext
from analyzer.taint.module_graph import (
    apply_tsconfig_paths,
    build_per_file_fn_index,
    exported_bindings,
)


def _ctx(path: str, source: str) -> AnalysisContext:
    tree = JavaScriptParser().parse(source)
    return AnalysisContext(
        source_code=source,
        file_path=path,
        tree=tree,
        root_node=tree.root_node,
        lines=source.splitlines(),
        language="javascript",
    )


def test_apply_tsconfig_paths() -> None:
    assert apply_tsconfig_paths("@app/util", {"@app/*": ["src/*"]}) == "src/util"


def test_index_js_resolution_cross_file_taint() -> None:
    lib = """
function runQuery(q) { db.query(q); }
module.exports = { runQuery };
"""
    app = """
const { runQuery } = require('./lib');
runQuery(req.params.id);
"""
    files = {"app.js": app, "lib/index.js": lib}
    contexts = [_ctx("app.js", app), _ctx("lib/index.js", lib)]
    idx = build_per_file_fn_index(contexts, files)
    assert "runQuery" in idx["app.js"]

    orch = Orchestrator(Settings())
    resp = orch.analyze_bundle_sync(
        AnalyzeBundleRequest(files=files, config=ScanConfig(enable_taint=True))
    )
    assert any(f.rule_id == "JS-SQL-001" for f in resp.findings)


def test_export_function_bindings() -> None:
    src = "export function runQuery(q) { db.query(q); }"
    ctx = _ctx("lib.js", src)
    binds = exported_bindings(ctx.root_node)
    assert binds.get("runQuery") == "runQuery"
