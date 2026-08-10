"""Module-graph resolution bugfixes: string keys, subscript calls, aliases, Windows paths."""

from analyzer.api.schemas import AnalyzeBundleRequest, ScanConfig
from analyzer.config import Settings
from analyzer.core.orchestrator import Orchestrator
from analyzer.taint.module_graph import (
    build_per_file_fn_index,
    exported_bindings,
    import_paths_from_root,
)
from analyzer.taint.tracker import merge_fn_index_from_roots
from tests.conftest import make_js_context

DB_STR_KEY = """
module.exports = { 'run-query': function(q) { db.query(q); } };
"""

APP_SUBSCRIPT = """
const db = require('./db');
app.get('/x', (req, res) => {
  db['run-query'](req.query.x);
});
"""

APP_SUBSCRIPT_SAFE = """
const db = require('./db');
app.get('/x', (req, res) => {
  db['run-query']('SELECT 1');
});
"""


def test_string_keyed_export_object_is_indexed() -> None:
    ctx = make_js_context(DB_STR_KEY, "db.js")
    idx = merge_fn_index_from_roots([ctx.root_node], file_path="db.js")
    assert "run-query" in idx


def test_computed_subscript_call_resolves_cross_file() -> None:
    files = {"app.js": APP_SUBSCRIPT, "db.js": DB_STR_KEY}
    contexts = [make_js_context(APP_SUBSCRIPT, "app.js"), make_js_context(DB_STR_KEY, "db.js")]
    idx = build_per_file_fn_index(contexts, files)
    assert "db.run-query" in idx["app.js"]

    orch = Orchestrator(Settings())
    resp = orch.analyze_bundle_sync(
        AnalyzeBundleRequest(files=files, config=ScanConfig(enable_taint=True))
    )
    assert any(f.rule_id == "JS-SQL-001" for f in resp.findings)


def test_computed_subscript_call__negative__static_arg() -> None:
    orch = Orchestrator(Settings())
    resp = orch.analyze_bundle_sync(
        AnalyzeBundleRequest(
            files={"app.js": APP_SUBSCRIPT_SAFE, "db.js": DB_STR_KEY},
            config=ScanConfig(enable_taint=True),
        )
    )
    assert not any(f.rule_id == "JS-SQL-001" for f in resp.findings)


TSCONFIG_APP = """
import { runQuery } from '@app/db';
app.get('/x', (req, res) => {
  runQuery(req.query.x);
});
"""

TSCONFIG_DB = """
export function runQuery(q) { db.query(q); }
"""


def test_tsconfig_alias_resolves_from_bundle_root() -> None:
    files = {"src/app.ts": TSCONFIG_APP, "src/db.ts": TSCONFIG_DB}
    orch = Orchestrator(Settings())
    resp = orch.analyze_bundle_sync(
        AnalyzeBundleRequest(
            files=files,
            config=ScanConfig(enable_taint=True),
            tsconfig_paths={"@app/*": ["src/*"]},
        )
    )
    assert any(f.rule_id == "JS-SQL-001" for f in resp.findings)


def test_tsconfig_alias_merges_exports_into_importer_index() -> None:
    files = {"src/app.js": TSCONFIG_APP, "src/db.js": TSCONFIG_DB}
    contexts = [
        make_js_context(TSCONFIG_APP, "src/app.js"),
        make_js_context(TSCONFIG_DB, "src/db.js"),
    ]
    idx = build_per_file_fn_index(contexts, files, tsconfig_paths={"@app/*": ["src/*"]})
    assert "runQuery" in idx["src/app.js"]


DB_NESTED = """
exports.utils = { helper(x) { db.query(x); } };
"""

APP_NESTED = """
const { utils } = require('./db');
app.get('/x', (req, res) => {
  utils.helper(req.query.x);
});
"""


def test_nested_export_object_is_indexed() -> None:
    ctx = make_js_context(DB_NESTED, "db.js")
    idx = merge_fn_index_from_roots([ctx.root_node], file_path="db.js")
    assert "helper" in idx


def test_nested_export_object_bindings() -> None:
    ctx = make_js_context(DB_NESTED, "db.js")
    binds = exported_bindings(ctx.root_node)
    assert binds.get("utils.helper") == "helper"


def test_nested_export_object_resolves_cross_file() -> None:
    files = {"app.js": APP_NESTED, "db.js": DB_NESTED}
    orch = Orchestrator(Settings())
    resp = orch.analyze_bundle_sync(
        AnalyzeBundleRequest(files=files, config=ScanConfig(enable_taint=True))
    )
    assert any(f.rule_id == "JS-SQL-001" for f in resp.findings)


DB_WIN = """
module.exports = { runQuery: function(q) { db.query(q); } };
"""

# JS source with Windows-style separators: require('.\lib\db') escaped per JS rules.
APP_WIN = """
const { runQuery } = require('.\\\\lib\\\\db');
app.get('/x', (req, res) => {
  runQuery(req.params.id);
});
"""


def test_windows_style_require_specifier_resolves() -> None:
    files = {"app.js": APP_WIN, "lib/db.js": DB_WIN}
    contexts = [make_js_context(APP_WIN, "app.js"), make_js_context(DB_WIN, "lib/db.js")]
    idx = build_per_file_fn_index(contexts, files)
    assert "runQuery" in idx["app.js"]

    orch = Orchestrator(Settings())
    resp = orch.analyze_bundle_sync(
        AnalyzeBundleRequest(files=files, config=ScanConfig(enable_taint=True))
    )
    assert any(f.rule_id == "JS-SQL-001" for f in resp.findings)


def test_import_paths_from_root_skips_comments_and_strings() -> None:
    src = """
import { a } from './real-import';
const db = require('./real-require');
export { b } from './real-reexport';
// require('./comment-line');
/* import { c } from './comment-block'; */
const s = "require('./in-string')";
const t = `import { d } from './in-template'`;
"""
    ctx = make_js_context(src, "app.js")
    paths = import_paths_from_root(ctx.root_node)
    assert sorted(paths) == ["./real-import", "./real-reexport", "./real-require"]


def _evil(export_name: str) -> str:
    return f"exports.{export_name} = function(x) {{ db.query(x); }};"


def test_phantom_imports_do_not_merge_fn_index() -> None:
    app = """
// const e1 = require('./evil1');
/* import { e2 } from './evil2'; */
const s = "require('./evil3')";
const { runQuery } = require('./db');
app.get('/x', (req, res) => {
  runQuery(req.query.x);
});
"""
    files = {
        "app.js": app,
        "db.js": "exports.runQuery = function(q) { db.query(q); };",
        "evil1.js": _evil("e1"),
        "evil2.js": _evil("e2"),
        "evil3.js": _evil("e3"),
    }
    contexts = [make_js_context(src, path) for path, src in files.items()]
    idx = build_per_file_fn_index(contexts, files)
    assert "runQuery" in idx["app.js"]
    assert "e1" not in idx["app.js"]
    assert "e2" not in idx["app.js"]
    assert "e3" not in idx["app.js"]


def test_named_import_alias_resolves_exported_function() -> None:
    files = {
        "app.js": "import { runQuery as execute } from './db'; execute(req.query.x);",
        "db.js": "export function runQuery(q) { db.query(q); }",
    }
    response = Orchestrator(Settings()).analyze_bundle_sync(
        AnalyzeBundleRequest(files=files, config=ScanConfig(enable_taint=True))
    )

    assert any(f.rule_id == "JS-SQL-001" for f in response.findings)


def test_commonjs_destructuring_alias_resolves_exported_function() -> None:
    files = {
        "app.js": "const { runQuery: execute } = require('./db'); execute(req.query.x);",
        "db.js": "exports.runQuery = function(q) { db.query(q); };",
    }
    response = Orchestrator(Settings()).analyze_bundle_sync(
        AnalyzeBundleRequest(files=files, config=ScanConfig(enable_taint=True))
    )

    assert any(f.rule_id == "JS-SQL-001" for f in response.findings)


def test_tsx_extension_resolves_cross_file_function() -> None:
    files = {
        "app.tsx": "import { runQuery } from './db'; runQuery(req.query.x);",
        "db.tsx": "export function runQuery(q) { db.query(q); }",
    }
    response = Orchestrator(Settings()).analyze_bundle_sync(
        AnalyzeBundleRequest(files=files, config=ScanConfig(enable_taint=True))
    )

    assert any(f.rule_id == "JS-SQL-001" for f in response.findings)


def test_unrelated_receiver_does_not_resolve_nested_export() -> None:
    files = {
        "db.js": "exports.utils = { helper(x) { db.query(x); } };",
        "app.js": (
            "const dbApi = require('./db'); "
            "const harmless = { helper(x) { return x; } }; "
            "harmless.helper(req.query.x);"
        ),
    }
    response = Orchestrator(Settings()).analyze_bundle_sync(
        AnalyzeBundleRequest(files=files, config=ScanConfig(enable_taint=True))
    )

    assert not any(f.rule_id == "JS-SQL-001" for f in response.findings)
