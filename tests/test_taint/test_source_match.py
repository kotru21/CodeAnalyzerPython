from analyzer.taint.source_match import matches_taint_source
from tests.conftest import make_js_context


def test_exact_req_params_matches():
    ctx = make_js_context("const x = req.params.id;")
    node = ctx.root_node.children[0].children[1].child_by_field_name("value")
    assert matches_taint_source(node, "req.params")


def test_req_body_parser_does_not_match_req_body():
    ctx = make_js_context("const x = req.bodyParser.config;")
    node = ctx.root_node.children[0].children[1].child_by_field_name("value")
    assert not matches_taint_source(node, "req.body")


def test_weak_source_process_env():
    from analyzer.taint.sources_sinks import is_weak_source

    assert is_weak_source("process.env")
    assert not is_weak_source("req.body")
