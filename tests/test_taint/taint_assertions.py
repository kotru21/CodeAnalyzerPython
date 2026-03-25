from analyzer.taint.tracker import TaintFlow


def assert_any_flow(
    flows: list[TaintFlow],
    *,
    sink_method: str,
    source_substr: str | None = None,
) -> None:
    assert flows, "expected at least one TaintFlow"
    match = [f for f in flows if f.sink_method == sink_method]
    assert match, f"no flow with sink_method={sink_method!r}: {flows!r}"
    if source_substr is not None:
        assert any(source_substr in f.source for f in match), flows


def assert_no_flow_with_sink(flows: list[TaintFlow], sink_method: str) -> None:
    assert not any(f.sink_method == sink_method for f in flows), flows
