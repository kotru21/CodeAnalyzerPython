from analyzer.parsers.ts_parser import TypeScriptParser
from analyzer.rules.base import AnalysisContext
from analyzer.rules.registry import get_all_rules, reset_registry
from tests.conftest import make_js_context


def _ts_context(source_code: str, file_path: str = "test.ts") -> AnalysisContext:
    parser = TypeScriptParser()
    tree = parser.parse(source_code)
    return AnalysisContext(
        source_code=source_code,
        file_path=file_path,
        tree=tree,
        root_node=tree.root_node,
        lines=source_code.splitlines(),
        language="typescript",
    )


def test_next_searchparams_redirect_detected() -> None:
    reset_registry()
    code = """
import { redirect } from 'next/navigation';
export default function Page({ searchParams }) {
  redirect(searchParams.next);
}
"""
    ctx = make_js_context(code, "page.js")
    rule = next(r for r in get_all_rules() if r.meta().rule_id == "JS-NEXT-001")
    assert rule.run(ctx)


def test_nest_query_sql_detected() -> None:
    reset_registry()
    code = """
@Controller('users')
export class UsersController {
  @Get()
  find(@Query('id') id: string) {
    return this.db.query(`SELECT * FROM users WHERE id = '${id}'`);
  }
}
"""
    ctx = _ts_context(code, "users.controller.ts")
    rule = next(r for r in get_all_rules() if r.meta().rule_id == "JS-NEST-001")
    assert rule.run(ctx)
