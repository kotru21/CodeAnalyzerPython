"""Small labeled real-world-style snippets (framework data paths)."""

from eval.cases_pack._util import mk


def cases_realworld() -> list[dict]:
    return [
        mk(
            "RW-NEXT-SEARCHPARAMS-REDIRECT",
            "JS-NEXT-001",
            "medium",
            "vulnerable",
            "page.tsx",
            """import { redirect } from 'next/navigation';

export default function Page({ searchParams }) {
  redirect(searchParams.next);
}
""",
            "CWE-601",
            "Next.js searchParams → redirect",
            tags=["realworld:next"],
        ),
        mk(
            "RW-NEST-QUERY-SQL",
            "JS-NEST-001",
            "medium",
            "vulnerable",
            "users.controller.ts",
            """@Controller('users')
export class UsersController {
  @Get()
  find(@Query('id') id: string) {
    return this.db.query(`SELECT * FROM users WHERE id = '${id}'`);
  }
}
""",
            "CWE-89",
            "NestJS @Query near raw SQL template",
            tags=["realworld:nest"],
        ),
        mk(
            "RW-NEXT-SAFE-LITERAL",
            "JS-NEXT-001",
            "easy",
            "safe",
            "page.tsx",
            """import { redirect } from 'next/navigation';

export default function Page() {
  redirect('/home');
}
""",
            None,
            "Next.js redirect with literal path",
            tags=["realworld:next"],
        ),
    ]
