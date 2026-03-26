from eval.cases_pack._util import mk


def cases_xss() -> list[dict]:
    return [
        mk(
            "XSS1-EASY-VULN-01",
            "JS-XSS-001",
            "easy",
            "vulnerable",
            "app.js",
            "document.body.innerHTML = req.query.x;",
            "CWE-79",
            "innerHTML с пользовательским вводом",
        ),
        mk(
            "XSS1-EASY-SAFE-01",
            "JS-XSS-001",
            "easy",
            "safe",
            "app.js",
            "document.body.textContent = req.query.x;",
            None,
            "textContent вместо innerHTML",
        ),
        mk(
            "XSS1-MED-VULN-01",
            "JS-XSS-001",
            "medium",
            "vulnerable",
            "app.js",
            """app.get('/p', (req, res) => {
  const html = req.body.fragment;
  if (html) {
    document.body.innerHTML = html;
  }
});""",
            "CWE-79",
            "innerHTML через переменную из req.body",
        ),
        mk(
            "XSS1-MED-SAFE-01",
            "JS-XSS-001",
            "medium",
            "safe",
            "app.js",
            """app.get('/p', (req, res) => {
  const t = req.body.title;
  const el = document.createElement('span');
  el.textContent = t;
  document.body.appendChild(el);
});""",
            None,
            "Создание текстового узла",
        ),
        mk(
            "XSS1-HARD-VULN-01",
            "JS-XSS-001",
            "hard",
            "vulnerable",
            "app.js",
            """function setHtml(node, val) {
  node.innerHTML = val;
}
function pick(req) {
  return req.query.h;
}
const el = document.getElementById('root');
app.get('/z', (req, res) => {
  setHtml(el, pick(req));
});""",
            "CWE-79",
            "Inter-procedural доставка значения в innerHTML",
        ),
        mk(
            "XSS1-HARD-SAFE-01",
            "JS-XSS-001",
            "hard",
            "safe",
            "app.js",
            """function setText(node, val) {
  node.textContent = val;
}
app.get('/z', (req, res) => {
  setText(document.body, req.query.t);
});""",
            None,
            "Доставка в textContent",
        ),
        mk(
            "XSS2-EASY-VULN-01",
            "JS-XSS-002",
            "easy",
            "vulnerable",
            "view.jsx",
            "const x = <div dangerouslySetInnerHTML={{ __html: req.query.block }} />;",
            "CWE-79",
            "dangerouslySetInnerHTML с вводом",
        ),
        mk(
            "XSS2-EASY-SAFE-01",
            "JS-XSS-002",
            "easy",
            "safe",
            "view.jsx",
            "const x = <div>Hello</div>;",
            None,
            "Без dangerouslySetInnerHTML (правило не должно срабатывать)",
        ),
        mk(
            "XSS2-MED-VULN-01",
            "JS-XSS-002",
            "medium",
            "vulnerable",
            "view.jsx",
            """const fragment = req.body.html;
const el = <section dangerouslySetInnerHTML={{ __html: fragment }} />;""",
            "CWE-79",
            "Промежуточная переменная",
        ),
        mk(
            "XSS2-MED-SAFE-01",
            "JS-XSS-002",
            "medium",
            "safe",
            "view.jsx",
            """const fragment = '<b>static</b>';
const el = <article>{fragment}</article>;""",
            None,
            "Статическая разметка в children",
        ),
        mk(
            "XSS2-HARD-VULN-01",
            "JS-XSS-002",
            "hard",
            "vulnerable",
            "view.tsx",
            """import type { Request } from 'express';
function Widget(props: { r: Request }) {
  return <div dangerouslySetInnerHTML={{ __html: props.r.query.x as string }} />;
}""",
            "CWE-79",
            "TypeScript + JSX",
        ),
        mk(
            "XSS2-HARD-SAFE-01",
            "JS-XSS-002",
            "hard",
            "safe",
            "view.tsx",
            """import type { FC } from 'react';
const Box: FC<{ t: string }> = ({ t }) => <div>{t}</div>;""",
            None,
            "TS-компонент без опасного атрибута",
        ),
    ]
