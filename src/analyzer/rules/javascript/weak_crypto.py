from tree_sitter import Node

from analyzer.core.severity import Confidence, Severity
from analyzer.rules.base import AnalysisContext, BaseRule, RawFinding, RuleMeta

_WEAK_ALGORITHMS = frozenset({"md5", "sha1", "md4", "ripemd160"})
_WEAK_CIPHERS = frozenset({"des", "des-ede", "des-ede3", "rc4", "rc2"})


class WeakCryptoRule(BaseRule):
    def meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id="JS-CRYPTO-001",
            title="Weak or broken cryptographic algorithm",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            cwe_id="CWE-327",
            owasp="A02:2021 Cryptographic Failures",
            description=(
                "Use of weak hashing (MD5, SHA1), weak ciphers (DES, RC4), "
                "or Math.random() for security-sensitive operations."
            ),
            remediation=(
                "Use SHA-256+ for hashing, AES-256-GCM for encryption, and "
                "crypto.randomBytes()/crypto.randomUUID() for random values."
            ),
        )

    def run(self, context: AnalysisContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        self._walk(context.root_node, context, findings)
        return findings

    def _walk(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        if node.type == "call_expression":
            self._check_call(node, ctx, findings)
        for child in node.children:
            self._walk(child, ctx, findings)

    def _check_call(self, node: Node, ctx: AnalysisContext, findings: list[RawFinding]) -> None:
        func = node.child_by_field_name("function")
        if func is None:
            return

        if func.type == "member_expression":
            obj = func.child_by_field_name("object")
            prop = func.child_by_field_name("property")
            if obj is None or prop is None:
                return
            obj_name = obj.text.decode() if obj.text else ""
            method = prop.text.decode() if prop.text else ""

            if obj_name == "Math" and method == "random":
                findings.append(self._make_finding(node, ctx, "Math.random()"))
                return

            if method in ("createHash", "createCipher", "createCipheriv"):
                args = node.child_by_field_name("arguments")
                if args:
                    first = next((c for c in args.children if c.is_named), None)
                    if first and first.type == "string":
                        algo = first.text.decode().strip("\"'`").lower() if first.text else ""
                        weak = _WEAK_ALGORITHMS if method == "createHash" else _WEAK_CIPHERS
                        if any(algo.startswith(w) for w in weak):
                            findings.append(self._make_finding(node, ctx, algo))

    def _make_finding(self, node: Node, ctx: AnalysisContext, detail: str = "") -> RawFinding:
        return RawFinding(
            rule_id=self.meta().rule_id,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            column=node.start_point[1],
            code_snippet=self._snippet(ctx, node.start_point[0] + 1),
            extra_info=detail,
        )
