import logging
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import uuid4

from analyzer.api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    Finding,
    ScanStats,
)
from analyzer.config import Settings
from analyzer.core.language_detect import detect_language
from analyzer.core.severity import Severity
from analyzer.knowledge.cwe_database import CWEDatabase
from analyzer.parsers.factory import get_parser
from analyzer.rules.base import AnalysisContext, BaseRule, RawFinding
from analyzer.rules.registry import get_rules_for_language
from analyzer.taint.tracker import TaintFlow, TaintTracker
from analyzer.utils.hash import md5_fingerprint

_logger = logging.getLogger(__name__)


class Orchestrator:
    def __init__(self, settings: Settings, cwe_db: CWEDatabase | None = None) -> None:
        self._settings = settings
        self._cwe_db = cwe_db
        self._taint_tracker = TaintTracker()

    def analyze_sync(self, request: AnalyzeRequest) -> AnalyzeResponse:
        start = time.monotonic()
        scan_id = uuid4()

        language = request.language or detect_language(request.file_path)
        parser = get_parser(language=language, file_path=request.file_path)
        tree = parser.parse(request.source_code)

        context = AnalysisContext(
            source_code=request.source_code,
            file_path=request.file_path,
            tree=tree,
            root_node=tree.root_node,
            lines=request.source_code.splitlines(),
            language=language,
        )

        rules = get_rules_for_language(language)
        if request.config.rule_ids:
            allowed = set(request.config.rule_ids)
            rules = [r for r in rules if r.meta().rule_id in allowed]

        raw_findings = self._run_rules(rules, context)

        if request.config.enable_taint:
            taint_flows = self._taint_tracker.analyze(context)
            raw_findings.extend(self._taint_to_findings(taint_flows))

        raw_findings = self._deduplicate(raw_findings)

        threshold = request.config.severity_threshold
        raw_findings = self._filter_severity(raw_findings, rules, threshold)

        findings = self._enrich_findings(raw_findings, rules, context)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        stats = self._compute_stats(findings, context, elapsed_ms)

        return AnalyzeResponse(
            scan_id=scan_id,
            status="completed",
            language=language,
            stats=stats,
            findings=findings,
            created_at=datetime.now(UTC),
        )

    def _run_rules(self, rules: Sequence[BaseRule], context: AnalysisContext) -> list[RawFinding]:
        results: list[RawFinding] = []
        for rule in rules:
            if rule.should_skip(context):
                continue
            try:
                results.extend(rule.run(context))
            except Exception:
                _logger.exception("Rule %s failed", rule.meta().rule_id)
        return results

    def _taint_to_findings(self, flows: list[TaintFlow]) -> list[RawFinding]:
        results: list[RawFinding] = []
        flow_rule_map = {
            "query": "JS-SQL-001",
            "exec": "JS-CMD-001",
            "execSync": "JS-CMD-001",
            "eval": "JS-CMD-001",
            "redirect": "JS-REDIRECT-001",
            "send": "JS-XSS-001",
            "readFile": "JS-PATH-001",
            "readFileSync": "JS-PATH-001",
            "writeFile": "JS-PATH-001",
            "writeFileSync": "JS-PATH-001",
        }
        for flow in flows:
            rule_id = flow_rule_map.get(flow.sink_method)
            if rule_id:
                results.append(
                    RawFinding(
                        rule_id=rule_id,
                        line_start=flow.sink_line,
                        line_end=flow.sink_line,
                        extra_info=f"taint: {flow.source} → {flow.sink_method}",
                    )
                )
        return results

    @staticmethod
    def _deduplicate(findings: list[RawFinding]) -> list[RawFinding]:
        seen: set[str] = set()
        deduped: list[RawFinding] = []
        for f in findings:
            key = md5_fingerprint(f.rule_id, str(f.line_start), str(f.column or 0))
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    def _filter_severity(
        self,
        findings: list[RawFinding],
        all_rules: Sequence[BaseRule],
        threshold: Severity,
    ) -> list[RawFinding]:
        order = list(Severity)
        threshold_idx = order.index(threshold)
        from analyzer.rules.registry import get_all_rules

        full_rule_map = {r.meta().rule_id: r for r in get_all_rules()}
        return [
            f
            for f in findings
            if f.rule_id in full_rule_map
            and order.index(full_rule_map[f.rule_id].meta().severity) <= threshold_idx
        ]

    def _enrich_findings(
        self,
        raw_findings: list[RawFinding],
        rules: Sequence[BaseRule],
        context: AnalysisContext,
    ) -> list[Finding]:
        from analyzer.rules.registry import get_all_rules

        rule_map = {r.meta().rule_id: r for r in get_all_rules()}
        enriched: list[Finding] = []

        for rf in raw_findings:
            rule = rule_map.get(rf.rule_id)
            if rule is None:
                continue
            meta = rule.meta()

            description = meta.description
            remediation = meta.remediation
            owasp = meta.owasp

            if self._cwe_db:
                cwe_entry = self._cwe_db.get(meta.cwe_id)
                if cwe_entry:
                    if cwe_entry.description:
                        description = cwe_entry.description
                    if cwe_entry.mitigations:
                        remediation = meta.remediation + " | " + cwe_entry.mitigations[0]

            snippet = rf.code_snippet or self._get_snippet(context, rf.line_start)

            enriched.append(
                Finding(
                    rule_id=meta.rule_id,
                    title=meta.title,
                    severity=meta.severity,
                    confidence=meta.confidence,
                    file_path=context.file_path,
                    line_start=rf.line_start,
                    line_end=rf.line_end,
                    column=rf.column,
                    code_snippet=snippet,
                    description=description,
                    remediation=remediation,
                    cwe_id=meta.cwe_id,
                    owasp_category=owasp,
                )
            )
        return enriched

    @staticmethod
    def _get_snippet(ctx: AnalysisContext, line: int) -> str:
        idx = line - 1
        if 0 <= idx < len(ctx.lines):
            return ctx.lines[idx]
        return ""

    @staticmethod
    def _compute_stats(findings: list[Finding], ctx: AnalysisContext, elapsed_ms: int) -> ScanStats:
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return ScanStats(
            total_findings=len(findings),
            critical=counts.get(Severity.CRITICAL, 0),
            high=counts.get(Severity.HIGH, 0),
            medium=counts.get(Severity.MEDIUM, 0),
            low=counts.get(Severity.LOW, 0),
            info=counts.get(Severity.INFO, 0),
            files_scanned=1,
            lines_scanned=len(ctx.lines),
            scan_duration_ms=elapsed_ms,
        )
