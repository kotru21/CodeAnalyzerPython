import logging
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import uuid4

from analyzer.api.schemas import (
    AnalyzeBundleRequest,
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
from analyzer.taint.tracker import TaintFlow, TaintTracker, merge_fn_index_from_roots
from analyzer.utils.hash import md5_fingerprint

_logger = logging.getLogger(__name__)


class Orchestrator:
    def __init__(self, settings: Settings, cwe_db: CWEDatabase | None = None) -> None:
        self._settings = settings
        self._cwe_db = cwe_db
        self._taint_tracker = TaintTracker()

    def analyze_sync(self, request: AnalyzeRequest) -> AnalyzeResponse:
        start = time.monotonic()
        scan_id = request.scan_id if request.scan_id is not None else uuid4()
        budget_ms = self._settings.analysis_budget_ms
        deadline: float | None = None
        if budget_ms is not None and budget_ms > 0:
            deadline = start + budget_ms / 1000.0

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

        raw_findings, failed_rules = self._run_rules(rules, context, deadline)
        for rf in raw_findings:
            rf.file_path = context.file_path
        time_budget_exceeded = deadline is not None and time.monotonic() > deadline

        if request.config.enable_taint and not time_budget_exceeded:
            taint_flows = self._taint_tracker.analyze(context)
            raw_findings.extend(
                self._taint_to_findings(taint_flows, file_path=context.file_path)
            )

        raw_findings = self._deduplicate(raw_findings)

        threshold = request.config.severity_threshold
        raw_findings = self._filter_severity(raw_findings, rules, threshold)

        ctx_map = {context.file_path: context}
        findings = self._enrich_findings(raw_findings, rules, ctx_map)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        stats = self._compute_stats(
            findings,
            context,
            elapsed_ms,
            time_budget_exceeded=time_budget_exceeded,
        )

        return AnalyzeResponse(
            scan_id=scan_id,
            status="completed",
            language=language,
            stats=stats,
            findings=findings,
            created_at=datetime.now(UTC),
            failed_rules=failed_rules,
        )

    def _run_rules(
        self,
        rules: Sequence[BaseRule],
        context: AnalysisContext,
        deadline: float | None,
    ) -> tuple[list[RawFinding], list[str]]:
        results: list[RawFinding] = []
        failed_rules: list[str] = []
        for rule in rules:
            if deadline is not None and time.monotonic() > deadline:
                break
            if rule.should_skip(context):
                continue
            try:
                results.extend(rule.run(context))
            except Exception:
                _logger.exception("Rule %s failed", rule.meta().rule_id)
                failed_rules.append(rule.meta().rule_id)
        return results, failed_rules

    def analyze_bundle_sync(self, request: AnalyzeBundleRequest) -> AnalyzeResponse:
        start = time.monotonic()
        scan_id = request.scan_id if request.scan_id is not None else uuid4()
        budget_ms = self._settings.analysis_budget_ms
        deadline: float | None = None
        if budget_ms is not None and budget_ms > 0:
            deadline = start + budget_ms / 1000.0

        paths = sorted(request.files.keys())
        contexts: list[AnalysisContext] = []
        for rel in paths:
            src = request.files[rel]
            lang = request.language or detect_language(rel)
            parser = get_parser(language=lang, file_path=rel)
            tree = parser.parse(src)
            contexts.append(
                AnalysisContext(
                    source_code=src,
                    file_path=rel,
                    tree=tree,
                    root_node=tree.root_node,
                    lines=src.splitlines(),
                    language=lang,
                )
            )

        primary_lang = contexts[0].language if contexts else "javascript"
        rules = get_rules_for_language(primary_lang)
        if request.config.rule_ids:
            allowed = set(request.config.rule_ids)
            rules = [r for r in rules if r.meta().rule_id in allowed]

        merged_idx = merge_fn_index_from_roots([c.root_node for c in contexts])
        raw_findings: list[RawFinding] = []
        failed_rules: list[str] = []

        for ctx in contexts:
            if deadline is not None and time.monotonic() > deadline:
                break
            r, f = self._run_rules(rules, ctx, deadline)
            for rf in r:
                rf.file_path = ctx.file_path
            raw_findings.extend(r)
            failed_rules.extend(f)

        time_budget_exceeded = deadline is not None and time.monotonic() > deadline

        if request.config.enable_taint and not time_budget_exceeded:
            for ctx in contexts:
                if deadline is not None and time.monotonic() > deadline:
                    time_budget_exceeded = True
                    break
                flows = self._taint_tracker.analyze(ctx, fn_index=merged_idx)
                raw_findings.extend(
                    self._taint_to_findings(flows, file_path=ctx.file_path)
                )

        raw_findings = self._deduplicate(raw_findings)
        raw_findings = self._filter_severity(
            raw_findings, rules, request.config.severity_threshold
        )

        ctx_map = {c.file_path: c for c in contexts}
        findings = self._enrich_findings(raw_findings, rules, ctx_map)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        primary_ctx = contexts[0]
        stats = self._compute_stats(
            findings,
            primary_ctx,
            elapsed_ms,
            time_budget_exceeded=time_budget_exceeded,
            files_scanned=len(contexts),
            lines_scanned=sum(len(c.lines) for c in contexts),
        )

        return AnalyzeResponse(
            scan_id=scan_id,
            status="completed",
            language=primary_lang,
            stats=stats,
            findings=findings,
            created_at=datetime.now(UTC),
            failed_rules=list(dict.fromkeys(failed_rules)),
        )

    def _taint_to_findings(
        self, flows: list[TaintFlow], *, file_path: str | None = None
    ) -> list[RawFinding]:
        results: list[RawFinding] = []
        flow_rule_map = {
            "query": "JS-SQL-001",
            "$queryRaw": "JS-SQL-001",
            "$executeRaw": "JS-SQL-001",
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
                        file_path=file_path,
                        taint_confirmed=True,
                    )
                )
        return results

    @staticmethod
    def _deduplicate(findings: list[RawFinding]) -> list[RawFinding]:
        merged: dict[str, RawFinding] = {}
        for f in findings:
            key = md5_fingerprint(f.rule_id, str(f.line_start), f.file_path or "")
            existing = merged.get(key)
            if existing is None:
                merged[key] = f
                continue
            if f.taint_confirmed:
                existing.taint_confirmed = True
            if f.extra_info and "taint:" in f.extra_info:
                existing.extra_info = (
                    f"{existing.extra_info}; {f.extra_info}".strip("; ")
                    if existing.extra_info
                    else f.extra_info
                )
            if existing.column is None and f.column is not None:
                existing.column = f.column
            if not existing.code_snippet and f.code_snippet:
                existing.code_snippet = f.code_snippet
        return list(merged.values())

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
        contexts: dict[str, AnalysisContext],
    ) -> list[Finding]:
        from analyzer.rules.registry import get_all_rules

        rule_map = {r.meta().rule_id: r for r in get_all_rules()}
        enriched: list[Finding] = []
        default_ctx = next(iter(contexts.values()))

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

            fp = rf.file_path if rf.file_path else default_ctx.file_path
            ctx = contexts.get(fp) or default_ctx
            snippet = rf.code_snippet or self._get_snippet(ctx, rf.line_start)

            enriched.append(
                Finding(
                    rule_id=meta.rule_id,
                    title=meta.title,
                    severity=meta.severity,
                    confidence=meta.confidence,
                    file_path=fp,
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
    def _compute_stats(
        findings: list[Finding],
        ctx: AnalysisContext,
        elapsed_ms: int,
        *,
        time_budget_exceeded: bool = False,
        files_scanned: int | None = None,
        lines_scanned: int | None = None,
    ) -> ScanStats:
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
            files_scanned=files_scanned if files_scanned is not None else 1,
            lines_scanned=(
                lines_scanned if lines_scanned is not None else len(ctx.lines)
            ),
            scan_duration_ms=elapsed_ms,
            time_budget_exceeded=time_budget_exceeded,
        )
