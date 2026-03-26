from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from analyzer.core.severity import Confidence, Severity


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    cwe_id: str
    owasp: str
    description: str
    remediation: str


@dataclass
class AnalysisContext:
    source_code: str
    file_path: str
    tree: Any  # tree_sitter.Tree
    root_node: Any  # tree_sitter.Node
    lines: list[str]
    language: str  # "javascript" | "typescript" | "jsx" | "tsx"


@dataclass
class RawFinding:
    rule_id: str
    line_start: int
    line_end: int
    column: int | None = None
    code_snippet: str = ""
    extra_info: str = ""
    file_path: str | None = None


class BaseRule(ABC):
    @abstractmethod
    def meta(self) -> RuleMeta: ...

    @abstractmethod
    def run(self, context: AnalysisContext) -> list[RawFinding]: ...

    def should_skip(self, context: AnalysisContext) -> bool:
        return False

    def _snippet(self, context: AnalysisContext, line: int, radius: int = 0) -> str:
        start = max(0, line - 1 - radius)
        end = min(len(context.lines), line + radius)
        return "\n".join(context.lines[start:end])
