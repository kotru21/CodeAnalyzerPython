from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from analyzer.api.dependencies import get_orchestrator
from analyzer.api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    HealthResponse,
    RuleInfo,
)
from analyzer.config import Settings, get_settings
from analyzer.core.orchestrator import Orchestrator
from analyzer.rules.registry import get_all_rules, get_rules_for_language

router = APIRouter(prefix="/api/v1")


@router.post("/analyze/sync", response_model=AnalyzeResponse)
async def analyze_sync(
    request: AnalyzeRequest,
    orchestrator: Annotated[Orchestrator, Depends(get_orchestrator)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AnalyzeResponse:
    if len(request.source_code.encode()) > settings.max_sync_source_bytes:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Source too large for sync analysis. "
                f"Max: {settings.max_sync_source_bytes} bytes. Use /analyze/async."
            ),
        )
    return orchestrator.analyze_sync(request)


@router.get("/rules", response_model=list[RuleInfo])
async def list_rules(language: str | None = None) -> list[RuleInfo]:
    if language:
        rules = get_rules_for_language(language)
    else:
        rules = get_all_rules()
    return [
        RuleInfo(
            rule_id=r.meta().rule_id,
            title=r.meta().title,
            severity=r.meta().severity,
            confidence=r.meta().confidence,
            cwe_id=r.meta().cwe_id,
            owasp=r.meta().owasp,
            description=r.meta().description,
        )
        for r in rules
    ]


@router.get("/health", response_model=HealthResponse)
async def health(settings: Annotated[Settings, Depends(get_settings)]) -> HealthResponse:
    return HealthResponse(
        status="healthy",
        version=settings.app_version,
        rules_loaded=len(get_all_rules()),
    )
