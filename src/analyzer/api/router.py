from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException

from analyzer.api.dependencies import get_orchestrator
from analyzer.api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    AsyncAnalyzeResponse,
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
    rules = get_rules_for_language(language) if language else get_all_rules()
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


@router.post("/analyze/async", response_model=AsyncAnalyzeResponse)
async def analyze_async(request: AnalyzeRequest) -> AsyncAnalyzeResponse:
    from analyzer.workers.tasks import run_async_scan

    scan_id = str(uuid4())
    task = run_async_scan.delay(
        source_code=request.source_code,
        file_path=request.file_path,
        scan_id=scan_id,
        config=request.config.model_dump(),
    )
    return AsyncAnalyzeResponse(
        task_id=task.id,
        scan_id=UUID(scan_id),
        status="queued",
        poll_url=f"/api/v1/results/{scan_id}",
    )


@router.get("/results/{scan_id}")
async def get_results(scan_id: str) -> dict:  # type: ignore[type-arg]
    return {"scan_id": scan_id, "status": "pending", "message": "Full persistence TBD"}


@router.get("/health", response_model=HealthResponse)
async def health(settings: Annotated[Settings, Depends(get_settings)]) -> HealthResponse:
    return HealthResponse(
        status="healthy",
        version=settings.app_version,
        rules_loaded=len(get_all_rules()),
    )
