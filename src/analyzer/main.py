from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from analyzer.api.router import router
from analyzer.config import get_settings


def _ensure_api_key_policy() -> None:
    """Non-debug deployments must set ANALYZER_API_KEY."""
    settings = get_settings()
    if settings.debug:
        return
    if not (settings.api_key and settings.api_key.strip()):
        msg = "ANALYZER_API_KEY is required unless ANALYZER_DEBUG=true"
        raise RuntimeError(msg)


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    _ensure_api_key_policy()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    docs_url = "/docs" if settings.debug else None
    openapi_url = "/openapi.json" if settings.debug else None
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url=docs_url,
        openapi_url=openapi_url,
        lifespan=_lifespan,
    )
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    app.include_router(router)
    return app


app = create_app()
