from fastapi import FastAPI

from analyzer.api.router import router
from analyzer.config import get_settings


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url="/docs",
        openapi_url="/openapi.json",
    )
    app.include_router(router)
    return app


app = create_app()
