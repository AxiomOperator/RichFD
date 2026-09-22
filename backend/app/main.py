import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import settings
from .fw import FwError
from . import scheduler
from .history import history
from .routers import (
    analysis,
    audit,
    auth,
    catalog,
    history as history_router,
    hosts,
    ops,
    policies,
    richrules,
    status,
    templates,
    tools,
    transfer,
    zones,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    history.start()
    scheduler.start()
    yield
    history.stop()
    scheduler.stop()


def create_app(watch: bool = True) -> FastAPI:
    app = FastAPI(title="richrule", docs_url="/api/docs", openapi_url="/api/openapi.json",
                  lifespan=lifespan if watch else None)

    @app.exception_handler(FwError)
    async def fw_error(request: Request, exc: FwError):
        return JSONResponse({"detail": exc.message}, status_code=exc.status)

    for r in (auth, status, zones, policies, ops, richrules, catalog, audit, history_router, analysis,
              transfer, templates, tools, hosts):
        app.include_router(r.router)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        if settings.tls_cert:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        if request.url.path.startswith("/api"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    # Serve the built SPA; unknown non-API paths fall back to index.html for client routing.
    dist = settings.static_dir
    if (dist / "index.html").exists():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        async def spa(path: str):
            if path.startswith("api/"):
                return JSONResponse({"detail": "Not Found"}, status_code=404)
            candidate = (dist / path).resolve()
            if path and candidate.is_file() and candidate.is_relative_to(dist.resolve()):
                return FileResponse(candidate)
            return FileResponse(dist / "index.html")
    else:
        logging.getLogger("richrule").warning(
            "frontend not built (%s missing); serving API only", dist / "index.html"
        )

    return app


app = create_app()


def run() -> None:
    import uvicorn

    tls = {}
    if settings.tls_cert:
        if not settings.tls_key:
            raise SystemExit("RICHRULE_TLS_CERT is set but RICHRULE_TLS_KEY is not")
        tls = {"ssl_certfile": settings.tls_cert, "ssl_keyfile": settings.tls_key}
    uvicorn.run(app, host=settings.host, port=settings.port, proxy_headers=False, **tls)


if __name__ == "__main__":
    run()
