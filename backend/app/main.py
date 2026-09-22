import logging

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import settings
from .fw import FwError
from .routers import audit, auth, catalog, ops, richrules, status, zones


def create_app() -> FastAPI:
    app = FastAPI(title="richrule", docs_url="/api/docs", openapi_url="/api/openapi.json")

    @app.exception_handler(FwError)
    async def fw_error(request: Request, exc: FwError):
        return JSONResponse({"detail": exc.message}, status_code=exc.status)

    for r in (auth, status, zones, ops, richrules, catalog, audit):
        app.include_router(r.router)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
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

    uvicorn.run(app, host=settings.host, port=settings.port, proxy_headers=False)


if __name__ == "__main__":
    run()
