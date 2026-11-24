"""Application entry point: `uvicorn --factory siem.main:create_app`."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import auth, db, web
from .config import load_settings
from .security import RateLimitMiddleware, SecurityHeadersMiddleware, RequestBoundaryMiddleware

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


def create_app():
    settings = load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db.init_pool(settings.db_dsn)
        yield
        db.close_pool()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.settings = settings
    auth.setup_oauth(settings)

    # Order: last added runs first.
    # Short-lived signed cookie that only holds OIDC state/nonce during sign-in.
    app.add_middleware(SessionMiddleware, secret_key=settings.session_secret,
                       session_cookie="__Host-oidc", max_age=600, same_site="lax",
                       https_only=True)
    app.add_middleware(RequestBoundaryMiddleware, origin=settings.base_url)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[settings.hostname, "127.0.0.1"])

    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")),
              name="static")
    app.include_router(auth.router)
    app.include_router(web.router)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        if exc.status_code in (301, 302, 303, 307) and exc.headers:
            return RedirectResponse(exc.headers["Location"], status_code=303)
        messages = {400: "Bad request.", 403: "You don't have permission to do that.",
                    404: "Page not found.", 409: "That already exists."}
        message = exc.detail if exc.status_code in (400, 409) and isinstance(exc.detail, str) \
            else messages.get(exc.status_code, "Something went wrong.")
        return web.templates.TemplateResponse(
            request, "error.html",
            {"status": exc.status_code, "message": message,
             "user": getattr(request.state, "user", None)},
            status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        return web.templates.TemplateResponse(
            request, "error.html", {"status": 400, "message": "Bad request.", "user": None},
            status_code=400)

    return SecurityHeadersMiddleware(app)

