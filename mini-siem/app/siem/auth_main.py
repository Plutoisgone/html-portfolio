"""Login service entry point: `uvicorn --factory siem.auth_main:create_app`.

The only process that creates sessions (N12). It connects as the dedicated
login-service DB role (SIEM_DB_AUTH_USER), the only role with INSERT on
`sessions` and EXECUTE on `bootstrap_first_admin` / `consume_breakglass`, and it
alone holds the OIDC client secret and the OIDC state-cookie key. It serves only
/auth/login, /auth/callback, /auth/logout, /auth/breakglass and /healthz; Caddy
routes /auth/* here and everything else to the web app.
"""
from __future__ import annotations

from fastapi import APIRouter

from . import auth, db
from .config import load_auth_settings
from .main import base_app
from .security import SecurityHeadersMiddleware

health = APIRouter()


@health.get("/healthz", include_in_schema=False)
def healthz():
    db.fetch_one("SELECT 1")
    return {"status": "ok"}


def create_app():
    settings = load_auth_settings()
    app = base_app(settings, oidc_state_cookie=True)
    auth.setup_oauth(settings)
    app.include_router(auth.router)
    app.include_router(health)
    return SecurityHeadersMiddleware(app)
