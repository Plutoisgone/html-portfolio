"""Authentication: Entra ID single sign-on, server-side sessions, roles, break-glass.

- Normal users sign in with Entra ID (OIDC authorization code flow + PKCE).
  MFA and device rules are enforced by Entra Conditional Access.
- Only users already registered in the app (or listed as initial super admins)
  can sign in. Everyone else is denied and the attempt is audited.
- Sessions are random tokens; only their SHA-256 hash is stored.
- Break-glass: a one-time link created from the server's command line (needs
  SSH from the management network). There is no password login to attack.
- Sessions are CREATED only by the separate login service (`siem.auth_main`), which
  alone holds the DB role allowed to INSERT into `sessions` (N12). The web app
  (`siem.main`) imports this module only to authenticate existing sessions.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable
from uuid import UUID
from contextlib import nullcontext

import logging
import warnings

import httpx
from authlib.integrations.starlette_client import OAuth, OAuthError
from joserfc.errors import JoseError as JoserfcError

with warnings.catch_warnings():  # authlib.jose is deprecated but still raises these types
    warnings.simplefilter("ignore")
    from authlib.jose.errors import JoseError

log = logging.getLogger("siem.auth")
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from . import audit, db
from .config import Settings
from .security import SESSION_COOKIE, csrf_ok, hash_token, new_token

ROLES = ("super_admin", "client_admin", "analyst", "read_only")
BREAKGLASS_SESSION_HOURS = 1
BREAKGLASS_TOKEN_MINUTES = 10

router = APIRouter()
oauth = OAuth()


def setup_oauth(settings: Settings) -> None:
    oauth.register(
        name="entra",
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret,
        server_metadata_url=settings.oidc_metadata_url,
        client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"},
    )


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _ua(request: Request) -> str:
    return request.headers.get("user-agent", "")[:300]


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------ sessions
def create_session(response: Response, request: Request, user_id: int, via: str,
                   settings: Settings, conn=None) -> None:
    token = new_token()
    hours = BREAKGLASS_SESSION_HOURS if via == "breakglass" else settings.session_absolute_hours
    with (db.tx() if conn is None else nullcontext(conn)) as conn:
        old = request.cookies.get(SESSION_COOKIE)
        if old and len(old) <= 100:
            conn.execute("DELETE FROM sessions WHERE id_hash=%s", (hash_token(old),))
        conn.execute(
            """INSERT INTO sessions (id_hash, user_id, csrf_token, via, ip, user_agent, expires_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (hash_token(token), user_id, new_token(), via, client_ip(request), _ua(request),
             _now() + timedelta(hours=hours)),
        )
    response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=True, samesite="lax",
                        path="/", max_age=hours * 3600)


_SESSION_READ = """SELECT s.id_hash, s.csrf_token, s.via, s.last_seen_at, s.expires_at,
                          u.id AS user_id, u.email, u.role, u.active
                   FROM sessions s JOIN users u ON u.id = s.user_id
                   WHERE s.id_hash = %s"""
_SESSION_FOR_UPDATE = _SESSION_READ + " FOR UPDATE OF s"


def load_session(request: Request, settings: Settings, touch: bool = True) -> dict | None:
    """Authenticate the session cookie. touch=False is for the login service, whose
    DB role may read and delete sessions but not update them: no row lock and no
    last_seen_at refresh (used by logout, which deletes the row anyway)."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token or len(token) > 100:
        return None
    idle = timedelta(minutes=settings.session_idle_minutes)
    with db.tx() as conn:
        row = conn.execute(_SESSION_FOR_UPDATE if touch else _SESSION_READ,
                           (hash_token(token),)).fetchone()
        if not row:
            return None
        now = _now()
        if not row["active"] or (row["via"] == "breakglass" and row["role"] != "super_admin") or row["expires_at"] <= now or row["last_seen_at"] + idle <= now:
            conn.execute("DELETE FROM sessions WHERE id_hash = %s", (row["id_hash"],))
            return None
        if touch:
            conn.execute("UPDATE sessions SET last_seen_at = %s WHERE id_hash = %s",
                         (now, row["id_hash"]))
    return row


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def current_user(request: Request, settings: Settings = Depends(get_settings)) -> dict:
    sess = load_session(request, settings)
    if sess is None:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    request.state.user = sess
    return sess


def logout_user(request: Request, settings: Settings = Depends(get_settings)) -> dict:
    """current_user for the login service: same checks, read-only on the session row."""
    sess = load_session(request, settings, touch=False)
    if sess is None:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    request.state.user = sess
    return sess


def require_role(*roles: str) -> Callable[..., dict]:
    for r in roles:
        if r not in ROLES:
            raise ValueError(f"Unknown role {r}")

    def dep(user: dict = Depends(current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return dep


def check_csrf(user: dict, token: str | None) -> None:
    if not csrf_ok(user["csrf_token"], token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


# ------------------------------------------------------------------ SSO login
def resolve_user(claims: dict, settings: Settings, conn=None) -> tuple[dict | None, str]:
    """Map validated ID-token claims to an app user. Returns (user, reason)."""
    if claims.get("tid") != settings.oidc_tenant_id:
        return None, "wrong_tenant"
    if settings.require_mfa_claim and "mfa" not in (claims.get("amr") or []):
        return None, "mfa_missing"
    oid = claims.get("oid")
    # UPN is display metadata only; it never authorizes an identity.
    upn = (claims.get("preferred_username") or "").strip().lower()
    try:
        oid = str(UUID(str(oid)))
    except (ValueError, TypeError):
        return None, "missing_claims"
    if not upn or len(upn) > 254:
        return None, "missing_claims"

    with (db.tx() if conn is None else nullcontext(conn)) as conn:
        conn.execute("SELECT pg_advisory_xact_lock(7313)")
        user = conn.execute("SELECT * FROM users WHERE entra_oid = %s", (oid,)).fetchone()
        if user is None:
            if oid in settings.initial_super_admins and not conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                # Only possible while the users table is empty (enforced in the DB function).
                user = conn.execute("SELECT * FROM bootstrap_first_admin(%s, %s)", (oid, upn)).fetchone()
                if user is not None:
                    audit.write("bootstrap", "user.created", target=upn,
                                details={"role": "super_admin", "oid": oid}, conn=conn)
        if user is None:
            return None, "not_registered"
        if not user["active"]:
            return None, "inactive"
        conn.execute("UPDATE users SET last_login_at = now() WHERE id = %s", (user["id"],))
    return user, "ok"


@router.get("/auth/login")
async def login(request: Request, settings: Settings = Depends(get_settings)):
    redirect_uri = f"{settings.base_url}/auth/callback"
    return await oauth.entra.authorize_redirect(request, redirect_uri, prompt="select_account")


@router.get("/auth/callback")
async def callback(request: Request, settings: Settings = Depends(get_settings)):
    ip, ua = client_ip(request), _ua(request)
    try:
        token = await oauth.entra.authorize_access_token(request)
    except Exception as exc:  # noqa: BLE001 - every validation failure must fail closed AND be audited
        # Authlib >= 1.6 decodes ID tokens with joserfc, whose errors are not
        # authlib.jose.errors.JoseError subclasses; catching only those turned every
        # forged/expired token into an unaudited HTTP 500. Classify for the audit
        # record without echoing attacker-controlled text.
        kind = ("oauth" if isinstance(exc, OAuthError) else
                "token_validation" if isinstance(exc, (JoseError, JoserfcError, ValueError)) else
                "idp_unreachable" if isinstance(exc, httpx.HTTPError) else "unexpected")
        if kind == "unexpected":
            log.error("SSO callback failed unexpectedly (%s)", type(exc).__name__)
        await run_in_threadpool(audit.write, "anonymous", "auth.login.failed", ip=ip, user_agent=ua,
                                details={"error": type(exc).__name__, "kind": kind}, severity="warning")
        return RedirectResponse("/login?error=sso", status_code=303)
    claims = token.get("userinfo") or {}
    # Authlib validates the ID token, including nonce, via its OIDC flow.
    if (not token.get("id_token") or claims.get("iss") != f"https://login.microsoftonline.com/{settings.oidc_tenant_id}/v2.0"
            or claims.get("aud") != settings.oidc_client_id or not claims.get("nonce")
            or type(claims.get("exp")) is not int or claims["exp"] <= int(_now().timestamp())):
        await run_in_threadpool(audit.write, "anonymous", "auth.login.denied", ip=ip, details={"reason": "invalid_oidc_claims"})
        return RedirectResponse("/login?error=denied", status_code=303)
    request.session.clear()
    return await run_in_threadpool(finish_sso, request, settings, claims, ip, ua)


def finish_sso(request, settings, claims, ip, ua):
    with db.tx() as conn:
        user, reason = resolve_user(claims, settings, conn=conn)
        if user is None:
            audit.write("anonymous", "auth.login.denied", ip=ip, user_agent=ua, details={"reason": reason}, conn=conn)
            return RedirectResponse("/login?error=denied", status_code=303)
        response = RedirectResponse("/", status_code=303)
        create_session(response, request, user["id"], "sso", settings, conn=conn)
        audit.write(user["email"], "auth.login", ip=ip, user_agent=ua, conn=conn)
    return response


@router.post("/auth/logout")
def logout(request: Request, csrf: str = Form(""), user: dict = Depends(logout_user)):
    check_csrf(user, csrf)
    with db.tx() as conn:
        conn.execute("DELETE FROM sessions WHERE id_hash = %s", (user["id_hash"],))
        audit.write(user["email"], "auth.logout", ip=client_ip(request), user_agent=_ua(request), conn=conn)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True)
    return response


# ------------------------------------------------------------------ break-glass
def create_breakglass_token(email: str) -> str:
    """CLI only. Requires the dedicated emergency DB role."""
    email = email.strip().lower()
    token = new_token()
    with db.tx() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(7313)")
        user = conn.execute("SELECT id, role, active FROM users WHERE email=%s", (email,)).fetchone()
        if not user or not user["active"] or user["role"] != "super_admin":
            raise ValueError("Break-glass is only for an existing, active super admin.")
        conn.execute("INSERT INTO breakglass_tokens (token_hash, user_id, expires_at) VALUES (%s,%s,%s)",
                     (hash_token(token), user["id"], _now()+timedelta(minutes=BREAKGLASS_TOKEN_MINUTES)))
        audit.write("cli", "auth.breakglass.token_created", target=email, conn=conn)
    return token


@router.post("/auth/breakglass")
def breakglass_consume(request: Request, token: str = Form(""),
                             settings: Settings = Depends(get_settings)):
    ip, ua = client_ip(request), _ua(request)
    if not token or len(token) > 100:
        raise HTTPException(status_code=400)
    with db.tx() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(7313)")
        row = conn.execute("SELECT * FROM consume_breakglass(%s)", (hash_token(token),)).fetchone()
        if not row:
            audit.write("anonymous", "auth.breakglass.failed", ip=ip, user_agent=ua, severity="critical", conn=conn)
            return RedirectResponse("/login?error=breakglass", status_code=303)
        response = RedirectResponse("/", status_code=303)
        create_session(response, request, row["id"], "breakglass", settings, conn=conn)
        audit.write(row["email"], "auth.breakglass.login", ip=ip, user_agent=ua, conn=conn)
    return response
