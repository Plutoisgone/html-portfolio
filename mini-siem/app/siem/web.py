"""Pages: login, dashboard, user admin, audit log."""
from __future__ import annotations

import re
from contextlib import contextmanager
from uuid import UUID
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from . import audit, db
from .auth import ROLES, _ua, check_csrf, client_ip, current_user, require_role
from .security import SESSION_COOKIE

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
router = APIRouter()

EMAIL_RE = re.compile(r"^[a-z0-9._%+\-']{1,64}@[a-z0-9.\-]{1,190}\.[a-z]{2,24}$")
ERRORS = {
    "sso": "Sign-in with Microsoft failed. Try again.",
    "denied": "Your account is not allowed to use this system. Ask a super admin to add you.",
    "breakglass": "That break-glass code is invalid, expired or already used.",
}


def render(request: Request, name: str, **ctx) -> HTMLResponse:
    return templates.TemplateResponse(request, name, ctx)


@router.get("/healthz", include_in_schema=False)
def healthz():
    db.fetch_one("SELECT 1")
    return {"status": "ok"}


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str | None = None):
    return render(request, "login.html", error=ERRORS.get(error or ""))


@router.get("/breakglass", response_class=HTMLResponse)
def breakglass_page(request: Request):
    return render(request, "breakglass.html")


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: dict = Depends(current_user)):
    return render(request, "dashboard.html", user=user)


# ------------------------------------------------------------------ users
@contextmanager
def admin_tx(request: Request):
    """One transaction for a privileged change and its audit record.

    The change itself runs inside a SECURITY DEFINER function that re-authenticates
    the caller's raw session token as an active super admin. A deferred database
    trigger refuses to commit the change unless a matching audit record was
    written in the same transaction, so a failing audit write rolls everything back.
    """
    import psycopg.errors as pge
    token = request.cookies.get(SESSION_COOKIE, "")
    idle = request.app.state.settings.session_idle_minutes
    try:
        with db.tx() as conn:
            yield conn, token, idle
    except pge.InsufficientPrivilege:
        raise HTTPException(status_code=403)
    except pge.UniqueViolation:
        raise HTTPException(status_code=409, detail="User already exists")
    except pge.NoDataFound:
        raise HTTPException(status_code=404)
    except pge.RaiseException as exc:
        raise HTTPException(status_code=400, detail=_db_message(exc))


def _db_message(exc) -> str:
    known = {"You cannot change your own role", "You cannot deactivate yourself",
             "At least one super admin must stay active"}
    msg = (getattr(exc.diag, "message_primary", "") or "").strip()
    return msg if msg in known else "Request rejected"


@router.get("/admin/users", response_class=HTMLResponse)
def users_page(request: Request, user: dict = Depends(require_role("super_admin"))):
    users = db.fetch_all(
        "SELECT id, email, role, active, entra_oid, last_login_at FROM users ORDER BY email"
    )
    return render(request, "users.html", user=user, users=users, roles=ROLES)


@router.post("/admin/users")
def add_user(request: Request, email: str = Form(...), role: str = Form(...),
             entra_oid: str = Form(...), csrf: str = Form(""), user: dict = Depends(require_role("super_admin"))):
    check_csrf(user, csrf)
    try:
        entra_oid = str(UUID(entra_oid))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Entra object ID")
    email = email.strip().lower()
    if len(email) > 254 or not EMAIL_RE.fullmatch(email) or role not in ROLES:
        raise HTTPException(status_code=400, detail="Invalid email or role")
    with admin_tx(request) as (conn, token, idle):
        if conn.execute("SELECT 1 FROM users WHERE email = %s OR entra_oid = %s", (email, entra_oid)).fetchone():
            raise HTTPException(status_code=409, detail="User already exists")
        conn.execute("SELECT admin_create_user(%s, %s, %s, %s, %s)", (token, idle, email, entra_oid, role))
        audit.write(user["email"], "user.created", target=email, ip=client_ip(request),
                    user_agent=_ua(request), details={"role": role, "oid": entra_oid}, conn=conn)
    return RedirectResponse("/admin/users", status_code=303)


@router.post("/admin/users/{user_id}/role")
def change_role(request: Request, user_id: int, role: str = Form(...), csrf: str = Form(""),
                user: dict = Depends(require_role("super_admin"))):
    check_csrf(user, csrf)
    if role not in ROLES:
        raise HTTPException(status_code=400)
    if user_id == user["user_id"]:
        raise HTTPException(status_code=400, detail="You cannot change your own role")
    with admin_tx(request) as (conn, token, idle):
        target = conn.execute("SELECT email, old_role FROM admin_set_role(%s, %s, %s, %s)",
                              (token, idle, user_id, role)).fetchone()
        audit.write(user["email"], "user.role_changed", target=target["email"], ip=client_ip(request),
                    user_agent=_ua(request), details={"from": target["old_role"], "to": role}, conn=conn)
    return RedirectResponse("/admin/users", status_code=303)


@router.post("/admin/users/{user_id}/active")
def set_active(request: Request, user_id: int, active: str = Form(...), csrf: str = Form(""),
               user: dict = Depends(require_role("super_admin"))):
    check_csrf(user, csrf)
    if active not in ("true", "false"):
        raise HTTPException(status_code=400)
    make_active = active == "true"
    if user_id == user["user_id"]:
        raise HTTPException(status_code=400, detail="You cannot deactivate yourself")
    with admin_tx(request) as (conn, token, idle):
        email = conn.execute("SELECT admin_set_active(%s, %s, %s, %s) AS email",
                             (token, idle, user_id, make_active)).fetchone()["email"]
        action = "user.activated" if make_active else "user.deactivated"
        audit.write(user["email"], action, target=email, ip=client_ip(request),
                    user_agent=_ua(request), conn=conn)
    return RedirectResponse("/admin/users", status_code=303)


# ------------------------------------------------------------------ audit
STALE_AFTER_SECONDS = 5 * 60   # worker cycle is 60 s; three+ missed cycles is an alarm


@router.get("/admin/audit", response_class=HTMLResponse)
def audit_page(request: Request, user: dict = Depends(require_role("super_admin"))):
    rows = db.fetch_all(
        "SELECT id, ts, actor, action, target, severity, ip FROM audit_log ORDER BY id DESC LIMIT 200"
    )
    ok, bad = audit.verify_recent()
    status = db.fetch_one(
        "SELECT checked_at, ok, full_scan, checkpoint_id, detail, "
        "extract(epoch FROM clock_timestamp() - checked_at) AS age FROM audit_verification "
        "ORDER BY id DESC LIMIT 1")
    last_ok = db.fetch_one("SELECT checked_at FROM audit_verification WHERE ok ORDER BY id DESC LIMIT 1")
    worker_state = ("missing" if status is None else "failed" if not status["ok"]
                    else "stale" if status["age"] > STALE_AFTER_SECONDS else "ok")
    audit.write(user["email"], "audit.viewed", ip=client_ip(request), user_agent=_ua(request))
    return render(request, "audit.html", user=user, rows=rows, chain_ok=ok, bad_id=bad,
                  worker=status, worker_state=worker_state, last_ok=last_ok)


@router.get('/events', response_class=HTMLResponse)
def event_page(request: Request, source: str = '', term: str = '', rule: str = '',
               user: dict = Depends(require_role('super_admin'))):
    # The initial event store is deliberately single-tenant. No customer role
    # is permitted to see global event data or source names.
    from .event_query import search_query
    from .events import RULES
    if user['via'] != 'sso':
        raise HTTPException(status_code=403)
    try:
        query, params = search_query(source, term, rule)
    except ValueError:
        raise HTTPException(status_code=400, detail='Invalid event filter')
    with db.tx() as conn:
        conn.execute("SET LOCAL statement_timeout = '3s'")
        rows = conn.execute(query, params).fetchall()
        audit.write(user['email'], 'events.viewed', ip=client_ip(request),
                    user_agent=_ua(request), conn=conn)
    return render(request, 'events.html', user=user, rows=rows, source=source,
                  term=term, rule=rule, rules=RULES)
