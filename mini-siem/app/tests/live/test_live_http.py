"""LIVE: HTTP, session, authorization and break-glass tests through Caddy -> app -> PostgreSQL.

Real requests over TLS to the deployed lab. Entra ID sign-in itself cannot be
exercised without a real tenant, so tests that need an SSO session insert a
session row directly (as the bootstrap superuser) and say so in their name:
"simulated_sso_session". Break-glass sessions are created through the real
CLI + HTTP flow.
"""
from __future__ import annotations

import concurrent.futures as cf
import hashlib
import re
import secrets
import time
import uuid

import pytest

pytestmark = pytest.mark.live

BOSS = ("boss@lab.test", "33333333-3333-4333-8333-333333333333")
ADMIN2 = ("admin2@lab.test", "44444444-4444-4444-8444-444444444444")
ANALYST = ("analyst@lab.test", "55555555-5555-4555-8555-555555555555")
HEADERS = ["content-security-policy", "strict-transport-security", "x-frame-options",
           "x-content-type-options", "referrer-policy", "permissions-policy",
           "cross-origin-opener-policy", "cache-control"]


@pytest.fixture(autouse=True)
def known_users(lab):
    """Reset the lab users (triggers bypassed: this is test setup, not app behaviour)."""
    rows = ",".join(f"('{e}','{o}','{r}')" for (e, o), r in
                    [(BOSS, "super_admin"), (ADMIN2, "super_admin"), (ANALYST, "analyst")])
    lab.bootstrap_sql(f"""
        SET session_replication_role = replica;
        DELETE FROM users WHERE email LIKE 'live-%';
        INSERT INTO users(email,entra_oid,role) VALUES {rows}
        ON CONFLICT (email) DO UPDATE SET role=EXCLUDED.role, active=true;
        DELETE FROM sessions; DELETE FROM breakglass_tokens;""")
    time.sleep(1.1)  # stay clear of the per-IP auth limiter between tests


def auth_post(c, path, **kw):
    """POST to /auth/*, waiting out the per-IP auth rate limiter (all tests share one source IP)."""
    for _ in range(40):
        r = c.post(path, **kw)
        if r.status_code != 429:
            return r
        time.sleep(3)
    return r


def simulated_sso_session(lab, email: str, via: str = "sso") -> tuple[str, str]:
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    h = hashlib.sha256(token.encode()).hexdigest()
    lab.bootstrap_sql(f"""INSERT INTO sessions(id_hash,user_id,csrf_token,via,expires_at)
        SELECT '\\x{h}', id, '{csrf}', '{via}', now()+interval '1 hour' FROM users WHERE email='{email}';""")
    return token, csrf


def client_for(lab, token=None):
    c = lab.http()
    if token:
        c.cookies.set("__Host-siem", token, domain=lab.url.split("//")[1])
    return c


def breakglass_login(lab, email):
    code = lab.breakglass_code(email)
    c = lab.http()
    r = auth_post(c, "/auth/breakglass", data={"token": code})
    assert r.status_code == 303 and r.headers["location"] == "/", r.text
    page = c.get("/admin/users")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    return c, csrf, code


def user_id(lab, email):
    return int(lab.bootstrap_sql(f"SELECT id FROM users WHERE email='{email}'"))


# ------------------------------------------------------------------ headers
@pytest.mark.parametrize("path,expected", [("/login", 200), ("/", 303), ("/nope", 404),
                                           ("/admin/users", 303), ("/static/style.css", 200)])
def test_security_headers_on_app_responses(lab, path, expected):
    r = lab.http().get(path)
    assert r.status_code == expected
    missing = [h for h in HEADERS if h not in r.headers]
    assert not missing, f"{path} {r.status_code} missing {missing}"
    assert "uvicorn" not in r.headers.get("server", "").lower()


def test_security_headers_on_proxy_generated_413(lab):
    r = auth_post(lab.http(), "/auth/breakglass", content=b"token=" + b"a" * 40000,
                        headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 413
    assert not [h for h in HEADERS if h not in r.headers], dict(r.headers)


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"])
def test_unsupported_methods_rejected_with_headers(lab, method):
    r = lab.http().request(method, "/login")
    assert r.status_code in (405, 404)
    assert "content-security-policy" in r.headers


# ------------------------------------------------------------------ CSRF / origin
@pytest.mark.parametrize("origin", [None, "null", "https://evil.test", "http://siem.lab.test"])
def test_cross_origin_state_change_rejected(lab, origin):
    token, csrf = simulated_sso_session(lab, BOSS[0])
    c = client_for(lab, token)
    headers = {} if origin is None else {"Origin": origin}
    if origin is None:
        c.headers.pop("Origin")
    r = c.post(f"/admin/users/{user_id(lab, ANALYST[0])}/role", data={"role": "super_admin", "csrf": csrf},
               headers=headers)
    assert r.status_code == 403
    assert lab.bootstrap_sql(f"SELECT role FROM users WHERE email='{ANALYST[0]}'") == "analyst"


def test_missing_csrf_token_rejected(lab):
    token, _ = simulated_sso_session(lab, BOSS[0])
    r = client_for(lab, token).post(f"/admin/users/{user_id(lab, ANALYST[0])}/role", data={"role": "super_admin"})
    assert r.status_code == 403
    assert lab.bootstrap_sql(f"SELECT role FROM users WHERE email='{ANALYST[0]}'") == "analyst"


# ------------------------------------------------------------------ authorization
@pytest.mark.parametrize("path", ["/admin/users", "/admin/audit", "/events"])
def test_non_admin_denied_simulated_sso_session(lab, path):
    token, _ = simulated_sso_session(lab, ANALYST[0])
    assert client_for(lab, token).get(path).status_code == 403


def test_non_admin_cannot_post_admin_actions_simulated_sso_session(lab):
    token, csrf = simulated_sso_session(lab, ANALYST[0])
    r = client_for(lab, token).post(f"/admin/users/{user_id(lab, ANALYST[0])}/role",
                                    data={"role": "super_admin", "csrf": csrf})
    assert r.status_code == 403
    assert lab.bootstrap_sql(f"SELECT role FROM users WHERE email='{ANALYST[0]}'") == "analyst"


def test_forged_and_garbage_cookies_rejected(lab):
    for value in ["", "x", secrets.token_urlsafe(32), "' OR 1=1 --", "A" * 200]:
        assert client_for(lab, value).get("/admin/users").status_code == 303


def test_breakglass_session_cannot_open_event_console(lab):
    c, _, _ = breakglass_login(lab, BOSS[0])
    assert c.get("/events").status_code == 403


# ------------------------------------------------------------------ break-glass
def test_breakglass_single_use(lab):
    code = lab.breakglass_code(BOSS[0])
    c = lab.http()
    assert auth_post(c, "/auth/breakglass", data={"token": code}).headers["location"] == "/"
    assert auth_post(lab.http(), "/auth/breakglass", data={"token": code}).headers["location"] == "/login?error=breakglass"


def test_breakglass_token_revoked_on_demotion(lab):
    code = lab.breakglass_code(ADMIN2[0])
    boss, csrf, _ = breakglass_login(lab, BOSS[0])
    r = boss.post(f"/admin/users/{user_id(lab, ADMIN2[0])}/role", data={"role": "analyst", "csrf": csrf})
    assert r.status_code == 303
    r = auth_post(lab.http(), "/auth/breakglass", data={"token": code})
    assert r.headers["location"] == "/login?error=breakglass"
    assert lab.bootstrap_sql(f"SELECT count(*) FROM breakglass_tokens t JOIN users u ON u.id=t.user_id WHERE u.email='{ADMIN2[0]}'") == "0"


def test_breakglass_token_revoked_on_deactivation(lab):
    code = lab.breakglass_code(ADMIN2[0])
    boss, csrf, _ = breakglass_login(lab, BOSS[0])
    assert boss.post(f"/admin/users/{user_id(lab, ADMIN2[0])}/active", data={"active": "false", "csrf": csrf}).status_code == 303
    assert auth_post(lab.http(), "/auth/breakglass", data={"token": code}).headers["location"] == "/login?error=breakglass"


def test_breakglass_token_revoked_on_deletion(lab):
    code = lab.breakglass_code(ADMIN2[0])
    lab.bootstrap_sql(f"SET session_replication_role = replica; DELETE FROM users WHERE email='{ADMIN2[0]}';")
    assert auth_post(lab.http(), "/auth/breakglass", data={"token": code}).headers["location"] == "/login?error=breakglass"


def test_breakglass_token_expired_rejected(lab):
    code = lab.breakglass_code(BOSS[0])
    h = hashlib.sha256(code.encode()).hexdigest()
    lab.bootstrap_sql(f"SET session_replication_role = replica; UPDATE breakglass_tokens SET created_at=now()-interval '20 minutes', expires_at=now()-interval '10 minutes' WHERE token_hash='\\x{h}';")
    assert auth_post(lab.http(), "/auth/breakglass", data={"token": code}).headers["location"] == "/login?error=breakglass"


def test_breakglass_cli_refuses_non_admin(lab):
    with pytest.raises(RuntimeError):
        lab.breakglass_code(ANALYST[0])


def test_concurrent_breakglass_consumption_single_winner(lab):
    code = lab.breakglass_code(BOSS[0])
    def attempt(_):
        return auth_post(lab.http(), "/auth/breakglass", data={"token": code}).headers.get("location")
    with cf.ThreadPoolExecutor(8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert results.count("/") == 1, results


# ------------------------------------------------------------------ sessions
def test_session_revoked_after_role_change(lab):
    victim_token, _ = simulated_sso_session(lab, ADMIN2[0])
    boss, csrf, _ = breakglass_login(lab, BOSS[0])
    assert client_for(lab, victim_token).get("/admin/users").status_code == 200
    boss.post(f"/admin/users/{user_id(lab, ADMIN2[0])}/role", data={"role": "read_only", "csrf": csrf})
    assert client_for(lab, victim_token).get("/admin/users").status_code == 303


def test_session_fixation_prevented(lab):
    planted = secrets.token_urlsafe(32)
    code = lab.breakglass_code(BOSS[0])
    c = client_for(lab, planted)
    r = auth_post(c, "/auth/breakglass", data={"token": code})
    issued = r.cookies.get("__Host-siem")
    assert issued and issued != planted
    cookie = r.headers["set-cookie"].lower()
    for flag in ["secure", "httponly", "samesite=lax", "path=/"]:
        assert flag in cookie
    assert "domain=" not in cookie  # __Host- prefix requirement


def test_logout_invalidates_server_side(lab):
    c, csrf, _ = breakglass_login(lab, BOSS[0])
    token = c.cookies.get("__Host-siem")
    assert auth_post(c, "/auth/logout", data={"csrf": csrf}).status_code == 303
    assert client_for(lab, token).get("/").status_code == 303


def test_idle_timeout_enforced(lab):
    token, _ = simulated_sso_session(lab, BOSS[0])
    h = hashlib.sha256(token.encode()).hexdigest()
    lab.bootstrap_sql(f"UPDATE sessions SET last_seen_at=now()-interval '2 hours' WHERE id_hash='\\x{h}'")
    assert client_for(lab, token).get("/").status_code == 303


# ------------------------------------------------------------------ races
def test_last_super_admin_race(lab):
    """Two super admins deactivate each other at the same instant; at least one must survive."""
    a, a_csrf, _ = breakglass_login(lab, BOSS[0])
    b, b_csrf, _ = breakglass_login(lab, ADMIN2[0])
    with cf.ThreadPoolExecutor(2) as pool:
        fa = pool.submit(a.post, f"/admin/users/{user_id(lab, ADMIN2[0])}/active", data={"active": "false", "csrf": a_csrf})
        fb = pool.submit(b.post, f"/admin/users/{user_id(lab, BOSS[0])}/active", data={"active": "false", "csrf": b_csrf})
        fa.result(), fb.result()
    assert int(lab.bootstrap_sql("SELECT count(*) FROM users WHERE role='super_admin' AND active")) >= 1


# ------------------------------------------------------------------ input handling
@pytest.mark.parametrize("path", ["/static/../siem/config.py", "/static/%2e%2e/siem/config.py",
                                  "/static/..%2fsiem%2fconfig.py", "/static//etc/passwd",
                                  "/static/%2e%2e%2f%2e%2e%2fetc%2fpasswd"])
def test_static_path_traversal(lab, path):
    r = lab.http().get(path)
    assert r.status_code in (400, 404)
    assert "SECRETS_DIR" not in r.text and "root:x:" not in r.text


@pytest.mark.parametrize("term", ["' OR 1=1 --", "%' UNION SELECT entra_oid FROM users --", "\\x00",
                                  "<script>alert(1)</script>", "a" * 128])
def test_event_search_injection_simulated_sso_session(lab, term):
    token, _ = simulated_sso_session(lab, BOSS[0])
    r = client_for(lab, token).get("/events", params={"term": term})
    assert r.status_code in (200, 400)
    assert "<script>alert(1)</script>" not in r.text
    assert ANALYST[1] not in r.text


def test_stored_xss_in_event_is_escaped_simulated_sso_session(lab):
    marker = uuid.uuid4().hex
    # Insert with the ingest role's privileges (pg_hba only admits that role from the
    # collector network, so use SET ROLE locally rather than a network login).
    lab.bootstrap_sql("SET ROLE siem_ingest; INSERT INTO security_events(source_id,message) VALUES "
                      f"('live-xss', '<script>alert(''{marker}'')</script><img src=x onerror=alert(1)>');")
    token, _ = simulated_sso_session(lab, BOSS[0])
    r = client_for(lab, token).get("/events", params={"source": "live-xss"})
    assert r.status_code == 200 and marker in r.text
    assert "<script>alert(" not in r.text and "<img src=x" not in r.text
    assert "&lt;script&gt;" in r.text


def test_add_user_requires_valid_oid(lab):
    c, csrf, _ = breakglass_login(lab, BOSS[0])
    for oid in ["", "not-a-uuid", "33333333-3333-4333-8333-33333333333", "' OR 1=1"]:
        r = c.post("/admin/users", data={"email": "live-x@lab.test", "role": "analyst", "entra_oid": oid, "csrf": csrf})
        assert r.status_code in (400, 422)


def test_duplicate_oid_rejected(lab):
    c, csrf, _ = breakglass_login(lab, BOSS[0])
    r = c.post("/admin/users", data={"email": "live-dup@lab.test", "role": "super_admin",
                                     "entra_oid": ANALYST[1], "csrf": csrf})
    assert r.status_code == 409


# ------------------------------------------------------------------ atomic audit
@pytest.mark.parametrize("action,path,data,check", [
    ("user.role_changed", "/admin/users/{analyst}/role", {"role": "super_admin"},
     "SELECT role FROM users WHERE email='analyst@lab.test'"),
    ("user.deactivated", "/admin/users/{analyst}/active", {"active": "false"},
     "SELECT active::text FROM users WHERE email='analyst@lab.test'"),
    ("user.created", "/admin/users", {"email": "live-new@lab.test", "role": "analyst",
                                      "entra_oid": "66666666-6666-4666-8666-666666666666"},
     "SELECT count(*) FROM users WHERE email='live-new@lab.test'"),
])
def test_admin_action_rolls_back_when_audit_write_fails(lab, action, path, data, check):
    """Make the mandatory audit INSERT fail; the privileged change must not commit."""
    c, csrf, _ = breakglass_login(lab, BOSS[0])
    before = lab.bootstrap_sql(check)
    lab.bootstrap_sql(f"ALTER TABLE audit_log ADD CONSTRAINT live_force_fail CHECK (action <> '{action}') NOT VALID")
    try:
        r = c.post(path.format(analyst=user_id(lab, ANALYST[0])), data={**data, "csrf": csrf})
        assert r.status_code >= 500 or r.status_code == 400, r.status_code
        assert "content-security-policy" in r.headers
    finally:
        lab.bootstrap_sql("ALTER TABLE audit_log DROP CONSTRAINT live_force_fail")
    assert lab.bootstrap_sql(check) == before, "privileged change committed without its audit record"
