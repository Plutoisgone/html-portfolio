"""LIVE regression tests for the Phase 0.1 hardening (against the deployed lab).

* Least privilege at the database level, probed with each role's REAL credentials.
* pg_hba network confinement and TLS-only database access.
* The web DB credential alone can no longer escalate privileges or change roles silently,
  and cannot create (forge) a session: only the login service's role can (N12).
* Integrity failures are surfaced on the audit page (not only as a missing heartbeat).
* The operator verification command (`siem.worker --verify-once`).
"""
from __future__ import annotations

import hashlib
import secrets

import psycopg
import pytest

from .test_live_audit_tamper import RESTORE, _owner
from .test_live_http import ADMIN2, ANALYST, BOSS, breakglass_login, known_users  # noqa: F401

pytestmark = pytest.mark.live


def _denied(lab, kind, sql, params=()):
    with lab.connect(kind) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(sql, params)


# ------------------------------------------------------------------ database privileges
@pytest.mark.parametrize("kind,sql", [
    ("app", "UPDATE users SET role='super_admin'"),
    ("app", "UPDATE users SET active=true"),
    ("app", "UPDATE users SET entra_oid=gen_random_uuid()"),
    ("app", "INSERT INTO users(email,entra_oid,role) VALUES ('x@x.test',gen_random_uuid(),'super_admin')"),
    ("app", "DELETE FROM users"),
    ("app", "UPDATE audit_log SET actor='x'"),
    ("app", "DELETE FROM audit_log"),
    ("app", "TRUNCATE audit_log"),
    ("app", "UPDATE audit_head SET last_id=0"),
    ("app", "INSERT INTO audit_verification(ok,full_scan,checkpoint_id,detail) VALUES (true,true,0,'forged')"),
    ("app", "SELECT * FROM breakglass_tokens"),
    ("app", "INSERT INTO breakglass_tokens(token_hash,user_id,expires_at) VALUES ('\\x00',1,now())"),
    ("app", "SELECT admin_actor('x', 30)"),
    ("app", "CREATE TABLE pwn(i int)"),
    ("app", "SELECT pg_read_file('/etc/passwd')"),
    # N12: the web role cannot create sessions, nor mint one through the sign-in functions.
    ("app", "INSERT INTO sessions(id_hash,user_id,csrf_token,via,expires_at) SELECT sha256('x'), id, repeat('c',43), 'sso', now()+interval '1 hour' FROM users LIMIT 1"),
    ("app", "SELECT * FROM consume_breakglass(sha256('x'))"),
    ("app", "SELECT * FROM bootstrap_first_admin(gen_random_uuid(), 'x@x.test')"),
    # The login-service role: sessions and sign-in only.
    ("auth", "UPDATE users SET role='super_admin'"),
    ("auth", "UPDATE users SET active=true"),
    ("auth", "INSERT INTO users(email,entra_oid,role) VALUES ('x@x.test',gen_random_uuid(),'super_admin')"),
    ("auth", "DELETE FROM users"),
    ("auth", "UPDATE sessions SET last_seen_at=now()"),
    ("auth", "SELECT * FROM breakglass_tokens"),
    ("auth", "SELECT * FROM customers"),
    ("auth", "SELECT * FROM staff_customers"),
    ("auth", "SELECT * FROM security_events"),
    ("auth", "SELECT * FROM audit_verification"),
    ("auth", "UPDATE audit_log SET actor='x'"),
    ("auth", "UPDATE audit_head SET last_id=0"),
    ("auth", "SELECT admin_actor('x', 30)"),
    ("auth", "SELECT session_customer_ids('x', 30)"),
    ("auth", "SELECT admin_create_customer('x', 30, 'pwn', 'pwn')"),
    ("auth", "CREATE TABLE pwn(i int)"),
    ("worker", "SELECT * FROM users"),
    ("worker", "SELECT * FROM sessions"),
    ("worker", "INSERT INTO audit_log(id,actor,action,severity,prev_hash,hash) VALUES (1,'w','w','info','','')"),
    ("worker", "DELETE FROM audit_verification"),
    ("worker", "INSERT INTO audit_verification(checked_at,ok,full_scan,checkpoint_id,detail) VALUES (now()-interval '1 day',true,true,0,'backdated')"),
    ("emergency", "SELECT entra_oid FROM users"),
    ("emergency", "UPDATE users SET role='super_admin'"),
    ("emergency", "SELECT * FROM sessions"),
    ("emergency", "INSERT INTO breakglass_tokens(token_hash,user_id,expires_at,used_at) VALUES ('\\x00',1,now(),now())"),
    ("owner", "CREATE ROLE pwn LOGIN SUPERUSER"),
    ("owner", "SELECT pg_read_file('/etc/passwd')"),
])
def test_role_is_denied(lab, kind, sql):
    _denied(lab, kind, sql)


def test_no_runtime_role_is_privileged(lab):
    roles = [lab.role(k) for k in ("owner", "app", "worker", "emergency", "ingest", "auth")]
    out = lab.bootstrap_sql("SELECT string_agg(rolname, ',') FROM pg_roles WHERE rolname = ANY(ARRAY['"
                            + "','".join(roles) + "']) AND (rolsuper OR rolcreaterole OR rolcreatedb OR "
                            "rolreplication OR rolbypassrls)")
    assert out == "", f"over-privileged roles: {out}"


# ------------------------------------------------------------------ pg_hba / TLS
def test_ingest_credential_rejected_from_backend_network(lab):
    with pytest.raises(psycopg.OperationalError, match="pg_hba.conf rejects"):
        lab.connect("ingest")


def test_plaintext_database_connection_rejected(lab):
    with pytest.raises(psycopg.OperationalError, match="no encryption"):
        psycopg.connect(host="postgres", hostaddr=lab.pg_addr, dbname="siem", user=lab.role("app"),
                        password=lab.secret("db_app_password"), sslmode="disable", connect_timeout=5)


def test_bootstrap_superuser_cannot_log_in_over_network(lab):
    with pytest.raises(psycopg.OperationalError, match="pg_hba.conf rejects"):
        psycopg.connect(host="postgres", hostaddr=lab.pg_addr, dbname="siem", user="siem_bootstrap",
                        password=lab.secret("db_bootstrap_password"), sslmode="verify-full",
                        sslrootcert=str(lab.deploy / "postgres/tls/ca.crt"), connect_timeout=5)


def test_server_identity_verified(lab):
    with pytest.raises(psycopg.OperationalError, match="does not match host name"):
        psycopg.connect(host=lab.pg_addr, dbname="siem", user=lab.role("app"),
                        password=lab.secret("db_app_password"), sslmode="verify-full",
                        sslrootcert=str(lab.deploy / "postgres/tls/ca.crt"), connect_timeout=5)


def test_connections_use_tls13(lab):
    with lab.connect("app") as c:
        row = c.execute("SELECT ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()").fetchone()
    assert row["ssl"] and row["version"] in ("TLSv1.3", "TLSv1.2")


# ------------------------------------------------------------------ stolen web DB credential
def _session_token(lab, email, *, expired=False):
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    h = hashlib.sha256(token.encode()).hexdigest()
    when = "now()-interval '2 hours'" if expired else "now()"
    lab.bootstrap_sql(f"""INSERT INTO sessions(id_hash,user_id,csrf_token,via,expires_at,created_at,last_seen_at)
        SELECT '\\x{h}', id, '{csrf}', 'sso', now()+interval '1 hour', {when}, {when} FROM users WHERE email='{email}';""")
    return token


def _uid(lab, email):
    return int(lab.bootstrap_sql(f"SELECT id FROM users WHERE email='{email}'"))


@pytest.mark.parametrize("who", ["none", "garbage", "analyst", "expired_admin"])
def test_stolen_app_credential_cannot_escalate_without_live_admin_session(lab, who):
    token = {"none": "", "garbage": secrets.token_urlsafe(32),
             "analyst": _session_token(lab, ANALYST[0]),
             "expired_admin": _session_token(lab, BOSS[0], expired=True)}[who]
    with lab.connect("app") as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT * FROM admin_set_role(%s, 30, %s, 'super_admin')", (token, _uid(lab, ANALYST[0])))
    assert lab.bootstrap_sql(f"SELECT role FROM users WHERE email='{ANALYST[0]}'") == "analyst"


def test_app_password_cannot_forge_session(lab):
    """N12 (Phase 1 review): with ONLY the web DB password, insert a 'sso' session for the
    super admin, then use it as the session-bound customer scope and as an admin token."""
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    h = hashlib.sha256(token.encode()).digest()
    with lab.connect("app") as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("INSERT INTO sessions(id_hash,user_id,csrf_token,via,expires_at) "
                         "SELECT %s, id, %s, 'sso', now()+interval '1 hour' FROM users WHERE email=%s",
                         (h, csrf, BOSS[0]))
    assert lab.bootstrap_sql("SELECT count(*) FROM sessions") == "0"
    with lab.connect("app") as conn:
        conn.execute("SELECT set_config('siem.session', %s, false)", (token,))
        ids = conn.execute("SELECT session_customer_ids(current_setting('siem.session'), 30) AS ids").fetchone()["ids"]
        assert ids == []
        assert conn.execute("SELECT count(*) AS n FROM customers").fetchone()["n"] == 0
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT admin_create_customer(current_setting('siem.session'), 30, 'forged-co', 'Forged')")
    assert lab.bootstrap_sql("SELECT count(*) FROM customers WHERE slug='forged-co'") == "0"


def _secret_names(lab, service):
    import subprocess
    r = subprocess.run(["docker", "exec", f"{lab.project}-{service}-1", "ls", "/run/secrets"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return set(r.stdout.split())


def test_service_secrets_are_separated(lab):
    app, auth = _secret_names(lab, "app"), _secret_names(lab, "auth")
    assert "db_app_password" in app
    assert not app & {"oidc_client_secret", "db_auth_password", "session_secret"}, app
    assert {"db_auth_password", "oidc_client_secret", "session_secret"} <= auth
    assert "db_app_password" not in auth, auth


def test_web_app_does_not_serve_login_routes(lab):
    """Caddy sends /auth/* to the login service; the web app itself has no such route."""
    import subprocess
    probe = ("import urllib.request,urllib.error\n"
             "try:\n urllib.request.urlopen('http://127.0.0.1:8000/auth/login', timeout=5); print('OPEN')\n"
             "except urllib.error.HTTPError as e: print(e.code)\n")
    r = subprocess.run(["docker", "exec", "-i", f"{lab.project}-app-1", "python", "-"], input=probe,
                       capture_output=True, text=True, timeout=30)
    assert r.stdout.strip() == "404", r.stdout + r.stderr


def test_even_with_admin_session_an_unaudited_change_cannot_commit(lab):
    """Attacker holds the web DB password AND a live admin session token but skips the audit write."""
    token = _session_token(lab, BOSS[0])
    with lab.connect("app") as conn:
        conn.execute("SELECT * FROM admin_set_role(%s, 30, %s, 'super_admin')", (token, _uid(lab, ANALYST[0])))
        with pytest.raises(psycopg.Error, match="requires an audit record"):
            conn.commit()
    assert lab.bootstrap_sql(f"SELECT role FROM users WHERE email='{ANALYST[0]}'") == "analyst"


def test_audit_txid_cannot_be_forged_to_satisfy_enforcement(lab):
    with lab.connect("app") as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("INSERT INTO audit_log(id,actor,action,severity,prev_hash,hash,txid) "
                         "VALUES (999999,'a','user.role_changed','info',repeat('0',64),repeat('0',64),'1')")


def test_admin_function_enforces_last_super_admin_and_self_rules(lab):
    token = _session_token(lab, BOSS[0])
    with lab.connect("app") as conn:
        with pytest.raises(psycopg.errors.RaiseException, match="own role"):
            conn.execute("SELECT * FROM admin_set_role(%s, 30, %s, 'analyst')", (token, _uid(lab, BOSS[0])))
    lab.bootstrap_sql(f"SET session_replication_role=replica; UPDATE users SET active=false WHERE email='{ADMIN2[0]}'")
    with lab.connect("app") as conn:
        with pytest.raises(psycopg.errors.RaiseException, match="own role|deactivate yourself"):
            conn.execute("SELECT admin_set_active(%s, 30, %s, false)", (token, _uid(lab, BOSS[0])))


# ------------------------------------------------------------------ integrity status in the UI
def test_tampering_is_surfaced_on_audit_page(lab):
    c, _, _ = breakglass_login(lab, BOSS[0])           # also writes audit rows
    r = lab.compose("run", "--rm", "-T", "--no-deps", "worker", "python", "-m", "siem.worker", "--verify-once")
    assert r.returncode == 0 and "Audit chain OK" in r.stdout, r.stdout + r.stderr
    assert "Independent verification passed" in c.get("/admin/audit").text
    lab.bootstrap_sql("CREATE TABLE audit_tamper_backup AS SELECT * FROM audit_log;"
                      "CREATE TABLE audit_head_tamper_backup AS SELECT * FROM audit_head;")
    try:
        _owner(lab, ["UPDATE audit_log SET actor='attacker' WHERE id=1"])
        r = lab.compose("run", "--rm", "-T", "--no-deps", "worker", "python", "-m", "siem.worker", "--verify-once")
        assert r.returncode == 1 and "BROKEN" in r.stdout, r.stdout + r.stderr
        page = c.get("/admin/audit").text
        assert "AUDIT INTEGRITY ALERT" in page and "AuditIntegrityError at id 1" in page
    finally:
        lab.bootstrap_sql(RESTORE)
    r = lab.compose("run", "--rm", "-T", "--no-deps", "worker", "python", "-m", "siem.worker", "--verify-once")
    assert r.returncode == 0, r.stdout + r.stderr


def test_stale_verification_is_flagged(lab):
    c, _, _ = breakglass_login(lab, BOSS[0])
    lab.bootstrap_sql("CREATE TABLE av_backup AS SELECT * FROM audit_verification;"
                      "UPDATE audit_verification SET checked_at = checked_at - interval '1 hour';")
    try:
        assert "AUDIT VERIFICATION STALE" in c.get("/admin/audit").text
    finally:
        lab.bootstrap_sql("DELETE FROM audit_verification; INSERT INTO audit_verification OVERRIDING SYSTEM VALUE "
                          "SELECT * FROM av_backup; DROP TABLE av_backup;")
