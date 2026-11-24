"""End-to-end smoke test against a running stack.

Usage: SIEM_URL=https://siem.example:443 python tests/smoke_test.py
Needs a super admin in the DB and a break-glass code in BREAKGLASS_CODE.
"""
import os
import re
import sys
import uuid

import httpx

URL = os.environ["SIEM_URL"].rstrip("/")
CODE = os.environ.get("BREAKGLASS_CODE", "")
fails = 0
NEW_OID = str(uuid.uuid4())  # unique per run, so the smoke test can be re-run
NEW_EMAIL = f"smoke-{NEW_OID[:8]}@lab.test"


def check(name, cond, extra=""):
    global fails
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    fails += 0 if cond else 1


c = httpx.Client(verify=os.environ.get("SIEM_CA_FILE") or True, trust_env=False, follow_redirects=False, timeout=10, headers={"Origin": URL})
r = c.get(f"{URL}/login")
check("login page loads", r.status_code == 200, r.status_code)
for h in ["content-security-policy", "strict-transport-security", "x-frame-options",
          "x-content-type-options", "referrer-policy"]:
    check(f"header {h}", h in r.headers)
check("no server banner leak", "uvicorn" not in r.headers.get("server", "").lower())
r = c.get(f"{URL}/")
check("unauthenticated / -> /login", r.status_code == 303 and r.headers.get("location") == "/login",
      r.status_code)
r = c.get(f"{URL}/admin/users")
check("unauthenticated admin -> /login", r.status_code == 303, r.status_code)
for p in ["/docs", "/openapi.json", "/redoc"]:
    check(f"{p} disabled", c.get(f"{URL}{p}").status_code == 404)
r = c.post(f"{URL}/auth/breakglass", data={"token": "wrong"})
check("bad break-glass code rejected", r.headers.get("location") == "/login?error=breakglass")

if CODE:
    r = c.post(f"{URL}/auth/breakglass", data={"token": CODE})
    check("break-glass login", r.status_code == 303 and r.headers.get("location") == "/", r.status_code)
    cookie = r.cookies.get("__Host-siem")
    check("session cookie flags", "httponly" in r.headers.get("set-cookie", "").lower()
          and "secure" in r.headers.get("set-cookie", "").lower())
    r2 = c.post(f"{URL}/auth/breakglass", data={"token": CODE})
    check("break-glass code is single-use", r2.headers.get("location") == "/login?error=breakglass")
    page = c.get(f"{URL}/admin/users")
    check("admin users page with session", page.status_code == 200, page.status_code)
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    r = c.post(f"{URL}/admin/users", data={"email": NEW_EMAIL, "role": "analyst", "entra_oid": NEW_OID})
    check("add user WITHOUT csrf blocked", r.status_code == 403, r.status_code)
    r = c.post(f"{URL}/admin/users", data={"email": NEW_EMAIL, "role": "analyst", "entra_oid": NEW_OID, "csrf": csrf})
    check("add user with csrf", r.status_code == 303, r.status_code)
    r = c.post(f"{URL}/admin/users", data={"email": "<script>@x.y", "role": "analyst", "entra_oid": "11111111-1111-4111-8111-111111111111", "csrf": csrf})
    check("invalid email rejected", r.status_code == 400, r.status_code)
    r = c.post(f"{URL}/admin/users", data={"email": "x@lab.test", "role": "god", "entra_oid": "11111111-1111-4111-8111-111111111112", "csrf": csrf})
    check("invalid role rejected", r.status_code == 400, r.status_code)
    a = c.get(f"{URL}/admin/audit")
    check("audit page + independent verification passed", a.status_code == 200 and "Independent verification passed" in a.text, a.text[:200] if a.status_code == 200 else a.status_code)
    check("audit shows break-glass login", "auth.breakglass.login" in a.text)
    r = c.post(f"{URL}/auth/logout", data={"csrf": csrf})
    check("logout", r.status_code == 303)
    c.cookies.clear()
    c.cookies.set("__Host-siem", cookie)
    check("old session invalid after logout", c.get(f"{URL}/").status_code == 303)

print(f"\n{fails} failure(s)")
sys.exit(1 if fails else 0)
