"""OIDC callback validation with the REAL Authlib/joserfc code path.

Integration level: real login-service create_app() wiring (siem.auth_main), real SessionMiddleware state/nonce
cookie, real RS256 signatures against a JWKS, real claim validation. The only
stand-ins are (a) the token-endpoint HTTP call, replaced by a function that
returns the ID token under test, and (b) finish_sso, which would need a
database. This is NOT a live Microsoft Entra ID test.
"""
from __future__ import annotations

import time
from urllib.parse import parse_qs, urlsplit

import pytest
from joserfc import jwt
from joserfc.jwk import OctKey, RSAKey
from starlette.responses import RedirectResponse
from starlette.testclient import TestClient

from siem import auth, auth_main, config

TENANT = "11111111-1111-4111-8111-111111111111"
CLIENT = "22222222-2222-4222-8222-222222222222"
OID = "33333333-3333-4333-8333-333333333333"
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"
SIGNING_KEY = RSAKey.generate_key(2048, parameters={"kid": "k1"}, private=True)
OTHER_KEY = RSAKey.generate_key(2048, parameters={"kid": "k1"}, private=True)


def settings():
    return config.Settings(hostname="siem.test", oidc_tenant_id=TENANT, oidc_client_id=CLIENT,
                           oidc_client_secret="s", initial_super_admins=[OID],
                           session_secret="ab" * 32, db_dsn="")


@pytest.fixture
def flow(monkeypatch):
    monkeypatch.setattr(auth_main, "load_auth_settings", settings)
    finished = {}

    def fake_finish(request, s, claims, ip, ua):
        finished["claims"] = dict(claims)
        return RedirectResponse("/signed-in", status_code=303)

    monkeypatch.setattr(auth, "finish_sso", fake_finish)
    audited = []
    monkeypatch.setattr(auth.audit, "write", lambda *a, **kw: audited.append(a[1]))
    app = auth_main.create_app()
    auth.oauth.entra.server_metadata.update({
        "issuer": ISSUER, "authorization_endpoint": f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize",
        "token_endpoint": f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
        "jwks": {"keys": [SIGNING_KEY.as_dict(private=False)]},
        "id_token_signing_alg_values_supported": ["RS256"], "_loaded_at": time.time()})
    client = TestClient(app, base_url="https://siem.test", raise_server_exceptions=False,
                        follow_redirects=False)

    def run(make_token, *, replay=False):
        r = client.get("/auth/login")
        assert r.status_code == 302, r.text[:300]
        q = parse_qs(urlsplit(r.headers["location"]).query)
        state, nonce = q["state"][0], q["nonce"][0]
        assert q["code_challenge_method"] == ["S256"]
        id_token = make_token(nonce)

        async def fetch_access_token(**params):
            return {"access_token": "at", "token_type": "Bearer", "id_token": id_token}

        monkeypatch.setattr(auth.oauth.entra, "fetch_access_token", fetch_access_token)
        finished.clear()
        audited.clear()
        resp = client.get("/auth/callback", params={"code": "c", "state": state})
        if replay:
            finished.clear()
            resp = client.get("/auth/callback", params={"code": "c", "state": state})
        run.audited = list(audited)
        return resp, finished.get("claims")

    return run


def claims(_nonce, **over):
    now = int(time.time())
    base = {"iss": ISSUER, "aud": CLIENT, "tid": TENANT, "oid": OID, "sub": "pairwise-sub",
            "preferred_username": "boss@lab.test", "nonce": _nonce, "iat": now, "nbf": now,
            "exp": now + 3600, "ver": "2.0"}
    base.update(over)
    return {k: v for k, v in base.items() if v is not None}


def signed(c, key=SIGNING_KEY, alg="RS256"):
    return jwt.encode({"alg": alg, "kid": "k1", "typ": "JWT"}, c, key)


def test_valid_token_accepted(flow):
    resp, got = flow(lambda n: signed(claims(n)))
    assert resp.headers["location"] == "/signed-in"
    assert got["oid"] == OID and got["tid"] == TENANT


@pytest.mark.parametrize("name,make", [
    ("forged signature", lambda n: signed(claims(n), key=OTHER_KEY)),
    ("wrong issuer", lambda n: signed(claims(n, iss="https://login.microsoftonline.com/common/v2.0"))),
    ("other tenant issuer", lambda n: signed(claims(n, iss="https://login.microsoftonline.com/99999999-9999-4999-8999-999999999999/v2.0"))),
    ("wrong audience", lambda n: signed(claims(n, aud="someone-else"))),
    ("expired", lambda n: signed(claims(n, exp=int(time.time()) - 600, iat=int(time.time()) - 4000))),
    ("not yet valid", lambda n: signed(claims(n, nbf=int(time.time()) + 3600))),
    ("wrong nonce", lambda n: signed(claims("attacker-nonce"))),
    ("missing nonce", lambda n: signed(claims(n, nonce=None))),
    ("missing exp", lambda n: signed(claims(n, exp=None))),
    ("alg none", lambda n: jwt.encode({"alg": "none"}, claims(n), None, algorithms=["none"])),
    ("HS256 key confusion", lambda n: signed(claims(n), key=OctKey.import_key(b"x" * 32), alg="HS256")),
    ("garbage token", lambda n: "not.a.jwt"),
])
def test_invalid_id_token_rejected_without_session(flow, name, make):
    resp, got = flow(make)
    assert got is None, f"{name}: reached account resolution"
    assert resp.status_code in (303, 400), f"{name}: status {resp.status_code}"
    assert resp.headers.get("location", "").startswith("/login?error="), f"{name}: {resp.status_code}"
    assert "__Host-siem" not in resp.headers.get("set-cookie", "")
    assert "content-security-policy" in resp.headers
    assert flow.audited == ["auth.login.failed"], f"{name}: failure not audited: {flow.audited}"


def test_state_replay_rejected(flow):
    resp, got = flow(lambda n: signed(claims(n)), replay=True)
    assert got is None
    assert resp.headers.get("location", "").startswith("/login?error=")
