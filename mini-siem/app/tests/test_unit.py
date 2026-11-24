"""Unit tests that need no database or network. Run: pytest tests/test_unit.py"""
from datetime import datetime, timezone

import pytest

from siem import audit, config
from siem.security import RateLimiter, csrf_ok, hash_token, new_token


def make_settings(**kw):
    base = dict(hostname="siem.test", oidc_tenant_id="tenant-a", oidc_client_id="c",
                oidc_client_secret="s", initial_super_admins=["boss@x.test"],
                session_secret="k", db_dsn="")
    base.update(kw)
    return config.Settings(**base)


def chain(n):
    rows, prev = [], audit.GENESIS
    for i in range(1, n + 1):
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        rec = audit._record(ts, "a", f"act{i}", None, "info", "192.0.2.1", None, {"i": i})
        rec["id"] = i
        h = audit.compute_hash(prev, rec)
        rows.append(dict(id=i, ts=ts, actor="a", action=f"act{i}", target=None, severity="info",
                         ip="192.0.2.1", user_agent=None, details={"i": i}, prev_hash=prev, hash=h))
        prev = h
    return rows


def test_chain_valid():
    assert audit.verify_rows(chain(5)) == (True, None)


def test_chain_detects_edit():
    rows = chain(5)
    rows[2]["actor"] = "attacker"
    assert audit.verify_rows(rows) == (False, 3)


def test_chain_detects_deletion():
    rows = chain(5)
    del rows[1]
    assert audit.verify_rows(rows) == (False, 3)


def test_rate_limiter():
    rl = RateLimiter(3, 60)
    assert all(rl.allow("ip", now=t) for t in (0, 1, 2))
    assert not rl.allow("ip", now=3)
    assert rl.allow("ip", now=61)


def test_csrf_and_tokens():
    t = new_token()
    assert len(t) >= 40 and t != new_token()
    assert csrf_ok(t, t) and not csrf_ok(t, "x") and not csrf_ok(t, None)
    assert hash_token(t) != t.encode() and len(hash_token(t)) == 32


def test_secret_rejects_placeholder(tmp_path, monkeypatch):
    (tmp_path / "s").write_text("CHANGE_ME\n")
    monkeypatch.setattr(config, "SECRETS_DIR", tmp_path)
    with pytest.raises(config.ConfigError):
        config.secret("s")
    with pytest.raises(config.ConfigError):
        config.secret("missing")
    assert config.secret("missing", required=False) is None
