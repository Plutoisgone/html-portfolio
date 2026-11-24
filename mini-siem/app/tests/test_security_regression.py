import json
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient
from siem import audit, checkpoint
from siem.security import RateLimiter, RateLimitMiddleware, SecurityHeadersMiddleware, SECURITY_HEADERS, csrf_ok
from test_unit import chain


@pytest.mark.parametrize('mutation', ['id','truncate','empty','reorder','first','rehash'])
def test_audit_tampering(mutation):
    rows = chain(5)
    head = (5, rows[-1]['hash'])
    if mutation == 'id': rows[2]['id'] = 10
    elif mutation == 'truncate': rows.pop()
    elif mutation == 'empty': rows.clear()
    elif mutation == 'reorder': rows[1], rows[2] = rows[2], rows[1]
    elif mutation == 'first': rows.pop(0)
    else:
        rows[-1]['actor'] = 'changed'
        r = rows[-1]
        rec = audit._record(r['ts'],r['actor'],r['action'],r['target'],r['severity'],r['ip'],r['user_agent'],r['details'])
        rec['id'] = r['id']
        r['hash'] = audit.compute_hash(r['prev_hash'],rec)
    assert not audit.verify_rows(rows, expected=head)[0]


def test_segment_requires_explicit_anchor():
    rows = chain(5)
    assert not audit.verify_rows(rows[2:])[0]
    assert audit.verify_rows(rows[2:],start_id=2,start_hash=rows[1]['hash'],expected=(5,rows[-1]['hash']))[0]


def test_checkpoint_authentication(tmp_path):
    key = b'k'*32
    path = tmp_path/'checkpoint.json'
    signed = checkpoint.encode(key,5,'a'*64)
    checkpoint.save(path,signed)
    assert checkpoint.read(path,key) == (5,'a'*64)
    envelope = json.loads(signed)
    envelope['body']['id'] = 4
    with pytest.raises(ValueError): checkpoint.decode(key,json.dumps(envelope).encode())
    with pytest.raises(ValueError): checkpoint.decode(b'x'*32,signed)
    path.unlink()
    with pytest.raises(FileNotFoundError): checkpoint.read(path,key)


def test_snapshot_detects_rollback_even_if_db_head_changed():
    class Result:
        def __init__(self,row): self.row=row
        def fetchone(self): return self.row
    class Conn:
        def execute(self,sql,args=()):
            return Result({'last_id':0,'last_hash':audit.GENESIS} if 'audit_head' in sql else None)
    assert audit.verify_snapshot(Conn(),(5,'a'*64)) == (False,5)


def test_rate_limiter_hard_cap_and_expiry():
    """Bounded key table; idle keys expire; a full table degrades to a shared
    overflow bucket instead of locking every new client out (Phase 0.2 behaviour)."""
    rl = RateLimiter(2, 60, max_keys=16)
    for i in range(16):
        assert rl.allow(str(i), now=1)
    assert len(rl) == 16
    assert rl.allow('extra', now=1) and rl.allow('extra2', now=1)   # overflow bucket: burst 2
    assert not rl.allow('extra3', now=1)                              # ...then shared limit
    assert len(rl) == 16                                              # never grows past the cap
    assert rl.allow('0', now=2) and not rl.allow('0', now=3)          # per-key limit still exact
    assert rl.allow('extra', now=200)                                 # idle keys expired
    assert len(rl) == 1


def test_rate_limiter_memory_bounded_under_flood():
    """Regression for the reported memory exhaustion: 50,000 distinct sources at full
    rate must stay at the key cap and in single-digit megabytes."""
    import tracemalloc
    tracemalloc.start()
    rl = RateLimiter(300, 60)
    for k in range(50_000):
        for i in range(3):
            rl.allow(f"198.18.{k // 256 % 256}.{k % 256}-{k}", now=1.0 + i * 0.001)
    current, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert len(rl) == RateLimiter.MAX_KEYS
    assert current < 12_000_000, current


def test_ipv6_clients_grouped_per_64():
    from siem.security import client_key
    assert client_key('2001:db8:1:2:aaaa::1') == client_key('2001:db8:1:2:ffff::9') == '2001:db8:1:2::/64'
    assert client_key('2001:db8:1:3::1') != client_key('2001:db8:1:2::1')
    assert client_key('::ffff:192.0.2.7') == '192.0.2.7'
    assert client_key('192.0.2.7') == '192.0.2.7'
    assert client_key(None) == 'unknown' and client_key('not-an-ip') == 'invalid'


def test_rate_limit_concurrency():
    rl = RateLimiter(10,60)
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(lambda _: rl.allow('same'),range(200))) == 10


def test_all_http_status_security_headers():
    async def ok(request): return PlainTextResponse('ok')
    async def error(request): raise RuntimeError('test')
    app = Starlette(routes=[Route('/auth/ok',ok),Route('/error',error)])
    app.add_middleware(RateLimitMiddleware,auth_limit=1)
    client = TestClient(SecurityHeadersMiddleware(app),raise_server_exceptions=False)
    for url,status in [('/auth/ok',200),('/auth/ok',429),('/missing',404),('/error',500)]:
        response = client.get(url)
        assert response.status_code == status
        for name,value in SECURITY_HEADERS.items(): assert response.headers[name] == value


def test_csrf_unicode_is_rejected_without_exception():
    assert not csrf_ok('token','不')


def test_tenancy_grants_are_read_only_for_app_and_absent_elsewhere():
    from siem import migrate
    grants = migrate.role_grants("app", "worker", "emergency", "ingest")
    tenancy_fns = (
        "admin_create_customer(text, integer, text, text)",
        "admin_set_customer_active(text, integer, integer, boolean)",
        "admin_assign_staff(text, integer, integer, integer, boolean)",
        "session_customer_ids(text, integer)",
    )
    app = grants["app"]
    assert "GRANT SELECT ON customers, staff_customers TO {r}" in app
    for fn in tenancy_fns:
        assert f"GRANT EXECUTE ON FUNCTION {fn} TO {{r}}" in app
    # Exactly those new lines: nothing else mentions the new tables or functions.
    tenancy_lines = [s for s in app if "customer" in s or "staff" in s]
    assert len(tenancy_lines) == 1 + len(tenancy_fns)
    for line in tenancy_lines:
        assert not any(w in line for w in ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "ALL"))
    for role in ("worker", "emergency", "ingest"):
        assert not [s for s in grants[role] if "customer" in s or "staff" in s]
    assert "require_tenant_audit" not in " ".join(sum(grants.values(), []))


def test_migration_6_is_known_and_last():
    from siem import migrate
    assert len(migrate.MIGRATIONS) == 5  # versions 2..6
    m6 = migrate.MIGRATIONS[-1]
    for needle in ("CREATE TABLE customers", "CREATE TABLE staff_customers",
                   "FORCE ROW LEVEL SECURITY", "require_tenant_audit", "SIA01",
                   "via = 'sso'"):
        assert needle in m6
    import inspect
    assert "current not in (0, 2, 3, 4, 5, 6)" in inspect.getsource(migrate.main)
    assert [p for p, _ in migrate.APP_SCOPED_POLICIES] == ["customers_scope", "staff_customers_scope"]
