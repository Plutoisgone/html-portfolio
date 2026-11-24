import pytest
from test_unit import make_settings

@pytest.mark.parametrize("claims,reason", [
    ({"tid": "other", "oid": "11111111-1111-4111-8111-111111111111", "preferred_username": "a@x.test"}, "wrong_tenant"),
    ({"tid": "tenant-a", "preferred_username": "a@x.test"}, "missing_claims"),
    ({"tid": "tenant-a", "oid": "11111111-1111-4111-8111-111111111111"}, "missing_claims"),
])
def test_resolve_user_rejects(claims, reason):
    from siem.auth import resolve_user
    assert resolve_user(claims, make_settings()) == (None, reason)


def test_resolve_user_requires_mfa_when_enabled():
    s = make_settings(require_mfa_claim=True)
    claims = {"tid": "tenant-a", "oid": "11111111-1111-4111-8111-111111111111", "preferred_username": "a@x.test", "amr": ["pwd"]}
    from siem.auth import resolve_user
    assert resolve_user(claims, s) == (None, "mfa_missing")




def test_upn_cannot_claim_another_identity():
    from siem.auth import resolve_user
    class Conn:
        def execute(self,sql,args=()):
            assert 'email =' not in sql
            return self
        def fetchone(self): return None
    settings = make_settings(initial_super_admins=['11111111-1111-4111-8111-111111111111'])
    claims = {'tid':'tenant-a','oid':'22222222-2222-4222-8222-222222222222','preferred_username':'boss@x.test'}
    assert resolve_user(claims,settings,conn=Conn()) == (None,'not_registered')


def test_registered_oid_not_upn_controls_login():
    from siem.auth import resolve_user
    class Conn:
        def execute(self,sql,args=()):
            if 'WHERE entra_oid' in sql: assert args == ('11111111-1111-4111-8111-111111111111',)
            return self
        def fetchone(self): return {'id':1,'email':'old@x.test','active':True,'role':'analyst'}
    claims = {'tid':'tenant-a','oid':'11111111-1111-4111-8111-111111111111','preferred_username':'renamed@x.test'}
    user,reason=resolve_user(claims,make_settings(),conn=Conn())
    assert reason=='ok' and user['role']=='analyst'


def test_admin_audit_failure_rolls_back_transaction(monkeypatch):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from siem import web
    events=[]
    class Conn:
        def execute(self,sql,args=()):
            if 'admin_create_user' in sql: events.append('insert')
            self.row={'exists':1} if 'JOIN sessions' in sql else None
            return self
        def fetchone(self): return self.row
    @contextmanager
    def tx():
        try:
            yield Conn()
            events.append('commit')
        except Exception:
            events.append('rollback')
            raise
    def fail(*args,**kwargs):
        assert isinstance(kwargs['conn'],Conn)
        raise RuntimeError('audit unavailable')
    monkeypatch.setattr(web.db,'tx',tx)
    monkeypatch.setattr(web.audit,'write',fail)
    with pytest.raises(RuntimeError):
        web.add_user(SimpleNamespace(client=None,headers={},cookies={'__Host-siem':'t'*43},app=SimpleNamespace(state=SimpleNamespace(settings=make_settings()))), 'new@x.test','analyst','11111111-1111-4111-8111-111111111111','ok',{'csrf_token':'ok','id_hash':b'h','user_id':1,'email':'boss@x.test'})
    assert events==['insert','rollback']


def test_breakglass_rejected_if_db_function_denies(monkeypatch):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from siem import auth
    class Conn:
        def execute(self,sql,args=()):
            assert 'consume_breakglass' in sql or 'advisory' in sql
            return self
        def fetchone(self): return None
    @contextmanager
    def tx(): yield Conn()
    monkeypatch.setattr(auth.db,'tx',tx)
    monkeypatch.setattr(auth.audit,'write',lambda *a,**k: None)
    response=auth.breakglass_consume(SimpleNamespace(client=None,headers={}), 'token',make_settings())
    assert response.headers['location']=='/login?error=breakglass'
    assert 'set-cookie' not in response.headers


def test_actual_asgi_boundary_wired(monkeypatch):
    from starlette.testclient import TestClient
    from siem import main, auth
    monkeypatch.setattr(main,'load_settings',lambda:make_settings())
    monkeypatch.setattr(auth,'setup_oauth',lambda settings:None)
    client=TestClient(main.create_app(),base_url='https://siem.test',raise_server_exceptions=False)
    assert client.post('/auth/breakglass',data={'token':'x'},headers={'Origin':'https://evil.test'}).status_code==403
    assert client.post('/auth/breakglass',data={'token':'x'*20000},headers={'Origin':'https://siem.test'}).status_code==413
    assert client.get('/login',headers={'Host':'evil.test'}).status_code==400


@pytest.mark.parametrize('bad',['aud','exp','nonce','iss'])
def test_callback_rejects_inconsistent_claims(monkeypatch,bad):
    import asyncio
    from datetime import datetime, timezone
    from types import SimpleNamespace
    from siem import auth
    settings=make_settings()
    claims={'aud':settings.oidc_client_id,'exp':int(datetime.now(timezone.utc).timestamp())+3600,'nonce':'nonce','iss':f'https://login.microsoftonline.com/{settings.oidc_tenant_id}/v2.0'}
    claims[bad]=0 if bad=='exp' else ''
    async def token(request): return {'id_token':'not-a-real-token','userinfo':claims}
    monkeypatch.setattr(auth,'oauth',SimpleNamespace(entra=SimpleNamespace(authorize_access_token=token)))
    monkeypatch.setattr(auth.audit,'write',lambda *a,**kw:None)
    response=asyncio.run(auth.callback(SimpleNamespace(client=None,headers={},session={}),settings))
    assert response.headers['location']=='/login?error=denied'
    assert 'set-cookie' not in response.headers
