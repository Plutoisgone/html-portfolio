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
    from siem import main, auth_main, auth
    monkeypatch.setattr(auth_main,'load_auth_settings',lambda:make_settings())
    monkeypatch.setattr(auth,'setup_oauth',lambda settings:None)
    client=TestClient(auth_main.create_app(),base_url='https://siem.test',raise_server_exceptions=False)
    assert client.post('/auth/breakglass',data={'token':'x'},headers={'Origin':'https://evil.test'}).status_code==403
    assert client.post('/auth/breakglass',data={'token':'x'*20000},headers={'Origin':'https://siem.test'}).status_code==413
    assert client.get('/auth/login',headers={'Host':'evil.test'}).status_code==400
    monkeypatch.setattr(main,'load_settings',lambda:make_settings())
    web=TestClient(main.create_app(),base_url='https://siem.test',raise_server_exceptions=False)
    assert web.get('/login',headers={'Host':'evil.test'}).status_code==400


def test_only_the_login_service_mounts_auth_routes(monkeypatch):
    """N12: the web app (which holds the web DB role) has no session-creating route,
    and the login service serves nothing but /auth/* and /healthz."""
    from starlette.testclient import TestClient
    from siem import main, auth_main, auth
    monkeypatch.setattr(main,'load_settings',lambda:make_settings())
    monkeypatch.setattr(auth_main,'load_auth_settings',lambda:make_settings())
    monkeypatch.setattr(auth,'setup_oauth',lambda settings:None)
    monkeypatch.setattr(auth.audit,'write',lambda *a,**k: None)
    o={'Origin':'https://siem.test'}
    web=TestClient(main.create_app(),base_url='https://siem.test',raise_server_exceptions=False,follow_redirects=False)
    for path in ('/auth/login','/auth/callback'):
        assert web.get(path).status_code==404, path
    for path in ('/auth/breakglass','/auth/logout'):
        assert web.post(path,data={'token':'x','csrf':'x'},headers=o).status_code==404, path
    assert web.get('/login').status_code==200 and web.get('/breakglass').status_code==200
    login=TestClient(auth_main.create_app(),base_url='https://siem.test',raise_server_exceptions=False,follow_redirects=False)
    for path in ('/login','/breakglass','/','/admin/users','/admin/audit','/static/style.css'):
        assert login.get(path).status_code==404, path
    assert login.post('/admin/users',data={'csrf':'x'},headers=o).status_code==404
    # logout without a session goes back to the web app's login page
    r=login.post('/auth/logout',data={'csrf':'x'},headers=o)
    assert r.status_code==303 and r.headers['location']=='/login'


def test_web_app_never_registers_oidc(monkeypatch):
    from siem import main, auth
    monkeypatch.setattr(main,'load_settings',lambda:make_settings())
    def boom(settings): raise AssertionError('web app must not configure OIDC')
    monkeypatch.setattr(auth,'setup_oauth',boom)
    main.create_app()


def test_logout_does_not_need_session_update_privilege(monkeypatch):
    """The login-service role has no UPDATE on sessions: logout must neither lock the
    row FOR UPDATE nor touch last_seen_at."""
    from contextlib import contextmanager
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace
    from siem import auth
    seen=[]
    now=datetime.now(timezone.utc)
    row={'id_hash':b'h','csrf_token':'c'*43,'via':'sso','last_seen_at':now,'expires_at':now+timedelta(hours=1),
         'user_id':1,'email':'boss@x.test','role':'super_admin','active':True}
    class Conn:
        def execute(self,sql,args=()):
            seen.append(sql); return self
        def fetchone(self): return row
    @contextmanager
    def tx(): yield Conn()
    monkeypatch.setattr(auth.db,'tx',tx)
    req=SimpleNamespace(cookies={'__Host-siem':'t'*43})
    assert auth.load_session(req, make_settings(), touch=False) is row
    assert not [s for s in seen if 'FOR UPDATE' in s or s.lstrip().startswith('UPDATE')]
    seen.clear()
    assert auth.load_session(req, make_settings()) is row
    assert [s for s in seen if 'FOR UPDATE' in s] and [s for s in seen if 'UPDATE sessions SET last_seen_at' in s]


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


def _service_env(monkeypatch, tmp_path, secrets):
    from siem import config
    for k, v in {"SIEM_HOSTNAME": "siem.test", "SIEM_OIDC_TENANT_ID": "11111111-1111-4111-8111-111111111111",
                 "SIEM_OIDC_CLIENT_ID": "22222222-2222-4222-8222-222222222222",
                 "SIEM_INITIAL_SUPER_ADMIN_OIDS": "33333333-3333-4333-8333-333333333333",
                 "SIEM_DB_APP_USER": "siem_app", "SIEM_DB_AUTH_USER": "siem_auth"}.items():
        monkeypatch.setenv(k, v)
    for name, value in secrets.items():
        (tmp_path / name).write_text(value)
    monkeypatch.setattr(config, "SECRETS_DIR", tmp_path)
    return config


def test_web_settings_need_no_oidc_or_auth_secrets(monkeypatch, tmp_path):
    config = _service_env(monkeypatch, tmp_path, {"db_app_password": "app-pw"})
    s = config.load_settings()
    assert s.oidc_client_secret == "" and s.session_secret == ""
    assert "user=siem_app" in s.db_dsn and "app-pw" in s.db_dsn


def test_login_service_settings_use_auth_role_and_need_oidc_secret(monkeypatch, tmp_path):
    import pytest
    config = _service_env(monkeypatch, tmp_path, {"db_auth_password": "auth-pw", "session_secret": "ab" * 32})
    with pytest.raises(config.ConfigError, match="oidc_client_secret"):
        config.load_auth_settings()
    (tmp_path / "oidc_client_secret").write_text("client-secret")
    s = config.load_auth_settings()
    assert "user=siem_auth" in s.db_dsn and "auth-pw" in s.db_dsn and "app-pw" not in s.db_dsn
    assert s.oidc_client_secret == "client-secret"
    (tmp_path / "session_secret").write_text("short")
    with pytest.raises(config.ConfigError):
        config.load_auth_settings()
