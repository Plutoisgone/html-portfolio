import io
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient
from siem.security import RequestBoundaryMiddleware, SecurityHeadersMiddleware
from siem import audit, checkpoint, worker

ORIGIN = 'https://siem.test'

@pytest.fixture
def client():
    async def echo(request):
        return PlainTextResponse(await request.body())
    app = Starlette(routes=[Route('/form', echo, methods=['GET','POST'])])
    return TestClient(SecurityHeadersMiddleware(RequestBoundaryMiddleware(app, ORIGIN, max_body=64)))

@pytest.mark.parametrize('origin', [None,'null','https://evil.test','https://siem.test.evil.test','http://siem.test'])
def test_cross_origin_forms_rejected(client, origin):
    assert client.post('/form',data={'token':'value'},headers={'Origin':origin} if origin else {}).status_code == 403


def test_same_origin_form(client):
    assert client.post('/form',data={'token':'value'},headers={'Origin':ORIGIN}).text == 'token=value'


def test_multipart_rejected(client):
    assert client.post('/form',content=b'x',headers={'Origin':ORIGIN,'Content-Type':'multipart/form-data; boundary=test'}).status_code == 415


def test_oversized_form_rejected(client):
    assert client.post('/form',data={'token':'a'*100},headers={'Origin':ORIGIN}).status_code == 413


def test_streamed_oversized_form_rejected(client):
    r=client.post('/form',content=iter([b'a'*40,b'b'*40]),headers={'Origin':ORIGIN,'Content-Type':'application/x-www-form-urlencoded'})
    assert r.status_code == 413
    assert r.headers['cache-control']=='no-store'


def test_ambiguous_framing_rejected(client):
    assert client.post('/form',content=b'x',headers=[('Origin',ORIGIN),('Content-Type','application/x-www-form-urlencoded'),('Content-Length','1'),('Content-Length','2')]).status_code==400


def test_get_body_rejected(client):
    assert client.request('GET','/form',content=b'x').status_code==400


@pytest.mark.parametrize('bad',['http://x.test','https://','https://user:pass@x.test','https://x.test/#fragment'])
def test_insecure_worker_url_rejected(bad):
    with pytest.raises(ValueError): worker.require_https(bad)


def test_https_worker_url():
    worker.require_https('https://s3.example.test')


class FakeS3:
    def __init__(self, body, mode='COMPLIANCE', until=None, version='v1', keys=()):
        self.body,self.mode,self.until,self.version,self.keys=body,mode,until or datetime.now(timezone.utc)+timedelta(days=1),version,keys
    def get_object(self, **kwargs):
        return {'Body':io.BytesIO(self.body),'ObjectLockMode':self.mode,'ObjectLockRetainUntilDate':self.until,'VersionId':self.version}
    def get_paginator(self, name):
        return SimpleNamespace(paginate=lambda **kw:[{'Versions':[{'Key':k,'VersionId':self.version} for k in self.keys]}])


@pytest.mark.parametrize('case',['wrong_bytes','governance','short_retention','missing_version'])
def test_remote_upload_not_accepted(case):
    retain=datetime.now(timezone.utc)+timedelta(days=1)
    s3=FakeS3(b'good',until=retain)
    if case=='wrong_bytes': s3.body=b'bad'
    elif case=='governance': s3.mode='GOVERNANCE'
    elif case=='short_retention': s3.until=retain-timedelta(seconds=1)
    elif case=='missing_version': s3.version=None
    with pytest.raises(RuntimeError): worker.verify_remote_object(s3,'bucket','key',s3.version,b'good',retain)


def test_remote_upload_verified():
    retain=datetime.now(timezone.utc)+timedelta(days=1)
    s3=FakeS3(b'good',until=retain)
    worker.verify_remote_object(s3,'bucket','key','v1',b'good',retain)


def test_remote_anchor_detects_local_rollback():
    key=b'k'*32
    anchor=(3,'a'*64)
    s3=FakeS3(checkpoint.encode(key,*anchor),keys=[f'audit/000000000001-000000000003-{anchor[1]}.checkpoint.json'])
    worker.verify_remote_anchor(s3,'bucket',key,anchor)
    with pytest.raises(RuntimeError): worker.verify_remote_anchor(s3,'bucket',key,(0,audit.GENESIS))


def test_remote_anchor_missing_fails_closed():
    s3=FakeS3(b'')
    worker.verify_remote_anchor(s3,'bucket',b'k'*32,(0,audit.GENESIS))
    with pytest.raises(RuntimeError): worker.verify_remote_anchor(s3,'bucket',b'k'*32,(1,'a'*64))


def test_secret_settings_not_in_repr():
    from test_unit import make_settings
    cfg=make_settings(oidc_client_secret='client-secret-hidden',session_secret='session-secret-hidden',db_dsn='db-secret-hidden',s3_access_key='key-hidden',s3_secret_key='s3-hidden',heartbeat_url='https://hidden.test')
    for secret in ['client-secret-hidden','session-secret-hidden','db-secret-hidden','key-hidden','s3-hidden','hidden.test']:
        assert secret not in repr(cfg)
