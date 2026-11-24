import hashlib
import json
import socket
import ssl
import subprocess
import threading
from pathlib import Path
from unittest.mock import Mock

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape
from siem.collector import Frames, Admission, handle, load_sources, tls_context
from siem.events import MAX_FRAME, normalize, persist
from siem.event_query import search_query


@pytest.mark.parametrize('message,rule', [
    (b'<134> action=deny src=192.0.2.1', 'firewall_deny'),
    (b'<38> category=authentication status=failed', 'auth_failure'),
    (b'<11> event=malware_detected', 'malware_indicator'),
    (b'<14> action=allow', None),
    (b'<14> action=deny action=allow', None),
    (b'<14> msg="action=deny"', None),
    (b'<14> action="deny', None),
])
def test_rules(message,rule):
    event=normalize('firewall-01',message)
    assert event.rule == rule and event.source == 'firewall-01'


def test_priority_and_source_spoofing():
    event=normalize('trusted',b'<191> source_id=other action=drop')
    assert (event.source,event.facility,event.severity)==('trusted',23,7)


@pytest.mark.parametrize('source,frame', [
    ('../bad',b'hello'),('good',b''),('good',b'x'*(MAX_FRAME+1)),
    ('good',b'<192> invalid'),('good',b'\xff'),('good',b'hello\x00world'),
    ('good',b'hello\nworld'),('good',b'hello\x1b[31m'),
])
def test_invalid_event(source,frame):
    with pytest.raises(ValueError): normalize(source,frame)


def test_octet_fragmentation():
    frames=Frames()
    assert list(frames.feed(b'5 hel'))==[]
    assert list(frames.feed(b'lo3 ab'))==[b'hello']
    assert list(frames.feed(b'c'))==[b'abc']


def test_line_fragmentation():
    frames=Frames()
    assert list(frames.feed(b'<14> he'))==[]
    assert list(frames.feed(b'llo\r\n<13> x\n'))==[b'<14> hello',b'<13> x']


@pytest.mark.parametrize('chunks', [[b'9999 x'],[b'12345'],[b'0 '],[b'1x '],[b'0001 x'],[b'x'*4096,b'x'*4096,b'xx'],[b'\n']])
def test_bad_frames(chunks):
    frames=Frames()
    with pytest.raises(ValueError):
        for chunk in chunks: list(frames.feed(chunk))


def test_exact_frame_limit():
    frames=Frames()
    assert list(frames.feed(b'x'*4096))==[]
    assert list(frames.feed(b'x'*4096))==[]
    assert list(frames.feed(b'\r\n'))==[b'x'*8192]


def test_rate_bound():
    rate=Admission(rate=0,burst=3)
    assert [rate.take() for _ in range(5)]==[True,True,True,False,False]


def test_parameterized_persistence_and_search():
    conn=Mock()
    payload="x'); DROP TABLE users;--"
    event=normalize('source',payload.encode())
    persist(conn,event)
    query, params=conn.execute.call_args.args
    assert payload not in query and payload in params
    query, params=search_query('source',payload,'any')
    assert payload not in query and params==('source',payload)
    assert 'LIMIT 100' in query and '24 hours' in query


@pytest.mark.parametrize('source,term,rule',[('x\n','',''),('','x'*129,''),('','','bogus'),('','a\n','')])
def test_bad_search(source,term,rule):
    with pytest.raises(ValueError): search_query(source,term,rule)


def test_template_escapes_untrusted_message():
    env=Environment(loader=FileSystemLoader(Path(__file__).parents[1]/'siem/templates'),autoescape=select_autoescape(['html']))
    html=env.get_template('events.html').render(user=None,source='',term='"><script>x</script>',rule='',rules=[],rows=[dict(id=1,received_at='now',source_id='test',rule_id=None,facility=1,severity=2,message='<script>alert(1)</script>')])
    assert '<script>' not in html and '&lt;script&gt;' in html


def test_registry(tmp_path):
    p=tmp_path/'sources.json'; p.write_text(json.dumps({'a'*64:'source'}))
    assert load_sources(p)=={'a'*64:'source'}
    p.write_text('{"'+('a'*64)+'":"one","'+('a'*64)+'":"two"}')
    with pytest.raises(ValueError): load_sources(p)


@pytest.fixture(scope='module')
def pki(tmp_path_factory):
    d=tmp_path_factory.mktemp('pki')
    def openssl(*args):
        subprocess.run(['openssl',*args],cwd=d,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    openssl('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','1','-subj','/CN=Test CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout','ca.key','-out','client-ca.crt')
    for name,usage in [('server','serverAuth'),('client','clientAuth'),('unknown','clientAuth')]:
        openssl('req','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN='+name,'-keyout',name+'.key','-out',name+'.csr')
        (d/'ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\nextendedKeyUsage='+usage+'\n'+('subjectAltName=DNS:server\n' if name=='server' else ''))
        openssl('x509','-req','-in',name+'.csr','-CA','client-ca.crt','-CAkey','ca.key','-CAcreateserial','-days','1','-extfile','ext','-out',name+'.crt')
    return d


@pytest.mark.parametrize('cert,accepted',[('client',True),('unknown',False),(None,False)])
def test_real_mtls(pki,cert,accepted):
    fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert((pki/'client.crt').read_text())).hexdigest()
    ctx=tls_context(pki)
    left,right=socket.socketpair()
    got=[]
    thread=threading.Thread(target=handle,args=(left,ctx,{fingerprint:'trusted'},got.append,Admission()),daemon=True)
    thread.start()
    client=ssl.create_default_context(cafile=str(pki/'client-ca.crt'))
    client.minimum_version=ssl.TLSVersion.TLSv1_2
    if cert: client.load_cert_chain(pki/(cert+'.crt'),pki/(cert+'.key'))
    try:
        with right:
            right.settimeout(3)
            with client.wrap_socket(right,server_hostname='server') as secure:
                secure.sendall(b'<134> action=deny\n')
                # Wait for server to process data; close gracefully via context.
                if accepted:
                    import time
                    for _ in range(100):
                        if got: break
                        time.sleep(.01)
    except OSError:
        if accepted: raise
    thread.join(5)
    assert not thread.is_alive()
    assert len(got)==int(accepted)
    if accepted: assert got[0].source=='trusted' and got[0].rule=='firewall_deny'
