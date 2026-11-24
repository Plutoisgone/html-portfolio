"""Worker-only authenticated checkpoint. The key and state are outside PostgreSQL."""
import hashlib
import hmac
import json
import os
import re
import tempfile
from pathlib import Path

GENESIS = '0' * 64


def encode(key: bytes, last_id: int, last_hash: str) -> bytes:
    body = {'id': last_id, 'hash': last_hash}
    raw = json.dumps(body, sort_keys=True, separators=(',', ':')).encode()
    return json.dumps({'body': body, 'mac': hmac.new(key, raw, hashlib.sha256).hexdigest()}, sort_keys=True).encode()


def decode(key: bytes, data: bytes) -> tuple[int, str]:
    envelope = json.loads(data)
    body = envelope['body']
    i, h = body['id'], body['hash']
    if type(i) is not int or i < 0 or not isinstance(h, str) or not re.fullmatch('[0-9a-f]{64}', h) or (i == 0 and h != GENESIS):
        raise ValueError('Invalid checkpoint')
    expected = json.loads(encode(key, i, h))['mac']
    if not hmac.compare_digest(expected, envelope['mac']):
        raise ValueError('Checkpoint authentication failed')
    return i, h


def read(path: Path, key: bytes):
    return decode(key, path.read_bytes())


def save(path: Path, data: bytes):
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
        dfd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if os.path.exists(name):
            os.unlink(name)
