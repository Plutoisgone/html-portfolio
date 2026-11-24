"""Opt-in mTLS TCP syslog receiver. No UDP or unauthenticated fallback.

Supports RFC 6587 octet-counted and LF-delimited messages, with bounded
connections, deadlines, buffers, and global admission rate. No raw log data
or certificate fingerprints are written to service diagnostics.
"""
from __future__ import annotations
import hashlib
import json
import logging
import re
import socket
import ssl
import threading
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from .events import MAX_FRAME, SOURCE_RE, normalize, persist

LOG = logging.getLogger('siem.collector')
MAX_CLIENTS = 16
CONNECTION_SECONDS = 120
FRAME_SECONDS = 10


class Frames:
    def __init__(self):
        self.buffer = bytearray()
        self.length = None
        self.mode = None

    def feed(self, chunk: bytes):
        if len(chunk) > 4096:
            raise ValueError('Chunk too large')
        self.buffer.extend(chunk)
        while self.buffer:
            if self.mode is None:
                self.mode = 'octet' if 48 <= self.buffer[0] <= 57 else 'line'
            if self.mode == 'octet':
                if self.length is None:
                    pos = self.buffer.find(b' ')
                    if pos < 0:
                        if len(self.buffer) > 4 or not self.buffer.isdigit():
                            raise ValueError('Invalid octet prefix')
                        return
                    prefix = bytes(self.buffer[:pos])
                    if not re.fullmatch(rb'[1-9][0-9]{0,3}', prefix):
                        raise ValueError('Invalid octet prefix')
                    self.length = int(prefix)
                    if self.length > MAX_FRAME:
                        raise ValueError('Oversized frame')
                    del self.buffer[:pos+1]
                if len(self.buffer) < self.length:
                    return
                frame = bytes(self.buffer[:self.length])
                del self.buffer[:self.length]
                self.length = None
            else:
                pos = self.buffer.find(b'\n')
                if pos < 0:
                    if len(self.buffer) > MAX_FRAME + 1:
                        raise ValueError('Oversized frame')
                    return
                frame = bytes(self.buffer[:pos]).removesuffix(b'\r')
                del self.buffer[:pos+1]
                if not 1 <= len(frame) <= MAX_FRAME:
                    raise ValueError('Invalid frame length')
            yield frame


def load_sources(path: Path):
    if path.stat().st_size > 65536:
        raise ValueError('Source registry too large')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate registry key')
            result[key] = value
        return result
    registry = json.loads(path.read_text(), object_pairs_hook=unique)
    if not isinstance(registry, dict) or not 1 <= len(registry) <= 100:
        raise ValueError('Configure 1–100 authenticated sources')
    for fingerprint, source in registry.items():
        if not re.fullmatch(r'[0-9a-f]{64}', fingerprint) or not isinstance(source, str) or not SOURCE_RE.fullmatch(source):
            raise ValueError('Invalid source registration')
    return registry


def tls_context(directory: Path):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(directory / 'server.crt', directory / 'server.key')
    ctx.load_verify_locations(cafile=str(directory / 'client-ca.crt'))
    return ctx


class Admission:
    def __init__(self, rate=5, burst=20):
        self.rate, self.burst = rate, burst
        self.tokens, self.last = float(burst), time.monotonic()
        self.lock = threading.Lock()

    def take(self):
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.burst, self.tokens + (now-self.last)*self.rate)
            self.last = now
            if self.tokens < 1:
                return False
            self.tokens -= 1
            return True


def handle(sock, context, registry, sink, admission, source_limits=None):
    try:
        with sock:
            sock.settimeout(5)
            with context.wrap_socket(sock, server_side=True) as tls:
                source = registry.get(hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest())
                if source is None:
                    return
                deadline = time.monotonic() + CONNECTION_SECONDS
                frame_deadline = min(deadline, time.monotonic() + FRAME_SECONDS)
                frames = Frames()
                while time.monotonic() < frame_deadline:
                    tls.settimeout(max(0.001, frame_deadline-time.monotonic()))
                    chunk = tls.recv(4096)
                    if not chunk:
                        return
                    for frame in frames.feed(chunk):
                        if time.monotonic() >= deadline or (source_limits is not None and not source_limits[source].take()) or not admission.take():
                            return
                        sink(normalize(source, frame))
                        frame_deadline = min(deadline, time.monotonic() + FRAME_SECONDS)
                    if time.monotonic() >= deadline:
                        return
    except (OSError, ValueError):
        # Untrusted peers can repeatedly cause these; avoid log amplification.
        return
    except Exception:
        LOG.error('Ingestion failed; event delivery not guaranteed')


def serve(context, registry, sink):
    slots = threading.BoundedSemaphore(MAX_CLIENTS)
    admission = Admission()
    source_limits = {source: Admission(rate=2, burst=10) for source in set(registry.values())}
    def run(sock):
        try:
            handle(sock, context, registry, sink, admission, source_limits)
        finally:
            slots.release()
    with ThreadPoolExecutor(max_workers=MAX_CLIENTS) as pool, socket.socket(socket.AF_INET) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('0.0.0.0', 6514))
        listener.listen(MAX_CLIENTS)
        while True:
            conn, _ = listener.accept()
            if not slots.acquire(blocking=False):
                conn.close()
                continue
            pool.submit(run, conn)


def main():
    from psycopg_pool import ConnectionPool
    from .config import db_dsn
    logging.basicConfig(level=logging.INFO)
    path = Path('/collector-tls')
    context, registry = tls_context(path), load_sources(path / 'sources.json')
    dsn = db_dsn('SIEM_DB_INGEST_USER', 'db_ingest_password')
    with ConnectionPool(dsn, min_size=1, max_size=4, timeout=3, kwargs={'options':'-c statement_timeout=3000 -c lock_timeout=2000'}) as pool:
        pool.wait(timeout=15)
        def sink(event):
            with pool.connection() as conn:
                persist(conn, event)
        serve(context, registry, sink)


if __name__ == '__main__':
    main()
