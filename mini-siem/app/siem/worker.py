"""Background worker: run with `python -m siem.worker`.

Every cycle it:
1. Exports new audit rows to S3 (Wasabi) with Object Lock in COMPLIANCE mode,
   so no one - including an admin - can delete them before retention ends.
2. Verifies the full audit hash chain and logs a critical event if it is broken.
3. Deletes expired sessions and break-glass codes.
4. Pings the external dead-man's switch URL, if configured. If the pings stop,
   the external service alerts the team.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import logging
import time
from datetime import datetime, timedelta, timezone
import re
import sys
from urllib.parse import urlsplit

import boto3
import httpx
from botocore.config import Config as BotoConfig

from . import audit, db, checkpoint
from pathlib import Path
from .config import Settings, db_dsn, env, secret

log = logging.getLogger("siem.worker")
CYCLE_SECONDS = 60          # bounds the unanchored (truncatable) window
FULL_SCAN_EVERY = 60        # full re-hash of the whole chain hourly (and at start)
EXPORT_BATCH = 250


def s3_client(settings: Settings):
    return boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint or None,
        region_name=settings.s3_region or None,
        aws_access_key_id=settings.s3_access_key,
        aws_secret_access_key=settings.s3_secret_key,
        # Some S3-compatible stores (e.g. Wasabi) reject the newer default checksums;
        # we send Content-MD5 ourselves, which Object Lock uploads require.
        config=BotoConfig(connect_timeout=5, read_timeout=30, retries={"max_attempts": 5, "mode": "standard"},
                          request_checksum_calculation="when_required",
                          response_checksum_validation="when_required"),
    )


def build_export(rows: list[dict]) -> bytes:
    lines = "\n".join(json.dumps(r, default=str, sort_keys=True) for r in rows) + "\n"
    return gzip.compress(lines.encode())


CHECKPOINT_PATH = Path('/audit-state/checkpoint.json')



def require_https(value: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('Expected an HTTPS URL without userinfo or fragment')


def verify_remote_object(s3, bucket, object_key, version, body, retain):
    """Read back the exact object version and verify COMPLIANCE retention and bytes."""
    if not version or version == 'null':
        raise RuntimeError('Immutable object version missing')
    result = s3.get_object(Bucket=bucket, Key=object_key, VersionId=version)
    stream = result['Body']
    try:
        if result.get('ObjectLockMode') != 'COMPLIANCE' or result.get('VersionId') != version or not isinstance(result.get('ObjectLockRetainUntilDate'), datetime) or result['ObjectLockRetainUntilDate'] < retain:
            raise RuntimeError('Object retention not verified')
        # Bound reads, including unexpected remote content.
        if stream.read(len(body) + 1) != body:
            raise RuntimeError('Remote object differs from uploaded bytes')
    finally:
        stream.close()


def newest_remote_checkpoint(s3, bucket, key, after_id):
    """Newest authenticated, COMPLIANCE-locked checkpoint at or after the local one.

    The listing starts just before the batch that produced the local checkpoint
    (keys are zero-padded and sort by first id; a batch is at most EXPORT_BATCH
    rows), so its cost no longer grows with the age of the bucket.
    """
    newest = None
    marker = f"audit/{max(0, after_id - EXPORT_BATCH):012d}"
    pages = s3.get_paginator('list_object_versions').paginate(Bucket=bucket, Prefix='audit/', KeyMarker=marker)
    for page in pages:
        for obj in page.get('Versions', []):
            name = obj['Key']
            match = re.fullmatch(r'audit/(\d{12,})-(\d{12,})-([0-9a-f]{64})\.checkpoint\.json', name)
            if match:
                i = int(match[2])
                if newest is None or i > newest[0]:
                    newest = (i, name, match[3], obj['VersionId'])
                elif i == newest[0] and match[3] != newest[2]:
                    raise RuntimeError('Conflicting remote audit checkpoints')
    if newest is None:
        return None
    result = s3.get_object(Bucket=bucket, Key=newest[1], VersionId=newest[3])
    stream = result['Body']
    try:
        if result.get('ObjectLockMode') != 'COMPLIANCE' or result.get('VersionId') != newest[3] or not isinstance(result.get('ObjectLockRetainUntilDate'), datetime) or result['ObjectLockRetainUntilDate'] <= datetime.now(timezone.utc):
            raise RuntimeError('Remote checkpoint is not immutable')
        data = stream.read(4097)
        if len(data) > 4096:
            raise RuntimeError('Remote checkpoint too large')
        remote = checkpoint.decode(key, data)
    finally:
        stream.close()
    if remote != (newest[0], newest[2]):
        raise RuntimeError('Remote checkpoint name and content disagree')
    return remote


def verify_remote_anchor(s3, bucket, key, anchor, conn=None):
    """Detect local checkpoint rollback against the newest authenticated remote checkpoint.

    Returns the anchor to use. Bucket/prefix must be dedicated to this installation.
    The one disagreement that is resolved automatically is the crash window between
    uploading a batch's checkpoint and saving it locally: remote is ahead by at most
    one batch AND the database rows between the two checkpoints chain exactly from
    the local anchor to the remote one. Anything else stops the worker for operator
    investigation; never reset a checkpoint to clear an error.
    """
    remote = newest_remote_checkpoint(s3, bucket, key, anchor[0])
    if remote is None:
        if anchor != (0, audit.GENESIS):
            raise RuntimeError('Remote checkpoint missing; explicit recovery/backfill required')
        return anchor
    if remote == anchor:
        return anchor
    if conn is not None and anchor[0] < remote[0] <= anchor[0] + EXPORT_BATCH:
        rows = conn.execute("SELECT * FROM audit_log WHERE id>%s AND id<=%s ORDER BY id",
                            (anchor[0], remote[0])).fetchall()
        ok, _ = audit.verify_rows(rows, start_id=anchor[0], start_hash=anchor[1], expected=remote)
        if ok:
            log.warning('Adopting remote checkpoint %s (local was %s): interrupted export recovered',
                        remote[0], anchor[0])
            return remote
    raise RuntimeError('Local and remote checkpoints disagree; investigate before proceeding')


class AuditIntegrityError(RuntimeError):
    def __init__(self, first_bad):
        super().__init__(f"Audit integrity failed at {first_bad}")
        self.first_bad = first_bad


def export_audit(settings: Settings, key: bytes, s3=None, full: bool = True) -> int:
    anchor = checkpoint.read(CHECKPOINT_PATH, key)  # missing or invalid is fatal
    total = 0
    # Verify and export from the same database snapshot, preventing a verification/export race.
    with db.tx() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        if settings.audit_export_enabled:
            s3 = s3 or s3_client(settings)
            adopted = verify_remote_anchor(s3, settings.s3_bucket, key, anchor, conn=conn)
            if adopted != anchor:
                checkpoint.save(CHECKPOINT_PATH, checkpoint.encode(key, *adopted))
                anchor = adopted
        ok, bad = audit.verify_snapshot(conn, anchor) if full else audit.verify_from_anchor(conn, anchor)
        if not ok:
            raise AuditIntegrityError(bad)
        while True:
            rows = conn.execute("SELECT * FROM audit_log WHERE id>%s ORDER BY id LIMIT %s", (anchor[0], EXPORT_BATCH)).fetchall()
            if not rows:
                return total
            first, last = rows[0]['id'], rows[-1]['id']
            next_anchor = (last, rows[-1]['hash'])
            signed = checkpoint.encode(key, *next_anchor)
            if settings.audit_export_enabled:
                prefix = f"audit/{first:012d}-{last:012d}-{next_anchor[1]}"
                retain = (datetime.now(timezone.utc) + timedelta(days=settings.audit_retention_days)).replace(microsecond=0)
                for suffix, body, content_type in [('.jsonl.gz', build_export(rows), 'application/gzip'), ('.checkpoint.json', signed, 'application/json')]:
                    md5 = base64.b64encode(hashlib.md5(body, usedforsecurity=False).digest()).decode()
                    result = s3.put_object(Bucket=settings.s3_bucket, Key=prefix+suffix, Body=body,
                                  ContentMD5=md5, ContentType=content_type, ObjectLockMode='COMPLIANCE',
                                  ObjectLockRetainUntilDate=retain)
                    verify_remote_object(s3, settings.s3_bucket, prefix+suffix, result.get("VersionId"), body, retain)
            checkpoint.save(CHECKPOINT_PATH, signed)
            anchor = next_anchor
            total += len(rows)


def cleanup() -> None:
    db.execute("SELECT cleanup_expired()")
    db.execute("SELECT prune_security_events()")


def heartbeat(settings: Settings) -> None:
    if settings.heartbeat_url:
        httpx.get(settings.heartbeat_url, timeout=10, trust_env=False, follow_redirects=False).raise_for_status()


def _safe_detail(exc: BaseException | None, exported: int = 0) -> str:
    if exc is None:
        return f"ok exported {exported}"
    if isinstance(exc, AuditIntegrityError):
        return f"AuditIntegrityError at id {int(exc.first_bad)}"
    return re.sub(r"[^A-Za-z0-9_]", "", type(exc).__name__)[:80] or "Error"


def record_status(ok: bool, full: bool, key: bytes, detail: str) -> None:
    """Best effort: a database that cannot take this row shows up as a stale status."""
    try:
        ckpt = checkpoint.read(CHECKPOINT_PATH, key)[0]
    except Exception:
        ckpt = 0
    try:
        db.execute("INSERT INTO audit_verification (ok, full_scan, checkpoint_id, detail) VALUES (%s,%s,%s,%s)",
                   (ok, full, ckpt, detail[:160]))
    except Exception as exc:
        log.error("Could not record verification status (%s)", type(exc).__name__)


def run_cycle(settings: Settings, key: bytes, state: dict | None = None) -> int:
    """Integrity check + export first, then housekeeping. No heartbeat on any failure:
    the external dead-man's switch must alert."""
    state = state if state is not None else {}
    cycle = state.get("cycle", 0)
    state["cycle"] = cycle + 1
    full = cycle % FULL_SCAN_EVERY == 0
    try:
        exported = export_audit(settings, key, full=full)
    except Exception as exc:
        record_status(False, full, key, _safe_detail(exc))
        raise
    record_status(True, full, key, _safe_detail(None, exported))
    cleanup()
    heartbeat(settings)
    return exported


def worker_settings() -> Settings:
    # Empty strings are unused web settings, not credentials.
    return Settings(  # nosec B106
        hostname='', oidc_tenant_id='', oidc_client_id='', oidc_client_secret='',
                    initial_super_admins=[], session_secret='', db_dsn=db_dsn('SIEM_DB_WORKER_USER', 'db_worker_password'),
                    s3_endpoint=env('SIEM_S3_ENDPOINT'), s3_bucket=env('SIEM_S3_BUCKET'), s3_region=env('SIEM_S3_REGION'),
                    s3_access_key=secret('s3_access_key', required=False), s3_secret_key=secret('s3_secret_key', required=False),
                    audit_retention_days=int(env('SIEM_AUDIT_RETENTION_DAYS', '365')), heartbeat_url=env('SIEM_HEARTBEAT_URL'))


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    argv = sys.argv[1:] if argv is None else argv
    settings = worker_settings()
    if settings.s3_bucket and not settings.audit_export_enabled:
        raise RuntimeError('S3 configured without credentials')
    for url in (settings.s3_endpoint, settings.heartbeat_url):
        if url:
            require_https(url)
    if settings.audit_retention_days < 1:
        raise RuntimeError('Retention must be positive')
    key = bytes.fromhex(secret('audit_checkpoint_key'))
    if len(key) != 32:
        raise RuntimeError('Invalid checkpoint key')
    db.init_pool(settings.db_dsn, min_size=1, max_size=2)
    if argv == ["--verify-once"]:
        # Operator command: full anchored verification (+ export of pending rows).
        try:
            exported = export_audit(settings, key, full=True)
        except Exception as exc:
            record_status(False, True, key, _safe_detail(exc))
            print(f"Audit chain BROKEN or unverifiable: {_safe_detail(exc)}")
            return 1
        record_status(True, True, key, _safe_detail(None, exported))
        print(f"Audit chain OK; anchored checkpoint at id {checkpoint.read(CHECKPOINT_PATH, key)[0]}")
        return 0
    if argv:
        print("usage: python -m siem.worker [--verify-once]")
        return 2
    if not settings.audit_export_enabled:
        log.warning('S3 disabled: checkpoint is local only; do not enable S3 later without explicit backfill.')
    if not settings.heartbeat_url:
        log.warning('SIEM_HEARTBEAT_URL not set: integrity failures are visible only on the audit page '
                    'and in these logs. Configure an external dead-man\'s switch for production.')
    state: dict = {}
    while True:
        try:
            run_cycle(settings, key, state)
        except Exception as exc:
            # Exception messages may include signed URLs, database DSNs or credentials.
            log.error('Audit integrity/export or cleanup failure (%s); heartbeat withheld', _safe_detail(exc))
        time.sleep(CYCLE_SECONDS)


if __name__ == "__main__":
    sys.exit(main())
