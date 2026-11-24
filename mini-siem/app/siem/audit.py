"""Tamper-evident audit log.

Each row stores the hash of the previous row, so deleting or editing any row
in the middle breaks the chain and `verify_chain` reports it. Rows are also
append-only at the database level and exported to immutable S3 storage.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from typing import Any
from contextlib import nullcontext

from . import db

GENESIS = "0" * 64
AUDIT_LOCK_KEY = 7312

CRITICAL_ACTIONS = {
    "auth.breakglass.login",
    "auth.breakglass.token_created",
    "user.role_changed",
    "user.created",
    "user.deactivated",
    "auth.login.denied",
}


def _canonical(row: dict[str, Any]) -> str:
    return json.dumps(row, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(prev_hash: str, record: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + _canonical(record)).encode()).hexdigest()


def _record(ts: datetime, actor: str, action: str, target: str | None, severity: str,
            ip: str | None, user_agent: str | None, details: dict) -> dict[str, Any]:
    return {
        "ts": ts.astimezone(timezone.utc).isoformat(),
        "actor": actor,
        "action": action,
        "target": target,
        "severity": severity,
        "ip": ip,
        "user_agent": user_agent,
        "details": details,
    }


def write(actor: str, action: str, target: str | None = None, *, ip: str | None = None,
          user_agent: str | None = None, details: dict | None = None,
          severity: str | None = None, conn=None) -> None:
    details = details or {}
    if severity is None:
        severity = "critical" if action in CRITICAL_ACTIONS else "info"
    ua = (user_agent or "")[:300] or None
    ip = str(ipaddress.ip_address(ip)) if ip else None
    with (db.tx() if conn is None else nullcontext(conn)) as conn:
        # Serialise writers so the chain has no forks.
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (AUDIT_LOCK_KEY,))
        last = conn.execute("SELECT last_id, last_hash FROM audit_head WHERE id = 1").fetchone()
        record_id, prev = last["last_id"] + 1, last["last_hash"]
        ts = datetime.now(timezone.utc)
        rec = _record(ts, actor, action, target, severity, ip, ua, details)
        rec["id"] = record_id
        h = compute_hash(prev, rec)
        conn.execute(
            """INSERT INTO audit_log (id, ts, actor, action, target, severity, ip, user_agent,
                                      details, prev_hash, hash)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)""",
            (record_id, ts, actor, action, target, severity, ip, ua, json.dumps(details), prev, h),
        )


def verify_rows(rows, *, start_id=0, start_hash=GENESIS, expected=None):
    """Verify an ordered contiguous sequence from an explicit trusted anchor."""
    last_id, prev = start_id, start_hash
    for r in rows:
        if r["id"] != last_id + 1 or r["prev_hash"] != prev:
            return False, r["id"]
        ip = str(r["ip"]) if r["ip"] is not None else None
        ts = r["ts"]
        rec = _record(ts if isinstance(ts, datetime) else datetime.fromisoformat(ts),
                      r["actor"], r["action"], r["target"], r["severity"], ip,
                      r["user_agent"], r["details"])
        rec["id"] = r["id"]
        if compute_hash(prev, rec) != r["hash"]:
            return False, r["id"]
        last_id, prev = r["id"], r["hash"]
    if expected is not None and (last_id, prev) != expected:
        return False, last_id + 1
    return True, None


def verify_snapshot(conn, anchor=None):
    """Caller uses a repeatable-read transaction; stream rows in bounded batches."""
    head = conn.execute("SELECT last_id, last_hash FROM audit_head WHERE id=1").fetchone()
    if not head:
        return False, 0
    if anchor is not None:
        aid, ahash = anchor
        if aid == 0:
            if ahash != GENESIS:
                return False, 0
        else:
            row = conn.execute("SELECT hash FROM audit_log WHERE id=%s", (aid,)).fetchone()
            if not row or row["hash"] != ahash:
                return False, aid
    with conn.cursor(name="audit_verify") as cur:
        cur.execute("SELECT * FROM audit_log ORDER BY id")
        return verify_rows(cur, expected=(head["last_id"], head["last_hash"]))


def verify_from_anchor(conn, anchor):
    """Cheap per-cycle check: the anchored row is unchanged and every row after it
    chains correctly up to the protected head. Rows *before* the anchor are only
    re-hashed by the periodic full scan (verify_snapshot)."""
    head = conn.execute("SELECT last_id, last_hash FROM audit_head WHERE id=1").fetchone()
    if not head:
        return False, 0
    aid, ahash = anchor
    if head["last_id"] < aid:
        return False, aid  # head rolled back below the externally anchored position
    if aid == 0:
        if ahash != GENESIS:
            return False, 0
    else:
        row = conn.execute("SELECT hash FROM audit_log WHERE id=%s", (aid,)).fetchone()
        if not row or row["hash"] != ahash:
            return False, aid
    with conn.cursor(name="audit_verify_incremental") as cur:
        cur.execute("SELECT * FROM audit_log WHERE id > %s ORDER BY id", (aid,))
        return verify_rows(cur, start_id=aid, start_hash=ahash,
                           expected=(head["last_id"], head["last_hash"]))


def verify_chain(anchor=None):
    with db.tx() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        return verify_snapshot(conn, anchor)


def verify_recent(limit=5000):
    with db.tx() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        head = conn.execute("SELECT last_id,last_hash FROM audit_head WHERE id=1").fetchone()
        if not head:
            return False, 0
        rows = conn.execute("SELECT * FROM (SELECT * FROM audit_log ORDER BY id DESC LIMIT %s) t ORDER BY id", (limit,)).fetchall()
        start_id = max(0, head["last_id"] - limit)
        anchor = conn.execute("SELECT hash FROM audit_log WHERE id=%s", (start_id,)).fetchone() if start_id else None
        if start_id and not anchor:
            return False, start_id
        return verify_rows(rows, start_id=start_id, start_hash=anchor["hash"] if anchor else GENESIS,
                           expected=(head["last_id"], head["last_hash"]))
