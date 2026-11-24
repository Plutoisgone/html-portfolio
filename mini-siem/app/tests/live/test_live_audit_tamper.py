"""LIVE: audit-log tampering by an attacker holding the schema-owner credential.

Regression for the reported "audit log integrity bypass" (record ID modification,
truncation, complete deletion) plus edit, reorder and full-chain recomputation.

Attacker model used here: stolen migration/owner DB password, network access to
PostgreSQL. The owner can disable the append-only triggers, so the defence under
test is the worker's HMAC checkpoint, which lives outside PostgreSQL.

Each scenario: write rows -> worker checkpoints -> owner tampers -> the worker's
REAL code path runs once -> bootstrap superuser restores the original rows.
"""
from __future__ import annotations

import json

import pytest

from siem import audit

pytestmark = pytest.mark.live

RESTORE = """
ALTER TABLE audit_log DISABLE TRIGGER USER;
DELETE FROM audit_log;
INSERT INTO audit_log SELECT * FROM audit_tamper_backup;
UPDATE audit_head h SET last_id=b.last_id, last_hash=b.last_hash FROM audit_head_tamper_backup b WHERE h.id=1;
ALTER TABLE audit_log ENABLE TRIGGER USER;
DROP TABLE audit_tamper_backup; DROP TABLE audit_head_tamper_backup;
"""


def _write_rows(lab, n: int) -> None:
    with lab.connect("app") as conn:
        for i in range(n):
            with conn.transaction():
                audit.write("live-test", "test.tamper_fixture", target=f"row-{i}",
                            details={"i": i, "unicode": "Zürich ✓"}, conn=conn)


@pytest.fixture
def checkpointed(lab):
    """Rows covered by a fresh checkpoint, plus 3 rows written after it."""
    _write_rows(lab, 5)
    ok, out = lab.worker_verify()
    assert ok, f"baseline chain must verify before tampering:\n{out}"
    with lab.connect("worker") as c:
        ckpt = c.execute("SELECT last_id FROM audit_head").fetchone()["last_id"]
    _write_rows(lab, 3)
    lab.bootstrap_sql("CREATE TABLE audit_tamper_backup AS SELECT * FROM audit_log;"
                      "CREATE TABLE audit_head_tamper_backup AS SELECT * FROM audit_head;")
    yield ckpt
    lab.bootstrap_sql(RESTORE)
    ok, out = lab.worker_verify()
    assert ok, f"restore must leave a verifiable chain:\n{out}"


def _owner(lab, sql_list):
    with lab.connect("owner") as conn:
        with conn.transaction():
            conn.execute("ALTER TABLE audit_log DISABLE TRIGGER USER")
            for sql in sql_list:
                conn.execute(sql)
            conn.execute("ALTER TABLE audit_log ENABLE TRIGGER USER")


def _recompute_from(lab, start_id: int) -> None:
    """Owner rewrites every hash from start_id onward so the DB chain is self-consistent."""
    with lab.connect("owner") as conn:
        with conn.transaction():
            conn.execute("ALTER TABLE audit_log DISABLE TRIGGER USER")
            prev = conn.execute("SELECT hash FROM audit_log WHERE id=%s", (start_id - 1,)).fetchone()
            prev = prev["hash"] if prev else audit.GENESIS
            rows = conn.execute("SELECT * FROM audit_log WHERE id>=%s ORDER BY id", (start_id,)).fetchall()
            for r in rows:
                rec = audit._record(r["ts"], r["actor"], r["action"], r["target"], r["severity"],
                                    str(r["ip"]) if r["ip"] else None, r["user_agent"], r["details"])
                rec["id"] = r["id"]
                h = audit.compute_hash(prev, rec)
                conn.execute("UPDATE audit_log SET prev_hash=%s, hash=%s WHERE id=%s", (prev, h, r["id"]))
                prev = h
            last = rows[-1]["id"] if rows else start_id - 1
            conn.execute("UPDATE audit_head SET last_id=%s, last_hash=%s WHERE id=1", (last, prev))
            conn.execute("ALTER TABLE audit_log ENABLE TRIGGER USER")


def _assert_detected(lab, scenario):
    ok, out = lab.worker_verify()
    assert not ok, f"{scenario}: tampering was NOT detected\n{out}"


def test_owner_can_disable_triggers_so_checkpoint_is_required(lab, checkpointed):
    """Documents the threat: the owner really can bypass the DB-level append-only trigger."""
    _owner(lab, ["UPDATE audit_log SET actor='attacker' WHERE id=2"])
    with lab.connect("worker") as c:
        assert c.execute("SELECT actor FROM audit_log WHERE id=2").fetchone()["actor"] == "attacker"
    _assert_detected(lab, "edit")


def test_record_id_modification_detected(lab, checkpointed):
    _owner(lab, [f"UPDATE audit_log SET id=id+100000 WHERE id={checkpointed - 1}"])
    _assert_detected(lab, "id modification")


def test_reordering_detected(lab, checkpointed):
    a, b = checkpointed - 2, checkpointed - 1
    tmp = 900_000_000  # schema enforces id > 0
    _owner(lab, [f"UPDATE audit_log SET id={tmp} WHERE id={a}", f"UPDATE audit_log SET id={a} WHERE id={b}",
                 f"UPDATE audit_log SET id={b} WHERE id={tmp}"])
    _assert_detected(lab, "reorder")


def test_truncation_into_checkpointed_range_detected(lab, checkpointed):
    keep = checkpointed - 2
    with lab.connect("owner") as c:
        h = c.execute("SELECT hash FROM audit_log WHERE id=%s", (keep,)).fetchone()["hash"]
    _owner(lab, [f"DELETE FROM audit_log WHERE id>{keep}",
                 f"UPDATE audit_head SET last_id={keep}, last_hash='{h}' WHERE id=1"])
    _assert_detected(lab, "tail truncation (head rewritten)")


def test_complete_deletion_detected(lab, checkpointed):
    _owner(lab, ["DELETE FROM audit_log", f"UPDATE audit_head SET last_id=0, last_hash='{audit.GENESIS}' WHERE id=1"])
    _assert_detected(lab, "complete deletion (head reset to genesis)")


def test_full_chain_recomputation_detected(lab, checkpointed):
    """Edit an old row, then recompute every later hash and the head, as a capable attacker would."""
    with lab.connect("owner") as c:
        c.execute("ALTER TABLE audit_log DISABLE TRIGGER USER")
        c.execute("UPDATE audit_log SET details=%s::jsonb WHERE id=2", (json.dumps({"forged": True}),))
        c.execute("ALTER TABLE audit_log ENABLE TRIGGER USER")
        c.commit()
    _recompute_from(lab, 2)
    _assert_detected(lab, "rewrite + full recomputation")


def test_truncation_after_last_checkpoint_is_a_documented_residual(lab, checkpointed):
    """Rows written after the newest checkpoint have no external anchor yet.

    Deleting ONLY those rows (and rewriting the head) is not detectable by any
    hash-chain design until it is anchored. This test pins that documented
    residual window so a change in behaviour is noticed either way.
    """
    with lab.connect("owner") as c:
        h = c.execute("SELECT hash FROM audit_log WHERE id=%s", (checkpointed,)).fetchone()["hash"]
    _owner(lab, [f"DELETE FROM audit_log WHERE id>{checkpointed}",
                 f"UPDATE audit_head SET last_id={checkpointed}, last_hash='{h}' WHERE id=1"])
    ok, out = lab.worker_verify()
    assert ok, "behaviour changed: post-checkpoint truncation is now detected; update THREAT_MODEL.md"
