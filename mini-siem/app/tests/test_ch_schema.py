"""Offline checks of the ClickHouse schema (siem.ch_schema) and the users.xml written by setup.sh.

* Every table is keyed by customer first, so per-customer reads stay cheap and the
  row policy filters on the leading key column.
* Event retention is bounded.
* The ingest account can only INSERT into siem.events; it can never read back.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

import pytest

from siem import ch_schema
from siem.config import ConfigError

from test_setup_script import _prepare, _run, pytestmark as _root_only


def _order_by(ddl: str) -> list[str]:
    m = re.search(r"ORDER BY \(([^)]*)\)", ddl)
    assert m, ddl
    return [c.strip() for c in m.group(1).split(",")]


def test_every_table_starts_order_by_with_customer_id():
    tables = ch_schema.table_ddl(90)
    assert set(tables) == {"events", "alerts"}
    for name, ddl in tables.items():
        assert ddl.startswith(f"CREATE TABLE IF NOT EXISTS siem.{name} "), name
        assert re.search(r"\(\s*customer_id UInt32,", ddl), name
        assert _order_by(ddl)[0] == "customer_id", name
        assert "TTL toDateTime(received_at) + INTERVAL 90 DAY" in ddl, name
    assert "ENGINE = MergeTree" in tables["events"]
    assert "PARTITION BY toYYYYMM(received_at)" in tables["events"]
    # Dedup by vendor ID must not be split across months by arrival time.
    assert "PARTITION BY toYYYYMM(alert_time)" in tables["alerts"]
    assert ch_schema.ALERTS_PARTITION_KEY == "toYYYYMM(alert_time)"
    assert _order_by(tables["events"]) == ["customer_id", "received_at"]
    assert "ENGINE = ReplacingMergeTree" in tables["alerts"]
    assert _order_by(tables["alerts"]) == ["customer_id", "product", "alert_id"]


def test_row_policy_scopes_reader_by_customer_setting():
    sql = ch_schema.ROW_POLICY
    assert "ON siem.events, siem.alerts FOR SELECT" in sql
    assert "getSettingOrDefault('SQL_siem_customer_ids', '')" in sql
    assert "toString(customer_id)" in sql
    assert sql.rstrip().endswith("TO siem_reader")


def test_retention_bounds(monkeypatch):
    monkeypatch.delenv("SIEM_EVENT_RETENTION_DAYS", raising=False)
    assert ch_schema.retention_days() == 90
    for ok in ("1", "730", "365"):
        monkeypatch.setenv("SIEM_EVENT_RETENTION_DAYS", ok)
        assert ch_schema.retention_days() == int(ok)
    for bad in ("0", "731", "-5", "abc", "90 DAY", ""):
        monkeypatch.setenv("SIEM_EVENT_RETENTION_DAYS", bad)
        with pytest.raises(ConfigError):
            ch_schema.retention_days()


class _FakeAdmin:
    def __init__(self, stored_days, alerts_key="toYYYYMM(alert_time)", alerts_rows=0):
        self.sql, self.stored, self.key, self.rows = [], stored_days, alerts_key, alerts_rows

    def run(self, sql):
        self.sql.append(sql)
        if sql.startswith("SELECT partition_key"):
            return self.key
        if sql.startswith("SELECT count() FROM siem.alerts"):
            return str(self.rows)
        if sql.startswith("SELECT create_table_query"):
            return f"CREATE TABLE siem.x (...) TTL toDateTime(received_at) + toIntervalDay({self.stored}) SETTINGS x"
        return ""


def test_apply_changes_ttl_only_when_retention_changed():
    same = _FakeAdmin(90)
    ch_schema.apply(same, 90)
    assert not [s for s in same.sql if "MODIFY TTL" in s]
    assert [x for x in same.sql if not x.startswith("SELECT")][:4] == ch_schema.statements(90)
    assert not [x for x in same.sql if x.startswith("DROP")]
    changed = _FakeAdmin(90)
    ch_schema.apply(changed, 30)
    assert [s for s in changed.sql if "MODIFY TTL" in s] == [
        f"ALTER TABLE siem.{t} MODIFY TTL toDateTime(received_at) + INTERVAL 30 DAY" for t in ("events", "alerts")]


def _users(tmp_path):
    d = _prepare(tmp_path)
    r = _run(d)
    assert r.returncode == 0, r.stdout + r.stderr
    return d, ET.parse(d / "clickhouse/users.d/users.xml").getroot()


def _grants(user) -> list[str]:
    return [q.text.strip() for q in user.findall("grants/query")]


@_root_only
def test_ingest_user_has_no_select(tmp_path):
    d, root = _users(tmp_path)
    users = root.find("users")
    assert users.find("default").get("remove") == "remove"
    ingest = users.find("siem_ingest")
    assert _grants(ingest) == ["GRANT INSERT ON siem.events"]
    assert not any("SELECT" in g or "ALL" in g for g in _grants(ingest))
    assert [ip.text for ip in ingest.findall("networks/ip")] == ["172.31.250.32/27", "172.31.250.64/28"]
    reader = users.find("siem_reader")
    assert _grants(reader)[0] == "GRANT SELECT ON siem.*"
    assert not any(re.search(r"INSERT|ALTER|DROP|CREATE|ALL", g) for g in _grants(reader))
    assert [ip.text for ip in reader.findall("networks/ip")] == ["172.31.250.32/27"]
    assert [ip.text for ip in users.find("siem_admin").findall("networks/ip")] == ["172.31.250.32/27"]
    # Readonly profile: only the customer-scope setting may be changed per query.
    prof = root.find("profiles/siem_readonly")
    assert prof.find("readonly").text == "1"
    changeable = [c.tag for c in prof.find("constraints") if c.find("changeable_in_readonly") is not None]
    assert changeable == ["SQL_siem_customer_ids"]
    assert users.find("siem_reader/profile").text == "siem_readonly"
    # Reserved for Plan 4: the secret exists, but no ClickHouse account uses it yet.
    assert (d / "secrets/ch_connector_password").is_file()
    assert users.find("siem_connector") is None


@_root_only
def test_clickhouse_server_cert_signed_by_setup_ca(tmp_path):
    import subprocess
    d, _ = _users(tmp_path)
    tls = d / "clickhouse/tls"
    r = subprocess.run(["openssl", "verify", "-CAfile", str(d / "postgres/tls/ca.crt"), "-verify_hostname",
                        "clickhouse", str(tls / "server.crt")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    st = (tls / "server.key").stat()
    assert st.st_gid == 101 and st.st_mode & 0o777 == 0o640


def test_old_alerts_partition_key_recreated_only_when_empty():
    for missing in ("",):                                   # fresh install: nothing to drop
        fresh = _FakeAdmin(90, alerts_key=missing)
        ch_schema.apply(fresh, 90)
        assert not [x for x in fresh.sql if x.startswith("DROP")]
    old = _FakeAdmin(90, alerts_key="toYYYYMM(received_at)")
    ch_schema.apply(old, 90)
    drop = old.sql.index("DROP TABLE siem.alerts SYNC")
    create = next(i for i, x in enumerate(old.sql) if x.startswith("CREATE TABLE IF NOT EXISTS siem.alerts"))
    assert drop < create
    full = _FakeAdmin(90, alerts_key="toYYYYMM(received_at)", alerts_rows=5)
    with pytest.raises(RuntimeError, match="holds 5 rows"):
        ch_schema.apply(full, 90)
    assert not [x for x in full.sql if x.startswith("DROP")]
