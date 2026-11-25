"""LIVE checks of the ClickHouse event store (against the deployed lab).

* HTTPS 8443 is the only listener; plaintext HTTP (8123) and native TCP (9000) are gone.
* The server certificate is only accepted with the setup CA (name "clickhouse").
* Each account can do only its job: ingest can INSERT into siem.events but never read,
  the reader can only SELECT, and only the rows of the customers named in the
  per-query setting SQL_siem_customer_ids (nothing at all without it).

All rows are synthetic and tagged with a per-run source_id, removed afterwards.
"""
from __future__ import annotations

import secrets
import socket
import ssl

import httpx
import pytest

pytestmark = pytest.mark.live


@pytest.fixture(scope="module")
def ch_addr(lab):
    return lab.container_ip("clickhouse")


def _ok(r) -> str:
    assert r.status_code == 200, r.text[:500]
    return r.text.strip()


def _denied(r, *codes: int):
    assert r.status_code != 200, "query was allowed: " + r.text[:200]
    assert any(f"Code: {c}." in r.text for c in codes), r.text[:500]


@pytest.fixture(scope="module")
def seeded(lab):
    """Rows for customers 1, 2 and 3, written by the migration account."""
    tag = "live-" + secrets.token_hex(6)
    rows = ",".join(f"({c}, '{tag}', 'synthetic', 3, 5, 'deny', 'test', 'synthetic event {i}', '{{}}')"
                    for i, c in enumerate([1, 1, 1, 2, 2, 3]))
    _ok(lab.ch("siem_admin", "INSERT INTO siem.events (customer_id, source_id, product, severity, wazuh_level, "
                             f"action, rule, message, raw) VALUES {rows}"))
    yield tag
    lab.ch("siem_admin", f"DELETE FROM siem.events WHERE source_id = '{tag}'")


# ------------------------------------------------------------------ transport
@pytest.mark.parametrize("port", [8123, 9000, 9440, 9004, 9005, 9009])
def test_plaintext_and_other_ports_refused(ch_addr, port):
    with pytest.raises(OSError):
        socket.create_connection((ch_addr, port), timeout=3).close()


def test_https_with_wrong_ca_refused(lab):
    with pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED"):
        lab.ch("siem_reader", "SELECT 1", ca=lab.web_ca)


def test_https_with_wrong_name_refused(lab, ch_addr):
    ctx = ssl.create_default_context(cafile=str(lab.deploy / "postgres/tls/ca.crt"))
    with httpx.Client(verify=ctx, trust_env=False, timeout=10) as c:
        with pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED"):
            c.get(f"https://{ch_addr}:8443/ping")      # name = IP address, not "clickhouse"


@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1])
def test_old_tls_versions_refused(lab, ch_addr, version):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ctx.maximum_version = version
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    with socket.create_connection((ch_addr, 8443), timeout=5) as raw:
        with pytest.raises(ssl.SSLError) as e:
            ctx.wrap_socket(raw, server_hostname="clickhouse")
    if "NO_PROTOCOLS_AVAILABLE" in str(e.value):
        pytest.skip(f"local OpenSSL cannot offer {version.name}; cannot probe the server")
    # The SERVER refused it (protocol_version alert), not the local library.
    assert "ALERT_PROTOCOL_VERSION" in str(e.value), e.value


def test_tls12_and_tls13_accepted(lab, ch_addr):
    ctx = ssl.create_default_context(cafile=str(lab.deploy / "postgres/tls/ca.crt"))
    for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        ctx.minimum_version = ctx.maximum_version = version
        with socket.create_connection((ch_addr, 8443), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname="clickhouse") as tls:
                assert tls.version() == version.name.replace("TLSv1_", "TLSv1.")


def test_ping_and_admin_login_over_verified_tls(lab):
    assert _ok(lab.ch("siem_admin", "SELECT 1")) == "1"


def test_bad_password_refused(lab, ch_addr):
    ctx = ssl.create_default_context(cafile=str(lab.deploy / "postgres/tls/ca.crt"))
    with httpx.Client(verify=ctx, trust_env=False, timeout=10) as c:
        r = c.post(f"https://{ch_addr}:8443/", content=b"SELECT 1", extensions={"sni_hostname": "clickhouse"},
                   headers={"X-ClickHouse-User": "siem_reader", "X-ClickHouse-Key": "wrong"})
    _denied(r, 516)


def test_default_user_removed(lab, ch_addr):
    ctx = ssl.create_default_context(cafile=str(lab.deploy / "postgres/tls/ca.crt"))
    with httpx.Client(verify=ctx, trust_env=False, timeout=10) as c:
        r = c.post(f"https://{ch_addr}:8443/", content=b"SELECT 1", extensions={"sni_hostname": "clickhouse"})
    _denied(r, 194, 516)   # REQUIRED_PASSWORD / AUTHENTICATION_FAILED: no such user


# ------------------------------------------------------------------ schema
def test_tables_are_customer_keyed(lab):
    out = _ok(lab.ch("siem_admin", "SELECT name, sorting_key, engine FROM system.tables WHERE database='siem' "
                                   "ORDER BY name FORMAT TSV"))
    assert out.splitlines() == ["alerts\tcustomer_id, product, alert_id\tReplacingMergeTree",
                                "events\tcustomer_id, received_at\tMergeTree"]
    ttl = _ok(lab.ch("siem_admin", "SELECT create_table_query FROM system.tables WHERE database='siem' "
                                   "AND name='events' FORMAT TSVRaw"))
    assert f"toIntervalDay({lab.env.get('SIEM_EVENT_RETENTION_DAYS', '90')})" in ttl


# ------------------------------------------------------------------ ingest account
def test_ingest_can_insert_events_only(lab, seeded):
    _ok(lab.ch("siem_ingest", "INSERT INTO siem.events (customer_id, source_id, product, severity, wazuh_level, "
                              f"action, rule, message, raw) VALUES (9, '{seeded}', 'synthetic', 1, 1, 'allow', "
                              "'test', 'ingest test', '{}')"))
    _denied(lab.ch("siem_ingest", "SELECT count() FROM siem.events"), 497)
    _denied(lab.ch("siem_ingest", "SELECT count() FROM siem.alerts"), 497)
    _denied(lab.ch("siem_ingest", "INSERT INTO siem.alerts (customer_id, alert_id, alert_time, product, severity, "
                                  "wazuh_level, title, vendor_url, raw) VALUES (1, 'x', now64(3), 'p', 1, 1, 't', '', '')"),
            497)
    _denied(lab.ch("siem_ingest", "ALTER TABLE siem.events DELETE WHERE 1"), 497)
    _denied(lab.ch("siem_ingest", "SELECT count() FROM system.query_log"), 497, 60)


# ------------------------------------------------------------------ reader account
@pytest.mark.parametrize("sql", [
    "INSERT INTO siem.events (customer_id, source_id, product, severity, wazuh_level, action, rule, message, raw) "
    "VALUES (1, 'x', 'p', 1, 1, 'allow', 'r', 'm', '')",
    "ALTER TABLE siem.events DELETE WHERE 1",
    "ALTER TABLE siem.events MODIFY TTL toDateTime(received_at) + INTERVAL 1 DAY",
    "DROP TABLE siem.events",
    "TRUNCATE TABLE siem.events",
    "DROP ROW POLICY customer_scope ON siem.events",
    "CREATE TABLE siem.pwn (i UInt8) ENGINE = Memory",
    "SELECT count() FROM system.users",
    "SELECT count() FROM system.query_log",
    "SELECT * FROM file('/etc/passwd', 'LineAsString')",
])
def test_reader_cannot_write_or_escape(lab, sql):
    # 164 READONLY, 497 ACCESS_DENIED, 60 UNKNOWN_TABLE (query_log not yet created)
    _denied(lab.ch("siem_reader", sql), 164, 497, 60)


@pytest.mark.parametrize("setting", [{"readonly": "0"}, {"max_result_rows": "0"},
                                     {"max_execution_time": "0"}, {"max_memory_usage": "0"}])
def test_reader_cannot_lift_its_limits(lab, setting):
    _denied(lab.ch("siem_reader", "SELECT 1", settings=setting), 164)


def _reader_count(lab, tag, ids=None):
    settings = {} if ids is None else {"SQL_siem_customer_ids": ids}
    return lab.ch("siem_reader", f"SELECT count() FROM siem.events WHERE source_id = '{tag}'", settings=settings)


def test_reader_sees_nothing_without_customer_setting(lab, seeded):
    assert _ok(lab.ch("siem_admin", f"SELECT count() FROM siem.events WHERE source_id = '{seeded}'")) in ("6", "7")
    assert _ok(_reader_count(lab, seeded)) == "0"          # getSettingOrDefault: unset -> no rows, no error
    assert _ok(_reader_count(lab, seeded, "")) == "0"
    assert _ok(lab.ch("siem_reader", "SELECT count() FROM siem.alerts")) == "0"


def test_reader_sees_only_listed_customers(lab, seeded):
    assert _ok(_reader_count(lab, seeded, "1")) == "3"
    assert _ok(lab.ch("siem_reader", f"SELECT DISTINCT customer_id FROM siem.events WHERE source_id = '{seeded}'",
                      settings={"SQL_siem_customer_ids": "1"})) == "1"
    assert _ok(_reader_count(lab, seeded, "2")) == "2"
    assert _ok(_reader_count(lab, seeded, "1,3")) == "4"
    # Junk or partial ids never widen the scope.
    for junk in ("1 ", " 1", "01", "*", "%", "1;2", "0", "4294967297", "true", "1 OR 1"):
        assert _ok(_reader_count(lab, seeded, junk)) == "0", junk


def test_reader_cannot_bypass_policy_with_own_filter(lab, seeded):
    out = _ok(lab.ch("siem_reader", f"SELECT count() FROM siem.events WHERE source_id = '{seeded}' "
                                    "AND customer_id IN (2, 3)", settings={"SQL_siem_customer_ids": "1"}))
    assert out == "0"
