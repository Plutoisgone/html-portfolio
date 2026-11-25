"""ClickHouse schema. Applied once per deploy by the one-shot `ch_migrate` service,
connected as `siem_admin` over HTTPS (port 8443, server certificate verified
against the setup CA). The app reads as `siem_reader`, the collector will write as
`siem_ingest`; neither can change the schema.

Every table is keyed by customer first. The row policy is a second, independent
fence behind the app's own customer filter: `siem_reader` sees only rows whose
customer_id is listed in the per-query setting SQL_siem_customer_ids, and nothing
at all when the setting is missing.

Plain HTTPS through httpx (already a dependency) is enough for a handful of DDL
statements; the driver for the query layer comes with Task 3.

Usage: python -m siem.ch_schema
"""
from __future__ import annotations

import re
import ssl
import sys

import httpx

from .config import ConfigError, env, secret

DEFAULT_RETENTION_DAYS = 90
MAX_RETENTION_DAYS = 730
TABLES = ("events", "alerts")

_EVENTS = """CREATE TABLE IF NOT EXISTS siem.events (
    customer_id UInt32,
    received_at DateTime64(3, 'UTC') DEFAULT now64(3),
    event_time Nullable(DateTime64(3, 'UTC')),
    source_id LowCardinality(String),
    product LowCardinality(String),
    severity UInt8,
    wazuh_level UInt8,
    src_ip Nullable(IPv6),
    src_port Nullable(UInt16),
    dst_ip Nullable(IPv6),
    dst_port Nullable(UInt16),
    `user` Nullable(String),
    action LowCardinality(String),
    rule String,
    message String,
    raw String CODEC(ZSTD(3))
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(received_at)
ORDER BY (customer_id, received_at)
TTL toDateTime(received_at) + INTERVAL {days} DAY"""

# ReplacingMergeTree: the same vendor alert ID delivered twice collapses to one row.
_ALERTS = """CREATE TABLE IF NOT EXISTS siem.alerts (
    customer_id UInt32,
    alert_id String,
    received_at DateTime64(3, 'UTC') DEFAULT now64(3),
    alert_time DateTime64(3, 'UTC'),
    product LowCardinality(String),
    severity UInt8,
    wazuh_level UInt8,
    title String,
    vendor_url String,
    raw String CODEC(ZSTD(3))
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(received_at)
ORDER BY (customer_id, product, alert_id)
TTL toDateTime(received_at) + INTERVAL {days} DAY"""

ROW_POLICY = (
    "CREATE ROW POLICY OR REPLACE customer_scope ON siem.events, siem.alerts FOR SELECT "
    "USING has(splitByChar(',', getSettingOrDefault('SQL_siem_customer_ids', '')), toString(customer_id)) "
    "TO siem_reader"
)


def retention_days() -> int:
    raw = env("SIEM_EVENT_RETENTION_DAYS", str(DEFAULT_RETENTION_DAYS))
    if not re.fullmatch(r"[0-9]{1,4}", raw or ""):
        raise ConfigError("SIEM_EVENT_RETENTION_DAYS must be a whole number of days")
    days = int(raw)
    if not 1 <= days <= MAX_RETENTION_DAYS:
        raise ConfigError(f"SIEM_EVENT_RETENTION_DAYS must be between 1 and {MAX_RETENTION_DAYS}")
    return days


def table_ddl(days: int) -> dict[str, str]:
    days = int(days)
    return {"events": _EVENTS.format(days=days), "alerts": _ALERTS.format(days=days)}


def statements(days: int) -> list[str]:
    return ["CREATE DATABASE IF NOT EXISTS siem", *table_ddl(days).values(), ROW_POLICY]


class Admin:
    """Minimal ClickHouse HTTPS client for the migration account."""

    def __init__(self) -> None:
        host = env("SIEM_CH_HOST", "clickhouse")
        port = int(env("SIEM_CH_PORT", "8443"))
        ctx = ssl.create_default_context(cafile=env("SIEM_CH_CA_FILE", required=True))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._client = httpx.Client(
            base_url=f"https://{host}:{port}", verify=ctx, trust_env=False, timeout=60,
            headers={"X-ClickHouse-User": env("SIEM_CH_ADMIN_USER", "siem_admin"),
                     "X-ClickHouse-Key": secret("ch_admin_password")})

    def run(self, sql: str) -> str:
        r = self._client.post("/", content=sql.encode())
        if r.status_code != 200:
            raise RuntimeError(f"ClickHouse error {r.status_code}: {r.text[:500]}")
        return r.text

    def close(self) -> None:
        self._client.close()


def apply(admin, days: int) -> None:
    for sql in statements(days):
        admin.run(sql)
    # CREATE ... IF NOT EXISTS keeps an old TTL; bring retention in line with .env.
    for table in TABLES:
        current = admin.run(
            f"SELECT create_table_query FROM system.tables WHERE database='siem' AND name='{table}' FORMAT TSVRaw")
        # ClickHouse stores the TTL normalised as toIntervalDay(N).
        found = re.search(r"TTL toDateTime\(received_at\) \+ (?:toIntervalDay\((\d+)\)|INTERVAL (\d+) DAY)", current)
        if not found or int(found.group(1) or found.group(2)) != days:
            print(f"Setting {table} retention to {days} days")
            admin.run(f"ALTER TABLE siem.{table} MODIFY TTL toDateTime(received_at) + INTERVAL {days} DAY")


def main() -> int:
    days = retention_days()
    admin = Admin()
    try:
        apply(admin, days)
    finally:
        admin.close()
    print(f"ClickHouse schema is up to date (retention {days} days).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
