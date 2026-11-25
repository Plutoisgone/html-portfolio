"""LIVE: a ClickHouse outage must not take the web UI down.

The app has no compose dependency on clickhouse/ch_migrate, so with ClickHouse
stopped the app still (re)starts, reports healthy, and serves PostgreSQL-backed
pages such as the audit log. ClickHouse is always started again afterwards.
"""
from __future__ import annotations

import time

import pytest

from .test_live_http import BOSS, breakglass_login, known_users  # noqa: F401

pytestmark = pytest.mark.live


def _health(lab, service):
    cid = lab.compose("ps", "-q", service).stdout.strip()
    r = lab.compose("ps", "--format", "{{.Health}}", service)
    return cid, r.stdout.strip()


def _wait(lab, service, want, timeout=150):
    end = time.time() + timeout
    while time.time() < end:
        if _health(lab, service)[1] == want:
            return True
        time.sleep(3)
    return False


def test_app_serves_while_clickhouse_is_stopped(lab, known_users):  # noqa: F811
    try:
        r = lab.compose("stop", "clickhouse")
        assert r.returncode == 0, r.stderr
        assert lab.compose("ps", "-q", "--status", "running", "clickhouse").stdout.strip() == ""
        # A fresh start of the web app must not wait for (or start) ClickHouse.
        r = lab.compose("up", "-d", "--no-build", "--force-recreate", "app")
        assert r.returncode == 0, r.stderr
        assert lab.compose("ps", "-q", "--status", "running", "clickhouse").stdout.strip() == ""
        assert _wait(lab, "app", "healthy"), lab.compose("ps", "-a").stdout
        r = lab.compose("exec", "-T", "app", "python", "-c",
                        "import urllib.request as u; print(u.urlopen('http://127.0.0.1:8000/healthz', timeout=5).status)")
        assert r.stdout.strip() == "200", r.stdout + r.stderr
        c, _, _ = breakglass_login(lab, BOSS[0])
        page = c.get("/admin/audit")
        assert page.status_code == 200, page.text[:300]
        assert "audit" in page.text.lower()
    finally:
        lab.compose("start", "clickhouse")
        assert _wait(lab, "clickhouse", "healthy"), lab.compose("ps", "-a").stdout
