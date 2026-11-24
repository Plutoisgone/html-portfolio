"""Regression for the reported deployment defect (missing clickhouse/users.d/) and the
rest of setup.sh: runs the REAL script in a disposable copy of deploy/, twice.

Needs root (it chowns to container UIDs), bash, openssl and python3; skipped otherwise.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
pytestmark = pytest.mark.skipif(os.geteuid() != 0 or not shutil.which("openssl"),
                                reason="setup.sh needs root and openssl")

ENV = {
    "SIEM_HOSTNAME": "siem.lab.test", "SIEM_BIND_IP": "192.0.2.10",
    "SIEM_OIDC_TENANT_ID": "11111111-1111-4111-8111-111111111111",
    "SIEM_OIDC_CLIENT_ID": "22222222-2222-4222-8222-222222222222",
    "SIEM_INITIAL_SUPER_ADMIN_OIDS": "33333333-3333-4333-8333-333333333333",
}


def _prepare(tmp_path: Path, **over) -> Path:
    d = tmp_path / "deploy"
    shutil.copytree(DEPLOY, d, ignore=shutil.ignore_patterns("secrets", ".env", "tls", "users.d"))
    lines = []
    for line in (d / ".env.example").read_text().splitlines():
        k = line.split("=", 1)[0]
        if k in ENV:
            line = f"{k}={ENV[k]}"
        if k == "DATA_DIR":
            line = f"DATA_DIR={tmp_path / 'data'}"
        if k in over:
            line = f"{k}={over[k]}"
        lines.append(line)
    (d / ".env").write_text("\n".join(lines) + "\n")
    return d


def _run(d: Path):
    return subprocess.run(["bash", str(d / "setup.sh")], capture_output=True, text=True, timeout=180)


def test_clean_setup_creates_every_directory_and_is_rerunnable(tmp_path):
    d = _prepare(tmp_path)
    assert not (d / "clickhouse/users.d").exists()      # the Phase 0 failure condition
    r = _run(d)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (d / "clickhouse/users.d/users.xml").is_file()
    data = tmp_path / "data"
    for sub, uid, mode in [("postgres", 70, 0o700), ("audit-state", 10001, 0o700), ("caddy/data", 10002, 0o700)]:
        st_ = (data / sub).stat()
        assert st_.st_uid == uid and stat.S_IMODE(st_.st_mode) == mode, sub
    for name in ["db_bootstrap_password", "db_owner_password", "db_app_password", "db_worker_password",
                 "db_emergency_password", "db_ingest_password", "audit_checkpoint_key", "session_secret"]:
        p = d / "secrets" / name
        assert stat.S_IMODE(p.stat().st_mode) == 0o440 and len(p.read_text().strip()) == 64, name
    key = d / "postgres/tls/server.key"
    assert stat.S_IMODE(key.stat().st_mode) == 0o640 and key.stat().st_gid == 70
    hba = (d / "postgres/pg_hba.conf").read_text()
    assert "hostssl   siem  siem_ingest     172.31.250.64/28" in hba and "hostnossl all   all" in hba
    before = {p.name: p.read_text() for p in (d / "secrets").iterdir()}
    r2 = _run(d)
    assert r2.returncode == 0, r2.stdout + r2.stderr
    assert before == {p.name: p.read_text() for p in (d / "secrets").iterdir()}, "secrets must never be regenerated"


@pytest.mark.parametrize("key,value", [("SIEM_BIND_IP", "0.0.0.0"), ("COLLECT_DB_SUBNET", "172.31.250.32/27"),
                                       ("SIEM_DB_APP_USER", "siem_owner"), ("DATA_DIR", "relative/path")])
def test_unsafe_settings_rejected(tmp_path, key, value):
    d = _prepare(tmp_path, **{key: value})
    assert _run(d).returncode != 0


def test_env_file_is_not_executed(tmp_path):
    d = _prepare(tmp_path)
    marker = tmp_path / "pwned"
    with open(d / ".env", "a") as f:
        f.write(f"SIEM_TLS=$(touch {marker})\n")
    _run(d)
    assert not marker.exists()
