"""Live integration fixtures. These tests talk to a REAL deployed lab stack.

They are skipped unless SIEM_LIVE=1. Never point them at production: several
tests deliberately tamper with the audit log as the schema owner and then
restore it.

Required environment:
  SIEM_LIVE=1
  SIEM_LIVE_DEPLOY_DIR   path to the deploy/ folder (secrets/, postgres/tls/ca.crt, .env)
  SIEM_LIVE_PG_ADDR      IP address of the postgres container on the backend network
  SIEM_LIVE_URL          e.g. https://siem.lab.test (must resolve to the Caddy bind IP)
  SIEM_LIVE_WEB_CA       Caddy root CA certificate (lab "tls internal") for TLS verification
Optional:
  SIEM_LIVE_PROJECT      docker compose project name (default mini-siem)
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

LIVE = os.environ.get("SIEM_LIVE") == "1"
pytestmark = pytest.mark.skipif(not LIVE, reason="live lab stack not configured (SIEM_LIVE=1)")


def _env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        pytest.skip(f"{name} not set")
    return value


class Lab:
    def __init__(self) -> None:
        self.deploy = Path(_env("SIEM_LIVE_DEPLOY_DIR"))
        self.pg_addr = _env("SIEM_LIVE_PG_ADDR")
        self.url = _env("SIEM_LIVE_URL").rstrip("/")
        self.web_ca = _env("SIEM_LIVE_WEB_CA")
        self.project = os.environ.get("SIEM_LIVE_PROJECT", "mini-siem")
        self.env = {}
        for line in (self.deploy / ".env").read_text().splitlines():
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                self.env[k] = v

    def secret(self, name: str) -> str:
        return (self.deploy / "secrets" / name).read_text().strip()

    def role(self, kind: str) -> str:
        if kind == "ingest":
            return "siem_ingest"
        return self.env[f"SIEM_DB_{kind.upper()}_USER"]

    def connect(self, kind: str, **kw):
        import psycopg
        from psycopg.rows import dict_row
        return psycopg.connect(
            host="postgres", hostaddr=self.pg_addr, dbname="siem", user=self.role(kind),
            password=self.secret(f"db_{kind}_password"), sslmode="verify-full",
            sslrootcert=str(self.deploy / "postgres/tls/ca.crt"), connect_timeout=5,
            row_factory=dict_row, **kw)

    def bootstrap_sql(self, sql: str) -> str:
        """Run SQL as the local-only bootstrap superuser inside the postgres container."""
        r = subprocess.run(
            ["docker", "exec", "-i", f"{self.project}-postgres-1", "psql", "-U", "siem_bootstrap",
             "-d", "siem", "-v", "ON_ERROR_STOP=1", "-Atq"],
            input=sql, capture_output=True, text=True, timeout=60)
        if r.returncode:
            raise RuntimeError(r.stderr)
        return r.stdout.strip()

    def worker_verify(self) -> tuple[bool, str]:
        """Run the worker's real integrity/export code path once inside the worker container."""
        # A one-off container from the worker service definition (same image, secrets,
        # checkpoint volume, networks). The long-running worker is stopped during the
        # live run so it cannot advance the checkpoint between test steps.
        script = (Path(__file__).parent / "verify_once.py").read_text()
        r = self.compose("run", "--rm", "-T", "--no-deps", "--entrypoint", "python", "worker", "-",
                         input=script)
        out = r.stdout + r.stderr
        return ("RESULT OK" in out and "RESULT DETECTED" not in out), out

    def http(self, **kw):
        import httpx
        return httpx.Client(base_url=self.url, verify=self.web_ca, trust_env=False,
                            follow_redirects=False, timeout=15, headers={"Origin": self.url}, **kw)

    def compose(self, *args: str, input: str | None = None):
        return subprocess.run(["docker", "compose", "-p", self.project, *args], input=input,
                              capture_output=True, text=True, timeout=180, cwd=self.deploy)

    def breakglass_code(self, email: str) -> str:
        r = self.compose("run", "--rm", "-T", "--no-deps", "emergency", "breakglass", email)
        for line in r.stdout.splitlines():
            line = line.strip()
            if len(line) == 43 and " " not in line:
                return line
        raise RuntimeError("no break-glass code issued: " + r.stdout[-500:] + r.stderr[-500:])


@pytest.fixture(scope="session")
def lab() -> Lab:
    if not LIVE:
        pytest.skip("live lab stack not configured")
    lab = Lab()
    lab.compose("stop", "worker")
    yield lab
    lab.compose("start", "worker")
