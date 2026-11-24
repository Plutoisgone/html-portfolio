# Test evidence

## Executed

- `cd app && python -m pytest -q tests/test_unit.py tests/test_security_regression.py` — **19 passed**. Includes audit tampering (six mutations), explicit segment anchor, checkpoint HMAC and missing state, simulated snapshot rollback, bounded concurrent rate limiting, error HTTP headers and CSRF.
- `tests/test_auth.py` — **8 passed using a temporary mocked Authlib import boundary**. No real Authlib execution, OIDC or PostgreSQL connection. The test cases exercise identity mapping and the application transaction/deny paths with fake connections. No fallback stubs are shipped in application code.
- Setup script executed twice on a throwaway copy as root, with synthetic UUIDs and temporary data directory. Both completed; missing ClickHouse users directory generated. OpenSSL verified the PostgreSQL certificate CA and DNS hostname. Generated key mode 0640 root:70 and checkpoint mode 0600 uid/gid 10001 were observed; checkpoint authenticated successfully. No host hardening script executed.
- Python compilation, YAML parsing and shell syntax checks performed. These do not demonstrate that images build or services start.

## Not executed / blockers

Docker, PostgreSQL client/server and pinned Authlib/psycopg dependencies are unavailable in the test environment. Installing missing dependencies failed. Local installed FastAPI/Starlette versions differ from the project's pinned versions. Full stack build, live OIDC, PostgreSQL TLS and privileges, Wasabi Object Lock, Caddy config validation, Hyper-V deployment, CVE/dependency scanning, external penetration tests, load and resource measurements, and backup/restore remain NOT TESTED. No claims of zero CVEs or compliance are made.

## Reproduce on an authorized lab

1. In a Python 3.12 environment install the hashed requirements and pytest: `cd app && python -m pip install --require-hashes --no-deps -r requirements.txt && python -m pip install pytest`.
2. `python -m pytest -q tests/test_unit.py tests/test_auth.py tests/test_security_regression.py` (real dependencies; still mock DB in selected unit tests).
3. Follow DEPLOYMENT_GUIDE.md to start the isolated lab; run `db_acceptance.sql`, smoke tests and negative TLS/identity tests. Validate all security gates before deployment.
4. Run original CI workflow for Bandit, Semgrep, pip-audit, ShellCheck and Trivy. Resolve scan failures; pin verified image digests. Run external DAST and load testing only on the authorized lab.
