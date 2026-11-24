# Phase 0.2 — Test evidence

Executed in the isolated review container on 2026-11-24, using the available installed Python libraries, not the complete pinned deployment environment.

| Test | Result |
|---|---|
| Original unit and security regression tests | 19 passed |
| New Phase 0.2 tests | 24 passed |
| Authentication/authorization tests (Authlib import mocked; database and OAuth mocked where required) | 13 passed |
| Combined local tests | 56 passed, split as 43 using available real libraries and 13 with mocked Authlib boundary |
| Temporary setup script executions | 2 passed |
| PostgreSQL certificate CA and hostname check using OpenSSL | Passed |
| Compose YAML parse and selected static assertions | Passed; not a Docker Compose validation |
| Python compile and shell syntax | Passed |
| Dependency installation attempt | Failed: configured package index provided no Authlib distribution; no lock installation or CVE scan completed |
| PostgreSQL, Caddy, Docker, nftables runtime | NOT TESTED |
| Live Entra, Wasabi, TLS network, backup restoration, ZAP, load, container escape and external network scans | NOT TESTED |

Reproduce after installing the hash-pinned requirements and pytest:

```
cd app
python -m pip install --require-hashes --no-deps -r requirements.txt
python -m pytest -q tests/test_unit.py tests/test_security_regression.py tests/test_phase02.py tests/test_auth.py
python -m compileall -q siem tests
```

The 13 mocked tests exercise claims and route handling; they do not validate real JWT signatures, OIDC code flow, or real database privilege changes. Fake S3 tests prove application decisions, not Wasabi behavior. Tests are supplied in `app/tests/` and must be repeated with the pinned stack. No production acceptance or numerical security score is warranted.
