# Phase 1 test results

Executed locally in the isolated development container on the release source:

```text
cd app
PYTHONPATH=. pytest -q tests/test_events.py tests/test_unit.py tests/test_security_regression.py tests/test_phase02.py
80 passed
```

43 inherited tests and 37 new Phase 1 cases. New cases cover rules, malformed payloads, authenticated source identity vs claimed source fields, priority parsing, fragmented framing, bounds, rate limiting, parameterized query construction, HTML escaping, registry duplicate detection, and three actual TLS socket handshakes (enrolled certificate accepted; unregistered certificate signed by trusted CA and missing certificate rejected). TLS tests use temporary OpenSSL-generated certificates and an in-memory event sink, not a deployed collector or database. The persistence/query tests use mocks. Tests do not establish full vendor compatibility or end-to-end deployment success.

Other executed checks:
- Python source compilation: passed.
- Shell syntax checks for setup, host hardening, PostgreSQL initialization: passed.
- Compose YAML parsing and selected collector isolation structural assertions: passed (not Docker Compose runtime validation).
- Setup script: two successful runs using a disposable directory and synthetic settings. Collector directory created; generated ingest password unchanged on rerun. No generated secrets or test certificates packaged.
- OpenSSL strict validation of generated PostgreSQL server certificate against CA and hostname: passed.

Not executed: original `test_auth.py` (Authlib unavailable), live Docker deployment, PostgreSQL schema/grants and SQL acceptance tests (psycopg and PostgreSQL unavailable), Entra sign-in and route authorization, live host firewall checks, Wasabi Object Lock, real vendor compatibility, throughput benchmarking, dependency and image CVE scans, full penetration testing. The CI workflow contains scanning tasks, but no fresh CI execution is claimed. See PHASE1_GUIDE.md for the manual acceptance gates.

Release decision: **isolated synthetic-log lab candidate only; not production approved**.
