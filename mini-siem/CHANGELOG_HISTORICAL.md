# Phase 1 lab candidate

- Added opt-in authenticated TLS syslog, bounded frames/connections/rates, certificate allowlist.
- Added insert-only collector role, separated collector networks, PostgreSQL event storage and 24-hour retention function.
- Added SSO super-admin event search, three heuristic rules, synthetic sender and regression tests.
- No full auth/admin separation, vendor adapters, durable queue or live deployment verification.

# Phase 0.1 — remediation candidate

- Immutable Entra object UUID provisioning and one-time bootstrap.
- Separate worker and emergency database credentials; constrained SQL functions, transactional access revocation and audit writes.
- Audit ID hashing, protected database head, worker-only authenticated checkpoint, atomic local persistence, snapshot-consistent offsite export.
- PostgreSQL TLS certificate provisioning and fail-closed client validation.
- Bounded concurrency-safe rate limiter and complete ASGI response security headers.
- Setup directory and random secret generation fixes; additional regression tests and TLS-verifying smoke test.
- Fresh install required; prior schema and audit evidence deliberately not rewritten.
- Full deployment and independent production acceptance remain pending.

## Phase 0.2 — 2026-11-24
- Strict same-origin form submission and bounded ASGI request parsing; proxy and process resource/time limits.
- Exact version readback and COMPLIANCE retention verification; remote checkpoint rollback detection using version listings.
- Local-only database bootstrap superuser; restricted migration owner; new database constraints and session revalidation.
- Management interface binding; future ClickHouse profile isolated and disabled by default.
- Literal .env parser and restricted host config; secret redaction and stronger OIDC claim checks.
- New regression tests, updated deployment guide, policy example and explicit production blockers.
