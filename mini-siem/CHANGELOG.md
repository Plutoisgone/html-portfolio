# Changelog

## Phase 0.1 — security-hardened release (2026-11-24)

Base: Phase 1 lab candidate (which already contained Phase 0.1/0.2 remediation attempts). Older
entries: `CHANGELOG_HISTORICAL.md`.

### Security fixes
- **Privileged changes enforced in the database** (N2/R2/R8): new migration 5 adds session-authenticated
  `SECURITY DEFINER` admin functions and deferred constraint triggers that refuse to commit any role,
  activation, user-creation or break-glass change without a same-transaction audit record; the web role
  lost `INSERT`/`UPDATE(role,active)` on `users`; audit inserts are column-restricted.
- **Grants reset on every deploy** so privileges removed in a release really disappear after upgrade.
- **OIDC callback** (N1): every token validation failure (joserfc included) is audited and fails closed
  instead of returning an unaudited HTTP 500.
- **Integrity alarms** (N3): `audit_verification` table written by the worker every cycle; audit page shows
  failed / stale / missing verification; warning when no heartbeat URL is configured.
- **Worker**: 60 s cycle (was 300 s), incremental verification + hourly full re-hash, safe recovery of the
  checkpoint crash window (N6), bounded S3 listing (N7), `python -m siem.worker --verify-once`.
- **Rate limiter** (R5): token buckets, < 12 MB at 50,000 sources, overflow bucket instead of global lockout, IPv6 /64 grouping.
- **Caddy**: security headers also on Caddy-generated errors (R9), `Server` header stripped, header size and upstream timeouts.
- **PostgreSQL**: generated `pg_hba.conf` binds each role to its own Docker network (N5); hardened derived
  image without `gosu`, with `apk upgrade` and HEALTHCHECK.
- **Supply chain** (N4): app base moved to Debian 13 (103 → 53 HIGH, 2 → 0 CRITICAL); all images pinned by
  digest; GitHub Actions pinned to commit SHAs; scanners run from digest-pinned images; meaningful Trivy gate;
  Gitleaks and IaC scanning in CI; SBOMs (CycloneDX + SPDX).
- **Host**: Docker repository key fingerprint verified (N9); auditd watch on the checkpoint directory.
- **CLI**: `verify-audit` clearly labelled database-only (N8).

### New
- `deploy/backup.sh`, `deploy/restore.sh` (N11); `deploy/verify-deployment.sh` (runtime CIS-Docker checks).
- Tests: `tests/live/` (99 live tests), `test_oidc_integration.py`, `test_fuzz_properties.py` (Hypothesis),
  `test_setup_script.py`, `tests/load/locustfile.py`; rewritten `db_acceptance.sql`.
- Documentation: SECURITY_ASSESSMENT, PENETRATION_TEST_REPORT, VULNERABILITY_REMEDIATION, THREAT_MODEL,
  SECURITY_ARCHITECTURE, TEST_RESULTS, WAZUH_COMPARISON, DEPLOYMENT_GUIDE; raw outputs in `evidence/`.

### Behaviour changes
- `.env` requires `COLLECT_DB_SUBNET`.
- Users page shows the Entra object ID instead of "linked".
- Smoke test uses a unique user per run and checks the independent verification banner.

### Known limitations
See SECURITY_ASSESSMENT.md §4. Not production-approved.
