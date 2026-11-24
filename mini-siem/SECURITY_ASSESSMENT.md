# Security assessment and release decision — Mini-SIEM Phase 0.1 (hardened)

Date: 2026-11-24 · Scope: full source, configuration, dependencies, container images and deployment
scripts of the release in this archive (Phase 0 foundation + opt-in Phase 1 lab collector).
Companion documents: VULNERABILITY_REMEDIATION.md (per-finding detail), PENETRATION_TEST_REPORT.md,
THREAT_MODEL.md, SECURITY_ARCHITECTURE.md, TEST_RESULTS.md, WAZUH_COMPARISON.md.

## 1. What was done

1. Extracted and reviewed **both** supplied archives line by line (Phase 0: 3,529 lines; Phase 1 lab
   candidate: 5,265 lines). The candidate was chosen as the code base (owner decision).
2. Deployed each version live and attacked it with real credentials (§ PENETRATION_TEST_REPORT.md).
3. Verified every reported finding against source and, where possible, live behaviour.
4. Fixed the remaining and newly found issues in the real source; added regression tests that fail on
   the vulnerable code and pass on the release.
5. Re-ran everything on a clean install, an in-place upgrade, and a restore from backup.

## 2. Findings overview

| Severity | Reported (R1–R10) | New (N1–N11) | Open after Phase 0.1 |
|---|---|---|---|
| Critical | 0 | 0 | 0 |
| High | 4 | 0 | **0** |
| Medium | 4 | 4 (N1–N4) | 0 open; N4 partially remediated with documented accepted residual (unfixed upstream CVEs) |
| Low | 1 (+1 deployment) | 6 | 0 |

Container CVEs (Trivy): app image 53 HIGH / 0 CRITICAL, **0 with an available fix**; see TEST_RESULTS.md §6.

## 3. Acceptance criteria (from the release brief)

| Criterion | Status | Evidence |
|---|---|---|
| All reported vulnerabilities independently verified; remediated or disproven | **Met** — 10/10 confirmed, 10/10 remediated | VULNERABILITY_REMEDIATION.md |
| Regression test for every remediated vulnerability | **Met** | test map in VULNERABILITY_REMEDIATION.md; `evidence/regression-tests-vs-candidate-code.txt` |
| No unresolved critical/high findings | **Met** for the tested scope | §2 |
| Medium/low fixed or justified | **Met** (N4 residual justified) | VULNERABILITY_REMEDIATION.md N4 |
| Clean installation succeeds in the target environment | **Partially met** — succeeded on Ubuntu 24.04 + Docker (fresh and upgrade); **unverified on a Hyper-V VM with `harden.sh` applied** | TEST_RESULTS.md §1–2 |
| Authentication and authorization tests pass | **Met** at integration level (real JOSE validation, live RBAC); **live Entra ID not tested** | TEST_RESULTS.md |
| Audit integrity detects deletion, truncation, modification, reordering within the threat model | **Met** (live, owner-credential attacker; documented ≤ ~60 s post-checkpoint window) | `test_live_audit_tamper.py` |
| Database permissions enforce least privilege | **Met** (live, every role) | `db_acceptance.sql`, `test_live_hardening.py` |
| Resource use within 4 vCPU / 8 GB under a documented workload | **Met** for the documented workloads (< 250 MiB RSS, < 1 vCPU) | TEST_RESULTS.md §5 |
| Existing functionality does not regress | **Met** — all 93 inherited tests still pass (some updated for intentional behaviour changes), smoke test 25/25 | `evidence/unit-junit.xml`, `evidence/smoke-test.txt` |

## 4. Residual risks accepted for this release

1. Post-checkpoint truncation window (≤ ~60 s) for an attacker with owner/superuser DB access.
2. Host root, worker compromise (HMAC key) and a compromised web process acting as a logged-in admin (THREAT_MODEL A5, A7, A9).
3. Caddy → app plain HTTP on a dedicated two-member bridge.
4. No two-person rule for super-admin actions; no multi-tenant isolation; Phase 1 events not anchored.
5. 53 unfixed Debian HIGH CVEs; 2 Caddy HIGH CVEs in unused code paths; Postgres libxml2 fix not verified here.
6. Untested external dependencies: Entra ID, Wasabi Object Lock, AppArmor, Hyper-V; ZAP and Grype not run.
7. In-process rate limiting (single app replica by design).

## 5. Release decision

**APPROVED for an isolated lab / pilot on the target Hyper-V VM with synthetic data.**
**NOT APPROVED for production or customer data.**

Production gate (all required):

1. Install on the real Hyper-V VM with `host/harden.sh`; `deploy/verify-deployment.sh` reports **0 failures** (incl. AppArmor).
2. Live Entra ID tests: bootstrap oid, unassigned user, foreign tenant, MFA/Conditional Access enforced.
3. Wasabi: export enabled, delete/overwrite of an exported object refused, retention verified, heartbeat monitor alerting.
4. OWASP ZAP authenticated scan and Grype scan with no unresolved High.
5. Rebuild with `APK_UPGRADE=1`/`APT_UPGRADE=1` on the release date and re-scan.
6. Independent third-party penetration test of the deployed VM.

This release is **not** vulnerability-free and is **not** claimed to be unhackable. It is the strongest
foundation we could realistically build and verify in this environment before Phase 1 work resumes.
