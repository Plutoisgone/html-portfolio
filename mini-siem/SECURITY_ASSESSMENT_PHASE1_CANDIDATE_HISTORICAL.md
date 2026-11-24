# Phase 1 security assessment

This is a delta assessment, not an independent full penetration test. Earlier findings and fixes are preserved in SECURITY_ASSESSMENT_PHASE01_HISTORICAL.md and SECURITY_ASSESSMENT_PHASE02_HISTORICAL.md.

| Control | Implementation / evidence |
|---|---|
| Unauthenticated log input | mTLS and leaf allowlist; actual local TLS tests pass |
| Source identity spoofing in log body | Certificate mapping only; unit test passes |
| Unbounded framing and malformed records | 8 KiB cap, connection and time limits, strict UTF-8/control validation; parser tests pass |
| Excessive ingest privileges | New restricted DB role and isolated service network; SQL acceptance test included but unexecuted |
| SQL injection and unsafe display | Bound SQL parameters and autoescaping; unit tests pass |
| Unrestricted cross-customer reads | Global console restricted to SSO super-admin; no tenant isolation claimed; live RBAC test pending |
| Sensitive search terms in access logs | Uvicorn access logging disabled; inherited Caddy config omits request URI; runtime verification pending |
| Log storage pressure | Bounded admission, 24-hour batched pruning; no hard disk quota, queue, or delivery guarantee |
| Collector egress | Dedicated named bridge and host firewall rules; runtime verification pending |
| Database TLS | Strict CA/hostname verification in setup; certificate generation checked, live DB TLS pending |

Residual high-priority risks: inherited app can modify authentication/admin tables; full privilege separation is incomplete. New ingest account can forge or flood events if stolen. A compromised trusted sender can generate false signals. Log delivery is best-effort and device logs are not immutable. No CVE scan results, live container tests, PostgreSQL permission validation, cross-tenant assurance, or independent pentest. Use synthetic logs only. See PHASE1_GUIDE.md for acceptance steps and operational limitations.
