# Penetration test report — Mini-SIEM Phase 0.1

| | |
|---|---|
| Date | 2026-11-24 |
| Authorization / scope | The project owner's own isolated development lab only: Docker stack bound to `192.0.2.2` (`siem.lab.test`), its PostgreSQL on internal bridges, the CLI. No third-party, Entra, Wasabi or customer systems were touched. |
| Targets | (1) Phase 0 original — deployment only; (2) Phase 1 lab candidate — full; (3) Phase 0.1 release — full re-test |
| Approach | Grey/white box: source review + live attacks with each real credential type an attacker might steal |
| Tester | AI-assisted engineering review (Claude). **This is not an independent third-party penetration test.** |

## 1. Executive summary

All ten reported vulnerabilities were confirmed against Phase 0. The Phase 1 candidate had already fixed
most of them, but live testing against it found **three Medium issues that unit tests with mocks had
hidden**:

1. the web application's database credential could silently make anyone a super admin;
2. forged ID tokens caused unhandled 500 errors and were never audited;
3. a fully re-hashed (tampered) audit chain was still shown as "intact" in the console.

It also found that proxy-generated error pages had no security headers.

All of these are fixed in Phase 0.1 and have regression tests that fail on the candidate code and
pass on the release. **No exploitable Critical or High issue remains in the tested scope.** Untested
surfaces (live Entra ID, Wasabi, AppArmor on the real VM, OWASP ZAP) are listed in §5.

## 2. Attack narrative and results (Phase 0.1 release)

| # | Attack | Technique | Result | Evidence |
|---|---|---|---|---|
| P1 | Reach services from outside | Nmap all 65,535 TCP ports on bind IP | Only 443 (Mini-SIEM); DB/app not exposed | `evidence/nmap-bind-ip-allports.txt` |
| P2 | Weak TLS | `ssl-enum-ciphers` | TLS 1.2/1.3, ECDHE+AEAD only, grade A | `evidence/nmap-tls-443.txt` |
| P3 | Forge an Entra login | unsigned / wrong-key / HS256-confusion / wrong issuer, tenant, audience / expired / nonce replay / state replay | Rejected, audited, no session | `test_oidc_integration.py` |
| P4 | Session attacks | random, garbage, SQL-ish cookies; fixation (pre-planted cookie); reuse after logout; idle expiry | All rejected; new token issued at login | `test_live_http.py` |
| P5 | CSRF / cross-origin | POST with no / `null` / foreign / http origin; missing CSRF token | 403, no state change | `test_live_http.py` |
| P6 | Vertical privilege escalation via UI | analyst session → admin pages and admin POSTs | 403 | `test_live_http.py` |
| P7 | Escalation with stolen web DB password | `UPDATE users SET role`, `INSERT users`, admin functions with no/garbage/analyst/expired token | `42501` permission denied / not authorized | `test_live_hardening.py` |
| P8 | Escalation with stolen DB password + live admin token, hiding it | call `admin_set_role` but skip the audit write; forge `txid` | COMMIT refused; `txid` not insertable | `test_live_hardening.py` |
| P9 | Audit tampering as schema owner | disable triggers then edit / renumber / reorder / truncate / delete all / edit + re-hash entire chain | Detected by worker; alarm on audit page | `test_live_audit_tamper.py`, `test_tampering_is_surfaced_on_audit_page` |
| P10 | Audit rollback via old backup | restore older dump while checkpoint is newer | `AuditIntegrityError at id 554` | `evidence/dr-rollback-detection.txt` |
| P11 | Break-glass abuse | replay, demote/deactivate/delete owner before use, expiry, CLI for analyst, 8 parallel consumers | Rejected; exactly one winner | `test_live_http.py` |
| P12 | Race on last super admin | two admins deactivate each other concurrently | ≥ 1 super admin remains | `test_last_super_admin_race` |
| P13 | Injection | SQLi strings and UNION in event search; Hypothesis fuzzing of the query builder | Parameterised; SQL text independent of input | live + `test_fuzz_properties.py` |
| P14 | Stored XSS | `<script>`/`onerror` payloads inserted as events, rendered in console | Escaped; CSP `default-src 'none'` | `test_stored_xss_in_event_is_escaped…` |
| P15 | Path traversal | `/static/../`, encoded variants, `//etc/passwd` | 404, no file content | `test_static_path_traversal` |
| P16 | Lateral DB movement | ingest credential from backend net; plaintext; bootstrap over network; wrong TLS host name | All rejected by pg_hba/TLS | `test_live_hardening.py` |
| P17 | Role privilege abuse | 26 forbidden statements across app/worker/emergency/owner | All denied | `test_role_is_denied` |
| P18 | Resource exhaustion | 1,500 req/s for 120 s; 50k-source limiter flood (unit); oversized/ambiguous bodies | Bounded (<250 MiB total), no crash, 413/429/503 with headers | `evidence/load-flood-*`, tests |
| P19 | Container escape surface | runtime inspection of every container | non-root, CapEff=0, NoNewPrivs, seccomp, read-only; AppArmor unavailable in lab | `evidence/verify-deployment.txt` |
| P20 | Secrets exposure | Gitleaks over tree + git history; `docker inspect` env; settings `repr` | No leaks; secrets only as files per service | `evidence/gitleaks-*` |

## 3. Findings discovered by live testing of the Phase 1 candidate

| ID | Severity | Finding | Proof (candidate) | Status |
|---|---|---|---|---|
| N2 | Medium | `siem_app` could `UPDATE users SET role='super_admin'` with no audit | psql as `siem_app` → `UPDATE 1` | Fixed (P7, P8) |
| N1 | Medium | Forged/invalid ID tokens → unhandled joserfc exception → HTTP 500, no audit row | 12/12 negative OIDC cases returned 500 | Fixed (P3) |
| N3 | Medium | After full chain re-hash, console showed "Hash chain intact" | owner re-hash + page view | Fixed (P9) |
| R9b | Low | Caddy-generated 413 without any security header, `Server: Caddy` leaked | live header test 1/51 failing | Fixed |
| N5 | Low | `pg_hba` allowed any role from the collector network | config review + connection test | Fixed (P16) |
| R5b | Low/Med | Limiter: 107 MB at cap and lockout of all new clients | measured with tracemalloc | Fixed |

## 4. Phase 0 original — deployment confirmation

`deploy/setup.sh` failed on a clean checkout: `clickhouse/users.d/users.xml: No such file or directory`
(exit 1). The remaining Phase 0 findings were confirmed by code review (see VULNERABILITY_REMEDIATION.md);
a full live attack on Phase 0 was not completed because the candidate superseded it.

## 5. Not tested (and why)

| Surface | Reason | How to test |
|---|---|---|
| Live Microsoft Entra ID flow, Conditional Access/MFA | no tenant in the lab | see TEST_RESULTS.md §7 |
| Wasabi Object Lock (delete denial, retention) | no bucket | `aws s3api delete-object …` must fail |
| AppArmor confinement; `host/harden.sh` (nftables, SSH, auditd) | sandbox kernel / would alter sandbox host | run on a disposable Hyper-V VM |
| OWASP ZAP baseline/full scan | image unavailable (registry limits) | commands in TEST_RESULTS.md §7 |
| Grype | vulnerability DB host blocked | command in TEST_RESULTS.md §7 |
| Phase 1 collector under adversarial load | opt-in lab profile; mTLS framing covered by unit tests only | enable `--profile ingest` in a lab |
| Physical/hypervisor attacks, Hyper-V host compromise | out of scope | — |

## 6. Conclusion

Within the documented threat model and tested scope, the Phase 0.1 release resisted every attack attempted.
Residual risks (post-checkpoint window, host root, compromised web process acting as a logged-in admin,
unfixed base-image CVEs, untested external services) are documented in THREAT_MODEL.md and
VULNERABILITY_REMEDIATION.md. An **independent** penetration test against the real Hyper-V deployment
is required before production use.
