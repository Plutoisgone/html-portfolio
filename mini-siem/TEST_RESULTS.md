# Test results — Mini-SIEM Phase 0.1 (hardened release)

All results below were produced on **2026-11-24** in an isolated development container
(Ubuntu 24.04.5, 4 vCPU, Docker Engine 29.9.3, cgroup v1). Raw outputs are in `evidence/`.
Nothing here was run against production, customer data or third-party systems.

**Legend.** PASS = executed and passed. NOT TESTED = could not be executed; a reproducible
command is given. "Live" = against the real deployed stack (Caddy → app → PostgreSQL over TLS,
worker, real secrets), not mocks. Unit tests that use stand-ins are labelled as such.

## 1. Environment limits that shaped testing (honest disclosure)

| Limitation | Effect |
|---|---|
| Not a Hyper-V VM; Docker runs inside a cloud container | Clean install verified on Ubuntu 24.04 + Docker, **not** on the target Hyper-V VM. `host/harden.sh` was not executed (it would reconfigure the sandbox's SSH/firewall) — only ShellCheck-validated. |
| Kernel without AppArmor | AppArmor confinement **NOT TESTED**; `verify-deployment.sh` correctly reports FAIL for it here. Seccomp **is** verified (kernel mode 2). |
| No Microsoft Entra tenant | Live SSO **NOT TESTED**. OIDC validation is tested with the real Authlib/joserfc code and real RS256 keys; only the token-endpoint HTTP call is stubbed. SSO sessions in live tests are inserted directly and named `simulated_sso_session`. |
| No Wasabi bucket | Object Lock export **NOT TESTED** live (unit-tested with a fake S3 client). |
| Egress proxy blocks some hosts | Grype DB (`grype.anchore.io`), Semgrep registry, Alpine CDN, GHCR blobs blocked. Semgrep used the official OSS rules cloned from GitHub; Postgres image built with `APK_UPGRADE=0`. |
| Docker Hub rate limits | OWASP ZAP image could not be pulled → ZAP **NOT TESTED**. |

## 2. Summary

| Area | Tool / suite | Result |
|---|---|---|
| Unit, integration (in-process), property/fuzz, setup script | pytest 9 + Hypothesis | **126 passed / 0 failed** (`evidence/unit-junit.xml`) |
| Live regression, authN/authZ, DB permissions, tamper, API, races | pytest live suite | **99 passed / 0 failed** (`evidence/live-junit-release.xml`, 228 s) |
| SQL acceptance (privileges, tokens, audit enforcement, events) | psql | **PASS** on fresh install, upgraded candidate DB, and restored DB |
| End-to-end smoke | `app/tests/smoke_test.py` (TLS-verifying) | **25/25 PASS** (`evidence/smoke-test.txt`) |
| Runtime container hardening | `deploy/verify-deployment.sh` | **35 PASS / 4 FAIL** — all 4 = AppArmor unavailable in sandbox |
| Regression tests detect the old bugs | new tests run against candidate code | **15 fail on candidate**, pass on release (`evidence/regression-tests-vs-candidate-code.txt`) |
| SAST | Bandit 1.9.4 | **0 issues** (3 justified `nosec`) |
| SAST | Semgrep (656 OSS rules, local) | 8 findings, all triaged (1 fixed, 6 false positive, 1 accepted) |
| SCA | pip-audit | **No known vulnerabilities** (42 hash-pinned packages) |
| Secrets | Gitleaks 8.30.1 | **No leaks** (source tree and all git history) |
| Container CVEs | Trivy 0.76.2 | app 53 HIGH/0 CRIT (0 fixable); postgres 1 HIGH (fixable, see §6); caddy 2 HIGH |
| Container CVEs | Grype | **NOT TESTED** (DB host blocked) |
| IaC | Trivy config; Checkov | 0 misconfigurations; **146 passed / 0 failed** |
| Shell | ShellCheck | 0 warnings (6 scripts) |
| Network | Nmap 7.94 | only 443/tcp on the bind IP (plus sandbox infra port 2024, not Mini-SIEM); TLS 1.2/1.3 AEAD only, all ciphers grade A |
| DAST | OWASP ZAP | **NOT TESTED** (image unavailable); live HTTP suite covers headers, CSRF, XSS, SQLi, traversal, methods, cookies |
| Load / exhaustion | Locust 2.x | realistic: 0 errors, p95 24 ms; flood 1,500 req/s: bounded, no restart |
| Backup / restore / DR | `deploy/backup.sh`, `deploy/restore.sh` | **PASS**: identical data restored; rollback detected |
| Clean install | `setup.sh` + compose | **PASS** (fresh) and **PASS** (in-place upgrade of candidate DB, 188 audit rows kept) |

## 3. Offline tests (126)

| File | Tests | What it proves | Stand-ins |
|---|---|---|---|
| `test_unit.py` | 6 | chain basics, limiter, CSRF/tokens, secret-file rules | none |
| `test_auth.py` | 13 | oid/tid authorization, UPN cannot claim identity, rollback on audit failure, ASGI boundary wiring | DB connection mocked |
| `test_oidc_integration.py` | 14 | **real** Authlib/joserfc validation: valid token accepted; 12 forged/invalid tokens rejected, audited, no cookie; state replay rejected | token-endpoint call, `finish_sso` |
| `test_security_regression.py` | 15 | tamper mutations, anchors, HMAC checkpoint, limiter memory (<12 MB @ 50k keys), IPv6 /64, headers on all statuses | none |
| `test_phase02.py` | 24 | origin/CSRF boundary, body limits, S3 object/retention/rollback verification | fake S3 client |
| `test_events.py` | 37 | syslog framing, normalization, rules, real mTLS handshakes, escaping | in-memory sink |
| `test_fuzz_properties.py` | 11 (≈3,700 generated cases) | parser bounds, normalize only raises `ValueError`, SQL text independent of input, any field change/permutation/deletion detected, checkpoint forgery rejected, ASGI boundary never 500 | none |
| `test_setup_script.py` | 6 | real `setup.sh` twice: all dirs/owners/modes (R10), secrets never regenerated, `.env` never executed, unsafe settings rejected | none (runs as root) |

## 4. Live tests (99) — `SIEM_LIVE=1 pytest tests/live`

| File | Tests | Highlights |
|---|---|---|
| `test_live_audit_tamper.py` | 7 | owner-credential attacks: edit, id change, reorder, truncation, full deletion, full re-hash → detected; post-checkpoint truncation pinned as residual |
| `test_live_hardening.py` | 41 | 26 forbidden operations per real role credential; no privileged roles; pg_hba network confinement; plaintext/bootstrap/wrong-hostname rejected; TLS 1.3; escalation impossible without live admin token; unaudited change cannot COMMIT; `txid` unforgeable; tamper alarm shown on audit page; stale alarm |
| `test_live_http.py` | 50 | headers on 200/303/404/405/413; cross-origin & missing-CSRF rejected; RBAC (analyst denied admin pages/actions); forged cookies; break-glass single-use, revocation on demotion/deactivation/deletion, expiry, CLI refusal, 8-way race → 1 winner; session revocation, fixation, logout, idle timeout; last-super-admin race; path traversal; SQLi & stored XSS in event search; OID validation; duplicate OID; audit-failure rollback (3 actions) |
| `test_live_zz_ratelimit.py` | 1 | 429 responses carry all security headers |

The same suite on the **Phase 1 candidate** (before fixes): 7/7 tamper, 50/51 HTTP — the failure was
the Caddy-generated 413 without security headers. Escalation via the app credential and the
"intact" banner after tampering were found by manual live probing and then encoded as tests.

## 5. Performance and resource budget (target: 4 vCPU / 8 GB)

Load generated from the same 4-vCPU host (so CPU figures are conservative). DB pre-loaded with
200,000 security events (~11 h at the collector's maximum admission rate).

| Profile | Requests | Errors | p50 / p95 / p99 / max | Peak per container (RSS) | Sum of peaks |
|---|---|---|---|---|---|
| Realistic: 10 authenticated analysts, 180 s | 600 (CSV; 602 incl. in-flight in console) | 0 | 7 / 24 / 32 / 72 ms | app 72 MiB (24 % CPU), postgres 98 MiB, worker 41 MiB, caddy 15 MiB | **225 MiB** |
| Flood: 200 clients, 120 s, ~1,500 req/s | 180,254 | 99.5 % 429 (limiter, by design), 82 × 503 (uvicorn concurrency cap) | 86 / 120 / 150 / 333 ms | app 62 MiB (40 % CPU), caddy 35 MiB (47 % CPU), postgres 103 MiB | **241 MiB** |

Container limits total 2.5 GiB with ClickHouse disabled (Phase 0.1 default), leaving > 5 GiB for the OS,
page cache and future ClickHouse. Flood produced only 93 audit rows for ~44,700 break-glass attempts
(limiter protects the audit log from flooding). Not measured: the collector under load, 100 GB disk growth,
long-duration soak.

## 6. Container vulnerability scan detail (Trivy 0.76.2, DB 2026-11-24)

| Image | Before (candidate) | Release | Fixable | Disposition |
|---|---|---|---|---|
| `mini-siem-app` | 103 HIGH, 2 CRIT (Debian 12) | **53 HIGH, 0 CRIT** (Debian 13) | 0 | accepted until Debian ships fixes; rebuild monthly |
| `mini-siem-postgres` | 27 (26 in `gosu`) | **1 HIGH** (libxml2) | 1 | fixed by `APK_UPGRADE=1` (default) — **not verified here** (Alpine CDN blocked) |
| `caddy:2.11.9-alpine` | 2 HIGH | 2 HIGH | 1 (x/net) | code paths unused (no HTML templates, no ACME/JWK parsing); update when Caddy releases |
| python packages (app) | 0 | 0 | — | pip-audit agrees |

## 7. NOT TESTED — reproducible commands

```bash
# Grype (needs access to grype.anchore.io)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest mini-siem-app:local --fail-on high --only-fixed
# OWASP ZAP baseline + authenticated scan (lab only; use a break-glass or test SSO session cookie)
docker run --rm --network host -v $PWD:/zap/wrk zaproxy/zaproxy:stable zap-baseline.py -t https://<SIEM_HOSTNAME>/login -r zap-baseline.html
docker run --rm --network host -v $PWD:/zap/wrk zaproxy/zaproxy:stable zap-full-scan.py -t https://<SIEM_HOSTNAME>/ \
  -z "-config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=Cookie -config replacer.full_list(0).replacement=__Host-siem=<TOKEN>"
# AppArmor + seccomp on the real VM
sudo ./deploy/verify-deployment.sh          # expect 0 failures
# Entra ID: sign in as the bootstrap oid; as an unassigned user; with a user from another tenant; without MFA
# Wasabi: export with S3 enabled, then try: aws s3api delete-object --bucket <b> --key <k> --version-id <v> --endpoint-url <wasabi>  (must fail)
# Host hardening on a disposable Hyper-V VM snapshot
sudo host/harden.sh && sudo reboot && sudo nft list ruleset && sudo aa-status
```
