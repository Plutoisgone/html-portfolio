# Threat model — Mini-SIEM Phase 0.1

Scope: one Ubuntu 24.04 Hyper-V VM (4 vCPU / 8 GB / 100 GB) running the Docker stack in
`deploy/compose.yaml`, operated by an MSP for its own staff. Phase 1 log collection exists as an
**opt-in lab profile** (synthetic data only) and is in scope only where it touches Phase 0 assets.

## 1. Assets

| Asset | Why it matters |
|---|---|
| Administrative audit log (`audit_log`, checkpoints, Wasabi copies) | Evidence of who did what; must survive a malicious insider |
| Identities and roles (`users`, sessions, break-glass tokens) | Control who can see customer security data |
| Secrets (`deploy/secrets/*`, DB TLS keys, checkpoint HMAC key, OIDC client secret) | Compromise of any one grants a specific capability (table in §5) |
| Security events (Phase 1 lab) | Confidentiality of customer telemetry (synthetic only in this release) |
| Availability of the console and of audit verification | An MSP must be able to respond during incidents |

## 2. Trust boundaries

```
Internet ─╳─ (nftables: mgmt VLAN only) ─► Caddy :443 ──edge bridge──► app :8000   (everything else)
                                                       └──edge bridge──► auth :8000  (/auth/* only)
                                                                       │ TLS+SCRAM (backend, internal)
                         worker ──backend──► PostgreSQL ◄──collect_db── collector (opt-in, mTLS :6514)
                         worker ──egress──► Wasabi (Object Lock) / heartbeat
auth ──egress──► login.microsoftonline.com (OIDC)
(app is still attached to egress but no longer needs it: it does no OIDC since Phase 1 / N12)
Operator ──SSH key, mgmt VLAN──► host (root) ──► docker compose
```

* B1 Browser ↔ Caddy (TLS, CSP, same-origin POST, session cookie `__Host-`).
* B2 Caddy ↔ app and Caddy ↔ auth (plain HTTP on the edge bridge, which holds only these three
  containers — accepted residual).
* B2a Login service ↔ web app (Phase 1, N12): only the login service's DB role can create a session; the
  web app can only read, refresh (`last_seen_at`) and delete sessions. A web-side compromise therefore
  cannot mint a session.
* B3 Containers ↔ PostgreSQL (TLS verify-full, SCRAM, per-role network confinement, least-privilege roles).
* B4 Worker ↔ Wasabi (HTTPS, Object Lock COMPLIANCE, read-back verification).
* B5 Host root ↔ everything (full trust; see §4).
* B6 Entra ID (trusted IdP; tenant- and object-ID-pinned).

## 3. Adversaries and what Phase 0.1 guarantees

| # | Adversary | Capability assumed | Defended? | How / residual |
|---|---|---|---|---|
| A1 | External attacker on the internet | network only | Yes | Nothing published except 443 on the mgmt interface; nftables allows mgmt VLAN only; no password login |
| A2 | Attacker on the mgmt VLAN without credentials | HTTP(S) to Caddy | Yes | SSO only; break-glass needs a 256-bit CLI-issued code; rate limiting; tested forged tokens/cookies/CSRF |
| A3 | Authenticated low-privilege user (analyst/read_only/client_admin) | valid session | Yes | deny-by-default `require_role`; admin & event pages super-admin only; live RBAC tests |
| A4 | Stolen **web-app DB password** (SQLi or leaked secret) | connect as `siem_app` from the backend network | Mostly | cannot create (forge) a session — no `INSERT` on sessions, no sign-in functions (N12; until Phase 1 it **could**, which made it a full super-admin compromise); cannot change roles/create users without a live super-admin session token; cannot change/delete audit rows; cannot forge `txid`; can read users/sessions hashes/events (confidentiality residual) |
| A4b | Stolen **login-service DB password** (`db_auth_password`) | connect as `siem_auth` from the backend network | Partially | can create a session for any active user (its job) and so act as them; cannot change roles/users directly, read customers, events, break-glass tokens or call admin functions; every admin action still needs the audit row. Separate secret, separate container serving four routes |
| A5 | Compromised **web process** (RCE in app container) | A4 + live session tokens in transit (no OIDC client secret, no OIDC state key since Phase 1) | Partially | can act as any admin who is using the console at that moment; every privileged change is still forced into the audit log and externally anchored; cannot read S3 keys, checkpoint key, owner password |
| A6 | Stolen **schema-owner** (migration) password | DDL on the schema | Detect, not prevent | can disable triggers and rewrite rows; HMAC checkpoint + full re-hash detect any change up to the last checkpoint (live-tested); post-checkpoint window ≤ ~60 s is undetectable |
| A7 | Compromised **worker** | checkpoint HMAC key, S3 write key | Detect partially | can forge local checkpoints, but cannot delete or overwrite Object-Locked objects already in Wasabi; remote/local disagreement halts export and raises alarms |
| A8 | **Malicious or compromised super admin** (web UI) | full application privileges | Accountability, not prevention | every role/user/break-glass action audited atomically (DB-enforced) and exported to WORM storage; cannot delete/alter audit log from the UI; cannot demote/deactivate self; cannot remove the last super admin. **No two-person rule** (residual) |
| A9 | Malicious **host administrator (root)** | everything on the VM | **Out of scope for prevention** | can read all secrets, stop the worker, rewrite the DB and checkpoint. Only audit objects already written to Wasabi Object Lock (COMPLIANCE) survive; heartbeat monitor alerts when the worker stops. Mitigate organisationally: separate Wasabi account owner, SSH key custody, auditd forwarding |
| A10 | Trusted syslog sender compromised (Phase 1 lab) | valid client cert | Partially | can inject false events within rate limits; cannot read data; certificate revocation via allowlist |
| A11 | Supply-chain attacker | malicious upstream package/image | Reduced | hash-pinned Python deps, digest-pinned images, SHA-pinned CI actions, SBOM, scans; no reproducible-build or signature verification (residual) |
| A12 | Resource-exhaustion attacker on mgmt VLAN | many requests/sources | Yes (bounded) | token-bucket limiter bounded at 20k keys/<12 MB, uvicorn concurrency cap, Caddy body/header/time limits, container memory/pid limits; live flood test |

## 4. Explicit non-goals / out of scope (Phase 0.1)

* Prevention against host root (A9); confidentiality against a compromised app process (A5).
* Multi-tenant isolation (single-tenant console; `client_admin` has no tenant-scoped views yet).
* Immutability of security events (Phase 1 lab events are deletable by retention; only the *administrative*
  audit log is anchored).
* Two-person approval for privileged changes (recommended for Phase 1+).
* Live verification of Entra ID, Wasabi, AppArmor and Hyper-V (see TEST_RESULTS.md §7).

## 5. Secret compromise matrix

| Secret | Mounted into | If stolen, attacker can… | …but cannot |
|---|---|---|---|
| `db_bootstrap_password` | postgres only (local socket trust anyway) | nothing remotely (network login rejected) | — |
| `db_owner_password` | migrate (one-shot) | DDL, disable triggers (A6) | evade checkpoint detection of anchored rows |
| `db_app_password` | app | A4 | create a session (N12), escalate without a live admin token; alter audit |
| `db_auth_password` | auth (login service) | A4b: create sessions for existing active users, record last sign-in | change roles/users, read customers/events/break-glass tokens, call admin functions |
| `db_worker_password` | worker | read audit rows, insert verification status, run cleanup functions | read users/sessions; write audit rows |
| `db_emergency_password` | emergency (CLI, on demand) | create break-glass tokens for **existing active super admins** (audited) | elevate anyone, read OIDs |
| `db_ingest_password` | collector (opt-in) | insert events from the collector network only | read anything; connect from backend network |
| `audit_checkpoint_key` | worker | forge local checkpoints (A7) | alter Object-Locked remote checkpoints |
| `session_secret` | auth (login service) | forge the short-lived OIDC state cookie | forge app sessions (server-side, random) |
| `oidc_client_secret` | auth (login service) | redeem auth codes for this app registration | bypass Entra MFA/CA or tenant/oid checks |
| `s3_*` keys | worker | add objects to the bucket | delete/shorten COMPLIANCE-locked objects (policy has no delete; COMPLIANCE cannot be bypassed) |

## 6. Mapping to OWASP Top 10 (2021) / API Top 10 (2023)

| Category | Status in Phase 0.1 |
|---|---|
| A01 Broken access control / API1 BOLA / API5 BFLA | deny-by-default roles, DB-level authorization of admin mutations, live RBAC/IDOR tests |
| A02 Cryptographic failures | TLS 1.2/1.3 AEAD only (Caddy), TLS verify-full to DB, SHA-256 session-token hashing, HMAC-SHA-256 checkpoints via stdlib, no custom crypto |
| A03 Injection | parameterised SQL everywhere; fuzzed query builder; Jinja autoescape + strict CSP |
| A04 Insecure design | threat model, fail-closed integrity, atomic audit |
| A05 Security misconfiguration | generated pg_hba, read-only containers, no capabilities, verify script |
| A06 Vulnerable components | pip-audit clean; image CVEs documented; pinning |
| A07 Identification & authentication failures / API2 | Entra OIDC with oid/tid pinning; server-side sessions; idle/absolute expiry; revocation |
| A08 Software & data integrity | hash-pinned deps, digest pins, SBOM; audit chain + external anchors |
| A09 Logging & monitoring failures | every privileged action audited; integrity alarms on UI; heartbeat |
| A10 SSRF | no user-controlled outbound URLs (endpoints are operator config, HTTPS-validated) |
| API4 Unrestricted resource consumption | limiter, concurrency caps, body limits, container limits |

ASVS 5.0 Level 3, CIS benchmarks, NIST SSDF and Zero Trust mapping: see `SECURITY_ARCHITECTURE.md` §8.
