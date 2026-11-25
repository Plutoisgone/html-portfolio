# Security architecture — Mini-SIEM Phase 0.1

Status keys: **[V]** implemented and experimentally verified here · **[I]** implemented, not verifiable in
this environment · **[P]** proposed for a later phase.

## 1. Components and isolation

| Service | Image (pinned) | User | Networks | Secrets mounted | Limits |
|---|---|---|---|---|---|
| caddy | `caddy:2.11.9-alpine@sha256:003a97…` | 10002 | edge (publishes `SIEM_BIND_IP:443` only) | none | 1 CPU, 256 MiB, 256 pids |
| app | `mini-siem-app:local` (python 3.12 slim trixie `@sha256:37fc60…`) | 10001 | edge, backend, egress (unused since Phase 1) | db_app, ch_reader | 2 CPU, 512 MiB |
| auth (login service, Phase 1, N12) | same image, `siem.auth_main:create_app` | 10001 | edge, backend, egress (Entra ID) | db_auth, session (OIDC state key), oidc | 1 CPU, 256 MiB |
| worker | same image | 10001 | backend, egress | db_worker, checkpoint key, s3 keys | 1 CPU, 384 MiB |
| migrate | same image (one-shot) | 10001 | backend | db_owner | 1 CPU, 256 MiB |
| ch_migrate | same image (one-shot, `siem.ch_schema`) | 10001 | backend | ch_admin | 0.5 CPU, 128 MiB |
| emergency | same image (CLI, on demand) | 10001 | backend | db_emergency | 0.5 CPU, 128 MiB |
| postgres | `mini-siem-postgres:local` (postgres 17 alpine `@sha256:f9cf3e…`, no gosu) | 70 | backend, collect_db | bootstrap + role passwords (init) | 2 CPU, 1 GiB |
| collector (opt-in) | same app image | 10001 | collect_edge, collect_db | db_ingest | 1 CPU, 256 MiB |
| clickhouse | `clickhouse-server:25.8@sha256:0152dd…` | 101 | backend (HTTPS 8443 only, cert from the setup CA) | none (users.xml holds hashes) | `CLICKHOUSE_CPUS`/`CLICKHOUSE_MEMORY` (2 CPU, 3 GiB) |

All services: `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`, tmpfs `/tmp`, json-file log
rotation. **[V]** by `deploy/verify-deployment.sh` (kernel-level CapEff=0, NoNewPrivs=1, Seccomp mode 2,
read-only rootfs, non-root, limits, internal networks). AppArmor `docker-default` **[I]** (sandbox kernel
lacks AppArmor; the script fails loudly if it is missing on the VM).

## 2. Identity, sessions and authorization

* Sign-in runs in a **separate login service** (`auth` container): Caddy routes `/auth/login`,
  `/auth/callback`, `/auth/logout` and `/auth/breakglass` there and everything else to the web app. Only
  its DB role can create a session (N12); the web app authenticates, refreshes and expires sessions but
  cannot create one, and holds neither the OIDC client secret nor the state-cookie key. **[V]**
* Entra ID OIDC authorization-code flow with PKCE (S256), state and nonce in a signed 10-minute
  `__Host-oidc` cookie (login service only). **[V]** in-process with real JOSE validation; live tenant **[I]**.
* Identity = (`tid`, `oid`); UPN is display only. Users are provisioned by object ID; first admin only
  while the users table is empty. **[V]**
* Server-side sessions: 256-bit random token in `__Host-siem` (Secure, HttpOnly, SameSite=Lax, Path=/),
  SHA-256 stored; idle (≤ 60 min) and absolute (≤ 24 h) expiry; rotated on login (fixation-safe);
  revoked on role/active change by DB trigger; break-glass sessions 1 h and re-validated per request. **[V]**
* CSRF: per-session token + strict same-origin `Origin` check on every POST + form-only content type. **[V]**
* Authorization is enforced twice for privileged changes: in the route (`require_role`) and **inside
  PostgreSQL** (`admin_actor` re-authenticates the raw session token). **[V]**
* Deny-by-default: every non-public route depends on `current_user`/`require_role`; public routes are
  `/login`, `/breakglass`, `/auth/*`, `/healthz`, `/static`. **[V]** (live unauthenticated tests)

## 3. Database least privilege (PostgreSQL 17)

| Role | Can | Cannot |
|---|---|---|
| `siem_bootstrap` (superuser) | local socket inside the container only | log in over any network (pg_hba reject) |
| owner (`siem_owner`) | own schema, run migrations | superuser/createrole/createdb/replication/bypassrls |
| app (`siem_app`) | read users/events/audit; read, refresh (`last_seen_at`) and delete sessions; call admin functions; append audit rows | **create sessions** (no INSERT, no `bootstrap_first_admin` / `consume_breakglass`; N12), INSERT users, UPDATE role/active/oid, touch tokens, UPDATE/DELETE/TRUNCATE audit, write verification status |
| login service (`siem_auth`) | read users; set `last_login_at`; read/insert/delete sessions; append audit rows; read `audit_head`; call `bootstrap_first_admin`, `consume_breakglass` | update sessions or role/active/oid; insert/delete users; read break-glass tokens, customers, staff assignments, events, verification status; call admin functions or `session_customer_ids`; connect except from `backend` |
| worker | read audit; insert verification status; run cleanup/prune functions | read users/sessions; write audit |
| emergency | read id/email/role/active; insert tokens; append audit | read OIDs; update users; set `used_at` |
| ingest | insert specific event columns | read anything; connect except from `collect_db` |

Grants are reset (REVOKE ALL) and re-applied on every deploy. **[V]** `db_acceptance.sql`, live tests.

## 4. Audit integrity design

1. **Hash chain** — `hash = SHA-256(prev_hash ‖ canonical JSON(id, ts, actor, action, target, severity, ip, ua, details))`.
2. **Protected head** — `audit_head` (last id, last hash) advanced only by an AFTER INSERT trigger that
   enforces `id = last+1` and `prev_hash = last_hash`. **[V]**
3. **Append-only** — statement trigger rejects UPDATE/DELETE/TRUNCATE; no runtime role has those privileges. **[V]**
4. **Atomicity, DB-enforced** — deferred constraint triggers refuse COMMIT of privileged changes without an
   audit row from the same transaction (`txid`). **[V]**
5. **Independent anchors** — HMAC-SHA-256 checkpoint (key only in the worker) stored outside PostgreSQL;
   when enabled, each export batch and checkpoint is written to Wasabi with Object Lock **COMPLIANCE**,
   re-read by version and retention-checked; local vs. remote rollback detection. **[V]** local / **[I]** Wasabi.
6. **Verification** — every 60 s from the anchor; full re-hash at start and hourly; status row per cycle
   shown on the audit page (failed / stale alarms); heartbeat withheld on failure. **[V]**
7. **Threat-model limits** — see THREAT_MODEL.md A6/A7/A9 and the ≤ ~60 s post-checkpoint window.

Cryptography uses only Python's `hashlib`/`hmac`/`secrets`, PostgreSQL `sha256()`, OpenSSL (via Caddy,
PostgreSQL, psycopg) and Authlib/joserfc. No custom algorithms.

## 5. Network segmentation and transport security

* Host nftables (`host/harden.sh`): input SSH from `MGMT_NETS` only; published 443 from `MGMT_NETS`, 6514
  from `SYSLOG_SOURCES`; container egress limited to DNS/443/587; collector bridge has no egress. **[I]**
* Docker networks: `backend` and `collect_db` are `internal` (no route out) **[V]**; pg_hba binds each role
  to its network **[V]**.
* TLS: Caddy TLS 1.2/1.3, AEAD suites only, HSTS 2 years **[V]** (Nmap); DB TLS 1.3 verify-full **[V]**;
  Caddy→app and Caddy→auth plaintext on a 3-member bridge (residual) — mTLS proposed **[P]**.

## 6. Secrets

Docker secret files (0440 root:10050), each mounted only into the service that needs it; never in
environment variables or images; `.env` is parsed literally (never sourced as shell) **[V]**;
`Settings.__repr__` hides secrets **[V]**. Rotation: regenerate a file and restart (DB passwords need an
`ALTER ROLE`; documented in DEPLOYMENT_GUIDE.md). Hardware-backed secret storage **[P]**.

## 7. Resilience, backup and recovery

* `deploy/backup.sh` — pg_dump + matching checkpoint + config/secrets, SHA-256 manifest, optional GnuPG
  encryption; worker paused so dump and checkpoint match. **[V]**
* `deploy/restore.sh` — refuses to overwrite; restores verbatim (triggers disabled during load), re-applies
  grants, runs anchored verification. Live DR test restored identical data and detected a rollback. **[V]**
* Resource bounds keep the stack < 250 MiB RSS under flood **[V]**; Hyper-V checkpoints/Veeam for VM-level DR **[I]**.

## 8. Standards mapping (summary; not a certification)

| Framework | Coverage in Phase 0.1 | Notable gaps |
|---|---|---|
| **OWASP ASVS 5.0 L3** | V1 encoding/injection, V3 web frontend (CSP, cookies, headers), V4 API, V6/V7 authentication & sessions (federated only), V8 authorization incl. DB-level, V9 self-contained tokens (JOSE validation), V10 OAuth/OIDC (PKCE, state, nonce, issuer/audience/tenant pinning), V11 cryptography (standard libs), V12 secure communication, V13 configuration, V14 data protection, V16 security logging | formal L3 verification not performed; no per-tenant data segregation; no step-up re-auth for privileged changes; no two-person approval |
| **CIS Ubuntu 24.04 L1** | `harden.sh`: SSH (keys only, ciphers), sysctl, module blacklist, core dumps, auditd rules, AIDE, auto-updates, umask, AppArmor, chrony, nftables default-drop | script not executed on a VM here; separate /tmp,/var partitions and bootloader password not automated |
| **CIS Docker** | daemon: icc off, no-new-privileges, live-restore, userland-proxy off, log limits; containers: non-root, read-only, caps dropped, limits, pinned digests, healthchecks, no privileged, no host network/pid | user-namespace remapping not enabled (would break bind-mount ownership); content trust not enforced |
| **NIST SSDF (SP 800-218)** | PO: threat model, security requirements; PS: pinned & hashed deps, SBOM, protected secrets; PW: SAST/SCA/secret scan/fuzz/DAST-equivalent, code review; RV: vulnerability records with root cause & regression tests | no signed releases/provenance (SLSA) |
| **Zero Trust (NIST SP 800-207)** | strong IdP-bound identity per request, per-request session re-validation, least-privilege DB roles with network binding, explicit authorization in the data tier, encrypted service traffic (except Caddy→app), continuous integrity verification | no device posture beyond Entra CA; no workload identity/mTLS between all services |
