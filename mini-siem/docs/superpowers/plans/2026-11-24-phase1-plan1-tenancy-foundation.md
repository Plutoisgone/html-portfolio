# Phase 1 · Plan 1 — Customer separation and ClickHouse foundation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Customers, staff-to-customer assignments and a customer-scoped log store exist, and the database —
not only the web layer — stops one customer's data being read under another.

**Architecture:** PostgreSQL (migration 6) holds customers and assignments behind session-authenticated
`SECURITY DEFINER` functions and row-level security. ClickHouse is enabled with `siem.events` / `siem.alerts`
tables keyed by `customer_id`, per-service users and a row policy. The app resolves an analyst's customer
scope from PostgreSQL on every request and the only ClickHouse query builder refuses to run without it.

**Tech Stack:** Python 3.12, FastAPI, psycopg 3, PostgreSQL 17, ClickHouse 25.8, `clickhouse-connect` (Apache-2.0), pytest, Hypothesis.

**Spec:** `mini-siem/docs/superpowers/specs/2026-11-24-phase1-msp-integrations-design.md` (§3 goals 1, 6, 7; §5.1; §5.5 Logs/Customers; §7 cross-tenant tests; §8 step 1). Plans 2–5 (Check Point, Sophos Firewall, API connectors, console + load + Wazuh replay) follow this one.

All paths below are relative to `mini-siem/`. Run Python tests from `mini-siem/app`.

## Global Constraints

- Target VM: 4 vCPU / 8 GB / 100 GB; total container memory limits must stay ≤ 6.5 GiB (leave ≥ 1.5 GiB for the host).
- FOSS only; new Python dependencies hash-pinned in `app/requirements.txt` (`pip-compile --generate-hashes`).
- No Phase 0.1 control may be weakened: TLS verify-full to PostgreSQL, deny-by-default grants (`role_grants`), container hardening anchor `*hardening`, audit-in-same-transaction triggers (SQLSTATE `SIA01`).
- No customer identity is ever taken from request bodies, query strings or message content without checking it against the caller's scope.
- Nothing copied from Wazuh (GPL v2); Mini-SIEM has no licence yet.
- Synthetic data only in the lab until the production gate (SECURITY_ASSESSMENT.md §5) is met.
- Break-glass sessions (`user['via'] != 'sso'`) get **no** customer scope.

## Review Focus

1. Analyst with **zero** assigned customers → sees nothing (an empty scope must never become "no filter"). → Task 3 `test_empty_scope_refused`, Task 5 `test_unassigned_analyst_sees_nothing`.
2. Customer **deactivated**, or analyst **unassigned / demoted / deactivated** while logged in → loses access on the next request, no caching. → Task 1 `db_tenancy_acceptance.sql` block 4, Task 5 `test_scope_revoked_mid_session`.
3. **IDOR**: `customer=<id>` for a customer outside scope, or a non-numeric / huge value → 404 with no data and no hint the customer exists. → Task 4 `test_customer_param_outside_scope_is_404`.
4. ClickHouse **down or slow** → error page, never a fallback that skips the filter. → Task 4 `test_clickhouse_unavailable_shows_error`.
5. Duplicate customer **slug / name with odd characters** (Unicode, `<script>`, 200 chars) → rejected or escaped, audited. → Task 1 SQL block 2, Task 4 `test_customer_name_is_escaped`.

---

### Task 1: Migration 6 — customers, assignments, scope function, RLS

**Files:**
- Modify: `app/siem/migrate.py` (append migration 6 to `MIGRATIONS`; allowed versions `(0, 2, 3, 4, 5, 6)`; extend `ADMIN_FUNCTIONS` and `role_grants`)
- Create: `app/tests/db_tenancy_acceptance.sql`
- Modify: `app/tests/test_security_regression.py` (grant-set assertions)

**Interfaces:**
- Produces (SQL, all `SECURITY DEFINER SET search_path=pg_catalog,public`, auth via existing `admin_actor(p_token text, p_idle_minutes int)`):
  - `admin_create_customer(p_token text, p_idle int, p_slug text, p_name text) RETURNS integer`
  - `admin_set_customer_active(p_token text, p_idle int, p_customer int, p_active boolean) RETURNS text` (returns slug)
  - `admin_assign_staff(p_token text, p_idle int, p_user int, p_customer int, p_assigned boolean) RETURNS text` (returns slug)
  - `session_customer_ids(p_token text, p_idle int) RETURNS integer[]` — `STABLE`; resolves an **active SSO session** (not break-glass: `sessions.via = 'sso'`) of an **active** user; `super_admin` → all active customers; other roles → active customers in `staff_customers`; anything else → `'{}'`. Never raises for an unknown token (returns `'{}'`).
  - Tables: `customers(id int identity pk, slug text unique CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,31}$'), name text CHECK (length(name) BETWEEN 1 AND 100 AND name !~ '[[:cntrl:]]'), active boolean NOT NULL DEFAULT true, created_at timestamptz DEFAULT now())`; `staff_customers(user_id int REFERENCES users ON DELETE CASCADE, customer_id int REFERENCES customers, PRIMARY KEY (user_id, customer_id))`.
  - RLS: `ALTER TABLE customers ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY`; policy `customers_scope FOR SELECT USING (id = ANY(session_customer_ids(current_setting('siem.session', true), 60)))`. Same pattern on `staff_customers` (`customer_id = ANY(...)`).
  - Audit enforcement: new constraint trigger function `require_tenant_audit()` (deferred, `SIA01`), actions `customer.created`, `customer.activated`/`customer.deactivated`, `customer.staff_assigned`/`customer.staff_removed`, `target` = customer slug.
  - Grants: app role `SELECT` on `customers`, `staff_customers` (filtered by RLS) and `EXECUTE` on the four functions; no INSERT/UPDATE/DELETE. Worker, emergency, ingest: nothing new.

- [ ] **Step 1: Write the failing SQL acceptance test** `app/tests/db_tenancy_acceptance.sql` in the style of `db_acceptance.sql` (single transaction, `ROLLBACK` at the end, `DO $$ … RAISE EXCEPTION` on any failed expectation). Blocks:
  1. As app role: `INSERT INTO customers …`, `UPDATE customers …`, `INSERT INTO staff_customers …` each raise `42501`.
  2. `admin_create_customer` with a super-admin token: slug `'Bad Slug'`, `'a'`, 33-char slug, name with `E'\n'`, duplicate slug → each raises; valid call without an `audit_log` row in the transaction → `SIA01` at `SET CONSTRAINTS ALL IMMEDIATE`.
  3. Analyst token assigned to customer A only: `session_customer_ids` = `{A}`; `SET LOCAL siem.session = <token>; SELECT count(*) FROM customers` = 1; super admin → all active; break-glass session token → `'{}'`; random 40-char token → `'{}'`; no `siem.session` set → `SELECT count(*) FROM customers` = 0.
  4. Deactivate customer A → analyst's scope `'{}'`; reactivate, unassign → `'{}'`; deactivate the analyst user → `'{}'`.
  5. `admin_assign_staff` / `admin_create_customer` with an analyst token → `42501`.

- [ ] **Step 2: Run it against the current lab database and confirm it fails**

Run: `sudo docker compose exec -T postgres psql -U siem_bootstrap -d siem -v ON_ERROR_STOP=1 < ../app/tests/db_tenancy_acceptance.sql`
Expected: `ERROR: relation "customers" does not exist`

- [ ] **Step 3: Implement migration 6** in `app/siem/migrate.py` with the tables, functions, policies, trigger and grants listed under Interfaces. `session_customer_ids` hashes the token exactly like `admin_actor` (`sha256(convert_to(p_token,'UTF8'))`), checks `expires_at` and idle time, and must not update `last_seen_at`.

- [ ] **Step 4: Update `test_security_regression.py`** — the expected app-role grant set includes exactly the new SELECT and EXECUTE lines and no write privilege on `customers`/`staff_customers`.

Run: `python -m pytest -q tests/test_security_regression.py`
Expected: PASS

- [ ] **Step 5: Apply and re-run all SQL acceptance files**

Run: `sudo docker compose run --rm migrate && for f in db_acceptance db_events_acceptance db_tenancy_acceptance; do sudo docker compose exec -T postgres psql -U siem_bootstrap -d siem -v ON_ERROR_STOP=1 < ../app/tests/$f.sql || exit 1; done`
Expected: `Applying migration 6`, then each file ends with `ROLLBACK` and no `ERROR`.

- [ ] **Step 6: Commit** — `feat(db): customers, staff assignments and session-bound customer scope (migration 6)`

---

### Task 1A: Separate login service — only it may create sessions (owner decision 2026-11-24)

Added after the Task 1 review found that the web app's DB role has `INSERT ON sessions`: anyone holding
only the app DB password can insert a forged `via='sso'` session for a super admin, which
`admin_actor` and `session_customer_ids` then accept. This defeats the plan decision "a stolen DB
password alone reads nothing" and the Phase 0.1 claim in PENETRATION_TEST_REPORT.md P7. Owner chose
to move session creation into its own service.

**Files:**
- Create: `app/siem/auth_main.py` (`create_app()` for the login service: mounts only the `auth.router` routes `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/breakglass`, plus `/healthz`)
- Modify: `app/siem/main.py` (web app no longer mounts `auth.router`; keeps `/login` and `/breakglass` pages, which post to `/auth/*`), `app/siem/auth.py` (session creation and break-glass consumption use the auth DB pool), `app/siem/config.py` (auth service reads `SIEM_DB_AUTH_USER` / secret `db_auth_password`; web app no longer requires `oidc_client_secret`)
- Modify: `app/siem/migrate.py` (new role grants: `auth_role`), `deploy/compose.yaml` (new service `auth` from `mini-siem-app:local`, command `uvicorn siem.auth_main:create_app --factory …`, `*hardening`, networks `edge` + `backend`, secrets `db_auth_password`, `oidc_client_secret`, `session_secret`/state secret as the app uses today; `app` loses `oidc_client_secret`), `deploy/caddy/Caddyfile` (`handle /auth/*` → `auth:8000`, everything else → `app:8000`, security headers on both), `deploy/setup.sh` (generate `db_auth_password`, create role, pg_hba line for the auth role from `BACKEND_SUBNET` only), `deploy/postgres/01-app-role.sh`, `deploy/.env.example` (`SIEM_DB_AUTH_USER=siem_auth`), `deploy/verify-deployment.sh` (auth container checks)
- Test: `app/tests/test_security_regression.py`, `app/tests/test_oidc_integration.py` and `app/tests/test_auth.py` (target the login-service app), `app/tests/db_acceptance.sql`, `app/tests/live/test_live_hardening.py`, `app/tests/smoke_test.py`
- Docs: `VULNERABILITY_REMEDIATION.md` (new finding **N12**, High: forged session via app DB role — found in Phase 1 review, fixed here), `PENETRATION_TEST_REPORT.md` (correct P7: the original test did not cover a forged session row), `THREAT_MODEL.md`, `SECURITY_ARCHITECTURE.md`, `DEPLOYMENT_GUIDE.md` (new `.env` key, new service), `CHANGELOG.md`

**Interfaces:**
- Produces:
  - DB role `auth_role` (env `SIEM_DB_AUTH_USER`) grants, exactly: `SELECT ON users`; `UPDATE (last_login_at) ON users`; `SELECT, INSERT, DELETE ON sessions`; `SELECT, INSERT (<AUDIT_INSERT_COLUMNS>) ON audit_log`; `SELECT ON audit_head`; `EXECUTE` on `bootstrap_first_admin(uuid, text)` and `consume_breakglass(bytea)`.
  - Web app role: **loses** `INSERT ON sessions` and `EXECUTE` on `bootstrap_first_admin` and `consume_breakglass`; keeps `SELECT, DELETE ON sessions` and `UPDATE (last_seen_at) ON sessions`.
  - `grant_roles` requires five distinct runtime roles plus the owner.
  - The web app container has no `oidc_client_secret` and no `db_auth_password`; the auth container has no `db_app_password`.
  - URLs unchanged for users: `/auth/login`, `/auth/callback` (Entra redirect URI unchanged), `/auth/logout`, `/auth/breakglass`.

- [ ] **Step 1: Write failing tests**
  - `db_acceptance.sql`: as app role, `INSERT INTO sessions …` → `42501`; `SELECT bootstrap_first_admin(...)` and `SELECT consume_breakglass(...)` → `42501`; as auth role, `UPDATE users SET role=…` → `42501`, `SELECT … FROM customers` → 0 rows (RLS, no token).
  - `test_live_hardening.py::test_app_password_cannot_forge_session`: psql as app role inserting a `via='sso'` session for the super admin → `42501`; then `SET siem.session` to that token → `session_customer_ids` returns `{}` and `admin_create_customer` raises `42501`.
  - `test_live_hardening.py::test_service_secrets_are_separated`: `docker exec` listing `/run/secrets` — app has no `oidc_client_secret`/`db_auth_password`; auth has no `db_app_password`.
  - `test_security_regression.py`: expected grant sets for both roles as above.
- [ ] **Step 2: Run and confirm failure** — offline: `python -m pytest -q tests/test_security_regression.py` → FAIL; SQL file on the lab → `ERROR` at the first new check.
- [ ] **Step 3: Implement** the files listed. Keep `auth.py` logic unchanged apart from which pool it uses; no new auth features.
- [ ] **Step 4: Run everything** — offline suite PASS; lab redeploy (`lab-up.sh`); all SQL acceptance files PASS; full live suite PASS (existing tests updated only where routes moved service); smoke test PASS through Caddy; `verify-deployment.sh` shows the `auth` container non-root, CapEff 0, read-only, NoNewPrivs, seccomp.
- [ ] **Step 5: Update docs** listed under Files.
- [ ] **Step 6: Commit** — `fix(security): only a separate login service may create sessions (N12)`

---

### Task 2: Enable ClickHouse with TLS, per-service users and customer-keyed tables

**Files:**
- Modify: `deploy/compose.yaml` (clickhouse: remove `profiles: [future]`, network `backend`, memory `${CLICKHOUSE_MEMORY:-3G}`; new one-shot service `ch_migrate` like `migrate`)
- Modify: `deploy/setup.sh` (ClickHouse server cert from the existing setup CA, SAN `clickhouse`; users `siem_admin`, `siem_reader`, `siem_ingest`; new secret `ch_reader_password` etc. already exist — add `ch_connector_password` reserved for Plan 4, not granted yet)
- Create: `deploy/clickhouse/config.d/tls.xml` (HTTPS 8443 only: `<http_port remove="1"/>`, `<tcp_port remove="1"/>`, `<https_port>8443</https_port>`, TLS 1.2+, server cert/key)
- Create: `app/siem/ch_schema.py` (DDL + `main()` applied by `ch_migrate` as `siem_admin`)
- Test: `app/tests/test_ch_schema.py` (offline), `app/tests/live/test_live_clickhouse.py`

**Interfaces:**
- Produces:
  - `siem.events(customer_id UInt32, received_at DateTime64(3,'UTC') DEFAULT now64(3), event_time Nullable(DateTime64(3,'UTC')), source_id LowCardinality(String), product LowCardinality(String), severity UInt8, wazuh_level UInt8, src_ip Nullable(IPv6), src_port Nullable(UInt16), dst_ip Nullable(IPv6), dst_port Nullable(UInt16), user Nullable(String), action LowCardinality(String), rule String, message String, raw String CODEC(ZSTD(3)))` — `ENGINE = MergeTree PARTITION BY toYYYYMM(received_at) ORDER BY (customer_id, received_at) TTL toDateTime(received_at) + INTERVAL {retention_days} DAY`.
  - `siem.alerts(customer_id UInt32, alert_id String, received_at DateTime64(3,'UTC') DEFAULT now64(3), alert_time DateTime64(3,'UTC'), product LowCardinality(String), severity UInt8, wazuh_level UInt8, title String, vendor_url String, raw String CODEC(ZSTD(3)))` — `ENGINE = ReplacingMergeTree ORDER BY (customer_id, product, alert_id)` (dedup by vendor ID), same partition and TTL.
  - Row policy: `CREATE ROW POLICY customer_scope ON siem.events, siem.alerts FOR SELECT USING has(splitByChar(',', getSetting('SQL_siem_customer_ids')), toString(customer_id)) TO siem_reader`.
  - Users: `siem_reader` SELECT on `siem.*` only, readonly profile; `siem_ingest` INSERT on `siem.events` only (no SELECT); `siem_admin` used only by `ch_migrate`. All restricted to `BACKEND_SUBNET` (ingest additionally `COLLECT_DB_SUBNET`).
  - `ch_schema.retention_days()` reads env `SIEM_EVENT_RETENTION_DAYS`, default `90`, allowed `1..730`.

- [ ] **Step 1: Write offline tests** `test_ch_schema.py`: `test_every_table_starts_order_by_with_customer_id` (parse DDL strings), `test_retention_bounds` (`0` and `731` raise `ConfigError`, unset → `90`), `test_ingest_user_has_no_select` (parse generated `users.xml` from `setup.sh` run in a temp dir, as `test_setup_script.py` does).
- [ ] **Step 2: Run and confirm failure** — `python -m pytest -q tests/test_ch_schema.py` → FAIL (`ModuleNotFoundError: siem.ch_schema`).
- [ ] **Step 3: Implement** `ch_schema.py`, compose/setup/config changes.
- [ ] **Step 4: Offline tests pass** — `python -m pytest -q tests/test_ch_schema.py tests/test_setup_script.py` → PASS.
- [ ] **Step 5: Write live tests** `test_live_clickhouse.py`: plaintext port 8123/9000 refused; HTTPS with wrong CA refused; `siem_ingest` `SELECT` → error 497 (access denied); `siem_reader` `INSERT`/`ALTER`/`DROP` → denied; reader `SELECT count() FROM siem.events` with `SQL_siem_customer_ids` unset returns 0 although rows exist (seeded by `siem_admin`); set to `'1'` returns only customer 1 rows.
- [ ] **Step 6: Deploy and run** — `sudo docker compose up -d && sudo ./verify-deployment.sh && SIEM_LIVE=1 … python -m pytest -q tests/live/test_live_clickhouse.py` → PASS; `verify-deployment.sh` lists clickhouse with CapEff 0, read-only rootfs, NoNewPrivs.
- [ ] **Step 7: Commit** — `feat(deploy): enable ClickHouse over TLS with customer-keyed tables and row policy`

---

### Task 3: Customer scope in the app and the scoped ClickHouse query builder

**Files:**
- Create: `app/siem/scope.py`, `app/siem/ch.py`, `app/siem/log_query.py`
- Modify: `app/requirements.in` (+ `clickhouse-connect`), regenerate `app/requirements.txt` with hashes
- Test: `app/tests/test_scope.py`, extend `app/tests/test_fuzz_properties.py`

**Interfaces:**
- Consumes: `session_customer_ids` (Task 1), `siem.events` + row policy (Task 2), `db.tx()`, the session cookie token as used by `web.admin_tx`.
- Produces:
  - `scope.customer_ids(conn, token: str, idle_minutes: int) -> frozenset[int]` — calls `session_customer_ids`; returns `frozenset()` for break-glass.
  - `scope.require(ids: frozenset[int], customer: int | None) -> tuple[int, ...]` — `customer is None` → all of `ids` sorted; `customer` in `ids` → `(customer,)`; otherwise raises `scope.OutOfScope`; empty `ids` → raises `scope.NoScope`.
  - `ch.reader() -> clickhouse_connect.driver.Client` — HTTPS 8443, `verify=True`, CA from `SIEM_CH_CA_FILE`, user `siem_reader`, password secret `ch_reader_password`, `query_limit=1000`, `send_receive_timeout=5`.
  - `log_query.LogFilter` (frozen dataclass: `start: datetime`, `end: datetime`, `source_id: str = ''`, `src_ip: str = ''`, `dst_ip: str = ''`, `action: str = ''`, `text: str = ''`, `page: int = 0`) with validation: range ≤ 31 days, `source_id` matches `events.SOURCE_RE`, IPs parse with `ipaddress`, `action` ∈ `('', 'allow', 'deny', 'drop', 'alert')`, `text` ≤ 128 bytes no control chars, `page` 0..99.
  - `log_query.build(customers: tuple[int, ...], f: LogFilter) -> tuple[str, dict, dict]` — returns `(sql, parameters, settings)`; raises `scope.NoScope` if `customers` is empty; SQL is a fixed template with `customer_id IN {customers:Array(UInt32)}` always first in WHERE, `ORDER BY received_at DESC LIMIT 100 OFFSET {offset:UInt32}`; `settings == {'SQL_siem_customer_ids': ','.join(map(str, customers))}`.

- [ ] **Step 1: Write failing tests** `test_scope.py`:
  - `test_empty_scope_refused`: `log_query.build((), LogFilter(...))` raises `scope.NoScope`.
  - `test_require_out_of_scope`: `scope.require(frozenset({1, 2}), 3)` raises `scope.OutOfScope`; `scope.require(frozenset({2, 1}), None) == (1, 2)`.
  - `test_customer_filter_always_present`: for any valid filter, `"customer_id IN {customers:Array(UInt32)}"` appears before any other condition and `parameters['customers'] == customers`.
  - `test_filter_validation`: 32-day range, `src_ip='1.2.3'`, `action='rm -rf'`, `text='\x1b[2J'`, `page=100` each raise `ValueError`.
  - Hypothesis (in `test_fuzz_properties.py`): `test_log_query_sql_independent_of_values` — SQL text identical for all values of the same filter shape (as the existing event-query property).
- [ ] **Step 2: Run and confirm failure** — `python -m pytest -q tests/test_scope.py` → FAIL (`ModuleNotFoundError`).
- [ ] **Step 3: Implement** `scope.py`, `ch.py`, `log_query.py`; add `clickhouse-connect` and regenerate hashes (`pip-compile --generate-hashes requirements.in`).
- [ ] **Step 4: Tests pass** — `python -m pytest -q tests --ignore=tests/smoke_test.py --ignore=tests/live` → all PASS; `pip-audit -r requirements.txt --require-hashes` → no known vulnerabilities.
- [ ] **Step 5: Commit** — `feat(app): customer scope resolution and scoped ClickHouse log query builder`

---

### Task 4: Customer administration and scoped Logs page

**Files:**
- Modify: `app/siem/web.py` (routes below), `app/siem/templates/base.html` (nav: Logs, Customers for super admins)
- Create: `app/siem/templates/customers.html`, `app/siem/templates/logs.html`
- Test: `app/tests/test_tenancy_web.py` (in-process, `TestClient`, DB and ClickHouse calls mocked at the `scope`/`ch` boundary)

**Interfaces:**
- Consumes: Task 1 functions via `admin_tx(request)`; `scope.customer_ids`, `scope.require`, `log_query.build`, `ch.reader()`.
- Produces routes:
  - `GET /admin/customers` (super_admin, SSO) — list customers and assigned staff; audit `customers.viewed`.
  - `POST /admin/customers` (`slug`, `name`, CSRF) → `admin_create_customer`; audit `customer.created`.
  - `POST /admin/customers/{customer_id}/active` (`active`) → `admin_set_customer_active`; audit `customer.activated`/`customer.deactivated`.
  - `POST /admin/customers/{customer_id}/staff` (`user_id`, `assigned`) → `admin_assign_staff`; audit `customer.staff_assigned`/`customer.staff_removed`.
  - `GET /logs` (roles `super_admin`, `client_admin`, `analyst`, `read_only`; SSO only) query params = `LogFilter` fields + `customer: int | None`; out-of-scope or no scope → 404 page "No customer selected or available"; audit `logs.viewed` with details `{"customers": [...], "filters": {...}}` (no raw values over 128 bytes).
  - Errors from ClickHouse (`clickhouse_connect.driver.exceptions.ClickHouseError`, timeouts) → 503 page "Log store unavailable", audited `logs.unavailable`.

- [ ] **Step 1: Write failing tests** `test_tenancy_web.py`:
  - `test_customer_param_outside_scope_is_404`: scope `{1}`, `GET /logs?customer=2` → 404, `ch.reader` never called; `customer=abc` → 422/400; `customer=99999999999` → 400.
  - `test_breakglass_gets_no_logs`: break-glass session → 404 for `/logs`, 403 for `/admin/customers`.
  - `test_analyst_cannot_manage_customers`: analyst POSTs to the three admin routes → 403.
  - `test_clickhouse_unavailable_shows_error`: reader raises → 503, body contains "Log store unavailable", no rows rendered.
  - `test_customer_name_is_escaped`: customer name `<script>x</script>` rendered escaped on `/admin/customers` and in the `/logs` customer selector.
  - `test_logs_view_audited`: successful `/logs` writes exactly one `logs.viewed` audit row containing the customer IDs.
- [ ] **Step 2: Run and confirm failure** — `python -m pytest -q tests/test_tenancy_web.py` → FAIL (404 for unknown routes).
- [ ] **Step 3: Implement** routes and templates (follow `users.html` / `events.html` patterns, CSRF via `check_csrf`, CSP unchanged — no inline script).
- [ ] **Step 4: Tests pass** — full offline suite → PASS; `bandit -q -r siem -ll` → no issues.
- [ ] **Step 5: Commit** — `feat(web): customer administration and customer-scoped Logs page`

---

### Task 5: Live cross-customer attack tests, docs and release checks

**Files:**
- Create: `app/tests/live/test_live_tenancy.py`
- Modify: `app/tests/smoke_test.py` (Logs page reachable for the super admin), `DEPLOYMENT_GUIDE.md` (ClickHouse now on; new `.env` keys `SIEM_EVENT_RETENTION_DAYS`, `CLICKHOUSE_MEMORY`; customer admin how-to), `CHANGELOG.md`, `SECURITY_ARCHITECTURE.md` (tenant model), `THREAT_MODEL.md` (cross-tenant threats and the trust boundary: a stolen app DB password **plus** a live analyst session token reaches only that analyst's customers), `TEST_RESULTS.md`
- Modify: `.github/workflows/mini-siem-security.yml` and `mini-siem/.github/workflows/security.yml` only if new test paths need excluding (live tests stay excluded)

**Interfaces:**
- Consumes: everything above; live fixtures in `tests/live/conftest.py` (`Lab`, sessions via the existing helpers).

- [ ] **Step 1: Write live tests** (lab stack, synthetic data; seed customers `lab-a`, `lab-b`, analysts `ana-a` (assigned A), `ana-none` (no assignment), and 50 events per customer via `siem_admin`):
  - `test_analyst_sees_only_own_customer`: `ana-a` `/logs` returns only `lab-a` rows; `?customer=<lab-b id>` → 404.
  - `test_unassigned_analyst_sees_nothing`: `ana-none` → 404 "No customer selected or available", zero rows.
  - `test_scope_revoked_mid_session`: `ana-a` logged in; super admin unassigns A → `ana-a`'s next `/logs` → 404; reassign → works; deactivate customer A → 404.
  - `test_app_db_password_cannot_widen_scope`: psql as app role with `SET siem.session` = `ana-a` token → `customers` shows only `lab-a`; `SET siem.session` = garbage → 0 rows; direct `INSERT INTO staff_customers` → `42501`.
  - `test_reader_password_without_scope_setting_reads_nothing`: ClickHouse as `siem_reader` without `SQL_siem_customer_ids` → 0 rows.
  - `test_customer_changes_are_audited`: create/deactivate/assign actions appear in `audit_log` and `--verify-once` still reports the chain OK.
- [ ] **Step 2: Run** — `SIEM_LIVE=1 … python -m pytest -q tests/live` → all PASS (existing 99 + new); smoke test 25/25 + Logs check.
- [ ] **Step 3: Resource check** — `docker stats --no-stream` after seeding 1,000,000 synthetic events across 2 customers: total memory of all containers < 6.5 GiB, ClickHouse disk for 1M events recorded in `TEST_RESULTS.md` (measurement, not estimate).
- [ ] **Step 4: Scanners** — CI workflow green on the PR (tests, Bandit, Semgrep, pip-audit, ShellCheck, Gitleaks, Trivy image + config).
- [ ] **Step 5: Update docs** listed under Files with what was built and measured; mark anything not run as NOT TESTED with the command.
- [ ] **Step 6: Commit** — `test(live): cross-customer attack tests; docs for customer separation`

---

## Notes on decisions taken in this plan (engineer's calls, for the owner to check)

1. **Spec refinement — RLS key.** The spec said RLS "keyed on a per-transaction setting". Any database user can
   set a custom setting, so a stolen app DB password could set any customer list. The plan instead keys
   RLS on the caller's **session token** (`siem.session`), checked by `session_customer_ids` against the
   sessions table — the same proof Phase 0.1 already requires for admin functions. A stolen DB password
   alone reads nothing; with a live analyst token it reaches only that analyst's customers.
2. **ClickHouse row policy is a safety net, not the boundary.** The reader user can set its own
   `SQL_siem_customer_ids`, so the policy only protects against a query that forgets the filter. The
   boundary for log reads is the app's scope check (Tasks 3–4) — stated in THREAT_MODEL.md.
3. **ClickHouse memory 3 GiB** (was 4 GiB, disabled) to keep total limits within 6.5 GiB.
4. **Retention default 90 days**, configurable 1–730 (spec §6 assumption).
5. **Wazuh-comparable `wazuh_level` column** included now (spec §5.6) so Plans 2–4 parsers fill it from day one.
