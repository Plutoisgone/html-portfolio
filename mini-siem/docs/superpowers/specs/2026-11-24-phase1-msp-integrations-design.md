# Phase 1 design — multi-customer ingestion of Sophos, Check Point and Huntress

Status: **draft for owner approval** · Date: 2026-11-24 · Builds on: Phase 0.1 (merged to `main`)

## 1. Intent

Mini-SIEM is meant to become a secure, resource-efficient alternative to Wazuh for a managed IT and
security provider (MSP) serving several customers. Phase 1 makes it useful for the first time. MSP staff
open one console and see, for each customer:

- **firewall logs** from Sophos Firewall (XG/XGS) and Check Point, searchable;
- **one alert list** combining Huntress incidents, Sophos Central alerts and firewall security events
  (IPS, ATP, malware, …).

The vendors do the detection; Mini-SIEM collects, separates by customer, normalises and displays.
It starts as a lab on the owner's real devices and must grow into production without a rewrite.

## 2. Decisions taken with the owner

| Decision | Source |
|---|---|
| Several customers (MSP); customer separation is required from the start | owner, 2026-11-24 |
| Only MSP staff sign in (own Entra ID tenant); customers do not log in | owner, 2026-11-24 |
| Goal: view logs and alerts from Sophos, Check Point and Huntress in Mini-SIEM | owner, 2026-11-24 |
| Lab first, production later, on the real devices | owner, 2026-11-24 |
| Hyper-V, Ubuntu 24.04, 4 vCPU / 8 GB / 100 GB, FOSS, Entra ID, Wasabi Object Lock, ClickHouse, PostgreSQL | original brief |
| Later sources: Windows and Linux servers and endpoints | original brief (not in this phase) |
| Engineer decides independently where reasonable | original brief |

## 3. Goals, non-goals, anti-goals

**Goals**
1. Customer (tenant) model enforced **in the database**, not only in the web layer.
2. Ingest Check Point (Log Exporter, syslog over mutual TLS) and Sophos Firewall (syslog over TLS).
3. Pull Huntress incidents and Sophos Central alerts/events through their APIs, using per-customer credentials.
4. Vendor parsers producing common fields (time, customer, device, product, severity, src/dst IP and port,
   user, action, rule, message) plus the raw line.
5. Console: per-customer log search, unified alert list, source health (last seen, rejected messages).
6. Staff RBAC: access limited to the customers an analyst is assigned to; super admins see all.
7. Every tenant-scoped read and every change to customers, sources or credentials is audited in the existing tamper-evident audit log.
8. Fits the 4 vCPU / 8 GB / 100 GB VM under the workload in §6, measured.

**Non-goals (this phase)**
- Own detection rules, correlation, UEBA, threat intel enrichment.
- Notifications (email/Teams/webhooks) — planned next phase.
- Customer logins, customer-facing reports.
- Windows/Linux collection, active response, high availability.

**Anti-goals (failure even if it "works")**
- Any path where one customer's data can be read or written under another customer, including through a bug in a single SQL query.
- A device or API credential of customer A being able to inject events as customer B.
- API keys in config files, environment variables, logs or the database in plaintext.
- Silent data loss: dropped or rejected messages must be counted and visible.
- Weakening any Phase 0.1 control (mTLS, audit integrity, least-privilege roles, container hardening).

## 4. Approaches considered

| | A. Extend the Mini-SIEM services (**chosen**) | B. Off-the-shelf pipeline (Vector) in front | C. Keep events in PostgreSQL |
|---|---|---|---|
| How | Existing mTLS collector gains per-customer source mapping and vendor parsers; a new isolated *connector* service polls the APIs; events go to ClickHouse | Vector receives syslog/TLS and polls HTTP, parses with VRL, writes to ClickHouse; Mini-SIEM keeps UI, tenancy, audit | As today: events table in PostgreSQL |
| For | One tested codebase; customer identity derived server-side from the client certificate; reuses Phase 0.1 hardening and test harness | Mature, fast parsing and buffering; less code to write | Least change |
| Against | More code to write and maintain (parsers, retry/backoff) | Tenant tagging lives in pipeline config, outside the app's tested controls; another component to harden, scan and pin; API polling with per-tenant secrets is awkward in Vector | Will not fit firewall volume in 100 GB; ClickHouse is a stated requirement |

**Why A:** tenant separation is the property that must not fail, and A keeps every decision about
"which customer does this belong to" inside code that is unit-, property- and live-tested, with
no tenant-controlled input. B remains an option later for very high volume (§10).

## 5. Design

### 5.1 Data placement
- **PostgreSQL** (control plane): customers, staff-to-customer assignments, sources (devices and API
  connectors), credential *references*, source health counters, audit log. Row-level security (RLS) on
  every tenant-scoped table, policy keyed on a per-transaction setting that only `SECURITY DEFINER`
  functions set after checking the staff assignment.
- **ClickHouse** (data plane): `events` and `alerts` tables, `customer_id` as the first column of the sort key,
  partitioned by month, with a TTL for retention (§6). ClickHouse row policies restrict the read user
  to the customer list passed by the app; the app additionally always filters by customer and the
  query builder refuses a query without one. Insert users are per service (collector, connector) and cannot read.
- Raw lines are kept alongside parsed fields so parsers can be fixed and re-run.

### 5.2 Customer identity of incoming data (never from message content)
- **Syslog devices:** each device gets its own client certificate, issued by the Mini-SIEM lab CA. The
  certificate fingerprint maps to exactly one `(customer_id, source_id, product)` in PostgreSQL
  (replaces `sources.json`). Unknown fingerprint → connection refused and counted. Hostnames or
  fields inside the message are recorded but never used to pick the customer.
- **Check Point:** Log Exporter supports TLS with mutual authentication only (Check Point Log Exporter
  TLS configuration docs) — connects directly.
- **Sophos Firewall:** supports TLS syslog ("Secure log transmission"). Whether it presents a client
  certificate is **unverified**; first lab task is to test it. If it does not, a per-customer relay
  (rsyslog with gnutls on the customer side or on a dedicated small VM) terminates the device's TLS
  and forwards to Mini-SIEM with that customer's client certificate. Documented as reduced
  assurance: the relay, not the device, is authenticated.
- **APIs (Huntress, Sophos Central):** each connector instance is bound to one customer; the customer
  is taken from the connector configuration, not from API responses. Responses for a different
  organisation ID than configured are rejected and alarmed.

### 5.3 Credentials for API connectors
- Stored encrypted (libsodium sealed box / `cryptography` AEAD — no custom crypto) with a key that only
  the connector service holds as a Docker secret; the web app can create or replace a credential but
  cannot read it back (write-only from the UI, like a password field). Every create/replace/delete audited.
- Least privilege at the vendor: read-only API keys, one per customer.
- Exact endpoints, auth scheme and rate limits of the Huntress REST API and the Sophos Central SIEM
  API to be confirmed from vendor documentation before implementation (**not yet verified**).

### 5.4 Services (all keep Phase 0.1 container hardening)
| Service | Change |
|---|---|
| `collector` | per-customer source lookup, vendor parsers, write to ClickHouse in batches, counters for rejected/dropped; bounded in-memory queue with back-pressure (close connection when full, never drop silently); raised but measured rate limits |
| `connector` (new) | polls each customer's APIs on a schedule with checkpointing (no gaps, no duplicates via vendor IDs), exponential back-off, per-customer isolation (one customer's failure doesn't stop others); outbound network only to the vendor API hosts |
| `app` | customer admin, staff assignments, log search, alert list, source health; every tenant read via RLS-protected functions; tenant-scoped views audited |
| `worker` | unchanged audit duties + ClickHouse health/retention checks |
| `clickhouse` | enabled; TLS for clients; users per service; row policies |

### 5.5 Console (sketch)
```
[Customer: All assigned ▾]  Alerts | Logs | Sources | Customers(admin)
Alerts:  time | customer | product | severity | title | status-link to vendor console
Logs:    filters: time range, device, src/dst IP, action, rule, text  → 100 rows/page, export CSV (audited)
Sources: customer | device/connector | product | last seen | accepted / rejected (24 h) | status
```

## 6. Sizing assumption (to be corrected by the owner)

Not given in the brief, so assumed: **up to 20 customers, 40 firewalls, ~5 million firewall events/day
in total, 90 days searchable**. At an estimated ~500 bytes/line raw and ClickHouse compression of
roughly 8–10× this is in the order of 25–30 GB for 90 days — inside 100 GB with room for PostgreSQL,
OS and images. These are estimates, **not measurements**: Phase 1 acceptance includes a replay test at
this volume measuring CPU, RAM, ingest rate and disk per day. If the real numbers are larger, the
levers are shorter retention, Wasabi archive of older partitions, or a larger disk.

## 7. Security testing required before Phase 1 is accepted
- Cross-tenant tests: analyst assigned to customer A cannot read B via UI, API parameters, export,
  search filters or crafted IDs (IDOR); DB-level test that the app role with RLS cannot read B even with raw SQL.
- Device of customer A cannot write as B (certificate swap, spoofed hostnames in messages).
- Connector: credential not readable by app role; wrong-organisation response rejected; vendor outage → back-off, no data loss after recovery.
- Parser fuzzing (Hypothesis) for every vendor format; oversized/malformed lines counted, not crashing.
- Load replay at §6 volume within the VM budget; disk-full behaviour (stop ingest, alarm, no corruption).
- Regression: full Phase 0.1 suites still pass.

## 8. Delivery order
1. Customer model, staff assignments, RLS, ClickHouse enabled with tenant-scoped schema, cross-tenant tests.
2. Check Point via Log Exporter (direct mTLS) + parser.
3. Sophos Firewall: client-certificate test on the real firewall; direct or relay; parser.
4. Huntress connector; then Sophos Central connector.
5. Console pages, source health, load test, documentation, security assessment of Phase 1.

## 9. Left to the builder
Exact ClickHouse schema and codecs; parser field mappings per vendor log type; batch sizes; polling
intervals within vendor rate limits; UI details within the sketch.

## 10. Risks and open items
- Sophos Firewall client-certificate support unverified (relay fallback, §5.2).
- Vendor API details unverified (§5.3).
- Volume assumption (§6) unverified.
- Real customer data is still not allowed until the Phase 0.1 production gate (SECURITY_ASSESSMENT.md §5)
  and a Phase 1 security assessment are complete; lab uses owner's devices with test or non-sensitive traffic.
- Single VM: no HA; ingestion stops during maintenance (devices must buffer or data is lost — to be documented per vendor).
