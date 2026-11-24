# Security architecture comparison: Mini-SIEM Phase 0.1 vs. Wazuh 4.14.10

**Wazuh version compared:** 4.14.10 — newest release listed on the official release-notes index
(4.x line, 5 November 2026; no 5.x release listed) at https://documentation.wazuh.com/current/release-notes/index.html,
retrieved 2026-11-24.

**Method and honesty rules.** Wazuh statements come only from the official documentation pages cited
below; **Wazuh was not installed or tested here**. Mini-SIEM claims are labelled
**[V]** experimentally verified in this assessment, **[I]** implemented but not verifiable here, **[P]** proposed.
Wazuh is a mature, full XDR/SIEM platform (agents, FIM, vulnerability
detection, SCA, active response, an extensive ruleset). Mini-SIEM Phase 0.1 is a hardened *foundation*
plus a lab-grade syslog collector. The first table compares the **security architecture of the platform itself**;
the feature comparison after it shows the functional gap.

Sources (official): quickstart sizing — https://documentation.wazuh.com/current/quickstart.html ·
server requirements — …/installation-guide/wazuh-server/index.html · OVA 4.14.10 — …/deployment-options/virtual-machine/virtual-machine.html ·
architecture & component communication — …/getting-started/architecture.html ·
agent enrollment options — …/user-manual/reference/ossec-conf/client.html ·
SSO (SAML) — …/user-manual/user-administration/single-sign-on/index.html and …/microsoft-entra-id.html ·
RBAC — …/user-manual/user-administration/rbac.html · event logging/rotation — …/user-manual/manager/event-logging.html

| Dimension | Wazuh 4.14.10 (per official docs) | Mini-SIEM Phase 0.1 | Assessment |
|---|---|---|---|
| **Authentication** | Dashboard: internal user database plus SAML 2.0 SSO (Entra ID, Okta, Keycloak, …) via the indexer security plugin. Dashboard↔server API: TLS + username/password. | Entra ID **OIDC only**, no local passwords **[V in-process / I live]**; identity pinned to tenant + immutable object ID **[V]**; break-glass one-time CLI code **[V]**. | Mini-SIEM has a smaller attack surface (no password store); Wazuh is more flexible (multiple IdPs, local fallback users). |
| **Authorization / RBAC** | Indexer roles + Wazuh API RBAC; SSO users mapped through `backend_roles` (documented admin and read-only mappings; `run_as` required). | 4 fixed roles; route checks **and** database-level authorization of privileged changes via session-authenticated functions **[V]**. | Wazuh RBAC is far richer (fine-grained, multi-tenant dashboards). Mini-SIEM's DB-enforced admin path is stricter for the few actions it has. |
| **Audit integrity** | Logs compressed daily and "digitally signed" with MD5, SHA1 and SHA256 checksum files (`.sum`) per rotated file. Docs reviewed do not describe a keyed/externally anchored chain. | Per-record hash chain with protected head, append-only DB, DB-enforced atomic auditing, HMAC checkpoints outside the DB, optional Wasabi Object Lock COMPLIANCE copies, 60 s verification with UI alarms **[V local / I Wasabi]**. | Mini-SIEM's *administrative* audit trail is stronger against an insider with DB access. Wazuh protects far more *event* data; Mini-SIEM events are not anchored. |
| **Data storage security** | Wazuh indexer (OpenSearch-based) with its security plugin. | PostgreSQL 17 with least-privilege roles, per-network pg_hba, data checksums **[V]**; ClickHouse disabled until Phase 1+. Disk encryption via LUKS **[I]**. | Comparable intent; Mini-SIEM's role model is narrower and easier to audit. |
| **Encryption in transit** | Agent↔server messages AES with 256-bit keys by default; dashboard↔server TLS; enrollment with optional password and agent/manager certificate verification. | Browser↔Caddy TLS 1.2/1.3 AEAD, grade A **[V]**; app/worker↔DB TLS 1.3 verify-full **[V]**; collector mTLS with leaf-cert allowlist **[V]**; Caddy→app plaintext on a 2-member bridge (residual). | Both encrypt the important paths; Wazuh's agent channel is purpose-built; Mini-SIEM has no agents yet. |
| **Network exposure** | Commonly documented default ports 1514/1515 (agents/enrollment), 55000 (API), 9200 (indexer), 443 (dashboard) — operator must firewall. *(Stated from prior knowledge of Wazuh's docs; the ports page was not retrieved in this assessment — verify.)* | One published port (443 on the mgmt IP) + opt-in 6514; host nftables default-drop incl. Docker published ports **[V port scan / I nftables]**. | Mini-SIEM smaller by design. |
| **Container security** | Official Docker deployment exists (not reviewed in detail here — **not compared**). | Non-root, read-only rootfs, all caps dropped, no-new-privileges, seccomp (kernel-verified), limits, digest pins, verify script **[V]**; AppArmor **[I]**. | Not assessed for Wazuh. |
| **Dependency security** | Regular releases update dependencies (e.g. 4.14.6 notes: cryptography, urllib3, python-multipart updates). | Hash-pinned Python deps (pip-audit clean), SBOMs, Trivy gate on fixable vulns; 53 unfixed Debian HIGH in base **[V]**. | Wazuh has a full release engineering team; Mini-SIEM has a smaller surface but a single maintainer. |
| **Tenant isolation** | Multi-tenancy via OpenSearch tenants and agent groups (documented role mappings reference `global_tenant`). | **None** — single-tenant console; events limited to SSO super admins. | Wazuh clearly ahead; essential for an MSP (Phase 1+ requirement). |
| **Resource efficiency** | Quickstart (all-in-one): 4 vCPU / 8 GiB / 50 GB for 1–25 agents (90 days); OVA 4.14.10 needs 4 cores / 8 GB. | Measured peak < 250 MiB RSS total under a 1,500 req/s flood with 200k events **[V]**; container limits total 2.5 GiB. | Mini-SIEM is far lighter today, but it does far less; the real comparison must be repeated once Phase 1 ingests and indexes real volume. |
| **Compromised-account resilience** | SSO users get roles via IdP attributes; internal users have passwords. | Stolen web DB password cannot escalate; stolen admin session cannot erase or bypass the audit trail; break-glass revoked on demotion **[V]**. | Mini-SIEM explicitly engineered for this; Wazuh docs reviewed do not make equivalent claims (not tested either way). |
| **Backup / DR** | Documented backup guidance exists (not reviewed in detail — **not compared**). | `backup.sh`/`restore.sh` with matching checkpoint, live DR test incl. rollback detection **[V]**. | — |
| **Production readiness** | Mature, widely deployed, extensive rules and integrations (incl. Windows/Linux agents, many firewall decoders). | **Not production-approved** (see SECURITY_ASSESSMENT.md decision). No agents, no vendor parsers, no correlation, no tenant isolation. | Wazuh is production-ready; Mini-SIEM is a hardened foundation. |

## Feature comparison

Added after the architecture comparison, at the owner's request. **Wazuh column:** features as listed in Wazuh's
official documentation (sources below), retrieved 2026-11-24; Wazuh was **not installed or tested**, so this says
what Wazuh documents, not how well it works. **Mini-SIEM column:** what is in this release's source code.
Status labels: **Yes** (in this release), **Lab** (Phase 1 lab collector: opt-in, synthetic data only),
**Planned** (on the roadmap, not implemented), **No** (not planned yet).

Sources (official): capabilities index — https://documentation.wazuh.com/current/user-manual/capabilities/index.html ·
use cases — …/getting-started/use-cases/index.html · log data analysis — …/getting-started/use-cases/log-analysis.html ·
cloud workload protection — …/getting-started/use-cases/cloud-workload-protection.html ·
regulatory compliance — …/getting-started/use-cases/regulatory-compliance.html ·
external API integration — …/user-manual/manager/integration-with-external-apis.html

### Data collection

| Feature | Wazuh 4.14.10 | Mini-SIEM Phase 0.1 |
|---|---|---|
| Endpoint agent (Windows, Linux, macOS) | Yes — the Wazuh agent | **No** agent; Planned: standard forwarders (WEF/WEC, Fluent Bit, rsyslog) instead of an own agent |
| Agentless monitoring (SSH to devices) | Yes | No |
| Syslog from network devices | Yes — syslog on the Wazuh server | **Lab** — TCP/6514 with mandatory mutual TLS and a certificate allowlist; no UDP or plaintext; deliberately low rate limits |
| journald / log files on hosts | Yes — via the agent | No (Planned via forwarders) |
| Cloud provider logs (AWS, Azure, Google Cloud) | Yes — through provider APIs | No |
| SaaS logs (Office 365, GitHub) | Yes | No |
| Sophos Central, Huntress APIs | Not covered by the pages reviewed (possible through custom integrations) | Planned (pull with per-tenant credentials) |
| Durable queue, delivery acknowledgement, loss accounting | Not reviewed | **No** — lab collector can lose events |

### Analysis and detection

| Feature | Wazuh 4.14.10 | Mini-SIEM Phase 0.1 |
|---|---|---|
| Log parsing (decoders) | Yes — decoders turn logs into structured fields | **Lab** — generic key/value tokens only; no vendor parsers |
| Detection rules | Yes — rule engine with an extensive default ruleset and custom rules | **Lab** — 3 illustrative rules (authentication failure, firewall deny, malware indicator) |
| Correlation across events | Yes — rules can build on earlier events | No |
| Threat intelligence (CDB lists, VirusTotal, YARA) | Yes | No |
| Malware and rootkit detection | Yes (FIM rules, rootkit behaviour, ClamAV and Windows Defender log collection) | No |
| Threat hunting | Yes — documented use case | Basic event search only (source, text, rule; 100-result cap) |

### Endpoint security

| Feature | Wazuh 4.14.10 | Mini-SIEM Phase 0.1 |
|---|---|---|
| File integrity monitoring (incl. Windows Registry) | Yes | No (the SIEM host itself uses AIDE via `host/harden.sh`) |
| Vulnerability detection | Yes | No (the SIEM's own images are scanned in CI with Trivy) |
| Security configuration assessment (CIS-style policies) | Yes — SCA with built-in and custom policies | No (the SIEM host is hardened and checked by its own scripts) |
| System inventory (packages, ports, processes; osquery) | Yes — Syscollector, osquery | No |
| System call / command monitoring | Yes — Linux audit integration, command monitoring | No |
| Container monitoring (Docker, Kubernetes) | Yes | No |

### Response, alerting and compliance

| Feature | Wazuh 4.14.10 | Mini-SIEM Phase 0.1 |
|---|---|---|
| Active response (block IP, disable account, custom scripts) | Yes | No (deliberately not planned before tenant isolation) |
| Alerting to Slack, PagerDuty, Shuffle, custom scripts | Yes — Integrator module | No event alerting. Only a dead-man's-switch heartbeat when audit integrity verification fails |
| Compliance mapping (PCI DSS, GDPR, HIPAA, NIST 800-53, TSC) | Yes | No |
| Dashboards and reports | Yes — Wazuh dashboard, custom dashboards | Fixed pages: overview, events, users, audit log |

### Platform and administration

| Feature | Wazuh 4.14.10 | Mini-SIEM Phase 0.1 |
|---|---|---|
| Single sign-on | Yes — SAML 2.0 (Entra ID, Okta, Keycloak, …) | **Yes** — Entra ID OIDC only, no local passwords |
| Local user accounts | Yes | No — one-time break-glass codes from the host CLI instead |
| Role-based access control | Yes — fine-grained, plus API RBAC | **Yes** — 4 fixed roles, privileged changes enforced in the database |
| Multi-tenancy (per-customer separation) | Yes — tenants and agent groups | **No** — single tenant; Planned first for MSP use |
| Tamper-evident administrative audit log | Signed checksums of rotated log files | **Yes** — hash chain, keyed checkpoints, optional Wasabi Object Lock |
| Event retention / archiving | Yes — indexer storage and archives | **Lab** — events pruned after 24 h, not archived |
| Scale-out / high availability | Yes — clustered server and indexer | No — single VM by design |
| API for automation | Yes — Wazuh server API | No |

### What this means

Wazuh documents almost every row above (exceptions are marked); Mini-SIEM covers only identity, access control, audit integrity and a lab-grade
syslog receiver. Mini-SIEM **cannot replace Wazuh today** for monitoring endpoints, detecting threats or
meeting compliance needs. Its value is a smaller, more tightly controlled platform core that the roadmap
below would build on. Mini-SIEM's lead is limited to its own administrative security (see the architecture
table above). If customers need detection now, deploying Wazuh, possibly alongside Mini-SIEM, is the
realistic option.

## Implications for the roadmap (proposed, not implemented)

To become a credible MSP alternative while keeping the security properties above:

1. **Tenant isolation first** (row-level security keyed by tenant, tenant-scoped roles, per-tenant retention) **[P]**.
2. Reuse open standards instead of writing agents: Windows via WEF/WEC or Fluent Bit, Linux via journald/rsyslog over mTLS **[P]**.
3. Vendor parsers in priority order: Sophos XG/XGS syslog, Check Point (Log Exporter/CEF), Sophos Central & Huntress via their APIs (pull, with per-tenant credentials in a secret store) **[P]**.
4. Extend anchoring to events (per-batch hashes in Object Lock) and add a two-person rule for privileged changes **[P]**.
5. Benchmark against Wazuh on the same 4 vCPU / 8 GB VM with identical log replay before claiming efficiency advantages **[P]**.
