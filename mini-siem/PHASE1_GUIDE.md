# Mini-SIEM Phase 1 — secure log collection lab candidate

This release extends Phase 0.2. It is a single-tenant, low-volume proof of concept; not an enterprise SIEM or a production-approved release. The old guides describe the inherited foundation. Use this file for Phase 1 differences.

## New capabilities

- Optional TCP/6514 receiver using TLS 1.2 or newer, mandatory client certificates and an explicit SHA-256 leaf-certificate allowlist. No UDP or plaintext fallback.
- RFC 6587-style octet-counted and LF/CRLF-delimited frames (one framing mode per connection). UTF-8 text and up to 8192 bytes; malformed messages are rejected. Source identity is server-assigned, and receipt time is database-generated; device-supplied fields are untrusted.
- PostgreSQL event storage separated from administrative audit logs. New collector DB account can insert only specified event columns. No authentication/audit secrets are mounted in the collector. The app can read events; the worker can execute a fixed retention function. Collector has its own ingress and database networks. The PostgreSQL instance remains shared.
- SSO super-admin-only event console, source/text/rule filters and a 100-result cap. No tenant-scoped access yet. The break-glass session cannot access the event console.
- Three illustrative per-event rules: authentication failure, firewall denial, and malware indicator. These use exact generic key/value tokens, not validated vendor-specific parsing, behavior analytics, correlation or confirmed incidents.

## Lab hardware and limitations

Target Ubuntu Server 24.04 LTS in Hyper-V, 4 vCPU, 8 GB RAM, 100 GB disk. Not benchmarked on that target. ClickHouse now runs (HTTPS 8443 only, customer-keyed tables, reader row policy); device logs from the collector still go to PostgreSQL until Plan 2. At most 16 concurrent client connections, 5 accepted frames/sec globally with burst 20, 2/sec per enrolled source with burst 10, 10-second frame deadline and 120-second connection lifetime. Senders must reconnect. These deliberately low limits are for a lab, not enterprise throughput. Rate-limit or malformed input closes the connection. No durable receiver queue, delivery ACK, retry or loss accounting is implemented. Device logs are not immutable or archived to Wasabi; Wasabi is for administrative audit records only.

Events are intended to be pruned after 24 hours (worker runs every 5 min, max 10,000 per cycle). A worker or database failure may delay pruning. PostgreSQL files may not shrink following deletion. Monitor disk and WAL, configure an external filesystem quota/alert and stop the collector before disk exhaustion. Retention is not a hard disk quota, especially if credentials are compromised. Do not ingest customer data in this version; use synthetic logs only.

## Fresh isolated deployment

1. Preserve Phase 0.2 database, audit checkpoint, keys and immutable backups. Use a new VM or fresh project/data directory. Do not run `docker compose down -v` against an existing deployment. Existing DBs require separately reviewed provisioning of the new role; no in-place migration is supported by this guide.
2. Follow the existing `DEPLOYMENT_GUIDE.md` for Entra app registration, Ubuntu, TLS for the web dashboard and security configuration. Copy `deploy/.env.example` to `.env`, fill required values, and run `sudo ./setup.sh` inside deploy. Complete the OIDC secret and optional Wasabi settings. The new setup generates `db_ingest_password`. Never copy secrets to the ZIP or Git.
3. Configure `host/host.conf` with the actual management subnet and a narrow `SYSLOG_SOURCES` allowlist of authorized test machines. Review `host/harden.sh` before running on a disposable VM with console access: it changes SSH, packages and firewall rules. Confirm Docker published port 6514 is reachable only from those test sources, and collector edge network cannot initiate outbound connections. Use upstream ACLs as additional protection. No public Internet exposure.
4. First build and start only the base stack: `sudo docker compose up -d --build`. Check `sudo docker compose ps -a` and migration logs. Sign in using your Entra account with Conditional Access MFA enforced. Check the dashboard before exposing any collection port.
5. Obtain certificates from an approved lab CA. Required files inside `deploy/collector/tls/`:
   - `server.crt`: PEM server certificate/chain, serverAuth and DNS SAN matching collector hostname.
   - `server.key`: matching private key (PEM, no passphrase for unattended startup).
   - `client-ca.crt`: trusted CA chain for client certificates.
   - `sources.json`: JSON object mapping lowercase SHA-256 DER leaf certificate fingerprints (64 hex characters) to source IDs (1–64 ASCII letters, digits, dots, underscores, hyphens; first character alphanumeric).

   Example fingerprint: `openssl x509 -in test-client.crt -outform DER | sha256sum`. Use the 64-character hex value as key in sources.json. Example value: `"lab-firewall-01"`. Each source must hold a separate client certificate/private key with clientAuth EKU. Keep the CA signing key and client private keys OFF the SIEM host. Directory owner root:10050, mode 0750; files root:10050, mode 0440. Configure source allowlist and certificate lifecycle; to revoke a client, remove its fingerprint and recreate the collector. Existing sessions close on restart. CA CRL/OCSP is not implemented.
6. Enable the collector: from `deploy/`, run `sudo docker compose --profile ingest up -d collector`. Confirm `sudo docker compose --profile ingest ps` and inspect collector logs. If configuration is missing/invalid, it should fail closed. The listener is published only when the profile is enabled.
7. From the allowlisted lab machine with client credentials and trusted server CA, run:

   ```sh
   python3 tools/send_test_event.py --host siem.example.internal --ca server-ca.crt --cert test-client.crt --key test-client.key
   ```

   Copy the synthetic marker from the output, sign into the web console, open Events and search for it. Confirm `firewall_deny`, authenticated source identity and server receipt time. Try both framing modes with `--framing line`. An open TLS connection alone is NOT proof of persistence.
8. Stop collection with `sudo docker compose --profile ingest stop collector`. Keep event/administrative audit records according to your approved retention policy.

## Acceptance gates (not executed here)

- Verify Docker image builds and container health, startup/migrations on fresh PostgreSQL, certificate permissions, role grants and SQL acceptance tests. For default role names, from deploy: `sudo docker compose exec -T postgres psql -U siem_bootstrap -d siem < ../app/tests/db_acceptance.sql`, then repeat with `../app/tests/db_events_acceptance.sql`. Run only on disposable lab; rollback is built into tests.
- Verify Entra login, conditional access, unauthorized users and all non-super-admin roles are denied `/events`, and emergency sessions are denied. Check actual audit records after event queries. Verify Wasabi Object Lock and backup recovery separately.
- From allowed and disallowed source IPs test network policy; from a lab source test absent, expired, unknown and untrusted client certificates. Confirm no plaintext fallback.
- Test a real authorized Sophos/Check Point device or a lab relay that supports mutually authenticated TLS, framing and reconnection. No validated vendor adapters or real-device compatibility claim yet. Windows/Linux agents, Sophos Central/Huntress API integrations and ClickHouse are pending. If a device lacks mTLS, use a separately configured trusted relay with appropriately documented source attribution; never turn off TLS validation.
- Run actual dependency/image scanning and host/firewall checks; verify log loss under load, DB/WAL growth and disk alarms. Test disaster recovery. Do not move to customer production until independently reviewed.

## Security model and residual risks

Ingestion privileges are isolated from authentication/admin operations, but the inherited web application still holds privileged auth/admin DB permissions. Full separation of auth, administration and dashboard is not complete; Phase 0.3 architecture work remains pending. A compromised collector or enrolled sender can fabricate events and exhaust its allowed bandwidth; a compromised collector DB credential can bypass in-process limits. The service does not attest that message contents are true. Source certificates establish transport identity, not event authenticity. No cross-customer isolation, HA, durable queue, active response, detection tuning, independent production pentest or guaranteed CVE-free build. Do not enable it on a customer network.
