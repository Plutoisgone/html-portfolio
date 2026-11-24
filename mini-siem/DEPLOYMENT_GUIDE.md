# Deployment guide — Mini-SIEM Phase 0.1 (Hyper-V, Ubuntu Server 24.04 LTS)

Target: Hyper-V Generation 2 VM, **4 vCPU, 8 GB RAM (Dynamic Memory off), 100 GB disk**, Secure Boot
template "Microsoft UEFI Certificate Authority", Ubuntu Server 24.04 LTS installed with
**"Encrypt the LVM group with LUKS"**. Lab/pilot only until the production gate in SECURITY_ASSESSMENT.md §5 is met.

Values in `<ANGLE_BRACKETS>` are yours to fill in. Run everything as root via `sudo` from a root-owned
copy of this project (e.g. `/opt/mini-siem`), never from a group/world-writable directory.

## 1. Host hardening

```bash
sudo mkdir -p /opt/mini-siem && sudo chown root:root /opt/mini-siem
# copy the extracted archive into /opt/mini-siem (scp/rsync), then:
cd /opt/mini-siem/host
sudo cp host.conf.example host.conf && sudo chmod 600 host.conf && sudo nano host.conf
# take a Hyper-V checkpoint and keep the VM console open, then:
sudo ./harden.sh
```

`harden.sh` applies CIS-L1-style settings, SSH keys-only, nftables default-drop (incl. Docker published
ports), auditd (now also watching `/opt/mini-siem/data/audit-state/`), AIDE, unattended security updates,
and installs Docker from Docker's repository **after verifying the signing-key fingerprint**
`9DC8 5822 9FC7 DD38 854A E2D8 8D81 803C 0EBF CD88`. Open a second SSH session to confirm access, then reboot.

## 2. Entra ID app registration

1. App registrations → New: single tenant; redirect URI (Web) `https://<SIEM_HOSTNAME>/auth/callback`.
2. Certificates & secrets → client secret (expiry ≤ 12 months; diary the rotation).
3. Enterprise app → **Assignment required = Yes**; assign only operators.
4. Conditional Access: phishing-resistant MFA, sign-in frequency 8 h, optionally compliant device.
5. Record the **tenant ID**, **client ID** and the **object ID** of the first administrator
   (Entra → Users → user → Object ID). Users are authorized by object ID, never by UPN.

## 3. Wasabi Object Lock bucket (strongly recommended)

Create a **new, dedicated** bucket with **Object Lock enabled at creation** and versioning on; a dedicated
user with exactly the policy in `deploy/s3-policy.example.json` (no delete, no bypass, no bucket admin).
Use your region's Wasabi endpoint for `SIEM_S3_ENDPOINT`. Configure an external dead-man's switch
(e.g. healthchecks.io) for `SIEM_HEARTBEAT_URL`: it alerts when integrity verification or export fails.

## 4. Configure and install

```bash
cd /opt/mini-siem/deploy
sudo cp .env.example .env && sudo nano .env      # literal KEY=value only; no quotes/expansion
sudo ./setup.sh                                  # secrets, TLS CA/certs, pg_hba.conf, data dirs (re-runnable)
sudo nano secrets/oidc_client_secret             # paste the Entra client secret
sudo nano secrets/s3_access_key secrets/s3_secret_key   # if S3 is enabled
sudo docker compose config --quiet
sudo docker compose build                        # app + hardened postgres images
sudo docker compose up -d
sudo docker compose ps -a                        # app/postgres healthy, worker up, migrate Exited (0)
sudo ./verify-deployment.sh                      # MUST report 0 failures on the VM (AppArmor included)
```

Key `.env` settings: `SIEM_BIND_IP` = the VM's management IPv4 (never 0.0.0.0); `SIEM_INITIAL_SUPER_ADMIN_OIDS`;
non-overlapping `EDGE_SUBNET`, `BACKEND_SUBNET`, `COLLECT_DB_SUBNET` (setup refuses overlaps).
TLS: `SIEM_TLS=internal` for a lab, or put your certificate in `caddy/certs/` and set
`SIEM_TLS=/certs/cert.pem /certs/key.pem`.

Building behind a TLS-inspecting proxy: pass the proxy CA as a build secret
(`docker build --secret id=pip_ca,src=<ca.pem> …`); never disable verification.

## 5. Post-install verification (lab)

```bash
sudo docker compose exec worker python -m siem.worker --verify-once      # "Audit chain OK; anchored …"
sudo docker compose exec -T postgres psql -U siem_bootstrap -d siem -v ON_ERROR_STOP=1 < ../app/tests/db_acceptance.sql
sudo docker compose exec -T postgres psql -U siem_bootstrap -d siem -v ON_ERROR_STOP=1 < ../app/tests/db_events_acceptance.sql
# from an admin PC on the management VLAN (Python + httpx):
SIEM_URL=https://<SIEM_HOSTNAME> SIEM_CA_FILE=<ca.pem> BREAKGLASS_CODE=<code> python3 app/tests/smoke_test.py
```

Full live regression suite (lab only — it deliberately tampers with and restores the audit log):

```bash
cd app && SIEM_LIVE=1 SIEM_LIVE_DEPLOY_DIR=/opt/mini-siem/deploy \
  SIEM_LIVE_PG_ADDR=$(sudo docker inspect -f '{{(index .NetworkSettings.Networks "mini-siem_backend").IPAddress}}' mini-siem-postgres-1) \
  SIEM_LIVE_URL=https://<SIEM_HOSTNAME> SIEM_LIVE_WEB_CA=<ca.pem> python -m pytest tests/live
```

## 6. Daily operation

| Task | Command |
|---|---|
| Status / logs | `sudo docker compose ps` · `sudo docker compose logs -f app worker` |
| Anchored audit verification | `sudo docker compose exec worker python -m siem.worker --verify-once` |
| Break-glass code | `sudo docker compose run --rm emergency breakglass <SUPER_ADMIN_EMAIL>` (valid 10 min, single use, audited) |
| Audit integrity status | Console → Audit log (red banner = failed or stale verification) |
| Backup | `sudo ./backup.sh /secure/backups` (optionally `BACKUP_GPG_RECIPIENT=<keyid>`) |
| Restore (new VM / DR) | copy release, then `sudo ./restore.sh /secure/backups/mini-siem-<stamp>` |
| Runtime hardening check | `sudo ./verify-deployment.sh` |

## 7. Upgrading

* **From the Phase 1 lab candidate (schema v4):** tested in place. Add `COLLECT_DB_SUBNET=172.31.250.64/28`
  (or your value) to `.env`, run `sudo ./setup.sh` (regenerates `pg_hba.conf`), rebuild, `docker compose up -d`.
  Migration 5 applies and **all runtime grants are reset**. Run `--verify-once` afterwards.
* **From Phase 0 (schema v1):** not supported in place (superuser owner, incompatible audit format). Back up
  the old database and its S3 exports as evidence, then install fresh.
* Images are pinned by digest. To update: pull, scan (`trivy image --ignore-unfixed --severity HIGH,CRITICAL`),
  update the digest in `compose.yaml` / Dockerfiles, rebuild, re-run section 5. Rebuild at least monthly.

## 8. Backup and disaster recovery

`backup.sh` pauses the worker so the database dump and the HMAC checkpoint match. **Always restore them
together.** Restoring an older dump with a newer checkpoint is reported as tampering (by design): rows after
the backup must then be recovered from the Wasabi export. The backup contains all secrets — store it
encrypted and off-host (e.g. Veeam immutable repository). Test a restore on a scratch VM at least quarterly.

## 9. Secret rotation

* `oidc_client_secret`, S3 keys: replace file, `docker compose up -d --force-recreate app worker`.
* DB role passwords: change file, then
  `docker compose exec -T postgres psql -U siem_bootstrap -d siem -c "ALTER ROLE <role> PASSWORD '<new>'"`
  (run the command from a root shell without recording history), recreate the affected service.
* `audit_checkpoint_key`: rotation requires re-signing the current checkpoint with the new key while the
  worker is stopped, after a successful `--verify-once`; procedure is manual (documented risk).
* DB TLS: server cert valid 365 days — delete `postgres/tls/server.*`, re-run `setup.sh` (CA kept), restart postgres.

## 10. Phase 1 lab collector (opt-in)

Disabled by default. See `PHASE1_GUIDE.md`. Synthetic logs only; the release decision does not cover it.
