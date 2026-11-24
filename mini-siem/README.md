# Mini-SIEM — Phase 0.1 security-hardened release

> **Status:** approved for an isolated lab / pilot with synthetic data. **Not production-approved** —
> see `SECURITY_ASSESSMENT.md` §5 for the production gate.
>
> Start here: `SECURITY_ASSESSMENT.md` (decision) · `DEPLOYMENT_GUIDE.md` (install) ·
> `VULNERABILITY_REMEDIATION.md` · `PENETRATION_TEST_REPORT.md` · `THREAT_MODEL.md` ·
> `SECURITY_ARCHITECTURE.md` · `TEST_RESULTS.md` · `WAZUH_COMPARISON.md` · `CHANGELOG.md` ·
> SBOMs in `sbom/` · raw test/scan output in `evidence/`.
>
> The sections below are the original Phase 0 README, kept for reference; where they differ,
> `DEPLOYMENT_GUIDE.md` wins (e.g. users are identified by Entra **object ID**, not UPN).

---

# Phase 1 lab candidate

See [PHASE1_GUIDE.md](PHASE1_GUIDE.md) for the new optional mTLS collector, event store, console, deployment steps and limitations. The remainder of this README describes the inherited Phase 0.2 foundation. Phase 0.3 auth/admin separation and live acceptance remain incomplete.

# Mini-SIEM: Phase 0.2 (security remediation candidate)

**LAB ONLY.** Read `SECURITY_ASSESSMENT.md`, `TEST_RESULTS.md` and `DEPLOYMENT_GUIDE.md` first. Use a new database, checkpoint key and dedicated bucket; retain all old evidence.

**Lab only. Fresh database required.** Read `SECURITY_ASSESSMENT.md` and `DEPLOYMENT_GUIDE.md` before deployment. Full stack validation is pending.

Phase 0 builds the hardened base that every later phase sits on. It includes:

- A hardened Ubuntu 24.04 host: CIS Level 1-style settings, nftables firewall, auditd, AIDE, automatic security updates, SSH with keys only.
- A Docker stack in which every container runs as non-root, with a read-only filesystem, no Linux capabilities, and its own network zone.
- Sign-in through **Entra ID single sign-on** only. There is no password login to attack. MFA is enforced by Conditional Access.
- Roles: `super_admin`, `client_admin`, `analyst` and `read_only`.
- A **tamper-evident audit log**. It is hash-chained, the database blocks any edit or delete of its rows, and it is copied to S3 with Object Lock.
- A **break-glass** emergency login that can only be created from the server's command line.
- A CI pipeline that runs unit tests, Bandit, Semgrep, pip-audit, ShellCheck and Trivy.

Values written as `<LIKE_THIS>` are placeholders. Replace them with your own values.

---

## 1. What you need

| Item | Notes |
| --- | --- |
| Hyper-V VM | Generation 2, 4 vCPU, 8 GB RAM (Dynamic Memory **off**), 100 GB disk |
| Ubuntu Server 24.04 LTS | Install with **"Encrypt the LVM group with LUKS"** ticked |
| A DNS name | For example `<SIEM_HOSTNAME>`, resolving to the VM's IP |
| Entra ID admin | To create an app registration and a Conditional Access policy |
| Wasabi (or other S3) bucket | Created **with Object Lock enabled**, for the immutable audit copy |
| Management VLAN / VPN | The only network allowed to reach SSH and the dashboard |

## 2. Install Ubuntu

1. In Hyper-V, set the Secure Boot template to **Microsoft UEFI Certificate Authority**.
2. During install, choose **Use an entire disk > Set up this disk as an LVM group > Encrypt the LVM group with LUKS**. Store the passphrase in your password manager. You'll type it at every boot from the Hyper-V console.
3. Tick **Install OpenSSH server**. Give the VM a static IP.
4. From your PC, copy your SSH key: `ssh-copy-id <ADMIN_USER>@<VM_IP>`.

## 3. Harden the host

```bash
sudo mkdir -p /opt/mini-siem && sudo chown $USER /opt/mini-siem
# copy this project folder into /opt/mini-siem (scp, git clone, etc.)
cd /opt/mini-siem/host
cp host.conf.example host.conf
nano host.conf          # fill in every value
sudo ./harden.sh
```

Then, **before closing your current SSH session**, open a **new** SSH session from the management network to confirm you can still log in. After that, run `sudo reboot`.

What `harden.sh` does:

- Applies all updates and turns on automatic security updates (with a reboot at 03:30 if one is needed).
- Locks down SSH: keys only, no root login, only your admin user, modern ciphers.
- Sets up an nftables firewall:
  - SSH and HTTPS only from `MGMT_NETS`.
  - Syslog/TLS (6514) only from `SYSLOG_SOURCES`, and agents (24224) only from `AGENT_SOURCES`.
  - Outbound traffic limited to DNS, NTP and HTTPS.
  - It also guards Docker's published ports, which normally bypass host firewalls.
- Applies kernel hardening through sysctl, disables unused filesystems and USB storage, and turns off core dumps.
- Sets up auditd rules for identity, sudo, SSH, the firewall, Docker and the SIEM config, plus an AIDE file-integrity baseline.
- Installs Docker from Docker's official repository with a hardened `daemon.json`. Your user is **not** added to the `docker` group, because that group is equivalent to root. Use `sudo docker ...`.

## 4. Register the app in Entra ID

1. **Entra admin center > App registrations > New registration.**
   - Name: `Mini-SIEM`. Account type: **this organisational directory only**.
   - Redirect URI: platform **Web**, `https://<SIEM_HOSTNAME>/auth/callback`.
2. **Certificates & secrets > New client secret.** Copy the value. You'll put it in `deploy/secrets/oidc_client_secret`.
3. Note the **Application (client) ID** and **Directory (tenant) ID**.
4. **Enterprise applications > Mini-SIEM > Properties:** set **Assignment required = Yes**. Then, under **Users and groups**, assign only the people who should have access.
5. **Conditional Access > New policy** for the Mini-SIEM app:
   - Grant: **Require authentication strength: Phishing-resistant MFA** (FIDO2 key or Windows Hello). If that isn't possible yet, use "Require MFA".
   - Session: sign-in frequency of 8 hours.
   - Optionally, require a compliant device (Intune).

## 5. Create the immutable audit bucket (Wasabi)

1. Create a bucket such as `<AUDIT_BUCKET>` with **Object Locking enabled**. This can only be switched on at creation.
2. Create a dedicated user and access key with this policy. It can upload and set retention, but it **cannot delete**:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:PutObjectRetention", "s3:GetObjectVersion", "s3:GetObjectRetention"],
      "Resource": ["arn:aws:s3:::<AUDIT_BUCKET>", "arn:aws:s3:::<AUDIT_BUCKET>/*"] },
    { "Effect": "Deny",
      "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention",
                 "s3:PutBucketObjectLockConfiguration", "s3:DeleteBucket"],
      "Resource": ["arn:aws:s3:::<AUDIT_BUCKET>", "arn:aws:s3:::<AUDIT_BUCKET>/*"] }
  ]
}
```

3. Use your bucket region's service URL from Wasabi's documentation for `SIEM_S3_ENDPOINT`.

## 6. Deploy

```bash
cd /opt/mini-siem/deploy
cp .env.example .env
nano .env                       # fill in every CHANGE_ME
sudo ./setup.sh                 # creates secrets, data folders and permissions
sudo nano secrets/oidc_client_secret   # paste the Entra client secret
sudo nano secrets/s3_access_key        # if using S3
sudo nano secrets/s3_secret_key
sudo docker compose up -d --build
sudo docker compose ps          # everything "healthy"/"Up"; migrate "Exited (0)"
```

**TLS certificate:** `SIEM_TLS=internal` makes Caddy use its own private CA, which is fine for a lab. Browsers will warn until you trust that CA. For production, copy your company certificate to `deploy/caddy/certs/cert.pem` and `key.pem`, then set `SIEM_TLS=/certs/cert.pem /certs/key.pem` as a literal value in `.env` (no shell quoting).

**First sign-in:** browse to `https://<SIEM_HOSTNAME>` and sign in with the verified Entra object UUID listed in `SIEM_INITIAL_SUPER_ADMIN_OIDS`. That account becomes the first super admin. Add everyone else under **Users**, using their verified Entra object UUID and UPN. Only the first login can bootstrap a super admin.

## 7. Break-glass (emergency access)

Use this only when Entra ID sign-in is unavailable. It requires SSH from the management network.

```bash
cd /opt/mini-siem/deploy
sudo docker compose run --rm emergency breakglass <SUPER_ADMIN_UPN>
```

Open `https://<SIEM_HOSTNAME>/breakglass` and paste the code. The code is valid for 10 minutes and works once. The session lasts 1 hour. Every step is logged as **critical**.

## 8. Phase 0 gate: checks before moving on

- [ ] From **outside** the management network, `https://<SIEM_HOSTNAME>` and SSH both time out.
- [ ] From the management network, sign-in works and asks for MFA.
- [ ] A user who isn't registered is denied, and the attempt shows in the audit log.
- [ ] `sudo docker compose exec app python -m siem.cli verify-audit` prints `Audit chain OK`.
- [ ] Audit files appear in the S3 bucket within 5 minutes, and deleting one is refused.
- [ ] The heartbeat check (if configured) shows pings every 5 minutes.
- [ ] From a PC on the management network (Python + `pip install httpx`), run the end-to-end smoke test with a break-glass code:
  ```bash
  SIEM_URL=https://<SIEM_HOSTNAME> SIEM_CA_FILE=/path/to/trusted-ca.pem BREAKGLASS_CODE=<CODE> python3 app/tests/smoke_test.py
  ```
- [ ] An external vulnerability scan of the VM shows no high or critical findings.

## 9. Operations

| Task | Command |
| --- | --- |
| Status | `sudo docker compose ps` |
| Logs | `sudo docker compose logs -f app worker` |
| Update app | `git pull && sudo docker compose up -d --build` |
| Update base images | `sudo docker compose pull && sudo docker compose up -d` |
| Check audit chain | `sudo docker compose exec app python -m siem.cli verify-audit` |
| Back up config | Back up `/opt/mini-siem/deploy` (including `secrets/`) and `/opt/mini-siem/data/postgres` with Veeam |

**Updating images:** for production, pin images by digest (`image: postgres:17-alpine@sha256:...`) after testing, then rebuild monthly.

## 10. Known limitations (Phase 0)

- The outbound firewall allows HTTPS to any address. Phase 2 adds an egress proxy with a domain allowlist.
- Break-glass uses a one-time code from the server console rather than a hardware key. This is still strong, because creating a code requires SSH key access from the management network.
- `harden.sh` has been syntax-checked and linted, but not yet run on a real VM. Run it on a fresh test VM first and check the output.
- ClickHouse is disabled by default and isolated in the `future` profile. Do not enable it in Phase 0.2.
- Pin the GitHub Actions in `.github/workflows/security.yml` to commit SHAs before relying on the pipeline.
