#!/usr/bin/env bash
# One-time (and re-runnable) setup: secrets, folders, permissions.
# Run from the deploy folder as root:  sudo ./setup.sh
set -euo pipefail
umask 077
cd "$(dirname "$0")"

die()  { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
info() { printf '\033[1;34m==> %s\033[0m\n' "$*"; }

[[ $EUID -eq 0 ]] || die "Run as root (sudo)."
[[ -f .env ]] || die "Copy .env.example to .env and fill it in first."
grep -q "CHANGE_ME" .env && die ".env still contains CHANGE_ME values."
# Never execute a deployment .env as root. Accept literal KEY=value only.
[[ ! -L .env ]] || die ".env must not be a symlink."
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -z "$line" || "$line" == \#* ]] && continue
  [[ "$line" =~ ^([A-Z_][A-Z0-9_]*)=(.*)$ ]] || die "Invalid .env assignment."
  key=${BASH_REMATCH[1]}; value=${BASH_REMATCH[2]}
  case "$key" in
    SIEM_HOSTNAME|SIEM_BIND_IP|SIEM_TLS|SIEM_OIDC_TENANT_ID|SIEM_OIDC_CLIENT_ID|SIEM_INITIAL_SUPER_ADMIN_OIDS|SIEM_REQUIRE_MFA_CLAIM|SIEM_SESSION_IDLE_MINUTES|SIEM_SESSION_ABSOLUTE_HOURS|SIEM_S3_ENDPOINT|SIEM_S3_REGION|SIEM_S3_BUCKET|SIEM_AUDIT_RETENTION_DAYS|SIEM_HEARTBEAT_URL|EDGE_SUBNET|CADDY_IP|EDGE_DYNAMIC_RANGE|BACKEND_SUBNET|COLLECT_DB_SUBNET|SIEM_DB_OWNER_USER|SIEM_DB_APP_USER|SIEM_DB_WORKER_USER|SIEM_DB_EMERGENCY_USER|SIEM_DB_AUTH_USER|DATA_DIR|CLICKHOUSE_CPUS|CLICKHOUSE_MEMORY|SIEM_EVENT_RETENTION_DAYS) export "$key=$value" ;;
    *) die "Unexpected .env key: $key" ;;
  esac
done < .env
[[ -n "${SIEM_DB_AUTH_USER:-}" ]] || die "SIEM_DB_AUTH_USER is missing from .env. Add SIEM_DB_AUTH_USER=siem_auth (login-service DB role, see .env.example)."
python3 - <<'VALIDATE'
import ipaddress, os, re
from pathlib import Path
from uuid import UUID
bind = ipaddress.IPv4Address(os.environ['SIEM_BIND_IP'])
if bind.is_unspecified or bind.is_multicast or bind.is_loopback:
    raise SystemExit('Use a specific management interface IPv4 address')
nets = {key: ipaddress.IPv4Network(os.environ[key]) for key in ('EDGE_SUBNET','BACKEND_SUBNET','COLLECT_DB_SUBNET')}
ipaddress.IPv4Network(os.environ['EDGE_DYNAMIC_RANGE'])
keys = list(nets)
for i, a in enumerate(keys):
    for b in keys[i+1:]:
        if nets[a].overlaps(nets[b]):
            raise SystemExit(f'{a} and {b} overlap; pg_hba network separation would be meaningless')
ipaddress.IPv4Address(os.environ['CADDY_IP'])
for key in ('SIEM_OIDC_TENANT_ID','SIEM_OIDC_CLIENT_ID'):
    UUID(os.environ[key])
for oid in os.environ['SIEM_INITIAL_SUPER_ADMIN_OIDS'].split(','):
    UUID(oid.strip())
roles = [os.environ['SIEM_DB_'+r+'_USER'] for r in ('OWNER','APP','WORKER','EMERGENCY','AUTH')]
if len(set(roles)) != 5 or not all(re.fullmatch('[a-z][a-z0-9_]{0,62}', r) and not r.startswith('pg_') and r not in ('siem_bootstrap','siem_ingest') for r in roles):
    raise SystemExit('Invalid or duplicate database roles')
days = os.environ.get('SIEM_EVENT_RETENTION_DAYS', '90')
if not re.fullmatch('[0-9]{1,4}', days) or not 1 <= int(days) <= 730:
    raise SystemExit('SIEM_EVENT_RETENTION_DAYS must be a whole number of days, 1..730')
if not re.fullmatch('[1-9][0-9]*[MG]', os.environ.get('CLICKHOUSE_MEMORY', '3G')):
    raise SystemExit('CLICKHOUSE_MEMORY must look like 3G or 3072M')
path = Path(os.environ['DATA_DIR'])
if not path.is_absolute() or path == Path('/') or path.resolve() != path:
    raise SystemExit('DATA_DIR must be an absolute, canonical, non-symlink path')
VALIDATE

SECRET_GID=10050   # shared group that lets containers read only the secrets mounted into them
PG_UID=70; CH_UID=101; CADDY_UID=10002

if [[ -e "$DATA_DIR/postgres/PG_VERSION" && ! -s secrets/db_bootstrap_password ]]; then
  die "Existing pre-0.2 database detected. Preserve original database and audit files; use a fresh deployment directory."
fi
if [[ -e "$DATA_DIR/postgres/PG_VERSION" && ! -s secrets/db_ingest_password ]]; then
  die "Phase 1 requires a fresh lab database or a separately reviewed database role upgrade. Preserve prior evidence."
fi
info "Creating secrets"
install -d -m 0750 -o root -g "$SECRET_GID" secrets
gen() {  # random secret, created once and never overwritten
  local f="secrets/$1"
  if [[ ! -s "$f" ]]; then
    openssl rand -hex 32 > "$f"
    echo "  generated $1"
  fi
}
placeholder() {  # value you must fill in yourself
  local f="secrets/$1"
  [[ -e "$f" ]] || { echo "CHANGE_ME" > "$f"; echo "  created $1 (FILL THIS IN)"; }
}
for s in db_ingest_password db_bootstrap_password db_owner_password db_app_password db_worker_password db_emergency_password db_auth_password audit_checkpoint_key session_secret ch_admin_password ch_reader_password ch_ingest_password ch_connector_password; do
  gen "$s"
done
placeholder oidc_client_secret
if [[ -n "${SIEM_S3_BUCKET:-}" ]]; then
  placeholder s3_access_key
  placeholder s3_secret_key
else
  [[ -e secrets/s3_access_key ]] || : > secrets/s3_access_key
  [[ -e secrets/s3_secret_key ]] || : > secrets/s3_secret_key
fi
chown root:"$SECRET_GID" secrets/*
chmod 0440 secrets/*

install -d -m 0750 -o root -g "$SECRET_GID" collector/tls

info "Writing ClickHouse users (password hashes only)"
# Deny by default: each account gets only what its service needs, and only from
# the Docker networks that service sits on. ch_connector_password is reserved for
# the Plan 4 connector and deliberately has no account yet.
install -d -m 0755 clickhouse/users.d
sha() { tr -d '\n' < "secrets/$1" | sha256sum | cut -d' ' -f1; }
cat > clickhouse/users.d/users.xml <<EOF
<clickhouse>
  <profiles>
    <siem_readonly>
      <!-- readonly=1: no writes, no DDL and no setting changes, except the
           customer scope that the row policy reads (changeable_in_readonly). -->
      <readonly>1</readonly>
      <max_execution_time>60</max_execution_time>
      <max_memory_usage>1000000000</max_memory_usage>
      <max_result_rows>100000</max_result_rows>
      <constraints>
        <SQL_siem_customer_ids><changeable_in_readonly/></SQL_siem_customer_ids>
      </constraints>
    </siem_readonly>
    <siem_writer>
      <max_execution_time>60</max_execution_time>
      <max_memory_usage>1000000000</max_memory_usage>
    </siem_writer>
  </profiles>
  <users>
    <default remove="remove"/>
    <siem_admin>
      <password_sha256_hex>$(sha ch_admin_password)</password_sha256_hex>
      <networks><ip>${BACKEND_SUBNET}</ip></networks>
      <profile>default</profile><quota>default</quota>
      <access_management>1</access_management>
    </siem_admin>
    <siem_reader>
      <password_sha256_hex>$(sha ch_reader_password)</password_sha256_hex>
      <networks><ip>${BACKEND_SUBNET}</ip></networks>
      <profile>siem_readonly</profile><quota>default</quota>
      <grants>
        <query>GRANT SELECT ON siem.*</query>
        <query>GRANT SELECT ON system.settings</query>
      </grants>
    </siem_reader>
    <siem_ingest>
      <password_sha256_hex>$(sha ch_ingest_password)</password_sha256_hex>
      <networks><ip>${BACKEND_SUBNET}</ip><ip>${COLLECT_DB_SUBNET}</ip></networks>
      <profile>siem_writer</profile><quota>default</quota>
      <grants><query>GRANT INSERT ON siem.events</query></grants>
    </siem_ingest>
  </users>
</clickhouse>
EOF
chown root:"$SECRET_GID" clickhouse/users.d/users.xml
chmod 0440 clickhouse/users.d/users.xml

info "Preparing PostgreSQL TLS certificates"
install -d -m 0700 postgres/tls
if [[ ! -e postgres/tls/ca.crt && ! -e postgres/tls/server.key ]]; then
  openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj /CN=MiniSIEM-DB-CA -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -keyout postgres/tls/ca.key -out postgres/tls/ca.crt
  openssl req -newkey rsa:3072 -nodes -subj /CN=postgres -keyout postgres/tls/server.key -out postgres/tls/server.csr
  printf "subjectAltName=DNS:postgres\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\nextendedKeyUsage=serverAuth\n" > postgres/tls/server.ext
  openssl x509 -req -in postgres/tls/server.csr -CA postgres/tls/ca.crt -CAkey postgres/tls/ca.key -CAcreateserial -days 365 -extfile postgres/tls/server.ext -out postgres/tls/server.crt
fi
[[ -s postgres/tls/ca.crt && -s postgres/tls/server.key && -s postgres/tls/server.crt ]] || die "Incomplete DB TLS files"
chown root:70 postgres/tls/server.key
chmod 0640 postgres/tls/server.key
chmod 0644 postgres/tls/ca.crt postgres/tls/server.crt
openssl verify -CAfile postgres/tls/ca.crt -verify_hostname postgres postgres/tls/server.crt >/dev/null

info "Preparing ClickHouse TLS certificate"
# Issued by the same setup CA as PostgreSQL; clients verify the name "clickhouse".
install -d -m 0750 -o root -g "$CH_UID" clickhouse/tls
if [[ ! -e clickhouse/tls/server.crt || ! -e clickhouse/tls/server.key ]]; then
  [[ -s postgres/tls/ca.key ]] || die "Setup CA key postgres/tls/ca.key missing; cannot issue the ClickHouse certificate"
  openssl req -newkey rsa:3072 -nodes -subj /CN=clickhouse -keyout clickhouse/tls/server.key -out clickhouse/tls/server.csr
  printf "subjectAltName=DNS:clickhouse\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\nextendedKeyUsage=serverAuth\n" > clickhouse/tls/server.ext
  openssl x509 -req -in clickhouse/tls/server.csr -CA postgres/tls/ca.crt -CAkey postgres/tls/ca.key -CAcreateserial -days 365 -extfile clickhouse/tls/server.ext -out clickhouse/tls/server.crt
  rm -f clickhouse/tls/server.csr
fi
[[ -s clickhouse/tls/server.key && -s clickhouse/tls/server.crt ]] || die "Incomplete ClickHouse TLS files"
chown root:"$CH_UID" clickhouse/tls/server.key
chmod 0640 clickhouse/tls/server.key
chmod 0644 clickhouse/tls/server.crt
openssl verify -CAfile postgres/tls/ca.crt -verify_hostname clickhouse clickhouse/tls/server.crt >/dev/null \
  || die "ClickHouse certificate is not valid for 'clickhouse' under the setup CA"

info "Writing PostgreSQL client authentication rules (pg_hba.conf)"
# First match wins. TLS + SCRAM only; each role may connect only from its own
# Docker network, so a stolen web/worker password is useless from the collector
# network and the ingest password is useless from the backend network.
cat > postgres/pg_hba.conf <<HBA
# Generated by setup.sh from .env - edit .env and re-run instead.
local     all   siem_bootstrap                         trust
local     all   all                                    reject
host      all   siem_bootstrap  all                    reject
hostnossl all   all             all                    reject
hostssl   siem  siem_ingest     ${COLLECT_DB_SUBNET}   scram-sha-256
hostssl   siem  siem_ingest     all                    reject
hostssl   siem  ${SIEM_DB_AUTH_USER}       ${BACKEND_SUBNET}      scram-sha-256
hostssl   siem  ${SIEM_DB_AUTH_USER}       all                    reject
hostssl   siem  all             ${BACKEND_SUBNET}      scram-sha-256
host      all   all             all                    reject
HBA
chown root:root postgres/pg_hba.conf
chmod 0644 postgres/pg_hba.conf

info "Creating data folders in ${DATA_DIR}"
install -d -m 0750 "$DATA_DIR"
# Do not silently reset checkpoint for an existing deployment.
if [[ ! -d "$DATA_DIR/audit-state" ]]; then
  [[ ! -e "$DATA_DIR/postgres/PG_VERSION" ]] || die "Existing database: preserve evidence; fresh Phase 0.1 installation required."
  install -d -m 0700 -o 10001 -g 10001 "$DATA_DIR/audit-state"
  python3 - "$DATA_DIR/audit-state/checkpoint.json" <<'PYCODE'
import hashlib, hmac, json, sys
from pathlib import Path
key = bytes.fromhex(Path('secrets/audit_checkpoint_key').read_text().strip())
body = {'id': 0, 'hash': '0'*64}
raw = json.dumps(body, sort_keys=True, separators=(',', ':')).encode()
Path(sys.argv[1]).write_text(json.dumps({'body': body, 'mac': hmac.new(key, raw, hashlib.sha256).hexdigest()}, sort_keys=True))
PYCODE
  chown 10001:10001 "$DATA_DIR/audit-state/checkpoint.json"
  chmod 0600 "$DATA_DIR/audit-state/checkpoint.json"
fi
[[ -s "$DATA_DIR/audit-state/checkpoint.json" ]] || die "Checkpoint missing; investigate, do not reset."
install -d -m 0700 -o "$PG_UID"    -g "$PG_UID"    "$DATA_DIR/postgres"
install -d -m 0700 -o "$CH_UID"    -g "$CH_UID"    "$DATA_DIR/clickhouse"
install -d -m 0700 -o "$CADDY_UID" -g "$CADDY_UID" "$DATA_DIR/caddy" "$DATA_DIR/caddy/data" "$DATA_DIR/caddy/config"
install -d -m 0750 -o root -g "$CADDY_UID" caddy/certs

chmod 0640 .env

# Upgrade path: the role script in postgres/ only runs by itself on the FIRST start
# of an empty data directory. On an existing database, run the same idempotent
# script inside the running postgres container (local socket, bootstrap superuser)
# so roles added by a newer release exist before the app starts, e.g. the
# login-service role SIEM_DB_AUTH_USER (N12). Grants come from migrate as usual.
if [[ -e "$DATA_DIR/postgres/PG_VERSION" ]]; then
  info "Existing database: ensuring all database login roles exist"
  command -v docker >/dev/null || die "docker is required to update roles on an existing database"
  docker compose up -d --wait postgres >/dev/null || die "Could not start postgres to update roles"
  docker compose exec -T postgres sh /docker-entrypoint-initdb.d/01-app-role.sh >/dev/null \
    || die "Updating database roles failed"
  echo "  database roles up to date"
fi
info "Setup complete."
if grep -qs CHANGE_ME secrets/*; then
  echo "Still to fill in:"; grep -l CHANGE_ME secrets/* | sed 's/^/  /'
  echo "Edit with: sudo nano secrets/<name>   (no trailing spaces)"
fi
