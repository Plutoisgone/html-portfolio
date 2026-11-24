#!/usr/bin/env bash
# Consistent backup of one Mini-SIEM installation. Run from the deploy folder as root:
#   sudo ./backup.sh /secure/backup/location
# Produces <dest>/mini-siem-<UTC timestamp>/ containing:
#   database.dump      pg_dump custom format (schema, data, grants, audit chain)
#   audit-state/       the worker's HMAC checkpoint (MUST be restored together with the dump)
#   config.tar         .env, secrets/, postgres/tls/, caddy/certs/ (SENSITIVE)
#   SHA256SUMS         integrity manifest
# The worker is stopped while the dump and checkpoint are taken, so they match exactly.
# Optional: BACKUP_GPG_RECIPIENT=<key id> encrypts the whole set with GnuPG (public key).
# Store backups off-host (e.g. Veeam/immutable repository). The audit rows themselves are
# additionally kept in Wasabi Object Lock when S3 export is enabled.
set -euo pipefail
umask 077
cd "$(dirname "$0")" || exit 1
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)." >&2; exit 1; }
dest_root="${1:?usage: backup.sh <destination directory>}"
[[ -d "$dest_root" ]] || { echo "Destination $dest_root does not exist." >&2; exit 1; }
data_dir="$(grep -E '^DATA_DIR=' .env | head -1 | cut -d= -f2-)"
[[ -n "$data_dir" && -d "$data_dir/audit-state" ]] || { echo "DATA_DIR/audit-state not found." >&2; exit 1; }

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="${dest_root%/}/mini-siem-${stamp}"
install -d -m 0700 "$out"
restart_worker=0
if docker compose ps --status running --services 2>/dev/null | grep -qx worker; then
  docker compose stop worker >/dev/null
  restart_worker=1
fi
trap '[[ $restart_worker -eq 1 ]] && docker compose start worker >/dev/null' EXIT

docker compose exec -T postgres pg_dump -U siem_bootstrap -d siem --format=custom --no-password > "$out/database.dump"
cp -a "$data_dir/audit-state" "$out/audit-state"
tar -cf "$out/config.tar" .env secrets postgres/tls caddy/certs
( cd "$out" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )
if [[ -n "${BACKUP_GPG_RECIPIENT:-}" ]]; then
  tar -C "$dest_root" -cf - "mini-siem-${stamp}" | gpg --batch --yes --encrypt --recipient "$BACKUP_GPG_RECIPIENT" \
    --output "${out}.tar.gpg"
  rm -rf "$out"
  echo "Encrypted backup: ${out}.tar.gpg"
else
  echo "Backup: $out  (contains secrets: protect it like the server itself)"
fi
