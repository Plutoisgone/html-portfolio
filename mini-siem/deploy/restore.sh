#!/usr/bin/env bash
# Restore a backup made by backup.sh onto a FRESH installation directory.
#   sudo ./restore.sh /path/to/mini-siem-<stamp>
# Preconditions: this deploy folder has NO .env/secrets yet and DATA_DIR (from the backup's .env)
# does not exist yet. Restoring over a live installation is refused on purpose.
# Steps: unpack config -> setup.sh (dirs, pg_hba) -> start postgres -> pg_restore (triggers
# disabled so historic audit rows are loaded verbatim) -> restore the matching checkpoint ->
# migrate (re-applies grants) -> start everything -> anchored verification.
set -euo pipefail
umask 077
cd "$(dirname "$0")" || exit 1
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)." >&2; exit 1; }
src="${1:?usage: restore.sh <backup directory>}"
[[ -f "$src/database.dump" && -f "$src/config.tar" && -d "$src/audit-state" ]] || { echo "Not a backup.sh directory." >&2; exit 1; }
( cd "$src" && sha256sum --quiet -c SHA256SUMS ) || { echo "Backup integrity check FAILED." >&2; exit 1; }
[[ ! -e .env && ! -e secrets ]] || { echo "Refusing: this deploy folder already has .env/secrets." >&2; exit 1; }

tar -xf "$src/config.tar"
# Backups taken before the Phase 1 login service (N12) have no login-service role setting;
# setup.sh below generates its missing secret and initdb creates the role.
if ! grep -q '^SIEM_DB_AUTH_USER=' .env; then
  echo "SIEM_DB_AUTH_USER=siem_auth" >> .env
  echo "Added SIEM_DB_AUTH_USER=siem_auth to .env (backup predates the login service)."
fi
data_dir="$(grep -E '^DATA_DIR=' .env | head -1 | cut -d= -f2-)"
[[ ! -e "$data_dir/postgres/PG_VERSION" ]] || { echo "Refusing: $data_dir already holds a database." >&2; exit 1; }
rm -rf "${data_dir:?}/audit-state"
./setup.sh
install -o 10001 -g 10001 -m 0600 "$src/audit-state/checkpoint.json" "$data_dir/audit-state/checkpoint.json"

docker compose up -d --no-build postgres
for _ in $(seq 1 60); do
  docker compose exec -T postgres pg_isready -U siem_bootstrap -d siem >/dev/null 2>&1 && break
  sleep 2
done
docker compose exec -T postgres pg_restore -U siem_bootstrap -d siem --clean --if-exists \
  --disable-triggers --exit-on-error < "$src/database.dump"
docker compose up -d --no-build
docker compose run --rm -T --no-deps worker python -m siem.worker --verify-once
echo "Restore complete. Review the audit page and run ./verify-deployment.sh."
