#!/bin/sh
set -eu
# Creates the database login roles. Runs automatically on the FIRST start of an
# empty data directory (docker-entrypoint-initdb.d). It is idempotent, so setup.sh
# also runs it on an EXISTING database (docker compose exec postgres ...) to add
# roles introduced by an upgrade, e.g. the login-service role (N12). Existing roles
# keep their privileges (migrate resets grants every deploy); attributes and
# password are re-asserted from the secret files.
# The initdb superuser is local-only; application migrations use a non-superuser.
ROLE_PW=$(cat /run/secrets/db_owner_password) psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v role="$SIEM_DB_OWNER_USER" -v db="$POSTGRES_DB" <<'SQL'
\getenv role_pw ROLE_PW
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role') AS missing \gset
\if :missing
CREATE ROLE :"role" LOGIN PASSWORD :'role_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
\endif
ALTER ROLE :"role" LOGIN PASSWORD :'role_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER DATABASE :"db" OWNER TO :"role";
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
SQL
for entry in "${SIEM_DB_APP_USER}:db_app_password" "${SIEM_DB_WORKER_USER}:db_worker_password" "${SIEM_DB_EMERGENCY_USER}:db_emergency_password" "${SIEM_DB_INGEST_USER}:db_ingest_password" "${SIEM_DB_AUTH_USER}:db_auth_password"; do
  role=${entry%%:*}; file=${entry#*:}
  # psql reads the password from the environment, not the command line.
  ROLE_PW=$(cat "/run/secrets/$file") psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v role="$role" -v db="$POSTGRES_DB" <<'SQL'
\getenv role_pw ROLE_PW
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role') AS missing \gset
\if :missing
CREATE ROLE :"role" LOGIN PASSWORD :'role_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
\endif
ALTER ROLE :"role" LOGIN PASSWORD :'role_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO :"role";
ALTER ROLE :"role" SET idle_in_transaction_session_timeout = '60s';
ALTER ROLE :"role" SET lock_timeout = '10s';
SQL
done
