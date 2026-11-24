#!/bin/sh
set -eu
# The initdb superuser is local-only; application migrations use a non-superuser.
ROLE_PW=$(cat /run/secrets/db_owner_password) psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v role="$SIEM_DB_OWNER_USER" -v db="$POSTGRES_DB" <<'SQL'
\getenv role_pw ROLE_PW
CREATE ROLE :"role" LOGIN PASSWORD :'role_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER DATABASE :"db" OWNER TO :"role";
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
SQL
for entry in "${SIEM_DB_APP_USER}:db_app_password" "${SIEM_DB_WORKER_USER}:db_worker_password" "${SIEM_DB_EMERGENCY_USER}:db_emergency_password" "${SIEM_DB_INGEST_USER}:db_ingest_password"; do
  role=${entry%%:*}; file=${entry#*:}
  # psql reads the password from the environment, not the command line.
  ROLE_PW=$(cat "/run/secrets/$file") psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v role="$role" -v db="$POSTGRES_DB" <<'SQL'
\getenv role_pw ROLE_PW
CREATE ROLE :"role" LOGIN PASSWORD :'role_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO :"role";
ALTER ROLE :"role" SET idle_in_transaction_session_timeout = '60s';
ALTER ROLE :"role" SET lock_timeout = '10s';
SQL
done
