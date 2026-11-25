#!/usr/bin/env bash
# Post-deployment hardening check of the RUNNING containers (CIS Docker 5.x style).
# Reads real runtime state from `docker inspect` and /proc; changes nothing.
# Run from the deploy folder:  sudo ./verify-deployment.sh
# Exit code: 0 = all checks passed, 1 = at least one FAIL. WARN lines need review.
set -uo pipefail
cd "$(dirname "$0")" || exit 1
PROJECT="${COMPOSE_PROJECT_NAME:-mini-siem}"
fails=0
pass() { printf 'PASS  %-10s %s\n' "$1" "$2"; }
fail() { printf 'FAIL  %-10s %s\n' "$1" "$2"; fails=$((fails + 1)); }
warn() { printf 'WARN  %-10s %s\n' "$1" "$2"; }

mapfile -t ids < <(docker ps -q --filter "label=com.docker.compose.project=${PROJECT}")
[[ ${#ids[@]} -gt 0 ]] || { echo "No running containers for project ${PROJECT}"; exit 1; }

for id in "${ids[@]}"; do
  svc=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$id")
  user=$(docker inspect -f '{{.Config.User}}' "$id")
  [[ -n "$user" && "${user%%:*}" != "0" && "${user%%:*}" != "root" ]] && pass "$svc" "non-root user ($user)" || fail "$svc" "runs as root or user unset ('$user')"
  [[ $(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$id") == true ]] && pass "$svc" "read-only root filesystem" || fail "$svc" "writable root filesystem"
  [[ $(docker inspect -f '{{.HostConfig.Privileged}}' "$id") == false ]] && pass "$svc" "not privileged" || fail "$svc" "privileged container"
  capdrop=$(docker inspect -f '{{join .HostConfig.CapDrop ","}}' "$id"); capadd=$(docker inspect -f '{{join .HostConfig.CapAdd ","}}' "$id")
  [[ "$capdrop" == *ALL* && -z "$capadd" ]] && pass "$svc" "all capabilities dropped" || fail "$svc" "capabilities: drop=[$capdrop] add=[$capadd]"
  pid=$(docker inspect -f '{{.State.Pid}}' "$id")
  capeff=$(awk '/^CapEff/{print $2}' "/proc/$pid/status" 2>/dev/null)
  [[ "$capeff" == "0000000000000000" ]] && pass "$svc" "effective capabilities empty (kernel)" || fail "$svc" "CapEff=$capeff"
  nnp=$(awk '/^NoNewPrivs/{print $2}' "/proc/$pid/status" 2>/dev/null)
  [[ "$nnp" == 1 ]] && pass "$svc" "no_new_privs set (kernel)" || fail "$svc" "NoNewPrivs=$nnp"
  seccomp=$(awk '/^Seccomp:/{print $2}' "/proc/$pid/status" 2>/dev/null)
  if [[ "$seccomp" == 2 ]]; then pass "$svc" "seccomp filter active (kernel mode 2)"
  else fail "$svc" "seccomp NOT active (mode ${seccomp:-?}); host kernel/daemon lacks seccomp"; fi
  aa=$(docker inspect -f '{{.AppArmorProfile}}' "$id")
  if [[ -n "$aa" && "$aa" != unconfined ]]; then pass "$svc" "AppArmor profile $aa"
  else fail "$svc" "AppArmor not applied ('${aa:-none}'); enable AppArmor on the host"; fi
  mem=$(docker inspect -f '{{.HostConfig.Memory}}' "$id"); pids=$(docker inspect -f '{{.HostConfig.PidsLimit}}' "$id")
  [[ "$mem" -gt 0 && "${pids:-0}" -gt 0 ]] && pass "$svc" "memory=$((mem / 1048576))MiB pids=$pids" || fail "$svc" "missing memory/pids limit"
  ports=$(docker inspect -f '{{range $p, $b := .NetworkSettings.Ports}}{{range $b}}{{.HostIp}}:{{.HostPort}}->{{$p}} {{end}}{{end}}' "$id")
  if [[ -n "$ports" ]]; then
    case "$svc" in
      caddy|collector) [[ "$ports" == *0.0.0.0:* || "$ports" == *"[::]"* ]] && fail "$svc" "published on all interfaces: $ports" || pass "$svc" "published only on $ports" ;;
      *) fail "$svc" "unexpected published port $ports" ;;
    esac
  fi
  secrets=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/run/secrets"}}{{.Source}}{{end}}{{end}}' "$id")
  [[ -z "$secrets" ]] || warn "$svc" "whole secrets directory mounted ($secrets)"
done

# N12: only the login service may create sessions; each service holds only its own secrets.
secret_mounts() {  # names of the Docker secrets mounted into a service container (running, or a finished one-shot)
  local cid; cid=$(docker ps -aq --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=$1" | head -1)
  [[ -n "$cid" ]] || return 1
  docker inspect -f '{{range .Mounts}}{{.Destination}}{{"\n"}}{{end}}' "$cid" | sed -n 's#^/run/secrets/##p' | sort
}
check_secrets() {  # service, required secrets, forbidden secrets
  local svc=$1 have; have=$(secret_mounts "$svc") || { fail "$svc" "service not running"; return; }
  for s in $2; do grep -qx "$s" <<<"$have" && pass "$svc" "has secret $s" || fail "$svc" "missing secret $s"; done
  for s in $3; do grep -qx "$s" <<<"$have" && fail "$svc" "must not hold secret $s" || pass "$svc" "does not hold $s"; done
}
CH_SECRETS="ch_admin_password ch_reader_password ch_ingest_password ch_connector_password"
check_secrets app  "db_app_password ch_reader_password" "db_auth_password oidc_client_secret session_secret ch_admin_password ch_ingest_password ch_connector_password"
check_secrets clickhouse "" "$CH_SECRETS db_owner_password"          # users.xml holds hashes only
check_secrets ch_migrate "ch_admin_password" "ch_reader_password ch_ingest_password ch_connector_password db_owner_password"
check_secrets auth "db_auth_password oidc_client_secret session_secret" "db_app_password"
authcmd=$(docker inspect -f '{{join .Config.Cmd " "}}' "$(docker ps -q --filter "label=com.docker.compose.project=${PROJECT}" --filter label=com.docker.compose.service=auth | head -1)" 2>/dev/null)
[[ "$authcmd" == *siem.auth_main:create_app* ]] && pass "auth" "runs the login service (siem.auth_main)" || fail "auth" "unexpected command: ${authcmd:-none}"

# ClickHouse: HTTPS 8443 must be its ONLY listening TCP port (no 8123 HTTP, no 9000 native).
chid=$(docker ps -q --filter "label=com.docker.compose.project=${PROJECT}" --filter label=com.docker.compose.service=clickhouse | head -1)
if [[ -n "$chid" ]]; then
  chpid=$(docker inspect -f '{{.State.Pid}}' "$chid")
  # (127.0.0.11 = Docker's embedded DNS resolver inside the network namespace, not ClickHouse.)
  listen=$(for h in $(awk 'FNR>1 && $4=="0A" && $2 !~ /^0B00007F:/ {n=split($2,a,":"); print a[n]}' "/proc/$chpid/net/tcp" "/proc/$chpid/net/tcp6" 2>/dev/null); do
             echo $((16#$h)); done | sort -un | tr '\n' ' ')
  [[ "$listen" == "8443 " ]] && pass "clickhouse" "only listener is HTTPS 8443" || fail "clickhouse" "listening TCP ports: ${listen:-none}"
else
  fail "clickhouse" "service not running"
fi

# One-shot services have exited, so the kernel checks above cannot see them; check their
# container configuration instead (same hardening anchor as the long-running services).
for svc in migrate ch_migrate; do
  id=$(docker ps -aq --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=$svc" | head -1)
  [[ -n "$id" ]] || { fail "$svc" "one-shot container not found"; continue; }
  conf=$(docker inspect -f '{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.Privileged}}|{{join .HostConfig.CapDrop ","}}|{{join .HostConfig.CapAdd ","}}|{{join .HostConfig.SecurityOpt ","}}|{{.HostConfig.Memory}}|{{.State.ExitCode}}' "$id")
  IFS='|' read -r u ro priv drop add sec mem code <<<"$conf"
  [[ -n "$u" && "${u%%:*}" != 0 && "${u%%:*}" != root && "$ro" == true && "$priv" == false && "$drop" == *ALL* && -z "$add" && "$sec" == *no-new-privileges:true* && "$mem" -gt 0 ]] \
    && pass "$svc" "one-shot ($u): read-only, caps dropped, no-new-privileges, memory limit (config)" \
    || fail "$svc" "one-shot hardening config: $conf"
  [[ "$code" == 0 ]] && pass "$svc" "completed successfully" || fail "$svc" "exit code $code"
done

# Internal TLS server certificates (setup CA): FAIL when they expire within 30 days.
# Renew: delete the server.* files, re-run setup.sh, restart the service (DEPLOYMENT_GUIDE.md).
for cert in postgres/tls/server.crt clickhouse/tls/server.crt; do
  if [[ ! -r "$cert" ]]; then fail "tls" "$cert missing or unreadable"; continue; fi
  end=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2)
  if openssl x509 -in "$cert" -noout -checkend $((30 * 86400)) >/dev/null 2>&1; then
    pass "tls" "$cert valid for 30+ days (until $end)"
  else
    fail "tls" "$cert expires within 30 days or has expired ($end); renew it"
  fi
done

for net in backend collect_db; do
  internal=$(docker network inspect -f '{{.Internal}}' "${PROJECT}_${net}" 2>/dev/null)
  [[ "$internal" == true ]] && pass "network" "${net} is internal (no route out)" || fail "network" "${net} internal=${internal:-missing}"
done
echo
echo "${fails} failure(s)"
[[ $fails -eq 0 ]]
