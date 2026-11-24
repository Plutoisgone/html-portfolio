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

for net in backend collect_db; do
  internal=$(docker network inspect -f '{{.Internal}}' "${PROJECT}_${net}" 2>/dev/null)
  [[ "$internal" == true ]] && pass "network" "${net} is internal (no route out)" || fail "network" "${net} internal=${internal:-missing}"
done
echo
echo "${fails} failure(s)"
[[ $fails -eq 0 ]]
