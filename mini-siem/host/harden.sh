#!/usr/bin/env bash
# Mini-SIEM host hardening for Ubuntu Server 24.04 LTS.
# Based on CIS Ubuntu Linux Level 1 controls that matter for a single-purpose server.
# Safe to re-run. Run as root:  sudo ./harden.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CONF="${HERE}/host.conf"

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33mWARN: %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root (sudo)."
[[ -f "$CONF" ]] || die "Missing ${CONF}. Copy host.conf.example to host.conf and fill it in."
[[ ! -L "$CONF" && $(stat -c %u "$CONF") == 0 ]] || die "host.conf must be root-owned and not a symlink."
mode=$(stat -c %a "$CONF")
(( (8#$mode & 022) == 0 )) || die "host.conf must not be group/world writable."
# host.conf is a trusted root-owned shell configuration, not an untrusted input.
# shellcheck source=/dev/null
source "$CONF"

for v in ADMIN_USER MGMT_NETS SYSLOG_SOURCES AGENT_SOURCES DNS_SERVERS SSH_PORT SYSLOG_UDP; do
  val="${!v:-}"
  [[ -n "$val" && "$val" != *CHANGE_ME* ]] || die "Set ${v} in host.conf."
done
[[ "$ADMIN_USER" =~ ^[a-z_][a-z0-9_-]*$ && "$SSH_PORT" =~ ^[0-9]{1,5}$ ]] || die "Invalid SSH configuration."
(( 10#$SSH_PORT >= 1 && 10#$SSH_PORT <= 65535 )) || die "Invalid SSH port."
python3 - "$MGMT_NETS" "$SYSLOG_SOURCES" "$AGENT_SOURCES" "$DNS_SERVERS" <<'VALIDATE'
import ipaddress, sys
for group in sys.argv[1:4]:
    for item in group.split(): ipaddress.IPv4Network(item, strict=False)
for item in sys.argv[4].split(): ipaddress.IPv4Address(item)
VALIDATE

. /etc/os-release
[[ "${ID}" == "ubuntu" && "${VERSION_ID}" == "24.04" ]] || warn "Tested on Ubuntu 24.04 only (found ${PRETTY_NAME})."

# ---------------------------------------------------------------- safety check
# Refuse to disable password SSH unless the admin user already has a key.
AUTH_KEYS="$(getent passwd "$ADMIN_USER" | cut -d: -f6)/.ssh/authorized_keys"
id "$ADMIN_USER" >/dev/null 2>&1 || die "User ${ADMIN_USER} does not exist."
[[ -s "$AUTH_KEYS" ]] || die "${AUTH_KEYS} is empty. Add your SSH public key first or you will be locked out."
id -nG "$ADMIN_USER" | grep -qw sudo || die "${ADMIN_USER} is not in the sudo group."

# ---------------------------------------------------------------- disk encryption
log "Checking disk encryption"
if lsblk -o TYPE | grep -q crypt; then
  echo "LUKS encryption detected."
else
  warn "No LUKS-encrypted volume found. Reinstall Ubuntu with 'Encrypt the LVM group' before production use."
fi

# ---------------------------------------------------------------- packages
log "Updating packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get -y -q full-upgrade
apt-get -y -q install nftables auditd audispd-plugins apparmor apparmor-utils \
  unattended-upgrades chrony ca-certificates curl gnupg aide libpam-pwquality

log "Removing unneeded network services"
apt-get -y -q purge telnet rsh-client talk ftp xinetd nis avahi-daemon cups 2>/dev/null || true
apt-get -y -q autoremove

# ---------------------------------------------------------------- auto updates
log "Enabling automatic security updates"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
cat > /etc/apt/apt.conf.d/52mini-siem-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
  "${distro_id}:${distro_codename}-security";
  "${distro_id}ESMApps:${distro_codename}-apps-security";
  "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:30";
EOF

# ---------------------------------------------------------------- kernel / sysctl
log "Applying kernel hardening (sysctl)"
cat > /etc/sysctl.d/60-mini-siem.conf <<'EOF'
# Network
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
# Docker needs forwarding between its bridges; nftables controls what is allowed.
net.ipv4.ip_forward = 1
# Kernel
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
EOF
sysctl --system >/dev/null

log "Disabling unused filesystems and USB storage"
cat > /etc/modprobe.d/mini-siem-blacklist.conf <<'EOF'
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install udf /bin/false
install usb-storage /bin/false
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
EOF

log "Disabling core dumps"
cat > /etc/security/limits.d/60-no-core.conf <<'EOF'
* hard core 0
EOF
mkdir -p /etc/systemd/coredump.conf.d
printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' > /etc/systemd/coredump.conf.d/60-disable.conf

log "Setting restrictive default umask"
sed -i 's/^UMASK.*/UMASK\t\t027/' /etc/login.defs

# ---------------------------------------------------------------- SSH
log "Hardening SSH"
SSHD_DROPIN=/etc/ssh/sshd_config.d/60-mini-siem.conf
cat > "$SSHD_DROPIN" <<EOF
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitEmptyPasswords no
AllowUsers ${ADMIN_USER}
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
Banner /etc/issue.net
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
EOF
echo "Authorized access only. All activity is logged and monitored." > /etc/issue.net
sshd -t || die "sshd config test failed; not reloading."
# Ubuntu 24.04 uses socket activation; daemon-reload regenerates the listen port.
systemctl daemon-reload
if systemctl is-active --quiet ssh.socket; then
  systemctl restart ssh.socket
fi
systemctl restart ssh

# ---------------------------------------------------------------- firewall
log "Configuring nftables firewall"
to_set() { local out=""; for x in $1; do out+="${x}, "; done; echo "${out%, }"; }
MGMT_SET="$(to_set "$MGMT_NETS")"
SYSLOG_SET="$(to_set "$SYSLOG_SOURCES")"
AGENT_SET="$(to_set "$AGENT_SOURCES")"
DNS_SET="$(to_set "$DNS_SERVERS")"

cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
# Mini-SIEM firewall. Generated by harden.sh - edit host.conf and re-run instead.
destroy table inet mini_siem
table inet mini_siem {
  set mgmt       { type ipv4_addr; flags interval; elements = { ${MGMT_SET} } }
  set syslog_src { type ipv4_addr; flags interval; elements = { ${SYSLOG_SET} } }
  set agent_src  { type ipv4_addr; flags interval; elements = { ${AGENT_SET} } }
  set dns        { type ipv4_addr; flags interval; elements = { ${DNS_SET} } }

  # Traffic to the host itself (SSH).
  chain input {
    type filter hook input priority filter; policy drop;
    ct state invalid drop
    ct state established,related accept
    iif lo accept
    ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 10/second accept
    ip6 nexthdr icmpv6 accept
    tcp dport ${SSH_PORT} ip saddr @mgmt ct state new limit rate 10/minute accept
    limit rate 5/minute log prefix "nft-input-drop: " flags all
  }

  # Traffic to published container ports (Docker DNATs these, so they pass FORWARD).
  # Runs before Docker's own rules; a drop here is final.
  chain forward_guard {
    type filter hook forward priority -10; policy accept;
    ct state invalid drop
    ct status dnat ct original proto-dst 443   ip saddr @mgmt       accept
    # Only explicitly allowlisted sources may reach the optional TLS collector.
    ct status dnat ct original proto-dst 6514 ip saddr @syslog_src tcp dport 6514 accept
    ct status dnat ct direction original limit rate 5/minute log prefix "nft-published-drop: " flags all
    ct status dnat ct direction original drop
    ct state established,related accept
    iifname != "br-*" oifname "br-*" drop
  }

  # Outbound from the host and containers: DNS, NTP and HTTP(S) only.
  # Phase 2 narrows HTTPS to an egress proxy with a domain allowlist.
  chain output {
    type filter hook output priority filter; policy drop;
    ct state established,related accept
    oif lo accept
    ip daddr @dns udp dport 53 accept
    ip daddr @dns tcp dport 53 accept
    udp dport 123 accept
    tcp dport { 80, 443 } accept
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept
    limit rate 5/minute log prefix "nft-output-drop: " flags all
  }

  chain forward_egress {
    type filter hook forward priority -5; policy accept;
    ct state established,related accept
    # Collector needs no outbound connections on its published network.
    iifname "br-siem-collect" ct state new drop
    # New connections leaving through the uplink from containers.
    iifname "br-*" oifname != "br-*" ct state new ip daddr @dns meta l4proto { tcp, udp } th dport 53 accept
    iifname "br-*" oifname != "br-*" ct state new tcp dport 443 accept
    # SMTP submission for email alerts.
    iifname "br-*" oifname != "br-*" ct state new tcp dport 587 accept
    iifname "br-*" oifname != "br-*" ct state new limit rate 5/minute log prefix "nft-egress-drop: " flags all
    iifname "br-*" oifname != "br-*" ct state new drop
  }
}
EOF
nft -c -f /etc/nftables.conf || die "nftables config check failed."
systemctl enable --now nftables
nft -f /etc/nftables.conf
# ufw would fight nftables; make sure it is off.
systemctl disable --now ufw 2>/dev/null || true

# ---------------------------------------------------------------- auditd
log "Configuring auditd"
cat > /etc/audit/rules.d/60-mini-siem.rules <<'EOF'
-D
-b 8192
-f 1
# Identity and privilege
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /var/log/sudo.log -p wa -k sudo_log
# SSH and firewall
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/nftables.conf -p wa -k firewall
# Docker and the SIEM itself
-w /usr/bin/dockerd -p x -k docker
-w /etc/docker/ -p wa -k docker
-w /opt/mini-siem/deploy/ -p wa -k siem_config
-w /opt/mini-siem/deploy/secrets/ -p rwa -k siem_secrets
-w /opt/mini-siem/data/audit-state/ -p wa -k siem_audit_anchor
# Privileged commands and time changes
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root_cmd
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
# Make rules immutable until reboot
-e 2
EOF
printf 'Defaults logfile="/var/log/sudo.log"\nDefaults use_pty\n' > /etc/sudoers.d/60-mini-siem
chmod 440 /etc/sudoers.d/60-mini-siem
visudo -cf /etc/sudoers.d/60-mini-siem >/dev/null
systemctl enable --now auditd
augenrules --load >/dev/null 2>&1 || warn "auditd rules are immutable until reboot; new rules load after reboot."

# ---------------------------------------------------------------- AppArmor / time
log "Ensuring AppArmor and time sync"
systemctl enable --now apparmor
aa-status --enabled && echo "AppArmor enabled."
systemctl enable --now chrony

# ---------------------------------------------------------------- Docker
log "Installing Docker Engine from Docker's official repository"
install -m 0755 -d /etc/apt/keyrings
# Docker's published release-signing key fingerprint (docs.docker.com/engine/install/ubuntu).
DOCKER_KEY_FPR="9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
if [[ ! -f /etc/apt/keyrings/docker.asc ]]; then
  curl -fsSL --proto '=https' --tlsv1.2 https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc.new
  got="$(gpg --show-keys --with-colons /etc/apt/keyrings/docker.asc.new 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')"
  [[ "$got" == "$DOCKER_KEY_FPR" ]] || { rm -f /etc/apt/keyrings/docker.asc.new; die "Docker signing key fingerprint mismatch (got '${got}')."; }
  mv /etc/apt/keyrings/docker.asc.new /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
fi
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update -q
apt-get -y -q install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

log "Hardening the Docker daemon"
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'EOF'
{
  "icc": false,
  "no-new-privileges": true,
  "live-restore": true,
  "userland-proxy": false,
  "log-driver": "json-file",
  "log-opts": { "max-size": "20m", "max-file": "5" },
  "default-ulimits": { "nofile": { "Name": "nofile", "Soft": 65536, "Hard": 65536 } }
}
EOF
systemctl restart docker
# The admin user is NOT added to the docker group: docker group = root. Use sudo.

# ---------------------------------------------------------------- file integrity
log "Initialising AIDE file-integrity database (takes a few minutes)"
if [[ ! -f /var/lib/aide/aide.db ]]; then
  aideinit -y -f >/dev/null 2>&1 || warn "AIDE init failed; run 'sudo aideinit' manually."
fi

log "Done. Reboot now to load all settings:  sudo reboot"
echo "Before closing this session, open a NEW SSH session from the management network to confirm you can still log in."
