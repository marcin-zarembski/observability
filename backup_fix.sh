#!/usr/bin/env bash
set -euo pipefail

# NFS repair / SSH tunnel helper for RHEL 8.10
# Server:
#   - Ensure AllowTcpForwarding yes, validate, restart sshd
#   - exportfs -ra, verify NFS (2049 + nfsd processes)
# Clients:
#   - rm -rf /16t_elkbackup/*   (DOMYŚLNIE ZAWSZE)
#   - restart autossh-nfs-tunnel
#   - mount -vvv -t nfs4 -o port=3335,proto=tcp localhost:/elkbackup /16t_elkbackup
#   - ls -lt /16t_elkbackup

SERVER=false
CLIENTS=false
DO_RM="yes"          # yes|no   (domyślnie czyść zawsze – zgodnie z pkt 1)
HOSTS_FILE=""
HOSTS_LIST=""
SSH_USER="${USER:-}"
SSH_KEY=""
DRY_RUN=false
VERBOSE=false

log()  { echo "[*] $*"; }
warn() { echo "[!] $*" >&2; }
die()  { echo "[x] $*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

maybe_run() {
  if $DRY_RUN; then
    echo "DRY-RUN: $*"
  else
    eval "$@"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --server) SERVER=true ;;
      --clients) CLIENTS=true ;;
      --rm) DO_RM="yes" ;;
      --no-rm) DO_RM="no" ;;
      --hosts-file) HOSTS_FILE="$2"; shift ;;
      --hosts-list) HOSTS_LIST="$2"; shift ;;
      --user) SSH_USER="$2"; shift ;;
      --ssh-key) SSH_KEY="$2"; shift ;;
      --dry-run) DRY_RUN=true ;;
      --verbose) VERBOSE=true ;;
      -h|--help)
        grep -E '^# ' "$0" | sed 's/^# //'; exit 0 ;;
      *) die "Unknown arg: $1" ;;
    esac
    shift
  done
}

ssh_base_opts=(
  -o StrictHostKeyChecking=accept-new
  -o ServerAliveInterval=30
  -o ServerAliveCountMax=3
  -o BatchMode=yes
)

ssh_cmd() {
  local host="$1"; shift
  local user_host="$host"
  [[ -n "$SSH_USER" ]] && user_host="$SSH_USER@$host"
  local args=("${ssh_base_opts[@]}")
  [[ -n "$SSH_KEY" ]] && args+=("-i" "$SSH_KEY")
  if $DRY_RUN; then
    echo "DRY-RUN: ssh ${args[*]} $user_host $*"
  else
    ssh "${args[@]}" "$user_host" "$@"
  fi
}

backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    local ts; ts="$(date +%Y%m%d-%H%M%S)"
    maybe_run "cp -a '$f' '${f}.bak-${ts}'"
  fi
}

ensure_allow_tcp_forwarding_yes() {
  local cfg="/etc/ssh/sshd_config"
  [[ -r "$cfg" ]] || die "Cannot read $cfg (need root?)"
  backup_file "$cfg"

  if grep -qiE '^\s*AllowTcpForwarding\b' "$cfg"; then
    maybe_run "sed -ri 's/^\s*#?\s*AllowTcpForwarding\s+.*/AllowTcpForwarding yes/i' '$cfg'"
  else
    maybe_run "printf '\\nAllowTcpForwarding yes\\n' >> '$cfg'"
  fi

  if $DRY_RUN; then
    log "Would validate sshd config with: sshd -t"
  else
    sshd -t || die "sshd configuration validation failed after editing $cfg."
  fi

  maybe_run "systemctl restart sshd"
  maybe_run "systemctl is-active --quiet sshd"
  log "sshd restarted and active."
}

server_refresh_nfs() {
  maybe_run "exportfs -ra" || warn "exportfs -ra failed or not installed"
  if command -v ss >/dev/null 2>&1; then
    maybe_run "ss -tulpn | grep -E '[:.]2049\\s' || true"
  else
    need_cmd netstat
    maybe_run "netstat -tulpn | grep 2049 || true"
  fi
  maybe_run "ps aux | grep -E 'nfsd|nfsdcld' | grep -v grep || true"
}

server_run_all() {
  ensure_allow_tcp_forwarding_yes
  server_refresh_nfs
}

clients_run_all() {
  local hosts=()
  if [[ -n "$HOSTS_FILE" ]]; then
    [[ -r "$HOSTS_FILE" ]] || die "Cannot read hosts file: $HOSTS_FILE"
    mapfile -t hosts < <(grep -vE '^\s*(#|$)' "$HOSTS_FILE")
  elif [[ -n "$HOSTS_LIST" ]]; then
    IFS=',' read -r -a hosts <<< "$HOSTS_LIST"
  else
    die "No clients provided. Use --hosts-file or --hosts-list."
  fi

  for h in "${hosts[@]}"; do
    log "=== CLIENT: $h ==="
    local user_host="$h"
    [[ -n "$SSH_USER" ]] && user_host="$SSH_USER@$h"
    local args=("${ssh_base_opts[@]}")
    [[ -n "$SSH_KEY" ]] && args+=("-i" "$SSH_KEY")

    if $DRY_RUN; then
      echo "DRY-RUN: ssh ${args[*]} $user_host 'bash -s' <<'EOF' ... EOF"
      continue
    fi

    DO_RM_VAL="$DO_RM" ssh "${args[@]}" "$user_host" 'bash' -s -- <<'EOF'
set -euo pipefail
log(){ echo "[*] CLIENT: $*"; }
warn(){ echo "[!] CLIENT: $*" >&2; }

DO_RM="${DO_RM_VAL:-yes}"

is_root() { [ "$(id -u)" -eq 0 ]; }
as_root() {
  if is_root; then
    "$@"
  else
    # bez interakcji: wymagane NOPASSWD w sudoers
    sudo -n "$@" || { echo "[x] Need root or passwordless sudo for: $*"; exit 101; }
  fi
}

client_rm_local(){
  if [[ "$DO_RM" == "no" ]]; then
    log "Skipping rm (--no-rm)."; return 0
  fi
  local mp="/16t_elkbackup"
  # Dodatkowe bezpieczniki: istnieje i nie jest '/'
  if [[ "$mp" == "/" || "$mp" == "" ]]; then
    echo "[x] Refusing to remove from '$mp'"; exit 102
  fi
  as_root bash -c 'shopt -s dotglob nullglob; rm -rf --one-file-system /16t_elkbackup/*'
  log "Cleaned $mp/*"
}

client_restart_tunnel(){
  as_root systemctl restart autossh-nfs-tunnel || true
  if ! as_root systemctl is-active --quiet autossh-nfs-tunnel; then
    warn "autossh-nfs-tunnel not active; showing status:"
    as_root systemctl status --no-pager autossh-nfs-tunnel || true
  fi
}

client_mount_nfs(){
  local mp="/16t_elkbackup"
  local src="localhost:/elkbackup"
  local opts="port=3335,proto=tcp"
  as_root mkdir -p "$mp"

  # jeśli już NFS z właściwego źródła — pomijamy mount
  local cur_src
  cur_src="$(findmnt -n -o SOURCE,FSTYPE --target "$mp" 2>/dev/null | awk '{print $1" "$2}' || true)"
  if [[ "$cur_src" == "$src nfs" || "$cur_src" == "$src nfs4" ]]; then
    log "$mp already mounted from $src"
  else
    log "Mounting $src -> $mp"
    as_root mount -vvv -t nfs4 -o "$opts" "$src" "$mp"
  fi

  ls -lt "$mp" || true
  if [[ -z "$(ls -A "$mp" 2>/dev/null || true)" ]]; then
    warn "$mp appears empty."
  else
    log "$mp has content."
  fi
}

client_rm_local
client_restart_tunnel
client_mount_nfs
EOF

  done
}

main() {
  parse_args "$@"

  need_cmd sed
  need_cmd grep
  need_cmd awk
  need_cmd findmnt

  if ! $SERVER && ! $CLIENTS; then
    die "Select scope: --server and/or --clients (see -h)."
  fi

  if $SERVER; then
    log "=== SERVER tasks ==="
    server_run_all
  fi

  if $CLIENTS; then
    log "=== CLIENT tasks ==="
    clients_run_all
  fi

  log "Done."
}

main "$@"
