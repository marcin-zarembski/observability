#!/usr/bin/env bash
set -euo pipefail

# NFS repair / SSH tunnel helper for RHEL 8.10
# - Server side:
#   * Ensure AllowTcpForwarding yes in /etc/ssh/sshd_config (backup + validate)
#   * exportfs -ra
#   * systemctl restart sshd
#   * verify NFS is listening on 2049 and nfsd processes exist
# - Client side (over SSH):
#   * (optional) rm -rf /16t_elkbackup/*  (only if actually mounted as nfs*)
#   * systemctl restart autossh-nfs-tunnel
#   * mount -vvv -t nfs4 -o port=3335,proto=tcp localhost:/elkbackup /16t_elkbackup
#   * ls -lt /16t_elkbackup
#
# Usage examples:
#   sudo ./backupFix.sh --server
#   ./backupFix.sh --clients --hosts-file ./es_nodes.txt
#   sudo ./backupFix.sh --server --clients --hosts-list "es1,es2,es3"
#
# Flags:
#   --rm            : attempt to rm -rf /16t_elkbackup/* on clients if mounted as nfs*
#   --no-rm         : skip removal even if mounted (default: auto = only if mounted)
#   --hosts-file    : path to file with hosts (one per line; comments allowed)
#   --hosts-list    : comma-separated list of hosts
#   --user <name>   : SSH user for clients (default: current user)
#   --ssh-key <p>   : SSH key path (default: ssh-agent/default)
#   --dry-run       : print actions only
#   --verbose       : extra logs

SERVER=false
CLIENTS=false
DO_RM="auto"   # auto|yes|no
HOSTS_FILE=""
HOSTS_LIST=""
SSH_USER="${USER:-}"
SSH_KEY=""
DRY_RUN=false
VERBOSE=false

log() { echo "[*] $*"; }
warn() { echo "[!] $*" >&2; }
die() { echo "[x] $*" >&2; exit 1; }

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

# For single short commands (no heredoc)
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
    local ts
    ts="$(date +%Y%m%d-%H%M%S)"
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
    if ! sshd -t; then
      die "sshd configuration validation failed after editing $cfg."
    fi
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
      echo "DRY-RUN: ssh ${args[*]} $user_host 'bash -s' < <remote-script>"
      continue
    fi

    DO_RM_VAL="$DO_RM" ssh "${args[@]}" "$user_host" 'bash' -s -- <<'EOF'
set -euo pipefail
log(){ echo "[*] CLIENT: $*"; }
warn(){ echo "[!] CLIENT: $*" >&2; }

DO_RM="${DO_RM_VAL:-auto}"

client_rm_if_mounted(){
  local mp="/16t_elkbackup"
  local mtype
  mtype="$(findmnt -n -o FSTYPE --target "$mp" 2>/dev/null || true)"
  if [[ "$DO_RM" == "no" ]]; then
    log "Skipping rm on $mp (--no-rm)."; return 0
  fi
  if [[ -z "$mtype" ]]; then
    if [[ "$DO_RM" == "yes" ]]; then
      warn "$mp is not mounted; --rm requested but skipping for safety."
    else
      log "$mp is not mounted; skip rm."
    fi
    return 0
  fi
  if [[ "$mtype" =~ ^nfs ]]; then
    log "Cleaning $mp/* (mounted as $mtype)."
    rm -rf --one-file-system ${mp}/* || true
  else
    warn "$mp is mounted as $mtype, not nfs*. Skipping rm."
  fi
}

client_restart_tunnel(){
  systemctl restart autossh-nfs-tunnel || true
  systemctl is-active --quiet autossh-nfs-tunnel || systemctl status --no-pager autossh-nfs-tunnel || true
}

client_mount_nfs(){
  local mp="/16t_elkbackup"
  local src="localhost:/elkbackup"
  local opts="port=3335,proto=tcp"
  mkdir -p "$mp"
  local cur_src
  cur_src="$(findmnt -n -o SOURCE --target "$mp" 2>/dev/null || true)"
  if [[ "$cur_src" == "$src" ]]; then
    log "$mp already mounted from $src"
  else
    log "Mounting $src -> $mp"
    mount -vvv -t nfs4 -o "$opts" "$src" "$mp"
  fi

  ls -lt "$mp" || true
  if [[ -z "$(ls -A "$mp" 2>/dev/null || true)" ]]; then
    warn "$mp appears empty."
  else
    log "$mp has content."
  fi
}

client_rm_if_mounted
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
