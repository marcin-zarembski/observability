#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------
# Elasticsearch OS Optimizer (VM/XFS, RHEL8) — multi-host
# ------------------------------------------------------------

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=10)
SSH_USER=""
HOSTS=()

print_help() {
  cat <<EOF
Usage:
  $0 [--ssh-user <user>] [--hosts-file <file> | --hosts-list <h1> <h2> ...]

Options:
  --ssh-user       SSH username to use for all hosts (optional; defaults to current user)
  --hosts-file     File with hosts (one per line, comments starting with # allowed)
  --hosts-list     Hosts passed directly as arguments
  --help           Show this help and exit
EOF
}

# -------------------------
# Arg parsing
# -------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-user) SSH_USER="$2"; shift 2;;
    --hosts-file)
      [[ -f "$2" ]] || { echo "Error: hosts file '$2' not found" >&2; exit 1; }
      while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        HOSTS+=("$line")
      done < "$2"
      shift 2;;
    --hosts-list)
      shift
      while [[ $# -gt 0 && ! "$1" =~ ^-- ]]; do HOSTS+=("$1"); shift; done;;
    --help|-h) print_help; exit 0;;
    *) echo "Unknown argument: $1" >&2; print_help; exit 1;;
  esac
done

if ((${#HOSTS[@]}==0)); then
  echo "Error: no hosts provided. Use --hosts-file or --hosts-list." >&2
  exit 1
fi

# -------------------------
# Remote payload
# -------------------------
REMOTE_SCRIPT=$(cat <<'REMOTE_PAYLOAD'
set -euo pipefail

log() { echo -e "$1"; }

get_es_identity() {
  local user group mainpid
  user=$(systemctl show elasticsearch -p User --value 2>/dev/null || true)
  group=$(systemctl show elasticsearch -p Group --value 2>/dev/null || true)
  mainpid=$(systemctl show elasticsearch -p MainPID --value 2>/dev/null || true)
  if [[ -z "${user}" || "${user}" == "-" ]]; then
    user=$(ps -eo user:32,comm,pid | awk '/java/ && /org\.elasticsearch\.bootstrap\.Elasticsearch/ {print $1; exit}') || true
  fi
  if [[ -z "${group}" || "${group}" == "-" ]]; then
    [[ -n "${user:-}" ]] && group=$(id -gn "$user" 2>/dev/null || true)
  fi
  echo "$user|$group|$mainpid"
}

check_and_disable_swap() {
  log "[1] Checking swap status..."
  if swapon --show | grep -q "."; then
    log "  Swap is ENABLED. Disabling now..."
    sudo swapoff -a
    if grep -Eq '^[[:space:]]*[^#].*[[:space:]]swap[[:space:]]' /etc/fstab; then
      TS=$(date +%Y%m%d-%H%M%S)
      sudo cp -a /etc/fstab /etc/fstab.backup-$TS
      sudo awk 'BEGIN{OFS="	"} /^[[:space:]]*#/ {print; next} NF>=3 && $3=="swap" {print "#" $0; next} {print}' /etc/fstab | sudo tee /etc/fstab.tmp >/dev/null
      sudo mv /etc/fstab.tmp /etc/fstab
    fi
    log "  Swap disabled."
  else
    log "  Swap is already disabled."
  fi
}

check_and_set_vm_max_map_count() {
  log "[2] Checking vm.max_map_count..."
  current=$(sysctl -n vm.max_map_count)
  target=262144
  if [[ "$current" -lt "$target" ]]; then
    CONF_FILE="/etc/sysctl.d/99-elasticsearch.conf"
    if [[ -f "$CONF_FILE" ]] && grep -q "^vm.max_map_count" "$CONF_FILE"; then
      sudo sed -i "s/^vm.max_map_count.*/vm.max_map_count = $target/" "$CONF_FILE"
    else
      echo "vm.max_map_count = $target" | sudo tee -a "$CONF_FILE" >/dev/null
    fi
    sudo sysctl -w vm.max_map_count=$target >/dev/null
  fi
  newval=$(sysctl -n vm.max_map_count)
  log "  vm.max_map_count = $newval"
}

ensure_systemd_es_limits() {
  log "[3] Ensuring systemd limits and restart policy..."
  DROPIN_DIR="/etc/systemd/system/elasticsearch.service.d"
  UNIT_FILE="$DROPIN_DIR/elasticsearch.conf"
  TS=$(date +%Y%m%d-%H%M%S)
  KEYS="LimitNOFILE=1048576;LimitNPROC=64000;LimitMEMLOCK=infinity;TasksMax=infinity;Restart=on-failure;RestartSec=5s;TimeoutStopSec=5min;KillSignal=SIGTERM;OOMPolicy=continue"

  sudo mkdir -p "$DROPIN_DIR"
  [[ -f "$UNIT_FILE" ]] || echo -e "[Unit]\n[Service]" | sudo tee "$UNIT_FILE" >/dev/null
  sudo cp -a "$UNIT_FILE" "${UNIT_FILE}.backup-$TS"

  sudo awk -v keys="$KEYS" '
    BEGIN { n=split(keys,arr,";"); for(i=1;i<=n;i++){ split(arr[i],kv,"="); desired[kv[1]]=kv[2]; seen[kv[1]]=0 } in_service=0; }
    function print_missing(){ for(k in desired) if(!seen[k]) print k "=" desired[k] }
    {
      if ($0 ~ /^[[:space:]]*\[/) {
        if (in_service) { print_missing(); in_service=0 }
        print $0
        if (tolower($0) ~ /^\[service\]/) { in_service=1; for(k in desired) seen[k]=0 }
        next
      }
      if (in_service) {
        matched=0
        for(k in desired) {
          pat="^[[:space:]]*" k "[[:space:]]*="
          if ($0 ~ pat) { print k "=" desired[k]; seen[k]=1; matched=1; break }
        }
        if (!matched) print $0
      } else print $0
    }
    END { if (in_service) print_missing(); }
  ' "$UNIT_FILE" | sudo tee "$UNIT_FILE.tmp" >/dev/null && sudo mv "$UNIT_FILE.tmp" "$UNIT_FILE"
}

ensure_jvm_heap_settings() {
  log "[4] Ensuring JVM heap size..."
  local FILE="/etc/elasticsearch/jvm.options"
  local TS=$(date +%Y%m%d-%H%M%S)
  local XMS="-Xms28g"
  local XMX="-Xmx28g"
  if sudo test -f "$FILE"; then
    sudo cp -a "$FILE" "${FILE}.backup-$TS"
    sudo awk -v xms="$XMS" -v xmx="$XMX" '
      BEGIN{found_xms=0;found_xmx=0}
      /^[[:space:]]*-/ {
        if ($0 ~ /^-Xms/) { if (!found_xms){print xms;found_xms=1}; next }
        if ($0 ~ /^-Xmx/) { if (!found_xmx){print xmx;found_xmx=1}; next }
      }
      {print}
      END { if(!found_xms) print xms; if(!found_xmx) print xmx }
    ' "$FILE" | sudo tee "$FILE.tmp" >/dev/null && sudo mv "$FILE.tmp" "$FILE"
  fi
}

ensure_thp_disabled() {
  log "[5] Checking Transparent Huge Pages (THP)..."
  local enabled="/sys/kernel/mm/transparent_hugepage/enabled"
  local defrag="/sys/kernel/mm/transparent_hugepage/defrag"
  if [[ ! -f "$enabled" ]]; then
    log "  WARNING: THP control file not found."
    return
  fi
  local cur_enabled=$(cat "$enabled")
  local cur_defrag=""; [[ -f "$defrag" ]] && cur_defrag=$(cat "$defrag")
  if echo "$cur_enabled" | grep -q '\[never\]'; then
    log "  THP already disabled."
  else
    echo never | sudo tee "$enabled" >/dev/null || true
    [[ -f "$defrag" ]] && echo never | sudo tee "$defrag" >/dev/null || true
    local SERVICE_FILE="/etc/systemd/system/disable-thp.service"
    if [[ ! -f "$SERVICE_FILE" ]]; then
      sudo tee "$SERVICE_FILE" >/dev/null <<'EOF'
[Unit]
Description=Disable Transparent Huge Pages
[Service]
Type=oneshot
ExecStart=/usr/bin/bash -c 'echo never > /sys/kernel/mm/transparent_hugepage/enabled'
ExecStart=/usr/bin/bash -c '[ -f /sys/kernel/mm/transparent_hugepage/defrag ] && echo never > /sys/kernel/mm/transparent_hugepage/defrag || true'
[Install]
WantedBy=multi-user.target
EOF
      sudo systemctl enable disable-thp.service >/dev/null
    fi
  fi
}

ensure_memory_lock_enabled() {
  log "[6] Ensuring bootstrap.memory_lock..."
  local FILE="/etc/elasticsearch/elasticsearch.yml"
  local TS=$(date +%Y%m%d-%H%M%S)
  if sudo test -f "$FILE"; then
    sudo cp -a "$FILE" "${FILE}.backup-$TS"
    if sudo grep -q '^bootstrap.memory_lock:' "$FILE"; then
      sudo sed -i 's/^bootstrap.memory_lock:.*/bootstrap.memory_lock: true/' "$FILE"
    else
      echo "bootstrap.memory_lock: true" | sudo tee -a "$FILE" >/dev/null
    fi
  fi
}

ensure_network_sysctl() {
  log "[7] Ensuring network sysctl..."
  local CONF_FILE="/etc/sysctl.d/99-elasticsearch.conf"
  local -a KV=("net.core.somaxconn=4096" "net.core.netdev_max_backlog=16384" "net.ipv4.tcp_max_syn_backlog=8192" "net.ipv4.tcp_fin_timeout=30" "net.ipv4.tcp_tw_reuse=1" "net.ipv4.ip_local_port_range=1024 65000")
  for entry in "${KV[@]}"; do
    key="${entry%%=*}"; val="${entry#*=}"
    if grep -q "^${key}[[:space:]]*=" "$CONF_FILE" 2>/dev/null; then
      sudo sed -i "s|^${key}[[:space:]]*=.*|${key} = ${val}|" "$CONF_FILE"
    else
      echo "${key} = ${val}" | sudo tee -a "$CONF_FILE" >/dev/null
    fi
    sudo sysctl -w "${key}=${val}" >/dev/null || true
  done
  for entry in "${KV[@]}"; do
    key="${entry%%=*}"; want="${entry#*=}"
    have=$(sysctl -n "$key" 2>/dev/null || echo "")
    have_norm=$(echo "$have" | awk '{$1=$1;print}')
    want_norm=$(echo "$want" | awk '{$1=$1;print}')
    if [[ "$have_norm" == "$want_norm" ]]; then
      log "  OK: $key = $have_norm"
    else
      log "  WARN: $key is '$have' (wanted '$want')"
    fi
  done
}

final_restart_and_validate() {
  log "[8] Restarting Elasticsearch..."
  sudo systemctl daemon-reload
  sudo systemctl restart elasticsearch
  for i in {1..60}; do systemctl is-active --quiet elasticsearch && break; sleep 1; done
  if ! systemctl is-active --quiet elasticsearch; then
    echo "  ERROR: Elasticsearch did not become active"; exit 1
  fi
  systemctl show elasticsearch -p LimitNOFILE -p LimitNPROC -p TasksMax -p OOMPolicy -p Restart -p RestartUSec -p TimeoutStopUSec -p KillSignal || true
  IFS='|' read -r ES_USER ES_GROUP MAINPID < <(get_es_identity)
  ES_REAL_PID=$(pgrep -f 'org.elasticsearch.server.Elasticsearch' | head -n1 || true)
  [[ -z "$ES_REAL_PID" && -n "$MAINPID" ]] && ES_REAL_PID="$MAINPID"
  if [[ -n "$ES_REAL_PID" && -e "/proc/$ES_REAL_PID/limits" ]]; then
    log "  Runtime /proc limits for PID $ES_REAL_PID:"
    egrep 'Max open files|Max processes|Max locked memory' "/proc/$ES_REAL_PID/limits" || true
    log "  JVM heap flags:"
    tr '\0' ' ' < "/proc/$ES_REAL_PID/cmdline" | egrep -- "-Xms|-Xmx" || true
  fi
}

check_and_disable_swap
check_and_set_vm_max_map_count
ensure_systemd_es_limits
ensure_jvm_heap_settings
ensure_thp_disabled
ensure_memory_lock_enabled
ensure_network_sysctl
final_restart_and_validate
REMOTE_PAYLOAD
)

# -------------------------
# Run on each host
# -------------------------
for H in "${HOSTS[@]}"; do
  echo -e "\n============================\n>>> $H\n============================"
  if [[ -n "$SSH_USER" ]]; then
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$H" "bash -s" <<< "$REMOTE_SCRIPT" || echo "[ERROR] Host $H failed" >&2
  else
    ssh "${SSH_OPTS[@]}" "$H" "bash -s" <<< "$REMOTE_SCRIPT" || echo "[ERROR] Host $H failed" >&2
  fi
done

echo -e "\nAll done."
