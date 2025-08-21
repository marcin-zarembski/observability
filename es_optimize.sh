#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------
# Elasticsearch OS Optimizer (VM/XFS, RHEL8) — multi-host (sudo-safe)
# Steps implemented:
#   [1] Disable swap (runtime + persist)
#   [2] Ensure vm.max_map_count >= 262144 (runtime + persist)
#   [3] Ensure systemd limits/restart policy in drop-in
#   [4] Ensure JVM heap settings in /etc/elasticsearch/jvm.options
#   [5] Disable Transparent Huge Pages (THP)
#   [6] Ensure bootstrap.memory_lock: true in elasticsearch.yml
#   [7] Ensure network sysctl tuning (somaxconn, backlog, TCP params)
# Final step: ONE restart of elasticsearch at the end of all checks.
# Remote execution with: --hosts-file or --hosts-list (SSH)
# NOTE: This version fixes file existence checks in /etc/elasticsearch when the
#       SSH user lacks directory traverse perms (uses 'sudo test -f ...').
#       It also normalizes comparison of ip_local_port_range and reads JVM flags
#       from /proc/<pid>/cmdline to avoid the server-cli 4m/64m confusion.
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

Behavior:
  - Connects to each host via SSH and applies:
      [1] Swap off + fstab cleanup for swap entries
      [2] vm.max_map_count >= 262144 (sysctl runtime + /etc/sysctl.d/99-elasticsearch.conf)
      [3] Ensure drop-in /etc/systemd/system/elasticsearch.service.d/elasticsearch.conf has critical limits
      [4] Ensure JVM heap settings in /etc/elasticsearch/jvm.options (-Xms28g / -Xmx28g)
      [5] Disable Transparent Huge Pages (THP)
      [6] Ensure bootstrap.memory_lock: true in elasticsearch.yml
      [7] Ensure network sysctl tuning (somaxconn, backlog, TCP params)
  - Finally restarts elasticsearch ONCE and validates limits and heap.
  - Service user/group are discovered automatically on each host via systemd.
EOF
}

# -------------------------
# Arg parsing
# -------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-user)
      SSH_USER="$2"; shift 2;;
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
    --help|-h)
      print_help; exit 0;;
    *)
      echo "Unknown argument: $1" >&2; print_help; exit 1;;
  esac
done

if ((${#HOSTS[@]}==0)); then
  echo "Error: no hosts provided. Use --hosts-file or --hosts-list." >&2
  exit 1
fi

# -------------------------
# Remote payload (executed on target)
# -------------------------
REMOTE_SCRIPT=$(cat <<'REMOTE_PAYLOAD'
set -euo pipefail

log() { echo -e "$1"; }

sudo_test_file() {
  # sudo-based file existence check (works even if caller can't traverse dir)
  local path="$1"; sudo sh -c "test -f '$path'" 2>/dev/null
}

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
      log "  Found active swap entries in /etc/fstab. Commenting them out..."
      TS=$(date +%Y%m%d-%H%M%S)
      sudo cp -a /etc/fstab /etc/fstab.backup-$TS
      sudo awk 'BEGIN{OFS="\t"} /^[[:space:]]*#/ {print; next} NF>=3 && $3=="swap" {print "#" $0; next} {print}' /etc/fstab | sudo tee /etc/fstab.tmp >/dev/null
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
    log "  Current value ($current) is lower than required ($target). Updating..."
    CONF_FILE="/etc/sysctl.d/99-elasticsearch.conf"
    if sudo_test_file "$CONF_FILE" && sudo grep -q "^vm.max_map_count" "$CONF_FILE"; then
      sudo sed -i "s/^vm.max_map_count.*/vm.max_map_count = $target/" "$CONF_FILE"
    else
      echo "vm.max_map_count = $target" | sudo tee -a "$CONF_FILE" >/dev/null
    fi
    sudo sysctl -w vm.max_map_count=$target >/devnull 2>&1 || sudo sysctl -w vm.max_map_count=$target >/dev/null
  else
    log "  vm.max_map_count is already sufficient: $current"
  fi
  newval=$(sysctl -n vm.max_map_count)
  if [[ "$newval" -ge "$target" ]]; then
    log "  OK: vm.max_map_count = $newval"
  else
    echo "  ERROR: vm.max_map_count is $newval, expected >= $target" >&2
    exit 1
  fi
}

ensure_systemd_es_limits() {
  log "[3] Ensuring systemd limits and restart policy for Elasticsearch (no restart here)..."
  DROPIN_DIR="/etc/systemd/system/elasticsearch.service.d"
  UNIT_FILE="$DROPIN_DIR/elasticsearch.conf"
  TS=$(date +%Y%m%d-%H%M%S)
  KEYS="LimitNOFILE=1048576;LimitNPROC=64000;LimitMEMLOCK=infinity;TasksMax=infinity;Restart=on-failure;RestartSec=5s;TimeoutStopSec=900;KillSignal=SIGTERM;OOMPolicy=continue"

  sudo mkdir -p "$DROPIN_DIR"
  [[ -f "$UNIT_FILE" ]] || echo -e "[Unit]\n[Service]" | sudo tee "$UNIT_FILE" >/dev/null
  sudo cp -a "$UNIT_FILE" "${UNIT_FILE}.backup-$TS"

  sudo awk -v keys="$KEYS" '
    BEGIN {
      n = split(keys, arr, ";");
      for (i=1;i<=n;i++) { split(arr[i], kv, "="); desired[kv[1]] = kv[2]; seen[kv[1]] = 0; }
      in_service = 0; service_present = 0;
    }
    function print_missing(){ for (k in desired) { if (!seen[k]) { print k "=" desired[k] } } }
    {
      if ($0 ~ /^[[:space:]]*\[/) {
        if (in_service) { print_missing(); in_service=0; }
        line=$0; lower=line;
        for (i=1;i<=length(line);i++){c=substr(line,i,1); if (c>="A"&&c<="Z") lower=substr(lower,1,i-1) tolower(c) substr(lower,i+1)}
        if (lower ~ /^[[:space:]]*\[service\][[:space:]]*$/) { in_service=1; service_present=1; for (k in desired) seen[k]=0; }
        print $0; next;
      }
      if (in_service) {
        matched=0;
        for (k in desired) {
          pat = "^[[:space:]]*" k "[[:space:]]*="
          if ($0 ~ pat) { print k "=" desired[k]; seen[k]=1; matched=1; break; }
        }
        if (!matched) print $0;
      } else print $0;
    }
    END {
      if (in_service) { print_missing(); }
      if (!service_present) { print "[Service]"; for (k in desired) print k "=" desired[k]; }
    }
  ' "$UNIT_FILE" | sudo tee "$UNIT_FILE.tmp" >/dev/null && sudo mv "$UNIT_FILE.tmp" "$UNIT_FILE"

  log "  Drop-in updated. Daemon reload will happen in final step."
}

ensure_jvm_heap_settings() {
  log "[4] Ensuring JVM heap size in /etc/elasticsearch/jvm.options ..."
  local FILE="/etc/elasticsearch/jvm.options"
  local TS=$(date +%Y%m%d-%H%M%S)
  local XMS="-Xms28g"
  local XMX="-Xmx28g"

  if sudo_test_file "$FILE"; then
    sudo cp -a "$FILE" "${FILE}.backup-$TS"
    # Use sudo to read file as well, in case perms restrict
    sudo awk -v xms="$XMS" -v xmx="$XMX" '
      BEGIN{found_xms=0; found_xmx=0}
      /^[[:space:]]*-/ {
        if ($0 ~ /^-Xms/) { if (!found_xms) {print xms; found_xms=1}; next}
        if ($0 ~ /^-Xmx/) { if (!found_xmx) {print xmx; found_xmx=1}; next}
      }
      {print}
      END {
        if (!found_xms) print xms;
        if (!found_xmx) print xmx;
      }
    ' "$FILE" | sudo tee "$FILE.tmp" >/dev/null && sudo mv "$FILE.tmp" "$FILE"
    log "  Updated heap settings to $XMS / $XMX"
  else
    log "  ERROR: $FILE not found (or not accessible)"
  fi
}

ensure_thp_disabled() {
  log "[5] Checking Transparent Huge Pages (THP)..."
  thp_file="/sys/kernel/mm/transparent_hugepage/enabled"
  if [[ -f "$thp_file" ]]; then
    current=$(cat "$thp_file")
    log "  Current THP setting: $current"
    if ! echo "$current" | grep -q '\\[never\\]'; then
      log "  Disabling THP..."
      echo never | sudo tee "$thp_file" >/dev/null || true
      SERVICE_FILE="/etc/systemd/system/disable-thp.service"
      if [[ ! -f "$SERVICE_FILE" ]]; then
        sudo tee "$SERVICE_FILE" >/dev/null <<EOF2
[Unit]
Description=Disable Transparent Huge Pages

[Service]
Type=oneshot
ExecStart=/usr/bin/bash -c 'echo never > /sys/kernel/mm/transparent_hugepage/enabled'

[Install]
WantedBy=multi-user.target
EOF2
        sudo systemctl enable disable-thp.service >/dev/null
      fi
    else
      log "  THP already disabled."
    fi
  else
    log "  WARNING: THP control file not found."
  fi
}

ensure_memory_lock_enabled() {
  log "[6] Ensuring bootstrap.memory_lock: true in elasticsearch.yml..."
  local FILE="/etc/elasticsearch/elasticsearch.yml"
  local TS=$(date +%Y%m%d-%H%M%S)
  if sudo_test_file "$FILE"; then
    sudo cp -a "$FILE" "${FILE}.backup-$TS"
    if sudo grep -q '^bootstrap.memory_lock:' "$FILE"; then
      sudo sed -i 's/^bootstrap.memory_lock:.*/bootstrap.memory_lock: true/' "$FILE"
    else
      echo "bootstrap.memory_lock: true" | sudo tee -a "$FILE" >/dev/null
    fi
    log "  bootstrap.memory_lock set to true"
  else
    log "  ERROR: $FILE not found (or not accessible)"
  fi
}

ensure_network_sysctl() {
  log "[7] Ensuring network sysctl tuning..."
  local CONF_FILE="/etc/sysctl.d/99-elasticsearch.conf"
  local -a KV=(
    "net.core.somaxconn=4096"
    "net.core.netdev_max_backlog=16384"
    "net.ipv4.tcp_max_syn_backlog=8192"
    "net.ipv4.tcp_fin_timeout=30"
    "net.ipv4.tcp_tw_reuse=1"
    "net.ipv4.ip_local_port_range=1024 65000"
  )

  sudo touch "$CONF_FILE"
  sudo chmod 0644 "$CONF_FILE"

  for entry in "${KV[@]}"; do
    key="${entry%%=*}"
    val="${entry#*=}"
    if sudo grep -q "^${key}[[:space:]]*=" "$CONF_FILE" 2>/dev/null; then
      sudo sed -i "s|^${key}[[:space:]]*=.*|${key} = ${val}|" "$CONF_FILE"
    else
      echo "${key} = ${val}" | sudo tee -a "$CONF_FILE" >/dev/null
    fi
    sudo sysctl -w "${key}=${val}" >/dev/null || true
  done

  local ok=1
  for entry in "${KV[@]}"; do
    key="${entry%%=*}"; want="${entry#*=}"
    have=$(sysctl -n "$key" 2>/dev/null || echo "")
    # Normalize whitespace for range values (e.g., '1024   65000' vs '1024 65000')
    have_norm=$(echo "$have" | tr -s ' ')
    want_norm=$(echo "$want" | tr -s ' ')
    if [[ "$have_norm" == "$want_norm" ]]; then
      log "  OK: $key = $have"
    else
      log "  WARN: $key is '$have' (wanted '$want')"
      ok=0
    fi
  done
  [[ $ok -eq 1 ]] || log "  Some sysctls differ from desired values. Review $CONF_FILE."
}

final_restart_and_validate() {
  log "[8] Reloading systemd, restarting elasticsearch, and validating..."

  sudo systemctl daemon-reload
  sudo systemctl restart elasticsearch

  # Retry loop up to 60s for elasticsearch to be active
  for i in {1..60}; do
    if systemctl is-active --quiet elasticsearch; then
      log "  Elasticsearch is active."
      break
    fi
    sleep 1
  done

  if ! systemctl is-active --quiet elasticsearch; then
    echo "  ERROR: Elasticsearch did not become active within 60s" >&2
    sudo journalctl -u elasticsearch --no-pager -n 50 || true
    exit 1
  fi

  systemctl show elasticsearch -p LimitNOFILE -p LimitNPROC -p TasksMax -p OOMPolicy -p Restart -p RestartUSec -p TimeoutStopUSec -p KillSignal || true

  IFS='|' read -r ES_USER ES_GROUP MAINPID < <(get_es_identity)
  if [[ -n "${MAINPID:-}" && "${MAINPID:-0}" -gt 0 ]]; then
    log "  Runtime /proc limits for PID $MAINPID (user=${ES_USER:-?}):"
    cat /proc/$MAINPID/limits | egrep 'Max open files|Max processes|Max locked memory' || true

    log "  Checking JVM heap flags (from /proc/$MAINPID/cmdline):"
    # Print real JVM args; avoid the server-cli 4m/64m output
    tr '\0' ' ' < /proc/$MAINPID/cmdline | egrep -- "-Xms|-Xmx" || true

    log "  Note: you can verify memory lock via: curl -s http://localhost:9200/_nodes?filter_path=**.process.mlockall"
  else
    log "  WARNING: Could not determine MainPID; printing recent logs:"
    sudo journalctl -u elasticsearch --no-pager -n 50 || true
  fi

  if [[ -f /sys/kernel/mm/transparent_hugepage/enabled ]]; then
    thp=$(cat /sys/kernel/mm/transparent_hugepage/enabled)
    log "  Transparent Huge Pages setting: $thp"
    if echo "$thp" | grep -q '\\[never\\]'; then
      log "  OK: THP is disabled"
    else
      log "  WARNING: THP may not be disabled correctly"
    fi
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
