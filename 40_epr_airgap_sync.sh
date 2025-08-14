#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/00_common.sh"

print_help() {
  cat <<'EOF'
Usage:
  40_epr_airgap_sync.sh --mode <kibana-upload|kibana-config|epr-deploy> [options]

Modes:

  kibana-upload
    --kibana-url <https://kib:5601> --kbn-user <user> --kbn-pass <pass> [--ca <path>]
    --integrations-dir <dir>
    Upload integration .zip packages to Kibana via API (air-gapped).

  kibana-config
    --registry-url <http://local-epr:8080/> --kibana-hosts-file <file> [--ssh-user <user>]
    Set xpack.fleet.registryUrl in kibana.yml on Kibana hosts and restart Kibana.

  epr-deploy
    --epr-host <host> --epr-tar <image.tar> [--name <epr>] [--port <8080>] [--ssh-user <user>]
    [--kibana-hosts-file <file>]
    1) Upload and load EPR image (docker/podman) on <host>, run container on port <port>.
    2) If --kibana-hosts-file provided, set in kibana.yml:
         xpack.fleet.isAirGapped: true
         xpack.fleet.registryUrl: "http://<epr-host>:<port>"
       and restart Kibana on those hosts.

Examples:
  ./40_epr_airgap_sync.sh --mode kibana-upload --kibana-url https://kib:5601 \
    --kbn-user svc --kbn-pass '***' --ca cfg/tls/ca.crt --integrations-dir ./artifacts/integrations

  ./40_epr_airgap_sync.sh --mode kibana-config --registry-url http://epr01:8080/ \
    --kibana-hosts-file inventory/hosts_kibana.txt --ssh-user deploy

  ./40_epr_airgap_sync.sh --mode epr-deploy --epr-host epr01 --epr-tar ./artifacts/package-registry-8.18.3.tar \
    --port 8080 --kibana-hosts-file inventory/hosts_kibana.txt --ssh-user deploy
EOF
  exit 0
}

[[ $# -eq 0 ]] && print_help
require_cmd curl jq

MODE=""
KBN_URL="" KBN_USER="" KBN_PASS="" CA_FILE=""
INTEGRATIONS_DIR="" REGISTRY_URL="" KBN_HOSTS_FILE=""
EPR_HOST="" EPR_TAR="" EPR_NAME="epr" EPR_PORT="8080"

ARGS=("$@")
# Pre-parse --ssh-user
for ((i=0;i<${#ARGS[@]};i++)); do case "${ARGS[i]}" in --ssh-user) export DEFAULT_SSH_USER="${ARGS[i+1]}";; esac; done

i=0
while [[ $i -lt ${#ARGS[@]} ]]; do
  case "${ARGS[i]}" in
    --mode) MODE="${ARGS[i+1]}"; ((i+=2));;
    --kibana-url) KBN_URL="${ARGS[i+1]}"; ((i+=2));;
    --kbn-user) KBN_USER="${ARGS[i+1]}"; ((i+=2));;
    --kbn-pass) KBN_PASS="${ARGS[i+1]}"; ((i+=2));;
    --ca) CA_FILE="${ARGS[i+1]}"; ((i+=2));;
    --integrations-dir) INTEGRATIONS_DIR="${ARGS[i+1]}"; ((i+=2));;
    --registry-url) REGISTRY_URL="${ARGS[i+1]}"; ((i+=2));;
    --kibana-hosts-file) KBN_HOSTS_FILE="${ARGS[i+1]}"; ((i+=2));;
    --epr-host) EPR_HOST="${ARGS[i+1]}"; ((i+=2));;
    --epr-tar)  EPR_TAR="${ARGS[i+1]}";  ((i+=2));;
    --name)     EPR_NAME="${ARGS[i+1]}"; ((i+=2));;
    --port)     EPR_PORT="${ARGS[i+1]}"; ((i+=2));;
    --help) print_help;;
    --ssh-user) ((i+=2));; # consumed
    *) ((i+=1));;
  esac
done

LOG_FILE="$LOG_DIR/$(date +%Y%m%d_%H%M%S)_40_epr_airgap_sync.log"

# Mode: kibana-upload
if [[ "$MODE" == "kibana-upload" ]]; then
  [[ -n "$KBN_URL" && -n "$KBN_USER" && -n "$KBN_PASS" && -n "$INTEGRATIONS_DIR" ]] || die "Missing args for kibana-upload"
  [[ -d "$INTEGRATIONS_DIR" ]] || die "Integrations dir not found: $INTEGRATIONS_DIR"
  shopt -s nullglob
  for zip in "$INTEGRATIONS_DIR"/*.zip; do
    name="$(basename "$zip")"
    log "Uploading package: $name"
    if [[ -n "$CA_FILE" ]]; then
      curl -sSf --user "$KBN_USER:$KBN_PASS" --cacert "$CA_FILE" \
        -H "kbn-xsrf: true" -F "file=@$zip" "$KBN_URL/api/fleet/epm/packages" >/dev/null
    else
      curl -sSf --user "$KBN_USER:$KBN_PASS" -k \
        -H "kbn-xsrf: true" -F "file=@$zip" "$KBN_URL/api/fleet/epm/packages" >/dev/null
    fi
  done
  log "Upload completed."
  exit 0
fi

# Mode: kibana-config
if [[ "$MODE" == "kibana-config" ]]; then
  [[ -n "$REGISTRY_URL" && -n "$KBN_HOSTS_FILE" ]] || die "Missing args for kibana-config"
  mapfile -t KBN_HOSTS < "$KBN_HOSTS_FILE"
  for HOST in "${KBN_HOSTS[@]}"; do
    log "[$HOST] Setting xpack.fleet.registryUrl -> $REGISTRY_URL and restarting Kibana"
    run_ssh "$HOST" "sudo bash -lc '
      Y=/etc/kibana/kibana.yml
      mkdir -p /etc/kibana
      if grep -q \"^xpack.fleet.registryUrl:\" \"\$Y\" 2>/dev/null; then
        sed -i \"s|^xpack.fleet.registryUrl:.*|xpack.fleet.registryUrl: $REGISTRY_URL|\" \"\$Y\"
      else
        echo \"xpack.fleet.registryUrl: $REGISTRY_URL\" >> \"\$Y\"
      fi
      systemctl restart kibana
    '"
  done
  log "Kibana config updated."
  exit 0
fi

# Mode: epr-deploy
if [[ "$MODE" == "epr-deploy" ]]; then
  [[ -n "$EPR_HOST" && -n "$EPR_TAR" ]] || die "Missing --epr-host/--epr-tar for epr-deploy"
  [[ -f "$EPR_TAR" ]] || die "EPR tar image not found: $EPR_TAR"

  REMOTE_TMP="/tmp"
  log "[$EPR_HOST] Uploading EPR image tar"
  run_ssh "$EPR_HOST" "sudo mkdir -p '$REMOTE_TMP'"
  run_scp_to "$EPR_TAR" "$EPR_HOST" "$REMOTE_TMP/"
  TAR_REMOTE="$REMOTE_TMP/$(basename "$EPR_TAR")"

  log "[$EPR_HOST] Detecting container runtime"
  RUNTIME="$(run_ssh "$EPR_HOST" "command -v docker >/dev/null 2>&1 && echo docker || (command -v podman >/dev/null 2>&1 && echo podman || echo none)")"
  [[ "$RUNTIME" != "none" ]] || die "Neither docker nor podman found on $EPR_HOST"

  log "[$EPR_HOST] Loading image: $TAR_REMOTE"
  LOAD_OUT="$(run_ssh "$EPR_HOST" "sudo $RUNTIME load -i '$TAR_REMOTE' 2>&1 || true")"
  echo "$LOAD_OUT" | tee -a "$LOG_FILE" >/dev/null
  IMG="$(echo "$LOAD_OUT" | awk '/Loaded image/ {print $NF}' | tail -n1)"
  if [[ -z "$IMG" ]]; then
    IMG="$(echo "$LOAD_OUT" | awk -F': ' '/Loaded image/ || /Loaded image\(s\)/ {print $2}' | tail -n1)"
  fi
  [[ -n "$IMG" ]] || IMG="docker.elastic.co/package-registry/distribution:latest"

  log "[$EPR_HOST] (Re)starting container '$EPR_NAME' on port $EPR_PORT (image: $IMG)"
  run_ssh "$EPR_HOST" "sudo $RUNTIME rm -f '$EPR_NAME' >/dev/null 2>&1 || true"
  run_ssh "$EPR_HOST" "sudo $RUNTIME run -d --name '$EPR_NAME' --restart unless-stopped -p $EPR_PORT:8080 '$IMG'"

  EPR_URL="http://$(echo "$EPR_HOST" | awk -F'@' '{print $NF}'):$EPR_PORT"
  log "[$EPR_HOST] Waiting for $EPR_URL/health (24x5s)"
  if ! retry 24 5 bash -lc "curl -fsS '$EPR_URL/health' >/dev/null"; then
    warn "[$EPR_HOST] EPR health check failed at $EPR_URL/health"
  else
    log "[$EPR_HOST] EPR is healthy"
  fi

  if [[ -n "$KBN_HOSTS_FILE" ]]; then
    mapfile -t KBN_HOSTS < "$KBN_HOSTS_FILE"
    for HOST in "${KBN_HOSTS[@]}"; do
      log "[$HOST] Enabling air-gapped mode and setting registryUrl: $EPR_URL"
      run_ssh "$HOST" "sudo bash -lc '
        Y=/etc/kibana/kibana.yml
        mkdir -p /etc/kibana
        if grep -q \"^xpack.fleet.isAirGapped:\" \"\$Y\" 2>/dev/null; then
          sed -i \"s|^xpack.fleet.isAirGapped:.*|xpack.fleet.isAirGapped: true|\" \"\$Y\"
        else
          echo \"xpack.fleet.isAirGapped: true\" >> \"\$Y\"
        fi
        if grep -q \"^xpack.fleet.registryUrl:\" \"\$Y\" 2>/dev/null; then
          sed -i \"s|^xpack.fleet.registryUrl:.*|xpack.fleet.registryUrl: $EPR_URL|\" \"\$Y\"
        else
          echo \"xpack.fleet.registryUrl: $EPR_URL\" >> \"\$Y\"
        fi
        systemctl restart kibana
      '"
    done
    log "Kibana hosts updated for air-gapped EPR."
  else
    warn "No --kibana-hosts-file provided; Kibana config step skipped."
  fi

  log "EPR deployment finished."
  exit 0
fi

die "Unknown --mode (use kibana-upload | kibana-config | epr-deploy)"
