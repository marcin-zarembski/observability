#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=00_common.sh
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
    --registry-url <http(s)://local-epr:PORT/> --kibana-hosts-file <file> [--ssh-user <user>]
    Set xpack.fleet.registryUrl in kibana.yml on Kibana hosts and restart Kibana.

  epr-deploy  (SECURE-ONLY: HTTPS with TLS)
    --epr-host <host> --epr-tar <image.tar> [--name <epr>] [--port <8443>] [--ssh-user <user>]
    --epr-cert </path/to/server.crt> --epr-key </path/to/server.key> --epr-ca </path/to/ca-chain.pem>
    [--kibana-hosts-file <file>]
    1) Upload & load EPR image (docker/podman) on <host>, run container on HTTPS port <port>.
       Container starts with --tls-cert/--tls-key and mounts cert/key read-only.
    2) If --kibana-hosts-file is provided, then for each Kibana host:
         - copy CA to /etc/kibana/certs/epr-ca-chain.pem (proper owner/permissions)
         - inject Environment=NODE_EXTRA_CA_CERTS into the main kibana.service unit file
         - set xpack.fleet.isAirGapped: true and xpack.fleet.registryUrl: "https://<epr-host>:<port>"
         - systemctl daemon-reload + restart Kibana

Examples:
  ./40_epr_airgap_sync.sh --mode kibana-upload --kibana-url https://kib:5601 \
    --kbn-user svc --kbn-pass '***' --ca cfg/tls/ca.crt --integrations-dir ./artifacts/integrations

  ./40_epr_airgap_sync.sh --mode kibana-config --registry-url https://epr01:8443/ \
    --kibana-hosts-file inventory/hosts_kibana.txt --ssh-user deploy

  ./40_epr_airgap_sync.sh --mode epr-deploy --epr-host epr01 --epr-tar ./artifacts/package-registry-8.18.3.tar \
    --port 8443 --epr-cert cfg/tls/epr.crt --epr-key cfg/tls/epr.key --epr-ca cfg/tls/epr-ca-chain.pem \
    --kibana-hosts-file inventory/hosts_kibana.txt --ssh-user deploy
EOF
  exit 0
}

[[ $# -eq 0 ]] && print_help
require_cmd curl jq

MODE=""

# kibana-upload
KBN_URL="" KBN_USER="" KBN_PASS="" CA_FILE=""
INTEGRATIONS_DIR=""

# kibana-config
REGISTRY_URL="" KBN_HOSTS_FILE=""

# epr-deploy (secure-only)
EPR_HOST="" EPR_TAR="" EPR_NAME="epr" EPR_PORT="8443"
EPR_CERT="" EPR_KEY="" EPR_CA=""

ARGS=("$@")
# Pre-parse --ssh-user so SSH helpers pick it up
for ((i=0;i<${#ARGS[@]};i++)); do
  case "${ARGS[i]}" in
    --ssh-user) export DEFAULT_SSH_USER="${ARGS[i+1]}";;
  esac
done

i=0
while [[ $i -lt ${#ARGS[@]} ]]; do
  case "${ARGS[i]}" in
    --mode) MODE="${ARGS[i+1]}"; ((i+=2));;

    # kibana-upload
    --kibana-url) KBN_URL="${ARGS[i+1]}"; ((i+=2));;
    --kbn-user)   KBN_USER="${ARGS[i+1]}"; ((i+=2));;
    --kbn-pass)   KBN_PASS="${ARGS[i+1]}"; ((i+=2));;
    --ca)         CA_FILE="${ARGS[i+1]}"; ((i+=2));;
    --integrations-dir) INTEGRATIONS_DIR="${ARGS[i+1]}"; ((i+=2));;

    # kibana-config
    --registry-url) REGISTRY_URL="${ARGS[i+1]}"; ((i+=2));;
    --kibana-hosts-file) KBN_HOSTS_FILE="${ARGS[i+1]}"; ((i+=2));;

    # epr-deploy (secure-only)
    --epr-host) EPR_HOST="${ARGS[i+1]}"; ((i+=2));;
    --epr-tar)  EPR_TAR="${ARGS[i+1]}";  ((i+=2));;
    --name)     EPR_NAME="${ARGS[i+1]}"; ((i+=2));;
    --port)     EPR_PORT="${ARGS[i+1]}"; ((i+=2));;
    --epr-cert) EPR_CERT="${ARGS[i+1]}"; ((i+=2));;
    --epr-key)  EPR_KEY="${ARGS[i+1]}";  ((i+=2));;
    --epr-ca)   EPR_CA="${ARGS[i+1]}";   ((i+=2));;

    --help) print_help;;
    --ssh-user) ((i+=2));; # consumed above
    *) ((i+=1));;
  esac
done

LOG_FILE="$LOG_DIR/$(date +%Y%m%d_%H%M%S)_40_epr_airgap_sync.log"

# ------------------------ Mode: kibana-upload ------------------------
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

# ------------------------ Mode: kibana-config ------------------------
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

# ------------------------ Mode: epr-deploy (SECURE-ONLY) ------------------------
if [[ "$MODE" == "epr-deploy" ]]; then
  # Enforce HTTPS with server cert/key and CA chain
  [[ -n "$EPR_HOST" && -n "$EPR_TAR" && -n "$EPR_CERT" && -n "$EPR_KEY" && -n "$EPR_CA" ]] || \
    die "Missing required args for secure epr-deploy: --epr-host --epr-tar --epr-cert --epr-key --epr-ca"
  [[ -f "$EPR_TAR" && -f "$EPR_CERT" && -f "$EPR_KEY" && -f "$EPR_CA" ]] || \
    die "One or more files do not exist (check --epr-tar/--epr-cert/--epr-key/--epr-ca)"

  REMOTE_TMP="/tmp"
  log "[$EPR_HOST] Uploading EPR image tar + TLS materials"
  run_ssh "$EPR_HOST" "sudo mkdir -p '$REMOTE_TMP/epr_tls'"
  run_scp_to "$EPR_TAR"  "$EPR_HOST" "$REMOTE_TMP/"
  run_scp_to "$EPR_CERT" "$EPR_HOST" "$REMOTE_TMP/epr_tls/cert.pem"
  run_scp_to "$EPR_KEY"  "$EPR_HOST" "$REMOTE_TMP/epr_tls/key.pem"
  TAR_REMOTE="$REMOTE_TMP/$(basename "$EPR_TAR")"
  CERT_REMOTE="$REMOTE_TMP/epr_tls/cert.pem"
  KEY_REMOTE="$REMOTE_TMP/epr_tls/key.pem"

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

  log "[$EPR_HOST] (Re)starting secure EPR container '$EPR_NAME' on HTTPS port $EPR_PORT (image: $IMG)"
  run_ssh "$EPR_HOST" "sudo $RUNTIME rm -f '$EPR_NAME' >/dev/null 2>&1 || true"
  # Map host:$EPR_PORT -> container:8080; mount cert/key read-only, pass TLS args to process
  run_ssh "$EPR_HOST" "sudo $RUNTIME run -d --name '$EPR_NAME' --restart unless-stopped \
    -p $EPR_PORT:8080 \
    -v $CERT_REMOTE:/usr/share/package-registry/config/cert.pem:ro \
    -v $KEY_REMOTE:/usr/share/package-registry/config/key.pem:ro \
    '$IMG' \
    --tls-cert /usr/share/package-registry/config/cert.pem \
    --tls-key  /usr/share/package-registry/config/key.pem"

  # Health check via HTTPS using the provided CA
  EPR_URL="https://$(echo "$EPR_HOST" | awk -F'@' '{print $NF}'):$EPR_PORT"
  log "[$EPR_HOST] Waiting for $EPR_URL/health (24x5s, TLS verify with provided CA)"
  if ! retry 24 5 bash -lc "curl -fsS --cacert '$EPR_CA' '$EPR_URL/health' >/dev/null"; then
    warn "[$EPR_HOST] EPR health check failed at $EPR_URL/health (with --cacert)"
  else
    log "[$EPR_HOST] EPR is healthy (HTTPS)"
  fi

  # Configure Kibana hosts (CA ownership/permissions + env var in unit + kibana.yml)
  if [[ -n "$KBN_HOSTS_FILE" ]]; then
    [[ -f "$KBN_HOSTS_FILE" ]] || die "Kibana hosts file not found: $KBN_HOSTS_FILE"
    mapfile -t KBN_HOSTS < "$KBN_HOSTS_FILE"

    for HOST in "${KBN_HOSTS[@]}"; do
      log "[$HOST] Installing EPR CA, setting NODE_EXTRA_CA_CERTS in unit, and configuring registryUrl: $EPR_URL"

      # Ensure target directories exist with sane perms
      run_ssh "$HOST" "sudo mkdir -p /etc/kibana/certs && sudo chmod 0755 /etc/kibana && sudo chmod 0755 /etc/kibana/certs"

      # Copy CA to Kibana
      run_scp_to "$EPR_CA" "$HOST" "/etc/kibana/certs/epr-ca-chain.pem"

      # Fix ownership/permissions according to Kibana service user/group
      run_ssh "$HOST" "sudo bash -lc '
        set -e
        SVC_USER=\$(systemctl show kibana -p User --value 2>/dev/null || true)
        SVC_GROUP=\$(systemctl show kibana -p Group --value 2>/dev/null || true)
        [[ -n \"\$SVC_USER\" ]] || SVC_USER=\"kibana\"
        [[ -n \"\$SVC_GROUP\" ]] || SVC_GROUP=\"kibana\"
        chown \"\$SVC_USER:\$SVC_GROUP\" /etc/kibana/certs/epr-ca-chain.pem
        chmod 0644 /etc/kibana/certs/epr-ca-chain.pem

        # Inject NODE_EXTRA_CA_CERTS into the main unit file (if missing)
        UNIT_FILE=/usr/lib/systemd/system/kibana.service
        if [[ ! -f \"\$UNIT_FILE\" ]]; then
          UNIT_FILE=/etc/systemd/system/kibana.service
        fi
        if [[ -f \"\$UNIT_FILE\" ]]; then
          if ! grep -q \"NODE_EXTRA_CA_CERTS\" \"\$UNIT_FILE\"; then
            sed -i \"/^\[Service\]/a Environment=\\\"NODE_EXTRA_CA_CERTS=/etc/kibana/certs/epr-ca-chain.pem\\\"\" \"\$UNIT_FILE\"
          fi
        else
          echo \"ERROR: Kibana systemd unit file not found\" >&2; exit 1
        fi

        systemctl daemon-reload
      '"

      # Update kibana.yml to air-gapped + secure registry
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

        # Keep kibana.yml world-readable but owned by root (common on RPM installs)
        chmod 0644 \"\$Y\"
        systemctl restart kibana
      '"
    done
    log "Kibana hosts updated for secure (HTTPS) air-gapped EPR with proper ownership."
  else
    warn "No --kibana-hosts-file provided; Kibana config step skipped."
  fi

  log "Secure EPR deployment finished."
  exit 0
fi

die "Unknown --mode (use kibana-upload | kibana-config | epr-deploy)"
