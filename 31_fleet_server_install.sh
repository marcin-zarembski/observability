#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/00_common.sh"

print_help() {
  cat <<'EOF'
Usage:
  31_fleet_server_install.sh --host <fleet-host> --agent-tar <path.tar.gz> \
    --es-url <https://es:9200> --fleet-url <https://fleet:8220> \
    --service-token-file <file> (--ca <path> | --insecure) \
    [--cert <crt> --key <key>] | [--p12 <p12> --p12-pass <pass>] \
    [--data-dir </var/lib/elastic-agent>] [--remote-tmp </tmp>] [--ssh-user <user>]

What it does:
  - Uploads and extracts Elastic Agent tar.gz on the target host (no RPM).
  - Enrolls the agent as Fleet Server with TLS (PEM cert+key) or P12 converted to PEM on remote.
  - Waits for agent to become healthy; dumps journal on failure.

Examples:
  PEM:
    ./31_fleet_server_install.sh --host fleet01 --agent-tar ./artifacts/elastic-agent-8.18.3-linux-x86_64.tar.gz \
      --es-url https://es:9200 --fleet-url https://fleet:8220 \
      --service-token-file ./secrets/fleet_server_service_token \
      --ca /etc/kibana/fleet/certs/ca.pem --cert /etc/kibana/fleet/certs/cert.pem --key /etc/kibana/fleet/certs/key.pem
  P12:
    ./31_fleet_server_install.sh --host fleet01 --agent-tar ./artifacts/elastic-agent-8.18.3-linux-x86_64.tar.gz \
      --es-url https://es:9200 --fleet-url https://fleet:8220 \
      --service-token-file ./secrets/fleet_server_service_token \
      --ca /etc/kibana/fleet/certs/ca.pem --p12 ./cfg/tls/fleet.p12 --p12-pass 'secret'
EOF
  exit 0
}

[[ $# -eq 0 ]] && print_help

require_cmd ssh scp tar

HOST="" AGENT_TAR="" ES_URL="" FLEET_URL="" SERVICE_TOKEN_FILE=""
CA_FILE="" INSECURE=0 REMOTE_TMP="/tmp" DATA_DIR="/var/lib/elastic-agent"
CERT="" KEY="" P12="" P12_PASS=""

ARGS=("$@")
# Pre-parse --ssh-user
for ((i=0;i<${#ARGS[@]};i++)); do case "${ARGS[i]}" in --ssh-user) export DEFAULT_SSH_USER="${ARGS[i+1]}";; esac; done

i=0
while [[ $i -lt ${#ARGS[@]} ]]; do
  case "${ARGS[i]}" in
    --host) HOST="${ARGS[i+1]}"; ((i+=2));;
    --agent-tar) AGENT_TAR="${ARGS[i+1]}"; ((i+=2));;
    --es-url) ES_URL="${ARGS[i+1]}"; ((i+=2));;
    --fleet-url) FLEET_URL="${ARGS[i+1]}"; ((i+=2));;
    --service-token-file) SERVICE_TOKEN_FILE="${ARGS[i+1]}"; ((i+=2));;
    --ca) CA_FILE="${ARGS[i+1]}"; ((i+=2));;
    --insecure) INSECURE=1; ((i+=1));;
    --cert) CERT="${ARGS[i+1]}"; ((i+=2));;
    --key)  KEY="${ARGS[i+1]}";  ((i+=2));;
    --p12)  P12="${ARGS[i+1]}";  ((i+=2));;
    --p12-pass) P12_PASS="${ARGS[i+1]}"; ((i+=2));;
    --data-dir) DATA_DIR="${ARGS[i+1]}"; ((i+=2));;
    --remote-tmp) REMOTE_TMP="${ARGS[i+1]}"; ((i+=2));;
    --help) print_help;;
    --ssh-user) ((i+=2));; # consumed
    *) ((i+=1));;
  esac
done

[[ -n "$HOST" && -f "$AGENT_TAR" && -n "$ES_URL" && -n "$FLEET_URL" && -f "$SERVICE_TOKEN_FILE" ]] || die "Missing required arguments"
if (( INSECURE==0 )) && [[ -z "$CA_FILE" ]]; then die "Provide --ca or --insecure"; fi
if [[ -n "$P12" || -n "$P12_PASS" ]]; then [[ -f "$P12" && -n "$P12_PASS" ]] || die "Provide both --p12 and --p12-pass"; fi
if [[ -n "$CERT" || -n "$KEY" ]]; then [[ -f "$CERT" && -f "$KEY" ]] || die "Provide both --cert and --key"; fi
if [[ -n "$P12" && ( -n "$CERT" || -n "$KEY" ) ]]; then die "Use either PEM (--cert/--key) or P12 (--p12/--p12-pass), not both"; fi

LOG_FILE="$LOG_DIR/$(date +%Y%m%d_%H%M%S)_31_fleet_server_install.log"
TOKEN="$(cat "$SERVICE_TOKEN_FILE")"

# Upload tar.gz and optional files
TS="$(date +%s)"
WORKDIR_REMOTE="$REMOTE_TMP/ea-install-$TS"
log "[$HOST] Creating remote workdir: $WORKDIR_REMOTE"
run_ssh "$HOST" "sudo mkdir -p '$WORKDIR_REMOTE'"

log "[$HOST] Uploading elastic-agent tar.gz"
run_scp_to "$AGENT_TAR" "$HOST" "$WORKDIR_REMOTE/"
AGENT_TAR_REMOTE="$WORKDIR_REMOTE/$(basename "$AGENT_TAR")"

# TLS material
TLS_CERT_REMOTE=""
TLS_KEY_REMOTE=""

if (( INSECURE==0 )); then
  run_scp_to "$CA_FILE" "$HOST" "$WORKDIR_REMOTE/"
  CA_REMOTE="$WORKDIR_REMOTE/$(basename "$CA_FILE")"
fi

if [[ -n "$CERT" && -n "$KEY" ]]; then
  run_scp_to "$CERT" "$HOST" "$WORKDIR_REMOTE/"
  run_scp_to "$KEY"  "$HOST" "$WORKDIR_REMOTE/"
  TLS_CERT_REMOTE="$WORKDIR_REMOTE/$(basename "$CERT")"
  TLS_KEY_REMOTE="$WORKDIR_REMOTE/$(basename "$KEY")"
elif [[ -n "$P12" ]]; then
  require_cmd openssl
  run_scp_to "$P12" "$HOST" "$WORKDIR_REMOTE/"
  P12_REMOTE="$WORKDIR_REMOTE/$(basename "$P12")"
  # Convert P12 -> PEM on remote (cert + unencrypted key)
  log "[$HOST] Converting P12 to PEM cert/key on remote"
  run_ssh "$HOST" "sudo bash -lc '
    set -e
    umask 077
    openssl pkcs12 -in \"$P12_REMOTE\" -clcerts -nokeys -out \"$WORKDIR_REMOTE/fleet.crt\" -passin pass:\"$P12_PASS\"
    openssl pkcs12 -in \"$P12_REMOTE\" -nocerts -nodes -out \"$WORKDIR_REMOTE/fleet.key\" -passin pass:\"$P12_PASS\"
  '"
  TLS_CERT_REMOTE="$WORKDIR_REMOTE/fleet.crt"
  TLS_KEY_REMOTE="$WORKDIR_REMOTE/fleet.key"
fi

# Extract tar.gz
log "[$HOST] Extracting agent tar.gz"
run_ssh "$HOST" "sudo tar -xzf '$AGENT_TAR_REMOTE' -C '$WORKDIR_REMOTE'"
AGENT_DIR_REMOTE="$(basename "$AGENT_TAR" .tar.gz)"
# Try to detect exact dir name (some archives include full name with OS/arch)
AGENT_DIR_REMOTE="$(basename "$AGENT_DIR_REMOTE" .tgz)"
# Find the first directory containing elastic-agent binary
EA_PATH_REMOTE_CMD="set -e; cd '$WORKDIR_REMOTE'; EA_DIR=\$(find . -maxdepth 1 -type d -name 'elastic-agent*' | head -n1); echo \$EA_DIR"
EA_DIR_REMOTE="$(run_ssh "$HOST" "bash -lc '$EA_PATH_REMOTE_CMD'" | tr -d '
')"
[[ -n "$EA_DIR_REMOTE" ]] || die "[$HOST] Could not locate extracted elastic-agent directory"

# Clean previous install (idempotent)
run_ssh "$HOST" "sudo elastic-agent uninstall -f >/dev/null 2>&1 || true; sudo rm -rf '$DATA_DIR' || true"

# Build args
CA_ARG=()
(( INSECURE==0 )) && CA_ARG=(--certificate-authorities "$CA_REMOTE") || CA_ARG=(--insecure)
TLS_ARGS=()
if [[ -n "$TLS_CERT_REMOTE" && -n "$TLS_KEY_REMOTE" ]]; then
  TLS_ARGS=(--fleet-server-cert "$TLS_CERT_REMOTE" --fleet-server-cert-key "$TLS_KEY_REMOTE")
fi

# Enroll as Fleet Server via tar.gz installer
log "[$HOST] Enrolling as Fleet Server from tar.gz"
run_ssh "$HOST" "sudo bash -lc 'cd \"$WORKDIR_REMOTE/$EA_DIR_REMOTE\" && ./elastic-agent install \
  --url=\"$FLEET_URL\" \
  --fleet-server-es=\"$ES_URL\" \
  --fleet-server-service-token=\"$TOKEN\" \
  ${CA_ARG[*]} \
  ${TLS_ARGS[*]} \
  --non-interactive'" || { dump_journal "$HOST" "elastic-agent"; die "[$HOST] Fleet Server install failed"; }

# Wait for readiness
log "[$HOST] Waiting for elastic-agent to become healthy"
if ! retry 24 5 run_ssh "$HOST" "sudo elastic-agent status >/dev/null 2>&1"; then
  dump_journal "$HOST" "elastic-agent"
  die "[$HOST] elastic-agent did not become healthy"
fi

log "[$HOST] Fleet Server ready."
