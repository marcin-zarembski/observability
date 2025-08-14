#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/00_common.sh"

print_help() {
  cat <<'EOF'
Usage:
  31_fleet_server_install.sh --host <fleet-host> --agent-rpm <path> \
    --es-url <https://es:9200> --fleet-url <https://fleet:8220> \
    --service-token-file <file> (--ca <path> | --insecure) \
    [--cert <crt> --key <key>] | [--p12 <p12> --p12-pass <pass>] \
    [--data-dir </var/lib/elastic-agent>] [--remote-tmp </tmp>] [--ssh-user <user>]

What it does:
  - Installs/updates elastic-agent RPM on the target host.
  - Enrolls the agent as Fleet Server with TLS (PEM cert+key) or P12 converted to PEM on remote.
  - Waits for agent to become healthy; dumps journal on failure.

Examples:
  PEM:
    ./31_fleet_server_install.sh --host fleet01 --agent-rpm ./artifacts/elastic-agent-8.18.3-x86_64.rpm \
      --es-url https://es:9200 --fleet-url https://fleet:8220 \
      --service-token-file ./secrets/fleet_server_service_token \
      --ca cfg/tls/ca.crt --cert cfg/tls/fleet.crt --key cfg/tls/fleet.key
  P12:
    ./31_fleet_server_install.sh --host fleet01 --agent-rpm ./artifacts/elastic-agent-8.18.3-x86_64.rpm \
      --es-url https://es:9200 --fleet-url https://fleet:8220 \
      --service-token-file ./secrets/fleet_server_service_token \
      --ca cfg/tls/ca.crt --p12 cfg/tls/fleet.p12 --p12-pass 'secret'
EOF
  exit 0
}

[[ $# -eq 0 ]] && print_help

require_cmd ssh scp rpm

HOST="" AGENT_RPM="" ES_URL="" FLEET_URL="" SERVICE_TOKEN_FILE=""
CA_FILE="" INSECURE=0 REMOTE_TMP="/tmp" DATA_DIR="/var/lib/elastic-agent"
CERT="" KEY="" P12="" P12_PASS=""

ARGS=("$@")
# Pre-parse --ssh-user
for ((i=0;i<${#ARGS[@]};i++)); do case "${ARGS[i]}" in --ssh-user) export DEFAULT_SSH_USER="${ARGS[i+1]}";; esac; done

i=0
while [[ $i -lt ${#ARGS[@]} ]]; do
  case "${ARGS[i]}" in
    --host) HOST="${ARGS[i+1]}"; ((i+=2));;
    --agent-rpm) AGENT_RPM="${ARGS[i+1]}"; ((i+=2));;
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

[[ -n "$HOST" && -f "$AGENT_RPM" && -n "$ES_URL" && -n "$FLEET_URL" && -f "$SERVICE_TOKEN_FILE" ]] || die "Missing required arguments"
if (( INSECURE==0 )) && [[ -z "$CA_FILE" ]]; then die "Provide --ca or --insecure"; fi
if [[ -n "$P12" || -n "$P12_PASS" ]]; then [[ -f "$P12" && -n "$P12_PASS" ]] || die "Provide both --p12 and --p12-pass"; fi
if [[ -n "$CERT" || -n "$KEY" ]]; then [[ -f "$CERT" && -f "$KEY" ]] || die "Provide both --cert and --key"; fi
if [[ -n "$P12" && ( -n "$CERT" || -n "$KEY" ) ]]; then die "Use either PEM (--cert/--key) or P12 (--p12/--p12-pass), not both"; fi

LOG_FILE="$LOG_DIR/$(date +%Y%m%d_%H%M%S)_31_fleet_server_install.log"
TOKEN="$(cat "$SERVICE_TOKEN_FILE")"

# Upload RPM and optional files
log "[$HOST] Preparing remote temp directory"
run_ssh "$HOST" "sudo mkdir -p '$REMOTE_TMP'"

log "[$HOST] Uploading elastic-agent RPM"
run_scp_to "$AGENT_RPM" "$HOST" "$REMOTE_TMP/"
AGENT_RPM_REMOTE="$REMOTE_TMP/$(basename "$AGENT_RPM")"

# TLS material
TLS_CERT_REMOTE=""
TLS_KEY_REMOTE=""

if [[ -n "$CA_FILE" ]]; then
  run_scp_to "$CA_FILE" "$HOST" "$REMOTE_TMP/"
  CA_REMOTE="$REMOTE_TMP/$(basename "$CA_FILE")"
fi

if [[ -n "$CERT" && -n "$KEY" ]]; then
  run_scp_to "$CERT" "$HOST" "$REMOTE_TMP/"
  run_scp_to "$KEY"  "$HOST" "$REMOTE_TMP/"
  TLS_CERT_REMOTE="$REMOTE_TMP/$(basename "$CERT")"
  TLS_KEY_REMOTE="$REMOTE_TMP/$(basename "$KEY")"
elif [[ -n "$P12" ]]; then
  require_cmd openssl
  run_scp_to "$P12" "$HOST" "$REMOTE_TMP/"
  P12_REMOTE="$REMOTE_TMP/$(basename "$P12")"
  # Convert P12 -> PEM on remote (cert + unencrypted key)
  log "[$HOST] Converting P12 to PEM cert/key on remote"
  run_ssh "$HOST" "sudo bash -lc '
    set -e
    umask 077
    openssl pkcs12 -in \"$P12_REMOTE\" -clcerts -nokeys -out \"$REMOTE_TMP/fleet.crt\" -passin pass:\"$P12_PASS\"
    openssl pkcs12 -in \"$P12_REMOTE\" -nocerts -nodes -out \"$REMOTE_TMP/fleet.key\" -passin pass:\"$P12_PASS\"
  '"
  TLS_CERT_REMOTE="$REMOTE_TMP/fleet.crt"
  TLS_KEY_REMOTE="$REMOTE_TMP/fleet.key"
fi

# Install/upgrade agent RPM
log "[$HOST] Installing/Upgrading elastic-agent RPM"
run_ssh "$HOST" "sudo rpm -Uvh --force '$AGENT_RPM_REMOTE' || sudo rpm -ivh '$AGENT_RPM_REMOTE'"

# Clean previous install (idempotent)
run_ssh "$HOST" "sudo elastic-agent uninstall -f >/dev/null 2>&1 || true; sudo rm -rf '$DATA_DIR' || true"

# Build args
CA_ARG=()
(( INSECURE==0 )) && CA_ARG=(--certificate-authorities "$CA_REMOTE") || CA_ARG=(--insecure)
TLS_ARGS=()
if [[ -n "$TLS_CERT_REMOTE" && -n "$TLS_KEY_REMOTE" ]]; then
  TLS_ARGS=(--fleet-server-cert "$TLS_CERT_REMOTE" --fleet-server-cert-key "$TLS_KEY_REMOTE")
fi

# Enroll as Fleet Server
log "[$HOST] Enrolling as Fleet Server"
run_ssh "$HOST" "sudo elastic-agent install \
  --url='$FLEET_URL' \
  --fleet-server-es='$ES_URL' \
  --fleet-server-service-token='$TOKEN' \
  ${CA_ARG[*]} \
  ${TLS_ARGS[*]} \
  --non-interactive" || { dump_journal "$HOST" "elastic-agent"; die "[$HOST] Fleet Server install failed"; }

# Wait for readiness
log "[$HOST] Waiting for elastic-agent to become healthy"
if ! retry 24 5 run_ssh "$HOST" "sudo elastic-agent status >/dev/null 2>&1"; then
  dump_journal "$HOST" "elastic-agent"
  die "[$HOST] elastic-agent did not become healthy"
fi

log "[$HOST] Fleet Server ready."
