#!/usr/bin/env bash
# 31_fleet_server_install.sh — Install local Fleet Server from tar.gz (no SSH)
# - Runs entirely on the local machine
# - Uses Elastic Agent tar.gz installer
# - Supports TLS via PEM (CA+cert+key) or P12 (converted locally)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=00_common.sh
source "$SCRIPT_DIR/00_common.sh"

print_help() {
  cat <<'EOF'
Usage:
  31_fleet_server_install.sh \
    --agent-tar <elastic-agent-8.18.3-linux-x86_64.tar.gz> \
    --es-url <https://es:9200> \
    --fleet-url <https://this-host:8220> \
    --service-token-file <file> \
    (--ca <path> | --insecure) \
    [ --cert <fleet.crt> --key <fleet.key> | --p12 <fleet.p12> --p12-pass <pass> ] \
    [--data-dir </var/lib/elastic-agent>] [--workdir </tmp>]

What it does:
  - Extracts Elastic Agent tar.gz locally and installs Fleet Server (no rpm, no ssh).
  - Uses either PEM cert+key (+CA) or converts P12 -> PEM locally.
  - Waits for agent to become healthy; prints diagnostics on failure.

Examples:
  PEM:
    ./31_fleet_server_install.sh \
      --agent-tar ./artifacts/elastic-agent-8.18.3-linux-x86_64.tar.gz \
      --es-url https://es01:9200 \
      --fleet-url https://$(hostname -f):8220 \
      --service-token-file ./secrets/fleet_server_service_token \
      --ca /etc/kibana/fleet/certs/ca.pem \
      --cert /etc/kibana/fleet/certs/cert.pem \
      --key  /etc/kibana/fleet/certs/key.pem

  P12:
    ./31_fleet_server_install.sh \
      --agent-tar ./artifacts/elastic-agent-8.18.3-linux-x86_64.tar.gz \
      --es-url https://es01:9200 \
      --fleet-url https://$(hostname -f):8220 \
      --service-token-file ./secrets/fleet_server_service_token \
      --ca /etc/kibana/fleet/certs/ca.pem \
      --p12 ./cfg/tls/fleet.p12 --p12-pass 'secret'
EOF
  exit 0
}

[[ $# -eq 0 ]] && print_help
require_cmd tar

# Args
AGENT_TAR="" ES_URL="" FLEET_URL="" SERVICE_TOKEN_FILE=""
CA_FILE="" INSECURE=0 DATA_DIR="/var/lib/elastic-agent" WORKDIR="/tmp"
CERT="" KEY="" P12="" P12_PASS="" KEEP_WORKDIR=0

ARGS=("$@")
i=0
while [[ $i -lt ${#ARGS[@]} ]]; do
  case "${ARGS[i]}" in
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
    --workdir) WORKDIR="${ARGS[i+1]}"; ((i+=2));;
    --keep-workdir) KEEP_WORKDIR=1; ((i+=1));;
    --help|-h) print_help;;
    *) ((i+=1));;
  esac
done

# Validate inputs
[[ -f "$AGENT_TAR" && -n "$ES_URL" && -n "$FLEET_URL" && -f "$SERVICE_TOKEN_FILE" ]] || die "Missing required arguments"
if (( INSECURE==0 )) && [[ -z "$CA_FILE" ]]; then die "Provide --ca or --insecure"; fi
if [[ -n "$P12" || -n "$P12_PASS" ]]; then [[ -f "$P12" && -n "$P12_PASS" ]] || die "Provide both --p12 and --p12-pass"; fi
if [[ -n "$CERT" || -n "$KEY" ]]; then [[ -f "$CERT" && -f "$KEY" ]] || die "Provide both --cert and --key"; fi
if [[ -n "$P12" && ( -n "$CERT" || -n "$KEY" ) ]]; then die "Use either PEM (--cert/--key) or P12 (--p12/--p12-pass), not both"; fi

LOG_FILE="$LOG_DIR/$(date +%Y%m%d_%H%M%S)_31_fleet_server_install_local.log"
TOKEN="$(cat "$SERVICE_TOKEN_FILE")"

# Prepare local workdir
TS="$(date +%s)"
WORKDIR_LOCAL="$WORKDIR/ea-install-$TS"
log "[local] Using workdir: $WORKDIR_LOCAL"
sudo mkdir -p "$WORKDIR_LOCAL"
sudo chown $(id -u):$(id -g) "$WORKDIR_LOCAL" || true

# Copy CA/cert/key/P12 into workdir (only those provided)
CA_LOCAL="" TLS_CERT_LOCAL="" TLS_KEY_LOCAL=""
if (( INSECURE==0 )); then
  CA_LOCAL="$WORKDIR_LOCAL/$(basename "$CA_FILE")"
  cp "$CA_FILE" "$CA_LOCAL"
fi
if [[ -n "$CERT" && -n "$KEY" ]]; then
  TLS_CERT_LOCAL="$WORKDIR_LOCAL/$(basename "$CERT")"
  TLS_KEY_LOCAL="$WORKDIR_LOCAL/$(basename "$KEY")"
  cp "$CERT" "$TLS_CERT_LOCAL"; cp "$KEY" "$TLS_KEY_LOCAL"
elif [[ -n "$P12" ]]; then
  require_cmd openssl
  P12_LOCAL="$WORKDIR_LOCAL/$(basename "$P12")"
  cp "$P12" "$P12_LOCAL"
  log "[local] Converting P12 to PEM cert/key locally"
  ( cd "$WORKDIR_LOCAL" && umask 077 && \
    openssl pkcs12 -in "$P12_LOCAL" -clcerts -nokeys -out fleet.crt -passin pass:"$P12_PASS" && \
    openssl pkcs12 -in "$P12_LOCAL" -nocerts -nodes -out fleet.key -passin pass:"$P12_PASS" )
  TLS_CERT_LOCAL="$WORKDIR_LOCAL/fleet.crt"
  TLS_KEY_LOCAL="$WORKDIR_LOCAL/fleet.key"
fi

# Extract tar.gz locally
log "[local] Extracting agent tar.gz"
sudo tar -xzf "$AGENT_TAR" -C "$WORKDIR_LOCAL"
EA_DIR_LOCAL="$(find "$WORKDIR_LOCAL" -maxdepth 1 -type d -name 'elastic-agent*' | head -n1)"
[[ -n "$EA_DIR_LOCAL" ]] || die "Could not locate extracted elastic-agent directory"

# Clean previous install (idempotent)
log "[local] Removing previous agent (if any) and data dir"
sudo elastic-agent uninstall -f >/dev/null 2>&1 || true
sudo rm -rf "$DATA_DIR" || true

# Build args
CA_ARG=()
(( INSECURE==0 )) && CA_ARG=(--certificate-authorities "$CA_LOCAL") || CA_ARG=(--insecure)
TLS_ARGS=()
if [[ -n "$TLS_CERT_LOCAL" && -n "$TLS_KEY_LOCAL" ]]; then
  TLS_ARGS=(--fleet-server-cert "$TLS_CERT_LOCAL" --fleet-server-cert-key "$TLS_KEY_LOCAL")
fi

# Enroll as Fleet Server
log "[local] Installing Fleet Server from tar.gz"
sudo bash -lc "cd '$EA_DIR_LOCAL' && ./elastic-agent install \
  --url='$FLEET_URL' \
  --fleet-server-es='$ES_URL' \
  --fleet-server-service-token='$TOKEN' \
  ${CA_ARG[*]} \
  ${TLS_ARGS[*]} \
  --non-interactive"

# Wait for readiness
log "[local] Waiting for elastic-agent to become healthy"
if ! retry 24 5 sudo elastic-agent status >/dev/null 2>&1; then
  dump_journal_local "elastic-agent"
  die "[local] elastic-agent did not become healthy"
fi

# Cleanup
if (( KEEP_WORKDIR==0 )); then
  log "[local] Cleaning up workdir $WORKDIR_LOCAL"
  sudo rm -rf "$WORKDIR_LOCAL" || true
fi

log "[local] Fleet Server ready."
