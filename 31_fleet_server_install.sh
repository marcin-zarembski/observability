#!/usr/bin/env bash
# 31_fleet_server_install.sh — Install local Fleet Server from tar.gz (no SSH)
# - Runs on the local machine
# - Uses Elastic Agent tar.gz installer
# - Ensures a Fleet policy with Fleet Server integration exists (via Kibana API)
# - Supports TLS via PEM (CA+cert+key) or P12 (converted locally)
# - Supports custom tags via repeated --tag

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
    --kbn-url <https://kibana:5601> --kbn-user <user> --kbn-pass <pass> \
    [--kbn-ca <kibana-ca.pem> | --kbn-insecure] \
    [--policy-name "Fleet Server Policy"] \
    [--data-dir </var/lib/elastic-agent>] [--workdir </tmp>] [--keep-workdir] \
    [--tag <tag>]...

What it does:
  - Extracts Elastic Agent tar.gz and installs Fleet Server locally (no rpm, no ssh).
  - Ensures a Fleet policy exists in Kibana and has the Fleet Server integration (creates if missing).
  - Uses either PEM cert+key (+CA) or converts P12 -> PEM locally.
  - Supports custom tags for the agent (--tag can be used multiple times).
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
      --key  /etc/kibana/fleet/certs/key.pem \
      --kbn-url https://$(hostname -f):5601 --kbn-user elastic --kbn-pass '***' --kbn-insecure \
      --policy-name "Fleet Server Policy" \
      --tag prod --tag mars
EOF
  exit 0
}

[[ $# -eq 0 ]] && print_help
require_cmd tar curl jq

# Args
AGENT_TAR="" ES_URL="" FLEET_URL="" SERVICE_TOKEN_FILE=""
CA_FILE="" INSECURE=0 DATA_DIR="/var/lib/elastic-agent" WORKDIR="/tmp"
CERT="" KEY="" P12="" P12_PASS="" KEEP_WORKDIR=0
# Kibana / policy
KBN_URL="" KBN_USER="" KBN_PASS="" KBN_CA="" KBN_INSECURE=0
POLICY_NAME="Fleet Server Policy"
# Tags
TAGS=()

# Parse
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
    --kbn-url) KBN_URL="${ARGS[i+1]}"; ((i+=2));;
    --kbn-user) KBN_USER="${ARGS[i+1]}"; ((i+=2));;
    --kbn-pass) KBN_PASS="${ARGS[i+1]}"; ((i+=2));;
    --kbn-ca)   KBN_CA="${ARGS[i+1]}"; ((i+=2));;
    --kbn-insecure) KBN_INSECURE=1; ((i+=1));;
    --policy-name) POLICY_NAME="${ARGS[i+1]}"; ((i+=2));;
    --tag) TAGS+=("${ARGS[i+1]}"); ((i+=2));;
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
[[ -n "$KBN_URL" && -n "$KBN_USER" && -n "$KBN_PASS" ]] || die "Provide --kbn-url, --kbn-user and --kbn-pass"

LOG_FILE="$LOG_DIR/$(date +%Y%m%d_%H%M%S)_31_fleet_server_install_local.log"
TOKEN="$(cat "$SERVICE_TOKEN_FILE")"

# Prepare local workdir
TS="$(date +%s)"
WORKDIR_LOCAL="$WORKDIR/ea-install-$TS"
log "[local] Using workdir: $WORKDIR_LOCAL"
sudo mkdir -p "$WORKDIR_LOCAL"
sudo chown "$(id -u)":"$(id -g)" "$WORKDIR_LOCAL" || true

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

# --- Ensure Fleet policy with Fleet Server integration exists via Kibana API ---
log "[local] Ensuring Fleet policy with Fleet Server integration exists in Kibana"
KBN_CURL_OPTS=(-sS -u "$KBN_USER:$KBN_PASS" -H 'kbn-xsrf: true' -H 'Content-Type: application/json')
(( KBN_INSECURE )) && KBN_CURL_OPTS+=(-k) || true
[[ -n "$KBN_CA" ]] && KBN_CURL_OPTS+=(--cacert "$KBN_CA")

# 1) Find policy by name (or create)
POLICIES_JSON="$(curl "${KBN_CURL_OPTS[@]}" "$KBN_URL/api/fleet/agent_policies")" || die "Failed to list agent policies"
POLICY_ID="$(jq -r --arg n "$POLICY_NAME" '.items[]? | select(.name==$n) | .id' <<<"$POLICIES_JSON" | head -n1 || true)"

if [[ -z "${POLICY_ID:-}" || "$POLICY_ID" == "null" ]]; then
  log "[local] Creating policy '$POLICY_NAME'"
  read -r -d '' CREATE_POLICY_BODY <<JSON
{
  "name":"$POLICY_NAME",
  "namespace":"default",
  "description":"Auto-created by installer",
  "monitoring_enabled":["logs","metrics"],
  "is_default_fleet_server": true
}
JSON
  CREATE_RESP="$(curl "${KBN_CURL_OPTS[@]}" -X POST "$KBN_URL/api/fleet/agent_policies" -d "$CREATE_POLICY_BODY")" || die "Create policy failed"
  POLICY_ID="$(jq -r '.item.id // empty' <<<"$CREATE_RESP")"
  [[ -n "$POLICY_ID" ]] || die "Failed to parse created policy id: $CREATE_RESP"
else
  log "[local] Using existing policy '$POLICY_NAME' (id=$POLICY_ID)"
fi

# 2) Ensure fleet_server package is installed (best-effort)
PKG_INFO="$(curl "${KBN_CURL_OPTS[@]}" "$KBN_URL/api/fleet/epm/packages/fleet_server" || true)"
PKG_VER="$(jq -r '.item.version // .version // empty' <<<"$PKG_INFO" || true)"
if [[ -n "$PKG_VER" ]]; then
  log "[local] Ensuring package fleet_server@$PKG_VER is installed"
  curl "${KBN_CURL_OPTS[@]}" -X POST "$KBN_URL/api/fleet/epm/packages/fleet_server/$PKG_VER" -d '{"force":true}' >/dev/null || true
fi

# 3) Check if policy already has Fleet Server integration
POLICY_DETAIL_JSON="$(curl "${KBN_CURL_OPTS[@]}" "$KBN_URL/api/fleet/agent_policies/$POLICY_ID")" || die "Failed to read policy details"
HAS_FS_ID="$(jq -r '[.item.package_policies[]? | select(.package.name=="fleet_server") | .id][0] // ""' <<<"$POLICY_DETAIL_JSON")"

# 4) If missing, add Fleet Server package policy
if [[ -z "$HAS_FS_ID" ]]; then
  log "[local] Adding Fleet Server integration to policy '$POLICY_NAME'"
  FS_PP_NAME="fleet-server-$(hostname -s)-$TS"
  read -r -d '' ADD_PP_BODY <<JSON
{
  "name": "$FS_PP_NAME",
  "namespace": "default",
  "policy_id": "$POLICY_ID",
  "package": { "name": "fleet_server" }
}
JSON
  ADD_PP_RESP="$(curl "${KBN_CURL_OPTS[@]}" -X POST "$KBN_URL/api/fleet/package_policies" -d "$ADD_PP_BODY")" || die "Add package policy failed"
  PP_ID="$(jq -r '.item.id // empty' <<<"$ADD_PP_RESP")"
  [[ -n "$PP_ID" ]] || die "Failed to add Fleet Server integration: $ADD_PP_RESP"
else
  log "[local] Policy already contains Fleet Server integration (package policy id=$HAS_FS_ID)"
fi

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
TAG_ARGS=()
for t in "${TAGS[@]}"; do
  TAG_ARGS+=(--tag "$t")
done

# Enroll as Fleet Server with explicit policy
log "[local] Installing Fleet Server from tar.gz (policy '$POLICY_NAME', id=$POLICY_ID)"
sudo bash -lc "cd '$EA_DIR_LOCAL' && ./elastic-agent install \
  --url='$FLEET_URL' \
  --fleet-server-es='$ES_URL' \
  --fleet-server-service-token='$TOKEN' \
  --fleet-server-policy='$POLICY_ID' \
  ${CA_ARG[*]} \
  ${TLS_ARGS[*]} \
  ${TAG_ARGS[*]} \
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
