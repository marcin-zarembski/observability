#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/00_common.sh"

print_help() {
  cat <<'EOF'
Usage:
  31_fleet_server_install_local.sh --agent-tar <path> \
    --es-url <https://es:9200> --fleet-url <https://fleet:8220> \
    --service-token-file <file> (--ca <path> | --insecure) \
    --kbn-url <https://kibana:5601> --kbn-user <user> --kbn-pass <pass> \
    [--kbn-ca <pem> | --kbn-insecure] \
    [--cert <crt> --key <key>] \
    [--policy-name <name>] [--stack-version <ver>]

What it does:
  - Installs/updates elastic-agent from tar.gz locally.
  - Ensures a Fleet Server policy exists in Kibana (creates if missing).
  - Enrolls the agent as Fleet Server using that policy.
  - Waits for agent to become healthy.

EOF
  exit 0
}

[[ $# -eq 0 ]] && print_help

require_cmd tar curl jq

AGENT_TAR="" ES_URL="" FLEET_URL="" SERVICE_TOKEN_FILE=""
CA_FILE="" INSECURE=0 CERT="" KEY=""
KBN_URL="" KBN_USER="" KBN_PASS="" KBN_CA="" KBN_INSECURE=0
POLICY_NAME="Fleet Server Policy" STACK_VERSION="8.18.3"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent-tar) AGENT_TAR="$2"; shift 2;;
    --es-url) ES_URL="$2"; shift 2;;
    --fleet-url) FLEET_URL="$2"; shift 2;;
    --service-token-file) SERVICE_TOKEN_FILE="$2"; shift 2;;
    --ca) CA_FILE="$2"; shift 2;;
    --insecure) INSECURE=1; shift 1;;
    --cert) CERT="$2"; shift 2;;
    --key) KEY="$2"; shift 2;;
    --kbn-url) KBN_URL="$2"; shift 2;;
    --kbn-user) KBN_USER="$2"; shift 2;;
    --kbn-pass) KBN_PASS="$2"; shift 2;;
    --kbn-ca) KBN_CA="$2"; shift 2;;
    --kbn-insecure) KBN_INSECURE=1; shift 1;;
    --policy-name) POLICY_NAME="$2"; shift 2;;
    --stack-version) STACK_VERSION="$2"; shift 2;;
    --help) print_help;;
    *) die "Unknown arg: $1";;
  esac
done

[[ -f "$AGENT_TAR" && -n "$ES_URL" && -n "$FLEET_URL" && -f "$SERVICE_TOKEN_FILE" ]] || die "Missing required arguments"
if (( INSECURE==0 )) && [[ -z "$CA_FILE" ]]; then die "Provide --ca or --insecure"; fi
[[ -n "$KBN_URL" && -n "$KBN_USER" && -n "$KBN_PASS" ]] || die "Need Kibana URL/user/pass"

TOKEN="$(cat "$SERVICE_TOKEN_FILE")"
WORK_DIR="/opt/Elastic/Agent"
sudo mkdir -p "$WORK_DIR"
sudo tar -xzf "$AGENT_TAR" -C "$WORK_DIR" --strip-components=1

# --- Ensure Fleet Server policy exists ---
log "[local] Checking/creating Fleet Server policy '$POLICY_NAME'"
KBN_CURL_OPTS=(-s -u "$KBN_USER:$KBN_PASS" -H 'kbn-xsrf: true')
(( KBN_INSECURE )) && KBN_CURL_OPTS+=(-k) || true
[[ -n "$KBN_CA" ]] && KBN_CURL_OPTS+=(--cacert "$KBN_CA")

POLICY_ID=$(curl "${KBN_CURL_OPTS[@]}" \
  "$KBN_URL/api/fleet/agent_policies" | jq -r --arg NAME "$POLICY_NAME" '.items[] | select(.name==$NAME) | .id' || true)

if [[ -z "$POLICY_ID" ]]; then
  log "[local] Creating new Fleet Server policy"
  POLICY_ID=$(curl "${KBN_CURL_OPTS[@]}" -X POST \
    "$KBN_URL/api/fleet/agent_policies" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"$POLICY_NAME\",\"namespace\":\"default\",\"is_default_fleet_server\":true}" \
    | jq -r '.item.id')
  [[ -z "$POLICY_ID" ]] && die "Failed to create Fleet Server policy"
fi
log "[local] Using Fleet Server policy ID: $POLICY_ID"

# --- Install agent ---
sudo "$WORK_DIR/elastic-agent" uninstall -f >/dev/null 2>&1 || true
sudo rm -rf /var/lib/elastic-agent || true

CA_ARG=()
(( INSECURE==0 )) && CA_ARG=(--certificate-authorities "$CA_FILE") || CA_ARG=(--insecure)
TLS_ARGS=()
if [[ -n "$CERT" && -n "$KEY" ]]; then
  TLS_ARGS=(--fleet-server-cert "$CERT" --fleet-server-cert-key "$KEY")
fi

log "[local] Enrolling as Fleet Server"
sudo "$WORK_DIR/elastic-agent" install \
  --url="$FLEET_URL" \
  --fleet-server-es="$ES_URL" \
  --fleet-server-service-token="$TOKEN" \
  --fleet-server-policy="$POLICY_ID" \
  "${CA_ARG[@]}" \
  "${TLS_ARGS[@]}" \
  --non-interactive || { dump_journal "localhost" "elastic-agent"; die "Fleet Server install failed"; }

log "[local] Waiting for elastic-agent to become healthy"
if ! retry 24 5 sudo "$WORK_DIR/elastic-agent" status >/dev/null 2>&1; then
  dump_journal "localhost" "elastic-agent"
  die "elastic-agent did not become healthy"
fi

log "[local] Fleet Server ready."
