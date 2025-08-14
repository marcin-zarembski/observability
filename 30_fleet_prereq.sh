#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/00_common.sh"

print_help() {
  cat <<'EOF'
Usage:
  30_fleet_prereq.sh --es-url <https://es:9200> --es-user <user> --es-pass <pass> \
    --kibana-url <https://kib:5601> --kbn-user <user> --kbn-pass <pass> \
    [--ca <path>] [--policy-name <name>] [--out-dir <dir>] [--ssh-user <user>]

What it does:
  - Ensures Fleet Server service token exists in Elasticsearch; stores it locally.
  - Ensures Agent Policy exists in Kibana; fetches/creates an Enrollment Token; stores it locally.

Options:
  --policy-name <name>    Default: Observability-Default
  --out-dir <dir>         Default: ./secrets

Examples:
  ./30_fleet_prereq.sh --es-url https://es:9200 --es-user svc --es-pass '***' \
    --kibana-url https://kib:5601 --kbn-user svc --kbn-pass '***' --ca cfg/tls/ca.crt
EOF
  exit 0
}

[[ $# -eq 0 ]] && print_help

require_cmd curl jq

ES_URL="" ES_USER="" ES_PASS=""
KBN_URL="" KBN_USER="" KBN_PASS=""
CA_FILE=""
POLICY_NAME="Observability-Default"
OUT_DIR="./secrets"

ARGS=("$@")
# Pre-parse to capture --ssh-user early
for ((i=0;i<${#ARGS[@]};i++)); do
  case "${ARGS[i]}" in --ssh-user) export DEFAULT_SSH_USER="${ARGS[i+1]}";; esac
done

i=0
while [[ $i -lt ${#ARGS[@]} ]]; do
  case "${ARGS[i]}" in
    --es-url) ES_URL="${ARGS[i+1]}"; ((i+=2));;
    --es-user) ES_USER="${ARGS[i+1]}"; ((i+=2));;
    --es-pass) ES_PASS="${ARGS[i+1]}"; ((i+=2));;
    --kibana-url) KBN_URL="${ARGS[i+1]}"; ((i+=2));;
    --kbn-user) KBN_USER="${ARGS[i+1]}"; ((i+=2));;
    --kbn-pass) KBN_PASS="${ARGS[i+1]}"; ((i+=2));;
    --ca) CA_FILE="${ARGS[i+1]}"; ((i+=2));;
    --policy-name) POLICY_NAME="${ARGS[i+1]}"; ((i+=2));;
    --out-dir) OUT_DIR="${ARGS[i+1]}"; ((i+=2));;
    --help) print_help;;
    --ssh-user) ((i+=2));; # already consumed
    *) ((i+=1));;
  esac
done

LOG_FILE="$LOG_DIR/$(date +%Y%m%d_%H%M%S)_30_fleet_prereq.log"
mkdir -p "$OUT_DIR"

# 1) Ensure Fleet Server service token (named)
log "Ensuring Fleet Server service token exists (service: elastic/fleet-server)"
NAME="fleet-server-service-token"
CREATE_URL="$ES_URL/_security/service/elastic/fleet-server/credential/token/$NAME"
RESP="$(curl_es "$CREATE_URL" "$ES_USER" "$ES_PASS" "$CA_FILE" || true)"
TOKEN_VAL="$(echo "$RESP" | jq -r '.token.value // empty')"
[[ -n "$TOKEN_VAL" ]] || die "Could not obtain Fleet Server service token from $CREATE_URL"
echo -n "$TOKEN_VAL" > "$OUT_DIR/fleet_server_service_token"
log "Saved: $OUT_DIR/fleet_server_service_token"

# 2) Ensure Agent Policy and Enrollment Token
log "Ensuring agent policy '$POLICY_NAME' exists in Kibana"
LIST="$(curl_kbn_json GET "$KBN_URL/api/fleet/agent_policies?perPage=100" "$KBN_USER" "$KBN_PASS" "$CA_FILE" || true)"
POLICY_ID="$(echo "$LIST" | jq -r --arg n "$POLICY_NAME" '.items[]?|select(.name==$n)|.id' | head -n1)"
if [[ -z "$POLICY_ID" || "$POLICY_ID" == "null" ]]; then
  BODY="$(jq -n --arg name "$POLICY_NAME" --arg ns "default" '{name:$name, namespace:$ns, description:"Observability default (air-gapped)"}')"
  RESP="$(curl_kbn_json POST "$KBN_URL/api/fleet/agent_policies" "$KBN_USER" "$KBN_PASS" "$CA_FILE" "$BODY")"
  POLICY_ID="$(echo "$RESP" | jq -r '.item.id')"
fi
[[ -n "$POLICY_ID" && "$POLICY_ID" != "null" ]] || die "Failed to ensure agent policy"

log "Ensuring enrollment token for policy id: $POLICY_ID"
TOKENS="$(curl_kbn_json GET "$KBN_URL/api/fleet/enrollment_api_keys" "$KBN_USER" "$KBN_PASS" "$CA_FILE" || true)"
ENR_TOKEN="$(echo "$TOKENS" | jq -r --arg id "$POLICY_ID" '.list[]?|select(.policy_id==$id)|.api_key' | head -n1)"
if [[ -z "$ENR_TOKEN" || "$ENR_TOKEN" == "null" ]]; then
  BODY="$(jq -n --arg id "$POLICY_ID" '{policy_id:$id}')"
  RESP="$(curl_kbn_json POST "$KBN_URL/api/fleet/enrollment_api_keys" "$KBN_USER" "$KBN_PASS" "$CA_FILE" "$BODY")"
  ENR_TOKEN="$(echo "$RESP" | jq -r '.item.api_key')"
fi
[[ -n "$ENR_TOKEN" && "$ENR_TOKEN" != "null" ]] || die "Failed to obtain enrollment token"

OUT_TOKEN="$OUT_DIR/enrollment_token_${POLICY_ID}"
echo -n "$ENR_TOKEN" > "$OUT_TOKEN"
log "Saved: $OUT_TOKEN"

log "Fleet prerequisites ready."
