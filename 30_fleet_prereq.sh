#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=00_common.sh
source "$SCRIPT_DIR/00_common.sh"

print_help() {
  cat <<'EOF'
Usage:
  30_fleet_prereq.sh \
    --es-url <https://es:9200> --es-user <user> --es-pass <pass> \
    --kibana-url <https://kib:5601> --kbn-user <user> --kbn-pass <pass> \
    --policy-name <name> \
    [--ca <path>] [--out-dir <dir>] [--ssh-user <user>]

What it does:
  - Initializes Fleet in Kibana (idempotent).
  - Creates a Fleet Server service token in Elasticsearch (idempotent; on 409 creates a new name with timestamp).
  - Ensures the Agent Policy exists in Kibana; creates it if missing.
  - Ensures an Enrollment Token exists for the policy; creates it if missing.
  - Saves tokens to --out-dir (default: ./secrets).

Examples:
  ./30_fleet_prereq.sh \
    --es-url https://es:9200 --es-user elastic --es-pass '***' \
    --kibana-url https://kib:5601 --kbn-user svc --kbn-pass '***' \
    --policy-name Observability-Default \
    --ca cfg/tls/ca.crt --out-dir ./secrets
EOF
  exit 0
}

[[ $# -eq 0 ]] && print_help
require_cmd curl jq

ES_URL="" ES_USER="" ES_PASS=""
KBN_URL="" KBN_USER="" KBN_PASS=""
CA_FILE="" OUT_DIR="./secrets" POLICY_NAME=""

ARGS=("$@")
# Pre-parse --ssh-user early (for consistency with other scripts, even though this one doesn’t SSH)
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
    --policy-name) POLICY_NAME="${ARGS[i+1]}"; ((i+=2));;
    --ca) CA_FILE="${ARGS[i+1]}"; ((i+=2));;
    --out-dir) OUT_DIR="${ARGS[i+1]}"; ((i+=2));;
    --help) print_help;;
    --ssh-user) ((i+=2));; # consumed above
    *) ((i+=1));;
  esac
done

# Require explicit policy name (safer than defaulting silently)
[[ -n "$ES_URL" && -n "$ES_USER" && -n "$ES_PASS" ]] || die "Missing ES connection args"
[[ -n "$KBN_URL" && -n "$KBN_USER" && -n "$KBN_PASS" ]] || die "Missing Kibana connection args"
[[ -n "$POLICY_NAME" ]] || die "Missing required --policy-name"

LOG_FILE="$LOG_DIR/$(date +%Y%m%d_%H%M%S)_30_fleet_prereq.log"
mkdir -p "$OUT_DIR"

# Helper: curl to Kibana with/without CA (no --fail so we can read body on 4xx)
_kbn_curl() {
  local method="$1"; shift
  local url="$1"; shift
  local data="${1:-}"
  local common=(-sS -X "$method" -u "$KBN_USER:$KBN_PASS" -H 'kbn-xsrf: true')
  [[ -n "$data" ]] && common+=(-H 'Content-Type: application/json' -d "$data")
  if [[ -n "$CA_FILE" ]]; then
    curl "${common[@]}" --cacert "$CA_FILE" "$url"
  else
    curl "${common[@]}" -k "$url"
  fi
}

# Helper: curl to ES with/without CA (no --fail)
_es_curl() {
  local method="$1"; shift
  local url="$1"; shift
  if [[ -n "$CA_FILE" ]]; then
    curl -sS -X "$method" -u "$ES_USER:$ES_PASS" --cacert "$CA_FILE" "$url"
  else
    curl -sS -k -X "$method" -u "$ES_USER:$ES_PASS" "$url"
  fi
}

log "Ensuring Fleet is initialized in Kibana"
SETUP_RESP="$(_kbn_curl POST "$KBN_URL/api/fleet/setup")" || true
# Optional: surface status if present
echo "$SETUP_RESP" | jq -r '.status // empty' >/dev/null 2>&1 || true

# Quick reachability check (optional)
if STATUS="$(_kbn_curl GET "$KBN_URL/api/status")"; then
  log "Kibana seems reachable (HTTP 200) – proceeding."
else
  warn "Kibana status endpoint check failed; continuing anyway."
fi

# 1) Ensure Fleet Server service token
log "Ensuring Fleet Server service token exists (service: elastic/fleet-server)"
BASE_NAME="fleet-server-service-token"
CREATE_URL="$ES_URL/_security/service/elastic/fleet-server/credential/token/$BASE_NAME"

# Attempt #1 with canonical name, capture HTTP code
RESP1="$(_es_curl POST "$CREATE_URL" || true)"
CODE1="$(echo "$RESP1" | jq -r '."status" // empty' 2>/dev/null || true)"
# Some clusters don’t echo 'status' in body; capture via -w if needed:
if [[ -z "$CODE1" ]]; then
  if [[ -n "$CA_FILE" ]]; then
    RESP_RAW="$(curl -sS -w '\n%{http_code}' -X POST -u "$ES_USER:$ES_PASS" --cacert "$CA_FILE" "$CREATE_URL" || true)"
  else
    RESP_RAW="$(curl -sS -w '\n%{http_code}' -k -X POST -u "$ES_USER:$ES_PASS" "$CREATE_URL" || true)"
  fi
  RESP1="$(echo "$RESP_RAW" | sed -n '1,$-1p')"
  CODE1="$(echo "$RESP_RAW" | tail -n1)"
fi

TOKEN_VAL=""
if [[ "$CODE1" == "201" ]]; then
  TOKEN_VAL="$(echo "$RESP1" | jq -r '.token.value // empty')"
elif [[ "$CODE1" == "409" ]]; then
  # Name already exists: create a new one with a timestamp suffix
  SUF="$(date +%Y%m%d%H%M%S)"
  NEW_NAME="${BASE_NAME}-${SUF}"
  CREATE_URL2="$ES_URL/_security/service/elastic/fleet-server/credential/token/$NEW_NAME"
  RESP2="$(_es_curl POST "$CREATE_URL2" || true)"
  TOKEN_VAL="$(echo "$RESP2" | jq -r '.token.value // empty')"
else
  # Could be 4xx/5xx; show body to the user
  error "Could not obtain Fleet Server service token. Response:"
  echo "[ES] $RESP1" >&2
  die "Aborting."
fi

[[ -n "$TOKEN_VAL" ]] || { error "Service token JSON did not include token.value"; die "Aborting."; }
echo -n "$TOKEN_VAL" > "$OUT_DIR/fleet_server_service_token"
chmod 600 "$OUT_DIR/fleet_server_service_token" || true
log "Saved Fleet Server service token -> $OUT_DIR/fleet_server_service_token"

# 2) Ensure Agent Policy
log "Ensuring agent policy '$POLICY_NAME' exists in Kibana"
LIST="$(_kbn_curl GET "$KBN_URL/api/fleet/agent_policies?perPage=100" || true)"
POLICY_ID="$(echo "$LIST" | jq -r --arg n "$POLICY_NAME" '.items[]?|select(.name==$n)|.id' | head -n1)"

if [[ -z "$POLICY_ID" || "$POLICY_ID" == "null" ]]; then
  BODY="$(jq -n --arg name "$POLICY_NAME" --arg ns "default" \
         '{name:$name, namespace:$ns, description:"Observability default (air-gapped)"}')"
  RESP="$(_kbn_curl POST "$KBN_URL/api/fleet/agent_policies" "$BODY" || true)"
  if ! echo "$RESP" | jq -e '.item.id' >/dev/null 2>&1; then
    error "Create policy failed. Response:"
    echo "[KIBANA] $RESP" >&2
    die "Aborting."
  fi
  POLICY_ID="$(echo "$RESP" | jq -r '.item.id')"
fi
[[ -n "$POLICY_ID" && "$POLICY_ID" != "null" ]] || die "Failed to ensure agent policy"

# 3) Ensure Enrollment Token for that policy
log "Ensuring enrollment token for policy id: $POLICY_ID"
TOKENS="$(_kbn_curl GET "$KBN_URL/api/fleet/enrollment_api_keys" || true)"
ENR_TOKEN="$(echo "$TOKENS" | jq -r --arg id "$POLICY_ID" '.list[]?|select(.policy_id==$id)|.api_key' | head -n1)"

if [[ -z "$ENR_TOKEN" || "$ENR_TOKEN" == "null" ]]; then
  BODY="$(jq -n --arg id "$POLICY_ID" '{policy_id:$id}')"
  RESP="$(_kbn_curl POST "$KBN_URL/api/fleet/enrollment_api_keys" "$BODY" || true)"
  if ! echo "$RESP" | jq -e '.item.api_key' >/dev/null 2>&1; then
    error "Create enrollment token failed. Response:"
    echo "[KIBANA] $RESP" >&2
    die "Aborting."
  fi
  ENR_TOKEN="$(echo "$RESP" | jq -r '.item.api_key')"
fi
[[ -n "$ENR_TOKEN" && "$ENR_TOKEN" != "null" ]] || die "Failed to obtain enrollment token"

OUT_TOKEN="$OUT_DIR/enrollment_token_${POLICY_ID}"
echo -n "$ENR_TOKEN" > "$OUT_TOKEN"
chmod 600 "$OUT_TOKEN" || true
log "Saved Enrollment Token -> $OUT_TOKEN"

log "Fleet prerequisites completed successfully."
