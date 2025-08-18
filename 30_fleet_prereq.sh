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
    --kibana-url <https://kib:5601> [--kbn-user <user>] [--kbn-pass <pass>] \
    [--ca <path>] [--policy-name <name>] [--out-dir <dir>] [--ssh-user <user>]

What it does:
  0) Ensures Kibana Fleet is initialized (idempotent):
       - checks a simple Fleet endpoint; if not OK -> POST /api/fleet/setup
  1) Ensures Fleet Server service token exists in Elasticsearch (POST).
  2) Ensures Agent Policy exists in Kibana (create if missing).
  3) Ensures Enrollment Token for that policy (create if missing).
  4) Saves tokens into --out-dir (default: ./secrets).

Notes:
  - If --kbn-user/--kbn-pass are omitted, ES creds (--es-user/--es-pass) are reused.

Examples:
  ./30_fleet_prereq.sh \
    --es-url https://es:9200 --es-user elastic --es-pass '***' \
    --kibana-url https://kib:5601 \
    --ca cfg/tls/ca.crt --policy-name Observability-Default --out-dir ./secrets
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
# Pre-capture --ssh-user (affects SSH helpers if ever used)
for ((i=0;i<${#ARGS[@]};i++)); do
  case "${ARGS[i]}" in --ssh-user) export DEFAULT_SSH_USER="${ARGS[i+1]}";; esac
done

# Parse args
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
    --ssh-user) ((i+=2));; # consumed above
    *) ((i+=1));;
  esac
done

# Validate required inputs
[[ -n "$ES_URL" && -n "$ES_USER" && -n "$ES_PASS" ]] || die "Missing --es-url/--es-user/--es-pass"
[[ -n "$KBN_URL" ]] || die "Missing --kibana-url"
# Reuse ES creds for Kibana if not provided
[[ -n "$KBN_USER" ]] || KBN_USER="$ES_USER"
[[ -n "$KBN_PASS" ]] || KBN_PASS="$ES_PASS"

LOG_FILE="$LOG_DIR/$(date +%Y%m%d_%H%M%S)_30_fleet_prereq.log"
mkdir -p "$OUT_DIR"

# Helper: curl to Kibana with/without CA and capture HTTP code
_kbn_http_code() {
  local method="$1" url="$2"; shift 2
  local hdrs=(-H "kbn-xsrf: true")
  if [[ -n "$CA_FILE" ]]; then
    curl -sS -o /dev/null -w "%{http_code}" -X "$method" --user "$KBN_USER:$KBN_PASS" --cacert "$CA_FILE" "${hdrs[@]}" "$url" "$@"
  else
    curl -sS -k -o /dev/null -w "%{http_code}" -X "$method" --user "$KBN_USER:$KBN_PASS" "${hdrs[@]}" "$url" "$@"
  fi
}

_kbn_call() {
  # _kbn_call <METHOD> <URL> [DATA]
  local method="$1" url="$2" data="${3:-}"
  local common=(-H "kbn-xsrf: true")
  [[ -n "$data" ]] && common+=(-H "Content-Type: application/json" -d "$data")
  if [[ -n "$CA_FILE" ]]; then
    curl -sS -X "$method" --user "$KBN_USER:$KBN_PASS" --cacert "$CA_FILE" "${common[@]}" "$url"
  else
    curl -sS -k -X "$method" --user "$KBN_USER:$KBN_PASS" "${common[@]}" "$url"
  fi
}

_es_post() {
  # _es_post <URL>
  local url="$1"
  if [[ -n "$CA_FILE" ]]; then
    curl -sS -X POST --user "$ES_USER:$ES_PASS" --cacert "$CA_FILE" "$url"
  else
    curl -sS -k -X POST --user "$ES_USER:$ES_PASS" "$url"
  fi
}

log "Ensuring Fleet is initialized in Kibana"
# Quick probe: a simple Fleet endpoint. If not 2xx -> run setup.
probe_code="$(_kbn_http_code GET "$KBN_URL/api/fleet/agents?perPage=1")" || probe_code="000"
if [[ "$probe_code" =~ ^2[0-9][0-9]$ ]]; then
  log "Fleet seems reachable (HTTP $probe_code) – proceeding."
else
  log "Fleet not initialized or unreachable (probe HTTP $probe_code) – running /api/fleet/setup"
  SETUP_RESP="$(_kbn_call POST "$KBN_URL/api/fleet/setup")" || true
  # Not fatal if already initialized; log response for visibility
  echo "$SETUP_RESP" | jq -r '.status, .isInitialized? // empty' 2>/dev/null | sed 's/^/[KIBANA setup] /' || true
fi

# 1) Ensure Fleet Server service token
log "Ensuring Fleet Server service token exists (service: elastic/fleet-server)"
NAME="fleet-server-service-token"
CREATE_URL="$ES_URL/_security/service/elastic/fleet-server/credential/token/$NAME"
RESP="$(_es_post "$CREATE_URL" || true)"
TOKEN_VAL="$(echo "$RESP" | jq -r '.token.value // empty')"
if [[ -z "$TOKEN_VAL" ]]; then
  error "Could not obtain Fleet Server service token. Response:"
  echo "$RESP" | sed 's/^/[ES] /' >&2
  die "Aborting."
fi
echo -n "$TOKEN_VAL" > "$OUT_DIR/fleet_server_service_token"
log "Saved: $OUT_DIR/fleet_server_service_token"

# 2) Ensure Agent Policy
log "Ensuring agent policy '$POLICY_NAME' exists in Kibana"
LIST="$(_kbn_call GET "$KBN_URL/api/fleet/agent_policies?perPage=100" || true)"
POLICY_ID="$(echo "$LIST" | jq -r --arg n "$POLICY_NAME" '.items[]?|select(.name==$n)|.id' | head -n1)"

if [[ -z "$POLICY_ID" || "$POLICY_ID" == "null" ]]; then
  log "Creating Fleet policy $POLICY_NAME"
  BODY="$(jq -n --arg name "$POLICY_NAME" --arg ns "default" '{name:$name, namespace:$ns, description:"Observability default (air-gapped)"}')"
  RESP="$(_kbn_call POST "$KBN_URL/api/fleet/agent_policies" "$BODY" || true)"
  if ! echo "$RESP" | jq -e '.item.id' >/dev/null 2>&1; then
    error "Create policy failed. Response:"
    echo "$RESP" | sed 's/^/[KIBANA] /' >&2
    die "Aborting."
  fi
  POLICY_ID="$(echo "$RESP" | jq -r '.item.id')"
fi
[[ -n "$POLICY_ID" && "$POLICY_ID" != "null" ]] || die "Failed to ensure agent policy"

# 3) Ensure Enrollment Token for that policy
log "Ensuring enrollment token for policy id: $POLICY_ID"
TOKENS="$(_kbn_call GET "$KBN_URL/api/fleet/enrollment_api_keys" || true)"
ENR_TOKEN="$(echo "$TOKENS" | jq -r --arg id "$POLICY_ID" '.list[]?|select(.policy_id==$id)|.api_key' | head -n1)"
if [[ -z "$ENR_TOKEN" || "$ENR_TOKEN" == "null" ]]; then
  BODY="$(jq -n --arg id "$POLICY_ID" '{policy_id:$id}')"
  RESP="$(_kbn_call POST "$KBN_URL/api/fleet/enrollment_api_keys" "$BODY" || true)"
  ENR_TOKEN="$(echo "$RESP" | jq -r '.item.api_key')"
fi
[[ -n "$ENR_TOKEN" && "$ENR_TOKEN" != "null" ]] || die "Failed to obtain enrollment token"

OUT_TOKEN="$OUT_DIR/enrollment_token_${POLICY_ID}"
echo -n "$ENR_TOKEN" > "$OUT_TOKEN"
log "Saved: $OUT_TOKEN"

log "Fleet prerequisites ready."
