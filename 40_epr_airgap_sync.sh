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
    [--kibana-url <https://kib:5601>] \
    [--policy-name <name>] \
    [--kbn-user <user>] [--kbn-pass <pass>] \
    [--ca <path>] [--out-dir <dir>] [--ssh-user <user>]

What it does:
  - Initializes Fleet in Kibana (idempotent).
  - Creates a Fleet Server service token in Elasticsearch (idempotent; on 409 retries with timestamped name).
  - Ensures the Agent Policy exists in Kibana; creates it if missing.
  - Ensures an Enrollment Token exists for that policy; creates it if missing.
  - Saves tokens to --out-dir (default: ./secrets).

Notes:
  - If --kbn-user/--kbn-pass are not provided, the script will use --es-user/--es-pass for Kibana API calls.
  - If --policy-name is not provided, it defaults to "observability-default".
  - If --kibana-url is not provided, it defaults to the same host as --es-url but with port 5601.

Examples:
  ./30_fleet_prereq.sh \
    --es-url https://es:9200 --es-user elastic --es-pass '***' \
    --ca cfg/tls/ca.crt --out-dir ./secrets
EOF
  exit 0
}

[[ $# -eq 0 ]] && print_help
require_cmd curl jq

ES_URL="" ES_USER="" ES_PASS=""
KBN_URL="" KBN_USER="" KBN_PASS=""
CA_FILE="" OUT_DIR="./secrets" POLICY_NAME="observability-default"

ARGS=("$@")
# Pre-parse --ssh-user (kept for consistency with other scripts)
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
    --ssh-user) ((i+=2));; # consumed
    *) ((i+=1));;
  esac
done

# Defaults: Kibana creds inherit from ES creds if not provided
[[ -z "$KBN_USER" ]] && KBN_USER="$ES_USER"
[[ -z "$KBN_PASS" ]] && KBN_PASS="$ES_PASS"

# Validate required args
[[ -n "$ES_URL" && -n "$ES_USER" && -n "$ES_PASS" ]] || die "Missing ES connection args (--es-url/--es-user/--es-pass)"

# If Kibana URL is empty, build it from ES host
if [[ -z "$KBN_URL" ]]; then
  HOST_PART="$(echo "$ES_URL" | sed -E 's#https?://([^:/]+).*#\1#')"
  SCHEME="$(echo "$ES_URL" | grep -oE '^https?')"
  KBN_URL="$SCHEME://$HOST_PART:5601"
fi

LOG_FILE="$LOG_DIR/$(date +%Y%m%d_%H%M%S)_30_fleet_prereq.log"
mkdir -p "$OUT_DIR"

# Helpers (no --fail to surface error bodies)
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

_es_curl() {
  local method="$1"; shift
  local url="$1"; shift
  if [[ -n "$CA_FILE" ]]; then
    curl -sS -X "$method" -u "$ES_USER:$ES_PASS" --cacert "$CA_FILE" "$url"
  else
    curl -sS -k -X "$method" -u "$ES_USER:$ES_PASS" "$url"
  fi
}

# 0) Ensure Fleet is initialized (idempotent)
log "Ensuring Fleet is initialized in Kibana"
SETUP_RESP="$(_kbn_curl POST "$KBN_URL/api/fleet/setup")" || true
echo "$SETUP_RESP" | jq -r '.status // empty' >/dev/null 2>&1 || true

# Optional reachability info
if STATUS="$(_kbn_curl GET "$KBN_URL/api/status")"; then
  log "Kibana seems reachable (HTTP 200) – proceeding."
else
  warn "Kibana status endpoint check failed; proceeding anyway."
fi

# 1) Fleet Server service token
log "Ensuring Fleet Server service token exists (service: elastic/fleet-server)"
BASE_NAME="fleet-server-service-token"
CREATE_URL="$ES_URL/_security/service/elastic/fleet-server/credential/token/$BASE_NAME"

# Try canonical name; capture HTTP code
if [[ -n "$CA_FILE" ]]; then
  RESP_RAW="$(curl -sS -w '\n%{http_code}' -X POST -u "$ES_USER:$ES_PASS" --cacert "$CA_FILE" "$CREATE_URL" || true)"
else
  RESP_RAW="$(curl -sS -w '\n%{http_code}' -k -X POST -u "$ES_USER:$ES_PASS" "$CREATE_URL" || true)"
fi
RESP_CODE="$(printf '%s\n' "$RESP_RAW" | tail -n1)"
RESP_BODY="$(printf '%s\n' "$RESP_RAW" | sed '$d')"

TOKEN_VAL=""
if [[ "$RESP_CODE" == "201" ]]; then
  TOKEN_VAL="$(echo "$RESP_BODY" | jq -r '.token.value // empty')"
elif [[ "$RESP_CODE" == "409" ]]; then
  SUF="$(date +%Y%m%d%H%M%S)"
  NEW_NAME="${BASE_NAME}-${SUF}"
  CREATE_URL2="$ES_URL/_security/service/elastic/fleet-server/credential/token/$NEW_NAME"
  RESP2="$(_es_curl POST "$CREATE_URL2" || true)"
  TOKEN_VAL="$(echo "$RESP2" | jq -r '.token.value // empty')"
else
  error "Could not obtain Fleet Server service token. Response:"
  echo "[ES] HTTP $RESP_CODE :: $RESP_BODY" >&2
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

# 3) Ensure Enrollment Token
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

# 4) Copy certs into /etc/kibana/fleet/certs and fix permissions
sudo mkdir -p /etc/kibana/fleet/certs
sudo cp "$CA_FILE"  /etc/kibana/fleet/certs/epr-ca-chain.pem
sudo cp "$EPR_CERT" /etc/kibana/fleet/certs/epr.crt
sudo cp "$EPR_KEY"  /etc/kibana/fleet/certs/epr.key

sudo bash -lc '
  set -e
  SVC_USER=$(systemctl show kibana -p User --value 2>/dev/null || true)
  SVC_GROUP=$(systemctl show kibana -p Group --value 2>/dev/null || true)
  [[ -n "$SVC_USER" ]] || SVC_USER="kibana"
  [[ -n "$SVC_GROUP" ]] || SVC_GROUP="kibana"

  chown -R "$SVC_USER:$SVC_GROUP" /etc/kibana/fleet/certs
  chmod 0750 /etc/kibana/fleet/certs
  chmod 0644 /etc/kibana/fleet/certs/epr-ca-chain.pem /etc/kibana/fleet/certs/epr.crt
  chmod 0600 /etc/kibana/fleet/certs/epr.key

  UNIT_FILE=/usr/lib/systemd/system/kibana.service
  if [[ ! -f "$UNIT_FILE" ]]; then UNIT_FILE=/etc/systemd/system/kibana.service; fi
  if [[ -f "$UNIT_FILE" ]]; then
    if ! grep -q "NODE_EXTRA_CA_CERTS" "$UNIT_FILE"; then
      sed -i "/^\[Service\]/a Environment=\"NODE_EXTRA_CA_CERTS=/etc/kibana/fleet/certs/epr-ca-chain.pem\"" "$UNIT_FILE"
    fi
  else
    echo "ERROR: Kibana systemd unit file not found" >&2; exit 1
  fi
  systemctl daemon-reload
'

log "Fleet prerequisites completed successfully."
