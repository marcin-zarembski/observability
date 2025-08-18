#!/bin/bash
set -euo pipefail

# ========================
# Fleet prereq preparation
# ========================
#  - Ensures Fleet Server policy exists (or creates)
#  - Creates enrollment token
#  - Creates Fleet Server service token
#  - Saves outputs to --out-dir or stdout
#
# Requires: curl, jq
# ========================

# ---------- functions ----------
print_help() {
  cat <<EOF
Usage: $0 --es-url <url> --es-user <user> --es-pass <pass> [--ca <ca-file>]
          [--policy-name <name>] [--out-dir <dir>]

Options:
  --es-url         Elasticsearch URL (e.g. https://es01:9200)
  --es-user        Elasticsearch username
  --es-pass        Elasticsearch password
  --ca             Path to CA certificate (optional; if not given, -k used)
  --policy-name    Fleet Server policy name (default: observability)
  --out-dir        Directory to save tokens (default: stdout only)
  --help           Show this help
EOF
}

log() { echo "[INFO ] $*"; }
err() { echo "[ERROR] $*" >&2; }
die() { err "$*"; exit 1; }

# ---------- parse args ----------
ES_URL=""
ES_USER=""
ES_PASS=""
CA_FILE=""
POLICY_NAME="observability"
OUT_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --es-url) ES_URL="$2"; shift 2;;
    --es-user) ES_USER="$2"; shift 2;;
    --es-pass) ES_PASS="$2"; shift 2;;
    --ca) CA_FILE="$2"; shift 2;;
    --policy-name) POLICY_NAME="$2"; shift 2;;
    --out-dir) OUT_DIR="$2"; shift 2;;
    --help) print_help; exit 0;;
    *) die "Unknown arg: $1";;
  esac
done

[[ -z "$ES_URL" || -z "$ES_USER" || -z "$ES_PASS" ]] && die "Missing required params"

if [[ -n "$OUT_DIR" ]]; then
  mkdir -p "$OUT_DIR"
fi

# curl wrapper
curl_es() {
  local method="$1"; shift
  local url="$1"; shift
  local args=("$@")
  if [[ -n "$CA_FILE" ]]; then
    curl --silent --show-error --fail -X "$method" \
      --user "$ES_USER:$ES_PASS" --cacert "$CA_FILE" "$url" "${args[@]}"
  else
    curl --silent --show-error --fail -k -X "$method" \
      --user "$ES_USER:$ES_PASS" "$url" "${args[@]}"
  fi
}

# ---------- 1) Ensure Fleet Server policy ----------
log "Ensuring Fleet Server policy: $POLICY_NAME"
POLICY_ID=$(curl_es GET "$ES_URL/api/fleet/agent_policies?perPage=1000" -H "kbn-xsrf: true" 2>/dev/null | jq -r --arg NAME "$POLICY_NAME" '.items[] | select(.name==$NAME) | .id' || true)

if [[ -z "$POLICY_ID" ]]; then
  log "Creating Fleet Server policy $POLICY_NAME"
  POLICY_ID=$(curl_es POST "$ES_URL/api/fleet/agent_policies" \
    -H "Content-Type: application/json" -H "kbn-xsrf: true" \
    -d "{\"name\":\"$POLICY_NAME\",\"namespace\":\"default\",\"monitoring_enabled\":[\"logs\",\"metrics\"]}" \
    | jq -r '.item.id')
fi
[[ -n "$POLICY_ID" ]] || die "Failed to ensure Fleet Server policy"

[[ -n "$OUT_DIR" ]] && echo -n "$POLICY_ID" > "$OUT_DIR/fleet_policy_id"
log "Policy ID: $POLICY_ID"

# ---------- 2) Enrollment token ----------
log "Creating enrollment token"
ENROLL_TOKEN=$(curl_es POST "$ES_URL/api/fleet/enrollment_api_keys" \
  -H "Content-Type: application/json" -H "kbn-xsrf: true" \
  -d "{\"policy_id\":\"$POLICY_ID\"}" \
  | jq -r '.item.api_key')
[[ -n "$ENROLL_TOKEN" ]] || die "Failed to create enrollment token"

[[ -n "$OUT_DIR" ]] && echo -n "$ENROLL_TOKEN" > "$OUT_DIR/fleet_enrollment_token"
log "Enrollment token saved"

# ---------- 3) Fleet Server service token ----------
log "Ensuring Fleet Server service token (elastic/fleet-server)"
NAME="fleet-server-service-token"
CREATE_URL="$ES_URL/_security/service/elastic/fleet-server/credential/token/$NAME"

RESP="$(curl_es POST "$CREATE_URL" || true)"
TOKEN_VAL="$(echo "$RESP" | jq -r '.token.value // empty')"
[[ -n "$TOKEN_VAL" ]] || die "Could not obtain Fleet Server service token from $CREATE_URL"

[[ -n "$OUT_DIR" ]] && echo -n "$TOKEN_VAL" > "$OUT_DIR/fleet_server_service_token"
log "Service token saved"

# ---------- Summary ----------
echo
log "Fleet prereqs ready:"
echo "  Policy ID:      $POLICY_ID"
echo "  Enrollment key: ${ENROLL_TOKEN:0:8}..."
echo "  Service token:  ${TOKEN_VAL:0:8}..."
if [[ -n "$OUT_DIR" ]]; then
  log "Files saved in $OUT_DIR/"
fi
