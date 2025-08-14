#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/00_common.sh"

print_help() {
  cat <<'EOF'
Usage:
  41_agent_artifacts_sync.sh --kibana-url <https://kib:5601> --kbn-user <user> --kbn-pass <pass> \
    --source <http://repo.local/elastic-agent/8.18.3/> [--ca <path>]

What it does:
  - Creates/updates a Fleet "Agent download source" pointing to your local repository.
  - Sets it as default.

Example:
  ./41_agent_artifacts_sync.sh --kibana-url https://kib:5601 --kbn-user svc --kbn-pass '***' \
    --source http://jfrog.local/elastic-agent/8.18.3/ --ca cfg/tls/ca.crt
EOF
  exit 0
}

[[ $# -eq 0 ]] && print_help
require_cmd curl jq

KBN_URL="" KBN_USER="" KBN_PASS="" CA_FILE="" SOURCE=""

ARGS=("$@")
i=0
while [[ $i -lt ${#ARGS[@]} ]]; do
  case "${ARGS[i]}" in
    --kibana-url) KBN_URL="${ARGS[i+1]}"; ((i+=2));;
    --kbn-user) KBN_USER="${ARGS[i+1]}"; ((i+=2));;
    --kbn-pass) KBN_PASS="${ARGS[i+1]}"; ((i+=2));;
    --ca) CA_FILE="${ARGS[i+1]}"; ((i+=2));;
    --source) SOURCE="${ARGS[i+1]}"; ((i+=2));;
    --help) print_help;;
    *) ((i+=1));;
  esac
done

[[ -n "$KBN_URL" && -n "$KBN_USER" && -n "$KBN_PASS" && -n "$SOURCE" ]] || die "Missing required arguments"

LOG_FILE="$LOG_DIR/$(date +%Y%m%d_%H%M%S)_41_agent_artifacts_sync.log"

log "Querying existing Fleet download sources"
LIST="$(curl_kbn_json GET "$KBN_URL/api/fleet/agent_download_sources" "$KBN_USER" "$KBN_PASS" "$CA_FILE" || true)"
ID="$(echo "$LIST" | jq -r --arg u "$SOURCE" '.items[]?|select(.host==$u)|.id' | head -n1)"

if [[ -z "$ID" || "$ID" == "null" ]]; then
  log "Creating new download source -> $SOURCE"
  BODY="$(jq -n --arg host "$SOURCE" '{name:"Airgapped Source",host:$host,is_default:false}')"
  RESP="$(curl_kbn_json POST "$KBN_URL/api/fleet/agent_download_sources" "$KBN_USER" "$KBN_PASS" "$CA_FILE" "$BODY")"
  ID="$(echo "$RESP" | jq -r '.item.id')"
fi
[[ -n "$ID" && "$ID" != "null" ]] || die "Failed to create or find download source"

log "Setting download source as default"
curl_kbn_json PUT "$KBN_URL/api/fleet/agent_download_sources/$ID/default" "$KBN_USER" "$KBN_PASS" "$CA_FILE" >/dev/null || die "Failed to set default"

log "Done."
