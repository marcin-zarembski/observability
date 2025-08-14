#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/00_common.sh"

print_help() {
  cat <<'EOF'
Usage:
  60_post_checks.sh --es-url <https://es:9200> --es-user <user> --es-pass <pass> [--ca <path>] \
    --kibana-url <https://kib:5601> --kbn-user <user> --kbn-pass <pass> [--ca <path>] \
    [--agents-hosts-file <file>] [--ssh-user <user>]

What it does:
  - ES: cluster health + versions per node.
  - Kibana: /api/status and Fleet availability check.
  - Fleet: agent count via API.
  - Agents (optional): systemd and agent status per host; dumps last journal on failures.

Example:
  ./60_post_checks.sh --es-url https://es:9200 --es-user svc --es-pass '***' --ca cfg/tls/ca.crt \
    --kibana-url https://kib:5601 --kbn-user svc --kbn-pass '***' --ca cfg/tls/ca.crt \
    --agents-hosts-file inventory/hosts_agents.txt --ssh-user deploy
EOF
  exit 0
}

[[ $# -eq 0 ]] && print_help
require_cmd curl jq

ES_URL="" ES_USER="" ES_PASS="" ES_CA=""
KBN_URL="" KBN_USER="" KBN_PASS="" KBN_CA=""
AGENTS_HOSTS_FILE=""

ARGS=("$@")
# Pre-parse --ssh-user
for ((i=0;i<${#ARGS[@]};i++)); do case "${ARGS[i]}" in --ssh-user) export DEFAULT_SSH_USER="${ARGS[i+1]}";; esac; done

i=0
while [[ $i -lt ${#ARGS[@]} ]]; do
  case "${ARGS[i]}" in
    --es-url) ES_URL="${ARGS[i+1]}"; ((i+=2));;
    --es-user) ES_USER="${ARGS[i+1]}"; ((i+=2));;
    --es-pass) ES_PASS="${ARGS[i+1]}"; ((i+=2));;
    --kibana-url) KBN_URL="${ARGS[i+1]}"; ((i+=2));;
    --kbn-user) KBN_USER="${ARGS[i+1]}"; ((i+=2));;
    --kbn-pass) KBN_PASS="${ARGS[i+1]}"; ((i+=2));;
    --ca)
      # Accept two --ca flags: first for ES, second for Kibana.
      if [[ -z "$ES_CA" ]]; then ES_CA="${ARGS[i+1]}"; else KBN_CA="${ARGS[i+1]}"; fi
      ((i+=2));;
    --agents-hosts-file) AGENTS_HOSTS_FILE="${ARGS[i+1]}"; ((i+=2));;
    --help) print_help;;
    --ssh-user) ((i+=2));; # consumed
    *) ((i+=1));;
  esac
done

LOG_FILE="$LOG_DIR/$(date +%Y%m%d_%H%M%S)_60_post_checks.log"

log "ES: cluster health"
curl_es "$ES_URL/_cluster/health?pretty" "$ES_USER" "$ES_PASS" "$ES_CA" | tee -a "$LOG_FILE" >/dev/null || warn "ES health failed"

log "ES: versions per node"
curl_es "$ES_URL/_nodes?filter_path=nodes.*.version,nodes.*.name&pretty" "$ES_USER" "$ES_PASS" "$ES_CA" | tee -a "$LOG_FILE" >/dev/null || true

log "Kibana: /api/status"
curl_kbn_json GET "$KBN_URL/api/status" "$KBN_USER" "$KBN_PASS" "$KBN_CA" | jq '.status' | tee -a "$LOG_FILE" >/dev/null || warn "Kibana status failed"

log "Fleet: agents count"
curl_kbn_json GET "$KBN_URL/api/fleet/agents?perPage=1" "$KBN_USER" "$KBN_PASS" "$KBN_CA" | jq '.total' | tee -a "$LOG_FILE" >/dev/null || true

if [[ -n "$AGENTS_HOSTS_FILE" && -f "$AGENTS_HOSTS_FILE" ]]; then
  mapfile -t HOSTS < "$AGENTS_HOSTS_FILE"
  for H in "${HOSTS[@]}"; do
    log "[$H] elastic-agent systemd and status"
    if ! run_ssh "$H" "sudo systemctl is-active --quiet elastic-agent && sudo elastic-agent status >/dev/null 2>&1"; then
      dump_journal "$H" "elastic-agent"
    else
      run_ssh "$H" "sudo elastic-agent status || true"
    fi
  done
fi

log "Post-checks completed."
