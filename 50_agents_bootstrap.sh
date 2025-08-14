#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/00_common.sh"

print_help() {
  cat <<'EOF'
Usage:
  50_agents_bootstrap.sh --agent-rpm <path> (--hosts-file <file> | --hosts-list <...>) \
    --fleet-url <https://fleet:8220> --enrollment-token <token> (--ca <path> | --insecure) \
    [--remote-tmp </tmp>] [--ssh-user <user>]

What it does:
  - If elastic-agent is present: rpm upgrade (idempotent) and ensure it's enrolled.
  - If not present: rpm install + enroll to Fleet.
  - Waits for status; dumps journal on issues.

Example:
  ./50_agents_bootstrap.sh --agent-rpm ./artifacts/elastic-agent-8.18.3-x86_64.rpm \
    --hosts-file inventory/hosts_agents.txt \
    --fleet-url https://fleet:8220 --enrollment-token "$(cat ./secrets/enrollment_token_*)" \
    --ca cfg/tls/ca.crt --ssh-user deploy
EOF
  exit 0
}

[[ $# -eq 0 ]] && print_help

require_cmd ssh scp rpm

AGENT_RPM="" FLEET_URL="" ENR_TOKEN="" CA_FILE="" INSECURE=0 REMOTE_TMP="/tmp"
ARGS=("$@")

# Pre-parse --ssh-user, then hosts
for ((i=0;i<${#ARGS[@]};i++)); do case "${ARGS[i]}" in --ssh-user) export DEFAULT_SSH_USER="${ARGS[i+1]}";; esac; done
parse_hosts_args "${ARGS[@]}"

i=0
while [[ $i -lt ${#ARGS[@]} ]]; do
  case "${ARGS[i]}" in
    --agent-rpm) AGENT_RPM="${ARGS[i+1]}"; ((i+=2));;
    --fleet-url) FLEET_URL="${ARGS[i+1]}"; ((i+=2));;
    --enrollment-token) ENR_TOKEN="${ARGS[i+1]}"; ((i+=2));;
    --ca) CA_FILE="${ARGS[i+1]}"; ((i+=2));;
    --insecure) INSECURE=1; ((i+=1));;
    --remote-tmp) REMOTE_TMP="${ARGS[i+1]}"; ((i+=2));;
    --help) print_help;;
    --hosts-file|--hosts-list|--ssh-user) ((i+=1));;
    *) ((i+=1));;
  esac
done

[[ -f "$AGENT_RPM" && -n "$FLEET_URL" && -n "$ENR_TOKEN" ]] || die "Missing required arguments"
if (( INSECURE==0 )) && [[ -z "$CA_FILE" ]]; then die "Provide --ca or --insecure"; fi

LOG_FILE="$LOG_DIR/$(date +%Y%m%d_%H%M%S)_50_agents_bootstrap.log"

for HOST in "${HOSTS[@]}"; do
  log "=== [$HOST] ==="
  run_ssh "$HOST" "sudo mkdir -p '$REMOTE_TMP'"
  BASENAME="$(basename "$AGENT_RPM")"
  RPM_REMOTE="$REMOTE_TMP/$BASENAME"
  run_scp_to "$AGENT_RPM" "$HOST" "$RPM_REMOTE"

  # Upload CA if used
  if (( INSECURE==0 )); then
    run_scp_to "$CA_FILE" "$HOST" "$REMOTE_TMP/"
    CA_REMOTE="$REMOTE_TMP/$(basename "$CA_FILE")"
  fi

  # Install/upgrade rpm
  if run_ssh "$HOST" "command -v elastic-agent >/dev/null 2>&1"; then
    log "[$HOST] elastic-agent present -> rpm upgrade (idempotent)"
    run_ssh "$HOST" "sudo rpm -Uvh --force '$RPM_REMOTE' || sudo rpm -ivh '$RPM_REMOTE'"
    # Ensure agent is enrolled; if not, reinstall it
    if ! run_ssh "$HOST" "sudo elastic-agent status >/dev/null 2>&1"; then
      log "[$HOST] Agent not enrolled/healthy -> reinstall"
      run_ssh "$HOST" "sudo elastic-agent uninstall -f || true"
      if (( INSECURE==0 )); then
        run_ssh "$HOST" "sudo elastic-agent install --url='$FLEET_URL' --enrollment-token='$ENR_TOKEN' --certificate-authorities '$CA_REMOTE' --non-interactive"
      else
        run_ssh "$HOST" "sudo elastic-agent install --url='$FLEET_URL' --enrollment-token='$ENR_TOKEN' --insecure --non-interactive"
      fi
    fi
  else
    log "[$HOST] elastic-agent not present -> install and enroll"
    run_ssh "$HOST" "sudo rpm -ivh '$RPM_REMOTE'"
    if (( INSECURE==0 )); then
      run_ssh "$HOST" "sudo elastic-agent install --url='$FLEET_URL' --enrollment-token='$ENR_TOKEN' --certificate-authorities '$CA_REMOTE' --non-interactive"
    else
      run_ssh "$HOST" "sudo elastic-agent install --url='$FLEET_URL' --enrollment-token='$ENR_TOKEN' --insecure --non-interactive"
    fi
  fi

  log "[$HOST] Verifying agent status"
  if ! retry 18 5 run_ssh "$HOST" "sudo elastic-agent status >/dev/null 2>&1"; then
    dump_journal "$HOST" "elastic-agent"
    warn "[$HOST] Agent is not healthy"
  else
    log "[$HOST] OK"
  fi
done

log "Finished."
