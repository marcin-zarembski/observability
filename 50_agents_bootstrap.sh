#!/usr/bin/env bash
# 50_agents_bootstrap.sh — Install/upgrade & enroll Elastic Agents on multiple hosts
# - Supports agent RPM OR tar.gz (air‑gapped friendly)
# - Enrolls to Fleet with CA or --insecure
# - Supports custom tags (--tag can be used multiple times)
# - Idempotent health checks; dumps journal on issues

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=00_common.sh
source "$SCRIPT_DIR/00_common.sh"

print_help() {
  cat <<'EOF'
Usage:
  50_agents_bootstrap.sh \
    [--agent-rpm <path.rpm> | --agent-tar <elastic-agent-<ver>-linux-x86_64.tar.gz>] \
    (--hosts-file <file> | --hosts-list <host1,host2,...>) \
    --fleet-url <https://fleet:8220> \
    --enrollment-token <token> \
    (--ca <path> | --insecure) \
    [--remote-tmp </tmp>] [--ssh-user <user>] \
    [--tag <tag>]...

What it does:
  - If tar.gz is provided: uploads tarball, extracts, runs 'elastic-agent install' on the remote.
  - If RPM is provided: installs/upgrades RPM and ensures enrollment.
  - If agent already present but unhealthy: uninstalls and re-installs.
  - Waits for healthy status; dumps journal on failure.
  - Passes any number of --tag to elastic-agent install.

Examples:
  TAR:
    ./50_agents_bootstrap.sh \
      --agent-tar ./artifacts/elastic-agent-8.18.3-linux-x86_64.tar.gz \
      --hosts-file inventory/hosts_agents.txt \
      --fleet-url https://fleet:8220 \
      --enrollment-token "$(cat ./secrets/enrollment_token_agents)" \
      --ca /etc/kibana/fleet/certs/ca.pem \
      --ssh-user deploy \
      --tag prod --tag eu-central

  RPM:
    ./50_agents_bootstrap.sh \
      --agent-rpm ./artifacts/elastic-agent-8.18.3-x86_64.rpm \
      --hosts-list host1,host2 \
      --fleet-url https://fleet:8220 \
      --enrollment-token "$(cat ./secrets/enrollment_token_agents)" \
      --insecure
EOF
  exit 0
}

[[ $# -eq 0 ]] && print_help

require_cmd ssh scp

AGENT_RPM="" AGENT_TAR="" FLEET_URL="" ENR_TOKEN="" CA_FILE="" INSECURE=0 REMOTE_TMP="/tmp"
TAGS=()

ARGS=("$@")

# Pre-parse --ssh-user then parse hosts
for ((i=0;i<${#ARGS[@]};i++)); do
  case "${ARGS[i]}" in --ssh-user) export DEFAULT_SSH_USER="${ARGS[i+1]}";; esac
done
parse_hosts_args "${ARGS[@]}"

# Parse rest
i=0
while [[ $i -lt ${#ARGS[@]} ]]; do
  case "${ARGS[i]}" in
    --agent-rpm) AGENT_RPM="${ARGS[i+1]}"; ((i+=2));;
    --agent-tar) AGENT_TAR="${ARGS[i+1]}"; ((i+=2));;
    --fleet-url) FLEET_URL="${ARGS[i+1]}"; ((i+=2));;
    --enrollment-token) ENR_TOKEN="${ARGS[i+1]}"; ((i+=2));;
    --ca) CA_FILE="${ARGS[i+1]}"; ((i+=2));;
    --insecure) INSECURE=1; ((i+=1));;
    --remote-tmp) REMOTE_TMP="${ARGS[i+1]}"; ((i+=2));;
    --ssh-user) ((i+=2));; # already consumed
    --hosts-file|--hosts-list) ((i+=2));; # consumed in parse_hosts_args
    --tag) TAGS+=("${ARGS[i+1]}"); ((i+=2));;
    --help|-h) print_help;;
    *) ((i+=1));;
  esac
done

# Validate
if [[ -z "$AGENT_RPM" && -z "$AGENT_TAR" ]]; then
  die "Provide either --agent-rpm or --agent-tar"
fi
if [[ -n "$AGENT_RPM" && -n "$AGENT_TAR" ]]; then
  warn "Both --agent-rpm and --agent-tar provided; proceeding with --agent-tar (preferred)."
fi
[[ -n "$FLEET_URL" && -n "$ENR_TOKEN" ]] || die "Missing required args: --fleet-url and/or --enrollment-token"
if (( INSECURE==0 )) && [[ -z "$CA_FILE" ]]; then die "Provide --ca or --insecure"; fi
if [[ -n "$AGENT_RPM" && ! -f "$AGENT_RPM" ]]; then die "RPM not found: $AGENT_RPM"; fi
if [[ -n "$AGENT_TAR" && ! -f "$AGENT_TAR" ]]; then die "tar.gz not found: $AGENT_TAR"; fi

LOG_FILE="$LOG_DIR/$(date +%Y%m%d_%H%M%S)_50_agents_bootstrap.log"

# Helper: build tag args string for remote shell
build_tag_args() {
  local arr=()
  for t in "${TAGS[@]}"; do
    arr+=("--tag" "$t")
  done
  printf "%q " "${arr[@]}"
}

TAG_ARGS_STR="$(build_tag_args)" # properly shell-quoted tokens

for HOST in "${HOSTS[@]}"; do
  log "=== [$HOST] ==="
  run_ssh "$HOST" "sudo mkdir -p '$REMOTE_TMP'"

  # Upload CA if used
  CA_REMOTE=""
  if (( INSECURE==0 )); then
    run_scp_to "$CA_FILE" "$HOST" "$REMOTE_TMP/"
    CA_REMOTE="$REMOTE_TMP/$(basename "$CA_FILE")"
  fi

  if [[ -n "$AGENT_TAR" ]]; then
    # --- TAR.GZ FLOW ---
    BASENAME_TAR="$(basename "$AGENT_TAR")"
    TAR_REMOTE="$REMOTE_TMP/$BASENAME_TAR"
    log "[$HOST] Uploading agent tarball"
    run_scp_to "$AGENT_TAR" "$HOST" "$TAR_REMOTE"

    # If agent exists but unhealthy -> uninstall first (idempotent)
    if run_ssh "$HOST" "command -v elastic-agent >/dev/null 2>&1"; then
      if ! run_ssh "$HOST" "sudo elastic-agent status >/dev/null 2>&1"; then
        log "[$HOST] Existing agent unhealthy -> uninstall"
        run_ssh "$HOST" "sudo elastic-agent uninstall -f || true"
      else
        log "[$HOST] Existing agent appears healthy; will reinstall to ensure version/policy"
        run_ssh "$HOST" "sudo elastic-agent uninstall -f || true"
      fi
    fi

    # Extract and install
    log "[$HOST] Extracting tarball and installing"
    run_ssh "$HOST" "sudo mkdir -p '$REMOTE_TMP/ea-tmp' && sudo tar -xzf '$TAR_REMOTE' -C '$REMOTE_TMP/ea-tmp'"
    # Find extracted dir
    EA_DIR_REMOTE="$(run_ssh "$HOST" "find '$REMOTE_TMP/ea-tmp' -maxdepth 1 -type d -name 'elastic-agent*' | head -n1" | tr -d '\r')"
    [[ -n "$EA_DIR_REMOTE" ]] || { dump_journal "$HOST" "elastic-agent"; die "[$HOST] Could not locate extracted elastic-agent directory"; }

    # Build CA/insecure args for remote
    if (( INSECURE==0 )); then
      INSTALL_CA_ARG="--certificate-authorities '$CA_REMOTE'"
    else
      INSTALL_CA_ARG="--insecure"
    fi

    # Run install with tags and enrollment
    log "[$HOST] Running elastic-agent install"
    run_ssh "$HOST" "sudo bash -lc 'cd $EA_DIR_REMOTE && ./elastic-agent install \
      --url=\"$FLEET_URL\" \
      --enrollment-token=\"$ENR_TOKEN\" \
      $INSTALL_CA_ARG \
      $TAG_ARGS_STR \
      --non-interactive'"

    # Cleanup extracted files (keep tar by default)
    run_ssh "$HOST" "sudo rm -rf '$REMOTE_TMP/ea-tmp'" || true

  else
    # --- RPM FLOW ---
    require_cmd rpm || true  # rpm used on remote, not locally; keep for sanity
    BASENAME_RPM="$(basename "$AGENT_RPM")"
    RPM_REMOTE="$REMOTE_TMP/$BASENAME_RPM"
    log "[$HOST] Uploading agent RPM"
    run_scp_to "$AGENT_RPM" "$HOST" "$RPM_REMOTE"

    if run_ssh "$HOST" "command -v elastic-agent >/dev/null 2>&1"; then
      log "[$HOST] elastic-agent present -> rpm upgrade (idempotent)"
      run_ssh "$HOST" "sudo rpm -Uvh --force '$RPM_REMOTE' || sudo rpm -ivh '$RPM_REMOTE'"
      # If not healthy, reinstall
      if ! run_ssh "$HOST" "sudo elastic-agent status >/dev/null 2>&1"; then
        log "[$HOST] Agent not enrolled/healthy -> reinstall"
        run_ssh "$HOST" "sudo elastic-agent uninstall -f || true"
        if (( INSECURE==0 )); then
          run_ssh "$HOST" "sudo elastic-agent install --url='$FLEET_URL' --enrollment-token='$ENR_TOKEN' --certificate-authorities '$CA_REMOTE' $TAG_ARGS_STR --non-interactive"
        else
          run_ssh "$HOST" "sudo elastic-agent install --url='$FLEET_URL' --enrollment-token='$ENR_TOKEN' --insecure $TAG_ARGS_STR --non-interactive"
        fi
      fi
    else
      log "[$HOST] elastic-agent not present -> install and enroll"
      run_ssh "$HOST" "sudo rpm -ivh '$RPM_REMOTE'"
      if (( INSECURE==0 )); then
        run_ssh "$HOST" "sudo elastic-agent install --url='$FLEET_URL' --enrollment-token='$ENR_TOKEN' --certificate-authorities '$CA_REMOTE' $TAG_ARGS_STR --non-interactive"
      else
        run_ssh "$HOST" "sudo elastic-agent install --url='$FLEET_URL' --enrollment-token='$ENR_TOKEN' --insecure $TAG_ARGS_STR --non-interactive"
      fi
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
