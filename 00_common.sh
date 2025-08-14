#!/usr/bin/env bash
set -euo pipefail

# ===== Global config =====
LOG_DIR="./logs"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=10)
SCP_OPTS=(-o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=10)
# Default SSH user = current shell user unless overridden via --ssh-user or env DEFAULT_SSH_USER
DEFAULT_SSH_USER="${DEFAULT_SSH_USER:-$USER}"

mkdir -p "$LOG_DIR"

# ===== Utilities =====
ts() { date +"%Y-%m-%d %H:%M:%S%z"; }

log()   { echo "[$(ts)] [INFO ] $*" | tee -a "${LOG_FILE:-/dev/null}"; }
warn()  { echo "[$(ts)] [WARN ] $*" | tee -a "${LOG_FILE:-/dev/null}" >&2; }
error() { echo "[$(ts)] [ERROR] $*" | tee -a "${LOG_FILE:-/dev/null}" >&2; }
die()   { error "$*"; exit 1; }

require_cmd() {
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || die "Missing required command in PATH: $c"
  done
}

retry() {
  local max="$1"; shift
  local delay="$1"; shift
  local n=1
  until "$@"; do
    if (( n >= max )); then return 1; fi
    sleep "$delay"
    ((n++))
  done
}

# ===== Hosts parsing / SSH helpers =====
HOSTS=()

parse_hosts_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --hosts-file)
        [[ -f "$2" ]] || die "Hosts file not found: $2"
        mapfile -t HOSTS < "$2"
        shift 2
        ;;
      --hosts-list)
        shift
        while [[ $# -gt 0 && "$1" != --* ]]; do HOSTS+=("$1"); shift; done
        ;;
      *)
        break
        ;;
    esac
  done
  [[ "${#HOSTS[@]}" -gt 0 ]] || die "No hosts provided (use --hosts-file or --hosts-list)"
}

ssh_user_host() {
  local host="$1"
  if [[ -n "$DEFAULT_SSH_USER" && "$host" != *@* ]]; then
    printf "%s@%s" "$DEFAULT_SSH_USER" "$host"
  else
    printf "%s" "$host"
  fi
}

run_ssh() {
  local host="$1"; shift
  local uh; uh="$(ssh_user_host "$host")"
  ssh "${SSH_OPTS[@]}" "$uh" "$@"
}

run_scp_to() {
  local src="$1" host="$2" dest="$3"
  local uh; uh="$(ssh_user_host "$host")"
  scp "${SCP_OPTS[@]}" "$src" "$uh:$dest"
}

dump_journal() {
  local host="$1" unit="$2" lines="${3:-300}"
  run_ssh "$host" "sudo journalctl -u '$unit' -n $lines --no-pager || true"
}

# ===== HTTP helpers (ES/Kibana) =====
curl_es() { # curl_es <URL> <user> <pass> [<ca>]
  local url="$1" u="$2" p="$3" ca="${4:-}"
  if [[ -n "$ca" ]]; then
    curl --silent --show-error --fail --user "$u:$p" --cacert "$ca" "$url"
  else
    curl --silent --show-error --fail --user "$u:$p" -k "$url"
  fi
}

curl_kbn_json() { # curl_kbn_json <METHOD> <URL> <user> <pass> [<ca>] [<json-body>]
  local m="$1" url="$2" u="$3" p="$4" ca="${5:-}" body="${6:-}"
  local common=(--silent --show-error --fail -H "kbn-xsrf: true" -H "Content-Type: application/json" -X "$m")
  [[ -n "$body" ]] && common+=(-d "$body")
  if [[ -n "$ca" ]]; then
    curl "${common[@]}" --user "$u:$p" --cacert "$ca" "$url"
  else
    curl "${common[@]}" -k --user "$u:$p" "$url"
  fi
}
