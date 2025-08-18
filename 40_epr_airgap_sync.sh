#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)"
# shellcheck source=00_common.sh
source "$SCRIPT_DIR/00_common.sh"

print_help() {
  cat <<'EOF'
Usage:
  40_epr_deploy.sh \
    --epr-host <host> \
    [ --epr-tar <image.tar> ] \
    ( --epr-cert </path/to/server.crt> --epr-key </path/to/server.key> --epr-ca </path/to/ca-chain.pem>
      | --from-es-jks-host <es-host> [--es-config \/etc\/elasticsearch\/elasticsearch.yml] --jks-pass <password> [--src-alias <alias>] ) \
    [--port <8443>] [--name <epr>] \
    [--kibana-hosts-file <file>] [--ssh-user <user>]

What it does:
  - Secure-only EPR deploy (HTTPS): loads provided image tar and runs container with TLS cert\/key.
  - Health-checks EPR via HTTPS using the provided CA chain.
  - Optional JKS auto-conversion (reuses Elasticsearch JKS materials):
      * reads keystore\/truststore paths from elasticsearch.yml on <es-host>
      * converts JKS -> PEM (epr.key, epr.crt fullchain, epr-ca-chain.pem) next to the JKS
      * copies PEMs locally and uses them for secure EPR
  - Optionally configures Kibana hosts to trust the EPR CA and use the secure registry URL:
      * copies CA to /etc/kibana/certs/epr-ca-chain.pem (ownership = kibana service user)
      * injects Environment=NODE_EXTRA_CA_CERTS into the main systemd unit for Kibana
      * sets in /etc/kibana/kibana.yml:
          xpack.fleet.isAirGapped: true
          xpack.fleet.registryUrl: "https://<epr-host>:<port>"
      * restarts Kibana (systemd)

Notes:
  - Requires Docker or Podman on the EPR host.
  - For JKS flow, keytool & openssl must be present on the Elasticsearch host.
  - The JKS password provided via --jks-pass is used for both keystore and truststore.
  - All SSH connections default to the current shell user unless --ssh-user is provided.

Examples:
  # Using PEM files
  ./40_epr_deploy.sh \
    --epr-host epr01 \
    --epr-tar ./artifacts/package-registry-8.18.3.tar \
    --epr-cert ./cfg/tls/epr.crt --epr-key ./cfg/tls/epr.key --epr-ca ./cfg/tls/epr-ca-chain.pem \
    --port 8443 --kibana-hosts-file ./inventory/hosts_kibana.txt --ssh-user deploy

  # Using Elasticsearch JKS on remote ES host
  ./40_epr_deploy.sh \
    --epr-host epr01 \
    --epr-tar ./artifacts/package-registry-8.18.3.tar \
    --from-es-jks-host es01 --es-config /etc/elasticsearch/elasticsearch.yml --jks-pass 'Secret123' \
    --port 8443 --kibana-hosts-file ./inventory/hosts_kibana.txt --ssh-user deploy
EOF
  exit 0
}

[[ $# -eq 0 ]] && print_help
require_cmd ssh scp curl jq sed awk grep

# Args
EPR_HOST="" EPR_TAR="" EPR_CERT="" EPR_KEY="" EPR_CA=""
EPR_NAME="epr" EPR_PORT="8443" KBN_HOSTS_FILE=""
# JKS auto-conversion inputs
ES_CONF_HOST="" ES_CONF_PATH="/etc/elasticsearch/elasticsearch.yml" JKS_PASS="" SRC_ALIAS=""

ARGS=("$@")
# Pre-parse --ssh-user so helper uses it
for ((i=0;i<${#ARGS[@]};i++)); do
  case "${ARGS[i]}" in --ssh-user) export DEFAULT_SSH_USER="${ARGS[i+1]}";; esac
done

# Parse
i=0
while [[ $i -lt ${#ARGS[@]} ]]; do
  case "${ARGS[i]}" in
    --epr-host) EPR_HOST="${ARGS[i+1]}"; ((i+=2));;    --epr-tar)  EPR_TAR="${ARGS[i+1]}";  ((i+=2));;
    --epr-cert) EPR_CERT="${ARGS[i+1]}"; ((i+=2));;
    --epr-key)  EPR_KEY="${ARGS[i+1]}";  ((i+=2));;
    --epr-ca)   EPR_CA="${ARGS[i+1]}";   ((i+=2));;
    --name)     EPR_NAME="${ARGS[i+1]}"; ((i+=2));;
    --port)     EPR_PORT="${ARGS[i+1]}"; ((i+=2));;    --kibana-hosts-file) KBN_HOSTS_FILE="${ARGS[i+1]}"; ((i+=2));;
    --from-es-jks-host) ES_CONF_HOST="${ARGS[i+1]}"; ((i+=2));;
    --es-config) ES_CONF_PATH="${ARGS[i+1]}"; ((i+=2));;
    --jks-pass) JKS_PASS="${ARGS[i+1]}"; ((i+=2));;
    --src-alias) SRC_ALIAS="${ARGS[i+1]}"; ((i+=2));;
    --help) print_help;;
    --ssh-user) ((i+=2));; # consumed earlier
    *) ((i+=1));;
  esac
done

# Validate (either PEM inputs OR JKS auto-conversion inputs)
[[ -n "$EPR_HOST" ]] || die "Missing required arg: --epr-host"
[[ -n "$EPR_TAR" ]] || die "Missing required arg: --epr-tar"

if [[ -n "$EPR_CERT" || -n "$EPR_KEY" || -n "$EPR_CA" ]]; then
  [[ -n "$EPR_CERT" && -n "$EPR_KEY" && -n "$EPR_CA" ]] || die "Provide all of --epr-cert/--epr-key/--epr-ca or none (when using --from-es-jks-host)"
  [[ -f "$EPR_CERT" && -f "$EPR_KEY" && -f "$EPR_CA" ]] || die "One or more PEM files do not exist"
elif [[ -n "$ES_CONF_HOST" && -n "$JKS_PASS" ]]; then
  : # JKS mode selected; will derive PEMs below
else
  die "Either provide --epr-cert/--epr-key/--epr-ca OR use --from-es-jks-host with --jks-pass"
fi

LOG_FILE="$LOG_DIR/$(date +%Y%m%d_%H%M%S)_40_epr_deploy.log"

# 0) If JKS auto-conversion requested, perform it on the ES host and pull PEMs locally
LOCAL_TLS_TMP="${SCRIPT_DIR}/.tls_tmp_$(date +%s)"
if [[ -n "$ES_CONF_HOST" && -n "$JKS_PASS" ]]; then
  log "[$ES_CONF_HOST] Reading $ES_CONF_PATH to locate keystore/truststore paths"
  # Extract paths from elasticsearch.yml (best-effort without yq)
  KEYSTORE_PATH="$(run_ssh "$ES_CONF_HOST" "awk -F: '/xpack.security.http.ssl.keystore.path/ {sub(/^[ \t]+/,\"\"); sub(/#[^$]*/,\"\"); print \$2}' $ES_CONF_PATH | sed 's/[ \"\'\''	]//g' | head -n1)"
  TRUSTSTORE_PATH="$(run_ssh "$ES_CONF_HOST" "awk -F: '/xpack.security.http.ssl.truststore.path/ {sub(/^[ \t]+/,\"\"); sub(/#[^$]*/,\"\"); print \$2}' $ES_CONF_PATH | sed 's/[ \"\'\''	]//g' | head -n1)"
  [[ -n "$KEYSTORE_PATH" ]] || die "Could not parse keystore.path from $ES_CONF_PATH on $ES_CONF_HOST"
  [[ -n "$TRUSTSTORE_PATH" ]] || die "Could not parse truststore.path from $ES_CONF_PATH on $ES_CONF_HOST"

  run_ssh "$ES_CONF_HOST" "bash -lc 'command -v keytool >/dev/null && command -v openssl >/dev/null'" || die "keytool and openssl are required on $ES_CONF_HOST"

  ESDIR_CMD="dirname '$KEYSTORE_PATH'"
  ES_DIR="$(run_ssh "$ES_CONF_HOST" "$ESDIR_CMD")"

  # Determine alias if not provided
  if [[ -z "$SRC_ALIAS" ]]; then
    SRC_ALIAS="$(run_ssh "$ES_CONF_HOST" "keytool -list -keystore '$KEYSTORE_PATH' -storepass '$JKS_PASS' 2>/dev/null | awk -F': ' '/Alias name/ {a=\$2} /Entry type: PrivateKeyEntry/ {print a; exit}'")"
    [[ -n "$SRC_ALIAS" ]] || die "Could not determine PrivateKeyEntry alias from keystore"
  fi

  log "[$ES_CONF_HOST] Converting JKS -> PEM in $ES_DIR (alias=$SRC_ALIAS)"
  run_ssh "$ES_CONF_HOST" "bash -lc '
    set -e
    keytool -importkeystore \
      -srckeystore "$KEYSTORE_PATH" -srcstoretype JKS -srcstorepass "$JKS_PASS" \
      -destkeystore "$ES_DIR/epr.p12" -deststoretype PKCS12 -deststorepass "$JKS_PASS" \
      -srcalias "$SRC_ALIAS"
    openssl pkcs12 -in "$ES_DIR/epr.p12" -passin pass:"$JKS_PASS" -nocerts -nodes -out "$ES_DIR/epr.key"
    openssl pkcs12 -in "$ES_DIR/epr.p12" -passin pass:"$JKS_PASS" -clcerts -nokeys -out "$ES_DIR/epr.crt"
    : > "$ES_DIR/epr-ca-chain.pem"
    for a in $(keytool -list -keystore "$TRUSTSTORE_PATH" -storepass "$JKS_PASS" 2>/dev/null | awk -F': ' '/Alias name/ {print $2}'); do
      keytool -exportcert -rfc -alias "$a" -keystore "$TRUSTSTORE_PATH" -storepass "$JKS_PASS" >> "$ES_DIR/epr-ca-chain.pem"
    done
    chmod 600 "$ES_DIR/epr.key"
  '"

  mkdir -p "$LOCAL_TLS_TMP"
  log "[$ES_CONF_HOST] Pulling PEMs locally to $LOCAL_TLS_TMP"
  scp "${DEFAULT_SSH_USER:-$USER}@$ES_CONF_HOST:$ES_DIR/epr.key" "$LOCAL_TLS_TMP/" >/dev/null
  scp "${DEFAULT_SSH_USER:-$USER}@$ES_CONF_HOST:$ES_DIR/epr.crt" "$LOCAL_TLS_TMP/" >/dev/null
  scp "${DEFAULT_SSH_USER:-$USER}@$ES_CONF_HOST:$ES_DIR/epr-ca-chain.pem" "$LOCAL_TLS_TMP/" >/dev/null

  EPR_KEY="$LOCAL_TLS_TMP/epr.key"
  EPR_CERT="$LOCAL_TLS_TMP/epr.crt"
  EPR_CA="$LOCAL_TLS_TMP/epr-ca-chain.pem"
fi

# 1) Upload image + TLS materials, detect runtime
REMOTE_TMP="/tmp"
log "[$EPR_HOST] Preparing remote directory and uploading image+TLS"
run_ssh "$EPR_HOST" "sudo mkdir -p '$REMOTE_TMP/epr_tls' && sudo chmod 700 '$REMOTE_TMP/epr_tls'"
run_scp_to "$EPR_TAR"  "$EPR_HOST" "$REMOTE_TMP/"
run_scp_to "$EPR_CERT" "$EPR_HOST" "$REMOTE_TMP/epr_tls/cert.pem"
run_scp_to "$EPR_KEY"  "$EPR_HOST" "$REMOTE_TMP/epr_tls/key.pem"
TAR_REMOTE="$REMOTE_TMP/$(basename "$EPR_TAR")"
CERT_REMOTE="$REMOTE_TMP/epr_tls/cert.pem"
KEY_REMOTE="$REMOTE_TMP/epr_tls/key.pem"

log "[$EPR_HOST] Detecting container runtime"
RUNTIME="$(run_ssh "$EPR_HOST" "command -v docker >/dev/null 2>&1 && echo docker || (command -v podman >/dev/null 2>&1 && echo podman || echo none)")"
[[ "$RUNTIME" != "none" ]] || die "Neither docker nor podman found on $EPR_HOST"

# 2) Load image and (re)start container securely
log "[$EPR_HOST] Loading EPR image: $TAR_REMOTE"
LOAD_OUT="$(run_ssh "$EPR_HOST" "sudo $RUNTIME load -i '$TAR_REMOTE' 2>&1 || true")"
echo "$LOAD_OUT" | tee -a "$LOG_FILE" >/dev/null
IMG="$(echo "$LOAD_OUT" | awk '/Loaded image/ {print $NF}' | tail -n1)"
if [[ -z "$IMG" ]]; then
  IMG="$(echo "$LOAD_OUT" | awk -F': ' '/Loaded image/ || /Loaded image\(s\)/ {print $2}' | tail -n1)"
fi
[[ -n "$IMG" ]] || IMG="docker.elastic.co/package-registry/distribution:latest"

log "[$EPR_HOST] (Re)starting secure EPR container '$EPR_NAME' on HTTPS port $EPR_PORT (image: $IMG)"
run_ssh "$EPR_HOST" "sudo $RUNTIME rm -f '$EPR_NAME' >/dev/null 2>&1 || true"
run_ssh "$EPR_HOST" "sudo $RUNTIME run -d --name '$EPR_NAME' --restart unless-stopped \
  -p $EPR_PORT:8080 \
  -v $CERT_REMOTE:/usr/share/package-registry/config/cert.pem:ro \
  -v $KEY_REMOTE:/usr/share/package-registry/config/key.pem:ro \
  '$IMG' \
  --tls-cert /usr/share/package-registry/config/cert.pem \
  --tls-key  /usr/share/package-registry/config/key.pem"

# 3) Health check via HTTPS using provided CA
EPR_URL="https://$(echo "$EPR_HOST" | awk -F'@' '{print $NF}'):$EPR_PORT"
log "[$EPR_HOST] Waiting for $EPR_URL/health (24x5s, TLS verify with provided CA)"
if ! retry 24 5 bash -lc "curl -fsS --cacert '$EPR_CA' '$EPR_URL/health' >/dev/null"; then
  warn "[$EPR_HOST] EPR health check failed at $EPR_URL/health (with --cacert)"
else
  log "[$EPR_HOST] EPR is healthy (HTTPS)"
fi

# 4) Configure Kibana hosts (optional)
if [[ -n "$KBN_HOSTS_FILE" ]]; then
  [[ -f "$KBN_HOSTS_FILE" ]] || die "Kibana hosts file not found: $KBN_HOSTS_FILE"
  mapfile -t KBN_HOSTS < "$KBN_HOSTS_FILE"

  for HOST in "${KBN_HOSTS[@]}"; do
    log "[$HOST] Installing EPR CA, injecting NODE_EXTRA_CA_CERTS, configuring registryUrl: $EPR_URL"

    # Ensure target directories exist
    run_ssh "$HOST" "sudo mkdir -p /etc/kibana/certs && sudo chmod 0755 /etc/kibana && sudo chmod 0755 /etc/kibana/certs"

    # Copy CA
    run_scp_to "$EPR_CA" "$HOST" "/etc/kibana/certs/epr-ca-chain.pem"

    # Fix ownership/permissions according to Kibana service user/group; inject env into main unit
    run_ssh "$HOST" "sudo bash -lc '
      set -e
      SVC_USER=$(systemctl show kibana -p User --value 2>/dev/null || true)
      SVC_GROUP=$(systemctl show kibana -p Group --value 2>/dev/null || true)
      [[ -n "$SVC_USER" ]] || SVC_USER="kibana"
      [[ -n "$SVC_GROUP" ]] || SVC_GROUP="kibana"
      chown "$SVC_USER:$SVC_GROUP" /etc/kibana/certs/epr-ca-chain.pem
      chmod 0644 /etc/kibana/certs/epr-ca-chain.pem

      UNIT_FILE=/usr/lib/systemd/system/kibana.service
      if [[ ! -f "$UNIT_FILE" ]]; then UNIT_FILE=/etc/systemd/system/kibana.service; fi
      if [[ -f "$UNIT_FILE" ]]; then
        if ! grep -q "NODE_EXTRA_CA_CERTS" "$UNIT_FILE"; then
          sed -i "/^\[Service\]/a Environment=\"NODE_EXTRA_CA_CERTS=/etc/kibana/certs/epr-ca-chain.pem\"" "$UNIT_FILE"
        fi
      else
        echo "ERROR: Kibana systemd unit file not found" >&2; exit 1
      fi
      systemctl daemon-reload
    '"

    # Update kibana.yml and restart
    run_ssh "$HOST" "sudo bash -lc '
      Y=/etc/kibana/kibana.yml
      mkdir -p /etc/kibana
      if grep -q "^xpack.fleet.isAirGapped:" "$Y" 2>/dev/null; then
        sed -i "s|^xpack.fleet.isAirGapped:.*|xpack.fleet.isAirGapped: true|" "$Y"
      else
        echo "xpack.fleet.isAirGapped: true" >> "$Y"
      fi
      if grep -q "^xpack.fleet.registryUrl:" "$Y" 2>/dev/null; then
        sed -i "s|^xpack.fleet.registryUrl:.*|xpack.fleet.registryUrl: $EPR_URL|" "$Y"
      else
        echo "xpack.fleet.registryUrl: $EPR_URL" >> "$Y"
      fi
      chmod 0644 "$Y"
      systemctl restart kibana
    '"
  done
  log "Kibana hosts updated for secure (HTTPS) air-gapped EPR with proper ownership."
else
  warn "No --kibana-hosts-file provided; Kibana configuration step skipped."
fi

log "Secure EPR deployment completed."
