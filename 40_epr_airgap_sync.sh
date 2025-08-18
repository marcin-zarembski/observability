#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)"
# shellcheck source=00_common.sh
source "$SCRIPT_DIR/00_common.sh"

print_help() {
  cat <<'EOF'
Usage:
  40_epr_deploy.sh \
    --epr-tar <image.tar> \
    ( --epr-cert </path/to/server.crt> --epr-key </path/to/server.key> --epr-ca </path/to/ca-chain.pem>
      | --from-es-jks [--es-config /etc/elasticsearch/elasticsearch.yml] --jks-pass <password> [--src-alias <alias>] ) \
    [--port <8443>] [--name <epr>]

What it does:
  - **Local-only** secure EPR deploy (HTTPS) on this machine (no SSH, no remote hosts).
  - Loads provided image tar and runs EPR container with TLS cert/key.
  - Health-checks EPR via HTTPS using the provided CA chain.
  - Optional JKS auto-conversion (reuses **local** Elasticsearch JKS materials):
      * reads keystore/truststore paths from local elasticsearch.yml
      * converts JKS -> PEM (epr.key, epr.crt fullchain, epr-ca-chain.pem) next to the JKS, then uses them
  - Configures **local Kibana** to trust EPR CA and use the secure registry URL:
      * copies CA to /etc/kibana/certs/epr-ca-chain.pem (ownership = Kibana service user)
      * injects Environment=NODE_EXTRA_CA_CERTS into the main systemd unit for Kibana
      * sets in /etc/kibana/kibana.yml:
          xpack.fleet.isAirGapped: true
          xpack.fleet.registryUrl: "https://localhost:<port>"
      * restarts Kibana (systemd)

Notes:
  - Requires Docker or Podman **installed locally**.
  - For JKS flow, keytool & openssl must be present locally.

Examples:
  # Using PEM files
  ./40_epr_deploy.sh \
    --epr-tar ./artifacts/package-registry-8.18.3.tar \
    --epr-cert ./cfg/tls/epr.crt --epr-key ./cfg/tls/epr.key --epr-ca ./cfg/tls/epr-ca-chain.pem \
    --port 8443

  # Using local Elasticsearch JKS
  ./40_epr_deploy.sh \
    --epr-tar ./artifacts/package-registry-8.18.3.tar \
    --from-es-jks --es-config /etc/elasticsearch/elasticsearch.yml --jks-pass 'Secret123' \
    --port 8443
EOF
  exit 0
}

[[ $# -eq 0 ]] && print_help
require_cmd curl jq sed awk grep

# Args
EPR_TAR="" EPR_CERT="" EPR_KEY="" EPR_CA=""
EPR_NAME="epr" EPR_PORT="8443"
# JKS auto-conversion inputs (local)
FROM_ES_JKS="" ES_CONF_PATH="/etc/elasticsearch/elasticsearch.yml" JKS_PASS="" SRC_ALIAS=""

ARGS=("$@")

i=0
while [[ $i -lt ${#ARGS[@]} ]]; do
  case "${ARGS[i]}" in
    --epr-tar)  EPR_TAR="${ARGS[i+1]}";  ((i+=2));;
    --epr-cert) EPR_CERT="${ARGS[i+1]}"; ((i+=2));;
    --epr-key)  EPR_KEY="${ARGS[i+1]}";  ((i+=2));;
    --epr-ca)   EPR_CA="${ARGS[i+1]}";   ((i+=2));;
    --name)     EPR_NAME="${ARGS[i+1]}"; ((i+=2));;
    --port)     EPR_PORT="${ARGS[i+1]}"; ((i+=2));;
    --from-es-jks) FROM_ES_JKS="yes"; ((i+=1));;
    --es-config) ES_CONF_PATH="${ARGS[i+1]}"; ((i+=2));;
    --jks-pass) JKS_PASS="${ARGS[i+1]}"; ((i+=2));;
    --src-alias) SRC_ALIAS="${ARGS[i+1]}"; ((i+=2));;
    --help) print_help;;
    *) ((i+=1));;
  esac
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
[[ -n "$EPR_TAR" ]] || die "Missing required arg: --epr-tar"

if [[ -n "$EPR_CERT" || -n "$EPR_KEY" || -n "$EPR_CA" ]]; then
  [[ -n "$EPR_CERT" && -n "$EPR_KEY" && -n "$EPR_CA" ]] || die "Provide all of --epr-cert/--epr-key/--epr-ca or none (when using --from-es-jks)"
  [[ -f "$EPR_CERT" && -f "$EPR_KEY" && -f "$EPR_CA" ]] || die "One or more PEM files do not exist"
elif [[ -n "$FROM_ES_JKS" && -n "$JKS_PASS" ]]; then
  : # JKS mode selected; will derive PEMs below
else
  die "Either provide --epr-cert/--epr-key/--epr-ca OR use --from-es-jks with --jks-pass"
files do not exist"
elif [[ -n "$ES_CONF_HOST" && -n "$JKS_PASS" ]]; then
  : # JKS mode selected; will derive PEMs below
else
  die "Either provide --epr-cert/--epr-key/--epr-ca OR use --from-es-jks-host with --jks-pass"
fi

LOG_FILE="$LOG_DIR/$(date +%Y%m%d_%H%M%S)_40_epr_deploy.log"

# 0) If JKS auto-conversion requested, perform it locally using elasticsearch.yml
LOCAL_TLS_TMP="${SCRIPT_DIR}/.tls_tmp_$(date +%s)"
if [[ -n "$FROM_ES_JKS" && -n "$JKS_PASS" ]]; then
  log "[local] Reading $ES_CONF_PATH to locate keystore/truststore paths"
  # Extract paths from elasticsearch.yml (best-effort without yq)
  KEYSTORE_PATH="$(sudo awk -F: '/xpack.security.http.ssl.keystore.path/ {sub(/^[ 	]+/,""); sub(/#[^$]*/,""); print $2}' "$ES_CONF_PATH" | sed 's/[ \"	]//g' | head -n1)"
  TRUSTSTORE_PATH="$(sudo awk -F: '/xpack.security.http.ssl.truststore.path/ {sub(/^[ 	]+/,""); sub(/#[^$]*/,""); print $2}' "$ES_CONF_PATH" | sed 's/[ \"	]//g' | head -n1)"
  [[ -n "$KEYSTORE_PATH" ]] || die "Could not parse keystore.path from $ES_CONF_PATH"
  [[ -n "$TRUSTSTORE_PATH" ]] || die "Could not parse truststore.path from $ES_CONF_PATH"

  command -v keytool >/dev/null || die "keytool not found locally"
  command -v openssl >/dev/null || die "openssl not found locally"

  ES_DIR="$(dirname "$KEYSTORE_PATH")"

  # Determine alias if not provided
  if [[ -z "$SRC_ALIAS" ]]; then
    SRC_ALIAS="$(sudo keytool -list -keystore "$KEYSTORE_PATH" -storepass "$JKS_PASS" 2>/dev/null | awk -F': ' '/Alias name/ {a=$2} /Entry type: PrivateKeyEntry/ {print a; exit}')"
    [[ -n "$SRC_ALIAS" ]] || die "Could not determine PrivateKeyEntry alias from keystore"
  fi

  log "[local] Converting JKS -> PEM in $ES_DIR (alias=$SRC_ALIAS)"
  sudo bash -lc "set -e; \
    keytool -importkeystore \
      -srckeystore '$KEYSTORE_PATH' -srcstoretype JKS -srcstorepass '$JKS_PASS' \
      -destkeystore '$ES_DIR/epr.p12' -deststoretype PKCS12 -deststorepass '$JKS_PASS' \
      -srcalias '$SRC_ALIAS'; \
    openssl pkcs12 -in '$ES_DIR/epr.p12' -passin pass:'$JKS_PASS' -nocerts -nodes -out '$ES_DIR/epr.key'; \
    openssl pkcs12 -in '$ES_DIR/epr.p12' -passin pass:'$JKS_PASS' -clcerts -nokeys -out '$ES_DIR/epr.crt'; \
    : > '$ES_DIR/epr-ca-chain.pem'; \
    for a in $(keytool -list -keystore '$TRUSTSTORE_PATH' -storepass '$JKS_PASS' 2>/dev/null | awk -F': ' '/Alias name/ {print $2}'); do \
      keytool -exportcert -rfc -alias "$a" -keystore '$TRUSTSTORE_PATH' -storepass '$JKS_PASS' >> '$ES_DIR/epr-ca-chain.pem'; \
    done; \
    chmod 600 '$ES_DIR/epr.key'"

  # Ensure readable perms for non-root tooling (curl) on CA/cert; key stays 600
sudo chmod 644 "$ES_DIR/epr.crt" "$ES_DIR/epr-ca-chain.pem" || true

# Use PEMs in their original directory next to JKS
EPR_KEY="$ES_DIR/epr.key"
EPR_CERT="$ES_DIR/epr.crt"
EPR_CA="$ES_DIR/epr-ca-chain.pem"

# 1) Load image locally and (re)start container securely
log "[local] Detecting container runtime"
if command -v docker >/dev/null 2>&1; then RUNTIME=docker; elif command -v podman >/dev/null 2>&1; then RUNTIME=podman; else die "Neither docker nor podman found"; fi

log "[local] Loading EPR image: $EPR_TAR"
$RUNTIME load -i "$EPR_TAR" >/dev/null 2>&1 || true

log "[local] (Re)starting secure EPR container '$EPR_NAME' on HTTPS port $EPR_PORT"
$RUNTIME rm -f "$EPR_NAME" >/dev/null 2>&1 || true
$RUNTIME run -d --name "$EPR_NAME" --restart unless-stopped \
  -p "$EPR_PORT:8080" \
  -v "$EPR_CERT:/usr/share/package-registry/config/cert.pem:ro" \
  -v "$EPR_KEY:/usr/share/package-registry/config/key.pem:ro" \
  -v "$EPR_CA:/usr/share/package-registry/config/ca.pem:ro" \
  "$( $RUNTIME images --format '{{.Repository}}:{{.Tag}}' | grep package-registry | head -n1 || echo docker.elastic.co/package-registry/distribution:latest)" \
  --tls-cert /usr/share/package-registry/config/cert.pem \
  --tls-key  /usr/share/package-registry/config/key.pem

# 2) Health check via HTTPS using provided CA
EPR_URL="https://localhost:$EPR_PORT"
log "[local] Waiting for $EPR_URL/health (24x5s, TLS verify with provided CA)"
if ! retry 24 5 bash -lc "curl -fsS --cacert '$EPR_CA' '$EPR_URL/health' >/dev/null"; then
  warn "[local] EPR health check failed at $EPR_URL/health (with --cacert)"
else
  log "[local] EPR is healthy (HTTPS)"
fi

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

# 3) Configure LOCAL Kibana
log "[local] Installing EPR CA, injecting NODE_EXTRA_CA_CERTS, configuring registryUrl: $EPR_URL"

# Ensure target directories exist
sudo mkdir -p /etc/kibana/certs
sudo chmod 0755 /etc/kibana
sudo chmod 0755 /etc/kibana/certs

# Copy CA
sudo cp "$EPR_CA" /etc/kibana/certs/epr-ca-chain.pem

# Fix ownership/permissions according to Kibana service user/group; inject env into main unit
sudo bash -lc '
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
'

# Update kibana.yml and restart
sudo bash -lc '
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
'

log "Local secure EPR deployment completed."
