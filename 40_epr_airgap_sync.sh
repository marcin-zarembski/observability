#!/usr/bin/env bash
# 40_epr_deploy.sh — Local secure Elastic Package Registry (EPR) deploy
# Runs on a single (local) host. No SSH. Works with either PEM inputs or
# converts local Elasticsearch JKS -> PEM and uses those.
# Requires: bash, curl, jq, sed, awk, grep, and either docker or podman.

# Guard against running with sh
if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: Run this script with bash (not sh). Example: bash $0 ..." >&2
  exit 1
fi

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=00_common.sh
source "$SCRIPT_DIR/00_common.sh"

print_help() {
  cat <<'EOF'
Usage:
  40_epr_deploy.sh \
    --epr-tar <image.tar> \
    ( --epr-cert </path/server.crt> --epr-key </path/server.key> --epr-ca </path/ca-chain.pem>
      | --from-es-jks [--es-config /etc/elasticsearch/elasticsearch.yml] --ks-pass <ks_password> --ts-pass <ts_password> [--src-alias <alias>] ) \
    [--port <8443>] [--name <epr>]

What it does:
  - Local-only secure EPR deploy (HTTPS) using docker or podman.
  - Health-checks EPR via HTTPS using the provided CA chain.
  - Optional JKS auto-conversion (reuses local Elasticsearch JKS materials):
      * reads keystore/truststore paths from local elasticsearch.yml
      * converts JKS -> PEM (epr.key, epr.crt fullchain, epr-ca-chain.pem) next to the JKS
      * uses those PEMs directly (no tmp copies)
  - Configures local Kibana to trust and use the secure EPR:
      * copies CA, cert, key to /etc/kibana/fleet/certs
      * injects Environment=NODE_EXTRA_CA_CERTS into main kibana.service unit
      * sets in /etc/kibana/kibana.yml:
          xpack.fleet.isAirGapped: true
          xpack.fleet.registryUrl: "https://localhost:<port>"
      * restarts Kibana (systemd)

Notes:
  - Requires docker or podman installed locally.
  - For JKS flow, keytool & openssl must be present locally.
  - Key will be installed for Kibana with 0600 permissions (owned by Kibana service user).

Examples:
  # Using PEM files
  ./40_epr_deploy.sh \
    --epr-tar ./artifacts/package-registry-8.18.3.tar \
    --epr-cert /etc/elasticsearch/ssl/http_fullchain.crt \
    --epr-key  /etc/elasticsearch/ssl/http.key \
    --epr-ca   /etc/elasticsearch/ssl/ca-chain.pem \
    --port 8443

  # Using local Elasticsearch JKS
  ./40_epr_deploy.sh \
    --epr-tar ./artifacts/package-registry-8.18.3.tar \
    --from-es-jks --es-config /etc/elasticsearch/elasticsearch.yml \
    --ks-pass 'KeystorePass' --ts-pass 'TruststorePass' \
    --port 8443
EOF
  exit 0
}

[[ $# -eq 0 ]] && print_help
require_cmd curl jq sed awk grep

# Args
EPR_TAR="" EPR_CERT="" EPR_KEY="" EPR_CA=""
EPR_NAME="epr" EPR_PORT="8443"
# JKS auto-conversion (local)
FROM_ES_JKS="" ES_CONF_PATH="/etc/elasticsearch/elasticsearch.yml" KS_PASS="" TS_PASS="" SRC_ALIAS=""

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
    --ks-pass)  KS_PASS="${ARGS[i+1]}"; ((i+=2));;
    --ts-pass)  TS_PASS="${ARGS[i+1]}"; ((i+=2));;
    --src-alias) SRC_ALIAS="${ARGS[i+1]}"; ((i+=2));;
    --help|-h) print_help;;
    *) ((i+=1));;
  esac
done

# Validate inputs (either PEM or JKS)
[[ -n "$EPR_TAR" ]] || die "Missing required arg: --epr-tar"

if [[ -n "$EPR_CERT" || -n "$EPR_KEY" || -n "$EPR_CA" ]]; then
  [[ -n "$EPR_CERT" && -n "$EPR_KEY" && -n "$EPR_CA" ]] || die "Provide all of --epr-cert/--epr-key/--epr-ca or none (when using --from-es-jks)"
  [[ -f "$EPR_CERT" && -f "$EPR_KEY" && -f "$EPR_CA" ]] || die "One or more PEM files do not exist"
elif [[ -n "$FROM_ES_JKS" ]]; then
  [[ -f "$ES_CONF_PATH" ]] || die "elasticsearch.yml not found: $ES_CONF_PATH"
  [[ -n "$KS_PASS" && -n "$TS_PASS" ]] || die "--from-es-jks requires --ks-pass and --ts-pass"
else
  die "Either provide --epr-cert/--epr-key/--epr-ca OR use --from-es-jks with --ks-pass/--ts-pass"
fi

LOG_FILE="$LOG_DIR/$(date +%Y%m%d_%H%M%S)_40_epr_deploy.log"

# 0) If JKS auto-conversion requested, perform it locally using elasticsearch.yml
if [[ -n "$FROM_ES_JKS" ]]; then
  log "[local] Reading $ES_CONF_PATH to locate keystore/truststore paths"
  # Extract paths from elasticsearch.yml without external YAML tools
  KEYSTORE_PATH="$(sudo awk -F: '/xpack.security.http.ssl.keystore.path/ {sub(/^[ 	]+/,""); sub(/#[^$]*/,""); print $2}' "$ES_CONF_PATH" | sed 's/[ \"	]//g' | head -n1)"
  TRUSTSTORE_PATH="$(sudo awk -F: '/xpack.security.http.ssl.truststore.path/ {sub(/^[ 	]+/,""); sub(/#[^$]*/,""); print $2}' "$ES_CONF_PATH" | sed 's/[ \"	]//g' | head -n1)"
  [[ -n "$KEYSTORE_PATH" ]] || die "Could not parse xpack.security.http.ssl.keystore.path from $ES_CONF_PATH"
  [[ -n "$TRUSTSTORE_PATH" ]] || die "Could not parse xpack.security.http.ssl.truststore.path from $ES_CONF_PATH"

  require_cmd keytool
  require_cmd openssl

  ES_DIR="$(dirname "$KEYSTORE_PATH")"

  # Determine alias (first PrivateKeyEntry) if not provided
  if [[ -z "$SRC_ALIAS" ]]; then
    SRC_ALIAS="$(sudo keytool -list -v -keystore "$KEYSTORE_PATH" -storepass "$KS_PASS" 2>/dev/null | awk -F': ' '/Alias name/ {a=$2} /Entry type: PrivateKeyEntry/ {print a; exit}')"
  fi
  [[ -n "$SRC_ALIAS" ]] || die "No PrivateKeyEntry found in keystore ($KEYSTORE_PATH). Cannot extract key+cert."

  log "[local] Converting JKS -> PEM in $ES_DIR (alias=$SRC_ALIAS)"
  sudo bash -lc "set -e; \
    keytool -importkeystore \
      -srckeystore '$KEYSTORE_PATH' -srcstoretype JKS -srcstorepass '$KS_PASS' \
      -destkeystore '$ES_DIR/epr.p12' -deststoretype PKCS12 -deststorepass '$KS_PASS' \
      -srcalias '$SRC_ALIAS'; \
    openssl pkcs12 -in '$ES_DIR/epr.p12' -passin pass:'$KS_PASS' -nocerts -nodes -out '$ES_DIR/epr.key'; \
    openssl pkcs12 -in '$ES_DIR/epr.p12' -passin pass:'$KS_PASS' -clcerts -nokeys -out '$ES_DIR/epr.crt'; \
    : > '$ES_DIR/epr-ca-chain.pem'; \
    for a in $(keytool -list -keystore '$TRUSTSTORE_PATH' -storepass '$TS_PASS' 2>/dev/null | awk -F': ' '/Alias name/ {print $2}'); do \
      keytool -exportcert -rfc -alias "$a" -keystore '$TRUSTSTORE_PATH' -storepass '$TS_PASS' >> '$ES_DIR/epr-ca-chain.pem'; \
    done; \
    chmod 600 '$ES_DIR/epr.key'; \
    chmod 644 '$ES_DIR/epr.crt' '$ES_DIR/epr-ca-chain.pem' || true"

  # Basic validation
  sudo grep -q "BEGIN PRIVATE KEY" "$ES_DIR/epr.key"      || die "Extracted key looks invalid: $ES_DIR/epr.key"
  sudo grep -q "BEGIN CERTIFICATE" "$ES_DIR/epr.crt"      || warn "Extracted cert appears empty — your keystore may not contain the leaf cert. You can still start EPR if you provide a valid cert via --epr-cert later."
  sudo test -s "$ES_DIR/epr-ca-chain.pem"                  || warn "Extracted CA chain is empty."

  # Use PEMs in original JKS directory
  EPR_KEY="$ES_DIR/epr.key"
  EPR_CERT="$ES_DIR/epr.crt"
  EPR_CA="$ES_DIR/epr-ca-chain.pem"
fi

# 1) Detect container runtime
log "[local] Detecting container runtime"
if command -v docker >/dev/null 2>&1; then RUNTIME=docker; elif command -v podman >/dev/null 2>&1; then RUNTIME=podman; else die "Neither docker nor podman found"; fi

# 2) Load image
log "[local] Loading EPR image: $EPR_TAR"
$RUNTIME load -i "$EPR_TAR" >/dev/null 2>&1 || true

# Determine image name (best-effort)
IMG_NAME="$($RUNTIME images --format '{{.Repository}}:{{.Tag}}' | grep -E 'package-registry' | head -n1)"
[[ -n "$IMG_NAME" ]] || IMG_NAME="docker.elastic.co/package-registry/distribution:latest"

# 3) (Re)start EPR container securely
log "[local] (Re)starting secure EPR container '$EPR_NAME' on HTTPS port $EPR_PORT (image: $IMG_NAME)"
$RUNTIME rm -f "$EPR_NAME" >/dev/null 2>&1 || true
$RUNTIME run -d --name "$EPR_NAME" --restart unless-stopped \
  -p "$EPR_PORT:8080" \
  -v "$EPR_CERT:/usr/share/package-registry/config/cert.pem:ro" \
  -v "$EPR_KEY:/usr/share/package-registry/config/key.pem:ro" \
  -v "$EPR_CA:/usr/share/package-registry/config/ca.pem:ro" \
  "$IMG_NAME" \
  --tls-cert /usr/share/package-registry/config/cert.pem \
  --tls-key  /usr/share/package-registry/config/key.pem

# 4) Health check via HTTPS using provided CA
EPR_URL="https://localhost:$EPR_PORT"
log "[local] Waiting for $EPR_URL/health (24x5s, TLS verify with provided CA)"
if ! retry 24 5 bash -lc "curl -fsS --cacert '$EPR_CA' '$EPR_URL/health' >/dev/null"; then
  warn "[local] EPR health check failed at $EPR_URL/health (with --cacert)"
else
  log "[local] EPR is healthy (HTTPS)"
fi

# 5) Configure LOCAL Kibana
KBN_CERT_DIR="/etc/kibana/fleet/certs"
log "[local] Installing EPR TLS materials for Kibana in $KBN_CERT_DIR and configuring registryUrl: $EPR_URL"

sudo mkdir -p "$KBN_CERT_DIR"
sudo cp "$EPR_CA"  "$KBN_CERT_DIR/epr-ca-chain.pem"
sudo cp "$EPR_CERT" "$KBN_CERT_DIR/epr.crt"
sudo cp "$EPR_KEY"  "$KBN_CERT_DIR/epr.key"

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
    sed -i "s|^xpack.fleet.registryUrl:.*|xpack.fleet.registryUrl: '$EPR_URL'|" "$Y"
  else
    echo "xpack.fleet.registryUrl: '$EPR_URL'" >> "$Y"
  fi
  chmod 0644 "$Y"
  systemctl restart kibana
'

log "Local secure EPR deployment completed."
