#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=00_common.sh
source "$SCRIPT_DIR/00_common.sh"

print_help() {
  cat <<'EOF'
Usage:
  40_epr_deploy.sh \
    --image-tar <path> --cert <cert.pem> --key <key.pem> --ca <ca.pem>

What it does:
  - Loads the EPR Docker/Podman image from tarball.
  - Deploys it locally with TLS cert, key and CA.
  - Configures Kibana to trust and use this EPR.

Notes:
  - Requires root privileges for Podman/Docker image storage.
  - Certificates are copied to /etc/kibana/fleet/certs with proper ownership for Kibana user.
EOF
  exit 0
}

[[ $# -eq 0 ]] && print_help
require_cmd podman
require_cmd sudo

IMAGE_TAR="" EPR_CERT="" EPR_KEY="" EPR_CA=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image-tar) IMAGE_TAR="$2"; shift 2;;
    --cert) EPR_CERT="$2"; shift 2;;
    --key)  EPR_KEY="$2"; shift 2;;
    --ca)   EPR_CA="$2"; shift 2;;
    --help) print_help;;
    *) die "Unknown arg: $1";;
  esac
done

[[ -n "$IMAGE_TAR" && -n "$EPR_CERT" && -n "$EPR_KEY" && -n "$EPR_CA" ]] || die "Missing required args"

# Ensure destination for certs
CERT_DIR="/etc/kibana/fleet/certs"
sudo mkdir -p "$CERT_DIR"
sudo cp "$EPR_CERT" "$CERT_DIR/cert.pem"
sudo cp "$EPR_KEY"  "$CERT_DIR/key.pem"
sudo cp "$EPR_CA"   "$CERT_DIR/ca.pem"

# Set permissions for Kibana user
default_kbn_user=$(systemctl show kibana -p User --value || true)
default_kbn_group=$(systemctl show kibana -p Group --value || true)
[[ -z "$default_kbn_user" ]] && default_kbn_user="kibana"
[[ -z "$default_kbn_group" ]] && default_kbn_group="kibana"

sudo chown -R "$default_kbn_user:$default_kbn_group" "$CERT_DIR"
sudo chmod 750 "$CERT_DIR"
sudo chmod 640 "$CERT_DIR"/*

# Load image
log "Importing EPR image from $IMAGE_TAR"
sudo TMPDIR=/app/containers podman load -i "$IMAGE_TAR"

# Run container
EPR_PORT=8443
CONTAINER_NAME="epr-secure"
sudo podman rm -f "$CONTAINER_NAME" 2>/dev/null || true
sudo podman run -d --name "$CONTAINER_NAME" \
  -p $EPR_PORT:8443 \
  -v "$CERT_DIR/cert.pem:/usr/share/package-registry/config/cert.pem:ro" \
  -v "$CERT_DIR/key.pem:/usr/share/package-registry/config/key.pem:ro" \
  -v "$CERT_DIR/ca.pem:/usr/share/package-registry/config/ca.pem:ro" \
  docker.elastic.co/package-registry/distribution:8.18.3 \
  --insecure=false --ssl --ssl-cert=/usr/share/package-registry/config/cert.pem \
  --ssl-key=/usr/share/package-registry/config/key.pem --ca=/usr/share/package-registry/config/ca.pem

# Health check
log "Waiting for EPR to become available..."
SERVER_HOST="$(hostname -f 2>/dev/null || hostname)"
for i in {1..30}; do
  if curl -sS --cacert "$EPR_CA" "https://$SERVER_HOST:$EPR_PORT/_status" >/dev/null; then
    log "EPR is up and reachable at https://$SERVER_HOST:$EPR_PORT"
    EPR_URL="https://$SERVER_HOST:$EPR_PORT"
    break
  fi
  sleep 2
done
[[ -n "${EPR_URL:-}" ]] || die "EPR did not start correctly"

# Update Kibana config
log "Configuring Kibana to use EPR at $EPR_URL"
KBN_CFG="/etc/kibana/kibana.yml"
sudo bash -c "grep -q 'xpack.fleet.registryUrl' $KBN_CFG && sed -i 's#xpack.fleet.registryUrl.*#xpack.fleet.registryUrl: \"$EPR_URL\"#' $KBN_CFG || echo 'xpack.fleet.registryUrl: \"$EPR_URL\"' >> $KBN_CFG"

log "Restarting Kibana service"
sudo systemctl restart kibana

log "EPR deployment completed successfully."
