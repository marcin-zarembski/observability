#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./fix_forwarding.sh hosts.txt
#
# hosts.txt = plik z listą hostów (jeden host per linia, bez #komentarzy)
# wymagane: SSH dostęp (najlepiej jako root albo z sudo NOPASSWD)

HOSTS_FILE="${1:-hosts.txt}"

[[ -r "$HOSTS_FILE" ]] || { echo "File not found: $HOSTS_FILE"; exit 1; }

# wspólne opcje ssh
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o BatchMode=yes)

for host in $(grep -vE '^\s*(#|$)' "$HOSTS_FILE"); do
  echo "=== $host ==="

  ssh "${SSH_OPTS[@]}" "$host" 'bash -s' <<'EOF'
set -euo pipefail
echo "[*] Writing drop-in to /etc/ssh/sshd_config.d/99-forwarding.conf"
printf "AllowTcpForwarding yes\n" | sudo tee /etc/ssh/sshd_config.d/99-forwarding.conf >/dev/null

echo "[*] Validating sshd config"
sudo sshd -t

echo "[*] Restarting sshd"
sudo systemctl restart sshd

echo "[*] Effective value:"
sshd -T | grep -i allowtcpforwarding
EOF

done
