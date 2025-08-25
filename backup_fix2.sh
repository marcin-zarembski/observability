#!/usr/bin/env bash
set -euo pipefail

# Usage: ./force_forwarding.sh hosts.txt
# Wymagane: dostęp SSH na hosty (najlepiej jako root lub z sudo NOPASSWD)

HOSTS_FILE="${1:-hosts.txt}"
[[ -r "$HOSTS_FILE" ]] || { echo "File not found: $HOSTS_FILE"; exit 1; }

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o BatchMode=yes)

for host in $(grep -vE '^\s*(#|$)' "$HOSTS_FILE"); do
  echo "=== $host ==="
  ssh "${SSH_OPTS[@]}" "$host" 'bash -s' <<'EOF'
set -euo pipefail

SSHD_MAIN="/etc/ssh/sshd_config"
DIR_D="/etc/ssh/sshd_config.d"
OVERRIDE="$DIR_D/zzz-forwarding-override.conf"
INCLUDE_LINE="Include /etc/ssh/sshd_config.d/zzz-forwarding-override.conf"

echo "[*] Ensuring $DIR_D exists"
sudo mkdir -p "$DIR_D"

echo "[*] Writing $OVERRIDE"
sudo tee "$OVERRIDE" >/dev/null <<'EOC'
# Force TCP forwarding (global)
AllowTcpForwarding yes

# Also ensure inside a catch-all Match block (overrides earlier Matches)
Match all
    AllowTcpForwarding yes
EOC

# Make sure our include is the LAST thing parsed
echo "[*] Ensuring final Include in $SSHD_MAIN"
if ! sudo grep -qxF "$INCLUDE_LINE" "$SSHD_MAIN"; then
  # backup once
  if [ ! -f "${SSHD_MAIN}.bak-forwarding" ]; then
    sudo cp -a "$SSHD_MAIN" "${SSHD_MAIN}.bak-forwarding"
    echo "[*] Backup created: ${SSHD_MAIN}.bak-forwarding"
  fi
  # append include at EOF to guarantee last-wins
  echo "" | sudo tee -a "$SSHD_MAIN" >/dev/null
  echo "$INCLUDE_LINE" | sudo tee -a "$SSHD_MAIN" >/dev/null
  echo "[*] Appended: $INCLUDE_LINE"
else
  echo "[*] Include already present"
fi

echo "[*] Validating sshd config..."
sudo sshd -t

echo "[*] Restarting sshd..."
sudo systemctl restart sshd

echo "[*] Effective (global):"
sshd -T | grep -i '^allowtcpforwarding'

# Show effective in a realistic context (user=root, addr=127.0.0.1, host=$(hostname -f))
HNAME="$(hostname -f 2>/dev/null || hostname)"
echo "[*] Effective (context root@${HNAME}/127.0.0.1):"
sshd -T -C user=root,host="$HNAME",addr=127.0.0.1 | grep -i '^allowtcpforwarding' || true
EOF
done
