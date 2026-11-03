#!/usr/bin/env bash
# Prepare a managed node (HAProxy VM or cloudflared LXC) for Gateway Console.
# Run as root ON THE NODE:
#   bash prepare-node.sh --key "ssh-ed25519 AAAA... gwconsole@gwc" --from 192.168.10.50 [--haproxy]
#
#   --key      the dashboard public key (on the dashboard LXC: gwconsole pubkey)
#   --from     dashboard LXC IP; the key is only accepted from this address
#   --haproxy  also install socat and check the HAProxy admin stats socket
set -euo pipefail

KEY=""; FROM=""; HAP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --key) KEY="$2"; shift 2 ;;
    --from) FROM="$2"; shift 2 ;;
    --haproxy) HAP=1; shift ;;
    *) echo "unknown arg $1"; exit 1 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
[ -n "$KEY" ] && [ -n "$FROM" ] || { sed -n '2,9p' "$0"; exit 1; }

echo "==> authorized_keys (restricted to $FROM)"
mkdir -p /root/.ssh && chmod 700 /root/.ssh
touch /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
KEYBODY=$(echo "$KEY" | awk '{print $2}')
if grep -q "$KEYBODY" /root/.ssh/authorized_keys; then
  echo "    key already present"
else
  echo "from=\"$FROM\",no-port-forwarding,no-agent-forwarding,no-X11-forwarding $KEY" >> /root/.ssh/authorized_keys
  echo "    added"
fi
if grep -Eq '^\s*PermitRootLogin\s+no' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
  echo "    WARNING: sshd has 'PermitRootLogin no'. Set 'PermitRootLogin prohibit-password' (key-only) and restart ssh,"
  echo "             or use a dedicated user with sudo: true in config.yaml."
fi

if [ "$HAP" = 1 ]; then
  echo "==> HAProxy"
  command -v socat >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq socat >/dev/null; echo "    socat installed"; }
  CFG=/etc/haproxy/haproxy.cfg
  if grep -Eq '^\s*stats\s+socket\s+\S+.*level\s+admin' "$CFG"; then
    echo "    admin stats socket: OK ($(grep -E '^\s*stats\s+socket' "$CFG" | head -1 | xargs))"
  else
    echo "    MISSING admin stats socket. Add this line inside the 'global' section of $CFG:"
    echo "        stats socket /run/haproxy/admin.sock mode 660 level admin"
    echo "    then:  haproxy -c -f $CFG && systemctl reload haproxy"
  fi
fi
echo "done."
