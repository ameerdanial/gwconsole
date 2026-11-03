#!/usr/bin/env bash
# Gateway Console installer — run as root on a fresh Debian 12/13 or Ubuntu 22.04+ LXC.
#   cd gwconsole && bash install.sh
# Re-running it upgrades the app and keeps /etc/gwconsole untouched.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"
APP=/opt/gwconsole
ETC=/etc/gwconsole
VAR=/var/lib/gwconsole

echo "==> packages"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv openssh-client ca-certificates git >/dev/null

echo "==> user"
id gwconsole >/dev/null 2>&1 || useradd --system --home-dir "$VAR" --shell /usr/sbin/nologin gwconsole

NEW_VER=$(cat "$SRC/VERSION" 2>/dev/null || echo unknown)
OLD_VER=$(cat "$APP/VERSION" 2>/dev/null || echo none)
echo "==> app -> $APP  ($OLD_VER -> $NEW_VER)"
mkdir -p "$APP"
rm -rf "$APP/app"
cp -r "$SRC/app" "$APP/"
cp "$SRC/requirements.txt" "$SRC/VERSION" "$APP/"
if [ -d "$SRC/.git" ] && command -v git >/dev/null; then
  git -C "$SRC" describe --tags --always --dirty 2>/dev/null > "$APP/BUILD" || true
fi
[ -d "$APP/venv" ] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --upgrade pip
"$APP/venv/bin/pip" install -q -r "$APP/requirements.txt"
chown -R root:root "$APP"

echo "==> config -> $ETC"
mkdir -p "$ETC" "$VAR"
chown -R gwconsole:gwconsole "$VAR"; chmod 750 "$VAR"
if [ ! -f "$ETC/id_ed25519" ]; then
  ssh-keygen -q -t ed25519 -N '' -C "gwconsole@$(hostname)" -f "$ETC/id_ed25519"
fi
chown gwconsole:gwconsole "$ETC/id_ed25519"; chmod 600 "$ETC/id_ed25519"
touch "$ETC/known_hosts"; chmod 644 "$ETC/known_hosts"
if [ ! -f "$ETC/config.yaml" ]; then
  cp "$SRC/config.example.yaml" "$ETC/config.yaml"
  NEW_CONFIG=1
fi
chown root:gwconsole "$ETC/config.yaml"; chmod 640 "$ETC/config.yaml"
if [ ! -f "$ETC/env" ]; then
  cat > "$ETC/env" <<'EOF'
# Cloudflare API tokens (referenced by api_token_env in config.yaml)
CF_TOKEN_MAIN=
CF_TOKEN_PENIPUMY=
CF_TOKEN_KODJE=
EOF
fi
chown root:root "$ETC/env"; chmod 600 "$ETC/env"
chown root:gwconsole "$ETC"; chmod 750 "$ETC"

echo "==> CLI helper"
cat > /usr/local/bin/gwconsole <<'EOF'
#!/usr/bin/env bash
set -e
ETC=/etc/gwconsole
run() { cd /opt/gwconsole; set -a; [ -r $ETC/env ] && . $ETC/env; set +a; GWC_CONFIG=$ETC/config.yaml exec /opt/gwconsole/venv/bin/python -m app "$@"; }
case "${1:-}" in
  hashpw) run hashpw ;;
  version) echo "gwconsole $(cat /opt/gwconsole/VERSION 2>/dev/null)$( [ -s /opt/gwconsole/BUILD ] && echo " ($(cat /opt/gwconsole/BUILD))")" ;;
  check)  run check ;;
  pubkey) cat $ETC/id_ed25519.pub ;;
  trust)
    [ -n "${2:-}" ] || { echo "usage: gwconsole trust <host> [port]"; exit 1; }
    tmp=$(mktemp); ssh-keyscan -p "${3:-22}" -t ed25519,ecdsa,rsa "$2" 2>/dev/null > "$tmp"
    [ -s "$tmp" ] || { echo "could not reach $2:${3:-22}"; rm -f "$tmp"; exit 1; }
    echo "Host keys for $2:"; ssh-keygen -lf "$tmp"
    read -r -p "Trust these keys? [y/N] " a
    if [ "$a" = y ] || [ "$a" = Y ]; then
      ssh-keygen -R "$2" -f $ETC/known_hosts >/dev/null 2>&1 || true
      [ "${3:-22}" = 22 ] || ssh-keygen -R "[$2]:$3" -f $ETC/known_hosts >/dev/null 2>&1 || true
      cat "$tmp" >> $ETC/known_hosts; chmod 644 $ETC/known_hosts; echo "added."
    fi
    rm -f "$tmp" ;;
  logs)    exec journalctl -u gwconsole -f ;;
  restart) systemctl restart gwconsole && systemctl --no-pager status gwconsole | head -5 ;;
  *) echo "usage: gwconsole {version|hashpw|check|pubkey|trust <host> [port]|logs|restart}"; exit 1 ;;
esac
EOF
chmod 755 /usr/local/bin/gwconsole

echo "==> systemd"
cp "$SRC/gwconsole.service" /etc/systemd/system/gwconsole.service
systemctl daemon-reload
systemctl enable gwconsole >/dev/null 2>&1

if [ "${NEW_CONFIG:-0}" = 1 ]; then
  cat <<EOF

Installed. Next steps:
  1. gwconsole hashpw                     # paste the hash under users: in $ETC/config.yaml
  2. nano $ETC/config.yaml                 # node IPs, tunnels, CF account IDs
  3. nano $ETC/env                         # Cloudflare API tokens
  4. gwconsole pubkey                      # add this key on the HAProxy VM and cloudflared LXC
                                           #   (see prepare-node.sh)
  5. gwconsole trust <haproxy-ip>; gwconsole trust <cloudflared-ip>
  6. gwconsole check
  7. systemctl start gwconsole             # http://$(hostname -I | awk '{print $1}'):8088

EOF
else
  systemctl restart gwconsole
  echo "Upgraded $OLD_VER -> $NEW_VER and restarted. Config untouched."
fi
