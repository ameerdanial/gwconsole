#!/usr/bin/env bash
# Gateway Console installer and upgrader — run as root on a Debian 12/13 or Ubuntu 22.04+ LXC.
#   fresh install:  cd gwconsole && bash install.sh
#   upgrade:        cd gwconsole && git fetch --tags && git checkout vX.Y.Z && bash install.sh
# Upgrades back up /etc/gwconsole and the database first, and never touch your settings.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"
APP=/opt/gwconsole
ETC=/etc/gwconsole
VAR=/var/lib/gwconsole
BAK=/var/backups/gwconsole

NEW_VER=$(cat "$SRC/VERSION" 2>/dev/null || echo unknown)
OLD_VER=$(cat "$APP/VERSION" 2>/dev/null || echo none)

echo "==> packages"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv openssh-client ca-certificates git >/dev/null

echo "==> user"
id gwconsole >/dev/null 2>&1 || useradd --system --home-dir "$VAR" --shell /usr/sbin/nologin gwconsole

if [ "$OLD_VER" != none ]; then
  echo "==> backup before upgrade -> $BAK"
  systemctl stop gwconsole 2>/dev/null || true
  mkdir -p "$BAK"; chmod 700 "$BAK"
  TS=$(date +%Y%m%d-%H%M%S)
  (umask 077; tar czf "$BAK/gwconsole-$OLD_VER-$TS.tar.gz" -C / etc/gwconsole $( [ -d "$VAR" ] && echo var/lib/gwconsole ) 2>/dev/null) || true
  ls -1t "$BAK"/gwconsole-*.tar.gz 2>/dev/null | tail -n +11 | xargs -r rm -f      # keep the last 10
  echo "    saved $BAK/gwconsole-$OLD_VER-$TS.tar.gz"
fi

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
if [ ! -f "$ETC/secret.key" ]; then     # encrypts tokens / webhooks stored in the database
  (umask 077; "$APP/venv/bin/python" -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > "$ETC/secret.key")
  echo "    created $ETC/secret.key — keep it with your backups; the database secrets can't be read without it"
fi
chown root:gwconsole "$ETC/secret.key"; chmod 640 "$ETC/secret.key"
if [ ! -f "$ETC/config.yaml" ]; then
  cp "$SRC/config.example.yaml" "$ETC/config.yaml"
  NEW_CONFIG=1
fi
chown root:gwconsole "$ETC/config.yaml"; chmod 640 "$ETC/config.yaml"
if [ ! -f "$ETC/env" ]; then
  cat > "$ETC/env" <<'EOF'
# Optional. Only used once, to import Cloudflare tokens referenced by api_token_env in an
# old (v1.1) config.yaml. From v1.2 on, add tokens in the web UI: Settings → Cloudflare.
EOF
fi
chown root:root "$ETC/env"; chmod 600 "$ETC/env"
chown root:gwconsole "$ETC"; chmod 750 "$ETC"

echo "==> CLI helper"
cat > /usr/local/bin/gwconsole <<'EOF'
#!/usr/bin/env bash
# gwconsole — helper for the Gateway Console dashboard (installed by install.sh)
set -e
ETC=/etc/gwconsole
# run the app's CLI as the service user, so the database keeps the right owner
run() { cd /opt/gwconsole; set -a; [ -r $ETC/env ] && . $ETC/env; set +a
        GWC_CONFIG=$ETC/config.yaml exec runuser -u gwconsole -- /opt/gwconsole/venv/bin/python -m app "$@"; }
case "${1:-}" in
  version) echo "gwconsole $(cat /opt/gwconsole/VERSION 2>/dev/null)$( [ -s /opt/gwconsole/BUILD ] && echo " ($(cat /opt/gwconsole/BUILD))")" ;;
  create-admin)   run create-admin "${2:-}" ;;
  reset-password) [ -n "${2:-}" ] || { echo "usage: gwconsole reset-password <user>"; exit 1; }; run reset-password "$2" ;;
  users)  run users ;;
  check)  run check ;;
  hashpw) run hashpw ;;
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
  *) cat <<USAGE
usage: gwconsole <command>
  version                  installed version
  create-admin [user]      create a superadmin (first install, or locked out)
  reset-password <user>    set a new password (also re-enables the account)
  users                    list users and roles
  check                    test SSH to every node and every Cloudflare token
  pubkey                   print the dashboard's SSH public key (for prepare-node.sh)
  logs | restart           follow logs / restart the service
USAGE
     exit 1 ;;
esac
EOF
chmod 755 /usr/local/bin/gwconsole

echo "==> systemd"
cp "$SRC/gwconsole.service" /etc/systemd/system/gwconsole.service
systemctl daemon-reload
systemctl enable gwconsole >/dev/null 2>&1

if [ "${NEW_CONFIG:-0}" = 1 ]; then
  cat <<EOF

Installed v$NEW_VER. Next steps:
  1. gwconsole create-admin ameer          # your superadmin login
  2. systemctl start gwconsole              # open http://$(hostname -I | awk '{print $1}'):8088
  3. In the browser: Settings → Nodes       # add the HAProxy VM and cloudflared LXC
                     Settings → Cloudflare  # add your account ID + API token
     (each node needs prepare-node.sh once; the Nodes page shows the exact command)

EOF
else
  systemctl start gwconsole
  echo "Upgraded $OLD_VER -> $NEW_VER. Settings and database kept; backup in $BAK."
  [ "$NEW_VER" != "$OLD_VER" ] && echo "Read CHANGELOG.md for what's new."
fi
