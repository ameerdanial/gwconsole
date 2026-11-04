#!/usr/bin/env bash
# Gateway Console installer and upgrader. Run as root on any systemd Linux host
# (VM, LXC, bare metal): Debian 12+, Ubuntu 22.04+, RHEL / Rocky / Alma / Fedora.
#
#   fresh install:   bash install.sh                  asks a few questions, defaults in [brackets]
#   unattended:      GWC_ADMIN_PASSWORD='…' bash install.sh --yes --admin ameer [--listen IP] [--port N]
#   upgrade:         gwconsole upgrade                (or: git checkout vX.Y.Z && bash install.sh)
#
# Upgrades never ask anything: they back up /etc/gwconsole and the database first and keep
# every setting. After a fresh install the browser walks you through nodes, Cloudflare and alerts.
set -euo pipefail

usage() { sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; cat <<'EOF'

options:
  --listen IP       bind address                       (default 0.0.0.0 = all interfaces)
  --port N          web port                           (default 8088)
  --admin NAME      first superadmin username          (default admin)
  --yes, -y         don't ask: take the defaults / the values given above
  --no-firewall     never touch ufw / firewalld
  --skip-packages   don't install OS packages (you installed python3 >= 3.10, venv, ssh client, git)
  --help
EOF
}

# ---- arguments ---------------------------------------------------------------------------------
LISTEN=""; PORT=""; ADMIN=""; YES=0; FIREWALL=1; PKGS=1
while [ $# -gt 0 ]; do
  case "$1" in
    --listen) LISTEN="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --admin) ADMIN="${2:-}"; shift 2 ;;
    -y|--yes) YES=1; shift ;;
    --no-firewall) FIREWALL=0; shift ;;
    --skip-packages) PKGS=0; shift ;;
    --upgrade) shift ;;                       # accepted for clarity; upgrades are detected
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1  (see --help)"; exit 1 ;;
  esac
done

SRC="$(cd "$(dirname "$0")" && pwd)"
APP=/opt/gwconsole
ETC=/etc/gwconsole
VAR=/var/lib/gwconsole
BAK=/var/backups/gwconsole
NEW_VER=$(cat "$SRC/VERSION" 2>/dev/null || echo unknown)
OLD_VER=$(cat "$APP/VERSION" 2>/dev/null || echo none)
UPGRADE=0; [ "$OLD_VER" != none ] && UPGRADE=1

# ---- output helpers ----------------------------------------------------------------------------
if [ -t 1 ]; then B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; D=$'\e[2m'; N=$'\e[0m'; else B= G= Y= R= D= N=; fi
step() { echo "${B}==>${N} $*"; }
ok()   { echo "    ${G}✓${N} $*"; }
warn() { echo "    ${Y}!${N} $*"; }
die()  { echo "    ${R}✗ $*${N}" >&2; exit 1; }

# Questions are read from the terminal, so "curl … | bash" still works. No terminal or --yes → defaults.
TTY=""
if [ "$YES" = 0 ] && [ "$UPGRADE" = 0 ] && { exec 3</dev/tty; } 2>/dev/null; then TTY=1; fi
ask() {   # ask VAR "question" default   (locals are __-prefixed so they never shadow VAR)
  local __v=$1 __q=$2 __def=${3:-} __a=""
  if [ -n "$TTY" ]; then read -r -u 3 -p "    $__q ${__def:+${D}[$__def]${N} }" __a || true; fi
  printf -v "$__v" '%s' "${__a:-$__def}"
}
yesno() { # yesno "question" default(y/n) → exit status
  local __yn=""; ask __yn "$1 (y/n)" "$2"; case "$__yn" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}
ask_secret() {
  local __v=$1 __q=$2 __a=""
  read -r -s -u 3 -p "    $__q " __a || true; echo
  printf -v "$__v" '%s' "$__a"
}
pw_problem() {  # same rule as the app (store.check_password_strength)
  local p=$1
  [ ${#p} -ge 10 ] || { echo "at least 10 characters"; return; }
  [[ $p =~ [a-z] && $p =~ [A-Z] && $p =~ [0-9] ]] || { echo "needs upper and lower case letters and a digit"; return; }
}
valid_user() { [[ $1 =~ ^[A-Za-z0-9_.@-]{2,48}$ ]]; }
valid_port() { [[ $1 =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
valid_ip()   { [ "$1" = 0.0.0.0 ] || [ "$1" = "::" ] || python_ok_ip "$1"; }
python_ok_ip() { "${PY:-python3}" -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$1" 2>/dev/null; }
host_ips() { { hostname -I 2>/dev/null || ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1; } \
             | tr ' ' '\n' | grep -E '^[0-9]+\.' | head -5; }
port_free() { "$PY" - "$1" "$2" <<'PYEOF' 2>/dev/null
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
fam = socket.AF_INET6 if ":" in host else socket.AF_INET
s = socket.socket(fam, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind((host, port))
except OSError:
    sys.exit(1)
PYEOF
}

echo
echo "${B}Gateway Console $NEW_VER${N} — $( [ $UPGRADE = 1 ] && echo "upgrade from $OLD_VER" || echo "fresh install")"
echo

# ---- preflight ---------------------------------------------------------------------------------
step "checking this host"
[ "$(id -u)" -eq 0 ] || die "run as root (sudo bash install.sh)"
[ -f "$SRC/app/main.py" ] || die "run install.sh from inside the gwconsole folder"
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null; then ok "systemd"
else die "systemd is not running here. Gateway Console runs as a systemd service; on an LXC make sure it's a systemd template (Debian/Ubuntu/Rocky)."; fi
OS="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
if command -v apt-get >/dev/null; then PM=apt
elif command -v dnf >/dev/null; then PM=dnf
elif command -v yum >/dev/null; then PM=yum
else PM=""; fi
ok "$OS${PM:+ ($PM)}"

pick_python() {
  PY=""
  for c in python3.13 python3.12 python3.11 python3.10 python3; do
    command -v "$c" >/dev/null || continue
    if "$c" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then PY=$(command -v "$c"); return 0; fi
  done
  return 1
}

if [ "$PKGS" = 1 ]; then
  step "installing packages"
  case "$PM" in
    apt)
      apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv openssh-client ca-certificates git >/dev/null
      ;;
    dnf|yum)
      $PM install -y -q python3 openssh-clients ca-certificates git >/dev/null
      if ! pick_python; then     # RHEL/Rocky/Alma 8–9 ship 3.6/3.9 as python3; 3.11 is in AppStream
        $PM install -y -q python3.11 >/dev/null 2>&1 || $PM install -y -q python3.12 >/dev/null 2>&1 || true
      fi
      ;;
    *) warn "unknown package manager: install python3 (3.10+), python3-venv, an ssh client and git yourself, then use --skip-packages"; exit 1 ;;
  esac
  ok "python, venv, ssh client, git"
fi
pick_python || die "Python 3.10 or newer is needed (found: $(python3 -V 2>&1 || echo none)). Debian 12+, Ubuntu 22.04+ and RHEL-family 8+ (python3.11) have it."
"$PY" -c 'import venv, ensurepip' 2>/dev/null || die "$PY has no venv/ensurepip module — install the python3-venv package"
ok "$("$PY" -V) at $PY"

if [ -d "$APP/venv" ] && ! "$APP/venv/bin/python" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
  warn "old virtualenv uses an unsupported Python — rebuilding it"; rm -rf "$APP/venv"
fi

if command -v timedatectl >/dev/null && [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = no ]; then
  warn "clock is not NTP-synchronised — Cloudflare API calls and alert times may be off (timedatectl set-ntp true)"
fi
if "$PY" -c 'import urllib.request; urllib.request.urlopen("https://api.cloudflare.com/client/v4/", timeout=6)' 2>/dev/null \
   || "$PY" -c 'import urllib.request, urllib.error, sys
try: urllib.request.urlopen("https://api.cloudflare.com/client/v4/", timeout=6)
except urllib.error.HTTPError: sys.exit(0)
except Exception: sys.exit(1)' 2>/dev/null; then ok "can reach api.cloudflare.com"
else warn "cannot reach api.cloudflare.com right now — the Cloudflare features need outbound HTTPS"; fi

# ---- questions (fresh install only) -----------------------------------------------------------
if [ "$UPGRADE" = 0 ]; then
  HAVE_CFG=0; [ -f "$ETC/config.yaml" ] && HAVE_CFG=1
  if [ $HAVE_CFG = 1 ]; then
    LISTEN=$(awk '/^listen:/{print $2}' "$ETC/config.yaml"); PORT=$(awk '/^port:/{print $2}' "$ETC/config.yaml")
    ok "keeping existing $ETC/config.yaml (listen ${LISTEN:-0.0.0.0}, port ${PORT:-8088})"
  fi
  LISTEN=${LISTEN:-0.0.0.0}; PORT=${PORT:-8088}; ADMIN=${ADMIN:-admin}

  if [ -n "$TTY" ]; then
    echo; step "a few questions (Enter keeps the default)"
    if [ $HAVE_CFG = 0 ]; then
      echo "    ${D}This host's addresses: $(host_ips | xargs | sed 's/ /, /g'). 0.0.0.0 listens on all of them.${N}"
      d=$LISTEN; while :; do ask LISTEN "Listen address:" "$d"; valid_ip "$LISTEN" && break; warn "not an IP address"; done
      d=$PORT; while :; do
        ask PORT "Web port:" "$d"
        valid_port "$PORT" || { warn "1-65535"; continue; }
        port_free "$LISTEN" "$PORT" && break; warn "port $PORT is already in use on $LISTEN — pick another"
      done
    fi
  fi
  valid_ip "$LISTEN" || die "--listen: not an IP address: $LISTEN"
  valid_port "$PORT" || die "--port: not a port: $PORT"
  [ $HAVE_CFG = 1 ] || port_free "$LISTEN" "$PORT" || die "port $PORT is already in use on $LISTEN (use --port)"

  # first superadmin — skipped when the database already has users (re-install, or v1.1 import)
  NEED_ADMIN=1
  if [ -f "$VAR/gwconsole.db" ] || grep -Eq '^users:' "$ETC/config.yaml" 2>/dev/null; then NEED_ADMIN=0; fi
  if [ $NEED_ADMIN = 1 ]; then
    if [ -n "$TTY" ]; then
      d=$ADMIN; while :; do ask ADMIN "Admin username:" "$d"; valid_user "$ADMIN" && break; warn "2-48 chars: letters, digits, _ . @ -"; done
      echo "    ${D}Password: 10+ characters with upper and lower case letters and a digit.${N}"
      while :; do
        ask_secret ADMIN_PW "Admin password:"
        p=$(pw_problem "$ADMIN_PW"); [ -z "$p" ] || { warn "$p"; continue; }
        ask_secret ADMIN_PW2 "Repeat password:"
        [ "$ADMIN_PW" = "$ADMIN_PW2" ] && break; warn "passwords don't match"
      done
      unset ADMIN_PW2
    else
      ADMIN_PW=${GWC_ADMIN_PASSWORD:-}
      valid_user "$ADMIN" || die "--admin: 2-48 chars, letters, digits, _ . @ -"
      [ -n "$ADMIN_PW" ] || die "no terminal to ask for a password: set GWC_ADMIN_PASSWORD (env, not an argument) or run interactively"
      p=$(pw_problem "$ADMIN_PW"); [ -z "$p" ] || die "GWC_ADMIN_PASSWORD: $p"
    fi
  fi

  FW=""
  if [ "$FIREWALL" = 1 ]; then
    if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then FW=ufw
    elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then FW=firewalld; fi
    if [ -n "$FW" ] && ! yesno "$FW is active. Open TCP port $PORT for the dashboard?" y; then FW=""; fi
  fi
  [ -n "$TTY" ] && echo
fi
unset GWC_ADMIN_PASSWORD

# ---- install -----------------------------------------------------------------------------------
step "service user"
id gwconsole >/dev/null 2>&1 || useradd --system --home-dir "$VAR" --shell "$(command -v nologin || echo /sbin/nologin)" gwconsole
ok "gwconsole"

if [ "$UPGRADE" = 1 ]; then
  step "backup before upgrade"
  systemctl stop gwconsole 2>/dev/null || true
  mkdir -p "$BAK"; chown root:"$(id -gn gwconsole)" "$BAK"; chmod 750 "$BAK"
  TS=$(date +%Y%m%d-%H%M%S)
  (umask 027; tar czf "$BAK/gwconsole-$OLD_VER-$TS.tar.gz" -C / etc/gwconsole $( [ -d "$VAR" ] && echo var/lib/gwconsole ) 2>/dev/null) || true
  chgrp gwconsole "$BAK/gwconsole-$OLD_VER-$TS.tar.gz" 2>/dev/null || true
  # keep the last 10 upgrade backups (nightly gwconsole-backup-* files are pruned separately)
  ls -1t "$BAK"/gwconsole-*.tar.gz 2>/dev/null | grep -v -e '/gwconsole-backup-' -e '/gwconsole-before-restore-' | tail -n +11 | xargs -r rm -f
  ok "$BAK/gwconsole-$OLD_VER-$TS.tar.gz"
fi

step "application → $APP  ($OLD_VER → $NEW_VER)"
mkdir -p "$APP"
rm -rf "$APP/app"
cp -r "$SRC/app" "$APP/"
cp "$SRC/requirements.txt" "$SRC/VERSION" "$SRC/prepare-node.sh" "$SRC/CHANGELOG.md" "$APP/"
rm -f "$APP/BUILD" "$APP/SOURCE"
if [ -d "$SRC/.git" ] && command -v git >/dev/null; then
  git -C "$SRC" describe --tags --always --dirty 2>/dev/null > "$APP/BUILD" || true
  echo "$SRC" > "$APP/SOURCE"                      # used by 'gwconsole upgrade'
fi
[ -d "$APP/venv" ] || "$PY" -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --disable-pip-version-check --upgrade pip
"$APP/venv/bin/pip" install -q --disable-pip-version-check -r "$APP/requirements.txt"
chown -R root:root "$APP"
ok "python packages installed"

step "configuration → $ETC"
mkdir -p "$ETC" "$VAR" "$VAR/helper" /var/lib/gwconsole-helper "$BAK"
chown -R gwconsole:gwconsole "$VAR"; chmod 750 "$VAR" "$VAR/helper"
chown root:gwconsole /var/lib/gwconsole-helper "$BAK"; chmod 750 /var/lib/gwconsole-helper "$BAK"   # root writes, the app reads
find "$BAK" -maxdepth 1 -name 'gwconsole-*.tar.gz' -exec chgrp gwconsole {} + -exec chmod 640 {} + 2>/dev/null || true
if [ ! -f "$ETC/id_ed25519" ]; then
  ssh-keygen -q -t ed25519 -N '' -C "gwconsole@$(hostname)" -f "$ETC/id_ed25519"
  ok "created the dashboard SSH key"
fi
chown gwconsole:gwconsole "$ETC/id_ed25519"; chmod 600 "$ETC/id_ed25519"
touch "$ETC/known_hosts"; chmod 644 "$ETC/known_hosts"
if [ ! -f "$ETC/secret.key" ]; then     # encrypts tokens / webhooks stored in the database
  (umask 077; "$APP/venv/bin/python" -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > "$ETC/secret.key")
  ok "created $ETC/secret.key — keep it with your backups; stored tokens can't be read without it"
fi
chown root:gwconsole "$ETC/secret.key"; chmod 640 "$ETC/secret.key"
if [ ! -f "$ETC/config.yaml" ]; then
  sed -e "s/^listen: [^ ]*/listen: $LISTEN/" -e "s/^port: [0-9]*/port: $PORT/" "$SRC/config.example.yaml" > "$ETC/config.yaml"
  ok "wrote config.yaml (listen $LISTEN, port $PORT)"
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

step "gwconsole command"
cat > /usr/local/bin/gwconsole <<'EOF'
#!/usr/bin/env bash
# gwconsole — helper for the Gateway Console dashboard (installed by install.sh)
set -e
ETC=/etc/gwconsole; APP=/opt/gwconsole; VAR=/var/lib/gwconsole
# run the app's CLI as the service user, so the database keeps the right owner
run() { cd $APP; set -a; [ -r $ETC/env ] && . $ETC/env; set +a
        GWC_CONFIG=$ETC/config.yaml exec runuser -u gwconsole -- $APP/venv/bin/python -m app "$@"; }
need_root() { [ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }; }
url() { local l p; l=$(awk '/^listen:/{print $2}' $ETC/config.yaml); p=$(awk '/^port:/{print $2}' $ETC/config.yaml)
        [ "$l" = 0.0.0.0 ] || [ "$l" = "::" ] && l=$(hostname -I 2>/dev/null | awk '{print $1}'); echo "http://${l:-127.0.0.1}:${p:-8088}"; }
case "${1:-}" in
  version) echo "gwconsole $(cat $APP/VERSION 2>/dev/null)$( [ -s $APP/BUILD ] && echo " ($(cat $APP/BUILD))")" ;;
  status)
    echo "gwconsole $(cat $APP/VERSION 2>/dev/null)   $(systemctl is-active gwconsole 2>/dev/null)   $(url)" ;;
  create-admin)   need_root; shift; run create-admin "$@" ;;
  reset-password) need_root; [ -n "${2:-}" ] || { echo "usage: gwconsole reset-password <user>"; exit 1; }; shift; run reset-password "$@" ;;
  reset-2fa) need_root; [ -n "${2:-}" ] || { echo "usage: gwconsole reset-2fa <user>"; exit 1; }; shift; run reset-2fa "$@" ;;
  users)  need_root; run users ;;
  check)  need_root; run check ;;
  hashpw) run hashpw ;;
  pubkey) cat $ETC/id_ed25519.pub ;;
  trust)
    need_root; [ -n "${2:-}" ] || { echo "usage: gwconsole trust <host> [port]"; exit 1; }
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
  upgrade)
    need_root; shift; want=""; yes=0
    force=0
    for a in "$@"; do case "$a" in -y|--yes) yes=1 ;; --force) force=1 ;; v*) want=$a ;; *) echo "usage: gwconsole upgrade [vX.Y.Z] [--yes] [--force]"; exit 1 ;; esac; done
    SRC=$(cat $APP/SOURCE 2>/dev/null || true)
    [ -n "$SRC" ] && [ -d "$SRC/.git" ] || { echo "installed from a tarball (no git clone recorded). Download the new release and run its install.sh."; exit 1; }
    [ -z "$(git -C "$SRC" status --porcelain --untracked-files=no)" ] || { echo "$SRC has local changes — commit or 'git -C $SRC stash' them first"; exit 1; }
    echo "fetching from $(git -C "$SRC" remote get-url origin 2>/dev/null || echo origin)…"
    git -C "$SRC" fetch --quiet --tags --force origin || { echo "git fetch failed (network or deploy key?)"; exit 1; }
    cur=v$(cat $APP/VERSION)
    latest=$(git -C "$SRC" tag -l 'v[0-9]*' --sort=-v:refname | head -1)
    want=${want:-$latest}
    git -C "$SRC" rev-parse -q --verify "refs/tags/$want" >/dev/null || { echo "no such version: $want"; exit 1; }
    if [ "$want" = "$cur" ]; then echo "already on $cur (latest is $latest)"; exit 0; fi
    if [ "$(printf '%s\n%s\n' "$cur" "$want" | sort -V | tail -1)" = "$cur" ]; then
      echo "note: $want is OLDER than $cur. Its database may not understand newer data;"
      echo "      to really go back, restore the matching backup from /var/backups/gwconsole."
      # versions before 1.5.0 don't know scoped access: limited users would get everything their role allows
      if [ "$(printf '%s\n%s\n' "$want" v1.5.0 | sort -V | head -1)" = "$want" ] && [ "$want" != v1.5.0 ]; then
        scoped=$($APP/venv/bin/python -c "import sqlite3,sys; c=sqlite3.connect('file:$VAR/gwconsole.db?mode=ro',uri=True); print(', '.join(r[0] for r in c.execute(\"SELECT username FROM users WHERE scope_mode='pick'\")))" 2>/dev/null || true)
        if [ -n "$scoped" ] && [ $force = 0 ]; then
          echo "refusing: $want doesn't know scoped access, so these limited users would get everything their role allows: $scoped"
          echo "set them to Everything (or remove them) first, or add --force if you really mean it."
          exit 1
        fi
      fi
    fi
    echo; echo "installed: $cur    →    $want"; echo
    git -C "$SRC" show "$want:CHANGELOG.md" 2>/dev/null | awk -v v="${want#v}" '
      index($0, "## [" v "]") == 1 {p=1; print; next}  p && /^## \[/ {exit}  p {print}' | head -60
    echo
    if [ $yes = 0 ]; then read -r -p "Upgrade to $want now? A backup is taken first. [y/N] " a; [ "$a" = y ] || [ "$a" = Y ] || { echo "not upgraded."; exit 0; }; fi
    git -C "$SRC" -c advice.detachedHead=false checkout --quiet "$want"
    exec bash "$SRC/install.sh" --upgrade ;;
  backup)  need_root; shift; cd $APP; GWC_CONFIG=$ETC/config.yaml exec $APP/venv/bin/python -m app backup "$@" ;;
  restore) need_root; [ -n "${2:-}" ] || { echo "usage: gwconsole restore <backup file> [--by <user>]"; ls -1t /var/backups/gwconsole/*.tar.gz 2>/dev/null | head -5; exit 1; }
           f=$(realpath -s "$2"); shift 2
           cd $APP; GWC_CONFIG=$ETC/config.yaml exec $APP/venv/bin/python -m app restore "$f" "$@" ;;
  allow-all) need_root; run allow-all ;;
  helper)  need_root; shift; exec $APP/venv/bin/python -I $APP/app/helper.py "$@" ;;
  logs)    exec journalctl -u gwconsole -f ;;
  restart) need_root; systemctl restart gwconsole && systemctl --no-pager status gwconsole | head -5 ;;
  *) cat <<USAGE
usage: gwconsole <command>
  status                   version, service state and URL
  upgrade [vX.Y.Z] [-y]    fetch new versions, show what's new, back up and upgrade
  create-admin [user]      create a superadmin (locked out?)
  reset-password <user>    set a new password (also re-enables the account)
  reset-2fa <user>         turn off a user's two-step sign-in (lost phone)
  users                    list users and roles
  check                    test SSH to every node and every Cloudflare token
  pubkey                   print the dashboard's SSH public key (for prepare-node.sh)
  backup                   back up settings, keys and the database now (/var/backups/gwconsole)
  restore <file>           put a backup back (asks for the passphrase of a downloaded one); rolls back if it won't start
  allow-all                remove the "allowed networks" sign-in restriction (locked out?)
  logs | restart | version
USAGE
     exit 1 ;;
esac
EOF
chmod 755 /usr/local/bin/gwconsole
ok "/usr/local/bin/gwconsole"

step "systemd service"
cp "$SRC/gwconsole.service" /etc/systemd/system/gwconsole.service
cp "$SRC"/systemd/gwconsole-helper.path "$SRC"/systemd/gwconsole-helper.service \
   "$SRC"/systemd/gwconsole-daily.service "$SRC"/systemd/gwconsole-daily.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable gwconsole >/dev/null 2>&1
systemctl enable --now gwconsole-helper.path gwconsole-daily.timer >/dev/null 2>&1 || warn "could not enable the update/backup helper units"
ok "enabled at boot (+ update helper and nightly backup)"

if [ "$UPGRADE" = 0 ] && [ "${NEED_ADMIN:-0}" = 1 ]; then
  step "superadmin"
  printf '%s\n' "$ADMIN_PW" | /usr/local/bin/gwconsole create-admin "$ADMIN" --password-stdin >/dev/null
  unset ADMIN_PW
  ok "$ADMIN"
fi

if [ -n "${FW:-}" ]; then
  step "firewall"
  if [ "$FW" = ufw ]; then ufw allow "$PORT/tcp" comment gwconsole >/dev/null
  else firewall-cmd --quiet --permanent --add-port="$PORT/tcp" && firewall-cmd --quiet --reload; fi
  ok "$FW: TCP $PORT open"
fi

step "starting"
systemctl restart gwconsole
PORT=$(awk '/^port:/{print $2}' "$ETC/config.yaml"); PORT=${PORT:-8088}
LISTEN=$(awk '/^listen:/{print $2}' "$ETC/config.yaml"); LISTEN=${LISTEN:-0.0.0.0}
PROBE=$LISTEN; [ "$PROBE" = 0.0.0.0 ] && PROBE=127.0.0.1; [ "$PROBE" = "::" ] && PROBE=::1
case "$PROBE" in *:*) PROBE_URL="http://[$PROBE]:$PORT/api/health" ;; *) PROBE_URL="http://$PROBE:$PORT/api/health" ;; esac
up=0
for _ in $(seq 1 30); do
  if "$PY" -c 'import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=2)' "$PROBE_URL" 2>/dev/null; then up=1; break; fi
  sleep 1
done
if [ $up = 1 ]; then ok "running"
else warn "the service didn't answer within 30 s — check: journalctl -u gwconsole -n 50"; fi

if [ "$LISTEN" = 0.0.0.0 ] || [ "$LISTEN" = "::" ]; then URLS=$(host_ips | sed "s|.*|http://&:$PORT|"); else URLS="http://$LISTEN:$PORT"; fi
echo
if [ "$UPGRADE" = 1 ]; then
  echo "${G}${B}Upgraded $OLD_VER → $NEW_VER.${N} Settings and database kept; backup in $BAK."
  [ "$NEW_VER" != "$OLD_VER" ] && echo "What's new: $SRC/CHANGELOG.md"
else
  echo "${G}${B}Gateway Console $NEW_VER is installed.${N}"
  echo
  echo "  Open:   $(echo "$URLS" | head -1)"
  echo "$URLS" | tail -n +2 | sed 's/^/          /'
  [ "${NEED_ADMIN:-0}" = 1 ] && echo "  Login:  $ADMIN  (the password you just chose)"
  echo
  echo "  The browser takes you through the rest: add your HAProxy and cloudflared nodes,"
  echo "  your Cloudflare account and (optionally) Telegram / Discord alerts."
  echo
  echo "  ${D}gwconsole status | upgrade | logs | reset-password <user>${N}"
fi
echo
