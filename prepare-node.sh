#!/usr/bin/env bash
# Prepare a managed node (a host running HAProxy and/or cloudflared) for Gateway Console.
# Run as root ON THE NODE. With no options it asks for what it needs:
#   bash prepare-node.sh
# or give everything up front (the dashboard's Settings → Nodes shows this exact line):
#   bash prepare-node.sh --key "ssh-ed25519 AAAA… gwconsole@host" --from 192.168.10.50 [--yes]
#
#   --key KEY       the dashboard's public key (on the dashboard: gwconsole pubkey)
#   --from IP       the dashboard's IP; the key only works from there (IP, CIDR or comma list)
#   --user NAME     account the dashboard logs in as (default root). Not root → passwordless sudo is set up
#   --fix-socket    add / fix HAProxy's admin stats socket without asking (validated, backed up, rolled back)
#   --yes, -y       no questions: take the defaults (also fixes the socket)
# HAProxy and cloudflared are detected automatically (--haproxy is still accepted).
# Works on Debian / Ubuntu / RHEL / Rocky / Alma / Fedora, on a VM, an LXC or bare metal.
set -euo pipefail

KEY=""; FROM=""; USERN=root; FIX=ask; YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --key) KEY="${2:-}"; shift 2 ;;
    --from) FROM="${2:-}"; shift 2 ;;
    --user) USERN="${2:-}"; shift 2 ;;
    --fix-socket) FIX=yes; shift ;;
    --no-fix-socket) FIX=no; shift ;;
    --haproxy) shift ;;
    -y|--yes) YES=1; shift ;;
    -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1  (see --help)"; exit 1 ;;
  esac
done
[ "$YES" = 1 ] && [ "$FIX" = ask ] && FIX=yes

if [ -t 1 ]; then B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; D=$'\e[2m'; N=$'\e[0m'; else B= G= Y= R= D= N=; fi
step() { echo "${B}==>${N} $*"; }
ok()   { echo "    ${G}✓${N} $*"; }
warn() { echo "    ${Y}!${N} $*"; }
die()  { echo "    ${R}✗ $*${N}" >&2; exit 1; }
result() { [ -t 1 ] || echo "@@gwc $*"; }   # machine-readable lines for the dashboard's "password once" setup

TTY=""
if [ "$YES" = 0 ] && { exec 3</dev/tty; } 2>/dev/null; then TTY=1; fi
ask() { local __v=$1 __q=$2 __def=${3:-} __a=""     # __-prefixed locals never shadow VAR
        if [ -n "$TTY" ]; then read -r -u 3 -p "    $__q ${__def:+${D}[$__def]${N} }" __a || true; fi
        printf -v "$__v" '%s' "${__a:-$__def}"; }
yesno() { local __yn=""; ask __yn "$1 (y/n)" "$2"; case "$__yn" in y|Y|yes) return 0 ;; *) return 1 ;; esac; }
pkg_install() {
  if command -v apt-get >/dev/null; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null
  elif command -v dnf >/dev/null; then dnf install -y -q "$@" >/dev/null
  elif command -v yum >/dev/null; then yum install -y -q "$@" >/dev/null
  else return 1; fi
}

[ "$(id -u)" -eq 0 ] || die "run as root (sudo bash prepare-node.sh …)"
echo; echo "${B}Gateway Console — prepare this node${N} ($(hostname), $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-linux}"))"; echo

# ---- what to ask ---------------------------------------------------------------------------------
if [ -z "$KEY" ]; then
  [ -n "$TTY" ] || die "--key is required (on the dashboard run: gwconsole pubkey)"
  echo "    ${D}On the dashboard host run 'gwconsole pubkey' and paste the line here.${N}"
  ask KEY "Dashboard public key:"
fi
KEYTYPE=$(echo "$KEY" | awk '{print $1}'); KEYBODY=$(echo "$KEY" | awk '{print $2}')
case "$KEYTYPE" in ssh-ed25519|ecdsa-sha2-*|ssh-rsa) ;; *) die "that doesn't look like an SSH public key" ;; esac
echo "$KEY" | ssh-keygen -lf - >/dev/null 2>&1 || [ ${#KEYBODY} -gt 60 ] || die "invalid public key"
if [ -z "$FROM" ]; then
  [ -n "$TTY" ] || die "--from is required (the dashboard host's IP)"
  hint=$(echo "${SSH_CLIENT:-}" | awk '{print $1}')
  echo "    ${D}The key will only be accepted from the dashboard's address.${N}"
  ask FROM "Dashboard IP:" "$hint"
fi
[[ $FROM =~ ^[0-9A-Fa-f.:/,*?]+$ ]] || die "--from: give an IP, a CIDR (10.0.0.0/24) or a comma-separated list"
id "$USERN" >/dev/null 2>&1 || die "user $USERN doesn't exist on this node"

HAS_HAP=0; command -v haproxy >/dev/null && HAS_HAP=1
HAS_CFD=0; command -v cloudflared >/dev/null && HAS_CFD=1
[ $HAS_HAP = 1 ] && ok "HAProxy found: $(haproxy -v 2>/dev/null | head -1 | awk '{print $3}')"
[ $HAS_CFD = 1 ] && ok "cloudflared found: $(cloudflared --version 2>/dev/null | head -1 | awk '{print $3}')"
[ $HAS_HAP = 0 ] && [ $HAS_CFD = 0 ] && warn "neither haproxy nor cloudflared is installed here yet — setting up access anyway"
result "haproxy=$HAS_HAP cloudflared=$HAS_CFD"

# ---- SSH key ---------------------------------------------------------------------------------------
step "SSH access for the dashboard (user $USERN, only from $FROM)"
HOME_DIR=$(getent passwd "$USERN" | cut -d: -f6)
AK="$HOME_DIR/.ssh/authorized_keys"
mkdir -p "$HOME_DIR/.ssh"; touch "$AK"
LINE="from=\"$FROM\",no-port-forwarding,no-agent-forwarding,no-X11-forwarding $KEY"
if grep -qxF "$LINE" "$AK"; then ok "key already installed"
else
  if grep -qF "$KEYBODY" "$AK"; then grep -vF "$KEYBODY" "$AK" > "$AK.gwc.tmp" || true; cat "$AK.gwc.tmp" > "$AK"; rm -f "$AK.gwc.tmp"; ok "replaced the old entry for this key"; fi
  echo "$LINE" >> "$AK"; ok "key added to $AK"
fi
chown -R "$USERN:" "$HOME_DIR/.ssh" 2>/dev/null || chown -R "$USERN" "$HOME_DIR/.ssh"
chmod 700 "$HOME_DIR/.ssh"; chmod 600 "$AK"
command -v restorecon >/dev/null && restorecon -R "$HOME_DIR/.ssh" 2>/dev/null || true

SSHD=$(sshd -T 2>/dev/null || true)
if [ -n "$SSHD" ]; then
  if [ "$USERN" = root ] && echo "$SSHD" | grep -qi '^permitrootlogin no$'; then
    warn "sshd has 'PermitRootLogin no' — root can't log in even with a key."
    warn "Either set 'PermitRootLogin prohibit-password' and restart sshd, or re-run with --user <sudo user>."
    result "warn=permitrootlogin-no"
  fi
  echo "$SSHD" | grep -qi '^pubkeyauthentication no$' && warn "sshd has 'PubkeyAuthentication no' — key logins are disabled"
fi

SUDO=0
if [ "$USERN" != root ]; then
  SUDO=1
  step "passwordless sudo for $USERN (the dashboard runs commands with sudo -n)"
  if ! command -v sudo >/dev/null; then pkg_install sudo || die "install sudo first"; fi
  F="/etc/sudoers.d/gwconsole-$USERN"
  if [ -f "$F" ]; then ok "already set up ($F)"
  elif [ "$YES" = 1 ] || yesno "Allow $USERN to run commands as root without a password?" y; then
    echo "$USERN ALL=(root) NOPASSWD: ALL" > "$F.tmp"; chmod 440 "$F.tmp"
    if visudo -cf "$F.tmp" >/dev/null; then mv "$F.tmp" "$F"; ok "$F"; else rm -f "$F.tmp"; die "sudoers check failed"; fi
  else
    warn "skipped — config changes from the dashboard will fail until $USERN can sudo without a password"
  fi
fi
result "user=$USERN sudo=$SUDO"

# ---- HAProxy -------------------------------------------------------------------------------------
if [ $HAS_HAP = 1 ]; then
  step "HAProxy"
  if command -v socat >/dev/null; then ok "socat present"
  elif pkg_install socat; then ok "socat installed"
  else warn "couldn't install socat — install it yourself (live stats and enable/disable need it)"; fi

  CFG=/etc/haproxy/haproxy.cfg
  [ -f "$CFG" ] || CFG=$(ps -o args= -C haproxy 2>/dev/null | grep -oP -- '-f\s*\K\S+' | head -1 || true)
  if [ -z "$CFG" ] || [ ! -f "$CFG" ]; then warn "haproxy.cfg not found — skipping the stats socket check"
  else
    # the 'stats socket' line inside the global section (if any)
    SLINE=$(awk '/^[[:space:]]*global([[:space:]]|$)/{g=1;next} /^[^[:space:]#]/{g=0} g && /^[[:space:]]*stats[[:space:]]+socket[[:space:]]/{print NR": "$0; exit}' "$CFG")
    SOCK=""; NEEDS=""
    if [ -n "$SLINE" ]; then
      SOCK=$(echo "$SLINE" | awk '{print $4}')
      echo "$SLINE" | grep -Eq 'level[[:space:]]+admin' || NEEDS=level
    else
      NEEDS=missing
      if [ -d /run/haproxy ]; then SOCK=/run/haproxy/admin.sock          # Debian / Ubuntu
      elif [ -d /var/lib/haproxy ]; then SOCK=/var/lib/haproxy/admin.sock # RHEL family (SELinux-friendly)
      else SOCK=/run/haproxy/admin.sock; fi
    fi
    if [ -z "$NEEDS" ]; then ok "admin stats socket: $SOCK"
    else
      [ "$NEEDS" = missing ] && warn "no stats socket in $CFG — the dashboard needs one for live stats and enable/disable"
      [ "$NEEDS" = level ] && warn "stats socket $SOCK is not 'level admin' — read-only, so enable/disable/drain won't work"
      do_fix=0
      case "$FIX" in yes) do_fix=1 ;; ask) yesno "Fix it now? (validated with haproxy -c, backed up, rolled back on error)" y && do_fix=1 ;; esac
      if [ $do_fix = 1 ]; then
        BKP="$CFG.gwc-$(date +%Y%m%d-%H%M%S)"; cp -p "$CFG" "$BKP"
        if [ "$NEEDS" = missing ]; then
          [ "$SOCK" = /run/haproxy/admin.sock ] && mkdir -p /run/haproxy
          awk -v s="$SOCK" '{print} !done && /^[[:space:]]*global([[:space:]]|$)/{print "    stats socket " s " mode 660 level admin"; done=1}' "$BKP" > "$CFG"
        else
          n=${SLINE%%:*}     # keep path and options, drop any old level, keep a trailing comment
          awk -v n="$n" 'NR==n { c = ""; i = index($0, "#"); if (i) { c = "  " substr($0, i); $0 = substr($0, 1, i - 1) }
                                 sub(/[[:space:]]+level[[:space:]]+[a-z]+/, ""); sub(/[[:space:]]+$/, "")
                                 if ($0 !~ /[[:space:]]mode[[:space:]]+[0-9]+/) $0 = $0 " mode 660"
                                 $0 = $0 " level admin" c } {print}' "$BKP" > "$CFG"
        fi
        CHK=$(mktemp)
        if ! haproxy -c -f "$CFG" >"$CHK" 2>&1; then
          cp -p "$BKP" "$CFG"; warn "haproxy -c rejected the change — restored the original:"; grep -E 'ALERT|ERROR' "$CHK" | tail -5 | sed 's/^/        /'; rm -f "$CHK"
        else
          rm -f "$CHK"
          if systemctl reload haproxy 2>/dev/null || systemctl restart haproxy; then
            for _ in 1 2 3 4 5 6; do [ -S "$SOCK" ] && break; sleep 0.5; done
            if [ -S "$SOCK" ]; then ok "stats socket ready: $SOCK, level admin (backup: $BKP)"; NEEDS=""
            else warn "config is valid and HAProxy reloaded, but $SOCK didn't appear yet — check: systemctl status haproxy"; NEEDS=""; fi
          else
            cp -p "$BKP" "$CFG"; systemctl restart haproxy || true
            warn "HAProxy failed to reload — restored the original config"
          fi
        fi
      else
        echo "    Add this line inside the 'global' section of $CFG, then: haproxy -c -f $CFG && systemctl reload haproxy"
        echo "        stats socket $SOCK mode 660 level admin"
      fi
    fi
    result "socket=$SOCK socket_ok=$([ -z "$NEEDS" ] && echo 1 || echo 0)"
  fi
fi

# ---- summary -------------------------------------------------------------------------------------
FP=""
for k in /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ecdsa_key.pub /etc/ssh/ssh_host_rsa_key.pub; do
  [ -f "$k" ] && { FP=$(ssh-keygen -lf "$k" | awk '{print $2" "$NF}'); break; }
done
echo
echo "${G}${B}Done.${N} In the dashboard: Settings → Nodes → Add node, with"
echo "    host:        $(hostname -I 2>/dev/null | awk '{print $1}')   ssh user: $USERN$( [ $SUDO = 1 ] && echo "   use sudo: yes")"
[ -n "${SOCK:-}" ] && echo "    stats socket: $SOCK"
[ -n "$FP" ] && echo "    host key:    $FP   ← should match the fingerprint the dashboard shows"
echo
