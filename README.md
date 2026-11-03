# GW//CONSOLE — HAProxy + Cloudflare Tunnel dashboard

One web UI to watch **and** manage your HAProxy and cloudflared gateways.
It runs on any small Linux host (VM, LXC or bare metal) and talks to the gateway nodes over SSH (key auth, no agents),
plus the Cloudflare API for edge health and DNS routes. A background checker records
every alert and can message you on Telegram or Discord.

```
            browser ──HTTP:8088──▶  gwconsole host ──▶ Telegram / Discord (alerts)
                                     │  SSH (key, from= locked, host key pinned)
                    ┌────────────────┼──────────────────┐
                    ▼                                   ▼
           HAProxy node(s)                     cloudflared node(s)
   admin socket · haproxy.cfg · systemd    config.yml per tunnel · systemd units
                                     │
                                     └── HTTPS ──▶ api.cloudflare.com (tunnels, DNS)
```

![Overview](docs/overview.png)

## What it does

| Page | See | Do |
|---|---|---|
| **Overview** | KPIs, active alerts, node and tunnel cards | — |
| **HAProxy** | Six status tiles (service, backends, connections, rates, traffic, version), then every frontend, backend and server with check status, sessions, rates, bytes, 2xx/4xx/5xx | **+ Add** a site or TCP service, **Edit / Delete** any frontend or backend, add/remove servers, server **ready / drain / maint**, **reload** (config-checked first), restart, logs, **Edit config** |
| **Tunnels** | Every cloudflared service on the node (auto-discovered): local state, Cloudflare edge status, connections, ingress rules, DNS status per hostname, orphan DNS records, tunnels in your accounts that run nowhere you manage | **New tunnel**, **delete tunnel**, **add / remove hostname**, start / stop / restart, logs, rule tester, create/fix DNS route, **Edit config** |
| **Alerts** | Active and past alerts: what, when it started, how long it lasted, who acknowledged it | Acknowledge, mute an alert or a whole node, export CSV, check now |
| **Activity** | Audit log of every change (who, what, result, output) | — |
| **Settings** | Users, sessions, Cloudflare accounts, nodes, notifications, backups, general, about & updates (superadmin only) | Everything that used to be in config files, plus **updating the dashboard**, **backups**, **config history** |

### Adding sites and editing HAProxy (no config typing)
**+ Add** on the HAProxy page opens one form for both halves of HAProxy:

- **Frontend** (where traffic comes in): *New*, *Use existing* or *None*.
- **Backend** (the servers behind it): *New*, *Use existing* or *None*.
- **Cloudflare** (optional): publish the hostname through a tunnel and create its DNS record, in the same step.

Choose **Website (HTTP)** to route a hostname to new servers on your existing frontend, or **TCP service** (a game server, a database…) for its own port. Typing the hostname fills in the backend name, the Cloudflare hostname and where cloudflared should send it.

Tabs cover what HAProxy can do without a wall of fields:

| Frontend | Backend |
|---|---|
| **Routing**: Host / path (starts, ends, exact, regex) / header / source IP / method / TLS SNI → send to backend, redirect, redirect to HTTPS, deny, allow only from IPs, set header; reorder; default backend | **Servers**: address, weight, max conn, check, **backup (DR)**; per server: HTTPS to server, SNI, PROXY protocol, check interval / rise / fall, cookie, start disabled |
| **Bind & HTTPS**: listen addresses, certificate, HTTP/2 (off by default — Cloudflare Tunnel already does TLS) | **Health check**: TCP connect or HTTP method / path / Host / healthy status |
| **Headers & redirects**, **Limits & timeouts** (max conn, timeouts, rate limit per IP, logging) | **Headers**, **Timeouts & retries**, sticky sessions by cookie |
| **Advanced** | **Advanced** |

The right side updates as you type: **what will happen** in plain words, **checks** (name free, hostname not routed elsewhere, HTTP/TCP modes match, port free, each server reachable from the HAProxy node) and the **exact haproxy.cfg diff**. **Review diff & apply** runs `haproxy -c`, then the usual safe apply. If the Cloudflare step fails, the HAProxy change is undone too.

**Edit** on any frontend or backend opens the same form with only that part. Anything the form has no field for stays in the **Advanced** tab exactly as written, and unchanged lines keep their exact formatting and position, so saving through the form never loses or reshuffles your config. **Delete** is refused while a backend is still used by a frontend. **+ server** and **✕** on a backend add or remove one server.

![Add a site](docs/add-site.png)

### Config editor (side panel)
**Edit config** on the HAProxy or Tunnels page slides the editor in over the live stats.

- **Editor tab**: validate → review the diff → apply.
- **History tab**: every backup, with who made the change that followed it and +/− line counts. Pick one to see what restoring it would change, then **Restore this version** (it goes through the same safe apply).

![Editor](docs/editor.png)

### Safe apply (HAProxy and cloudflared)
1. Upload to a temp file on the node and validate it there (`haproxy -c -f` / `cloudflared tunnel ingress validate`). Invalid → nothing changes.
2. Refuse if the file changed on the server since you opened it (someone edited over SSH).
3. Back up the current file to `gwc-backups/` (last 20 kept, configurable).
4. Write in place, then `systemctl reload haproxy` or `systemctl restart cloudflared-<name>`.
5. Wait, then check the service is still `active`. If reload or the check fails, it **restores the backup and reloads again automatically**.

Every change keeps running to the end even if you close the browser tab mid-way.
Server ready/drain/maint goes through the admin socket, so it only lasts until the next HAProxy restart.

### Alerts and notifications
A background checker runs every 30 s (configurable), even with no browser open.

- **One alert per problem**: an alert opens when a problem appears and resolves after it has been gone for two checks in a row. If it returns within 10 minutes, the same alert reopens (shown as *flapping*) instead of creating noise.
- **No false recoveries**: if a node is unreachable or the Cloudflare API is failing, alerts that depend on it stay open instead of resolving.
- **Acknowledge** marks "I'm on it". **Mute** an alert, or a whole node during maintenance (30 min – 7 days): it is still recorded but sends no messages.
- **Telegram / Discord** (Settings → Notifications): only new, escalated and resolved alerts are sent, combined into one message per check. Choose the minimum severity and whether to send recoveries for each channel.

![Alerts](docs/alerts.png)

### Users and roles
| | Viewer | Operator | Superadmin |
|---|---|---|---|
| See all pages, logs, alerts, configs (read-only) | ✔ | ✔ | ✔ |
| Acknowledge / mute alerts | | ✔ | ✔ |
| Server state, reload/restart, edit configs, tunnels, hostnames, DNS routes | | ✔ | ✔ |
| Users, Cloudflare accounts, nodes, notifications, settings | | | ✔ |

New users and password resets get a temporary password that must be changed at first sign-in. Superadmins can see every signed-in session and revoke it. The last active superadmin can't be demoted, disabled or deleted.

### Managing tunnels
**New tunnel** (button on each cloudflared node): name, Cloudflare account, and optionally a first hostname and origin. The dashboard creates the tunnel through the Cloudflare API, writes the credentials (600) and `config.yml`, installs `cloudflared-<name>.service`, enables it, checks it is active and creates the DNS record. If anything fails, all of it is undone.

**+ Hostname / Remove** edits the ingress list (keeping your comments and indentation) through the safe-apply pipeline, and can create or delete the DNS record. It never repoints a record that belongs to another tunnel; that needs the explicit **Fix route** button.

**Delete** (type the name to confirm) stops the unit and moves its files into `<tunnel_base_dir>/.gwc-archive/<name>-<timestamp>/` (nothing erased), then optionally deletes the DNS records and the tunnel in Cloudflare.

**Token-run tunnels** (`cloudflared tunnel run --token …`) are detected and can be started, stopped or deleted; their hostnames live in the Zero Trust dashboard.

### Updates, backups and config history
- **Update from the dashboard** (Settings → About & updates): a nightly check (or **Check for updates**) lists new versions with their changelog. **Update now** backs up, installs, restarts and checks that the new version answers; if it doesn't, it **goes back to the previous version automatically**. Telegram/Discord tell you when a new version is out. You can let bug-fix releases (x.y.**Z**) install themselves.
- **What's new**: after an update everyone sees a one-time banner with the changes.
- **Backups** (Settings → Backups): every night (the last 14 are kept) and before every update — settings, keys, users, nodes, accounts and alerts. Optionally copied to one of your nodes over SSH. **Download** gives a passphrase-encrypted file. Restore with `gwconsole restore <file>`.
- **Config history**: every change to `haproxy.cfg` and tunnel configs is also committed to a local git history, with who made it. If someone edits a file **outside the dashboard** (over SSH), you get an alert within 15 minutes; it's recorded in the history and you **Accept change** on the Alerts page.
- **Node software**: cloudflared on each node against the latest Cloudflare release, HAProxy against your OS packages. **Update cloudflared** restarts the tunnels one at a time and goes back to the old version if a tunnel doesn't come back.
- **Sign-in security**: a message when someone signs in from a new address or an address gets locked out, and an optional list of networks allowed to sign in.

![About & updates](docs/about-updates.png)

## Install

Any Linux host with **systemd** works — a VM, an LXC or bare metal: Debian 12+, Ubuntu 22.04+, or RHEL / Rocky / Alma / Fedora (Python 3.10+ is installed for you; 3.11 on RHEL 8/9). 1 vCPU and 512 MB is plenty. It only needs to reach the gateway nodes over SSH, and `api.cloudflare.com` if you use the Cloudflare features.

### 1. Get the code
The repo is private, so the host pulls it with a read-only **deploy key** (it can't push and can't see your other repos):

```bash
apt install -y git            # or: dnf install -y git
ssh-keygen -t ed25519 -N '' -f ~/.ssh/gwconsole_deploy -C "deploy@$(hostname)"
cat ~/.ssh/gwconsole_deploy.pub
#  → GitHub: repo → Settings → Deploy keys → Add deploy key (leave "Allow write access" OFF)
cat >> ~/.ssh/config <<'EOF'
Host github-gwconsole
  HostName github.com
  User git
  IdentityFile ~/.ssh/gwconsole_deploy
  IdentitiesOnly yes
EOF
git clone github-gwconsole:ameerdanial/gwconsole.git /root/gwconsole
cd /root/gwconsole && git checkout v1.3.0      # a tagged release
```

### 2. Run the installer
```bash
bash install.sh
```
It checks the host first (root, systemd, Python, free port, clock, Cloudflare reachable), then asks four things — **Enter keeps the default**:

```
==> a few questions (Enter keeps the default)
    This host's addresses: 192.168.10.50. 0.0.0.0 listens on all of them.
    Listen address: [0.0.0.0]
    Web port: [8088]
    Admin username: [admin] ameer
    Admin password:                  (10+ characters, upper + lower case and a digit)
    Repeat password:
```
If `ufw` or `firewalld` is active it offers to open the port. Then it installs, starts the service, waits until it answers and prints the address to open.

Unattended (Ansible, cloud-init…): pass everything as options and the password through the environment, never as an argument:
```bash
GWC_ADMIN_PASSWORD='…' bash install.sh --yes --admin ameer --port 8088 [--listen 10.0.0.5] [--no-firewall]
```

### 3. Finish in the browser (setup wizard)
Sign in and the dashboard walks you through three steps — skip any of them, all of it stays editable in **Settings**. Reopen the wizard any time from **Settings → General**.

![Setup wizard](docs/setup-wizard.png)

**Nodes.** **+ Add node** → type, name, IP → **Scan host key** and compare the fingerprint with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the node. Then choose how the dashboard gets in:

- **Use the node's password once** (easiest): enter root's password, or a sudo user's. The dashboard logs in one time over the pinned host key, installs its SSH key (accepted only from the dashboard's IP), installs `socat`, sets up HAProxy's admin stats socket if it's missing (validated with `haproxy -c`, backed up, rolled back on error), proves the key works — and forgets the password. It's never stored or logged.
  Debian and Ubuntu don't let root log in with a password by default; give a sudo user instead and the dashboard still connects as root with its key (or as that user with passwordless sudo, if root can't log in over SSH at all).
- **Run a command on the node**: the form shows a one-liner to paste into a root shell on the node:
  ```bash
  curl -fsSL http://<dashboard>:8088/prepare-node.sh | bash -s -- --key "ssh-ed25519 AAAA… gwconsole@host" --from 192.168.10.50
  ```
  `prepare-node.sh` also runs on its own and asks for whatever is missing: `bash prepare-node.sh`.

Saving runs a connection test. If an HAProxy node's admin socket goes missing later, **Settings → Nodes → Test** and the HAProxy page show a **Fix it** button that makes the same safe change.

![Add node](docs/add-node.png)

**Cloudflare** (optional): a name, the Account ID and an API token. **Test before saving** shows which permissions the token has.

- **Account ID**: dash.cloudflare.com → click a domain → right-hand column, **API** box → **Account ID** (also the long code in the address bar).
- **API token**: Profile → API Tokens → Create Custom Token:

| Permission | Level |
|---|---|
| Account · Cloudflare Tunnel | **Edit** (Read if you only want to watch) |
| Zone · Zone | Read |
| Zone · DNS | **Edit** (Read if you never create/fix/delete routes) |

Tunnels are matched to their account automatically by the `tunnel:` ID in each `config.yml`.

**Alerts** (optional):
- **Telegram**: create a bot with @BotFather (bot token), message the bot once, get your chat ID from @userinfobot (groups: add @RawDataBot; the ID starts with `-100`).
- **Discord**: channel → Edit Channel → Integrations → Webhooks → New Webhook → Copy URL.

Use **Send test**. The last step also saves the dashboard URL so each message links back here.

## Upgrading

From 1.3 on: **Settings → About & updates → Update now**. It needs the `gwconsole-helper` units that `install.sh` sets up (a small root service that only knows "check", "upgrade to a tag" and "back up").

From the shell, or to get from 1.2 to 1.3 the first time:

```bash
gwconsole upgrade            # fetch, show what's new, confirm, back up, upgrade, restart
gwconsole upgrade v1.3.0     # a specific version
```
It runs `git fetch --tags --force` in the folder you installed from, shows the newest release with its `CHANGELOG.md` notes and asks before doing anything. The upgrade itself is `install.sh`: it stops the service, backs up `/etc/gwconsole` and the database to `/var/backups/gwconsole/` (last 10 kept), upgrades, starts it again and asks no questions.

By hand it's the same: `cd /root/gwconsole && git fetch --tags --force && git checkout vX.Y.Z && bash install.sh`.

**From 1.1 to 1.2**: nothing to do by hand. On first start, the users, nodes and Cloudflare accounts in your old `config.yaml` (and tokens from `/etc/gwconsole/env`) are imported into the database once. You sign in with the same password. From then on, manage them in Settings; the old sections in `config.yaml` are ignored but left in place.

**Rolling back**: `gwconsole upgrade v1.1.0` (or `git checkout v1.1.0 && bash install.sh`) works, because 1.1 still reads `config.yaml` (changes you made in the 1.2 Settings page are not carried back).

## Day-to-day

```bash
gwconsole status                # version, service state and the URL to open
gwconsole version               # installed version, e.g. "gwconsole 1.3.0 (v1.3.0)"
gwconsole users                 # list users and roles
gwconsole reset-password ameer  # locked out? set a new password (also re-enables the account)
gwconsole create-admin <user>   # add another superadmin from the shell
gwconsole check                 # test SSH to every node and every Cloudflare token
gwconsole backup                # back up now (also nightly, automatically)
gwconsole restore <file>        # put a backup back; asks for the passphrase of a downloaded .gwcbak
gwconsole allow-all             # locked out by "allowed networks"? remove the restriction
gwconsole logs | restart
```

Where things live:

| What | Where |
|---|---|
| Bootstrap config (listen, port, paths) | `/etc/gwconsole/config.yaml` |
| Users, nodes, accounts, alerts, settings | `/var/lib/gwconsole/gwconsole.db` (SQLite) |
| Key that encrypts tokens/webhooks in the DB | `/etc/gwconsole/secret.key`. **Back it up with the DB.** |
| Dashboard SSH key | `/etc/gwconsole/id_ed25519` |
| Audit log | `/var/lib/gwconsole/audit.log` |
| Config backups on the nodes | `/etc/haproxy/gwc-backups/`, `/root/.cloudflared/<tunnel>/gwc-backups/` |
| Dashboard backups (nightly, before updates/restores) | `/var/backups/gwconsole/` |
| Config history (git) | `/var/lib/gwconsole/config-history/` — `git log -p` works there |
| Update helper state and log | `/var/lib/gwconsole-helper/` (written by root, read by the dashboard) |

## Version control & releases

- `main` holds the latest code. Every release is an annotated tag `vX.Y.Z` ([SemVer](https://semver.org/)); `VERSION` holds the current number, shown in the UI and by `gwconsole version`.
- Every commit touches one file and its message says what the file is for (`path: description`), so GitHub's file list doubles as documentation.
- `CHANGELOG.md` records what changed in each release. Add notes under **Unreleased** as you work.
- **CI** (GitHub Actions) runs on every push and PR: pytest on Python 3.11/3.12/3.13, a compile check, and syntax checks for the shell scripts and every JS file.
- **Cutting a release:**
  ```bash
  ./release.sh 1.3.0           # dates the changelog, bumps VERSION, tags v1.3.0
  git push && git push --tags  # Actions builds gwconsole-v1.3.0.tar.gz and publishes a GitHub Release
  ```
- Tests: `pip install -r requirements-dev.txt && python -m pytest -q`.
- Secrets never go in the repo: `config.yaml`, `env`, keys, `secret.key` and `known_hosts` are git-ignored.

## Adding the DR site later
**Settings → Nodes → + Add node** for each DR node, with a site label like `DR`. Every page handles multiple nodes.

## Security notes
- This tool can reload and restart your gateways. Only expose it on the management VLAN or Tailscale, never publicly.
- Passwords are scrypt-hashed. Sessions are stored hashed in the database and survive restarts. 5 failed logins per IP lock that IP out for 5 minutes. Cookies are `HttpOnly` + `SameSite=Strict`, and every change also needs an `X-GWC` header.
- Roles are enforced on the server for every request; hiding buttons in the UI is only a convenience.
- The SSH key works only from the dashboard IP (`from=` in authorized_keys). Nodes added in Settings pin their host key; a changed key blocks the connection.
- "Use the node's password once" sends the password only over that pinned-host-key SSH session and keeps it in memory for that one request: it's never written to the database, logs or audit trail. A sudo password goes to `sudo` on stdin, never on a command line.
- `/prepare-node.sh` and `/api/health` are the only addresses served without a login; neither holds anything secret (the public key is passed as an argument).
- Cloudflare tokens, the Telegram bot token and the Discord webhook are encrypted in the database with `secret.key` (root:gwconsole 640). The app runs as the unprivileged `gwconsole` user in a hardened systemd unit.
- Updating needs root, so the app can only *ask*: it writes one line (`check`, `upgrade vX.Y.Z` or `backup`, plus who asked) that the root helper validates against a fixed pattern, and it only installs version tags that exist in your repository. Nothing else the app writes is ever run as root.
- **Allowed networks** (Settings → General) limits sign-in and every API call to the networks you list; the form refuses a list that would lock you out, and `gwconsole allow-all` on the host resets it.
- Downloaded backups are encrypted (scrypt + AES-256-GCM) with a passphrase you choose; they contain `secret.key`.

## Files
```
app/                  FastAPI backend + web UI (no build step, no CDN) — see app/README.md
tests/                pytest suite — see tests/README.md
docs/                 screenshots used in this README
.github/workflows/    CI and release automation
install.sh            interactive installer / upgrader for the dashboard host (any systemd Linux)
prepare-node.sh       one-time setup on each managed node (also served by the dashboard)
release.sh            cut a release (changelog, VERSION, tag)
config.example.yaml   bootstrap config template
gwconsole.service     systemd unit for the dashboard
systemd/              root helper (updates, backups) and the nightly timer
VERSION · CHANGELOG.md · requirements.txt · requirements-dev.txt
```
