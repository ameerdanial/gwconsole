# GW//CONSOLE — HAProxy + Cloudflare Tunnel dashboard

One web UI to watch **and** manage the HAProxy VM and the cloudflared LXC.
It runs in its own small LXC and talks to both nodes over SSH (key auth, no agents),
plus the Cloudflare API for edge health and DNS routes.

```
            browser ──HTTP:8088──▶  gwconsole LXC
                                     │  SSH (key, from= locked)
                    ┌────────────────┼──────────────────┐
                    ▼                                   ▼
             HAProxy VM                          cloudflared-lxc
   admin socket · haproxy.cfg · systemd    config.yml per tunnel · systemd units
                                     │
                                     └── HTTPS ──▶ api.cloudflare.com (tunnels, DNS)
```

## What it does

| Page | See | Do |
|---|---|---|
| **Overview** | KPIs, alert list (backend/server down, tunnel down/degraded, DNS mismatches, node unreachable), node + tunnel cards | — |
| **HAProxy** | `show info` + `show stat`: frontends, backends, every server with check status, sessions, rates, bytes, 2xx/4xx/5xx | Server **ready / drain / maint** (runtime), **reload** (config-checked first), restart, service & access logs |
| **Tunnels** | Every cloudflared service on the node (auto-discovered): local state, Cloudflare edge status, edge connections (colos), ingress rules, DNS status per hostname, orphan DNS records, and tunnels in your accounts that run nowhere you manage | **New tunnel**, **delete tunnel**, **add / remove hostname**, start / stop / restart, logs, test which ingress rule matches a URL, create/fix DNS route |
| **Config** | `haproxy.cfg` and every tunnel's `config.yml` in an editor | Validate → review diff → apply, restore from backups |
| **Activity** | Audit log of every change (who, what, result, output) | — |

### Safe apply (both HAProxy and cloudflared)

1. Upload to a temp file on the node and validate it there (`haproxy -c -f` / `cloudflared tunnel ingress validate`). Invalid → nothing changes.
2. Refuse if the file changed on the server since you opened it (someone edited over SSH).
3. Back up the current file to `gwc-backups/` (last 20 kept).
4. Write in place, then `systemctl reload haproxy` or `systemctl restart cloudflared-<name>`.
5. Wait, then check the service is still `active`. If reload or the check fails, it **restores the backup and reloads again automatically**.

### Managing tunnels

**New tunnel** (button on each cloudflared node): give it a name, pick the Cloudflare account, and optionally a first hostname and origin service. The dashboard then:
1. Creates a locally managed tunnel through the Cloudflare API.
2. Writes `<tunnel_base_dir>/<name>/<tunnel-id>.json` (credentials, chmod 600) and `config.yml` on the node.
3. Runs `cloudflared ingress validate`, installs `cloudflared-<name>.service`, and runs `systemctl enable --now`.
4. Checks the unit is active, then creates the proxied CNAME.

If anything fails at step 2–4, the unit and directory are removed and the tunnel is deleted in Cloudflare again.

**+ Hostname / Remove** (on each tunnel):
- Edits the ingress list in `config.yml` and keeps your comments and indentation. A new rule goes before the catch-all.
- Goes through the same safe-apply pipeline (validate, backup, restart, rollback).
- Can create the DNS record when adding, or delete it when removing.
- Never repoints a DNS record that already belongs to another tunnel. That needs the explicit **Fix route** button.

**Delete** (type the name to confirm):
1. Stops and disables the unit.
2. Moves the config, credentials, backups and the unit file into `<tunnel_base_dir>/.gwc-archive/<name>-<timestamp>/`. Nothing is erased on the node. A shared template such as `cloudflared@.service` is left alone.
3. Optionally deletes the DNS records pointing at the tunnel, then the tunnel in Cloudflare.

To undo a delete, move the files back from the archive and run `systemctl enable --now` on the unit.

**In Cloudflare, not on a managed node** lists tunnels in your accounts that no managed node runs, such as leftovers or tunnels on other servers.
- Ones with no live connections can be deleted, along with their DNS records.
- Ones with live connections are labelled *running elsewhere* and can't be deleted from here.

**Token-run tunnels** (`cloudflared tunnel run --token …`) are detected and can be started, stopped, restarted or deleted. Their hostnames live in the Zero Trust dashboard, so the hostname editor is hidden for them.

Every change in this section keeps running to the end even if you close the browser tab mid-way. The remote script ignores hangups, and the server finishes the job and writes the audit entry.

Server ready/drain/maint goes through the admin socket, so it only lasts until the next restart. To make it permanent, change the config.

## Install

### 1. Dashboard LXC
A small Debian 12/13 or Ubuntu LXC (1 vCPU, 512 MB is plenty). Put it on the mgmt VLAN, the same network that can reach both gateways on SSH.

The repo is private, so the LXC pulls it with a read-only **deploy key**. That key can't push and can't see your other repos.

```bash
# on the LXC
apt update && apt install -y git
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
git clone github-gwconsole:<your-github-user>/gwconsole.git /root/gwconsole
cd /root/gwconsole && git checkout v1.1.0      # deploy a tagged release
bash install.sh
gwconsole hashpw            # copy the scrypt$... output
nano /etc/gwconsole/config.yaml   # paste hash under users:, set node IPs, tunnels, CF account IDs
nano /etc/gwconsole/env           # CF API tokens
gwconsole pubkey            # copy this for step 2
```

### 2. On each managed node (HAProxy VM and cloudflared-lxc)
Copy `prepare-node.sh` over, then:

```bash
# HAProxy VM   (scp /root/gwconsole/prepare-node.sh over from the dashboard LXC)
bash prepare-node.sh --key "<output of gwconsole pubkey>" --from <dashboard-ip> --haproxy
# cloudflared-lxc
bash prepare-node.sh --key "<output of gwconsole pubkey>" --from <dashboard-ip>
```

This adds the key to `/root/.ssh/authorized_keys` and only accepts it from the dashboard IP.
On HAProxy it also installs `socat` and checks the admin socket. If the script says it is missing, add this under `global` in `haproxy.cfg`:

```
stats socket /run/haproxy/admin.sock mode 660 level admin
```
then `haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl reload haproxy`.

### 3. Trust host keys, test, start
```bash
gwconsole trust <haproxy-ip>
gwconsole trust <cloudflared-ip>
gwconsole check             # should print [ok] for every node, tunnel and CF account
systemctl start gwconsole
```
Open `http://<dashboard-ip>:8088`.

### Cloudflare API token
Make one per Cloudflare account under **My Profile → API Tokens → Create Custom Token**:

| Permission | Level |
|---|---|
| Account · Cloudflare Tunnel | **Edit** (Read if you only want to watch) |
| Zone · Zone | Read |
| Zone · DNS | **Edit** (Read if you never create/fix/delete routes) |

Account ID is on the zone overview page (right sidebar). Put the token in `/etc/gwconsole/env`, e.g. `CF_TOKEN_MAIN=...`, then `gwconsole restart`.

You don't list tunnels in `config.yaml`. They are discovered from the systemd units on the node, and each one is matched to its account by the `tunnel:` line in its `config.yml` (UUID or name). For token-run tunnels, the ID inside the token is used.

## Day-to-day

```bash
gwconsole logs        # follow dashboard logs
gwconsole restart     # after editing config.yaml / env
gwconsole check       # connectivity test
gwconsole version     # what's installed, e.g. "gwconsole 1.1.0 (v1.1.0)"
```

### Upgrade / roll back
```bash
cd /root/gwconsole
git fetch --tags
git tag --sort=-v:refname | head        # available releases
git checkout v1.2.0 && bash install.sh  # upgrade; config.yaml / env / keys are never touched
git checkout v1.1.0 && bash install.sh  # roll back the same way
```
Check `CHANGELOG.md` before upgrading. Anything that needs a config change is listed there.

Backups on the nodes: `/etc/haproxy/gwc-backups/` and `/root/.cloudflared/<tunnel>/gwc-backups/`.
Audit log: `/var/lib/gwconsole/audit.log` (JSON lines).

## Version control & releases

- `main` holds the latest code. Every release is an annotated tag `vX.Y.Z` ([SemVer](https://semver.org/)), and `VERSION` holds the current number, which the UI and `gwconsole version` show.
- `CHANGELOG.md` records what changed in each release. Add notes under **Unreleased** as you work.
- **CI** (GitHub Actions) runs on every push and PR: pytest on Python 3.11/3.12/3.13, a compile check, and parse checks for the shell scripts and the JS.
- **Cutting a release:**
  ```bash
  ./release.sh 1.2.0          # bumps VERSION, dates the changelog, commits, tags v1.2.0
  git push && git push --tags # Actions builds gwconsole-v1.2.0.tar.gz and publishes a GitHub Release
  ```
- Run the tests locally: `pip install -r requirements-dev.txt && python -m pytest -q`.
- For bigger changes, work on a branch (`git switch -c feature/x`), push it, open a PR, and let CI pass before merging.
- Secrets never go in the repo. `config.yaml`, `env`, keys and `known_hosts` are git-ignored and live only in `/etc/gwconsole/` on the LXC.

## Adding the DR site later
Add another entry under `haproxy_nodes:` / `cloudflared_nodes:` with `site: DR`, run `prepare-node.sh` on it, `gwconsole trust <ip>`, `gwconsole restart`. Every page handles multiple nodes.

## Security notes
- This tool can reload and restart your gateways. Only expose it on the mgmt VLAN or Tailscale, never through the tunnel or HAProxy publicly.
- Login is scrypt-hashed. Sessions are in memory (a restart logs everyone out). 5 failed logins per IP lock that IP out for 5 minutes. Cookies are `HttpOnly` + `SameSite=Strict`, and every change also needs an `X-GWC` header.
- The SSH key works only from the dashboard IP (`from=` in authorized_keys). Host keys are pinned in `/etc/gwconsole/known_hosts`.
- Prefer non-root? Create a user on the node with `NOPASSWD` sudo, then set `user: <name>` and `sudo: true` for that node.
- CF tokens live in `/etc/gwconsole/env` (root 600). systemd loads them, and the app runs as the unprivileged `gwconsole` user with a hardened unit.

## Files
```
app/            FastAPI backend + static UI (no build step, no CDN)
  main.py       routes, alerts, auth guard
  haproxy.py    admin socket stats, server state, service, config target
  cloudflared.py  units, config.yml parsing, rule test, config target
  configops.py  validate → backup → write → activate → check → rollback
  cfapi.py      Cloudflare tunnels + DNS: report, route, create/delete tunnel
  inventory.py  auto-discovery of cloudflared units on each node
  tunnelops.py  create / delete (archive) tunnels, comment-preserving ingress edits
  sshpool.py    persistent asyncssh connections
tests/          pytest suite (ingress edits, discovery, stats parsing, config, auth)
.github/        CI + release workflows
VERSION         current version;  CHANGELOG.md  release notes;  release.sh  cut a release
install.sh      installer / upgrader for the dashboard LXC
prepare-node.sh one-time setup on each managed node
config.example.yaml
gwconsole.service
```
