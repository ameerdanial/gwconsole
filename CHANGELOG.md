# Changelog

All notable changes to Gateway Console. Versions follow [Semantic Versioning](https://semver.org/):
MAJOR for breaking config/install changes, MINOR for new features, PATCH for fixes.

## [Unreleased]

## [1.4.1] - 2026-11-04
### Added
- **My account** (click your name at the bottom of the menu), for every role:
  - your profile;
  - change your password (optionally keeping your other browsers signed in);
  - your signed-in browsers, with "Sign out" for one or all others;
  - **preferences**, saved for your user on every browser: 24-hour or 12-hour clock, date style
    (4 Nov 2026 / 04/11/2026 / 2026-11-04), time zone, start page, auto-refresh on/off.
- **Sign me out when I'm away** (15 min / 30 min / 1 h / 4 h / 8 h, or only when the sign-in ends):
  - you get a one-minute "Stay signed in" warning first;
  - pages refreshing by themselves don't count as being there;
  - it's checked on the server too, so a closed tab doesn't stay signed in.
  - Superadmins can set the longest allowed time for everyone in Settings → Sign-in security.
- **User card and menu** at the bottom of the sidebar: My account, Preferences, Signed-in browsers,
  What's new, Sign out.
- **Footer** on every page and on the sign-in page: version, whether it's up to date, release notes
  and © ADProject.
- **Activity search and filters:**
  - search text, user, result, Today / 7 / 30 days / All, and categories (config changes, server
    state, tunnels & DNS, monitoring, users & settings, updates & backups, sign-ins);
  - "Hide sign-ins" is on by default;
  - rows are grouped by day, with the full output under Details;
  - "Load 50 more" and CSV export.
- Settings → Cloudflare token help in the setup wizard lists Zone · Analytics · Read.

### Changed
- **New Overview:**
  - Tiles: sites up, servers healthy, backend servers up, tunnels healthy, requests today (vs
    yesterday) and open alerts.
  - "Needs attention" shows the 8 most important alerts instead of all of them.
  - Sites with response times, today's traffic per hour, and server CPU / memory / disk.
  - Gateways with every HAProxy backend's servers and every tunnel's edge connections.
- **One date and time format everywhere**, following your preferences.
- **Phones:**
  - your initials in the top bar open the same menu (Sign out was missing on phones);
  - ☰ opens the page list.
- The version moved from the sidebar to the footer.
- The Alerts page's "Started" column no longer wraps.
- Summary tile text wraps instead of being cut off on phones.

### Fixed
- Overview server squares and the "About HTTPS" box in the HAProxy form were laid out wrongly
  (style names reused in 1.4.0).
- **Tunnels whose origin is `localhost`:**
  - Monitoring now checks them from the cloudflared machine instead of from the dashboard;
  - they only match an HAProxy frontend on that same machine.
- Internal site checks use the tunnel rule's "HTTP Host header" when it has one.
- **Time zones** work on minimal LXC/VM images without the system time-zone database (`tzdata`
  is now installed with the dashboard). Before, the weekly summary and daily traffic could fall
  back to UTC.
- Wording: "1 user / 2 users" instead of "user(s)".

## [1.4.0] - 2026-11-04
### Added
- **Monitoring page.** Every public hostname is found automatically from your tunnels and HAProxy host
  rules and checked every minute, publicly (through Cloudflare) and internally (straight to the origin
  with the right Host header; TCP services get a port check). Response time, uptime for 24 hours and
  7 days, certificate expiry, and per-site options: path, expected status, a word the page must
  contain, slow limit, and "Don't check this site". Add your own checks with "+ Add a check".
- **Server health.** CPU load, memory, the fullest disk and uptime for every node, read over SSH.
  **Watched services**: pick systemd services per server; a stopped one raises an alert and operators
  get a Restart button.
- **"Server" node type** for hosts without HAProxy or cloudflared (web, database, cache, game servers):
  health and watched services only. Added the same way as other nodes (password once, or the command).
- **Graphs** over 1 hour / 6 hours / 24 hours / 7 days: response time per site, memory, CPU load and disk
  per server, requests and 5xx per HAProxy backend, connections. Drawn in the page with no outside
  libraries.
- **Traffic page.** Per site from Cloudflare: requests, visits and unique visitors, bandwidth, share
  served from Cloudflare's cache, 4xx/5xx, threats blocked and top countries. Per HAProxy frontend and
  backend: requests, data, 4xx/5xx and busiest hour, including internal and TCP traffic. Today /
  7 days / 30 days / 12 months, change vs the previous period, stacked chart and CSV export. Kept for a
  year. Needs the token permission **Zone → Analytics → Read** (Settings → Cloudflare → Test shows it).
- **New alerts:** site down (3 failed checks in a row) and slow, backend 5xx share, disk 80 % / 90 %,
  memory 95 %, CPU load above 2× cores for 10 minutes, watched service stopped, certificate expiring
  in 14 / 3 days (HAProxy .pem files on the node and the public certificate), server unreachable.
- **Weekly summary** to Telegram/Discord (Monday 09:00 by default): uptime per site, incidents and the
  longest outage, busiest sites, the backend with the most 5xx, disks filling up. "Send one now" to try it.
- **Settings → Monitoring:** check intervals, down/slow rules, alert thresholds, how long history is
  kept (with the database size), weekly summary day, time and channels, and sites not to check.
- **Drain / maintenance kept after a restart.** On the HAProxy page they are now also written into
  haproxy.cfg (`disabled` / `weight 0`, remembering the original weight) without a reload; "ready"
  undoes it. A 📌 shows a kept state, and a warning shows when the running state and the file disagree.
  Untick "Keep after restart" for a runtime-only change.
- **Version history** in Settings → About & updates: every release with its notes (Added / Changed /
  Fixed), and **Update history**: each upgrade on this dashboard, who ran it, how long it took and
  whether it rolled back. Option to switch off the "new version" message.
- Orphan DNS records on a tunnel can be deleted, or turned into a hostname, from the CF Tunnels page.

### Changed
- **Tunnels is now "CF Tunnels"**, above HAProxy in the menu, and redesigned: a summary row, a
  searchable tunnel list with a "Needs attention" filter, and a detail panel showing each hostname's
  full route (cloudflared → HAProxy frontend → backend → servers up), its DNS state with Fix / Create
  route, and whether the site is up. A new **Hostnames** tab lists every public hostname end to end,
  with CSV export. Tunnels found in Cloudflare but run elsewhere fold away at the bottom.
- The menu is now Overview, Monitoring, Traffic, CF Tunnels, HAProxy, Alerts, Activity, Settings.
- **Settings are grouped** into Access (Users & sessions, Sign-in security), Connections (Nodes,
  Cloudflare accounts), Alerts (Notifications, Monitoring) and System (General, Backups, Config history,
  About & updates). Sign-in security and Config history have their own pages. Old links still work.
- **About & updates redesigned:** a version card (installed when and by whom, previous version kept for
  rollback, host), and a check-for-updates box showing the new version's notes and the steps an update
  takes.
- Settings → Cloudflare → Test also checks the Analytics permission.

## [1.3.0] - 2026-11-03
### Added
- **Add sites and edit HAProxy without typing config.** "+ Add" on the HAProxy page opens one form
  with a Frontend part (new / use existing / none), a Backend part (new / use existing / none) and an
  optional Cloudflare part (adds the hostname to a tunnel and creates its DNS record). Website (HTTP)
  or TCP service; typing the hostname fills in the names and the tunnel target.
  - Frontend tabs: Routing (host, path, header, source IP, method, TLS SNI → backend, redirect,
    redirect to HTTPS, deny, allow only from IPs, set header; reorder), Bind & HTTPS, Headers &
    redirects, Limits & timeouts (incl. rate limit per IP), Advanced.
  - Backend tabs: Servers (weight, max conn, check, backup for DR, and per server HTTPS, SNI, PROXY
    protocol, check timing, cookie, start disabled), Health check, Headers, Timeouts & retries, Advanced.
  - Live plan, checks (name free, hostname not routed elsewhere, HTTP/TCP modes match, port free,
    servers reachable from the HAProxy node) and the exact haproxy.cfg diff; `haproxy -c` before apply;
    the HAProxy change is undone if the Cloudflare step fails.
  - Edit / Delete on every frontend and backend (same form, one part); delete is refused while a
    backend is still in use. "+ server" and ✕ to add or remove one server.
  - Edits are merged in place: unchanged lines keep their formatting and position, lines the form
    doesn't understand stay in Advanced exactly as written.
- **New HAProxy header**: six tiles — service (uptime, start time in your time zone, restarts),
  backends and servers up/down, connections vs maxconn, rates, traffic and 5xx share, HAProxy version.
- **Update from the dashboard** (Settings → About & updates): nightly or on-demand check, changelog of
  each new version, "Update now" with a live log, automatic rollback to the previous version if the
  new one doesn't start, optional automatic install of bug-fix releases, Telegram/Discord message
  when a new version is out, and a one-time "Updated to … — see what's new" banner for everyone.
  Runs through a small root helper (systemd `gwconsole-helper.path`) that accepts only a fixed list
  of requests.
- **Backups of the dashboard** (Settings → Backups, `gwconsole backup` / `gwconsole restore`): nightly
  and before every update/restore, optional copy to a node over SSH, passphrase-encrypted download.
- **Config history**: every change to haproxy.cfg and tunnel configs is committed to a local git
  repository with who made it. **Changed outside the dashboard** alerts (checked every 15 minutes) with
  "Accept change" on the Alerts page.
- **Node software** (Settings → About & updates): cloudflared vs the latest Cloudflare release and
  HAProxy vs the OS packages; **Update cloudflared** restarts the tunnels one at a time and rolls
  back if one doesn't come back.
- **Sign-in security** (Settings → General): message on a sign-in from a new address and when an address
  is locked out after failed attempts; optional **allowed networks** for sign-in and the API
  (`gwconsole allow-all` to reset).

### Changed
- Settings has new tabs: Backups and About & updates (version info moved there).
- `install.sh` installs the helper units, keeps backups readable by the dashboard (root:gwconsole) and
  copies CHANGELOG.md for "What's new".

### Fixed
- Tunnels page: the empty state still pointed to config.yaml; it now links to Settings → Nodes.

## [1.2.0] - 2026-11-03
### Added
- **Config editor in a side panel**: "Edit config" on the HAProxy and Tunnels pages opens the
  editor over the live stats. A **History** tab lists every backup with who made the change,
  shows the diff against the current file, and restores a version in one click.
  The Config page is gone from the sidebar (old `#/config/...` links still work).
- **Alerts page**: a background checker (every 30 s, even with no browser open) keeps each alert's
  lifecycle — firing → resolved with start time and duration, flapping grouped into one alert,
  escalations tracked. Active and History views, filters, acknowledge, mute an alert or a whole
  node (maintenance), CSV export, 90-day retention.
- **Telegram and Discord notifications** (Settings → Notifications): only new, escalated and
  resolved alerts, batched per check, never repeated; minimum severity and recoveries per channel;
  "Send test" button.
- **Users and roles**: viewer (read-only), operator (day-to-day changes), superadmin (everything).
  Add, disable, delete, reset password (temporary password, must be changed at first login),
  change your own password, see and revoke signed-in sessions. Sessions survive restarts.
- **Settings page** (superadmin): Cloudflare accounts with a token permission test (checks Tunnel
  and DNS read/edit without changing anything), nodes with host-key scan + fingerprint confirmation
  and an SSH test, notifications, general settings.
- CLI: `gwconsole create-admin`, `reset-password <user>`, `users`.
- **Easier installation**: `install.sh` checks the host first (root, systemd, Python, free port,
  clock, Cloudflare reachable), then asks for the listen address, port and the first admin login
  (Enter keeps the default), offers to open the port in ufw/firewalld, starts the service, waits
  until it answers and prints the URL. Unattended: `--yes --admin --port --listen` with the password
  in `GWC_ADMIN_PASSWORD`. Works on any systemd host — VM, LXC or bare metal — Debian/Ubuntu (apt)
  and RHEL/Rocky/Alma/Fedora (dnf, Python 3.11 installed when the system one is too old).
- **Setup wizard** in the browser after a fresh install: Nodes → Cloudflare → Alerts → Done.
  Every step can be skipped; reopen it from Settings → General.
- **"Use the node's password once"** when adding a node: the dashboard logs in one time over the
  pinned host key, installs its SSH key (accepted only from the dashboard's IP), `socat` and the
  HAProxy admin socket, checks the key works and forgets the password (never stored or logged).
  Works with root or a sudo user; falls back to that user + passwordless sudo when root can't log in.
- The other option shows a one-line command to paste on the node:
  `curl -fsSL http://<dashboard>/prepare-node.sh | bash -s -- --key … --from …`.
- **Fix it button** for a missing or read-only HAProxy stats socket (HAProxy page and the node test):
  adds `stats socket … level admin` through the safe-apply path and installs `socat`.
- `gwconsole upgrade [vX.Y.Z]`: fetches tags, shows the new version's changelog, asks, backs up and
  upgrades. `gwconsole status`: version, service state and URL.

### Changed
- Users, nodes, Cloudflare accounts and settings now live in a SQLite database
  (`/var/lib/gwconsole/gwconsole.db`). On the first start of 1.2.0 they are imported from
  `config.yaml` once; after that the web UI is the source of truth. `config.yaml` is only the
  bootstrap file (listen address, port, paths).
- Secrets (Cloudflare tokens, Telegram bot token, Discord webhook) are encrypted at rest with
  `/etc/gwconsole/secret.key`, created by `install.sh`.
- Nodes added in the UI pin their SSH host key; existing nodes keep using `known_hosts` until edited.
- `install.sh` backs up `/etc/gwconsole` and the database to `/var/backups/gwconsole/` before upgrading.
- `prepare-node.sh` asks for the key and dashboard IP when they aren't given, detects HAProxy and
  cloudflared by itself (`--haproxy` is no longer needed), supports dnf, a non-root `--user` with
  passwordless sudo, and offers to add the admin stats socket (RHEL's `/var/lib/haproxy` included).
- Web UI JavaScript split into one file per page under `app/static/js/`.
- Git history rewritten so every file has its own descriptive commit; the `v1.1.0` tag was
  recreated (same code). Existing clones: `git fetch --tags --force`.

### Fixed
- Config backups are listed and pruned by when they were taken, not by file modification time.
- Validation errors from the API show a readable message instead of "HTTP 422".

## [1.1.0] - 2026-11-03
### Added
- **Tunnel lifecycle**: create a tunnel (Cloudflare API + credentials + config.yml + systemd unit + DNS)
  with full rollback on failure; delete a tunnel (stop/disable, archive files to `.gwc-archive/`,
  optional DNS and Cloudflare cleanup).
- **Add / remove hostname** form; ingress edits keep comments and indentation (ruamel.yaml) and go
  through the safe-apply pipeline, with optional DNS record create/delete.
- **Auto-discovery** of `cloudflared-*`, `cloudflared@*` and `cloudflared.service` units; Cloudflare
  account auto-matched by tunnel ID; token-run tunnels detected.
- "In Cloudflare, not on a managed node" panel; delete leftovers that have no live connections.
- Version shown in the UI, `gwconsole version`, installer prints `old -> new` on upgrade.
- Test suite (pytest) and GitHub Actions CI; tagged releases build a tarball automatically.

### Changed
- `tunnels:` in `config.yaml` is now optional (overrides only).
- Cloudflare token needs *Cloudflare Tunnel: Edit* and *DNS: Edit* for the new features.

### Fixed / hardened
- Automatic DNS routing never repoints a record that belongs to another tunnel (only *Fix route* does).
- Mutating operations finish even if the browser tab is closed mid-way (remote script ignores
  hangups; server side shielded from cancellation).
- Audit log write failures no longer break operations.

## [1.0.0] - 2026-11-03 (before version control, not tagged)
### Added
- Initial release: overview with KPIs and alerts; HAProxy live stats, server ready/drain/maint,
  reload/restart, logs; cloudflared service control, edge status, ingress view, DNS route check,
  rule tester; config editor with validate → diff → backup → apply → health check → auto-rollback;
  audit log; scrypt login; SSH key access with `from=` restriction; installer and node prep script.

[Unreleased]: ../../compare/v1.4.1...HEAD
[1.4.1]: ../../compare/v1.4.0...v1.4.1
[1.4.0]: ../../compare/v1.3.0...v1.4.0
[1.2.0]: ../../compare/v1.1.0...v1.2.0
[1.1.0]: ../../releases/tag/v1.1.0
