# Changelog

All notable changes to Gateway Console. Versions follow [Semantic Versioning](https://semver.org/):
MAJOR for breaking config/install changes, MINOR for new features, PATCH for fixes.

## [Unreleased]

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

[Unreleased]: ../../compare/v1.2.0...HEAD
[1.2.0]: ../../compare/v1.1.0...v1.2.0
[1.1.0]: ../../releases/tag/v1.1.0
