# app/ — Gateway Console backend and web UI

Python package run by `python -m app serve` (FastAPI + uvicorn). The web UI in `static/`
is plain HTML/CSS/JS served as-is — no build step, no CDN.

| File | What it does |
|---|---|
| `main.py` | App startup, login with the two-step sign-in step, role, scope and idle sign-out guard, version header for open tabs, and the gateway APIs (overview, HAProxy incl. drain/maint kept after restart, tunnels with routes, config editor, activity search and CSV) |
| `api_account.py` | My account APIs for every role: profile, preferences, your own signed-in browsers, two-step sign-in (set up, recovery codes, remembered browsers, turn off) |
| `api_monitor.py` | Monitoring and Traffic APIs: sites, servers, watched services and Restart, graphs, Settings → Monitoring, weekly summary, Traffic page and CSV, per-hostname routes for CF Tunnels |
| `api_alerts.py` | Alerts API: active/history, acknowledge, mutes, CSV export, check now |
| `api_haproxy.py` | HAProxy Add / Edit APIs: form model of every frontend and backend, dry-run plan (summary, checks, diff, `haproxy -c`), apply with optional Cloudflare publish and undo, reachability / free-port probes |
| `api_system.py` | Version and What's new, release notes for every version, update history, update check / install through the root helper, backups (list with checks, back up now, encrypted download, upload, preview and restore through the root helper, damaged-backup alert), node software versions and cloudflared update, config history |
| `api_admin.py` | Superadmin APIs: users, what each user can manage (choices, preview, save), 2FA reset, sessions, Cloudflare accounts, nodes (incl. "use the node's password once" setup), notifications, general settings, setup wizard; change own password |
| `state.py` | Shared runtime state (settings, SSH pool, Cloudflare client, store) and role, scope and audit helpers |
| `scope.py` | Scoped access: which tunnels, hostnames and HAProxy backends a user can manage, filtering what they see, rewriting their HAProxy edits to their own rules and checking every change before and after |
| `totp.py` | Two-step sign-in codes (RFC 6238), recovery codes and the setup QR code |
| `collect.py` | Gathers live state from all nodes and Cloudflare, and turns it into alert rules |
| `alerts.py` | Background alert engine: firing → resolved lifecycle, flapping, mutes, retention, notifications (includes the monitoring alerts) |
| `monitor.py` | Background monitoring: site checks (public + internal), server health and watched services over SSH, certificate expiry, 1-minute / 15-minute history, HAProxy counter history, monitoring alerts, weekly summary |
| `sites.py` | Public hostnames and where they go: discovery from tunnel ingress and HAProxy host rules, route tunnel → HAProxy frontend → backend → servers |
| `traffic.py` | Traffic numbers per day for a year: Cloudflare GraphQL Analytics per hostname and zone, HAProxy per frontend/backend; builds the Traffic page and CSV |
| `notify.py` | Telegram and Discord message formatting and sending |
| `db.py` | SQLite database with versioned schema migrations (v1.4 adds the Server node type, checks, health, services, samples, traffic and update history; v1.4.1 user preferences and idle sign-out; v1.5 scoped access, two-step sign-in and remembered browsers) |
| `store.py` | Data access: users and their preferences, what they can manage, two-step sign-in, sessions with sign-out when away, remembered browsers, settings (general and monitoring), Cloudflare accounts, nodes; one-time import from config.yaml |
| `vault.py` | Encrypts secrets in the database with `/etc/gwconsole/secret.key` |
| `config.py` | Loads the bootstrap `config.yaml` and defines the node (HAProxy, cloudflared, Server), tunnel and account data classes |
| `auth.py` | scrypt password hashing and the login brute-force guard |
| `audit.py` | Append-only audit log (`audit.log`) and searching it for the Activity page (text, user, result, category, time; paged; limited to what a user can see) |
| `sshpool.py` | Persistent SSH connections to nodes, host-key pinning and scanning |
| `history.py` | Config history (local git mirror of every managed config file) and "changed outside the dashboard" detection |
| `backup.py` | Dashboard backups: consistent snapshot, passphrase encryption, archive checks, what a backup holds (inspect), nightly-style verification, safe restore, copy to a node |
| `versions.py` | cloudflared / HAProxy versions on the nodes; cloudflared update with one-at-a-time tunnel restarts and rollback |
| `helper.py` | Root-side helper run by systemd: update check, upgrade with automatic rollback (recorded in the update history), backups, restores — only a fixed list of requests |
| `configops.py` | Safe config apply: validate, backup, write, reload, health check, rollback; backup listing |
| `hpcfg.py` | HAProxy config model: parses frontends/backends into form fields, keeps unknown lines, merges edits in place, references and validation, kept server state (`disabled` / `weight`) |
| `haproxy.py` | HAProxy: runtime stats via the admin socket, server state, reload/restart, config target, admin-socket fixer |
| `cloudflared.py` | cloudflared: service status, ingress parsing, rule test, config target |
| `inventory.py` | Auto-discovers cloudflared tunnels from systemd units on each node |
| `tunnelops.py` | Tunnel lifecycle on nodes: create, archive-delete, comment-preserving ingress edits |
| `cfapi.py` | Cloudflare API client: tunnels, DNS routes, create/delete, GraphQL analytics, token permission test |
| `__main__.py` | Command line: serve, check, create-admin, reset-password (`--password-stdin` for install.sh), reset-2fa, users, version, backup, restore with health check and automatic rollback |
| `static/index.html` | Page shell: login form and two-step code step, sidebar with the user card and menu, header, footer |
| `static/style.css` | All styling (dark theme, tables, forms, side panel, charts, settings sections) |
| `static/js/core.js` | Helpers, API client (notices a new version), date/time formatting from your preferences, modals, ⋯ menus, roles, login, two-step sign-in (code step, setup, recovery codes) and password flow, scope banner, sign-out when away, user menu, footer, router |
| `static/js/charts.js` | Line charts with hover tooltips, stacked bar charts and sparklines as inline SVG (no libraries) |
| `static/js/editor.js` | Config editor side panel with History tab |
| `static/js/overview.js` · `monitoring.js` · `traffic.js` · `tunnels.js` (CF Tunnels) · `haproxy.js` · `alerts.js` · `activity.js` · `account.js` (My account) · `settings.js` | One file per page |
| `static/js/hpform.js` | HAProxy "+ Add" / Edit side panel: Frontend, Backend and Cloudflare parts, tabs, live plan, checks and diff |
| `static/js/setup.js` | First-run setup wizard: Nodes → Cloudflare → Alerts → Done (reuses the Settings forms) |
| `static/js/app.js` | Entry point: starts the app |
