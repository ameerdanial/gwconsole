# app/ — Gateway Console backend and web UI

Python package run by `python -m app serve` (FastAPI + uvicorn). The web UI in `static/`
is plain HTML/CSS/JS served as-is — no build step, no CDN.

| File | What it does |
|---|---|
| `main.py` | App startup, login, role guard, and the gateway APIs (overview, HAProxy, tunnels, config editor, activity) |
| `api_alerts.py` | Alerts API: active/history, acknowledge, mutes, CSV export, check now |
| `api_haproxy.py` | HAProxy Add / Edit APIs: form model of every frontend and backend, dry-run plan (summary, checks, diff, `haproxy -c`), apply with optional Cloudflare publish and undo, reachability / free-port probes |
| `api_system.py` | Version and What's new, update check / install through the root helper, backups (list, back up now, encrypted download), node software versions and cloudflared update, config history |
| `api_admin.py` | Superadmin APIs: users, sessions, Cloudflare accounts, nodes (incl. "use the node's password once" setup), notifications, general settings, setup wizard; change own password |
| `state.py` | Shared runtime state (settings, SSH pool, Cloudflare client, store) and role/audit helpers |
| `collect.py` | Gathers live state from all nodes and Cloudflare, and turns it into alert rules |
| `alerts.py` | Background alert engine: firing → resolved lifecycle, flapping, mutes, retention, notifications |
| `notify.py` | Telegram and Discord message formatting and sending |
| `db.py` | SQLite database with versioned schema migrations |
| `store.py` | Data access: users, sessions, settings, Cloudflare accounts, nodes; one-time import from config.yaml |
| `vault.py` | Encrypts secrets in the database with `/etc/gwconsole/secret.key` |
| `config.py` | Loads the bootstrap `config.yaml` and defines the node/tunnel/account data classes |
| `auth.py` | scrypt password hashing and the login brute-force guard |
| `audit.py` | Append-only audit log (`audit.log`) |
| `sshpool.py` | Persistent SSH connections to nodes, host-key pinning and scanning |
| `history.py` | Config history (local git mirror of every managed config file) and "changed outside the dashboard" detection |
| `backup.py` | Dashboard backups: consistent snapshot, passphrase encryption, safe restore, copy to a node |
| `versions.py` | cloudflared / HAProxy versions on the nodes; cloudflared update with one-at-a-time tunnel restarts and rollback |
| `helper.py` | Root-side helper run by systemd: update check, upgrade with automatic rollback, backups — only a fixed list of requests |
| `configops.py` | Safe config apply: validate, backup, write, reload, health check, rollback; backup listing |
| `hpcfg.py` | HAProxy config model: parses frontends/backends into form fields, keeps unknown lines, merges edits in place, references and validation |
| `haproxy.py` | HAProxy: runtime stats via the admin socket, server state, reload/restart, config target, admin-socket fixer |
| `cloudflared.py` | cloudflared: service status, ingress parsing, rule test, config target |
| `inventory.py` | Auto-discovers cloudflared tunnels from systemd units on each node |
| `tunnelops.py` | Tunnel lifecycle on nodes: create, archive-delete, comment-preserving ingress edits |
| `cfapi.py` | Cloudflare API client: tunnels, DNS routes, create/delete, token permission test |
| `__main__.py` | Command line: serve, check, create-admin, reset-password (`--password-stdin` for install.sh), users, version |
| `static/index.html` | Page shell: login form, sidebar, header |
| `static/style.css` | All styling (dark theme, tables, forms, side panel, settings) |
| `static/js/core.js` | Helpers, API client, modals, roles, login and password flow, router |
| `static/js/editor.js` | Config editor side panel with History tab |
| `static/js/overview.js` · `haproxy.js` · `tunnels.js` · `alerts.js` · `activity.js` · `settings.js` | One file per page |
| `static/js/hpform.js` | HAProxy "+ Add" / Edit side panel: Frontend, Backend and Cloudflare parts, tabs, live plan, checks and diff |
| `static/js/setup.js` | First-run setup wizard: Nodes → Cloudflare → Alerts → Done (reuses the Settings forms) |
| `static/js/app.js` | Entry point: starts the app |
