# app/ — Gateway Console backend and web UI

Python package run by `python -m app serve` (FastAPI + uvicorn). The web UI in `static/`
is plain HTML/CSS/JS served as-is — no build step, no CDN.

| File | What it does |
|---|---|
| `main.py` | App startup, login, role guard, and the gateway APIs (overview, HAProxy, tunnels, config editor, activity) |
| `api_alerts.py` | Alerts API: active/history, acknowledge, mutes, CSV export, check now |
| `api_admin.py` | Superadmin APIs: users, sessions, Cloudflare accounts, nodes, notifications, general settings; change own password |
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
| `configops.py` | Safe config apply: validate, backup, write, reload, health check, rollback; backup listing |
| `haproxy.py` | HAProxy: runtime stats via the admin socket, server state, reload/restart, config target |
| `cloudflared.py` | cloudflared: service status, ingress parsing, rule test, config target |
| `inventory.py` | Auto-discovers cloudflared tunnels from systemd units on each node |
| `tunnelops.py` | Tunnel lifecycle on nodes: create, archive-delete, comment-preserving ingress edits |
| `cfapi.py` | Cloudflare API client: tunnels, DNS routes, create/delete, token permission test |
| `__main__.py` | Command line: serve, check, create-admin, reset-password, users, version |
| `static/index.html` | Page shell: login form, sidebar, header |
| `static/style.css` | All styling (dark theme, tables, forms, side panel, settings) |
| `static/js/core.js` | Helpers, API client, modals, roles, login and password flow, router |
| `static/js/editor.js` | Config editor side panel with History tab |
| `static/js/overview.js` · `haproxy.js` · `tunnels.js` · `alerts.js` · `activity.js` · `settings.js` | One file per page |
| `static/js/app.js` | Entry point: starts the app |
