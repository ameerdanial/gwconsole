# tests/ — automated tests

Run them with `pip install -r requirements-dev.txt && python -m pytest -q`.
CI runs the same suite on Python 3.11, 3.12 and 3.13 for every push and pull request, with a real `haproxy` installed for the config checks.

| File | Covers |
|---|---|
| `conftest.py` | Fixtures: a throwaway database + secret key, and a running app with a test config |
| `test_api.py` | Login, roles and permissions, forced password change, CSRF header, admin endpoints |
| `test_store.py` | Users and the last-superadmin guard, sessions, settings validation, encrypted accounts, nodes, YAML import |
| `test_alerts.py` | Alert lifecycle (open, resolve, escalate, flap), unreachable nodes, mutes, notification text |
| `test_ingress.py` | Adding/removing tunnel hostnames while keeping comments and indentation |
| `test_discovery.py` | Discovering cloudflared tunnels from systemd unit output |
| `test_haproxy_parse.py` | Parsing HAProxy `show info` / `show stat` |
| `test_core.py` | Version, password hashing, diffs, loading config.yaml |
| `test_hpcfg.py` | HAProxy config model: parsing, unchanged saves change nothing, in-place edits, rules, rename/delete protection, validation, real `haproxy -c` |
| `test_system.py` | Backups (encryption, restore safety), root helper requests, changelog sections, config history, update/backup APIs, sign-in security |
| `test_setup.py` | HAProxy admin-socket fixer, setup wizard API, public health/script endpoints, password-once input checks, `create-admin --password-stdin` |
| `test_monitor.py` | Database upgrade to v1.4, Server nodes, Settings → Monitoring, health parsing, routes through HAProxy, kept server state, monitoring alerts and API, HAProxy counter history, Cloudflare traffic parsing and the Traffic API, release notes |
| `test_scope.py` | Scoped access: domain matching, own and shared backends, rule edits that keep other rules, refusals and the before/after safety net, filtered tunnels and activity, access choices, migration 4, and a check that every route that changes something tests the role and the scope |
| `test_twofa.py` | Two-step sign-in: RFC 6238 test vectors, replay and clock drift, recovery codes, the sign-in flow with a ticket, remembered browsers, lock-out, the "required for" policy, turning it off, superadmin reset |
| `test_restore.py` | Restore: what a backup holds, damaged backup detection, upload → passphrase → preview → restore with password, 2FA code and RESTORE, refusing a newer version, the 200 MB upload limit, superadmin only, helper restore requests, the damaged-backup alert |
| `test_account.py` | My account API and preferences, sign-out when away (cap, auto-refresh not counting), password change options, Activity search and CSV, Overview data, localhost tunnel routes, upgrade from the 1.4.0 database |
