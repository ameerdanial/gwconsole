# tests/ — automated tests

Run them with `pip install -r requirements-dev.txt && python -m pytest -q`.
CI runs the same suite on Python 3.11, 3.12 and 3.13 for every push and pull request.

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
| `test_setup.py` | HAProxy admin-socket fixer, setup wizard API, public health/script endpoints, password-once input checks, `create-admin --password-stdin` |
