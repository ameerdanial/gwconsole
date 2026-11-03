# Changelog

All notable changes to Gateway Console. Versions follow [Semantic Versioning](https://semver.org/):
MAJOR for breaking config/install changes, MINOR for new features, PATCH for fixes.

## [Unreleased]

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

[Unreleased]: ../../compare/v1.1.0...HEAD
[1.1.0]: ../../releases/tag/v1.1.0
