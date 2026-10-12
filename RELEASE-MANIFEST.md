# Release manifest

- Release: H.A.D.E.S. Build Worker `0.0.4-dev.m4.2.9`
- Purpose: signed, read-only diagnostic receiver; arbitrary code execution remains disabled.
- Supported architecture: `aarch64`
- Update target: existing app slug `hades_build_worker` from this repository; no second app.
- Startup: `boot: auto`; listener remains gated by the existing stored `enabled: true` option.
- Persistent state: existing app data path `/data/hades-m42.5`; worker key and replay ledger paths are unchanged.
- Security: no published ports, host mounts, privileged access, or new Home Assistant API access.
- Compatibility: STATUS_CHECK accepts worker versions `0.0.4-dev.m4.2.5` and `0.0.4-dev.m4.2.9` for forward update and rollback; broker source requires the matching compatibility patch.
- Public surface audit: all release files scanned for private keys, credentials, tokens, local network addresses, private bridge paths, app IDs, and local install paths; no matches found.
- Docker/HA image build: not run. Home Assistant runtime behavior and live configuration retention remain unverified.
- Test report: see the pull request commit checks and local results; no live service was started or changed.
- `SHA256SUMS` covers release files except itself and this manifest.

This is a prepared source update. It is not an installation or a live recovery claim.
