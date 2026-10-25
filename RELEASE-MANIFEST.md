# Candidate manifest

- Source candidate branch: `codex/m573-signed-github-pull-20261025`.
- Candidate app version: `0.0.6-dev.m5.13`; the validator in this repository retains support for prior Worker versions and explicitly accepts this candidate version.
- Release status: source candidate only, not published, merged, or installed.
- Scope: optional outbound GitHub pull transport for the existing signed, read-only diagnostic protocol; default off.
- Repository: fixed private `engelssebastian239-ops/hades-hermes-queue`; no arbitrary issue execution, model route, package install, or deployment.
- Permissions: existing add-on sandbox and API permissions retained; no public ports, host mounts, Supervisor API, Docker API, or new privileges. Home Assistant Ingress is enabled only for protected token provisioning.
- Credentials: private broker key stays with trusted broker operator; GitHub token is entered via authenticated Ingress and stored in app-private data with mode 0600. No credentials are committed.
- Validation: see PR checks for full Node test suite, syntax checks, and local ARM64 QEMU builds of both images. No image publication, artifact upload, deployment, or live GitHub/Home Assistant call is part of validation.
- Operational boundary: this source change does not install the add-on or configure the broker. Compatibility with the separately deployed HERMES validator has not been verified and remains an install gate. The app does not pin a Home Assistant Owner identity; access relies on HA Ingress authentication, the pinned GitHub token account, and broker Ed25519 verification. ChatGPT Plus has no protected server-side signing broker path today, so it cannot autonomously create signed diagnostic tasks through GitHub.
