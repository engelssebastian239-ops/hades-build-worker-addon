# M576 Mobile install pull

M576 adds an optional GitHub issue poller to the Build Worker. It accepts only the fixed `PLAN_M574` and `INSTALL_M574` schemas in the private `engelssebastian239-ops/hades-hermes-queue` repository. Requests are authenticated and their results are signed hash-only receipts. The feature is off by default. The diagnostic puller remains an independent loop with the existing broker trust, key, ledger, options, and permissions.

This is not a completed ChatGPT Plus-to-Miner route and does not install HERMES or create a HADES↔HERMES chat connection. The protected server-side job signing and package-delivery path is still missing. No install request should be assumed available until that route, the installer, its profile enforcement, and the existing LegacyBroker response-version compatibility have each been verified.

## Setup and access

Install a reviewed Worker candidate first. The Worker must remain `enabled: true`; `mobile_install_enabled` defaults to `false`. Configure the installer’s public adapter ID and base64 DER Ed25519 public key in `mobile_install_adapter_id` and `mobile_install_adapter_public_key`. Obtain those public values from the separately installed installer’s protected Home Assistant logs and verify their `sha256:` identity matches the key. They are public verification material, not signing secrets. A missing or mismatched pin blocks the Mobile feature before it writes Mobile state.

The Worker reuses its existing Home Assistant Ingress credential form and mode-0600 GitHub token file under `/data/hades-m42.5`. When Mobile is enabled, a new token is not persisted until the authenticated account and private repository, pinned Contents file, pinned successful Actions run, and Issues read access pass. Required fine-grained token permissions are Metadata read, Contents read, Actions read, and Issues read/write for the private queue repository. No token is placed in add-on options, environment overrides, issue comments, or log messages. Keep `github_pull_enabled` independent: it controls the original diagnostic poller. Mobile activation starts only its own single-flight 120-second poll loop.

Set the adapter public pin before enabling Mobile. If the Mobile read preflight fails while setting up the first token, the new credential is not saved. For diagnostic-only setup, leave Mobile disabled until the shared credential has been provisioned.

Read readiness does not prove write access. The UI/status remains `WRITE_UNVERIFIED` until this process receives HTTP 201 for its own valid signed `PLAN_M574` receipt comment. Only then can a later `INSTALL_M574` be considered. A permission failure does not disable the existing diagnostic poller.

## State, recovery, and removal

Plans, archive bytes, ledgers, and comment outbox state are stored under the Worker’s private `/data/hades-m42.5/mobile-install` directory with mode 0700 directories and mode 0600 files. Do not copy these files into chat or issue comments. An ambiguous or interrupted installer request stays `UNKNOWN`; the poller does not resend it. Reconciliation requires a separate signed operator decision and is not supplied by the current Plus route.

To stop Mobile polling, set `mobile_install_enabled: false` and restart the Worker. This leaves the separate diagnostic poller governed by `github_pull_enabled`. The GitHub token is shared with that existing puller; removing it also disables diagnostics. Before removing the installer add-on or deleting its `/data`, take a protected Home Assistant backup of that add-on data and preserve the installer’s encryption key together with its encrypted source backups. Without that key, those source snapshots cannot be decrypted. Never export the key to chat, issue comments, shell logs, or this repository.

The installer’s Supervisor partial backup can include shared Supervisor configuration, so the Worker does not invoke partial restore as a Mobile-only rollback. The installer can restore only the pinned old Mobile source state after a confirmed build failure. This source rollback does not restore Mobile user data. Worker/installer CI builds are source validation only; they do not publish images, install add-ons, or prove a live runtime connection.
