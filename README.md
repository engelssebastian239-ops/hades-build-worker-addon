# H.A.D.E.S. Build Worker

A Home Assistant app repository with a read-only diagnostic receiver.

## Safety defaults

- Diagnostic receiver disabled by default.
- Only `STATUS_CHECK`, `HEARTBEAT_CHECK`, and `QUEUE_HEALTH_CHECK` are accepted.
- No arbitrary code execution, shell interface, host mounts, Supervisor API, Docker API, privileged mode, or published ports.
- The app targets aarch64 and starts manually.
- Keep the receiver disabled until broker and worker identities are securely provisioned. Installing this test app alone does not establish a broker connection.

This is a test build. The Docker image has not been built or validated by Home Assistant Supervisor. Review the source and logs before enabling diagnostics.

## H.A.D.E.S. M3.5 Puller

The repository also contains the separate [`hades_m35_puller`](hades_m35_puller/) app. Home Assistant discovers it from its top-level `config.yaml`; the root `repository.yaml` identifies this repository for the app store. The puller is manual-start and intake-only, with no execution of issue content. Its installation remains gated on verifying UID-1000 write access to the Supervisor-managed persistent `/data` volume. See [`hades_m35_puller/README.md`](hades_m35_puller/README.md).

## Install from Home Assistant on Android

1. Open Home Assistant and go to **Settings → Apps → Install app**.
2. Open the top-right menu, choose **Repositories**, and add:
   `https://github.com/engelssebastian239-ops/hades-build-worker-addon`
3. Select **Add**, return to the app store, refresh if needed, and install **H.A.D.E.S. Build Worker**.
4. Leave `enabled` set to `false`. Do not configure public ports or router forwarding.

The Android app manages the Home Assistant OS app on the server.

## Development

Requires Node.js 20 or later. No npm packages are required.

```sh
npm test
npm run syntax
```

See [docs/INSTALL.md](docs/INSTALL.md) and [SECURITY.md](SECURITY.md).