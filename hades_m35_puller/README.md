# H.A.D.E.S. M3.5 Puller

This standalone Home Assistant app sits beside `hades_build_worker` and bundles the M3.5 Node intake runtime. It does not modify or depend on the Build Worker.

## Isolation and behavior

- The image starts its launcher as container root. The launcher verifies the `node` account is UID/GID 1000, prepares only this app's private data directories and known credential files, then uses `su-exec` to start the worker as UID/GID 1000. Root does not read credential contents.
- `mode` is fixed to `intake-only`. The worker validates issue fields and posts receipt acknowledgements only; it does not execute issue content, run a model, or invoke a shell.
- `boot: manual_only`; no app options can enable another mode.
- No published ports or ingress; no host networking, host namespaces, devices, privileged capabilities, explicit host-path mappings, Home Assistant API, Supervisor API, or Docker API.
- Home Assistant's standard per-app `/data` storage is used for the credential and persistent receipt state. `map: []` requests no extra host-directory mounts. Startup begins as container root only to create the app-specific secrets and state directories with owner UID/GID 1000 and mode `0700`, and to normalize known credential files to owner 1000 and mode `0600`. It rejects symlink paths, does not recursively change ownership, reads no secrets as root, and then drops to UID/GID 1000 before starting the worker. The temporary Supervisor probe confirmed that this narrow root-bootstrap/UID-1000 pattern works on this Home Assistant host; it did not access the production add-on's separate `/data` volume.
- The bundled `config.json` contains only non-secret repository/polling settings and fixed paths. The App does not read `/data/options.json`.

## Local checks

Run the app-specific tests from the repository root: `node --test tests/hades-m35-puller.test.mjs tests/m35-pagination.test.mjs tests/m35-tty-provisioning.test.mjs tests/m35-credential-file.test.mjs`. They check the manifest's isolation flags, root bootstrap and UID-1000 privilege drop, fixed intake-only configuration, independent fingerprint validation, bounded issue/comment pagination, TTY encryption, and credential-file cleanup. They do not build or start a container, run the worker/provisioner, or contact GitHub.

The client fetches issue and comment pages at 100 items each, up to 10 pages. If the final page is full, it fails closed with a pagination-limit error rather than treating an incomplete result as complete.

The Docker base is pinned to the Docker Official Image OCI index `node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402`. The registry index was checked on 2026-10-21 and includes `linux/arm64/v8` and `linux/amd64`. A temporary diagnostic app verified on this Home Assistant host that root can create a private subdirectory on a Supervisor-managed `/data` volume, assign it to UID 1000, and drop privileges for a write. The production app applies that pattern only to its own secrets and state directories; it never changes ownership of `/data` or uses a host mount.

## Installation (not performed)

**Single Home Assistant UI step, after this repository has been published to a reachable Git URL:** open **Settings → Apps → App Store → ⋮ → Repositories** and add that repository URL. Then select **H.A.D.E.S. M3.5 Puller** from the store. This checkout has not been pushed, so the app is not currently installable from the store.

Before running the provisioner, supply `HADES_M35_TRUSTED_PUBLIC_KEY_SHA256` from a separately trusted fingerprint captured from the server; do not copy it from `public-for-windows.json`. The provisioner validates that external pin against the actual public-key DER hash and then checks that the private key matches. Only after that may a separately approved provisioning operation create the server-side keypair and token in the app's `/data` volume.

Do not start the production app until it is installed and the provisioned credential file owner/mode are verified. After startup, the worker performs live GitHub reads and may post receipt comments; neither was done for this draft.
