# H.A.D.E.S. M3.5 Puller

This standalone Home Assistant app sits beside `hades_build_worker` and bundles the M3.5 Node intake runtime. It does not modify or depend on the Build Worker.

## Isolation and behavior

- The app is manual-start only and keeps `mode: intake-only`. The worker validates issue fields and posts receipt acknowledgements only; it does not execute issue content, run a model, or invoke a shell.
- Home Assistant Ingress is enabled for its setup/status page. Home Assistant handles user authentication. The app accepts HTTP connections only from the Supervisor ingress proxy at `172.30.32.2`; it has no published port, host networking, host namespaces, devices, privileged capabilities, host-directory mappings, Home Assistant API, Supervisor API, or Docker API.
- No `/share`, configuration, or other host-directory mount is requested. The app uses only its standard private `/data` volume.
- The image starts its launcher as container root. The launcher verifies the `node` account is UID/GID 1000, prepares only this app's private data directories and known credential files, then drops to UID/GID 1000. Root does not read credential contents. No recursive ownership change is used.
- When no token exists, the Ingress page accepts the GitHub PAT through a password input. The request body is size-limited, protected by a per-process CSRF nonce, and never logged. The app verifies the GitHub account, private repository, and test issue before creating the token file exclusively with mode `0600`. The worker starts only after successful verification.
- When a token already exists, it must be a regular non-symlink file owned by UID 1000 with mode `0600`. The Ingress page then starts the worker. Attempts to replace an existing token are rejected.
- The bundled `config.json` contains only non-secret repository/polling settings and fixed paths. The app does not read `/data/options.json`.

## Setup

1. Update H.A.D.E.S. M3.5 Puller to this version.
2. Open the app's **Web UI** through Home Assistant. This opens its authenticated Ingress page.
3. Enter the fine-grained GitHub token directly in the password field and submit. Do not put it into File Editor, a shell command, or chat.
4. The page confirms only whether setup succeeded. The worker begins after the token passes read-only GitHub checks. It remains manual-start and intake-only.

The token is sent from the browser to Home Assistant over the authenticated Home Assistant session (use the HTTPS Tailnet/Home Assistant address). It is not sent to ChatGPT, stored in Home Assistant app options, or written to logs. Do not use a shared device or capture the token field in a screenshot.

## Local checks

Run the app-specific tests from the repository root:
`node --test tests/hades-m35-puller.test.mjs tests/m35-ingress-provisioner.test.mjs tests/m35-pagination.test.mjs tests/m35-tty-provisioning.test.mjs tests/m35-credential-file.test.mjs`.

They cover ingress-only access, CSRF, bounded request input, token validation, file permissions, root bootstrap, intake-only behavior, pagination, TTY encryption helpers, and credential cleanup. They do not build or start the Home Assistant app or contact GitHub; the ingress test uses mocked GitHub replies.

The client fetches issue and comment pages at 100 items each, up to 10 pages. If the final page is full, it fails closed with a pagination-limit error rather than treating an incomplete result as complete.

The Docker base is pinned to the Docker Official Image OCI index `node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402`. It includes `linux/arm64/v8` and `linux/amd64`. A temporary diagnostic app verified on this Home Assistant host that root can create a private subdirectory on a Supervisor-managed `/data` volume, assign it to UID 1000, and drop privileges for a write. The production app applies that pattern only to its own secrets and state directories.

## GitHub calls

Provisioning performs read-only GET requests to verify the token's account, repository visibility, and access to issue 1. Once running, the intake worker reads authorized open issues and may post receipt comments. It never executes issue content. Do not start the app until you are ready for those documented GitHub calls.
