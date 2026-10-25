# Signed GitHub diagnostic pull

This is an optional, outbound-only transport for the existing diagnostic receiver. It does not install or deploy an add-on, transfer packages, invoke a model, provide a shell, or accept arbitrary issue instructions. The HTTP diagnostic endpoint remains available unchanged. Both `enabled` and `github_pull_enabled` must be explicitly true; both defaults are false. App startup remains manual, with no published ports or new host, Supervisor, or Docker API access.

## Fixed protocol and limits

The worker polls only the private repository `engelssebastian239-ops/hades-hermes-queue` at `https://api.github.com`, every 120 seconds. The authenticated GitHub account must be exactly `engelssebastian239-ops`, and the repository must report itself private on every poll. Redirects are rejected. Requests time out after 8 seconds; response bodies are bounded; each poll reads at most three pages of 30 issues, processes at most five nonterminal eligible issues, and makes at most 20 API calls. Malformed, expired, invalid-signature, replay-conflicting, and already-terminal issues do not use the five-task processing budget. GitHub rate-limit responses use `Retry-After` or the reset time; other failures use bounded exponential backoff. There are no GitHub webhooks or inbound GitHub connections.

An eligible open issue must be authored by the fixed owner and have exactly this title and JSON body shape:

```text
HADES-DIAGNOSTIC-V1 <UUID taskId>
```

```json
{"schema":"HADES_GITHUB_DIAGNOSTIC_V1","envelope":{}}
```

The envelope must have exactly the existing signed diagnostic request fields. The worker passes its exact JSON to `createDiagnosticReceiver.handle`; that receiver remains responsible for Ed25519 verification, identity correlation, TTL, allowed-operation, and replay checks. Pull requests, other authors, extra fields, malformed titles, and arbitrary content are ignored. The only allowed operations remain `STATUS_CHECK`, `HEARTBEAT_CHECK`, and `QUEUE_HEALTH_CHECK`.

The worker verifies its existing signed response and may post only this fixed comment format:

```text
<!-- HADES-DIAGNOSTIC-RESULT-V1 -->
<exact signed response JSON>
```

The response comment contains no issue text, token, or other result decoration. A private, mode-0600, worker-owned ledger is atomically fsynced before the one permitted POST. On restart, a `POST_ATTEMPTED` entry only reconciles comments; a matching owner comment completes it, while an absent or conflicting comment becomes terminally ambiguous. The worker never retries an uncertain POST, so a lost response may require operator inspection rather than risking duplicate comments. The existing diagnostic replay ledger makes a repeated signed envelope return its prior signed result.

## One-time operator setup

The source candidate is branch `codex/m573-signed-github-pull-20261025`, with app version `0.0.6-dev.m5.13`. It is not published or installed. The validator in this repository accepts both the previous `0.0.6-dev.m5.12` and this candidate version; compatibility with the separately deployed HERMES validator has not been verified and must be confirmed before installation. A maintainer must first review and install the candidate Worker update in Home Assistant, preserving its existing app data and options. The updated app must be running with `enabled: true`, a separately provisioned trusted broker ID/public key, and `github_pull_enabled: true`. The feature must remain off until that exact install and identity setup are complete.

Then use the Home Assistant-authenticated app Ingress page. This add-on does not receive or pin the Home Assistant account identity or Owner role. The security boundary is HA Ingress authentication plus the exact GitHub token-account check and the existing broker Ed25519 signature checks; limit app Ingress access to trusted operators. The setup page accepts a fine-grained GitHub token only for this fixed repository, checks the account, private-repository status, and issue access, then writes it to `/data/hades-m42.5/github-pull-token` as a worker-owned mode-0600 file. The token is never placed in app options, environment variables, command arguments, logs, or comments. Required token permissions are repository metadata read and Issues read/write. Replacing the token requires a reviewed operator procedure; the setup endpoint refuses overwrite. Do not paste the token into ChatGPT, issues, logs, or a shell command.

The first install and enabling of Ingress are bootstrap actions that this pull transport cannot perform. No live Home Assistant or GitHub request, installation, or end-to-end connection is claimed by this source patch. Installation and operation remain an explicit operator task.

## Broker key and signing helper

The included helpers are for controlled/manual diagnostics and tests; they do not provide the protected, persistent signing service that ChatGPT Plus needs. Do not treat a Windows PC or other general-purpose client as a permanent broker. Production signing still requires a separately reviewed server-side broker using a supported secret store.

For controlled/manual diagnostics only, create a broker identity in a protected directory:

```sh
umask 077
node hades_build_worker/tools/create-diagnostic-broker-key.mjs /absolute/private/path/hades-broker-ed25519.pem
```

The helper creates a mode-0600 Ed25519 private key exclusively and prints only the broker ID and public-key material. Provision that public identity to the Worker through the protected Home Assistant app configuration. Do not put the private file in this repository, Home Assistant app options, or chat.

After an operator has separately obtained the Worker public key, the helper can produce one short-lived signed diagnostic issue payload:

```sh
node hades_build_worker/tools/sign-diagnostic-request.mjs /absolute/private/path/hades-broker-ed25519.pem '<WORKER_PUBLIC_KEY_BASE64>' STATUS_CHECK
```

This prints the fixed issue title/body and expiry, not the private key. A human can manually create the issue in the private repository before expiry, but this helper is not a protected production broker. ChatGPT Plus and its GitHub connector currently do not have access to a server-side signing service, so this channel does not give Plus autonomous signed task submission. Do not work around this by accepting unsigned issue text or by exposing the key.

## Verification

Run `npm test` and `npm run syntax`. The existing PR validation workflow also runs the full suite and syntax checks on the free standard Linux runner, then builds both app images locally for ARM64 using QEMU. It does not publish images, upload artifacts, use registry credentials, or deploy.
