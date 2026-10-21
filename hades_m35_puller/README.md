# H.A.D.E.S. M3.5 Supervisor /data Probe

This is a temporary diagnostic branch. It runs only `diagnostics/probe.sh` as `node:node` (UID/GID 1000) to test whether this Home Assistant Supervisor-managed app `/data` mount allows creating, writing, inspecting, and removing one constant, non-secret probe file.

It does **not** run the Puller, Provisioner, Worker, or contact GitHub. It has no credentials, network requests, listeners, ports, host mounts, or Supervisor API access.

## Run once

1. In Home Assistant, add this repository URL to **Settings → Apps → App Store → ⋮ → Repositories**:
   `https://github.com/engelssebastian239-ops/hades-build-worker-addon#m35-permission-probe`
2. Install **H.A.D.E.S. M3.5 /data Permission Probe (Temporary)** and start it manually once.
3. In its log, success requires all of:
   - `process_uid=1000 process_gid=1000`
   - `probe_write_confirmed=yes`
   - `probe_file_removed=yes`
   - exit status 0

Any other result is a failed or incomplete test. Do not provision a token or start the normal Puller from this branch.

## Scope of the result

Home Assistant hashes the repository URL including `#branch` when it creates a repository ID. Therefore this branch has its own temporary app ID and its own newly created `/data` directory. A successful run proves UID/GID 1000 can write to a real Supervisor-managed app `/data` mount on this host. It is a strong check of the standard mount behavior, but it does not inspect another app's existing data directory.

After reading the result, stop and uninstall this temporary probe app, then remove the repository entry. The normal Puller remains a separate draft PR and is not installed or started by this probe.
