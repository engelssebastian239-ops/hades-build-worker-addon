# H.A.D.E.S. M3.5 Supervisor /data Probe

This temporary diagnostic branch tests the proposed startup model against the real Home Assistant Supervisor-managed `/data` mount: a small root bootstrap creates a protected app subdirectory owned by `node:node` (UID/GID 1000), then `su-exec` drops to that identity and writes one constant, non-secret probe file.

It does **not** run the Puller, Provisioner, Worker, or contact GitHub. It contains no credentials or keys and opens no ports or listeners. It does not change the owner or mode of `/data`; it creates and removes only a uniquely named temporary subdirectory.

## Run once

1. In Home Assistant, add this repository URL to **Settings → Apps → App Store → ⋮ → Repositories**:
   `https://github.com/engelssebastian239-ops/hades-build-worker-addon#m35-permission-probe`
2. Update **H.A.D.E.S. M3.5 /data Permission Probe (Temporary)** so it uses the latest branch commit, then start it manually once.
3. In its log, success requires:
   - `bootstrap_uid=0 bootstrap_gid=0`
   - `protected_directory_owner=1000:1000 mode=700`
   - `probe_write_confirmed=yes`
   - `probe_file_removed=yes`
   - exit status 0

Any other result is a failed or incomplete test. Do not provision a token or start the normal Puller from this branch.

## Scope of the result

Home Assistant hashes the repository URL including `#branch` when it creates a repository ID. This branch therefore has its own temporary app ID and its own newly created `/data` directory. A successful run proves that this host allows the proposed root-bootstrap/UID-1000 privilege-drop pattern on an actual Supervisor-managed app volume. It does not inspect another app's existing data directory.

After the result is reviewed, stop and uninstall this temporary probe app, then remove the repository entry. The normal Puller remains a separate draft PR and is not installed or started by this probe.
