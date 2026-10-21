# One-time `/data` permission probe

This directory is an inactive diagnostic build variant, not a second Home Assistant app. It deliberately contains no `config.yaml`, so Supervisor cannot discover it as another add-on. The existing `hades_m35_puller/config.yaml` remains the sole manifest and keeps the same repository identity and `slug: hades_m35_puller`; therefore a later diagnostic image rebuild uses the same add-on ID and Supervisor-managed `/data` path.

## Exact later change

For a separately authorized test only:

1. Preserve the current `hades_m35_puller/Dockerfile` unchanged as the production version.
2. Temporarily use this file as `hades_m35_puller/Dockerfile` (the only app file switched for the diagnostic build). Do not change `config.yaml`, `repository.yaml`, `run.sh`, the slug, or the repository URL.
3. Rebuild/update the existing add-on entry from the same repository, verify its full add-on ID is unchanged, then manually start it once. The probe image copies only `diagnostics/probe.sh`; it does not copy the puller source, config, tools, keys, or tokens. The script opens no sockets and makes no network requests.
4. Read the start log for `process_uid`, `process_gid`, `/data` owner/mode, probe-file owner/mode, and `probe_file_removed=yes`. A failed create/write or any nonzero exit is a failed permission test.
5. Stop the add-on if it has not already exited, restore the production `Dockerfile`, and rebuild/update the original puller image before any later normal start.

The probe itself checks the effective process identity before creating its uniquely named file. It uses only a constant, non-secret test string. An EXIT handler runs on success and on post-creation errors, attempts cleanup twice, and confirms absence; if the file still remains, the probe exits nonzero with `PROBE_CLEANUP_FAILED` rather than claiming success. No permission changes are attempted. This diagnostic variant has not been built, installed, or started.

## Safety properties

- Existing manual-only policy and manifest remain unchanged.
- No extra app manifest/slug, host path mapping, device, capability, API access, port, ingress, or network listener is added.
- The image uses the already pinned Node 22 Alpine digest and runs as `node:node` only; it has no root bootstrap.
- The existing app's Worker, Provisioner, and Build Worker are not part of this probe image.
