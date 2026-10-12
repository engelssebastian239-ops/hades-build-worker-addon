# Update, backup, and rollback

This release updates the already-installed app from this repository. It does not create a new app instance.

## Before updating

1. In Home Assistant, open **Settings → System → Backups** and create a full backup. Confirm the backup includes Home Assistant apps and their data.
2. Open the existing **H.A.D.E.S. Build Worker** app detail page. Confirm it is the installed entry from `hades-build-worker-addon`, version `0.0.4-dev.m4.2.5`, and slug `hades_build_worker`.
3. Review the existing app configuration in place. Confirm `enabled: true`, the trusted broker ID, and trusted broker public key are already set. Do not copy the public key to notes or logs. If these values are absent or differ, stop before updating.
4. Confirm the app data backup is available. The worker key and replay ledger live in the existing `/data/hades-m42.5` app data volume and are not part of the repository.

## Update through the Home Assistant app

After this update has been merged to the repository's default branch:

1. In the Home Assistant Android app, open **Settings → Apps** (older releases call this **Add-ons**).
2. Open the app-store menu **⋮ → Check for updates** or **Reload**.
3. Open the already-installed **H.A.D.E.S. Build Worker** entry. Confirm the displayed candidate is `0.0.4-dev.m4.2.9` and the installed repository is `engelssebastian239-ops/hades-build-worker-addon`.
4. Select **Update** on that existing entry. Do not select **Install**, create an additional app, uninstall, or remove app data. If Home Assistant offers a backup-before-update option, enable it; retain the full backup from step 1 regardless.
5. After the update, inspect the same app's options again. Confirm `enabled: true`, trusted broker ID, and trusted broker public key remain unchanged. Check logs for `HADES_BUILD_WORKER_READY` and the `0.0.4-dev.m4.2.9` version. A `HADES_BUILD_WORKER_DISABLED` state means the stored `enabled` option is not true; do not reboot or proceed with broker checks in that state.
6. Confirm the app boot setting now shows automatic/start-on-boot. If it is still manual or unavailable, stop acceptance; `boot: auto` in source alone has not been shown to update the installed setting.
7. Confirm the same worker identity is reported as before. Do not rotate or recreate keys. Validate signed `STATUS_CHECK` with the broker only after the broker accepts both supported worker versions. A full host reboot is a separate, controlled acceptance step.

The app manifest changes `boot` from `manual_only` to `auto`. The app slug, data path, option schema, and secure execution restrictions remain unchanged. Home Assistant stores the app's selected options separately from repository defaults; the repository's `enabled: false` is only the default for a new app. This update procedure explicitly verifies the existing stored `enabled: true` before and after applying the update. Do not infer that auto boot alone enables diagnostics.

## Rollback

1. If post-update checks fail, do not uninstall the app or remove its data.
2. In **Settings → System → Backups**, restore the full backup made immediately before the update, including the H.A.D.E.S. app and its data. Follow the UI's backup restore flow and verify the app returns to `0.0.4-dev.m4.2.5`.
3. Confirm the original app options, worker identity, key, and replay ledger are present. If the backup does not include the app image and data, stop and use Home Assistant's supported restore flow with an administrator; do not delete or recreate the app.

Restoring a backup may require a Home Assistant restart. Do this only as part of the separately approved installation/rollback window.

## Current preparation status

The source update and local tests do not prove a Home Assistant image build, Supervisor update behavior, or live option preservation. Verify the stored options and identity in Home Assistant during the separately approved update.
