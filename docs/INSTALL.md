# H.A.D.E.S. Build Worker — controlled update and recovery

## Scope and approval gate

The installed Home Assistant app is confirmed to use this repository. Worker PR #2 proposes version `0.0.5-dev.m5.6`; the default branch remains on the prior release until the PR is reviewed and merged.

Merging can make the update available to Home Assistant. The automatic-update setting has not been verified, so treat merge as potentially starting the app update. Do not merge or update without the owner's explicit approval for this Worker-only change.

The update may restart the Build Worker app. It must not restart the Home Assistant host. Keep `package_stage_enabled: false`; this update does not authorize a package transfer, installation, or code execution.

## Preserve the existing installation

- Update the already-installed app in place through Home Assistant. Do not install a duplicate, uninstall the app, clear app data, or reset its options.
- The existing and candidate launchers use the same Supervisor-persistent `/data/hades-m42.5` directory. Both use the same worker identity file and diagnostic replay-ledger paths.
- Existing options remain compatible: `enabled`, `listen_port`, `trusted_broker_id`, and `trusted_broker_public_key`. The new `package_stage_enabled` option defaults to false when absent and must remain false for this update.
- No production private key or broker secret belongs in the repository, an issue, or a command.

## Controlled update sequence

1. Obtain explicit approval for merging PR #2 and updating only the existing Build Worker app. Treat automatic updating as potentially enabled because its current setting is unknown.
2. A full Home Assistant backup is reported present. Its integrity and restore procedure have not been verified; backup presence alone is not proof of a tested rollback.
3. Merge only Worker PR #2 after review. Do not merge the separate queue PR stack as part of this update.
4. Refresh the existing repository in Home Assistant and update the existing app in place, preserving all current options and app data. Keep package staging disabled.
5. Verify the displayed app version, app health, and unchanged worker identity. The existing diagnostic protocol and replay ledger must remain intact.
6. Stop if the update or verification fails. Do not uninstall or clear data. Do not attempt a full Home Assistant restore without separate approval.

## Rollback boundary

The app's state lives under Home Assistant's persistent app data directory. The proposed update retains the same data path, identity file, and diagnostic ledger; this is a code-level compatibility check, not a tested rollback.

A full Home Assistant restore replaces the current Home Assistant installation and apps and restarts Home Assistant. The available backup has not been integrity-tested or restored. Therefore rollback readiness is **NOT VERIFIED**. Do not describe the update as having a tested rollback.

## Package staging gate

The receiver remains disabled by default. `package_stage_enabled` must remain false during the Worker update. A first live `PACKAGE_STAGE` transfer requires its own explicit approval after the Worker and broker changes are independently reviewed and the end-to-end path is ready.


## M5.8 broker compatibility gate

**Worker update status: NO-GO until the broker is upgraded first.** The current M3.5 `STATUS_CHECK` validator accepts only Worker version `0.0.4-dev.m4.2.5`. This candidate reports `0.0.5-dev.m5.6`; an in-place Worker update before the broker validator changes would cause its signed status response to fail schema validation.

The backward-compatible M3.5 change accepting both exact versions is present in private Queue Draft PR #25, but is not merged or deployed. Safe order:
1. Separately review and obtain authorization to deploy the M3.5 dual-version validator, keeping `packageStageEnabled: false`.
2. Verify the current `0.0.4-dev.m4.2.5` Worker still passes `STATUS_CHECK`.
3. Obtain explicit authorization for this Worker update, then update the existing app in place.
4. Verify `STATUS_CHECK` succeeds for `0.0.5-dev.m5.6`.
5. Request separate authorization before the first live `PACKAGE_STAGE`.

The owner-provided Home Assistant screenshot indicates automatic updates are switched off. The app source itself is confirmed; this does not remove the broker compatibility dependency.
