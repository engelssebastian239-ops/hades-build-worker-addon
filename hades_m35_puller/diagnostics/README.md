# One-time `/data` root-bootstrap probe

This is a temporary diagnostic image for the permission test. Keep the existing manifest, app slug, repository URL, and all production files unchanged while this branch is selected for the diagnostic build.

The previous probe ran directly as UID 1000 and confirmed that the Supervisor mount is `root:root` mode `755`; UID 1000 therefore cannot create a directory at the top level of `/data`. This updated probe tests a narrow root bootstrap: root creates one unique temporary child directory, assigns only that directory to UID/GID 1000 with mode `0700`, and then checks that UID 1000 can write a mode-`0600` file inside it.

## Run

1. In Home Assistant, refresh the temporary repository and update the existing temporary probe app.
2. Manually start it once. Do not start the production Puller.
3. Read the add-on log. Expected markers are `bootstrap_uid=0 bootstrap_gid=0`, `protected_directory_owner=1000:1000 mode=700`, `probe_write_confirmed=yes`, and `probe_file_removed=yes`. A nonzero exit or missing marker is a failed probe.
4. Stop/remove the temporary probe app when the result is captured. The production Puller has not been changed by this branch.

The probe writes only a constant, non-secret value to a uniquely named temporary directory and has no network access or sockets. An EXIT handler attempts to remove the directory twice and confirms that it is gone; cleanup failure is reported as `PROBE_CLEANUP_FAILED`.

The image uses the pinned Node 22 Alpine base plus `su-exec`, starts as root solely for this probe, and includes no Puller source, config, tools, key, or token. It does not change permissions on `/data` itself.
