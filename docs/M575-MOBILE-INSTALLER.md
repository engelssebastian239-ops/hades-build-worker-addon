# M575 scoped Mobile installer candidate

M575 is a source-only candidate for one narrowly scoped change to the Home Assistant Mobile app. It targets `local_hades_m2_mobile`, whose local-app source is `/addons/hades_m2_mobile`. The only allowed installed-file change is the M574 `Dockerfile` asset-copy correction: add the existing `wled-control.mjs` dependency to the image so the shipped browser module graph can load. It does not change Mobile backend code or data, and it does not install HERMES.

The candidate is pinned to `engelssebastian239-ops/hades-hermes-queue` commit `addf609d98256e989e1fc7b2f833d80f95628ae7`, package path `hades-m2-local-app/hades_m2_mobile`. The expected old and candidate Dockerfile SHA-256 values are `acba06f11b28daeea6d0f35ce924b7813cca1084d243f84324acda7295c8080b` and `5c58e91ffa3465e984969a7438aec8e15607a07d3edb293dda7e016aacfed448`. All other Mobile source files must match exactly. These values describe a code gate; they are not an instruction to install or a claim that an installation has been verified.

The add-on is manual-start and `enabled` defaults to `false`. Its request and response protocol requires a separately trusted Ed25519 broker key, but this candidate has no protected Plus signing or package-delivery broker. ChatGPT Plus therefore cannot create an install request through this code today. The packaged source and test candidate are not installed on the Home Assistant system, and no end-to-end connection or installation is claimed.

## Privilege and filesystem boundary

The user explicitly authorized a separate app with the Home Assistant Supervisor `manager` role for this installer. That role injects a broad Supervisor API credential; it is not limited by the add-on's AppArmor filesystem profile. A defect or compromise in the installer could therefore affect Supervisor-managed apps and backups. The code currently calls only fixed preflight, backup, job-status, and `local_hades_m2_mobile` rebuild routes, but this fixed-route behavior is an application constraint, not a reduced Supervisor token.

The `local_apps` read-write map exposes `/addons`, which contains other local-app sources. This is also a broad underlying mount. The custom AppArmor profile is intended to allow reads from the Mobile source while restricting writes to the Mobile `Dockerfile` and named temporary Dockerfiles. It disallows writes to Mobile configuration and other app paths. Startup checks the exact expected enforced profile name, the bundled profile's pinned SHA-256, and positive/negative filesystem probes. If those checks fail, installation is blocked. The profile has not been validated against the live Home Assistant kernel and Supervisor installation, so these checks remain a required deployment gate; source inspection and unit tests do not prove live enforcement.

The repository-derived profile identity is `c406e920_hades_mobile_installer`, for the canonical repository URL `https://github.com/engelssebastian239-ops/hades-build-worker-addon`. A branch-qualified repository URL produces a different identity. A branch name is not a commit pin, so do not install this candidate from a `#branch` URL and treat it as a pinned build.

## Backup and recovery behavior

Before promotion the code requests an encrypted Supervisor partial backup for the fixed Mobile app. The background request returns a job ID; the installer persists it immediately, waits for the job and its child jobs to finish successfully, then obtains the backup slug from the completed job reference and checks the backup's protected status and contents before promotion. Supervisor partial backups also include Supervisor configuration and repository metadata; this is broader than a Mobile-only backup. The installer never calls Supervisor's partial-restore endpoint because restoring that backup could change those unrelated settings.

The installer also stores an encrypted exact source snapshot and its encryption key in protected add-on data files with mode `0600`. On a confirmed build failure it can restore the previous Dockerfile and rebuild the unchanged Mobile source. This is a source-only rollback, not a data restore or a guarantee that every Supervisor-level failure is recoverable. Mobile data/schema migration is outside this candidate's allowed delta.

A timeout, lost Supervisor response, or restart during an in-flight operation is recorded as `UNKNOWN`. The code does not blindly retry a rebuild or start a rollback while the outcome may still be running. A separately signed reconciliation decision is required after job status has been checked. No protected broker currently exists to produce those signed requests, so operators must not treat reconciliation as an available recovery interface today.

## Packaging and current blockers

`tools/package-mobile-m574.mjs` accepts only the exact commit and checks the pinned regression-test hash, source file types, link count, file count, Dockerfile hash, and required `server-first/mobile-pwa/studio-night.png` asset. That 2.1 MB PNG is absent from the local source snapshot. The packager must stop in this workspace; do not replace the image with a dummy or claim that a package was produced. The helper creates a local package only; it does not sign requests, upload artifacts, install the add-on, or deploy it.

The candidate still needs review and a controlled source publication, a complete exact source checkout including the real PNG, a protected server-side signing/package route, compatible provisioning of the installer and broker key, and live verification of the Supervisor version, manager token behavior, profile enforcement, backup behavior, and Mobile rebuild. Until those are complete, this is implementation source only—not a usable installation path.
