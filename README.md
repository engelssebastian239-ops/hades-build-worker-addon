# H.A.D.E.S. Build Worker

Home Assistant app repository for the existing signed, read-only diagnostic receiver.

## Update target

Release `0.0.4-dev.m4.2.9` updates the existing app with slug `hades_build_worker`. Update the installed app from this same repository entry. Do not install a second app instance. Keep the existing app data and Supervisor options.

## Safety properties

- `STATUS_CHECK`, `HEARTBEAT_CHECK`, and `QUEUE_HEALTH_CHECK` only.
- Arbitrary code execution remains disabled.
- No host mounts, Supervisor or Docker API access, privileged mode, or published ports.
- Auto boot starts the app process; the stored `enabled` option must still be `true` for the diagnostic listener to become ready.
- The repository default remains `enabled: false` for new installations. Existing configured options must be verified before and after an update.

## Verification

Node.js 20 or later; no npm packages are required.

```sh
npm test
npm run syntax
```

See [the update, backup, and rollback procedure](docs/INSTALL.md) and [SECURITY.md](SECURITY.md).
