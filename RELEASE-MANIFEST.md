# Release manifest

- Release: H.A.D.E.S. Build Worker `0.0.4-dev.m4.2.5`
- Purpose: disabled-by-default, signed, read-only diagnostic receiver.
- Supported architecture: `aarch64`
- Home Assistant app repository metadata: `repository.yaml`
- Base image: Home Assistant base image pinned by digest in `hades_build_worker/Dockerfile`.
- Public scope: app source, non-secret metadata, tests, installation and security documentation.
- Private keys, tokens, runtime ledgers, local network addresses, and private-repository data are excluded.
- Docker/HA image build: **not run**; no authorized Docker/Podman/Buildah build tool is available in the developer bridge.
- Test results: `npm test` passed 7/7; `npm run syntax` passed.
- The existing local `0.0.3-dev` installation was not changed.
- `SHA256SUMS` lists SHA-256 digests for the release files (excluding itself and this manifest).

This manifest does not claim a Home Assistant Supervisor installation or a live broker/worker round trip.