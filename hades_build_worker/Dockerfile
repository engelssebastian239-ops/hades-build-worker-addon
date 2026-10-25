# H.A.D.E.S. M4.2.5 local app candidate. Supervisor builds this on the FinestraMiner.
FROM ghcr.io/home-assistant/base@sha256:8fde4170393bdf7a121ea4d6e34b417e1d0b90125948459f9f9f70cdf5d77c16
ARG BUILD_VERSION=0.0.6-dev.m5.13
ARG BUILD_ARCH=aarch64
LABEL io.hass.version="${BUILD_VERSION}" \
      io.hass.type="app" \
      io.hass.arch="${BUILD_ARCH}"
RUN apk add --no-cache nodejs
WORKDIR /opt/hades-m42.5
COPY shared/protocol.mjs ./shared/protocol.mjs
COPY worker/main.mjs ./worker/main.mjs
COPY worker/package-stage.mjs ./worker/package-stage.mjs
COPY worker/github-pull.mjs ./worker/github-pull.mjs
COPY worker/mobile-install-plan.mjs ./worker/mobile-install-plan.mjs
COPY worker/mobile-install-queue.mjs ./worker/mobile-install-queue.mjs
COPY worker/mobile-install-receipt.mjs ./worker/mobile-install-receipt.mjs
COPY worker/mobile-install-client.mjs ./worker/mobile-install-client.mjs
COPY worker/mobile-install-store.mjs ./worker/mobile-install-store.mjs
COPY worker/mobile-install-controller.mjs ./worker/mobile-install-controller.mjs
COPY worker/mobile-install-github.mjs ./worker/mobile-install-github.mjs
COPY worker/mobile-install-runtime.mjs ./worker/mobile-install-runtime.mjs
COPY worker/launcher.mjs ./worker/launcher.mjs
USER root:root
ENTRYPOINT ["/usr/bin/node", "/opt/hades-m42.5/worker/launcher.mjs"]
