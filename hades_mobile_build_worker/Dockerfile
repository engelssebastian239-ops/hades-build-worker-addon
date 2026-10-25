FROM ghcr.io/home-assistant/base@sha256:8fde4170393bdf7a121ea4d6e34b417e1d0b90125948459f9f9f70cdf5d77c16
ARG BUILD_ARCH=aarch64
LABEL io.hass.type="app" io.hass.arch="${BUILD_ARCH}"
RUN apk add --no-cache nodejs
WORKDIR /opt/hades-mobile-plan-worker
COPY shared/identity.mjs ./shared/identity.mjs
COPY worker/launcher.mjs ./worker/launcher.mjs
COPY worker/main.mjs ./worker/main.mjs
COPY worker/mobile-install-plan.mjs ./worker/mobile-install-plan.mjs
COPY worker/mobile-install-queue.mjs ./worker/mobile-install-queue.mjs
COPY worker/mobile-install-github.mjs ./worker/mobile-install-github.mjs
COPY worker/mobile-install-store.mjs ./worker/mobile-install-store.mjs
COPY worker/mobile-install-receipt.mjs ./worker/mobile-install-receipt.mjs
COPY worker/mobile-install-client.mjs ./worker/mobile-install-client.mjs
COPY worker/mobile-install-controller.mjs ./worker/mobile-install-controller.mjs
COPY worker/mobile-install-runtime.mjs ./worker/mobile-install-runtime.mjs
COPY worker/mobile-credential-provisioner.mjs ./worker/mobile-credential-provisioner.mjs
USER root:root
ENTRYPOINT ["/usr/bin/node", "/opt/hades-mobile-plan-worker/worker/launcher.mjs"]
