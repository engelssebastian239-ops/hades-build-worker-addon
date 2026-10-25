FROM ghcr.io/home-assistant/base@sha256:8fde4170393bdf7a121ea4d6e34b417e1d0b90125948459f9f9f70cdf5d77c16
RUN apk add --no-cache nodejs
WORKDIR /opt/hades-m575
COPY installer.mjs ./installer.mjs
COPY main.mjs ./main.mjs
COPY apparmor.txt ./apparmor.txt
USER root:root
ENTRYPOINT ["/usr/bin/node", "/opt/hades-m575/main.mjs"]
