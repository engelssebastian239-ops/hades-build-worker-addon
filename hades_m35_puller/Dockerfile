# OCI index verified 2026-10-21; includes linux/arm64/v8 and linux/amd64.
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402

WORKDIR /opt/hades-m35-puller
COPY m35-source/src/ ./src/
COPY m35-source/tools/ ./tools/
COPY config.json ./config.json
COPY run.sh /usr/local/bin/run-hades-m35-puller

RUN test "$(id -u node)" = "1000" \
    && chmod 0555 /usr/local/bin/run-hades-m35-puller

USER node:node
ENTRYPOINT ["/usr/local/bin/run-hades-m35-puller"]
