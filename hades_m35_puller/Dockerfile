# One-time diagnostic image; this branch must never run the Puller.
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402

COPY diagnostics/probe.sh /usr/local/bin/m35-data-permission-probe

RUN test "$(id -u node)" = "1000" \
    && test "$(id -g node)" = "1000" \
    && chmod 0555 /usr/local/bin/m35-data-permission-probe

USER node:node
ENTRYPOINT ["/usr/local/bin/m35-data-permission-probe"]
