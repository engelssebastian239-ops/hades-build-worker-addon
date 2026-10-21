# Temporary diagnostic image only: validates root bootstrap plus UID 1000 access
# to a dedicated child directory in the Supervisor-managed /data mount.
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402

RUN apk add --no-cache su-exec \
    && test "$(id -u node)" = "1000" \
    && test "$(id -g node)" = "1000"

COPY diagnostics/probe.sh /usr/local/bin/m35-data-permission-probe
RUN chmod 0555 /usr/local/bin/m35-data-permission-probe

# The probe intentionally starts as root to mirror a minimal bootstrap that
# creates only the app-owned subdirectory and then checks access as node.
USER root
ENTRYPOINT ["/usr/local/bin/m35-data-permission-probe"]
