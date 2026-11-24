# syntax=docker/dockerfile:1
# Thin hardening layer over the official image, pinned by digest.
#  - apk upgrade: picks up fixed Alpine packages (libxml2 CVE-2026-86144 at release time).
#  - gosu removed: it only runs when the entrypoint starts as root. This deployment
#    always starts PostgreSQL as uid 70 (compose `user: "70:70"`), so gosu was dead
#    weight carrying 26 HIGH/CRITICAL Go stdlib CVEs (Trivy, 2026-11-24).
FROM postgres:17-alpine@sha256:f9cf3e1f0066f0eb0c48707d864f0ac5941e9ff454a072077d97a4d278d07d73
ARG APK_UPGRADE=1
# Optional build secret "pip_ca": CA bundle for builds behind a TLS-inspecting proxy.
RUN --mount=type=secret,id=pip_ca,required=false \
    if [ -f /run/secrets/pip_ca ]; then export SSL_CERT_FILE=/run/secrets/pip_ca; fi \
 && if [ "$APK_UPGRADE" = "1" ]; then apk upgrade --no-cache; fi \
 && rm -f /usr/local/bin/gosu
HEALTHCHECK --interval=10s --timeout=5s --retries=10 CMD ["pg_isready", "-U", "siem_bootstrap", "-d", "siem"]
USER 70:70
