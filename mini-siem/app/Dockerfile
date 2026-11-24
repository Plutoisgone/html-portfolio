# syntax=docker/dockerfile:1
# Base pinned by digest (Debian 13 "trixie"; bookworm carried 103 HIGH/CRITICAL OS CVEs
# incl. 2 CRITICAL, trixie 53 HIGH / 0 CRITICAL, none fixable at release time).
# Refresh: docker pull python:3.12-slim-trixie && docker inspect --format "{{index .RepoDigests 0}}" ...
FROM python:3.12-slim-trixie@sha256:37fc60d303cb9294d3718b5b48998a0210bb1c73611c1399ef5eb7964c0536e5 AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.txt .
# --require-hashes: every package must match the hash pinned in requirements.txt.
# Optional build secret "pip_ca": CA bundle for builds behind a TLS-inspecting proxy.
RUN --mount=type=secret,id=pip_ca,required=false \
    if [ -f /run/secrets/pip_ca ]; then export PIP_CERT=/run/secrets/pip_ca; fi \
 && python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes --no-deps -r requirements.txt

FROM python:3.12-slim-trixie@sha256:37fc60d303cb9294d3718b5b48998a0210bb1c73611c1399ef5eb7964c0536e5
ARG APT_UPGRADE=1
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN if [ "$APT_UPGRADE" = "1" ]; then apt-get update && apt-get -y upgrade && rm -rf /var/lib/apt/lists/*; fi \
 && groupadd --system --gid 10001 siem \
 && useradd --system --uid 10001 --gid siem --home /nonexistent --shell /usr/sbin/nologin siem
COPY --from=build /opt/venv /opt/venv
WORKDIR /srv
COPY --chown=root:root siem ./siem
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status==200 else 1)"
CMD ["uvicorn", "--factory", "siem.main:create_app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--no-server-header", "--no-date-header", "--no-access-log", "--workers", "1", "--limit-concurrency", "64", "--timeout-keep-alive", "5"]
