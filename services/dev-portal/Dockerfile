# syntax=docker/dockerfile:1.7
# dev-portal — self-service LiteLLM virtual-key issuance + tool-config snippets
# See docs/solution-map.md §1.4 for design context.

# DHI runtime images intentionally have no shell or package manager. Resolve
# Python wheels in the matching dev image, then copy only the virtualenv into
# the non-root runtime image.
FROM dhi.io/python:3.12.13-dev@sha256:a7dc6d4025e3e94ab67f7331729a582c3eda127afa64d15c855ab82b44e8a7ea AS python-builder
WORKDIR /build
COPY requirements.txt requirements.lock ./
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install \
        --no-cache-dir \
        --no-compile \
        --disable-pip-version-check \
        --require-hashes \
        -r requirements.lock

FROM dhi.io/python:3.12.13@sha256:eb7705c04a8240fa06d1f3d6e8adb61f72e5f0b2b457411a2840297cb5f997f3

ENV PATH=/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONNOUSERSITE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY --from=python-builder /opt/venv /opt/venv
# Application code remains root-owned and read-only to DHI's uid/gid 65532.
COPY --chown=0:0 app ./app

USER 65532:65532

# Exec-form RUN is deliberate: the DHI runtime has no /bin/sh. This also
# proves the final non-root identity can traverse imported code/templates.
RUN ["/opt/venv/bin/python", "-c", "from pathlib import Path; assert Path('/app/app/main.py').is_file(); assert Path('/app/app/templates/index.html').is_file(); import app"]

EXPOSE 8080

# The owner+project creation lock is process-local. This deployed topology is
# deliberately one container/one worker; do not add workers or replicas without
# replacing it with a distributed/transactional lock.
# Uvicorn's default access log includes the full OIDC callback URI and would
# copy the one-time authorization code to Docker, Loki, and Cribl. Explicit
# structured application audit events and path-free Traefik metadata remain.
CMD ["/opt/venv/bin/python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--no-server-header", "--no-access-log"]
