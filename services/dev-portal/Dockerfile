# syntax=docker/dockerfile:1.25.0@sha256:0adf442eae370b6087e08edc7c50b552d80ddf261576f4ebd6421006b2461f12
# dev-portal — self-service LiteLLM virtual-key issuance + tool-config snippets
# See docs/solution-map.md §1.4 for design context.

# DHI runtime images intentionally have no shell or package manager. Resolve
# Python wheels in the matching dev image, then copy only the virtualenv into
# the non-root runtime image.
FROM dhi.io/python:3.14.6-dev@sha256:9b72c38a520f44fafa1c4a3026e9b390eb3b4967c62d38be01400ecbb0232b65 AS python-builder
WORKDIR /build
COPY requirements.txt requirements.lock ./
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install \
        --no-cache-dir \
        --no-compile \
        --disable-pip-version-check \
        --only-binary=:all: \
        --require-hashes \
        -r requirements.lock

FROM dhi.io/python:3.14.6@sha256:c82da5a1a30a6214f45c42def5b6f5b85981c7dc7a1802015a6ebf264675436d

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
