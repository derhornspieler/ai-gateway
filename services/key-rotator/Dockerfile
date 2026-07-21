# syntax=docker/dockerfile:1.25.0@sha256:0adf442eae370b6087e08edc7c50b552d80ddf261576f4ebd6421006b2461f12
# key-rotator — see README.md and docs/solution-map.md §1.7 for design.
#
# Runs only on segmented application/data networks (docs/solution-map.md §3),
# none of which provide direct internet egress. All vendor HTTP calls use
# envoy-egress via the
# EGRESS_BASE env var — this image itself has no special network config,
# that boundary is enforced by Docker network placement + firewalld/
# DOCKER-USER rules at the compose/ansible layer, not here.

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

WORKDIR /app
COPY --from=python-builder /opt/venv /opt/venv

# Application code stays root-owned and read-only to the runtime identity.
# Giving the service user ownership allowed an RCE to rewrite imported source
# and persist until the container was replaced when this image is run without
# Compose's read_only mount.
COPY --chown=0:0 app ./app

ENV PATH=/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONNOUSERSITE=1 \
    PYTHONUNBUFFERED=1

USER 65532:65532

# Build-time regression: every nested package must be importable by the final
# non-root runtime identity, not merely present in a root-owned image layer.
RUN ["/opt/venv/bin/python", "-c", "from pathlib import Path; assert Path('/app/app/drivers/anthropic_wif.py').is_file(); import app.drivers.anthropic_wif"]

EXPOSE 8080

CMD ["/opt/venv/bin/python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
