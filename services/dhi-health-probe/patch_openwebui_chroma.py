#!/usr/bin/env python3
"""Lock Open WebUI to its local embedded Chroma database.

This exact, version-locked transform removes Open WebUI's optional remote
Chroma client. It fails closed when the pinned v0.10.2 source changes.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import sys


EXPECTED_SOURCE_SHA256 = (
    "ef9bb881574bb0113f26c358c579ae97413404543060ff7e7c3616eb9491d801"
)
EXPECTED_PATCHED_SHA256 = (
    "ccd1099aca07e2b4c04212cd96dc0b672b8b639ff0df4bf023fd00b35ea04be5"
)
MAX_SOURCE_BYTES = 256 * 1024

REMOTE_CONFIG_IMPORTS = """\
from open_webui.config import (
    CHROMA_CLIENT_AUTH_CREDENTIALS,
    CHROMA_CLIENT_AUTH_PROVIDER,
    CHROMA_DATA_PATH,
    CHROMA_DATABASE,
    CHROMA_HTTP_HEADERS,
    CHROMA_HTTP_HOST,
    CHROMA_HTTP_PORT,
    CHROMA_HTTP_SSL,
    CHROMA_TENANT,
)
""".encode("utf-8")

LOCAL_CONFIG_IMPORTS = """\
from open_webui.config import (
    CHROMA_DATA_PATH,
    CHROMA_DATABASE,
    CHROMA_TENANT,
)
""".encode("utf-8")

OPTIONAL_REMOTE_CLIENT = """\
        settings_dict = {
            'allow_reset': True,
            'anonymized_telemetry': False,
        }
        if CHROMA_CLIENT_AUTH_PROVIDER is not None:
            settings_dict['chroma_client_auth_provider'] = CHROMA_CLIENT_AUTH_PROVIDER
        if CHROMA_CLIENT_AUTH_CREDENTIALS is not None:
            settings_dict['chroma_client_auth_credentials'] = CHROMA_CLIENT_AUTH_CREDENTIALS

        if CHROMA_HTTP_HOST != '':
            self.client = chromadb.HttpClient(
                host=CHROMA_HTTP_HOST,
                port=CHROMA_HTTP_PORT,
                headers=CHROMA_HTTP_HEADERS,
                ssl=CHROMA_HTTP_SSL,
                tenant=CHROMA_TENANT,
                database=CHROMA_DATABASE,
                settings=Settings(**settings_dict),
            )
        else:
            self.client = chromadb.PersistentClient(
                path=CHROMA_DATA_PATH,
                settings=Settings(**settings_dict),
                tenant=CHROMA_TENANT,
                database=CHROMA_DATABASE,
            )
""".encode("utf-8")

LOCAL_CLIENT_ONLY = """\
        # AI Gateway never exposes or connects to a Chroma HTTP server. Keep
        # the vector database inside Open WebUI's protected data volume.
        settings = Settings(
            allow_reset=True,
            anonymized_telemetry=False,
        )
        self.client = chromadb.PersistentClient(
            path=CHROMA_DATA_PATH,
            settings=settings,
            tenant=CHROMA_TENANT,
            database=CHROMA_DATABASE,
        )
""".encode("utf-8")


def transform(source: bytes) -> bytes:
    if len(source) > MAX_SOURCE_BYTES:
        raise ValueError("Open WebUI Chroma source exceeds the reviewed bound")
    if hashlib.sha256(source).hexdigest() != EXPECTED_SOURCE_SHA256:
        raise ValueError("Open WebUI Chroma source digest drifted")
    if source.count(REMOTE_CONFIG_IMPORTS) != 1:
        raise ValueError("Open WebUI Chroma imports drifted")
    if source.count(OPTIONAL_REMOTE_CLIENT) != 1:
        raise ValueError("Open WebUI Chroma client setup drifted")

    patched = source.replace(REMOTE_CONFIG_IMPORTS, LOCAL_CONFIG_IMPORTS, 1)
    patched = patched.replace(OPTIONAL_REMOTE_CLIENT, LOCAL_CLIENT_ONLY, 1)
    for forbidden in (
        b"chromadb.HttpClient",
        b"CHROMA_HTTP_",
        b"CHROMA_CLIENT_AUTH_",
        b"chroma_client_auth_",
    ):
        if forbidden in patched:
            raise ValueError("remote Chroma configuration remains after patching")
    if patched.count(b"chromadb.PersistentClient(") != 1:
        raise ValueError("local Chroma client is not fixed exactly once")
    if patched.count(b"metadata={'hnsw:space': 'cosine'}") != 2:
        raise ValueError("fixed Chroma collection policy drifted")
    if hashlib.sha256(patched).hexdigest() != EXPECTED_PATCHED_SHA256:
        raise ValueError("patched Open WebUI Chroma source digest drifted")
    compile(patched, "chroma.py", "exec")
    return patched


def patch_file(path: Path) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != 0
    ):
        raise ValueError("Open WebUI Chroma source has an unsafe file boundary")
    with path.open("rb") as source_file:
        source = source_file.read(MAX_SOURCE_BYTES + 1)
    patched = transform(source)
    with path.open("wb") as destination:
        destination.write(patched)
        destination.flush()
        os.fsync(destination.fileno())


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    try:
        patch_file(Path(sys.argv[1]))
    except Exception as exc:  # build-only diagnostic; source contains no secrets
        print(f"Open WebUI Chroma hardening failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
