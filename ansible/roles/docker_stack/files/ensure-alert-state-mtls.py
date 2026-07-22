#!/usr/bin/env python3
"""Create and verify the private Prometheus-to-Alloy mTLS identity."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile


FILES = {
    "ca_key": ("state", "alert_state_ca.key", 0, 0, 0o600),
    "ca_cert": ("secrets", "alert_state_ca.pem", 0, 0, 0o644),
    "server_key": ("secrets", "alert_state_alloy.key", 0, 473, 0o440),
    "server_cert": ("secrets", "alert_state_alloy.crt", 0, 0, 0o644),
    "client_key": ("secrets", "alert_state_prometheus.key", 0, 65532, 0o440),
    "client_cert": ("secrets", "alert_state_prometheus.crt", 0, 0, 0o644),
}
ROOT_UID = 0
ROOT_GID = 0


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def command(*arguments: str, capture: bool = False) -> str:
    result = subprocess.run(
        arguments,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or "command failed"
        fail(f"OpenSSL rejected alert-state mTLS material: {detail}")
    return result.stdout if capture else ""


def require_directory(path: Path, mode: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        fail(f"cannot inspect {path}: {exc}")
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != ROOT_UID
        or metadata.st_gid != ROOT_GID
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        fail(f"unsafe alert-state mTLS directory: {path}")


def material_paths(secrets_dir: Path, state_dir: Path) -> dict[str, Path]:
    return {
        name: (state_dir if location == "state" else secrets_dir) / filename
        for name, (location, filename, _uid, _gid, _mode) in FILES.items()
    }


def validate_file(name: str, path: Path) -> None:
    _location, _filename, uid, gid, mode = FILES[name]
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_nlink != 1
    ):
        fail(f"unsafe alert-state mTLS file: {path}")


def public_key_digest(*arguments: str) -> str:
    return hashlib.sha256(command(*arguments, capture=True).encode()).hexdigest()


def extension_values(certificate_text: str, extension_name: str) -> set[str]:
    """Return the single-line values for one X.509 extension."""

    marker = f"X509v3 {extension_name}:"
    lines = certificate_text.splitlines()
    matches = [index for index, line in enumerate(lines) if line.strip() == marker]
    if len(matches) != 1 or matches[0] + 1 >= len(lines):
        fail(f"alert-state certificate has malformed {extension_name}")
    values = {
        value.strip()
        for value in lines[matches[0] + 1].strip().split(",")
        if value.strip()
    }
    if not values:
        fail(f"alert-state certificate has malformed {extension_name}")
    return values


def validate(paths: dict[str, Path]) -> None:
    for name, path in paths.items():
        validate_file(name, path)

    ca_text = command(
        "openssl", "x509", "-in", str(paths["ca_cert"]), "-noout", "-text",
        capture=True,
    )
    if "CA:TRUE" not in ca_text or "Certificate Sign" not in ca_text:
        fail("alert-state root certificate is not a signing CA")
    for name in ("ca_cert", "server_cert", "client_cert"):
        command(
            "openssl", "x509", "-in", str(paths[name]), "-noout", "-checkend", "2592000"
        )
    command(
        "openssl", "verify", "-CAfile", str(paths["ca_cert"]),
        "-purpose", "sslserver", str(paths["server_cert"]),
    )
    server_text = command(
        "openssl", "x509", "-in", str(paths["server_cert"]), "-noout", "-text",
        capture=True,
    )
    if extension_values(server_text, "Subject Alternative Name") != {
        "DNS:alloy-alert-state"
    }:
        fail("alert-state server certificate SAN is not exactly alloy-alert-state")
    if extension_values(server_text, "Extended Key Usage") != {
        "TLS Web Server Authentication"
    }:
        fail("alert-state server certificate has unexpected extended key usage")
    command(
        "openssl", "verify", "-CAfile", str(paths["ca_cert"]),
        "-purpose", "sslclient", str(paths["client_cert"]),
    )
    client_text = command(
        "openssl", "x509", "-in", str(paths["client_cert"]), "-noout", "-text",
        capture=True,
    )
    if extension_values(client_text, "Extended Key Usage") != {
        "TLS Web Client Authentication"
    }:
        fail("alert-state client certificate has unexpected extended key usage")
    if "X509v3 Subject Alternative Name:" in client_text:
        fail("alert-state client certificate must not contain a SAN")
    for key_name, certificate_name in (
        ("ca_key", "ca_cert"),
        ("server_key", "server_cert"),
        ("client_key", "client_cert"),
    ):
        key_digest = public_key_digest(
            "openssl", "pkey", "-in", str(paths[key_name]), "-pubout"
        )
        certificate_digest = public_key_digest(
            "openssl", "x509", "-in", str(paths[certificate_name]), "-pubkey", "-noout"
        )
        if key_digest != certificate_digest:
            fail(f"{key_name} does not match {certificate_name}")


def write_extensions(path: Path, *, usage: str, san: str | None = None) -> None:
    lines = [
        "basicConstraints=critical,CA:FALSE",
        "keyUsage=critical,digitalSignature,keyEncipherment",
        f"extendedKeyUsage={usage}",
    ]
    if san is not None:
        lines.append(f"subjectAltName=DNS:{san}")
    path.write_text("\n".join(lines) + "\n", encoding="ascii")
    path.chmod(0o600)


def generate(paths: dict[str, Path], state_dir: Path) -> None:
    with tempfile.TemporaryDirectory(prefix=".alert-state-mtls-", dir=state_dir) as raw:
        work = Path(raw)
        generated = {name: work / path.name for name, path in paths.items()}
        command(
            "openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256", "-nodes",
            "-days", "3650", "-subj", "/CN=AI Gateway Alert State Root CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", str(generated["ca_key"]), "-out", str(generated["ca_cert"]),
        )
        for prefix, common_name, usage, san in (
            ("server", "alloy-alert-state", "serverAuth", "alloy-alert-state"),
            ("client", "prometheus-alert-state", "clientAuth", None),
        ):
            csr = work / f"{prefix}.csr"
            extensions = work / f"{prefix}.cnf"
            write_extensions(extensions, usage=usage, san=san)
            command(
                "openssl", "req", "-new", "-newkey", "rsa:2048", "-sha256", "-nodes",
                "-subj", f"/CN={common_name}", "-keyout", str(generated[f"{prefix}_key"]),
                "-out", str(csr),
            )
            command(
                "openssl", "x509", "-req", "-sha256", "-days", "825",
                "-in", str(csr), "-CA", str(generated["ca_cert"]),
                "-CAkey", str(generated["ca_key"]), "-CAcreateserial",
                "-extfile", str(extensions), "-out", str(generated[f"{prefix}_cert"]),
            )

        for name, destination in paths.items():
            _location, _filename, uid, gid, mode = FILES[name]
            temporary = destination.with_name(f".{destination.name}.new-{os.getpid()}")
            shutil.copyfile(generated[name], temporary)
            os.chown(temporary, uid, gid)
            os.chmod(temporary, mode)
            os.replace(temporary, destination)


def reconcile(secrets_dir: Path, state_dir: Path) -> bool:
    if not secrets_dir.is_absolute() or not state_dir.is_absolute():
        fail("alert-state mTLS directories must be absolute")
    require_directory(secrets_dir, 0o700)
    state_dir.mkdir(mode=0o700, parents=False, exist_ok=True)
    require_directory(state_dir, 0o700)
    paths = material_paths(secrets_dir, state_dir)
    existing: set[str] = set()
    for name, path in paths.items():
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            fail(f"cannot inspect alert-state mTLS material: {exc}")
        existing.add(name)
    if existing and existing != set(paths):
        fail("alert-state mTLS material is incomplete; restore the missing files")
    changed = not existing
    if changed:
        generate(paths, state_dir)
    validate(paths)
    return changed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--secrets-dir", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    arguments = parser.parse_args()
    changed = reconcile(arguments.secrets_dir, arguments.state_dir)
    print(f"AIGW_ALERT_STATE_MTLS_OK changed={'true' if changed else 'false'}")


if __name__ == "__main__":
    main()
