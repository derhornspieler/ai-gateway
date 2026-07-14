#!/usr/bin/env python3
"""Validate and atomically install the AI Gateway edge TLS material.

HTTPS terminates at the two Traefik edges (traefik-int, traefik-adm) and
nowhere else: container-to-container application traffic stays plain HTTP on
segmented internal-only bridges. This tool owns the only certificate store
those two edges read (`certs/int.crt`, `certs/int.key`, `certs/ca.pem`), so it
is the single place where edge key material is proven before it goes live.

Every check runs BEFORE any byte of the live store is touched. A failure leaves
the previous certificates exactly as they were.

The tool shells out only to an absolute OpenSSL 3 binary (Rocky 9 ships one at
/usr/bin/openssl). It never writes private-key bytes to stdout, stderr, or any
argv: the key reaches OpenSSL by file path and reaches its destination by an
O_EXCL temp file plus os.replace.
"""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

# Absolute by construction: a PATH-resolved openssl would let anything that can
# write a directory on PATH decide what "valid certificate" means. The tests
# override this explicitly because macOS ships LibreSSL at this path.
DEFAULT_OPENSSL = "/usr/bin/openssl"

BEGIN_CERT = "-----BEGIN CERTIFICATE-----"
END_CERT = "-----END CERTIFICATE-----"

# Pinned refusal. The mode-2 ceremony signs a CSR; the customer's root/issuing
# private key must never be requested, transported, or stored by this platform.
PRIVATE_KEY_IN_CERT_FATAL = (
    "FATAL: certificate input contains private key material; the customer CA "
    "signing key must never be supplied"
)

CHAIN_NEEDS_ROOT_HINT = (
    "the chain file must contain the COMPLETE chain including the self-signed "
    "root CA certificate; a leaf+intermediate bundle is not sufficient"
)


class CheckFailure(Exception):
    """A named validation check refused the supplied material."""

    def __init__(self, check: str, detail: str) -> None:
        super().__init__(f"{check}: {detail}")
        self.check = check
        self.detail = detail


def fail(check: str, detail: str) -> None:
    raise CheckFailure(check, detail)


class OpenSSL:
    def __init__(self, binary: str) -> None:
        self.binary = binary

    def run(
        self,
        *arguments: str,
        stdin: str | None = None,
        check_name: str = "openssl",
    ) -> str:
        """Run openssl with an argv list. Never a shell, never a secret in argv."""
        completed = subprocess.run(  # noqa: S603 - argv list, absolute binary
            [self.binary, *arguments],
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            fail(check_name, (completed.stderr or "").strip() or "openssl refused the input")
        return completed.stdout

    def try_run(self, *arguments: str, stdin: str | None = None) -> tuple[int, str, str]:
        completed = subprocess.run(  # noqa: S603 - argv list, absolute binary
            [self.binary, *arguments],
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return completed.returncode, completed.stdout, completed.stderr


# ── input boundaries ────────────────────────────────────────────────────────


def require_safe_file(
    path: Path,
    label: str,
    *,
    expect_owner: tuple[int, int] | None = None,
    expect_mode: int | None = None,
) -> None:
    """Reject anything that is not a private, regular, single-link real file.

    lstat (never stat): a symlink here would let a non-root writer of the link's
    directory redirect what we validate and what we install.
    """
    if not path.is_absolute():
        fail("input-shape", f"{label} must be an absolute path: {path}")
    try:
        info = path.lstat()
    except OSError as error:
        fail("input-shape", f"{label} is not readable: {path} ({error.strerror})")
    if stat.S_ISLNK(info.st_mode):
        fail("input-shape", f"{label} is a symlink; supply the real file: {path}")
    if not stat.S_ISREG(info.st_mode):
        fail("input-shape", f"{label} is not a regular file: {path}")
    if info.st_nlink != 1:
        fail("input-shape", f"{label} has {info.st_nlink} hard links; expected exactly 1: {path}")
    if expect_owner is not None:
        want_uid, want_gid = expect_owner
        if (info.st_uid, info.st_gid) != (want_uid, want_gid):
            fail(
                "input-shape",
                f"{label} is owned {info.st_uid}:{info.st_gid}; expected "
                f"{want_uid}:{want_gid}: {path}",
            )
    if expect_mode is not None:
        actual = stat.S_IMODE(info.st_mode)
        if actual != expect_mode:
            fail(
                "input-shape",
                f"{label} has mode {actual:04o}; expected {expect_mode:04o}: {path}",
            )


def read_certificate_file(path: Path, label: str) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if "PRIVATE KEY" in text:
        print(PRIVATE_KEY_IN_CERT_FATAL, file=sys.stderr)
        print(f"  offending input: {label} ({path})", file=sys.stderr)
        raise SystemExit(1)
    certificates = split_pem_certificates(text)
    if not certificates:
        fail("pem-shape", f"{label} contains no PEM certificate: {path}")
    return certificates


def split_pem_certificates(text: str) -> list[str]:
    certificates: list[str] = []
    remainder = text
    while BEGIN_CERT in remainder:
        start = remainder.index(BEGIN_CERT)
        try:
            end = remainder.index(END_CERT, start) + len(END_CERT)
        except ValueError:
            fail("pem-shape", "a PEM certificate block is not terminated")
        certificates.append(remainder[start:end] + "\n")
        remainder = remainder[end:]
    return certificates


# ── certificate introspection ───────────────────────────────────────────────


def certificate_text(openssl: OpenSSL, pem: str, label: str) -> str:
    return openssl.run("x509", "-noout", "-text", stdin=pem, check_name=f"pem-shape:{label}")


def extension_section(text: str, heading: str) -> str:
    """Return the indented body under an X509v3 extension heading."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith(heading):
            body = [line.strip()[len(heading) :].strip()]
            base = len(line) - len(line.lstrip())
            for following in lines[index + 1 :]:
                if not following.strip():
                    continue
                indent = len(following) - len(following.lstrip())
                if indent <= base:
                    break
                body.append(following.strip())
            return " ".join(part for part in body if part)
    return ""


def subject_and_issuer(openssl: OpenSSL, pem: str) -> tuple[str, str]:
    out = openssl.run("x509", "-noout", "-subject", "-issuer", stdin=pem, check_name="pem-shape")
    subject = issuer = ""
    for line in out.splitlines():
        if line.startswith("subject="):
            subject = line[len("subject=") :].strip()
        elif line.startswith("issuer="):
            issuer = line[len("issuer=") :].strip()
    return subject, issuer


def is_self_signed(openssl: OpenSSL, pem: str) -> bool:
    subject, issuer = subject_and_issuer(openssl, pem)
    return bool(subject) and subject == issuer


def is_ca(text: str) -> bool:
    return "CA:TRUE" in extension_section(text, "X509v3 Basic Constraints:").upper()


# ── the checks ──────────────────────────────────────────────────────────────


def check_key_matches_leaf(openssl: OpenSSL, key_path: Path, leaf_pem: str) -> str:
    """Compare public keys; return the PUBLIC half for the strength check.

    The private key travels to openssl by file path and never crosses a stream
    this process reads, so it cannot leak into stdout, stderr, or a log.
    """
    from_key = openssl.run("pkey", "-in", str(key_path), "-pubout", check_name="key-match")
    from_leaf = openssl.run("x509", "-noout", "-pubkey", stdin=leaf_pem, check_name="key-match")
    if from_key.strip() != from_leaf.strip():
        fail(
            "key-match",
            "the private key does not match the leaf certificate's public key",
        )
    return from_key


def check_key_strength(openssl: OpenSSL, public_key_pem: str) -> None:
    """Inspect the PUBLIC half only: `pkey -in <key> -text` would print the private key."""
    text = openssl.run(
        "pkey", "-pubin", "-noout", "-text", stdin=public_key_pem, check_name="key-strength"
    )
    if "Public-Key:" in text:
        raw = text.split("Public-Key:", 1)[1].split(")", 1)[0]
        digits = "".join(character for character in raw if character.isdigit())
        bits = int(digits) if digits else 0
    else:
        bits = 0
    lowered = text.lower()
    if "rsa" in lowered:
        if bits < 2048:
            fail("key-strength", f"RSA key is {bits} bits; 2048 is the minimum")
        return
    if "nist curve: p-256" in lowered or "nist curve: p-384" in lowered:
        return
    if bits >= 2048:
        return
    fail("key-strength", "key must be RSA >= 2048 bits or EC P-256/P-384")


def check_san(text: str, domain: str) -> None:
    section = extension_section(text, "X509v3 Subject Alternative Name:")
    entries = {entry.strip() for entry in section.split(",") if entry.strip()}
    required = {f"DNS:*.{domain}", f"DNS:{domain}"}
    missing = sorted(required - entries)
    if missing:
        fail(
            "san",
            f"leaf Subject Alternative Name is missing {', '.join(missing)}; "
            f"the edge certificate must carry both the wildcard and the apex "
            f"for {domain} (found: {section or 'no SAN extension'})",
        )


def check_eku(text: str) -> None:
    section = extension_section(text, "X509v3 Extended Key Usage:")
    if "TLS Web Server Authentication" not in section:
        fail(
            "eku",
            "leaf Extended Key Usage does not include TLS Web Server Authentication "
            f"(found: {section or 'no EKU extension'})",
        )


def check_leaf_is_not_a_ca(text: str) -> None:
    if is_ca(text):
        fail("leaf-basic-constraints", "leaf certificate asserts CA:TRUE; it must be an end-entity")


def check_chain_shape(openssl: OpenSSL, leaf_pem: str, chain_pems: list[str]) -> list[str]:
    """Every chain member is a CA, the leaf is not smuggled in, and a root is present."""
    roots: list[str] = []
    for index, pem in enumerate(chain_pems):
        text = certificate_text(openssl, pem, f"chain[{index}]")
        if not is_ca(text):
            subject, _ = subject_and_issuer(openssl, pem)
            fail("ca-constraints", f"chain certificate is not a CA (CA:TRUE absent): {subject}")
        if pem.strip() == leaf_pem.strip():
            fail("ca-constraints", "the leaf certificate also appears in the chain/CA bundle")
        if is_self_signed(openssl, pem):
            roots.append(pem)
    if not roots:
        fail("ca-constraints", f"no self-signed root CA is present in the chain; {CHAIN_NEEDS_ROOT_HINT}")
    return roots


def check_not_self_signed(openssl: OpenSSL, leaf_pem: str) -> None:
    if is_self_signed(openssl, leaf_pem):
        subject, _ = subject_and_issuer(openssl, leaf_pem)
        fail(
            "not-self-signed",
            "the edge certificate is self-signed. This is the bootstrap placeholder, "
            f"not real edge material ({subject}). Install a CA-issued certificate "
            "before serving this deployment.",
        )


def check_validity(openssl: OpenSSL, pems: list[str], min_days: int) -> None:
    """Every cert in the path -- leaf, intermediates, root -- must outlive the window.

    An expiring root is just as fatal as an expiring leaf, and it is the one
    operators forget.
    """
    seconds = min_days * 86400
    for pem in pems:
        subject, _ = subject_and_issuer(openssl, pem)
        code, _, _ = openssl.try_run("x509", "-noout", "-checkend", str(seconds), stdin=pem)
        if code != 0:
            enddate = openssl.run("x509", "-noout", "-enddate", stdin=pem, check_name="validity")
            fail(
                "validity",
                f"certificate expires within the {min_days}-day safety window "
                f"({enddate.strip()}): {subject}",
            )


def check_chain_verifies(
    openssl: OpenSSL, leaf_pem: str, chain_pems: list[str], roots: list[str], domain: str
) -> None:
    """Anchor only on self-signed roots; intermediates are untrusted inputs.

    Putting the intermediate in -CAfile would make it a trust anchor and the
    verification would no longer prove the chain reaches the customer's root.
    """
    intermediates = [pem for pem in chain_pems if pem not in roots]
    with tempfile.TemporaryDirectory(prefix="edge-tls-verify-") as workspace:
        work = Path(workspace)
        leaf_file = work / "leaf.pem"
        roots_file = work / "roots.pem"
        untrusted_file = work / "untrusted.pem"
        leaf_file.write_text(leaf_pem, encoding="utf-8")
        roots_file.write_text("".join(roots), encoding="utf-8")
        untrusted_file.write_text("".join(intermediates), encoding="utf-8")
        arguments = [
            "verify",
            "-CAfile",
            str(roots_file),
            "-untrusted",
            str(untrusted_file),
            "-purpose",
            "sslserver",
            str(leaf_file),
        ]
        code, out, err = openssl.try_run(*arguments)
        if code != 0:
            # Surface OpenSSL's reason verbatim. A root CA with name constraints
            # reports "permitted subtree violation" here, and the operator needs
            # to read that exact phrase to understand that the DOMAIN -- not the
            # chain -- is what the CA refuses to certify.
            fail(
                "chain-verify",
                "the chain does not verify to the supplied root:\n"
                + "\n".join(
                    f"    {line}"
                    for line in (err + out).strip().splitlines()
                    if line.strip()
                ),
            )
        # Prove the wildcard actually covers a real published vhost. A root with
        # DNS name constraints rejects the leaf here if the domain is outside its
        # permitted subtree -- surface OpenSSL's message verbatim.
        code, out, err = openssl.try_run(
            *arguments[:-1], "-verify_hostname", f"portal.{domain}", str(leaf_file)
        )
        if code != 0:
            fail(
                "hostname-verify",
                f"the certificate does not verify for the published vhost "
                f"portal.{domain}:\n"
                + "\n".join(
                    f"    {line}"
                    for line in (err + out).strip().splitlines()
                    if line.strip()
                ),
            )


# ── composite validation ────────────────────────────────────────────────────


def validate_material(
    openssl: OpenSSL,
    *,
    leaf_pems: list[str],
    chain_pems: list[str],
    key_path: Path,
    domain: str,
    min_days: int,
    reject_self_signed: bool,
) -> None:
    leaf_pem = leaf_pems[0]
    leaf_text = certificate_text(openssl, leaf_pem, "leaf")

    public_key = check_key_matches_leaf(openssl, key_path, leaf_pem)
    check_key_strength(openssl, public_key)
    check_san(leaf_text, domain)
    check_eku(leaf_text)
    check_leaf_is_not_a_ca(leaf_text)
    if reject_self_signed:
        check_not_self_signed(openssl, leaf_pem)
    roots = check_chain_shape(openssl, leaf_pem, chain_pems)
    check_validity(openssl, [leaf_pem, *chain_pems], min_days)
    check_chain_verifies(openssl, leaf_pem, chain_pems, roots, domain)


# ── atomic installation ─────────────────────────────────────────────────────


def atomic_write(
    directory: Path, name: str, content: bytes, mode: int, owner: tuple[int, int]
) -> bool:
    """Write via an O_EXCL temp file + os.replace. Returns True iff bytes changed."""
    target = directory / name
    try:
        previous = target.read_bytes()
    except OSError:
        previous = None
    if previous == content:
        # Still reconcile the boundary: correct bytes under a wrong mode are unsafe.
        os.chmod(target, mode)
        if os.geteuid() == 0:
            os.chown(target, owner[0], owner[1])
        return False

    handle, temporary = tempfile.mkstemp(prefix=f".{name}.", dir=str(directory))
    try:
        os.write(handle, content)
        os.fchmod(handle, mode)
        if os.geteuid() == 0:
            os.fchown(handle, owner[0], owner[1])
        os.fsync(handle)
    finally:
        os.close(handle)
    os.replace(temporary, target)
    directory_handle = os.open(str(directory), os.O_RDONLY)
    try:
        os.fsync(directory_handle)
    finally:
        os.close(directory_handle)
    return True


def install_material(
    certs_dir: Path, leaf_pem: str, chain_pems: list[str], key_path: Path
) -> bool:
    chain = "".join(chain_pems)
    int_crt = (leaf_pem.rstrip("\n") + "\n" + chain.rstrip("\n") + "\n").encode("utf-8")
    ca_pem = (chain.rstrip("\n") + "\n").encode("utf-8")
    key_bytes = key_path.read_bytes()

    # Key first: an edge that briefly has a new cert with an old key fails closed
    # (Traefik refuses the pair), whereas the reverse can serve a stale identity.
    changed = atomic_write(certs_dir, "int.key", key_bytes, 0o640, (0, 65532))
    changed |= atomic_write(certs_dir, "int.crt", int_crt, 0o644, (0, 0))
    changed |= atomic_write(certs_dir, "ca.pem", ca_pem, 0o644, (0, 0))
    return changed


# ── subcommands ─────────────────────────────────────────────────────────────


def parse_owner(value: str) -> tuple[int, int]:
    try:
        uid, gid = value.split(":", 1)
        return int(uid), int(gid)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected UID:GID, got {value!r}") from None


def load_installed(
    openssl: OpenSSL, certs_dir: Path, key_owner: tuple[int, int], key_mode: int
) -> tuple[list[str], list[str], Path]:
    int_crt = certs_dir / "int.crt"
    ca_pem = certs_dir / "ca.pem"
    int_key = certs_dir / "int.key"
    require_safe_file(int_crt, "certs/int.crt", expect_owner=(0, 0) if os.geteuid() == 0 else None,
                      expect_mode=0o644)
    require_safe_file(ca_pem, "certs/ca.pem", expect_owner=(0, 0) if os.geteuid() == 0 else None,
                      expect_mode=0o644)
    require_safe_file(int_key, "certs/int.key", expect_owner=key_owner, expect_mode=key_mode)
    installed = read_certificate_file(int_crt, "certs/int.crt")
    bundle = read_certificate_file(ca_pem, "certs/ca.pem")
    return installed, bundle, int_key


def command_validate(arguments: argparse.Namespace) -> int:
    openssl = OpenSSL(arguments.openssl)
    leaf = Path(arguments.leaf)
    key = Path(arguments.key)
    chain = Path(arguments.chain)
    require_safe_file(leaf, "--leaf")
    require_safe_file(chain, "--chain")
    require_safe_file(key, "--key", expect_owner=arguments.expect_key_owner,
                      expect_mode=arguments.expect_key_mode)
    leaf_pems = read_certificate_file(leaf, "--leaf")
    chain_pems = read_certificate_file(chain, "--chain")
    validate_material(
        openssl,
        leaf_pems=leaf_pems,
        chain_pems=chain_pems,
        key_path=key,
        domain=arguments.domain,
        min_days=arguments.min_days_remaining,
        reject_self_signed=True,
    )
    print("edge-tls=valid")
    return 0


def command_validate_installed(arguments: argparse.Namespace) -> int:
    openssl = OpenSSL(arguments.openssl)
    certs_dir = Path(arguments.certs_dir)
    installed, bundle, key = load_installed(
        openssl, certs_dir, arguments.expect_key_owner, arguments.expect_key_mode
    )
    leaf_pem = installed[0]
    chain_pems = bundle
    if arguments.reject_self_signed:
        # The bootstrap placeholder is its own CA bundle. Refuse that shape before
        # anything else so the operator gets the honest reason.
        if any(pem.strip() == leaf_pem.strip() for pem in bundle):
            fail(
                "not-self-signed",
                "certs/ca.pem contains the edge leaf itself. This is the self-signed "
                "bootstrap placeholder, not real edge material.",
            )
    validate_material(
        openssl,
        leaf_pems=installed,
        chain_pems=chain_pems,
        key_path=key,
        domain=arguments.domain,
        min_days=arguments.min_days_remaining,
        reject_self_signed=arguments.reject_self_signed,
    )
    print("edge-tls=valid")
    return 0


def command_install(arguments: argparse.Namespace) -> int:
    openssl = OpenSSL(arguments.openssl)
    leaf = Path(arguments.leaf)
    key = Path(arguments.key)
    chain = Path(arguments.chain)
    certs_dir = Path(arguments.certs_dir)
    if not certs_dir.is_dir():
        fail("input-shape", f"--certs-dir is not a directory: {certs_dir}")
    require_safe_file(leaf, "--leaf")
    require_safe_file(chain, "--chain")
    require_safe_file(key, "--key", expect_owner=arguments.expect_key_owner,
                      expect_mode=arguments.expect_key_mode)
    leaf_pems = read_certificate_file(leaf, "--leaf")
    chain_pems = read_certificate_file(chain, "--chain")
    # Validation is complete before the first byte of certs/ is touched.
    validate_material(
        openssl,
        leaf_pems=leaf_pems,
        chain_pems=chain_pems,
        key_path=key,
        domain=arguments.domain,
        min_days=arguments.min_days_remaining,
        reject_self_signed=True,
    )
    changed = install_material(certs_dir, leaf_pems[0], chain_pems, key)
    print("edge-tls=changed" if changed else "edge-tls=unchanged")
    return 0


def command_validate_ca_bundle(arguments: argparse.Namespace) -> int:
    openssl = OpenSSL(arguments.openssl)
    bundle = Path(arguments.bundle)
    require_safe_file(bundle, "--bundle")
    certificates = read_certificate_file(bundle, "--bundle")
    for pem in certificates:
        text = certificate_text(openssl, pem, "bundle")
        if not is_ca(text):
            subject, _ = subject_and_issuer(openssl, pem)
            fail("ca-constraints", f"CA bundle entry is not a CA (CA:TRUE absent): {subject}")
    check_validity(openssl, certificates, arguments.min_days_remaining)
    print("edge-tls=valid")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--openssl",
        default=DEFAULT_OPENSSL,
        help=argparse.SUPPRESS,  # tests only; production uses the absolute default
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common(target: argparse.ArgumentParser) -> None:
        target.add_argument("--domain", required=True)
        target.add_argument("--min-days-remaining", type=int, default=30)

    validate = subparsers.add_parser("validate")
    validate.add_argument("--leaf", required=True)
    validate.add_argument("--key", required=True)
    validate.add_argument("--chain", required=True)
    validate.add_argument("--expect-key-owner", type=parse_owner, default=None)
    validate.add_argument("--expect-key-mode", type=lambda v: int(v, 8), default=0o600)
    add_common(validate)
    validate.set_defaults(handler=command_validate)

    validate_installed = subparsers.add_parser("validate-installed")
    validate_installed.add_argument("--certs-dir", required=True)
    validate_installed.add_argument("--reject-self-signed", action="store_true")
    validate_installed.add_argument("--expect-key-owner", type=parse_owner, default=(0, 65532))
    validate_installed.add_argument("--expect-key-mode", type=lambda v: int(v, 8), default=0o640)
    add_common(validate_installed)
    validate_installed.set_defaults(handler=command_validate_installed)

    install = subparsers.add_parser("install")
    install.add_argument("--leaf", required=True)
    install.add_argument("--key", required=True)
    install.add_argument("--chain", required=True)
    install.add_argument("--certs-dir", required=True)
    install.add_argument("--expect-key-owner", type=parse_owner, default=None)
    install.add_argument("--expect-key-mode", type=lambda v: int(v, 8), default=0o600)
    add_common(install)
    install.set_defaults(handler=command_install)

    ca_bundle = subparsers.add_parser("validate-ca-bundle")
    ca_bundle.add_argument("--bundle", required=True)
    ca_bundle.add_argument("--min-days-remaining", type=int, default=30)
    ca_bundle.set_defaults(handler=command_validate_ca_bundle)

    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if not shutil.which(arguments.openssl) and not Path(arguments.openssl).is_file():
        print(f"FATAL: openssl not found at {arguments.openssl}", file=sys.stderr)
        return 1
    try:
        return arguments.handler(arguments)
    except CheckFailure as failure:
        print(f"edge-tls: FAILED {failure.check}: {failure.detail}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
