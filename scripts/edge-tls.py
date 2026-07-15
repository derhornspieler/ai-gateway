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

# The NIST prime curves the public web PKI issues for TLS leaves. P-521 is a
# stronger key than P-256, not a weaker one -- its 521-bit field must never be
# compared against the 2048-bit RSA minimum. Curves outside this set (P-192,
# P-224, or any non-NIST curve) are refused as genuinely weak.
STRONG_EC_CURVES = frozenset({"p-256", "p-384", "p-521"})

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

# The single synthetic one-label host used to exercise the wildcard in the
# name-constraint self-test. It stands in for "any *.DOMAIN leaf Vault's aigw
# role issues"; it is never a real published vhost, so the self-test never
# demands that a specific service name (e.g. samba-ad) be permitted by the
# customer CA -- the gateway only issues *.DOMAIN and the apex DOMAIN.
NAME_CONSTRAINT_PROBE_LABEL = "aigw-nc-probe"


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


def check_key_matches_cert(
    openssl: OpenSSL, key_path: Path, cert_pem: str, *, subject: str = "certificate"
) -> str:
    """Compare public keys; return the PUBLIC half for the strength check.

    The private key travels to openssl by file path and never crosses a stream
    this process reads, so it cannot leak into stdout, stderr, or a log. This is
    the general key<->certificate binding proof: the edge leaf uses it (via
    check_key_matches_leaf), and the customer-intermediate ceremony uses it to
    prove the supplied key belongs to the supplied intermediate -- a supplied
    ROOT key (or any other key) fails here before Vault is ever touched.
    """
    from_key = openssl.run("pkey", "-in", str(key_path), "-pubout", check_name="key-match")
    from_cert = openssl.run("x509", "-noout", "-pubkey", stdin=cert_pem, check_name="key-match")
    if from_key.strip() != from_cert.strip():
        fail(
            "key-match",
            f"the private key does not match the {subject}'s public key",
        )
    return from_key


def check_key_matches_leaf(openssl: OpenSSL, key_path: Path, leaf_pem: str) -> str:
    return check_key_matches_cert(openssl, key_path, leaf_pem, subject="leaf certificate")


def check_key_strength(openssl: OpenSSL, public_key_pem: str) -> None:
    """Inspect the PUBLIC half only: `pkey -in <key> -text` would print the private key.

    An EC key is judged by its named curve, never by an RSA bit threshold. All
    three NIST prime curves the web PKI issues -- P-256, P-384, P-521 -- are
    strong; P-521 reports 521 "bits" and must NOT be refused for failing a
    2048-bit RSA rule. RSA keys must carry a >= 2048-bit modulus.
    """
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
    if "nist curve:" in lowered:
        # EC key. Accept only the strong NIST prime curves; a weaker curve
        # (P-192/P-224) or any non-NIST curve is a genuinely weak key.
        curve = lowered.split("nist curve:", 1)[1].splitlines()[0].strip()
        if curve in STRONG_EC_CURVES:
            return
        fail(
            "key-strength",
            f"EC key uses unsupported curve {curve or '(unnamed)'}; the edge key "
            "must use NIST curve P-256, P-384, or P-521",
        )
    # RSA (or any non-EC key without a NIST curve): require a >= 2048-bit modulus.
    if bits < 2048:
        fail("key-strength", f"RSA key is {bits} bits; 2048 is the minimum")


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


def check_ca_key_usage(text: str) -> None:
    """An issuing CA certificate must be permitted to sign certificates.

    The non-Extended `X509v3 Key Usage:` heading holds `Certificate Sign` for a
    real intermediate; `extension_section` matches the exact heading so the
    Extended Key Usage section is never confused for it.
    """
    section = extension_section(text, "X509v3 Key Usage:")
    if "Certificate Sign" not in section:
        fail(
            "ca-key-usage",
            "the intermediate CA certificate does not carry the Certificate Sign "
            f"key usage and cannot issue leaves (found: {section or 'no Key Usage extension'})",
        )


def count_private_key_blocks(text: str) -> int:
    """Count PEM private-key BEGIN lines. Each `-----BEGIN ... PRIVATE KEY-----`
    is one block; the END line is not counted."""
    return sum(
        1
        for line in text.splitlines()
        if line.startswith("-----BEGIN") and "PRIVATE KEY" in line
    )


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


def check_intermediate_chain(
    openssl: OpenSSL, intermediate_pem: str, chain_pems: list[str]
) -> list[str]:
    """Every chain member is a CA, a self-signed root is present, and the
    supplied intermediate verifies up to that root.

    Unlike check_chain_shape (used for a leaf, which must NOT appear in its own
    chain), the intermediate legitimately appears in `chain = intermediate +
    root`, so this cannot reuse that helper.
    """
    roots: list[str] = []
    for index, pem in enumerate(chain_pems):
        text = certificate_text(openssl, pem, f"chain[{index}]")
        if not is_ca(text):
            subject, _ = subject_and_issuer(openssl, pem)
            fail("ca-constraints", f"chain certificate is not a CA (CA:TRUE absent): {subject}")
        if is_self_signed(openssl, pem):
            roots.append(pem)
    if not roots:
        fail("ca-constraints", f"no self-signed root CA is present in the chain; {CHAIN_NEEDS_ROOT_HINT}")
    other_intermediates = [
        pem for pem in chain_pems if pem not in roots and pem.strip() != intermediate_pem.strip()
    ]
    with tempfile.TemporaryDirectory(prefix="edge-tls-int-verify-") as workspace:
        work = Path(workspace)
        intermediate_file = work / "intermediate.pem"
        roots_file = work / "roots.pem"
        untrusted_file = work / "untrusted.pem"
        intermediate_file.write_text(intermediate_pem, encoding="utf-8")
        roots_file.write_text("".join(roots), encoding="utf-8")
        arguments = ["verify", "-CAfile", str(roots_file)]
        if other_intermediates:
            # A multi-level chain needs its middle intermediates as -untrusted;
            # an empty -untrusted file is an OpenSSL error, so only pass it when
            # there is something to pass.
            untrusted_file.write_text("".join(other_intermediates), encoding="utf-8")
            arguments += ["-untrusted", str(untrusted_file)]
        code, out, err = openssl.try_run(*arguments, str(intermediate_file))
        if code != 0:
            fail(
                "chain-verify",
                "the supplied intermediate does not verify to a self-signed root in "
                "the chain:\n"
                + "\n".join(
                    f"    {line}" for line in (err + out).strip().splitlines() if line.strip()
                ),
            )
    return roots


def check_intermediate_name_constraints(
    openssl: OpenSSL,
    key_path: Path,
    intermediate_pem: str,
    roots: list[str],
    chain_pems: list[str],
    domain: str,
) -> None:
    """Prove the domain falls inside the CA's permitted name-constraint subtree.

    Because this mode holds the intermediate's PRIVATE KEY, it can do what no
    other mode can: sign a throwaway test leaf under the SUPPLIED intermediate
    and run the exact `openssl verify` the real edge leaves get. If the root (or
    the intermediate itself) carries DNS name constraints that do not permit
    `domain`, OpenSSL returns error 47 and its verbatim "permitted subtree
    violation" is surfaced -- fail closed BEFORE any Vault mutation.

    The test leaf mirrors EXACTLY what Vault's `aigw` role issues: the wildcard
    `*.DOMAIN` and the apex `DOMAIN`, and nothing else. A one-label probe host
    under the wildcard plus the apex together exercise the whole namespace the
    gateway ever certifies. It deliberately does NOT probe a specific service
    host such as `samba-ad.DOMAIN`: that leaf is lab-only, is covered by the
    wildcard when issued, and pinning it here would false-reject a production
    intermediate whose name constraints exclude that one host even though the
    gateway never issues it.

    The intermediate's private key reaches openssl only as `-CAkey <path>`; the
    signed test leaf is written to the temp dir, never to a stream this process
    reads, so no key bytes can leak.
    """
    untrusted = [pem for pem in chain_pems if pem not in roots]
    if all(pem.strip() != intermediate_pem.strip() for pem in untrusted):
        untrusted.insert(0, intermediate_pem)
    with tempfile.TemporaryDirectory(prefix="edge-tls-nc-") as workspace:
        work = Path(workspace)
        ca_file = work / "intermediate.pem"
        roots_file = work / "roots.pem"
        untrusted_file = work / "untrusted.pem"
        test_key = work / "testleaf.key"
        test_csr = work / "testleaf.csr"
        test_ext = work / "testleaf.ext"
        test_leaf = work / "testleaf.pem"
        ca_file.write_text(intermediate_pem, encoding="utf-8")
        roots_file.write_text("".join(roots), encoding="utf-8")
        untrusted_file.write_text("".join(untrusted), encoding="utf-8")
        openssl.run(
            "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-subj", f"/CN=*.{domain}",
            "-keyout", str(test_key), "-out", str(test_csr),
            check_name="name-constraints",
        )
        test_ext.write_text(
            f"subjectAltName=DNS:*.{domain},DNS:{domain}\n"
            "extendedKeyUsage=serverAuth\n"
            "basicConstraints=critical,CA:FALSE\n",
            encoding="utf-8",
        )
        openssl.run(
            "x509", "-req", "-in", str(test_csr),
            "-CA", str(ca_file), "-CAkey", str(key_path), "-CAcreateserial",
            "-days", "1", "-extfile", str(test_ext), "-out", str(test_leaf),
            check_name="name-constraints",
        )
        base = [
            "verify", "-CAfile", str(roots_file), "-untrusted", str(untrusted_file),
            "-purpose", "sslserver",
        ]
        for hostname in (f"{NAME_CONSTRAINT_PROBE_LABEL}.{domain}", domain):
            code, out, err = openssl.try_run(*base, "-verify_hostname", hostname, str(test_leaf))
            if code != 0:
                fail(
                    "name-constraints",
                    f"a leaf for {hostname} signed by the supplied intermediate does not "
                    f"verify to the customer root; {domain} may fall outside the CA's "
                    "permitted name-constraint subtree:\n"
                    + "\n".join(
                        f"    {line}"
                        for line in (err + out).strip().splitlines()
                        if line.strip()
                    ),
                )


# ── composite validation ────────────────────────────────────────────────────


def validate_intermediate_material(
    openssl: OpenSSL,
    *,
    intermediate_pem: str,
    chain_pems: list[str],
    key_path: Path,
    domain: str,
    min_days: int,
) -> None:
    """Fail-closed validation of an operator-supplied intermediate CA + key.

    Every check runs BEFORE the caller imports anything into Vault; the first
    failure aborts. The order is deliberate so the operator gets the most
    specific reason (a self-signed root refusal, not a downstream chain error).
    """
    text = certificate_text(openssl, intermediate_pem, "intermediate")
    if not is_ca(text):
        fail(
            "ca-constraints",
            "the supplied intermediate is not a CA certificate (CA:TRUE absent)",
        )
    check_ca_key_usage(text)
    if is_self_signed(openssl, intermediate_pem):
        subject, _ = subject_and_issuer(openssl, intermediate_pem)
        fail(
            "self-signed-root",
            "refusing to import a self-signed root CA; supply an intermediate "
            f"issued by your root, not the root itself ({subject})",
        )
    public_key = check_key_matches_cert(
        openssl, key_path, intermediate_pem, subject="intermediate certificate"
    )
    check_key_strength(openssl, public_key)
    key_text = key_path.read_text(encoding="utf-8", errors="replace")
    if count_private_key_blocks(key_text) != 1:
        fail(
            "single-key",
            "the intermediate key file must contain exactly one private key; a "
            "bundle including the root/issuing key is refused",
        )
    roots = check_intermediate_chain(openssl, intermediate_pem, chain_pems)
    check_validity(openssl, [intermediate_pem, *chain_pems], min_days)
    check_intermediate_name_constraints(
        openssl, key_path, intermediate_pem, roots, chain_pems, domain
    )


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


def command_validate_intermediate(arguments: argparse.Namespace) -> int:
    openssl = OpenSSL(arguments.openssl)
    intermediate = Path(arguments.intermediate)
    key = Path(arguments.intermediate_key)
    chain = Path(arguments.chain)
    # 1. custody: absolute, regular, non-symlink, single-link; key owner + 0600.
    require_safe_file(intermediate, "--intermediate")
    require_safe_file(chain, "--chain")
    require_safe_file(
        key, "--intermediate-key",
        expect_owner=arguments.expect_key_owner, expect_mode=arguments.expect_key_mode,
    )
    # 2. no smuggled private key in either public file (the root/issuing key must
    #    never be supplied); read_certificate_file refuses `PRIVATE KEY`.
    intermediate_pems = read_certificate_file(intermediate, "--intermediate")
    # EXACTLY ONE certificate. A multi-cert --intermediate file (intermediate+root
    # concatenated, which many CA tools emit) would be piped whole into
    # pki_int/issuers/import/bundle by the shell ceremony, storing the customer
    # ROOT as a keyless Vault issuer -- the exact "unwanted trust surface" the
    # ceremony forbids. The root belongs in --chain, never in --intermediate.
    if len(intermediate_pems) != 1:
        fail(
            "single-intermediate",
            f"--intermediate must contain exactly one certificate; found "
            f"{len(intermediate_pems)}. A multi-cert intermediate file (e.g. "
            "intermediate+root concatenated) would import the customer root into "
            "Vault as a keyless issuer. Supply the intermediate alone; put the "
            "root (and any parent CAs) in --chain.",
        )
    chain_pems = read_certificate_file(chain, "--chain")
    validate_intermediate_material(
        openssl,
        intermediate_pem=intermediate_pems[0],
        chain_pems=chain_pems,
        key_path=key,
        domain=arguments.domain,
        min_days=arguments.min_days_remaining,
    )
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

    validate_intermediate = subparsers.add_parser("validate-intermediate")
    validate_intermediate.add_argument("--intermediate", required=True)
    validate_intermediate.add_argument("--intermediate-key", required=True)
    validate_intermediate.add_argument("--chain", required=True)
    validate_intermediate.add_argument("--expect-key-owner", type=parse_owner, default=None)
    validate_intermediate.add_argument("--expect-key-mode", type=lambda v: int(v, 8), default=0o600)
    add_common(validate_intermediate)
    validate_intermediate.set_defaults(handler=command_validate_intermediate)

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
