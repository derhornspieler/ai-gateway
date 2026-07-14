#!/usr/bin/env python3
"""Validate that temporary host-network access is build-only and allow-listed."""

from __future__ import annotations

import json
from pathlib import Path
import sys


DOCKERFILE_FRONTEND = (
    "# syntax=docker/dockerfile:1.7@sha256:"
    "a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e"
)
FRONTEND_DOCKERFILES = {
    "services/dev-portal/Dockerfile",
    "services/dhi-health-probe/Dockerfile",
    "services/dhi-health-probe/Dockerfile.open-webui",
    "services/egress-proxy/Dockerfile",
    "services/key-rotator/Dockerfile",
    "services/lab-dns/Dockerfile",
    "services/vault-ui-proxy/Dockerfile",
}


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[2] not in {"base", "lab"}:
        raise SystemExit("usage: validate-build-contract.py ROOT base|lab")

    root = Path(sys.argv[1]).resolve()
    profile = sys.argv[2]
    services = json.load(sys.stdin)["services"]

    dockerfiles = sorted((root / "services").glob("**/Dockerfile*"))
    if not dockerfiles:
        raise SystemExit("no service Dockerfiles found for frontend verification")
    frontend_dockerfiles: set[str] = set()
    for dockerfile in dockerfiles:
        if not dockerfile.is_file():
            raise SystemExit(f"unexpected Dockerfile object: {dockerfile}")
        first_line = dockerfile.read_text(encoding="utf-8").splitlines()[0]
        if first_line.startswith("# syntax="):
            frontend_dockerfiles.add(str(dockerfile.relative_to(root)))
        if first_line.startswith("# syntax=") and first_line != DOCKERFILE_FRONTEND:
            raise SystemExit(
                f"{dockerfile.relative_to(root)} has an unpinned Dockerfile frontend"
            )
    if frontend_dockerfiles != FRONTEND_DOCKERFILES:
        raise SystemExit(
            "Dockerfile frontend declarations changed: expected "
            f"{sorted(FRONTEND_DOCKERFILES)}, got {sorted(frontend_dockerfiles)}"
        )

    expected_contexts = {
        "traefik-int": root / "services/traefik",
        "traefik-adm": root / "services/traefik",
        "dev-portal": root / "services/dev-portal",
        "admin-portal": root / "services/dev-portal",
        "key-rotator": root / "services/key-rotator",
        "envoy-egress": root / "services/egress-proxy",
        "oauth2-proxy": root / "services/dhi-health-probe",
        "oauth2-proxy-grafana": root / "services/dhi-health-probe",
        "oauth2-proxy-prometheus": root / "services/dhi-health-probe",
        "oauth2-proxy-vault": root / "services/dhi-health-probe",
        "open-webui": root / "services/dhi-health-probe",
        "keycloak": root / "services/dhi-health-probe",
        "vault": root / "services/dhi-health-probe",
        "vault-ui-proxy": root / "services/vault-ui-proxy",
        "redis": root / "services/dhi-health-probe",
        "alloy": root / "services/dhi-health-probe",
        "prometheus": root / "services/dhi-health-probe",
        "node-exporter": root / "services/dhi-health-probe",
        "loki": root / "services/dhi-health-probe",
        "grafana": root / "services/dhi-health-probe",
        "cribl-mock": root / "services/dhi-health-probe",
    }
    expected_host_networks = {"dev-portal", "admin-portal", "key-rotator"}
    expected_no_networks = set(expected_contexts) - expected_host_networks
    if profile == "lab":
        expected_contexts["samba-ad"] = root / "services/samba-ad-lab"
        expected_contexts["lab-dns"] = root / "services/lab-dns"
        expected_host_networks.add("samba-ad")
        expected_no_networks.add("lab-dns")

    host_network_builds: set[str] = set()
    for name, service in services.items():
        build = service.get("build")
        if not isinstance(build, dict):
            continue
        if build.get("network") == "host":
            host_network_builds.add(name)
        if name in expected_contexts:
            actual = Path(build.get("context", "")).resolve()
            if actual != expected_contexts[name].resolve():
                raise SystemExit(
                    f"{name} build context {actual} is outside its allow-listed directory"
                )
        if name in expected_no_networks and build.get("network") != "none":
            raise SystemExit(f"{name} build must have network: none")

    if host_network_builds != expected_host_networks:
        raise SystemExit(
            "host-network builds must be exactly "
            f"{sorted(expected_host_networks)}, got {sorted(host_network_builds)}"
        )

    secret_excludes = {
        ".env",
        ".env.*",
        "secrets/",
        "**/*.key",
        "**/*.p12",
        "**/*.pfx",
    }
    for relative in ("services/dev-portal", "services/key-rotator"):
        rules = {
            line.strip()
            for line in (root / relative / ".dockerignore").read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        missing = secret_excludes - rules
        if missing:
            raise SystemExit(f"{relative}/.dockerignore misses {sorted(missing)}")

    exact_contexts = {
        "services/traefik": {"*", "!Dockerfile"},
        "services/dhi-health-probe": {
            "*",
            "!Dockerfile",
            "!Dockerfile.open-webui",
            "!go.mod",
            "!main.go",
            "!main_test.go",
            "!patch_openwebui_oauth.py",
            "!verify_openwebui_oauth.py",
        },
        "services/egress-proxy": {
            "*", "!Dockerfile", "!go.mod", "!entrypoint.go", "!entrypoint_test.go",
            "!envoy.yaml", "!certs/", "!certs/*.pem",
        },
        "services/vault-ui-proxy": {
            "*", "!Dockerfile", "!go.mod", "!main.go", "!main_test.go",
            "!upstream-provenance.json",
            "!cmd/", "!cmd/extract-ui/", "!cmd/extract-ui/main.go",
            "!cmd/extract-ui/main_test.go",
        },
    }
    for relative, required in exact_contexts.items():
        rules = {
            line.strip()
            for line in (root / relative / ".dockerignore").read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        if rules != required:
            raise SystemExit(f"{relative} build context is not exact-file allow-listed")

    if profile == "lab":
        rules = [
            line.strip()
            for line in (root / "services/samba-ad-lab/.dockerignore").read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        required = {
            "*",
            "!Dockerfile",
            "!policy-rc.d",
            "!samba-ad-entrypoint",
            "!samba-ad-healthcheck",
            "!samba-ad-secret-tool",
        }
        if not required.issubset(rules) or rules[0] != "*":
            raise SystemExit("Samba build context is not exact-file allow-listed")

        dns_rules = [
            line.strip()
            for line in (root / "services/lab-dns/.dockerignore").read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if dns_rules != ["*", "!Dockerfile", "!healthcheck.go"]:
            raise SystemExit("lab-dns build context is not exact-file allow-listed")


if __name__ == "__main__":
    main()
