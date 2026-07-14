#!/usr/bin/env python3
"""Docker/Compose version-skew canary for the runtime contracts this repo relies on.

`scripts/validate-compose.sh` only proves the *rendered model* is sound. Two
production outages came from *runtime* behaviour changing under an unpinned
Docker CE (`ansible/roles/os_baseline/tasks/main.yml` installs `docker-ce` and
`docker-compose-plugin` from `docker-ce-stable` with no version pin, so every
converge gets whatever Compose shipped that week):

  A. Compose model validation on live-project `exec`
     `docker compose exec` validates the *whole* project model. With
     `COMPOSE_PROFILES=""` on a lab host the profile-gated `samba-ad` service
     disappears while the lab overlay's `keycloak: depends_on: samba-ad`
     survives, so Compose rejects the project with
     `depends on undefined service`. Fixed by activating the real joined
     profile set on every exec-style task.

  B. Implicit tmpfs option tokens in `docker inspect`
     `ansible/roles/verify/tasks/main.yml` asserts token sets over
     `HostConfig.Tmpfs[<dest>]`. `rw` is *implicit* in the Compose spec for
     grafana (`compose/docker-compose.yml`:
     `/var/lib/grafana/plugins:uid=65532,gid=65532,mode=0700,noexec,nosuid,nodev`)
     yet the verify role requires `rw` in the inspect output. A Compose/Engine
     release that stops materialising implicit tokens fails the converge at the
     verify role — after the stack is already live.

Neither is visible to a render-only gate, so this canary actually starts
containers on the CI runner and asserts the observable shapes. It is
deliberately hermetic: the probe image is built `FROM scratch` around a static
Go binary, so it pulls nothing and cannot be rate-limited by a registry.

Exit codes:
  0  every runtime contract held on this Docker/Compose
  1  a runtime contract broke (real version skew — read the report)
  2  the canary could not run (harness fault, not a product defect)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Kept byte-for-byte in step with the reviewed live-container assertions in
# ansible/roles/verify/tasks/main.yml. scripts/tests/test_ci_health_checks.py
# fails if the verify role and this canary ever disagree.
OPEN_WEBUI_TMPFS_SPEC = "/tmp:rw,noexec,nosuid,nodev,mode=1777,size=256m"
OPEN_WEBUI_REQUIRED_TOKENS = {
    "rw",
    "noexec",
    "nosuid",
    "nodev",
    "mode=1777",
    "size=256m",
}
GRAFANA_TMPFS_SPEC = (
    "/var/lib/grafana/plugins:uid=65532,gid=65532,mode=0700,noexec,nosuid,nodev"
)
GRAFANA_REQUIRED_TOKENS = {
    "rw",
    "noexec",
    "nosuid",
    "nodev",
    "uid=65532",
    "gid=65532",
    "mode=0700",
}

PROBE_IMAGE = "aigw-ci-compose-canary:local"
PROJECT = "aigw-canary"
GATED_PROFILE = "lab-ad"

# CI builds the probe with the runner's own Go toolchain, so the canary pulls
# nothing at all. A controller workstation without Go falls back to this
# tag-and-digest-pinned builder, per the repository's never-`latest` rule.
GO_BUILDER_IMAGE = (
    "golang:1.25-alpine@sha256:"
    "56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587"
)

PROBE_SOURCE = """package main

import (
\t"os"
\t"time"
)

// Static, dependency-free probe. With no argument it parks forever so the
// container stays up for `compose exec`; with `ok` it exits zero so an exec
// that reaches the container is unambiguous.
func main() {
\tif len(os.Args) > 1 && os.Args[1] == "ok" {
\t\tos.Exit(0)
\t}
\tfor {
\t\ttime.Sleep(time.Hour)
\t}
}
"""

PROBE_DOCKERFILE = """FROM scratch
COPY probe /probe
ENTRYPOINT ["/probe"]
"""

# Mirrors the shape that broke: a default service whose *overlay* dependency is
# profile-gated. The base file alone is always valid; only base+overlay with an
# emptied COMPOSE_PROFILES can produce `depends on undefined service`.
BASE_COMPOSE = f"""services:
  probe:
    image: {PROBE_IMAGE}
    pull_policy: never
    read_only: true
    tmpfs:
      - {OPEN_WEBUI_TMPFS_SPEC}
      - {GRAFANA_TMPFS_SPEC}
"""

OVERLAY_COMPOSE = f"""services:
  probe:
    depends_on:
      gated:
        condition: service_started
  gated:
    image: {PROBE_IMAGE}
    pull_policy: never
    profiles: [{GATED_PROFILE}]
"""


class HarnessError(RuntimeError):
    """The canary itself could not run — never reported as version skew."""


def run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    merged = dict(os.environ)
    # A persisted Docker context must never redirect the canary, exactly as in
    # scripts/validate-compose.sh.
    for name in (
        "DOCKER_CONTEXT",
        "DOCKER_HOST",
        "DOCKER_TLS",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "DOCKER_API_VERSION",
    ):
        merged.pop(name, None)
    merged.update(env or {})
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        argv,
        cwd=str(cwd) if cwd else None,
        env=merged,
        capture_output=True,
        text=True,
        check=False,
    )
    if check and completed.returncode != 0:
        raise HarnessError(
            f"command failed ({completed.returncode}): {' '.join(argv)}\n"
            f"stdout: {completed.stdout}\nstderr: {completed.stderr}"
        )
    return completed


def build_probe_image(docker: str, workdir: Path) -> None:
    build = workdir / "probe-image"
    build.mkdir()
    (build / "main.go").write_text(PROBE_SOURCE, encoding="utf-8")
    (build / "go.mod").write_text("module aigw/canary\n\ngo 1.25\n", encoding="utf-8")
    (build / "Dockerfile").write_text(PROBE_DOCKERFILE, encoding="utf-8")

    go = shutil.which("go")
    if go is not None:
        run(
            [go, "build", "-trimpath", "-o", "probe", "."],
            cwd=build,
            env={"CGO_ENABLED": "0", "GOOS": "linux", "GOFLAGS": "-mod=mod"},
        )
    else:
        run(
            [
                docker,
                "run",
                "--rm",
                "--network=none",
                "--volume",
                f"{build}:/src",
                "--workdir",
                "/src",
                "--env",
                "CGO_ENABLED=0",
                "--env",
                "GOOS=linux",
                "--env",
                "GOFLAGS=-mod=mod",
                GO_BUILDER_IMAGE,
                "go",
                "build",
                "-trimpath",
                "-o",
                "probe",
                ".",
            ]
        )
    run([docker, "build", "--tag", PROBE_IMAGE, "."], cwd=build)


def compose(docker: str, workdir: Path, *args: str, profiles: str, check: bool = True):
    argv = [
        docker,
        "compose",
        "--project-name",
        PROJECT,
        "--project-directory",
        str(workdir),
        "-f",
        str(workdir / "docker-compose.yml"),
        "-f",
        str(workdir / "docker-compose.overlay.yml"),
        *args,
    ]
    # COMPOSE_PROFILES is the whole point of contract A: it must be passed
    # exactly as an Ansible task would, never via --profile.
    return run(argv, cwd=workdir, env={"COMPOSE_PROFILES": profiles}, check=check)


def tmpfs_tokens(inspected: dict, destination: str) -> set[str]:
    host_config = inspected.get("HostConfig") or {}
    tmpfs = host_config.get("Tmpfs") or {}
    raw = tmpfs.get(destination)
    if not isinstance(raw, str):
        return set()
    return {token for token in raw.split(",") if token}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--summary",
        type=Path,
        default=None,
        help="append a Markdown report here (GITHUB_STEP_SUMMARY)",
    )
    args = parser.parse_args()

    docker = shutil.which("docker")
    if docker is None:
        raise HarnessError("docker is required")

    versions = {
        "engine": run(
            [docker, "version", "--format", "{{.Server.Version}}"]
        ).stdout.strip(),
        "compose": run([docker, "compose", "version", "--short"]).stdout.strip(),
    }

    failures: list[str] = []
    notes: list[str] = []

    with tempfile.TemporaryDirectory(prefix="aigw-canary-") as raw_workdir:
        workdir = Path(raw_workdir)
        (workdir / "docker-compose.yml").write_text(BASE_COMPOSE, encoding="utf-8")
        (workdir / "docker-compose.overlay.yml").write_text(
            OVERLAY_COMPOSE, encoding="utf-8"
        )
        build_probe_image(docker, workdir)

        try:
            # --- Contract A: live-project exec under the real joined profiles.
            joined = compose(
                docker, workdir, "up", "-d", "--wait", profiles=GATED_PROFILE
            )
            if joined.returncode != 0:
                raise HarnessError(f"canary project failed to start: {joined.stderr}")

            exec_joined = compose(
                docker,
                workdir,
                "exec",
                "-T",
                "probe",
                "/probe",
                "ok",
                profiles=GATED_PROFILE,
                check=False,
            )
            if exec_joined.returncode != 0:
                failures.append(
                    "CONTRACT A BROKEN: `compose exec` on a live project rejected the "
                    "reviewed joined profile set "
                    f"(COMPOSE_PROFILES={GATED_PROFILE!r}); every exec-style Ansible "
                    "task in ansible/roles/{docker_stack,verify} will fail on this "
                    f"Compose.\nstderr: {exec_joined.stderr.strip()}"
                )

            # Informational: is the emptied-profile trap still armed? If Compose
            # ever stops validating the full model here, the joined-profile fix
            # stays correct — it just stops being load-bearing.
            exec_empty = compose(
                docker,
                workdir,
                "exec",
                "-T",
                "probe",
                "/probe",
                "ok",
                profiles="",
                check=False,
            )
            if exec_empty.returncode == 0:
                notes.append(
                    "Compose accepted `exec` with an emptied COMPOSE_PROFILES: this "
                    "release no longer validates profile-gated depends_on for live "
                    "queries. The joined-profile contract remains correct but is no "
                    "longer load-bearing on this version."
                )
            else:
                notes.append(
                    "Compose still rejects `exec` with an emptied COMPOSE_PROFILES "
                    "(the joined-profile contract is load-bearing on this version)."
                )

            # --- Contract B: implicit tmpfs option tokens survive to inspect.
            container = compose(
                docker, workdir, "ps", "-q", "probe", profiles=GATED_PROFILE
            ).stdout.strip()
            if not container:
                raise HarnessError("canary probe container id is unavailable")
            inspected = json.loads(run([docker, "inspect", container]).stdout)[0]

            for label, destination, spec, required in (
                (
                    "open-webui",
                    "/tmp",
                    OPEN_WEBUI_TMPFS_SPEC,
                    OPEN_WEBUI_REQUIRED_TOKENS,
                ),
                (
                    "grafana",
                    "/var/lib/grafana/plugins",
                    GRAFANA_TMPFS_SPEC,
                    GRAFANA_REQUIRED_TOKENS,
                ),
            ):
                observed = tmpfs_tokens(inspected, destination)
                missing = required - observed
                notes.append(
                    f"tmpfs {destination} -> "
                    f"{','.join(sorted(observed)) or '<absent>'}"
                )
                if missing:
                    failures.append(
                        f"CONTRACT B BROKEN: HostConfig.Tmpfs[{destination!r}] lost "
                        f"{sorted(missing)} on this Docker/Compose. "
                        f"ansible/roles/verify/tasks/main.yml requires "
                        f"{sorted(required)} for the {label} service "
                        f"(compose spec {spec!r}), so a converge fails at the verify "
                        "role with the stack already live."
                    )

            mounts = inspected.get("Mounts")
            if not isinstance(mounts, list):
                failures.append(
                    "CONTRACT B BROKEN: `docker inspect` no longer reports a Mounts "
                    "list; ansible/roles/verify/tasks/main.yml fails closed on "
                    "malformed mount metadata."
                )
        finally:
            compose(
                docker,
                workdir,
                "down",
                "--volumes",
                "--remove-orphans",
                "--timeout",
                "5",
                profiles=GATED_PROFILE,
                check=False,
            )
            run([docker, "image", "rm", "-f", PROBE_IMAGE], check=False)

    report = [
        "## Docker/Compose runtime skew canary",
        "",
        f"- Engine `{versions['engine']}`, Compose `{versions['compose']}`",
        *[f"- {note}" for note in notes],
        "",
    ]
    if failures:
        report += [
            "### ACTION REQUIRED — a runtime contract broke on this Docker/Compose",
            "",
            *[f"- {failure}" for failure in failures],
        ]
    else:
        report += ["**All runtime contracts held on this Docker/Compose.**"]

    text = "\n".join(report) + "\n"
    print(text)
    if args.summary is not None:
        with args.summary.open("a", encoding="utf-8") as handle:
            handle.write(text)

    for failure in failures:
        first = failure.splitlines()[0]
        print(f"::warning title=Docker/Compose runtime skew::{first}")
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HarnessError as error:
        print(f"::error title=Canary harness fault::{error}", file=sys.stderr)
        raise SystemExit(2) from error
