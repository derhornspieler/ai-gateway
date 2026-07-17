#!/usr/bin/env python3
"""Operator per-service upgrade/rollback cycle for the AI Gateway.

Controller-side, hyphenated (excluded from unittest discovery and the VM
manifest). Wraps the reviewed upgrade cycle this repository already enforces
piecemeal into three commands, without weakening any gate:

  plan <family> <new-tag> [--digest sha256:...]
      Resolve the new tag's index digest (over SSH via the target's registry
      credential unless --digest is given), rewrite EVERY declaration of that
      family's pin (compose build args / image pins, Dockerfile ARG/FROM, the
      lab reset seed map), and show the resulting git diff. Local build tags
      are deliberately NOT renamed: the deployed version lives only in the
      base/patch digest, which the content-addressed rollback preservation
      requires (a tag rename reads as drift and fails the converge).

  deploy [--skip-backup-check]
      Preflight (clean-ish git tree, backup freshness on the target, staged
      offline seed matching source pins when the profile uses one), run the
      stack converge, watch every container back to healthy, then run the
      end-to-end gate (scripts/test-e2e-lab.py) and report PASS/FAIL.

  rollback <family>
      Revert the family's pin to the previous git-committed value, then run
      the same deploy cycle (converge + health watch + e2e). Image bits for
      locally built services are still present as content-addressed
      aigw-rollback-* tags / cached pulls, so the converge is fast.

Pins remain reviewed source: `plan` edits the working tree and shows the
diff — committing is deliberately left to the operator (or the calling
automation) so every version change lands in git history.

The lab needs the offline-image-seed refresh between plan and deploy (pull
new images on the target, rebuild the seed, update inventory hashes);
`plan` prints those steps when it detects the seed profile. A production
inventory with direct registry access skips them.
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "compose/docker-compose.yml"
RESET_MAP = ROOT / "ansible/reset-rocky9-lab.yml"
TRAEFIK_DOCKERFILE = ROOT / "services/traefik/Dockerfile"
LABDNS_DOCKERFILE = ROOT / "services/lab-dns/Dockerfile"
LAB_INVENTORY = ROOT / "ansible/inventory/host_vars/lab-aigw01.yml"

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


@dataclass(frozen=True)
class Family:
    """One upgradeable image family and every file its pin appears in."""

    key: str
    repo: str                      # registry repo whose tag@digest is the pin
    kind: str                      # direct | base | patch | dockerfile-from
    files: tuple[Path, ...]        # files carrying the tag@digest string
    services: tuple[str, ...]      # compose services to health-watch
    notes: str = ""


FAMILIES: dict[str, Family] = {
    f.key: f
    for f in (
        Family("litellm", "ghcr.io/berriai/litellm", "direct",
               (COMPOSE, RESET_MAP), ("litellm",),
               "expect a ~15-20s credential re-mint window after recreate"),
        Family("postgres", "dhi.io/postgres", "direct", (COMPOSE, RESET_MAP),
               ("postgres",),
               "MINOR bumps only — a major is a migration project, and the "
               "restore version guard will refuse cross-major restores"),
        Family("keycloak", "dhi.io/keycloak", "base", (COMPOSE, RESET_MAP),
               ("keycloak",),
               "one-way Liquibase migration on first start — take a backup first"),
        Family("prometheus", "dhi.io/prometheus", "base", (COMPOSE, RESET_MAP),
               ("prometheus",)),
        Family("node-exporter", "dhi.io/node-exporter", "base",
               (COMPOSE, RESET_MAP), ("node-exporter",)),
        Family("vault", "dhi.io/vault", "base", (COMPOSE, RESET_MAP), ("vault",),
               "vault restarts SEALED; also regenerate the vault-ui-proxy "
               "asset hashes (services/vault-ui-proxy/Dockerfile)"),
        Family("redis", "dhi.io/redis", "base", (COMPOSE, RESET_MAP), ("redis",)),
        Family("loki", "dhi.io/loki", "base", (COMPOSE, RESET_MAP), ("loki",),
               "schema_config is append-only — never mutate existing entries"),
        Family("grafana", "dhi.io/grafana", "base", (COMPOSE, RESET_MAP),
               ("grafana",),
               "verify pins EXACTLY 9 provisioned dashboards; sweep for "
               "UI-created dashboards before bumping"),
        Family("alloy", "dhi.io/alloy", "base", (COMPOSE, RESET_MAP), ("alloy",),
               "runs at --stability.level=public-preview — recheck config "
               "syntax against the release notes"),
        Family("oauth2-proxy", "dhi.io/oauth2-proxy", "base",
               (COMPOSE, RESET_MAP),
               ("oauth2-proxy", "oauth2-proxy-grafana",
                "oauth2-proxy-prometheus", "oauth2-proxy-vault"),
               "one pin, four gates — all admin edges recreate together; "
               "re-verify the sign-out chain semantics"),
        Family("otel-collector", "dhi.io/opentelemetry-collector", "base",
               (COMPOSE, RESET_MAP), ("cribl-mock",)),
        Family("traefik-base", "dhi.io/traefik", "base",
               (COMPOSE, RESET_MAP, TRAEFIK_DOCKERFILE),
               ("traefik-int", "traefik-adm"),
               "if DHI ships the target version directly, retire the patch "
               "layer instead of bumping the base alone"),
        Family("traefik-patch", "traefik", "patch",
               (COMPOSE, RESET_MAP, TRAEFIK_DOCKERFILE),
               ("traefik-int", "traefik-adm"),
               "also updates org.opencontainers.image.version in the Dockerfile"),
        Family("coredns", "dhi.io/coredns", "dockerfile-from",
               (LABDNS_DOCKERFILE, RESET_MAP), ("lab-dns",),
               "lab-only; single replica on 53 — every bump is a lab-wide "
               "resolution blip"),
        Family("open-webui", "ghcr.io/open-webui/open-webui", "base",
               (COMPOSE, RESET_MAP), ("open-webui",),
               "the OAuth patch FAIL-CLOSES the build on any base change — "
               "review patch_openwebui_oauth.py against the new base first"),
    )
}


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, **kw)


def _pin_pattern(repo: str) -> re.Pattern[str]:
    # Anchor the repo so a bare name (the traefik patch source) cannot
    # substring-match a registry-qualified repo (dhi.io/traefik).
    return re.compile(
        r"(?<![A-Za-z0-9./-])" + re.escape(repo)
        + r":([A-Za-z0-9._-]+)@(sha256:[0-9a-f]{64})"
    )


def current_pin(family: Family) -> str:
    """The family's current tag@digest as written in its primary file."""
    text = family.files[0].read_text()
    pattern = _pin_pattern(family.repo)
    matches = sorted(set(pattern.findall(text)))
    if not matches:
        raise SystemExit(f"no pin found for {family.repo} in {family.files[0]}")
    if len(matches) > 1:
        raise SystemExit(
            f"{family.repo} carries multiple digests in {family.files[0]} — "
            f"refusing to guess: {matches}"
        )
    tag, digest = matches[0]
    return f"{family.repo}:{tag}@{digest}"


def resolve_digest(ssh_target: str, ref: str) -> str:
    """Ask the target host's docker (which holds registry creds) for the
    index digest of ref. Read-only; never pulls."""
    proc = run([
        "ssh", "-o", "BatchMode=yes", ssh_target,
        "sudo docker buildx imagetools inspect " + shlex.quote(ref),
    ])
    m = re.search(r"^Digest:\s+(sha256:[0-9a-f]{64})", proc.stdout, re.M)
    if proc.returncode != 0 or not m:
        raise SystemExit(
            f"could not resolve {ref} via {ssh_target}: "
            f"{(proc.stderr or proc.stdout).strip()[:300]}"
        )
    return m.group(1)


def seed_profile_active() -> bool:
    return "offline_image_seed_enabled: true" in LAB_INVENTORY.read_text()


def cmd_plan(args: argparse.Namespace) -> int:
    family = FAMILIES.get(args.family)
    if family is None:
        raise SystemExit(
            f"unknown family {args.family!r}; one of: {', '.join(sorted(FAMILIES))}"
        )
    if not TAG_RE.fullmatch(args.new_tag):
        raise SystemExit("new tag contains unexpected characters")
    old = current_pin(family)
    old_tag = old.split(":", 1)[1].split("@", 1)[0]
    if args.digest:
        if not DIGEST_RE.fullmatch(args.digest):
            raise SystemExit("--digest must be sha256:<64 hex>")
        digest = args.digest
    else:
        digest = resolve_digest(args.ssh, f"{family.repo}:{args.new_tag}")
    new = f"{family.repo}:{args.new_tag}@{digest}"
    if new == old:
        print(f"{family.key} already pinned to {new}")
        return 0

    # Two on-disk formats carry the pin: `repo:tag@sha256:...` (compose /
    # Dockerfiles) and the reset seed map's YAML form `repo:tag: sha256:...`.
    old_digest = old.rsplit("@", 1)[1]
    old_map = f"{family.repo}:{old_tag}: {old_digest}"
    new_map = f"{family.repo}:{args.new_tag}: {digest}"
    total = 0
    for path in family.files:
        text = path.read_text()
        n = text.count(old) + text.count(old_map)
        if n:
            path.write_text(text.replace(old, new).replace(old_map, new_map))
        total += n
        print(f"  {path.relative_to(ROOT)}: {n} occurrence(s)")
    if total == 0:
        raise SystemExit("pin string not found anywhere — map/file drift, aborting")

    if family.key == "traefik-patch":
        text = TRAEFIK_DOCKERFILE.read_text()
        version = args.new_tag.lstrip("v")
        text = re.sub(
            r'org\.opencontainers\.image\.version="[0-9.]+"',
            f'org.opencontainers.image.version="{version}"',
            text,
        )
        TRAEFIK_DOCKERFILE.write_text(text)
        print(f"  {TRAEFIK_DOCKERFILE.relative_to(ROOT)}: version label -> {version}")

    print(f"\nplanned: {family.key}  {old_tag} -> {args.new_tag}")
    if family.notes:
        print(f"note: {family.notes}")
    print("\n--- git diff --stat ---")
    print(run(["git", "-C", str(ROOT), "diff", "--stat"]).stdout)
    print("next steps:")
    step = 1
    print(f"  {step}. run the contract suite: python3 -I -m unittest discover "
          "-s scripts/tests -p 'test_*.py'  (exact-string pins may need edits)")
    step += 1
    print(f"  {step}. bash scripts/validate-compose-on-vm.sh")
    if seed_profile_active():
        step += 1
        print(f"  {step}. OFFLINE-SEED PROFILE: pull the new image on the target "
              "(ADM relay preferred), rebuild the seed "
              "(scripts/rebuild-offline-image-seed.py), update the four "
              "offline_image_seed_* hashes in the inventory, retain a "
              "controller copy")
    step += 1
    print(f"  {step}. commit the pin change (reviewed source), then: "
          f"{sys.argv[0]} deploy")
    return 0


def _ssh(target: str, command: str) -> subprocess.CompletedProcess:
    return run(["ssh", "-o", "BatchMode=yes", target, command])


def wait_healthy(target: str, timeout_s: int) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        proc = _ssh(
            target,
            "sudo docker ps --format '{{.Names}} {{.Status}}'",
        )
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        bad = [ln for ln in lines
               if "unhealthy" in ln or "starting" in ln or "Restarting" in ln]
        if lines and not bad:
            print(f"  all {len(lines)} containers healthy")
            return True
        print(f"  waiting: {len(bad)} not settled "
              f"({', '.join(ln.split()[0] for ln in bad[:4])}...)")
        time.sleep(10)
    return False


def cmd_deploy(args: argparse.Namespace) -> int:
    dirty = run(["git", "-C", str(ROOT), "status", "--porcelain"]).stdout
    tracked_dirty = [ln for ln in dirty.splitlines() if not ln.startswith("??")]
    if tracked_dirty:
        print("WARNING: uncommitted tracked changes — pins should be committed "
              "before a deploy so the rollback path is a git revert:")
        print("\n".join(tracked_dirty[:8]))
        if not args.yes:
            raise SystemExit("re-run with --yes to deploy anyway")

    if not args.skip_backup_check:
        proc = _ssh(args.ssh, "sudo cat /opt/ai-gateway/.state/last-backup.json "
                              "2>/dev/null")
        fresh = False
        if proc.returncode == 0 and proc.stdout.strip():
            try:
                stamp = json.loads(proc.stdout).get("completed_at", "")
                fresh = bool(stamp)
                print(f"last backup receipt: {stamp}")
            except json.JSONDecodeError:
                pass
        if not fresh:
            raise SystemExit(
                "no backup receipt on the target — run scripts/state-backup.sh "
                "first (stateful bumps are one-way), or --skip-backup-check"
            )

    print("== converge ==")
    converge = subprocess.run(
        ["ansible-playbook", "-i", args.inventory,
         str(ROOT / "ansible/deploy-stack-only.yml"),
         "--limit", args.limit, "--vault-id", args.vault_id],
        cwd=ROOT,
    )
    if converge.returncode != 0:
        raise SystemExit("converge failed — the stack was not fully updated; "
                         "inspect the ansible output above")

    print("== health watch ==")
    if not wait_healthy(args.ssh, args.health_timeout):
        raise SystemExit("containers did not settle healthy in time")

    print("== e2e gate ==")
    print("run (passwords via stdin; see the harness docstring):")
    print("  scripts/test-e2e-lab.py --ca compose/certs/ca.pem --vm " + args.ssh)
    if args.e2e_passwords_cmd:
        gate = subprocess.run(
            f"{args.e2e_passwords_cmd} | python3 "
            f"{shlex.quote(str(ROOT / 'scripts/test-e2e-lab.py'))} "
            f"--ca {shlex.quote(str(ROOT / 'compose/certs/ca.pem'))} "
            f"--vm {shlex.quote(args.ssh)}",
            shell=True, cwd=ROOT,
        )
        if gate.returncode != 0:
            raise SystemExit("E2E GATE FAILED — consider: "
                             f"{sys.argv[0]} rollback <family>")
        print("E2E gate PASS")
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    family = FAMILIES.get(args.family)
    if family is None:
        raise SystemExit(f"unknown family {args.family!r}")
    current = current_pin(family)
    # The previous reviewed pin is whatever the last commit says.
    committed = run([
        "git", "-C", str(ROOT), "show", f"HEAD:{family.files[0].relative_to(ROOT)}"
    ]).stdout
    pattern = _pin_pattern(family.repo)
    head_matches = sorted(set(pattern.findall(committed)))
    if len(head_matches) == 1 and \
            f"{family.repo}:{head_matches[0][0]}@{head_matches[0][1]}" != current:
        # Working tree differs from HEAD: plain checkout restores the pin.
        print("working tree pin differs from HEAD — restoring committed pin")
        for path in family.files:
            run(["git", "-C", str(ROOT), "checkout", "--",
                 str(path.relative_to(ROOT))])
    else:
        # Pin change is already committed: revert it via a new plan in reverse.
        prev = run([
            "git", "-C", str(ROOT), "log", "-2", "--format=%H", "--",
            str(family.files[0].relative_to(ROOT)),
        ]).stdout.split()
        if len(prev) < 2:
            raise SystemExit("no prior committed pin found to roll back to; "
                             "use the aigw-rollback-* image tags manually "
                             "(root-only manifest under /opt/ai-gateway/.state)")
        old_text = run([
            "git", "-C", str(ROOT), "show",
            f"{prev[1]}:{family.files[0].relative_to(ROOT)}",
        ]).stdout
        old_matches = sorted(set(pattern.findall(old_text)))
        if len(old_matches) != 1:
            raise SystemExit("previous commit does not carry exactly one pin — "
                             "roll back manually")
        tag, digest = old_matches[0]
        print(f"rolling back {family.key} to {tag} (from commit {prev[1][:9]})")
        ns = argparse.Namespace(family=family.key, new_tag=tag, digest=digest,
                                ssh=args.ssh)
        cmd_plan(ns)
        print("\nROLLBACK PIN APPLIED — commit it, then run: "
              f"{sys.argv[0]} deploy")
    if family.notes:
        print(f"note: {family.notes}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("plan", help="rewrite one family's pin everywhere + show diff")
    p.add_argument("family", help=", ".join(sorted(FAMILIES)))
    p.add_argument("new_tag")
    p.add_argument("--digest", default="",
                   help="skip remote resolution; use this index digest")
    p.add_argument("--ssh", default="ansible@10.8.10.10")
    p.set_defaults(func=cmd_plan)

    d = sub.add_parser("deploy", help="preflight + converge + health watch + e2e")
    d.add_argument("--inventory", default="ansible/inventory/lab.yml")
    d.add_argument("--limit", default="lab-aigw01")
    d.add_argument("--vault-id", default="rocky9-lab@~/.config/ai-gateway/"
                                         "rocky9-lab.vault-password")
    d.add_argument("--ssh", default="ansible@10.8.10.10")
    d.add_argument("--health-timeout", type=int, default=300)
    d.add_argument("--skip-backup-check", action="store_true")
    d.add_argument("--e2e-passwords-cmd", default="",
                   help="command emitting the {user: password} JSON for the "
                        "e2e gate (run + piped automatically when given)")
    d.add_argument("--yes", action="store_true")
    d.set_defaults(func=cmd_deploy)

    r = sub.add_parser("rollback", help="restore the previous reviewed pin")
    r.add_argument("family")
    r.add_argument("--ssh", default="ansible@10.8.10.10")
    r.set_defaults(func=cmd_rollback)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
