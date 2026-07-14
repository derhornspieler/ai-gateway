#!/usr/bin/env bash
# Render-only Compose validation with synthetic, non-production credentials.
# This script never starts containers and never needs access to the Ansible
# Vault overlay; compose/.env.example intentionally remains fail-closed.
set -euo pipefail
# This validator runs from both the controller source tree and the deployed
# root-owned stack. Never let a persisted Docker context redirect even its
# render-only Compose or isolated validation containers; retain DOCKER_CONFIG
# so a DHI credential remains available when Docker consults it.
unset DOCKER_CONTEXT DOCKER_HOST DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_API_VERSION

# This render gate is also used from the macOS controller. Select only the
# platform's conventional local Unix Docker socket; never fall back to an
# inherited context, DOCKER_HOST, or a TCP endpoint. The deployed Rocky 9
# path remains /run/docker.sock, while Docker Desktop exposes its user socket
# at /var/run/docker.sock on Darwin.
case "$(uname -s)" in
  Linux) docker_local_host=unix:///run/docker.sock ;;
  Darwin) docker_local_host=unix:///var/run/docker.sock ;;
  *) echo "unsupported OS for local-only Docker Compose validation" >&2; exit 1 ;;
esac
export AIGW_LOCAL_DOCKER_HOST="$docker_local_host"

# Assertions are release gates in the validation helpers. Isolated mode ignores
# PYTHONOPTIMIZE/PYTHONPATH/PYTHONHOME so an ambient controller environment
# cannot turn `assert` statements into no-ops or inject validation modules.
PYTHONOPTIMIZE=2 python3 -I -c \
  'import sys; raise SystemExit(0 if sys.flags.optimize == 0 else 1)'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_DIR="$ROOT/compose"
if [[ ! -f "$COMPOSE_DIR/docker-compose.yml" ]]; then
  # Deployed layout: Ansible places the allow-listed Compose files directly
  # at /opt/ai-gateway while retaining services/ and scripts/ beneath it.
  COMPOSE_DIR="$ROOT"
fi
# Compose files live under compose/ in the controller checkout but services/
# remains a sibling in both controller and deployed layouts.  Do not derive a
# service source path from COMPOSE_DIR or source validation will inspect a
# nonexistent compose/services tree.
SERVICES_DIR="$ROOT/services"

# Controller-source validation has no rendered .env, so retain the reviewed
# default. A deployed stack must instead validate the exact root that Ansible
# configured for Docker; never assume /var/lib/docker when the daemon owns a
# custom data-root. Parse only this non-secret key without sourcing .env.
docker_data_root=/var/lib/docker
if [[ "$COMPOSE_DIR" == "$ROOT" ]]; then
  docker_data_root="$(python3 -I - "$ROOT/.env" <<'PY'
import os
from pathlib import Path
import re
import stat
import sys

path = Path(sys.argv[1])
metadata = path.lstat()
if (not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or
        metadata.st_uid != 0 or metadata.st_gid != 0 or metadata.st_mode & 0o077):
    raise SystemExit("deployed .env must be a root-owned non-group-readable regular file")
values = []
for line in path.read_text(encoding="utf-8").splitlines():
    if line.startswith("DOCKER_DATA_ROOT="):
        values.append(line.split("=", 1)[1])
if len(values) != 1:
    raise SystemExit("deployed .env must define exactly one DOCKER_DATA_ROOT")
value = values[0]
if re.fullmatch(
    r"/(?:[A-Za-z0-9][A-Za-z0-9._-]{0,62})(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,62}){0,15}",
    value,
) is None:
    raise SystemExit("deployed DOCKER_DATA_ROOT is not canonical")
print(value)
PY
)"
fi

python3 -I - "$COMPOSE_DIR/bind-source-digest-inputs.json" <<'PY'
import json
from pathlib import PurePosixPath
import re
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
assert set(manifest) == {"base", "platform_dns", "lab_identity"}
service_pattern = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
segment_pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
assert set(manifest["base"]).isdisjoint(manifest["platform_dns"])
assert set(manifest["base"]).isdisjoint(manifest["lab_identity"])
assert set(manifest["platform_dns"]).isdisjoint(manifest["lab_identity"])
for profile in ("base", "platform_dns", "lab_identity"):
    assert isinstance(manifest[profile], dict) and manifest[profile]
    for service, sources in manifest[profile].items():
        assert service_pattern.fullmatch(service), service
        assert isinstance(sources, list) and sources, service
        assert len(sources) == len(set(sources)), service
        parsed = [PurePosixPath(source) for source in sources]
        for source in parsed:
            assert not source.is_absolute() and len(source.parts) <= 16, source
            assert all(segment_pattern.fullmatch(part) for part in source.parts), source
        assert not any(
            left in right.parents or right in left.parents
            for index, left in enumerate(parsed)
            for right in parsed[index + 1 :]
        ), service
PY

# Non-root DHI services must not inherit a restrictive controller umask for
# reviewed non-secret bind-mounted configuration. Private material has its own
# narrower Ansible ownership contract and is intentionally not checked here.
python3 -I - "$COMPOSE_DIR" <<'PY'
from pathlib import Path
import stat
import sys

root = Path(sys.argv[1])
for relative in (
    "traefik/traefik-int.yml",
    "traefik/traefik-adm.yml",
    "traefik/dynamic-int.yml",
    "traefik/dynamic-adm.yml",
    "grafana/provisioning/alerting/empty.yml",
    "grafana/provisioning/dashboards/dashboards.yml",
    "grafana/provisioning/dashboards/json/ai-gateway-live-logs.json",
    "grafana/provisioning/dashboards/json/ai-gateway-overview.json",
    "grafana/provisioning/dashboards/json/ai-gateway-request-audit.json",
    "grafana/provisioning/dashboards/json/edge-identity-services.json",
    "grafana/provisioning/dashboards/json/grafana-lgtm-stack.json",
    "grafana/provisioning/dashboards/json/rocky9-host.json",
    "grafana/provisioning/datasources/datasources.yml",
    "grafana/provisioning/plugins/empty.yml",
):
    path = root / relative
    assert path.is_file() and not path.is_symlink(), relative
    assert stat.S_IMODE(path.stat().st_mode) == 0o644, relative
for relative in (
    "traefik",
    "grafana",
    "grafana/provisioning",
    "grafana/provisioning/alerting",
    "grafana/provisioning/dashboards",
    "grafana/provisioning/dashboards/json",
    "grafana/provisioning/datasources",
    "grafana/provisioning/plugins",
):
    path = root / relative
    assert path.is_dir() and not path.is_symlink(), relative
    assert stat.S_IMODE(path.stat().st_mode) == 0o755, relative
PY

# Negative regression: even a hostile optimization environment cannot bypass
# the separate assert-based identity policy gate when invoked in isolated mode.
PYTHONOPTIMIZE=2 python3 -I "$ROOT/scripts/validate-identity-policy.py" >/dev/null

# Static regression for Vault 2.x recovery: the helper must stay stdin-only
# and hardened. This is deliberately source inspection, not an unseal call.
bash -n "$ROOT/scripts/vault-unseal.sh"
python3 -I - "$ROOT/scripts/vault-unseal.sh" <<'PY'
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_text()
for required in (
    'docker_cmd=(docker --host unix:///run/docker.sock)',
    'exec "${docker_cmd[@]}" run --rm -i',
    "--network net-vault",
    "--user 65532:65532",
    "--read-only",
    "--cap-drop ALL",
    "--security-opt no-new-privileges:true",
    "--log-driver none",
    "--entrypoint /usr/bin/python3",
    "sys.stdin.buffer.read(8193)",
    "urllib.request.ProxyHandler({})",
    "RejectRedirects()",
):
    assert required in text, required
assert "operator unseal" not in text
assert "VAULT_UNSEAL_KEY" not in text
PY
grep -Fq 'common_name="*.$DOMAIN" alt_names="$DOMAIN"' "$ROOT/scripts/vault-bootstrap.sh"

python3 -I - "$ROOT/scripts/validate-vault-config.sh" <<'PY'
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_text()
assert "$validation_dir/config.hcl:/vault/config/aigw.hcl:ro,Z" in text
assert "$STACK_DIR/vault/config.hcl:/vault/config/aigw.hcl" not in text
assert "trap cleanup EXIT HUP INT TERM" in text
assert "--security-opt no-new-privileges:true" in text
PY

# Every broad operational start must exclude the successful volume initializer.
bash -n "$ROOT/scripts/aigw-runtime-up.sh" \
  "$ROOT/scripts/vault-bootstrap.sh" "$ROOT/scripts/state-restore.sh" \
  "$ROOT/scripts/pre-upgrade-check.sh"
python3 -I - "$ROOT/scripts/aigw-runtime-up.sh" \
  "$ROOT/scripts/vault-bootstrap.sh" "$ROOT/scripts/state-restore.sh" <<'PY'
from pathlib import Path
import sys

runtime, bootstrap, restore = (Path(path).read_text() for path in sys.argv[1:])
for required in (
    "config --services",
    "initializer_count",
    '[[ "$service" == volume-init ]]',
    "up --no-deps --no-build",
):
    assert required in runtime, required
assert "aigw-runtime-up.sh" in bootstrap
assert "up -d --no-deps --force-recreate" in bootstrap
assert '"$STACK_DIR/scripts/aigw-runtime-up.sh" -d' not in restore
assert '"${compose[@]}" stop -t 60' in restore
assert restore.count("require_project_stopped") == 3
assert 'label=com.docker.compose.project=$PROJECT' in restore
assert "the captured graph is intentionally stopped" in restore
assert "full current-source Ansible converge" in restore
assert "rm -f -- .state/bind-digest.key" in restore
assert "unsafe .state boundary after restore" in restore
assert "up -d --build" not in restore
PY

# Controller-side persistence evidence must stay deterministic and outside the
# deployed operational-script trust boundary.  It is optional in the deployed
# layout by design; when the controller source is present, compile it, exercise
# its help path, and prove it cannot grow process/network/database clients.
SAFE_INVENTORY="$ROOT/scripts/safe-inventory-marker.py"
if [[ -f "$SAFE_INVENTORY" ]]; then
  python3 -I "$SAFE_INVENTORY" --help >/dev/null
  python3 -I - "$SAFE_INVENTORY" <<'PY'
import ast
from pathlib import Path
import sys

source = Path(sys.argv[1])
compile(source.read_bytes(), str(source), "exec")
tree = ast.parse(source.read_text(encoding="utf-8"))
imports = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        imports.update(alias.name.split(".", 1)[0] for alias in node.names)
    elif isinstance(node, ast.ImportFrom) and node.module:
        imports.add(node.module.split(".", 1)[0])
for forbidden in (
    "docker", "http", "psycopg", "requests", "socket", "sqlite3",
    "subprocess", "urllib",
):
    assert forbidden not in imports, forbidden
PY
fi

# The backup gate and Ansible build step must share one source/context/image-ID
# planner. Static validation is safe on both the controller and deployed host;
# it does not inspect images, read the rendered Compose model, or start anything.
python3 -I - "$ROOT/scripts/plan-compose-builds.py" \
  "$ROOT/scripts/pre-upgrade-check.sh" \
  "$ROOT/scripts/preserve-compose-rollbacks.py" <<'PY'
import json
from pathlib import Path
import re
import sys

planner = Path(sys.argv[1]).read_text()
gate = Path(sys.argv[2]).read_text()
rollback = Path(sys.argv[3]).read_text()
compile(planner, sys.argv[1], "exec")
compile(rollback, sys.argv[3], "exec")
for required in (
    'DOCKER_BINARY = "/usr/bin/docker"',
    '[DOCKER_BINARY, "--host", LOCAL_DOCKER_HOST, "image", "inspect", image]',
    'canonical_build["context"] = f"services/{relative_context.as_posix()}"',
    'b"aigw-compose-build-input/v2\\0"',
    'digest.update(struct.pack(">IQ", mode, size))',
    'legacy_record["digest"] = legacy_digest',
    'previous_record not in (record, legacy_record)',
):
    assert required in planner, required
assert 'scripts/plan-compose-builds.py' in gate
for required in (
    'MANIFEST_NAME = "compose-build-rollbacks.json"',
    'BUILD_INPUTS_NAME = "compose-build-inputs.json"',
    'ROLLBACK_SCHEMA = 2',
    'MAX_SERVICES = 256',
    'LOCAL_DOCKER_HOST = "unix:///run/docker.sock"',
    'env=FIXED_DOCKER_ENV',
    'docker.tag_image(source_image_id, rollback_image)',
    'source_image_id = _container_image(',
    'labels.get("com.docker.compose.container-number") != "1"',
    'restart_count = container.get("RestartCount")',
    'health.get("Status") == "healthy"',
    'docker.prove_key_rotator_dependency_gate(',
    'KEY_ROTATOR_READINESS_HEALTHCHECK',
    'and (not initialized or sealed)',
    '"status": "first-build"',
    'rollback_manifest_exists, existing_records = _load_existing_manifest_with_presence(',
    '_load_completed_build_inputs(build_inputs_path, project)',
    'os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW',
    'existing build-input receipt must be owned by root:root',
    'stack path must be owned by root:root',
    'stack path mode must be 0750',
    'source_digest = source_image_id.removeprefix("sha256:")',
    'is_first_build_retry = (',
    'existing_record["source_image_id"] == source_image_id',
    'existing_rollback_id = docker.inspect_image(',
    'def retire_first_build_records(',
    '"retired_services": sorted(retired)',
    'merged_records = dict(existing_records)',
    'os.replace(temporary_name, path)',
):
    assert required in rollback, required
assert "shell=True" not in rollback
stateful = gate.split("stateful=(", 1)[1].split(")", 1)[0].split()
for required in ("open-webui", "vault", "alloy", "prometheus", "loki", "tempo", "grafana", "samba-ad"):
    assert required in stateful, required

bind_digest_helper = Path(sys.argv[1]).parent / "compute-bind-source-digests.py"
bind_digest_source = bind_digest_helper.read_text()
compile(bind_digest_source, str(bind_digest_helper), "exec")
for required in (
    "hmac.new(",
    "sys.stdin.buffer.read(MAX_KEY_BYTES + 1)",
    "O_NOFOLLOW",
    "hard-linked bind source is forbidden",
    "bind source changed while hashing",
    "nested bind sources",
    "MAX_OBJECTS_PER_SERVICE",
    "MAX_BYTES_PER_SERVICE",
):
    assert required in bind_digest_source, required
for forbidden in ("subprocess", "socket", "urllib", "requests"):
    assert f"import {forbidden}" not in bind_digest_source

ansible = Path(sys.argv[1]).parents[1] / "ansible/roles/docker_stack/tasks/main.yml"
if ansible.is_file():
    source = ansible.read_text()
    stack_task = source.split("- name: Stack directory", 1)[1].split(
        "- name: Create allow-listed compose config directories", 1
    )[0]
    assert "owner: root" in stack_task
    assert "group: root" in stack_task
    assert 'mode: "0750"' in stack_task
    assert '"{{ stack_dir }}/scripts/plan-compose-builds.py"' in source
    assert '"{{ stack_dir }}/scripts/preserve-compose-rollbacks.py"' in source
    assert "import hashlib\n        import json\n        import os" not in source
    assert source.count("register: effective_compose_model") == 1
    preserve_task = source.index(
        "- name: Preserve exact running images for planned build rollback"
    )
    build_task = source.index(
        "- name: Build only missing or build-input-changed custom images"
    )
    marker_task = source.index(
        "- name: Persist deployed custom-image build-input manifest"
    )
    retire_task = source.index(
        "- name: Retire deployed first-build rollback retry proofs"
    )
    deploy_task = source.index(
        "- name: Deploy stack without implicitly rebuilding custom images"
    )
    assert preserve_task < build_task
    assert build_task < deploy_task < marker_task < retire_task
    assert "compose-build-rollbacks.json" in source[preserve_task:build_task]
    assert ").schema == 2" in source[preserve_task:build_task]
    assert "--retire-first-builds" in source[retire_task:]
    assert "retired_services | length > 0" in source[retire_task:]
    assert "compose_build_plan.services | length > 0" in source[preserve_task:build_task]
    assert ").updated_services |" in source[preserve_task:build_task]
    assert "difference((compose_rollback_preservation.stdout | from_json).services.keys()" in source[preserve_task:build_task]

    # Root-owned target code is an explicit flat manifest. A recursive copy
    # would silently deploy local unit tests, bytecode, editor metadata, or any
    # future file that happened to appear beneath scripts/.
    expected_scripts = (
        "aigw-compose.sh",
        "aigw-runtime-up.sh",
        "compute-bind-source-digests.py",
        "load-offline-image-seed.py",
        "plan-compose-builds.py",
        "preserve-compose-rollbacks.py",
        "pre-upgrade-check.sh",
        "reconcile-openwebui-key.py",
        "remove-lab-local-keycloak-users.py",
        "restore_archive.py",
        "rotate-vault-audit.sh",
        "state-backup.sh",
        "state-restore.sh",
        "test-portal-group-flow.py",
        "test-portal-identity-flow.py",
        "test-portal-key-lifecycle.py",
        "test-portal-login.py",
        "validate-build-contract.py",
        "validate-compose.sh",
        "validate-identity-policy.py",
        "validate-vault-config.sh",
        "vault-bootstrap.sh",
        "vault-unseal.sh",
        "verify-live-lab-identity.py",
    )
    manifest = re.search(
        r"(?ms)^    aigw_operational_scripts:\n"
        r"(?P<body>(?:      - [A-Za-z0-9._-]+\n)+)"
        r"  block:$",
        source,
    )
    assert manifest is not None, "operational-script manifest missing"
    deployed_scripts = tuple(
        re.findall(r"(?m)^      - ([A-Za-z0-9._-]+)$", manifest.group("body"))
    )
    assert deployed_scripts == expected_scripts, deployed_scripts
    assert all("/" not in name for name in deployed_scripts)
    assert not {"tests", "__pycache__", ".DS_Store"} & set(deployed_scripts)
    assert not any(name.endswith(".pyc") for name in deployed_scripts)
    # Evidence canonicalization is controller-side only: deploying it would
    # add production-host authority without any operational requirement.
    assert "safe-inventory-marker.py" not in deployed_scripts
    assert re.search(
        r'(?m)^\s*src:\s*"?\{\{ playbook_dir \}\}/\.\./scripts/"?\s*$',
        source,
    ) is None
    assert 'src: "{{ playbook_dir }}/../scripts/{{ item }}"' in source
    assert "../scripts/tests" not in source

    # Vanilla Rocky 9 keeps the table-name registry in /usr/share and has no
    # /etc/iproute2/rt_tables until an administrator creates an override.
    # Preflight must remain read-only, and the role must seed—not shadow—the
    # vendor names before adding the project block.
    site = ansible.parents[3] / "site.yml"
    site_source = site.read_text()
    # Full converge delegates the runtime SELinux transition to a dedicated
    # role, rather than duplicating its gates in site.yml.  Keep the static
    # release contract anchored to both the caller's desired state and the
    # role's effective-runtime proof.  Merely setting inventory variables must
    # never let Docker run while SELinux is disabled, permissive, or non-targeted.
    for required in (
        "aigw_selinux_policy == 'targeted'",
        "aigw_selinux_state == 'enforcing'",
        "- role: selinux_baseline",
        "- role: network_routing",
        "- role: firewalld_zones",
        "- role: os_baseline",
        "- role: docker_stack",
        "- role: verify",
    ):
        assert required in site_source, required
    assert site_source.index("- role: selinux_baseline") < site_source.index(
        "- role: network_routing"
    )
    assert site_source.index("- role: selinux_baseline") < site_source.index(
        "- role: firewalld_zones"
    )
    assert site_source.index("- role: selinux_baseline") < site_source.index(
        "- role: os_baseline"
    )
    selinux_baseline = ansible.parents[2] / "selinux_baseline/tasks/main.yml"
    selinux_baseline_source = selinux_baseline.read_text()
    for required in (
        "ansible.builtin.command: getenforce",
        "ansible.posix.selinux",
        "policy: \"{{ aigw_selinux_policy }}\"",
        "state: \"{{ aigw_selinux_state }}\"",
        "ansible_facts.selinux.status | default('disabled') == 'enabled'",
        "ansible_facts.selinux.mode | default('') == aigw_selinux_state",
        "ansible_facts.selinux.type | default('') == aigw_selinux_policy",
        "aigw_selinux_mode_after.stdout | trim == 'Enforcing'",
        "aigw_selinux_audit_window_start",
        "date +'%m/%d/%y %H:%M:%S'",
        "SELinux did not reach the required targeted/enforcing runtime state",
    ):
        assert required in selinux_baseline_source, required

    stack_only_source = (site.parent / "deploy-stack-only.yml").read_text()
    for required in (
        "ansible_facts.selinux.status == 'enabled'",
        "ansible_facts.selinux.mode == 'enforcing'",
        "ansible_facts.selinux.type == 'targeted'",
        "preflight_selinux_mode.stdout | trim == 'Enforcing'",
        "'name=selinux' in (stack_only_docker_info.stdout | from_json).SecurityOptions",
        "DockerRootDir == docker_data_root",
        "aigw_selinux_audit_window_start",
        "date +'%m/%d/%y %H:%M:%S'",
        "- role: verify",
    ):
        assert required in stack_only_source, required
    assert stack_only_source.index("- role: docker_stack") < stack_only_source.index(
        "- role: verify"
    )

    baseline = ansible.parents[2] / "os_baseline/tasks/main.yml"
    baseline_source = baseline.read_text()
    for required in (
        "- container-selinux",
        "- policycoreutils-python-utils",
        "- audit",
        '"selinux-enabled": true',
        "validate: /usr/bin/dockerd --validate --config-file %s",
        "Read whether Docker was already active before daemon configuration",
        "Restart an already-active Docker daemon after config change or missing SELinux support",
    ):
        assert required in baseline_source, required

    selinux_boundary = source.split(
        "- name: Define the exact SELinux read-only bind-source boundary", 1
    )[1].split("# DHI Alloy runs as uid 473", 1)[0]
    for required in (
        "community.general.sefcontext",
        "setype: container_ro_file_t",
        "restorecon",
        "'/certs'",
        "'/secrets/redis_password'",
        "'/secrets/redis_users.acl'",
        "'/secrets/samba_ad_admin_password'",
        "'/secrets/samba_ad_bind_password'",
    ):
        assert required in selinux_boundary, required
    bind_manifest = json.loads(
        (ansible.parents[3].parent / "compose/bind-source-digest-inputs.json").read_text()
    )
    manifest_sources = {
        path
        for profile in ("base", "platform_dns", "lab_identity")
        for paths in bind_manifest[profile].values()
        for path in paths
    }
    fcontext_rules = [
        (path.lstrip("/"), recursive == "true")
        for path, recursive in re.findall(
            r"\{'path': stack_dir ~ '(/[^']+)', 'recursive': (true|false)\}",
            selinux_boundary,
        )
    ]
    assert fcontext_rules

    def covered(source_path, rule):
        rule_path, recursive = rule
        return source_path == rule_path or (
            recursive and source_path.startswith(rule_path.rstrip("/") + "/")
        )

    assert all(any(covered(path, rule) for rule in fcontext_rules) for path in manifest_sources)
    assert all(any(covered(path, rule) for path in manifest_sources) for rule in fcontext_rules)
    assert "docker_data_root" not in selinux_boundary
    assert "{{ stack_dir }}:/" not in selinux_boundary
    assert "{{ docker_data_root }}/containers:/logs:ro" in source
    assert "- label=disable" in source
    assert "openwebui_reconcile_staging.path }}/reconcile.py:/reconcile.py:ro,Z" in source
    assert "{{ stack_dir }}/scripts/reconcile-openwebui-key.py:/reconcile.py" not in source
    assert "Remove private reconciliation staging directory" in source
    bind_digest_task = source.split(
        "- name: Compute keyed bind-source content digests", 1
    )[1].split("- name: Record the exact bind-source recreation contract", 1)[0]
    assert "aigw_bind_digest_key.content | b64decode" in bind_digest_task
    assert "stdin_add_newline: false" in bind_digest_task
    assert "no_log: true" in bind_digest_task
    assert "portal_session_secret" not in bind_digest_task
    for required in (
        ".state/bind-digest.key",
        "O_EXCL",
        "O_NOFOLLOW",
        "mode == '0600'",
        "stat.nlink | int) == 1",
        "stat.size | int) == 64",
    ):
        assert required in source, required
    selinux_inventory = source.split(
        "- name: Inventory every existing Docker container before persistent relabeling",
        1,
    )[1].split(
        "- name: Define the exact SELinux read-only bind-source boundary", 1
    )[0]
    assert "docker\n      - --host\n      - unix:///run/docker.sock\n      - ps\n      - -aq" in selinux_inventory
    assert "--filter" not in selinux_inventory
    restore_task = source.split(
        "- name: Apply the reviewed read-only container contexts before Compose", 1
    )[1].split("- name: Read effective SELinux contexts", 1)[0]
    assert (
        "when: aigw_containers_before_selinux.stdout_lines | length == 0"
        in restore_task
    )

    vault_validator = ansible.parents[3].parent / "scripts/validate-vault-config.sh"
    assert ":/vault/config/aigw.hcl:ro,Z" in vault_validator.read_text()
    canonical_path = r"^/(?:[A-Za-z0-9][A-Za-z0-9._-]{0,62})(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,62}){0,15}$"
    # stack_dir, docker_data_root, and the durable host marker are all
    # operator-provided absolute paths. Keep their canonical path validation
    # explicit so an existing-host converge cannot write an arbitrary marker.
    assert site_source.count(canonical_path) == 3
    assert "stack_dir | length <= 192" in site_source
    assert "docker_data_root | length <= 192" in site_source
    assert "stack_dir != docker_data_root" in site_source
    assert "not stack_dir.startswith(docker_data_root ~ '/')" in site_source
    assert "not docker_data_root.startswith(stack_dir ~ '/')" in site_source
    assert "aigw_docker_host_marker | length <= 192" in site_source
    assert "aigw_docker_host_marker is match(" in site_source
    assert "compose_project_name is match('^[a-z0-9][a-z0-9_-]{0,62}$')" in site_source
    assert site_source.index("stack_dir is match(") < site_source.index("  roles:")
    assert "/usr/share/iproute2/rt_tables" in site_source
    assert "preflight_rt_tables.content | b64decode" in site_source
    assert "argv: [cat, /etc/iproute2/rt_tables]" not in site_source
    routing = ansible.parents[2] / "network_routing/tasks/main.yml"
    routing_source = routing.read_text()
    assert "Seed the administrator registry from the Rocky vendor registry" in routing_source
    assert "src: /usr/share/iproute2/rt_tables" in routing_source
    assert "remote_src: true" in routing_source
    assert "Remove explicitly retired service-source artifacts" in source
    assert "egress-proxy/docker-entrypoint.sh" in source
    assert "mode: preserve" not in source
    for required in (
        "Reconcile the non-root Traefik private-key boundary",
        'group: "65532"',
        'mode: "0640"',
        "Require a root-only authenticated-restore marker",
        "Require restored Vault state instead of replacement initialization",
        "- -address=http://127.0.0.1:8200",
        "Require the encrypted controller Vault unseal key after initialization",
        "Automatically unseal initialized Vault from controller inventory",
        "Require automatic unseal for every initialized Vault deployment",
        "Bound the Vault bootstrap health exception to fresh uninitialized state",
    ):
        assert required in source, required
    assert (
        "      - vault\n"
        "      - status\n"
        "      - -address=http://127.0.0.1:8200\n"
        "      - -format=json\n"
    ) in source

    verify = ansible.parents[2] / "verify/tasks/main.yml"
    verify_source = verify.read_text()
    assert "{{ eth1_ip }}\", hostname: \"admin." not in verify_source
    assert "{{ eth2_ip }}\", hostname: \"portal." not in verify_source
    for required in (
        '{ address: "{{ traefik_int_portal_ip }}", hostname: "portal.',
        '{ address: "{{ traefik_int_chat_ip }}", hostname: "api.',
        '{ address: "{{ traefik_adm_admin_ip }}", hostname: "admin.',
        '{ address: "{{ traefik_adm_admin_ip }}", hostname: "admin-portal.',
        '{ address: "{{ traefik_adm_admin_ip }}", hostname: "litellm-admin.',
        'hostname: "admin.{{ aigw_domain }}", path: /, status: "303"',
        'hostname: "admin-portal.{{ aigw_domain }}", path: /healthz, status: "301"',
        'hostname: "litellm-admin.{{ aigw_domain }}", path: /, status: "302"',
        'hostname: "litellm-admin.{{ aigw_domain }}", path: /ui, status: "302"',
        "Host-origin traffic to",
        "a physical published address is deliberately denied",
        "register: grafana_datasource_graph",
        "retries: 12",
        "delay: 5",
        "until: grafana_datasource_graph.rc == 0",
        "file:/var/lib/grafana/grafana.db?mode=ro",
        '"{{ compose_project_name }}-grafana-1:ro"',
        "'name=selinux'",
        'disabled != {"alloy", "node-exporter"}',
        'proc_label != "system_u:system_r:spc_t:s0"',
        "container_t MCS ProcessLabel",
        "container_file_t MCS MountLabel",
        "container_var_lib_t",
        "private bind MCS drift",
        "shared bind context drift",
        "bind-objects=",
        "AVC,USER_AVC",
        "aigw_recent_selinux_denials.stdout | trim == ''",
        "aigw_recent_selinux_denials.stderr | trim == '<no matches>'",
    ):
        assert required in verify_source, required
    assert 'stdin: "{{ grafana_admin_password }}"' not in verify_source
PY

BUSYBOX_PIN='dhi.io/busybox:1.38.0-alpine@sha256:69a25015bda2c7dfac5d3a88990b56bc0f38539b313c448b171edef1497193ad'
for helper_script in rotate-vault-audit.sh state-backup.sh state-restore.sh; do
  [[ "$(grep -Fc "$BUSYBOX_PIN" "$ROOT/scripts/$helper_script")" -eq 1 ]]
done
! grep -Eq 'helper_image=.*(postgres|redis)|/usr/bin/tar' \
  "$ROOT/scripts/rotate-vault-audit.sh" \
  "$ROOT/scripts/state-backup.sh" \
  "$ROOT/scripts/state-restore.sh"

# Backup restart must preserve the exact pre-quiesce set without asking
# Compose to traverse dependencies and rerun the exited volume initializer.
python3 -I - "$ROOT/scripts/state-backup.sh" <<'PY'
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_text()
assert 'running_containers+=("${service_containers[@]}")' in text
assert text.count('"${docker_cmd[@]}" start "${running_containers[@]}"') == 2
assert '"${compose[@]}" start "${running[@]}"' not in text
assert 'if [[ "$logical" == openwebui_data ]]' in text
assert 'volume_tar_args=(--numeric-owner --exclude ./cache -czf - -C /source)' in text
PY

# The portal's owner+project issuance lock is process-local. Keep the reviewed
# one-container/one-worker topology executable as a release invariant until a
# distributed or database transaction lock replaces it. Its production Python
# graph must also stay complete, exact-pinned, and hash-locked: otherwise a
# future container rebuild can silently consume different transitive artifacts.
python3 -I - "$ROOT/services/dev-portal/Dockerfile" \
  "$ROOT/services/dev-portal/requirements.txt" \
  "$ROOT/services/dev-portal/requirements.lock" <<'PY'
import json
from pathlib import Path
import re
import sys

dockerfile = Path(sys.argv[1]).read_text()
commands = [
    line.removeprefix("CMD ")
    for line in dockerfile.splitlines()
    if line.startswith("CMD ")
]
assert len(commands) == 1
command = json.loads(commands[0])
assert command.count("--workers") == 1
index = command.index("--workers")
assert command[index + 1] == "1"
assert command.count("--no-access-log") == 1

assert "COPY requirements.txt requirements.lock ./" in dockerfile
builder = dockerfile.split("FROM ", 2)[1]
assert "--require-hashes" in builder
assert "-r requirements.lock" in builder
assert "-r requirements.txt" not in builder

direct = Path(sys.argv[2]).read_text().splitlines()
lock_text = Path(sys.argv[3]).read_text()
assert lock_text.startswith(
    "# This file was autogenerated by uv via the following command:\n"
    "#    uv pip compile requirements.txt --python-version 3.12 "
    "--python-platform linux --generate-hashes --output-file requirements.lock\n"
)

def canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()

direct_pins = {}
for raw in direct:
    requirement = raw.split("#", 1)[0].strip()
    if not requirement:
        continue
    match = re.fullmatch(r"([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?==([^\s;]+)", requirement)
    assert match is not None, f"direct portal dependency is not exact-pinned: {requirement}"
    direct_pins[canonical_name(match.group(1))] = match.group(2)

locked = {}
records = re.split(r"(?m)(?=^[A-Za-z0-9_.-]+==)", lock_text)[1:]
assert records, "portal dependency lock is empty"
for record in records:
    first = record.splitlines()[0]
    match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\\\s;]+) \\", first)
    assert match is not None, f"lock entry is not exact-pinned: {first}"
    assert "--hash=sha256:" in record, f"lock entry has no SHA-256 hash: {first}"
    name = canonical_name(match.group(1))
    assert name not in locked, f"duplicate lock entry: {name}"
    locked[name] = match.group(2)
assert direct_pins.items() <= locked.items(), (direct_pins, locked)
PY

env \
  COMPOSE_PROFILES=vault-ui \
  VAULT_UI_ENABLED=true \
  DOMAIN=aigw.internal \
  DOCKER_DATA_ROOT="$docker_data_root" \
  ETH1_IP=10.8.10.10 \
  ETH2_IP=10.20.0.10 \
  TRAEFIK_INT_CHAT_IP=172.28.3.2 \
  TRAEFIK_INT_PORTAL_IP=172.28.4.2 \
  TRAEFIK_ADM_ADMIN_IP=172.28.5.2 \
  OAUTH2_PROXY_LITELLM_IP=172.28.5.3 \
  TRAEFIK_ADM_GRAFANA_IP=172.28.6.2 \
  OAUTH2_PROXY_GRAFANA_IP=172.28.6.3 \
  ENVOY_EGRESS_IP=172.28.0.2 \
  ALLOY_INTERNAL_IP=172.28.2.2 \
  ALLOY_TELEMETRY_IP=172.28.13.2 \
  ALLOY_OBSERVABILITY_IP=172.28.15.2 \
  PROMETHEUS_OBSERVABILITY_IP=172.28.15.3 \
  TEMPO_INGEST_IP=172.28.16.2 \
  LAB_DNS_IP=172.28.18.2 \
  LAB_DNS_ADM_CIDR=10.8.10.0/24 \
  AIGW_BIND_DIGEST_TRAEFIK_INT=0000000000000000000000000000000000000000000000000000000000000001 \
  AIGW_BIND_DIGEST_TRAEFIK_ADM=0000000000000000000000000000000000000000000000000000000000000002 \
  AIGW_BIND_DIGEST_LITELLM=0000000000000000000000000000000000000000000000000000000000000003 \
  AIGW_BIND_DIGEST_OPEN_WEBUI=0000000000000000000000000000000000000000000000000000000000000004 \
  AIGW_BIND_DIGEST_KEYCLOAK=0000000000000000000000000000000000000000000000000000000000000005 \
  AIGW_BIND_DIGEST_VAULT=0000000000000000000000000000000000000000000000000000000000000006 \
  AIGW_BIND_DIGEST_POSTGRES=0000000000000000000000000000000000000000000000000000000000000007 \
  AIGW_BIND_DIGEST_REDIS=0000000000000000000000000000000000000000000000000000000000000008 \
  AIGW_BIND_DIGEST_ALLOY=0000000000000000000000000000000000000000000000000000000000000009 \
  AIGW_BIND_DIGEST_PROMETHEUS=000000000000000000000000000000000000000000000000000000000000000a \
  AIGW_BIND_DIGEST_LOKI=000000000000000000000000000000000000000000000000000000000000000b \
  AIGW_BIND_DIGEST_TEMPO=000000000000000000000000000000000000000000000000000000000000000c \
  AIGW_BIND_DIGEST_GRAFANA=000000000000000000000000000000000000000000000000000000000000000d \
  AIGW_BIND_DIGEST_CRIBL_MOCK=000000000000000000000000000000000000000000000000000000000000000e \
  AIGW_BIND_DIGEST_LAB_DNS=000000000000000000000000000000000000000000000000000000000000000f \
  AIGW_BIND_DIGEST_SAMBA_AD=0000000000000000000000000000000000000000000000000000000000000010 \
  AIGW_BIND_DIGEST_KEY_ROTATOR_LAB=0000000000000000000000000000000000000000000000000000000000000011 \
  PG_SUPER_PASSWORD=ValidationSuperPassword_0123456789 \
  PG_LITELLM_PASSWORD=ValidationLiteLLMPassword_0123456789 \
  PG_KEYCLOAK_PASSWORD=ValidationKeycloakPassword_0123456789 \
  PG_ROTATOR_PASSWORD=ValidationRotatorPassword_0123456789 \
  KC_ADMIN_PASSWORD=ValidationKeycloakAdmin_0123456789 \
  KC_BOOTSTRAP_ADMIN_CLIENT_SECRET=ValidationKeycloakBootstrapSecret01234567 \
  LITELLM_MASTER_KEY=sk-ValidationMasterKey_0123456789ABCDEF \
  LITELLM_SALT_KEY=ValidationSaltKey_0123456789ABCDEFGHIJ \
  REDIS_PASSWORD=ValidationRedisPassword_0123456789ABC \
  WEBUI_LITELLM_KEY=sk-ValidationVirtualKey_0123456789 \
  WEBUI_SECRET_KEY=ValidationStableWebuiSecret_0123456789ABC \
  WEBUI_OIDC_CLIENT_SECRET=ValidationWebuiOIDCSecret0123456789ABC \
  PORTAL_OIDC_CLIENT_SECRET=ValidationPortalOIDCSecret0123456789AB \
  ADMIN_PORTAL_OIDC_CLIENT_SECRET=ValidationAdminPortalOIDC0123456789AB \
  OAUTH2_PROXY_CLIENT_SECRET=ValidationOauth2ClientSecret0123456789A \
  OAUTH2_PROXY_LITELLM_COOKIE_SECRET=LitellmCookie0123456789ABCDEFGHI \
  OAUTH2_PROXY_GRAFANA_COOKIE_SECRET=GrafanaCookie0123456789ABCDEFGHI \
  OAUTH2_PROXY_PROMETHEUS_COOKIE_SECRET=PromCookie0123456789ABCDEFGHIJKL \
  OAUTH2_PROXY_VAULT_COOKIE_SECRET=VaultCookie0123456789ABCDEFGHIJK \
  PORTAL_SESSION_SECRET=ValidationPortalSession0123456789ABCDE \
  ADMIN_PORTAL_SESSION_SECRET=ValidationAdminPortalSession0123456789 \
  ROTATOR_INTERNAL_TOKEN=ValidationRotatorInternal0123456789ABCDE \
  PORTAL_IDENTITY_TOKEN=ValidationPortalIdentity0123456789ABCDE \
  ROTATOR_VAULT_TOKEN=ValidationVaultToken0123456789ABCDE \
  GRAFANA_ADMIN_PASSWORD=ValidationGrafanaAdmin_0123456789 \
  CRIBL_OTLP_ENDPOINT=cribl-mock:4317 \
  CRIBL_OTLP_INSECURE=true \
  CRIBL_OTLP_CA_FILE=/etc/ssl/certs/aigw-ca.pem \
  CRIBL_OTLP_SERVER_NAME=cribl-mock \
  sh -eu -c '
    docker --host "$AIGW_LOCAL_DOCKER_HOST" compose --project-directory "$1" -f "$2/docker-compose.yml" config -q
    base_services="$(docker --host "$AIGW_LOCAL_DOCKER_HOST" compose --project-directory "$1" -f "$2/docker-compose.yml" config --services)"
    vault_hash_enabled="$(docker --host "$AIGW_LOCAL_DOCKER_HOST" compose --project-directory "$1" -f "$2/docker-compose.yml" config --hash vault)"
    vault_volumes_enabled="$(docker --host "$AIGW_LOCAL_DOCKER_HOST" compose --project-directory "$1" -f "$2/docker-compose.yml" config --format json |
      python3 -I -c '\''import json,sys; config=json.load(sys.stdin); print(json.dumps({name: config["volumes"][name] for name in ("vault_data", "vault_audit")}, sort_keys=True, separators=(",", ":")))'\'')"
    disabled_services="$(COMPOSE_PROFILES= VAULT_UI_ENABLED=false docker --host "$AIGW_LOCAL_DOCKER_HOST" compose --project-directory "$1" -f "$2/docker-compose.yml" config --services)"
    vault_hash_disabled="$(COMPOSE_PROFILES= VAULT_UI_ENABLED=false docker --host "$AIGW_LOCAL_DOCKER_HOST" compose --project-directory "$1" -f "$2/docker-compose.yml" config --hash vault)"
    vault_volumes_disabled="$(COMPOSE_PROFILES= VAULT_UI_ENABLED=false docker --host "$AIGW_LOCAL_DOCKER_HOST" compose --project-directory "$1" -f "$2/docker-compose.yml" config --format json |
      python3 -I -c '\''import json,sys; config=json.load(sys.stdin); print(json.dumps({name: config["volumes"][name] for name in ("vault_data", "vault_audit")}, sort_keys=True, separators=(",", ":")))'\'')"
    test "$vault_hash_enabled" = "$vault_hash_disabled"
    test "$vault_volumes_enabled" = "$vault_volumes_disabled"
    COMPOSE_PROFILES= VAULT_UI_ENABLED=false docker --host "$AIGW_LOCAL_DOCKER_HOST" compose --project-directory "$1" -f "$2/docker-compose.yml" config --format json |
      python3 -I -c '\''
import json
import sys
base = set(sys.argv[1].splitlines())
disabled = set(sys.argv[2].splitlines())
model = json.load(sys.stdin)["services"]
assert base - disabled == {"oauth2-proxy-vault", "vault-ui-proxy"}
assert not disabled - base
assert "vault" in disabled
assert "vault" in model
assert "oauth2-proxy-vault" not in model
assert "vault-ui-proxy" not in model
assert model["traefik-adm"]["environment"]["VAULT_UI_ENABLED"] == "false"
'\'' "$base_services" "$disabled_services"
    redis_hash_before="$(docker --host "$AIGW_LOCAL_DOCKER_HOST" compose --project-directory "$1" -f "$2/docker-compose.yml" config --hash redis)"
    vault_hash_before="$(docker --host "$AIGW_LOCAL_DOCKER_HOST" compose --project-directory "$1" -f "$2/docker-compose.yml" config --hash vault)"
    initializer_hash_before="$(docker --host "$AIGW_LOCAL_DOCKER_HOST" compose --project-directory "$1" -f "$2/docker-compose.yml" config --hash volume-init)"
    redis_hash_after="$(AIGW_BIND_DIGEST_REDIS=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff docker --host "$AIGW_LOCAL_DOCKER_HOST" compose --project-directory "$1" -f "$2/docker-compose.yml" config --hash redis)"
    vault_hash_after="$(AIGW_BIND_DIGEST_REDIS=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff docker --host "$AIGW_LOCAL_DOCKER_HOST" compose --project-directory "$1" -f "$2/docker-compose.yml" config --hash vault)"
    initializer_hash_after="$(AIGW_BIND_DIGEST_REDIS=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff docker --host "$AIGW_LOCAL_DOCKER_HOST" compose --project-directory "$1" -f "$2/docker-compose.yml" config --hash volume-init)"
    test "$redis_hash_before" != "$redis_hash_after"
    test "$vault_hash_before" = "$vault_hash_after"
    test "$initializer_hash_before" = "$initializer_hash_after"
    docker --host "$AIGW_LOCAL_DOCKER_HOST" compose --project-directory "$1" -f "$2/docker-compose.yml" config --format json |
      python3 -I -c '\''
import json
import os
from pathlib import Path
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
project_root = Path(sys.argv[2])
docker_data_root = Path(os.environ["DOCKER_DATA_ROOT"]).resolve(strict=False)
services = json.load(sys.stdin)["services"]
assert "lab-dns" not in services
for name in (
    "oauth2-proxy", "oauth2-proxy-grafana",
    "oauth2-proxy-prometheus", "oauth2-proxy-vault",
):
    env = services[name]["environment"]
    assert env["OAUTH2_PROXY_COOKIE_REFRESH"] == "5m", name
    assert env["OAUTH2_PROXY_COOKIE_EXPIRE"] == "8h", name
    assert env["OAUTH2_PROXY_SCOPE"] == "openid email profile", name
    assert env["OAUTH2_PROXY_OIDC_EMAIL_CLAIM"] == "preferred_username", name
    assert env["OAUTH2_PROXY_SKIP_PROVIDER_BUTTON"] == "true", name
    assert env["OAUTH2_PROXY_OIDC_GROUPS_CLAIM"] == "roles", name
litellm_admin_proxy = services["oauth2-proxy"]["environment"]
assert litellm_admin_proxy["OAUTH2_PROXY_REDIRECT_URL"] == (
    "https://litellm-admin.aigw.internal/oauth2/callback"
)
assert litellm_admin_proxy["OAUTH2_PROXY_COOKIE_NAME"] == (
    "_aigw_litellm_admin_oauth"
)
assert litellm_admin_proxy["OAUTH2_PROXY_UPSTREAMS"] == "http://litellm:4000"
internal_edge = services["traefik-int"]
assert "net-int-edge" in internal_edge["networks"]
assert [name for name, service in services.items() if "net-int-edge" in service.get("networks", {})] == ["traefik-int"]
assert services["traefik-adm"]["environment"]["VAULT_UI_ENABLED"] == "true"
assert services["keycloak"]["user"] == "65532:65532"
assert "net-grafana" not in services["keycloak"]["networks"]
vault = services["vault"]
assert "VAULT_LOCAL_CONFIG" not in vault.get("environment", {})
assert vault["command"] == ["server", "-config=/vault/config/aigw.hcl"]
assert vault["cap_add"] == ["IPC_LOCK"]
assert vault["cap_drop"] == ["ALL"]
assert vault["security_opt"] == ["no-new-privileges:true"]
assert vault["ulimits"]["memlock"] == {"soft": -1, "hard": -1}
config_mount = next(v for v in vault["volumes"] if v["target"] == "/vault/config/aigw.hcl")
assert config_mount["type"] == "bind"
assert config_mount["read_only"] is True
vault_ui_proxy = services["vault-ui-proxy"]
assert vault_ui_proxy["image"] == "ai-gateway/dhi-vault-ui-proxy:2.0.3"
assert vault_ui_proxy["user"] == "1000:1000"
assert vault_ui_proxy["read_only"] is True
assert set(vault_ui_proxy["networks"]) == {"net-vault"}
assert "ports" not in vault_ui_proxy
assert "environment" not in vault_ui_proxy
assert vault_ui_proxy["depends_on"] == {
    "vault": {"condition": "service_started", "required": True}
}
assert services["oauth2-proxy-vault"]["environment"]["OAUTH2_PROXY_UPSTREAMS"] == (
    "http://vault-ui-proxy:8080"
)
assert services["oauth2-proxy-vault"]["depends_on"] == {
    "vault-ui-proxy": {"condition": "service_healthy", "required": True}
}
assert services["envoy-egress"]["healthcheck"]["test"] == ["CMD", "/usr/local/bin/aigw-envoy-entrypoint", "health"]
for edge in ("traefik-int", "traefik-adm"):
    assert services[edge]["user"] == "65532:65532"
    assert services[edge]["healthcheck"]["test"] == ["CMD", "traefik", "healthcheck"]
for proxy in (
    "oauth2-proxy", "oauth2-proxy-grafana",
    "oauth2-proxy-prometheus", "oauth2-proxy-vault",
):
    assert services[proxy]["healthcheck"]["test"] == [
        "CMD", "/usr/local/bin/aigw-health-probe", "http", "--url",
        "http://127.0.0.1:4180/ready",
    ]
assert services["open-webui"]["healthcheck"]["test"] == [
    "CMD", "/usr/local/bin/aigw-health-probe", "http", "--url",
    "http://127.0.0.1:8080/health",
]
assert services["vault-ui-proxy"]["healthcheck"]["test"] == [
    "CMD", "/usr/local/bin/vault-ui-proxy", "check",
]
litellm_probe = services["litellm"]["healthcheck"]["test"]
assert litellm_probe[:3] == ["CMD", "python3", "-c"]
assert len(litellm_probe) == 4
assert "http://127.0.0.1:4000/health/readiness" in litellm_probe[3]
assert "/health/liveliness" not in litellm_probe[3]
assert services["open-webui"]["build"]["dockerfile"] == "Dockerfile.open-webui"
assert services["open-webui"]["image"] == "ai-gateway/open-webui:0.10.2-aigw1"
assert services["open-webui"]["build"]["args"]["BASE_IMAGE"] == (
    "ghcr.io/open-webui/open-webui:v0.10.2@sha256:"
    "9fcea9c6e32ab60b0498f3986c6cdf651ddbe61db48d2213a3d28048ddd673d4"
)
assert services["open-webui"]["environment"]["WEBUI_SECRET_KEY"] == "ValidationStableWebuiSecret_0123456789ABC"
assert services["open-webui"]["environment"]["SSL_CERT_FILE"] == "/etc/ssl/certs/aigw-ca.pem"
assert services["open-webui"]["environment"]["WEBUI_SESSION_COOKIE_SECURE"] == "true"
assert services["open-webui"]["environment"]["WEBUI_AUTH_COOKIE_SECURE"] == "true"
open_webui = services["open-webui"]
assert open_webui["user"] == "65532:65532"
assert open_webui["read_only"] is True
assert open_webui["tmpfs"] == ["/tmp:rw,noexec,nosuid,nodev,mode=1777,size=256m"]
assert open_webui["environment"]["HOME"] == "/app/backend/data"
assert open_webui["environment"]["PYTHONNOUSERSITE"] == "1"
assert open_webui["environment"]["PYTHONDONTWRITEBYTECODE"] == "1"
assert open_webui["environment"]["STATIC_DIR"] == "/tmp/static"
assert open_webui["depends_on"]["volume-init"]["condition"] == "service_completed_successfully"
openwebui_mounts = {mount["target"]: mount for mount in open_webui["volumes"]}
assert openwebui_mounts["/app/backend/data"] == {
    "type": "volume", "source": "openwebui_data", "target": "/app/backend/data",
    "volume": {},
}
volume_init = services["volume-init"]
assert volume_init["logging"] == {
    "driver": "json-file",
    "options": {
        "max-size": "20m",
        "max-file": "5",
        "labels": "com.docker.compose.project,com.docker.compose.service",
    },
}
volume_init_mounts = {mount["target"]: mount for mount in volume_init["volumes"]}
assert volume_init_mounts["/state/openwebui"] == {
    "type": "volume", "source": "openwebui_data", "target": "/state/openwebui",
    "volume": {},
}
assert "chown -hR 65532:65532 /state/openwebui && chmod 0700 /state/openwebui" in volume_init["command"][0]
redis = services["redis"]
assert redis["user"] == "65532:65532"
assert "REDIS_PASSWORD" not in redis.get("environment", {})
assert redis["command"] == [
    "redis-server", "/etc/redis/redis.conf", "--bind", "0.0.0.0",
    "--save", "", "--appendonly", "no", "--aclfile",
    "/run/secrets/redis_users.acl", "--maxmemory", "384mb",
    "--maxmemory-policy", "allkeys-lru",
]
assert "ValidationRedisPassword_0123456789ABC" not in json.dumps(redis)
redis_mounts = {volume["target"]: volume for volume in redis["volumes"]}
assert set(redis_mounts) == {
    "/run/secrets/redis_users.acl", "/run/secrets/redis_password",
}
for target, mount in redis_mounts.items():
    assert mount["type"] == "bind", target
    assert mount["read_only"] is True, target
    assert mount["bind"]["selinux"] == "Z", target
assert redis["healthcheck"]["test"] == [
    "CMD", "/usr/local/bin/aigw-health-probe", "redis", "--password-file",
    "/run/secrets/redis_password",
]
prometheus_probe = services["prometheus"]["healthcheck"]["test"]
assert prometheus_probe == ["CMD", "/usr/local/bin/aigw-health-probe", "http", "--url", "http://172.28.15.3:9090/-/ready"]
alloy = services["alloy"]
assert alloy["user"] == "473:473"
assert alloy["cap_drop"] == ["ALL"]
assert alloy["healthcheck"]["test"] == [
    "CMD", "/usr/local/bin/aigw-health-probe", "http", "--url",
    "http://172.28.15.2:12345/-/ready", "--contains", "Alloy is ready.",
]
assert services["node-exporter"]["healthcheck"]["test"] == [
    "CMD", "/usr/local/bin/aigw-health-probe", "http", "--url",
    "http://127.0.0.1:9100/metrics", "--contains", "node_exporter_build_info",
]
node_exporter = services["node-exporter"]
assert node_exporter["user"] == "65532:65532"
assert node_exporter["read_only"] is True
assert node_exporter["tmpfs"] == [
    "/tmp",
    "/host/run:uid=65532,gid=65532,mode=0555,noexec,nosuid,nodev,size=1m",
]
assert len(node_exporter["volumes"]) == 1
node_exporter_root = node_exporter["volumes"][0]
assert set(node_exporter_root) == {
    "type", "source", "target", "read_only", "bind",
}
assert node_exporter_root | {"bind": {}} == {
    "type": "bind", "source": "/", "target": "/host", "read_only": True,
    "bind": {},
}
node_exporter_bind = node_exporter_root["bind"]
# Compose v2 emits create_host_path for short bind syntax while Compose v5
# omits that default. The source is `/` (necessarily present), so either
# representation has the same security boundary; keep every other bind field
# forbidden and continue requiring rslave explicitly.
assert set(node_exporter_bind) <= {"propagation", "create_host_path"}
assert node_exporter_bind["propagation"] == "rslave"
assert node_exporter_bind.get("create_host_path") in (None, True)
assert services["loki"]["healthcheck"]["test"] == [
    "CMD", "/usr/local/bin/aigw-health-probe", "http", "--url",
    "http://127.0.0.1:3100/ready",
]
assert services["tempo"]["healthcheck"]["test"] == ["CMD", "/opt/tempo/tempo", "--health"]
assert services["cribl-mock"]["healthcheck"]["test"] == [
    "CMD", "/usr/local/bin/aigw-health-probe", "http", "--url",
    "http://127.0.0.1:13133/",
]
# Every base long-running service has an exec-form application health contract.
# volume-init is the sole intentional exited-0 one-shot exception.
for name, service in services.items():
    if name == "volume-init":
        continue
    assert "healthcheck" in service, name
    assert service["healthcheck"]["test"][0] == "CMD", name
    assert service.get("labels", {}).get(
        "com.aigw.contract.selinux-generation"
    ) == "1", name
    assert "no-new-privileges:true" in service.get("security_opt", []), name
assert "com.aigw.contract.selinux-generation" not in services["volume-init"].get(
    "labels", {}
)
bind_digest_services = {
    "traefik-int", "traefik-adm", "litellm", "open-webui", "keycloak",
    "vault", "postgres", "redis", "alloy", "prometheus", "loki", "tempo",
    "grafana", "cribl-mock",
}
assert bind_digest_services == set(manifest["base"])
bind_digest_environment = {
    "traefik-int": "AIGW_BIND_DIGEST_TRAEFIK_INT",
    "traefik-adm": "AIGW_BIND_DIGEST_TRAEFIK_ADM",
    "litellm": "AIGW_BIND_DIGEST_LITELLM",
    "open-webui": "AIGW_BIND_DIGEST_OPEN_WEBUI",
    "keycloak": "AIGW_BIND_DIGEST_KEYCLOAK",
    "vault": "AIGW_BIND_DIGEST_VAULT",
    "postgres": "AIGW_BIND_DIGEST_POSTGRES",
    "redis": "AIGW_BIND_DIGEST_REDIS",
    "alloy": "AIGW_BIND_DIGEST_ALLOY",
    "prometheus": "AIGW_BIND_DIGEST_PROMETHEUS",
    "loki": "AIGW_BIND_DIGEST_LOKI",
    "tempo": "AIGW_BIND_DIGEST_TEMPO",
    "grafana": "AIGW_BIND_DIGEST_GRAFANA",
    "cribl-mock": "AIGW_BIND_DIGEST_CRIBL_MOCK",
}
assert set(bind_digest_environment) == bind_digest_services

def project_bind_sources(service):
    sources = set()
    for mount in service.get("volumes", []):
        if mount["type"] != "bind":
            continue
        source = Path(mount["source"])
        if not source.is_absolute():
            source = project_root / source
        try:
            sources.add(source.relative_to(project_root).as_posix())
        except ValueError:
            pass
    return sources

for name, service in services.items():
    assert project_bind_sources(service) == set(manifest["base"].get(name, [])), name
for name, service in services.items():
    marker = service.get("labels", {}).get(
        "com.aigw.contract.bind-source-digest"
    )
    if name in bind_digest_services:
        assert marker == os.environ[bind_digest_environment[name]], name
    else:
        assert marker is None, name

label_disabled = {
    name for name, service in services.items()
    if "label=disable" in service.get("security_opt", [])
}
assert label_disabled == {"alloy", "node-exporter"}, label_disabled
assert services["alloy"]["user"] == "473:473"
assert services["node-exporter"]["user"] == "65532:65532"
assert services["node-exporter"]["tmpfs"] == [
    "/tmp",
    "/host/run:uid=65532,gid=65532,mode=0555,noexec,nosuid,nodev,size=1m",
]
for name, service in services.items():
    for mount in service.get("volumes", []):
        if mount["type"] != "bind":
            continue
        source = mount["source"]
        relabel = mount.get("bind", {}).get("selinux")
        if name in label_disabled:
            assert relabel is None, (name, source, relabel)
            continue
        source_path = Path(source)
        assert source_path.is_absolute() and source_path != Path("/"), (name, source)
        try:
            source_path.resolve(strict=False).relative_to(docker_data_root)
        except ValueError:
            pass
        else:
            raise AssertionError((name, source, "Docker runtime bind requested relabel"))
        assert relabel in {"z", "Z"}, (name, source, relabel)
postgres = services["postgres"]
assert postgres["image"].startswith("dhi.io/postgres:16.14@sha256:")
assert any(v["target"] == "/var/lib/postgresql/16/data" for v in postgres["volumes"])
assert "cap_add" not in postgres
volume_init = services["volume-init"]
assert volume_init["network_mode"] == "none"
assert sorted(volume_init["cap_add"]) == ["CHOWN", "FOWNER", "FSETID"]
assert volume_init["cap_drop"] == ["ALL"]
assert "/state/grafana/plugins" not in "\n".join(volume_init["command"])
expected_dhi = {
    "oauth2-proxy", "oauth2-proxy-grafana", "oauth2-proxy-prometheus",
    "oauth2-proxy-vault", "keycloak", "vault", "postgres",
    "vault-ui-proxy",
    "redis", "alloy", "prometheus", "node-exporter", "loki", "tempo",
    "grafana", "cribl-mock",
}
for name in expected_dhi:
    service = services[name]
    image = service["image"]
    assert image.startswith("dhi.io/") or image.startswith("ai-gateway/dhi-"), (name, image)
grafana = services["grafana"]
assert grafana["environment"]["GF_PLUGINS_PREINSTALL"] == ""
assert grafana["environment"]["GF_AUTH_PROXY_WHITELIST"] == "172.28.6.3"
assert grafana["environment"]["GF_AUTH_BASIC_ENABLED"] == "false"
assert grafana["environment"]["GF_AUTH_DISABLE_LOGIN_FORM"] == "true"
grafana_tmpfs = {
    entry.split(":", 1)[0]: set(entry.split(":", 1)[1].split(","))
    for entry in grafana["tmpfs"]
}
assert len(grafana["tmpfs"]) == len(grafana_tmpfs) == 2
assert set(grafana_tmpfs) == {"/tmp", "/var/lib/grafana/plugins"}
for path, expected_options in {
    "/tmp": {"mode=1777"},
    "/var/lib/grafana/plugins": {
        "uid=65532", "gid=65532", "mode=0700", "noexec", "nosuid", "nodev",
    },
}.items():
    # Compose v5 preserves short-syntax options, while v2 may materialize the
    # implicit writable mode. Accept only those two canonical renderings.
    assert grafana_tmpfs[path] in (expected_options, expected_options | {"rw"})
assert services["oauth2-proxy-grafana"]["networks"]["net-grafana"]["ipv4_address"] == "172.28.6.3"
assert services["key-rotator"]["environment"]["KEYCLOAK_PUBLIC_URL"] == "https://auth.aigw.internal"
assert services["key-rotator"]["environment"]["WIF_KEYCLOAK_PUBLIC_URL"] == "https://idp.wif-a.example.invalid"
assert services["keycloak"].get("read_only", False) is False
portal = services["dev-portal"]
assert portal.get("command") in (None, [])
assert portal.get("entrypoint") in (None, [])
assert portal.get("deploy", {}).get("replicas", 1) == 1
admin_portal = services["admin-portal"]
assert admin_portal["image"] == portal["image"] == "ai-gateway/portal:1"
assert admin_portal["environment"]["OIDC_CLIENT_ID"] == "admin-portal"
assert admin_portal["environment"]["ROTATOR_INTERNAL_TOKEN"] == "ValidationRotatorInternal0123456789ABCDE"
assert portal["environment"]["ROTATOR_INTERNAL_TOKEN"] == "ValidationPortalIdentity0123456789ABCDE"
assert set(admin_portal["networks"]) == {"net-admin-app", "net-telemetry"}
assert set(portal["networks"]) == {"net-portal", "net-telemetry"}
'\'' "$2/bind-source-digest-inputs.json" "$1"
    docker --host "$AIGW_LOCAL_DOCKER_HOST" compose --project-directory "$1" -f "$2/docker-compose.yml" config --format json |
      python3 -I "$1/scripts/validate-build-contract.py" "$1" base
    docker --host "$AIGW_LOCAL_DOCKER_HOST" compose --project-directory "$1" -f "$2/docker-compose.yml" \
      -f "$2/docker-compose.platform-dns.yml" -f "$2/docker-compose.lab.yml" --profile lab-ad --profile vault-ui config --format json |
      python3 -I -c '\''
import json
import os
from pathlib import Path
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
project_root = Path(sys.argv[2])
docker_data_root = Path(os.environ["DOCKER_DATA_ROOT"]).resolve(strict=False)
config = json.load(sys.stdin)
assert "secrets" not in config
dns = config["services"]["lab-dns"]
assert dns.get("privileged", False) is False
assert dns["read_only"] is True
assert dns["user"] == "65532:65532"
assert dns["cap_drop"] == ["ALL"]
assert dns["cap_add"] == ["NET_BIND_SERVICE"]
assert dns["security_opt"] == ["no-new-privileges:true"]
assert list(dns["networks"]) == ["net-lab-dns"]
assert dns["build"]["network"] == "none"
assert dns["healthcheck"]["test"] == ["CMD", "/dns-healthcheck"]
assert dns["environment"] == {"LAB_DNS_ADM_CIDR": "10.8.10.0/24"}
ports = {(p.get("host_ip"), int(p["published"]), p["protocol"], int(p["target"])) for p in dns["ports"]}
assert ports == {
    ("10.8.10.10", 53, "tcp", 53),
    ("10.8.10.10", 53, "udp", 53),
    ("10.20.0.10", 53, "tcp", 53),
    ("10.20.0.10", 53, "udp", 53),
}
assert config["networks"]["net-lab-dns"]["external"] is True
assert all(v["read_only"] for v in dns["volumes"])
adm_zone = next(
    mount for mount in dns["volumes"]
    if mount["target"] == "/etc/coredns/zones/db.aigw.internal.adm"
)
assert adm_zone["type"] == "bind"
assert adm_zone["read_only"] is True
assert adm_zone["bind"]["selinux"] == "Z"
assert Path(adm_zone["source"]).name == "db.aigw.internal.adm"
samba = config["services"]["samba-ad"]
assert samba["healthcheck"]["test"] == ["CMD", "/usr/local/sbin/samba-ad-healthcheck"]
assert samba.get("labels", {}).get(
    "com.aigw.contract.selinux-generation"
) == "1"
samba_mounts = {mount["target"]: mount for mount in samba["volumes"]}
expected_samba_relabels = {
    "/run/secrets/samba_ad_admin_password": "Z",
    "/run/secrets/samba_ad_bind_password": "z",
    "/run/secrets/samba_user_lab-admin_password": "Z",
    "/run/secrets/samba_user_lab-developer_password": "Z",
    "/run/secrets/samba_user_lab-user_password": "Z",
}
for target, expected_relabel in expected_samba_relabels.items():
    mount = samba_mounts[target]
    assert mount["type"] == "bind", target
    assert mount["read_only"] is True, target
    assert mount["bind"]["selinux"] == expected_relabel, target
rotator_bind = next(
    mount for mount in config["services"]["key-rotator"]["volumes"]
    if mount["target"] == "/run/secrets/samba_keycloak_bind_password"
)
assert rotator_bind["type"] == "bind"
assert rotator_bind["read_only"] is True
assert rotator_bind["bind"]["selinux"] == "z"

bind_digest_services = {
    "traefik-int", "traefik-adm", "litellm", "open-webui", "keycloak",
    "vault", "postgres", "redis", "alloy", "prometheus", "loki", "tempo",
    "grafana", "cribl-mock", "lab-dns", "samba-ad", "key-rotator",
}
expected_bind_sources = dict(manifest["base"])
expected_bind_sources.update(manifest["platform_dns"])
expected_bind_sources.update(manifest["lab_identity"])
assert bind_digest_services == set(expected_bind_sources)
bind_digest_environment = {
    "traefik-int": "AIGW_BIND_DIGEST_TRAEFIK_INT",
    "traefik-adm": "AIGW_BIND_DIGEST_TRAEFIK_ADM",
    "litellm": "AIGW_BIND_DIGEST_LITELLM",
    "open-webui": "AIGW_BIND_DIGEST_OPEN_WEBUI",
    "keycloak": "AIGW_BIND_DIGEST_KEYCLOAK",
    "vault": "AIGW_BIND_DIGEST_VAULT",
    "postgres": "AIGW_BIND_DIGEST_POSTGRES",
    "redis": "AIGW_BIND_DIGEST_REDIS",
    "alloy": "AIGW_BIND_DIGEST_ALLOY",
    "prometheus": "AIGW_BIND_DIGEST_PROMETHEUS",
    "loki": "AIGW_BIND_DIGEST_LOKI",
    "tempo": "AIGW_BIND_DIGEST_TEMPO",
    "grafana": "AIGW_BIND_DIGEST_GRAFANA",
    "cribl-mock": "AIGW_BIND_DIGEST_CRIBL_MOCK",
    "lab-dns": "AIGW_BIND_DIGEST_LAB_DNS",
    "samba-ad": "AIGW_BIND_DIGEST_SAMBA_AD",
    "key-rotator": "AIGW_BIND_DIGEST_KEY_ROTATOR_LAB",
}
assert set(bind_digest_environment) == bind_digest_services

def project_bind_sources(service):
    sources = set()
    for mount in service.get("volumes", []):
        if mount["type"] != "bind":
            continue
        source = Path(mount["source"])
        if not source.is_absolute():
            source = project_root / source
        try:
            sources.add(source.relative_to(project_root).as_posix())
        except ValueError:
            pass
    return sources

for name, service in config["services"].items():
    assert project_bind_sources(service) == set(expected_bind_sources.get(name, [])), name
for name, service in config["services"].items():
    marker = service.get("labels", {}).get(
        "com.aigw.contract.bind-source-digest"
    )
    if name in bind_digest_services:
        assert marker == os.environ[bind_digest_environment[name]], name
    else:
        assert marker is None, name

label_disabled = {
    name for name, service in config["services"].items()
    if "label=disable" in service.get("security_opt", [])
}
assert label_disabled == {"alloy", "node-exporter"}, label_disabled
assert config["services"]["alloy"]["user"] == "473:473"
node_exporter = config["services"]["node-exporter"]
assert node_exporter["user"] == "65532:65532"
assert node_exporter["read_only"] is True
assert node_exporter["tmpfs"] == [
    "/tmp",
    "/host/run:uid=65532,gid=65532,mode=0555,noexec,nosuid,nodev,size=1m",
]
assert len(node_exporter["volumes"]) == 1
node_exporter_root = node_exporter["volumes"][0]
assert set(node_exporter_root) == {
    "type", "source", "target", "read_only", "bind",
}
assert node_exporter_root | {"bind": {}} == {
    "type": "bind", "source": "/", "target": "/host", "read_only": True,
    "bind": {},
}
node_exporter_bind = node_exporter_root["bind"]
assert set(node_exporter_bind) <= {"propagation", "create_host_path"}
assert node_exporter_bind["propagation"] == "rslave"
assert node_exporter_bind.get("create_host_path") in (None, True)
grafana = config["services"]["grafana"]
grafana_tmpfs = {
    entry.split(":", 1)[0]: set(entry.split(":", 1)[1].split(","))
    for entry in grafana["tmpfs"]
}
assert len(grafana["tmpfs"]) == len(grafana_tmpfs) == 2
assert set(grafana_tmpfs) == {"/tmp", "/var/lib/grafana/plugins"}
for path, expected_options in {
    "/tmp": {"mode=1777"},
    "/var/lib/grafana/plugins": {
        "uid=65532", "gid=65532", "mode=0700", "noexec", "nosuid", "nodev",
    },
}.items():
    assert grafana_tmpfs[path] in (expected_options, expected_options | {"rw"})
for name, service in config["services"].items():
    if name != "volume-init":
        assert service.get("labels", {}).get(
            "com.aigw.contract.selinux-generation"
        ) == "1", name
        assert "no-new-privileges:true" in service.get("security_opt", []), name
    for mount in service.get("volumes", []):
        if mount["type"] != "bind":
            continue
        source = mount["source"]
        relabel = mount.get("bind", {}).get("selinux")
        if name in label_disabled:
            assert relabel is None, (name, source, relabel)
            continue
        source_path = Path(source)
        assert source_path.is_absolute() and source_path != Path("/"), (name, source)
        try:
            source_path.resolve(strict=False).relative_to(docker_data_root)
        except ValueError:
            pass
        else:
            raise AssertionError((name, source, "Docker runtime bind requested relabel"))
        assert relabel in {"z", "Z"}, (name, source, relabel)
for name, service in config["services"].items():
    if name == "volume-init":
        continue
    assert "healthcheck" in service, name
    assert service["healthcheck"]["test"][0] == "CMD", name
'\'' "$2/bind-source-digest-inputs.json" "$1"
    docker --host "$AIGW_LOCAL_DOCKER_HOST" compose --project-directory "$1" -f "$2/docker-compose.yml" \
      -f "$2/docker-compose.platform-dns.yml" -f "$2/docker-compose.lab.yml" --profile lab-ad --profile vault-ui config --format json |
      python3 -I "$1/scripts/validate-build-contract.py" "$1" lab
  ' sh "$ROOT" "$COMPOSE_DIR"

grep -Fq 'LAB_DNS_ADM_CIDR: ${LAB_DNS_ADM_CIDR:?LAB_DNS_ADM_CIDR must be set}' "$COMPOSE_DIR/docker-compose.platform-dns.yml"
python3 -I - "$SERVICES_DIR/lab-dns/Corefile" <<'PY'
from pathlib import Path
import re
import sys

corefile = Path(sys.argv[1]).read_text(encoding="utf-8")
assert "view adm {" in corefile
assert "expr incidr(client_ip(), '{$LAB_DNS_ADM_CIDR}')" in corefile
assert "db.aigw.internal.adm" in corefile
assert re.search(r"(?m)^\s*forward(?:\s|$)", corefile) is None
PY

for config in "$COMPOSE_DIR/traefik/traefik-int.yml" "$COMPOSE_DIR/traefik/traefik-adm.yml"; do
  [[ "$(grep -Fc 'checkNewVersion: false' "$config")" -eq 1 ]]
  [[ "$(grep -Fc 'sendAnonymousUsage: false' "$config")" -eq 1 ]]
  [[ "$(grep -Fc '  format: json' "$config")" -eq 1 ]]
  [[ "$(grep -Fc '      ClientUsername: drop' "$config")" -eq 1 ]]
  [[ "$(grep -Fc '      RequestLine: drop' "$config")" -eq 1 ]]
  [[ "$(grep -Fc '      RequestPath: drop' "$config")" -eq 1 ]]
  [[ "$(grep -Fc '      defaultMode: drop' "$config")" -eq 2 ]]
  [[ "$(grep -Fc 'ping:' "$config")" -eq 1 ]]
  [[ "$(grep -Fc '  entryPoint: metrics' "$config")" -eq 2 ]]
done

python3 -I - "$COMPOSE_DIR/cribl-mock/config.yaml" <<'PY'
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_text()
assert "health_check:" in text
assert "endpoint: 127.0.0.1:13133" in text
assert "extensions: [health_check]" in text
PY

# Prompts are deliberately retained in Tempo/Cribl spans, not duplicated into
# PostgreSQL spend rows.  Keep the DB-side opt-out explicit: relying on an
# upstream default would make an otherwise routine LiteLLM upgrade a sensitive
# data-expansion event.
python3 -I - "$COMPOSE_DIR/litellm/config.yaml" <<'PY'
from pathlib import Path
import re
import sys

text = Path(sys.argv[1]).read_text()
assert text.count("general_settings:") == 1
assert text.count("router_settings:") == 1
general = text.split("general_settings:", 1)[1].split("router_settings:", 1)[0]
assert len(re.findall(r"(?m)^  store_prompts_in_spend_logs: false$", general)) == 1
assert "store_prompts_in_spend_logs: true" not in text
PY

python3 -I - "$COMPOSE_DIR/alloy/config.alloy" <<'PY'
from pathlib import Path
import re
import sys

text = Path(sys.argv[1]).read_text()
begin = "// BEGIN AIGW MANAGED CRIBL TLS"
end = "// END AIGW MANAGED CRIBL TLS"
assert text.count(begin) == text.count(end) == 1
lines = text.splitlines()
assert sum(line == f"    {begin}" for line in lines) == 1
assert sum(line == f"    {end}" for line in lines) == 1
assert not any(line == begin or line == end for line in lines)
managed = text.split(begin, 1)[1].split(end, 1)[0]
tls_only = ("ca_file", "server_name", "insecure_skip_verify", "min_version")
if "insecure = true" in managed:
    assert all(field not in managed for field in tls_only)
else:
    assert "insecure             = false" in managed
    assert all(field in managed for field in tls_only)

correlation_begin = "// BEGIN AIGW MANAGED TRACE CORRELATION"
correlation_end = "// END AIGW MANAGED TRACE CORRELATION"
assert text.count(correlation_begin) == text.count(correlation_end) == 1
correlation = text.split(correlation_begin, 1)[1].split(correlation_end, 1)[0]
assert 'otelcol.processor.transform "aigw_correlation"' in correlation
assert 'error_mode = "ignore"' in correlation
assert 'context = "span"' in correlation
assert text.count(
    'traces  = [otelcol.processor.transform.aigw_correlation.input]'
) == 1
assert text.count('traces  = [otelcol.processor.batch.default.input]') == 1
for canonical, source in (
    ('aigw.user.id', 'metadata.user_api_key_user_id'),
    ('aigw.api_key.id', 'metadata.user_api_key_hash'),
    ('aigw.request.id', 'litellm.call_id'),
    ('aigw.project.id', 'metadata.user_api_key_project_id'),
):
    assert canonical in correlation
    assert source in correlation
assert correlation.count('resource.attributes["service.name"] == "litellm"') == 5
assert correlation.count('name == "litellm_request"') == 5
assert '^[0-9a-f]{64}$' in correlation
assert 'aigw.api_key.alias' not in correlation
assert 'metadata.user_api_key_auth_metadata' in correlation
assert 'attributes["aigw.project.id"] == nil' in correlation
assert '(?P<project>[a-z0-9][a-z0-9_.-]{0,63})' in correlation
for forbidden in ('gen_ai.request.id', 'llm.user', 'authorization', 'access_token'):
    assert forbidden not in correlation

# Mirror the bounded RE2 project capture with representative Python-repr and
# JSON strings. Unsafe/malformed metadata must fail closed rather than emit a
# misleading first-class project correlation field.
project_capture = re.compile(
    r'''['"]aigw_project_id['"][ ]*:[ ]*['"]'''
    r'''(?P<project>[a-z0-9][a-z0-9_.-]{0,63})['"]'''
)
for sample in (
    "{'aigw_project_id': 'ai-gateway'}",
    '{"aigw_project_id": "project_1.prod"}',
):
    match = project_capture.search(sample)
    assert match and match.group('project') in {'ai-gateway', 'project_1.prod'}
for sample in (
    "{}",
    "{'aigw_project_id': ''}",
    "{'aigw_project_id': 'UPPER'}",
    "{'aigw_project_id': 'safe<script>'}",
    "{'aigw_project_id': 'a" + "b" * 64 + "'}",
    "{'aigw_project_id': 'safe-project}",
):
    assert project_capture.search(sample) is None
PY

# The volume initializer needs only ownership/mode capabilities. FSETID is
# necessary for its reviewed 2750 vault-audit contract after chgrp to gid 473.
grep -Fq 'cap_add: [CHOWN, FOWNER, FSETID]' "$COMPOSE_DIR/docker-compose.yml"
grep -Fq 'chmod 2750 /state/vault-audit' "$COMPOSE_DIR/docker-compose.yml"

acl_source="$ROOT/ansible/roles/docker_stack/tasks/main.yml"
acl_mode=source
acl_unit=/dev/null
if [[ ! -f "$acl_source" ]]; then
  # Deployed layout has the rendered reconciler and unit, not the controller's
  # Ansible source tree. Validate the live artifacts that the timer executes.
  acl_source=/usr/local/sbin/aigw-docker-log-acl
  acl_unit=/etc/systemd/system/aigw-docker-log-acl.service
  acl_mode=deployed
fi
python3 -I - "$acl_source" "$acl_mode" "$acl_unit" "$docker_data_root" <<'PY'
from pathlib import Path
import re
import sys

text = Path(sys.argv[1]).read_text()
mode = sys.argv[2]
docker_data_root = sys.argv[4]
assert re.fullmatch(
    r"/(?:[A-Za-z0-9][A-Za-z0-9._-]{0,62})(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,62}){0,15}",
    docker_data_root,
), docker_data_root
if mode == "source":
    acl_section = text.split("- name: Install scoped Docker json-log ACL reconciler", 1)[1].split(
        "- name: Install scoped Docker json-log ACL reconciliation service", 1
    )[0]
    assert "recursive: true\n" not in acl_section
    assert text.count("name: aigw-docker-log-acl.service") == 2
    assert "ExecStart=/usr/local/sbin/aigw-docker-log-acl" in text
    assert "aigw-docker-root-acl" not in text
    assert "state_root={{ docker_data_root | quote }}" in text
    # A pristine deployed host has no controller-side Ansible tree. Ensure the
    # exact helper and unit exist before the deployed validator inspects them,
    # while activation remains behind the later ACL boundary setup.
    render_gate = text.index(
        "- name: Validate render-only Compose and restricted build-network contracts"
    )
    assert text.index(
        "- name: Install scoped Docker json-log ACL reconciler"
    ) < render_gate
    assert text.index(
        "- name: Install scoped Docker json-log ACL reconciliation service"
    ) < render_gate
    assert text.index(
        "- name: Enable the scoped Docker json-log ACL timer"
    ) > render_gate
else:
    assert mode == "deployed"
    assert text.startswith("#!/usr/bin/env bash\nset -euo pipefail\n")
    assert "recursive: true" not in text
    unit = Path(sys.argv[3]).read_text()
    for required in (
        "Type=oneshot",
        "ExecStart=/usr/local/sbin/aigw-docker-log-acl",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        f"ReadOnlyPaths={docker_data_root}",
        f"ReadWritePaths={docker_data_root}/containers",
        "RestrictAddressFamilies=AF_UNIX",
    ):
        assert required in unit
    assert "BindReadOnlyPaths=/run/docker.sock" not in unit
for command in (
    "require_access_acl \"$state_root\" --x",
    "require_access_acl \"$root\" r-x",
    "require_no_default_acl \"$root\"",
    "/usr/bin/setfacl -k -- \"$project_dir\"",
    "/usr/bin/setfacl -m u:473:r-x \"$project_dir\"",
    "/usr/bin/setfacl -m u:473:--- \"$candidate\"",
    "/usr/bin/setfacl -m u:473:r-- \"$candidate\"",
    "/usr/bin/curl --unix-socket /run/docker.sock --noproxy '*'",
    "--connect-timeout 5 --max-time 10",
    "--max-filesize 1048576",
    "http://localhost/containers/json?all=1",
    "filters={\"label\":[\"com.docker.compose.project=",
    "com.docker.compose.project.working_dir",
    "com.docker.compose.config-hash",
    "/usr/bin/find \"$project_dir\" -xdev -mindepth 1 -maxdepth 1 -print0",
):
    assert command in text
for forbidden in (
    "require_default_acl",
    "-m d:",
    "com.docker.compose.service=alloy",
    "-exec /usr/bin/setfacl",
    "/usr/bin/docker --host",
):
    assert forbidden not in text
PY

firewall_role="$ROOT/ansible/roles/firewalld_zones/tasks/main.yml"
verify_role="$ROOT/ansible/roles/verify/tasks/main.yml"
if [[ -f "$firewall_role" && -f "$verify_role" ]]; then
  python3 -I - "$firewall_role" "$verify_role" <<'PY'
from pathlib import Path
import sys

firewall = Path(sys.argv[1]).read_text()
verify = Path(sys.argv[2]).read_text()

nm_start = firewall.index(
    "- name: Read the active NetworkManager connection UUID for each physical interface"
)
bind = firewall.index("- name: Bind interfaces to project zones")
nm_section = firewall[nm_start:bind]
assert nm_start < bind
for required in (
    "GENERAL.CON-UUID",
    "connection.zone",
    "nmcli",
    "connection\n      - modify",
    "Prove saved NetworkManager firewalld zones before any later reload",
):
    assert required in nm_section
for forbidden in (
    "connection\n      - up",
    "device\n      - reapply",
):
    assert forbidden not in nm_section
assert "item.item.target | replace('%%', '')" in firewall
for required in (
    "firewalld — exact runtime and saved-profile zone ownership",
    '"--get-zone-of-interface", interface',
    '"connection.zone"',
    '"--permanent", f"--zone={expected}", "--list-interfaces"',
):
    assert required in verify
PY
fi

python3 -I - "$ROOT/scripts/reconcile-openwebui-key.py" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text()
compile(source, str(path), "exec")
for required in (
    'ALIAS = "aigw-open-webui-service"',
    'USER_ID = "svc-open-webui"',
    'MODELS = ["claude-sonnet", "claude-haiku", "gpt"]',
    'ROUTES = ["/v1/models", "/v1/chat/completions"]',
    '"aigw_key_kind": "service"',
    '"aigw_service": "open-webui"',
    '"aigw_project_id": "open-webui"',
    'lookup(master, "key_alias", ALIAS)',
    'lookup(master, "key_hash", token_hash)',
    'payload={**payload, "key": token_hash}',
    'if candidate == master:',
):
    assert required in source
for forbidden in ("service_account_id", "key_type", "team_id"):
    assert forbidden not in source
PY

echo "Base and lab Compose configurations are valid (render-only; no containers started)."
