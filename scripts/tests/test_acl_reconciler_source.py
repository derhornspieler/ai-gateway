from __future__ import annotations

import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / "ansible" / "roles" / "docker_stack" / "tasks" / "main.yml"
OS_PREP = ROOT / "ansible" / "os-prep.yml"
OS_BASELINE = ROOT / "ansible" / "roles" / "os_baseline" / "tasks" / "main.yml"


class DockerLogAclReconcilerSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = TASKS.read_text(encoding="utf-8")
        cls.os_prep = OS_PREP.read_text(encoding="utf-8")
        cls.helper_block = cls.source.split(
            "- name: Install scoped Docker json-log ACL reconciler", 1
        )[1].split(
            "- name: Install scoped Docker json-log ACL reconciliation service", 1
        )[0]
        cls.unit_block = cls.source.split(
            "- name: Install scoped Docker json-log ACL reconciliation service", 1
        )[1].split(
            "- name: Validate static Vault server configuration in an isolated container",
            1,
        )[0]

    def rendered_helper(self, docker_root: str = "/var/lib/docker") -> str:
        literal = self.helper_block.split("    content: |\n", 1)[1]
        rendered_lines: list[str] = []
        for line in literal.splitlines():
            if line and not line.startswith("      "):
                break
            rendered_lines.append(line[6:] if line else "")
        return "\n".join(rendered_lines).replace(
            "{{ docker_data_root | quote }}", shlex.quote(docker_root)
        ).replace("{{ stack_dir | quote }}", shlex.quote("/opt/ai-gateway")).replace(
            "{{ compose_project_name }}", "ai-gateway"
        ).replace("{{ compose_project_name | quote }}", "'ai-gateway'")

    def test_reconciler_enumerates_only_the_exact_compose_project_tuple(self) -> None:
        helper = self.helper_block
        for required in (
            "/usr/bin/curl --unix-socket /run/docker.sock --noproxy '*'",
            "--data-urlencode 'filters={\"label\":[\"com.docker.compose.project={{ compose_project_name }}\"]}'",
            "http://localhost/containers/json?all=1",
            "--max-filesize 1048576",
            "com.docker.compose.project.working_dir",
            "com.docker.compose.config-hash",
            "Docker returned a container without the full AI Gateway Compose ownership tuple",
            'project_dir="$root/$identifier"',
            "require_root_owned_real \"$project_dir\" directory",
        ):
            self.assertIn(required, helper)
        self.assertNotIn("com.docker.compose.service=alloy", helper)
        self.assertNotIn("alloy_ids", helper)
        self.assertNotIn("-recursive", helper)
        self.assertIn("unset DOCKER_CONFIG DOCKER_CONTEXT DOCKER_HOST", helper)
        self.assertIn("HTTP_PROXY HTTPS_PROXY ALL_PROXY", helper)
        self.assertNotIn("/usr/bin/docker --host", helper)
        baseline = OS_BASELINE.read_text(encoding="utf-8")
        self.assertIn("- curl\n", baseline)

    def test_every_target_is_validated_before_the_first_acl_write(self) -> None:
        helper = self.helper_block
        validation = helper.index("# Validate every object that will be changed")
        first_write = helper.index('/usr/bin/setfacl -k -- "$project_dir"')
        self.assertLess(validation, first_write)
        for required in (
            "require_root_owned_real \"$candidate\" entry",
            "require_root_owned_real \"$candidate\" file",
            '[[ "$candidate" == *-json.log* ]]',
            '/usr/bin/find "$project_dir" -xdev -mindepth 1 -maxdepth 1 -print0',
            '[[ "$identifier" =~ ^[0-9a-f]{64}$ ]]',
        ):
            self.assertIn(required, helper)
        self.assertNotIn("-exec /usr/bin/setfacl", helper)
        self.assertNotIn("-maxdepth 2", helper)

    def test_no_default_acl_can_grant_future_nonproject_container_files(self) -> None:
        helper = self.helper_block
        for required in (
            "require_no_default_acl \"$root\"",
            "require_no_default_acl \"$project_dir\"",
            '/usr/bin/setfacl -k -- "$project_dir"',
            '/usr/bin/setfacl -m u:473:r-x "$project_dir"',
            '/usr/bin/setfacl -m u:473:r-- "$candidate"',
            '/usr/bin/setfacl -m u:473:--- "$candidate"',
        ):
            self.assertIn(required, helper)
        for forbidden in (
            "require_default_acl",
            "-m d:",
            "default:user",
            "aigw-docker-root-acl",
        ):
            self.assertNotIn(forbidden, helper)

    def test_injected_root_paths_are_canonical_before_any_role_mutation(self) -> None:
        path_pattern = (
            r"^/(?:[A-Za-z0-9][A-Za-z0-9._-]{0,62})"
            r"(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,62}){0,15}$"
        )
        self.assertGreaterEqual(self.os_prep.count(path_pattern), 2)
        self.assertIn("stack_dir | length <= 192", self.os_prep)
        self.assertIn("docker_data_root | length <= 192", self.os_prep)
        self.assertIn("stack_dir != docker_data_root", self.os_prep)
        self.assertIn("not stack_dir.startswith(docker_data_root ~ '/')", self.os_prep)
        self.assertIn("not docker_data_root.startswith(stack_dir ~ '/')", self.os_prep)
        self.assertIn(
            "compose_project_name is match('^[a-z0-9][a-z0-9_-]{0,62}$')",
            self.os_prep,
        )
        self.assertIn("state_root={{ docker_data_root | quote }}", self.helper_block)

        compiled = re.compile(path_pattern)
        for valid in ("/opt/ai-gateway", "/var/lib/docker", "/srv/a_b.c-1"):
            self.assertIsNotNone(compiled.fullmatch(valid), valid)
        for hostile in (
            "/var/lib/docker/../escape",
            "/var//lib/docker",
            "/var/lib/docker/",
            "/var/lib/docker\nReadWritePaths=/",
            "relative/path",
            "/var/lib/./docker",
        ):
            self.assertIsNone(compiled.fullmatch(hostile), hostile)

    def test_rendered_helper_is_valid_bash_for_a_nondefault_docker_root(self) -> None:
        result = subprocess.run(
            ["bash", "-n"],
            input=self.rendered_helper("/srv/docker-runtime"),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_trusted_container_ids_are_emitted_as_real_line_delimited_values(self) -> None:
        """A multi-container scan must not collapse IDs into one shell array item."""

        match = re.search(r"/usr/bin/python3 -I -c '([^']+)'", self.helper_block)
        self.assertIsNotNone(match)
        first_id = "a" * 64
        second_id = "b" * 64
        labels = {
            "com.docker.compose.project": "ai-gateway",
            "com.docker.compose.project.working_dir": "/opt/ai-gateway",
            "com.docker.compose.service": "alloy",
            "com.docker.compose.config-hash": "c" * 64,
        }
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                match.group(1),
                "ai-gateway",
                "/opt/ai-gateway",
            ],
            input=json.dumps(
                [
                    {"Id": first_id, "Labels": labels},
                    {"Id": second_id, "Labels": labels},
                ]
            ),
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [first_id, second_id])

        invalid_inventories = (
            [
                {
                    "Id": first_id,
                    "Labels": {
                        **labels,
                        "com.docker.compose.project.working_dir": "/tmp/other",
                    },
                }
            ],
            [
                {"Id": first_id, "Labels": labels},
                {"Id": first_id, "Labels": labels},
            ],
        )
        for inventory in invalid_inventories:
            rejected = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    match.group(1),
                    "ai-gateway",
                    "/opt/ai-gateway",
                ],
                input=json.dumps(inventory),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)

    def test_docker_enumeration_failure_is_not_treated_as_no_project_containers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "docker"
            (root / "containers").mkdir(parents=True)
            tools = Path(temporary) / "tools"
            tools.mkdir()
            fake_sources = {
                "curl": "#!/usr/bin/env bash\necho synthetic-daemon-failure >&2\nexit 42\n",
                "stat": "#!/usr/bin/env bash\nprintf '0:0\\n'\n",
                "getfacl": """#!/usr/bin/env bash
path=${!#}
if [[ "$path" == */containers ]]; then
  printf 'user::rwx\\nuser:473:r-x\\nmask::r-x\\n'
else
  printf 'user::rwx\\nuser:473:--x\\nmask::rwx\\n'
fi
""",
            }
            rendered = self.rendered_helper(str(root))
            for name, source in fake_sources.items():
                executable = tools / name
                executable.write_text(source, encoding="utf-8")
                executable.chmod(0o700)
                rendered = rendered.replace(f"/usr/bin/{name}", str(executable))

            result = subprocess.run(
                ["bash"],
                input=rendered,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Docker failed to enumerate AI Gateway project containers", result.stderr
        )

    def test_systemd_sandbox_writes_only_the_configured_containers_subtree(self) -> None:
        unit = self.unit_block
        for required in (
            "After=docker.service",
            "Requires=docker.service",
            "NoNewPrivileges=true",
            "PrivateDevices=true",
            "PrivateNetwork=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "ProtectKernelTunables=true",
            "ProtectKernelModules=true",
            "ProtectControlGroups=true",
            "RestrictAddressFamilies=AF_UNIX",
            "RestrictNamespaces=true",
            "CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER",
            "ReadOnlyPaths={{ docker_data_root }}",
            "ReadWritePaths={{ docker_data_root }}/containers",
        ):
            self.assertIn(required, unit)
        self.assertNotIn("BindReadOnlyPaths=/run/docker.sock", unit)
        self.assertNotIn("ReadWritePaths=/\n", unit)
        self.assertNotIn("ReadWritePaths={{ docker_data_root }}\n", unit)
        self.assertNotIn("ProtectSystem=false", unit)


if __name__ == "__main__":
    unittest.main()
