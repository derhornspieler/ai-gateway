from __future__ import annotations

from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / "ansible" / "roles" / "docker_stack" / "tasks" / "main.yml"
SITE = ROOT / "ansible" / "site.yml"


class AlloyAclReconcilerSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = TASKS.read_text()
        cls.site = SITE.read_text()
        cls.helper_block = cls.source.split(
            "- name: Install scoped Docker json-log ACL reconciler", 1
        )[1].split(
            "- name: Install scoped Docker json-log ACL reconciliation service", 1
        )[0]
        cls.unit_block = cls.source.split(
            "- name: Install scoped Docker json-log ACL reconciliation service", 1
        )[1].split("- name: Validate render-only Compose", 1)[0]

    def rendered_helper(self, docker_root: str = "/var/lib/docker") -> str:
        literal = self.helper_block.split("    content: |\n", 1)[1]
        rendered_lines = []
        for line in literal.splitlines():
            if line and not line.startswith("      "):
                break
            rendered_lines.append(line[6:] if line else "")
        return "\n".join(rendered_lines).replace(
            "{{ docker_data_root | quote }}", shlex.quote(docker_root)
        ).replace("{{ compose_project_name }}", "ai-gateway")

    def test_parent_acl_is_verified_and_only_containers_root_is_repaired(self) -> None:
        helper = self.helper_block
        containers_set = helper.index('/usr/bin/setfacl -m u:473:r-x "$root"')
        default_set = helper.index(
            '/usr/bin/setfacl -m d:u:473:--x,d:o:r-x "$root"'
        )
        child_walk = helper.index(
            '-exec /usr/bin/setfacl -m u:473:r-x {} +'
        )
        first_parent_verify = helper.index('require_access_acl "$state_root" --x')
        self.assertLess(first_parent_verify, containers_set)
        self.assertLess(containers_set, default_set)
        self.assertLess(default_set, child_walk)
        self.assertNotIn('/usr/bin/setfacl -m u:473:--x "$state_root"', helper)
        self.assertEqual(helper.count('require_access_acl "$state_root" --x'), 2)
        self.assertEqual(helper.count('require_access_acl "$root" r-x'), 2)
        self.assertEqual(helper.count('require_default_acl "$root" user 473 --x'), 2)
        self.assertIn('require_default_acl "$root" other \'\' r-x', helper)
        self.assertIn("/usr/bin/getfacl -cpn --", helper)
        self.assertIn("intersect_permissions", helper)
        self.assertNotIn("aigw-docker-root-acl", self.source)

    def test_every_mutated_child_is_validated_before_first_acl_write(self) -> None:
        helper = self.helper_block
        validation = helper.index("require_root_owned_real()")
        child_directory_check = helper.index("unexpected_child=$(/usr/bin/find")
        runtime_file_check = helper.index("unsafe_runtime_object=$(/usr/bin/find")
        symlink_check = helper.index("-type l -name '*-json.log*'")
        first_write = helper.index('/usr/bin/setfacl -m u:473:r-x "$root"')
        for check in (validation, child_directory_check, runtime_file_check, symlink_check):
            self.assertLess(check, first_write)
        for required in (
            '[[ -d "$state_root" && ! -L "$state_root" ]]',
            '[[ -d "$root" && ! -L "$root" ]]',
            '[[ ! -L "$path" ]]',
            '"$(/usr/bin/stat -c \'%u:%g\' -- "$path")" == 0:0',
            "\\( ! -type d -o ! -uid 0 -o ! -gid 0 \\)",
            "-type f \\( ! -uid 0 -o ! -gid 0 \\)",
            "unexpected type/owner beneath Docker containers root",
            "Docker runtime file must be owned by root:root",
            "refusing symlinked Docker json-log target",
        ):
            self.assertIn(required, helper)

    def test_helper_keeps_child_and_runtime_file_boundary_bounded(self) -> None:
        helper = self.helper_block
        for required in (
            "-xdev -mindepth 1 -maxdepth 1 -type d",
            "-exec /usr/bin/setfacl -m u:473:r-x {} +",
            "-xdev -mindepth 2 -maxdepth 2 -type f ! -name '*-json.log*'",
            "-xdev -mindepth 2 -maxdepth 2 -type f -name '*-json.log*'",
            "/usr/bin/docker --host unix:///run/docker.sock ps --no-trunc -q",
            "--filter 'label=com.docker.compose.project={{ compose_project_name }}'",
            "--filter 'label=com.docker.compose.service=alloy'",
            '[[ "${alloy_ids[0]}" =~ ^[0-9a-f]{64}$ ]]',
            "for runtime_file in hosts hostname resolv.conf",
        ):
            self.assertIn(required, helper)
        self.assertNotIn("-recursive", helper)
        self.assertNotIn("-maxdepth 3", helper)
        self.assertIn("unset DOCKER_CONFIG DOCKER_CONTEXT DOCKER_HOST", helper)
        self.assertIn("if ! alloy_output=$(", helper)
        self.assertNotIn("mapfile -t alloy_ids < <(", helper)

    def test_injected_root_paths_are_canonical_before_any_role_mutation(self) -> None:
        path_pattern = (
            r"^/(?:[A-Za-z0-9][A-Za-z0-9._-]{0,62})"
            r"(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,62}){0,15}$"
        )
        self.assertEqual(self.site.count(path_pattern), 2)
        self.assertIn("stack_dir | length <= 192", self.site)
        self.assertIn("docker_data_root | length <= 192", self.site)
        self.assertIn("stack_dir != docker_data_root", self.site)
        self.assertIn("not stack_dir.startswith(docker_data_root ~ '/')", self.site)
        self.assertIn("not docker_data_root.startswith(stack_dir ~ '/')", self.site)
        self.assertIn(
            "compose_project_name is match('^[a-z0-9][a-z0-9_-]{0,62}$')",
            self.site,
        )
        self.assertLess(
            self.site.index("stack_dir is match("), self.site.index("  roles:")
        )
        self.assertIn(
            "state_root={{ docker_data_root | quote }}", self.helper_block
        )

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

    def test_rendered_helper_is_valid_bash(self) -> None:
        result = subprocess.run(
            ["bash", "-n"],
            input=self.rendered_helper(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_docker_enumeration_failure_is_not_treated_as_zero_alloy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "docker"
            (root / "containers").mkdir(parents=True)
            tools = Path(temporary) / "tools"
            tools.mkdir()

            fake_sources = {
                "docker": "#!/usr/bin/env bash\necho synthetic-daemon-failure >&2\nexit 42\n",
                "find": "#!/usr/bin/env bash\nexit 0\n",
                "setfacl": "#!/usr/bin/env bash\nexit 0\n",
                "stat": "#!/usr/bin/env bash\nprintf '0:0\\n'\n",
                "getfacl": """#!/usr/bin/env bash
path=${!#}
if [[ "$path" == */containers ]]; then
  cat <<'EOF'
user::rwx
user:473:r-x
group::---
mask::r-x
other::---
default:user::rwx
default:user:473:--x
default:group::---
default:mask::r-x
default:other::r-x
EOF
else
  cat <<'EOF'
user::rwx
user:473:--x
group::---
mask::--x
other::---
EOF
fi
""",
            }
            rendered = self.rendered_helper(str(root))
            for name, source in fake_sources.items():
                executable = tools / name
                executable.write_text(source)
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
            "Docker failed to enumerate the running Alloy container", result.stderr
        )

    def test_systemd_sandbox_writes_only_the_containers_subtree(self) -> None:
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
            "BindReadOnlyPaths=/run/docker.sock",
            "ReadOnlyPaths={{ docker_data_root }}",
            "ReadWritePaths={{ docker_data_root }}/containers",
        ):
            self.assertIn(required, unit)
        self.assertNotIn("ReadWritePaths=/\n", unit)
        self.assertNotIn("ReadWritePaths={{ docker_data_root }}\n", unit)
        self.assertNotIn("ProtectSystem=false", unit)


if __name__ == "__main__":
    unittest.main()
