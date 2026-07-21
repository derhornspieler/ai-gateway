from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "plan-compose-builds.py"
ROOT = SCRIPT.parents[1]
STACK_TASKS = (ROOT / "ansible/roles/docker_stack/tasks/main.yml").read_text()
SPEC = importlib.util.spec_from_file_location("plan_compose_builds", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
planner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(planner)


class ComposeBuildPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.stack = Path(temporary.name)
        self.context = self.stack / "services" / "stateful-app"
        self.context.mkdir(parents=True)
        self.dockerfile = self.context / "Dockerfile"
        self.dockerfile.write_text("FROM scratch\n")
        self.state = self.stack / ".state" / "compose-build-inputs.json"
        self.state.parent.mkdir()
        self.model = {
            "services": {
                "stateful-app": {
                    "build": {"context": str(self.context), "network": "none"},
                    "image": "ai-gateway/stateful-app:stable",
                },
                "pulled-only": {"image": "example.invalid/pulled@sha256:" + "a" * 64},
            }
        }

    @staticmethod
    def image_id(_image: str) -> str:
        return "sha256:" + "b" * 64

    def test_unsafe_artifact_contract_matches_target_staging(self) -> None:
        self.assertEqual(
            planner.UNSAFE_DIRECTORY_NAMES,
            {
                "__pycache__",
                ".pytest_cache",
                ".ruff_cache",
                ".venv",
                "venv",
                ".tox",
                "node_modules",
                ".git",
                "secrets",
            },
        )
        self.assertEqual(planner.UNSAFE_FILE_NAMES, {".env"})
        self.assertEqual(planner.UNSAFE_FILE_PREFIXES, (".env.",))
        self.assertEqual(
            planner.UNSAFE_FILE_SUFFIXES,
            (".pyc", ".pyo", ".pyd", ".key", ".p12", ".pfx"),
        )
        self.assertEqual(
            planner.STAGED_EXECUTABLE_NAMES,
            {
                "policy-rc.d",
                "samba-ad-entrypoint",
                "samba-ad-healthcheck",
                "samba-ad-secret-tool",
            },
        )
        self.assertEqual(planner.STAGED_DIRECTORY_MODE, 0o755)
        self.assertEqual(planner.STAGED_FILE_MODE, 0o644)
        self.assertEqual(planner.STAGED_EXECUTABLE_MODE, 0o755)
        self.assertIn(
            "['policy-rc.d', 'samba-ad-entrypoint', 'samba-ad-healthcheck',\n"
            "             'samba-ad-secret-tool'] or item.path is regex('.*\\.sh$')",
            STACK_TASKS,
        )
        self.assertIn("else '0644'", STACK_TASKS)
        cleanup = STACK_TASKS.split(
            "- name: Find stale unsafe build-context artifacts", 1
        )[1].split("  register: stale_service_artifacts", 1)[0]
        expected_cleanup_patterns = set(planner.UNSAFE_DIRECTORY_NAMES) | {
            *planner.UNSAFE_FILE_NAMES,
            *(f"*{suffix}" for suffix in planner.UNSAFE_FILE_SUFFIXES),
            ".env.*",
        }
        for pattern in expected_cleanup_patterns:
            self.assertRegex(
                cleanup,
                rf"(?m)^\s+- [\"']?{re.escape(pattern)}[\"']?$",
                pattern,
            )
        self.assertIn(
            "item.path is not regex('(^|/)\\.env(?:\\.|$)|\\.(?:pyc|pyo|pyd|key|p12|pfx)$')",
            STACK_TASKS,
        )

        for service in ("dev-portal", "key-rotator"):
            rules = set(planner.DOCKERIGNORE_RULES[service])
            for directory in planner.UNSAFE_DIRECTORY_NAMES:
                self.assertIn(f"**/{directory}/", rules, service)
            self.assertIn("**/*.py[cod]", rules, service)
            for suffix in (".key", ".p12", ".pfx"):
                self.assertIn(f"**/*{suffix}", rules, service)
            self.assertTrue({".env", ".env.*", "**/.env", "**/.env.*"} <= rules)
        self.assertEqual(
            planner.GENERATED_BIND_ONLY_FILES,
            {
                "platform-dns": {
                    "Corefile",
                    "db.aigw.internal",
                    "db.aigw.internal.adm",
                }
            },
        )
        self.assertEqual(
            planner.DOCKER_IGNORED_PREFIXES,
            {
                "dev-portal": ("tests/",),
                "key-rotator": ("tests/",),
            },
        )

    def plan(self):
        return planner.plan_compose_builds(
            self.model,
            stack=self.stack,
            state_path=self.state,
            project="ai-gateway",
            image_inspector=self.image_id,
        )

    def persist(self, result) -> None:
        self.state.write_text(json.dumps(result["manifest"]))

    def test_source_drift_plans_stable_image_tag(self) -> None:
        initial = self.plan()
        self.assertEqual(initial["services"], ["stateful-app"])
        self.persist(initial)

        unchanged = self.plan()
        self.assertEqual(unchanged["services"], [])

        self.dockerfile.write_text("FROM scratch\nLABEL revision=two\n")
        drifted = self.plan()
        self.assertEqual(drifted["services"], ["stateful-app"])
        self.assertEqual(
            drifted["manifest"]["services"]["stateful-app"]["image"],
            "ai-gateway/stateful-app:stable",
        )
        self.assertEqual(
            drifted["manifest"]["services"]["stateful-app"]["image_id"],
            self.image_id("unused"),
        )

    def test_missing_local_image_is_always_planned(self) -> None:
        baseline = self.plan()
        self.persist(baseline)
        result = planner.plan_compose_builds(
            self.model,
            stack=self.stack,
            state_path=self.state,
            project="ai-gateway",
            image_inspector=lambda _image: None,
        )
        self.assertEqual(result["services"], ["stateful-app"])

    def test_workstation_and_secret_artifacts_do_not_change_release_digest(self) -> None:
        initial = self.plan()
        initial_digest = initial["manifest"]["services"]["stateful-app"]["digest"]

        for directory_name in planner.UNSAFE_DIRECTORY_NAMES:
            directory = self.context / directory_name
            directory.mkdir()
            (directory / "local-only.txt").write_text("not an image input\n")
        for filename in planner.UNSAFE_FILE_NAMES:
            (self.context / filename).write_text("local only\n")
        for suffix in planner.UNSAFE_FILE_SUFFIXES:
            (self.context / f"local-only{suffix}").write_text("local only\n")
        for prefix in planner.UNSAFE_FILE_PREFIXES:
            (self.context / f"{prefix}local").write_text("local only\n")

        with_artifacts = self.plan()
        self.assertEqual(
            with_artifacts["manifest"]["services"]["stateful-app"]["digest"],
            initial_digest,
        )

        reviewed = self.context / "reviewed.py"
        reviewed.write_text("print('reviewed')\n")
        self.assertNotEqual(
            self.plan()["manifest"]["services"]["stateful-app"]["digest"],
            initial_digest,
        )

    def test_checkout_modes_match_a_target_style_staged_tree(self) -> None:
        script = self.context / "start.sh"
        script.write_text("#!/bin/sh\nexit 0\n")
        script.chmod(0o600)
        self.dockerfile.chmod(0o600)
        private_checkout_digest = self.plan()["manifest"]["services"][
            "stateful-app"
        ]["digest"]

        for directory in [self.context, *self.context.iterdir()]:
            if directory.is_dir():
                directory.chmod(0o755)
        self.dockerfile.chmod(0o644)
        script.chmod(0o755)
        staged_digest = self.plan()["manifest"]["services"]["stateful-app"][
            "digest"
        ]

        self.assertEqual(private_checkout_digest, staged_digest)

    def test_symlink_and_special_context_entries_fail_closed(self) -> None:
        outside = self.stack / "outside.txt"
        outside.write_text("outside\n")
        (self.context / "linked.txt").symlink_to(outside)
        with self.assertRaisesRegex(planner.PlanError, "symlinks are not staged"):
            self.plan()

    def test_platform_dns_rendered_bind_files_are_not_image_inputs(self) -> None:
        context = self.stack / "services" / "platform-dns"
        context.mkdir()
        context.joinpath("Dockerfile").write_text("FROM scratch\n")
        context.joinpath("healthcheck.go").write_text("package main\n")
        context.joinpath(".dockerignore").write_text(
            "*\n!Dockerfile\n!healthcheck.go\n"
        )
        for filename in planner.GENERATED_BIND_ONLY_FILES["platform-dns"]:
            context.joinpath(filename).write_text(
                "rendered for customer.example\n"
            )
        self.model["services"]["stateful-app"]["build"]["context"] = str(context)

        rendered_digest = self.plan()["manifest"]["services"]["stateful-app"][
            "digest"
        ]
        for filename in planner.GENERATED_BIND_ONLY_FILES["platform-dns"]:
            context.joinpath(filename).write_text(
                "rendered for a different.example domain and address\n"
            )
        self.assertEqual(
            self.plan()["manifest"]["services"]["stateful-app"]["digest"],
            rendered_digest,
        )

        context.joinpath("healthcheck.go").write_text("package main // changed\n")
        self.assertNotEqual(
            self.plan()["manifest"]["services"]["stateful-app"]["digest"],
            rendered_digest,
        )

    def test_every_current_dockerignore_matches_the_explicit_planner_contract(self) -> None:
        services = ROOT / "services"
        contexts = {
            path.parent.name for path in services.glob("*/.dockerignore")
        }
        self.assertEqual(
            contexts,
            {
                "dev-portal",
                "dhi-health-probe",
                "egress-proxy",
                "key-rotator",
                "platform-dns",
                "samba-ad-preprod",
                "traefik",
                "vault-ui-proxy",
                "wif-provider-mock",
            },
        )
        self.assertEqual(contexts, set(planner.DOCKERIGNORE_RULES))
        for context_name in sorted(contexts):
            self.assertEqual(
                tuple(
                    (services / context_name / ".dockerignore")
                    .read_text()
                    .splitlines()
                ),
                planner.DOCKERIGNORE_RULES[context_name],
                context_name,
            )

        leading_star = contexts - {"dev-portal", "key-rotator"}
        for context_name in sorted(leading_star):
            lines = (services / context_name / ".dockerignore").read_text().splitlines()
            self.assertEqual(lines[0], "*", context_name)
        for context_name in ("dev-portal", "key-rotator"):
            lines = set(
                (services / context_name / ".dockerignore").read_text().splitlines()
            )
            self.assertTrue(
                {".env.*", "tests/"}.issubset(lines), context_name
            )

        bind_inputs = json.loads(
            (ROOT / "compose/bind-source-digest-inputs.json").read_text()
        )
        generated = {
            Path(path).relative_to("services/platform-dns").as_posix()
            for path in bind_inputs["platform_dns"]["platform-dns"]
        }
        self.assertEqual(
            generated,
            planner.GENERATED_BIND_ONLY_FILES["platform-dns"],
        )
        platform_ignore = set(
            (services / "platform-dns/.dockerignore").read_text().splitlines()
        )
        self.assertTrue(
            all(f"!{path}" not in platform_ignore for path in generated)
        )

    def test_changed_dockerignore_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stack = Path(temporary).resolve()
            build_root = stack / "services"
            context = build_root / "dev-portal"
            shutil.copytree(ROOT / "services/dev-portal", context)
            context.joinpath(".dockerignore").write_text("*.local\n")
            service = {
                "build": {"context": str(context), "network": "none"},
                "image": "ai-gateway/dev-portal:audit",
            }

            with self.assertRaisesRegex(
                planner.PlanError, "changed without a matching planner update"
            ):
                planner._context_record(
                    stack=stack,
                    build_root=build_root,
                    project="ai-gateway",
                    service_name="dev-portal",
                    service=service,
                    image_inspector=self.image_id,
                )

    def test_all_current_ignored_files_are_excluded_but_dockerfiles_are_hashed(self) -> None:
        source_services = ROOT / "services"
        contexts = sorted(
            path.parent.name for path in source_services.glob("*/.dockerignore")
        )
        with tempfile.TemporaryDirectory() as temporary:
            stack = Path(temporary).resolve()
            build_root = stack / "services"
            build_root.mkdir()
            for context_name in contexts:
                with self.subTest(context=context_name):
                    context = build_root / context_name
                    shutil.copytree(source_services / context_name, context)
                    service = {
                        "build": {"context": str(context), "network": "none"},
                        "image": f"ai-gateway/{context_name}:audit",
                    }

                    def digest() -> str:
                        record, _ = planner._context_record(
                            stack=stack,
                            build_root=build_root,
                            project="ai-gateway",
                            service_name=context_name,
                            service=service,
                            image_inspector=self.image_id,
                        )
                        return record["digest"]

                    baseline = digest()
                    ignored_paths = {
                        path
                        for path in context.rglob("*")
                        if path.is_file()
                        and planner._is_docker_ignored_path(
                            context_name,
                            path.relative_to(context).as_posix(),
                        )
                    }
                    for path in ignored_paths:
                        self.assertTrue(path.is_file(), path)
                        path.write_bytes(path.read_bytes() + b"\nignored audit change\n")
                    self.assertEqual(digest(), baseline, context_name)

                    dockerfile = context / "Dockerfile"
                    dockerfile.write_text(
                        dockerfile.read_text() + "\n# reviewed audit change\n"
                    )
                    self.assertNotEqual(digest(), baseline, context_name)

    def test_star_context_ignores_arbitrary_unlisted_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stack = Path(temporary).resolve()
            build_root = stack / "services"
            context = build_root / "egress-proxy"
            shutil.copytree(ROOT / "services/egress-proxy", context)
            service = {
                "build": {"context": str(context), "network": "none"},
                "image": "ai-gateway/egress-proxy:audit",
            }

            def digest() -> str:
                record, _ = planner._context_record(
                    stack=stack,
                    build_root=build_root,
                    project="ai-gateway",
                    service_name="egress-proxy",
                    service=service,
                    image_inspector=self.image_id,
                )
                return record["digest"]

            baseline = digest()
            context.joinpath("local-notes.txt").write_text("ignored\n")
            context.joinpath("certs/unreviewed.txt").write_text("ignored\n")
            context.joinpath("scratch").mkdir()
            context.joinpath("scratch/private.txt").write_text("ignored\n")
            self.assertEqual(digest(), baseline)

            context.joinpath("certs/reviewed.pem").write_text("reviewed\n")
            self.assertNotEqual(digest(), baseline)

    def test_legacy_digest_migrates_to_framed_v2_without_a_build(self) -> None:
        record, legacy_digest = planner._context_record(
            stack=self.stack,
            build_root=(self.stack / "services").resolve(),
            project="ai-gateway",
            service_name="stateful-app",
            service=self.model["services"]["stateful-app"],
            image_inspector=self.image_id,
        )
        legacy_record = dict(record)
        legacy_record["digest"] = legacy_digest
        self.state.write_text(
            json.dumps({"schema": 1, "services": {"stateful-app": legacy_record}})
        )

        migrated = self.plan()
        self.assertEqual(migrated["services"], [])
        self.assertEqual(
            migrated["manifest"]["services"]["stateful-app"], record
        )
        self.assertNotEqual(record["digest"], legacy_digest)

    def test_v2_framing_distinguishes_legacy_structural_collision(self) -> None:
        absorbed = self.context / "z"
        prefix = b"same-prefix"
        tail = b"tail"
        encoded_z_record = b"z\0" + b"0644" + b"F" + tail
        source = self.context / "a"
        source.write_bytes(prefix + encoded_z_record)
        folded, folded_legacy = planner._context_record(
            stack=self.stack,
            build_root=(self.stack / "services").resolve(),
            project="ai-gateway",
            service_name="stateful-app",
            service=self.model["services"]["stateful-app"],
            image_inspector=self.image_id,
        )

        source.write_bytes(prefix)
        absorbed.write_bytes(tail)
        split, split_legacy = planner._context_record(
            stack=self.stack,
            build_root=(self.stack / "services").resolve(),
            project="ai-gateway",
            service_name="stateful-app",
            service=self.model["services"]["stateful-app"],
            image_inspector=self.image_id,
        )
        self.assertEqual(folded_legacy, split_legacy)
        self.assertNotEqual(folded["digest"], split["digest"])

    def test_context_outside_services_root_is_rejected(self) -> None:
        outside = self.stack / "outside"
        outside.mkdir()
        self.model["services"]["stateful-app"]["build"]["context"] = str(outside)
        with self.assertRaisesRegex(planner.PlanError, "outside"):
            self.plan()


if __name__ == "__main__":
    unittest.main()
