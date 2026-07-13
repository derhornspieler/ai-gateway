from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "plan-compose-builds.py"
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
