from __future__ import annotations

import importlib
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness"))

import oss_common  # noqa: E402

WORKFLOW_PATH = ROOT / ".github" / "workflows" / "oss-compat-run.yml"
POLICY_ROOT = ROOT / "studies" / "oss-compat-v1" / "policies"
BOUNDARY_EXEC = "/usr/local/sbin/evoom-oss-untrusted-exec"

EXPECTED_STEPS = [
    "Checkout frozen protocol",
    "Set up Python",
    "Prove first API-visible dispatch",
    "Set up Node",
    "Set up Go",
    "Pin Rust 1.85.0",
    "Verify frozen study identity",
    "Install trusted execution boundary",
    "Run frozen case",
    "Kill residual untrusted processes",
    "Upload immutable raw case output",
]


def _workflow_text() -> str:
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def _step_names(text: str) -> list[str]:
    names: list[str] = []
    for match in re.finditer(r"(?m)^\s+- name:\s*(.+?)\s*$", text):
        names.append(match.group(1).strip("'\""))
    return names


def _step_block(text: str, name: str) -> str:
    pattern = re.compile(
        rf"(?ms)^\s+- name:\s*['\"]?{re.escape(name)}['\"]?\s*$"
        rf"(?P<body>.*?)(?=^\s+- (?:name:|uses:)|\Z)"
    )
    match = pattern.search(text)
    if match is None:
        raise AssertionError(f"missing workflow step: {name}")
    return match.group(0)


class OssBoundaryPolicyContractTests(unittest.TestCase):
    def test_boundary_code_and_tests_are_frozen_manifest_inputs(self) -> None:
        self.assertIn("harness/oss_untrusted_exec.py", oss_common.HARNESS_INPUTS)
        self.assertIn("tests/test_oss_untrusted_exec.py", oss_common.HARNESS_INPUTS)

    def test_all_six_policies_route_setup_and_test_through_boundary(self) -> None:
        policy_paths = sorted(POLICY_ROOT.glob("*.json"))
        self.assertEqual(6, len(policy_paths))
        for policy_path in policy_paths:
            with self.subTest(policy=policy_path.name):
                policy = json.loads(policy_path.read_text(encoding="utf-8"))
                for field, phase in (
                    ("setup_command", "setup"),
                    ("test_command", "test"),
                ):
                    command = policy[field]
                    self.assertGreater(len(command), 5)
                    self.assertEqual(
                        [BOUNDARY_EXEC, "--phase", phase, "--"], command[:4]
                    )
                    self.assertTrue(command[4], "wrapped command must not be empty")

    def test_python_setup_uses_an_unprivileged_user_install(self) -> None:
        policy = json.loads(
            (POLICY_ROOT / "python-requests-py312-v1.json").read_text(
                encoding="utf-8"
            )
        )
        setup = policy["setup_command"]
        self.assertEqual(["python", "-m", "pip", "install"], setup[4:8])
        self.assertIn("--user", setup[8:])


class OssBoundaryWorkflowContractTests(unittest.TestCase):
    def test_boundary_steps_have_exact_api_visible_names_and_order(self) -> None:
        self.assertEqual(EXPECTED_STEPS, _step_names(_workflow_text()))

    def test_run_is_success_gated_and_uses_a_clean_root_environment(self) -> None:
        block = _step_block(_workflow_text(), "Run frozen case")
        self.assertNotRegex(block, r"(?m)^\s+if:")
        self.assertIn("sudo env -i", block)
        self.assertIn("PATH=/", block)
        self.assertNotIn("GITHUB_TOKEN", block)
        self.assertNotIn("GH_TOKEN", block)
        self.assertNotIn("github.token", block)

    def test_install_proves_pid_namespace_boundary_before_execution(self) -> None:
        block = _step_block(_workflow_text(), "Install trusted execution boundary")
        self.assertIn("--self-test", block)
        self.assertIn("unshare", block)
        self.assertIn("/etc/evoom-oss-boundary.json", block)
        self.assertIn("real_tools", block)
        self.assertRegex(block, r"(?<!\d)0700(?!\d)")

    def test_cleanup_is_unconditional_but_upload_requires_cleanup_success(self) -> None:
        cleanup = _step_block(_workflow_text(), "Kill residual untrusted processes")
        self.assertRegex(cleanup, r"(?m)^\s+id:\s*trusted_cleanup\s*$")
        self.assertRegex(
            cleanup,
            r"(?m)^\s+if:\s*(?:\$\{\{\s*)?always\(\)(?:\s*\}\})?\s*$",
        )
        self.assertIn("--cleanup", cleanup)
        self.assertIn("--purge-homes", cleanup)

        upload = _step_block(_workflow_text(), "Upload immutable raw case output")
        condition = re.search(r"(?m)^\s+if:\s*(.+?)\s*$", upload)
        self.assertIsNotNone(condition)
        normalized = condition.group(1).replace("${{", "").replace("}}", "")
        self.assertIn("always()", normalized)
        self.assertIn("steps.trusted_cleanup.outcome == 'success'", normalized)


try:
    oss_untrusted_exec = importlib.import_module("oss_untrusted_exec")
except ModuleNotFoundError:
    oss_untrusted_exec = None


@unittest.skipIf(oss_untrusted_exec is None, "boundary wrapper is not present yet")
class OssBoundaryHelperTests(unittest.TestCase):
    def _helper(self, name: str):
        helper = getattr(oss_untrusted_exec, name, None)
        if helper is None:
            self.skipTest(f"boundary wrapper has no {name} helper yet")
        return helper

    def test_infer_phase_rejects_unknown_commands_and_classifies_policy_tools(self) -> None:
        infer_phase = self._helper("infer_phase")
        examples = [
            ("python", ["-m", "pip", "install", "--user", "x"], "setup"),
            ("python", ["-m", "pytest", "tests"], "test"),
            ("npm", ["install"], "setup"),
            ("npm", ["test"], "test"),
            ("go", ["mod", "download"], "setup"),
            ("go", ["test", "./..."], "test"),
            ("cargo", ["fetch", "--locked"], "setup"),
            ("cargo", ["test", "--locked"], "test"),
            ("cmake", ["-S", ".", "-B", "build"], "setup"),
            ("cmake", ["--build", "build"], "test"),
        ]
        for tool, arguments, expected in examples:
            with self.subTest(tool=tool, arguments=arguments):
                self.assertEqual(expected, infer_phase(tool, arguments))
        with self.assertRaises((ValueError, RuntimeError)):
            infer_phase("sh", ["-c", "true"])

    def test_uid_processes_parses_real_uid_not_names_or_substrings(self) -> None:
        uid_processes = self._helper("uid_processes")
        with tempfile.TemporaryDirectory() as temporary:
            proc = Path(temporary)
            for pid, uid in (("101", 12001), ("202", 12002)):
                process = proc / pid
                process.mkdir()
                (process / "status").write_text(
                    f"Name:\ttest-12001\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n",
                    encoding="utf-8",
                )
            (proc / "not-a-pid").mkdir()
            self.assertEqual([101], sorted(uid_processes(12001, proc_root=proc)))

    def test_child_environment_is_allowlisted_and_has_no_actions_secrets(self) -> None:
        child_environment = self._helper("child_environment")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            config = {
                "work_root": str(root / "work"),
                "output_root": str(root / "output"),
                "state_root": str(root / "state"),
                "untrusted_user": "evoom-oss-untrusted",
                "real_tools": {
                    "python": "/usr/bin/python3",
                    "npm": "/usr/bin/npm",
                    "go": "/usr/bin/go",
                    "cargo": "/usr/bin/cargo",
                    "cmake": "/usr/bin/cmake",
                },
            }
            environment = child_environment(config, home)
        self.assertEqual(str(home), environment["HOME"])
        self.assertEqual("C.UTF-8", environment["LANG"])
        self.assertEqual("UTC", environment["TZ"])
        forbidden_fragments = (
            "TOKEN",
            "SECRET",
            "PASSWORD",
            "ACTIONS_",
            "GITHUB_",
            "CREDENTIAL",
        )
        for name in environment:
            self.assertFalse(
                any(fragment in name.upper() for fragment in forbidden_fragments),
                name,
            )


if __name__ == "__main__":
    unittest.main()
