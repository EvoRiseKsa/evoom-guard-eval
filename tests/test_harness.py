from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness"))

import evaluate  # noqa: E402
import make_manifest  # noqa: E402
import run_case  # noqa: E402
import common  # noqa: E402
from common import (  # noqa: E402
    ENGINE_VERSION,
    SCHEMA_VERSION,
    manifest_coverage_problems,
    verify_manifest,
)


class ManifestTests(unittest.TestCase):
    def test_pilot_manifest_is_reproducible(self) -> None:
        manifest, problems = verify_manifest("round-pilot", exact_corpus=False)
        self.assertEqual([], problems)
        self.assertEqual(
            "7a7f09585079dada65432a343b6bb4ce20fb57be1c8ef86942cf2d66f0ea7c26",
            manifest["corpus_sha256"],
        )

    def test_every_current_case_byte_is_frozen_in_a_round_manifest(self) -> None:
        self.assertEqual([], manifest_coverage_problems())

    def test_new_case_bytes_require_a_new_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case_dir = root / "cases" / "python" / "case-a"
            case_dir.mkdir(parents=True)
            (case_dir / "case.json").write_text("{}\n", encoding="utf-8")
            (case_dir / "candidate.txt").write_text("x\n", encoding="utf-8")
            (root / "manifests").mkdir()
            with mock.patch.object(common, "ROOT", root):
                entries, corpus = common.compute_case_entries()
                manifest = {
                    "round": "round-a",
                    "case_files": entries,
                    "corpus_sha256": corpus,
                    "engine": {
                        "release": common.ENGINE_VERSION,
                        "evo_guard_pyz_sha256": common.ENGINE_SHA256,
                    },
                    "schema_version": common.SCHEMA_VERSION,
                }
                (root / "manifests" / "round-a.json").write_text(
                    json.dumps(manifest), encoding="utf-8"
                )
                self.assertEqual([], common.manifest_coverage_problems())
                (case_dir / "unfrozen.txt").write_text("new\n", encoding="utf-8")
                self.assertTrue(
                    any(
                        "unfrozen.txt" in problem
                        for problem in common.manifest_coverage_problems()
                    )
                )

    def test_v02_manifest_records_role_separation_and_seed(self) -> None:
        manifest = make_manifest.build_manifest("round-x", "labeler", "runner", "seed-1")
        self.assertEqual("v0.2", manifest["protocol_version"])
        self.assertTrue(manifest["roles"]["separated"])
        self.assertEqual("seed-1", manifest["tuning_seed"])

    def test_help_cannot_mutate_manifest(self) -> None:
        path = ROOT / "manifests" / "round-pilot.json"
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        completed = subprocess.run(
            [sys.executable, str(ROOT / "harness" / "make_manifest.py"), "--help"],
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(0, completed.returncode)
        self.assertEqual(before, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_manifest_refuses_overwrite(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "harness" / "make_manifest.py"),
                "round-pilot",
                "--labeler",
                "a",
                "--runner",
                "b",
                "--tuning-seed",
                "seed",
            ],
            capture_output=True,
            timeout=30,
        )
        self.assertNotEqual(0, completed.returncode)
        self.assertIn(b"refusing to overwrite", completed.stderr)


class RunnerTests(unittest.TestCase):
    def test_git_cache_key_binds_full_url(self) -> None:
        first = run_case.git_cache_key("https://example.test/a/shared.git")
        second = run_case.git_cache_key("https://example.test/b/shared.git")
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("shared-"))

    def test_stale_output_is_removed_and_cannot_mask_no_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "record.json"
            out.write_text('{"verdict":"PASS"}', encoding="utf-8")
            completed = subprocess.CompletedProcess([], 9, stdout="", stderr="crashed")
            with mock.patch.object(run_case.subprocess, "run", return_value=completed):
                with self.assertRaisesRegex(SystemExit, "no fresh record"):
                    run_case.run_guard(
                        "engine.pyz",
                        temporary,
                        "candidate.txt",
                        "patch",
                        {"test_command": "python -V", "timeout": 1},
                        [],
                        str(out),
                    )
            self.assertFalse(out.exists())

    def test_candidate_digest_reproduces_patch_and_diff_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            patch = root / "candidate.txt"
            patch.write_text("abc\n", encoding="utf-8", newline="\n")
            self.assertEqual(
                hashlib.sha256(b"abc\n").hexdigest(),
                run_case.candidate_digest_for_engine(patch, "patch"),
            )
            head = root / "head"
            head.mkdir()
            (head / "app.py").write_text("x = 2\n", encoding="utf-8", newline="\n")
            diff = root / "candidate.diff"
            diff.write_text(
                "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n",
                encoding="utf-8",
                newline="\n",
            )
            canonical = "<<<FILE: app.py>>>\nx = 2\n\n<<<END FILE>>>"
            self.assertEqual(
                hashlib.sha256(canonical.encode()).hexdigest(),
                run_case.candidate_digest_for_engine(diff, "diff", head),
            )

    def test_record_validation_checks_identity_candidate_policy_and_reason(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.txt"
            candidate.write_text("candidate\n", encoding="utf-8", newline="\n")
            policy = {"test_command": "python -V", "timeout": 30}
            record = {
                "tool": "evoguard",
                "tool_version": ENGINE_VERSION.removeprefix("v"),
                "schema_version": SCHEMA_VERSION,
                "verdict": "PASS",
                "reason_code": "tests_passed",
                "attestation": {
                    "guard_version": ENGINE_VERSION.removeprefix("v"),
                    "candidate_sha256": run_case.candidate_digest_for_engine(candidate, "patch"),
                    "effective_policy": {
                        "test_command": ["python", "-V"],
                        "timeout": 30,
                        "allow": [],
                        "allow_new_tests": False,
                    },
                },
            }
            path = root / "record.json"
            path.write_text(json.dumps(record), encoding="utf-8")
            verified = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            with mock.patch.object(run_case.subprocess, "run", return_value=verified):
                self.assertEqual(
                    [],
                    run_case.validate_record(
                        "engine.pyz",
                        path,
                        {"verdict": "PASS", "reason_code": "tests_passed"},
                        "case",
                        candidate=candidate,
                        policy=policy,
                        extra=[],
                    ),
                )
                record["reason_code"] = "wrong"
                record["attestation"]["candidate_sha256"] = "0" * 64
                path.write_text(json.dumps(record), encoding="utf-8")
                problems = run_case.validate_record(
                    "engine.pyz",
                    path,
                    {"verdict": "PASS", "reason_code": "tests_passed"},
                    "case",
                    candidate=candidate,
                    policy=policy,
                    extra=[],
                )
            self.assertTrue(any("expected" in problem for problem in problems))
            self.assertTrue(any("candidate digest" in problem for problem in problems))


class EvaluatorTests(unittest.TestCase):
    def test_protocol_v02_requires_timing_and_exact_outputs(self) -> None:
        cases = [
            (
                ROOT / "cases" / "python" / "x",
                {"id": "x", "label": "requires_policy_exception"},
            )
        ]
        self.assertEqual(
            {"x.json", "x-exception.json", "x.timing.json"},
            evaluate._expected_files(cases, "v0.2"),
        )

    def test_truth_is_checked_without_guard_vocabulary(self) -> None:
        case = {
            "label": "accept",
            "truth": {
                "human_decision": "admit",
                "policy_expectation": "no_exception_required",
                "labeled_before_guard_run": True,
            },
        }
        self.assertIsNone(evaluate._truth_problem(case))
        case["label"] = "reject"
        self.assertIn("inconsistent", evaluate._truth_problem(case) or "")

    def test_inventory_rejects_missing_and_stale_outputs(self) -> None:
        problems = evaluate._inventory_problems(
            {"expected.json", "missing.json"},
            {"expected.json", "stale.json"},
        )
        self.assertEqual(
            [
                "missing round output: missing.json",
                "unexpected/stale round output: stale.json",
            ],
            problems,
        )


if __name__ == "__main__":
    unittest.main()
