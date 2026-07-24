from __future__ import annotations

import copy
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness"))

import evaluate  # noqa: E402
import evaluation_contract  # noqa: E402
import evaluation_evidence  # noqa: E402
import evaluation_scoring  # noqa: E402
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
                    "protocol_version": "v0.3",
                    "round": "round-a",
                    "roles": {
                        "labeler": "labeler",
                        "runner": "runner",
                        "separated": True,
                    },
                    "tuning_seed": "seed-1",
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

    def test_v03_manifest_records_role_separation_and_seed(self) -> None:
        manifest = make_manifest.build_manifest("round-x", "labeler", "runner", "seed-1")
        self.assertEqual("v0.3", manifest["protocol_version"])
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
            record: dict[str, Any] = {
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
                with mock.patch.object(
                    run_case,
                    "load_json",
                    side_effect=AssertionError("record must not be parsed twice"),
                ):
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
                            record=record,
                            check_expectation=False,
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
    @staticmethod
    def _case(relative: str) -> dict:
        return json.loads((ROOT / relative / "case.json").read_text(encoding="utf-8"))

    def test_protocol_v02_and_v03_require_timing_and_exact_outputs(self) -> None:
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
        self.assertEqual(
            {"x.json", "x-exception.json", "x.timing.json"},
            evaluate._expected_files(cases, "v0.3"),
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

    def test_exact_pair_not_verdict_shape_controls_success(self) -> None:
        accept = self._case("cases/python/cn-eq-honest-fix")
        reject = self._case("cases/node/fe-assert-tamper")
        unsupported = copy.deepcopy(accept)
        unsupported["id"] = "unsupported-case"
        unsupported["label"] = "unsupported"
        unsupported["truth"]["human_decision"] = "escalate"
        unsupported["truth"]["policy_expectation"] = "unsupported"
        unsupported["guard_expectation"] = {
            "verdict": "ERROR",
            "reason_code": "policy_requirement_unsupported",
        }
        plan, issues = evaluation_contract.preflight_corpus(
            [
                (accept["id"], accept),
                (reject["id"], reject),
                (unsupported["id"], unsupported),
            ]
        )
        self.assertEqual((), issues)
        self.assertIsNotNone(plan)
        assert plan is not None

        summary = evaluation_scoring.score_conformance(
            plan,
            {
                (accept["id"], evaluation_contract.MAIN): {
                    "verdict": "ERROR",
                    "reason_code": "policy_requirement_unsupported",
                },
                (reject["id"], evaluation_contract.MAIN): {
                    "verdict": "REJECTED",
                    "reason_code": "wrong_reason",
                },
                (unsupported["id"], evaluation_contract.MAIN): {
                    "verdict": "ERROR",
                    "reason_code": "wrong_reason",
                },
            },
        )
        self.assertEqual(0, summary.matched_records)
        self.assertEqual(0, summary.axes.get("accepted", 0))
        self.assertEqual(0, summary.axes.get("attacks_blocked", 0))
        self.assertEqual(0, summary.axes.get("unsupported_matched", 0))
        self.assertEqual((0, 2), summary.by_ecosystem["python"])
        self.assertEqual((0, 1), summary.by_ecosystem["node"])

    def test_missing_main_and_exception_keep_manifest_denominators(self) -> None:
        case = self._case("cases/python/mi-all-equal-with-test-update")
        plan, issues = evaluation_contract.preflight_corpus([(case["id"], case)])
        self.assertEqual((), issues)
        self.assertIsNotNone(plan)
        assert plan is not None

        summary = evaluation_scoring.score_conformance(plan, {})
        self.assertEqual(2, summary.expected_records)
        self.assertEqual(0, summary.matched_records)
        self.assertEqual(1, summary.axes["escalation_total"])
        self.assertEqual(1, summary.axes["exception_total"])
        self.assertEqual(1, summary.axes["escalation_missed"])
        self.assertEqual(1, summary.axes["exception_unresolved"])
        self.assertFalse(summary.rows[0].main_matches)
        self.assertFalse(summary.rows[0].exception_matches)
        self.assertEqual((0, 1), summary.by_ecosystem["python"])
        self.assertEqual(
            (0, 1),
            summary.by_change_class["refactor_with_test_update"],
        )

    def test_invalid_json_returns_a_structured_issue_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "broken.json"
            path.write_text('{"verdict":', encoding="utf-8")
            read = evaluate._read_json_object(
                path,
                phase="evidence",
                code="invalid_record_json",
                case_id="case-a",
            )
        self.assertIsNone(read.value)
        self.assertIsNotNone(read.issue)
        assert read.issue is not None
        self.assertEqual("invalid_record_json", read.issue.code)
        self.assertEqual("case-a", read.issue.case_id)
        self.assertIn("line 1", read.issue.message)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text(
                '{"verdict":"PASS","verdict":"ERROR"}',
                encoding="utf-8",
            )
            read = evaluate._read_json_object(
                path,
                phase="evidence",
                code="invalid_record_json",
                case_id="case-a",
            )
        self.assertIsNone(read.value)
        self.assertIsNotNone(read.issue)
        assert read.issue is not None
        self.assertIn("duplicate JSON key", read.issue.message)

    def test_cli_invalid_record_json_is_a_fixed_denominator_failure(self) -> None:
        case = self._case("cases/python/cn-eq-honest-fix")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case_dir = root / "cases" / "python" / case["id"]
            case_dir.mkdir(parents=True)
            (case_dir / "case.json").write_text(
                json.dumps(case), encoding="utf-8"
            )
            (case_dir / "candidate.txt").write_text(
                "candidate\n", encoding="utf-8"
            )
            results = root / "results" / "bad-json"
            results.mkdir(parents=True)
            (results / f"{case['id']}.json").write_text(
                '{"verdict":', encoding="utf-8"
            )
            manifest_dir = root / "manifests"
            manifest_dir.mkdir()
            entries = [
                {
                    "path": f"cases/python/{case['id']}/case.json",
                    "sha256": common.sha256_file(case_dir / "case.json"),
                },
                {
                    "path": f"cases/python/{case['id']}/candidate.txt",
                    "sha256": common.sha256_file(case_dir / "candidate.txt"),
                },
            ]
            entries.sort(key=lambda item: item["path"])
            corpus = hashlib.sha256(
                "\n".join(
                    f"{item['sha256']}  {item['path']}" for item in entries
                ).encode()
            ).hexdigest()
            manifest = {
                "protocol_version": "v0.3",
                "round": "bad-json",
                "roles": {
                    "labeler": "labeler",
                    "runner": "runner",
                    "separated": True,
                },
                "tuning_seed": "seed",
                "engine": {
                    "release": common.ENGINE_VERSION,
                    "evo_guard_pyz_sha256": common.ENGINE_SHA256,
                },
                "schema_version": common.SCHEMA_VERSION,
                "case_files": entries,
                "corpus_sha256": corpus,
            }
            (manifest_dir / "bad-json.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            engine = root / "engine.pyz"
            engine.write_bytes(b"engine")
            with (
                mock.patch.object(evaluate, "ROOT", root),
                mock.patch.object(
                    evaluation_evidence,
                    "acquire_engine",
                    return_value=str(engine),
                ),
                mock.patch.object(
                    sys,
                    "argv",
                    ["evaluate.py", "--round", "bad-json"],
                ),
                redirect_stdout(io.StringIO()) as stdout,
                redirect_stderr(io.StringIO()) as stderr,
            ):
                self.assertEqual(1, evaluate.main())
        self.assertIn("exact expected pairs     : 0/1", stdout.getvalue())
        self.assertIn("invalid_record_json", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_boolean_timing_is_rejected(self) -> None:
        elapsed, issues = evaluation_evidence.validate_timing(
            "case-a",
            {"default_seconds": True},
            expects_exception=False,
        )
        self.assertEqual((), elapsed)
        self.assertEqual(["invalid_timing"], [issue.code for issue in issues])

    def test_huge_or_partially_invalid_timing_has_no_median_values(self) -> None:
        elapsed, issues = evaluation_evidence.validate_timing(
            "case-a",
            {
                "default_seconds": 1,
                "exception_seconds": 10**1000,
            },
            expects_exception=True,
        )
        self.assertEqual((), elapsed)
        self.assertEqual(["invalid_timing"], [issue.code for issue in issues])

    def test_metadata_error_returns_no_scorable_plan(self) -> None:
        case = self._case("cases/python/cn-eq-honest-fix")
        case["unregistered_metadata"] = "must fail closed"
        plan, issues = evaluation_contract.preflight_corpus([(case["id"], case)])
        self.assertIsNone(plan)
        self.assertIn("unknown_field", {issue.code for issue in issues})

        del case["unregistered_metadata"]
        case["guard_expectation"]["reason_code"] = "not_in_schema_1_11"
        plan, issues = evaluation_contract.preflight_corpus([(case["id"], case)])
        self.assertIsNone(plan)
        self.assertIn("unknown_reason_code", {issue.code for issue in issues})

    def test_cli_suppresses_scoring_and_engine_acquisition_on_bad_corpus(self) -> None:
        issue = evaluation_contract.EvaluationIssue(
            phase="corpus",
            code="unknown_label",
            message="unknown label",
        )
        with (
            mock.patch.object(
                evaluate,
                "preflight_round",
                return_value=(None, (issue,)),
            ),
            mock.patch.object(evaluate, "collect_evidence") as collect_evidence,
            mock.patch.object(evaluate, "score_conformance") as score_conformance,
            mock.patch.object(
                sys,
                "argv",
                ["evaluate.py", "--round", "bad-round"],
            ),
            redirect_stderr(io.StringIO()) as stderr,
        ):
            self.assertEqual(1, evaluate.main())
        collect_evidence.assert_not_called()
        score_conformance.assert_not_called()
        self.assertIn("SCORING SUPPRESSED", stderr.getvalue())

    def test_conformance_and_evidence_integrity_are_independent(self) -> None:
        case = self._case("cases/python/cn-eq-honest-fix")
        plan, issues = evaluation_contract.preflight_corpus([(case["id"], case)])
        self.assertEqual((), issues)
        self.assertIsNotNone(plan)
        assert plan is not None
        key = (case["id"], evaluation_contract.MAIN)
        summary = evaluation_scoring.score_conformance(
            plan,
            {
                key: {
                    "verdict": "PASS",
                    "reason_code": "tests_passed",
                }
            },
        )
        integrity = evaluation_scoring.summarize_evidence(plan, {key: False})
        self.assertEqual((1, 1), (summary.matched_records, summary.expected_records))
        self.assertEqual((0, 1), (integrity.valid_records, integrity.expected_records))

    def test_historical_pilot_is_exact_for_all_fourteen_records(self) -> None:
        manifest, problems = verify_manifest("round-pilot")
        self.assertEqual([], problems)
        case_inputs: list[tuple[str, object]] = []
        observed: dict[tuple[str, str], object] = {}
        for case_dir in common.case_dirs_from_manifest(manifest):
            case = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
            case_inputs.append((case_dir.name, case))
            case_id = case["id"]
            observed[(case_id, evaluation_contract.MAIN)] = json.loads(
                (ROOT / "results" / "round-pilot" / f"{case_id}.json").read_text(
                    encoding="utf-8"
                )
            )
            if case["label"] == "requires_policy_exception":
                observed[(case_id, evaluation_contract.EXCEPTION)] = json.loads(
                    (
                        ROOT
                        / "results"
                        / "round-pilot"
                        / f"{case_id}-exception.json"
                    ).read_text(encoding="utf-8")
                )
        plan, issues = evaluation_contract.preflight_corpus(case_inputs)
        self.assertEqual((), issues)
        self.assertIsNotNone(plan)
        assert plan is not None
        summary = evaluation_scoring.score_conformance(plan, observed)
        self.assertEqual((14, 14), (summary.matched_records, summary.expected_records))


if __name__ == "__main__":
    unittest.main()
