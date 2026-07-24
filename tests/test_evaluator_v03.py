from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness"))

import common  # noqa: E402
import evaluation_contract as contract  # noqa: E402
import evaluation_evidence as evidence  # noqa: E402
import evaluation_scoring as scoring  # noqa: E402


class EvaluatorArchitectureTests(unittest.TestCase):
    def test_dependency_direction_is_acyclic_and_effects_stay_outward(self) -> None:
        expected_forbidden = {
            "evaluation_contract.py": {
                "common",
                "run_case",
                "evaluation_scoring",
                "evaluation_evidence",
                "evaluate",
            },
            "evaluation_scoring.py": {
                "common",
                "run_case",
                "evaluation_evidence",
                "evaluate",
            },
            "evaluation_evidence.py": {"evaluate"},
        }
        for filename, forbidden in expected_forbidden.items():
            tree = ast.parse(
                (ROOT / "harness" / filename).read_text(encoding="utf-8")
            )
            imported = {
                alias.name.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            }
            imported.update(
                node.module.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module
            )
            self.assertEqual(set(), imported & forbidden, filename)

    def test_cli_remains_a_bounded_orchestrator(self) -> None:
        lines = (ROOT / "harness" / "evaluate.py").read_text(
            encoding="utf-8"
        ).splitlines()
        self.assertLessEqual(len(lines), 350)


class ClosedTerminalStatusTests(unittest.TestCase):
    def test_vocabulary_is_exactly_closed(self) -> None:
        self.assertEqual(
            {
                "EXACT",
                "MISSING",
                "INVALID_EVIDENCE",
                "WRONG_REASON",
                "UNEXPECTED_PASS",
                "UNEXPECTED_REJECTED",
                "UNEXPECTED_FAIL",
                "UNEXPECTED_ERROR",
                "UNEXPECTED_TAMPERED",
                "UNKNOWN_VERDICT",
            },
            {status.value for status in scoring.TerminalStatus},
        )

    def test_every_observed_verdict_has_one_terminal_class(self) -> None:
        expected = ("PASS", "tests_passed")
        cases = [
            (
                scoring.RunObservation(False, None, False),
                scoring.TerminalStatus.MISSING,
                scoring.TerminalStatus.MISSING,
            ),
            (
                scoring.RunObservation(True, expected, True),
                scoring.TerminalStatus.EXACT,
                scoring.TerminalStatus.EXACT,
            ),
            (
                scoring.RunObservation(True, expected, False),
                scoring.TerminalStatus.EXACT,
                scoring.TerminalStatus.INVALID_EVIDENCE,
            ),
            (
                scoring.RunObservation(True, ("PASS", "wrong"), True),
                scoring.TerminalStatus.WRONG_REASON,
                scoring.TerminalStatus.WRONG_REASON,
            ),
            (
                scoring.RunObservation(
                    True, ("REJECTED", "protected_harness_edit"), True
                ),
                scoring.TerminalStatus.UNEXPECTED_REJECTED,
                scoring.TerminalStatus.UNEXPECTED_REJECTED,
            ),
            (
                scoring.RunObservation(True, ("FAIL", "tests_failed"), True),
                scoring.TerminalStatus.UNEXPECTED_FAIL,
                scoring.TerminalStatus.UNEXPECTED_FAIL,
            ),
            (
                scoring.RunObservation(
                    True, ("ERROR", "no_parseable_edits"), True
                ),
                scoring.TerminalStatus.UNEXPECTED_ERROR,
                scoring.TerminalStatus.UNEXPECTED_ERROR,
            ),
            (
                scoring.RunObservation(
                    True, ("TAMPERED", "junit_exit_mismatch"), True
                ),
                scoring.TerminalStatus.UNEXPECTED_TAMPERED,
                scoring.TerminalStatus.UNEXPECTED_TAMPERED,
            ),
            (
                scoring.RunObservation(True, ("FUTURE", "reason"), True),
                scoring.TerminalStatus.UNKNOWN_VERDICT,
                scoring.TerminalStatus.UNKNOWN_VERDICT,
            ),
            (
                scoring.RunObservation(True, None, False),
                scoring.TerminalStatus.UNKNOWN_VERDICT,
                scoring.TerminalStatus.UNKNOWN_VERDICT,
            ),
        ]
        for observation, pair_status, terminal in cases:
            with self.subTest(observation=observation):
                result = scoring.score_run(("case", "main"), expected, observation)
                self.assertIs(pair_status, result.conformance_status)
                self.assertIs(terminal, result.terminal_status)

    def test_unexpected_pass_is_explicit(self) -> None:
        result = scoring.score_run(
            ("case", "main"),
            ("REJECTED", "protected_harness_edit"),
            scoring.RunObservation(True, ("PASS", "tests_passed"), True),
        )
        self.assertIs(
            scoring.TerminalStatus.UNEXPECTED_PASS,
            result.terminal_status,
        )


class FixedDenominatorAndContractTests(unittest.TestCase):
    @staticmethod
    def _case(relative: str) -> dict:
        return json.loads((ROOT / relative / "case.json").read_text(encoding="utf-8"))

    def test_exact_integrity_and_admissible_axes_cannot_collapse(self) -> None:
        case = self._case("cases/python/cn-eq-honest-fix")
        plan, issues = contract.preflight_corpus([(case["id"], case)])
        self.assertEqual((), issues)
        assert plan is not None
        key = (case["id"], contract.MAIN)
        summary = scoring.score_conformance(
            plan,
            {
                key: scoring.RunObservation(
                    True,
                    ("PASS", "tests_passed"),
                    False,
                )
            },
        )
        self.assertEqual((1, 0, 0, 1), (
            summary.exact_records,
            summary.valid_records,
            summary.admissible_records,
            summary.expected_records,
        ))
        self.assertIs(
            scoring.TerminalStatus.INVALID_EVIDENCE,
            summary.runs[0].terminal_status,
        )

    def test_missing_exception_remains_in_every_denominator(self) -> None:
        case = self._case("cases/python/mi-all-equal-with-test-update")
        plan, issues = contract.preflight_corpus([(case["id"], case)])
        self.assertEqual((), issues)
        assert plan is not None
        key = (case["id"], contract.MAIN)
        summary = scoring.score_conformance(
            plan,
            {
                key: scoring.RunObservation(
                    True,
                    ("REJECTED", "protected_harness_edit"),
                    True,
                )
            },
        )
        self.assertEqual((1, 1, 1, 2), (
            summary.exact_records,
            summary.valid_records,
            summary.admissible_records,
            summary.expected_records,
        ))
        self.assertEqual(
            scoring.TerminalStatus.MISSING,
            summary.rows[0].exception.terminal_status,
        )

    def test_legacy_label_to_expected_mapping_is_validated(self) -> None:
        case = self._case("cases/python/cn-eq-honest-fix")
        case["guard_expectation"] = {
            "verdict": "ERROR",
            "reason_code": "policy_requirement_unsupported",
        }
        plan, issues = contract.preflight_corpus([(case["id"], case)])
        self.assertIsNone(plan)
        self.assertIn("label_expectation_mismatch", {issue.code for issue in issues})

        exception_case = self._case(
            "cases/python/mi-all-equal-with-test-update"
        )
        del exception_case["exception"]
        plan, issues = contract.preflight_corpus(
            [(exception_case["id"], exception_case)]
        )
        self.assertIsNone(plan)
        self.assertIn("missing_exception", {issue.code for issue in issues})


class EvidenceBoundaryTests(unittest.TestCase):
    def _directory_link(self, link: Path, target: Path) -> None:
        if os.name == "nt":
            completed = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(target)],
                check=False,
                capture_output=True,
                text=True,
            )
            if completed.returncode != 0:
                self.skipTest(f"junction creation unavailable: {completed.stderr}")
        else:
            os.symlink(target, link, target_is_directory=True)

    def test_nonfinite_json_is_rejected_before_timing_validation(self) -> None:
        for token in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(token=token), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "timing.json"
                path.write_text(
                    f'{{"default_seconds":{token}}}',
                    encoding="utf-8",
                )
                read = evidence.read_json_object(
                    path,
                    phase="evidence",
                    code="invalid_timing_json",
                )
                self.assertIsNone(read.value)
                self.assertIn("non-finite", read.issue.message)

    def test_regular_containment_rejects_escape_and_nonregular_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            regular = root / "record.json"
            regular.write_text("{}", encoding="utf-8")
            self.assertIsNone(
                evidence.regular_file_issue(
                    root,
                    regular,
                    phase="evidence",
                    code="unsafe",
                )
            )
            outside = Path(temporary) / "outside.json"
            outside.write_text("{}", encoding="utf-8")
            self.assertIsNotNone(
                evidence.regular_file_issue(
                    root,
                    outside,
                    phase="evidence",
                    code="unsafe",
                )
            )
            directory = root / "directory"
            directory.mkdir()
            self.assertIsNotNone(
                evidence.regular_file_issue(
                    root,
                    directory,
                    phase="evidence",
                    code="unsafe",
                )
            )

    def test_symlink_or_reparse_output_fails_closed_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            linked = root / "linked.json"
            try:
                os.symlink(target, linked)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            issue = evidence.regular_file_issue(
                root,
                linked,
                phase="evidence",
                code="unsafe",
            )
            self.assertIsNotNone(issue)
            self.assertIn("reparse", issue.message)
            real_results = root / "real-results"
            real_results.mkdir()
            linked_results = root / "linked-results"
            os.symlink(real_results, linked_results, target_is_directory=True)
            _, inventory_issues = evidence._results_inventory(linked_results)
            self.assertEqual(
                {"unsafe_results_directory"},
                {item.code for item in inventory_issues},
            )

    def test_nested_or_special_results_are_not_silently_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "nested").mkdir()
            actual, issues = evidence._results_inventory(root)
            self.assertEqual(set(), actual)
            self.assertIn("nonregular_output", {issue.code for issue in issues})

    def test_linked_parent_cannot_redirect_results_or_publication(self) -> None:
        payloads = {
            "INPUTS.sha256": b"a\n",
            "SUMMARY.json": b"{}\n",
            "RESULTS.md": b"# result\n",
            "OUTPUTS.sha256": b"b\n",
        }
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            trusted = base / "trusted"
            trusted.mkdir()
            outside_results = base / "outside-results"
            (outside_results / "round").mkdir(parents=True)
            (outside_results / "round" / "case.json").write_text(
                "{}", encoding="utf-8"
            )
            self._directory_link(trusted / "results", outside_results)
            actual, inventory_issues = evidence._results_inventory(
                trusted / "results" / "round",
                trusted_root=trusted,
            )
            self.assertEqual(set(), actual)
            self.assertEqual(
                {"unsafe_results_directory"},
                {item.code for item in inventory_issues},
            )

            outside_publication = base / "outside-publication"
            outside_publication.mkdir()
            self._directory_link(
                trusted / "reanalysis",
                outside_publication,
            )
            redirected = trusted / "reanalysis" / "protocol-v0.3" / "round"
            write_issues = evidence.write_reanalysis(
                redirected,
                payloads,
                trusted_root=trusted,
            )
            self.assertEqual(
                {"unsafe_reanalysis_directory"},
                {item.code for item in write_issues},
            )
            self.assertEqual([], list(outside_publication.iterdir()))

            real_round = outside_publication / "protocol-v0.3" / "round"
            real_round.mkdir(parents=True)
            for name, value in payloads.items():
                (real_round / name).write_bytes(value)
            check_issues = evidence.check_reanalysis(
                redirected,
                payloads,
                trusted_root=trusted,
            )
            self.assertEqual(
                {"unsafe_reanalysis_directory"},
                {item.code for item in check_issues},
            )

    def test_case_is_frozen_rejects_nested_unmanifested_content(self) -> None:
        case_dir = ROOT / "cases" / "python" / "cn-eq-honest-fix"
        manifest = common.load_json(ROOT / "manifests" / "round-pilot.json")
        self.assertTrue(common.case_is_frozen(case_dir, manifest))
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "cases" / "python" / "case"
            copied.mkdir(parents=True)
            (copied / "case.json").write_text("{}", encoding="utf-8")
            (copied / "nested").mkdir()
            original_root = common.ROOT
            common.ROOT = Path(temporary)
            try:
                self.assertFalse(common.case_is_frozen(copied, {"case_files": []}))
            finally:
                common.ROOT = original_root


class ReanalysisPublicationTests(unittest.TestCase):
    def test_checksum_files_are_forced_to_lf_and_check_alias_is_public(self) -> None:
        completed = subprocess.run(
            [
                "git",
                "check-attr",
                "eol",
                "--",
                "reanalysis/protocol-v0.3/round-pilot/INPUTS.sha256",
                "reanalysis/protocol-v0.3/round-pilot/OUTPUTS.sha256",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(2, completed.stdout.count(": eol: lf"))
        help_result = subprocess.run(
            [sys.executable, "harness/evaluate.py", "--help"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("--check-reanalysis", help_result.stdout)
        self.assertIn("--check", help_result.stdout)

    def test_publication_is_exact_deterministic_and_non_overwriting(self) -> None:
        payloads = {
            "INPUTS.sha256": b"a\n",
            "SUMMARY.json": b"{}\n",
            "RESULTS.md": b"# result\n",
            "OUTPUTS.sha256": b"b\n",
        }
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "publication"
            root = Path(temporary)
            self.assertEqual(
                (),
                evidence.write_reanalysis(
                    directory,
                    payloads,
                    trusted_root=root,
                ),
            )
            self.assertEqual(
                (),
                evidence.check_reanalysis(
                    directory,
                    payloads,
                    trusted_root=root,
                ),
            )
            for name in ("INPUTS.sha256", "OUTPUTS.sha256"):
                path = directory / name
                path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
            self.assertIn(
                "reanalysis_output_mismatch",
                {
                    issue.code
                    for issue in evidence.check_reanalysis(
                        directory,
                        payloads,
                        trusted_root=root,
                    )
                },
            )
            for name, value in payloads.items():
                (directory / name).write_bytes(value)
            self.assertEqual(
                {"refuse_overwrite"},
                {
                    issue.code
                    for issue in evidence.write_reanalysis(
                        directory,
                        payloads,
                        trusted_root=root,
                    )
                },
            )
            (directory / "extra").write_text("x", encoding="utf-8")
            self.assertIn(
                "unexpected_reanalysis_output",
                {
                    issue.code
                    for issue in evidence.check_reanalysis(
                        directory,
                        payloads,
                        trusted_root=root,
                    )
                },
            )


if __name__ == "__main__":
    unittest.main()
