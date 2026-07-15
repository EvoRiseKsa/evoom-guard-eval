from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness"))

import evaluate_oss  # noqa: E402
import check_canonical_dispatch  # noqa: E402
import freeze_oss_cases  # noqa: E402
import make_oss_manifest  # noqa: E402
import oss_common  # noqa: E402
import run_oss_case  # noqa: E402


class OssStudyDataTests(unittest.TestCase):
    def test_embedded_signature_detection_uses_commit_bytes(self) -> None:
        unsigned = b"tree " + b"0" * 40 + b"\n\nmessage\n"
        signed = (
            b"tree "
            + b"0" * 40
            + b"\ngpgsig -----BEGIN PGP SIGNATURE-----\n"
            + b" continuation\n\nmessage\n"
        )
        sha256_signed = (
            b"tree "
            + b"0" * 40
            + b"\ngpgsig-sha256 -----BEGIN SSH SIGNATURE-----\n"
            + b" continuation\n\nmessage\n"
        )
        self.assertFalse(freeze_oss_cases._has_embedded_signature(unsigned))  # noqa: SLF001
        self.assertTrue(freeze_oss_cases._has_embedded_signature(signed))  # noqa: SLF001
        self.assertTrue(
            freeze_oss_cases._has_embedded_signature(sha256_signed)  # noqa: SLF001
        )
        with self.assertRaises(RuntimeError):
            freeze_oss_cases._has_embedded_signature(b"tree only")  # noqa: SLF001

    def test_frozen_study_is_internally_consistent(self) -> None:
        self.assertEqual([], oss_common.working_study_problems())
        selection = oss_common.load_json(oss_common.STUDY_ROOT / "SELECTION.json")
        self.assertEqual(
            [], freeze_oss_cases._check_local_structure(selection)  # noqa: SLF001
        )

    def test_selection_is_six_balanced_repository_pairs(self) -> None:
        selection = oss_common.load_json(oss_common.STUDY_ROOT / "SELECTION.json")
        repositories = selection["repositories"]
        self.assertEqual(6, len(repositories))
        self.assertEqual(6, len({repository["ecosystem"] for repository in repositories}))
        all_ids: set[str] = set()
        for repository in repositories:
            cases = repository["cases"]
            self.assertEqual(2, len(cases))
            self.assertEqual(
                {"verbatim_upstream_source_only", "verbatim_upstream_policy_trip"},
                {case["category"] for case in cases},
            )
            all_ids.update(case["id"] for case in cases)
        self.assertEqual(12, len(all_ids))

    def test_manifest_is_reproducible_and_complete(self) -> None:
        expected = make_oss_manifest.build_manifest()
        destination = oss_common.manifest_path()
        if destination.is_file():
            manifest, problems = oss_common.verify_manifest()
            self.assertEqual([], problems)
            self.assertEqual(expected, manifest)
        paths = [entry["path"] for entry in expected["input_files"]]
        self.assertEqual(sorted(paths), paths)
        self.assertEqual(len(paths), len(set(paths)))
        self.assertIn(".gitattributes", paths)
        self.assertIn("README.md", paths)
        self.assertIn("tests/test_oss_harness.py", paths)
        self.assertTrue(any(path.startswith("studies/oss-compat-v1/licenses/") for path in paths))

    def test_manifest_and_study_references_reject_traversal(self) -> None:
        with self.assertRaises(ValueError):
            oss_common.manifest_path("../../escape")
        for value in ("../outside.json", "/absolute.json", "..\\outside.json"):
            with self.assertRaises(ValueError):
                oss_common.resolve_study_file(value, "policies")

    def test_duplicate_physical_case_directory_is_detected(self) -> None:
        selection = {
            "repositories": [
                {
                    "key": "a",
                    "cases": [
                        {
                            "id": "same",
                            "expected_guard": {
                                "verdict": "PASS",
                                "reason_code": "tests_passed",
                            },
                        }
                    ],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as temporary:
            study = Path(temporary)
            (study / "cases" / "a" / "same").mkdir(parents=True)
            (study / "cases" / "b" / "same").mkdir(parents=True)
            with mock.patch.object(freeze_oss_cases, "STUDY_ROOT", study):
                problems = freeze_oss_cases._check_local_structure(selection)  # noqa: SLF001
        self.assertTrue(any("b/same" in problem for problem in problems))


class OssPathAndDigestTests(unittest.TestCase):
    def test_root_git_calls_authorize_only_the_protocol_checkout(self) -> None:
        command = run_oss_case._trusted_checkout_git("status")  # noqa: SLF001
        self.assertEqual("git", command[0])
        self.assertEqual(["-c", f"safe.directory={ROOT}"], command[1:3])
        self.assertEqual(["-C", str(ROOT), "status"], command[3:])

    def test_internal_symlinks_are_allowed_but_escapes_are_not(self) -> None:
        self.assertTrue(oss_common.safe_archive_symlink("dir/link", "../target"))
        self.assertFalse(oss_common.safe_archive_symlink("dir/link", "../../escape"))
        self.assertFalse(oss_common.safe_archive_symlink("dir/link", "/absolute"))

    def test_candidate_digest_uses_trusted_paths_not_diff_like_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            head = Path(temporary)
            content = "normal\n+++ ../not-a-header\n"
            (head / "app.txt").write_text(content, encoding="utf-8", newline="\n")
            actual = run_oss_case.candidate_digest(
                head, [{"status": "M", "path": "app.txt"}]
            )
        canonical = f"<<<FILE: app.txt>>>\n{content}\n<<<END FILE>>>"
        self.assertEqual(hashlib.sha256(canonical.encode()).hexdigest(), actual)

    def test_candidate_digest_rejects_escaping_trusted_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                run_oss_case.candidate_digest(
                    Path(temporary), [{"status": "M", "path": "../escape"}]
                )


class OssRecordAndFailureTests(unittest.TestCase):
    def _source_case(self) -> tuple[Path, dict[str, object]]:
        for case_dir, case in oss_common.case_map().values():
            if case["category"] == "verbatim_upstream_source_only":
                return case_dir, case
        self.fail("no source-only case")

    def test_record_bindings_detect_cross_case_substitution(self) -> None:
        case_dir, case = self._source_case()
        policy = oss_common.load_json(
            oss_common.resolve_study_file(case["policy"], "policies")
        )
        provenance = oss_common.load_json(case_dir / "provenance.json")
        created = datetime.now(timezone.utc).timestamp()
        source = case["source"]
        record = {
            "tool": "evoguard",
            "tool_version": oss_common.ENGINE_VERSION.removeprefix("v"),
            "schema_version": oss_common.SCHEMA_VERSION,
            "verdict": "PASS",
            "reason_code": "tests_passed",
            "exit_code": 0,
            "source": "diff",
            "base_reconstruction": "ok",
            "files_changed": [entry["path"] for entry in provenance["changed_paths"]],
            "test_command_ran": True,
            "baseline": {"verdict": "PASS"},
            "attestation": {
                "created_utc": datetime.fromtimestamp(created, timezone.utc).isoformat(),
                "guard_version": oss_common.ENGINE_VERSION.removeprefix("v"),
                "base_sha": source["base_commit"],
                "head_sha": source["head_commit"],
                "base_tree_sha": source["base_tree"],
                "head_tree_sha": source["head_tree"],
                "candidate_sha256": case["candidate_canonical_sha256"],
                "effective_policy": run_oss_case.expected_effective_policy(policy),
            },
        }
        self.assertEqual(
            [],
            run_oss_case.record_binding_problems(
                record,
                case,
                policy,
                provenance,
                case["candidate_canonical_sha256"],
                created - 1,
                created + 1,
                0,
            ),
        )
        record["attestation"]["base_sha"] = "0" * 40
        problems = run_oss_case.record_binding_problems(
            record,
            case,
            policy,
            provenance,
            case["candidate_canonical_sha256"],
            created - 1,
            created + 1,
            0,
        )
        self.assertIn("attestation mismatch for base_sha", problems)

    def test_malformed_files_changed_is_an_integrity_problem_not_a_crash(self) -> None:
        case_dir, case = self._source_case()
        policy = oss_common.load_json(
            oss_common.resolve_study_file(case["policy"], "policies")
        )
        provenance = oss_common.load_json(case_dir / "provenance.json")
        record = {
            "tool": "evoguard",
            "tool_version": oss_common.ENGINE_VERSION.removeprefix("v"),
            "schema_version": oss_common.SCHEMA_VERSION,
            "exit_code": 0,
            "source": "diff",
            "base_reconstruction": "ok",
            "files_changed": [{}],
            "attestation": {},
        }
        problems = run_oss_case.record_binding_problems(
            record,
            case,
            policy,
            provenance,
            case["candidate_canonical_sha256"],
            0,
            1,
            0,
        )
        self.assertIn("record files_changed is not a list of paths", problems)

    def test_early_harness_failure_is_preserved_without_forging_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "case-a"
            with mock.patch.object(run_oss_case, "_FAILURE_OUTPUT_DIR", output):
                run_oss_case._preserve_harness_failure(RuntimeError("boom"))  # noqa: SLF001
            envelope = json.loads((output / "run-envelope.json").read_text())
            self.assertFalse(envelope["success"])
            self.assertFalse((output / "verdict.json").exists())
            self.assertTrue((output / "guard.stderr.txt").is_file())


class OssEvaluatorTests(unittest.TestCase):
    def test_evidence_paths_must_be_contained_and_not_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            outside = Path(temporary) / "outside"
            root.mkdir()
            outside.mkdir()
            regular = root / "regular"
            regular.mkdir()
            self.assertTrue(evaluate_oss.is_contained(regular, root))
            self.assertFalse(evaluate_oss.is_contained(outside, root))
            link = root / "linked"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError:
                return
            self.assertTrue(evaluate_oss.is_link_or_reparse_point(link))

    def test_integrity_valid_late_failure_preserves_partial_outputs(self) -> None:
        case_id, (case_dir, case) = next(iter(oss_common.case_map().items()))
        claim_scope = {
            "accuracy_claims_allowed": False,
            "independent": False,
            "kind": "same_owner_compatibility",
        }
        fake_manifest = {
            "claim_scope": claim_scope,
            "engine": {},
            "corpus_sha256": "0" * 64,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "manifest.json"
            manifest.write_text("{}\n", encoding="utf-8", newline="\n")
            output = root / "results" / oss_common.STUDY_ID / case_id
            output.mkdir(parents=True)
            (output.parent / "archives").mkdir()
            (output.parent / "RUN.json").write_bytes(
                oss_common.canonical_json_bytes({"run": {"id": 123}})
            )
            (output / "guard.stdout.txt").write_bytes(b"")
            (output / "guard.stderr.txt").write_text(
                "HARNESS FAILURE\n", encoding="utf-8", newline="\n"
            )
            (output / "verdict.json").write_bytes(
                oss_common.canonical_json_bytes({"partial": True})
            )
            (output / "guard-report.md").write_text(
                "partial report\n", encoding="utf-8", newline="\n"
            )
            (output / "timing.json").write_bytes(
                oss_common.canonical_json_bytes(
                    {
                        "source_acquisition_and_verification_seconds": 0.1,
                        "head_checkout_seconds": 0.1,
                        "guard_seconds": 0.7,
                        "total_seconds": 1.0,
                    }
                )
            )
            environment_path = oss_common.resolve_study_file(
                case["environment"], "environments"
            )
            commit = "a" * 40
            run_id = "123"
            pre_hashes = {
                name: oss_common.sha256_file(output / name)
                for name in run_oss_case.PRE_ENVELOPE_OUTPUT_NAMES
            }
            runner = {
                "os": "posix",
                "runner_os": "Linux",
                "runner_arch": "X64",
                "image_os": "ubuntu24",
                "image_version": "20260701.1",
                "github_actions": "true",
                "github_event_name": "workflow_dispatch",
                "github_repository": run_oss_case.EXPECTED_GITHUB_REPOSITORY,
                "github_run_id": run_id,
                "github_run_attempt": "1",
                "github_sha": commit,
                "github_ref": run_oss_case.EXPECTED_GITHUB_REF,
                "github_ref_name": oss_common.PROTOCOL_TAG,
                "github_ref_type": "tag",
                "github_ref_protected": "true",
                "github_workflow_ref": run_oss_case.EXPECTED_GITHUB_WORKFLOW_REF,
                "canonical_dispatch_id": run_id,
            }
            finding = "harness failed before a validated Guard result"
            envelope = {
                "run_envelope_schema": "evoom.oss-run-envelope/1",
                "study_id": oss_common.STUDY_ID,
                "case_id": case_id,
                "claim_scope": claim_scope,
                "manifest_sha256": oss_common.sha256_file(manifest),
                "manifest_git_commit": commit,
                "execution_git_commit": commit,
                "protocol_tag": oss_common.PROTOCOL_TAG,
                "protocol_tag_commit": commit,
                "engine": {
                    "release": oss_common.ENGINE_VERSION,
                    "sha256": oss_common.ENGINE_SHA256,
                },
                "candidate_sha256": oss_common.sha256_file(
                    case_dir / "candidate.diff"
                ),
                "candidate_canonical_sha256": case["candidate_canonical_sha256"],
                "policy_sha256": oss_common.sha256_file(
                    oss_common.resolve_study_file(case["policy"], "policies")
                ),
                "environment_sha256": oss_common.sha256_file(environment_path),
                "environment": oss_common.load_json(environment_path),
                "source": case["source"],
                "runtime": {
                    "os_release": {"VERSION_ID": "24.04"},
                },
                "runner": runner,
                "started_utc": "2026-07-15T00:00:00Z",
                "finished_utc": "2026-07-15T00:00:01Z",
                "guard_exit_code": None,
                "harness_failure": {"type": "RuntimeError", "message": "boom"},
                "record_integrity_problems": [],
                "conformance_findings": [finding],
                "verify_and_expectation_problems": [finding],
                "artifact_valid": True,
                "success": False,
                "output_files_present": sorted(run_oss_case.OUTPUT_NAMES),
                "pre_envelope_output_sha256": pre_hashes,
            }
            (output / "run-envelope.json").write_bytes(
                oss_common.canonical_json_bytes(envelope)
            )
            with (
                mock.patch.object(
                    evaluate_oss, "verify_manifest", return_value=(fake_manifest, [])
                ),
                mock.patch.object(
                    evaluate_oss,
                    "case_map",
                    return_value={case_id: (case_dir, case)},
                ),
                mock.patch.object(
                    evaluate_oss, "manifest_path", return_value=manifest
                ),
                mock.patch.object(
                    evaluate_oss, "verify_local_materialization", return_value=[]
                ),
            ):
                summary, _, problems = evaluate_oss.evaluate(
                    root / "results", Path("unused-engine"), github_run_id=run_id
                )
        self.assertEqual([], problems)
        self.assertTrue(summary["study_integrity_valid"])
        self.assertFalse(summary["all_cases_conformant"])
        self.assertEqual(1, summary["infrastructure_errors"])
        self.assertEqual(0, summary["green_reconstructed_baselines"]["count"])
        self.assertIsNone(summary["cases"][0]["observed"])
        self.assertEqual([f"{case_id}: {finding}"], summary["outcome_findings"])

    def test_missing_outputs_remain_in_fixed_denominators(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            summary, _, problems = evaluate_oss.evaluate(
                Path(temporary), Path("unused-engine"), github_run_id="123"
            )
        self.assertTrue(problems)
        self.assertEqual({"conformant": 0, "total": 6}, summary["source_only_conformance"])
        self.assertEqual(
            {"conformant": 0, "total": 6},
            summary["protected_policy_trip_detection"],
        )
        self.assertEqual(12, sum(summary["by_ecosystem"].values()))

    def test_nested_output_entry_is_not_ignored(self) -> None:
        case_id, (case_dir, case) = next(iter(oss_common.case_map().items()))
        fake_manifest = {
            "claim_scope": {
                "accuracy_claims_allowed": False,
                "independent": False,
                "kind": "same_owner_compatibility",
            },
            "engine": {},
            "corpus_sha256": "0" * 64,
        }
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / oss_common.STUDY_ID / case_id
            (output / "nested").mkdir(parents=True)
            with (
                mock.patch.object(
                    evaluate_oss, "verify_manifest", return_value=(fake_manifest, [])
                ),
                mock.patch.object(
                    evaluate_oss, "case_map", return_value={case_id: (case_dir, case)}
                ),
                mock.patch.object(evaluate_oss, "sha256_file", return_value="0" * 64),
            ):
                _, _, problems = evaluate_oss.evaluate(
                    Path(temporary), Path("unused-engine"), github_run_id="123"
                )
        self.assertTrue(any("output inventory mismatch" in problem for problem in problems))

    def test_timing_contract_rejects_nonfinite_negative_and_short_total(self) -> None:
        valid = {
            "source_acquisition_and_verification_seconds": 1,
            "head_checkout_seconds": 1,
            "guard_seconds": 2,
            "total_seconds": 4,
        }
        self.assertEqual((valid, []), evaluate_oss.validated_timings(valid))
        for bad in (-1, float("nan"), float("inf")):
            payload = dict(valid, guard_seconds=bad)
            self.assertTrue(evaluate_oss.validated_timings(payload)[1])
        self.assertTrue(
            evaluate_oss.validated_timings(dict(valid, total_seconds=1))[1]
        )
        self.assertTrue(
            evaluate_oss.validated_timings(dict(valid, untrusted_extra=1))[1]
        )
        self.assertEqual(
            (1.0, []),
            evaluate_oss.validated_failure_timing(
                {"harness_failed": True, "total_seconds": 1.0}
            ),
        )

    def test_negative_study_outcome_does_not_block_integrity_valid_publication(self) -> None:
        summary = {
            "repository_count": 1,
            "case_count": 1,
            "outcome_findings": ["case: expected PASS, got FAIL"],
        }
        with tempfile.TemporaryDirectory() as temporary:
            results = Path(temporary)
            (results / oss_common.STUDY_ID).mkdir()
            argv = [
                "evaluate_oss.py",
                "--study",
                oss_common.STUDY_ID,
                "--results",
                str(results),
                "--github-run-id",
                "123",
                "--write",
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(evaluate_oss, "acquire_engine", return_value=Path("engine")),
                mock.patch.object(
                    evaluate_oss,
                    "evaluate",
                    return_value=(summary, "negative but valid\n", []),
                ),
            ):
                self.assertEqual(0, evaluate_oss.main())

    def test_write_refuses_integrity_invalid_results_before_creating_meta(self) -> None:
        summary = {"repository_count": 1, "case_count": 1}
        with tempfile.TemporaryDirectory() as temporary:
            results = Path(temporary)
            study = results / oss_common.STUDY_ID
            study.mkdir()
            argv = [
                "evaluate_oss.py",
                "--study",
                oss_common.STUDY_ID,
                "--results",
                str(results),
                "--github-run-id",
                "123",
                "--write",
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(evaluate_oss, "acquire_engine", return_value=Path("engine")),
                mock.patch.object(
                    evaluate_oss,
                    "evaluate",
                    return_value=(summary, "invalid\n", ["tampered artifact"]),
                ),
            ):
                self.assertEqual(1, evaluate_oss.main())
            self.assertFalse((study / "SUMMARY.json").exists())
            self.assertFalse((study / "RESULTS.md").exists())
            self.assertFalse((study / "OUTPUTS.sha256").exists())

    def test_virtual_checksums_equal_post_write_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            study = Path(temporary)
            case = study / "case"
            case.mkdir()
            (case / "raw.txt").write_bytes(b"raw")
            virtual = {"RESULTS.md": b"result\n", "SUMMARY.json": b"{}\n"}
            before = evaluate_oss.output_checksums(study, virtual)
            for name, data in virtual.items():
                (study / name).write_bytes(data)
            after = evaluate_oss.output_checksums(study)
        self.assertEqual(before, after)

    def test_check_rejects_linked_summary_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            results = Path(temporary)
            study = results / oss_common.STUDY_ID
            study.mkdir()
            target = results / "outside.json"
            target.write_text("{}\n", encoding="utf-8")
            try:
                (study / "SUMMARY.json").symlink_to(target)
            except OSError:
                return
            argv = [
                "evaluate_oss.py",
                "--study",
                oss_common.STUDY_ID,
                "--results",
                str(results),
                "--check",
            ]
            with mock.patch.object(sys, "argv", argv):
                with self.assertRaises(SystemExit):
                    evaluate_oss.main()

    def test_check_rejects_malformed_summary_execution_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            results = Path(temporary)
            study = results / oss_common.STUDY_ID
            study.mkdir()
            (study / "SUMMARY.json").write_bytes(
                oss_common.canonical_json_bytes({"execution": []})
            )
            argv = [
                "evaluate_oss.py",
                "--study",
                oss_common.STUDY_ID,
                "--results",
                str(results),
                "--check",
            ]
            with mock.patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(SystemExit, "execution object"):
                    evaluate_oss.main()


class OssCanonicalDispatchTests(unittest.TestCase):
    def test_matching_runs_selects_earliest_and_uses_id_as_tiebreaker(self) -> None:
        commit = "a" * 40
        runs = [
            {
                "id": 20,
                "event": "workflow_dispatch",
                "head_sha": commit,
                "created_at": "2026-01-02T00:00:00Z",
            },
            {
                "id": 10,
                "event": "workflow_dispatch",
                "head_sha": commit,
                "created_at": "2026-01-02T00:00:00Z",
            },
            {"id": "malformed"},
        ]
        first, visible = check_canonical_dispatch.matching_runs(
            runs, commit=commit, current_run_id="20"
        )
        self.assertEqual("10", first)
        self.assertTrue(visible)

    def test_fetch_all_runs_paginates_without_silent_truncation(self) -> None:
        first_page = [{"id": value} for value in range(100)]
        second_page = [{"id": 100}]
        with mock.patch.object(
            check_canonical_dispatch,
            "_request_page",  # noqa: SLF001
            side_effect=[first_page, second_page],
        ) as request:
            runs = check_canonical_dispatch.fetch_all_runs("token")
        self.assertEqual(101, len(runs))
        self.assertEqual([mock.call("token", 1), mock.call("token", 2)], request.call_args_list)

    def test_github_identity_requires_exact_protected_tag_and_canonical_marker(self) -> None:
        commit = "b" * 40
        environment = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": run_oss_case.EXPECTED_GITHUB_REPOSITORY,
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": commit,
            "GITHUB_REF": run_oss_case.EXPECTED_GITHUB_REF,
            "GITHUB_REF_NAME": oss_common.PROTOCOL_TAG,
            "GITHUB_REF_TYPE": "tag",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_WORKFLOW_REF": run_oss_case.EXPECTED_GITHUB_WORKFLOW_REF,
            "OSS_CANONICAL_DISPATCH_ID": "123",
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            self.assertEqual([], run_oss_case.github_execution_problems(commit))
            os.environ["GITHUB_REF_TYPE"] = "branch"
            self.assertIn(
                "unexpected GitHub execution identity for github_ref_type",
                run_oss_case.github_execution_problems(commit),
            )

    def test_watchdog_covers_setup_and_test_for_candidate_and_baseline(self) -> None:
        self.assertEqual(
            5400,
            run_oss_case.guard_watchdog_seconds(
                {"timeout": 1200, "setup_command": ["cmake"]},
                {"baseline_evidence": True},
            ),
        )
        self.assertEqual(
            1800,
            run_oss_case.guard_watchdog_seconds(
                {"timeout": 1200, "setup_command": None},
                {"baseline_evidence": False},
            ),
        )


if __name__ == "__main__":
    unittest.main()
