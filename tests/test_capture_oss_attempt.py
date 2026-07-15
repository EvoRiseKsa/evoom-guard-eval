from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import zipfile
from email.message import Message
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness"))

import capture_oss_attempt as capture  # noqa: E402


def api_step(name: str, conclusion: str) -> dict[str, object]:
    return {"name": name, "status": "completed", "conclusion": conclusion}


def snapshots() -> dict[str, object]:
    jobs = []
    for number, case_id in enumerate(capture.EXPECTED_CASES, start=1):
        jobs.append(
            {
                "id": 1000 + number,
                "run_id": capture.EXPECTED_RUN_ID,
                "run_attempt": capture.EXPECTED_RUN_ATTEMPT,
                "name": case_id,
                "head_sha": capture.EXPECTED_PROTOCOL_COMMIT,
                "head_branch": capture.EXPECTED_PROTOCOL_TAG,
                "workflow_name": capture.EXPECTED_WORKFLOW_NAME,
                "status": "completed",
                "conclusion": "failure",
                "steps": [
                    api_step(name, conclusion)
                    for name, conclusion in capture.EXPECTED_STEP_CONCLUSIONS.items()
                ],
            }
        )
    dispatch = {
        "id": capture.EXPECTED_RUN_ID,
        "created_at": "2026-07-15T03:00:00Z",
        "event": "workflow_dispatch",
        "head_branch": capture.EXPECTED_PROTOCOL_TAG,
        "head_sha": capture.EXPECTED_PROTOCOL_COMMIT,
        "path": capture.EXPECTED_WORKFLOW_PATH,
    }
    return {
        "run.json": {
            "id": capture.EXPECTED_RUN_ID,
            "run_attempt": capture.EXPECTED_RUN_ATTEMPT,
            "workflow_id": 88,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "failure",
            "head_branch": capture.EXPECTED_PROTOCOL_TAG,
            "head_sha": capture.EXPECTED_PROTOCOL_COMMIT,
            "path": capture.EXPECTED_WORKFLOW_PATH,
            "name": capture.EXPECTED_WORKFLOW_NAME,
            "repository": {"full_name": capture.EXPECTED_REPOSITORY},
            "html_url": (
                f"https://github.com/{capture.EXPECTED_REPOSITORY}/actions/runs/"
                f"{capture.EXPECTED_RUN_ID}"
            ),
        },
        "workflow.json": {
            "id": 88,
            "path": capture.EXPECTED_WORKFLOW_PATH,
            "name": capture.EXPECTED_WORKFLOW_NAME,
        },
        "jobs.json": {"total_count": len(jobs), "jobs": jobs},
        "artifacts.json": {"total_count": 0, "artifacts": []},
        "dispatches.json": {"total_count": 1, "workflow_runs": [dispatch]},
        "tag-ref.json": {
            "ref": f"refs/tags/{capture.EXPECTED_PROTOCOL_TAG}",
            "object": {"type": "tag", "sha": capture.EXPECTED_TAG_OBJECT},
        },
        "tag-object.json": {
            "tag": capture.EXPECTED_PROTOCOL_TAG,
            "object": {"type": "commit", "sha": capture.EXPECTED_PROTOCOL_COMMIT},
        },
        "tag-ruleset.json": {
            "id": capture.EXPECTED_TAG_RULESET_ID,
            "target": "tag",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {"include": ["refs/tags/oss-protocol-v*"], "exclude": []}
            },
            "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}],
        },
    }


def log_archive() -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for case_id in capture.EXPECTED_CASES:
            archive.writestr(
                f"{case_id}/Install trusted execution boundary.txt",
                f"prefix\n{capture.EXPECTED_BOUNDARY_FAILURE}\nsuffix\n",
            )
    return stream.getvalue()


def generic_zip(name: str, payload: str = "evidence") -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, payload)
    return stream.getvalue()


def current_fixture(
    *, mixed: bool
) -> tuple[dict[str, object], bytes, dict[int, bytes], dict[str, object]]:
    import oss_common

    run_id = 424242
    commit = "c" * 40
    protocol: dict[str, object] = {
        "study_id": oss_common.STUDY_ID,
        "protocol_tag": oss_common.PROTOCOL_TAG,
        "protocol_commit": commit,
        "manifest_path": (
            f"studies/oss-compat-v1/manifests/{oss_common.STUDY_ID}.json"
        ),
        "manifest_sha256": "d" * 64,
    }
    cases = sorted(oss_common.case_map())
    infra_case = cases[0] if mixed else None
    jobs: list[dict[str, object]] = []
    artifacts: list[dict[str, object]] = []
    archives: dict[int, bytes] = {}
    for index, case_id in enumerate(cases, start=1):
        is_infra = case_id == infra_case
        required = capture._current_required_step_names(case_id)  # noqa: SLF001
        conclusions = {name: "success" for name in required}
        conclusions["Upload immutable infrastructure output"] = "skipped"
        if is_infra:
            conclusions["Install trusted execution boundary"] = "failure"
            conclusions["Run frozen case"] = "skipped"
            conclusions["Upload immutable raw case output"] = "skipped"
            conclusions["Upload immutable infrastructure output"] = "success"
        jobs.append(
            {
                "id": 5000 + index,
                "run_id": run_id,
                "run_attempt": 1,
                "name": case_id,
                "head_sha": commit,
                "head_branch": oss_common.PROTOCOL_TAG,
                "workflow_name": capture.EXPECTED_WORKFLOW_NAME,
                "status": "completed",
                "conclusion": "failure" if is_infra else "success",
                "steps": [
                    {
                        "name": name,
                        "number": number,
                        "status": "completed",
                        "conclusion": conclusions[name],
                    }
                    for number, name in enumerate(required, start=1)
                ],
            }
        )
        artifact_id = 7000 + index
        artifact_name = f"oss-infra-{case_id}" if is_infra else f"oss-{case_id}"
        archive = generic_zip(f"{case_id}/evidence.json", case_id)
        archives[artifact_id] = archive
        artifacts.append(
            {
                "id": artifact_id,
                "name": artifact_name,
                "size_in_bytes": len(archive),
                "digest": f"sha256:{hashlib.sha256(archive).hexdigest()}",
                "expired": False,
                "archive_download_url": (
                    f"{capture.API_ROOT}/repos/{capture.EXPECTED_REPOSITORY}/"
                    f"actions/artifacts/{artifact_id}/zip"
                ),
                "workflow_run": {"id": run_id, "head_sha": commit},
            }
        )
    dispatch = {
        "id": run_id,
        "created_at": "2026-07-15T05:00:00Z",
        "event": "workflow_dispatch",
        "head_branch": oss_common.PROTOCOL_TAG,
        "head_sha": commit,
        "path": capture.EXPECTED_WORKFLOW_PATH,
    }
    snapshots_value: dict[str, object] = {
        "run.json": {
            "id": run_id,
            "run_attempt": 1,
            "workflow_id": 88,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "failure" if mixed else "success",
            "head_branch": oss_common.PROTOCOL_TAG,
            "head_sha": commit,
            "path": capture.EXPECTED_WORKFLOW_PATH,
            "name": capture.EXPECTED_WORKFLOW_NAME,
            "created_at": dispatch["created_at"],
            "repository": {"full_name": capture.EXPECTED_REPOSITORY},
            "actor": {"login": "EvoRiseKsa"},
            "triggering_actor": {"login": "EvoRiseKsa"},
            "html_url": (
                f"https://github.com/{capture.EXPECTED_REPOSITORY}/actions/runs/"
                f"{run_id}"
            ),
        },
        "workflow.json": {
            "id": 88,
            "path": capture.EXPECTED_WORKFLOW_PATH,
            "name": capture.EXPECTED_WORKFLOW_NAME,
        },
        "jobs.json": {"total_count": len(jobs), "jobs": jobs},
        "artifacts.json": {
            "total_count": len(artifacts),
            "artifacts": artifacts,
        },
        "dispatches.json": {"total_count": 1, "workflow_runs": [dispatch]},
        "tag-ref.json": {
            "ref": f"refs/tags/{oss_common.PROTOCOL_TAG}",
            "object": {"type": "tag", "sha": "e" * 40},
        },
        "tag-object.json": {
            "sha": "e" * 40,
            "tag": oss_common.PROTOCOL_TAG,
            "object": {"type": "commit", "sha": commit},
        },
        "tag-ruleset.json": {
            "id": capture.EXPECTED_TAG_RULESET_ID,
            "target": "tag",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {
                    "include": ["refs/tags/oss-protocol-v*"],
                    "exclude": [],
                }
            },
            "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}],
        },
    }
    return snapshots_value, generic_zip("run.log"), archives, protocol


class CaptureValidationTests(unittest.TestCase):
    def test_exact_invalid_attempt_is_classified_without_product_inference(
        self,
    ) -> None:
        value = capture.validate_capture(
            snapshots(), log_archive(), "2026-07-15T04:00:00Z"
        )
        self.assertEqual("invalid_before_measurement", value["classification"])
        self.assertIs(value["product_inference_allowed"], False)
        self.assertEqual(0, value["cases_started"])
        self.assertEqual(0, value["guard_invocations"])
        self.assertEqual(0, value["product_artifact_count"])
        self.assertEqual(12, value["case_count"])
        self.assertEqual(12, value["boundary_failure"]["boundary_failure_occurrences"])

    def test_noncanonical_dispatch_and_changed_step_are_rejected(self) -> None:
        earlier = snapshots()
        earlier["dispatches.json"]["workflow_runs"].append(  # type: ignore[index]
            {
                "id": capture.EXPECTED_RUN_ID - 1,
                "created_at": "2026-07-15T02:59:59Z",
                "event": "workflow_dispatch",
                "head_branch": capture.EXPECTED_PROTOCOL_TAG,
                "head_sha": capture.EXPECTED_PROTOCOL_COMMIT,
                "path": capture.EXPECTED_WORKFLOW_PATH,
            }
        )
        earlier["dispatches.json"]["total_count"] = 2  # type: ignore[index]
        with self.assertRaisesRegex(RuntimeError, "first API-visible dispatch id"):
            capture.validate_capture(earlier, log_archive(), "2026-07-15T04:00:00Z")

        changed = snapshots()
        changed["jobs.json"]["jobs"][0]["steps"][2]["conclusion"] = "success"  # type: ignore[index]
        with self.assertRaisesRegex(RuntimeError, "conclusion mismatch"):
            capture.validate_capture(changed, log_archive(), "2026-07-15T04:00:00Z")

    def test_product_artifact_or_missing_log_failure_is_rejected(self) -> None:
        artifact = snapshots()
        artifact["artifacts.json"] = {  # type: ignore[assignment]
            "total_count": 1,
            "artifacts": [{"name": "oss-forged"}],
        }
        with self.assertRaisesRegex(RuntimeError, "artifacts.total_count"):
            capture.validate_capture(artifact, log_archive(), "2026-07-15T04:00:00Z")

        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("job.txt", "different failure")
        with self.assertRaisesRegex(RuntimeError, "for all matrix jobs"):
            capture.validate_capture(
                snapshots(), stream.getvalue(), "2026-07-15T04:00:00Z"
            )

    def test_tag_protection_is_part_of_the_capture_contract(self) -> None:
        unprotected = snapshots()
        unprotected["tag-ruleset.json"]["bypass_actors"] = [  # type: ignore[index]
            {"actor_type": "RepositoryRole", "actor_id": 5}
        ]
        with self.assertRaisesRegex(RuntimeError, "bypass actors"):
            capture.validate_capture(unprotected, log_archive(), "2026-07-15T04:00:00Z")


class CaptureWriterTests(unittest.TestCase):
    def test_bundle_is_complete_checksummed_and_never_overwritten(self) -> None:
        evidence = snapshots()
        logs = log_archive()
        attempt = capture.validate_capture(evidence, logs, "2026-07-15T04:00:00Z")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "attempt"
            capture.write_capture_bundle(output, evidence, logs, attempt)
            self.assertTrue((output / "ATTEMPT.json").is_file())
            self.assertTrue((output / "FAILURE.md").is_file())
            self.assertEqual(logs, (output / "actions-logs.zip").read_bytes())
            written = json.loads((output / "ATTEMPT.json").read_text("utf-8"))
            self.assertIs(written["product_inference_allowed"], False)
            failure = (output / "FAILURE.md").read_text("utf-8")
            self.assertIn("not** a 0/12 product result", failure)

            checksum_lines = (output / "SHA256SUMS").read_text("ascii").splitlines()
            paths = [line.split("  ", 1)[1] for line in checksum_lines]
            self.assertEqual(sorted(paths), paths)
            self.assertNotIn("SHA256SUMS", paths)
            for line in checksum_lines:
                digest, relative = line.split("  ", 1)
                self.assertEqual(
                    hashlib.sha256((output / relative).read_bytes()).hexdigest(),
                    digest,
                )
            with self.assertRaises(FileExistsError):
                capture.write_capture_bundle(output, evidence, logs, attempt)


class CurrentAttemptCaptureTests(unittest.TestCase):
    def test_mixed_inventory_is_preserved_but_never_a_product_denominator(
        self,
    ) -> None:
        evidence, logs, archives, protocol = current_fixture(mixed=True)
        attempt = capture.validate_current_capture(
            evidence,
            logs,
            archives,
            "2026-07-15T06:00:00Z",
            run_id=424242,
            protocol=protocol,
        )
        self.assertEqual(
            "invalid_or_incomplete_before_product_materialization",
            attempt["classification"],
        )
        self.assertIs(attempt["product_materialization_eligible"], False)
        self.assertIs(attempt["product_evaluation_performed"], False)
        self.assertIs(attempt["product_inference_allowed"], False)
        self.assertEqual(11, attempt["product_artifact_count"])
        self.assertEqual(1, attempt["infrastructure_artifact_count"])
        self.assertEqual(12, attempt["artifact_count"])

    def test_exact_product_inventory_is_only_eligible_not_evaluated(self) -> None:
        evidence, logs, archives, protocol = current_fixture(mixed=False)
        attempt = capture.validate_current_capture(
            evidence,
            logs,
            archives,
            "2026-07-15T06:00:00Z",
            run_id=424242,
            protocol=protocol,
        )
        self.assertEqual(
            "complete_product_inventory_not_evaluated", attempt["classification"]
        )
        self.assertIs(attempt["product_materialization_eligible"], True)
        self.assertIs(attempt["product_inference_allowed"], False)

    def test_product_eligibility_rejects_job_case_conclusion_mismatch(self) -> None:
        evidence, logs, archives, protocol = current_fixture(mixed=False)
        first_job = evidence["jobs.json"]["jobs"][0]  # type: ignore[index]
        first_job["conclusion"] = "failure"
        evidence["run.json"]["conclusion"] = "failure"  # type: ignore[index]
        attempt = capture.validate_current_capture(
            evidence,
            logs,
            archives,
            "2026-07-15T06:00:00Z",
            run_id=424242,
            protocol=protocol,
        )
        self.assertIs(attempt["product_materialization_eligible"], False)
        self.assertEqual(
            "invalid_or_incomplete_before_product_materialization",
            attempt["classification"],
        )

    def test_product_eligibility_rejects_run_matrix_conclusion_mismatch(self) -> None:
        evidence, logs, archives, protocol = current_fixture(mixed=False)
        evidence["run.json"]["conclusion"] = "failure"  # type: ignore[index]
        attempt = capture.validate_current_capture(
            evidence,
            logs,
            archives,
            "2026-07-15T06:00:00Z",
            run_id=424242,
            protocol=protocol,
        )
        self.assertIs(attempt["product_materialization_eligible"], False)
        self.assertEqual(
            "invalid_or_incomplete_before_product_materialization",
            attempt["classification"],
        )

    def test_current_capture_rejects_noncanonical_or_unbound_evidence(self) -> None:
        evidence, logs, archives, protocol = current_fixture(mixed=True)
        evidence["dispatches.json"]["workflow_runs"].append(  # type: ignore[index]
            {
                "id": 424241,
                "created_at": "2026-07-15T04:59:59Z",
                "event": "workflow_dispatch",
                "head_branch": protocol["protocol_tag"],
                "head_sha": protocol["protocol_commit"],
                "path": capture.EXPECTED_WORKFLOW_PATH,
            }
        )
        evidence["dispatches.json"]["total_count"] = 2  # type: ignore[index]
        with self.assertRaisesRegex(RuntimeError, "first API-visible dispatch id"):
            capture.validate_current_capture(
                evidence,
                logs,
                archives,
                "2026-07-15T06:00:00Z",
                run_id=424242,
                protocol=protocol,
            )

        evidence, logs, archives, protocol = current_fixture(mixed=True)
        artifact_id = next(iter(archives))
        archives[artifact_id] += b"tamper"
        with self.assertRaisesRegex(RuntimeError, "valid ZIP|byte size|API digest"):
            capture.validate_current_capture(
                evidence,
                logs,
                archives,
                "2026-07-15T06:00:00Z",
                run_id=424242,
                protocol=protocol,
            )

    def test_current_bundle_keeps_archives_unextracted_and_is_atomic(self) -> None:
        evidence, logs, archives, protocol = current_fixture(mixed=True)
        attempt = capture.validate_current_capture(
            evidence,
            logs,
            archives,
            "2026-07-15T06:00:00Z",
            run_id=424242,
            protocol=protocol,
        )
        manifest = b'{"study_id":"oss-pilot-02"}\n'
        protocol["manifest_sha256"] = hashlib.sha256(manifest).hexdigest()
        attempt["manifest_sha256"] = protocol["manifest_sha256"]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "attempt"
            capture.write_current_capture_bundle(
                output, evidence, logs, archives, manifest, attempt
            )
            self.assertEqual(manifest, (output / "FROZEN-MANIFEST.json").read_bytes())
            self.assertEqual(
                set(archives),
                {int(path.stem) for path in (output / "artifacts").glob("*.zip")},
            )
            self.assertFalse(any(output.rglob("evidence.json")))
            checksum_lines = (output / "SHA256SUMS").read_text("ascii").splitlines()
            for line in checksum_lines:
                digest, relative = line.split("  ", 1)
                self.assertEqual(
                    hashlib.sha256((output / relative).read_bytes()).hexdigest(),
                    digest,
                )
            with self.assertRaises(FileExistsError):
                capture.write_current_capture_bundle(
                    output, evidence, logs, archives, manifest, attempt
                )


class AuthenticationAndRedirectTests(unittest.TestCase):
    def test_environment_token_prevents_auth_subprocess(self) -> None:
        with (
            mock.patch.dict(os.environ, {"GH_TOKEN": "secret-value"}, clear=True),
            mock.patch.object(subprocess, "run") as run,
        ):
            self.assertEqual("secret-value", capture.github_token())
        run.assert_not_called()

    def test_api_token_is_not_forwarded_to_signed_download_url(self) -> None:
        headers = Message()
        headers["Location"] = "https://example.invalid/signed?sig=value"
        redirect = urllib.error.HTTPError(
            "https://api.github.com/example", 302, "Found", headers, None
        )

        class RedirectingOpener:
            def open(self, request: object, timeout: int) -> None:
                raise redirect

        class Response:
            status = 200
            headers = {"Content-Length": "3"}

            def __enter__(self) -> Response:
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self, size: int) -> bytes:
                return b"zip"

        with (
            mock.patch.object(
                capture.urllib.request,
                "build_opener",
                return_value=RedirectingOpener(),
            ),
            mock.patch.object(
                capture.urllib.request, "urlopen", return_value=Response()
            ) as urlopen,
        ):
            data = capture.GitHubClient("api-secret").redirected_bytes("/example", 10)
        self.assertEqual(b"zip", data)
        signed_request = urlopen.call_args.args[0]
        self.assertNotIn("Authorization", signed_request.headers)


if __name__ == "__main__":
    unittest.main()
