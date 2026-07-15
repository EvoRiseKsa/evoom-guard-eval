from __future__ import annotations

import copy
import io
import stat
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness"))

import materialize_oss_artifacts as artifacts  # noqa: E402
import oss_common  # noqa: E402


def make_zip(files: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return stream.getvalue()


def mandatory_files() -> dict[str, bytes]:
    return {
        "guard.stdout.txt": b"",
        "guard.stderr.txt": b"failure\n",
        "timing.json": b"{}\n",
        "run-envelope.json": b"{}\n",
    }


def api_step(name: str, number: int, conclusion: str = "success") -> dict[str, object]:
    return {
        "name": name,
        "number": number,
        "status": "completed",
        "conclusion": conclusion,
    }


def required_python_steps(run_conclusion: str = "failure") -> list[dict[str, object]]:
    names = (
        artifacts.CHECKOUT_STEP,
        artifacts.SETUP_PYTHON_STEP,
        artifacts.PREFLIGHT_STEP,
        artifacts.IDENTITY_STEP,
        artifacts.INSTALL_BOUNDARY_STEP,
        artifacts.RUN_CASE_STEP,
        artifacts.KILL_PROCESSES_STEP,
        artifacts.UPLOAD_STEP,
    )
    return [
        api_step(name, number, run_conclusion if name == artifacts.RUN_CASE_STEP else "success")
        for number, name in enumerate(names, start=2)
    ]


def api_job(
    case_id: str = "case-a", conclusion: str = "failure"
) -> dict[str, object]:
    return {
        "id": 789,
        "run_id": 123,
        "name": case_id,
        "head_sha": "a" * 40,
        "head_branch": oss_common.PROTOCOL_TAG,
        "workflow_name": artifacts.WORKFLOW_NAME,
        "status": "completed",
        "conclusion": conclusion,
        "steps": required_python_steps(conclusion),
    }


class ArtifactZipTests(unittest.TestCase):
    def test_flat_failure_archive_is_accepted(self) -> None:
        self.assertEqual(mandatory_files(), artifacts._zip_entries(make_zip(mandatory_files())))  # noqa: SLF001

    def test_nested_traversal_and_unexpected_entries_are_rejected(self) -> None:
        for name in ("../escape", "nested/file", "/absolute", "unknown.txt"):
            payload = mandatory_files() | {name: b"x"}
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                artifacts._zip_entries(make_zip(payload))  # noqa: SLF001

    def test_symlink_and_duplicate_zip_entries_are_rejected(self) -> None:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for name, data in mandatory_files().items():
                archive.writestr(name, data)
            link = zipfile.ZipInfo("verdict.json")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, b"target")
        with self.assertRaises(RuntimeError):
            artifacts._zip_entries(stream.getvalue())  # noqa: SLF001

        stream = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(stream, "w") as archive:
                for name, data in mandatory_files().items():
                    archive.writestr(name, data)
                archive.writestr("timing.json", b"duplicate")
        with self.assertRaises(RuntimeError):
            artifacts._zip_entries(stream.getvalue())  # noqa: SLF001


class ArtifactIndexTests(unittest.TestCase):
    def _index(self, manifest: Path, archive: bytes) -> dict[str, object]:
        commit = "a" * 40
        run_id = 123
        digest = oss_common.sha256_bytes(archive)
        return {
            "run_index_schema": artifacts.RUN_INDEX_SCHEMA,
            "api_version": artifacts.API_VERSION,
            "repository": artifacts.EXPECTED_GITHUB_REPOSITORY,
            "study_id": oss_common.STUDY_ID,
            "protocol_tag": oss_common.PROTOCOL_TAG,
            "protocol_commit": commit,
            "manifest_sha256": oss_common.sha256_file(manifest),
            "run": {
                "id": run_id,
                "run_number": 1,
                "run_attempt": 1,
                "workflow_id": 2,
                "event": "workflow_dispatch",
                "status": "completed",
                "conclusion": "failure",
                "head_branch": oss_common.PROTOCOL_TAG,
                "head_sha": commit,
                "path": artifacts.WORKFLOW_PATH,
                "created_at": "2026-07-15T00:00:00Z",
                "updated_at": "2026-07-15T00:01:00Z",
                "run_started_at": "2026-07-15T00:00:01Z",
                "html_url": (
                    "https://github.com/"
                    f"{artifacts.EXPECTED_GITHUB_REPOSITORY}/actions/runs/123"
                ),
                "artifacts_url": (
                    "https://api.github.com/repos/"
                    f"{artifacts.EXPECTED_GITHUB_REPOSITORY}/actions/runs/123/artifacts"
                ),
                "actor": "EvoRiseKsa",
                "triggering_actor": "EvoRiseKsa",
            },
            "canonical_dispatch": {
                "selection": artifacts.CANONICAL_SELECTION,
                "workflow_path": artifacts.WORKFLOW_PATH,
                "event": "workflow_dispatch",
                "head_sha": commit,
                "first_run_id": run_id,
                "first_created_at": "2026-07-15T00:00:00Z",
            },
            "jobs": [
                {
                    "id": 789,
                    "run_id": run_id,
                    "run_attempt": 1,
                    "name": "case-a",
                    "head_sha": commit,
                    "head_branch": oss_common.PROTOCOL_TAG,
                    "workflow_name": artifacts.WORKFLOW_NAME,
                    "status": "completed",
                    "conclusion": "failure",
                    "steps": required_python_steps(),
                }
            ],
            "artifacts": [
                {
                    "id": 456,
                    "node_id": "node",
                    "name": "oss-case-a",
                    "size_in_bytes": len(archive),
                    "created_at": "2026-07-15T00:01:00Z",
                    "updated_at": "2026-07-15T00:01:00Z",
                    "expires_at": "2026-10-13T00:01:00Z",
                    "digest": f"sha256:{digest}",
                    "archive_download_url": (
                        "https://api.github.com/repos/"
                        f"{artifacts.EXPECTED_GITHUB_REPOSITORY}/actions/artifacts/456/zip"
                    ),
                    "case_id": "case-a",
                    "archive_file": "archives/oss-case-a.zip",
                    "archive_sha256": digest,
                    "workflow_run_id": run_id,
                    "workflow_head_sha": commit,
                }
            ],
        }

    def test_index_and_archive_bind_extracted_bytes(self) -> None:
        archive = make_zip(mandatory_files())
        with tempfile.TemporaryDirectory() as temporary:
            study = Path(temporary)
            manifest = study / "manifest.json"
            manifest.write_text("{}\n", encoding="utf-8")
            (study / "archives").mkdir()
            (study / "archives" / "oss-case-a.zip").write_bytes(archive)
            output = study / "case-a"
            output.mkdir()
            for name, data in mandatory_files().items():
                (output / name).write_bytes(data)
            index = self._index(manifest, archive)
            with (
                mock.patch.object(artifacts, "_protocol_commit", return_value="a" * 40),
                mock.patch.object(artifacts, "manifest_path", return_value=manifest),
                mock.patch.object(
                    artifacts,
                    "case_map",
                    return_value={"case-a": (None, {"ecosystem": "python"})},
                ),
            ):
                self.assertEqual(
                    [],
                    artifacts.verify_local_materialization(study, index, "123"),
                )
                index["run"]["head_branch"] = "main"  # type: ignore[index]
                self.assertIn(
                    "RUN.json run mismatch for head_branch",
                    artifacts.verify_local_materialization(study, index, "123"),
                )
                index["run"]["head_branch"] = oss_common.PROTOCOL_TAG  # type: ignore[index]
                (output / "guard.stderr.txt").write_bytes(b"substituted")
                problems = artifacts.verify_local_materialization(study, index, "123")
        self.assertTrue(any("differs from archive" in problem for problem in problems))

    def test_online_verification_requires_exact_api_index(self) -> None:
        archive = make_zip(mandatory_files())
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / "manifest.json"
            manifest.write_text("{}\n", encoding="utf-8")
            index = self._index(manifest, archive)
            with mock.patch.object(artifacts, "fetch_run_index", return_value=index):
                self.assertEqual([], artifacts.verify_online_index(index, "token"))
                changed = dict(index, api_version="wrong")
                self.assertTrue(artifacts.verify_online_index(changed, "token"))
                changed_job = copy.deepcopy(index)
                changed_job["jobs"][0]["steps"][-1]["conclusion"] = "failure"  # type: ignore[index]
                self.assertTrue(artifacts.verify_online_index(changed_job, "token"))

    def test_local_index_rejects_forged_job_or_dispatch_proof(self) -> None:
        archive = make_zip(mandatory_files())
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / "manifest.json"
            manifest.write_text("{}\n", encoding="utf-8")
            index = self._index(manifest, archive)
            case = {"case-a": (None, {"ecosystem": "python"})}
            with (
                mock.patch.object(artifacts, "_protocol_commit", return_value="a" * 40),
                mock.patch.object(artifacts, "manifest_path", return_value=manifest),
                mock.patch.object(artifacts, "case_map", return_value=case),
            ):
                self.assertEqual([], artifacts.run_index_problems(index, "123"))
                forged_dispatch = copy.deepcopy(index)
                forged_dispatch["canonical_dispatch"]["first_run_id"] = 122  # type: ignore[index]
                self.assertIn(
                    "RUN.json canonical dispatch mismatch for first_run_id",
                    artifacts.run_index_problems(forged_dispatch, "123"),
                )
                forged_job = copy.deepcopy(index)
                forged_job["jobs"][0]["steps"][-1]["conclusion"] = "failure"  # type: ignore[index]
                self.assertTrue(
                    any(
                        "required job step failed or was skipped" in problem
                        for problem in artifacts.run_index_problems(forged_job, "123")
                    )
                )

    def test_canonical_dispatch_is_earliest_by_timestamp_then_id(self) -> None:
        runs = [
            {
                "id": 123,
                "event": "workflow_dispatch",
                "head_sha": "a" * 40,
                "created_at": "2026-07-15T00:00:00Z",
            },
            {
                "id": 124,
                "event": "workflow_dispatch",
                "head_sha": "a" * 40,
                "created_at": "2026-07-15T00:01:00Z",
            },
            {
                "id": 100,
                "event": "workflow_dispatch",
                "head_sha": "b" * 40,
                "created_at": "2026-07-14T00:00:00Z",
            },
        ]
        proof = artifacts._canonical_dispatch_proof(runs, "123", "a" * 40)  # noqa: SLF001
        self.assertEqual(123, proof["first_run_id"])
        with self.assertRaises(RuntimeError):
            artifacts._canonical_dispatch_proof(runs, "124", "a" * 40)  # noqa: SLF001
        tied = copy.deepcopy(runs)
        tied[1]["created_at"] = tied[0]["created_at"]
        tied[1]["id"] = 122
        with self.assertRaises(RuntimeError):
            artifacts._canonical_dispatch_proof(tied, "123", "a" * 40)  # noqa: SLF001

    def test_dispatch_inventory_uses_workflow_filename_and_fails_closed(self) -> None:
        run = {
            "id": 123,
            "event": "workflow_dispatch",
            "head_sha": "a" * 40,
            "created_at": "2026-07-15T00:00:00Z",
        }
        with mock.patch.object(
            artifacts,
            "_api_json",
            return_value={"total_count": 1, "workflow_runs": [run]},
        ) as request:
            self.assertEqual([run], artifacts._workflow_dispatch_runs("token"))  # noqa: SLF001
        request.assert_called_once_with(
            "/repos/EvoRiseKsa/evoom-guard-eval/actions/workflows/"
            "oss-compat-run.yml/runs?event=workflow_dispatch&per_page=100&page=1",
            "token",
        )
        with (
            mock.patch.object(
                artifacts,
                "_api_json",
                return_value={"total_count": 2, "workflow_runs": [run]},
            ),
            self.assertRaises(RuntimeError),
        ):
            artifacts._workflow_dispatch_runs("token")  # noqa: SLF001

    def test_jobs_require_exact_inventory_and_allow_case_failure(self) -> None:
        payload = {"total_count": 1, "jobs": [api_job()]}
        case = {"case-a": (None, {"ecosystem": "python"})}
        with mock.patch.object(artifacts, "case_map", return_value=case):
            selected = artifacts._selected_jobs(payload, "123", "a" * 40)  # noqa: SLF001
            self.assertEqual("failure", selected[0]["conclusion"])
            self.assertEqual(
                "failure",
                next(
                    step["conclusion"]
                    for step in selected[0]["steps"]
                    if step["name"] == artifacts.RUN_CASE_STEP
                ),
            )
            for malformed in (
                {"total_count": 0, "jobs": []},
                {"total_count": 2, "jobs": [api_job(), api_job("unexpected")]},
            ):
                with self.subTest(malformed=malformed), self.assertRaises(RuntimeError):
                    artifacts._selected_jobs(malformed, "123", "a" * 40)  # noqa: SLF001

    def test_jobs_reject_failed_or_missing_official_steps(self) -> None:
        case = {"case-a": (None, {"ecosystem": "python"})}
        required_success = (
            artifacts.CHECKOUT_STEP,
            artifacts.SETUP_PYTHON_STEP,
            artifacts.PREFLIGHT_STEP,
            artifacts.IDENTITY_STEP,
            artifacts.INSTALL_BOUNDARY_STEP,
            artifacts.KILL_PROCESSES_STEP,
            artifacts.UPLOAD_STEP,
        )
        with mock.patch.object(artifacts, "case_map", return_value=case):
            for name in required_success:
                job = api_job()
                step = next(step for step in job["steps"] if step["name"] == name)  # type: ignore[union-attr]
                step["conclusion"] = "failure"  # type: ignore[index]
                with self.subTest(name=name), self.assertRaises(RuntimeError):
                    artifacts._selected_jobs(  # noqa: SLF001
                        {"total_count": 1, "jobs": [job]}, "123", "a" * 40
                    )
            job = api_job()
            job["steps"] = [
                step
                for step in job["steps"]  # type: ignore[union-attr]
                if step["name"] != artifacts.IDENTITY_STEP
            ]
            with self.assertRaises(RuntimeError):
                artifacts._selected_jobs(  # noqa: SLF001
                    {"total_count": 1, "jobs": [job]}, "123", "a" * 40
                )

    def test_jobs_require_the_runtime_specific_setup_step(self) -> None:
        node_case = {"case-a": (None, {"ecosystem": "node"})}
        job = api_job()
        with mock.patch.object(artifacts, "case_map", return_value=node_case):
            with self.assertRaises(RuntimeError):
                artifacts._selected_jobs(  # noqa: SLF001
                    {"total_count": 1, "jobs": [job]}, "123", "a" * 40
                )
            steps = job["steps"]  # type: ignore[assignment]
            steps.insert(3, api_step(artifacts.SETUP_NODE_STEP, 5))  # type: ignore[union-attr]
            for number, step in enumerate(steps, start=2):  # type: ignore[union-attr]
                step["number"] = number
            selected = artifacts._selected_jobs(  # noqa: SLF001
                {"total_count": 1, "jobs": [job]}, "123", "a" * 40
            )
        self.assertIn(
            artifacts.SETUP_NODE_STEP,
            {step["name"] for step in selected[0]["steps"]},
        )


if __name__ == "__main__":
    unittest.main()
