#!/usr/bin/env python3
"""Capture immutable, non-evaluative evidence for OSS protocol attempts.

The no-argument mode remains intentionally bound to the historical v0.1
attempt.  ``current --run-id`` captures a v0.2 attempt without extracting or
evaluating any case artifact; it exists so a mixed product/infrastructure run
can be retained without being reinterpreted as product evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
API_ROOT = "https://api.github.com"
API_VERSION = "2022-11-28"
USER_AGENT = "evoom-guard-eval-attempt-capture/1"

EXPECTED_REPOSITORY = "EvoRiseKsa/evoom-guard-eval"
EXPECTED_WORKFLOW_FILE = "oss-compat-run.yml"
EXPECTED_WORKFLOW_PATH = f".github/workflows/{EXPECTED_WORKFLOW_FILE}"
EXPECTED_WORKFLOW_NAME = "OSS compatibility study (manual, frozen)"
EXPECTED_RUN_ID = 29386936311
EXPECTED_RUN_ATTEMPT = 1
EXPECTED_STUDY_ID = "oss-pilot-01"
EXPECTED_PROTOCOL_TAG = "oss-protocol-v0.1"
EXPECTED_PROTOCOL_COMMIT = "9b7bd9e1fe6a01fe75ddf1676f59e9eddebd5822"
EXPECTED_TAG_OBJECT = "42268b4c0990285391ed2cff28f14088f26117f9"
EXPECTED_TAG_RULESET_ID = 18956782
EXPECTED_CASES = (
    "requests-pr-7498-source-only",
    "requests-pr-7502-test-edit",
    "express-pr-7265-source-only",
    "express-pr-7377-test-edit",
    "fzf-pr-4734-source-only",
    "fzf-pr-4797-test-edit",
    "ripgrep-pr-3464-source-only",
    "ripgrep-pr-3467-test-edit",
    "fmt-pr-4822-source-only",
    "fmt-pr-4825-test-edit",
    "cjson-pr-1006-source-only",
    "cjson-pr-991-test-edit",
)
EXPECTED_STEP_CONCLUSIONS = {
    "Prove first API-visible dispatch": "success",
    "Verify frozen study identity": "success",
    "Install trusted execution boundary": "failure",
    "Run frozen case": "skipped",
    "Upload immutable raw case output": "skipped",
}
EXPECTED_BOUNDARY_FAILURE = (
    "OSS EXECUTION BOUNDARY FAILED: real tool is writable by the untrusted uid: "
    "/usr/local/bin/cmake"
)
CAPTURE_SCHEMA = "evoom-oss-invalid-attempt/v1"
CURRENT_CAPTURE_SCHEMA = "evoom-oss-attempt-capture/2"
MAX_JSON_BYTES = 20 * 1024 * 1024
MAX_LOG_ARCHIVE_BYTES = 250 * 1024 * 1024
MAX_LOG_MEMBER_BYTES = 100 * 1024 * 1024
MAX_LOG_UNCOMPRESSED_BYTES = 500 * 1024 * 1024
MAX_ARTIFACT_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 500 * 1024 * 1024

FINAL_JOB_CONCLUSIONS = {
    "action_required",
    "cancelled",
    "failure",
    "neutral",
    "skipped",
    "stale",
    "startup_failure",
    "success",
    "timed_out",
}
FINAL_STEP_CONCLUSIONS = {
    "action_required",
    "cancelled",
    "failure",
    "neutral",
    "skipped",
    "stale",
    "startup_failure",
    "success",
    "timed_out",
}

OUTPUT_DIRECTORY = (
    ROOT
    / "studies"
    / "oss-compat-v1"
    / "attempts"
    / EXPECTED_STUDY_ID
    / str(EXPECTED_RUN_ID)
)


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_limited(response: Any, limit: int) -> bytes:
    declared = response.headers.get("Content-Length")
    if declared is not None:
        try:
            if int(declared) > limit:
                raise RuntimeError("GitHub response exceeds the capture size limit")
        except ValueError as exc:
            raise RuntimeError("GitHub returned an invalid Content-Length") from exc
    data = response.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError("GitHub response exceeds the capture size limit")
    return data


def github_token() -> str:
    """Return an API token without ever logging it or an auth-command response."""
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        token = os.environ.get(name, "").strip()
        if token:
            return token
    try:
        completed = subprocess.run(
            ["gh", "auth", "token", "--hostname", "github.com"],
            check=True,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(
            "no GitHub token is available in GH_TOKEN/GITHUB_TOKEN or gh auth"
        ) from exc
    token = completed.stdout.decode("utf-8", "strict").strip()
    if not token:
        raise RuntimeError("gh auth returned an empty GitHub token")
    return token


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(  # type: ignore[override]
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


class GitHubClient:
    def __init__(self, token: str) -> None:
        if not token:
            raise ValueError("GitHub token must not be empty")
        self._token = token

    def _request(self, path: str) -> urllib.request.Request:
        if not path.startswith("/"):
            raise ValueError("GitHub API path must start with '/'")
        return urllib.request.Request(
            API_ROOT + path,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": USER_AGENT,
                "X-GitHub-Api-Version": API_VERSION,
            },
        )

    def json(self, path: str) -> Any:
        try:
            with urllib.request.urlopen(self._request(path), timeout=60) as response:
                data = _read_limited(response, MAX_JSON_BYTES)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"GitHub API request failed with HTTP {exc.code}: {path}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"GitHub API request failed: {path}") from exc
        try:
            return json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"GitHub API returned invalid JSON: {path}") from exc

    def redirected_bytes(self, path: str, limit: int) -> bytes:
        """Download a signed artifact without forwarding the API bearer token."""
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(self._request(path), timeout=60) as response:
                raise RuntimeError(
                    f"GitHub did not redirect the signed download endpoint: {path} "
                    f"(HTTP {response.status})"
                )
        except urllib.error.HTTPError as exc:
            if exc.code not in {301, 302, 303, 307, 308}:
                raise RuntimeError(
                    f"GitHub signed download request failed with HTTP {exc.code}: {path}"
                ) from exc
            location = exc.headers.get("Location")
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"GitHub signed download request failed: {path}"
            ) from exc
        if not location:
            raise RuntimeError("GitHub signed download response has no Location header")
        parsed = urllib.parse.urlsplit(location)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username:
            raise RuntimeError("GitHub returned an unsafe signed download URL")
        # Deliberately omit Authorization here: Location is a short-lived signed URL.
        request = urllib.request.Request(
            location,
            headers={"Accept": "application/zip", "User-Agent": USER_AGENT},
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return _read_limited(response, limit)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"GitHub signed download failed with HTTP {exc.code}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError("GitHub signed download failed") from exc


def _expect_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    return value


def _expect_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise RuntimeError(f"{label} must be a JSON array")
    return value


def _require_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise RuntimeError(f"{label} mismatch: expected {expected!r}, got {actual!r}")


def _step_map(job: dict[str, Any]) -> dict[str, dict[str, Any]]:
    steps = _expect_list(job.get("steps"), f"job {job.get('name')} steps")
    by_name: dict[str, dict[str, Any]] = {}
    for raw in steps:
        step = _expect_object(raw, f"job {job.get('name')} step")
        name = step.get("name")
        if not isinstance(name, str) or not name:
            raise RuntimeError(f"job {job.get('name')} has a malformed step name")
        if name in by_name:
            raise RuntimeError(f"job {job.get('name')} has duplicate step {name!r}")
        by_name[name] = step
    return by_name


def _validate_log_archive(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_LOG_ARCHIVE_BYTES:
        raise RuntimeError("Actions log archive exceeds the capture size limit")
    if not zipfile.is_zipfile(BytesIO(data)):
        raise RuntimeError("Actions logs are not a valid ZIP archive")
    marker = EXPECTED_BOUNDARY_FAILURE.encode("utf-8")
    occurrences = 0
    matching_members: list[str] = []
    uncompressed = 0
    with zipfile.ZipFile(BytesIO(data)) as archive:
        infos = archive.infolist()
        if not infos or len(infos) > 2000:
            raise RuntimeError("Actions log archive has an invalid member count")
        for info in infos:
            if info.flag_bits & 0x1:
                raise RuntimeError("Actions log archive contains an encrypted member")
            if info.file_size > MAX_LOG_MEMBER_BYTES:
                raise RuntimeError("Actions log archive contains an oversized member")
            uncompressed += info.file_size
            if uncompressed > MAX_LOG_UNCOMPRESSED_BYTES:
                raise RuntimeError("Actions log archive expands beyond the safe limit")
            if info.is_dir():
                continue
            member = archive.read(info)
            count = member.count(marker)
            if count:
                occurrences += count
                matching_members.append(info.filename)
    if occurrences < len(EXPECTED_CASES):
        raise RuntimeError(
            "Actions logs do not contain the boundary failure for all matrix jobs"
        )
    return {
        "archive_bytes": len(data),
        "archive_sha256": sha256_bytes(data),
        "boundary_failure_occurrences": occurrences,
        "members_with_boundary_failure": sorted(matching_members),
    }


def _validate_generic_zip(data: bytes, *, label: str, limit: int) -> dict[str, Any]:
    """Validate only bounded ZIP structure; never extract untrusted evidence."""
    if not data or len(data) > limit:
        raise RuntimeError(f"{label} archive has an invalid byte size")
    if not zipfile.is_zipfile(BytesIO(data)):
        raise RuntimeError(f"{label} is not a valid ZIP archive")
    uncompressed = 0
    with zipfile.ZipFile(BytesIO(data)) as archive:
        infos = archive.infolist()
        if not infos or len(infos) > 5000:
            raise RuntimeError(f"{label} archive has an invalid member count")
        for info in infos:
            if info.flag_bits & 0x1:
                raise RuntimeError(f"{label} archive contains an encrypted member")
            if info.file_size > MAX_LOG_MEMBER_BYTES:
                raise RuntimeError(f"{label} archive contains an oversized member")
            uncompressed += info.file_size
            if uncompressed > MAX_LOG_UNCOMPRESSED_BYTES:
                raise RuntimeError(f"{label} archive expands beyond the safe limit")
    return {
        "archive_bytes": len(data),
        "archive_sha256": sha256_bytes(data),
        "member_count": len(infos),
        "uncompressed_bytes": uncompressed,
    }


def _validate_tag_ruleset(tag_ruleset: dict[str, Any]) -> None:
    _require_equal(tag_ruleset.get("target"), "tag", "tag ruleset target")
    _require_equal(tag_ruleset.get("enforcement"), "active", "tag ruleset enforcement")
    _require_equal(tag_ruleset.get("bypass_actors"), [], "tag ruleset bypass actors")
    conditions = _expect_object(tag_ruleset.get("conditions"), "tag ruleset conditions")
    ref_names = _expect_object(conditions.get("ref_name"), "tag ruleset ref_name")
    includes = _expect_list(ref_names.get("include"), "tag ruleset includes")
    if "refs/tags/oss-protocol-v*" not in includes:
        raise RuntimeError("tag ruleset does not include OSS protocol tags")
    rules = _expect_list(tag_ruleset.get("rules"), "tag ruleset rules")
    rule_types = {rule.get("type") for rule in rules if isinstance(rule, dict)}
    if not {"deletion", "non_fast_forward"}.issubset(rule_types):
        raise RuntimeError("tag ruleset lacks deletion/non-fast-forward protection")


def resolve_current_protocol() -> dict[str, Any]:
    """Bind the current study constants to the local protected tag and manifest."""
    from oss_common import PROTOCOL_TAG, ROOT as OSS_ROOT, STUDY_ID, manifest_path

    manifest = manifest_path(STUDY_ID)
    if not manifest.is_file():
        raise RuntimeError("the current OSS manifest is not frozen")
    relative = manifest.relative_to(OSS_ROOT).as_posix()
    try:
        commit = subprocess.run(
            ["git", "-C", str(OSS_ROOT), "rev-parse", f"{PROTOCOL_TAG}^{{commit}}"],
            check=True,
            capture_output=True,
            encoding="ascii",
            timeout=30,
        ).stdout.strip()
        tagged_manifest = subprocess.run(
            ["git", "-C", str(OSS_ROOT), "show", f"{PROTOCOL_TAG}:{relative}"],
            check=True,
            capture_output=True,
            timeout=30,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("cannot resolve the current protected protocol tag") from exc
    if len(commit) != 40 or any(
        character not in "0123456789abcdef" for character in commit
    ):
        raise RuntimeError("the current protocol tag does not resolve to a full commit")
    if tagged_manifest != manifest.read_bytes():
        raise RuntimeError(
            "the working manifest differs from the protected protocol tag"
        )
    return {
        "study_id": STUDY_ID,
        "protocol_tag": PROTOCOL_TAG,
        "protocol_commit": commit,
        "manifest_path": relative,
        "manifest_sha256": sha256_bytes(tagged_manifest),
        "manifest_bytes": tagged_manifest,
    }


def _current_required_step_names(case_id: str) -> tuple[str, ...]:
    # Keep capture bound to the exact same official-step contract as the product
    # materializer without accepting the materializer's product-only conclusions.
    from materialize_oss_artifacts import _required_step_names

    return _required_step_names(case_id)


def validate_current_capture(
    snapshots: dict[str, Any],
    log_archive: bytes,
    artifact_archives: dict[int, bytes],
    captured_at: str,
    *,
    run_id: int,
    protocol: dict[str, Any],
) -> dict[str, Any]:
    """Validate and classify a current attempt without extracting any artifact."""
    from oss_common import PROTOCOL_TAG, STUDY_ID, case_map

    if run_id <= 0:
        raise RuntimeError("run id must be positive")
    for key, expected in {
        "study_id": STUDY_ID,
        "protocol_tag": PROTOCOL_TAG,
    }.items():
        _require_equal(protocol.get(key), expected, f"protocol.{key}")
    commit = protocol.get("protocol_commit")
    manifest_sha = protocol.get("manifest_sha256")
    if (
        not isinstance(commit, str)
        or len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit)
    ):
        raise RuntimeError("invalid current protocol commit")
    if (
        not isinstance(manifest_sha, str)
        or len(manifest_sha) != 64
        or any(character not in "0123456789abcdef" for character in manifest_sha)
    ):
        raise RuntimeError("invalid current manifest digest")

    run = _expect_object(snapshots.get("run.json"), "run API response")
    workflow = _expect_object(snapshots.get("workflow.json"), "workflow API response")
    jobs_payload = _expect_object(snapshots.get("jobs.json"), "jobs API response")
    artifacts_payload = _expect_object(
        snapshots.get("artifacts.json"), "artifacts API response"
    )
    dispatches_payload = _expect_object(
        snapshots.get("dispatches.json"), "dispatches API response"
    )
    tag_ref = _expect_object(snapshots.get("tag-ref.json"), "tag ref API response")
    tag_object = _expect_object(
        snapshots.get("tag-object.json"), "tag object API response"
    )
    tag_ruleset = _expect_object(
        snapshots.get("tag-ruleset.json"), "tag ruleset API response"
    )

    for field, expected in {
        "id": run_id,
        "run_attempt": 1,
        "event": "workflow_dispatch",
        "status": "completed",
        "head_branch": PROTOCOL_TAG,
        "head_sha": commit,
        "path": EXPECTED_WORKFLOW_PATH,
        "name": EXPECTED_WORKFLOW_NAME,
    }.items():
        _require_equal(run.get(field), expected, f"run.{field}")
    if run.get("conclusion") not in FINAL_JOB_CONCLUSIONS:
        raise RuntimeError("run has no supported final conclusion")
    repository = _expect_object(run.get("repository"), "run.repository")
    _require_equal(
        repository.get("full_name"), EXPECTED_REPOSITORY, "run.repository.full_name"
    )
    expected_url = f"https://github.com/{EXPECTED_REPOSITORY}/actions/runs/{run_id}"
    _require_equal(run.get("html_url"), expected_url, "run.html_url")
    for actor_field in ("actor", "triggering_actor"):
        actor = _expect_object(run.get(actor_field), f"run.{actor_field}")
        _require_equal(actor.get("login"), "EvoRiseKsa", f"run.{actor_field}.login")

    _require_equal(workflow.get("id"), run.get("workflow_id"), "workflow.id")
    _require_equal(workflow.get("path"), EXPECTED_WORKFLOW_PATH, "workflow.path")
    _require_equal(workflow.get("name"), EXPECTED_WORKFLOW_NAME, "workflow.name")

    expected_cases = set(case_map())
    jobs = _expect_list(jobs_payload.get("jobs"), "jobs.jobs")
    _require_equal(jobs_payload.get("total_count"), len(jobs), "jobs.total_count")
    _require_equal(len(jobs), len(expected_cases), "matrix job count")
    by_case: dict[str, dict[str, Any]] = {}
    step_observations: dict[str, dict[str, str]] = {}
    non_successful_steps: list[dict[str, str]] = []
    for raw_job in jobs:
        job = _expect_object(raw_job, "matrix job")
        case_id = job.get("name")
        if not isinstance(case_id, str) or case_id not in expected_cases:
            raise RuntimeError(f"unexpected matrix job: {case_id!r}")
        if case_id in by_case:
            raise RuntimeError(f"duplicate matrix job: {case_id}")
        by_case[case_id] = job
        for field, expected in {
            "run_id": run_id,
            "run_attempt": 1,
            "head_sha": commit,
            "head_branch": PROTOCOL_TAG,
            "workflow_name": EXPECTED_WORKFLOW_NAME,
            "status": "completed",
        }.items():
            _require_equal(job.get(field), expected, f"job {case_id}.{field}")
        if job.get("conclusion") not in FINAL_JOB_CONCLUSIONS:
            raise RuntimeError(f"job {case_id} has no supported final conclusion")
        steps = _step_map(job)
        previous_number = 0
        observed: dict[str, str] = {}
        for step_name in _current_required_step_names(case_id):
            step = steps.get(step_name)
            if step is None:
                raise RuntimeError(f"job {case_id} is missing step {step_name!r}")
            number = step.get("number")
            if not isinstance(number, int) or number <= previous_number:
                raise RuntimeError(f"job {case_id} has invalid official step ordering")
            previous_number = number
            _require_equal(
                step.get("status"),
                "completed",
                f"job {case_id} step {step_name}.status",
            )
            conclusion = step.get("conclusion")
            if conclusion not in FINAL_STEP_CONCLUSIONS:
                raise RuntimeError(
                    f"job {case_id} step {step_name} has no supported conclusion"
                )
            observed[step_name] = conclusion
            if conclusion != "success":
                non_successful_steps.append(
                    {"case_id": case_id, "step": step_name, "conclusion": conclusion}
                )
        step_observations[case_id] = observed
    _require_equal(set(by_case), expected_cases, "matrix case inventory")

    dispatches = _expect_list(
        dispatches_payload.get("workflow_runs"), "dispatches.workflow_runs"
    )
    _require_equal(
        dispatches_payload.get("total_count"), len(dispatches), "dispatch total_count"
    )
    candidates = [
        item
        for item in dispatches
        if isinstance(item, dict)
        and item.get("event") == "workflow_dispatch"
        and item.get("head_sha") == commit
        and item.get("path") == EXPECTED_WORKFLOW_PATH
        and isinstance(item.get("id"), int)
        and isinstance(item.get("created_at"), str)
    ]
    if not candidates:
        raise RuntimeError("no API-visible dispatch matches the frozen commit/workflow")
    first = min(candidates, key=lambda item: (item["created_at"], item["id"]))
    _require_equal(first.get("id"), run_id, "first API-visible dispatch id")
    _require_equal(first.get("head_branch"), PROTOCOL_TAG, "first dispatch head_branch")
    _require_equal(
        first.get("created_at"), run.get("created_at"), "dispatch created_at"
    )

    _require_equal(tag_ref.get("ref"), f"refs/tags/{PROTOCOL_TAG}", "tag ref")
    ref_target = _expect_object(tag_ref.get("object"), "tag ref object")
    _require_equal(ref_target.get("type"), "tag", "tag ref object.type")
    tag_sha = ref_target.get("sha")
    if not isinstance(tag_sha, str) or len(tag_sha) != 40:
        raise RuntimeError("tag ref has no annotated tag object")
    _require_equal(tag_object.get("sha"), tag_sha, "tag object sha")
    _require_equal(tag_object.get("tag"), PROTOCOL_TAG, "tag object tag")
    tag_target = _expect_object(tag_object.get("object"), "tag object target")
    _require_equal(tag_target.get("type"), "commit", "tag target type")
    _require_equal(tag_target.get("sha"), commit, "tag target sha")
    _validate_tag_ruleset(tag_ruleset)

    artifacts = _expect_list(artifacts_payload.get("artifacts"), "artifacts.artifacts")
    _require_equal(
        artifacts_payload.get("total_count"), len(artifacts), "artifacts.total_count"
    )
    if len(artifacts) > 100:
        raise RuntimeError(
            "artifact inventory exceeds the single-page capture contract"
        )
    product_names = {f"oss-{case_id}" for case_id in expected_cases}
    infrastructure_names = {f"oss-infra-{case_id}" for case_id in expected_cases}
    seen_ids: set[int] = set()
    selected_artifacts: list[dict[str, Any]] = []
    total_artifact_bytes = 0
    for raw_artifact in artifacts:
        artifact = _expect_object(raw_artifact, "artifact")
        artifact_id = artifact.get("id")
        name = artifact.get("name")
        size = artifact.get("size_in_bytes")
        digest = artifact.get("digest")
        if (
            not isinstance(artifact_id, int)
            or artifact_id <= 0
            or artifact_id in seen_ids
        ):
            raise RuntimeError("artifact has an invalid or duplicate id")
        seen_ids.add(artifact_id)
        if not isinstance(name, str) or not name:
            raise RuntimeError(f"artifact {artifact_id} has an invalid name")
        if not isinstance(size, int) or not 0 < size <= MAX_ARTIFACT_ARCHIVE_BYTES:
            raise RuntimeError(f"artifact {artifact_id} has an invalid size")
        if artifact.get("expired") is not False:
            raise RuntimeError(f"artifact {artifact_id} is expired")
        if (
            not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or len(digest) != 71
            or any(character not in "0123456789abcdef" for character in digest[7:])
        ):
            raise RuntimeError(f"artifact {artifact_id} has no API SHA-256 digest")
        workflow_run = _expect_object(
            artifact.get("workflow_run"), f"artifact {artifact_id}.workflow_run"
        )
        _require_equal(workflow_run.get("id"), run_id, f"artifact {artifact_id} run id")
        _require_equal(
            workflow_run.get("head_sha"), commit, f"artifact {artifact_id} head SHA"
        )
        expected_download = f"{API_ROOT}/repos/{EXPECTED_REPOSITORY}/actions/artifacts/{artifact_id}/zip"
        _require_equal(
            artifact.get("archive_download_url"),
            expected_download,
            f"artifact {artifact_id} download URL",
        )
        archive = artifact_archives.get(artifact_id)
        if archive is None:
            raise RuntimeError(f"artifact {artifact_id} archive is missing")
        _validate_generic_zip(
            archive, label=f"artifact {artifact_id}", limit=MAX_ARTIFACT_ARCHIVE_BYTES
        )
        _require_equal(len(archive), size, f"artifact {artifact_id} byte size")
        _require_equal(
            sha256_bytes(archive), digest[7:], f"artifact {artifact_id} API digest"
        )
        total_artifact_bytes += len(archive)
        if total_artifact_bytes > MAX_TOTAL_ARTIFACT_BYTES:
            raise RuntimeError(
                "combined artifact archives exceed the capture size limit"
            )
        if name in infrastructure_names:
            artifact_class = "infrastructure"
        elif name in product_names:
            artifact_class = "product"
        else:
            artifact_class = "unexpected"
        selected_artifacts.append(
            {
                "id": artifact_id,
                "name": name,
                "classification": artifact_class,
                "size_in_bytes": size,
                "api_digest": digest,
                "archive_file": f"artifacts/{artifact_id}.zip",
                "archive_sha256": sha256_bytes(archive),
            }
        )
    _require_equal(set(artifact_archives), seen_ids, "downloaded artifact inventory")

    actual_names = [item["name"] for item in selected_artifacts]
    exact_product_inventory = (
        len(actual_names) == len(product_names)
        and len(actual_names) == len(set(actual_names))
        and set(actual_names) == product_names
    )
    exact_product_steps = True
    for case_id, observed in step_observations.items():
        for step_name in _current_required_step_names(case_id):
            expected_conclusions = (
                {"success", "failure"}
                if step_name == "Run frozen case"
                else {"skipped"}
                if step_name == "Upload immutable infrastructure output"
                else {"success"}
            )
            if observed.get(step_name) not in expected_conclusions:
                exact_product_steps = False
    exact_product_job_conclusions = all(
        by_case[case_id].get("conclusion") == observed.get("Run frozen case")
        for case_id, observed in step_observations.items()
    )
    job_conclusions = [
        by_case[case_id].get("conclusion") for case_id in sorted(expected_cases)
    ]
    expected_run_conclusion = "failure" if "failure" in job_conclusions else "success"
    exact_product_run_conclusion = (
        all(conclusion in {"success", "failure"} for conclusion in job_conclusions)
        and run.get("conclusion") == expected_run_conclusion
    )
    eligible = (
        exact_product_inventory
        and exact_product_steps
        and exact_product_job_conclusions
        and exact_product_run_conclusion
    )
    log_evidence = _validate_generic_zip(
        log_archive, label="Actions logs", limit=MAX_LOG_ARCHIVE_BYTES
    )
    evidence_files = [
        "FROZEN-MANIFEST.json",
        "actions-logs.zip",
        *[f"api/{name}" for name in sorted(snapshots)],
        *[item["archive_file"] for item in selected_artifacts],
    ]
    return {
        "schema": CURRENT_CAPTURE_SCHEMA,
        "captured_at": captured_at,
        "repository": EXPECTED_REPOSITORY,
        "workflow_path": EXPECTED_WORKFLOW_PATH,
        "run_id": run_id,
        "run_attempt": 1,
        "run_url": expected_url,
        "run_conclusion": run.get("conclusion"),
        "study_id": STUDY_ID,
        "protocol_tag": PROTOCOL_TAG,
        "protocol_commit": commit,
        "tag_object": tag_sha,
        "manifest_path": protocol.get("manifest_path"),
        "manifest_sha256": manifest_sha,
        "classification": (
            "complete_product_inventory_not_evaluated"
            if eligible
            else "invalid_or_incomplete_before_product_materialization"
        ),
        "product_materialization_eligible": eligible,
        "product_evaluation_performed": False,
        "product_inference_allowed": False,
        "case_count": len(expected_cases),
        "case_steps_non_skipped": sum(
            observed.get("Run frozen case") != "skipped"
            for observed in step_observations.values()
        ),
        "canonical_dispatch": {
            "selection": "first API-visible workflow_dispatch for workflow and commit",
            "first_run_id": first["id"],
            "first_created_at": first["created_at"],
            "matching_dispatch_count": len(candidates),
        },
        "matrix_cases": sorted(by_case),
        "step_observations": step_observations,
        "non_successful_official_steps": non_successful_steps,
        "artifact_inventory": selected_artifacts,
        "artifact_count": len(selected_artifacts),
        "product_artifact_count": sum(
            item["classification"] == "product" for item in selected_artifacts
        ),
        "infrastructure_artifact_count": sum(
            item["classification"] == "infrastructure" for item in selected_artifacts
        ),
        "unexpected_artifact_count": sum(
            item["classification"] == "unexpected" for item in selected_artifacts
        ),
        "actions_logs": log_evidence,
        "evidence_files": evidence_files,
    }


def validate_capture(
    snapshots: dict[str, Any], log_archive: bytes, captured_at: str
) -> dict[str, Any]:
    """Validate the historical attempt and return its bounded classification."""
    run = _expect_object(snapshots.get("run.json"), "run API response")
    workflow = _expect_object(snapshots.get("workflow.json"), "workflow API response")
    jobs_payload = _expect_object(snapshots.get("jobs.json"), "jobs API response")
    artifacts_payload = _expect_object(
        snapshots.get("artifacts.json"), "artifacts API response"
    )
    dispatches_payload = _expect_object(
        snapshots.get("dispatches.json"), "dispatches API response"
    )
    tag_ref = _expect_object(snapshots.get("tag-ref.json"), "tag ref API response")
    tag_object = _expect_object(
        snapshots.get("tag-object.json"), "tag object API response"
    )
    tag_ruleset = _expect_object(
        snapshots.get("tag-ruleset.json"), "tag ruleset API response"
    )

    run_expectations = {
        "id": EXPECTED_RUN_ID,
        "run_attempt": EXPECTED_RUN_ATTEMPT,
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "failure",
        "head_branch": EXPECTED_PROTOCOL_TAG,
        "head_sha": EXPECTED_PROTOCOL_COMMIT,
        "path": EXPECTED_WORKFLOW_PATH,
        "name": EXPECTED_WORKFLOW_NAME,
    }
    for field, expected in run_expectations.items():
        _require_equal(run.get(field), expected, f"run.{field}")
    repository = _expect_object(run.get("repository"), "run.repository")
    _require_equal(
        repository.get("full_name"), EXPECTED_REPOSITORY, "run.repository.full_name"
    )
    run_url = run.get("html_url")
    expected_url = (
        f"https://github.com/{EXPECTED_REPOSITORY}/actions/runs/{EXPECTED_RUN_ID}"
    )
    _require_equal(run_url, expected_url, "run.html_url")

    _require_equal(workflow.get("id"), run.get("workflow_id"), "workflow.id")
    _require_equal(workflow.get("path"), EXPECTED_WORKFLOW_PATH, "workflow.path")
    _require_equal(workflow.get("name"), EXPECTED_WORKFLOW_NAME, "workflow.name")

    jobs = _expect_list(jobs_payload.get("jobs"), "jobs.jobs")
    _require_equal(jobs_payload.get("total_count"), len(jobs), "jobs.total_count")
    _require_equal(len(jobs), len(EXPECTED_CASES), "matrix job count")
    by_case: dict[str, dict[str, Any]] = {}
    step_observations: dict[str, dict[str, str]] = {}
    for raw_job in jobs:
        job = _expect_object(raw_job, "matrix job")
        name = job.get("name")
        if not isinstance(name, str) or name not in EXPECTED_CASES:
            raise RuntimeError(f"unexpected matrix job: {name!r}")
        if name in by_case:
            raise RuntimeError(f"duplicate matrix job: {name}")
        by_case[name] = job
        for field, expected in {
            "run_id": EXPECTED_RUN_ID,
            "run_attempt": EXPECTED_RUN_ATTEMPT,
            "head_sha": EXPECTED_PROTOCOL_COMMIT,
            "head_branch": EXPECTED_PROTOCOL_TAG,
            "workflow_name": EXPECTED_WORKFLOW_NAME,
            "status": "completed",
            "conclusion": "failure",
        }.items():
            _require_equal(job.get(field), expected, f"job {name}.{field}")
        steps = _step_map(job)
        observed: dict[str, str] = {}
        for step_name, expected_conclusion in EXPECTED_STEP_CONCLUSIONS.items():
            if step_name not in steps:
                raise RuntimeError(f"job {name} is missing step {step_name!r}")
            step = steps[step_name]
            _require_equal(
                step.get("conclusion"),
                expected_conclusion,
                f"job {name} step {step_name}.conclusion",
            )
            _require_equal(
                step.get("status"), "completed", f"job {name} step {step_name}.status"
            )
            observed[step_name] = expected_conclusion
        step_observations[name] = observed
    _require_equal(set(by_case), set(EXPECTED_CASES), "matrix case inventory")

    artifacts = _expect_list(artifacts_payload.get("artifacts"), "artifacts.artifacts")
    _require_equal(artifacts_payload.get("total_count"), 0, "artifacts.total_count")
    _require_equal(artifacts, [], "artifacts.artifacts")

    dispatches = _expect_list(
        dispatches_payload.get("workflow_runs"), "dispatches.workflow_runs"
    )
    _require_equal(
        dispatches_payload.get("total_count"), len(dispatches), "dispatch total_count"
    )
    candidates = [
        item
        for item in dispatches
        if isinstance(item, dict)
        and item.get("event") == "workflow_dispatch"
        and item.get("head_sha") == EXPECTED_PROTOCOL_COMMIT
        and item.get("path") == EXPECTED_WORKFLOW_PATH
    ]
    if not candidates:
        raise RuntimeError("no API-visible dispatch matches the frozen commit/workflow")
    first = min(
        candidates, key=lambda item: (str(item.get("created_at")), item.get("id"))
    )
    _require_equal(first.get("id"), EXPECTED_RUN_ID, "first API-visible dispatch id")
    _require_equal(
        first.get("head_branch"), EXPECTED_PROTOCOL_TAG, "first dispatch head_branch"
    )

    _require_equal(tag_ref.get("ref"), f"refs/tags/{EXPECTED_PROTOCOL_TAG}", "tag ref")
    ref_target = _expect_object(tag_ref.get("object"), "tag ref object")
    _require_equal(ref_target.get("type"), "tag", "tag ref object.type")
    _require_equal(ref_target.get("sha"), EXPECTED_TAG_OBJECT, "tag ref object.sha")
    _require_equal(tag_object.get("tag"), EXPECTED_PROTOCOL_TAG, "tag object tag")
    tag_target = _expect_object(tag_object.get("object"), "tag object target")
    _require_equal(tag_target.get("type"), "commit", "tag target type")
    _require_equal(tag_target.get("sha"), EXPECTED_PROTOCOL_COMMIT, "tag target sha")

    _require_equal(tag_ruleset.get("id"), EXPECTED_TAG_RULESET_ID, "tag ruleset id")
    _require_equal(tag_ruleset.get("target"), "tag", "tag ruleset target")
    _require_equal(tag_ruleset.get("enforcement"), "active", "tag ruleset enforcement")
    _require_equal(tag_ruleset.get("bypass_actors"), [], "tag ruleset bypass actors")
    conditions = _expect_object(tag_ruleset.get("conditions"), "tag ruleset conditions")
    ref_names = _expect_object(conditions.get("ref_name"), "tag ruleset ref_name")
    includes = _expect_list(ref_names.get("include"), "tag ruleset includes")
    if "refs/tags/oss-protocol-v*" not in includes:
        raise RuntimeError("tag ruleset does not include OSS protocol tags")
    rules = _expect_list(tag_ruleset.get("rules"), "tag ruleset rules")
    rule_types = {rule.get("type") for rule in rules if isinstance(rule, dict)}
    if not {"deletion", "non_fast_forward"}.issubset(rule_types):
        raise RuntimeError("tag ruleset lacks deletion/non-fast-forward protection")

    log_evidence = _validate_log_archive(log_archive)
    return {
        "schema": CAPTURE_SCHEMA,
        "captured_at": captured_at,
        "repository": EXPECTED_REPOSITORY,
        "workflow_path": EXPECTED_WORKFLOW_PATH,
        "run_id": EXPECTED_RUN_ID,
        "run_attempt": EXPECTED_RUN_ATTEMPT,
        "run_url": expected_url,
        "study_id": EXPECTED_STUDY_ID,
        "protocol_tag": EXPECTED_PROTOCOL_TAG,
        "protocol_commit": EXPECTED_PROTOCOL_COMMIT,
        "tag_object": EXPECTED_TAG_OBJECT,
        "classification": "invalid_before_measurement",
        "failure_domain": "trusted_execution_boundary_installation",
        "product_inference_allowed": False,
        "case_count": len(EXPECTED_CASES),
        "cases_started": 0,
        "guard_invocations": 0,
        "product_artifact_count": 0,
        "canonical_dispatch": {
            "selection": "first API-visible workflow_dispatch for workflow and commit",
            "first_run_id": first["id"],
            "first_created_at": first.get("created_at"),
            "matching_dispatch_count": len(candidates),
        },
        "matrix_cases": sorted(by_case),
        "step_contract": EXPECTED_STEP_CONCLUSIONS,
        "step_observations": step_observations,
        "boundary_failure": {
            "message": EXPECTED_BOUNDARY_FAILURE,
            **log_evidence,
        },
        "evidence_files": [
            "actions-logs.zip",
            *[f"api/{name}" for name in sorted(snapshots)],
        ],
    }


def _failure_markdown(attempt: dict[str, Any]) -> bytes:
    return (
        "# OSS compatibility protocol v0.1: invalid attempt\n\n"
        f"- Run: [{EXPECTED_RUN_ID}]({attempt['run_url']}) (attempt 1).\n"
        f"- Frozen commit: `{EXPECTED_PROTOCOL_COMMIT}` via "
        f"`{EXPECTED_PROTOCOL_TAG}`.\n"
        "- Classification: `invalid_before_measurement`.\n"
        "- All 12 matrix jobs passed canonical-dispatch and frozen-identity "
        "checks, then failed while installing the trusted execution boundary.\n"
        "- Every `Run frozen case` step was skipped. No Guard invocation began.\n"
        "- Every product-artifact upload was skipped; the Actions API reports "
        "zero artifacts.\n\n"
        "## Observed infrastructure failure\n\n"
        f"`{EXPECTED_BOUNDARY_FAILURE}`\n\n"
        "This run is **not** a 0/12 product result. It supports no inference about "
        "EvoOM Guard compatibility, acceptance, rejection, or verifier quality. "
        "The API snapshots and original Actions log ZIP are retained only as "
        "evidence of the invalid attempt.\n"
    ).encode("utf-8")


def _current_capture_markdown(attempt: dict[str, Any]) -> bytes:
    eligible = attempt["product_materialization_eligible"]
    if eligible:
        disposition = (
            "The API inventory contains exactly 12 product-named artifacts and the "
            "official upload contract completed. This capture still performs no "
            "extraction, record verification, scoring, or product inference; use the "
            "frozen materializer and evaluator for those steps."
        )
    else:
        disposition = (
            "The run does not contain the exact complete product-artifact inventory. "
            "It is not a product denominator and supports no product inference. The "
            "archives are retained only as immutable attempt evidence."
        )
    return (
        f"# OSS compatibility protocol {attempt['protocol_tag']}: captured attempt\n\n"
        f"- Run: [{attempt['run_id']}]({attempt['run_url']}) (attempt 1).\n"
        f"- Frozen commit: `{attempt['protocol_commit']}`.\n"
        f"- Manifest SHA-256: `{attempt['manifest_sha256']}`.\n"
        f"- Classification: `{attempt['classification']}`.\n"
        f"- Product artifacts: {attempt['product_artifact_count']}; "
        f"infrastructure artifacts: {attempt['infrastructure_artifact_count']}; "
        f"unexpected artifacts: {attempt['unexpected_artifact_count']}.\n"
        "- Artifact ZIPs are preserved byte-for-byte but were not extracted.\n\n"
        "## Scientific disposition\n\n"
        f"{disposition}\n"
    ).encode("utf-8")


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "xb") as handle:
        handle.write(data)


def _checksum_manifest(root: Path) -> bytes:
    lines: list[str] = []
    files = [item for item in root.rglob("*") if item.is_file()]
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative == "SHA256SUMS":
            continue
        lines.append(f"{sha256_bytes(path.read_bytes())}  {relative}")
    return ("\n".join(lines) + "\n").encode("ascii")


def write_capture_bundle(
    output: Path,
    snapshots: dict[str, Any],
    log_archive: bytes,
    attempt: dict[str, Any],
) -> None:
    """Atomically create a capture directory, refusing any replacement."""
    if output.exists():
        raise FileExistsError(f"refusing to replace existing capture: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.capture-", dir=output.parent)
    )
    try:
        _write_bytes(staging / "ATTEMPT.json", canonical_json_bytes(attempt))
        _write_bytes(staging / "FAILURE.md", _failure_markdown(attempt))
        _write_bytes(staging / "actions-logs.zip", log_archive)
        for name, payload in sorted(snapshots.items()):
            _write_bytes(staging / "api" / name, canonical_json_bytes(payload))
        _write_bytes(staging / "SHA256SUMS", _checksum_manifest(staging))
        staging.replace(output)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def write_current_capture_bundle(
    output: Path,
    snapshots: dict[str, Any],
    log_archive: bytes,
    artifact_archives: dict[int, bytes],
    manifest_bytes: bytes,
    attempt: dict[str, Any],
) -> None:
    """Atomically retain an attempt without extracting or interpreting archives."""
    if output.exists():
        raise FileExistsError(f"refusing to replace existing capture: {output}")
    if sha256_bytes(manifest_bytes) != attempt.get("manifest_sha256"):
        raise RuntimeError("frozen manifest bytes differ from the attempt binding")
    expected_ids = {
        item["id"]
        for item in attempt.get("artifact_inventory", [])
        if isinstance(item, dict) and isinstance(item.get("id"), int)
    }
    if set(artifact_archives) != expected_ids:
        raise RuntimeError("artifact archive inventory differs from ATTEMPT.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.capture-", dir=output.parent)
    )
    try:
        _write_bytes(staging / "ATTEMPT.json", canonical_json_bytes(attempt))
        _write_bytes(staging / "FAILURE.md", _current_capture_markdown(attempt))
        _write_bytes(staging / "FROZEN-MANIFEST.json", manifest_bytes)
        _write_bytes(staging / "actions-logs.zip", log_archive)
        for name, payload in sorted(snapshots.items()):
            _write_bytes(staging / "api" / name, canonical_json_bytes(payload))
        for artifact_id, archive in sorted(artifact_archives.items()):
            _write_bytes(staging / "artifacts" / f"{artifact_id}.zip", archive)
        _write_bytes(staging / "SHA256SUMS", _checksum_manifest(staging))
        staging.replace(output)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def _workflow_dispatches_for(
    client: GitHubClient, protocol_commit: str
) -> dict[str, Any]:
    query = urllib.parse.urlencode(
        {
            "event": "workflow_dispatch",
            "head_sha": protocol_commit,
            "per_page": 100,
            "page": 1,
        }
    )
    path = (
        f"/repos/{EXPECTED_REPOSITORY}/actions/workflows/"
        f"{EXPECTED_WORKFLOW_FILE}/runs?{query}"
    )
    first = _expect_object(client.json(path), "dispatches API response")
    runs = _expect_list(first.get("workflow_runs"), "dispatches.workflow_runs")
    total = first.get("total_count")
    if not isinstance(total, int) or total < 0:
        raise RuntimeError("dispatches.total_count is invalid")
    page = 1
    while len(runs) < total:
        page += 1
        if page > 10:
            raise RuntimeError("dispatch query exceeds the supported API page limit")
        next_query = urllib.parse.urlencode(
            {
                "event": "workflow_dispatch",
                "head_sha": protocol_commit,
                "per_page": 100,
                "page": page,
            }
        )
        payload = _expect_object(
            client.json(
                f"/repos/{EXPECTED_REPOSITORY}/actions/workflows/"
                f"{EXPECTED_WORKFLOW_FILE}/runs?{next_query}"
            ),
            "dispatches API page",
        )
        page_runs = _expect_list(payload.get("workflow_runs"), "dispatch page runs")
        if not page_runs:
            raise RuntimeError("dispatch API response was truncated")
        runs.extend(page_runs)
    if len(runs) != total:
        raise RuntimeError("dispatch API total_count does not match returned runs")
    return {"total_count": total, "workflow_runs": runs}


def _workflow_dispatches(client: GitHubClient) -> dict[str, Any]:
    return _workflow_dispatches_for(client, EXPECTED_PROTOCOL_COMMIT)


def fetch_capture(client: GitHubClient) -> tuple[dict[str, Any], bytes]:
    base = f"/repos/{EXPECTED_REPOSITORY}"
    run = client.json(f"{base}/actions/runs/{EXPECTED_RUN_ID}")
    workflow = client.json(f"{base}/actions/workflows/{EXPECTED_WORKFLOW_FILE}")
    jobs = client.json(
        f"{base}/actions/runs/{EXPECTED_RUN_ID}/attempts/"
        f"{EXPECTED_RUN_ATTEMPT}/jobs?per_page=100"
    )
    artifacts = client.json(
        f"{base}/actions/runs/{EXPECTED_RUN_ID}/artifacts?per_page=100"
    )
    dispatches = _workflow_dispatches(client)
    tag_ref = client.json(f"{base}/git/ref/tags/{EXPECTED_PROTOCOL_TAG}")
    ref_object = _expect_object(
        _expect_object(tag_ref, "tag ref API response").get("object"),
        "tag ref object",
    )
    tag_object = client.json(f"{base}/git/tags/{ref_object.get('sha')}")
    tag_ruleset = client.json(f"{base}/rulesets/{EXPECTED_TAG_RULESET_ID}")
    logs = client.redirected_bytes(
        f"{base}/actions/runs/{EXPECTED_RUN_ID}/attempts/{EXPECTED_RUN_ATTEMPT}/logs",
        MAX_LOG_ARCHIVE_BYTES,
    )
    return (
        {
            "artifacts.json": artifacts,
            "dispatches.json": dispatches,
            "jobs.json": jobs,
            "run.json": run,
            "tag-object.json": tag_object,
            "tag-ref.json": tag_ref,
            "tag-ruleset.json": tag_ruleset,
            "workflow.json": workflow,
        },
        logs,
    )


def fetch_current_capture(
    client: GitHubClient, run_id: int, protocol: dict[str, Any]
) -> tuple[dict[str, Any], bytes, dict[int, bytes]]:
    """Fetch every bounded API/log/artifact byte for a current attempt."""
    protocol_tag = protocol["protocol_tag"]
    protocol_commit = protocol["protocol_commit"]
    base = f"/repos/{EXPECTED_REPOSITORY}"
    run = client.json(f"{base}/actions/runs/{run_id}")
    workflow = client.json(f"{base}/actions/workflows/{EXPECTED_WORKFLOW_FILE}")
    jobs = client.json(f"{base}/actions/runs/{run_id}/attempts/1/jobs?per_page=100")
    artifacts = client.json(f"{base}/actions/runs/{run_id}/artifacts?per_page=100")
    dispatches = _workflow_dispatches_for(client, protocol_commit)
    tag_ref = client.json(f"{base}/git/ref/tags/{protocol_tag}")
    ref_object = _expect_object(
        _expect_object(tag_ref, "tag ref API response").get("object"),
        "tag ref object",
    )
    if ref_object.get("type") != "tag":
        raise RuntimeError("the current protocol tag is not annotated")
    tag_object = client.json(f"{base}/git/tags/{ref_object.get('sha')}")
    tag_ruleset = client.json(f"{base}/rulesets/{EXPECTED_TAG_RULESET_ID}")
    logs = client.redirected_bytes(
        f"{base}/actions/runs/{run_id}/attempts/1/logs",
        MAX_LOG_ARCHIVE_BYTES,
    )
    artifacts_object = _expect_object(artifacts, "artifacts API response")
    artifact_list = _expect_list(
        artifacts_object.get("artifacts"), "artifacts.artifacts"
    )
    if artifacts_object.get("total_count") != len(artifact_list):
        raise RuntimeError("artifact API response is truncated")
    artifact_archives: dict[int, bytes] = {}
    total = 0
    for raw in artifact_list:
        artifact = _expect_object(raw, "artifact")
        artifact_id = artifact.get("id")
        size = artifact.get("size_in_bytes")
        if not isinstance(artifact_id, int) or artifact_id <= 0:
            raise RuntimeError("artifact has an invalid id")
        if artifact_id in artifact_archives:
            raise RuntimeError("artifact API contains a duplicate id")
        if not isinstance(size, int) or not 0 < size <= MAX_ARTIFACT_ARCHIVE_BYTES:
            raise RuntimeError(f"artifact {artifact_id} has an invalid size")
        total += size
        if total > MAX_TOTAL_ARTIFACT_BYTES:
            raise RuntimeError(
                "combined artifact archives exceed the capture size limit"
            )
        artifact_archives[artifact_id] = client.redirected_bytes(
            f"{base}/actions/artifacts/{artifact_id}/zip", size
        )
    return (
        {
            "artifacts.json": artifacts,
            "dispatches.json": dispatches,
            "jobs.json": jobs,
            "run.json": run,
            "tag-object.json": tag_object,
            "tag-ref.json": tag_ref,
            "tag-ruleset.json": tag_ruleset,
            "workflow.json": workflow,
        },
        logs,
        artifact_archives,
    )


def _historical_main() -> int:
    if OUTPUT_DIRECTORY.exists():
        raise FileExistsError(
            f"refusing to replace existing capture: {OUTPUT_DIRECTORY}"
        )
    client = GitHubClient(github_token())
    snapshots, logs = fetch_capture(client)
    captured_at = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    attempt = validate_capture(snapshots, logs, captured_at)
    write_capture_bundle(OUTPUT_DIRECTORY, snapshots, logs, attempt)
    print(f"Captured invalid attempt evidence: {OUTPUT_DIRECTORY}")
    print("Classification: invalid_before_measurement; product inference: forbidden")
    return 0


def _current_main(run_id: int) -> int:
    protocol = resolve_current_protocol()
    from oss_common import STUDY_ROOT

    output = STUDY_ROOT / "attempts" / protocol["study_id"] / str(run_id)
    if output.exists():
        raise FileExistsError(f"refusing to replace existing capture: {output}")
    client = GitHubClient(github_token())
    snapshots, logs, artifact_archives = fetch_current_capture(client, run_id, protocol)
    captured_at = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    attempt = validate_current_capture(
        snapshots,
        logs,
        artifact_archives,
        captured_at,
        run_id=run_id,
        protocol=protocol,
    )
    write_current_capture_bundle(
        output,
        snapshots,
        logs,
        artifact_archives,
        protocol["manifest_bytes"],
        attempt,
    )
    print(f"Captured non-evaluative attempt evidence: {output}")
    print(
        "Product materialization eligible: "
        f"{str(attempt['product_materialization_eligible']).lower()}; "
        "capture alone permits no product inference"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        nargs="?",
        choices=("historical-v0.1", "current"),
        default="historical-v0.1",
        help="default preserves the one exact v0.1 failure; current captures v0.2",
    )
    parser.add_argument("--run-id", type=int)
    args = parser.parse_args(argv)
    if args.mode == "historical-v0.1":
        if args.run_id is not None:
            parser.error("--run-id is valid only in current mode")
        return _historical_main()
    if args.run_id is None or args.run_id <= 0:
        parser.error("current mode requires a positive --run-id")
    return _current_main(args.run_id)


if __name__ == "__main__":
    raise SystemExit(main())
