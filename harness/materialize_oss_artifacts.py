#!/usr/bin/env python3
"""Bind, download, verify, and safely materialize canonical Actions artifacts."""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from oss_common import (
    PROTOCOL_TAG,
    ROOT,
    STUDY_ROOT,
    STUDY_ID,
    canonical_json_bytes,
    case_map,
    load_json,
    manifest_path,
    sha256_bytes,
    sha256_file,
    verify_manifest,
    write_new,
)
from run_oss_case import EXPECTED_GITHUB_REPOSITORY, OUTPUT_NAMES

API_VERSION = "2026-03-10"
API_ROOT = "https://api.github.com"
WORKFLOW_PATH = ".github/workflows/oss-compat-run.yml"
WORKFLOW_FILE = "oss-compat-run.yml"
WORKFLOW_NAME = "OSS compatibility study (manual, frozen)"
RUN_INDEX_NAME = "RUN.json"
RUN_INDEX_SCHEMA = "evoom.oss-actions-run/1"
MAX_API_BYTES = 10 * 1024 * 1024
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
MAX_ZIP_ENTRIES = 20
MAX_COMPRESSION_RATIO = 1000
SHA256_PATTERN = re.compile(r"sha256:([0-9a-f]{64})\Z")
CHECKOUT_STEP = "Checkout frozen protocol"
SETUP_PYTHON_STEP = "Set up Python"
PREFLIGHT_STEP = "Prove first API-visible dispatch"
SETUP_NODE_STEP = "Set up Node"
SETUP_GO_STEP = "Set up Go"
SETUP_RUST_STEP = "Pin Rust 1.85.0"
IDENTITY_STEP = "Verify frozen study identity"
PREPARE_BOOTSTRAP_STEP = "Prepare trusted infrastructure fallback"
INSTALL_BOUNDARY_STEP = "Install trusted execution boundary"
RUN_CASE_STEP = "Run frozen case"
KILL_PROCESSES_STEP = "Kill residual untrusted processes"
CLASSIFY_OUTPUT_STEP = "Classify trusted case output"
UPLOAD_STEP = "Upload immutable raw case output"
INFRA_UPLOAD_STEP = "Upload immutable infrastructure output"
CANONICAL_SELECTION = "earliest_api_visible_workflow_dispatch_for_protocol_commit"
MAX_WORKFLOW_RUN_PAGES = 100


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _headers(token: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "evoom-oss-study-artifact-materializer",
        "X-GitHub-Api-Version": API_VERSION,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _is_link_or_reparse(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    is_junction = getattr(os.path, "isjunction", None)
    return (
        path.is_symlink()
        or bool(reparse_flag and attributes & reparse_flag)
        or bool(callable(is_junction) and is_junction(path))
    )


def _safe_regular(path: Path, root: Path, maximum: int = MAX_ARCHIVE_BYTES) -> bool:
    try:
        contained = path.resolve(strict=True).is_relative_to(root.resolve(strict=True))
        size = path.stat().st_size
    except OSError:
        return False
    return (
        contained
        and not _is_link_or_reparse(path)
        and path.is_file()
        and 0 <= size <= maximum
    )


def _read_limited(response: Any, limit: int) -> bytes:
    raw_length = response.headers.get("Content-Length")
    if raw_length:
        try:
            if int(raw_length) > limit:
                raise RuntimeError("response exceeds the byte limit")
        except ValueError as exc:
            raise RuntimeError("invalid response Content-Length") from exc
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(1 << 20, limit + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise RuntimeError("response exceeds the byte limit")


def _api_json(path: str, token: str | None) -> dict[str, Any]:
    if not path.startswith("/"):
        raise ValueError("API path must be absolute")
    request = urllib.request.Request(  # noqa: S310
        f"{API_ROOT}{path}", headers=_headers(token)
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        payload = json.loads(_read_limited(response, MAX_API_BYTES))
    if not isinstance(payload, dict):
        raise RuntimeError("GitHub API response is not an object")
    return payload


def _download_archive(artifact_id: int, token: str | None, expected_size: int) -> bytes:
    if not token:
        raise RuntimeError("artifact download requires an authenticated GitHub token")
    endpoint = (
        f"{API_ROOT}/repos/{EXPECTED_GITHUB_REPOSITORY}/actions/artifacts/"
        f"{artifact_id}/zip"
    )
    request = urllib.request.Request(endpoint, headers=_headers(token))  # noqa: S310
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        opener.open(request, timeout=30)
    except urllib.error.HTTPError as exc:
        if exc.code not in {301, 302, 303, 307, 308}:
            raise
        location = exc.headers.get("Location")
    else:
        raise RuntimeError("artifact API did not return a signed download redirect")
    if not location:
        raise RuntimeError("artifact API redirect has no Location")
    parsed = urllib.parse.urlparse(location)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise RuntimeError("unsafe artifact download redirect")
    unsigned_request = urllib.request.Request(  # noqa: S310
        location,
        headers={"User-Agent": "evoom-oss-study-artifact-materializer"},
    )
    with urllib.request.urlopen(unsigned_request, timeout=120) as response:  # noqa: S310
        archive = _read_limited(response, min(MAX_ARCHIVE_BYTES, expected_size))
    if len(archive) != expected_size:
        raise RuntimeError(
            f"downloaded artifact size mismatch: expected {expected_size}, got {len(archive)}"
        )
    return archive


def _token_from_environment_or_gh() -> str | None:
    for name in ("OSS_ACTIONS_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"):
        value = os.environ.get(name)
        if value:
            return value
    try:
        completed = subprocess.run(
            ["gh", "auth", "token"],
            check=True,
            capture_output=True,
            encoding="utf-8",
            timeout=20,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return completed.stdout.strip() or None


def _protocol_commit() -> str:
    completed = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", f"{PROTOCOL_TAG}^{{commit}}"],
        check=True,
        capture_output=True,
        encoding="ascii",
        timeout=30,
    )
    commit = completed.stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise RuntimeError("protocol tag does not resolve to a full commit")
    return commit


def expected_artifact_names() -> dict[str, str]:
    return {f"oss-{case_id}": case_id for case_id in sorted(case_map())}


def _require_product_artifact_inventory(artifacts: list[Any]) -> None:
    """Refuse to reinterpret an infrastructure attempt as product evidence."""
    if not artifacts:
        raise RuntimeError(
            "canonical run has zero artifacts; this is invalid before measurement. "
            "Do not score it; preserve its API and log evidence under attempts/"
        )
    infrastructure = sorted(
        artifact.get("name")
        for artifact in artifacts
        if isinstance(artifact, dict)
        and isinstance(artifact.get("name"), str)
        and artifact["name"].startswith("oss-infra-")
    )
    if infrastructure:
        raise RuntimeError(
            "canonical run contains infrastructure-failure artifacts "
            f"{infrastructure}; no product measurement may be materialized. "
            "Preserve the API, logs, and infra artifacts under attempts/"
        )


def _workflow_dispatch_runs(token: str | None) -> list[dict[str, Any]]:
    workflow = urllib.parse.quote(WORKFLOW_FILE, safe="")
    collected: list[dict[str, Any]] = []
    expected_total: int | None = None
    for page in range(1, MAX_WORKFLOW_RUN_PAGES + 1):
        payload = _api_json(
            f"/repos/{EXPECTED_GITHUB_REPOSITORY}/actions/workflows/{workflow}/runs"
            f"?event=workflow_dispatch&per_page=100&page={page}",
            token,
        )
        total = payload.get("total_count")
        runs = payload.get("workflow_runs")
        if not isinstance(total, int) or total < 0 or not isinstance(runs, list):
            raise RuntimeError("malformed workflow-run inventory")
        if expected_total is None:
            expected_total = total
        elif expected_total != total:
            raise RuntimeError("workflow-run inventory changed during pagination")
        for run in runs:
            if not isinstance(run, dict):
                raise RuntimeError("malformed workflow-run metadata")
            collected.append(run)
        if len(runs) < 100:
            if len(collected) != expected_total:
                raise RuntimeError("workflow-run response was truncated")
            return collected
    raise RuntimeError("workflow-run inventory exceeded the pagination limit")


def _canonical_dispatch_proof(
    runs: list[dict[str, Any]], run_id: str, commit: str
) -> dict[str, Any]:
    if not run_id.isdecimal():
        raise ValueError("run id must be decimal")
    matching: list[dict[str, Any]] = []
    for run in runs:
        identifier = run.get("id")
        created_at = run.get("created_at")
        event = run.get("event")
        head_sha = run.get("head_sha")
        if (
            not isinstance(identifier, int)
            or identifier <= 0
            or not isinstance(created_at, str)
            or not created_at
            or not isinstance(event, str)
            or not isinstance(head_sha, str)
        ):
            raise RuntimeError("incomplete workflow-run metadata")
        if event == "workflow_dispatch" and head_sha == commit:
            matching.append(run)
    selected = next((run for run in matching if run["id"] == int(run_id)), None)
    if selected is None:
        raise RuntimeError("selected run is not API-visible for the protocol commit")
    earliest = min(matching, key=lambda item: (item["created_at"], item["id"]))
    if earliest["id"] != int(run_id):
        raise RuntimeError(
            f"selected run is not the earliest API-visible dispatch; earliest is {earliest['id']}"
        )
    return {
        "selection": CANONICAL_SELECTION,
        "workflow_path": WORKFLOW_PATH,
        "event": "workflow_dispatch",
        "head_sha": commit,
        "first_run_id": int(run_id),
        "first_created_at": selected["created_at"],
    }


def _required_step_names(case_id: str) -> tuple[str, ...]:
    cases = case_map()
    if case_id not in cases:
        raise RuntimeError(f"unknown frozen case: {case_id}")
    case = cases[case_id][1]
    ecosystem = case.get("ecosystem") if isinstance(case, dict) else None
    runtime_step = {
        "node": SETUP_NODE_STEP,
        "go": SETUP_GO_STEP,
        "rust": SETUP_RUST_STEP,
    }.get(ecosystem)
    names = [CHECKOUT_STEP, SETUP_PYTHON_STEP, PREFLIGHT_STEP]
    if runtime_step:
        names.append(runtime_step)
    names.extend(
        (
            IDENTITY_STEP,
            PREPARE_BOOTSTRAP_STEP,
            INSTALL_BOUNDARY_STEP,
            RUN_CASE_STEP,
            KILL_PROCESSES_STEP,
            CLASSIFY_OUTPUT_STEP,
            UPLOAD_STEP,
            INFRA_UPLOAD_STEP,
        )
    )
    return tuple(names)


def _selected_job(
    job: dict[str, Any], case_id: str, run_id: str, commit: str
) -> dict[str, Any]:
    required = {
        "run_id": int(run_id),
        "name": case_id,
        "head_sha": commit,
        "head_branch": PROTOCOL_TAG,
        "workflow_name": WORKFLOW_NAME,
        "status": "completed",
    }
    for key, value in required.items():
        if job.get(key) != value:
            raise RuntimeError(f"{case_id}: job metadata mismatch for {key}")
    identifier = job.get("id")
    if not isinstance(identifier, int) or identifier <= 0:
        raise RuntimeError(f"{case_id}: invalid job id")
    if job.get("conclusion") not in {"success", "failure"}:
        raise RuntimeError(f"{case_id}: job has no final success/failure conclusion")
    steps = job.get("steps")
    if not isinstance(steps, list):
        raise RuntimeError(f"{case_id}: job has no step inventory")
    by_name: dict[str, dict[str, Any]] = {}
    for step in steps:
        if not isinstance(step, dict) or not isinstance(step.get("name"), str):
            raise RuntimeError(f"{case_id}: malformed job step")
        name = step["name"]
        if name in by_name:
            raise RuntimeError(f"{case_id}: duplicate job step name: {name}")
        by_name[name] = step
    selected_steps: list[dict[str, Any]] = []
    previous_number = 0
    for name in _required_step_names(case_id):
        step = by_name.get(name)
        if step is None:
            raise RuntimeError(f"{case_id}: missing required job step: {name}")
        number = step.get("number")
        if not isinstance(number, int) or number <= previous_number:
            raise RuntimeError(f"{case_id}: invalid job step order for {name}")
        previous_number = number
        if step.get("status") != "completed":
            raise RuntimeError(f"{case_id}: required job step is not completed: {name}")
        if name == RUN_CASE_STEP:
            allowed = {"success", "failure"}
        elif name == INFRA_UPLOAD_STEP:
            allowed = {"skipped"}
        else:
            allowed = {"success"}
        if step.get("conclusion") not in allowed:
            raise RuntimeError(f"{case_id}: required job step failed or was skipped: {name}")
        selected_steps.append(
            {
                "name": name,
                "number": number,
                "status": "completed",
                "conclusion": step["conclusion"],
            }
        )
    run_conclusion = next(
        step["conclusion"] for step in selected_steps if step["name"] == RUN_CASE_STEP
    )
    if job.get("conclusion") != run_conclusion:
        raise RuntimeError(f"{case_id}: job conclusion does not match the case step")
    return {
        "id": identifier,
        "run_id": int(run_id),
        "run_attempt": 1,
        "name": case_id,
        "head_sha": commit,
        "head_branch": PROTOCOL_TAG,
        "workflow_name": WORKFLOW_NAME,
        "status": "completed",
        "conclusion": job["conclusion"],
        "steps": selected_steps,
    }


def _selected_jobs(
    payload: dict[str, Any], run_id: str, commit: str
) -> list[dict[str, Any]]:
    jobs = payload.get("jobs")
    expected_cases = set(case_map())
    if (
        not isinstance(jobs, list)
        or payload.get("total_count") != len(jobs)
        or len(jobs) != len(expected_cases)
    ):
        raise RuntimeError("Actions job response was truncated or has the wrong count")
    by_name: dict[str, dict[str, Any]] = {}
    for job in jobs:
        if not isinstance(job, dict) or not isinstance(job.get("name"), str):
            raise RuntimeError("malformed Actions job metadata")
        name = job["name"]
        if name in by_name:
            raise RuntimeError(f"duplicate Actions job name: {name}")
        by_name[name] = job
    if set(by_name) != expected_cases:
        raise RuntimeError(
            f"job inventory mismatch: expected {sorted(expected_cases)}, got {sorted(by_name)}"
        )
    return [
        _selected_job(by_name[case_id], case_id, run_id, commit)
        for case_id in sorted(expected_cases)
    ]


def _selected_run(run: dict[str, Any], run_id: str, commit: str) -> dict[str, Any]:
    repository = run.get("repository")
    head_repository = run.get("head_repository")
    required = {
        "id": int(run_id),
        "event": "workflow_dispatch",
        "head_branch": PROTOCOL_TAG,
        "head_sha": commit,
        "run_attempt": 1,
        "path": WORKFLOW_PATH,
        "status": "completed",
        "html_url": (
            f"https://github.com/{EXPECTED_GITHUB_REPOSITORY}/actions/runs/{run_id}"
        ),
        "artifacts_url": (
            f"{API_ROOT}/repos/{EXPECTED_GITHUB_REPOSITORY}/actions/runs/"
            f"{run_id}/artifacts"
        ),
    }
    for key, value in required.items():
        if run.get(key) != value:
            raise RuntimeError(f"canonical run metadata mismatch for {key}")
    if run.get("conclusion") not in {"success", "failure"}:
        raise RuntimeError("canonical run has no final success/failure conclusion")
    if not isinstance(repository, dict) or repository.get("full_name") != EXPECTED_GITHUB_REPOSITORY:
        raise RuntimeError("canonical run repository mismatch")
    if (
        not isinstance(head_repository, dict)
        or head_repository.get("full_name") != EXPECTED_GITHUB_REPOSITORY
    ):
        raise RuntimeError("canonical run head repository mismatch")
    selected_fields = (
        "id",
        "run_number",
        "run_attempt",
        "workflow_id",
        "event",
        "status",
        "conclusion",
        "head_branch",
        "head_sha",
        "path",
        "created_at",
        "updated_at",
        "run_started_at",
        "html_url",
        "artifacts_url",
    )
    selected = {key: run.get(key) for key in selected_fields}
    if any(selected[key] is None for key in selected_fields):
        raise RuntimeError("canonical run metadata is incomplete")
    actor = run.get("actor")
    triggering_actor = run.get("triggering_actor")
    selected["actor"] = actor.get("login") if isinstance(actor, dict) else None
    selected["triggering_actor"] = (
        triggering_actor.get("login") if isinstance(triggering_actor, dict) else None
    )
    if selected["actor"] != "EvoRiseKsa" or selected["triggering_actor"] != "EvoRiseKsa":
        raise RuntimeError("canonical run actor metadata mismatch")
    return selected


def _selected_artifact(
    artifact: dict[str, Any],
    case_id: str,
    run_id: str,
    commit: str,
    *,
    require_downloadable: bool,
) -> dict[str, Any]:
    name = f"oss-{case_id}"
    artifact_id = artifact.get("id")
    size = artifact.get("size_in_bytes")
    digest = artifact.get("digest")
    workflow_run = artifact.get("workflow_run")
    if not isinstance(artifact_id, int) or artifact_id <= 0:
        raise RuntimeError(f"{name}: invalid artifact id")
    if not isinstance(size, int) or not 0 < size <= MAX_ARCHIVE_BYTES:
        raise RuntimeError(f"{name}: invalid artifact size")
    match = SHA256_PATTERN.fullmatch(str(digest))
    if not match:
        raise RuntimeError(f"{name}: missing API SHA-256 digest")
    if artifact.get("name") != name:
        raise RuntimeError(f"{name}: artifact name mismatch")
    if require_downloadable and artifact.get("expired") is not False:
        raise RuntimeError(f"{name}: artifact is expired")
    if not isinstance(workflow_run, dict) or workflow_run.get("id") != int(run_id):
        raise RuntimeError(f"{name}: artifact workflow run mismatch")
    if workflow_run.get("head_sha") != commit:
        raise RuntimeError(f"{name}: artifact head SHA mismatch")
    expected_url = (
        f"{API_ROOT}/repos/{EXPECTED_GITHUB_REPOSITORY}/actions/artifacts/"
        f"{artifact_id}/zip"
    )
    if artifact.get("archive_download_url") != expected_url:
        raise RuntimeError(f"{name}: artifact download URL mismatch")
    selected_fields = (
        "id",
        "node_id",
        "name",
        "size_in_bytes",
        "created_at",
        "updated_at",
        "expires_at",
        "digest",
        "archive_download_url",
    )
    selected = {key: artifact.get(key) for key in selected_fields}
    if any(selected[key] is None for key in selected_fields):
        raise RuntimeError(f"{name}: artifact metadata is incomplete")
    selected.update(
        {
            "case_id": case_id,
            "archive_file": f"archives/{name}.zip",
            "archive_sha256": match.group(1),
            "workflow_run_id": int(run_id),
            "workflow_head_sha": commit,
        }
    )
    return selected


def fetch_run_index(
    run_id: str, token: str | None, *, require_downloadable: bool = True
) -> dict[str, Any]:
    if not run_id.isdecimal():
        raise ValueError("run id must be decimal")
    commit = _protocol_commit()
    run = _api_json(
        f"/repos/{EXPECTED_GITHUB_REPOSITORY}/actions/runs/{run_id}", token
    )
    artifacts_payload = _api_json(
        f"/repos/{EXPECTED_GITHUB_REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100",
        token,
    )
    jobs_payload = _api_json(
        f"/repos/{EXPECTED_GITHUB_REPOSITORY}/actions/runs/{run_id}/attempts/1/jobs"
        "?per_page=100",
        token,
    )
    canonical_dispatch = _canonical_dispatch_proof(
        _workflow_dispatch_runs(token), run_id, commit
    )
    artifacts = artifacts_payload.get("artifacts")
    if not isinstance(artifacts, list):
        raise RuntimeError("Actions API returned no artifact list")
    if artifacts_payload.get("total_count") != len(artifacts):
        raise RuntimeError("Actions artifact response was truncated")
    _require_product_artifact_inventory(artifacts)
    expected = expected_artifact_names()
    by_name: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("name"), str):
            raise RuntimeError("malformed artifact metadata")
        name = artifact["name"]
        if name in by_name:
            raise RuntimeError(f"duplicate artifact name: {name}")
        by_name[name] = artifact
    if set(by_name) != set(expected):
        raise RuntimeError(
            f"artifact inventory mismatch: expected {sorted(expected)}, got {sorted(by_name)}"
        )
    selected_run = _selected_run(run, run_id, commit)
    selected_jobs = _selected_jobs(jobs_payload, run_id, commit)
    expected_run_conclusion = (
        "failure"
        if any(job["conclusion"] == "failure" for job in selected_jobs)
        else "success"
    )
    if selected_run["conclusion"] != expected_run_conclusion:
        raise RuntimeError("workflow conclusion does not match the exact matrix jobs")
    if canonical_dispatch["first_created_at"] != selected_run["created_at"]:
        raise RuntimeError("canonical dispatch proof does not match the selected run")
    return {
        "run_index_schema": RUN_INDEX_SCHEMA,
        "api_version": API_VERSION,
        "repository": EXPECTED_GITHUB_REPOSITORY,
        "study_id": STUDY_ID,
        "protocol_tag": PROTOCOL_TAG,
        "protocol_commit": commit,
        "manifest_sha256": sha256_file(manifest_path()),
        "run": selected_run,
        "canonical_dispatch": canonical_dispatch,
        "jobs": selected_jobs,
        "artifacts": [
            _selected_artifact(
                by_name[name],
                expected[name],
                run_id,
                commit,
                require_downloadable=require_downloadable,
            )
            for name in sorted(expected)
        ],
    }


def run_index_problems(
    index: dict[str, Any], expected_run_id: str | None = None
) -> list[str]:
    problems: list[str] = []
    expected_top = {
        "run_index_schema",
        "api_version",
        "repository",
        "study_id",
        "protocol_tag",
        "protocol_commit",
        "manifest_sha256",
        "run",
        "canonical_dispatch",
        "jobs",
        "artifacts",
    }
    if set(index) != expected_top:
        problems.append("RUN.json top-level field set mismatch")
    try:
        commit = _protocol_commit()
    except (OSError, RuntimeError, subprocess.SubprocessError):
        commit = None
        problems.append("cannot resolve the frozen protocol tag")
    expected_bindings = {
        "run_index_schema": RUN_INDEX_SCHEMA,
        "api_version": API_VERSION,
        "repository": EXPECTED_GITHUB_REPOSITORY,
        "study_id": STUDY_ID,
        "protocol_tag": PROTOCOL_TAG,
        "protocol_commit": commit,
        "manifest_sha256": (
            sha256_file(manifest_path()) if manifest_path().is_file() else None
        ),
    }
    for key, value in expected_bindings.items():
        if index.get(key) != value:
            problems.append(f"RUN.json binding mismatch for {key}")
    run = index.get("run")
    expected_run_fields = {
        "id",
        "run_number",
        "run_attempt",
        "workflow_id",
        "event",
        "status",
        "conclusion",
        "head_branch",
        "head_sha",
        "path",
        "created_at",
        "updated_at",
        "run_started_at",
        "html_url",
        "artifacts_url",
        "actor",
        "triggering_actor",
    }
    if not isinstance(run, dict):
        problems.append("RUN.json has no run object")
        run = {}
    elif set(run) != expected_run_fields:
        problems.append("RUN.json run field set mismatch")
    run_id = str(run.get("id") or "")
    if not run_id.isdecimal() or (expected_run_id and run_id != expected_run_id):
        problems.append("RUN.json canonical run id mismatch")
    run_bindings = {
        "event": "workflow_dispatch",
        "head_branch": PROTOCOL_TAG,
        "head_sha": commit,
        "run_attempt": 1,
        "path": WORKFLOW_PATH,
        "status": "completed",
        "html_url": (
            f"https://github.com/{EXPECTED_GITHUB_REPOSITORY}/actions/runs/{run_id}"
        ),
        "artifacts_url": (
            f"{API_ROOT}/repos/{EXPECTED_GITHUB_REPOSITORY}/actions/runs/"
            f"{run_id}/artifacts"
        ),
        "actor": "EvoRiseKsa",
        "triggering_actor": "EvoRiseKsa",
    }
    for key, value in run_bindings.items():
        if run.get(key) != value:
            problems.append(f"RUN.json run mismatch for {key}")
    if run.get("conclusion") not in {"success", "failure"}:
        problems.append("RUN.json has no final run conclusion")
    expected_cases = set(case_map())
    canonical_dispatch = index.get("canonical_dispatch")
    expected_canonical_fields = {
        "selection",
        "workflow_path",
        "event",
        "head_sha",
        "first_run_id",
        "first_created_at",
    }
    if not isinstance(canonical_dispatch, dict):
        problems.append("RUN.json has no canonical dispatch proof")
        canonical_dispatch = {}
    elif set(canonical_dispatch) != expected_canonical_fields:
        problems.append("RUN.json canonical dispatch field set mismatch")
    canonical_bindings = {
        "selection": CANONICAL_SELECTION,
        "workflow_path": WORKFLOW_PATH,
        "event": "workflow_dispatch",
        "head_sha": commit,
        "first_run_id": int(run_id) if run_id.isdecimal() else None,
        "first_created_at": run.get("created_at"),
    }
    for key, value in canonical_bindings.items():
        if canonical_dispatch.get(key) != value:
            problems.append(f"RUN.json canonical dispatch mismatch for {key}")

    jobs = index.get("jobs")
    if not isinstance(jobs, list) or len(jobs) != len(expected_cases):
        problems.append("RUN.json job count mismatch")
        jobs = []
    expected_job_fields = {
        "id",
        "run_id",
        "run_attempt",
        "name",
        "head_sha",
        "head_branch",
        "workflow_name",
        "status",
        "conclusion",
        "steps",
    }
    expected_step_fields = {"name", "number", "status", "conclusion"}
    seen_jobs: set[str] = set()
    seen_job_ids: set[int] = set()
    job_conclusions: list[str] = []
    for job in jobs:
        if not isinstance(job, dict):
            problems.append("RUN.json contains a malformed job object")
            continue
        if set(job) != expected_job_fields:
            problems.append("RUN.json job field set mismatch")
        case_id = job.get("name")
        if (
            not isinstance(case_id, str)
            or case_id not in expected_cases
            or case_id in seen_jobs
        ):
            problems.append(f"RUN.json invalid job case name: {case_id!r}")
            continue
        seen_jobs.add(case_id)
        job_id = job.get("id")
        if not isinstance(job_id, int) or job_id <= 0 or job_id in seen_job_ids:
            problems.append(f"{case_id}: invalid or duplicate job id")
        else:
            seen_job_ids.add(job_id)
        job_bindings = {
            "run_id": int(run_id) if run_id.isdecimal() else None,
            "run_attempt": 1,
            "head_sha": commit,
            "head_branch": PROTOCOL_TAG,
            "workflow_name": WORKFLOW_NAME,
            "status": "completed",
        }
        for key, value in job_bindings.items():
            if job.get(key) != value:
                problems.append(f"{case_id}: job binding mismatch for {key}")
        conclusion = job.get("conclusion")
        if conclusion not in {"success", "failure"}:
            problems.append(f"{case_id}: invalid final job conclusion")
        else:
            job_conclusions.append(conclusion)
        steps = job.get("steps")
        required_names = _required_step_names(case_id)
        if not isinstance(steps, list) or len(steps) != len(required_names):
            problems.append(f"{case_id}: required job step count mismatch")
            continue
        previous_number = 0
        run_step_conclusion: str | None = None
        for position, step in enumerate(steps):
            expected_name = required_names[position]
            if not isinstance(step, dict):
                problems.append(f"{case_id}: malformed required job step")
                continue
            if set(step) != expected_step_fields:
                problems.append(f"{case_id}: required job step field set mismatch")
            if step.get("name") != expected_name:
                problems.append(f"{case_id}: required job step name/order mismatch")
            number = step.get("number")
            if not isinstance(number, int) or number <= previous_number:
                problems.append(f"{case_id}: invalid required job step order")
            else:
                previous_number = number
            if step.get("status") != "completed":
                problems.append(f"{case_id}: required job step is not completed")
            if expected_name == RUN_CASE_STEP:
                allowed = {"success", "failure"}
            elif expected_name == INFRA_UPLOAD_STEP:
                allowed = {"skipped"}
            else:
                allowed = {"success"}
            if step.get("conclusion") not in allowed:
                problems.append(f"{case_id}: required job step failed or was skipped")
            if expected_name == RUN_CASE_STEP:
                run_step_conclusion = step.get("conclusion")
        if conclusion in {"success", "failure"} and conclusion != run_step_conclusion:
            problems.append(f"{case_id}: job conclusion does not match the case step")
    if seen_jobs != expected_cases:
        problems.append("RUN.json jobs do not cover the frozen cases")
    if len(job_conclusions) == len(expected_cases):
        expected_conclusion = "failure" if "failure" in job_conclusions else "success"
        if run.get("conclusion") != expected_conclusion:
            problems.append("RUN.json run conclusion does not match the exact matrix jobs")

    artifacts = index.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != len(expected_cases):
        problems.append("RUN.json artifact count mismatch")
        artifacts = []
    expected_artifact_fields = {
        "id",
        "node_id",
        "name",
        "size_in_bytes",
        "created_at",
        "updated_at",
        "expires_at",
        "digest",
        "archive_download_url",
        "case_id",
        "archive_file",
        "archive_sha256",
        "workflow_run_id",
        "workflow_head_sha",
    }
    seen: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict):
            problems.append("RUN.json contains a malformed artifact object")
            continue
        if set(item) != expected_artifact_fields:
            problems.append("RUN.json artifact field set mismatch")
        case_id = item.get("case_id")
        if not isinstance(case_id, str) or case_id not in expected_cases or case_id in seen:
            problems.append(f"RUN.json invalid artifact case id: {case_id!r}")
            continue
        seen.add(case_id)
        artifact_id = item.get("id")
        size = item.get("size_in_bytes")
        archive_sha = item.get("archive_sha256")
        if not isinstance(artifact_id, int) or artifact_id <= 0:
            problems.append(f"{case_id}: invalid artifact id")
        if not isinstance(size, int) or not 0 < size <= MAX_ARCHIVE_BYTES:
            problems.append(f"{case_id}: invalid artifact size")
        if not isinstance(archive_sha, str) or re.fullmatch(r"[0-9a-f]{64}", archive_sha) is None:
            problems.append(f"{case_id}: invalid archive digest")
        expected_values = {
            "name": f"oss-{case_id}",
            "archive_file": f"archives/oss-{case_id}.zip",
            "digest": f"sha256:{archive_sha}",
            "workflow_run_id": int(run_id) if run_id.isdecimal() else None,
            "workflow_head_sha": commit,
            "archive_download_url": (
                f"{API_ROOT}/repos/{EXPECTED_GITHUB_REPOSITORY}/actions/artifacts/"
                f"{artifact_id}/zip"
            ),
        }
        for key, value in expected_values.items():
            if item.get(key) != value:
                problems.append(f"{case_id}: artifact binding mismatch for {key}")
    if seen != expected_cases:
        problems.append("RUN.json artifacts do not cover the frozen cases")
    return problems


def _zip_entries(archive: bytes) -> dict[str, bytes]:
    try:
        handle = zipfile.ZipFile(io.BytesIO(archive))
    except (OSError, zipfile.BadZipFile) as exc:
        raise RuntimeError("artifact is not a valid ZIP archive") from exc
    with handle:
        infos = handle.infolist()
        if not 1 <= len(infos) <= MAX_ZIP_ENTRIES:
            raise RuntimeError("artifact ZIP entry count is outside the limit")
        entries: dict[str, bytes] = {}
        total_uncompressed = 0
        for info in infos:
            name = info.filename
            path = PurePosixPath(name)
            if (
                not name
                or "\\" in name
                or path.is_absolute()
                or len(path.parts) != 1
                or path.parts[0] in {".", ".."}
                or info.is_dir()
            ):
                raise RuntimeError(f"unsafe or nested ZIP entry: {name!r}")
            if name in entries:
                raise RuntimeError(f"duplicate ZIP entry: {name}")
            mode = (info.external_attr >> 16) & 0o170000
            if mode not in {0, stat.S_IFREG} or info.flag_bits & 0x1:
                raise RuntimeError(f"non-regular or encrypted ZIP entry: {name}")
            if info.file_size < 0 or info.file_size > MAX_UNCOMPRESSED_BYTES:
                raise RuntimeError(f"oversized ZIP entry: {name}")
            total_uncompressed += info.file_size
            if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                raise RuntimeError("artifact ZIP exceeds the uncompressed byte limit")
            if info.file_size and info.compress_size == 0:
                raise RuntimeError(f"invalid compression metadata: {name}")
            if (
                info.compress_size
                and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO
            ):
                raise RuntimeError(f"excessive ZIP compression ratio: {name}")
            data = handle.read(info)
            if len(data) != info.file_size:
                raise RuntimeError(f"ZIP entry size mismatch: {name}")
            entries[name] = data
    mandatory = {
        "guard.stdout.txt",
        "guard.stderr.txt",
        "timing.json",
        "run-envelope.json",
    }
    if not mandatory.issubset(entries) or not set(entries).issubset(OUTPUT_NAMES):
        raise RuntimeError(f"artifact output inventory mismatch: {sorted(entries)}")
    return entries


def verify_local_materialization(
    study_results: Path,
    index: dict[str, Any],
    expected_run_id: str | None = None,
) -> list[str]:
    problems = run_index_problems(index, expected_run_id)
    artifacts = index.get("artifacts")
    if not isinstance(artifacts, list):
        return ["RUN.json has no artifact list"]
    expected_cases = set(case_map())
    archives_directory = study_results / "archives"
    try:
        archive_entries = list(archives_directory.iterdir())
    except OSError:
        archive_entries = []
        problems.append("missing preserved artifact archive directory")
    expected_archive_names = {f"oss-{case_id}.zip" for case_id in expected_cases}
    if {path.name for path in archive_entries} != expected_archive_names:
        problems.append("preserved artifact archive inventory mismatch")
    if any(not _safe_regular(path, study_results) for path in archive_entries):
        problems.append("preserved artifact archive inventory is not regular")
    seen_cases: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict):
            problems.append("RUN.json contains a malformed artifact")
            continue
        case_id = item.get("case_id")
        if not isinstance(case_id, str) or case_id not in expected_cases or case_id in seen_cases:
            problems.append(f"invalid or duplicate artifact case id: {case_id!r}")
            continue
        seen_cases.add(case_id)
        expected_relative = f"archives/oss-{case_id}.zip"
        if item.get("archive_file") != expected_relative:
            problems.append(f"{case_id}: archive path mismatch")
            continue
        archive_path = study_results / "archives" / f"oss-{case_id}.zip"
        if not _safe_regular(archive_path, study_results):
            problems.append(f"{case_id}: unsafe or missing preserved artifact archive")
            continue
        try:
            archive = archive_path.read_bytes()
        except OSError:
            problems.append(f"{case_id}: missing preserved artifact archive")
            continue
        if len(archive) != item.get("size_in_bytes"):
            problems.append(f"{case_id}: preserved archive size mismatch")
        if sha256_bytes(archive) != item.get("archive_sha256"):
            problems.append(f"{case_id}: preserved archive digest mismatch")
        try:
            entries = _zip_entries(archive)
        except RuntimeError as exc:
            problems.append(f"{case_id}: {exc}")
            continue
        output = study_results / case_id
        try:
            output_entries = list(output.iterdir())
        except OSError:
            problems.append(f"{case_id}: missing extracted case directory")
            continue
        if _is_link_or_reparse(output):
            problems.append(f"{case_id}: extracted case directory is linked")
            continue
        actual_names = {path.name for path in output_entries}
        if any(not _safe_regular(path, output) for path in output_entries):
            problems.append(f"{case_id}: extracted case contains a non-regular file")
            continue
        if actual_names != set(entries):
            problems.append(f"{case_id}: extracted output inventory differs from archive")
            continue
        for name, data in entries.items():
            try:
                actual = (output / name).read_bytes()
            except OSError:
                problems.append(f"{case_id}: missing extracted file {name}")
                continue
            if actual != data:
                problems.append(f"{case_id}: extracted file differs from archive: {name}")
    if seen_cases != expected_cases:
        problems.append("RUN.json artifact cases do not cover the frozen corpus")
    return problems


def verify_online_index(index: dict[str, Any], token: str | None) -> list[str]:
    run = index.get("run")
    run_id = str(run.get("id") or "") if isinstance(run, dict) else ""
    try:
        expected = fetch_run_index(run_id, token, require_downloadable=False)
    except (OSError, RuntimeError, ValueError, urllib.error.URLError) as exc:
        return [f"GitHub Actions API verification failed: {type(exc).__name__}: {exc}"]
    return [] if index == expected else ["RUN.json differs from live GitHub Actions metadata"]


def materialize(run_id: str, results_root: Path, token: str | None) -> Path:
    manifest, manifest_problems = verify_manifest()
    if manifest_problems or not manifest:
        raise RuntimeError("frozen study manifest is missing or invalid")
    index = fetch_run_index(run_id, token)
    destination = results_root / STUDY_ID
    if _is_link_or_reparse(results_root):
        raise RuntimeError("refusing linked result root")
    if destination.exists():
        raise RuntimeError(f"refusing to overwrite study results: {destination}")
    results_root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{STUDY_ID}-", dir=results_root))
    try:
        archives = staging / "archives"
        archives.mkdir()
        for item in index["artifacts"]:
            archive = _download_archive(item["id"], token, item["size_in_bytes"])
            if sha256_bytes(archive) != item["archive_sha256"]:
                raise RuntimeError(f"{item['name']}: downloaded artifact digest mismatch")
            archive_path = archives / f"{item['name']}.zip"
            write_new(archive_path, archive)
            case_output = staging / item["case_id"]
            case_output.mkdir()
            for name, data in _zip_entries(archive).items():
                write_new(case_output / name, data)
        write_new(staging / RUN_INDEX_NAME, canonical_json_bytes(index))
        problems = verify_local_materialization(staging, index)
        if problems:
            raise RuntimeError("; ".join(problems))
        os.replace(staging, destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--results", required=True)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--if-present", action="store_true")
    args = parser.parse_args()
    results_root = Path(args.results).absolute()
    expected_results_root = (STUDY_ROOT / "results").resolve()
    if results_root.resolve() != expected_results_root:
        raise SystemExit(f"--results must be the protocol result root: {expected_results_root}")
    study_results = results_root / STUDY_ID
    if args.verify_only:
        if args.if_present and not study_results.is_dir():
            print(f"SKIP no published results yet for {STUDY_ID}")
            return 0
        token = _token_from_environment_or_gh()
        run_index_path = study_results / RUN_INDEX_NAME
        if not _safe_regular(run_index_path, study_results, MAX_API_BYTES):
            raise SystemExit("unsafe or missing RUN.json")
        index = load_json(run_index_path)
        run = index.get("run")
        indexed_run_id = str(run.get("id") or "") if isinstance(run, dict) else ""
        expected_run_id = args.run_id or indexed_run_id
        problems = verify_local_materialization(study_results, index, expected_run_id)
        problems.extend(verify_online_index(index, token))
        if problems:
            for problem in problems:
                print(f"PROBLEM: {problem}")
            return 1
        print(f"OK externally bound Actions artifacts for run {expected_run_id}")
        return 0
    if not args.run_id:
        raise SystemExit("--run-id is required for materialization")
    token = _token_from_environment_or_gh()
    destination = materialize(args.run_id, results_root, token)
    print(f"OK materialized externally bound artifacts in {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
