#!/usr/bin/env python3
"""Run one manifest-frozen OSS compatibility case and emit an audit envelope."""
from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import shutil
import subprocess
import sys
import time
import traceback
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from oss_common import (
    ENGINE_SHA256,
    ENGINE_VERSION,
    PROTOCOL_TAG,
    ROOT,
    SCHEMA_VERSION,
    STUDY_ID,
    canonical_candidate_digest,
    canonical_diff,
    canonical_json_bytes,
    case_map,
    changed_paths,
    ensure_commit,
    ensure_git_cache,
    extract_git_tree,
    load_json,
    manifest_path,
    resolve_study_file,
    safe_posix_relative_path,
    sha256_bytes,
    sha256_file,
    tree_sha,
    verify_manifest,
    write_new,
)

ENGINE_URL = (
    "https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/download/"
    f"{ENGINE_VERSION}/evo-guard.pyz"
)
OUTPUT_NAMES = {
    "verdict.json",
    "guard-report.md",
    "guard.stdout.txt",
    "guard.stderr.txt",
    "timing.json",
    "run-envelope.json",
}
PRE_ENVELOPE_OUTPUT_NAMES = OUTPUT_NAMES - {"run-envelope.json"}
EXPECTED_GITHUB_REPOSITORY = "EvoRiseKsa/evoom-guard-eval"
EXPECTED_GITHUB_REF = f"refs/tags/{PROTOCOL_TAG}"
EXPECTED_GITHUB_WORKFLOW_REF = (
    f"{EXPECTED_GITHUB_REPOSITORY}/.github/workflows/oss-compat-run.yml@"
    f"{EXPECTED_GITHUB_REF}"
)
_FAILURE_OUTPUT_DIR: Path | None = None
_ENTRY_STARTED = time.perf_counter()
_ENTRY_STARTED_UTC = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _prepare_failure_output(args: argparse.Namespace) -> None:
    global _FAILURE_OUTPUT_DIR
    if args.study != STUDY_ID:
        return
    try:
        if safe_posix_relative_path(args.case_id) != args.case_id or "/" in args.case_id:
            return
    except ValueError:
        return
    candidate = Path(args.output_root).resolve() / args.study / args.case_id
    if candidate.exists() and any(candidate.iterdir()):
        return
    _FAILURE_OUTPUT_DIR = candidate


def runner_identity() -> dict[str, str | None]:
    """Capture the immutable Actions identity used to attribute an artifact."""
    return {
        "os": os.name,
        "runner_os": os.environ.get("RUNNER_OS"),
        "runner_arch": os.environ.get("RUNNER_ARCH"),
        "image_os": os.environ.get("ImageOS"),
        "image_version": os.environ.get("ImageVersion"),
        "github_actions": os.environ.get("GITHUB_ACTIONS"),
        "github_event_name": os.environ.get("GITHUB_EVENT_NAME"),
        "github_repository": os.environ.get("GITHUB_REPOSITORY"),
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "github_sha": os.environ.get("GITHUB_SHA"),
        "github_ref": os.environ.get("GITHUB_REF"),
        "github_ref_name": os.environ.get("GITHUB_REF_NAME"),
        "github_ref_type": os.environ.get("GITHUB_REF_TYPE"),
        "github_ref_protected": os.environ.get("GITHUB_REF_PROTECTED"),
        "github_workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF"),
        "canonical_dispatch_id": os.environ.get("OSS_CANONICAL_DISPATCH_ID"),
    }


def github_execution_problems(commit: str) -> list[str]:
    """Require the protected tag's first, workflow-verified Actions dispatch."""
    identity = runner_identity()
    expected = {
        "github_actions": "true",
        "github_event_name": "workflow_dispatch",
        "github_repository": EXPECTED_GITHUB_REPOSITORY,
        "github_run_attempt": "1",
        "github_sha": commit,
        "github_ref": EXPECTED_GITHUB_REF,
        "github_ref_name": PROTOCOL_TAG,
        "github_ref_type": "tag",
        "github_ref_protected": "true",
        "github_workflow_ref": EXPECTED_GITHUB_WORKFLOW_REF,
    }
    problems = [
        f"unexpected GitHub execution identity for {key}"
        for key, value in expected.items()
        if identity.get(key) != value
    ]
    run_id = identity.get("github_run_id")
    if not isinstance(run_id, str) or not run_id.isdecimal():
        problems.append("missing or invalid GitHub run id")
    if identity.get("canonical_dispatch_id") != run_id:
        problems.append("workflow did not attest the first canonical dispatch")
    return problems


def _preserve_harness_failure(error: BaseException) -> None:
    output = _FAILURE_OUTPUT_DIR
    if output is None:
        return
    output.mkdir(parents=True, exist_ok=True)
    detail = (
        str(error)
        if isinstance(error, SystemExit)
        else "".join(traceback.format_exception(type(error), error, error.__traceback__))
    )
    stdout_path = output / "guard.stdout.txt"
    stderr_path = output / "guard.stderr.txt"
    timing_path = output / "timing.json"
    envelope_path = output / "run-envelope.json"
    if not stdout_path.exists():
        write_new(stdout_path, b"")
    if not stderr_path.exists():
        write_new(
            stderr_path,
            ("HARNESS FAILURE BEFORE A VALIDATED GUARD RESULT\n" + detail + "\n").encode(
                "utf-8", "replace"
            ),
        )
    if not timing_path.exists():
        write_new(
            timing_path,
            canonical_json_bytes(
                {
                    "harness_failed": True,
                    "total_seconds": time.perf_counter() - _ENTRY_STARTED,
                }
            ),
        )
    if envelope_path.exists():
        return
    pre_inventory = {path.name for path in output.iterdir()}
    pre_hashes = {
        name: sha256_file(output / name)
        for name in sorted(pre_inventory)
        if (output / name).is_file()
    }
    binding_problems: list[str] = []
    bindings: dict[str, Any] = {}
    try:
        manifest, manifest_problems = verify_manifest(STUDY_ID)
        if manifest_problems:
            raise RuntimeError("manifest verification failed")
        case_dir, case = case_map()[output.name]
        policy_path = resolve_study_file(case["policy"], "policies")
        environment_path = resolve_study_file(case["environment"], "environments")
        commit, tag_commit, dirty = _git_state()
        if dirty or commit != tag_commit or not _manifest_is_tagged():
            raise RuntimeError("protocol checkout binding failed")
        binding_problems.extend(github_execution_problems(commit))
        bindings = {
            "claim_scope": manifest["claim_scope"],
            "manifest_sha256": sha256_file(manifest_path()),
            "manifest_git_commit": tag_commit,
            "execution_git_commit": commit,
            "protocol_tag": PROTOCOL_TAG,
            "protocol_tag_commit": tag_commit,
            "engine": {"release": ENGINE_VERSION, "sha256": ENGINE_SHA256},
            "candidate_sha256": sha256_file(case_dir / "candidate.diff"),
            "candidate_canonical_sha256": case["candidate_canonical_sha256"],
            "policy_sha256": sha256_file(policy_path),
            "environment_sha256": sha256_file(environment_path),
            "environment": load_json(environment_path),
            "source": case["source"],
            "runtime": runtime_inventory(),
            "runner": runner_identity(),
        }
    except Exception as binding_error:  # invalid pre-protocol runs remain invalid evidence
        binding_problems.append(
            f"failure envelope binding unavailable: {type(binding_error).__name__}"
        )
    findings = ["harness failed before a validated Guard result"]
    write_new(
        envelope_path,
        canonical_json_bytes(
            {
                "run_envelope_schema": "evoom.oss-run-envelope/1",
                "study_id": STUDY_ID,
                "case_id": output.name,
                "started_utc": _ENTRY_STARTED_UTC,
                "finished_utc": datetime.now(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "success": False,
                "harness_failure": {
                    "type": type(error).__name__,
                    "message": str(error),
                },
                **bindings,
                "guard_exit_code": None,
                "record_integrity_problems": binding_problems,
                "conformance_findings": findings,
                "verify_and_expectation_problems": binding_problems + findings,
                "artifact_valid": not binding_problems,
                "output_files_present": sorted(pre_inventory | {"run-envelope.json"}),
                "pre_envelope_output_sha256": pre_hashes,
            }
        ),
    )


def acquire_engine(engine_arg: str | None, work_root: Path) -> Path:
    destination = Path(engine_arg).resolve() if engine_arg else work_root / "engine" / "evo-guard.pyz"
    if not destination.is_file():
        if engine_arg:
            raise FileNotFoundError(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(".download")
        temporary.unlink(missing_ok=True)
        try:
            with urllib.request.urlopen(ENGINE_URL, timeout=60) as response:  # noqa: S310
                with open(temporary, "xb") as output:
                    shutil.copyfileobj(response, output)
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
    actual = sha256_file(destination)
    if actual != ENGINE_SHA256:
        raise RuntimeError(f"engine digest mismatch: expected {ENGINE_SHA256}, got {actual}")
    return destination


def _tool_version(argv: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (completed.stdout or completed.stderr).strip()
    return text.splitlines()[0] if text else None


def _completed_bytes(value: str | bytes | None) -> bytes:
    if isinstance(value, bytes):
        return value
    return (value or "").encode("utf-8")


def _os_release() -> dict[str, str]:
    path = Path("/etc/os-release")
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def runtime_inventory() -> dict[str, Any]:
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "os_release": _os_release(),
        "python": _tool_version([sys.executable, "--version"]),
        "git": _tool_version(["git", "--version"]),
        "node": _tool_version(["node", "--version"]),
        "npm": _tool_version(["npm", "--version"]),
        "go": _tool_version(["go", "version"]),
        "rustc": _tool_version(["rustc", "--version"]),
        "cargo": _tool_version(["cargo", "--version"]),
        "cmake": _tool_version(["cmake", "--version"]),
        "gcc": _tool_version(["gcc", "--version"]),
        "g++": _tool_version(["g++", "--version"]),
        "make": _tool_version(["make", "--version"]),
    }


def candidate_digest(head: Path, entries: list[dict[str, str]]) -> str:
    return canonical_candidate_digest(
        entries, lambda relative: (head / Path(*relative.split("/"))).read_bytes()
    )


def _trusted_checkout_git(*arguments: str) -> list[str]:
    """Authorize only the runner-owned, manifest-frozen protocol checkout."""
    return [
        "git",
        "-c",
        f"safe.directory={ROOT}",
        "-C",
        str(ROOT),
        *arguments,
    ]


def _git_state() -> tuple[str, str, bool]:
    commit = subprocess.run(
        _trusted_checkout_git("rev-parse", "HEAD"),
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    tag_commit = subprocess.run(
        _trusted_checkout_git("rev-parse", f"{PROTOCOL_TAG}^{{commit}}"),
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    status = subprocess.run(
        _trusted_checkout_git("status", "--porcelain", "--untracked-files=no"),
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    return commit, tag_commit, bool(status.strip())


def _manifest_is_tagged() -> bool:
    relative = manifest_path().relative_to(ROOT).as_posix()
    tagged = subprocess.run(
        _trusted_checkout_git("show", f"{PROTOCOL_TAG}:{relative}"),
        check=True,
        capture_output=True,
        timeout=30,
    ).stdout
    return tagged == manifest_path().read_bytes()


def expected_effective_policy(policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "mode": "repo",
        "isolation": "subprocess",
        "docker_image": None,
        "docker_network": "none",
        "test_command": policy["test_command"],
        "setup_command": policy.get("setup_command"),
        "trust_setup_on_host": False,
        "setup_output_globs": sorted(policy.get("setup_output_globs", [])),
        "protected": sorted(policy.get("protected", [])),
        "allow": sorted(policy.get("allow", [])),
        "allow_new_tests": policy.get("allow_new_tests", False),
        "timeout": policy["timeout"],
        "mem_limit_mb": policy.get("mem_limit", 1024),
        "verifier_pack_required": False,
        "expect_verifier_pack_sha256": None,
        "blackbox": False,
        "blackbox_only": False,
        "require_report_integrity": policy.get("require_report_integrity"),
        "require_candidate_isolation": policy.get("require_candidate_isolation"),
        "min_diff_coverage": policy.get("min_diff_coverage"),
        "baseline_evidence": True,
        "require_demonstrated_fix": False,
        "policy_id": policy["policy_id"],
        "policy_version": policy["policy_version"],
    }


def guard_watchdog_seconds(policy: dict[str, Any], case: dict[str, Any]) -> int:
    """Bound every Guard command phase plus a ten-minute harness grace period."""
    timeout = policy.get("timeout")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
        raise ValueError("policy timeout must be a positive integer")
    phases_per_tree = 1 + int(bool(policy.get("setup_command")))
    tree_count = 2 if case.get("baseline_evidence") else 1
    return timeout * phases_per_tree * tree_count + 600


def _policy_problems(policy: dict[str, Any], effective: Any) -> list[str]:
    if not isinstance(effective, dict):
        return ["missing attestation.effective_policy"]
    mapping = expected_effective_policy(policy)
    problems: list[str] = []
    if set(effective) != set(mapping):
        problems.append(
            "effective policy field set mismatch: expected "
            f"{sorted(mapping)}, got {sorted(effective)}"
        )
    problems.extend(
        f"effective policy mismatch for {key}: expected {value!r}, got {effective.get(key)!r}"
        for key, value in mapping.items()
        if effective.get(key) != value
    )
    return problems


def record_binding_problems(
    record: dict[str, Any],
    case: dict[str, Any],
    policy: dict[str, Any],
    provenance: dict[str, Any],
    expected_candidate_digest: str,
    started_wall: float,
    finished_wall: float,
    process_returncode: int,
) -> list[str]:
    problems: list[str] = []
    if record.get("tool") != "evoguard":
        problems.append("unexpected tool identity")
    if record.get("tool_version") != ENGINE_VERSION.removeprefix("v"):
        problems.append("unexpected tool version")
    if record.get("schema_version") != SCHEMA_VERSION:
        problems.append("unexpected record schema")
    if record.get("exit_code") != process_returncode:
        problems.append("Guard process return code differs from the verdict record")
    if record.get("source") != "diff":
        problems.append("verdict record is not bound to diff mode")
    if record.get("base_reconstruction") != "ok":
        problems.append("verdict record has no successful base reconstruction")
    attestation = record.get("attestation")
    if not isinstance(attestation, dict):
        problems.append("missing attestation")
    else:
        source = case["source"]
        bindings = {
            "guard_version": ENGINE_VERSION.removeprefix("v"),
            "base_sha": source["base_commit"],
            "head_sha": source["head_commit"],
            "base_tree_sha": source["base_tree"],
            "head_tree_sha": source["head_tree"],
            "candidate_sha256": expected_candidate_digest,
        }
        for key, expected_value in bindings.items():
            if attestation.get(key) != expected_value:
                problems.append(f"attestation mismatch for {key}")
        problems.extend(_policy_problems(policy, attestation.get("effective_policy")))
        created = attestation.get("created_utc")
        try:
            created_wall = datetime.fromisoformat(str(created).replace("Z", "+00:00")).timestamp()
            if not (started_wall - 2 <= created_wall <= finished_wall + 2):
                problems.append("record timestamp is outside this invocation")
        except (TypeError, ValueError):
            problems.append("invalid attestation.created_utc")
    expected_paths = {entry["path"] for entry in provenance["changed_paths"]}
    files_changed = record.get("files_changed")
    if not isinstance(files_changed, list) or any(
        not isinstance(path, str) for path in files_changed
    ):
        problems.append("record files_changed is not a list of paths")
    else:
        if len(files_changed) != len(set(files_changed)):
            problems.append("record files_changed contains duplicate paths")
        if set(files_changed) != expected_paths:
            problems.append("record files_changed does not match the frozen upstream diff")
    return problems


def record_conformance_findings(
    record: dict[str, Any], case: dict[str, Any]
) -> list[str]:
    findings: list[str] = []
    expected = case["expected_guard"]
    if (record.get("verdict"), record.get("reason_code")) != (
        expected["verdict"],
        expected["reason_code"],
    ):
        findings.append(
            "outcome mismatch: expected "
            f"{expected['verdict']}/{expected['reason_code']}, got "
            f"{record.get('verdict')}/{record.get('reason_code')}"
        )
    if expected["verdict"] == "PASS":
        baseline = record.get("baseline")
        if not isinstance(baseline, dict) or baseline.get("verdict") != "PASS":
            findings.append("source-only case has no green reconstructed baseline")
        if record.get("test_command_ran") is not True:
            findings.append("source-only case did not run the declared suite")
    else:
        if record.get("test_command_ran") is not False:
            findings.append("protected policy trip unexpectedly ran the suite")
    return findings


def validate_record(
    engine: Path,
    record_path: Path,
    case: dict[str, Any],
    policy: dict[str, Any],
    provenance: dict[str, Any],
    expected_candidate_digest: str,
    started_wall: float,
    finished_wall: float,
    process_returncode: int,
) -> tuple[list[str], list[str]]:
    try:
        record = load_json(record_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [f"invalid verdict record: {type(exc).__name__}"], []
    integrity_problems = record_binding_problems(
        record,
        case,
        policy,
        provenance,
        expected_candidate_digest,
        started_wall,
        finished_wall,
        process_returncode,
    )
    try:
        verified = subprocess.run(
            [sys.executable, str(engine), "verify-record", str(record_path)],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        integrity_problems.append(f"verify-record could not complete: {type(exc).__name__}")
    else:
        if verified.returncode != 0:
            integrity_problems.append("verify-record rejected the verdict")
    return integrity_problems, record_conformance_findings(record, case)


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("case_id")
    parser.add_argument("--study", default=STUDY_ID)
    parser.add_argument("--engine", default=None)
    parser.add_argument("--work-root", required=True)
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args()
    _prepare_failure_output(args)

    manifest, manifest_problems = verify_manifest(args.study)
    if manifest_problems:
        raise SystemExit("invalid frozen manifest: " + "; ".join(manifest_problems))
    mapped = case_map()
    if args.case_id not in mapped:
        raise SystemExit(f"unknown frozen case: {args.case_id}")
    case_dir, case = mapped[args.case_id]
    provenance = load_json(case_dir / "provenance.json")
    candidate = case_dir / "candidate.diff"
    policy_path = resolve_study_file(case["policy"], "policies")
    environment_path = resolve_study_file(case["environment"], "environments")
    policy = load_json(policy_path)
    environment = load_json(environment_path)

    commit, tag_commit, dirty = _git_state()
    if dirty:
        raise SystemExit("refusing to execute from a dirty tracked checkout")
    github_sha = os.environ.get("GITHUB_SHA")
    if github_sha and github_sha != commit:
        raise SystemExit("GITHUB_SHA does not match the checked-out execution commit")
    if not _manifest_is_tagged():
        raise SystemExit("current manifest is not byte-identical to the protected protocol tag")
    if commit != tag_commit:
        raise SystemExit("execution must use the exact protected protocol tag commit")
    execution_problems = github_execution_problems(commit)
    if execution_problems:
        raise SystemExit("invalid canonical GitHub execution: " + "; ".join(execution_problems))

    output_dir = Path(args.output_root).resolve() / args.study / args.case_id
    if output_dir.exists() and any(output_dir.iterdir()):
        raise SystemExit(f"refusing to overwrite immutable case output: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    work_root = Path(args.work_root).resolve()
    case_work = work_root / args.study / args.case_id
    if case_work.exists():
        raise SystemExit(f"refusing to reuse case work directory: {case_work}")
    case_work.mkdir(parents=True)

    timing: dict[str, float] = {}
    total_started = time.perf_counter()
    source_started = time.perf_counter()
    cache = ensure_git_cache(case["source"]["url"], work_root / "source-cache")
    ensure_commit(cache, case["source"]["base_commit"])
    ensure_commit(cache, case["source"]["head_commit"])
    if tree_sha(cache, case["source"]["base_commit"]) != case["source"]["base_tree"]:
        raise SystemExit("upstream base tree no longer matches frozen provenance")
    if tree_sha(cache, case["source"]["head_commit"]) != case["source"]["head_tree"]:
        raise SystemExit("upstream head tree no longer matches frozen provenance")
    regenerated = canonical_diff(
        cache, case["source"]["base_commit"], case["source"]["head_commit"]
    )
    if sha256_bytes(regenerated) != case["candidate_sha256"] or regenerated != candidate.read_bytes():
        raise SystemExit("candidate does not reproduce byte-for-byte from upstream")
    actual_paths = changed_paths(
        cache, case["source"]["base_commit"], case["source"]["head_commit"]
    )
    if actual_paths != provenance["changed_paths"]:
        raise SystemExit("upstream changed-path inventory mismatch")
    timing["source_acquisition_and_verification_seconds"] = time.perf_counter() - source_started

    checkout_started = time.perf_counter()
    head = extract_git_tree(cache, case["source"]["head_commit"], case_work / "head")
    timing["head_checkout_seconds"] = time.perf_counter() - checkout_started
    expected_candidate_digest = candidate_digest(head, provenance["changed_paths"])
    if expected_candidate_digest != case["candidate_canonical_sha256"]:
        raise SystemExit("materialized candidate digest differs from the frozen case")
    engine = acquire_engine(args.engine, work_root)

    record_path = output_dir / "verdict.json"
    report_path = output_dir / "guard-report.md"
    argv = [
        sys.executable,
        str(engine),
        "guard",
        str(head),
        "--diff",
        str(candidate),
        "--config",
        str(policy_path),
        "--json",
        str(record_path),
        "--report",
        str(report_path),
        "--base-sha",
        case["source"]["base_commit"],
        "--head-sha",
        case["source"]["head_commit"],
        "--base-tree-sha",
        case["source"]["base_tree"],
        "--head-tree-sha",
        case["source"]["head_tree"],
    ]
    if case.get("baseline_evidence"):
        argv.append("--baseline-evidence")

    started_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    started_wall = time.time()
    guard_started = time.perf_counter()
    watchdog_seconds = guard_watchdog_seconds(policy, case)
    process = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name == "posix",
    )
    try:
        stdout, stderr = process.communicate(timeout=watchdog_seconds)
        completed = subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
        timeout_problem = None
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
        stdout, stderr = process.communicate()
        completed = subprocess.CompletedProcess(
            argv,
            124,
            stdout=stdout,
            stderr=stderr,
        )
        timeout_problem = "Guard exceeded the phase-aware watchdog plus harness grace"
    timing["guard_seconds"] = time.perf_counter() - guard_started
    finished_wall = time.time()
    finished_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    write_new(
        output_dir / "guard.stdout.txt", _completed_bytes(completed.stdout)
    )
    write_new(
        output_dir / "guard.stderr.txt", _completed_bytes(completed.stderr)
    )

    integrity_problems: list[str] = []
    conformance_findings: list[str] = []
    if timeout_problem:
        conformance_findings.append(timeout_problem)
    if record_path.is_file():
        record_integrity, record_findings = validate_record(
            engine,
            record_path,
            case,
            policy,
            provenance,
            expected_candidate_digest,
            started_wall,
            finished_wall,
            completed.returncode,
        )
        integrity_problems.extend(record_integrity)
        conformance_findings.extend(record_findings)
    else:
        conformance_findings.append("Guard produced no verdict record")
    if not report_path.is_file():
        conformance_findings.append("Guard produced no Markdown report")

    timing["total_seconds"] = time.perf_counter() - total_started
    write_new(output_dir / "timing.json", canonical_json_bytes(timing))
    pre_inventory = {path.name for path in output_dir.iterdir()}
    mandatory_failure_outputs = {"guard.stdout.txt", "guard.stderr.txt", "timing.json"}
    if not mandatory_failure_outputs.issubset(pre_inventory) or not pre_inventory.issubset(
        PRE_ENVELOPE_OUTPUT_NAMES
    ):
        integrity_problems.append(
            "unsafe pre-envelope output inventory: "
            f"{sorted(pre_inventory)}"
        )
    if not conformance_findings and pre_inventory != PRE_ENVELOPE_OUTPUT_NAMES:
        integrity_problems.append("conformant run has an incomplete output inventory")
    output_sha256 = {
        name: sha256_file(output_dir / name)
        for name in sorted(pre_inventory)
        if (output_dir / name).is_file()
    }
    envelope = {
        "run_envelope_schema": "evoom.oss-run-envelope/1",
        "study_id": args.study,
        "case_id": args.case_id,
        "claim_scope": manifest["claim_scope"],
        "manifest_sha256": sha256_file(manifest_path(args.study)),
        "manifest_git_commit": tag_commit,
        "execution_git_commit": commit,
        "protocol_tag": PROTOCOL_TAG,
        "protocol_tag_commit": tag_commit,
        "engine": {"release": ENGINE_VERSION, "sha256": sha256_file(engine)},
        "candidate_sha256": sha256_file(candidate),
        "candidate_canonical_sha256": expected_candidate_digest,
        "policy_sha256": sha256_file(policy_path),
        "environment_sha256": sha256_file(environment_path),
        "environment": environment,
        "source": case["source"],
        "runtime": runtime_inventory(),
        "runner": runner_identity(),
        "argv": ["<python>", "<digest-verified-evo-guard.pyz>", *argv[2:]],
        "started_utc": started_utc,
        "finished_utc": finished_utc,
        "guard_exit_code": completed.returncode,
        "guard_watchdog_seconds": watchdog_seconds,
        "watchdog_timed_out": timeout_problem is not None,
        "record_integrity_problems": integrity_problems,
        "conformance_findings": conformance_findings,
        "verify_and_expectation_problems": integrity_problems + conformance_findings,
        "artifact_valid": not integrity_problems,
        "success": not integrity_problems and not conformance_findings,
        "output_files_present": sorted(pre_inventory | {"run-envelope.json"}),
        "pre_envelope_output_sha256": output_sha256,
    }
    write_new(output_dir / "run-envelope.json", canonical_json_bytes(envelope))

    problems = integrity_problems + conformance_findings
    for problem in problems:
        print(f"PROBLEM: {problem}", file=sys.stderr)
    if not problems:
        print(
            f"OK  {args.case_id}  {case['expected_guard']['verdict']}/"
            f"{case['expected_guard']['reason_code']}"
        )
    return 1 if problems else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit as exc:
        if exc.code in {None, 0}:
            raise
        _preserve_harness_failure(exc)
        raise
    except Exception as exc:  # preserve every infrastructure failure as an artifact
        _preserve_harness_failure(exc)
        print(f"HARNESS FAILURE: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
