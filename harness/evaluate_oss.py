#!/usr/bin/env python3
"""Verify and summarize the same-owner OSS compatibility study."""
from __future__ import annotations

import argparse
import math
import os
import statistics
import stat
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from oss_common import (
    ENGINE_SHA256,
    ENGINE_VERSION,
    PROTOCOL_TAG,
    ROOT,
    STUDY_ID,
    canonical_json_bytes,
    case_map,
    load_json,
    manifest_path,
    resolve_study_file,
    sha256_bytes,
    sha256_file,
    verify_manifest,
    write_new,
)
from materialize_oss_artifacts import (
    RUN_INDEX_NAME,
    verify_local_materialization,
)
from run_oss_case import (
    EXPECTED_GITHUB_REF,
    EXPECTED_GITHUB_REPOSITORY,
    EXPECTED_GITHUB_WORKFLOW_REF,
    OUTPUT_NAMES,
    PRE_ENVELOPE_OUTPUT_NAMES,
    acquire_engine,
    guard_watchdog_seconds,
    record_binding_problems,
    record_conformance_findings,
)

MAX_EVIDENCE_FILE_BYTES = 100 * 1024 * 1024


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(fraction * len(ordered)) - 1)
    return ordered[index]


def _verify_record(engine: Path, path: Path) -> str | None:
    try:
        completed = subprocess.run(
            [sys.executable, str(engine), "verify-record", str(path)],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"verify-record could not complete: {type(exc).__name__}"
    if completed.returncode == 0:
        return None
    return "verify-record rejected the verdict"


def _utc_timestamp(value: Any) -> float:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()


def validated_timings(timing: dict[str, Any]) -> tuple[dict[str, float], list[str]]:
    expected_fields = {
        "source_acquisition_and_verification_seconds",
        "head_checkout_seconds",
        "guard_seconds",
        "total_seconds",
    }
    if set(timing) != expected_fields:
        return {}, ["timing field set mismatch"]
    values: dict[str, float] = {}
    try:
        for key in (
            "source_acquisition_and_verification_seconds",
            "head_checkout_seconds",
            "guard_seconds",
            "total_seconds",
        ):
            raw_value = timing[key]
            if isinstance(raw_value, bool):
                raise ValueError(key)
            value = float(raw_value)
            if not math.isfinite(value) or value < 0:
                raise ValueError(key)
            values[key] = value
    except (KeyError, TypeError, ValueError):
        return {}, ["missing or invalid timing values"]
    phase_total = sum(
        values[key]
        for key in (
            "source_acquisition_and_verification_seconds",
            "head_checkout_seconds",
            "guard_seconds",
        )
    )
    if values["total_seconds"] + 0.001 < phase_total:
        return values, ["total timing is shorter than measured phases"]
    return values, []


def validated_failure_timing(timing: dict[str, Any]) -> tuple[float | None, list[str]]:
    if set(timing) != {"harness_failed", "total_seconds"}:
        return None, ["early failure timing field set mismatch"]
    raw_total = timing.get("total_seconds")
    if timing.get("harness_failed") is not True or isinstance(raw_total, bool):
        return None, ["missing or invalid early failure timing"]
    try:
        total = float(raw_total)
    except (TypeError, ValueError):
        return None, ["missing or invalid early failure timing"]
    if not math.isfinite(total) or total < 0:
        return None, ["missing or invalid early failure timing"]
    return total, []


def runner_integrity_problems(
    runner: Any, manifest_commit: Any, github_run_id: str | None
) -> list[str]:
    if not isinstance(runner, dict):
        return ["run envelope has no runner identity"]
    expected_keys = {
        "canonical_dispatch_id",
        "github_actions",
        "github_event_name",
        "github_ref",
        "github_ref_name",
        "github_ref_protected",
        "github_ref_type",
        "github_repository",
        "github_run_attempt",
        "github_run_id",
        "github_sha",
        "github_workflow_ref",
        "image_os",
        "image_version",
        "os",
        "runner_arch",
        "runner_os",
    }
    problems: list[str] = []
    if set(runner) != expected_keys:
        problems.append("runner identity field set mismatch")
    expected = {
        "os": "posix",
        "runner_os": "Linux",
        "runner_arch": "X64",
        "github_actions": "true",
        "github_event_name": "workflow_dispatch",
        "github_repository": EXPECTED_GITHUB_REPOSITORY,
        "github_run_id": github_run_id,
        "github_run_attempt": "1",
        "github_sha": manifest_commit,
        "github_ref": EXPECTED_GITHUB_REF,
        "github_ref_name": PROTOCOL_TAG,
        "github_ref_type": "tag",
        "github_ref_protected": "true",
        "github_workflow_ref": EXPECTED_GITHUB_WORKFLOW_REF,
        "canonical_dispatch_id": github_run_id,
    }
    problems.extend(
        f"runner identity mismatch for {key}"
        for key, expected_value in expected.items()
        if runner.get(key) != expected_value
    )
    if not runner.get("image_os") or not runner.get("image_version"):
        problems.append("GitHub runner image metadata was not captured")
    return problems


def is_link_or_reparse_point(path: Path) -> bool:
    """Reject symlinks and Windows junction/reparse points in evidence paths."""
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


def is_contained(path: Path, root: Path) -> bool:
    try:
        return path.resolve(strict=True).is_relative_to(root.resolve(strict=True))
    except OSError:
        return False


def is_safe_regular_file(path: Path, root: Path) -> bool:
    if (
        is_link_or_reparse_point(path)
        or not is_contained(path, root)
        or not path.is_file()
    ):
        return False
    try:
        return path.stat().st_size <= MAX_EVIDENCE_FILE_BYTES
    except OSError:
        return False


def evaluate(
    results_root: Path,
    engine: Path,
    study_id: str = STUDY_ID,
    github_run_id: str | None = None,
) -> tuple[dict[str, Any], str, list[str]]:
    manifest, manifest_problems = verify_manifest(study_id)
    integrity_problems = list(manifest_problems)
    all_outcome_findings: list[str] = []
    mapped = case_map()
    study_results = results_root / study_id
    results_root_safe = (
        results_root.is_dir() and not is_link_or_reparse_point(results_root)
    )
    if results_root.is_dir() and not results_root_safe:
        integrity_problems.append("result root is a symlink or reparse point")
    study_results_safe = (
        results_root_safe
        and study_results.is_dir()
        and not is_link_or_reparse_point(study_results)
        and is_contained(study_results, results_root)
    )
    if not study_results.is_dir():
        integrity_problems.append(f"missing result root for study: {study_id}")
    elif not study_results_safe:
        integrity_problems.append("study result directory is not a contained regular directory")
    expected_case_ids = set(mapped)
    actual_case_ids: set[str] = set()
    allowed_root_files = {
        "SUMMARY.json",
        "RESULTS.md",
        "OUTPUTS.sha256",
        RUN_INDEX_NAME,
    }
    allowed_root_directories = {"archives"}
    if study_results_safe:
        for path in study_results.iterdir():
            if is_link_or_reparse_point(path) or not is_contained(path, study_results):
                integrity_problems.append(f"unsafe result-root entry: {path.name}")
                continue
            if path.name in expected_case_ids and path.is_dir():
                actual_case_ids.add(path.name)
            elif path.name in allowed_root_files and path.is_file():
                continue
            elif path.name in allowed_root_directories and path.is_dir():
                continue
            else:
                integrity_problems.append(f"unexpected result-root entry: {path.name}")
    for missing in sorted(expected_case_ids - actual_case_ids):
        integrity_problems.append(f"missing case output directory: {missing}")

    rows: list[dict[str, Any]] = []
    guard_times: list[float] = []
    total_times: list[float] = []
    repo_status: dict[str, list[bool]] = defaultdict(list)
    ecosystem_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    source_total = source_conformant = 0
    policy_total = policy_conformant = 0
    baseline_green = 0
    infrastructure_errors = 0
    case_runner_evidence_count = 0
    guard_invocation_count = 0
    verified_guard_record_count = 0
    pre_guard_infrastructure_error_count = 0

    if not github_run_id:
        integrity_problems.append("a canonical first-attempt GitHub run id is required")

    run_index: dict[str, Any] = {}
    run_index_path = study_results / RUN_INDEX_NAME
    if study_results_safe and is_safe_regular_file(run_index_path, study_results):
        try:
            run_index = load_json(run_index_path)
        except (OSError, ValueError):
            integrity_problems.append("missing or invalid RUN.json")
    else:
        integrity_problems.append("missing or unsafe RUN.json")
    if run_index:
        integrity_problems.extend(
            f"Actions artifact provenance: {problem}"
            for problem in verify_local_materialization(
                study_results, run_index, github_run_id
            )
        )

    manifest_file = manifest_path(study_id)
    manifest_sha256 = sha256_file(manifest_file) if manifest_file.is_file() else None

    for case_id, (case_dir, case) in sorted(mapped.items()):
        output = study_results / case_id
        local_integrity: list[str] = []
        outcome_findings: list[str] = []
        infrastructure_case = False
        category = case["category"]
        ecosystem_counts[case["ecosystem"]] += 1
        category_counts[category] += 1
        if category == "verbatim_upstream_source_only":
            source_total += 1
        else:
            policy_total += 1
        output_is_safe = (
            study_results_safe
            and output.is_dir()
            and not is_link_or_reparse_point(output)
            and is_contained(output, study_results)
        )
        if not output_is_safe:
            infrastructure_errors += 1
            local_integrity.append(
                "missing output directory"
                if not output.exists()
                else "case output is not a contained regular directory"
            )
            rows.append(
                {
                    "id": case_id,
                    "repository": case["repository"],
                    "ecosystem": case["ecosystem"],
                    "category": case["category"],
                    "expected": case["expected_guard"],
                    "observed": None,
                    "conformant": False,
                    "guard_seconds": None,
                    "total_seconds": None,
                    "artifact_integrity_valid": False,
                    "integrity_problems": local_integrity,
                    "outcome_findings": [],
                    "problems": local_integrity,
                }
            )
            repo_status[case["repository"]].append(False)
            continue

        entries = list(output.iterdir())
        inventory = {path.name for path in entries}
        for path in entries:
            if not is_safe_regular_file(path, output):
                local_integrity.append(f"non-regular output entry: {path.name}")
        mandatory_outputs = {
            "guard.stdout.txt",
            "guard.stderr.txt",
            "timing.json",
            "run-envelope.json",
        }
        if not mandatory_outputs.issubset(inventory) or not inventory.issubset(OUTPUT_NAMES):
            local_integrity.append(
                "output inventory outside the failure-safe contract: "
                f"{sorted(inventory)}"
            )

        envelope: dict[str, Any] = {}
        timing: dict[str, Any] = {}
        record: dict[str, Any] = {}
        envelope_path = output / "run-envelope.json"
        try:
            if not is_safe_regular_file(envelope_path, output):
                raise ValueError("unsafe envelope path")
            envelope = load_json(envelope_path)
        except (OSError, ValueError):
            local_integrity.append("missing or invalid run-envelope.json")
        timing_path = output / "timing.json"
        try:
            if not is_safe_regular_file(timing_path, output):
                raise ValueError("unsafe timing path")
            timing = load_json(timing_path)
        except (OSError, ValueError):
            local_integrity.append("missing or invalid timing.json")
        record_path = output / "verdict.json"
        if is_safe_regular_file(record_path, output):
            try:
                record = load_json(record_path)
            except (OSError, ValueError):
                local_integrity.append("invalid verdict.json")

        expected = case["expected_guard"]
        observed = None

        if envelope.get("run_envelope_schema") != "evoom.oss-run-envelope/1":
            local_integrity.append("run envelope schema mismatch")
        if envelope.get("claim_scope") != manifest.get("claim_scope"):
            local_integrity.append("run envelope claim scope mismatch")
        bindings = {
            "study_id": study_id,
            "case_id": case_id,
            "manifest_sha256": manifest_sha256,
            "candidate_sha256": sha256_file(case_dir / "candidate.diff"),
            "policy_sha256": sha256_file(resolve_study_file(case["policy"], "policies")),
            "environment_sha256": sha256_file(
                resolve_study_file(case["environment"], "environments")
            ),
            "candidate_canonical_sha256": case["candidate_canonical_sha256"],
        }
        for key, value in bindings.items():
            if envelope.get(key) != value:
                local_integrity.append(f"run envelope mismatch for {key}")
        engine_binding = envelope.get("engine", {})
        if engine_binding != {"release": ENGINE_VERSION, "sha256": ENGINE_SHA256}:
            local_integrity.append("run envelope engine binding mismatch")
        if envelope.get("source") != case["source"]:
            local_integrity.append("run envelope source binding mismatch")
        environment = load_json(resolve_study_file(case["environment"], "environments"))
        if envelope.get("environment") != environment:
            local_integrity.append("run envelope environment declaration mismatch")
        manifest_commit = envelope.get("manifest_git_commit")
        if envelope.get("protocol_tag") != PROTOCOL_TAG:
            local_integrity.append("run envelope protocol tag mismatch")
        if not isinstance(manifest_commit, str) or len(manifest_commit) != 40:
            local_integrity.append("run envelope has no full manifest Git commit")
        if envelope.get("protocol_tag_commit") != manifest_commit:
            local_integrity.append("protocol tag commit differs from manifest commit")
        if envelope.get("execution_git_commit") != manifest_commit:
            local_integrity.append("execution did not use the exact protocol commit")
        local_integrity.extend(
            runner_integrity_problems(envelope.get("runner"), manifest_commit, github_run_id)
        )
        harness_failure = envelope.get("harness_failure")
        if harness_failure is not None and not isinstance(harness_failure, dict):
            local_integrity.append("invalid harness_failure declaration")
        is_harness_failure = isinstance(harness_failure, dict)
        if record and not is_harness_failure:
            observed = {
                "verdict": record.get("verdict"),
                "reason_code": record.get("reason_code"),
            }

        runtime = envelope.get("runtime")
        if not isinstance(runtime, dict):
            local_integrity.append("runtime inventory is missing")
            runtime = {}
        os_release = runtime.get("os_release")
        if not isinstance(os_release, dict) or os_release.get("VERSION_ID") != "24.04":
            local_integrity.append("runtime is not the declared Ubuntu 24.04 environment")
        required_versions = {
            "python": ("python", "3.12.10"),
            "node": ("node", "24.14.1"),
            "go": ("go", "go1.23.12"),
            "rust": ("rustc", "1.85.0"),
        }
        ecosystem = case["ecosystem"]
        if not is_harness_failure and ecosystem in required_versions:
            tool, fragment = required_versions[ecosystem]
            if fragment not in str(runtime.get(tool) or ""):
                local_integrity.append(f"runtime version mismatch for {tool}")
        if not is_harness_failure and ecosystem in {"c", "cpp"}:
            for tool in ("cmake", "gcc", "g++", "make"):
                if not runtime.get(tool):
                    local_integrity.append(f"missing C/C++ runtime tool: {tool}")
        if envelope.get("output_files_present") != sorted(inventory):
            local_integrity.append("runner-declared output inventory mismatch")
        expected_output_hashes = {
            name: sha256_file(output / name)
            for name in sorted(PRE_ENVELOPE_OUTPUT_NAMES)
            if is_safe_regular_file(output / name, output)
        }
        if envelope.get("pre_envelope_output_sha256") != expected_output_hashes:
            local_integrity.append("raw output digest inventory mismatch")

        started_wall = finished_wall = None
        try:
            started_wall = _utc_timestamp(envelope["started_utc"])
            finished_wall = _utc_timestamp(envelope["finished_utc"])
            if finished_wall < started_wall:
                local_integrity.append("run envelope timestamps are reversed")
        except (KeyError, TypeError, ValueError):
            local_integrity.append("missing or invalid run envelope timestamps")

        process_returncode = envelope.get("guard_exit_code")
        recomputed_declared_integrity: list[str] = []
        if (
            record
            and not is_harness_failure
            and started_wall is not None
            and finished_wall is not None
            and isinstance(process_returncode, int)
            and not isinstance(process_returncode, bool)
        ):
            policy = load_json(resolve_study_file(case["policy"], "policies"))
            provenance = load_json(case_dir / "provenance.json")
            recomputed_declared_integrity.extend(
                record_binding_problems(
                    record, case, policy, provenance,
                    case["candidate_canonical_sha256"], started_wall,
                    finished_wall, process_returncode,
                )
            )
            verification_problem = _verify_record(engine, record_path)
            if verification_problem:
                recomputed_declared_integrity.append(verification_problem)

        pre_inventory = inventory - {"run-envelope.json"}
        mandatory_pre_outputs = {"guard.stdout.txt", "guard.stderr.txt", "timing.json"}
        if (
            not mandatory_pre_outputs.issubset(pre_inventory)
            or not pre_inventory.issubset(PRE_ENVELOPE_OUTPUT_NAMES)
        ):
            recomputed_declared_integrity.append(
                f"unsafe pre-envelope output inventory: {sorted(pre_inventory)}"
            )

        if is_harness_failure:
            if process_returncode is not None:
                local_integrity.append("harness failure envelope has a Guard return code")
            if timing.get("harness_failed") is True:
                total_seconds, timing_problems = validated_failure_timing(timing)
                guard_seconds = None
            else:
                timing_values, timing_problems = validated_timings(timing)
                total_seconds = (
                    timing_values.get("total_seconds") if timing_values else None
                )
                guard_seconds = (
                    timing_values.get("guard_seconds") if timing_values else None
                )
            outcome_findings.append("harness failed before a validated Guard result")
            infrastructure_case = True
            declared_integrity = envelope.get("record_integrity_problems")
            if declared_integrity != []:
                local_integrity.append("early failure envelope has invalid execution bindings")
        else:
            if not isinstance(process_returncode, int) or isinstance(process_returncode, bool):
                local_integrity.append("missing or invalid Guard process return code")
            expected_watchdog = guard_watchdog_seconds(
                load_json(resolve_study_file(case["policy"], "policies")), case
            )
            if envelope.get("guard_watchdog_seconds") != expected_watchdog:
                local_integrity.append("Guard watchdog binding mismatch")
            watchdog_timed_out = envelope.get("watchdog_timed_out")
            if not isinstance(watchdog_timed_out, bool):
                local_integrity.append("missing watchdog timeout declaration")
            elif watchdog_timed_out:
                outcome_findings.append(
                    "Guard exceeded the phase-aware watchdog plus harness grace"
                )
                infrastructure_case = True
            if record:
                outcome_findings.extend(record_conformance_findings(record, case))
            else:
                outcome_findings.append("Guard produced no verdict record")
                infrastructure_case = True
            if not is_safe_regular_file(output / "guard-report.md", output):
                outcome_findings.append("Guard produced no Markdown report")
            timing_values, timing_problems = validated_timings(timing)
            total_seconds = timing_values.get("total_seconds") if timing_values else None
            guard_seconds = timing_values.get("guard_seconds") if timing_values else None
            if not outcome_findings and pre_inventory != PRE_ENVELOPE_OUTPUT_NAMES:
                recomputed_declared_integrity.append(
                    "conformant run has an incomplete output inventory"
                )
            declared_integrity = envelope.get("record_integrity_problems")
            if declared_integrity != recomputed_declared_integrity:
                local_integrity.append("runner record-integrity declaration mismatch")
            if record.get("verdict") == "ERROR":
                infrastructure_case = True

        local_integrity.extend(timing_problems)
        local_integrity.extend(recomputed_declared_integrity)
        if envelope.get("conformance_findings") != outcome_findings:
            local_integrity.append("runner conformance declaration mismatch")
        declared_integrity = envelope.get("record_integrity_problems")
        if not isinstance(declared_integrity, list) or any(
            not isinstance(problem, str) for problem in declared_integrity
        ):
            local_integrity.append("invalid runner integrity-problem declaration")
            declared_integrity = []
        if envelope.get("verify_and_expectation_problems") != (
            declared_integrity + outcome_findings
        ):
            local_integrity.append("runner aggregate problem declaration mismatch")

        artifact_valid = not local_integrity
        if envelope.get("artifact_valid") is not artifact_valid:
            local_integrity.append("runner artifact-validity claim mismatch")
        expected_success = artifact_valid and not outcome_findings
        if envelope.get("success") is not expected_success:
            local_integrity.append("runner success claim mismatch")
        infrastructure_errors += int(infrastructure_case)

        # Coverage and outcome denominators are reported separately from the
        # fixed intention-to-test corpus.  A pre-Guard harness failure remains
        # a nonconformant case in the fixed denominator, but it is never
        # misrepresented as an observed Guard verdict.
        if not local_integrity:
            case_runner_evidence_count += 1
            if is_harness_failure:
                pre_guard_infrastructure_error_count += 1
            else:
                guard_invocation_count += 1
                if record:
                    verified_guard_record_count += 1

        conformant = not local_integrity and not outcome_findings
        if category == "verbatim_upstream_source_only":
            source_conformant += int(conformant)
            if (
                not local_integrity
                and not is_harness_failure
                and isinstance(record.get("baseline"), dict)
                and record["baseline"].get("verdict") == "PASS"
            ):
                baseline_green += 1
        else:
            policy_conformant += int(conformant)
        if not local_integrity and guard_seconds is not None and total_seconds is not None:
            guard_times.append(guard_seconds)
            total_times.append(total_seconds)
        repo_status[case["repository"]].append(conformant)
        integrity_problems.extend(
            f"{case_id}: {problem}" for problem in local_integrity
        )
        all_outcome_findings.extend(
            f"{case_id}: {finding}" for finding in outcome_findings
        )
        rows.append(
            {
                "id": case_id,
                "repository": case["repository"],
                "ecosystem": case["ecosystem"],
                "category": category,
                "expected": expected,
                "observed": observed,
                "conformant": conformant,
                "guard_seconds": guard_seconds,
                "total_seconds": total_seconds,
                "artifact_integrity_valid": not local_integrity,
                "integrity_problems": local_integrity,
                "outcome_findings": outcome_findings,
                "problems": local_integrity + outcome_findings,
            }
        )

    repository_compatible = sum(all(values) for values in repo_status.values())
    summary: dict[str, Any] = {
        "summary_schema": "evoom.oss-study-summary/4",
        "study_id": study_id,
        "claim_scope": manifest.get("claim_scope"),
        "study_design": {
            "evidence_kind": "repeated_engineering_case_conformance",
            "held_out": False,
            "prior_product_exposure": True,
            "unique_case_inventory": len(rows),
        },
        "engine": manifest.get("engine"),
        "execution": {
            "github_run_id": github_run_id,
            "github_run_url": (
                f"https://github.com/{EXPECTED_GITHUB_REPOSITORY}/actions/runs/"
                f"{github_run_id}"
                if github_run_id
                else None
            ),
            "required_attempt": 1,
            "protocol_tag": PROTOCOL_TAG,
            "first_api_visible_dispatch_enforced_by_actions_api": True,
            "owner_deleted_prior_runs_detectable": False,
        },
        "corpus_sha256": manifest.get("corpus_sha256"),
        "actions_artifact_provenance": {
            "archived_and_locally_verified": bool(run_index)
            and not any(
                problem.startswith("Actions artifact provenance:")
                for problem in integrity_problems
            ),
            "run_index_sha256": (
                sha256_file(run_index_path)
                if is_safe_regular_file(run_index_path, study_results)
                else None
            ),
            "artifact_count": (
                len(run_index.get("artifacts", []))
                if isinstance(run_index.get("artifacts"), list)
                else 0
            ),
        },
        "case_count": len(rows),
        "execution_coverage": {
            "fixed_case_denominator": len(rows),
            "case_runner_evidence_count": case_runner_evidence_count,
            "guard_invocation_count": guard_invocation_count,
            "verified_guard_record_count": verified_guard_record_count,
            "pre_guard_infrastructure_error_count": (
                pre_guard_infrastructure_error_count
            ),
            "product_outcome_denominator": verified_guard_record_count,
        },
        "conformance_denominator_kind": "fixed_repeated_engineering_case_inventory",
        "repository_count": len(repo_status),
        "repository_compatibility": {
            "conformant": repository_compatible,
            "total": len(repo_status),
        },
        "source_only_conformance": {"conformant": source_conformant, "total": source_total},
        "green_reconstructed_baselines": {"count": baseline_green, "total": source_total},
        "protected_policy_trip_detection": {
            "conformant": policy_conformant,
            "total": policy_total,
        },
        "infrastructure_errors": infrastructure_errors,
        "by_ecosystem": dict(sorted(ecosystem_counts.items())),
        "by_category": dict(sorted(category_counts.items())),
        "timing_seconds": {
            "valid_case_count": len(guard_times),
            "guard_median": statistics.median(guard_times) if guard_times else None,
            "guard_p95_nearest_rank": percentile(guard_times, 0.95),
            "total_median": statistics.median(total_times) if total_times else None,
            "total_p95_nearest_rank": percentile(total_times, 0.95),
        },
        "study_integrity_valid": not integrity_problems,
        "all_cases_conformant": all(row["conformant"] for row in rows),
        "integrity_problems": integrity_problems,
        "outcome_findings": all_outcome_findings,
        "cases": rows,
    }

    lines = [
        f"# OSS compatibility study — {study_id}",
        "",
        "> **Repeated same-owner engineering evidence only.** This corpus had prior",
        "> product-phase exposure; it is not held-out validation, an independent audit,",
        "> a population accuracy estimate, or evidence of generalization.",
        "",
        f"- Frozen engine: `{ENGINE_VERSION}` (`{ENGINE_SHA256}`)",
        f"- Repositories: {len(repo_status)}; cases: {len(rows)}",
        "- Guard invocation coverage: "
        f"{guard_invocation_count}/{len(rows)}; verified records: "
        f"{verified_guard_record_count}/{len(rows)}",
        "- Product-outcome denominator: "
        f"{verified_guard_record_count} verified Guard records; fixed conformance "
        f"denominator: {len(rows)} repeated engineering cases",
        f"- Source-only conformance: {source_conformant}/{source_total}",
        f"- Protected test/CI policy trips detected: {policy_conformant}/{policy_total}",
        f"- Green reconstructed baselines: {baseline_green}/{source_total}",
        f"- Infrastructure errors: {infrastructure_errors}",
        f"- Evidence integrity: {'valid' if not integrity_problems else 'invalid'}",
        "- Canonical ordering: first API-visible dispatch for the frozen commit",
        "- Owner-deleted prior runs detectable: no",
        "- Preserved Actions artifacts: "
        f"{len(run_index.get('artifacts', [])) if isinstance(run_index.get('artifacts'), list) else 0}/"
        f"{len(mapped)} locally API-digest-bound",
        "",
        "| Case | Repository | Expected | Observed | Result |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        expected = row["expected"]
        observed = row["observed"] or {}
        lines.append(
            f"| `{row['id']}` | {row['repository']} | "
            f"`{expected['verdict']}/{expected['reason_code']}` | "
            f"`{observed.get('verdict', 'MISSING')}/{observed.get('reason_code', 'MISSING')}` | "
            f"{'conformant' if row['conformant'] else 'problem'} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            "A PASS means the frozen repository suite and policy accepted that exact",
            "change in the captured environment. It does not prove the change or upstream",
            "project universally correct or secure. A protected-harness REJECTED result is",
            "a policy escalation, not an accusation that the upstream contributor cheated.",
            "These repeated cases had prior product-phase exposure and do not constitute",
            "a held-out sample or increase the unique sample size beyond 12.",
        ]
    )
    if integrity_problems:
        lines.extend(["", "## Evidence-integrity problems", ""])
        lines.extend(f"- {problem}" for problem in integrity_problems)
    if all_outcome_findings:
        lines.extend(["", "## Study outcome findings", ""])
        lines.extend(f"- {finding}" for finding in all_outcome_findings)
    return summary, "\n".join(lines) + "\n", integrity_problems


def output_checksums(
    study_results: Path, virtual_files: dict[str, bytes] | None = None
) -> str:
    if is_link_or_reparse_point(study_results):
        raise ValueError("refusing checksum traversal through a linked study root")
    paths: list[Path] = []
    for directory, dirnames, filenames in os.walk(study_results, followlinks=False):
        current = Path(directory)
        for name in dirnames:
            child = current / name
            if is_link_or_reparse_point(child) or not is_contained(child, study_results):
                raise ValueError(f"refusing checksum traversal through {child}")
        for name in filenames:
            path = current / name
            if not is_safe_regular_file(path, study_results):
                raise ValueError(f"refusing non-regular checksum input: {path}")
            if path.name != "OUTPUTS.sha256":
                paths.append(path)
    digests = {
        path.relative_to(study_results).as_posix(): sha256_file(path) for path in paths
    }
    for relative, data in (virtual_files or {}).items():
        if relative in digests or relative == "OUTPUTS.sha256" or "/" in relative:
            raise ValueError(f"invalid virtual checksum path: {relative}")
        digests[relative] = sha256_bytes(data)
    return "".join(
        f"{digest}  {relative}\n" for relative, digest in sorted(digests.items())
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--study", default=STUDY_ID)
    parser.add_argument("--results", required=True)
    parser.add_argument("--engine", default=None)
    parser.add_argument("--github-run-id", default=None)
    parser.add_argument(
        "--if-present",
        action="store_true",
        help="with --check, skip only when no study result directory exists yet",
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true")
    action.add_argument("--check", action="store_true")
    args = parser.parse_args()

    results_root = Path(args.results).absolute()
    study_results = results_root / args.study
    if args.if_present and args.check and not study_results.is_dir():
        print(f"SKIP  no published results yet for {args.study}")
        return 0
    github_run_id = args.github_run_id
    if args.write and not github_run_id:
        raise SystemExit(
            "--write requires --github-run-id from the canonical first API-visible dispatch"
        )
    if args.check and not github_run_id:
        summary_path = study_results / "SUMMARY.json"
        if (
            is_link_or_reparse_point(results_root)
            or is_link_or_reparse_point(study_results)
            or not is_contained(study_results, results_root)
        ):
            raise SystemExit("refusing linked or uncontained study result directory")
        if not is_safe_regular_file(summary_path, study_results):
            raise SystemExit(
                "--check requires a safe regular SUMMARY.json or --github-run-id"
            )
        try:
            published_summary = load_json(summary_path)
        except (OSError, ValueError) as exc:
            raise SystemExit("published SUMMARY.json is not valid JSON") from exc
        execution = published_summary.get("execution")
        if not isinstance(execution, dict):
            raise SystemExit("published SUMMARY.json has no execution object")
        github_run_id = str(execution.get("github_run_id") or "")
    if not github_run_id or not github_run_id.isdecimal():
        raise SystemExit("canonical GitHub run id must be a decimal integer")
    engine = acquire_engine(args.engine, ROOT / "work" / "oss-evaluate")
    summary, markdown, problems = evaluate(
        results_root, engine, args.study, github_run_id=github_run_id
    )
    summary_path = study_results / "SUMMARY.json"
    markdown_path = study_results / "RESULTS.md"
    checksums_path = study_results / "OUTPUTS.sha256"
    expected_summary = canonical_json_bytes(summary)
    expected_markdown = markdown.encode("utf-8")
    if args.write:
        for path in (summary_path, markdown_path, checksums_path):
            if path.exists():
                raise SystemExit(f"refusing to overwrite published study output: {path}")
        if not problems:
            try:
                expected_checksums = output_checksums(
                    study_results,
                    {
                        "RESULTS.md": expected_markdown,
                        "SUMMARY.json": expected_summary,
                    },
                ).encode("utf-8")
            except (OSError, ValueError) as exc:
                problems.append(f"cannot safely checksum study outputs: {exc}")
        if not problems:
            write_new(summary_path, expected_summary)
            write_new(markdown_path, expected_markdown)
            write_new(checksums_path, expected_checksums)
    else:
        comparisons = (
            (summary_path, expected_summary, "SUMMARY.json is not reproducible"),
            (markdown_path, expected_markdown, "RESULTS.md is not reproducible"),
        )
        for path, expected_bytes, message in comparisons:
            if not is_safe_regular_file(path, study_results):
                problems.append(f"unsafe or missing publication file: {path.name}")
            else:
                try:
                    if path.read_bytes() != expected_bytes:
                        problems.append(message)
                except OSError as exc:
                    problems.append(f"cannot read {path.name}: {exc}")
        if not is_safe_regular_file(checksums_path, study_results):
            problems.append("unsafe or missing publication file: OUTPUTS.sha256")
        else:
            try:
                expected_checksums_text = output_checksums(study_results)
                if checksums_path.read_text(encoding="utf-8") != expected_checksums_text:
                    problems.append("OUTPUTS.sha256 is not reproducible")
            except (OSError, UnicodeError, ValueError) as exc:
                problems.append(f"cannot safely verify OUTPUTS.sha256: {exc}")
    print(
        f"study={args.study} repositories={summary['repository_count']} "
        f"cases={summary['case_count']} problems={len(problems)}"
    )
    for problem in problems:
        print(f"PROBLEM: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
