"""Filesystem and verifier evidence boundary for protocol v0.3."""
from __future__ import annotations

import json
import hashlib
import math
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from common import (
    ROOT,
    load_json,
    sha256_file,
    verify_manifest_data,
)
from evaluation_contract import (
    EXCEPTION,
    MAIN,
    CorpusPlan,
    EvaluationIssue,
    ExpectedPair,
    RunKey,
    preflight_corpus,
    protocol_requires_timing,
)
from evaluation_scoring import (
    ConformanceSummary,
    EvidenceIntegrity,
    RunObservation,
    TerminalStatus,
)
from run_case import (
    acquire_base,
    acquire_engine,
    candidate_digest_for_engine,
    validate_record,
)

_SAFE_ROUND = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
RecordSpec = tuple[str, Path, ExpectedPair, list[str], str]


@dataclass(frozen=True)
class JsonObjectRead:
    value: dict[str, Any] | None
    issue: EvaluationIssue | None


@dataclass(frozen=True)
class RoundPlan:
    round_name: str
    protocol: str
    manifest_path: Path
    manifest: Mapping[str, Any]
    corpus: CorpusPlan
    case_dirs: Mapping[str, Path]


@dataclass(frozen=True)
class EvidenceResult:
    observations: Mapping[RunKey, RunObservation]
    issues: tuple[EvaluationIssue, ...]
    elapsed_seconds: tuple[float, ...]
    expected_timing_cases: frozenset[str]
    valid_timing_cases: frozenset[str]
    unexpected_outputs: int
    input_digests: tuple[tuple[str, str], ...]


def read_json_object(
    path: Path,
    *,
    phase: str,
    code: str,
    case_id: str | None = None,
) -> JsonObjectRead:
    """Parse one JSON object once and convert every parse failure to evidence."""

    try:
        value = load_json(path)
    except OSError as exc:
        issue = f"cannot read JSON: {exc}"
    except json.JSONDecodeError as exc:
        issue = (
            f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        )
    except UnicodeError as exc:
        issue = f"JSON is not valid UTF-8: {exc}"
    except ValueError as exc:
        issue = f"invalid JSON object: {exc}"
    else:
        return JsonObjectRead(value=value, issue=None)
    return JsonObjectRead(
        value=None,
        issue=EvaluationIssue(
            phase=phase,
            code=code,
            message=issue,
            case_id=case_id,
            artifact=path.name,
        ),
    )


def _is_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE
    )


def regular_file_issue(
    root: Path,
    path: Path,
    *,
    phase: str,
    code: str,
    case_id: str | None = None,
) -> EvaluationIssue | None:
    """Require a lexically contained, non-linked, regular file and path chain."""

    root = Path(os.path.abspath(root))
    path = Path(os.path.abspath(path))
    try:
        relative = path.relative_to(root)
    except ValueError:
        return EvaluationIssue(
            phase=phase,
            code=code,
            message=f"path escapes trusted root: {path}",
            case_id=case_id,
            artifact=path.name,
        )
    current = root
    chain = [root, *(root / Path(*relative.parts[:index]) for index in range(1, len(relative.parts) + 1))]
    for index, current in enumerate(chain):
        try:
            info = os.lstat(current)
        except OSError as exc:
            return EvaluationIssue(
                phase=phase,
                code=code,
                message=f"cannot inspect trusted path {current}: {exc}",
                case_id=case_id,
                artifact=path.name,
            )
        if _is_reparse(info):
            return EvaluationIssue(
                phase=phase,
                code=code,
                message=f"links and reparse points are forbidden: {current}",
                case_id=case_id,
                artifact=path.name,
            )
        is_leaf = index == len(chain) - 1
        if is_leaf and not stat.S_ISREG(info.st_mode):
            return EvaluationIssue(
                phase=phase,
                code=code,
                message=f"expected a regular file: {current}",
                case_id=case_id,
                artifact=path.name,
            )
        if not is_leaf and not stat.S_ISDIR(info.st_mode):
            return EvaluationIssue(
                phase=phase,
                code=code,
                message=f"non-directory in trusted path chain: {current}",
                case_id=case_id,
                artifact=path.name,
            )
    return None


def trusted_directory_issue(
    root: Path,
    directory: Path,
    *,
    phase: str,
    code: str,
    allow_missing: bool = False,
) -> EvaluationIssue | None:
    """Require a contained directory chain with no link or reparse parent."""

    root = Path(os.path.abspath(root))
    directory = Path(os.path.abspath(directory))
    try:
        relative = directory.relative_to(root)
    except ValueError:
        return EvaluationIssue(
            phase=phase,
            code=code,
            message=f"directory escapes trusted root: {directory}",
            artifact=directory.name,
        )
    chain = [
        root,
        *(
            root / Path(*relative.parts[:index])
            for index in range(1, len(relative.parts) + 1)
        ),
    ]
    missing_parent = False
    for current in chain:
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if allow_missing:
                missing_parent = True
                continue
            return EvaluationIssue(
                phase=phase,
                code=code,
                message=f"trusted directory is missing: {current}",
                artifact=directory.name,
            )
        except OSError as exc:
            return EvaluationIssue(
                phase=phase,
                code=code,
                message=f"cannot inspect trusted directory {current}: {exc}",
                artifact=directory.name,
            )
        if missing_parent:
            return EvaluationIssue(
                phase=phase,
                code=code,
                message=f"path exists below a missing parent: {current}",
                artifact=directory.name,
            )
        if _is_reparse(info) or not stat.S_ISDIR(info.st_mode):
            return EvaluationIssue(
                phase=phase,
                code=code,
                message=(
                    "trusted directory chain must contain only non-linked "
                    f"directories: {current}"
                ),
                artifact=directory.name,
            )
    return None


def _canonical_manifest_relative(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    parsed = PurePosixPath(value)
    if (
        "\\" in value
        or parsed.is_absolute()
        or parsed.as_posix() != value
        or len(parsed.parts) != 4
        or parsed.parts[0] != "cases"
        or any(part in {"", ".", ".."} for part in parsed.parts)
    ):
        return None
    return value


def _manifest_path(root: Path, round_name: str) -> Path:
    current = root / "manifests" / f"{round_name}.json"
    if current.exists() or current.is_symlink():
        return current
    return root / "MANIFEST.json"


def _manifest_input_issues(
    root: Path,
    manifest: Mapping[str, Any],
) -> list[EvaluationIssue]:
    issues: list[EvaluationIssue] = []
    entries = manifest.get("case_files")
    if not isinstance(entries, list):
        return issues
    for entry in entries:
        relative = (
            _canonical_manifest_relative(entry.get("path"))
            if isinstance(entry, Mapping)
            else None
        )
        if relative is None:
            continue
        issue = regular_file_issue(
            root,
            root / Path(*PurePosixPath(relative).parts),
            phase="corpus",
            code="unsafe_manifest_input",
        )
        if issue is not None:
            issues.append(issue)
    return issues


def _directory_inventory(
    directory: Path,
    *,
    phase: str,
    case_id: str,
) -> tuple[set[str], list[EvaluationIssue]]:
    names: set[str] = set()
    issues: list[EvaluationIssue] = []
    try:
        entries = list(os.scandir(directory))
    except OSError as exc:
        return names, [
            EvaluationIssue(
                phase=phase,
                code="case_inventory",
                message=f"cannot inspect case directory: {exc}",
                case_id=case_id,
            )
        ]
    for entry in entries:
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError as exc:
            issues.append(
                EvaluationIssue(
                    phase=phase,
                    code="case_inventory",
                    message=f"cannot inspect {entry.name}: {exc}",
                    case_id=case_id,
                )
            )
            continue
        names.add(entry.name)
        if _is_reparse(info):
            issues.append(
                EvaluationIssue(
                    phase=phase,
                    code="linked_case_entry",
                    message=f"case entries cannot be links/reparse points: {entry.name}",
                    case_id=case_id,
                    artifact=entry.name,
                )
            )
        elif not stat.S_ISREG(info.st_mode):
            issues.append(
                EvaluationIssue(
                    phase=phase,
                    code="nonregular_case_entry",
                    message=f"case entries must be regular files: {entry.name}",
                    case_id=case_id,
                    artifact=entry.name,
                )
            )
    return names, issues


def corpus_file_issues(
    plan: CorpusPlan,
    manifest: Mapping[str, Any],
    *,
    root: Path = ROOT,
) -> list[EvaluationIssue]:
    """Bind every planned case to one exact flat frozen case directory."""

    frozen_paths = {
        entry.get("path")
        for entry in manifest.get("case_files", [])
        if isinstance(entry, Mapping) and isinstance(entry.get("path"), str)
    }
    directories: dict[str, set[str]] = {}
    for value in frozen_paths:
        assert isinstance(value, str)
        directory, _, filename = value.rpartition("/")
        directories.setdefault(directory, set()).add(filename)
    issues: list[EvaluationIssue] = []
    metadata_directories = {
        directory for directory, files in directories.items() if "case.json" in files
    }
    planned_directories = {
        f"cases/{case.ecosystem}/{case.case_id}" for case in plan.cases
    }
    for directory, files in sorted(directories.items()):
        if "case.json" not in files:
            issues.append(
                EvaluationIssue(
                    phase="corpus",
                    code="orphan_case_files",
                    message=f"{directory} has no case.json ({', '.join(sorted(files))})",
                )
            )
    for directory in sorted(metadata_directories - planned_directories):
        issues.append(
            EvaluationIssue(
                phase="corpus",
                code="unplanned_case_directory",
                message=f"{directory} has no exact ecosystem/id plan match",
            )
        )
    for case in plan.cases:
        relative_dir = f"cases/{case.ecosystem}/{case.case_id}"
        candidate_name = "candidate.diff" if case.mode == "diff" else "candidate.txt"
        expected_names = {"case.json", candidate_name}
        frozen_names = directories.get(relative_dir, set())
        for name in sorted(expected_names - frozen_names):
            issues.append(
                EvaluationIssue(
                    phase="corpus",
                    code="case_file_membership",
                    message=f"manifest does not freeze {relative_dir}/{name}",
                    case_id=case.case_id,
                )
            )
        for name in sorted(frozen_names - expected_names):
            issues.append(
                EvaluationIssue(
                    phase="corpus",
                    code="unknown_case_file",
                    message=f"{relative_dir}/{name} is not in the closed case format",
                    case_id=case.case_id,
                )
            )
        disk_names, disk_issues = _directory_inventory(
            root / Path(*PurePosixPath(relative_dir).parts),
            phase="corpus",
            case_id=case.case_id,
        )
        issues.extend(disk_issues)
        for name in sorted(disk_names - expected_names):
            issues.append(
                EvaluationIssue(
                    phase="corpus",
                    code="unfrozen_case_file",
                    message=f"{relative_dir}/{name} is outside the frozen inventory",
                    case_id=case.case_id,
                )
            )
    if len(metadata_directories) != len(plan.cases):
        issues.append(
            EvaluationIssue(
                phase="corpus",
                code="corpus_cardinality_mismatch",
                message=(
                    f"manifest has {len(metadata_directories)} case directories; "
                    f"preflight has {len(plan.cases)}"
                ),
            )
        )
    return issues


def preflight_round(
    round_name: str,
    *,
    root: Path = ROOT,
) -> tuple[RoundPlan | None, tuple[EvaluationIssue, ...]]:
    """Create all denominators before engine acquisition or results inspection."""

    if _SAFE_ROUND.fullmatch(round_name) is None:
        return None, (
            EvaluationIssue(
                phase="corpus",
                code="invalid_round_name",
                message="round name must be one safe filename component",
            ),
        )
    manifest_path = _manifest_path(root, round_name)
    file_issue = regular_file_issue(
        root,
        manifest_path,
        phase="corpus",
        code="unsafe_manifest",
    )
    if file_issue is not None:
        return None, (file_issue,)
    read = read_json_object(
        manifest_path,
        phase="corpus",
        code="invalid_manifest_json",
    )
    if read.issue is not None or read.value is None:
        return None, (read.issue,) if read.issue is not None else ()
    manifest = read.value
    issues = _manifest_input_issues(root, manifest)
    if issues:
        return None, tuple(issues)

    _, manifest_problems = verify_manifest_data(
        round_name,
        manifest,
        root=root,
    )
    issues.extend(
        EvaluationIssue(
            phase="corpus",
            code="invalid_manifest",
            message=problem,
        )
        for problem in manifest_problems
    )
    if issues:
        return None, tuple(issues)

    # Derive directly instead of trusting a directory walk outside the manifest.
    case_directories = {}
    for entry in manifest.get("case_files", []):
        if not isinstance(entry, Mapping):
            continue
        relative = entry.get("path")
        if isinstance(relative, str) and relative.endswith("/case.json"):
            parts = PurePosixPath(relative).parts
            case_directories[parts[-2]] = root / Path(*parts[:-1])

    case_inputs: list[tuple[str, object]] = []
    for directory_id, case_dir in sorted(case_directories.items()):
        read = read_json_object(
            case_dir / "case.json",
            phase="corpus",
            code="invalid_case_json",
            case_id=directory_id,
        )
        if read.issue is not None:
            issues.append(read.issue)
        else:
            case_inputs.append((directory_id, read.value))
    plan, metadata_issues = preflight_corpus(case_inputs)
    issues.extend(metadata_issues)
    if plan is not None:
        issues.extend(corpus_file_issues(plan, manifest, root=root))
    if issues or plan is None:
        return None, tuple(issues)
    return (
        RoundPlan(
            round_name=round_name,
            protocol=str(manifest.get("protocol_version", "v0.1-legacy")),
            manifest_path=manifest_path,
            manifest=manifest,
            corpus=plan,
            case_dirs=case_directories,
        ),
        (),
    )


def expected_files(plan: CorpusPlan, protocol: str) -> set[str]:
    files: set[str] = set()
    for case in plan.cases:
        files.add(f"{case.case_id}.json")
        if case.exception_expected is not None:
            files.add(f"{case.case_id}-exception.json")
        if protocol_requires_timing(protocol):
            files.add(f"{case.case_id}.timing.json")
    return files


def inventory_problems(expected: set[str], actual: set[str]) -> list[str]:
    return [
        *(f"missing round output: {name}" for name in sorted(expected - actual)),
        *(
            f"unexpected/stale round output: {name}"
            for name in sorted(actual - expected)
        ),
    ]


def _results_inventory(
    directory: Path,
    *,
    trusted_root: Path | None = None,
) -> tuple[set[str], list[EvaluationIssue]]:
    actual: set[str] = set()
    issues: list[EvaluationIssue] = []
    directory_problem = trusted_directory_issue(
        directory if trusted_root is None else trusted_root,
        directory,
        phase="evidence",
        code="unsafe_results_directory",
    )
    if directory_problem is not None:
        return actual, [
            directory_problem
        ]
    try:
        entries = list(os.scandir(directory))
    except OSError as exc:
        return actual, [
            EvaluationIssue(
                phase="evidence",
                code="results_inventory",
                message=f"cannot inspect results directory: {exc}",
            )
        ]
    for entry in entries:
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError as exc:
            issues.append(
                EvaluationIssue(
                    phase="evidence",
                    code="results_inventory",
                    message=f"cannot inspect output {entry.name}: {exc}",
                    artifact=entry.name,
                )
            )
            continue
        if _is_reparse(info):
            issues.append(
                EvaluationIssue(
                    phase="evidence",
                    code="linked_output",
                    message="result links/reparse points are forbidden",
                    artifact=entry.name,
                )
            )
            continue
        if not stat.S_ISREG(info.st_mode):
            issues.append(
                EvaluationIssue(
                    phase="evidence",
                    code="nonregular_output",
                    message="result directories and special files are forbidden",
                    artifact=entry.name,
                )
            )
            continue
        if entry.name.endswith(".json"):
            actual.add(entry.name)
        elif entry.name != "RESULTS.md":
            issues.append(
                EvaluationIssue(
                    phase="evidence",
                    code="unexpected_result_entry",
                    message="only JSON evidence and RESULTS.md are allowed",
                    artifact=entry.name,
                )
            )
    return actual, issues


def validate_timing(
    case_id: str,
    value: object,
    *,
    expects_exception: bool,
) -> tuple[tuple[float, ...], tuple[EvaluationIssue, ...]]:
    issues: list[EvaluationIssue] = []
    if not isinstance(value, Mapping):
        return (), (
            EvaluationIssue(
                phase="evidence",
                code="invalid_timing_object",
                message="timing sidecar must be a JSON object",
                case_id=case_id,
            ),
        )
    required = {"default_seconds"}
    if expects_exception:
        required.add("exception_seconds")
    for key in sorted(required - set(value)):
        issues.append(
            EvaluationIssue(
                phase="evidence",
                code="missing_timing",
                message=f"timing field {key} is required",
                case_id=case_id,
            )
        )
    for key in sorted(set(value) - required):
        issues.append(
            EvaluationIssue(
                phase="evidence",
                code="unexpected_timing",
                message=f"unexpected timing field {key}",
                case_id=case_id,
            )
        )
    elapsed: list[float] = []
    for key in sorted(required & set(value)):
        raw = value[key]
        numeric: float | None = None
        if not isinstance(raw, bool) and isinstance(raw, (int, float)):
            try:
                numeric = float(raw)
            except (OverflowError, ValueError):
                numeric = None
        if numeric is None or not math.isfinite(numeric) or numeric < 0:
            issues.append(
                EvaluationIssue(
                    phase="evidence",
                    code="invalid_timing",
                    message=f"{key} must be a finite non-negative number",
                    case_id=case_id,
                )
            )
        else:
            elapsed.append(numeric)
    return (() if issues else tuple(elapsed)), tuple(issues)


def _candidate(case_dir: Path, case: Mapping[str, Any]) -> Path:
    return case_dir / (
        "candidate.diff" if case.get("mode", "patch") == "diff" else "candidate.txt"
    )


def _record_specs(
    case: Any,
    results_dir: Path,
) -> list[RecordSpec]:
    specs: list[RecordSpec] = [
        (
            MAIN,
            results_dir / f"{case.case_id}.json",
            case.main_expected,
            [],
            case.case_id,
        )
    ]
    if case.exception_expected is not None:
        specs.append(
            (
                EXCEPTION,
                results_dir / f"{case.case_id}-exception.json",
                case.exception_expected,
                list(case.metadata["exception"]["args"]),
                f"{case.case_id} (exception)",
            )
        )
    return specs


def collect_evidence(
    round_plan: RoundPlan,
    *,
    engine_arg: str | None = None,
    root: Path = ROOT,
) -> EvidenceResult:
    """Collect evidence only after corpus preflight fixed every denominator."""

    plan = round_plan.corpus
    results_dir = root / "results" / round_plan.round_name
    expected = expected_files(plan, round_plan.protocol)
    actual, issues = _results_inventory(results_dir, trusted_root=root)
    missing = expected - actual
    unexpected = actual - expected
    for problem in inventory_problems(expected, actual):
        issues.append(
            EvaluationIssue(
                phase="evidence",
                code="missing_output" if problem.startswith("missing") else "unexpected_output",
                message=problem,
            )
        )

    engine: str | None = None
    try:
        engine = acquire_engine(engine_arg, root / "work")
        engine_path = Path(engine)
        engine_issue = regular_file_issue(
            engine_path.parent,
            engine_path,
            phase="evidence",
            code="engine_integrity",
        )
        if engine_issue is not None:
            issues.append(engine_issue)
            engine = None
    except (Exception, SystemExit) as exc:
        issues.append(
            EvaluationIssue(
                phase="evidence",
                code="engine_integrity",
                message=f"cannot acquire digest-pinned engine: {exc}",
            )
        )

    observations: dict[RunKey, RunObservation] = {}
    elapsed: list[float] = []
    expected_timing_cases: set[str] = set()
    valid_timing_cases: set[str] = set()

    for case in plan.cases:
        case_dir = round_plan.case_dirs[case.case_id]
        candidate = _candidate(case_dir, case.metadata)
        parsed: dict[str, tuple[Path, dict[str, Any]]] = {}
        specs: list[RecordSpec] = _record_specs(case, results_dir)
        for run_name, record_path, _, _, _ in specs:
            key = (case.case_id, run_name)
            if record_path.name in missing:
                observations[key] = RunObservation(False, None, False)
                continue
            read = read_json_object(
                record_path,
                phase="evidence",
                code="invalid_record_json",
                case_id=case.case_id,
            )
            if read.issue is not None or read.value is None:
                if read.issue is not None:
                    issues.append(read.issue)
                observations[key] = RunObservation(True, None, False)
                continue
            pair = (read.value.get("verdict"), read.value.get("reason_code"))
            observations[key] = RunObservation(True, pair, False)
            parsed[run_name] = (record_path, read.value)

        candidate_digest: str | None = None
        if parsed and engine is not None:
            try:
                if case.mode == "diff":
                    head = acquire_base(case.metadata["source"], root / "work")
                    candidate_digest = candidate_digest_for_engine(candidate, case.mode, head)
                else:
                    candidate_digest = candidate_digest_for_engine(candidate, case.mode)
            except (Exception, SystemExit) as exc:
                issues.append(
                    EvaluationIssue(
                        phase="evidence",
                        code="candidate_integrity",
                        message=f"cannot bind frozen candidate: {exc}",
                        case_id=case.case_id,
                        artifact=candidate.name,
                    )
                )
        if candidate_digest is not None and engine is not None:
            for run_name, record_path, expected_pair, extra, label in specs:
                parsed_record = parsed.get(run_name)
                if parsed_record is None:
                    continue
                _, record = parsed_record
                try:
                    problems = validate_record(
                        engine,
                        record_path,
                        {
                            "verdict": expected_pair.verdict,
                            "reason_code": expected_pair.reason_code,
                        },
                        label,
                        candidate=candidate,
                        policy=case.metadata["policy"],
                        extra=extra,
                        candidate_digest=candidate_digest,
                        record=record,
                        check_expectation=False,
                    )
                except Exception as exc:
                    problems = [f"{label}: record validation failed: {exc}"]
                if problems:
                    issues.extend(
                        EvaluationIssue(
                            phase="evidence",
                            code="record_integrity",
                            message=problem,
                            case_id=case.case_id,
                            artifact=record_path.name,
                        )
                        for problem in problems
                    )
                else:
                    observations[(case.case_id, run_name)] = RunObservation(
                        True,
                        (record.get("verdict"), record.get("reason_code")),
                        True,
                    )

        if protocol_requires_timing(round_plan.protocol):
            expected_timing_cases.add(case.case_id)
            timing_path = results_dir / f"{case.case_id}.timing.json"
            if timing_path.name in missing:
                continue
            read = read_json_object(
                timing_path,
                phase="evidence",
                code="invalid_timing_json",
                case_id=case.case_id,
            )
            if read.issue is not None or read.value is None:
                if read.issue is not None:
                    issues.append(read.issue)
                continue
            values, timing_issues = validate_timing(
                case.case_id,
                read.value,
                expects_exception=case.exception_expected is not None,
            )
            issues.extend(timing_issues)
            if not timing_issues:
                valid_timing_cases.add(case.case_id)
                elapsed.extend(values)

    digest_inputs: list[tuple[str, str]] = [
        (
            round_plan.manifest_path.relative_to(root).as_posix(),
            sha256_file(round_plan.manifest_path),
        )
    ]
    for entry in round_plan.manifest.get("case_files", []):
        if isinstance(entry, Mapping):
            relative = entry.get("path")
            digest = entry.get("sha256")
            if isinstance(relative, str) and isinstance(digest, str):
                digest_inputs.append((relative, digest))
    for name in sorted(expected & actual):
        path = results_dir / name
        if regular_file_issue(
            results_dir,
            path,
            phase="evidence",
            code="unsafe_result_input",
        ) is None:
            digest_inputs.append(
                (path.relative_to(root).as_posix(), sha256_file(path))
            )

    return EvidenceResult(
        observations=observations,
        issues=tuple(issues),
        elapsed_seconds=tuple(elapsed),
        expected_timing_cases=frozenset(expected_timing_cases),
        valid_timing_cases=frozenset(valid_timing_cases),
        unexpected_outputs=len(unexpected),
        input_digests=tuple(sorted(digest_inputs)),
    )


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def reanalysis_payloads(
    round_plan: RoundPlan,
    evidence: EvidenceResult,
    summary: ConformanceSummary,
    integrity: EvidenceIntegrity,
) -> Mapping[str, bytes]:
    """Build the exact deterministic v0.3 reanalysis publication."""

    rows: list[dict[str, Any]] = []
    for row in summary.rows:
        runs = [row.main, *([row.exception] if row.exception is not None else [])]
        rows.append(
            {
                "case_id": row.case_id,
                "ecosystem": row.ecosystem,
                "change_class": row.change_class,
                "label": row.label,
                "case_exact": row.case_exact,
                "case_evidence_valid": row.case_evidence_valid,
                "case_admissible": row.case_admissible,
                "runs": [
                    {
                        "run": run.key[1],
                        "expected": {
                            "verdict": run.expected[0],
                            "reason_code": run.expected[1],
                        },
                        "observed": (
                            {
                                "verdict": run.observed[0],
                                "reason_code": run.observed[1],
                            }
                            if run.observed is not None
                            else None
                        ),
                        "conformance_status": run.conformance_status.value,
                        "terminal_status": run.terminal_status.value,
                        "exact_pair": run.exact_pair,
                        "evidence_valid": run.evidence_valid,
                        "admissible": run.admissible,
                    }
                    for run in runs
                ],
            }
        )
    status_counts = {
        status.value: sum(
            run.terminal_status is status for run in summary.runs
        )
        for status in TerminalStatus
    }
    payload = {
        "schema": "evoom-evaluation-reanalysis/v0.3",
        "source_round": round_plan.round_name,
        "source_protocol": round_plan.protocol,
        "reanalysis_protocol": "v0.3",
        "historical_inputs_immutable": True,
        "same_owner_evaluation": True,
        "independent_validation": False,
        "engine": round_plan.manifest.get("engine"),
        "schema_version": round_plan.manifest.get("schema_version"),
        "corpus_sha256": round_plan.manifest.get("corpus_sha256"),
        "denominators": {
            "cases": summary.expected_cases,
            "records": summary.expected_records,
            "timing_sidecars": integrity.expected_timings,
        },
        "exact_pair": {
            "records": summary.exact_records,
            "cases": summary.exact_cases,
        },
        "evidence_integrity": {
            "records": integrity.valid_records,
            "timing_sidecars": integrity.valid_timings,
            "unexpected_outputs": integrity.unexpected_outputs,
            "complete": integrity.complete,
        },
        "admissible": {
            "records": summary.admissible_records,
            "cases": summary.admissible_cases,
        },
        "terminal_status_counts": status_counts,
        "axes": dict(sorted(summary.axes.items())),
        "by_ecosystem": {
            key: {"exact_cases": value[0], "cases": value[1]}
            for key, value in summary.by_ecosystem.items()
        },
        "by_change_class": {
            key: {"exact_cases": value[0], "cases": value[1]}
            for key, value in summary.by_change_class.items()
        },
        "rows": rows,
    }
    input_lines = [
        *(
            f"{digest}  {relative}"
            for relative, digest in evidence.input_digests
        ),
        (
            f"{round_plan.manifest['engine']['evo_guard_pyz_sha256']}  "
            f"engine/evo-guard.pyz@{round_plan.manifest['engine']['release']}"
        ),
    ]
    inputs = ("\n".join(sorted(input_lines)) + "\n").encode("utf-8")
    summary_bytes = _json_bytes(payload)
    results_lines = [
        f"# Protocol v0.3 reanalysis — `{round_plan.round_name}`",
        "",
        (
            "This is a deterministic same-owner reanalysis of immutable historical "
            "inputs. It is not independent validation and it does not rewrite a tag, "
            "manifest, raw record, or historical result."
        ),
        "",
        "## Three independent axes",
        "",
        "| Axis | Result | Fixed denominator |",
        "|---|---:|---:|",
        (
            f"| Exact `(verdict, reason_code)` pairs | "
            f"{summary.exact_records} | {summary.expected_records} |"
        ),
        (
            f"| Evidence-valid records | {integrity.valid_records} | "
            f"{integrity.expected_records} |"
        ),
        (
            f"| Admissible records (exact + valid evidence) | "
            f"{summary.admissible_records} | {summary.expected_records} |"
        ),
        (
            f"| Exact cases | {summary.exact_cases} | "
            f"{summary.expected_cases} |"
        ),
        (
            f"| Admissible cases | {summary.admissible_cases} | "
            f"{summary.expected_cases} |"
        ),
        "",
        "## Terminal classification",
        "",
        "| Status | Runs |",
        "|---|---:|",
        *(
            f"| `{status}` | {count} |"
            for status, count in status_counts.items()
        ),
        "",
        "## Corrected interpretation",
        "",
        (
            "The earlier evaluator implementation corrupted the method used to "
            "derive published metrics: mismatched reasons could enter a numerator, "
            "missing outputs could shrink a denominator, and some malformed evidence "
            "did not fail closed. Those computation paths are therefore not accepted "
            "as protocol-v0.3 evidence."
        ),
        "",
        (
            "Recomputing from the unchanged bytes gives the exact, evidence-valid, "
            "and admissible counts above. This does not turn the author-selected "
            "10-case pilot into a field-rate estimate, blind evaluation, or "
            "third-party audit."
        ),
        "",
    ]
    results = "\n".join(results_lines).encode("utf-8")
    partial: dict[str, bytes] = {
        "INPUTS.sha256": inputs,
        "SUMMARY.json": summary_bytes,
        "RESULTS.md": results,
    }
    output_lines = [
        f"{_sha256_bytes(value)}  {name}" for name, value in sorted(partial.items())
    ]
    return {
        **partial,
        "OUTPUTS.sha256": ("\n".join(output_lines) + "\n").encode("utf-8"),
    }


def write_reanalysis(
    directory: Path,
    payloads: Mapping[str, bytes],
    *,
    trusted_root: Path,
) -> tuple[EvaluationIssue, ...]:
    """Create a reanalysis once; never overwrite a publication."""

    directory_problem = trusted_directory_issue(
        trusted_root,
        directory,
        phase="publication",
        code="unsafe_reanalysis_directory",
        allow_missing=True,
    )
    if directory_problem is not None:
        return (directory_problem,)
    expected = frozenset(payloads)
    if directory.exists():
        try:
            existing = frozenset(path.name for path in directory.iterdir())
        except OSError as exc:
            existing = frozenset()
            detail = str(exc)
        else:
            detail = ", ".join(sorted(existing))
        if existing:
            return (
                EvaluationIssue(
                    phase="publication",
                    code="refuse_overwrite",
                    message=f"reanalysis directory is not empty: {detail}",
                ),
            )
    directory.mkdir(parents=True, exist_ok=True)
    if expected != frozenset(
        {"INPUTS.sha256", "SUMMARY.json", "RESULTS.md", "OUTPUTS.sha256"}
    ):
        return (
            EvaluationIssue(
                phase="publication",
                code="invalid_publication_inventory",
                message="reanalysis payload does not have the exact four-file inventory",
            ),
        )
    for name, value in payloads.items():
        fd, temporary = tempfile.mkstemp(prefix=f".{name}.", dir=directory)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, directory / name)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return ()


def check_reanalysis(
    directory: Path,
    payloads: Mapping[str, bytes],
    *,
    trusted_root: Path,
) -> tuple[EvaluationIssue, ...]:
    """Check exact inventory, path type, and bytes of a frozen reanalysis."""

    directory_problem = trusted_directory_issue(
        trusted_root,
        directory,
        phase="publication",
        code="unsafe_reanalysis_directory",
    )
    if directory_problem is not None:
        return (directory_problem,)
    issues: list[EvaluationIssue] = []
    try:
        entries = list(os.scandir(directory))
    except OSError as exc:
        return (
            EvaluationIssue(
                phase="publication",
                code="missing_reanalysis",
                message=f"cannot inspect reanalysis directory: {exc}",
            ),
        )
    names = {entry.name for entry in entries}
    expected = set(payloads)
    for name in sorted(expected - names):
        issues.append(
            EvaluationIssue(
                phase="publication",
                code="missing_reanalysis_output",
                message=f"missing reanalysis output: {name}",
            )
        )
    for name in sorted(names - expected):
        issues.append(
            EvaluationIssue(
                phase="publication",
                code="unexpected_reanalysis_output",
                message=f"unexpected reanalysis output: {name}",
            )
        )
    for entry in entries:
        if entry.name not in payloads:
            continue
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError as exc:
            issues.append(
                EvaluationIssue(
                    phase="publication",
                    code="reanalysis_output_integrity",
                    message=f"cannot inspect {entry.name}: {exc}",
                )
            )
            continue
        if _is_reparse(info) or not stat.S_ISREG(info.st_mode):
            issues.append(
                EvaluationIssue(
                    phase="publication",
                    code="reanalysis_output_integrity",
                    message=f"{entry.name} must be a non-linked regular file",
                )
            )
            continue
        try:
            actual = Path(entry.path).read_bytes()
        except OSError as exc:
            issues.append(
                EvaluationIssue(
                    phase="publication",
                    code="reanalysis_output_integrity",
                    message=f"cannot read {entry.name}: {exc}",
                )
            )
        else:
            if actual != payloads[entry.name]:
                issues.append(
                    EvaluationIssue(
                        phase="publication",
                        code="reanalysis_output_mismatch",
                        message=f"reanalysis output differs: {entry.name}",
                    )
                )
    return tuple(issues)
