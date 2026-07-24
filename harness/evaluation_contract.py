"""Pure closed-world corpus contract for evaluation protocol v0.3.

This module deliberately performs no filesystem, network, subprocess, or
printing work. It validates every manifest-selected metadata object before
returning the immutable denominator plan consumed by evidence and scoring.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

RunKey = tuple[str, str]

MAIN = "main"
EXCEPTION = "exception"

LABELS = frozenset(
    {
        "accept",
        "reject",
        "requires_review",
        "requires_policy_exception",
        "unsupported",
    }
)
LABELS_REQUIRING_EXCEPTION = frozenset({"requires_policy_exception"})
TIMED_PROTOCOLS = frozenset({"v0.2", "v0.3"})

_TOP_LEVEL_KEYS = frozenset(
    {
        "id",
        "ecosystem",
        "change_class",
        "truth",
        "label",
        "source",
        "upstream",
        "license",
        "mode",
        "policy",
        "guard_expectation",
        "exception",
    }
)
_TOP_LEVEL_REQUIRED = _TOP_LEVEL_KEYS - {"mode", "exception"}
_TRUTH_KEYS = frozenset(
    {
        "human_decision",
        "policy_expectation",
        "rationale",
        "labeled_by",
        "labeled_before_guard_run",
    }
)
_EXPECTATION_KEYS = frozenset({"verdict", "reason_code"})
_POLICY_KEYS = frozenset({"test_command", "timeout"})
_EXCEPTION_KEYS = frozenset({"args", "guard_expectation"})
_SOURCE_KEYS = {
    "git": frozenset({"type", "url", "commit"}),
    "pypi-sdist": frozenset({"type", "package", "version", "sha256"}),
}
# Public reason/verdict relationships from the repository-pinned record schema
# 1.11.  Preflight validates expectations without importing or executing Guard.
_SCHEMA_REASON_VERDICTS: dict[str, frozenset[str]] = {
    "tests_passed": frozenset({"PASS"}),
    "protected_harness_edit": frozenset({"REJECTED"}),
    "tests_failed": frozenset({"FAIL"}),
    "no_parseable_edits": frozenset({"ERROR"}),
    "unsafe_path": frozenset({"ERROR"}),
    "patch_apply_failed": frozenset({"ERROR"}),
    "no_test_verdict": frozenset({"ERROR", "FAIL"}),
    "junit_exit_mismatch": frozenset({"TAMPERED"}),
    "empty_diff": frozenset({"ERROR"}),
    "binary_patch": frozenset({"ERROR"}),
    "reverse_apply_failed": frozenset({"ERROR"}),
    "no_verifiable_changes": frozenset({"ERROR"}),
    "diff_coverage_below_threshold": frozenset({"FAIL"}),
    "test_timeout": frozenset({"FAIL", "ERROR"}),
    "setup_timeout": frozenset({"ERROR"}),
    "setup_failed": frozenset({"ERROR"}),
    "assurance_requirement_not_met": frozenset({"ERROR"}),
    "fix_not_demonstrated": frozenset({"FAIL"}),
    "policy_requirement_unsupported": frozenset({"ERROR"}),
    "verifier_pack_identity_mismatch": frozenset({"ERROR"}),
    "verifier_pack_invalid": frozenset({"ERROR"}),
    "verifier_pack_required": frozenset({"ERROR"}),
    "verifier_pack_not_found": frozenset({"ERROR"}),
    "verifier_pack_snapshot_changed": frozenset({"TAMPERED"}),
    "candidate_not_exercised": frozenset({"ERROR"}),
    "candidate_tree_changed_during_run": frozenset({"TAMPERED"}),
    "test_command_unavailable": frozenset({"ERROR"}),
    "runtime_cleanup_failed": frozenset({"ERROR"}),
}
_TRUTH_LABELS: dict[tuple[str, str], frozenset[str]] = {
    ("admit", "no_exception_required"): frozenset({"accept"}),
    ("admit", "documented_exception_required"): frozenset(
        {"requires_policy_exception"}
    ),
    ("escalate", "documented_exception_required"): frozenset(
        {"requires_review", "requires_policy_exception"}
    ),
    ("block", "no_exception_required"): frozenset({"reject"}),
    ("block", "documented_exception_required"): frozenset({"reject"}),
    ("escalate", "unsupported"): frozenset({"unsupported"}),
}
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_HEX_40 = re.compile(r"[0-9a-fA-F]{40}\Z")
_HEX_64 = re.compile(r"[0-9a-fA-F]{64}\Z")


@dataclass(frozen=True)
class EvaluationIssue:
    """One machine-classifiable evaluator problem."""

    phase: str
    code: str
    message: str
    case_id: str | None = None
    artifact: str | None = None

    def render(self) -> str:
        locations = [
            value
            for value in (
                f"case={self.case_id}" if self.case_id else None,
                f"artifact={self.artifact}" if self.artifact else None,
            )
            if value is not None
        ]
        where = f" ({', '.join(locations)})" if locations else ""
        return f"[{self.phase}:{self.code}]{where} {self.message}"


@dataclass(frozen=True)
class ExpectedPair:
    verdict: str
    reason_code: str

    @property
    def pair(self) -> tuple[str, str]:
        return self.verdict, self.reason_code


@dataclass(frozen=True)
class CasePlan:
    case_id: str
    directory_id: str
    ecosystem: str
    change_class: str
    label: str
    mode: str
    main_expected: ExpectedPair
    exception_expected: ExpectedPair | None
    metadata: Mapping[str, Any]

    @property
    def run_keys(self) -> tuple[RunKey, ...]:
        keys = [(self.case_id, MAIN)]
        if self.exception_expected is not None:
            keys.append((self.case_id, EXCEPTION))
        return tuple(keys)


@dataclass(frozen=True)
class CorpusPlan:
    cases: tuple[CasePlan, ...]

    @property
    def expected_record_count(self) -> int:
        return sum(len(case.run_keys) for case in self.cases)

    @property
    def run_keys(self) -> tuple[RunKey, ...]:
        return tuple(key for case in self.cases for key in case.run_keys)


def protocol_requires_timing(protocol: str) -> bool:
    return protocol in TIMED_PROTOCOLS


def _issue(
    issues: list[EvaluationIssue],
    code: str,
    message: str,
    *,
    case_id: str | None = None,
) -> None:
    issues.append(
        EvaluationIssue(
            phase="corpus",
            code=code,
            message=message,
            case_id=case_id,
        )
    )


def _nonempty_string(
    value: object,
    field: str,
    issues: list[EvaluationIssue],
    *,
    case_id: str | None,
) -> str | None:
    if not isinstance(value, str) or not value.strip():
        _issue(
            issues,
            "invalid_field",
            f"{field} must be a non-empty string",
            case_id=case_id,
        )
        return None
    return value


def _closed_keys(
    value: Mapping[str, Any],
    allowed: frozenset[str],
    required: frozenset[str],
    field: str,
    issues: list[EvaluationIssue],
    *,
    case_id: str | None,
) -> None:
    keys = set(value)
    for name in sorted(required - keys):
        _issue(
            issues,
            "missing_field",
            f"{field}.{name} is required",
            case_id=case_id,
        )
    for name in sorted(keys - allowed):
        _issue(
            issues,
            "unknown_field",
            f"{field}.{name} is not part of protocol v0.3",
            case_id=case_id,
        )


def _expectation(
    value: object,
    field: str,
    issues: list[EvaluationIssue],
    *,
    case_id: str | None,
) -> ExpectedPair | None:
    if not isinstance(value, Mapping):
        _issue(
            issues,
            "invalid_expectation",
            f"{field} must be an object",
            case_id=case_id,
        )
        return None
    _closed_keys(
        value,
        _EXPECTATION_KEYS,
        _EXPECTATION_KEYS,
        field,
        issues,
        case_id=case_id,
    )
    verdict = _nonempty_string(
        value.get("verdict"),
        f"{field}.verdict",
        issues,
        case_id=case_id,
    )
    reason = _nonempty_string(
        value.get("reason_code"),
        f"{field}.reason_code",
        issues,
        case_id=case_id,
    )
    if verdict is None or reason is None:
        return None
    allowed_verdicts = _SCHEMA_REASON_VERDICTS.get(reason)
    if allowed_verdicts is None:
        _issue(
            issues,
            "unknown_reason_code",
            f"{field}.reason_code is not in the frozen schema 1.11 vocabulary",
            case_id=case_id,
        )
    elif verdict not in allowed_verdicts:
        _issue(
            issues,
            "reason_verdict_mismatch",
            (
                f"{field} pair {(verdict, reason)} contradicts the frozen "
                "schema 1.11 contract"
            ),
            case_id=case_id,
        )
    return ExpectedPair(verdict=verdict, reason_code=reason)


def _validate_truth(
    value: object,
    label: object,
    issues: list[EvaluationIssue],
    *,
    case_id: str | None,
) -> None:
    if not isinstance(value, Mapping):
        _issue(
            issues,
            "invalid_truth",
            "truth must be an object",
            case_id=case_id,
        )
        return
    _closed_keys(
        value,
        _TRUTH_KEYS,
        _TRUTH_KEYS,
        "truth",
        issues,
        case_id=case_id,
    )
    decision = _nonempty_string(
        value.get("human_decision"),
        "truth.human_decision",
        issues,
        case_id=case_id,
    )
    policy = _nonempty_string(
        value.get("policy_expectation"),
        "truth.policy_expectation",
        issues,
        case_id=case_id,
    )
    _nonempty_string(
        value.get("rationale"),
        "truth.rationale",
        issues,
        case_id=case_id,
    )
    _nonempty_string(
        value.get("labeled_by"),
        "truth.labeled_by",
        issues,
        case_id=case_id,
    )
    if value.get("labeled_before_guard_run") is not True:
        _issue(
            issues,
            "truth_not_frozen",
            "truth is not declared frozen before the Guard run",
            case_id=case_id,
        )
    if decision is not None and policy is not None and isinstance(label, str):
        allowed = _TRUTH_LABELS.get((decision, policy))
        if allowed is None or label not in allowed:
            _issue(
                issues,
                "truth_label_mismatch",
                f"truth ({decision}, {policy}) is inconsistent with label {label}",
                case_id=case_id,
            )


def _validate_source(
    value: object,
    issues: list[EvaluationIssue],
    *,
    case_id: str | None,
) -> None:
    if not isinstance(value, Mapping):
        _issue(
            issues,
            "invalid_source",
            "source must be an object",
            case_id=case_id,
        )
        return
    source_type = value.get("type")
    allowed = _SOURCE_KEYS.get(source_type) if isinstance(source_type, str) else None
    if allowed is None:
        _issue(
            issues,
            "invalid_source_type",
            f"unsupported source type: {source_type!r}",
            case_id=case_id,
        )
        return
    _closed_keys(
        value,
        allowed,
        allowed,
        "source",
        issues,
        case_id=case_id,
    )
    if source_type == "git":
        _nonempty_string(value.get("url"), "source.url", issues, case_id=case_id)
        commit = _nonempty_string(
            value.get("commit"), "source.commit", issues, case_id=case_id
        )
        if commit is not None and _HEX_40.fullmatch(commit) is None:
            _issue(
                issues,
                "invalid_source_revision",
                "source.commit must be a full 40-hex revision",
                case_id=case_id,
            )
    else:
        _nonempty_string(
            value.get("package"), "source.package", issues, case_id=case_id
        )
        _nonempty_string(
            value.get("version"), "source.version", issues, case_id=case_id
        )
        digest = _nonempty_string(
            value.get("sha256"), "source.sha256", issues, case_id=case_id
        )
        if digest is not None and _HEX_64.fullmatch(digest) is None:
            _issue(
                issues,
                "invalid_source_digest",
                "source.sha256 must be 64 hexadecimal characters",
                case_id=case_id,
            )


def _validate_policy(
    value: object,
    issues: list[EvaluationIssue],
    *,
    case_id: str | None,
) -> None:
    if not isinstance(value, Mapping):
        _issue(
            issues,
            "invalid_policy",
            "policy must be an object",
            case_id=case_id,
        )
        return
    _closed_keys(
        value,
        _POLICY_KEYS,
        _POLICY_KEYS,
        "policy",
        issues,
        case_id=case_id,
    )
    test_command = _nonempty_string(
        value.get("test_command"),
        "policy.test_command",
        issues,
        case_id=case_id,
    )
    if test_command is not None:
        try:
            parsed_command = shlex.split(test_command)
        except ValueError as exc:
            _issue(
                issues,
                "invalid_policy_command",
                f"policy.test_command is not valid shell syntax: {exc}",
                case_id=case_id,
            )
        else:
            if not parsed_command:
                _issue(
                    issues,
                    "invalid_policy_command",
                    "policy.test_command must contain an executable",
                    case_id=case_id,
                )
    timeout = value.get("timeout")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
        _issue(
            issues,
            "invalid_policy_timeout",
            "policy.timeout must be a positive integer",
            case_id=case_id,
        )


def _validate_label_expectations(
    label: object,
    main: ExpectedPair | None,
    exception: ExpectedPair | None,
    issues: list[EvaluationIssue],
    *,
    case_id: str | None,
) -> None:
    """Keep the Guard-contract mapping derived from, not chosen by, labels."""

    if not isinstance(label, str) or main is None:
        return
    required_main: tuple[str, str] | None = None
    if label == "accept":
        required_main = ("PASS", "tests_passed")
    elif label in {"requires_review", "requires_policy_exception"}:
        required_main = ("REJECTED", "protected_harness_edit")
    elif label == "unsupported":
        required_main = ("ERROR", "policy_requirement_unsupported")
    elif label == "reject" and main.verdict not in {"REJECTED", "FAIL"}:
        _issue(
            issues,
            "label_expectation_mismatch",
            "reject must expect a REJECTED or FAIL verdict",
            case_id=case_id,
        )
    if required_main is not None and main.pair != required_main:
        _issue(
            issues,
            "label_expectation_mismatch",
            f"label {label} requires main expectation {required_main}, got {main.pair}",
            case_id=case_id,
        )
    if (
        label == "requires_policy_exception"
        and exception is not None
        and exception.pair != ("PASS", "tests_passed")
    ):
        _issue(
            issues,
            "label_expectation_mismatch",
            "requires_policy_exception requires PASS/tests_passed after exception",
            case_id=case_id,
        )


def preflight_corpus(
    cases: Sequence[tuple[str, object]],
) -> tuple[CorpusPlan | None, tuple[EvaluationIssue, ...]]:
    """Validate every metadata object before returning a scorable corpus plan.

    A single error makes the returned plan ``None``.  Callers therefore cannot
    accidentally score only the subset whose metadata happened to parse.
    """

    issues: list[EvaluationIssue] = []
    plans: list[CasePlan] = []
    seen_ids: dict[str, str] = {}
    if not cases:
        _issue(issues, "empty_corpus", "manifest contains no case metadata")

    for directory_id, raw in cases:
        if not isinstance(raw, Mapping):
            _issue(
                issues,
                "invalid_case",
                "case metadata must be a JSON object",
                case_id=directory_id,
            )
            continue
        case_id_value = raw.get("id")
        case_id = case_id_value if isinstance(case_id_value, str) else directory_id
        _closed_keys(
            raw,
            _TOP_LEVEL_KEYS,
            _TOP_LEVEL_REQUIRED,
            "case",
            issues,
            case_id=case_id,
        )

        parsed_id = _nonempty_string(
            case_id_value,
            "case.id",
            issues,
            case_id=case_id,
        )
        if parsed_id is not None:
            if _SAFE_ID.fullmatch(parsed_id) is None:
                _issue(
                    issues,
                    "unsafe_case_id",
                    "case.id must be one safe filename component",
                    case_id=parsed_id,
                )
            if parsed_id != directory_id:
                _issue(
                    issues,
                    "directory_id_mismatch",
                    f"case directory {directory_id!r} does not match id {parsed_id!r}",
                    case_id=parsed_id,
                )
            folded_id = parsed_id.casefold()
            if folded_id in seen_ids:
                _issue(
                    issues,
                    "duplicate_case_id",
                    (
                        f"case id {parsed_id!r} collides with "
                        f"{seen_ids[folded_id]!r}"
                    ),
                    case_id=parsed_id,
                )
            else:
                seen_ids[folded_id] = parsed_id

        ecosystem = _nonempty_string(
            raw.get("ecosystem"),
            "case.ecosystem",
            issues,
            case_id=case_id,
        )
        if ecosystem is not None and _SAFE_ID.fullmatch(ecosystem) is None:
            _issue(
                issues,
                "invalid_ecosystem",
                "case.ecosystem must be one safe path component",
                case_id=case_id,
            )
        change_class = _nonempty_string(
            raw.get("change_class"),
            "case.change_class",
            issues,
            case_id=case_id,
        )
        if change_class is not None and _SAFE_ID.fullmatch(change_class) is None:
            _issue(
                issues,
                "invalid_change_class",
                "case.change_class must be one stable token",
                case_id=case_id,
            )
        _nonempty_string(
            raw.get("upstream"), "case.upstream", issues, case_id=case_id
        )
        _nonempty_string(
            raw.get("license"), "case.license", issues, case_id=case_id
        )

        label = raw.get("label")
        label_is_valid = isinstance(label, str) and label in LABELS
        if not label_is_valid:
            _issue(
                issues,
                "unknown_label",
                f"unknown label: {label!r}",
                case_id=case_id,
            )
        _validate_truth(raw.get("truth"), label, issues, case_id=case_id)
        _validate_source(raw.get("source"), issues, case_id=case_id)
        _validate_policy(raw.get("policy"), issues, case_id=case_id)

        mode = raw.get("mode", "patch")
        mode_is_valid = isinstance(mode, str) and mode in {"patch", "diff"}
        if not mode_is_valid:
            _issue(
                issues,
                "invalid_mode",
                f"mode must be 'patch' or 'diff', got {mode!r}",
                case_id=case_id,
            )

        main_expected = _expectation(
            raw.get("guard_expectation"),
            "guard_expectation",
            issues,
            case_id=case_id,
        )
        exception_expected: ExpectedPair | None = None
        exception = raw.get("exception")
        requires_exception = (
            isinstance(label, str) and label in LABELS_REQUIRING_EXCEPTION
        )
        if requires_exception:
            if not isinstance(exception, Mapping):
                _issue(
                    issues,
                    "missing_exception",
                    "label requires an exception object",
                    case_id=case_id,
                )
            else:
                _closed_keys(
                    exception,
                    _EXCEPTION_KEYS,
                    _EXCEPTION_KEYS,
                    "exception",
                    issues,
                    case_id=case_id,
                )
                args = exception.get("args")
                if (
                    not isinstance(args, list)
                    or not args
                    or any(not isinstance(arg, str) or not arg for arg in args)
                ):
                    _issue(
                        issues,
                        "invalid_exception_args",
                        "exception.args must be a non-empty list of strings",
                        case_id=case_id,
                    )
                exception_expected = _expectation(
                    exception.get("guard_expectation"),
                    "exception.guard_expectation",
                    issues,
                    case_id=case_id,
                )
        elif "exception" in raw:
            _issue(
                issues,
                "unexpected_exception",
                f"label {label!r} must not define an exception run",
                case_id=case_id,
            )

        _validate_label_expectations(
            label,
            main_expected,
            exception_expected,
            issues,
            case_id=case_id,
        )

        if (
            parsed_id is not None
            and ecosystem is not None
            and change_class is not None
            and label_is_valid
            and mode_is_valid
            and main_expected is not None
            and (not requires_exception or exception_expected is not None)
        ):
            assert isinstance(label, str)
            assert isinstance(mode, str)
            plans.append(
                CasePlan(
                    case_id=parsed_id,
                    directory_id=directory_id,
                    ecosystem=ecosystem,
                    change_class=change_class,
                    label=label,
                    mode=mode,
                    main_expected=main_expected,
                    exception_expected=exception_expected,
                    metadata=raw,
                )
            )

    if issues:
        return None, tuple(issues)
    return CorpusPlan(cases=tuple(plans)), ()
