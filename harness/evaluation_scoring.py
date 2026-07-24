"""Pure fixed-denominator scoring for evaluation protocol v0.3."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping

from evaluation_contract import (
    EXCEPTION,
    MAIN,
    CorpusPlan,
    ExpectedPair,
    RunKey,
)

ObservedPair = tuple[object, object] | None
KNOWN_VERDICTS = frozenset({"PASS", "REJECTED", "FAIL", "ERROR", "TAMPERED"})


class TerminalStatus(str, Enum):
    """Closed terminal vocabulary for every required evaluator run."""

    EXACT = "EXACT"
    MISSING = "MISSING"
    INVALID_EVIDENCE = "INVALID_EVIDENCE"
    WRONG_REASON = "WRONG_REASON"
    UNEXPECTED_PASS = "UNEXPECTED_PASS"
    UNEXPECTED_REJECTED = "UNEXPECTED_REJECTED"
    UNEXPECTED_FAIL = "UNEXPECTED_FAIL"
    UNEXPECTED_ERROR = "UNEXPECTED_ERROR"
    UNEXPECTED_TAMPERED = "UNEXPECTED_TAMPERED"
    UNKNOWN_VERDICT = "UNKNOWN_VERDICT"


@dataclass(frozen=True)
class RunObservation:
    """One required output's existence, parseable pair, and evidence validity."""

    present: bool
    pair: ObservedPair
    evidence_valid: bool


@dataclass(frozen=True)
class RunScore:
    key: RunKey
    expected: tuple[str, str]
    observed: ObservedPair
    conformance_status: TerminalStatus
    terminal_status: TerminalStatus
    exact_pair: bool
    evidence_valid: bool
    admissible: bool


@dataclass(frozen=True)
class ScoredRow:
    case_id: str
    label: str
    ecosystem: str
    change_class: str
    main: RunScore
    exception: RunScore | None
    case_exact: bool
    case_evidence_valid: bool
    case_admissible: bool

    # Stable compatibility properties for callers of the v0.2 evaluator API.
    @property
    def main_expected(self) -> tuple[str, str]:
        return self.main.expected

    @property
    def main_observed(self) -> ObservedPair:
        return self.main.observed

    @property
    def main_matches(self) -> bool:
        return self.main.exact_pair

    @property
    def exception_expected(self) -> tuple[str, str] | None:
        return self.exception.expected if self.exception is not None else None

    @property
    def exception_observed(self) -> ObservedPair:
        return self.exception.observed if self.exception is not None else None

    @property
    def exception_matches(self) -> bool | None:
        return self.exception.exact_pair if self.exception is not None else None

    @property
    def case_matches(self) -> bool:
        return self.case_exact

    @property
    def outcome(self) -> str:
        statuses = [self.main.terminal_status.value]
        if self.exception is not None:
            statuses.append(f"EXCEPTION-{self.exception.terminal_status.value}")
        return "+".join(statuses)


@dataclass(frozen=True)
class ConformanceSummary:
    rows: tuple[ScoredRow, ...]
    runs: tuple[RunScore, ...]
    axes: Mapping[str, int]
    by_ecosystem: Mapping[str, tuple[int, int]]
    by_change_class: Mapping[str, tuple[int, int]]
    exact_records: int
    valid_records: int
    admissible_records: int
    expected_records: int
    exact_cases: int
    admissible_cases: int
    expected_cases: int

    @property
    def matched_records(self) -> int:
        return self.exact_records


@dataclass(frozen=True)
class EvidenceIntegrity:
    valid_records: int
    expected_records: int
    valid_timings: int
    expected_timings: int
    unexpected_outputs: int

    @property
    def complete(self) -> bool:
        return (
            self.valid_records == self.expected_records
            and self.valid_timings == self.expected_timings
            and self.unexpected_outputs == 0
        )


def _pair(value: object) -> ObservedPair:
    if isinstance(value, ExpectedPair):
        return value.pair
    if isinstance(value, Mapping):
        return value.get("verdict"), value.get("reason_code")
    if isinstance(value, tuple) and len(value) == 2:
        return value
    return None


def normalize_observation(value: object) -> RunObservation:
    """Normalize legacy mapping inputs and the explicit v0.3 observation."""

    if isinstance(value, RunObservation):
        return value
    if value is None:
        return RunObservation(present=False, pair=None, evidence_valid=False)
    return RunObservation(present=True, pair=_pair(value), evidence_valid=True)


def conformance_status(
    observation: RunObservation,
    expected: tuple[str, str],
) -> TerminalStatus:
    """Classify only the observed pair; evidence validity is a separate axis."""

    if not observation.present:
        return TerminalStatus.MISSING
    observed = observation.pair
    if observed is None:
        return TerminalStatus.UNKNOWN_VERDICT
    verdict, reason = observed
    if not isinstance(verdict, str) or verdict not in KNOWN_VERDICTS:
        return TerminalStatus.UNKNOWN_VERDICT
    if not isinstance(reason, str) or not reason:
        return TerminalStatus.WRONG_REASON
    if observed == expected:
        return TerminalStatus.EXACT
    if verdict == expected[0]:
        return TerminalStatus.WRONG_REASON
    return {
        "PASS": TerminalStatus.UNEXPECTED_PASS,
        "REJECTED": TerminalStatus.UNEXPECTED_REJECTED,
        "FAIL": TerminalStatus.UNEXPECTED_FAIL,
        "ERROR": TerminalStatus.UNEXPECTED_ERROR,
        "TAMPERED": TerminalStatus.UNEXPECTED_TAMPERED,
    }[verdict]


def score_run(
    key: RunKey,
    expected: tuple[str, str],
    value: object,
) -> RunScore:
    observation = normalize_observation(value)
    pair_status = conformance_status(observation, expected)
    exact = pair_status is TerminalStatus.EXACT
    evidence_valid = observation.present and observation.evidence_valid
    terminal = pair_status
    if (
        observation.present
        and not evidence_valid
        and pair_status
        not in {TerminalStatus.MISSING, TerminalStatus.UNKNOWN_VERDICT}
    ):
        terminal = TerminalStatus.INVALID_EVIDENCE
    return RunScore(
        key=key,
        expected=expected,
        observed=observation.pair,
        conformance_status=pair_status,
        terminal_status=terminal,
        exact_pair=exact,
        evidence_valid=evidence_valid,
        admissible=exact and evidence_valid,
    )


def score_conformance(
    plan: CorpusPlan,
    observations: Mapping[RunKey, object],
) -> ConformanceSummary:
    """Score all required runs against denominators fixed only by ``plan``."""

    axes: Counter[str] = Counter(
        case_total=len(plan.cases),
        expected_record_total=plan.expected_record_count,
    )
    rows: list[ScoredRow] = []
    all_runs: list[RunScore] = []
    ecosystem_totals: Counter[str] = Counter()
    ecosystem_exact: Counter[str] = Counter()
    class_totals: Counter[str] = Counter()
    class_exact: Counter[str] = Counter()

    for case in plan.cases:
        ecosystem_totals[case.ecosystem] += 1
        class_totals[case.change_class] += 1
        if case.label == "accept":
            axes["accept_total"] += 1
        elif case.label in {"requires_policy_exception", "requires_review"}:
            axes["escalation_total"] += 1
        elif case.label == "reject":
            axes["attack_total"] += 1
        elif case.label == "unsupported":
            axes["unsupported_total"] += 1

        main_key = (case.case_id, MAIN)
        main = score_run(
            main_key,
            case.main_expected.pair,
            observations.get(main_key),
        )
        run_scores = [main]
        exception_score: RunScore | None = None
        if case.exception_expected is not None:
            axes["exception_total"] += 1
            exception_key = (case.case_id, EXCEPTION)
            exception_score = score_run(
                exception_key,
                case.exception_expected.pair,
                observations.get(exception_key),
            )
            run_scores.append(exception_score)

        case_exact = all(run.exact_pair for run in run_scores)
        case_valid = all(run.evidence_valid for run in run_scores)
        case_admissible = all(run.admissible for run in run_scores)
        if case_exact:
            axes["exact_cases"] += 1
            ecosystem_exact[case.ecosystem] += 1
            class_exact[case.change_class] += 1

        if case.label == "accept":
            if main.exact_pair:
                axes["accepted"] += 1
            else:
                axes["accept_mismatch"] += 1
                if main.observed is not None and main.observed[0] in {
                    "REJECTED",
                    "FAIL",
                    "TAMPERED",
                }:
                    axes["false_hard_rejection"] += 1
        elif case.label in {"requires_policy_exception", "requires_review"}:
            axes[
                "correctly_escalated" if main.exact_pair else "escalation_missed"
            ] += 1
            if exception_score is not None:
                axes[
                    "exception_resolved"
                    if exception_score.exact_pair
                    else "exception_unresolved"
                ] += 1
        elif case.label == "reject":
            axes["attacks_blocked" if main.exact_pair else "attacks_missed"] += 1
        elif case.label == "unsupported":
            axes[
                "unsupported_matched" if main.exact_pair else "unsupported_missed"
            ] += 1

        for run in run_scores:
            axes[f"status_{run.terminal_status.value}"] += 1
            if run.conformance_status is TerminalStatus.UNEXPECTED_ERROR:
                axes["infrastructure_errors"] += 1
        all_runs.extend(run_scores)
        rows.append(
            ScoredRow(
                case_id=case.case_id,
                label=case.label,
                ecosystem=case.ecosystem,
                change_class=case.change_class,
                main=main,
                exception=exception_score,
                case_exact=case_exact,
                case_evidence_valid=case_valid,
                case_admissible=case_admissible,
            )
        )

    exact_records = sum(run.exact_pair for run in all_runs)
    valid_records = sum(run.evidence_valid for run in all_runs)
    admissible_records = sum(run.admissible for run in all_runs)
    return ConformanceSummary(
        rows=tuple(rows),
        runs=tuple(all_runs),
        axes=dict(axes),
        by_ecosystem={
            key: (ecosystem_exact[key], total)
            for key, total in sorted(ecosystem_totals.items())
        },
        by_change_class={
            key: (class_exact[key], total)
            for key, total in sorted(class_totals.items())
        },
        exact_records=exact_records,
        valid_records=valid_records,
        admissible_records=admissible_records,
        expected_records=plan.expected_record_count,
        exact_cases=sum(row.case_exact for row in rows),
        admissible_cases=sum(row.case_admissible for row in rows),
        expected_cases=len(rows),
    )


def summarize_evidence(
    plan: CorpusPlan,
    valid_records: Mapping[RunKey, object],
    *,
    expected_timing_cases: Iterable[str] = (),
    valid_timing_cases: Iterable[str] = (),
    unexpected_outputs: int = 0,
) -> EvidenceIntegrity:
    """Summarize evidence independently from exact-pair conformance."""

    expected_timings = frozenset(expected_timing_cases)
    valid_timings = frozenset(valid_timing_cases)

    def is_valid(key: RunKey) -> bool:
        value = valid_records.get(key)
        if isinstance(value, RunObservation):
            return value.present and value.evidence_valid
        return value is True

    return EvidenceIntegrity(
        valid_records=sum(is_valid(key) for key in plan.run_keys),
        expected_records=plan.expected_record_count,
        valid_timings=len(expected_timings & valid_timings),
        expected_timings=len(expected_timings),
        unexpected_outputs=unexpected_outputs,
    )
