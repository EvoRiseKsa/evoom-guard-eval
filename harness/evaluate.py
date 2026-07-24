#!/usr/bin/env python3
"""Thin protocol-v0.3 evaluator command."""
from __future__ import annotations

import argparse
import statistics
import sys
from pathlib import Path
from typing import Any

from common import ROOT
from evaluation_contract import EvaluationIssue, protocol_requires_timing
from evaluation_evidence import (
    check_reanalysis,
    collect_evidence,
    inventory_problems,
    preflight_round,
    read_json_object,
    reanalysis_payloads,
    write_reanalysis,
)
from evaluation_scoring import (
    ConformanceSummary,
    TerminalStatus,
    score_conformance,
    summarize_evidence,
)

# Narrow compatibility aliases for callers that used the historical helpers.
_inventory_problems = inventory_problems
_read_json_object = read_json_object


def _expected_files(
    cases: list[tuple[Path, dict[str, Any]]],
    protocol: str,
) -> set[str]:
    files: set[str] = set()
    for _, case in cases:
        files.add(f"{case['id']}.json")
        if case.get("label") == "requires_policy_exception":
            files.add(f"{case['id']}-exception.json")
        if protocol_requires_timing(protocol):
            files.add(f"{case['id']}.timing.json")
    return files


def _truth_problem(case: dict[str, Any]) -> str | None:
    truth = case.get("truth", {})
    pair = (truth.get("human_decision"), truth.get("policy_expectation"))
    allowed = {
        ("admit", "no_exception_required"): {"accept"},
        ("admit", "documented_exception_required"): {
            "requires_policy_exception"
        },
        ("escalate", "documented_exception_required"): {
            "requires_review",
            "requires_policy_exception",
        },
        ("block", "no_exception_required"): {"reject"},
        ("block", "documented_exception_required"): {"reject"},
        ("escalate", "unsupported"): {"unsupported"},
    }
    if truth.get("labeled_before_guard_run") is not True:
        return "truth is not declared frozen before the Guard run"
    if case.get("label") not in allowed.get(pair, set()):
        return f"truth {pair} is inconsistent with label {case.get('label')}"
    return None


def _format_pair(pair: tuple[object, object] | None) -> str:
    return "<missing>" if pair is None else f"{pair[0]!s}/{pair[1]!s}"


def _print_issues(title: str, issues: tuple[EvaluationIssue, ...]) -> None:
    if not issues:
        return
    print(f"\n{title}:", file=sys.stderr)
    for issue in issues:
        print(f"  {issue.render()}", file=sys.stderr)


def _conformance_issues(
    summary: ConformanceSummary,
) -> tuple[EvaluationIssue, ...]:
    issues: list[EvaluationIssue] = []
    for run in summary.runs:
        if run.exact_pair:
            continue
        issues.append(
            EvaluationIssue(
                phase="conformance",
                code=run.conformance_status.value,
                message=(
                    f"expected {_format_pair(run.expected)}, "
                    f"got {_format_pair(run.observed)}"
                ),
                case_id=run.key[0],
                artifact=(
                    f"{run.key[0]}.json"
                    if run.key[1] == "main"
                    else f"{run.key[0]}-exception.json"
                ),
            )
        )
    return tuple(issues)


def _render(
    round_name: str,
    protocol: str,
    summary: ConformanceSummary,
    integrity: Any,
    elapsed_seconds: tuple[float, ...],
) -> None:
    print(f"round: {round_name}  source protocol: {protocol}")
    print("evaluator protocol: v0.3\n")
    for row in summary.rows:
        main = (
            f"main={_format_pair(row.main.observed)} "
            f"(expected {_format_pair(row.main.expected)})"
        )
        exception = ""
        if row.exception is not None:
            exception = (
                f"  exception={_format_pair(row.exception.observed)} "
                f"(expected {_format_pair(row.exception.expected)})"
            )
        print(
            f"  {row.case_id:34s} {row.label:28s} "
            f"{row.outcome:40s} {main}{exception}"
        )

    print("\nthree axes (all denominators fixed by corpus preflight):")
    print(
        f"  exact expected pairs     : "
        f"{summary.exact_records}/{summary.expected_records}"
    )
    print(
        f"  evidence-valid records   : "
        f"{integrity.valid_records}/{integrity.expected_records}"
    )
    print(
        f"  admissible records       : "
        f"{summary.admissible_records}/{summary.expected_records}"
    )
    print(
        f"  exact cases              : "
        f"{summary.exact_cases}/{summary.expected_cases}"
    )
    print(
        f"  admissible cases         : "
        f"{summary.admissible_cases}/{summary.expected_cases}"
    )

    axes = summary.axes
    print("\nlabel axes (exact pair only):")
    print(
        f"  legitimate acceptance   : "
        f"{axes.get('accepted', 0)}/{axes.get('accept_total', 0)}"
    )
    print(
        f"  false hard rejections   : "
        f"{axes.get('false_hard_rejection', 0)}/{axes.get('accept_total', 0)}"
    )
    print(
        f"  correct escalations     : "
        f"{axes.get('correctly_escalated', 0)}/"
        f"{axes.get('escalation_total', 0)}"
    )
    print(
        f"  exception resolutions   : "
        f"{axes.get('exception_resolved', 0)}/{axes.get('exception_total', 0)}"
    )
    print(
        f"  attacks blocked         : "
        f"{axes.get('attacks_blocked', 0)}/{axes.get('attack_total', 0)}"
    )
    print(
        f"  unsupported exact       : "
        f"{axes.get('unsupported_matched', 0)}/"
        f"{axes.get('unsupported_total', 0)}"
    )

    print("\nterminal status counts:")
    for status in TerminalStatus:
        print(f"  {status.value:24s} {axes.get(f'status_{status.value}', 0)}")

    print("\nby ecosystem (exact cases / fixed cases):")
    for ecosystem, (matched, total) in summary.by_ecosystem.items():
        print(f"  {ecosystem:12s} {matched}/{total}")
    print("\nby change class (exact cases / fixed cases):")
    for change_class, (matched, total) in summary.by_change_class.items():
        print(f"  {change_class:32s} {matched}/{total}")

    print("\nevidence integrity:")
    print(
        f"  verified records        : "
        f"{integrity.valid_records}/{integrity.expected_records}"
    )
    if integrity.expected_timings:
        print(
            f"  valid timing sidecars   : "
            f"{integrity.valid_timings}/{integrity.expected_timings}"
        )
    else:
        print("  valid timing sidecars   : not required by source protocol")
    print(f"  unexpected JSON outputs: {integrity.unexpected_outputs}")
    if (
        integrity.expected_timings
        and integrity.valid_timings == integrity.expected_timings
        and elapsed_seconds
    ):
        print(
            f"  median time to verdict  : "
            f"{statistics.median(elapsed_seconds):.3f}s"
        )
    elif integrity.expected_timings:
        print("  median time to verdict  : unavailable (invalid evidence)")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--round", required=True, dest="round_name")
    parser.add_argument(
        "--engine",
        default=None,
        help="local digest-checked evo-guard.pyz",
    )
    publication = parser.add_mutually_exclusive_group()
    publication.add_argument(
        "--write-reanalysis",
        action="store_true",
        help="create the deterministic protocol-v0.3 reanalysis once",
    )
    publication.add_argument(
        "--check-reanalysis",
        "--check",
        dest="check_reanalysis",
        action="store_true",
        help="recompute and check the frozen protocol-v0.3 reanalysis",
    )
    args = parser.parse_args()

    round_plan, corpus_issues = preflight_round(args.round_name, root=ROOT)
    if round_plan is None:
        _print_issues(
            "CORPUS PREFLIGHT FAILED — SCORING SUPPRESSED",
            corpus_issues,
        )
        return 1

    evidence = collect_evidence(
        round_plan,
        engine_arg=args.engine,
        root=ROOT,
    )
    summary = score_conformance(round_plan.corpus, evidence.observations)
    integrity = summarize_evidence(
        round_plan.corpus,
        evidence.observations,
        expected_timing_cases=evidence.expected_timing_cases,
        valid_timing_cases=evidence.valid_timing_cases,
        unexpected_outputs=evidence.unexpected_outputs,
    )
    conformance_issues = _conformance_issues(summary)
    _render(
        args.round_name,
        round_plan.protocol,
        summary,
        integrity,
        evidence.elapsed_seconds,
    )
    _print_issues("CONFORMANCE FAILURES", conformance_issues)
    _print_issues("EVIDENCE INTEGRITY FAILURES", evidence.issues)
    if conformance_issues or evidence.issues:
        return 1

    if args.write_reanalysis or args.check_reanalysis:
        directory = (
            ROOT
            / "reanalysis"
            / "protocol-v0.3"
            / args.round_name
        )
        payloads = reanalysis_payloads(
            round_plan,
            evidence,
            summary,
            integrity,
        )
        publication_issues = (
            write_reanalysis(directory, payloads, trusted_root=ROOT)
            if args.write_reanalysis
            else check_reanalysis(directory, payloads, trusted_root=ROOT)
        )
        _print_issues("REANALYSIS PUBLICATION FAILED", publication_issues)
        if publication_issues:
            return 1
        action = "created" if args.write_reanalysis else "verified"
        print(f"\nreanalysis {action}: {directory.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
