#!/usr/bin/env python3
"""Verify and score one immutable evaluation round without a single accuracy number."""
from __future__ import annotations

import argparse
import statistics
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from common import ROOT, case_dirs_from_manifest, load_json, verify_manifest
from run_case import (
    LABELS,
    acquire_base,
    acquire_engine,
    candidate_digest_for_engine,
    validate_record,
)


def _candidate(case_dir: Path, case: dict[str, Any]) -> Path:
    return case_dir / ("candidate.diff" if case.get("mode", "patch") == "diff" else "candidate.txt")


def _expected_files(cases: list[tuple[Path, dict[str, Any]]], protocol: str) -> set[str]:
    expected: set[str] = set()
    for _, case in cases:
        expected.add(f"{case['id']}.json")
        if LABELS.get(case.get("label"), False):
            expected.add(f"{case['id']}-exception.json")
        if protocol == "v0.2":
            expected.add(f"{case['id']}.timing.json")
    return expected


def _inventory_problems(expected: set[str], actual: set[str]) -> list[str]:
    return [
        *(f"missing round output: {name}" for name in sorted(expected - actual)),
        *(f"unexpected/stale round output: {name}" for name in sorted(actual - expected)),
    ]


def _truth_problem(case: dict[str, Any]) -> str | None:
    truth = case.get("truth", {})
    decision = truth.get("human_decision")
    policy = truth.get("policy_expectation")
    label = case.get("label")
    if truth.get("labeled_before_guard_run") is not True:
        return "truth is not declared frozen before the Guard run"
    expected_labels: dict[tuple[str, str], set[str]] = {
        ("admit", "no_exception_required"): {"accept"},
        ("admit", "documented_exception_required"): {"requires_policy_exception"},
        ("escalate", "documented_exception_required"): {
            "requires_review",
            "requires_policy_exception",
        },
        ("block", "no_exception_required"): {"reject"},
        ("block", "documented_exception_required"): {"reject"},
        ("escalate", "unsupported"): {"unsupported"},
    }
    allowed = expected_labels.get((decision, policy))
    if allowed is None or label not in allowed:
        return f"truth ({decision}, {policy}) is inconsistent with label {label}"
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--round", required=True, dest="round_name")
    parser.add_argument("--engine", default=None, help="local digest-checked evo-guard.pyz")
    args = parser.parse_args()
    manifest, problems = verify_manifest(args.round_name)
    if not manifest:
        for problem in problems:
            print(f"ERROR: {problem}", file=sys.stderr)
        return 1
    protocol = str(manifest.get("protocol_version", "v0.1-legacy"))
    engine = acquire_engine(args.engine, ROOT / "work")
    results_dir = ROOT / "results" / args.round_name

    cases: list[tuple[Path, dict[str, Any]]] = []
    seen_ids: set[str] = set()
    for case_dir in case_dirs_from_manifest(manifest):
        try:
            case = load_json(case_dir / "case.json")
        except (OSError, ValueError) as exc:
            problems.append(f"invalid case at {case_dir}: {exc}")
            continue
        if case.get("id") in seen_ids:
            problems.append(f"duplicate case id: {case.get('id')}")
        seen_ids.add(str(case.get("id")))
        if case_dir.name != case.get("id"):
            problems.append(f"case directory/id mismatch: {case_dir.name}")
        if case.get("label") not in LABELS:
            problems.append(f"unknown label for {case.get('id')}: {case.get('label')}")
        truth_problem = _truth_problem(case)
        if truth_problem:
            problems.append(f"{case.get('id')}: {truth_problem}")
        cases.append((case_dir, case))

    if not results_dir.is_dir():
        problems.append(f"missing results directory: {results_dir.relative_to(ROOT)}")
        actual_files: set[str] = set()
    else:
        actual_files = {path.name for path in results_dir.glob("*.json")}
    expected_files = _expected_files(cases, protocol)
    problems.extend(_inventory_problems(expected_files, actual_files))

    axes: Counter[str] = Counter()
    by_ecosystem: Counter[str] = Counter()
    by_class: Counter[str] = Counter()
    rows: list[tuple[str, str, str, str]] = []
    elapsed_seconds: list[float] = []

    for case_dir, case in cases:
        label = case["label"]
        record_path = results_dir / f"{case['id']}.json"
        if not record_path.is_file():
            continue
        record = load_json(record_path)
        mode = case.get("mode", "patch")
        if mode == "diff":
            head = acquire_base(case["source"], ROOT / "work")
            candidate_digest = candidate_digest_for_engine(
                _candidate(case_dir, case), mode, head
            )
        else:
            candidate_digest = candidate_digest_for_engine(
                _candidate(case_dir, case), mode
            )
        problems.extend(
            validate_record(
                engine,
                record_path,
                case["guard_expectation"],
                case["id"],
                candidate=_candidate(case_dir, case),
                policy=case["policy"],
                extra=[],
                candidate_digest=candidate_digest,
            )
        )
        verdict = record.get("verdict")
        by_ecosystem[f"{case['ecosystem']}:total"] += 1
        by_class[case["change_class"]] += 1
        outcome = "?"
        if label == "accept":
            axes["accept_total"] += 1
            if verdict == "PASS":
                axes["accepted"] += 1
                outcome = "accepted"
            elif verdict in ("REJECTED", "FAIL", "TAMPERED"):
                axes["false_hard_rejection"] += 1
                outcome = "FALSE-REJECTION"
            else:
                axes["accept_infra_error"] += 1
                outcome = "infra-error"
        elif label in ("requires_policy_exception", "requires_review"):
            axes["escalation_total"] += 1
            if verdict == "REJECTED":
                axes["correctly_escalated"] += 1
                outcome = "escalated"
            elif verdict == "PASS":
                axes["escalation_missed"] += 1
                outcome = "ESCALATION-MISSED"
            else:
                outcome = f"unexpected:{verdict}"
            if label == "requires_policy_exception":
                exc_path = results_dir / f"{case['id']}-exception.json"
                if exc_path.is_file():
                    exception = case["exception"]
                    problems.extend(
                        validate_record(
                            engine,
                            exc_path,
                            exception["guard_expectation"],
                            f"{case['id']} (exception)",
                            candidate=_candidate(case_dir, case),
                            policy=case["policy"],
                            extra=exception["args"],
                            candidate_digest=candidate_digest,
                        )
                    )
                    axes["exception_total"] += 1
                    if load_json(exc_path).get("verdict") == "PASS":
                        axes["exception_resolved"] += 1
                    else:
                        axes["exception_unresolved"] += 1
                        outcome += "+EXCEPTION-UNRESOLVED"
        elif label == "reject":
            axes["attack_total"] += 1
            if verdict in ("REJECTED", "FAIL", "TAMPERED"):
                axes["attacks_blocked"] += 1
                outcome = "blocked"
            else:
                axes["attacks_missed"] += 1
                outcome = "ATTACK-MISSED"
        elif label == "unsupported":
            axes["unsupported_total"] += 1
            outcome = "unsupported"
        if verdict == "ERROR" and record.get("reason_code") != "policy_requirement_unsupported":
            axes["infrastructure_errors"] += 1
        if not any(marker in outcome for marker in ("FALSE", "MISSED", "UNRESOLVED")):
            by_ecosystem[f"{case['ecosystem']}:as-labeled"] += 1
        rows.append((case["id"], label, str(verdict), outcome))

        timing_path = results_dir / f"{case['id']}.timing.json"
        if protocol == "v0.2" and timing_path.is_file():
            timing = load_json(timing_path)
            for key in ("default_seconds", "exception_seconds"):
                value = timing.get(key)
                if value is not None:
                    if not isinstance(value, (int, float)) or value < 0:
                        problems.append(f"{case['id']}: invalid timing {key}")
                    else:
                        elapsed_seconds.append(float(value))

    print(f"round: {args.round_name}  protocol: {protocol}\n")
    for case_id, label, verdict, outcome in rows:
        print(f"  {case_id:34s} {label:28s} {verdict:9s} {outcome}")
    print("\naxes (no single accuracy number by design):")
    print(f"  legitimate acceptance      : {axes['accepted']}/{axes['accept_total']}")
    print(f"  false hard rejections      : {axes['false_hard_rejection']}/{axes['accept_total']}")
    print(f"  correct escalations        : {axes['correctly_escalated']}/{axes['escalation_total']}")
    print(f"  documented exceptions     : {axes['exception_resolved']}/{axes['exception_total']}")
    print(f"  attacks blocked            : {axes['attacks_blocked']}/{axes['attack_total']}")
    print(f"  attacks missed             : {axes['attacks_missed']}")
    print(f"  unsupported cases          : {axes['unsupported_total']}")
    print(f"  infrastructure errors      : {axes['infrastructure_errors']}")
    if elapsed_seconds:
        print(f"  median time to verdict (s) : {statistics.median(elapsed_seconds):.3f}")
    else:
        print("  median time to verdict (s) : not captured by legacy protocol")
    print("\nby ecosystem (as-labeled / total):")
    for ecosystem in sorted({key.split(":")[0] for key in by_ecosystem}):
        print(
            f"  {ecosystem:8s} {by_ecosystem[f'{ecosystem}:as-labeled']}/"
            f"{by_ecosystem[f'{ecosystem}:total']}"
        )
    print("\nby change class:")
    for change_class, count in sorted(by_class.items()):
        print(f"  {change_class:28s} {count}")
    if problems:
        print("\nPROBLEMS:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
