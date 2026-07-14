#!/usr/bin/env python3
"""Compute the multi-axis metrics for one evaluation round.

    python harness/evaluate.py --round round-pilot

Reads every case's independent ``truth`` (never Guard vocabulary) and the raw
records the round produced, and prints the published axes — there is
deliberately no single accuracy number. Exits non-zero when any expected
record is missing, so a partial round cannot masquerade as a complete one.

The comparison here is observed records vs the LABEL layer; the runner already
compared observed vs the contract mapping (guard_expectation) at run time.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _case_dirs() -> list[str]:
    found: list[str] = []
    cases_root = os.path.join(ROOT, "cases")
    for ecosystem in sorted(os.listdir(cases_root)):
        eco_dir = os.path.join(cases_root, ecosystem)
        if not os.path.isdir(eco_dir):
            continue
        for case_id in sorted(os.listdir(eco_dir)):
            if os.path.isfile(os.path.join(eco_dir, case_id, "case.json")):
                found.append(os.path.join(eco_dir, case_id))
    return found


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--round", required=True, dest="round_name")
    args = parser.parse_args()
    results_dir = os.path.join(ROOT, "results", args.round_name)

    axes: Counter[str] = Counter()
    by_ecosystem: Counter[str] = Counter()
    by_class: Counter[str] = Counter()
    problems: list[str] = []
    rows: list[tuple[str, str, str, str]] = []

    for case_dir in _case_dirs():
        case = _load(os.path.join(case_dir, "case.json"))
        label = case["label"]
        record_path = os.path.join(results_dir, f"{case['id']}.json")
        if not os.path.isfile(record_path):
            problems.append(f"missing record: {case['id']}")
            continue
        record = _load(record_path)
        verdict = record.get("verdict")
        eco_key = f"{case['ecosystem']}:total"
        by_ecosystem[eco_key] += 1
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
                exc_path = os.path.join(results_dir, f"{case['id']}-exception.json")
                if not os.path.isfile(exc_path):
                    problems.append(f"missing exception record: {case['id']}")
                else:
                    axes["exception_total"] += 1
                    if _load(exc_path).get("verdict") == "PASS":
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
        if verdict == "ERROR" and record.get("reason_code") not in (
            "policy_requirement_unsupported",
        ):
            axes["infrastructure_errors"] += 1

        eco_ok = f"{case['ecosystem']}:as-labeled"
        if "FALSE" not in outcome and "MISSED" not in outcome and "UNRESOLVED" not in outcome:
            by_ecosystem[eco_ok] += 1
        rows.append((case["id"], label, str(verdict), outcome))

    print(f"round: {args.round_name}\n")
    for case_id, label, verdict, outcome in rows:
        print(f"  {case_id:34s} {label:28s} {verdict:9s} {outcome}")
    print("\naxes (no single accuracy number by design):")
    print(f"  legitimate acceptance      : {axes['accepted']}/{axes['accept_total']}")
    print(f"  false hard rejections      : {axes['false_hard_rejection']}/{axes['accept_total']}")
    print(
        f"  correct escalations        : "
        f"{axes['correctly_escalated']}/{axes['escalation_total']}"
    )
    print(
        f"  documented-exception resolutions: "
        f"{axes['exception_resolved']}/{axes['exception_total']}"
    )
    print(f"  attacks blocked            : {axes['attacks_blocked']}/{axes['attack_total']}")
    print(f"  attacks missed             : {axes['attacks_missed']}")
    print(f"  unsupported cases          : {axes['unsupported_total']}")
    print(f"  infrastructure errors      : {axes['infrastructure_errors']}")
    print("\nby ecosystem (as-labeled / total):")
    for ecosystem in sorted({k.split(":")[0] for k in by_ecosystem}):
        ok = by_ecosystem[f"{ecosystem}:as-labeled"]
        total = by_ecosystem[f"{ecosystem}:total"]
        print(f"  {ecosystem:8s} {ok}/{total}")
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
