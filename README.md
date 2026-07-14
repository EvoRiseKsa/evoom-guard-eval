# `evoom-guard-eval` — the independent real-world evaluation corpus

**Protocol v0.1 — frozen 2026-07-14** (tag `protocol-v0.1`). Changes to the
methodology below fork a new protocol version; they never mutate a round that
already ran. The frozen-core rule applies: nothing here touches
EvoOM-Guard-m; the tool version and policy under test are pinned, never
adapted to the corpus.

**Honest scope:** this repository lives under the same account as the tool it
evaluates. It is a reproducible, pre-registered evaluation — labels frozen
and hashed before execution, raw verdicts published — **not** third-party
validation. Independence claims begin only when an external party labels or
replicates a round.

## Why a separate repository

- The core stays frozen while evaluation grows.
- Labels can be authored and hash-frozen before any Guard execution, by a
  labeler who does not run the tool.
- Raw verdicts, the corpus hash, and the methodology publish as first-class
  artifacts instead of test fixtures inside the tool.
- A future independent evaluator can fork the harness and swap only the corpus.

This implements the commitment already written in the tool's
`benchmarks/README.md`: freeze the Guard version and policy, publish the
corpus hash, label before running, separate tuning from held-out evaluation.

## What it measures (and what it does not)

Measures **verdict quality on real, diverse changes**: acceptance of
legitimate work, refusal of cheating, and honest classification of
policy-sensitive gray cases — per ecosystem and per change class.

Does not measure: parser robustness (fuzzing lives with the tool), field
adoption cost, or reviewer experience. A historical corpus is not a field
study; publish it as evidence, not as a marketing rate.

## Frozen under test

- Engine: the published `evo-guard.pyz` v3.5.2,
  sha256 `a370fac23233ea6f317d5d7e5347389197fc936bd9b5903c685b1d3755e0046f`
  (verified against `SHA256SUMS` and the pinned digest before every run).
- Schema: `1.11`.
- Policy: ONE effective policy per track, written down before the first run;
  its `policy_sha256` published. Policy changes fork a new evaluation round —
  they never mutate an existing one.

## Corpus composition (v1 target: 50–100 cases)

Weighted toward the acceptance side — the side with no evidence today:

| Group | Share | Sources |
|---|---|---|
| Legitimate changes | ~45% | bug fixes, refactors, dependency updates, test additions, packaging, CI hardening, config migrations — replayed from merged historical PRs of real OSS repos |
| Ambiguous / policy-sensitive | ~35% | spec-driven test edits, deleting obsolete tests, runner-config updates, lockfiles, snapshots, generated files, legitimate lifecycle scripts, monorepo tooling |
| Adversarial | ~20% | new externally-authored attempts (mutations, red-team contributions); the tool's own 14-case regression corpus is NOT duplicated here |

Ecosystems v1: Python (25–40) and Node (25–40) — the two with runner support
exercised in the tool's CI. Not only small/easy repositories.

## Labels — frozen before execution, in contract vocabulary

Five labels, each mapped to expected `(verdict, reason_code)` sets from the
frozen 1.11 contract so the corpus cannot drift from the contract:

- `accept` → expects `PASS/tests_passed`
- `reject` → expects `REJECTED` or `FAIL` with the named reason code
- `requires_review` → expects `REJECTED/protected_harness_edit` (policy trip
  whose correct human outcome is review, not merge-block forever)
- `requires_policy_exception` → expects rejection unless a documented
  `--allow` baseline is applied; the case ships both runs
- `unsupported` → expects `ERROR` with the named reason code

**Ground truth is independent of Guard.** Every case carries two separate
layers, and conflating them would make the evaluation circular:

1. `truth` — the human judgment, expressed without Guard vocabulary:
   `human_decision` (admit/block/escalate), `policy_expectation`
   (no_exception_required / documented_exception_required / unsupported), the
   rationale, who labeled it, and whether the label predates any Guard run.
2. `guard_expectation` — the contract MAPPING of the label to expected
   `(verdict, reason_code)` pairs. The runner compares observed records
   against this mapping; the metrics compare observed records against the
   independent `truth`. Guard output never defines the truth.

Labeling protocol: labeler ≠ runner; labels + rationale committed and the
corpus hash published BEFORE the first Guard execution; a tuning subset
(~20%) is drawn and the held-out remainder is never used to adjust policy.

## Case format (one directory per case)

```
cases/<ecosystem>/<id>/
  case.json        # source ref + digest, change class, truth (independent
                   # human judgment), label, guard_expectation (contract
                   # mapping), pinned policy, license/provenance
  candidate.txt    # the exact historical change as FILE/PATCH blocks
                   # (or candidate.diff for diff-mode cases)
```

Runner: downloads the pinned base revision (digest-verified), applies the
candidate through the published `.pyz`, writes the raw record to
`results/<round>/<id>.json`, validates it with `verify-record`, and compares
against `guard_expectation`. All raw records ship in the repo.

## Published metrics (no single accuracy number)

Per round, per ecosystem, per change class:

- legitimate acceptance rate, false rejection rate
- policy-review rate, allowlist-required rate
- known-attack block rate, missed-attack rate
- unsupported rate, infrastructure-error rate
- median time to verdict

Plus: corpus hash, engine digest, `policy_sha256`, raw JSONL, and the
labeler/runner separation statement.

## Round plan

- Round 0 (pilot): 10 cases (5 Python, 5 Node) to validate the harness and
  case format end to end — throwaway for metrics.
- Round 1: full v1 corpus, labels frozen, results published.
- Round 2+: new cases accumulate; each round pins its engine/policy; rounds
  are never re-scored retroactively.

## Exit criteria back into the freeze decision

Round 1 results feed the un-freeze decision in the core: high false
rejections → policy-sensitive-change governance work; weak pack semantics →
pack conformance; release-admission demand → artifact-first. The data picks
the next feature.
