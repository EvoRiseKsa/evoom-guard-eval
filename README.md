# `evoom-guard-eval` — reproducible real-world evaluation corpus

**Current protocol: v0.2.** Protocol v0.1 remains immutable at tag
`protocol-v0.1`; it covered the pilot as originally executed but did not yet
include the complete labeling, evaluator, or manifest tooling. Protocol v0.2
closes that gap and is frozen at tag `protocol-v0.2`. Existing tags and round
outputs are never moved or overwritten. See [`PROTOCOL.md`](PROTOCOL.md).

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

Runner: checks that the case is present byte-for-byte in the round's immutable
manifest, downloads the pinned base revision, applies the candidate through
the published `.pyz`, refuses to overwrite a prior result, writes a fresh raw
record to `results/<round>/<id>.json`, validates it with `verify-record`, and
binds its tool/schema/candidate/policy/verdict/reason/timestamp to this exact
invocation. Git caches are keyed by the full source URL and verified against
their configured origin.

The evaluator independently repeats record verification, derives the
canonical candidate digest for both patch and diff modes, checks the exact
expected result-file set (rejecting missing, extra, or stale records), checks
truth/label consistency, and measures timing sidecars for v0.2 rounds. It does
not trust the record's `verdict` field by itself.

## Published metrics (no single accuracy number)

Per round, per ecosystem, per change class:

- legitimate acceptance rate, false rejection rate
- policy-review rate, allowlist-required rate
- known-attack block rate, missed-attack rate
- unsupported rate, infrastructure-error rate
- median time to verdict

Plus: corpus hash, engine digest, `policy_sha256`, raw records, exact result
inventory, per-invocation timing, and the labeler/runner separation statement.

## Separate OSS compatibility study

`studies/oss-compat-v1/` is a canonical-run **same-owner engineering
compatibility study**, not Round 1 and not an independent audit. It freezes 12
historical merged changes from six unrelated projects across Python, Node, Go,
Rust, C++, and C. Each project contributes one source-only replay and one real
change that touches an existing test or CI workflow. The current v0.4 successor
repeats this exposed corpus only to test infrastructure recovery; it is not
blind, held out, model-independent, or a new sample.

The study has its own manifest, harness, workflow, and protected tags. Protocols
v0.1 and v0.2 produced no product measurement: their canonical runs failed
closed before any case runner or Guard invocation. Protocol v0.3 then started
nine case steps but produced a mixed inventory: nine product archives and three
pre-product infrastructure archives. It was captured as
`invalid_or_incomplete_before_product_materialization`; no archive was
materialized or evaluated, and the run is not a 9/12 product result. All three
attempts and their checksums are preserved under
`studies/oss-compat-v1/attempts/`.

The v0.4 successor repeats the same 12 cases after this product-phase exposure.
Only the trusted UID/GID ownership-scan infrastructure is amended; candidate
diffs, labels, expectations, policies, profiles, environments, licenses, and
Guard v3.5.2 remain frozen. V0.4 may report infrastructure completion and
descriptive exact-case conformance only. It cannot support accuracy,
false-positive-rate, generalization, held-out, or independent-validation
claims, and repeated runs never increase the unique sample size above 12.
The scanner permits one initial pass plus at most two complete retries (three
attempts total) under the same 900-second deadline, and only after correlating
a deletion-only boundary change with every failed-and-then-absent transient
partition; all other changes and errors remain terminal. These are internal
infrastructure attempts, not product reruns.
These files never enter the separate Round 1 corpus. An Actions-API preflight enforces the first API-visible
dispatch among retained runs; it cannot detect an earlier run deleted by the
repository owner. Before any upstream code runs, the harness switches to a
root-owned `env -i` execution with no Actions/artifact token. Setup and tests run
as a dedicated capability-free uid under a trusted PID/mount-namespace
supervisor. The host view is recursively read-only except for the exact case
execution root; real tool targets are canonicalized behind a root-owned alias
set. The protocol, engine, source cache, judge parent, and artifact output remain
root-owned. An unconditional cleanup must prove that no process of that uid
survives before the output is released to the official upload step. The live
self-test and `tests/oss_boundary_integration.sh` exercise detached-daemon,
forbidden-write, environment, real-pytest/JUnit, and forced-wrapper-death paths.
GitHub-hosted CI also configures and builds a real CMake program through the
same installed boundary. A root-owned marker created before installation makes
early infrastructure output distinct from product output; the two artifact
uploads are mutually exclusive, and the product materializer rejects every
`oss-infra-*` artifact.
This narrows host and artifact risk but is not a VM/network/kernel sandbox, and
the test process still writes the explicitly declared
`same_process_candidate_writable` JUnit channel. Evidence integrity failures
block publication, while integrity-valid negative product results remain
publishable rather than being selected away.
Canonical artifacts are preserved as ZIP archives and accepted only when their
sizes and SHA-256 digests match the live GitHub Actions API. The materializer
also binds the exact attempt-1 Jobs API inventory and every required official
step before safe extraction is checked byte-for-byte against the published case
directories.
The evaluator reports the fixed 12-case repeated-engineering denominator separately
from Guard invocation coverage and the verified-record product-outcome
denominator. A pre-Guard failure therefore cannot be presented as a Guard
verdict or as a 0/12 product score.
If the one canonical v0.4 run does not yield the exact 12 product artifacts,
`python harness/capture_oss_attempt.py current --run-id <RUN_ID>` preserves the
API records, original logs, frozen manifest, and every artifact ZIP without
extracting or evaluating them. A capture alone always forbids product inference;
only the separate product materializer and evaluator may publish a result.
See [`studies/oss-compat-v1/PROTOCOL.md`](studies/oss-compat-v1/PROTOCOL.md)
for the selection limits and non-hermetic dependency caveats.

## Round plan

- Round pilot: 10 cases (5 Python, 5 Node), executed under the legacy v0.1
  procedure with the declared labeler == runner exception. It is historical
  evidence, not an independent estimate.
- Round 1: 50–100 cases under v0.2, but it must not start until a distinct
  blind labeler is named and the manifest is publicly frozen.
- Round 2+: new cases accumulate; each round pins its engine/policy; rounds
  are never re-scored retroactively.

## Reproduce the current evidence

```bash
python -m unittest discover -s tests -v
python harness/make_manifest.py round-pilot --check
python harness/evaluate.py --round round-pilot
python harness/freeze_oss_cases.py --check
python harness/make_oss_manifest.py oss-pilot-01 --check
python harness/make_oss_manifest.py oss-pilot-02 --check
python harness/make_oss_manifest.py oss-pilot-03 --check
python harness/make_oss_manifest.py oss-pilot-04 --check --if-present
python harness/materialize_oss_artifacts.py --help
python harness/capture_oss_attempt.py current --run-id <RUN_ID>
python harness/evaluate_oss.py --study oss-pilot-04 \
  --results studies/oss-compat-v1/results --check --if-present
```

CI runs the manifest, evidence, and harness checks on Windows and Linux with
Python 3.11–3.13. The
published engine is downloaded with a timeout and accepted only when its
SHA-256 equals the frozen digest.

## License boundaries

Repository-authored harness and documentation are MIT licensed. Candidate
changes are derived from the upstream projects named in each `case.json` and
retain their upstream licenses; EvoOM Guard records remain subject to the
tool's own terms. See [`THIRD_PARTY.md`](THIRD_PARTY.md).

## Exit criteria back into the freeze decision

Round 1 results feed the un-freeze decision in the core: high false
rejections → policy-sensitive-change governance work; weak pack semantics →
pack conformance; release-admission demand → artifact-first. The data picks
the next feature.
