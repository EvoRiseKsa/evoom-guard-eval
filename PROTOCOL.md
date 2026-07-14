# Evaluation protocol v0.2

Protocol v0.2 is the first version that freezes the complete method: labeling,
manifest creation, case execution, semantic record verification, exact output
inventory, and metric computation. Tag `protocol-v0.1` is retained unchanged
as historical provenance for the pilot; it must never be moved.

## Invariants

1. The engine release, artifact SHA-256, schema, source revision, candidate,
   policy, truth, and Guard expectation are fixed before execution.
2. The blind labeler and runner have distinct stable identities for any round
   described as independent. A role conflict is permitted only when declared
   and the round is explicitly described as non-independent.
3. Every round has one immutable `manifests/<round>.json`; creation refuses an
   existing path. The manifest includes the per-file and aggregate corpus
   digests, role identities, separation flag, and tuning seed.
4. A case cannot run unless every file in its directory matches the frozen
   manifest. A prior result cannot be overwritten; retry under a new round.
5. The runner removes any stale output immediately before invoking Guard and
   accepts only a newly produced record whose timestamp falls within that
   invocation.
6. Both runner and evaluator execute `verify-record`. They also bind tool and
   schema versions, canonical candidate digest, effective command/timeout and
   allow policy, expected verdict, and expected reason code.
7. The evaluator rejects missing and extra JSON outputs. v0.2 requires one
   timing sidecar per case and publishes median time-to-verdict.
8. Results are append-only. Corrections, policy changes, new cases, or engine
   changes create a new round and a new manifest.

## Required publication order

1. Commit the completed cases and blind human truth.
2. Generate, commit, and push the round manifest.
3. Record the public manifest commit in the round notes.
4. Execute the tuning subset, if any. Policy changes after this step require a
   new manifest unless they were predeclared as tuning-only.
5. Execute held-out cases once.
6. Run the evaluator and publish raw records, timing sidecars, and results.

Git history proves ordering; branch and protocol-tag protection prevent silent
rewrites. A second GitHub account controlled by the author does not constitute
an independent labeler or auditor.

## Round 1 admission gate

Round 1 may begin only after all conditions are true:

- 50–100 sourced cases are complete and license/provenance fields are present;
- a distinct blind labeler has accepted the labeling hand-off;
- role identities and deterministic tuning seed are recorded in the manifest;
- the manifest commit is public before any held-out Guard execution;
- CI is green on the exact manifest commit.
