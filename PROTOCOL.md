# Evaluation protocol v0.3

Protocol v0.3 is the evaluator-hardening version. It retains the frozen
labeling, manifest, case-execution, and semantic-record contracts, but replaces
the unsound v0.2 metric implementation with fail-closed corpus preflight,
fixed denominators, exact-pair conformance, evidence integrity, and explicit
admissibility. Tags `protocol-v0.1` and `protocol-v0.2`, their manifests, and
their round outputs remain immutable historical provenance; they are not moved
or rewritten. See [`ERRATA.md`](ERRATA.md) for the non-retroactive correction.

The root `README.md` is itself a byte-frozen input of the separate
`oss-pilot-04` study. Its historical “current protocol v0.2” sentence is
therefore not rewritten in place. This document, `ERRATA.md`, and `STATUS.md`
are the authoritative v0.3 evaluator documents; changing that README requires
a separately pre-registered successor OSS-study manifest.

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
6. Before acquiring the engine or reading any result, the evaluator parses
   every manifest-selected `case.json` once and validates the complete
   closed-world metadata schema. A malformed, duplicated, unknown, incomplete,
   or truth-inconsistent corpus suppresses all scoring.
7. The immutable corpus plan fixes every case, expected main run, required
   exception run, ecosystem, and change-class denominator before result
   inventory is inspected. Missing outputs remain non-matching rows in those
   denominators; they can never disappear from a rate.
8. Conformance means equality of the complete expected
   `(verdict, reason_code)` pair for each required run. Verdict shape alone,
   `ERROR`, an `unsupported` classification, or a hard rejection with the
   wrong reason code is not success.
9. Each JSON object is parsed once by the evaluator. Read, syntax, shape,
   inventory, timing, attestation, identity, candidate, policy, schema, and
   `verify-record` failures are structured evidence-integrity errors. Boolean,
   negative, or non-finite timing values are invalid.
10. Conformance and evidence integrity are reported separately. An exact pair
    does not repair invalid evidence, and valid evidence does not turn a
    mismatched pair into conformance. Admissibility requires both an exact pair
    and valid evidence. Either class of failure makes evaluation fail closed.
11. Both runner and evaluator execute `verify-record`. They bind tool and
    schema versions, canonical candidate digest, effective command/timeout and
    allow policy, and record provenance; the pure evaluation model separately
    compares the exact expected pair.
12. The evaluator rejects missing and extra JSON outputs. v0.2 and v0.3 require
    one timing sidecar per case and publish median time-to-verdict.
13. Results are append-only. Corrections, policy changes, new cases, or engine
    changes create a new round and a new manifest.
14. Every required run ends in exactly one closed terminal status: `EXACT`,
    `MISSING`, `INVALID_EVIDENCE`, `WRONG_REASON`, `UNEXPECTED_PASS`,
    `UNEXPECTED_REJECTED`, `UNEXPECTED_FAIL`, `UNEXPECTED_ERROR`,
    `UNEXPECTED_TAMPERED`, or `UNKNOWN_VERDICT`.

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

Round 1 under v0.3 may begin only after all conditions are true:

- 50–100 sourced cases are complete and license/provenance fields are present;
- a distinct blind labeler has accepted the labeling hand-off;
- role identities and deterministic tuning seed are recorded in the manifest;
- the manifest commit is public before any held-out Guard execution;
- CI is green on the exact manifest commit.
