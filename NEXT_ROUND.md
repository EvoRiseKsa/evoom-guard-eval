# Next evaluation round: v3.7+ boundary

The public material in this repository is immutable historical evidence for
the v3.5.2 engine. It must not be retargeted, relabelled, or used to claim a
result for Trusted Finalizer or Artifact Admission features introduced later.

## What moves to a private evaluation workspace

The next round will begin in a restricted private workspace. It may hold
unpublished candidate selection, held-out/red-team cases, human rationales,
ground-truth labels, target-access details, and non-public pull-request
metadata. It must never contain GitHub, customer, or finalizer credentials.

The privacy boundary protects the integrity of a blind evaluation; it is not a
claim that private data makes the public engine unreviewable.

## Preconditions before execution

Before the first v3.7+ evaluation run, record and freeze:

1. the exact released Guard asset and SHA-256;
2. the exact policy and verifier-pack identity/digest for each track;
3. a corpus manifest and a separation between any tuning set and held-out set;
4. independent human `truth` labels and rationales created before a runner sees
   Guard results; and
5. the identity and role separation of labeler, runner, and reviewer.

The MANA account is controlled by the project owner. It can provide a
technical review role, but it does not satisfy an independent-labeler or
independent-evaluator requirement.

## Public output after a round

When a round is complete, publish only what is safe and needed to reproduce
the claim: a protocol version, engine/policy/pack digests, a sanitized corpus
manifest or committed-case hashes, labeler/runner separation statement,
aggregate and per-case result categories, failure classifications, exact
verification commands, and evidence checksums. Do not publish credentials,
private target metadata, or an unreleased held-out corpus before the evaluation
has closed.

## Claim boundary

Even a completed private round is not automatically an independent audit or a
field-rate estimate. Those claims require an adequately described sampling
method and genuinely independent labelers or replicators. The public output
must state its population, exclusions, failure/infrastructure-error rate, and
all material limitations.
