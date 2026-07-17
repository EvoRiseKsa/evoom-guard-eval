# Evaluation status and claim boundary

## Current target

The frozen protocol outputs in this repository target the published
`evo-guard.pyz` **v3.5.2** asset, SHA-256
`a370fac23233ea6f317d5d7e5347389197fc936bd9b5903c685b1d3755e0046f`.
This includes the historical `protocol-v0.1` and `protocol-v0.2` material and
the `studies/oss-compat-v1/` compatibility study.

The data here is therefore historical evidence about that pinned engine and
its declared policy/pack configurations. It is not evidence for a later engine
generation, including the v3.6 Trusted Finalizer architecture.

## What this repository can support

- Reproduction and inspection of the retained, declared runs.
- Engineering evidence about the exact pinned engine, corpus, policy, and
  recorded execution environment.
- Descriptive conformance for the explicitly named cases, subject to the
  protocol-specific limitations in [`PROTOCOL.md`](PROTOCOL.md) and
  [`studies/oss-compat-v1/PROTOCOL.md`](studies/oss-compat-v1/PROTOCOL.md).

## What it cannot support

- An independent audit or third-party validation: the evaluator and the tool
  owner are under the same account.
- A general field-accuracy, false-positive-rate, adoption, performance, or
  security guarantee.
- Validation of the Trusted Finalizer, its authority separation, or any
  artifact-bound admission claim introduced after v3.5.2.
- A larger sample size merely because an existing case or run is repeated.

## Rule for later engines

A v3.6-or-later evaluation must be a **new** versioned and pre-registered
round: declare the exact engine artifact, policy, verifier pack, source/context
binding claims, labels, corpus digest, and evaluator separation before
execution. It must publish new outputs under a new round identifier. It must
not edit, overwrite, reinterpret, or retarget existing tags, manifests, or
results.

The operational plan and public/private evidence boundary for that new round
are recorded in [`NEXT_ROUND.md`](NEXT_ROUND.md).
