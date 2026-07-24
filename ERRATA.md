# Evaluator errata and historical re-verification

## Scope

This erratum corrects the evaluator for protocol v0.3 and later. It does not
move either historical protocol tag and does not rewrite a manifest, raw
record, result table, checksum, or other published round output. The original
v0.2 metric-computation path is methodologically corrupted and must not be used
as evidence merely because it happened to return a plausible number.

The v0.2 evaluator had three fail-open implementation defects:

1. Its per-ecosystem “as-labeled” heuristic inferred success from the absence
   of selected failure words. `ERROR`, `unsupported`, or a verdict with the
   wrong `reason_code` could therefore enter the numerator. V0.3 accepts only
   the exact expected `(verdict, reason_code)` pair.
2. Main and exception denominators were incremented while iterating files that
   existed. A missing output could shrink a denominator. V0.3 fixes all
   denominators from the preflighted manifest corpus and represents a missing
   required output as a non-matching row.
3. Invalid result JSON could escape as a traceback, Python booleans passed the
   numeric timing check, and corpus-metadata errors did not stop later scoring.
   V0.3 parses each JSON object once with structured errors, rejects boolean
   timings, and suppresses scoring whenever corpus preflight fails.

Conformance and evidence integrity are now independent report dimensions, and
admissibility requires both. Exact output classification cannot cure a failed
attestation or `verify-record` check, and valid evidence cannot cure a
classification mismatch. Every required run receives one status from the
closed v0.3 terminal vocabulary.

## Historical round-pilot

The immutable `round-pilot` bytes were re-read under v0.3. All 14 required
records across the 10 fixed cases match their frozen expected
`(verdict, reason_code)` pairs exactly: **14/14**. All 14 also pass the v0.3
evidence-integrity checks, so the admissible-record count is **14/14**.

That agreement does **not** validate the old computation path. The historical
metric table remains preserved as provenance, while evaluator-derived claims
are superseded by the deterministic files under
`reanalysis/protocol-v0.3/round-pilot/`. This is a same-owner reanalysis of ten
author-selected cases, not independent validation, a field false-positive or
false-negative rate, or a security guarantee.

This is not a blanket “fail-open” declaration about the raw pilot bytes: the
v0.3 reanalysis found no missing output, exact-pair mismatch, or invalid record
in that fixed inventory. It is a precise rejection of the defective historical
metric method. The original tags and every file under `results/round-pilot/`
remain untouched.
