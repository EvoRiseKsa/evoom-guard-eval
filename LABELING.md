# Independent labeling protocol (Round 1+)

This is the hand-off document for an independent labeler. Following it makes
a round's labels *independent*: the labeler never sees Guard output, and the
labels are frozen and hashed before the tool runs.

## Roles

- **Labeler** — assigns the truth for each case. Must not run EvoOM Guard,
  must not see any Guard verdict, record, or expectation for the cases being
  labeled, and must not be the person who runs the round.
- **Runner** — executes `harness/run_case.py` after labels are frozen. Must
  not change any label afterwards; a label found to be wrong is recorded as a
  labeling erratum in the results, never edited retroactively.

## What the labeler receives, per case

1. The source reference (repository/package, pinned version or commit).
2. The candidate change itself (`candidate.diff` or `candidate.txt`).
3. The change's upstream context (PR/commit message, linked issue) when it
   exists.
4. This protocol and the label vocabulary below. **Nothing else** — no Guard
   runs, no `guard_expectation`, no prior rounds' results for these cases.

## What the labeler writes (the `truth` block)

For each case, exactly:

```json
"truth": {
  "human_decision": "admit | block | escalate",
  "policy_expectation": "no_exception_required | documented_exception_required | unsupported",
  "rationale": "2-4 sentences in the labeler's own words",
  "labeled_by": "<name or stable pseudonym>",
  "labeled_before_guard_run": true
}
```

- `human_decision` answers: *would a responsible maintainer admit this
  change?* — nothing about Guard.
- `policy_expectation` answers: *does admitting it require a reviewed,
  documented exception* (it touches tests/CI/config) *or not?*
- The five-way `label` and the `guard_expectation` mapping are derived
  AFTERWARDS by the runner from the frozen truth via the contract table in
  the README — the labeler never writes Guard vocabulary.

## Freezing order (must be verifiable from git history)

1. Labeler delivers `truth` blocks; runner assembles `case.json` files.
2. Commit and push all cases. Run:
   `python harness/make_manifest.py <round> --labeler <identity> --runner
   <identity> --tuning-seed <published-seed>`. The command refuses equal roles
   unless a non-independent pilot explicitly uses `--allow-role-conflict`, and
   refuses to overwrite `manifests/<round>.json`.
3. Commit and push `manifests/<round>.json`. Verify it independently with
   `python harness/make_manifest.py <round> --check`.
4. Only after both commits are public: run the round
   (`harness/run_case.py` per case), then `harness/evaluate.py --round <round>`.
5. Commit raw records, timing sidecars, and `RESULTS.md`. Rounds are never re-scored; corrections
   are new rounds.

## Tuning vs held-out

Before the first run, the runner draws ~20% of case IDs (deterministic seed,
recorded in the round's RESULTS.md) as the tuning subset. Policy adjustments
may use tuning-case outcomes only; held-out cases are run once, with the
frozen policy, and never used to adjust anything.

## Conflicts of interest, stated plainly

A round whose labeler and runner are the same person (or the tool's author)
must say so in its RESULTS.md, as round-0 and round-pilot do. Independence
claims start only when the labeler is a distinct person following this
document.
