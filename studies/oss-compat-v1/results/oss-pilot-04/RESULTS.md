# OSS compatibility study — oss-pilot-04

> **Repeated same-owner engineering evidence only.** This corpus had prior
> product-phase exposure; it is not held-out validation, an independent audit,
> a population accuracy estimate, or evidence of generalization.

- Frozen engine: `v3.5.2` (`a370fac23233ea6f317d5d7e5347389197fc936bd9b5903c685b1d3755e0046f`)
- Repositories: 6; cases: 12
- Guard invocation coverage: 12/12; verified records: 12/12
- Product-outcome denominator: 12 verified Guard records; fixed conformance denominator: 12 repeated engineering cases
- Source-only conformance: 4/6
- Protected test/CI policy trips detected: 6/6
- Green reconstructed baselines: 4/6
- Infrastructure errors: 2
- Evidence integrity: valid
- Canonical ordering: first API-visible dispatch for the frozen commit
- Owner-deleted prior runs detectable: no
- Preserved Actions artifacts: 12/12 locally API-digest-bound

| Case | Repository | Expected | Observed | Result |
|---|---|---|---|---|
| `cjson-pr-1006-source-only` | DaveGamble/cJSON | `PASS/tests_passed` | `PASS/tests_passed` | conformant |
| `cjson-pr-991-test-edit` | DaveGamble/cJSON | `REJECTED/protected_harness_edit` | `REJECTED/protected_harness_edit` | conformant |
| `express-pr-7265-source-only` | expressjs/express | `PASS/tests_passed` | `PASS/tests_passed` | conformant |
| `express-pr-7377-test-edit` | expressjs/express | `REJECTED/protected_harness_edit` | `REJECTED/protected_harness_edit` | conformant |
| `fmt-pr-4822-source-only` | fmtlib/fmt | `PASS/tests_passed` | `ERROR/no_test_verdict` | problem |
| `fmt-pr-4825-test-edit` | fmtlib/fmt | `REJECTED/protected_harness_edit` | `REJECTED/protected_harness_edit` | conformant |
| `fzf-pr-4734-source-only` | junegunn/fzf | `PASS/tests_passed` | `PASS/tests_passed` | conformant |
| `fzf-pr-4797-test-edit` | junegunn/fzf | `REJECTED/protected_harness_edit` | `REJECTED/protected_harness_edit` | conformant |
| `requests-pr-7498-source-only` | psf/requests | `PASS/tests_passed` | `PASS/tests_passed` | conformant |
| `requests-pr-7502-test-edit` | psf/requests | `REJECTED/protected_harness_edit` | `REJECTED/protected_harness_edit` | conformant |
| `ripgrep-pr-3464-source-only` | BurntSushi/ripgrep | `PASS/tests_passed` | `ERROR/setup_failed` | problem |
| `ripgrep-pr-3467-test-edit` | BurntSushi/ripgrep | `REJECTED/protected_harness_edit` | `REJECTED/protected_harness_edit` | conformant |

## Interpretation boundary

A PASS means the frozen repository suite and policy accepted that exact
change in the captured environment. It does not prove the change or upstream
project universally correct or secure. A protected-harness REJECTED result is
a policy escalation, not an accusation that the upstream contributor cheated.
These repeated cases had prior product-phase exposure and do not constitute
a held-out sample or increase the unique sample size beyond 12.

## Study outcome findings

- fmt-pr-4822-source-only: outcome mismatch: expected PASS/tests_passed, got ERROR/no_test_verdict
- fmt-pr-4822-source-only: source-only case has no green reconstructed baseline
- ripgrep-pr-3464-source-only: outcome mismatch: expected PASS/tests_passed, got ERROR/setup_failed
- ripgrep-pr-3464-source-only: source-only case has no green reconstructed baseline
- ripgrep-pr-3464-source-only: source-only case did not run the declared suite
