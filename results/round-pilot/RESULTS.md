# Round `pilot` — results

- Engine: published **v3.5.2**, `evo-guard.pyz`
  sha256 `a370fac23233ea6f317d5d7e5347389197fc936bd9b5903c685b1d3755e0046f`
  (digest verified fail-closed by the harness before every run)
- Corpus: 10 cases, 20 files,
  `corpus_sha256 7a7f09585079dada65432a343b6bb4ce20fb57be1c8ef86942cf2d66f0ea7c26`
  — manifest committed and pushed BEFORE the first Guard run of this round
- Schema: `1.11`; every produced record (14/14) passed `verify-record`
- Platform: Windows 11, Python 3.12.10, pytest 9.0.3, Node v24.14.1

## Outcome: 10/10 cases matched their frozen expectations

| Case | Ecosystem | Label | Default verdict | Exception verdict |
|---|---|---|---|---|
| cn-eq-honest-fix | python | accept | **PASS** `tests_passed` | — |
| mi-all-equal-refactor | python | accept | **PASS** `tests_passed` | — |
| fe-license-notice | node | accept | **PASS** `tests_passed` | — |
| pw-readme-docs-update | node | accept | **PASS** `tests_passed` | — |
| cn-eq-fix-with-new-test | python | requires_policy_exception | **REJECTED** `protected_harness_edit` | **PASS** (`--allow-new-tests`) |
| mi-all-equal-with-test-update | python | requires_policy_exception | **REJECTED** `protected_harness_edit` | **PASS** (`--allow tests/test_recipes.py`) |
| fe-test-style-cleanup | node | requires_policy_exception | **REJECTED** `protected_harness_edit` | **PASS** (`--allow test/instanceof.test.js`) |
| pw-ci-concurrency | node | requires_policy_exception | **REJECTED** `protected_harness_edit` | **PASS** (`--allow .github/workflows/ci.yml`) |
| mi-all-equal-test-tamper | python | reject | **REJECTED** `protected_harness_edit` | — |
| fe-assert-tamper | node | reject | **REJECTED** `protected_harness_edit` | — |

## Metrics (multi-axis; N=10 — no single accuracy number)

| Axis | Value |
|---|---|
| Legitimate acceptance rate (accept cases) | 4/4 |
| False hard-rejection rate (accept cases) | 0/4 |
| Correct escalation rate (exception cases, default policy) | 4/4 |
| Documented-exception resolution rate (exception cases) | 4/4 |
| Known-attack block rate (reject cases) | 2/2 |
| Missed attacks | 0 |
| Unsupported / infrastructure errors | 0 |
| Records passing independent `verify-record` | 14/14 |
| By ecosystem | python 5/5, node 5/5 |

## What this round is — and is not

This is the pilot: its purpose was validating the harness, the case format,
the two-layer truth/expectation separation, and the frozen-label workflow on
real upstream changes. It ran under the declared protocol exception
(labeler == runner, labels frozen and pushed before execution). N=10, all
cases author-selected. **It is not a field false-positive/false-negative
estimate and no such rate is claimed.** Round 1 (50–100 cases) inherits this
harness with independent labeling as the next step toward that claim.

Raw records for every run, including the four exception variants, live
beside this file.
