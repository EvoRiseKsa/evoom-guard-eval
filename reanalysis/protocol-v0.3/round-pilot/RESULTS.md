# Protocol v0.3 reanalysis — `round-pilot`

This is a deterministic same-owner reanalysis of immutable historical inputs. It is not independent validation and it does not rewrite a tag, manifest, raw record, or historical result.

## Three independent axes

| Axis | Result | Fixed denominator |
|---|---:|---:|
| Exact `(verdict, reason_code)` pairs | 14 | 14 |
| Evidence-valid records | 14 | 14 |
| Admissible records (exact + valid evidence) | 14 | 14 |
| Exact cases | 10 | 10 |
| Admissible cases | 10 | 10 |

## Terminal classification

| Status | Runs |
|---|---:|
| `EXACT` | 14 |
| `MISSING` | 0 |
| `INVALID_EVIDENCE` | 0 |
| `WRONG_REASON` | 0 |
| `UNEXPECTED_PASS` | 0 |
| `UNEXPECTED_REJECTED` | 0 |
| `UNEXPECTED_FAIL` | 0 |
| `UNEXPECTED_ERROR` | 0 |
| `UNEXPECTED_TAMPERED` | 0 |
| `UNKNOWN_VERDICT` | 0 |

## Corrected interpretation

The earlier evaluator implementation corrupted the method used to derive published metrics: mismatched reasons could enter a numerator, missing outputs could shrink a denominator, and some malformed evidence did not fail closed. Those computation paths are therefore not accepted as protocol-v0.3 evidence.

Recomputing from the unchanged bytes gives the exact, evidence-valid, and admissible counts above. This does not turn the author-selected 10-case pilot into a field-rate estimate, blind evaluation, or third-party audit.
