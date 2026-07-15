# OSS compatibility protocol v0.1: invalid attempt

- Run: [29386936311](https://github.com/EvoRiseKsa/evoom-guard-eval/actions/runs/29386936311) (attempt 1).
- Frozen commit: `9b7bd9e1fe6a01fe75ddf1676f59e9eddebd5822` via `oss-protocol-v0.1`.
- Classification: `invalid_before_measurement`.
- All 12 matrix jobs passed canonical-dispatch and frozen-identity checks, then failed while installing the trusted execution boundary.
- Every `Run frozen case` step was skipped. No Guard invocation began.
- Every product-artifact upload was skipped; the Actions API reports zero artifacts.

## Observed infrastructure failure

`OSS EXECUTION BOUNDARY FAILED: real tool is writable by the untrusted uid: /usr/local/bin/cmake`

This run is **not** a 0/12 product result. It supports no inference about EvoOM Guard compatibility, acceptance, rejection, or verifier quality. The API snapshots and original Actions log ZIP are retained only as evidence of the invalid attempt.
