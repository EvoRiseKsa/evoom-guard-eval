# OSS compatibility protocol v0.1

This directory is a **same-owner real-world compatibility and conformance
study**. It is not Round 1, not third-party validation, and not an estimate of
accuracy across open-source software. It uses a publicly frozen canonical-run
protocol, but it is not blind or model-independent: static-policy and harness
validation occurred during study construction.

## Question under test

Can the frozen EvoOM Guard v3.5.2 artifact replay ordinary changes from six
unrelated, well-known repositories while:

1. accepting source-only changes whose frozen, study-declared repo-native suite
   profiles stay green; and
2. refusing to run changes that edit an existing test or CI workflow under the
   default protected-harness policy?

The answer applies only to the named cases, revisions, policies, and captured
environments.

## Frozen scope

- Engine: `v3.5.2`, `evo-guard.pyz` SHA-256
  `a370fac23233ea6f317d5d7e5347389197fc936bd9b5903c685b1d3755e0046f`.
- Record schema: `1.11`.
- Study: `oss-pilot-01`.
- Protocol tag: `oss-protocol-v0.1`.
- Roles: curator and runner are both EvoRiseKsa; `independent=false`.
- Corpus: 12 verbatim historical upstream diffs, two from each repository.
- Positive cases use `baseline_evidence` so the same suite and setup run on the
  reconstructed base and candidate. Policy-trip cases are expected to stop at
  the static gate before setup or tests.

## Publication order

1. Commit the protocol, selection, exact diffs, provenance, policies, and
   environment declarations.
2. Generate `manifests/oss-pilot-01.json`; it refuses overwrite.
3. Merge that manifest and make CI green before the first canonical study
   workflow execution.
4. Tag the frozen protocol/manifest commit and protect `oss-protocol-v*` tags.
5. Manually dispatch the read-only Actions matrix from the exact
   `oss-protocol-v0.1` tag. A preflight query to the Actions API requires the
   current run to be the chronologically first API-visible `workflow_dispatch`
   for the frozen workflow commit; the exact protected tag ref, workflow ref,
   run ID, and attempt 1 are then bound into every envelope. Later API-visible
   dispatches and reruns fail closed. The API cannot reveal an earlier run that
   the repository owner deleted, so this ordering check is same-owner evidence,
   not an append-only timestamp or external notarization. Failed jobs are
   retained, not rerun into a preferred result. No user secrets and no
   `pull_request_target` are permitted.
6. Publish every raw record, stdout/stderr, timing, and run envelope. A failed
   or infrastructure case is retained; it is never silently replaced. If the
   harness fails before Guard emits a record, it still writes a failure
   envelope and logs rather than fabricating a verdict.
   GitHub retains the source archives for 90 days; publication also preserves
   the verified archive bytes and their API-reported SHA-256 digests.
   The frozen materializer requires exactly 12 named artifacts from the
   canonical run and exactly 12 corresponding attempt-1 Jobs API records. It
   requires the named checkout, runtime setup, canonical-dispatch, identity,
   boundary installation, case, cleanup, and official upload steps; checks job
   conclusions against the case steps; checks artifact IDs, run/head bindings,
   byte sizes and API digests; rejects unsafe ZIP entries; and only then extracts
   them atomically.

## Selection and truth limits

Selection is purposive and stratified, not random. Popularity makes the
integration environments recognizable; it does not make six repositories
representative of all projects. Upstream merge status is provenance, not a
proof that a change is universally correct. Static-policy and harness checks
were used while constructing the study, before its public freeze and first
canonical workflow execution. The design is therefore not blind or
model-independent. The curator assigned these same-owner dispositions as part
of that construction:

Eligibility also required a named redistribution-compatible license, no
credentials or privileged services, a text-only first-parent merge supported
by the harness, and a study profile expected to fit the profile-aware watchdog
(at most 90 minutes including harness grace) within the 120-minute Actions job
limit. These constraints deliberately bias the sample toward runnable projects
and limit generalization.

- `admit`: verbatim source-only upstream change; expected `PASS/tests_passed`.
- `escalate`: verbatim upstream change that edits tests or CI; expected
  `REJECTED/protected_harness_edit` under the frozen default policy.

No population accuracy, false-positive, or independent-audit claim may be
derived from this study.

## Runtime boundary

Jobs run on GitHub-hosted `ubuntu-24.04` with `contents: read`, `actions: read`,
no user secrets, and full-SHA-pinned Actions. The short-lived repository token
is exposed only to the preflight Actions-API query. The whole harness then runs
as root under `env -i` with only the frozen GitHub identity fields and trusted
tool paths; no `GITHUB_TOKEN`, `ACTIONS_RUNTIME_TOKEN`, artifact service token,
or runner credential is passed to repository code.

The source repositories are executable third-party code. Every setup/test
command is routed through the root-installed frozen boundary. Only the
ephemeral `evo_repo_*/repo` or `evo_baseline_*/repo` tree is transferred to a
dedicated system uid. The judge parent, protocol checkout, source cache, engine,
configuration, and result tree stay root-owned. A root PID 1 supervises a new
PID/mount-proc namespace; `setpriv` clears groups and all capability sets,
enables `no_new_privs`, applies process/file limits, and launches from a
credential-free allowlisted environment. The supervisor reaps detached
descendants, while a host-side process record and an unconditional uid cleanup
provide two additional kill paths. The result tree remains root mode `0700`
until cleanup proves there are no residual untrusted processes; only then is it
released to the runner uid, and upload is skipped unless that cleanup succeeds.
The installation step runs a live self-test that checks uid/gid/capability/env
state, a detached daemon, forbidden writes, and the exact JUnit channel. A
separate privileged Ubuntu integration test also executes real pytest and kills
the host wrapper to exercise the parent-death chain.

For pytest, Guard's exact `judge-result.xml` is exclusively pre-created in the
root-owned parent and made writable to the test uid, then reclaimed by root;
the uid cannot create sibling files. This prevents path replacement and access
to publication outputs, but it does **not** make the JUnit content adversarially
unforgeable: the same test process still writes it. That matches the frozen
`same_process_candidate_writable` assurance claim. This is a compatibility
study over historical changes, not an adversarial execution attestation.

The boundary is not a VM, gVisor, seccomp, filesystem, or network sandbox. The
untrusted uid can read ordinary world-readable runner files, use the live
network, and shares the host kernel; kernel escape and network side effects are
outside the guarantee. npm *install* lifecycle scripts are disabled via
`--ignore-scripts`, while the selected `npm test` project script is intentionally
executed. Network is needed for dependency acquisition in four profiles and is
therefore declared, not falsely described as isolated. Python and Node
dependency resolutions are live and not fully captured or hermetic. The runner
label, image metadata exposed by GitHub, OS release, architecture, and tool
versions are captured, but the mutable runner image is not pinned by digest.

The selected commands are study profiles, not the complete upstream CI
matrices. In particular, Requests omits doctest/coverage variants, fzf runs Go
tests without its Ruby integration matrix, and the C/C++ profiles use one GCC
and CMake configuration. Results apply only to these declared commands.

Each Guard command phase has the case policy timeout. Because baseline evidence
may run setup and test for both candidate and reconstructed base, the outer
watchdog covers four phases plus ten minutes of harness grace (90 minutes for
the 1200-second C++/Rust profiles). The Actions job limit is 120 minutes so the
failure envelope and artifact upload retain their own margin.

## Validity gates

The study is invalid if any of the following occurs:

- a case, expectation, policy, or manifest changes after the first run;
- a candidate diff does not reproduce exactly from its pinned base/head pair;
- the manifest inventory differs from the working inputs;
- a result is overwritten, omitted, or replaced after failure;
- `RUN.json`, a preserved archive, its live Actions API metadata/digest, or its
  safely extracted case bytes disagree;
- case artifacts come from different GitHub run IDs or any run attempt other
  than attempt 1;
- the current run is not the Actions-API-verified first API-visible dispatch for
  the frozen workflow commit, or it did not execute from the exact protected
  tag ref;
- `verify-record` rejects a published verdict;
- an upstream PR, issue, or comment is created by this experiment;
- the result is described as independent or universally representative.

Product failure gates are stricter than aggregate scoring: any known protected
test/CI edit receiving `PASS`, or any expected source-only case silently
receiving `PASS` without a verified record, is reported individually.

Publication integrity and product conformance are separate. Missing, altered,
cross-run, or unverifiable evidence makes CI fail. An integrity-valid negative
product outcome remains in `SUMMARY.json` and `RESULTS.md` and is publishable;
CI must not erase or prevent publication of that canonical negative result.

The public summary links the canonical Actions run. Every extracted byte must
match a preserved ZIP whose SHA-256 equals the digest served by GitHub's Actions
API; one required CI job rechecks the live API metadata. This closes local
envelope substitution, but it is not third-party notarization: the repository
owner still controls the workflow and publication, GitHub is the external
platform of record, an owner-deleted earlier run is not discoverable through
the runs API, and artifact availability is retention-bound. The study therefore
remains same-owner evidence and is not described as independent, append-only,
or universally tamper-proof.

## Reproduction

Before execution:

```bash
python harness/freeze_oss_cases.py --check
python harness/make_oss_manifest.py oss-pilot-01 --check
python -m unittest discover -s tests -v
```

The Linux boundary can be reproduced independently in a disposable privileged
Ubuntu container (it refuses to run this integration script on the host):

```bash
docker run --rm --privileged \
  -e EVOOM_BOUNDARY_CONTAINER_TEST=1 \
  --mount type=bind,src="$PWD",dst=/src,readonly \
  ubuntu:24.04 bash /src/tests/oss_boundary_integration.sh
```

After the manifest commit is public, the manual workflow runs each case with
`harness/run_oss_case.py`. Materialize the exact canonical run through the
Actions API, verify the archived bytes again, and then evaluate:

```bash
python harness/materialize_oss_artifacts.py \
  --run-id <canonical-first-api-visible-dispatch-id> \
  --results studies/oss-compat-v1/results
python harness/materialize_oss_artifacts.py \
  --run-id <canonical-first-api-visible-dispatch-id> \
  --results studies/oss-compat-v1/results \
  --verify-only
python harness/evaluate_oss.py \
  --study oss-pilot-01 \
  --results <artifact-root> \
  --github-run-id <canonical-first-api-visible-dispatch-id> \
  --write
```

The evaluator reports per-axis conformance and timing; it deliberately does
not emit a single marketing accuracy number.
