# Codex Session Retrospective History

Private repository for redacted Codex session retrospective artifacts.

This repository stores collaboration-retrospective summaries, not raw Codex
history. It is intentionally private because even redacted summaries can expose
workflow patterns, repo names, and operational context.

## Layout

```text
reports/
  daily/YYYY/MM/DD.md
  weekly/YYYY/MM/DD.md
  baseline/90-day-windows/YYYY-MM-DD_to_YYYY-MM-DD.md
data/
  episodes/YYYY/MM/episodes.jsonl
  turn_flags/YYYY/MM/turn_flags.jsonl
  trends/YYYY/MM/trend_report.json
  manifests/YYYY/MM/retained_manifest.json
retained/
  daily/{episodes.jsonl,turn_flags.jsonl,trend_report.json,retained_manifest.json}
  weekly/{episodes.jsonl,turn_flags.jsonl,trend_report.json,retained_manifest.json}
  baseline/{episodes.jsonl,turn_flags.jsonl,trend_report.json,retained_manifest.json}
schemas/
  session-retrospective-v1.schema.json
  retained-manifest-v1.schema.json
```

Artifact basenames are fixed to avoid leaking customer, repository, host,
session, or raw topic identifiers through Git paths.
Retained evidence host labels are also fixed: use only `local`,
`miku-bot-dev`, `hoteng-srv-01`, or `custom_source` in episode, source, and
trend artifacts. The `scope` label is reserved for coverage gaps such as
intentionally partial scans. Customer, repository, project, or ad hoc source
labels must be bucketed before artifacts reach this repository.

## Data Policy

Commit only redacted retrospective artifacts:

- episode/topic summaries
- flagged turn summaries
- trend JSON
- redacted source manifests
- daily, weekly, and baseline reports
- schemas and repo documentation

Do not commit raw rollout JSONL, full prompts, internal URLs, secrets, customer
data, proprietary code snippets, or unredacted tool output.

Before committing retained artifacts, run:

```bash
python scripts/validate_retained_history.py --root .
```

## V2 Admission Boundary

The repository-owned `pull_request_target` workflow provides baseline-owned
candidate feedback only. It must not handle `merge_group` events or authorize a
queue SHA: candidate repository code cannot be the authority that admits its
own formal-history mutation. That feedback pins CPython `3.13.12`, copies exact
`H` from the verified object store into a sealed execution tree, and runs
credential-free compile and unit-test commands as a nonprivileged UID before
the check can succeed. The trusted parent revalidates the source authority and
sealed tree after execution. This exact-`H` evidence is necessary feedback, but
it is not reusable as exact-`Q` admission evidence. Dependency installation
must preserve the pre-bound CPython target, executable digest, version, and
`pyvenv.cfg`; the venv is sealed against writes before UID drop. The fixed
commands use an explicit CLI `pycache_prefix` outside the read-only source tree.

Before branch policy enables the v2 merge queue and its `Trusted history gate`
required check, an external admission service must be installed. That service
validates the exact queue SHA from independently trusted code, publishes the
queue check through its bound GitHub App identity, and performs the history
authority compare-and-swap. Its trusted configuration supplies that dedicated
repository ID and App ID to `merge-group-snapshot --repository-id
--admission-app-id`; the GitHub Actions App is explicitly ineligible. Before
publishing success or attempting CAS, it must
materialize the exact `Q` tree with `prepare-runtime-execution`, run the fixed
CPython `3.13.12` compile and unittest commands without GitHub or CAS
credentials as a nonprivileged UID, revalidate with
`verify-runtime-authority`, and produce a parent-owned runtime receipt. The
receipt binds `B1`, `H`, `Q`, the `Q` and prospective trees, the structural
projection digest, Python executable and requirements digests, fixed command
digests, UIDs, empty credential environment, denied authority write access,
and successful exit codes. `admit-merge-group` recomputes the structural
projection and rejects a missing, stale, cross-`Q`, writable-authority, failed,
or otherwise mismatched receipt. Its required
`--expected-python-sha256` value comes from the external service's independent
trusted runtime configuration, never from the receipt or candidate tree. After
runtime validation, the command must reread the live pull request, queue ref,
repository merge configuration, active branch rules, branch protection, and
complete ruleset inventory. Every field and the resulting TCB digest must still
equal the original snapshot, including the immutable repository ID. All nested
GETs share one request-count, response-byte, and monotonic deadline budget. The
admission record binds that live-authority digest and a 30-second validity
window that starts before the first live read; the full response bodies and
validation must finish inside that window. The external service must
discard an expired record and repeat admission immediately before publishing
success or attempting CAS. Only that fresh admission record may feed CAS.
Until that external producer and receipt flow are proven, cutover is blocked
and the existing branch rules remain unchanged.

The external producer has a second, separate identity requirement. Its numeric
GitHub App ID and the fixed `retrospective-history-admission` slug must be
committed identically in `scripts/trusted_history_ci.py` and
`scripts/validate_retained_history.py`; an environment or repository variable
cannot supply or override that trust root. The tracked App ID is intentionally
unset during bootstrap development, so `history-v2-admission` fails closed
until the dedicated App exists and its real ID is reviewed and committed. The
one-time `bootstrap-v2-migration` authority does not use that App, but it is
valid only for the designated bootstrap candidate ref and only while the exact
predecessor marker set is present. Bootstrap cutover also requires both trusted
implementations to hold the same positive non-GitHub-Actions App ID and the
same fixed slug before any marker-removing transaction can be accepted.

The post-merge audit emits a schema-v3 provider receipt. It records a canonical
candidate-evidence object rather than a precomputed validation verdict. In the
bootstrap authority mode, the offline validator independently reopens clean
fixed snapshots for `B` and signed candidate `H`, verifies the bootstrap
signature role and single parent, and proves that `tree(H) == tree(S)` for the
provider squash `S`. In permanent history-v2 mode, the evidence binds the same
canonical admission JSON digest to both the candidate-`H` admission check and
the queue-`Q` gate check from the pinned App. The offline validator then reruns
the B1 candidate plan against `H` exactly once per default audit, carries the
validated squash coordinates into transaction validation under the same work
budget, recomputes the predecessor trust generation, and revalidates the exact
authorized `HEAD`, tree, and pristine checkout before and after retained-tree
validation. During validation, the frozen file snapshot and Git index must equal
the authorized tree's exact blob and mode inventory, while root object identity
and access policy remain stable. It then proves that the admitted prospective
and queue trees both equal `tree(S)`.
Decoded-object equality is insufficient: both checks must carry the exact same
SHA-256 digest, and every nested schema version is an exact integer.

Admission timing is ordered as `observation <= H check <= Q check < expiry`.
The `Q` check must complete no later than the recorded merge, but the merge may
finish after the admission TTL; the TTL constrains the authority decision, not
GitHub's subsequent merge latency. Failure to materialize either fixed snapshot
or to reprove any candidate property blocks the audit rather than trusting the
network collector's conclusion.

The post-merge default audit also binds the exact local squash object to
GitHub's read-only commit and pull-request APIs. Before any candidate dependency
or Python entry point runs, the audit uses the exact `before` revision's helper,
validator, and public keys to require a valid provider signature, exact payload
and signature equality, the `web-flow` committer, and one uniquely associated
merged same-repository pull request whose base and merge commit match the push.
The repository must use `PR_TITLE` for squash commit titles and `BLANK` for
squash commit messages. The resulting commit message is one line and must equal
the exact pull-request title, optionally followed by GitHub's canonical `(#n)`
suffix for that same pull request.
Only then may the validated candidate run in the disposable test tree. The
temporary receipt retains commit and pull-request provenance digests but no raw
author or committer identity, and an `always()` step removes it after use.
