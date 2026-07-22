# Codex Session Retrospective History

Private repository for redacted Codex session retrospective artifacts.

This repository stores collaboration-retrospective summaries, not raw Codex
history. It is intentionally private because even redacted summaries can expose
workflow patterns, repo names, and operational context.

## Compatibility And Layout

Version 1 retained history remains supported. The v1 schemas and the existing
`data/`, `reports/`, and `retained/` layouts continue to be validated and may
coexist with v2 runs; adding v2 support does not require rewriting v1 history.

### Version 1

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

V1 artifact basenames are fixed to avoid leaking customer, repository, host,
session, or raw topic identifiers through Git paths. V1 retained evidence host
labels are also fixed: use only `local`,
`miku-bot-dev`, `hoteng-srv-01`, or `custom_source` in episode, source, and
trend artifacts. The `scope` label is reserved for coverage gaps such as
intentionally partial scans. Customer, repository, project, or ad hoc source
labels must be bucketed before artifacts reach this repository.

### Version 2

Every v2 publication uses this path and contains exactly the same eight
artifacts:

```text
runs/<mode>/<window>/<run_id>/
  coverage.json
  episodes.jsonl
  manifest.json
  report.md
  summary.json
  topics.jsonl
  trend_report.json
  turn_findings.jsonl
schemas/
  session-retrospective-v2.schema.json
  retained-manifest-v2.schema.json
```

`<mode>` is one of `daily`, `weekly`, `baseline`, or `session`. `<window>` is a
single date or an ascending date range in the schema-defined path format. A
logical `run_id` is the canonical unpadded lowercase RFC 4648 Base32 encoding of
exactly 128 random bits. It has 26 characters and matches
`^[a-z2-7]{25}[aeimquy4]$`; the restricted final symbol rejects aliases with
nonzero unused bits. The path value, manifest `run_id`, and `run_ref` payload
must match exactly. Do not add descriptive path components, sharding levels, or
replace the fixed artifact basenames.

Each manifest names exactly one identity `key_id`. Every key-bearing artifact in
that bundle and every v2 bundle in the retained history must name that same key
generation. A mismatch blocks validation; v2 never treats it as permission to
rotate or silently rebuild history identity.

`session-retrospective-v2.schema.json` is the root union and shared vocabulary
for all eight artifact targets. `retained-manifest-v2.schema.json` is the
standalone manifest entry point and resolves its shared definitions from the
root schema. JSONL targets validate one decoded row at a time; the report target
validates the complete decoded Markdown document.

## V2 Publication Roles

Publication roles describe orchestration, not additional path levels or schema
variants. Every role must publish and validate an independent fixed eight-file
bundle under the append-only path above.

- A **standalone** run is independently scheduled, has no campaign parent, and
  is valid only when its complete publisher input fits one bounded preparation.
- A **campaign segment** is one bounded slice of a larger retrospective and is
  validated as a complete bundle before campaign aggregation. It owns no cursor
  or semantic-head successor.
- A **campaign root** is the aggregate campaign publication built after its
  segment set is fixed; it publishes one root bundle rather than nesting or
  copying segment directories.

All four modes may use campaign roles. A non-Baseline campaign must declare
`publication_campaign_reason: size_partition`; a Baseline campaign must declare
`publication_campaign_reason: baseline_window`. Every segment and root remains a
complete independently validated eight-artifact bundle, while only the root
counts as the retrospective/trend observation and owns state successors.

Campaign membership and lineage stay in schema-defined opaque references,
provenance, head bindings, and supersession fields where applicable. They must
not expose source-derived labels or raw identifiers in Git paths.

The history validator recomputes two domain-separated commitments. The
production-configuration root frames, in schema order, the four active
calibration/shadow receipt and model-era references. A campaign root frames the
campaign reference and count, then each segment's 1-based ordinal, run
reference, and already-validated retained bundle digest in ordinal order.
Segment-only prefixes are valid while a campaign is being assembled; once a
root exists, exactly one root and the complete contiguous segment set are
required. A root without segments, duplicate roots, or any commitment mismatch
is invalid.

Every retained template is re-rendered from its closed `template_id` and typed
slots. Both the stored `rendered_text` and `report.md` must match that canonical
rendering byte for byte; caller-provided prose is never used as renderer input.

### Episode Revision Transitions

Every `episode_record` is one immutable canonical revision. It binds the closed
`episode_revision_operation`, lineage ID, anchor, segmentation and policy
majors, sorted unique member turns, domain-separated member Merkle root and
count, presentation-range partition, generalized-content digest, predecessor
lineage metadata, and any transition-group or backfill evidence. The retained
history validator evaluates these fields against the complete predecessor graph
in both in-memory and indexed validation modes.

The operation set is closed:

- `create` has no predecessor and introduces one fresh lineage and nonempty
  membership not already owned by a compatible head.
- `extend` preserves lineage, anchor, both majors, and every predecessor member,
  and adds only later contiguous turns.
- `backfill` preserves the same identity and members, and adds only earlier
  turns or turns bound one-to-one to explicit, declared stable gap evidence.
- `split` is one atomic, contiguous-ordinal transition group from one current
  head to at least two deterministic successor identities. Its nonempty,
  pairwise-disjoint partitions must exactly cover the predecessor members, and
  each ordinal is the one-based bytewise sort position of that partition's
  member-turn root.
- `merge` consumes at least two distinct current heads and creates one
  deterministic successor whose members are the pairwise-disjoint exact union
  of all predecessors.

Current-head closure rejects forks, stale predecessors, overlapping split or
merge membership, partial transition groups, invented or removed members, and
non-deterministic successor identities. Root lineage IDs and anchors are unique;
a transition-group ID identifies exactly one atomic split or one merge, and one
predecessor cannot be consumed by multiple split groups. Across all compatible
current heads, each member turn has exactly one owner regardless of whether it
was introduced by `create`, `extend`, or `backfill`. A changed generalized
summary without a legal membership or lineage transition is not a revision and
is rejected.

### Retained Bundle Privacy

Privacy validation is a bundle operation over exactly the eight artifacts in
one canonical run directory. It enforces the complete basename inventory and a
64 MiB aggregate scan bound, runs the ordinary artifact validator once per file
in canonical basename order, then carries normalized detector input across JSON
values, JSONL rows, Markdown lines, and artifact boundaries. Concatenating
fragments without synthetic separators prevents a credential or encoded payload
from being hidden by splitting it across those boundaries. Findings retain
their per-artifact scope, while cross-boundary findings use the `__bundle__`
scope. A missing, duplicate, foreign-parent, non-byte, or oversized artifact set
fails before publication.

## Trust And Publication

Every formal v2 publication or admin change is delivered by pull request and
squash merge. Direct push is not a publication path. Git ancestry enforces the
append-only path and revision rules, while the publisher's identity is carried
inside each retained run rather than inferred from the final Git commit.

A publication pull request contains exactly one complete run. Campaign segments
and the campaign root therefore use separate ordered pull requests; a root can
be proposed only after every segment is already present on `master`. An admin
pull request may contain multiple authenticated admin commits, but every commit
must carry the same signed squash subject. Its net tree is validated as one
immutable merge plan and cannot contain retained runs.
A trust-root upgrade is the exception: it must contain exactly one
maintainer-signed commit under the separate protocol below.

CI imports only the checked-in public packets from
`retrospective-history-v2-admin-public.asc` and
`retrospective-history-v2-publisher.asc` in the trusted base. The admin bundle
contains the pinned maintainer and GitHub signing public keys. Private signing
keys are local authority material and must never be committed or consumed by
the workflow.

### Publisher Attestation

A publication commit adds exactly one complete eight-artifact `runs/**` bundle,
or one schema-defined campaign publication, and changes no admin or legacy
path. Its author, committer, and optional Git commit signature are checked only
for bounded, privacy-safe syntax. They do not prove publisher identity. This is
intentional: GitHub creates the final GitHub-signed commit during a required
squash merge, so the publisher's original Git signature cannot survive as the
signature of the final `master` commit.

Publisher provenance is the required `publisher_attestation` object in
`manifest.json`:

- `scheme` is exactly `openpgp-detached-v1`.
- `signer_fingerprint` is the trusted publisher key fingerprint.
- `signature` is a canonical ASCII-armored detached OpenPGP signature.

The signed payload is domain-separated and length-framed as follows:

```text
session-retrospective-publisher-attestation-v2
|| "R" || uint64_be(len(run_ref)) || run_ref
|| "D" || uint64_be(len(retained_bundle_digest_v2)) || retained_bundle_digest_v2
```

The retained bundle digest covers all eight artifacts using the canonical
manifest projection `omit-digest-and-publisher-attestation-v2`; the digest and
attestation fields are omitted from that projection to avoid a circular hash.
The detached signature then binds the run reference and that digest, and
therefore the complete retained bundle, to the publisher key imported from the
trusted base commit. Signature armor has no optional headers, uses canonical
64-column Base64 plus a verified CRC24 checksum, and contains exactly one v4
signature packet. Runtime validation accepts only the expected hashed creation
time and issuer-fingerprint subpackets, the matching unhashed issuer key ID, and
canonical algorithm-specific signature MPIs. Unknown, trailing, concatenated,
or otherwise ignored attestation bytes are rejected by both structured and
privacy validation before GPG verification.

Every publication commit and intermediate `runs/**` blob is checked against the
strict schemas, inventory, privacy policy, detached publisher attestation, and
range-global byte, line, node, depth, path, and object budgets. Add-then-delete
history cannot hide a raw or otherwise forbidden run artifact.

### Admin Role

An admin commit cannot touch `runs/**` and cannot be mixed with a publication
commit. It is limited to the validator's fixed schema, validator, test,
workflow, documentation, requirements, and key-material allowlist. Admin
validation bounds paths, objects, and bytes and uses the shared high-confidence
credential scanner. The scanner covers standard PKCS#8 and encrypted private
key blocks, structured binary OpenPGP Secret-Key and Secret-Subkey packets,
complete Authorization Bearer headers plus exact JSON/source/shell
`Authorization` key-value forms, GitHub and OpenAI tokens, AWS `AKIA`/`ASIA`,
Slack `xox*`, Google `AIza`, GitLab `glpat`, npm, and other explicit credential
forms without treating ordinary short Bearer examples or prefixed authorization
keys as secrets. Fixed candidate snapshots and every changed admin blob in the
range use this same scanner. The identical signed admin message and the derived
immutable squash subject are also scanned before a merge plan can be issued.

Every candidate admin commit requires the exact maintainer author and committer
metadata and is valid only with the administrator-specific maintainer
fingerprint. Exact identity matching covers the maintainer name and email;
ordinary independent Git author and committer timestamps and canonical timezone
offsets are accepted. GitHub's global signing identity is never candidate
authority. The exact `GitHub <noreply@github.com>` committer and trusted GitHub
fingerprint are accepted only by the single-commit default-branch validator for
the App-created final squash commit.

### Base-Controlled App Merge Transaction

The workflow uses `pull_request_target` only for pull requests targeting the
default `master` branch. Its workflow and executable validator come from the
exact trusted base commit. The pull-request title, draft flag, body, labels,
reviews, and merge-box choices are display or scheduling metadata; none is an
authorization input. A ready-for-review event may retry the same immutable
candidate after GitHub has refused to merge a draft, but it cannot authorize a
different tree, subject, base, or head.

Before any App token is created, a separate read-only job binds the event's
exact candidate SHA, removes checkout credentials, and copies only that tracked
tree into a Git-metadata-free validation root. With no repository secret or
GitHub credential in the executed environment, it installs the candidate's
hash-locked dependencies, compiles and tests the candidate Python, checks both
JSON schemas, runs checksum-pinned `actionlint`, and dry-runs both OpenPGP
exports while rejecting secret-key packets. The trusted job depends on this
gate and rejects the transaction if its fresh API resolution no longer equals
the validated SHA.

The transaction performs these operations in order:

1. Check out `github.workflow_sha` as the trusted base with
   `persist-credentials: false`, then mint a dedicated GitHub App token scoped
   to `Administration: read`, `Checks: write`, `Contents: write`, and `Pull
   requests: read` for this repository only.
2. Read the current PR route through the API and bind only the repository, PR
   number, base repository/ref/OID, and head OID. Require the workflow source to
   equal that base and the resolved head to equal the no-secrets gate output. A
   rerun after a lost merge response recovers the original base from the one
   parent of the recorded squash commit.
3. Check out the exact bound head as data into a separate directory. Require
   the base to be its ancestor and verify every trust-root path as a case-exact
   regular blob in the base tree.
4. Create an isolated Python environment from the trusted base and install only
   the universally hashed lock with `--require-hashes` and
   `--only-binary=:all:`.
5. Dry-run the base-controlled OpenPGP files, reject secret-key packets, import
   the exact maintainer, GitHub, and publisher public fingerprints into a new
   `GNUPGHOME`, and require its secret-key listing to remain empty.
6. Import and execute only base-controlled Python. The candidate checkout is a
   Git object database and is never imported, sourced, or executed.
7. Materialize the fixed head tree and run the complete retained-history
   validator against the full base-plus-head history.
8. Build a canonical immutable merge plan containing `base_oid`, `head_oid`,
   `head_tree_oid`, `trust_generation`, and `squash_subject`. The trust
   generation is a domain-separated commitment over every sorted trust-root
   path, mode, type, and blob OID in the base. A publication subject is derived
   from the one validated run; ordinary admin commits must all carry one
   identical signed subject; a trust-root upgrade uses its fixed signed subject.
9. Read branch protection and require strict required status checks, enforced
   administrators, linear history, disabled force pushes/deletions, no mutable
   review requirement, empty user/team push restrictions, and exactly the
   dedicated App in the allowed App set. The immutable candidate check must be
   pinned to that App as its expected source. Query all active rules applying to
   `master` and require an empty result, so no uninspected ruleset bypass can
   overlap this transaction.
10. Create or recover `Retrospective history immutable candidate` as an
    `in_progress` check whose deterministic external ID binds the complete merge
    plan. Append and fsync the local `prepared` and `check_created` WAL records.
    Enumerate all checks with that identity and require this check to be the sole
    active one; observed competition fails closed. The incomplete check cannot
    satisfy branch protection.
11. Immediately re-read branch protection, current PR head/base, the `master`
    ref, candidate tree, and remote trust generation. Reconfirm sole ownership,
    complete the exact check as success, confirm it through its direct API
    identity, and enumerate once more to require it to be the sole active intent
    before appending and fsyncing `merge_intent`. The completed check is the
    remote durable intent marker and strict up-to-date primitive; App-only
    `master` restrictions prevent an ordinary actor from using it.
12. Only the process that just established that unique intent and locally
    recorded it may issue one GitHub merge request with `merge_method: squash`,
    `sha: head_oid`, the immutable subject as `commit_title`, and an empty
    `commit_message`. Any observed competing check aborts before that request.
    The head SHA is the API CAS; strict required status checks, which this App
    must not bypass, reject a base that moved after validation. A recovery
    process that observes existing merge intent is query-only and never repeats
    the merge call.
13. Reconcile the result even when the merge response is lost. Require the PR
    to report the dedicated App bot as `merged_by`; require the resulting commit
    to have exactly the planned base parent, candidate tree, and one-line
    squash subject; and require that commit to be the current `master` or its
    ancestor. Fsync `completed` with the exact receipt. Only a definitive
    non-merge may fail the check and record `retry_safe`; an uncertain result
    retains merge intent and blocks retries.

The local publication WAL is an owner-only directory of append-only,
digest-chained generation records. Each record is written to a mode-`0600`
temporary file, fsynced, atomically renamed, and followed by a directory fsync;
the directory is mode `0700`. Generation zero must be `prepared`. Recovery
rejects truncated records, generation gaps, digest or immutable-scope changes,
illegal transitions, unknown entries, and unsafe file types or permissions.
Stale temporary files are removed before the chain is loaded. The WAL and merge
receipt live only in the workflow's `.trusted-merge-state` directory and never
enter retained history.

The deterministic remote check survives runner loss when the local WAL does
not. `in_progress` proves that no conforming process reached merge intent and
may be resumed. `completed/success` means a merge request might already have
been sent, so every later process only reconciles. A crash after that marker but
before the request can therefore leave the exact candidate inconclusive rather
than risk a duplicate side effect; recovery requires new, independently
validated authority instead of retrying the ambiguous request.

GitHub's Check Runs API does not provide atomic create-if-absent or uniqueness
for `external_id`. The repeated inventory and direct-identity reads therefore
provide fail-closed duplicate suppression for competition visible through the
API, not a formal global exactly-once guarantee under stale concurrent reads.
The WAL prevents a conforming transaction from reissuing after durable intent;
the merge request's head SHA, strict base enforcement, and exact-result
reconciliation remain the side-effect fences.

No success check creates an ordinary merge window: only the trusted App can
update `master`, and the App performs final reads, CAS merge, and result
reconciliation in one serialized transaction. If GitHub cannot enforce the
strict base condition or the App cannot prove the exact result, the transaction
does not claim authorization.

The same file also monitors every `master` push, but the push workflow definition
is loaded from event `after`; GitHub does not execute that YAML from `before`.
The monitor verifies `github.workflow_sha == after`, checks out `before` as the
validator/dependency/key source, checks out `after` as data, materializes the
fixed `after` snapshot, and validates the actual event range. Forced updates and
multi-commit updates fail. No Python helper, schema, dependency input, or key
from `after` is imported, but the after-controlled YAML orchestration means this
monitor is detection, not an immutable admission guard. It accepts ordinary
updates only when the protected trust root is unchanged and explicitly rejects
any claim that it can authorize the trust-root upgrade that controls itself.

For fork pull requests, including permitted private forks, the transaction reads
candidate objects through the base repository and never executes fork code. If
the event, object, key import, protection proof, App token, or API CAS is
unavailable, publication fails closed.

### Deployment And Bootstrap

The checked-in workflow is testable without an installed App. Deployment
requires a dedicated GitHub App installed only on this repository with
`Administration: read`, `Checks: write`, `Contents: write`, and `Pull requests:
read`. Configure `RETROSPECTIVE_HISTORY_MERGE_APP_ID` and
`RETROSPECTIVE_HISTORY_MERGE_APP_PRIVATE_KEY` as repository secrets. Enable
squash merge and disable merge commits and rebase merge.

Protect `master` with this exact App-only contract:

- Require `Retrospective history immutable candidate` from the dedicated App,
  with strict "branch must be up to date" semantics.
- Apply protection to administrators, require linear history, block force
  pushes and deletion, and leave required PR approvals disabled because mutable
  review state is not authorization.
- Restrict updates to exactly the dedicated App. The allowed user and team sets
  are empty; no administrator, repository role, user, team, or second App has a
  bypass path.
- Do not apply an active repository, organization, or enterprise ruleset to
  `master`. The App queries GitHub's effective branch-rules endpoint before the
  success check and again immediately before merge, and rejects every non-empty
  result. Branch protection is the sole merge-control policy, which makes the
  App identity and absence of human, role, team, deploy-key, or integration
  bypasses machine-testable.

The transaction tests exercise this protection shape, App identity, human and
ruleset bypass rejection, title/draft edits, head/base/trust-generation races,
WAL corruption, crashes around intent and merge effects, visible competing
checks, independent double invocation, lost responses, read-only recovery,
replay, and the final parent/tree/message receipt. Operators must also audit the
live branch protection JSON after every policy change. Ordinary resulting
`master` commits are monitored again against the same one-line message grammar.

### Protected Trust-Root Upgrade

The protected trust root consists of `.github/workflows/ci.yml`, the v2 lock and
input, both OpenPGP public-key files, both v2 schemas, all executable v2 history
modules, and `scripts/validate_retained_history.py`. Changing any one of these
paths activates a separate trust-root upgrade role:

1. The candidate range contains exactly one commit with subject `Upgrade
   session retrospective history v2 trust root`.
2. That commit uses the exact maintainer author/committer metadata and verifies
   only with the offline maintainer fingerprint. GitHub-signed admin metadata is
   not accepted for this role.
3. The immutable merge plan derives that fixed subject from candidate content;
   PR title and draft state remain informational.
4. The unchanged base transaction validates the fixed signed `base..head`
   candidate, re-reads the old trust generation, and the dedicated App performs
   the exact squash merge. Independent review happens before the maintainer
   creates the signed candidate; mutable PR approvals are not authority.
5. The resulting commit must match the old-base transaction receipt exactly.
   The after-controlled push monitor may reject its own trust-root replacement;
   that detection cannot override the reconciled App receipt.

This split permits deliberate validator or workflow upgrades without claiming
that candidate-controlled post-merge YAML can attest its own replacement.

The first migration cannot protect the pull request that introduces this
base-controlled workflow. Bootstrap therefore uses the exact historical
predecessor `97f236c56cbbf24776899178175e2603ecf30fb0`, the fixed message
`Bootstrap session retrospective history v2`, external review of the signed
candidate range, and pre-existing protected squash rules. After that squash
merge, install/configure the App and the App-only protection contract before
accepting any later v2 admin or publication pull request.
The GitHub-signed squash commit is the new trusted base; its author or signer is
not publisher provenance. The bootstrap merge's `push` job fails closed when
the event `before` commit does not yet contain the complete v2 trust root; that
first resulting `master` commit must therefore be checked by the same external
signed-candidate review. Once the trust root is present on `master`, ordinary
updates use the App transaction plus the after-controlled push monitor; later
trust-root changes repeat the protected upgrade protocol above.

Admin validation does not claim semantic zero-leak proof for arbitrary Python,
YAML, Markdown, or other source encodings. Standard source-code privacy and
secret review remains an independent protected-PR gate. The zero-leak invariant
is absolute for all retained `runs/**` artifacts and their intermediate history.

## Data Policy

Commit only redacted retrospective artifacts:

- episode/topic summaries
- flagged turn summaries
- trend JSON
- redacted source manifests
- daily, weekly, baseline, and session reports
- schemas and repo documentation

Do not commit raw rollout JSONL, full prompts, internal URLs, secrets, customer
data, proprietary code snippets, or unredacted tool output.

## Validation

CI uses Python 3.12 and a complete cross-platform hash lock for the exact v2
schema-validation dependency set. Create the environment only from a trusted
checkout and never invoke Python or pip from an untrusted checkout/import path:

```bash
cd "$TRUSTED_BASE"
python -I -m venv .venv-v2
.venv-v2/bin/python -I -m pip install \
  --only-binary=:all: \
  --require-hashes \
  --requirement requirements-v2.txt
```

Regenerate the universal lock from the direct input with the pinned command
recorded in `requirements-v2.txt`:

```bash
uv pip compile requirements-v2.in \
  --python-version 3.12 \
  --universal \
  --generate-hashes \
  --no-sources \
  --output-file requirements-v2.txt
```

Run the full test suite and validate the current retained-history tree:

```bash
.venv-v2/bin/python -m unittest discover -s tests
.venv-v2/bin/python scripts/validate_retained_history.py --root .
```

Whole-history v2 validation stores discovered paths and normalized cross-bundle
facts in a task-local SQLite index. Discovery commits at most 4096 new artifact
paths per transaction, bundle parsing admits at most 512 bundles per page, and
global supersession, campaign, revision-graph, trend, and publisher-attestation
checks consume indexed pages. Those values are page sizes, not repository
lifetime ceilings: every bundle admitted by the validated snapshot inventory is
classified while single-page memory and query work stay bounded. Per-directory
fanout, path, artifact, JSON, per-bundle row/byte, snapshot-transport, and
diagnostic limits still fail closed.

For a proposed append-only change, execute the validator script and dependencies
from a separate trusted base checkout, point `--root` at the candidate checkout,
and validate the explicit immutable range:

```bash
cd "$TRUSTED_BASE"
"$TRUSTED_BASE/.venv-v2/bin/python" \
  "$TRUSTED_BASE/scripts/validate_retained_history.py" \
  --root "$CANDIDATE_CHECKOUT" \
  --base-rev "$BASE_REV" \
  --head-rev "$HEAD_REV" \
  --write-merge-plan "$MERGE_PLAN_PATH"
```

The pull-request command requires the head to be a fast-forward descendant of
the base, validates the full fixed head snapshot, rejects v2 artifact
modification, deletion, rename, partial-bundle addition, multiple publication
runs, or non-atomic publication, and writes the deterministic immutable squash
subject, candidate tree, and trust generation. Tree validation materializes and
verifies a private snapshot
from fixed Git commit blobs, sanitizes inherited `GIT_*` repository and index
variables, and rechecks the exact checkout `HEAD` and clean status after the
scan. Mutable worktree files and PR metadata are never merge authority.
