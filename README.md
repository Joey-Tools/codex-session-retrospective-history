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
runs/<mode>/<w00>/<w01>/.../<w31>/<window>/<r00>/<r01>/.../<r31>/
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
single date or an ascending date range in the schema-defined path format. The
publisher computes a canonical SHA-256 routing digest from the mode/window tuple
and emits its 32 bytes as `<w00>` through `<w31>`. A logical `run_id` is exactly
64 lowercase hexadecimal characters and is emitted as the 32 two-hex-digit
components `<r00>` through `<r31>`; concatenating them must reproduce the
manifest value. These fixed-depth radix routes keep every run-bearing Git tree
bounded to at most 256 children. Do not add descriptive path components or
replace the fixed artifact basenames.

`session-retrospective-v2.schema.json` is the root union and shared vocabulary
for all eight artifact targets. `retained-manifest-v2.schema.json` is the
standalone manifest entry point and resolves its shared definitions from the
root schema. JSONL targets validate one decoded row at a time; the report target
validates the complete decoded Markdown document.

## V2 Publication Roles

Publication roles describe orchestration, not additional path levels or schema
variants. Every role must publish and validate an independent fixed eight-file
bundle under the fixed-depth radix path above.

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

CI uses Python 3.12 and the exact v2 schema-validation dependency set. Install
it before running tests or validators:

```bash
python -m pip install --requirement requirements-v2.txt
```

Run the full test suite and validate the current retained-history tree:

```bash
python -m unittest discover -s tests
python scripts/validate_retained_history.py --root .
```

For a proposed append-only change, make the complete base and head history
available locally and validate the explicit range:

```bash
python scripts/validate_retained_history.py \
  --root . \
  --base-rev "$BASE_REV" \
  --head-rev "$HEAD_REV"
```

The range command also validates the current tree. It requires the head to be a
fast-forward descendant of the base and rejects v2 artifact modification,
deletion, rename, partial-bundle addition, or non-atomic publication. Pull
request CI checks out full history and supplies the PR base and head SHAs.
