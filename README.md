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
own formal-history mutation.

Before branch policy enables the v2 merge queue and its `Trusted history gate`
required check, an external admission service must be installed. That service
validates the exact queue SHA from independently trusted code, publishes the
queue check through its bound GitHub App identity, and performs the history
authority compare-and-swap. Its trusted configuration supplies that dedicated
App ID to `merge-group-snapshot --admission-app-id`; the GitHub Actions App is
explicitly ineligible. Until that producer is proven, cutover is blocked and
the existing branch rules remain unchanged.

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
