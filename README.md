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
