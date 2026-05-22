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
  baseline/90-day-windows/*.md
data/
  episodes/YYYY/MM/*.jsonl
  turn_flags/YYYY/MM/*.jsonl
  trends/*.json
  manifests/YYYY/MM/*.json
schemas/
  session-retrospective-v1.schema.json
  retained-manifest-v1.schema.json
```

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
