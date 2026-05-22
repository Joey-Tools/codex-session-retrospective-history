# Data

This directory contains redacted machine-readable retrospective artifacts.

- `episodes/YYYY/MM/*.jsonl` stores episode/topic summaries.
- `turn_flags/YYYY/MM/*.jsonl` stores flagged turn summaries only.
- `trends/*.json` stores aggregate trend reports.
- `manifests/YYYY/MM/*.json` stores redacted source manifests promoted from
  transient helper output. Retained manifests must not include raw local paths,
  remote paths, or full shard worklists; keep `*_ref` hashes and coverage/status
  metadata only.

All JSONL records and `manifests/**/*.json` files must conform to
`schemas/session-retrospective-v1.schema.json` where applicable. Manifest
validation is part of the privacy gate: raw path fields, full worklists, and
non-hash `*_ref` values are invalid retained artifacts.
