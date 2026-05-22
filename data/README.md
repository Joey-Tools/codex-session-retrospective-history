# Data

This directory contains redacted machine-readable retrospective artifacts.

- `episodes/YYYY/MM/*.jsonl` stores episode/topic summaries.
- `turn_flags/YYYY/MM/*.jsonl` stores flagged turn summaries only.
- `trends/*.json` stores aggregate trend reports.
- `manifests/YYYY/MM/*.json` stores redacted source manifests promoted from
  transient helper output. Retained manifests must not include raw local paths,
  remote paths, or full shard worklists; keep `*_ref` hashes and coverage/status
  metadata only.

JSONL records must conform to `schemas/session-retrospective-v1.schema.json`
where applicable. `manifests/**/*.json` files must be validated specifically
against `schemas/retained-manifest-v1.schema.json`; validating a manifest
against the generic bundle schema is not sufficient.

Manifest validation is part of the privacy gate: raw path fields, path-like
free text, full worklists, and non-hash `*_ref` values are invalid retained
artifacts.
