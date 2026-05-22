# Data

This directory contains redacted machine-readable retrospective artifacts.

- `episodes/YYYY/MM/*.jsonl` stores episode/topic summaries.
- `turn_flags/YYYY/MM/*.jsonl` stores flagged turn summaries only.
- `trends/*.json` stores aggregate trend reports.
- `manifests/YYYY/MM/*.json` stores redacted source manifests promoted from
  transient helper output. Retained manifests must not include raw local paths,
  remote paths, or full shard worklists; keep only bounded source summaries,
  opaque `*_ref` values, and coverage/status metadata.

JSONL records must conform to `schemas/session-retrospective-v1.schema.json`
where applicable. `manifests/**/*.json` files must be validated specifically
against `schemas/retained-manifest-v1.schema.json`; validating a manifest
against the generic bundle schema is not sufficient.

Manifest validation is part of the privacy gate: raw path fields, path-like
free text, per-shard path lists, full worklists, and non-opaque `*_ref` values
are invalid retained artifacts. `*_ref` values must use the current
`path_ref_v1:<16 hex>` redaction-policy scheme, which is an opaque per-run
keyed reference rather than a plain hash of the raw path.
