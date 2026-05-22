# Data

This directory contains redacted machine-readable retrospective artifacts.

- `episodes/YYYY/MM/*.jsonl` stores episode/topic summaries.
- `turn_flags/YYYY/MM/*.jsonl` stores flagged turn summaries only.
- `trends/*.json` stores aggregate trend reports.

All JSONL records must conform to `schemas/session-retrospective-v1.schema.json`
where applicable.
