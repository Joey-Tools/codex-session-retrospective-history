# Codex Session Retrospective History Guidelines

- Explanations and summaries use Simplified Chinese. Code, comments, identifiers, commit messages, and Markdown code blocks use English.
- This repository stores redacted retrospective history only. Never commit raw Codex rollout files, full prompts, secrets, credentials, internal URLs, customer data, proprietary code snippets, or unredacted tool output.
- Retain episode/topic summaries broadly, but retain turn-level records only for flagged turns such as user correction, failed command, approval/auth friction, incomplete verification, safety/privacy risk, context loss, over-exploration, or under-asking.
- Keep generated reports and JSONL schema-valid. Run `python scripts/validate_retained_history.py --root .` before committing retained artifacts; if schema validation is unavailable, at minimum parse every JSON/JSONL file before committing.
- Treat source session paths and IDs as audit pointers, not as permission to copy raw source content into this repository.
- Do not modify host-level Codex state, remote hosts, Apple Notes, or Daily Work Report from this repository workflow.
