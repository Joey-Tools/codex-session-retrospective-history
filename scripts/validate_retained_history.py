#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import Counter
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any


FORBIDDEN_COMPONENTS = frozenset(
    {".codex", ".codex-local", ".codex-tmp", "archived_sessions", "raw", "scratch", "sessions", "transient"}
)
FORBIDDEN_FILENAMES = frozenset(
    {
        "auth.json",
        "config.toml",
        "history.jsonl",
        "session_index.jsonl",
        "source_metadata.json",
        "shard_manifest.json",
        "shards.jsonl",
        "turn_summaries.jsonl",
    }
)
FORBIDDEN_COMPACT_NAME_PARTS = frozenset(
    {
        "conversationlog",
        "fullprompt",
        "messagelog",
        "promptlog",
        "rawtranscript",
        "tooloutput",
        "turnsummaries",
        "userprompt",
    }
)
FORBIDDEN_COMPACT_NAME_PREFIXES = frozenset({"raw"})
FORBIDDEN_NAME_STEMS = frozenset(
    {
        "history",
        "session_index",
        "shard_manifest",
        "shards",
        "source_metadata",
        "turn_summaries",
    }
)
COMPRESSED_ARTIFACT_SUFFIXES = frozenset({".bz2", ".gz", ".xz", ".zip", ".zst"})
PATH_REF_RE = re.compile(r"^path_ref_v1:[0-9a-f]{16}$")
SESSION_REF_RE = re.compile(r"^session_ref_v1:[0-9a-f]{20}$")
EPISODE_REF_RE = re.compile(r"^episode_ref_v1:[0-9a-f]{20}$")
TURN_REF_RE = re.compile(r"^turn_ref_v1:[0-9a-f]{20}$")
SOURCE_HASH_RE = re.compile(r"^source_hash_v1:[0-9a-f]{20}$")
SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
SENSITIVE_TOKEN_RE = re.compile(
    r"(^|[._-])(?:password|passwd|pwd|credentials?|secret|token|api[._-]?key|authorization|private[._-]?key)($|[._-])",
    re.I,
)
RAW_ID_TOKEN_RE = re.compile(r"\b(?:session|turn|episode)(?:[._-]?id)[._-][A-Za-z0-9][A-Za-z0-9_.-]{5,}\b", re.I)
RAW_ID_VALUE_RE = re.compile(
    r"(?<![A-Za-z0-9_])[\"']?(?:session|turn|episode)(?:[._ -]?id)[\"']?(?:\s*[:=]\s*|\s+)[\"']?"
    r"(?!session_ref_v1:|turn_ref_v1:|episode_ref_v1:|row\.get\b|data\.get\b|value\.get\b)[A-Za-z0-9_.:-]{6,}\b",
    re.I,
)
BASELINE_MODE_RE = re.compile(r"^baseline-90d$")
PRIVATE_IPV4_RE = re.compile(
    r"(?<![\d.])(?:10(?:\.\d{1,3}){3}|100\.(?:6[4-9]|[78]\d|9\d|1[01]\d|12[0-7])(?:\.\d{1,3}){2}|127(?:\.\d{1,3}){3}|169\.254(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2})(?![\d.])"
)
PRIVATE_IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:::1|f[cd][0-9A-Fa-f]{0,2}(?::[0-9A-Fa-f]{0,4}){1,7}|fe[89abAB][0-9A-Fa-f]?(?::[0-9A-Fa-f]{0,4}){1,7})(?![0-9A-Fa-f:])",
    re.I,
)
TIMESTAMP_RE = re.compile(
    r"^(?:(?:\d{4}-(?:(?:01|03|05|07|08|10|12)-(?:0[1-9]|[12]\d|3[01])|(?:04|06|09|11)-(?:0[1-9]|[12]\d|30)|02-(?:0[1-9]|1\d|2[0-8])))|(?:(?:[0-9]{2}(?:0[48]|[2468][048]|[13579][26])|(?:[02468][048]|[13579][26])00)-02-29))T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?Z$"
)
TEXT_ARTIFACT_SUFFIXES = frozenset({".json", ".jsonl", ".md", ".txt"})
VALID_RETAINED_SUFFIXES = TEXT_ARTIFACT_SUFFIXES
STRIPPABLE_ARTIFACT_SUFFIXES = TEXT_ARTIFACT_SUFFIXES | COMPRESSED_ARTIFACT_SUFFIXES
ROOT_DOC_FILES = frozenset({".gitignore", "AGENTS.md", "README.md", "data/README.md", "reports/README.md"})
WORKFLOW_SUFFIXES = frozenset({".yaml", ".yml"})
CODEX_REVIEW_GATE_WORKFLOW_PATH = Path(".github/workflows/codex-review-gate.yml")
CODEX_REVIEW_GATE_WORKFLOW_SHA256 = (
    "8cfa575da7c17c72db5f8b82ac66301"
    "0ba3b10820de3406bee86185e93d72985"
)
CODEX_REVIEW_GATE_SAFE_INFRASTRUCTURE_LINE = "".join(
    ("          GH_", "TOKEN", ": ${{ github.", "token", " }}")
)
SCHEMA_FILES = frozenset({"retained-manifest-v1.schema.json", "session-retrospective-v1.schema.json"})
RETAINED_EXPORT_DIRS = frozenset({("retained", "daily"), ("retained", "weekly"), ("retained", "baseline")})
RETAINED_EXPORT_FILES = frozenset({"episodes.jsonl", "turn_flags.jsonl", "trend_report.json", "retained_manifest.json"})
RETAINED_EVIDENCE_HOSTS = frozenset({"local", "miku-bot-dev", "hoteng-srv-01", "custom_source"})
RETAINED_HOSTS = frozenset((*RETAINED_EVIDENCE_HOSTS, "scope"))
RETAINED_FIXED_MODES = frozenset({"daily", "weekly"})
RETAINED_MODEL_IDS = frozenset({"gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.5", "gpt-5.4", "gpt-5.3-codex"})
RETAINED_MODEL_ERAS = frozenset((*RETAINED_MODEL_IDS, "other-model", "pre-gpt-5.3-codex", "unknown"))
EPISODE_KEYS = frozenset(
    {
        "episode_id",
        "host",
        "session_id",
        "start",
        "end",
        "cwd",
        "model_era",
        "topic",
        "turn_count",
        "friction_flags",
        "outcome",
        "work_report_hint",
    }
)
TURN_FLAG_KEYS = frozenset(
    {
        "turn_id",
        "episode_id",
        "host",
        "session_id",
        "source_path",
        "source_hash",
        "timestamp",
        "cwd",
        "model",
        "model_era",
        "redacted_user_prompt_summary",
        "assistant_action_summary",
        "issue_flags",
        "prompt_improvement",
    }
)
TREND_KEYS = frozenset(
    {
        "schema_version",
        "window",
        "turn_count",
        "flagged_turn_count",
        "episode_count",
        "flags",
        "hosts",
        "model_eras",
        "coverage_gaps",
    }
)
MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "mode",
        "window",
        "sources",
        "coverage_gaps",
        "redaction_policy_version",
        "retention_note",
        "retention_safe",
    }
)
WINDOW_KEYS = frozenset({"mode", "start", "end"})
SOURCE_SUMMARY_KEYS = frozenset({"host", "root_ref", "status", "rollout_count", "summary_count"})
COVERAGE_GAP_KEYS = frozenset({"host", "reason", "root_ref", "bytes"})
SOURCE_STATUSES = frozenset({"empty", "missing", "ready", "stale"})
OUTCOMES = frozenset({"needs_review", "no_issue_observed"})
ISSUE_FLAGS = frozenset(
    {
        "approval_auth_friction",
        "context_loss",
        "failed_command",
        "over_exploration",
        "safety_privacy_flag",
        "under_asking",
        "user_correction",
        "verification_gap",
    }
)
COVERAGE_REASONS = frozenset(
    {
        "auth_gated",
        "codex_missing",
        "history_missing",
        "history_unreadable",
        "host_unreachable",
        "invalid_jsonl",
        "missing_codex",
        "no_rollout_or_summary_files",
        "oversized_rollout_skipped",
        "partial_host_scope",
        "remote_source_not_materialized",
        "session_index_missing",
        "session_index_unreadable",
        "source_root_missing",
        "source_root_symlink",
        "stale_host",
        "truncated_rollout_summary",
        "unreachable",
        "unsafe_source_artifact",
    }
)
MAX_MANIFEST_SOURCES = 16
MAX_COVERAGE_GAPS = 100
MAX_SAFE_TOKEN_LENGTH = 64
MAX_TOKEN_ARRAY_ITEMS = 16
MAX_COUNT_MAP_PROPERTIES = 64
MAX_COUNT = 1_000_000
RETAINED_SAFETY_TEXT_RE = re.compile(
    r"(?:\b(?:secret|token|credential|password|private key|production|destructive|rm -rf|reset --hard|customer data|pii)\b|"
    r"客户|客户数据|凭据|凭证|密钥|生产|破坏性)",
    re.I,
)
COMMON_BARE_TOKEN_RE = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})\b")
RISK_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----", re.I),
    re.compile(r"\b(?:https?|ssh)://", re.I),
    re.compile(r"\bgit@[A-Za-z0-9_.-]+:"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"(^|[^A-Za-z0-9_])(?:~|/(?:Users|home|root|private|tmp|var|etc|opt|Volumes|workspace|workspaces))/", re.I),
    re.compile(r"(^|[^A-Za-z0-9_])(?:\./|\.\./)?\.codex(?:-local|-tmp)?(?:/|\\)", re.I),
    re.compile(r"(^|[^A-Za-z0-9_])(?:sessions|archived_sessions)(?:/|\\)", re.I),
    re.compile(r"\b[A-Za-z]:\\(?:Users|home|root|private|tmp|var|etc|opt|workspace|workspaces)\\", re.I),
    re.compile(
        r"(?<![A-Za-z0-9_])[\"']?"
        r"[A-Za-z0-9._-]*(?:password|passwd|pwd|credential|secret(?:[\s._-]+key)?|token|api[\s._-]*key|authorization|private[\s._-]*key)[A-Za-z0-9._-]*[\"']?\s*[:=]\s*[\"']?"
        r"(?!(?:re\.compile|frozenset)\b)",
        re.I,
    ),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b", re.I),
    re.compile(r"\b(?:sk|rk)[-_](?:proj[-_])?[A-Za-z0-9_-]{16,}\b"),
    COMMON_BARE_TOKEN_RE,
    re.compile(r"(^|[^0-9a-fA-F])[0-9a-fA-F]{64}([^0-9a-fA-F]|$)"),
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    re.compile(r"\brollout(?:-summary)?-[A-Za-z0-9_.-]+\.jsonl\b", re.I),
    PRIVATE_IPV4_RE,
    PRIVATE_IPV6_RE,
    RAW_ID_VALUE_RE,
    RAW_ID_TOKEN_RE,
    re.compile(r"\b(?:[A-Za-z0-9-]+\.)+(?:internal|corp|local|lan|example|invalid|test)\b", re.I),
    RETAINED_SAFETY_TEXT_RE,
)
INFRASTRUCTURE_RISK_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----", re.I),
    re.compile(
        r"\bhttps?://(?:localhost|miku-bot-dev|hoteng-srv-01|(?:10|127)(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2})(?::\d{1,5})?(?:[/?#]|$)",
        re.I,
    ),
    re.compile(
        r"\bssh://(?:[A-Za-z0-9._-]+@)?(?:localhost|miku-bot-dev|hoteng-srv-01|(?:10|127)(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2}|[A-Za-z0-9-]+)(?::\d{1,5})?(?:[/:?#]|$)",
        re.I,
    ),
    re.compile(
        r"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9._-]+@)(?:localhost|miku-bot-dev|hoteng-srv-01|(?:10|127)(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2}|[A-Za-z0-9-]+):[A-Za-z0-9._~/-]+(?:\.git)?\b",
        re.I,
    ),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"(^|[^A-Za-z0-9_])(?:~|/(?:Users|home|root|private|tmp|var|etc|opt|Volumes|workspace|workspaces))/", re.I),
    re.compile(r"(^|[^A-Za-z0-9_])(?:\./|\.\./)?\.codex(?:-local|-tmp)?(?:/|\\)", re.I),
    re.compile(r"(^|[^A-Za-z0-9_])(?:sessions|archived_sessions)(?:/|\\)", re.I),
    re.compile(r"\b[A-Za-z]:\\(?:Users|home|root|private|tmp|var|etc|opt|workspace|workspaces)\\", re.I),
    re.compile(
        r"(?<![A-Za-z0-9_])[\"']?"
        r"(?!(?:safe[._-]?token(?:[._-]?re)?|common[._-]?bare[._-]?token[._-]?re|max[._-]?safe[._-]?token[._-]?length|max[._-]?token[._-]?array[._-]?items|sensitive[._-]?token[._-]?re|raw[._-]?id[._-]?token[._-]?re|tokens|risk[._-]?patterns?|infrastructure[._-]?risk[._-]?patterns?|safe[._-]?infrastructure[._-]?lines)[\"']?\s*[:=])"
        r"[A-Za-z0-9._-]*(?:password|passwd|pwd|credential|secret(?:[\s._-]+key)?|token|api[\s._-]*key|authorization|private[\s._-]*key)[A-Za-z0-9._-]*[\"']?\s*[:=]\s*[\"']?"
        r"(?!(?:re\.compile|frozenset)\b)",
        re.I,
    ),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b", re.I),
    re.compile(r"\b(?:sk|rk)[-_](?:proj[-_])?[A-Za-z0-9_-]{16,}\b"),
    COMMON_BARE_TOKEN_RE,
    re.compile(r"(^|[^0-9a-fA-F])[0-9a-fA-F]{64}([^0-9a-fA-F]|$)"),
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    re.compile(r"\brollout(?:-summary)?-[A-Za-z0-9_.-]+\.jsonl\b", re.I),
    PRIVATE_IPV4_RE,
    PRIVATE_IPV6_RE,
    RAW_ID_VALUE_RE,
    RAW_ID_TOKEN_RE,
    re.compile(r"\b(?:[A-Za-z0-9-]+\.)+(?:internal|corp|local|lan|example|invalid|test)\b", re.I),
)
SAFE_INFRASTRUCTURE_LINES = frozenset(
    {
        ".codex-local/",
        ".codex-tmp/",
        ".codex/",
        "archived_sessions/",
        "sessions/",
        "auth.json",
        "config.toml",
        "history.jsonl",
        "session_index.jsonl",
        "rollout-*.jsonl",
        "rollout-summary*.jsonl",
        "source_metadata.json",
        "shard_manifest.json",
        "shards.jsonl",
        "turn_summaries.jsonl",
    }
)


def git_visible_files(root: Path) -> list[Path] | None:
    top_result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if top_result.returncode != 0:
        return None
    top = Path(top_result.stdout.strip()).resolve()
    try:
        relative_root = root.resolve().relative_to(top)
    except ValueError:
        return None
    pathspec = "." if str(relative_root) == "." else relative_root.as_posix()
    files_result = subprocess.run(
        ["git", "-C", str(top), "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", pathspec],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if files_result.returncode != 0:
        return None
    files = []
    for raw_path in files_result.stdout.split(b"\0"):
        if not raw_path:
            continue
        path = top / raw_path.decode("utf-8")
        if path.is_file() or path.is_symlink():
            files.append(path)
    return sorted(files)


def iter_files(root: Path) -> list[Path]:
    git_files = git_visible_files(root)
    if git_files is not None:
        return git_files
    return sorted(
        path
        for path in root.rglob("*")
        if (path.is_file() or path.is_symlink())
        and ".git" not in path.relative_to(root).parts
        and "__pycache__" not in path.relative_to(root).parts
    )


def forbidden_name(name: str) -> bool:
    stem = name
    while Path(stem).suffix.lower() in STRIPPABLE_ARTIFACT_SUFFIXES:
        next_stem = Path(stem).with_suffix("").name
        if next_stem == stem:
            break
        stem = next_stem
    if sensitive_path_component(name, stem=stem):
        return True
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", stem)
    tokens = [token for token in re.split(r"[^a-z0-9]+", separated.lower()) if token]
    normalized = "_".join(tokens)
    if sensitive_path_component(normalized):
        return True
    if normalized in FORBIDDEN_NAME_STEMS:
        return True
    compacted = "".join(tokens)
    if any(compacted.startswith(prefix) for prefix in FORBIDDEN_COMPACT_NAME_PREFIXES):
        return True
    return any(part in compacted for part in FORBIDDEN_COMPACT_NAME_PARTS)


def sensitive_path_component(part: str, *, stem: str | None = None) -> bool:
    stem = part if stem is None else stem
    if RAW_ID_TOKEN_RE.search(part) or RAW_ID_TOKEN_RE.search(stem):
        return True
    if SENSITIVE_TOKEN_RE.search(stem):
        return True
    return any(
        pattern.search(part) or pattern.search(stem)
        for pattern in RISK_PATTERNS
        if pattern is not RETAINED_SAFETY_TEXT_RE
    )


def display_path_component(part: str) -> str:
    stem = part
    suffixes: list[str] = []
    while Path(stem).suffix.lower() in STRIPPABLE_ARTIFACT_SUFFIXES:
        suffix = Path(stem).suffix
        next_stem = Path(stem).with_suffix("").name
        if next_stem == stem:
            break
        suffixes.insert(0, suffix)
        stem = next_stem
    if sensitive_path_component(part, stem=stem):
        return "[redacted]" + "".join(suffixes)
    return part


def display_relative_path(relative: Path) -> str:
    return Path(*(display_path_component(part) for part in relative.parts)).as_posix()


def safe_exception_message(exc: Exception) -> str:
    if isinstance(exc, OSError):
        reason = exc.strerror or exc.__class__.__name__
        return f"{exc.__class__.__name__}: {reason}"
    if isinstance(exc, UnicodeDecodeError):
        return "UnicodeDecodeError: failed to decode as UTF-8"
    if isinstance(exc, json.JSONDecodeError):
        return f"JSONDecodeError: {exc.msg}"
    return str(exc)


def forbidden_path(relative: Path) -> bool:
    parts = tuple(part.lower() for part in relative.parts)
    if any(part in FORBIDDEN_COMPONENTS or forbidden_name(part) for part in parts[:-1]):
        return True
    name = relative.name.lower()
    return name in FORBIDDEN_FILENAMES or forbidden_name(name) or name.startswith("rollout")


def reject_duplicate_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    parsed: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError("duplicate JSON key is not allowed")
        seen.add(key)
        parsed[key] = value
    return parsed


def parse_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_json_object)


def parse_jsonl(path: Path) -> list[Any]:
    rows: list[Any] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line, object_pairs_hook=reject_duplicate_json_object))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"line {line_no}: invalid JSONL: {exc}") from exc
    return rows


def contains_risky_text(value: Any, *, include_safety_markers: bool = True) -> bool:
    if isinstance(value, str):
        return any(pattern.search(value) for pattern in RISK_PATTERNS if include_safety_markers or pattern is not RETAINED_SAFETY_TEXT_RE)
    if isinstance(value, dict):
        return any(contains_risky_text(child, include_safety_markers=include_safety_markers) for child in value.values())
    if isinstance(value, list):
        return any(contains_risky_text(child, include_safety_markers=include_safety_markers) for child in value)
    return False


def contains_infrastructure_risk_text(value: str, *, relative: Path | None = None) -> bool:
    approved_review_gate = (
        relative == CODEX_REVIEW_GATE_WORKFLOW_PATH
        and hashlib.sha256(value.encode("utf-8")).hexdigest() == CODEX_REVIEW_GATE_WORKFLOW_SHA256
    )
    for line in value.splitlines():
        if approved_review_gate and line == CODEX_REVIEW_GATE_SAFE_INFRASTRUCTURE_LINE:
            continue
        normalized_line = line.strip().rstrip(",").strip("\"'")
        if normalized_line in SAFE_INFRASTRUCTURE_LINES:
            continue
        if any(pattern.search(line) for pattern in INFRASTRUCTURE_RISK_PATTERNS):
            return True
    return False


def contains_decoded_infrastructure_risk(value: Any) -> bool:
    if isinstance(value, str):
        return contains_infrastructure_risk_text(value)
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and contains_infrastructure_risk_text(key):
                return True
            if contains_decoded_infrastructure_risk(child):
                return True
    if isinstance(value, list):
        return any(contains_decoded_infrastructure_risk(child) for child in value)
    return False


def contains_risky_token(value: Any) -> bool:
    return isinstance(value, str) and SENSITIVE_TOKEN_RE.search(value) is not None


def contains_risky_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and (contains_risky_text(key) or contains_risky_token(key)):
                return True
            if contains_risky_key(child):
                return True
    if isinstance(value, list):
        return any(contains_risky_key(child) for child in value)
    return False


def contains_raw_path_fields(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"root", "path"}:
                return True
            if contains_raw_path_fields(child):
                return True
    if isinstance(value, list):
        return any(contains_raw_path_fields(child) for child in value)
    return False


def unexpected_keys(row: dict[str, Any], allowed: frozenset[str]) -> list[str]:
    return ["unexpected field is not allowed"] if set(row) - allowed else []


def missing_keys(row: dict[str, Any], required: frozenset[str]) -> list[str]:
    return [f"missing required field: {key}" for key in sorted(required - set(row))]


def valid_timestamp_or_null(value: Any) -> bool:
    return value is None or valid_timestamp(value)


def valid_timestamp(value: Any) -> bool:
    return isinstance(value, str) and TIMESTAMP_RE.fullmatch(value) is not None


def timestamp_order_key(value: str) -> tuple[int, int, int, int, int, int, int]:
    main = value.removesuffix("Z")
    if "." in main:
        main, fraction = main.split(".", 1)
    else:
        fraction = ""
    date_part, time_part = main.split("T", 1)
    year, month, day = (int(part) for part in date_part.split("-", 2))
    hour, minute, second = (int(part) for part in time_part.split(":", 2))
    nanosecond = int(fraction.ljust(9, "0") or "0")
    return (year, month, day, hour, minute, second, nanosecond)


def timestamp_epoch_nanoseconds(value: str) -> int:
    year, month, day, hour, minute, second, nanosecond = timestamp_order_key(value)
    ordinal = dt.date(year, month, day).toordinal()
    seconds = ((ordinal * 24 + hour) * 60 + minute) * 60 + second
    return seconds * 1_000_000_000 + nanosecond


def valid_non_negative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_COUNT


def valid_schema_version_one(value: Any) -> bool:
    return type(value) is int and value == 1


def valid_safe_token(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= MAX_SAFE_TOKEN_LENGTH
        and SAFE_TOKEN_RE.fullmatch(value) is not None
        and not contains_risky_token(value)
        and not contains_risky_text(value)
    )


def valid_retained_host(value: Any) -> bool:
    return isinstance(value, str) and value in RETAINED_EVIDENCE_HOSTS


def valid_retained_coverage_host(value: Any) -> bool:
    return isinstance(value, str) and value in RETAINED_HOSTS


def valid_retained_mode(value: Any) -> bool:
    return isinstance(value, str) and (value in RETAINED_FIXED_MODES or BASELINE_MODE_RE.fullmatch(value) is not None)


def retained_mode_days(mode: str) -> int | None:
    if mode == "daily":
        return 1
    if mode == "weekly":
        return 7
    if mode == "baseline-90d":
        return 90
    return None


def expected_mode_from_retained_export_path(relative: Path) -> str | None:
    parts = relative.parts
    if len(parts) == 3 and parts[:2] in RETAINED_EXPORT_DIRS:
        return parts[1]
    return None


def validate_expected_mode(value: Any, expected_mode: str | None, label: str) -> list[str]:
    if expected_mode is None:
        return []
    if expected_mode == "baseline":
        if value != "baseline-90d":
            return [f"{label} must match retained/baseline export directory"]
        return []
    if value != expected_mode:
        return [f"{label} must match retained/{expected_mode} export directory"]
    return []


def valid_retained_model_id(value: Any) -> bool:
    return isinstance(value, str) and value in RETAINED_MODEL_IDS


def valid_retained_model_era(value: Any) -> bool:
    return isinstance(value, str) and value in RETAINED_MODEL_ERAS


def allowed_infrastructure_artifact(relative: Path) -> bool:
    path_text = relative.as_posix()
    if path_text in ROOT_DOC_FILES:
        return True
    parts = relative.parts
    if not parts:
        return False
    if parts[0] == ".github":
        return len(parts) >= 3 and parts[1] == "workflows" and relative.suffix.lower() in WORKFLOW_SUFFIXES
    if parts[0] == "scripts":
        return len(parts) == 2 and relative.suffix.lower() == ".py"
    if parts[0] == "schemas":
        return len(parts) == 2 and relative.name in SCHEMA_FILES
    if parts[0] == "tests":
        return len(parts) == 2 and relative.suffix.lower() == ".py"
    return False


def content_scanned_infrastructure_artifact(relative: Path) -> bool:
    return allowed_infrastructure_artifact(relative)


def valid_date_components(year_text: str, month_text: str, day_text: str) -> bool:
    if (
        re.fullmatch(r"\d{4}", year_text) is None
        or re.fullmatch(r"\d{2}", month_text) is None
        or re.fullmatch(r"\d{2}", day_text) is None
    ):
        return False
    try:
        dt.date(int(year_text), int(month_text), int(day_text))
    except ValueError:
        return False
    return True


def valid_baseline_report_filename(name: str) -> bool:
    match = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})_to_(\d{4})-(\d{2})-(\d{2})\.md", name)
    if match is None:
        return False
    start_year, start_month, start_day, end_year, end_month, end_day = match.groups()
    if not valid_date_components(start_year, start_month, start_day):
        return False
    if not valid_date_components(end_year, end_month, end_day):
        return False
    start = dt.date(int(start_year), int(start_month), int(start_day))
    end = dt.date(int(end_year), int(end_month), int(end_day))
    return (end - start).days == 90


def allowed_retained_text_artifact(relative: Path) -> bool:
    path_text = relative.as_posix()
    if path_text in {"data/README.md", "reports/README.md"}:
        return True
    parts = relative.parts
    if len(parts) == 5 and parts[0] == "reports" and parts[1] in {"daily", "weekly"}:
        year, month, day_file = parts[2], parts[3], parts[4]
        return bool(relative.suffix.lower() == ".md" and valid_date_components(year, month, Path(day_file).stem))
    if len(parts) == 4 and parts[:3] == ("reports", "baseline", "90-day-windows"):
        return valid_baseline_report_filename(parts[3])
    return False


def valid_year_month(parts: tuple[str, ...], start: int) -> bool:
    if len(parts) <= start + 1 or re.fullmatch(r"\d{4}", parts[start]) is None or re.fullmatch(r"\d{2}", parts[start + 1]) is None:
        return False
    year = int(parts[start])
    month = int(parts[start + 1])
    if not 1 <= month <= 12:
        return False
    try:
        dt.date(year, month, 1)
        if month == 12:
            dt.date(year + 1, 1, 1)
        else:
            dt.date(year, month + 1, 1)
    except ValueError:
        return False
    return True


def data_month_window(data_month: tuple[str, str, str]) -> tuple[
    tuple[int, int, int, int, int, int, int],
    tuple[int, int, int, int, int, int, int],
]:
    _, year_text, month_text = data_month
    year = int(year_text)
    month = int(month_text)
    start = dt.date(year, month, 1)
    if month == 12:
        end = dt.date(year + 1, 1, 1)
    else:
        end = dt.date(year, month + 1, 1)
    start_key = (start.year, start.month, start.day, 0, 0, 0, 0)
    end_key = (end.year, end.month, end.day, 0, 0, 0, 0)
    return (start_key, end_key)


def allowed_retained_json_artifact(relative: Path) -> str | None:
    parts = relative.parts
    if len(parts) == 3 and parts[:2] in RETAINED_EXPORT_DIRS and relative.name == "trend_report.json":
        return "trend"
    if len(parts) == 3 and parts[:2] in RETAINED_EXPORT_DIRS and relative.name == "retained_manifest.json":
        return "manifest"
    if len(parts) == 5 and parts[:2] == ("data", "trends") and valid_year_month(parts, 2) and relative.name == "trend_report.json":
        return "trend"
    if len(parts) == 5 and parts[:2] == ("data", "manifests") and valid_year_month(parts, 2) and relative.name == "retained_manifest.json":
        return "manifest"
    return None


def allowed_retained_jsonl_artifact(relative: Path) -> str | None:
    parts = relative.parts
    if len(parts) == 3 and parts[:2] in RETAINED_EXPORT_DIRS and relative.name == "episodes.jsonl":
        return "episode"
    if len(parts) == 3 and parts[:2] in RETAINED_EXPORT_DIRS and relative.name == "turn_flags.jsonl":
        return "turn_flag"
    if len(parts) == 5 and parts[:2] == ("data", "episodes") and valid_year_month(parts, 2) and relative.name == "episodes.jsonl":
        return "episode"
    if len(parts) == 5 and parts[:2] == ("data", "turn_flags") and valid_year_month(parts, 2) and relative.name == "turn_flags.jsonl":
        return "turn_flag"
    return None


def validate_safe_token_array(value: Any, label: str, *, min_items: int = 0) -> list[str]:
    if not isinstance(value, list):
        return [f"{label} must be safe-token array"]
    issues: list[str] = []
    if len(value) < min_items:
        issues.append(f"{label} must contain at least {min_items} item")
    if len(value) > MAX_TOKEN_ARRAY_ITEMS:
        issues.append(f"{label} must contain at most {MAX_TOKEN_ARRAY_ITEMS} items")
    if not all(valid_safe_token(item) for item in value):
        issues.append(f"{label} must be safe-token array")
    return issues


def validate_issue_flag_array(value: Any, label: str, *, min_items: int = 0) -> list[str]:
    issues = validate_safe_token_array(value, label, min_items=min_items)
    if isinstance(value, list):
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str) or item not in ISSUE_FLAGS:
                issues.append(f"{label} must use allowed issue flags")
                break
            if item in seen:
                issues.append(f"{label} must not contain duplicate issue flags")
                break
            seen.add(item)
    return issues


def validate_count_map(value: Any, label: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{label} must be an object"]
    issues: list[str] = []
    if len(value) > MAX_COUNT_MAP_PROPERTIES:
        issues.append(f"{label} must contain at most {MAX_COUNT_MAP_PROPERTIES} keys")
    for key, count in value.items():
        if not valid_safe_token(key):
            issues.append(f"{label} key must be a safe token")
        if label == "hosts" and not valid_retained_host(key):
            issues.append("hosts key must be an allowed retained host")
        if label == "model_eras" and not valid_retained_model_era(key):
            issues.append("model_eras key must be an allowed retained model era")
        if not valid_non_negative_int(count):
            issues.append(f"{label} value must be a bounded non-negative integer")
    return issues


def validate_issue_flag_count_map(value: Any, label: str) -> list[str]:
    issues = validate_count_map(value, label)
    if isinstance(value, dict):
        for key in value:
            if key not in ISSUE_FLAGS:
                issues.append(f"{label} keys must use allowed issue flags")
                break
    return issues


def validate_window(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["window must be an object"]
    issues = unexpected_keys(value, WINDOW_KEYS) + missing_keys(value, WINDOW_KEYS)
    if not valid_retained_mode(value.get("mode")):
        issues.append("window.mode must be an allowed retained mode")
    start_value = value.get("start")
    end_value = value.get("end")
    start_valid = valid_timestamp(start_value)
    end_valid = valid_timestamp(end_value)
    if not start_valid:
        issues.append("window.start must be timestamp")
    if not end_valid:
        issues.append("window.end must be timestamp")
    if start_valid and end_valid:
        if timestamp_order_key(start_value) >= timestamp_order_key(end_value):
            issues.append("window.start must be before window.end")
        elif isinstance(value.get("mode"), str):
            mode_days = retained_mode_days(value["mode"])
            if mode_days is not None:
                expected_ns = mode_days * 24 * 60 * 60 * 1_000_000_000
                if timestamp_epoch_nanoseconds(end_value) - timestamp_epoch_nanoseconds(start_value) != expected_ns:
                    issues.append("window duration must match window.mode")
    return issues


def retained_window_identity(value: Any) -> tuple[str, tuple[int, int, int, int, int, int, int], tuple[int, int, int, int, int, int, int]] | None:
    if not isinstance(value, dict):
        return None
    mode = value.get("mode")
    start = value.get("start")
    end = value.get("end")
    if not valid_retained_mode(mode) or not valid_timestamp(start) or not valid_timestamp(end):
        return None
    return (mode, timestamp_order_key(start), timestamp_order_key(end))


def valid_timestamp_key(value: Any) -> tuple[int, int, int, int, int, int, int] | None:
    if not valid_timestamp(value):
        return None
    return timestamp_order_key(value)


def validate_coverage_gap(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["coverage gap must be an object"]
    issues = unexpected_keys(value, COVERAGE_GAP_KEYS)
    if "host" not in value or not valid_retained_coverage_host(value.get("host")):
        issues.append("coverage gap host must be an allowed retained host")
    if "reason" not in value or value.get("reason") not in COVERAGE_REASONS:
        issues.append("coverage gap reason is invalid")
    if "root_ref" in value and not PATH_REF_RE.fullmatch(str(value.get("root_ref", ""))):
        issues.append("coverage gap root_ref must be path_ref_v1")
    if "bytes" in value and not valid_non_negative_int(value.get("bytes")):
        issues.append("coverage gap bytes must be a non-negative integer")
    return issues


def validate_coverage_gaps(value: Any) -> list[str]:
    if not isinstance(value, list):
        return ["coverage_gaps must be an array"]
    issues: list[str] = []
    if len(value) > MAX_COVERAGE_GAPS:
        issues.append(f"coverage_gaps must contain at most {MAX_COVERAGE_GAPS} items")
    for index, gap in enumerate(value, 1):
        issues.extend(f"coverage_gaps[{index}]: {issue}" for issue in validate_coverage_gap(gap))
    return issues


def validate_source_summary(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["source summary must be an object"]
    issues = unexpected_keys(value, SOURCE_SUMMARY_KEYS) + missing_keys(value, SOURCE_SUMMARY_KEYS)
    if not valid_retained_host(value.get("host")):
        issues.append("source host must be an allowed retained host")
    if not PATH_REF_RE.fullmatch(str(value.get("root_ref", ""))):
        issues.append("source root_ref must be path_ref_v1")
    if value.get("status") not in SOURCE_STATUSES:
        issues.append("source status is invalid")
    count_values: dict[str, int] = {}
    for key in ("rollout_count", "summary_count"):
        count = value.get(key)
        if valid_non_negative_int(count):
            count_values[key] = count
        else:
            count_values[key] = 0
            issues.append(f"source {key} must be a bounded non-negative integer")
    if value.get("status") == "ready" and not (
        count_values["rollout_count"] >= 1 or count_values["summary_count"] >= 1
    ):
        issues.append("ready source must have rollout_count or summary_count")
    if value.get("status") in {"empty", "missing", "stale"} and (
        value.get("rollout_count") != 0 or value.get("summary_count") != 0
    ):
        issues.append("non-ready source counts must be zero")
    return issues


def validate_retained_text(value: Any, label: str, *, nullable: bool = False) -> list[str]:
    if value is None and nullable:
        return []
    if not isinstance(value, str):
        return [f"{label} must be retained text"]
    if len(value) > 1200 or contains_risky_text(value):
        return [f"{label} contains retained-text risk"]
    return []


def validate_episode(row: Any) -> list[str]:
    issues: list[str] = []
    if not isinstance(row, dict):
        return ["episode row must be an object"]
    issues.extend(unexpected_keys(row, EPISODE_KEYS))
    issues.extend(missing_keys(row, EPISODE_KEYS))
    if contains_raw_path_fields(row):
        issues.append("episode contains raw root/path field")
    if contains_risky_key(row):
        issues.append("episode JSON key contains raw/sensitive evidence")
    if not EPISODE_REF_RE.fullmatch(str(row.get("episode_id", ""))):
        issues.append("episode_id must be episode_ref_v1")
    if not valid_retained_host(row.get("host")):
        issues.append("host must be an allowed retained host")
    if not SESSION_REF_RE.fullmatch(str(row.get("session_id", ""))):
        issues.append("session_id must be session_ref_v1")
    start_value = row.get("start")
    end_value = row.get("end")
    start_valid = valid_timestamp_or_null(start_value)
    end_valid = valid_timestamp_or_null(end_value)
    if not start_valid:
        issues.append("start must be timestamp or null")
    if not end_valid:
        issues.append("end must be timestamp or null")
    if start_valid and end_valid and isinstance(start_value, str) and isinstance(end_value, str):
        if timestamp_order_key(start_value) > timestamp_order_key(end_value):
            issues.append("episode start must be before or equal to end")
    if row.get("cwd") is not None and not PATH_REF_RE.fullmatch(str(row.get("cwd"))):
        issues.append("cwd must be path_ref_v1 or null")
    if not valid_retained_model_era(row.get("model_era")):
        issues.append("model_era must be an allowed retained model era")
    issues.extend(validate_retained_text(row.get("topic"), "topic"))
    if not valid_non_negative_int(row.get("turn_count")):
        issues.append("turn_count must be a bounded non-negative integer")
    issues.extend(validate_issue_flag_array(row.get("friction_flags"), "friction_flags"))
    if row.get("outcome") not in OUTCOMES:
        issues.append("outcome is invalid")
    issues.extend(validate_retained_text(row.get("work_report_hint"), "work_report_hint", nullable=True))
    return issues


def validate_turn_flag(row: Any) -> list[str]:
    issues: list[str] = []
    if not isinstance(row, dict):
        return ["turn flag row must be an object"]
    issues.extend(unexpected_keys(row, TURN_FLAG_KEYS))
    issues.extend(missing_keys(row, TURN_FLAG_KEYS))
    if contains_raw_path_fields(row):
        issues.append("turn flag contains raw root/path field")
    if contains_risky_key(row):
        issues.append("turn flag JSON key contains raw/sensitive evidence")
    if not TURN_REF_RE.fullmatch(str(row.get("turn_id", ""))):
        issues.append("turn_id must be turn_ref_v1")
    if not EPISODE_REF_RE.fullmatch(str(row.get("episode_id", ""))):
        issues.append("episode_id must be episode_ref_v1")
    if not valid_retained_host(row.get("host")):
        issues.append("host must be an allowed retained host")
    if not SESSION_REF_RE.fullmatch(str(row.get("session_id", ""))):
        issues.append("session_id must be session_ref_v1")
    if not PATH_REF_RE.fullmatch(str(row.get("source_path", ""))):
        issues.append("source_path must be path_ref_v1")
    if not SOURCE_HASH_RE.fullmatch(str(row.get("source_hash", ""))):
        issues.append("source_hash must be source_hash_v1")
    if not valid_timestamp_or_null(row.get("timestamp")):
        issues.append("timestamp must be timestamp or null")
    if row.get("cwd") is not None and not PATH_REF_RE.fullmatch(str(row.get("cwd"))):
        issues.append("cwd must be path_ref_v1 or null")
    if row.get("model") is not None and not valid_retained_model_id(row.get("model")):
        issues.append("model must be an allowed retained model id or null")
    if not valid_retained_model_era(row.get("model_era")):
        issues.append("model_era must be an allowed retained model era")
    for key in ("redacted_user_prompt_summary", "assistant_action_summary", "prompt_improvement"):
        issues.extend(validate_retained_text(row.get(key), key, nullable=(key == "prompt_improvement")))
    issues.extend(validate_issue_flag_array(row.get("issue_flags"), "issue_flags", min_items=1))
    return issues


def validate_trend(data: Any, *, expected_mode: str | None = None) -> list[str]:
    if not isinstance(data, dict):
        return ["trend must be an object"]
    issues = unexpected_keys(data, TREND_KEYS) + missing_keys(data, TREND_KEYS)
    if contains_risky_key(data):
        issues.append("trend JSON key contains raw/sensitive evidence")
    if not valid_schema_version_one(data.get("schema_version")):
        issues.append("trend schema_version must be 1")
    issues.extend(validate_window(data.get("window")))
    window = data.get("window") if isinstance(data.get("window"), dict) else {}
    issues.extend(validate_expected_mode(window.get("mode"), expected_mode, "trend window.mode"))
    for key in ("turn_count", "flagged_turn_count", "episode_count"):
        if not valid_non_negative_int(data.get(key)):
            issues.append(f"{key} must be a non-negative integer")
    if valid_non_negative_int(data.get("turn_count")) and valid_non_negative_int(data.get("flagged_turn_count")):
        if data["flagged_turn_count"] > data["turn_count"]:
            issues.append("flagged_turn_count must be less than or equal to turn_count")
    issues.extend(validate_issue_flag_count_map(data.get("flags"), "flags"))
    for key in ("hosts", "model_eras"):
        issues.extend(validate_count_map(data.get(key), key))
    issues.extend(validate_coverage_gaps(data.get("coverage_gaps")))
    return issues


def validate_manifest(data: Any, *, expected_mode: str | None = None) -> list[str]:
    issues: list[str] = []
    if not isinstance(data, dict):
        return ["manifest must be an object"]
    issues.extend(unexpected_keys(data, MANIFEST_KEYS))
    issues.extend(missing_keys(data, MANIFEST_KEYS))
    if contains_raw_path_fields(data):
        issues.append("manifest contains raw root/path field")
    if contains_risky_key(data):
        issues.append("manifest JSON key contains raw/sensitive evidence")
    if contains_risky_text(data):
        issues.append("manifest retained text contains raw/sensitive evidence")
    if not valid_schema_version_one(data.get("schema_version")):
        issues.append("manifest schema_version must be 1")
    if not valid_retained_mode(data.get("mode")):
        issues.append("manifest mode must be an allowed retained mode")
    issues.extend(validate_window(data.get("window")))
    window = data.get("window") if isinstance(data.get("window"), dict) else {}
    if isinstance(window, dict) and window.get("mode") != data.get("mode"):
        issues.append("manifest mode must match window.mode")
    issues.extend(validate_expected_mode(data.get("mode"), expected_mode, "manifest mode"))
    if not isinstance(data.get("sources"), list) or not data.get("sources"):
        issues.append("manifest sources must be a non-empty array")
    else:
        if len(data["sources"]) > MAX_MANIFEST_SOURCES:
            issues.append(f"manifest sources must contain at most {MAX_MANIFEST_SOURCES} items")
        for index, source in enumerate(data.get("sources", []), 1):
            issues.extend(f"sources[{index}]: {issue}" for issue in validate_source_summary(source))
    issues.extend(validate_coverage_gaps(data.get("coverage_gaps")))
    if not valid_schema_version_one(data.get("redaction_policy_version")):
        issues.append("manifest redaction_policy_version must be 1")
    if data.get("retention_note") != "Derived retained manifest; raw location fields removed and opaque refs preserved.":
        issues.append("manifest retention_note is invalid")
    if data.get("retention_safe") is not True:
        issues.append("manifest retention_safe must be true")
    return issues


def retained_export_key(relative: Path) -> tuple[str, str] | None:
    if len(relative.parts) == 3 and relative.parts[:2] in RETAINED_EXPORT_DIRS:
        return tuple(relative.parts[:2])
    return None


def retained_data_month_key(relative: Path) -> tuple[str, str, str] | None:
    parts = relative.parts
    if (
        len(parts) == 5
        and parts[0] == "data"
        and parts[1] in {"episodes", "turn_flags", "trends", "manifests"}
        and valid_year_month(parts, 2)
    ):
        return ("data", parts[2], parts[3])
    return None


def valid_trend_count_map(value: Any) -> bool:
    return isinstance(value, dict) and all(
        isinstance(key, str) and valid_non_negative_int(count) for key, count in value.items()
    )


def sorted_counter(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted((key, count) for key, count in counter.items() if count))


def validate_retained_export_consistency(
    export_dir: tuple[str, ...],
    rows: dict[str, list[Any]],
    trend: Any,
    manifest: Any = None,
    artifact_paths: dict[str, Path] | None = None,
    data_month: tuple[str, str, str] | None = None,
) -> list[str]:
    export_path = Path(*export_dir)
    artifact_paths = artifact_paths or {}
    episodes_path = artifact_paths.get("episode", export_path / "episodes.jsonl")
    turn_flags_path = artifact_paths.get("turn_flag", export_path / "turn_flags.jsonl")
    trend_path = artifact_paths.get("trend", export_path / "trend_report.json")
    manifest_path = artifact_paths.get("manifest", export_path / "retained_manifest.json")
    issues: list[str] = []

    episodes = [row for row in rows.get("episode", []) if isinstance(row, dict)]
    turn_flags = [row for row in rows.get("turn_flag", []) if isinstance(row, dict)]
    episodes_by_id: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(episodes, 1):
        episode_id = row.get("episode_id")
        if not isinstance(episode_id, str) or EPISODE_REF_RE.fullmatch(episode_id) is None:
            continue
        if episode_id in episodes_by_id:
            issues.append(f"{episodes_path}:{index}: duplicate episode_id")
            continue
        episodes_by_id[episode_id] = row
    turn_ids: set[str] = set()
    for index, row in enumerate(turn_flags, 1):
        turn_id = row.get("turn_id")
        if not isinstance(turn_id, str) or TURN_REF_RE.fullmatch(turn_id) is None:
            continue
        if turn_id in turn_ids:
            issues.append(f"{turn_flags_path}:{index}: duplicate turn_id")
            continue
        turn_ids.add(turn_id)

    for index, row in enumerate(turn_flags, 1):
        episode_id = row.get("episode_id")
        if not isinstance(episode_id, str) or not EPISODE_REF_RE.fullmatch(episode_id):
            continue
        episode = episodes_by_id.get(episode_id)
        if episode is None:
            issues.append(f"{turn_flags_path}:{index}: episode_id is missing from episodes export")
            continue
        if row.get("host") != episode.get("host"):
            issues.append(f"{turn_flags_path}:{index}: host must match referenced episode")
        if row.get("session_id") != episode.get("session_id"):
            issues.append(f"{turn_flags_path}:{index}: session_id must match referenced episode")
        timestamp_key = valid_timestamp_key(row.get("timestamp"))
        episode_start_key = valid_timestamp_key(episode.get("start"))
        episode_end_key = valid_timestamp_key(episode.get("end"))
        if (
            timestamp_key is not None
            and (
                (episode_start_key is not None and timestamp_key < episode_start_key)
                or (episode_end_key is not None and timestamp_key > episode_end_key)
            )
        ):
            issues.append(f"{turn_flags_path}:{index}: timestamp must be within referenced episode")

    flagged_turn_counts_by_episode = Counter[str]()
    for row in turn_flags:
        episode_id = row.get("episode_id")
        if isinstance(episode_id, str) and EPISODE_REF_RE.fullmatch(episode_id):
            flagged_turn_counts_by_episode[episode_id] += 1
    for episode_id, flagged_count in flagged_turn_counts_by_episode.items():
        episode = episodes_by_id.get(episode_id)
        if episode is None:
            continue
        turn_count = episode.get("turn_count")
        if valid_non_negative_int(turn_count) and flagged_count > turn_count:
            issues.append(f"{turn_flags_path}: flagged turns must not exceed referenced episode turn_count")

    row_window_identity = None
    row_window_label = None
    if isinstance(trend, dict):
        row_window_identity = retained_window_identity(trend.get("window"))
        row_window_label = "trend window"
    if row_window_identity is None and isinstance(manifest, dict):
        row_window_identity = retained_window_identity(manifest.get("window"))
        row_window_label = "manifest window"

    if data_month is not None:
        month_start, month_end = data_month_window(data_month)
        row_scope_crosses_into_data_month = (
            row_window_identity is not None
            and row_window_identity[0] in {"weekly", "baseline-90d"}
            and row_window_identity[1] < month_start
            and row_window_identity[2] <= month_end
        )
        for artifact, path in ((trend, trend_path), (manifest, manifest_path)):
            if isinstance(artifact, dict):
                window_identity = retained_window_identity(artifact.get("window"))
                if window_identity is not None:
                    _, window_start, window_end = window_identity
                    if window_start >= month_end or window_end <= month_start:
                        issues.append(f"{path}: window must overlap data month")
                    elif window_end > month_end:
                        issues.append(f"{path}: window end must be within data month")
        if not row_scope_crosses_into_data_month:
            for index, row in enumerate(episodes, 1):
                start_key = valid_timestamp_key(row.get("start"))
                end_key = valid_timestamp_key(row.get("end"))
                if (start_key is not None and (start_key < month_start or start_key >= month_end)) or (
                    end_key is not None and (end_key < month_start or end_key > month_end)
                ):
                    issues.append(f"{episodes_path}:{index}: episode start/end must be within data month")
            for index, row in enumerate(turn_flags, 1):
                timestamp_key = valid_timestamp_key(row.get("timestamp"))
                if timestamp_key is not None and (timestamp_key < month_start or timestamp_key >= month_end):
                    issues.append(f"{turn_flags_path}:{index}: timestamp must be within data month")

    if row_window_identity is not None:
        _, window_start, window_end = row_window_identity
        label = row_window_label or "retained window"
        for index, row in enumerate(episodes, 1):
            start_key = valid_timestamp_key(row.get("start"))
            end_key = valid_timestamp_key(row.get("end"))
            if (start_key is not None and (start_key < window_start or start_key >= window_end)) or (
                end_key is not None and (end_key < window_start or end_key > window_end)
            ):
                issues.append(f"{episodes_path}:{index}: episode start/end must be within {label}")
        for index, row in enumerate(turn_flags, 1):
            timestamp_key = valid_timestamp_key(row.get("timestamp"))
            if timestamp_key is not None and (timestamp_key < window_start or timestamp_key >= window_end):
                issues.append(f"{turn_flags_path}:{index}: timestamp must be within {label}")

    if not episodes and not turn_flags and "episode" not in rows and "turn_flag" not in rows and not isinstance(trend, dict):
        return issues

    if not isinstance(trend, dict):
        return issues

    if valid_non_negative_int(trend.get("episode_count")) and trend["episode_count"] != len(episodes):
        issues.append(f"{trend_path}: episode_count must match episodes.jsonl")
    if valid_non_negative_int(trend.get("flagged_turn_count")) and trend["flagged_turn_count"] != len(turn_flags):
        issues.append(f"{trend_path}: flagged_turn_count must match turn_flags.jsonl")

    episode_turn_counts = [
        row.get("turn_count") for row in episodes if valid_non_negative_int(row.get("turn_count"))
    ]
    if len(episode_turn_counts) == len(episodes):
        expected_turn_count = sum(episode_turn_counts)
        if valid_non_negative_int(trend.get("turn_count")) and trend["turn_count"] != expected_turn_count:
            issues.append(f"{trend_path}: turn_count must match episodes.jsonl turn_count total")

        expected_hosts = Counter[str]()
        expected_model_eras = Counter[str]()
        for row in episodes:
            turn_count = row["turn_count"]
            host = row.get("host")
            model_era = row.get("model_era")
            if valid_retained_host(host):
                expected_hosts[host] += turn_count
            if valid_retained_model_era(model_era):
                expected_model_eras[model_era] += turn_count
        if valid_trend_count_map(trend.get("hosts")) and trend["hosts"] != sorted_counter(expected_hosts):
            issues.append(f"{trend_path}: hosts must match episodes.jsonl turn_count totals")
        if valid_trend_count_map(trend.get("model_eras")) and trend["model_eras"] != sorted_counter(expected_model_eras):
            issues.append(f"{trend_path}: model_eras must match episodes.jsonl turn_count totals")

    expected_flags = Counter[str]()
    for row in turn_flags:
        flags = row.get("issue_flags")
        if isinstance(flags, list):
            expected_flags.update({flag for flag in flags if isinstance(flag, str) and flag in ISSUE_FLAGS})
    if valid_trend_count_map(trend.get("flags")) and trend["flags"] != sorted_counter(expected_flags):
        issues.append(f"{trend_path}: flags must match turn_flags.jsonl issue_flags")

    return issues


def validate_root(root: Path) -> list[str]:
    root = root.resolve()
    issues: list[str] = []
    if not root.is_dir():
        return ["root must be an existing directory"]
    retained_export_files: dict[tuple[str, str], set[str]] = {}
    retained_export_modes: dict[tuple[str, str], dict[str, str]] = {}
    retained_export_windows: dict[tuple[str, str], dict[str, tuple[str, tuple[int, int, int, int, int, int, int], tuple[int, int, int, int, int, int, int]]]] = {}
    retained_export_rows: dict[tuple[str, str], dict[str, list[Any]]] = {}
    retained_export_trends: dict[tuple[str, str], Any] = {}
    data_month_rows: dict[tuple[str, str, str], dict[str, list[Any]]] = {}
    data_month_trends: dict[tuple[str, str, str], Any] = {}
    data_month_manifests: dict[tuple[str, str, str], Any] = {}
    data_month_paths: dict[tuple[str, str, str], dict[str, Path]] = {}
    for path in iter_files(root):
        relative = path.relative_to(root)
        display_relative = display_relative_path(relative)
        export_key = retained_export_key(relative)
        data_month_key = retained_data_month_key(relative)
        if export_key is not None:
            retained_export_files.setdefault(export_key, set()).add(relative.name)
        if path.is_symlink():
            issues.append(f"{display_relative}: symlink artifact is not allowed")
            continue
        if forbidden_path(relative):
            issues.append(f"{display_relative}: forbidden raw/transient artifact")
            continue
        suffix = relative.suffix.lower()
        try:
            if content_scanned_infrastructure_artifact(relative):
                if contains_infrastructure_risk_text(
                    path.read_text(encoding="utf-8"), relative=relative
                ):
                    issues.append(f"{display_relative}: infrastructure text contains raw/sensitive evidence")
            if suffix == ".json":
                data = parse_json(path)
                if allowed_infrastructure_artifact(relative) and contains_decoded_infrastructure_risk(data):
                    issues.append(f"{display_relative}: infrastructure text contains raw/sensitive evidence")
                json_kind = allowed_retained_json_artifact(relative)
                if json_kind == "manifest":
                    expected_mode = expected_mode_from_retained_export_path(relative)
                    issues.extend(f"{display_relative}: {issue}" for issue in validate_manifest(data, expected_mode=expected_mode))
                    if expected_mode is not None and isinstance(data, dict) and isinstance(data.get("mode"), str):
                        retained_export_modes.setdefault(tuple(relative.parts[:2]), {})["manifest"] = data["mode"]
                    if export_key is not None and isinstance(data, dict):
                        window_identity = retained_window_identity(data.get("window"))
                        if window_identity is not None:
                            retained_export_windows.setdefault(export_key, {})["manifest"] = window_identity
                    if data_month_key is not None and isinstance(data, dict):
                        data_month_manifests[data_month_key] = data
                        data_month_paths.setdefault(data_month_key, {})["manifest"] = relative
                elif json_kind == "trend":
                    expected_mode = expected_mode_from_retained_export_path(relative)
                    issues.extend(f"{display_relative}: {issue}" for issue in validate_trend(data, expected_mode=expected_mode))
                    if expected_mode is not None and isinstance(data, dict):
                        window = data.get("window")
                        if isinstance(window, dict) and isinstance(window.get("mode"), str):
                            retained_export_modes.setdefault(tuple(relative.parts[:2]), {})["trend"] = window["mode"]
                        if export_key is not None:
                            retained_export_trends[export_key] = data
                            window_identity = retained_window_identity(window)
                            if window_identity is not None:
                                retained_export_windows.setdefault(export_key, {})["trend"] = window_identity
                    if data_month_key is not None and isinstance(data, dict):
                        data_month_trends[data_month_key] = data
                        data_month_paths.setdefault(data_month_key, {})["trend"] = relative
                elif relative.parts[0] in {"data", "reports"} or not allowed_infrastructure_artifact(relative):
                    issues.append(f"{display_relative}: unexpected JSON artifact")
                    if contains_risky_key(data):
                        issues.append(f"{display_relative}: JSON key contains raw/sensitive evidence")
                    if contains_risky_text(data):
                        issues.append(f"{display_relative}: retained text contains raw/sensitive evidence")
            elif suffix == ".jsonl":
                rows = parse_jsonl(path)
                jsonl_kind = allowed_retained_jsonl_artifact(relative)
                if jsonl_kind is None:
                    issues.append(f"{display_relative}: unexpected JSONL artifact")
                else:
                    validator = validate_episode if jsonl_kind == "episode" else validate_turn_flag
                    for index, row in enumerate(rows, 1):
                        issues.extend(f"{display_relative}:{index}: {issue}" for issue in validator(row))
                    if export_key is not None:
                        retained_export_rows.setdefault(export_key, {}).setdefault(jsonl_kind, []).extend(rows)
                    if data_month_key is not None:
                        data_month_rows.setdefault(data_month_key, {}).setdefault(jsonl_kind, []).extend(rows)
                        data_month_paths.setdefault(data_month_key, {})[jsonl_kind] = relative
            elif relative.parts[0] in {"data", "reports"} and suffix in {".md", ".txt"}:
                if not allowed_retained_text_artifact(relative):
                    issues.append(f"{display_relative}: unexpected retained text artifact location")
                include_safety_markers = relative.as_posix() not in {"data/README.md", "reports/README.md"}
                if contains_risky_text(path.read_text(encoding="utf-8"), include_safety_markers=include_safety_markers):
                    issues.append(f"{display_relative}: retained text contains raw/sensitive evidence")
            elif relative.parts[0] in {"data", "reports"} and suffix not in VALID_RETAINED_SUFFIXES:
                issues.append(f"{display_relative}: unexpected retained artifact suffix")
                try:
                    if contains_risky_text(path.read_text(encoding="utf-8")):
                        issues.append(f"{display_relative}: retained text contains raw/sensitive evidence")
                except UnicodeDecodeError:
                    pass
            elif not allowed_infrastructure_artifact(relative):
                issues.append(f"{display_relative}: unexpected retained artifact location")
                if suffix in TEXT_ARTIFACT_SUFFIXES:
                    try:
                        if contains_risky_text(path.read_text(encoding="utf-8")):
                            issues.append(f"{display_relative}: retained text contains raw/sensitive evidence")
                    except UnicodeDecodeError:
                        pass
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            issues.append(f"{display_relative}: {safe_exception_message(exc)}")
    for export_dir, names in sorted(retained_export_files.items()):
        if names != RETAINED_EXPORT_FILES:
            issues.append(f"{Path(*export_dir)}: retained export directory is incomplete or has extra files")
        modes = retained_export_modes.get(export_dir, {})
        if modes.get("trend") and modes.get("manifest") and modes["trend"] != modes["manifest"]:
            issues.append(f"{Path(*export_dir)}: retained export mode differs between trend and manifest")
        windows = retained_export_windows.get(export_dir, {})
        if windows.get("trend") and windows.get("manifest") and windows["trend"] != windows["manifest"]:
            issues.append(f"{Path(*export_dir)}: retained export window differs between trend and manifest")
        issues.extend(
            validate_retained_export_consistency(
                export_dir,
                retained_export_rows.get(export_dir, {}),
                retained_export_trends.get(export_dir),
            )
        )
    for data_month in sorted(set(data_month_rows) | set(data_month_trends) | set(data_month_manifests)):
        trend = data_month_trends.get(data_month)
        manifest = data_month_manifests.get(data_month)
        if isinstance(trend, dict) and isinstance(manifest, dict):
            trend_window = retained_window_identity(trend.get("window"))
            manifest_window = retained_window_identity(manifest.get("window"))
            if trend_window is not None and manifest_window is not None and trend_window != manifest_window:
                issues.append(f"{Path(*data_month)}: retained export window differs between trend and manifest")
        issues.extend(
            validate_retained_export_consistency(
                data_month,
                data_month_rows.get(data_month, {}),
                data_month_trends.get(data_month),
                manifest=data_month_manifests.get(data_month),
                artifact_paths=data_month_paths.get(data_month),
                data_month=data_month,
            )
        )
    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate retained session retrospective history artifacts.")
    parser.add_argument("--root", default=".")
    args = parser.parse_args(argv)
    issues = validate_root(Path(args.root).resolve())
    if issues:
        for issue in issues:
            print(issue)
        return 1
    print("retained history is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
