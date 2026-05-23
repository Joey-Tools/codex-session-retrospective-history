#!/usr/bin/env python3
from __future__ import annotations

import argparse
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
SOURCE_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
TIMESTAMP_RE = re.compile(
    r"^\d{4}-(?:(?:01|03|05|07|08|10|12)-(?:0[1-9]|[12]\d|3[01])|(?:04|06|09|11)-(?:0[1-9]|[12]\d|30)|02-(?:0[1-9]|1\d|2[0-9]))T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?Z$"
)
TEXT_ARTIFACT_SUFFIXES = frozenset({".json", ".jsonl", ".md", ".txt"})
VALID_RETAINED_SUFFIXES = TEXT_ARTIFACT_SUFFIXES
STRIPPABLE_ARTIFACT_SUFFIXES = TEXT_ARTIFACT_SUFFIXES | COMPRESSED_ARTIFACT_SUFFIXES
ROOT_DOC_FILES = frozenset({".gitignore", "AGENTS.md", "README.md", "data/README.md", "reports/README.md"})
WORKFLOW_SUFFIXES = frozenset({".yaml", ".yml"})
SCHEMA_FILES = frozenset({"retained-manifest-v1.schema.json", "session-retrospective-v1.schema.json"})
RETAINED_EXPORT_DIRS = frozenset({("retained", "daily"), ("retained", "weekly"), ("retained", "baseline")})
RETAINED_EXPORT_FILES = frozenset({"episodes.jsonl", "turn_flags.jsonl", "trend_report.json", "retained_manifest.json"})
RETAINED_EVIDENCE_HOSTS = frozenset({"local", "miku-bot-dev", "hoteng-srv-01", "custom_source"})
RETAINED_HOSTS = frozenset((*RETAINED_EVIDENCE_HOSTS, "scope"))
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
        "stale_host",
        "unreachable",
    }
)
MAX_MANIFEST_SOURCES = 16
MAX_COVERAGE_GAPS = 100
MAX_SAFE_TOKEN_LENGTH = 64
MAX_TOKEN_ARRAY_ITEMS = 16
MAX_COUNT_MAP_PROPERTIES = 64
MAX_COUNT = 1_000_000
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
        r"(?<![A-Za-z0-9_])[\"']?[A-Za-z0-9._-]*(?:password|passwd|pwd|credential|secret|token|api[._-]?key|authorization|private[._-]?key)[A-Za-z0-9._-]*[\"']?\s*[:=]",
        re.I,
    ),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b", re.I),
    re.compile(r"\b(?:sk|rk)[-_](?:proj[-_])?[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"(^|[^0-9a-fA-F])[0-9a-fA-F]{64}([^0-9a-fA-F]|$)"),
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    re.compile(r"\brollout(?:-summary)?-[A-Za-z0-9_.-]+\.jsonl\b", re.I),
    re.compile(
        r"(?<![A-Za-z0-9_])[\"']?(?:session|turn|episode)[-_ ]?id[\"']?\s*[:=]\s*[\"']?(?!session_ref_v1:|turn_ref_v1:|episode_ref_v1:)[A-Za-z0-9_.:-]{6,}\b",
        re.I,
    ),
    re.compile(r"\b(?:[A-Za-z0-9-]+\.)+(?:internal|corp|local|lan|example|invalid|test)\b", re.I),
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
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", stem)
    tokens = [token for token in re.split(r"[^a-z0-9]+", separated.lower()) if token]
    normalized = "_".join(tokens)
    if normalized in FORBIDDEN_NAME_STEMS:
        return True
    compacted = "".join(tokens)
    if any(compacted.startswith(prefix) for prefix in FORBIDDEN_COMPACT_NAME_PREFIXES):
        return True
    return any(part in compacted for part in FORBIDDEN_COMPACT_NAME_PARTS)


def forbidden_path(relative: Path) -> bool:
    parts = tuple(part.lower() for part in relative.parts)
    if any(part in FORBIDDEN_COMPONENTS or forbidden_name(part) for part in parts[:-1]):
        return True
    name = relative.name.lower()
    return name in FORBIDDEN_FILENAMES or forbidden_name(name) or name.startswith("rollout")


def parse_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_jsonl(path: Path) -> list[Any]:
    rows: list[Any] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {line_no}: invalid JSONL: {exc}") from exc
    return rows


def contains_risky_text(value: Any) -> bool:
    if isinstance(value, str):
        return any(pattern.search(value) for pattern in RISK_PATTERNS)
    if isinstance(value, dict):
        return any(contains_risky_text(child) for child in value.values())
    if isinstance(value, list):
        return any(contains_risky_text(child) for child in value)
    return False


def contains_risky_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and contains_risky_text(key):
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
    return value is None or (isinstance(value, str) and TIMESTAMP_RE.fullmatch(value) is not None)


def valid_non_negative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_COUNT


def valid_safe_token(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= MAX_SAFE_TOKEN_LENGTH
        and SAFE_TOKEN_RE.fullmatch(value) is not None
        and not contains_risky_text(value)
    )


def valid_retained_host(value: Any) -> bool:
    return isinstance(value, str) and value in RETAINED_EVIDENCE_HOSTS


def valid_retained_coverage_host(value: Any) -> bool:
    return isinstance(value, str) and value in RETAINED_HOSTS


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


def allowed_retained_text_artifact(relative: Path) -> bool:
    path_text = relative.as_posix()
    if path_text in {"data/README.md", "reports/README.md"}:
        return True
    parts = relative.parts
    if len(parts) == 5 and parts[0] == "reports" and parts[1] in {"daily", "weekly"}:
        year, month, day_file = parts[2], parts[3], parts[4]
        return bool(
            re.fullmatch(r"\d{4}", year)
            and re.fullmatch(r"\d{2}", month)
            and relative.suffix.lower() == ".md"
            and re.fullmatch(r"\d{2}", Path(day_file).stem)
        )
    if len(parts) == 4 and parts[:3] == ("reports", "baseline", "90-day-windows"):
        return bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}_to_\d{4}-\d{2}-\d{2}\.md", parts[3]))
    return False


def valid_year_month(parts: tuple[str, ...], start: int) -> bool:
    return len(parts) > start + 1 and bool(re.fullmatch(r"\d{4}", parts[start]) and re.fullmatch(r"\d{2}", parts[start + 1]))


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
        if not valid_non_negative_int(count):
            issues.append(f"{label} value must be a bounded non-negative integer")
    return issues


def validate_window(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["window must be an object"]
    issues = unexpected_keys(value, WINDOW_KEYS) + missing_keys(value, WINDOW_KEYS)
    if not valid_safe_token(value.get("mode")):
        issues.append("window.mode must be a safe token")
    if not isinstance(value.get("start"), str) or TIMESTAMP_RE.fullmatch(value.get("start", "")) is None:
        issues.append("window.start must be timestamp")
    if not isinstance(value.get("end"), str) or TIMESTAMP_RE.fullmatch(value.get("end", "")) is None:
        issues.append("window.end must be timestamp")
    return issues


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
    if not valid_timestamp_or_null(row.get("start")):
        issues.append("start must be timestamp or null")
    if not valid_timestamp_or_null(row.get("end")):
        issues.append("end must be timestamp or null")
    if row.get("cwd") is not None and not PATH_REF_RE.fullmatch(str(row.get("cwd"))):
        issues.append("cwd must be path_ref_v1 or null")
    if not valid_safe_token(row.get("model_era")):
        issues.append("model_era must be a safe token")
    issues.extend(validate_retained_text(row.get("topic"), "topic"))
    if not valid_non_negative_int(row.get("turn_count")):
        issues.append("turn_count must be a bounded non-negative integer")
    issues.extend(validate_safe_token_array(row.get("friction_flags"), "friction_flags"))
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
        issues.append("source_hash must be a 64-character hex digest")
    if not valid_timestamp_or_null(row.get("timestamp")):
        issues.append("timestamp must be timestamp or null")
    if row.get("cwd") is not None and not PATH_REF_RE.fullmatch(str(row.get("cwd"))):
        issues.append("cwd must be path_ref_v1 or null")
    if row.get("model") is not None and not valid_safe_token(row.get("model")):
        issues.append("model must be a safe token or null")
    if not valid_safe_token(row.get("model_era")):
        issues.append("model_era must be a safe token")
    for key in ("redacted_user_prompt_summary", "assistant_action_summary", "prompt_improvement"):
        issues.extend(validate_retained_text(row.get(key), key, nullable=(key == "prompt_improvement")))
    issues.extend(validate_safe_token_array(row.get("issue_flags"), "issue_flags", min_items=1))
    return issues


def validate_trend(data: Any) -> list[str]:
    if not isinstance(data, dict):
        return ["trend must be an object"]
    issues = unexpected_keys(data, TREND_KEYS) + missing_keys(data, TREND_KEYS)
    if contains_risky_key(data):
        issues.append("trend JSON key contains raw/sensitive evidence")
    if data.get("schema_version") != 1:
        issues.append("trend schema_version must be 1")
    issues.extend(validate_window(data.get("window")))
    for key in ("turn_count", "flagged_turn_count", "episode_count"):
        if not valid_non_negative_int(data.get(key)):
            issues.append(f"{key} must be a non-negative integer")
    for key in ("flags", "hosts", "model_eras"):
        issues.extend(validate_count_map(data.get(key), key))
    issues.extend(validate_coverage_gaps(data.get("coverage_gaps")))
    return issues


def validate_manifest(data: Any) -> list[str]:
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
    if data.get("schema_version") != 1:
        issues.append("manifest schema_version must be 1")
    if not valid_safe_token(data.get("mode")):
        issues.append("manifest mode must be a safe token")
    issues.extend(validate_window(data.get("window")))
    if not isinstance(data.get("sources"), list) or not data.get("sources"):
        issues.append("manifest sources must be a non-empty array")
    else:
        if len(data["sources"]) > MAX_MANIFEST_SOURCES:
            issues.append(f"manifest sources must contain at most {MAX_MANIFEST_SOURCES} items")
        for index, source in enumerate(data.get("sources", []), 1):
            issues.extend(f"sources[{index}]: {issue}" for issue in validate_source_summary(source))
    issues.extend(validate_coverage_gaps(data.get("coverage_gaps")))
    if data.get("redaction_policy_version") != 1:
        issues.append("manifest redaction_policy_version must be 1")
    if data.get("retention_note") != "Derived retained manifest; raw location fields removed and opaque refs preserved.":
        issues.append("manifest retention_note is invalid")
    if data.get("retention_safe") is not True:
        issues.append("manifest retention_safe must be true")
    return issues


def validate_root(root: Path) -> list[str]:
    root = root.resolve()
    issues: list[str] = []
    retained_export_files: dict[tuple[str, str], set[str]] = {}
    for path in iter_files(root):
        relative = path.relative_to(root)
        if len(relative.parts) == 3 and relative.parts[:2] in RETAINED_EXPORT_DIRS:
            retained_export_files.setdefault(tuple(relative.parts[:2]), set()).add(relative.name)
        if path.is_symlink():
            issues.append(f"{relative}: symlink artifact is not allowed")
            continue
        if forbidden_path(relative):
            issues.append(f"{relative}: forbidden raw/transient artifact")
            continue
        suffix = relative.suffix.lower()
        try:
            if suffix == ".json":
                data = parse_json(path)
                json_kind = allowed_retained_json_artifact(relative)
                if json_kind == "manifest":
                    issues.extend(f"{relative}: {issue}" for issue in validate_manifest(data))
                elif json_kind == "trend":
                    issues.extend(f"{relative}: {issue}" for issue in validate_trend(data))
                elif relative.parts[0] in {"data", "reports"} or not allowed_infrastructure_artifact(relative):
                    issues.append(f"{relative}: unexpected JSON artifact")
                    if contains_risky_key(data):
                        issues.append(f"{relative}: JSON key contains raw/sensitive evidence")
                    if contains_risky_text(data):
                        issues.append(f"{relative}: retained text contains raw/sensitive evidence")
            elif suffix == ".jsonl":
                rows = parse_jsonl(path)
                jsonl_kind = allowed_retained_jsonl_artifact(relative)
                if jsonl_kind is None:
                    issues.append(f"{relative}: unexpected JSONL artifact")
                else:
                    validator = validate_episode if jsonl_kind == "episode" else validate_turn_flag
                    for index, row in enumerate(rows, 1):
                        issues.extend(f"{relative}:{index}: {issue}" for issue in validator(row))
            elif relative.parts[0] in {"data", "reports"} and suffix in {".md", ".txt"}:
                if not allowed_retained_text_artifact(relative):
                    issues.append(f"{relative}: unexpected retained text artifact location")
                if contains_risky_text(path.read_text(encoding="utf-8")):
                    issues.append(f"{relative}: retained text contains raw/sensitive evidence")
            elif relative.parts[0] in {"data", "reports"} and suffix not in VALID_RETAINED_SUFFIXES:
                issues.append(f"{relative}: unexpected retained artifact suffix")
                try:
                    if contains_risky_text(path.read_text(encoding="utf-8")):
                        issues.append(f"{relative}: retained text contains raw/sensitive evidence")
                except UnicodeDecodeError:
                    pass
            elif not allowed_infrastructure_artifact(relative):
                issues.append(f"{relative}: unexpected retained artifact location")
                if suffix in TEXT_ARTIFACT_SUFFIXES:
                    try:
                        if contains_risky_text(path.read_text(encoding="utf-8")):
                            issues.append(f"{relative}: retained text contains raw/sensitive evidence")
                    except UnicodeDecodeError:
                        pass
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            issues.append(f"{relative}: {exc}")
    for export_dir, names in sorted(retained_export_files.items()):
        if names != RETAINED_EXPORT_FILES:
            issues.append(f"{Path(*export_dir)}: retained export directory is incomplete or has extra files")
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
