#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
from typing import Any


FORBIDDEN_COMPONENTS = frozenset({".codex", ".codex-local", ".codex-tmp", "raw", "scratch", "transient"})
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
PATH_REF_RE = re.compile(r"^path_ref_v1:[0-9a-f]{16}$")
SESSION_REF_RE = re.compile(r"^session_ref_v1:[0-9a-f]{20}$")
EPISODE_REF_RE = re.compile(r"^episode_ref_v1:[0-9a-f]{20}$")
TURN_REF_RE = re.compile(r"^turn_ref_v1:[0-9a-f]{20}$")
SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
RISK_PATTERNS = (
    re.compile(r"\b(?:https?|ssh)://", re.I),
    re.compile(r"\bgit@[A-Za-z0-9_.-]+:"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"(^|[^A-Za-z0-9_])(?:~|/(?:Users|home|root|private|tmp|var|etc|opt|Volumes|workspace|workspaces))/"),
    re.compile(r"(^|[^A-Za-z0-9_])(?:\./|\.\./)?\.codex(?:/|\\)"),
    re.compile(r"(^|[^A-Za-z0-9_])(?:sessions|archived_sessions)(?:/|\\)"),
    re.compile(r"\b[A-Za-z]:\\(?:Users|home|root|private|tmp|var|etc|opt|workspace|workspaces)\\"),
    re.compile(r"\b(?:password|passwd|pwd|credential|secret|token|api[_-]?key|authorization)\s*[:=]", re.I),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b", re.I),
    re.compile(r"\b(?:sk|rk)[-_](?:proj[-_])?[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"(^|[^0-9a-fA-F])[0-9a-fA-F]{64}([^0-9a-fA-F]|$)"),
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    re.compile(r"\brollout(?:-summary)?-[A-Za-z0-9_.-]+\.jsonl\b"),
    re.compile(
        r"\b(?:session|turn|episode)[-_ ]?id\s*[:=]\s*[\"']?(?!session_ref_v1:|turn_ref_v1:|episode_ref_v1:)[A-Za-z0-9_.:-]{6,}\b",
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
        if path.is_file():
            files.append(path)
    return sorted(files)


def iter_files(root: Path) -> list[Path]:
    git_files = git_visible_files(root)
    if git_files is not None:
        return git_files
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and ".git" not in path.relative_to(root).parts and "__pycache__" not in path.relative_to(root).parts
    )


def forbidden_name(name: str) -> bool:
    stem = name
    while True:
        next_stem, suffix = stem.rsplit(".", 1) if "." in stem else (stem, "")
        if not suffix:
            break
        stem = next_stem
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", stem)
    tokens = [token for token in re.split(r"[^a-z0-9]+", separated.lower()) if token]
    compacted = "".join(tokens)
    return any(part in compacted for part in FORBIDDEN_COMPACT_NAME_PARTS)


def forbidden_path(relative: Path) -> bool:
    if any(part in FORBIDDEN_COMPONENTS for part in relative.parts):
        return True
    name = relative.name
    return name in FORBIDDEN_FILENAMES or forbidden_name(name) or (name.startswith("rollout") and name.endswith(".jsonl"))


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
            raise ValueError(f"{path}:{line_no}: invalid JSONL: {exc}") from exc
    return rows


def contains_risky_text(value: Any) -> bool:
    if isinstance(value, str):
        return any(pattern.search(value) for pattern in RISK_PATTERNS)
    if isinstance(value, dict):
        return any(contains_risky_text(child) for child in value.values())
    if isinstance(value, list):
        return any(contains_risky_text(child) for child in value)
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


def validate_episode(row: Any) -> list[str]:
    issues: list[str] = []
    if not isinstance(row, dict):
        return ["episode row must be an object"]
    if not EPISODE_REF_RE.fullmatch(str(row.get("episode_id", ""))):
        issues.append("episode_id must be episode_ref_v1")
    if not SESSION_REF_RE.fullmatch(str(row.get("session_id", ""))):
        issues.append("session_id must be session_ref_v1")
    if row.get("cwd") is not None and not PATH_REF_RE.fullmatch(str(row.get("cwd"))):
        issues.append("cwd must be path_ref_v1 or null")
    if not isinstance(row.get("topic"), str) or contains_risky_text(row.get("topic")):
        issues.append("topic contains retained-text risk")
    return issues


def validate_turn_flag(row: Any) -> list[str]:
    issues: list[str] = []
    if not isinstance(row, dict):
        return ["turn flag row must be an object"]
    if not TURN_REF_RE.fullmatch(str(row.get("turn_id", ""))):
        issues.append("turn_id must be turn_ref_v1")
    if not EPISODE_REF_RE.fullmatch(str(row.get("episode_id", ""))):
        issues.append("episode_id must be episode_ref_v1")
    if not SESSION_REF_RE.fullmatch(str(row.get("session_id", ""))):
        issues.append("session_id must be session_ref_v1")
    if not PATH_REF_RE.fullmatch(str(row.get("source_path", ""))):
        issues.append("source_path must be path_ref_v1")
    if row.get("cwd") is not None and not PATH_REF_RE.fullmatch(str(row.get("cwd"))):
        issues.append("cwd must be path_ref_v1 or null")
    for key in ("redacted_user_prompt_summary", "assistant_action_summary", "prompt_improvement"):
        value = row.get(key)
        if value is not None and (not isinstance(value, str) or contains_risky_text(value)):
            issues.append(f"{key} contains retained-text risk")
    return issues


def validate_manifest(data: Any) -> list[str]:
    issues: list[str] = []
    if not isinstance(data, dict):
        return ["manifest must be an object"]
    if contains_raw_path_fields(data):
        issues.append("manifest contains raw root/path field")
    if data.get("retention_safe") is not True:
        issues.append("manifest retention_safe must be true")
    for source in data.get("sources", []):
        if not isinstance(source, dict) or not PATH_REF_RE.fullmatch(str(source.get("root_ref", ""))):
            issues.append("manifest source root_ref must be path_ref_v1")
    return issues


def validate_root(root: Path) -> list[str]:
    root = root.resolve()
    issues: list[str] = []
    for path in iter_files(root):
        relative = path.relative_to(root)
        if forbidden_path(relative):
            issues.append(f"{relative}: forbidden raw/transient artifact")
            continue
        try:
            if relative.suffix == ".json":
                data = parse_json(path)
                if relative.parts[:2] == ("data", "manifests"):
                    issues.extend(f"{relative}: {issue}" for issue in validate_manifest(data))
                elif relative.parts[0] in {"data", "reports"} and contains_risky_text(data):
                    issues.append(f"{relative}: retained text contains raw/sensitive evidence")
            elif relative.suffix == ".jsonl":
                rows = parse_jsonl(path)
                validator = validate_episode if relative.parts[:2] == ("data", "episodes") else validate_turn_flag if relative.parts[:2] == ("data", "turn_flags") else None
                if validator is None:
                    issues.append(f"{relative}: unexpected JSONL artifact")
                else:
                    for index, row in enumerate(rows, 1):
                        issues.extend(f"{relative}:{index}: {issue}" for issue in validator(row))
            elif relative.parts[0] in {"data", "reports"} and relative.suffix.lower() in {".md", ".txt"}:
                if contains_risky_text(path.read_text(encoding="utf-8")):
                    issues.append(f"{relative}: retained text contains raw/sensitive evidence")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            issues.append(f"{relative}: {exc}")
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
