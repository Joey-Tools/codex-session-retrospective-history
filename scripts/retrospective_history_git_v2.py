#!/usr/bin/env python3
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import time
from typing import Any, Iterable


RUN_MODES = frozenset({"baseline", "daily", "session", "weekly"})
RUN_ARTIFACTS = frozenset(
    {
        "coverage.json",
        "episodes.jsonl",
        "manifest.json",
        "report.md",
        "summary.json",
        "topics.jsonl",
        "trend_report.json",
        "turn_findings.jsonl",
    }
)
MAX_ARTIFACT_BYTES = {
    "coverage.json": 8 * 1024 * 1024,
    "episodes.jsonl": 16 * 1024 * 1024,
    "manifest.json": 8 * 1024 * 1024,
    "report.md": 256 * 1024,
    "summary.json": 8 * 1024 * 1024,
    "topics.jsonl": 16 * 1024 * 1024,
    "trend_report.json": 8 * 1024 * 1024,
    "turn_findings.jsonl": 16 * 1024 * 1024,
}
MAX_COMMIT_OBJECT_BYTES = 64 * 1024
MAX_CHANGED_RUN_PATHS = 4096
MAX_DIFF_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_REVISION_BYTES = 256
MAX_PATH_BYTES = 256
MAX_DIAGNOSTICS = 64
MAX_GIT_STDERR_BYTES = 4096
GIT_TIMEOUT_SECONDS = 30
COMMIT_PAGE_SIZE = 128
MAX_RANGE_COMMITS = 512
MAX_SEMANTIC_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_SEMANTIC_JSONL_ROWS = 200_000
MAX_RANGE_REVISION_FACTS = 1_000_000
PROCESS_IO_CHUNK_BYTES = 64 * 1024
PROCESS_TERMINATION_SECONDS = 1
DIAGNOSTIC_OMISSION = "validation: additional issues omitted"
WINDOW_ROUTE_COMPONENT_COUNT = 32
RUN_ROUTE_COMPONENT_COUNT = 32
RUN_PATH_COMPONENT_COUNT = 68
WINDOW_ROUTE_DOMAIN = b"session-retrospective-retained-window-route-v2"
V2_PUBLISHER_NAME = b"Codex Session Retrospective Publisher"
V2_PUBLISHER_EMAIL = b"12524680+JoeyTeng@users.noreply.github.com"
V2_SIGNING_FINGERPRINTS = frozenset({b"40FA5D05AC7A3D5C180B037FF6DCF7A06FFC9C52"})
FORBIDDEN_TRANSIENT_COMPONENTS = frozenset(
    {
        b".codex",
        b".codex-local",
        b".codex-tmp",
        b"archived_sessions",
        b"raw",
        b"scratch",
        b"sessions",
        b"transient",
    }
)
FORBIDDEN_TRANSIENT_FILENAMES = frozenset(
    {
        b"auth.json",
        b"config.toml",
        b"history.jsonl",
        b"session_index.jsonl",
        b"source_metadata.json",
        b"shard_manifest.json",
        b"shards.jsonl",
        b"turn_summaries.jsonl",
    }
)
FORBIDDEN_TRANSIENT_NAME_STEMS = frozenset(
    {
        b"history",
        b"session_index",
        b"shard_manifest",
        b"shards",
        b"source_metadata",
        b"turn_summaries",
    }
)
FORBIDDEN_TRANSIENT_COMPACT_PARTS = frozenset(
    {
        b"conversationlog",
        b"fullprompt",
        b"messagelog",
        b"promptlog",
        b"rawtranscript",
        b"tooloutput",
        b"turnsummaries",
        b"userprompt",
    }
)
STRIPPABLE_TRANSIENT_SUFFIXES = frozenset(
    {b".bz2", b".gz", b".json", b".jsonl", b".md", b".txt", b".xz", b".zip", b".zst"}
)
EDITOR_TRANSIENT_SUFFIX_RE = re.compile(
    rb"\.(?:bak|backup|old|orig|save|swap|sw[a-z]|temp|temporary|tmp)(?:\.[0-9]+)?$",
    re.I,
)

OID_RE = re.compile(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})")
RAW_DIFF_RE = re.compile(
    rb":(?P<old_mode>[0-7]{6}) (?P<new_mode>[0-7]{6}) "
    rb"(?P<old_oid>[0-9a-f]{40}|[0-9a-f]{64}) "
    rb"(?P<new_oid>[0-9a-f]{40}|[0-9a-f]{64}) "
    rb"(?P<status>[A-Z])(?:[0-9]+)?"
)
DATE_COMPONENT = rb"\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
WINDOW_RE = re.compile(
    rb"(?P<start>" + DATE_COMPONENT + rb")(?:_to_(?P<end>" + DATE_COMPONENT + rb"))?"
)
RUN_ID_RE = re.compile(rb"[0-9a-f]{64}")
ROUTE_COMPONENT_RE = re.compile(rb"[0-9a-f]{2}")
CAMPAIGN_REF_RE = re.compile(r"campaign_ref_v2:[0-9a-f]{32}")
REVISION_REF_PATTERNS = {
    "run": re.compile(r"run_revision_ref_v2:[0-9a-f]{32}"),
    "coverage": re.compile(r"coverage_revision_ref_v2:[0-9a-f]{32}"),
    "episode": re.compile(r"episode_revision_ref_v2:[0-9a-f]{32}"),
    "gap": re.compile(r"gap_revision_ref_v2:[0-9a-f]{32}"),
    "summary": re.compile(r"summary_revision_ref_v2:[0-9a-f]{32}"),
    "topic": re.compile(r"topic_revision_ref_v2:[0-9a-f]{32}"),
    "trend": re.compile(r"trend_revision_ref_v2:[0-9a-f]{32}"),
    "turn_finding": re.compile(r"turn_finding_revision_ref_v2:[0-9a-f]{32}"),
}
REVISION_ARTIFACT_FIELDS = {
    "coverage.json": (
        "coverage",
        "coverage_revision_ref",
        "predecessor_coverage_revision_ref",
        "supersedes_coverage_revision_refs",
    ),
    "episodes.jsonl": (
        "episode",
        "episode_revision_ref",
        "predecessor_episode_revision_ref",
        "supersedes_episode_revision_refs",
    ),
    "summary.json": (
        "summary",
        "summary_revision_ref",
        "predecessor_summary_revision_ref",
        "supersedes_summary_revision_refs",
    ),
    "topics.jsonl": (
        "topic",
        "topic_revision_ref",
        "predecessor_topic_revision_ref",
        "supersedes_topic_revision_refs",
    ),
    "trend_report.json": (
        "trend",
        "trend_revision_ref",
        "predecessor_trend_revision_ref",
        "supersedes_trend_revision_refs",
    ),
    "turn_findings.jsonl": (
        "turn_finding",
        "turn_finding_revision_ref",
        "predecessor_turn_finding_revision_ref",
        "supersedes_turn_finding_revision_refs",
    ),
}
SEMANTIC_JSON_ARTIFACTS = frozenset(
    {"coverage.json", "manifest.json", "summary.json", "trend_report.json"}
)
SEMANTIC_JSONL_ARTIFACTS = frozenset(
    {"episodes.jsonl", "topics.jsonl", "turn_findings.jsonl"}
)
SEMANTIC_ARTIFACTS = SEMANTIC_JSON_ARTIFACTS | SEMANTIC_JSONL_ARTIFACTS
IDENTITY_RE = re.compile(
    re.escape(V2_PUBLISHER_NAME) + rb" <" + re.escape(V2_PUBLISHER_EMAIL) + rb"> "
    rb"(?P<timestamp>0|[1-9][0-9]{0,11}) \+0000"
)
COMMIT_MESSAGE_RE = re.compile(
    rb"Publish session retrospective v2 "
    rb"(?P<mode>baseline|daily|session|weekly) "
    rb"(?P<window>" + DATE_COMPONENT + rb"(?:_to_" + DATE_COMPONENT + rb")?) "
    rb"(?P<run_ref>run_ref_v2:[0-9a-f]{64})\n"
)
ARMOR_HEADER_RE = re.compile(rb"[A-Za-z][A-Za-z0-9-]{0,31}: [\x20-\x7e]{0,200}")
ARMOR_PAYLOAD_RE = re.compile(rb"[A-Za-z0-9+/]+={0,2}")
ARMOR_CHECKSUM_RE = re.compile(rb"=[A-Za-z0-9+/]{4}")
VALIDSIG_FINGERPRINT_RE = re.compile(rb"(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})")
VALIDSIG_DATE_RE = re.compile(rb"\d{4}-\d{2}-\d{2}")
VALIDSIG_CLASS_RE = re.compile(rb"[0-9A-Fa-f]{2}")
VALIDSIG_STATUS_PREFIX = b"[GNUPG:] VALIDSIG "
COMMIT_HEADER_ORDER = (b"tree", b"parent", b"author", b"committer")
ZERO_OIDS = frozenset({b"0" * 40, b"0" * 64})


class _GitFailure(Exception):
    pass


class _ParseFailure(Exception):
    pass


class _CommitLimitExceeded(Exception):
    pass


class _SemanticFailure(Exception):
    pass


class _DuplicateKeyError(ValueError):
    pass


class _IssueCollector:
    def __init__(self) -> None:
        self.items: list[str] = []
        self._seen: set[str] = set()
        self._truncated = False

    def add(self, issue: str) -> None:
        if self._truncated or issue in self._seen:
            return
        self._seen.add(issue)
        if len(self.items) < MAX_DIAGNOSTICS - 1:
            self.items.append(issue)
        elif not self._truncated:
            self.items.append(DIAGNOSTIC_OMISSION)
            self._truncated = True


@dataclass(frozen=True)
class _RunPath:
    value: str
    mode: str
    window: str
    run_id: str
    artifact: str


@dataclass(frozen=True)
class _DiffEntry:
    path: bytes
    old_mode: bytes
    new_mode: bytes
    old_oid: bytes
    new_oid: bytes
    status: str
    run_path: _RunPath | None


@dataclass(frozen=True)
class _ParsedDiff:
    run_entries: tuple[_DiffEntry, ...]
    changed_path_count: int
    forbidden_transient_path_changed: bool
    non_run_path_changed: bool


@dataclass(frozen=True)
class _ObjectInfo:
    kind: bytes
    size: int


@dataclass(frozen=True)
class _RevisionFact:
    family: str
    current: str
    predecessors: tuple[str, ...]


@dataclass(frozen=True)
class _PublicationFacts:
    commit_index: int
    campaign_ref: str | None
    publication_role: str | None
    revisions: tuple[_RevisionFact, ...]


@dataclass(frozen=True)
class _PublisherIdentity:
    name: bytes
    email: bytes


@dataclass(frozen=True)
class _CommitHeader:
    name: bytes
    value: bytes


def _git_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    return environment


def _close_process_stream(stream: object) -> None:
    if stream is None:
        return
    try:
        stream.close()  # type: ignore[attr-defined]
    except OSError:
        pass


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
    for stream in (process.stdin, process.stdout, process.stderr):
        _close_process_stream(stream)
    try:
        process.wait(timeout=PROCESS_TERMINATION_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _run_process_bounded(
    arguments: list[str],
    *,
    input_data: bytes | None,
    environment: dict[str, str],
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    timeout_seconds: float,
) -> subprocess.CompletedProcess[bytes]:
    if max_stdout_bytes < 0 or max_stderr_bytes < 0 or timeout_seconds <= 0:
        raise _GitFailure
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=environment,
            bufsize=0,
        )
    except OSError as exc:
        raise _GitFailure from exc

    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    input_view = memoryview(input_data if input_data is not None else b"")
    input_offset = 0
    deadline = time.monotonic() + timeout_seconds
    try:
        if process.stdout is None or process.stderr is None:
            raise _GitFailure
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")

        if process.stdin is not None:
            if input_view:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                process.stdin.close()

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _GitFailure
            events = selector.select(min(remaining, 0.1))
            for key, _ in events:
                stream = key.fileobj
                if key.data == "stdin":
                    try:
                        written = os.write(
                            stream.fileno(),  # type: ignore[union-attr]
                            input_view[
                                input_offset : input_offset + PROCESS_IO_CHUNK_BYTES
                            ],
                        )
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        written = 0
                        input_offset = len(input_view)
                    else:
                        input_offset += written
                    if input_offset >= len(input_view) or written == 0:
                        selector.unregister(stream)
                        _close_process_stream(stream)
                    continue

                buffer = stdout if key.data == "stdout" else stderr
                limit = max_stdout_bytes if key.data == "stdout" else max_stderr_bytes
                read_size = min(
                    PROCESS_IO_CHUNK_BYTES,
                    max(1, limit - len(buffer) + 1),
                )
                try:
                    chunk = os.read(
                        stream.fileno(),  # type: ignore[union-attr]
                        read_size,
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    _close_process_stream(stream)
                    continue
                if len(buffer) + len(chunk) > limit:
                    raise _GitFailure
                buffer.extend(chunk)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _GitFailure
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise _GitFailure from exc
    except (OSError, ValueError, _GitFailure) as exc:
        _terminate_process(process)
        if isinstance(exc, _GitFailure):
            raise
        raise _GitFailure from exc
    finally:
        selector.close()
        input_view.release()

    return subprocess.CompletedProcess(
        arguments,
        returncode,
        stdout=bytes(stdout),
        stderr=bytes(stderr),
    )


def _run_git(
    root: Path,
    arguments: list[str],
    *,
    input_data: bytes | None = None,
    allowed_returncodes: frozenset[int] = frozenset({0}),
    max_stdout_bytes: int = 4096,
) -> subprocess.CompletedProcess[bytes]:
    result = _run_process_bounded(
        ["git", "-C", str(root), *arguments],
        input_data=input_data,
        environment=_git_environment(),
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=MAX_GIT_STDERR_BYTES,
        timeout_seconds=GIT_TIMEOUT_SECONDS,
    )
    if result.returncode not in allowed_returncodes:
        raise _GitFailure
    return result


def _valid_revision(revision: str) -> bool:
    if not isinstance(revision, str) or not revision:
        return False
    try:
        encoded = revision.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return len(encoded) <= MAX_REVISION_BYTES and not any(
        byte < 0x20 or byte == 0x7F for byte in encoded
    )


def _resolve_commit(root: Path, revision: str) -> bytes | None:
    if not _valid_revision(revision):
        return None
    try:
        result = _run_git(
            root,
            [
                "rev-parse",
                "--verify",
                "--quiet",
                "--end-of-options",
                f"{revision}^{{commit}}",
            ],
            max_stdout_bytes=128,
        )
    except _GitFailure:
        return None
    oid = result.stdout.strip()
    return oid if OID_RE.fullmatch(oid) else None


def _valid_window(window: bytes) -> bool:
    match = WINDOW_RE.fullmatch(window)
    if match is None:
        return False
    try:
        start = dt.date.fromisoformat(match.group("start").decode("ascii"))
        raw_end = match.group("end")
        if raw_end is None:
            return True
        end = dt.date.fromisoformat(raw_end.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return False
    return start < end


def _update_route_frame(hasher: Any, frame_type: bytes, value: bytes) -> None:
    hasher.update(frame_type)
    hasher.update(len(value).to_bytes(8, "big"))
    hasher.update(value)


def _window_route_components(mode: bytes, window: bytes) -> tuple[str, ...]:
    hasher = hashlib.sha256()
    hasher.update(WINDOW_ROUTE_DOMAIN)
    _update_route_frame(hasher, b"M", mode)
    _update_route_frame(hasher, b"W", window)
    digest = hasher.hexdigest()
    return tuple(digest[offset : offset + 2] for offset in range(0, 64, 2))


def _parse_run_path(path: bytes) -> _RunPath | None:
    if len(path) > MAX_PATH_BYTES:
        return None
    try:
        value = path.decode("ascii")
    except UnicodeDecodeError:
        return None
    parts = value.split("/")
    if len(parts) != RUN_PATH_COMPONENT_COUNT or parts[0] != "runs":
        return None
    mode = parts[1]
    window_route = parts[2 : 2 + WINDOW_ROUTE_COMPONENT_COUNT]
    window = parts[2 + WINDOW_ROUTE_COMPONENT_COUNT]
    run_route_start = 3 + WINDOW_ROUTE_COMPONENT_COUNT
    run_route = parts[run_route_start : run_route_start + RUN_ROUTE_COMPONENT_COUNT]
    artifact = parts[-1]
    if mode not in RUN_MODES:
        return None
    if not _valid_window(window.encode("ascii")):
        return None
    if any(
        ROUTE_COMPONENT_RE.fullmatch(component.encode("ascii")) is None
        for component in (*window_route, *run_route)
    ):
        return None
    if tuple(window_route) != _window_route_components(
        mode.encode("ascii"), window.encode("ascii")
    ):
        return None
    run_id = "".join(run_route)
    if RUN_ID_RE.fullmatch(run_id.encode("ascii")) is None:
        return None
    if artifact not in RUN_ARTIFACTS:
        return None
    return _RunPath(
        value=value, mode=mode, window=window, run_id=run_id, artifact=artifact
    )


def _is_run_candidate(path: bytes) -> bool:
    first_component = path.split(b"/", 1)[0]
    return first_component.lower() == b"runs"


def _forbidden_transient_name(name: bytes) -> bool:
    candidates: list[bytes] = []
    stem = name
    while True:
        candidates.append(stem)
        if stem.endswith(b"~"):
            stem = stem[:-1]
            continue
        editor_match = EDITOR_TRANSIENT_SUFFIX_RE.search(stem)
        if editor_match is not None:
            stem = stem[: editor_match.start()]
            continue
        separator = stem.rfind(b".")
        if separator <= 0 or stem[separator:].lower() not in STRIPPABLE_TRANSIENT_SUFFIXES:
            break
        stem = stem[:separator]
    normalized_candidates = {
        candidate.lower() for candidate in candidates if candidate
    } | {
        candidate[1:].lower()
        for candidate in candidates
        if candidate.startswith(b".") and len(candidate) > 1
    }
    if normalized_candidates.intersection(FORBIDDEN_TRANSIENT_FILENAMES):
        return True
    separated = re.sub(rb"([a-z0-9])([A-Z])", rb"\1 \2", stem)
    tokens = [
        token for token in re.split(rb"[^a-z0-9]+", separated.lower()) if token
    ]
    normalized = b"_".join(tokens)
    compacted = b"".join(tokens)
    return (
        normalized in FORBIDDEN_TRANSIENT_NAME_STEMS
        or compacted.startswith(b"raw")
        or any(part in compacted for part in FORBIDDEN_TRANSIENT_COMPACT_PARTS)
    )


def _is_forbidden_transient_path(path: bytes) -> bool:
    parts = tuple(path.split(b"/"))
    if not parts or any(
        part.lower() in FORBIDDEN_TRANSIENT_COMPONENTS
        or _forbidden_transient_name(part)
        for part in parts[:-1]
    ):
        return True
    name = parts[-1].lower()
    return (
        name in FORBIDDEN_TRANSIENT_FILENAMES
        or _forbidden_transient_name(parts[-1])
        or name.startswith(b"rollout")
    )


def _parse_diff(raw: bytes) -> _ParsedDiff:
    if not raw:
        return _ParsedDiff((), 0, False, False)
    fields = raw.split(b"\0")
    if fields[-1] != b"":
        raise _ParseFailure
    fields.pop()
    if len(fields) % 2:
        raise _ParseFailure
    entries: list[_DiffEntry] = []
    changed_path_count = 0
    forbidden_transient_path_changed = False
    non_run_path_changed = False
    for offset in range(0, len(fields), 2):
        metadata, path = fields[offset : offset + 2]
        match = RAW_DIFF_RE.fullmatch(metadata)
        if match is None:
            raise _ParseFailure
        changed_path_count += 1
        forbidden_transient_path_changed = (
            forbidden_transient_path_changed or _is_forbidden_transient_path(path)
        )
        if not _is_run_candidate(path):
            non_run_path_changed = True
            continue
        if len(entries) >= MAX_CHANGED_RUN_PATHS:
            raise _ParseFailure
        entries.append(
            _DiffEntry(
                path=path,
                old_mode=match.group("old_mode"),
                new_mode=match.group("new_mode"),
                old_oid=match.group("old_oid"),
                new_oid=match.group("new_oid"),
                status=match.group("status").decode("ascii"),
                run_path=_parse_run_path(path),
            )
        )
    return _ParsedDiff(
        tuple(entries),
        changed_path_count,
        forbidden_transient_path_changed,
        non_run_path_changed,
    )


def _batch_object_info(
    root: Path, object_ids: Iterable[bytes]
) -> dict[bytes, _ObjectInfo]:
    ordered_ids = sorted(set(object_ids))
    if not ordered_ids:
        return {}
    payload = b"".join(object_id + b"\n" for object_id in ordered_ids)
    result = _run_git(
        root,
        ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        input_data=payload,
        max_stdout_bytes=max(1024, len(ordered_ids) * 160),
    )
    lines = result.stdout.splitlines()
    if len(lines) != len(ordered_ids):
        raise _GitFailure
    objects: dict[bytes, _ObjectInfo] = {}
    for expected_oid, line in zip(ordered_ids, lines, strict=True):
        fields = line.split(b" ")
        if len(fields) != 3 or fields[0] != expected_oid or not fields[2].isdigit():
            raise _GitFailure
        objects[expected_oid] = _ObjectInfo(kind=fields[1], size=int(fields[2]))
    return objects


def _run_directory(run_path: _RunPath) -> str:
    return run_path.value.rsplit("/", 1)[0]


def _batch_parent_run_presence(
    root: Path, parent_oid: bytes, run_directories: Iterable[str]
) -> dict[str, bool]:
    ordered_directories = sorted(set(run_directories))
    if not ordered_directories:
        return {}
    expressions = [
        parent_oid + b":" + directory.encode("ascii")
        for directory in ordered_directories
    ]
    result = _run_git(
        root,
        ["cat-file", "--batch-check=%(objectname) %(objecttype)"],
        input_data=b"".join(expression + b"\n" for expression in expressions),
        max_stdout_bytes=max(
            1024, sum(len(expression) + 80 for expression in expressions)
        ),
    )
    lines = result.stdout.splitlines()
    if len(lines) != len(expressions):
        raise _GitFailure

    presence: dict[str, bool] = {}
    for directory, expression, line in zip(
        ordered_directories, expressions, lines, strict=True
    ):
        if line == expression + b" missing":
            presence[directory] = False
            continue
        fields = line.split(b" ")
        if (
            len(fields) != 2
            or OID_RE.fullmatch(fields[0]) is None
            or not fields[1].isalpha()
        ):
            raise _GitFailure
        presence[directory] = True
    return presence


def _validate_publication_run(
    root: Path,
    parent_oid: bytes,
    commit_index: int,
    entries: list[_DiffEntry],
    changed_path_count: int,
    issues: _IssueCollector,
) -> _RunPath | None:
    groups: dict[str, list[_DiffEntry]] = {}
    for entry in entries:
        if entry.run_path is None:
            continue
        groups.setdefault(_run_directory(entry.run_path), []).append(entry)

    publication_issue = f"commit {commit_index}: publication commit must add exactly one complete v2 run"
    if len(groups) != 1:
        issues.add(publication_issue)

    added_groups = {
        directory: group
        for directory, group in groups.items()
        if any(entry.status == "A" for entry in group)
    }
    parent_presence = _batch_parent_run_presence(root, parent_oid, added_groups.keys())
    complete_runs: list[_RunPath] = []
    for directory, group in sorted(added_groups.items()):
        label = f"commit {commit_index}: {directory}"
        if parent_presence[directory]:
            issues.add(
                f"{label}: adding artifacts to an existing v2 run is not allowed"
            )
            continue
        artifacts = [
            entry.run_path.artifact
            for entry in group
            if entry.run_path is not None and entry.status == "A"
        ]
        if (
            len(group) != len(RUN_ARTIFACTS)
            or len(artifacts) != len(RUN_ARTIFACTS)
            or frozenset(artifacts) != RUN_ARTIFACTS
        ):
            issues.add(
                f"{label}: new v2 run must atomically add exactly the eight required artifacts"
            )
            continue
        if (
            len(groups) == 1
            and len(entries) == len(group)
            and changed_path_count == len(entries)
        ):
            run_path = group[0].run_path
            if run_path is not None:
                complete_runs.append(run_path)

    if len(complete_runs) != 1:
        issues.add(publication_issue)
        return None
    return complete_runs[0]


def _entry_label(commit_index: int, run_path: _RunPath) -> str:
    return f"commit {commit_index}: {run_path.value}"


def _validate_run_entries(
    root: Path,
    commit_index: int,
    entries: list[_DiffEntry],
    issues: _IssueCollector,
) -> dict[bytes, _ObjectInfo]:
    inspect_objects: list[bytes] = []
    deleted_objects: set[tuple[bytes, bytes]] = set()
    added_objects: set[tuple[bytes, bytes]] = set()

    for entry in entries:
        run_path = entry.run_path
        if run_path is None:
            issues.add(f"commit {commit_index}: malformed v2 run path")
            continue
        label = _entry_label(commit_index, run_path)
        if entry.status == "D":
            issues.add(f"{label}: deletion is not allowed")
            deleted_objects.add((entry.old_mode, entry.old_oid))
            continue
        if entry.status == "A":
            added_objects.add((entry.new_mode, entry.new_oid))
        else:
            issues.add(f"{label}: modification is not allowed")
            if entry.old_mode != entry.new_mode:
                issues.add(f"{label}: mode or type change is not allowed")

        if entry.new_mode == b"120000":
            issues.add(f"{label}: symlink is not allowed")
            continue
        if entry.new_mode == b"160000":
            issues.add(f"{label}: gitlink is not allowed")
            continue
        if entry.new_mode != b"100644":
            if entry.new_mode.startswith(b"100"):
                issues.add(f"{label}: non-canonical file mode is not allowed")
            else:
                issues.add(f"{label}: non-regular Git entry is not allowed")
            continue
        if entry.new_oid in ZERO_OIDS:
            issues.add(f"{label}: missing Git object is not allowed")
            continue
        inspect_objects.append(entry.new_oid)

    if deleted_objects & added_objects:
        issues.add(f"commit {commit_index}: v2 run file rename is not allowed")

    objects = _batch_object_info(root, inspect_objects)
    for entry in entries:
        if entry.run_path is None or entry.new_oid not in objects:
            continue
        label = _entry_label(commit_index, entry.run_path)
        info = objects[entry.new_oid]
        if info.kind != b"blob":
            issues.add(f"{label}: non-regular Git object is not allowed")
        elif info.size > MAX_ARTIFACT_BYTES[entry.run_path.artifact]:
            issues.add(f"{label}: Git object exceeds the size limit")
    return objects


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _reject_non_json_constant(_: str) -> None:
    raise ValueError


def _validate_manifest_run_id(
    root: Path,
    commit_index: int,
    publication_run: _RunPath | None,
    entries: list[_DiffEntry],
    objects: dict[bytes, _ObjectInfo],
    issues: _IssueCollector,
) -> None:
    if publication_run is None:
        return
    issue = f"commit {commit_index}: manifest run_id does not match the physical v2 run route"
    manifest_entries = [
        entry
        for entry in entries
        if entry.run_path is not None
        and entry.run_path.artifact == "manifest.json"
        and _run_directory(entry.run_path) == _run_directory(publication_run)
    ]
    if len(manifest_entries) != 1:
        issues.add(issue)
        return
    entry = manifest_entries[0]
    info = objects.get(entry.new_oid)
    if (
        entry.status != "A"
        or entry.new_mode != b"100644"
        or info is None
        or info.kind != b"blob"
        or info.size > MAX_ARTIFACT_BYTES["manifest.json"]
    ):
        issues.add(issue)
        return
    raw = _run_git(
        root,
        ["cat-file", "blob", entry.new_oid.decode("ascii")],
        max_stdout_bytes=info.size,
    ).stdout
    if len(raw) != info.size:
        issues.add(issue)
        return
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ):
        issues.add(issue)
        return
    if not isinstance(value, dict) or value.get("run_id") != publication_run.run_id:
        issues.add(issue)


def _batch_blob_contents(
    root: Path, object_infos: dict[bytes, _ObjectInfo]
) -> dict[bytes, bytes]:
    ordered_ids = sorted(object_infos)
    if not ordered_ids:
        return {}
    result = _run_git(
        root,
        ["cat-file", "--batch"],
        input_data=b"".join(object_id + b"\n" for object_id in ordered_ids),
        max_stdout_bytes=max(
            1024,
            sum(
                object_infos[object_id].size + len(object_id) + 128
                for object_id in ordered_ids
            ),
        ),
    )
    raw = result.stdout
    offset = 0
    contents: dict[bytes, bytes] = {}
    for expected_oid in ordered_ids:
        header_end = raw.find(b"\n", offset)
        if header_end < 0:
            raise _SemanticFailure
        fields = raw[offset:header_end].split(b" ")
        info = object_infos[expected_oid]
        if (
            len(fields) != 3
            or fields[0] != expected_oid
            or fields[1] != b"blob"
            or not fields[2].isdigit()
            or int(fields[2]) != info.size
        ):
            raise _SemanticFailure
        content_start = header_end + 1
        content_end = content_start + info.size
        if content_end >= len(raw) or raw[content_end : content_end + 1] != b"\n":
            raise _SemanticFailure
        contents[expected_oid] = raw[content_start:content_end]
        offset = content_end + 1
    if offset != len(raw):
        raise _SemanticFailure
    return contents


def _load_publication_blobs(
    root: Path,
    publication_run: _RunPath,
    entries: list[_DiffEntry],
    objects: dict[bytes, _ObjectInfo],
) -> dict[str, bytes]:
    directory = _run_directory(publication_run)
    candidates: dict[str, tuple[bytes, _ObjectInfo]] = {}
    for entry in entries:
        run_path = entry.run_path
        if (
            run_path is None
            or _run_directory(run_path) != directory
            or run_path.artifact not in SEMANTIC_ARTIFACTS
            or entry.status != "A"
            or entry.new_mode != b"100644"
        ):
            continue
        info = objects.get(entry.new_oid)
        if info is None or info.kind != b"blob":
            continue
        candidates[run_path.artifact] = (entry.new_oid, info)
    if frozenset(candidates) != SEMANTIC_ARTIFACTS:
        return {}
    if sum(info.size for _, info in candidates.values()) > MAX_SEMANTIC_BUNDLE_BYTES:
        raise _SemanticFailure
    object_infos = {object_id: info for object_id, info in candidates.values()}
    contents = _batch_blob_contents(root, object_infos)
    return {
        artifact: contents[object_id] for artifact, (object_id, _) in candidates.items()
    }


def _parse_semantic_json(raw: bytes | None) -> Any | None:
    if raw is None:
        return None
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_constant,
        )
    except (
        MemoryError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ):
        return None


def _semantic_jsonl_values(raw: bytes) -> Iterable[Any]:
    offset = 0
    while offset < len(raw):
        line_end = raw.find(b"\n", offset)
        if line_end < 0:
            line = raw[offset:]
            offset = len(raw)
        else:
            line = raw[offset:line_end]
            offset = line_end + 1
        yield _parse_semantic_json(line)


def _revision_fact_from_values(
    family: str,
    current: Any,
    predecessor: Any,
    supersedes: Any,
) -> _RevisionFact | None:
    pattern = REVISION_REF_PATTERNS[family]
    if not isinstance(current, str) or pattern.fullmatch(current) is None:
        return None
    predecessors: list[str] = []
    if isinstance(predecessor, str) and pattern.fullmatch(predecessor) is not None:
        predecessors.append(predecessor)
    if isinstance(supersedes, list | tuple):
        predecessors.extend(
            value
            for value in supersedes
            if isinstance(value, str) and pattern.fullmatch(value) is not None
        )
    return _RevisionFact(
        family=family,
        current=current,
        predecessors=tuple(dict.fromkeys(predecessors)),
    )


def _revision_fact_from_record(
    value: Any, fields: tuple[str, str, str, str]
) -> _RevisionFact | None:
    if not isinstance(value, dict):
        return None
    family, current_field, predecessor_field, supersedes_field = fields
    return _revision_fact_from_values(
        family,
        value.get(current_field),
        value.get(predecessor_field),
        value.get(supersedes_field),
    )


def _extract_publication_facts(
    commit_index: int, blobs: dict[str, bytes]
) -> _PublicationFacts:
    documents = {
        artifact: _parse_semantic_json(blobs.get(artifact))
        for artifact in sorted(SEMANTIC_JSON_ARTIFACTS)
    }
    manifest_value = documents.get("manifest.json")
    manifest = manifest_value if isinstance(manifest_value, dict) else {}
    campaign_ref_value = manifest.get("campaign_ref")
    campaign_ref = (
        campaign_ref_value
        if isinstance(campaign_ref_value, str)
        and CAMPAIGN_REF_RE.fullmatch(campaign_ref_value) is not None
        else None
    )
    role_value = manifest.get("publication_role")
    publication_role = (
        role_value
        if isinstance(role_value, str)
        and role_value in {"campaign_root", "campaign_segment"}
        else None
    )

    revisions: list[_RevisionFact] = []
    supersession = manifest.get("supersession")
    run_fact = _revision_fact_from_values(
        "run",
        manifest.get("run_revision_ref"),
        None,
        supersession.get("supersedes_run_revision_refs")
        if isinstance(supersession, dict)
        else None,
    )
    if run_fact is not None:
        revisions.append(run_fact)

    for artifact in ("coverage.json", "summary.json", "trend_report.json"):
        fact = _revision_fact_from_record(
            documents.get(artifact), REVISION_ARTIFACT_FIELDS[artifact]
        )
        if fact is not None:
            revisions.append(fact)

    coverage = documents.get("coverage.json")
    if isinstance(coverage, dict) and isinstance(coverage.get("gaps"), list):
        for gap in coverage["gaps"]:
            if not isinstance(gap, dict):
                continue
            fact = _revision_fact_from_values(
                "gap",
                gap.get("gap_revision_ref"),
                gap.get("predecessor_gap_revision_ref"),
                None,
            )
            if fact is not None:
                revisions.append(fact)

    jsonl_row_count = 0
    for artifact in sorted(SEMANTIC_JSONL_ARTIFACTS):
        fields = REVISION_ARTIFACT_FIELDS[artifact]
        for value in _semantic_jsonl_values(blobs.get(artifact, b"")):
            jsonl_row_count += 1
            if jsonl_row_count > MAX_SEMANTIC_JSONL_ROWS:
                raise _SemanticFailure
            fact = _revision_fact_from_record(value, fields)
            if fact is not None:
                revisions.append(fact)
    if len(revisions) > MAX_RANGE_REVISION_FACTS:
        raise _SemanticFailure
    return _PublicationFacts(
        commit_index=commit_index,
        campaign_ref=campaign_ref,
        publication_role=publication_role,
        revisions=tuple(revisions),
    )


def _validate_cross_commit_order(
    publications: list[_PublicationFacts], issues: _IssueCollector
) -> None:
    range_revisions = {family: set() for family in sorted(REVISION_REF_PATTERNS)}
    campaign_segments: dict[str, list[int]] = {}
    for publication in publications:
        for revision in publication.revisions:
            range_revisions[revision.family].add(revision.current)
        if (
            publication.publication_role == "campaign_segment"
            and publication.campaign_ref is not None
        ):
            campaign_segments.setdefault(publication.campaign_ref, []).append(
                publication.commit_index
            )

    seen_revisions = {family: set() for family in sorted(REVISION_REF_PATTERNS)}
    for publication in sorted(publications, key=lambda item: item.commit_index):
        for revision in publication.revisions:
            if any(
                predecessor in range_revisions[revision.family]
                and predecessor not in seen_revisions[revision.family]
                for predecessor in revision.predecessors
            ):
                issues.add(
                    f"commit {publication.commit_index}: v2 revision predecessor must be published by an earlier commit"
                )
                break
        if (
            publication.publication_role == "campaign_root"
            and publication.campaign_ref is not None
            and any(
                segment_index > publication.commit_index
                for segment_index in campaign_segments.get(publication.campaign_ref, ())
            )
        ):
            issues.add(
                f"commit {publication.commit_index}: campaign root must be published after all campaign segments"
            )
        for revision in publication.revisions:
            seen_revisions[revision.family].add(revision.current)


def _parse_commit_headers(raw: bytes) -> tuple[list[_CommitHeader], bytes]:
    header_block, separator, message = raw.partition(b"\n\n")
    if not separator or b"\0" in raw or b"\r" in raw:
        raise _ParseFailure
    headers: list[_CommitHeader] = []
    for line in header_block.split(b"\n"):
        if line.startswith(b" "):
            if not headers or headers[-1].name != b"gpgsig":
                raise _ParseFailure
            previous = headers[-1]
            headers[-1] = _CommitHeader(
                previous.name, previous.value + b"\n" + line[1:]
            )
            continue
        name, separator, value = line.partition(b" ")
        if not separator or not name or not value:
            raise _ParseFailure
        headers.append(_CommitHeader(name=name, value=value))
    return headers, message


def _valid_signature(value: bytes) -> bool:
    if len(value) > 16 * 1024:
        return False
    lines = value.split(b"\n")
    if len(lines) < 4:
        return False
    if (
        lines[0] != b"-----BEGIN PGP SIGNATURE-----"
        or lines[-1] != b"-----END PGP SIGNATURE-----"
    ):
        return False
    body = lines[1:-1]
    try:
        separator_index = body.index(b"")
    except ValueError:
        return False
    if not all(
        ARMOR_HEADER_RE.fullmatch(line) is not None for line in body[:separator_index]
    ):
        return False
    payload_lines = body[separator_index + 1 :]
    if not payload_lines or any(not line for line in payload_lines):
        return False
    checksum: bytes | None = None
    if payload_lines[-1].startswith(b"="):
        checksum = payload_lines.pop()
        if ARMOR_CHECKSUM_RE.fullmatch(checksum) is None:
            return False
    if not payload_lines or any(
        len(line) > 76 or ARMOR_PAYLOAD_RE.fullmatch(line) is None
        for line in payload_lines
    ):
        return False
    try:
        decoded = base64.b64decode(b"".join(payload_lines), validate=True)
        if (
            checksum is not None
            and len(base64.b64decode(checksum[1:], validate=True)) != 3
        ):
            return False
    except (binascii.Error, ValueError):
        return False
    return bool(decoded)


def _validsig_matches_allowlist(status: bytes) -> bool:
    if len(status) > MAX_GIT_STDERR_BYTES or b"\0" in status or b"\r" in status:
        return False
    signer_fingerprints: list[bytes] = []
    for line in status.splitlines():
        if not line.startswith(VALIDSIG_STATUS_PREFIX):
            continue
        fields = line[len(VALIDSIG_STATUS_PREFIX) :].split(b" ")
        if len(fields) not in (9, 10) or any(not field for field in fields):
            return False
        if (
            VALIDSIG_FINGERPRINT_RE.fullmatch(fields[0]) is None
            or VALIDSIG_DATE_RE.fullmatch(fields[1]) is None
            or not all(field.isdigit() for field in fields[2:8])
            or VALIDSIG_CLASS_RE.fullmatch(fields[8]) is None
        ):
            return False
        try:
            dt.date.fromisoformat(fields[1].decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            return False
        signer_fingerprint = fields[0].upper()
        if len(fields) == 10:
            if VALIDSIG_FINGERPRINT_RE.fullmatch(fields[9]) is None:
                return False
        signer_fingerprints.append(signer_fingerprint)
    if len(signer_fingerprints) != 1:
        return False
    return signer_fingerprints[0] in V2_SIGNING_FINGERPRINTS


def _verify_commit_signature(root: Path, commit_oid: bytes) -> bool:
    try:
        result = _run_git(
            root,
            [
                "-c",
                "gpg.format=openpgp",
                "-c",
                "gpg.program=gpg",
                "-c",
                "gpg.openpgp.program=gpg",
                "verify-commit",
                "--raw",
                commit_oid.decode("ascii"),
            ],
            max_stdout_bytes=0,
        )
    except (_GitFailure, UnicodeDecodeError):
        return False
    return _validsig_matches_allowlist(result.stderr)


def _load_commit(root: Path, commit_oid: bytes) -> bytes:
    size_result = _run_git(
        root, ["cat-file", "-s", commit_oid.decode("ascii")], max_stdout_bytes=32
    )
    raw_size = size_result.stdout.strip()
    if not raw_size.isdigit() or int(raw_size) > MAX_COMMIT_OBJECT_BYTES:
        raise _ParseFailure
    size = int(raw_size)
    return _run_git(
        root,
        ["cat-file", "commit", commit_oid.decode("ascii")],
        max_stdout_bytes=size,
    ).stdout


def _validate_commit_metadata(
    root: Path,
    commit_oid: bytes,
    expected_parent: bytes,
    publication_run: _RunPath | None,
) -> _PublisherIdentity | None:
    try:
        raw = _load_commit(root, commit_oid)
        headers, message = _parse_commit_headers(raw)
    except (_GitFailure, _ParseFailure):
        return None

    names = tuple(header.name for header in headers)
    if names != (*COMMIT_HEADER_ORDER, b"gpgsig"):
        return None
    values = {header.name: header.value for header in headers}
    if (
        OID_RE.fullmatch(values[b"tree"]) is None
        or values[b"parent"] != expected_parent
    ):
        return None
    if not _valid_signature(values[b"gpgsig"]):
        return None

    author_match = IDENTITY_RE.fullmatch(values[b"author"])
    committer_match = IDENTITY_RE.fullmatch(values[b"committer"])
    if (
        author_match is None
        or committer_match is None
        or values[b"author"] != values[b"committer"]
    ):
        return None
    timestamp = int(author_match.group("timestamp"))
    if timestamp % 60:
        return None

    message_match = COMMIT_MESSAGE_RE.fullmatch(message)
    if message_match is None or not _valid_window(message_match.group("window")):
        return None
    mode = message_match.group("mode").decode("ascii")
    window = message_match.group("window").decode("ascii")
    if (
        publication_run is None
        or publication_run.mode != mode
        or publication_run.window != window
        or message_match.group("run_ref")
        != b"run_ref_v2:" + publication_run.run_id.encode("ascii")
    ):
        return None
    if not _verify_commit_signature(root, commit_oid):
        return None
    return _PublisherIdentity(
        name=V2_PUBLISHER_NAME,
        email=V2_PUBLISHER_EMAIL,
    )


def _linear_commits(
    root: Path, base_oid: bytes, head_oid: bytes
) -> list[tuple[bytes, bytes]]:
    cursor = head_oid
    base_revision = b"^" + base_oid
    backward_commits: list[tuple[bytes, bytes]] = []
    while cursor != base_oid:
        remaining = MAX_RANGE_COMMITS - len(backward_commits)
        if remaining <= 0:
            raise _CommitLimitExceeded
        page_size = min(COMMIT_PAGE_SIZE, remaining + 1)
        result = _run_git(
            root,
            [
                "rev-list",
                "--first-parent",
                "--parents",
                f"--max-count={page_size}",
                cursor.decode("ascii"),
                base_revision.decode("ascii"),
            ],
            max_stdout_bytes=page_size * 200,
        )
        lines = result.stdout.splitlines()
        if not lines or len(lines) > page_size:
            raise _ParseFailure

        page: list[tuple[bytes, bytes]] = []
        expected_commit = cursor
        for line in lines:
            fields = line.split(b" ")
            if len(fields) != 2 or any(
                OID_RE.fullmatch(field) is None for field in fields
            ):
                raise _ParseFailure
            commit_oid, parent_oid = fields
            if commit_oid != expected_commit:
                raise _ParseFailure
            page.append((commit_oid, parent_oid))
            expected_commit = parent_oid
        if len(page) > remaining:
            raise _CommitLimitExceeded
        backward_commits.extend(page)
        cursor = expected_commit
    backward_commits.reverse()
    return backward_commits


def validate_append_only_range(root: Path, base_rev: str, head_rev: str) -> list[str]:
    """Validate append-only v2 run objects in every commit from base to head."""

    try:
        resolved_root = Path(root).resolve(strict=True)
    except (OSError, RuntimeError, TypeError):
        return ["root must be an existing Git working tree"]
    if not resolved_root.is_dir():
        return ["root must be an existing Git working tree"]
    try:
        _run_git(
            resolved_root, ["rev-parse", "--is-inside-work-tree"], max_stdout_bytes=16
        )
    except _GitFailure:
        return ["root must be an existing Git working tree"]

    base_oid = _resolve_commit(resolved_root, base_rev)
    if base_oid is None:
        return ["range: base revision is not a commit"]
    head_oid = _resolve_commit(resolved_root, head_rev)
    if head_oid is None:
        return ["range: head revision is not a commit"]

    try:
        ancestry = _run_git(
            resolved_root,
            [
                "merge-base",
                "--is-ancestor",
                base_oid.decode("ascii"),
                head_oid.decode("ascii"),
            ],
            allowed_returncodes=frozenset({0, 1}),
            max_stdout_bytes=0,
        )
    except _GitFailure:
        return ["range: Git ancestry check failed"]
    if ancestry.returncode == 1:
        return ["range: head is not a fast-forward descendant of base"]

    try:
        commits = _linear_commits(resolved_root, base_oid, head_oid)
    except _CommitLimitExceeded:
        return ["range: commit count exceeds the validation limit"]
    except (_GitFailure, _ParseFailure):
        return ["range: commit graph is not a bounded linear ancestry path"]

    issues = _IssueCollector()
    publisher_identity: _PublisherIdentity | None = None
    publications: list[_PublicationFacts] = []
    revision_fact_count = 0
    range_has_run_changes = False
    range_has_non_run_changes = False
    for current_index, (commit_oid, parent_oid) in enumerate(commits, start=1):
        try:
            diff = _run_git(
                resolved_root,
                [
                    "diff-tree",
                    "--no-commit-id",
                    "--raw",
                    "-r",
                    "-z",
                    "--no-renames",
                    "--no-abbrev",
                    parent_oid.decode("ascii"),
                    commit_oid.decode("ascii"),
                    "--",
                ],
                max_stdout_bytes=MAX_DIFF_OUTPUT_BYTES,
            )
            parsed_diff = _parse_diff(diff.stdout)
            if parsed_diff.forbidden_transient_path_changed:
                issues.add(
                    f"commit {current_index}: forbidden raw or transient path changed"
                )
            entries = list(parsed_diff.run_entries)
            range_has_run_changes = range_has_run_changes or bool(entries)
            range_has_non_run_changes = (
                range_has_non_run_changes or parsed_diff.non_run_path_changed
            )
            if not entries:
                continue
            publication_run = _validate_publication_run(
                resolved_root,
                parent_oid,
                current_index,
                entries,
                parsed_diff.changed_path_count,
                issues,
            )
            objects = _validate_run_entries(
                resolved_root, current_index, entries, issues
            )
            _validate_manifest_run_id(
                resolved_root,
                current_index,
                publication_run,
                entries,
                objects,
                issues,
            )
            if publication_run is not None:
                blobs = _load_publication_blobs(
                    resolved_root, publication_run, entries, objects
                )
                facts = _extract_publication_facts(current_index, blobs)
                revision_fact_count += len(facts.revisions)
                if revision_fact_count > MAX_RANGE_REVISION_FACTS:
                    raise _SemanticFailure
                publications.append(facts)
            identity = _validate_commit_metadata(
                resolved_root, commit_oid, parent_oid, publication_run
            )
            if identity is None:
                issues.add(
                    f"commit {current_index}: v2 publication commit metadata is unsafe"
                )
            elif publisher_identity is None:
                publisher_identity = identity
            elif identity != publisher_identity:
                issues.add(
                    f"commit {current_index}: v2 publisher identity changed within the range"
                )
        except _GitFailure:
            issues.add(f"commit {current_index}: bounded Git object inspection failed")
        except _ParseFailure:
            issues.add(
                f"commit {current_index}: bounded Git diff is malformed or too large"
            )
        except _SemanticFailure:
            issues.add(
                f"commit {current_index}: bounded publication semantic inspection failed"
            )
    if range_has_run_changes and range_has_non_run_changes:
        issues.add(
            "range: publication pushes must not include infrastructure or other non-run changes"
        )
    _validate_cross_commit_order(publications, issues)
    return issues.items


def validate_checkout_matches_revision(root: Path, head_rev: str) -> list[str]:
    """Bind working-tree validation to one clean, exact head revision."""

    try:
        resolved_root = Path(root).resolve(strict=True)
    except (OSError, RuntimeError, TypeError):
        return ["range: checkout must be an existing Git working tree"]
    if not resolved_root.is_dir():
        return ["range: checkout must be an existing Git working tree"]

    expected_head = _resolve_commit(resolved_root, head_rev)
    if expected_head is None:
        return ["range: head revision is not a commit"]
    actual_head = _resolve_commit(resolved_root, "HEAD")
    if actual_head is None:
        return ["range: checkout HEAD is not a commit"]
    if actual_head != expected_head:
        return ["range: checkout HEAD does not match the requested head revision"]

    try:
        status = _run_git(
            resolved_root,
            [
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
            max_stdout_bytes=1,
        )
    except _GitFailure:
        return ["range: checkout must be clean before retained tree validation"]
    if status.stdout:
        return ["range: checkout must be clean before retained tree validation"]
    return []


__all__ = ["validate_append_only_range", "validate_checkout_matches_revision"]
