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
import tempfile
import time
from typing import Any, Iterable

try:
    from retrospective_history_attestation_v2 import (
        PUBLISHER_ATTESTATION_SCHEME,
        PublisherAttestationError,
        canonical_openpgp_detached_signature,
        publisher_attestation_payload,
    )
    from retrospective_history_credentials_v2 import (
        contains_high_confidence_credential,
    )
except ModuleNotFoundError:  # Imported as scripts.retrospective_history_git_v2.
    from scripts.retrospective_history_attestation_v2 import (
        PUBLISHER_ATTESTATION_SCHEME,
        PublisherAttestationError,
        canonical_openpgp_detached_signature,
        publisher_attestation_payload,
    )
    from scripts.retrospective_history_credentials_v2 import (
        contains_high_confidence_credential,
    )


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
MAX_CHANGED_ADMIN_PATHS = 4096
MAX_DIFF_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_RANGE_DIFF_BYTES = 32 * 1024 * 1024
MAX_RANGE_DIFF_ENTRIES = 65_536
MAX_RANGE_PATH_BYTES = 16 * 1024 * 1024
MAX_RANGE_OID_REFERENCES = 131_072
MAX_RANGE_UNIQUE_OIDS = 16_384
MAX_TREE_INVENTORY_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_RANGE_TREE_INVENTORY_BYTES = 256 * 1024 * 1024
MAX_RANGE_TREE_INVENTORY_ENTRIES = 1_000_000
MAX_RANGE_TREE_INVENTORY_PATH_BYTES = 256 * 1024 * 1024
MAX_REVISION_BYTES = 256
MAX_SQUASH_SUBJECT_BYTES = 256
MAX_PATH_BYTES = 256
MAX_DIAGNOSTICS = 64
MAX_GIT_STDERR_BYTES = 4096
GIT_TIMEOUT_SECONDS = 30
COMMIT_PAGE_SIZE = 128
MAX_RANGE_COMMITS = 512
MAX_SEMANTIC_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_SEMANTIC_JSON_DEPTH = 64
MAX_SEMANTIC_JSON_NODES = 200_000
MAX_SEMANTIC_JSON_CONTAINER_ITEMS = 100_000
MAX_SEMANTIC_JSON_STRING_BYTES = 1024 * 1024
MAX_SEMANTIC_JSON_SCALAR_BYTES = 4096
MAX_SEMANTIC_JSONL_ROW_BYTES = 1024 * 1024
MAX_RANGE_REVISION_FACTS = 1_000_000
MAX_RANGE_SEMANTIC_BYTES = 256 * 1024 * 1024
MAX_RANGE_SEMANTIC_LINES = 800_000
MAX_RANGE_SEMANTIC_NODES = 1_000_000
MAX_ADMIN_BLOB_BYTES = 1024 * 1024
MAX_ADMIN_SCAN_BYTES = 16 * 1024 * 1024
MAX_ADMIN_SCAN_OBJECTS = 4096
MAX_TRANSIENT_NAME_BYTES = 4096
MAX_TRANSIENT_SUFFIX_STRIPS = 32
PROCESS_IO_CHUNK_BYTES = 64 * 1024
PROCESS_TERMINATION_SECONDS = 1
DIAGNOSTIC_OMISSION = "validation: additional issues omitted"
RANGE_WORK_LIMIT_DIAGNOSTIC = "range: aggregate change work exceeds validation limit"
WINDOW_ROUTE_COMPONENT_COUNT = 32
RUN_ROUTE_COMPONENT_COUNT = 32
RUN_PATH_COMPONENT_COUNT = 68
WINDOW_ROUTE_DOMAIN = b"session-retrospective-retained-window-route-v2"
TRUST_GENERATION_DOMAIN = b"session-retrospective-trust-generation-v2\0"
V2_SIGNING_FINGERPRINTS = frozenset({b"40FA5D05AC7A3D5C180B037FF6DCF7A06FFC9C52"})
V2_ADMIN_BOOTSTRAP_BASE = b"97f236c56cbbf24776899178175e2603ecf30fb0"
V2_ADMIN_BOOTSTRAP_MESSAGE = b"Bootstrap session retrospective history v2\n"
V2_ADMIN_MAINTAINER_NAME = b"Joey Teng"
V2_ADMIN_MAINTAINER_EMAIL = b"joey.teng.dev@gmail.com"
V2_ADMIN_GITHUB_NAME = b"GitHub"
V2_ADMIN_GITHUB_EMAIL = b"noreply@github.com"
V2_ADMIN_MAINTAINER_SIGNING_FINGERPRINTS = frozenset(
    {b"EFBBC913F49A5F6E0AF0D248F70246143DC28F32"}
)
V2_ADMIN_GITHUB_SIGNING_FINGERPRINTS = frozenset(
    {b"968479A1AFF927E37D1A566BB5690EEEBB952194"}
)
V2_ADMIN_PATHS = frozenset(
    {
        b".github/workflows/ci.yml",
        b".gitignore",
        b"AGENTS.md",
        b"README.md",
        b"data/README.md",
        b"reports/README.md",
        b"requirements-v2.in",
        b"requirements-v2.txt",
        b"retrospective-history-v2-admin.asc",
        b"retrospective-history-v2-publisher.asc",
        b"schemas/retained-manifest-v1.schema.json",
        b"schemas/retained-manifest-v2.schema.json",
        b"schemas/session-retrospective-v1.schema.json",
        b"schemas/session-retrospective-v2.schema.json",
        b"scripts/retrospective_history_git_v2.py",
        b"scripts/retrospective_history_merge_v2.py",
        b"scripts/retrospective_history_attestation_v2.py",
        b"scripts/retrospective_history_credentials_v2.py",
        b"scripts/retrospective_history_privacy_v2.py",
        b"scripts/retrospective_history_templates_v2.py",
        b"scripts/retrospective_history_v2.py",
        b"scripts/validate_retained_history.py",
        b"tests/test_retrospective_history_git_v2.py",
        b"tests/test_retrospective_history_merge_v2.py",
        b"tests/test_retrospective_history_privacy_v2.py",
        b"tests/test_retrospective_history_v2.py",
        b"tests/test_retrospective_history_v2_ci.py",
        b"tests/test_retrospective_history_v2_schema_extensions.py",
        b"tests/test_validate_retained_history.py",
    }
)
V2_ADMIN_REQUIRED_PATHS = frozenset(
    {
        b".github/workflows/ci.yml",
        b"requirements-v2.in",
        b"requirements-v2.txt",
        b"retrospective-history-v2-admin.asc",
        b"retrospective-history-v2-publisher.asc",
        b"schemas/retained-manifest-v2.schema.json",
        b"schemas/session-retrospective-v2.schema.json",
        b"scripts/retrospective_history_git_v2.py",
        b"scripts/retrospective_history_merge_v2.py",
        b"scripts/retrospective_history_attestation_v2.py",
        b"scripts/retrospective_history_credentials_v2.py",
        b"scripts/retrospective_history_privacy_v2.py",
        b"scripts/retrospective_history_templates_v2.py",
        b"scripts/retrospective_history_v2.py",
        b"scripts/validate_retained_history.py",
    }
)
V2_TRUST_ROOT_PATHS = frozenset(
    {
        b".github/workflows/ci.yml",
        b"requirements-v2.in",
        b"requirements-v2.txt",
        b"retrospective-history-v2-admin.asc",
        b"retrospective-history-v2-publisher.asc",
        b"schemas/retained-manifest-v2.schema.json",
        b"schemas/session-retrospective-v2.schema.json",
        b"scripts/retrospective_history_attestation_v2.py",
        b"scripts/retrospective_history_credentials_v2.py",
        b"scripts/retrospective_history_git_v2.py",
        b"scripts/retrospective_history_merge_v2.py",
        b"scripts/retrospective_history_privacy_v2.py",
        b"scripts/retrospective_history_templates_v2.py",
        b"scripts/retrospective_history_v2.py",
        b"scripts/validate_retained_history.py",
    }
)
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
        b"archived_sessions",
        b"auth",
        b"authentication",
        b"authorization",
        b"config",
        b"credential",
        b"credentials",
        b"history",
        b"index",
        b"password",
        b"passwd",
        b"rollout",
        b"runs",
        b"scratch",
        b"secret",
        b"session",
        b"session_data",
        b"session_index",
        b"session_log",
        b"session_metadata",
        b"sessions",
        b"shard",
        b"shard_cache",
        b"shard_index",
        b"shard_manifest",
        b"shard_metadata",
        b"shards",
        b"source_metadata",
        b"token",
        b"transient",
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
FORBIDDEN_TRANSIENT_COMPACT_PREFIXES = (b"raw", b"rollout")
FORBIDDEN_TRANSIENT_COMPACT_NAMES = frozenset(
    re.sub(rb"[^a-z0-9]", b"", name.lower()) for name in FORBIDDEN_TRANSIENT_NAME_STEMS
)
STRIPPABLE_TRANSIENT_SUFFIXES = frozenset(
    {
        b".asc",
        b".bz2",
        b".gz",
        b".json",
        b".jsonl",
        b".md",
        b".py",
        b".txt",
        b".xz",
        b".yaml",
        b".yml",
        b".zip",
        b".zst",
    }
)
EDITOR_TRANSIENT_SUFFIX_RE = re.compile(
    rb"\.(?:bak|backup|old|orig|save|swap|sw[a-z]|temp|temporary|tmp)(?:\.[0-9]+)?$",
    re.I,
)
NUMERIC_ROTATION_SUFFIX_RE = re.compile(rb"\.[0-9]+$")
EMACS_VERSION_BACKUP_SUFFIX_RE = re.compile(rb"\.~[0-9]+~$")
OID_RE = re.compile(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})")
RAW_DIFF_RE = re.compile(
    rb":(?P<old_mode>[0-7]{6}) (?P<new_mode>[0-7]{6}) "
    rb"(?P<old_oid>[0-9a-f]{40}|[0-9a-f]{64}) "
    rb"(?P<new_oid>[0-9a-f]{40}|[0-9a-f]{64}) "
    rb"(?P<status>[A-Z])(?:[0-9]+)?"
)
TREE_ENTRY_METADATA_RE = re.compile(
    rb"(?P<mode>[0-7]{6}) (?P<kind>blob|tree|commit) "
    rb"(?P<oid>[0-9a-f]{40}|[0-9a-f]{64})"
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
COMMIT_MESSAGE_RE = re.compile(
    rb"Publish session retrospective v2 "
    rb"(?P<mode>baseline|daily|session|weekly) "
    rb"(?P<window>" + DATE_COMPONENT + rb"(?:_to_" + DATE_COMPONENT + rb")?) "
    rb"(?P<run_ref>run_ref_v2:[0-9a-f]{64})\n"
)
ADMIN_COMMIT_MESSAGE_RE = re.compile(
    rb"Administer session retrospective history v2: "
    rb"[A-Za-z0-9][A-Za-z0-9 ._:/()#-]{0,120}\n"
)
TRUST_ROOT_UPGRADE_MESSAGE = b"Upgrade session retrospective history v2 trust root\n"
GIT_TIMEZONE_RE = rb"(?:[+-](?:0[0-9]|1[0-3])[0-5][0-9]|[+-]1400)"
ADMIN_MAINTAINER_IDENTITY_RE = re.compile(
    re.escape(V2_ADMIN_MAINTAINER_NAME)
    + rb" <"
    + re.escape(V2_ADMIN_MAINTAINER_EMAIL)
    + rb"> (?P<timestamp>0|[1-9][0-9]{0,11}) "
    + GIT_TIMEZONE_RE
)
ADMIN_GITHUB_IDENTITY_RE = re.compile(
    re.escape(V2_ADMIN_GITHUB_NAME)
    + rb" <"
    + re.escape(V2_ADMIN_GITHUB_EMAIL)
    + rb"> (?P<timestamp>0|[1-9][0-9]{0,11}) "
    + GIT_TIMEZONE_RE
)
ADMIN_AUTHOR_IDENTITY_RE = re.compile(
    rb"[A-Za-z0-9][A-Za-z0-9 ._'()-]{0,99} "
    rb"<[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@"
    rb"[A-Za-z0-9.-]{1,189}> (?P<timestamp>0|[1-9][0-9]{0,11}) " + GIT_TIMEZONE_RE
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


class _RangeWorkLimitExceeded(Exception):
    pass


class _TreeInventoryFailure(Exception):
    pass


class _SemanticFailure(Exception):
    pass


class _AdminFailure(Exception):
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
class PullRequestMergePlan:
    base_oid: str
    head_oid: str
    head_tree_oid: str
    squash_subject: str
    trust_generation: str

    def as_dict(self) -> dict[str, str | int]:
        return {
            "schema_version": 1,
            "base_oid": self.base_oid,
            "head_oid": self.head_oid,
            "head_tree_oid": self.head_tree_oid,
            "squash_subject": self.squash_subject,
            "trust_generation": self.trust_generation,
        }


def trust_generation_from_entries(
    entries: Iterable[tuple[str, str, str, str]],
) -> str:
    expected_paths = {path.decode("ascii") for path in V2_TRUST_ROOT_PATHS}
    normalized: dict[str, tuple[str, str, str]] = {}
    for path, mode, object_type, object_id in entries:
        try:
            path.encode("ascii")
            encoded_object_id = object_id.encode("ascii")
        except (AttributeError, UnicodeEncodeError) as exc:
            raise ValueError("trust generation entry is not canonical ASCII") from exc
        if (
            path not in expected_paths
            or path in normalized
            or mode != "100644"
            or object_type != "blob"
            or OID_RE.fullmatch(encoded_object_id) is None
        ):
            raise ValueError("trust generation entry is invalid")
        normalized[path] = (mode, object_type, object_id)
    if set(normalized) != expected_paths:
        raise ValueError("trust generation entry set is incomplete")

    digest = hashlib.sha256(TRUST_GENERATION_DOMAIN)
    for path in sorted(normalized):
        mode, object_type, object_id = normalized[path]
        for field in (path, mode, object_type, object_id):
            encoded = field.encode("ascii")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
    return f"sha256:{digest.hexdigest()}"


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
    admin_entries: tuple[_DiffEntry, ...]
    changed_path_count: int
    forbidden_transient_path_changed: bool
    non_run_path_changed: bool


@dataclass(frozen=True)
class _ObjectInfo:
    kind: bytes
    size: int


@dataclass
class _AdminScanState:
    object_infos: dict[bytes, _ObjectInfo]
    scan_results: dict[bytes, bool]
    scanned_blob_bytes: int = 0
    scanned_blob_count: int = 0
    exhausted: bool = False


@dataclass
class _PublicationObjectCache:
    object_infos: dict[bytes, _ObjectInfo]
    blobs: dict[bytes, bytes]


@dataclass
class _RangeWorkBudget:
    diff_bytes: int
    entry_count: int
    path_bytes: int
    oid_references: int
    unique_oids: set[bytes]
    tree_inventory_bytes: int = 0
    tree_inventory_entries: int = 0
    tree_inventory_path_bytes: int = 0
    exhausted: bool = False


@dataclass(frozen=True)
class _RevisionFact:
    family: str
    current: str
    predecessors: tuple[str, ...]


@dataclass(frozen=True)
class _PublicationFacts:
    commit_index: int
    manifest_run_id: str | None
    campaign_ref: str | None
    publication_role: str | None
    revisions: tuple[_RevisionFact, ...]


@dataclass(frozen=True)
class _CommitHeader:
    name: bytes
    value: bytes


@dataclass
class _SemanticRangeBudget:
    bytes_attempted: int = 0
    lines_attempted: int = 0
    nodes_attempted: int = 0
    exhausted: bool = False


def sanitized_git_environment() -> dict[str, str]:
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
        environment=sanitized_git_environment(),
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
    if len(name) > MAX_TRANSIENT_NAME_BYTES:
        return True
    candidates: list[bytes] = []
    stem = name
    strip_count = 0
    while True:
        candidates.append(stem)
        next_stem: bytes | None = None
        emacs_match = EMACS_VERSION_BACKUP_SUFFIX_RE.search(stem)
        if emacs_match is not None:
            next_stem = stem[: emacs_match.start()]
        elif stem.endswith(b"~"):
            next_stem = stem[:-1]
        else:
            editor_match = EDITOR_TRANSIENT_SUFFIX_RE.search(stem)
            if editor_match is not None:
                next_stem = stem[: editor_match.start()]
            else:
                rotation_match = NUMERIC_ROTATION_SUFFIX_RE.search(stem)
                if rotation_match is not None:
                    next_stem = stem[: rotation_match.start()]
                else:
                    separator = stem.rfind(b".")
                    if (
                        separator > 0
                        and stem[separator:].lower() in STRIPPABLE_TRANSIENT_SUFFIXES
                    ):
                        next_stem = stem[:separator]
        if next_stem is None or next_stem == stem:
            break
        strip_count += 1
        if strip_count > MAX_TRANSIENT_SUFFIX_STRIPS:
            return True
        stem = next_stem
    normalized_candidates = {
        candidate.lower() for candidate in candidates if candidate
    } | {
        candidate[1:].lower()
        for candidate in candidates
        if candidate.startswith(b".") and len(candidate) > 1
    }
    if any(candidate.lower().startswith(b".codex") for candidate in candidates):
        return True
    if normalized_candidates.intersection(FORBIDDEN_TRANSIENT_FILENAMES):
        return True
    separated = re.sub(rb"([a-z0-9])([A-Z])", rb"\1 \2", stem)
    tokens = [token for token in re.split(rb"[^a-z0-9]+", separated.lower()) if token]
    normalized = b"_".join(tokens)
    compacted = b"".join(tokens)
    return (
        normalized in FORBIDDEN_TRANSIENT_NAME_STEMS
        or compacted in FORBIDDEN_TRANSIENT_COMPACT_NAMES
        or compacted.startswith(FORBIDDEN_TRANSIENT_COMPACT_PREFIXES)
        or any(part in compacted for part in FORBIDDEN_TRANSIENT_COMPACT_PARTS)
    )


def _is_forbidden_transient_path(path: bytes) -> bool:
    if _parse_run_path(path) is not None:
        return False
    parts = tuple(path.split(b"/"))
    return not parts or any(
        not part
        or part in {b".", b".."}
        or part.lower() in FORBIDDEN_TRANSIENT_COMPONENTS
        or _forbidden_transient_name(part)
        for part in parts
    )


def _admin_blob_is_safe(raw: bytes) -> bool:
    return not contains_high_confidence_credential(raw)


def _parse_diff(raw: bytes, work_budget: _RangeWorkBudget) -> _ParsedDiff:
    if work_budget.exhausted:
        raise _RangeWorkLimitExceeded
    if not raw:
        return _ParsedDiff((), (), 0, False, False)
    fields = raw.split(b"\0")
    if fields[-1] != b"":
        raise _ParseFailure
    fields.pop()
    if len(fields) % 2:
        raise _ParseFailure
    commit_entry_count = len(fields) // 2
    if (
        work_budget.diff_bytes + len(raw) > MAX_RANGE_DIFF_BYTES
        or work_budget.entry_count + commit_entry_count > MAX_RANGE_DIFF_ENTRIES
    ):
        work_budget.exhausted = True
        raise _RangeWorkLimitExceeded
    matches: list[re.Match[bytes]] = []
    commit_path_bytes = 0
    commit_oid_references = 0
    commit_unique_oids: set[bytes] = set()
    for offset in range(0, len(fields), 2):
        metadata, path = fields[offset : offset + 2]
        match = RAW_DIFF_RE.fullmatch(metadata)
        if match is None or not path or len(path) > MAX_TRANSIENT_NAME_BYTES:
            raise _ParseFailure
        matches.append(match)
        commit_path_bytes += len(path)
        if work_budget.path_bytes + commit_path_bytes > MAX_RANGE_PATH_BYTES:
            work_budget.exhausted = True
            raise _RangeWorkLimitExceeded
        for object_id in (match.group("old_oid"), match.group("new_oid")):
            if object_id in ZERO_OIDS:
                continue
            commit_oid_references += 1
            if (
                work_budget.oid_references + commit_oid_references
                > MAX_RANGE_OID_REFERENCES
            ):
                work_budget.exhausted = True
                raise _RangeWorkLimitExceeded
            if object_id not in work_budget.unique_oids:
                commit_unique_oids.add(object_id)
                if (
                    len(work_budget.unique_oids) + len(commit_unique_oids)
                    > MAX_RANGE_UNIQUE_OIDS
                ):
                    work_budget.exhausted = True
                    raise _RangeWorkLimitExceeded
    work_budget.diff_bytes += len(raw)
    work_budget.entry_count += commit_entry_count
    work_budget.path_bytes += commit_path_bytes
    work_budget.oid_references += commit_oid_references
    work_budget.unique_oids.update(commit_unique_oids)

    run_entries: list[_DiffEntry] = []
    admin_entries: list[_DiffEntry] = []
    changed_path_count = 0
    forbidden_transient_path_changed = False
    non_run_path_changed = False
    for entry_index, offset in enumerate(range(0, len(fields), 2)):
        metadata, path = fields[offset : offset + 2]
        match = matches[entry_index]
        changed_path_count += 1
        forbidden_transient_path_changed = (
            forbidden_transient_path_changed or _is_forbidden_transient_path(path)
        )
        entry = _DiffEntry(
            path=path,
            old_mode=match.group("old_mode"),
            new_mode=match.group("new_mode"),
            old_oid=match.group("old_oid"),
            new_oid=match.group("new_oid"),
            status=match.group("status").decode("ascii"),
            run_path=_parse_run_path(path),
        )
        if not _is_run_candidate(path):
            non_run_path_changed = True
            if len(admin_entries) >= MAX_CHANGED_ADMIN_PATHS:
                raise _ParseFailure
            admin_entries.append(entry)
            continue
        if len(run_entries) >= MAX_CHANGED_RUN_PATHS:
            raise _ParseFailure
        run_entries.append(entry)
    return _ParsedDiff(
        tuple(run_entries),
        tuple(admin_entries),
        changed_path_count,
        forbidden_transient_path_changed,
        non_run_path_changed,
    )


def _bounded_empty_tree_inventory(
    root: Path,
    commit_oid: bytes,
    work_budget: _RangeWorkBudget,
) -> dict[bytes, bytes]:
    if work_budget.exhausted:
        raise _RangeWorkLimitExceeded
    result = _run_git(
        root,
        [
            "ls-tree",
            "-r",
            "-t",
            "-z",
            "--full-tree",
            commit_oid.decode("ascii"),
        ],
        max_stdout_bytes=MAX_TREE_INVENTORY_OUTPUT_BYTES,
    )
    raw = result.stdout
    if work_budget.tree_inventory_bytes + len(raw) > MAX_RANGE_TREE_INVENTORY_BYTES:
        work_budget.exhausted = True
        raise _RangeWorkLimitExceeded

    records = raw.split(b"\0")
    if records[-1] != b"":
        raise _TreeInventoryFailure
    records.pop()
    if (
        work_budget.tree_inventory_entries + len(records)
        > MAX_RANGE_TREE_INVENTORY_ENTRIES
    ):
        work_budget.exhausted = True
        raise _RangeWorkLimitExceeded

    tree_entries: dict[bytes, bytes] = {}
    seen_paths: set[bytes] = set()
    nonempty_tree_paths: set[bytes] = set()
    inventory_path_bytes = 0
    for record in records:
        metadata, separator, path = record.partition(b"\t")
        match = TREE_ENTRY_METADATA_RE.fullmatch(metadata)
        if (
            not separator
            or match is None
            or not path
            or len(path) > MAX_TRANSIENT_NAME_BYTES
            or path in seen_paths
        ):
            raise _TreeInventoryFailure
        seen_paths.add(path)
        inventory_path_bytes += len(path)
        if (
            work_budget.tree_inventory_path_bytes + inventory_path_bytes
            > MAX_RANGE_TREE_INVENTORY_PATH_BYTES
        ):
            work_budget.exhausted = True
            raise _RangeWorkLimitExceeded

        parent, parent_separator, _name = path.rpartition(b"/")
        if parent_separator:
            if not parent:
                raise _TreeInventoryFailure
            nonempty_tree_paths.add(parent)
        if match.group("kind") == b"tree":
            if match.group("mode") != b"040000":
                raise _TreeInventoryFailure
            tree_entries[path] = match.group("oid")

    if not nonempty_tree_paths.issubset(tree_entries):
        raise _TreeInventoryFailure
    work_budget.tree_inventory_bytes += len(raw)
    work_budget.tree_inventory_entries += len(records)
    work_budget.tree_inventory_path_bytes += inventory_path_bytes
    return {
        path: object_id
        for path, object_id in tree_entries.items()
        if path not in nonempty_tree_paths
    }


def _empty_tree_diff(
    parent_inventory: dict[bytes, bytes],
    commit_inventory: dict[bytes, bytes],
    *,
    byte_limit: int,
) -> bytes:
    output = bytearray()
    for path in sorted(parent_inventory.keys() | commit_inventory.keys()):
        old_oid = parent_inventory.get(path)
        new_oid = commit_inventory.get(path)
        if old_oid == new_oid:
            continue
        object_id = old_oid if old_oid is not None else new_oid
        if object_id is None:
            raise _TreeInventoryFailure
        zero_oid = b"0" * len(object_id)
        if old_oid is None:
            old_mode = b"000000"
            new_mode = b"040000"
            old_value = zero_oid
            new_value = new_oid
            status = b"A"
        elif new_oid is None:
            old_mode = b"040000"
            new_mode = b"000000"
            old_value = old_oid
            new_value = zero_oid
            status = b"D"
        else:
            new_mode = b"040000"
            old_mode = b"040000"
            old_value = old_oid
            new_value = new_oid
            status = b"M"
        record = (
            b":"
            + old_mode
            + b" "
            + new_mode
            + b" "
            + old_value
            + b" "
            + new_value
            + b" "
            + status
            + b"\0"
            + path
            + b"\0"
        )
        if len(output) + len(record) > byte_limit:
            raise _RangeWorkLimitExceeded
        output.extend(record)
    return bytes(output)


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


def _cached_object_info(
    root: Path,
    object_ids: Iterable[bytes],
    cache: dict[bytes, _ObjectInfo],
) -> dict[bytes, _ObjectInfo]:
    requested = set(object_ids)
    missing = requested.difference(cache)
    if missing:
        cache.update(_batch_object_info(root, missing))
    return {object_id: cache[object_id] for object_id in requested}


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
    object_cache: dict[bytes, _ObjectInfo],
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

    objects = _cached_object_info(root, inspect_objects, object_cache)
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


def _validate_admin_entries(
    root: Path,
    commit_index: int,
    entries: tuple[_DiffEntry, ...],
    scan_state: _AdminScanState,
    issues: _IssueCollector,
) -> None:
    if scan_state.exhausted:
        raise _RangeWorkLimitExceeded

    unsafe = False
    inspect_objects: list[bytes] = []
    for entry in entries:
        if _is_forbidden_transient_path(entry.path):
            continue
        if entry.path not in V2_ADMIN_PATHS:
            unsafe = True
            continue
        if entry.status == "D":
            if entry.path in V2_ADMIN_REQUIRED_PATHS:
                unsafe = True
            continue
        if (
            entry.status not in {"A", "M"}
            or entry.new_mode != b"100644"
            or entry.new_oid in ZERO_OIDS
        ):
            unsafe = True
            continue
        inspect_objects.append(entry.new_oid)

    new_object_ids = {
        object_id
        for object_id in inspect_objects
        if object_id not in scan_state.object_infos
    }
    if (
        scan_state.scanned_blob_count + len(new_object_ids) > MAX_ADMIN_SCAN_OBJECTS
        or len(scan_state.object_infos) + len(new_object_ids) > MAX_ADMIN_SCAN_OBJECTS
    ):
        scan_state.exhausted = True
        raise _RangeWorkLimitExceeded
    if new_object_ids:
        inspected = _batch_object_info(root, new_object_ids)
        scan_state.object_infos.update(inspected)

    scannable: dict[bytes, _ObjectInfo] = {}
    for object_id in inspect_objects:
        info = scan_state.object_infos.get(object_id)
        if info is None or info.kind != b"blob" or info.size > MAX_ADMIN_BLOB_BYTES:
            unsafe = True
            continue
        scannable[object_id] = info

    unscanned = {
        object_id: info
        for object_id, info in scannable.items()
        if object_id not in scan_state.scan_results
    }
    additional_bytes = sum(info.size for info in unscanned.values())
    if (
        scan_state.exhausted
        or scan_state.scanned_blob_count + len(unscanned) > MAX_ADMIN_SCAN_OBJECTS
        or scan_state.scanned_blob_bytes + additional_bytes > MAX_ADMIN_SCAN_BYTES
    ):
        scan_state.exhausted = True
        raise _RangeWorkLimitExceeded
    if unscanned:
        try:
            contents = _batch_blob_contents(root, unscanned)
        except _SemanticFailure as exc:
            raise _AdminFailure from exc
        results = {
            object_id: _admin_blob_is_safe(contents[object_id])
            for object_id in sorted(unscanned)
        }
        scan_state.scanned_blob_count += len(unscanned)
        scan_state.scanned_blob_bytes += additional_bytes
        scan_state.scan_results.update(results)

    if any(
        not scan_state.scan_results.get(object_id, False) for object_id in scannable
    ):
        unsafe = True
    if unsafe:
        issues.add(f"commit {commit_index}: admin path, object, or secret gate failed")


def _load_publication_blobs(
    root: Path,
    publication_run: _RunPath,
    entries: list[_DiffEntry],
    objects: dict[bytes, _ObjectInfo],
    cache: _PublicationObjectCache,
    budget: _SemanticRangeBudget,
) -> dict[str, bytes]:
    directory = _run_directory(publication_run)
    candidates: dict[str, tuple[bytes, _ObjectInfo]] = {}
    for entry in entries:
        run_path = entry.run_path
        if (
            run_path is None
            or _run_directory(run_path) != directory
            or run_path.artifact not in RUN_ARTIFACTS
            or entry.status != "A"
            or entry.new_mode != b"100644"
        ):
            continue
        info = objects.get(entry.new_oid)
        if info is None or info.kind != b"blob":
            continue
        candidates[run_path.artifact] = (entry.new_oid, info)
    if frozenset(candidates) != RUN_ARTIFACTS:
        return {}

    bundle_bytes = sum(info.size for _, info in candidates.values())
    if bundle_bytes > MAX_SEMANTIC_BUNDLE_BYTES:
        raise _SemanticFailure

    missing_infos = {
        object_id: info
        for object_id, info in candidates.values()
        if object_id not in cache.blobs
    }
    read_bytes = sum(info.size for info in missing_infos.values())
    _consume_semantic_bytes(budget, read_bytes)
    if missing_infos:
        contents = _batch_blob_contents(root, missing_infos)
        if any(
            len(contents[object_id]) != info.size
            for object_id, info in missing_infos.items()
        ):
            raise _SemanticFailure
        cache.blobs.update(contents)

    return {
        artifact: cache.blobs[object_id]
        for artifact, (object_id, _) in candidates.items()
    }


def _consume_semantic_bytes(budget: _SemanticRangeBudget, amount: int) -> None:
    if budget.exhausted or amount < 0:
        budget.exhausted = True
        raise _SemanticFailure
    budget.bytes_attempted += amount
    if budget.bytes_attempted > MAX_RANGE_SEMANTIC_BYTES:
        budget.exhausted = True
        raise _SemanticFailure


def _consume_semantic_lines(budget: _SemanticRangeBudget, amount: int) -> None:
    if budget.exhausted or amount < 0:
        budget.exhausted = True
        raise _SemanticFailure
    budget.lines_attempted += amount
    if budget.lines_attempted > MAX_RANGE_SEMANTIC_LINES:
        budget.exhausted = True
        raise _SemanticFailure


def _consume_semantic_nodes(budget: _SemanticRangeBudget | None, amount: int) -> None:
    if budget is None:
        return
    if budget.exhausted or amount < 0:
        budget.exhausted = True
        raise _SemanticFailure
    budget.nodes_attempted += amount
    if budget.nodes_attempted > MAX_RANGE_SEMANTIC_NODES:
        budget.exhausted = True
        raise _SemanticFailure


def _semantic_json_preparse_node_count(
    raw: bytes,
    *,
    node_limit: int = MAX_SEMANTIC_JSON_NODES,
    range_budget: _SemanticRangeBudget | None = None,
    range_charge_multiplier: int = 1,
) -> int | None:
    if range_charge_multiplier <= 0:
        raise _SemanticFailure
    whitespace = b" \t\r\n"
    scalar_delimiters = b" \t\r\n,]}:"
    stack: list[list[Any]] = []
    root_state = "value"
    nodes = 0
    index = 0

    def register_value() -> bool:
        nonlocal nodes, root_state
        nodes += 1
        _consume_semantic_nodes(range_budget, range_charge_multiplier)
        if nodes > node_limit or nodes > MAX_SEMANTIC_JSON_NODES:
            raise _SemanticFailure
        if not stack:
            if root_state != "value":
                return False
            root_state = "done"
            return True
        frame = stack[-1]
        if frame[0] == "array" and frame[1] == "value_or_end":
            frame[1] = "comma_or_end"
        elif frame[0] == "object" and frame[1] == "value":
            frame[1] = "comma_or_end"
        else:
            return False
        frame[2] += 1
        if frame[2] > MAX_SEMANTIC_JSON_CONTAINER_ITEMS:
            raise _SemanticFailure
        return True

    def skip_string(start: int) -> int | None:
        cursor = start + 1
        while cursor < len(raw):
            if cursor - start - 1 > MAX_SEMANTIC_JSON_STRING_BYTES:
                raise _SemanticFailure
            byte = raw[cursor]
            if byte == 0x22:
                return cursor + 1
            if byte == 0x5C:
                cursor += 2
            else:
                cursor += 1
        return None

    while index < len(raw):
        while index < len(raw) and raw[index] in whitespace:
            index += 1
        if index >= len(raw):
            break

        if stack:
            frame = stack[-1]
            byte = raw[index]
            if frame[0] == "object":
                if frame[1] == "key_or_end":
                    if byte == 0x7D:
                        stack.pop()
                        index += 1
                        continue
                    if byte != 0x22:
                        return None
                    string_end = skip_string(index)
                    if string_end is None:
                        return None
                    index = string_end
                    frame[1] = "colon"
                    continue
                if frame[1] == "colon":
                    if byte != 0x3A:
                        return None
                    frame[1] = "value"
                    index += 1
                    continue
                if frame[1] == "comma_or_end":
                    if byte == 0x2C:
                        frame[1] = "key_or_end"
                        index += 1
                        continue
                    if byte == 0x7D:
                        stack.pop()
                        index += 1
                        continue
                    return None
            elif frame[1] == "value_or_end" and byte == 0x5D:
                stack.pop()
                index += 1
                continue
            elif frame[1] == "comma_or_end":
                if byte == 0x2C:
                    frame[1] = "value_or_end"
                    index += 1
                    continue
                if byte == 0x5D:
                    stack.pop()
                    index += 1
                    continue
                return None
        elif root_state == "done":
            return None

        byte = raw[index]
        if byte in (0x7B, 0x5B):
            if not register_value():
                return None
            if len(stack) + 1 > MAX_SEMANTIC_JSON_DEPTH:
                raise _SemanticFailure
            stack.append(
                ["object", "key_or_end", 0]
                if byte == 0x7B
                else ["array", "value_or_end", 0]
            )
            index += 1
            continue
        if byte == 0x22:
            if not register_value():
                return None
            string_end = skip_string(index)
            if string_end is None:
                return None
            index = string_end
            continue
        if byte in (0x2C, 0x3A, 0x5D, 0x7D):
            return None
        if not register_value():
            return None
        scalar_start = index
        index += 1
        while index < len(raw) and raw[index] not in scalar_delimiters:
            index += 1
        if index - scalar_start > MAX_SEMANTIC_JSON_SCALAR_BYTES:
            raise _SemanticFailure

    if stack or root_state != "done":
        return None
    return nodes


def _decode_semantic_json(raw: bytes) -> Any | None:
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


def _parse_semantic_json_with_nodes(
    raw: bytes | None,
    *,
    node_limit: int = MAX_SEMANTIC_JSON_NODES,
    range_budget: _SemanticRangeBudget | None = None,
    range_charge_multiplier: int = 1,
) -> tuple[Any | None, int]:
    if raw is None:
        return None, 0
    _consume_semantic_nodes(range_budget, range_charge_multiplier)
    nodes = _semantic_json_preparse_node_count(
        raw,
        node_limit=node_limit,
        range_budget=range_budget,
        range_charge_multiplier=range_charge_multiplier,
    )
    if nodes is None:
        return None, 0
    return _decode_semantic_json(raw), nodes


def _parse_semantic_json(
    raw: bytes | None, range_budget: _SemanticRangeBudget | None = None
) -> Any | None:
    return _parse_semantic_json_with_nodes(raw, range_budget=range_budget)[0]


def _semantic_jsonl_values(raw: bytes, budget: _SemanticRangeBudget) -> Iterable[Any]:
    offset = 0
    while offset < len(raw):
        line_end = raw.find(b"\n", offset)
        if line_end < 0:
            line = raw[offset:]
            offset = len(raw)
        else:
            line = raw[offset:line_end]
            offset = line_end + 1
        if len(line) > MAX_SEMANTIC_JSONL_ROW_BYTES:
            raise _SemanticFailure
        value, _ = _parse_semantic_json_with_nodes(
            line,
            range_budget=budget,
        )
        yield value


def _publication_line_count(blobs: dict[str, bytes]) -> int:
    return sum(
        raw.count(b"\n") + (not raw.endswith(b"\n")) for raw in blobs.values() if raw
    )


def _charge_strict_publication_parse(
    blobs: dict[str, bytes], budget: _SemanticRangeBudget
) -> None:
    # One bounded preparse accounts for itself and the trusted bundle validator pass.
    _consume_semantic_bytes(budget, 2 * sum(len(raw) for raw in blobs.values()))
    _consume_semantic_lines(budget, 2 * _publication_line_count(blobs))
    for artifact in sorted(SEMANTIC_JSON_ARTIFACTS):
        raw = blobs.get(artifact)
        if raw is None:
            continue
        _consume_semantic_nodes(budget, 2)
        _semantic_json_preparse_node_count(
            raw,
            range_budget=budget,
            range_charge_multiplier=2,
        )
    for artifact in sorted(SEMANTIC_JSONL_ARTIFACTS):
        raw = blobs.get(artifact, b"")
        offset = 0
        while offset < len(raw):
            line_end = raw.find(b"\n", offset)
            if line_end < 0:
                line = raw[offset:]
                offset = len(raw)
            else:
                line = raw[offset:line_end]
                offset = line_end + 1
            if len(line) > MAX_SEMANTIC_JSONL_ROW_BYTES:
                raise _SemanticFailure
            _consume_semantic_nodes(budget, 2)
            _semantic_json_preparse_node_count(
                line,
                range_budget=budget,
                range_charge_multiplier=2,
            )


def _load_structured_publication_validator() -> Any:
    try:
        from scripts import retrospective_history_v2 as validator
    except ModuleNotFoundError as error:
        if error.name != "scripts":
            raise
        import retrospective_history_v2 as validator
    return validator


def _strict_validate_publication_bundle(
    publication_run: _RunPath, blobs: dict[str, bytes]
) -> list[str]:
    if frozenset(blobs) != RUN_ARTIFACTS:
        return ["publication bundle is incomplete"]
    try:
        validator = _load_structured_publication_validator()

        required_attributes = (
            "MAX_BUNDLE_ARTIFACT_BYTES",
            "_ReadBudget",
            "_discover_bundles",
            "_load_privacy_validator",
            "_load_schema_validators",
            "_open_validation_root",
            "_validate_bundle",
        )
        if any(not hasattr(validator, name) for name in required_attributes):
            raise RuntimeError
        with tempfile.TemporaryDirectory(
            prefix="retrospective-history-v2-publication-"
        ) as temporary:
            root = Path(temporary)
            directory = root / _run_directory(publication_run)
            directory.mkdir(parents=True)
            visible_files: list[Path] = []
            for artifact in sorted(RUN_ARTIFACTS):
                relative = Path(_run_directory(publication_run), artifact)
                (root / relative).write_bytes(blobs[artifact])
                visible_files.append(relative)

            root_descriptor = validator._open_validation_root(root)
            try:
                issues: list[str] = []
                validators = validator._load_schema_validators()
                privacy_validator = validator._load_privacy_validator()
                if validators is None or privacy_validator is None:
                    raise RuntimeError
                bundles = validator._discover_bundles(
                    root, root_descriptor, visible_files, issues
                )
                if len(bundles) != 1:
                    raise RuntimeError
                read_budget = validator._ReadBudget(validator.MAX_BUNDLE_ARTIFACT_BYTES)
                validator._validate_bundle(
                    bundles[0],
                    root_descriptor,
                    issues,
                    validators,
                    privacy_validator,
                    read_budget,
                )
            finally:
                os.close(root_descriptor)
        if any(not isinstance(issue, str) for issue in issues):
            raise RuntimeError
        return sorted(dict.fromkeys(issues))
    except Exception:
        return ["trusted structured publication validation failed"]


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
    commit_index: int,
    blobs: dict[str, bytes],
    budget: _SemanticRangeBudget,
) -> _PublicationFacts:
    documents = {
        artifact: _parse_semantic_json(blobs.get(artifact), budget)
        for artifact in sorted(SEMANTIC_JSON_ARTIFACTS)
    }
    manifest_value = documents.get("manifest.json")
    manifest = manifest_value if isinstance(manifest_value, dict) else {}
    manifest_run_id_value = manifest.get("run_id")
    manifest_run_id = (
        manifest_run_id_value if isinstance(manifest_run_id_value, str) else None
    )
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

    for artifact in sorted(SEMANTIC_JSONL_ARTIFACTS):
        fields = REVISION_ARTIFACT_FIELDS[artifact]
        for value in _semantic_jsonl_values(blobs.get(artifact, b""), budget):
            fact = _revision_fact_from_record(value, fields)
            if fact is not None:
                revisions.append(fact)
    if len(revisions) > MAX_RANGE_REVISION_FACTS:
        raise _SemanticFailure
    return _PublicationFacts(
        commit_index=commit_index,
        manifest_run_id=manifest_run_id,
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


def _validsig_matches_allowlist(
    status: bytes,
    allowed_fingerprints: frozenset[bytes] | None = None,
) -> bool:
    if allowed_fingerprints is None:
        allowed_fingerprints = V2_SIGNING_FINGERPRINTS
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
    return signer_fingerprints[0] in allowed_fingerprints


def _verify_commit_signature(
    root: Path,
    commit_oid: bytes,
    allowed_fingerprints: frozenset[bytes] | None = None,
) -> bool:
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
    return _validsig_matches_allowlist(result.stderr, allowed_fingerprints)


def _verify_detached_openpgp_signature(
    signature: bytes,
    payload: bytes,
    signer_fingerprint: bytes,
) -> bool:
    if signer_fingerprint not in V2_SIGNING_FINGERPRINTS:
        return False
    try:
        canonical_signature = canonical_openpgp_detached_signature(
            signature,
            signer_fingerprint.decode("ascii"),
        )
    except (PublisherAttestationError, UnicodeDecodeError):
        return False
    try:
        with tempfile.TemporaryDirectory(
            prefix="retrospective-history-v2-attestation-"
        ) as raw:
            temporary = Path(raw)
            signature_path = temporary / "publisher-signature.asc"
            payload_path = temporary / "publisher-attestation.bin"
            signature_path.write_bytes(canonical_signature)
            payload_path.write_bytes(payload)
            result = _run_process_bounded(
                [
                    "gpg",
                    "--quiet",
                    "--no-options",
                    "--no-autostart",
                    "--batch",
                    "--status-fd=2",
                    "--verify",
                    str(signature_path),
                    str(payload_path),
                ],
                input_data=None,
                environment=sanitized_git_environment(),
                max_stdout_bytes=0,
                max_stderr_bytes=MAX_GIT_STDERR_BYTES,
                timeout_seconds=GIT_TIMEOUT_SECONDS,
            )
    except (OSError, _GitFailure):
        return False
    return result.returncode == 0 and _validsig_matches_allowlist(
        result.stderr,
        frozenset({signer_fingerprint}),
    )


def _verify_publisher_attestation(blobs: dict[str, bytes]) -> bool:
    manifest = _decode_semantic_json(blobs.get("manifest.json", b""))
    if not isinstance(manifest, dict):
        return False
    attestation = manifest.get("publisher_attestation")
    if not isinstance(attestation, dict) or set(attestation) != {
        "scheme",
        "signature",
        "signer_fingerprint",
    }:
        return False
    if attestation.get("scheme") != PUBLISHER_ATTESTATION_SCHEME:
        return False
    signature = attestation.get("signature")
    signer_fingerprint = attestation.get("signer_fingerprint")
    run_ref = manifest.get("run_ref")
    bundle_digest = manifest.get("retained_bundle_digest_v2")
    if not all(
        isinstance(value, str)
        for value in (signature, signer_fingerprint, run_ref, bundle_digest)
    ):
        return False
    try:
        encoded_signature = signature.encode("ascii")
        encoded_fingerprint = signer_fingerprint.encode("ascii")
        payload = publisher_attestation_payload(run_ref, bundle_digest)
    except (UnicodeEncodeError, ValueError):
        return False
    return _verify_detached_openpgp_signature(
        encoded_signature,
        payload,
        encoded_fingerprint,
    )


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


def _load_commit_message(root: Path, commit_oid: bytes) -> bytes:
    raw = _load_commit(root, commit_oid)
    _headers, message = _parse_commit_headers(raw)
    return message


def _validate_commit_metadata(
    root: Path,
    commit_oid: bytes,
    expected_parent: bytes,
    publication_run: _RunPath | None,
) -> bool:
    try:
        raw = _load_commit(root, commit_oid)
        headers, message = _parse_commit_headers(raw)
    except (_GitFailure, _ParseFailure):
        return False

    names = tuple(header.name for header in headers)
    if names not in {COMMIT_HEADER_ORDER, (*COMMIT_HEADER_ORDER, b"gpgsig")}:
        return False
    values = {header.name: header.value for header in headers}
    if (
        OID_RE.fullmatch(values[b"tree"]) is None
        or values[b"parent"] != expected_parent
    ):
        return False
    if b"gpgsig" in values and not _valid_signature(values[b"gpgsig"]):
        return False

    if (
        ADMIN_AUTHOR_IDENTITY_RE.fullmatch(values[b"author"]) is None
        or ADMIN_AUTHOR_IDENTITY_RE.fullmatch(values[b"committer"]) is None
    ):
        return False

    message_match = COMMIT_MESSAGE_RE.fullmatch(message)
    if message_match is None or not _valid_window(message_match.group("window")):
        return False
    mode = message_match.group("mode").decode("ascii")
    window = message_match.group("window").decode("ascii")
    if (
        publication_run is None
        or publication_run.mode != mode
        or publication_run.window != window
        or message_match.group("run_ref")
        != b"run_ref_v2:" + publication_run.run_id.encode("ascii")
    ):
        return False
    return True


def _validate_admin_commit_metadata(
    root: Path,
    commit_oid: bytes,
    expected_parent: bytes,
    *,
    bootstrap: bool,
    trust_root_upgrade: bool = False,
    allow_github_final_squash: bool = False,
) -> bool:
    try:
        raw = _load_commit(root, commit_oid)
        headers, message = _parse_commit_headers(raw)
    except (_GitFailure, _ParseFailure):
        return False

    names = tuple(header.name for header in headers)
    if names != (*COMMIT_HEADER_ORDER, b"gpgsig"):
        return False
    values = {header.name: header.value for header in headers}
    if (
        OID_RE.fullmatch(values[b"tree"]) is None
        or values[b"parent"] != expected_parent
        or not _valid_signature(values[b"gpgsig"])
    ):
        return False
    if bootstrap:
        if message != V2_ADMIN_BOOTSTRAP_MESSAGE:
            return False
    elif trust_root_upgrade:
        if message != TRUST_ROOT_UPGRADE_MESSAGE:
            return False
    elif ADMIN_COMMIT_MESSAGE_RE.fullmatch(message) is None:
        return False

    author = values[b"author"]
    committer = values[b"committer"]
    maintainer_author = ADMIN_MAINTAINER_IDENTITY_RE.fullmatch(author)
    maintainer_committer = ADMIN_MAINTAINER_IDENTITY_RE.fullmatch(committer)
    github_committer = ADMIN_GITHUB_IDENTITY_RE.fullmatch(committer)
    generic_author = ADMIN_AUTHOR_IDENTITY_RE.fullmatch(author)
    if maintainer_author is not None and maintainer_committer is not None:
        allowed_fingerprints = V2_ADMIN_MAINTAINER_SIGNING_FINGERPRINTS
    elif (
        trust_root_upgrade
        or not allow_github_final_squash
        or github_committer is None
        or generic_author is None
    ):
        return False
    else:
        allowed_fingerprints = V2_ADMIN_GITHUB_SIGNING_FINGERPRINTS
    return _verify_commit_signature(root, commit_oid, allowed_fingerprints)


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


def _validate_bootstrap_admin_tree(
    root: Path, head_oid: bytes, issues: _IssueCollector
) -> None:
    paths = sorted(V2_ADMIN_PATHS)
    expressions = [head_oid + b":" + path for path in paths]
    result = _run_git(
        root,
        ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        input_data=b"".join(expression + b"\n" for expression in expressions),
        max_stdout_bytes=max(
            1024, sum(len(expression) + 96 for expression in expressions)
        ),
    )
    lines = result.stdout.splitlines()
    if len(lines) != len(expressions):
        raise _GitFailure
    for expression, line in zip(expressions, lines, strict=True):
        fields = line.split(b" ")
        if (
            line == expression + b" missing"
            or len(fields) != 3
            or OID_RE.fullmatch(fields[0]) is None
            or fields[1] != b"blob"
            or not fields[2].isdigit()
            or int(fields[2]) > MAX_ADMIN_BLOB_BYTES
        ):
            issues.add("range: bootstrap admin tree is incomplete or unsafe")
            return


def _tree_oid(root: Path, commit_oid: bytes) -> bytes:
    result = _run_git(
        root,
        ["rev-parse", "--verify", f"{commit_oid.decode('ascii')}^{{tree}}"],
        max_stdout_bytes=MAX_REVISION_BYTES,
    )
    tree_oid = result.stdout.strip()
    if OID_RE.fullmatch(tree_oid) is None:
        raise _ParseFailure
    return tree_oid


def _trust_root_generation(root: Path, commit_oid: bytes) -> str:
    paths = sorted(path.decode("ascii") for path in V2_TRUST_ROOT_PATHS)
    result = _run_git(
        root,
        [
            "ls-tree",
            "-z",
            "--full-tree",
            commit_oid.decode("ascii"),
            "--",
            *paths,
        ],
        max_stdout_bytes=sum(len(path) + 128 for path in paths),
    )
    entries: list[tuple[str, str, str, str]] = []
    records = result.stdout.split(b"\0")
    if not records or records[-1] != b"":
        raise _ParseFailure
    for record in records[:-1]:
        try:
            metadata, encoded_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.split(b" ", 2)
            entries.append(
                (
                    encoded_path.decode("ascii"),
                    mode.decode("ascii"),
                    object_type.decode("ascii"),
                    object_id.decode("ascii"),
                )
            )
        except (UnicodeDecodeError, ValueError) as exc:
            raise _ParseFailure from exc
    try:
        return trust_generation_from_entries(entries)
    except ValueError as exc:
        raise _ParseFailure from exc


def _prospective_squash_diff(
    root: Path,
    base_oid: bytes,
    head_oid: bytes,
) -> _ParsedDiff:
    work_budget = _RangeWorkBudget(0, 0, 0, 0, set())
    diff = _run_git(
        root,
        [
            "diff-tree",
            "--no-commit-id",
            "--raw",
            "-r",
            "-z",
            "--no-renames",
            "--no-abbrev",
            base_oid.decode("ascii"),
            head_oid.decode("ascii"),
            "--",
        ],
        max_stdout_bytes=MAX_DIFF_OUTPUT_BYTES,
    )
    base_inventory = _bounded_empty_tree_inventory(root, base_oid, work_budget)
    head_inventory = _bounded_empty_tree_inventory(root, head_oid, work_budget)
    empty_tree_diff = _empty_tree_diff(
        base_inventory,
        head_inventory,
        byte_limit=MAX_DIFF_OUTPUT_BYTES - len(diff.stdout),
    )
    return _parse_diff(diff.stdout + empty_tree_diff, work_budget)


def _validate_prospective_squash(
    root: Path,
    base_oid: bytes,
    head_oid: bytes,
    roles: set[str],
    publication_runs: list[_RunPath],
    admin_messages: list[bytes],
    trust_root_upgrade: bool,
    issues: _IssueCollector,
) -> bytes | None:
    try:
        parsed_diff = _prospective_squash_diff(root, base_oid, head_oid)
    except _RangeWorkLimitExceeded:
        issues.add(RANGE_WORK_LIMIT_DIAGNOSTIC)
        return None
    except (_GitFailure, _ParseFailure, _TreeInventoryFailure):
        issues.add("range: prospective squash tree inspection failed")
        return None

    if parsed_diff.forbidden_transient_path_changed:
        issues.add(
            "range: prospective squash changes a forbidden raw or transient path"
        )
    if not parsed_diff.changed_path_count:
        issues.add("range: prospective squash must not be empty")
        return None

    run_entries = list(parsed_diff.run_entries)
    admin_entries = parsed_diff.admin_entries
    if roles == {"publication"}:
        if admin_entries:
            issues.add(
                "range: prospective publication squash must not change admin paths"
            )
        prospective_run = _validate_publication_run(
            root,
            base_oid,
            1,
            run_entries,
            parsed_diff.changed_path_count,
            issues,
        )
        if len(publication_runs) != 1:
            issues.add(
                "range: publication pull request must contain exactly one v2 run"
            )
            return None
        expected_run = publication_runs[0]
        if prospective_run is None or _run_directory(prospective_run) != _run_directory(
            expected_run
        ):
            issues.add(
                "range: prospective squash tree must contain the one validated publication run"
            )
            return None
        subject = (
            "Publish session retrospective v2 "
            f"{expected_run.mode} {expected_run.window} "
            f"run_ref_v2:{expected_run.run_id}"
        ).encode("ascii")
        if len(subject) > MAX_SQUASH_SUBJECT_BYTES:
            issues.add("range: immutable squash subject is unsafe")
            return None
        return subject

    if roles == {"admin"}:
        if run_entries:
            issues.add("range: prospective admin squash must not change retained runs")
        _validate_admin_entries(
            root,
            1,
            admin_entries,
            _AdminScanState({}, {}),
            issues,
        )
        if trust_root_upgrade:
            subject = TRUST_ROOT_UPGRADE_MESSAGE.removesuffix(b"\n")
        else:
            subjects = set(admin_messages)
            if len(subjects) != 1:
                issues.add(
                    "range: admin commits must carry one identical immutable squash subject"
                )
                return None
            message = next(iter(subjects))
            if ADMIN_COMMIT_MESSAGE_RE.fullmatch(message) is None:
                issues.add("range: immutable admin squash subject is invalid")
                return None
            subject = message.removesuffix(b"\n")
        if contains_high_confidence_credential(subject):
            issues.add(
                "range: immutable admin squash subject contains sensitive material"
            )
            return None
        if (
            not subject
            or len(subject) > MAX_SQUASH_SUBJECT_BYTES
            or b"\n" in subject
            or b"\r" in subject
            or b"\0" in subject
        ):
            issues.add("range: immutable admin squash subject is unsafe")
            return None
        return subject

    issues.add(
        "range: prospective squash must have exactly one publication or admin role"
    )
    return None


def _validate_role_range(
    root: Path,
    base_rev: str,
    head_rev: str,
    *,
    require_admin_only: bool,
    prospective_squash: bool = False,
    merge_plan_out: list[PullRequestMergePlan] | None = None,
    require_single_commit: bool = False,
) -> list[str]:
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

    if require_single_commit and len(commits) != 1:
        return ["range: default-branch update must be exactly one squash commit"]

    bootstrap = base_oid == V2_ADMIN_BOOTSTRAP_BASE
    if bootstrap and len(commits) != 1:
        return [
            "range: bootstrap must be exactly one authenticated admin squash commit"
        ]

    issues = _IssueCollector()
    publications: list[_PublicationFacts] = []
    publication_runs: list[_RunPath] = []
    admin_messages: list[bytes] = []
    revision_fact_count = 0
    roles: set[str] = set()
    admin_scan_state = _AdminScanState({}, {})
    publication_cache = _PublicationObjectCache({}, {})
    range_work_budget = _RangeWorkBudget(0, 0, 0, 0, set())
    empty_tree_inventories: dict[bytes, dict[bytes, bytes]] = {}
    semantic_budget = _SemanticRangeBudget()
    trust_root_upgrade_commits: list[int] = []

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
            for inventory_oid in (parent_oid, commit_oid):
                if inventory_oid not in empty_tree_inventories:
                    empty_tree_inventories[inventory_oid] = (
                        _bounded_empty_tree_inventory(
                            resolved_root,
                            inventory_oid,
                            range_work_budget,
                        )
                    )
            empty_tree_diff = _empty_tree_diff(
                empty_tree_inventories[parent_oid],
                empty_tree_inventories[commit_oid],
                byte_limit=MAX_DIFF_OUTPUT_BYTES - len(diff.stdout),
            )
            parsed_diff = _parse_diff(
                diff.stdout + empty_tree_diff,
                range_work_budget,
            )
            if parsed_diff.forbidden_transient_path_changed:
                issues.add(
                    f"commit {current_index}: forbidden raw or transient path changed"
                )

            run_entries = list(parsed_diff.run_entries)
            admin_entries = parsed_diff.admin_entries
            has_runs = bool(run_entries)
            has_admin = bool(admin_entries) or not parsed_diff.changed_path_count
            changes_trust_root = any(
                entry.path in V2_TRUST_ROOT_PATHS for entry in admin_entries
            )
            if changes_trust_root and not bootstrap:
                trust_root_upgrade_commits.append(current_index)
            if has_runs:
                roles.add("publication")
            if has_admin:
                roles.add("admin")
            if has_runs and admin_entries:
                issues.add(
                    f"commit {current_index}: admin and publication paths must not be mixed"
                )
            if not parsed_diff.changed_path_count:
                issues.add(f"commit {current_index}: empty admin commit is not allowed")

            admin_metadata_valid = True
            if has_admin:
                admin_metadata_valid = _validate_admin_commit_metadata(
                    resolved_root,
                    commit_oid,
                    parent_oid,
                    bootstrap=bootstrap,
                    trust_root_upgrade=changes_trust_root and not bootstrap,
                    allow_github_final_squash=(
                        require_single_commit
                        and not prospective_squash
                        and merge_plan_out is None
                        and not require_admin_only
                    ),
                )
                if not admin_metadata_valid:
                    issues.add(
                        f"commit {current_index}: v2 admin commit metadata is unsafe"
                    )
                else:
                    admin_messages.append(
                        _load_commit_message(resolved_root, commit_oid)
                    )
            if admin_entries:
                _validate_admin_entries(
                    resolved_root,
                    current_index,
                    admin_entries,
                    admin_scan_state,
                    issues,
                )

            if not has_runs:
                continue
            if require_admin_only:
                issues.add("range: pull requests must contain admin-only changes")
            if bootstrap:
                issues.add("range: bootstrap commit must not change retained runs")

            publication_run = _validate_publication_run(
                resolved_root,
                parent_oid,
                current_index,
                run_entries,
                parsed_diff.changed_path_count,
                issues,
            )
            objects = _validate_run_entries(
                resolved_root,
                current_index,
                run_entries,
                publication_cache.object_infos,
                issues,
            )
            metadata_valid = _validate_commit_metadata(
                resolved_root, commit_oid, parent_oid, publication_run
            )
            if not metadata_valid:
                issues.add(
                    f"commit {current_index}: v2 publication commit metadata is unsafe"
                )
                continue
            if publication_run is None:
                continue

            blobs = _load_publication_blobs(
                resolved_root,
                publication_run,
                run_entries,
                objects,
                publication_cache,
                semantic_budget,
            )
            if frozenset(blobs) != RUN_ARTIFACTS:
                issues.add(
                    f"commit {current_index}: publication bundle could not be loaded safely"
                )
                continue

            _charge_strict_publication_parse(blobs, semantic_budget)
            strict_issues = _strict_validate_publication_bundle(publication_run, blobs)
            for strict_issue in strict_issues:
                issues.add(f"commit {current_index}: {strict_issue}")
            if strict_issues:
                continue
            if not _verify_publisher_attestation(blobs):
                issues.add(f"commit {current_index}: publisher attestation is invalid")
                continue

            semantic_blobs = {
                artifact: blobs[artifact] for artifact in SEMANTIC_ARTIFACTS
            }
            _consume_semantic_bytes(
                semantic_budget, sum(len(raw) for raw in semantic_blobs.values())
            )
            _consume_semantic_lines(
                semantic_budget, _publication_line_count(semantic_blobs)
            )
            facts = _extract_publication_facts(
                current_index, semantic_blobs, semantic_budget
            )
            if facts.manifest_run_id != publication_run.run_id:
                issues.add(
                    f"commit {current_index}: manifest run_id does not match the physical v2 run route"
                )
            revision_fact_count += len(facts.revisions)
            if revision_fact_count > MAX_RANGE_REVISION_FACTS:
                raise _SemanticFailure
            publications.append(facts)
            publication_runs.append(publication_run)
        except _RangeWorkLimitExceeded:
            return [RANGE_WORK_LIMIT_DIAGNOSTIC]
        except _GitFailure:
            issues.add(f"commit {current_index}: bounded Git object inspection failed")
        except _ParseFailure:
            issues.add(
                f"commit {current_index}: bounded Git diff is malformed or too large"
            )
        except _TreeInventoryFailure:
            issues.add(
                f"commit {current_index}: bounded Git tree-entry inventory failed"
            )
        except _AdminFailure:
            issues.add(
                f"commit {current_index}: bounded admin object inspection failed"
            )
        except _SemanticFailure:
            issues.add(
                f"commit {current_index}: bounded publication semantic inspection failed"
            )
            return issues.items

    if len(roles) > 1:
        issues.add("range: admin and publication roles must not be mixed")
    if require_admin_only and roles.difference({"admin"}):
        issues.add("range: pull requests must contain admin-only changes")
    trust_root_upgrade = bool(trust_root_upgrade_commits)
    if trust_root_upgrade:
        if require_single_commit:
            issues.add(
                "range: candidate-controlled post-merge workflow cannot authorize a trust-root upgrade"
            )
        elif len(commits) != 1 or trust_root_upgrade_commits != [1]:
            issues.add(
                "range: trust-root upgrade must be exactly one maintainer-signed commit"
            )
    if bootstrap:
        if roles != {"admin"}:
            issues.add("range: bootstrap must contain one admin-only commit")
        else:
            try:
                _validate_bootstrap_admin_tree(resolved_root, head_oid, issues)
            except _GitFailure:
                issues.add("range: bootstrap admin tree inspection failed")
    _validate_cross_commit_order(publications, issues)
    squash_subject: bytes | None = None
    if prospective_squash:
        try:
            squash_subject = _validate_prospective_squash(
                resolved_root,
                base_oid,
                head_oid,
                roles,
                publication_runs,
                admin_messages,
                trust_root_upgrade,
                issues,
            )
        except _RangeWorkLimitExceeded:
            issues.add(RANGE_WORK_LIMIT_DIAGNOSTIC)
        except (_AdminFailure, _GitFailure, _ParseFailure, _TreeInventoryFailure):
            issues.add("range: prospective squash tree inspection failed")
    if squash_subject is not None and not issues.items and merge_plan_out is not None:
        try:
            merge_plan_out.append(
                PullRequestMergePlan(
                    base_oid=base_oid.decode("ascii"),
                    head_oid=head_oid.decode("ascii"),
                    head_tree_oid=_tree_oid(resolved_root, head_oid).decode("ascii"),
                    squash_subject=squash_subject.decode("ascii"),
                    trust_generation=_trust_root_generation(resolved_root, base_oid),
                )
            )
        except (_GitFailure, _ParseFailure, UnicodeDecodeError):
            issues.add("range: immutable merge plan could not be constructed")
    return issues.items


def validate_append_only_range(root: Path, base_rev: str, head_rev: str) -> list[str]:
    """Validate authenticated publication or admin commits from base to head."""

    return _validate_role_range(root, base_rev, head_rev, require_admin_only=False)


def validate_pull_request_squash(
    root: Path,
    base_rev: str,
    head_rev: str,
) -> list[str]:
    """Validate untrusted PR history and its immutable squash plan."""

    return _validate_role_range(
        root,
        base_rev,
        head_rev,
        require_admin_only=False,
        prospective_squash=True,
    )


def build_pull_request_merge_plan(
    root: Path,
    base_rev: str,
    head_rev: str,
) -> tuple[PullRequestMergePlan | None, list[str]]:
    """Validate a candidate and return its deterministic App merge plan."""

    plans: list[PullRequestMergePlan] = []
    issues = _validate_role_range(
        root,
        base_rev,
        head_rev,
        require_admin_only=False,
        prospective_squash=True,
        merge_plan_out=plans,
    )
    if issues:
        return None, issues
    if len(plans) != 1:
        return None, ["range: immutable merge plan could not be constructed"]
    return plans[0], []


def validate_default_branch_update(
    root: Path,
    base_rev: str,
    head_rev: str,
) -> list[str]:
    """Validate one actual protected-branch squash commit."""

    return _validate_role_range(
        root,
        base_rev,
        head_rev,
        require_admin_only=False,
        require_single_commit=True,
    )


def validate_admin_pull_request_range(
    root: Path, base_rev: str, head_rev: str
) -> list[str]:
    """Validate authenticated admin-only PR history and its prospective squash."""

    return _validate_role_range(
        root,
        base_rev,
        head_rev,
        require_admin_only=True,
        prospective_squash=True,
    )


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


__all__ = [
    "PullRequestMergePlan",
    "build_pull_request_merge_plan",
    "sanitized_git_environment",
    "trust_generation_from_entries",
    "validate_admin_pull_request_range",
    "validate_append_only_range",
    "validate_checkout_matches_revision",
    "validate_default_branch_update",
    "validate_pull_request_squash",
]
