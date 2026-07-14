#!/usr/bin/env python3
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import datetime as dt
from decimal import Decimal
import errno
from functools import lru_cache
import hashlib
import heapq
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Iterable, Sequence

try:
    from retrospective_history_templates_v2 import (
        TEMPLATE_IDS_BY_SECTION,
        validate_and_render_template,
    )
except ModuleNotFoundError:  # Imported as scripts.retrospective_history_v2 in tests.
    from scripts.retrospective_history_templates_v2 import (
        TEMPLATE_IDS_BY_SECTION,
        validate_and_render_template,
    )


try:
    from jsonschema import Draft202012Validator as _Draft202012Validator
    from jsonschema import FormatChecker as _FormatChecker
except (
    Exception
):  # pragma: no cover - exercised by dependency-failure tests via patching
    _Draft202012Validator = None
    _FormatChecker = None


ARTIFACT_BASENAMES = (
    "coverage.json",
    "episodes.jsonl",
    "manifest.json",
    "report.md",
    "summary.json",
    "topics.jsonl",
    "trend_report.json",
    "turn_findings.jsonl",
)
ARTIFACT_BASENAME_SET = frozenset(ARTIFACT_BASENAMES)
JSON_ARTIFACTS = frozenset(
    {"coverage.json", "manifest.json", "summary.json", "trend_report.json"}
)
JSONL_ARTIFACTS = frozenset({"episodes.jsonl", "topics.jsonl", "turn_findings.jsonl"})
SCHEMA_TARGETS = {
    "coverage.json": "coverage",
    "episodes.jsonl": "episode_record",
    "manifest.json": "manifest",
    "report.md": "report_markdown",
    "summary.json": "summary",
    "topics.jsonl": "topic_record",
    "trend_report.json": "trend_report",
    "turn_findings.jsonl": "turn_finding_record",
}
MODES = frozenset({"daily", "weekly", "baseline", "session"})
EXECUTION_KINDS = frozenset({"retrospective", "bootstrap_v2", "compliance_retraction"})
PUBLICATION_ROLES = frozenset({"standalone", "campaign_segment", "campaign_root"})
PUBLICATION_CAMPAIGN_REASONS = frozenset({"size_partition", "baseline_window"})
PUBLICATION_STATUSES = frozenset({"partial", "complete", "complete_with_terminal_gaps"})
FULL_PUBLICATION_STATUSES = frozenset({"complete", "complete_with_terminal_gaps"})
NEGATIVE_TREND_METRICS = frozenset(
    {
        "failed_command",
        "approval_request",
        "auth_denial",
        "retry",
        "user_correction",
        "incomplete_verification",
        "over_exploration",
        "under_asking",
        "context_loss",
        "assumption_risk",
        "verification_gap",
        "safety_privacy_risk",
    }
)
REVISION_KINDS = frozenset(
    {
        "initial",
        "backfill",
        "correction",
        "screening_correction",
        "identity_reconciliation",
        "split",
        "merge",
        "policy_transition",
        "model_transition",
        "compliance_retraction",
    }
)
SUPERSESSION_REASONS = frozenset(
    {
        "initial",
        "backfill",
        "correction",
        "identity_reconciliation",
        "screening_correction",
        "topic_split",
        "topic_merge",
        "policy_transition",
        "model_transition",
        "compliance_retraction",
    }
)

WINDOW_COMPONENT_RE = re.compile(
    r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
    r"(?:_to_\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01]))?$"
)
RUN_ID_RE = re.compile(r"^[0-9a-f]{64}$")
RUN_REF_RE = re.compile(r"^run_ref_v2:[0-9a-f]{64}$")
RUN_REVISION_REF_RE = re.compile(r"^run_revision_ref_v2:[0-9a-f]{32}$")
KEY_ID_RE = re.compile(r"^key_id_v2:[0-9a-f]{16}$")
POLICY_ERA_REF_RE = re.compile(r"^policy_era_ref_v2:[0-9a-f]{32}$")
MODEL_ERA_REF_RE = re.compile(r"^model_era_ref_v2:[0-9a-f]{32}$")
DIGEST_RE = re.compile(r"^retained_bundle_digest_v2:sha256:[0-9a-f]{64}$")
PRODUCTION_CONFIGURATION_ROOT_RE = re.compile(
    r"^production_configuration_root_v2:sha256:[0-9a-f]{64}$"
)
CAMPAIGN_SEGMENT_ROOT_RE = re.compile(r"^campaign_segment_root_v2:sha256:[0-9a-f]{64}$")

SCHEMA_DIRECTORY = Path(__file__).resolve().parents[1] / "schemas"
SESSION_SCHEMA_PATH = SCHEMA_DIRECTORY / "session-retrospective-v2.schema.json"
RETAINED_MANIFEST_SCHEMA_PATH = SCHEMA_DIRECTORY / "retained-manifest-v2.schema.json"
PRIVACY_VALIDATOR_PATH = Path(__file__).with_name("retrospective_history_privacy_v2.py")

MAX_SCHEMA_BYTES = 2 * 1024 * 1024
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
MAX_BUNDLE_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_DISCOVERY_ENTRIES = 65536
MAX_DISCOVERY_FILES = 4096
MAX_BUNDLES = 512
MAX_DISCOVERY_PATH_BYTES = 256
MAX_JSONL_ROWS = 100_000
MAX_BUNDLE_JSONL_ROWS = 200_000
MAX_HISTORY_REVISIONS = 1_000_000
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 200_000
MAX_JSON_CONTAINER_ITEMS = 100_000
MAX_SCHEMA_ERRORS_PER_INSTANCE = 8
MAX_DIAGNOSTICS = 64
READ_CHUNK_BYTES = 64 * 1024

WINDOW_ROUTE_COMPONENT_COUNT = 32
RUN_ROUTE_COMPONENT_COUNT = 32
RUN_ARTIFACT_PATH_COMPONENT_COUNT = 68
WINDOW_ROUTE_DOMAIN = b"session-retrospective-retained-window-route-v2"
ROUTE_COMPONENT_RE = re.compile(r"^[0-9a-f]{2}$")

SCHEMA_UNAVAILABLE_ISSUE = "schema: Draft 2020-12 validation is unavailable"
PRIVACY_UNAVAILABLE_ISSUE = "privacy: retained v2 privacy validation is unavailable"
DIAGNOSTIC_LIMIT_ISSUE = "validation: additional issues omitted"
DISCOVERY_LIMIT_ISSUE = "runs: discovery work limit exceeded"
PATH_COLLISION_ISSUE = "runs: v2 retained-run route collision detected"
VALIDATION_WORK_LIMIT_ISSUE = "runs: validation work limit exceeded"
JSON_RESOURCE_ISSUE = "JSON exceeds parser resource limits"
SCHEMA_DIAGNOSTIC_KEYWORDS = frozenset(
    {
        "additionalProperties",
        "allOf",
        "anyOf",
        "const",
        "contains",
        "enum",
        "format",
        "items",
        "maxItems",
        "maxLength",
        "maximum",
        "minContains",
        "minItems",
        "minLength",
        "minimum",
        "not",
        "oneOf",
        "pattern",
        "prefixItems",
        "required",
        "type",
        "uniqueItems",
    }
)

SOURCE_KINDS = frozenset(
    {"session_index", "history", "active_rollout", "archived_rollout"}
)
PRIVACY_BREACH_REASONS = frozenset(
    {
        "identity_plaintext_cleanup_breach",
        "provider_policy_breach",
        "provider_retention_breach",
        "raw_retention_breach",
        "working_retention_breach",
    }
)
REPORT_TEMPLATE_SECTIONS = (
    ("what_happened", "What Happened"),
    ("worked_well", "What Worked Well"),
    ("friction_and_confusion", "Friction And Confusion"),
    ("errors_and_verification", "Errors And Verification"),
    ("collaboration_patterns", "Collaboration Patterns"),
    ("safety_and_privacy", "Safety And Privacy"),
    ("prompt_improvements", "Prompt Improvements"),
    ("agents_guidance", "Durable AGENTS.md Guidance"),
    ("skill_candidates", "Reusable Skill Candidates"),
    ("follow_ups", "Follow-up Actions"),
)
REPORT_CONFIDENCE_ORDER = (
    ("coverage", "Coverage"),
    ("extraction", "Extraction"),
    ("review", "Review"),
    ("comparability", "Compatible"),
)

BUNDLE_DOMAIN_TAG = b"session-retrospective-retained-bundle-v2"
BUNDLE_DIGEST_CONTRACT = {
    "algorithm": "sha-256",
    "domain_tag": BUNDLE_DOMAIN_TAG.decode("ascii"),
    "ordering": "bytewise-basename",
    "framing": "typed-name-length-v2",
    "manifest_projection": "omit-retained_bundle_digest_v2-only",
}
PRODUCTION_CONFIGURATION_DOMAIN_TAG = (
    b"session-retrospective-production-configuration-v2"
)
PRODUCTION_CONFIGURATION_FIELDS = (
    "active_calibration_receipt_ref",
    "active_calibration_model_era_ref",
    "active_shadow_receipt_ref",
    "active_shadow_model_era_ref",
)
CAMPAIGN_SEGMENT_DOMAIN_TAG = b"session-retrospective-campaign-segments-v2"

MANIFEST_KEYS = frozenset(
    {
        "artifact_type",
        "schema_version",
        "execution_kind",
        "publication_role",
        "publication_campaign_reason",
        "mode",
        "window",
        "run_id",
        "run_input_ref",
        "run_ref",
        "run_revision_ref",
        "key_ids",
        "prepared_at",
        "status",
        "gap_summary",
        "supersession",
        "artifact_inventory",
        "retained_bundle_digest_v2",
        "bundle_digest_contract",
        "head_bindings",
        "eras",
        "provenance",
        "production_configuration_root_v2",
        "retention_contract",
        "campaign_ref",
        "campaign_segment_count",
        "campaign_segment_metadata",
        "campaign_segment_root_v2",
    }
)
MANIFEST_REQUIRED_KEYS = MANIFEST_KEYS - {
    "campaign_ref",
    "campaign_segment_count",
    "campaign_segment_metadata",
    "campaign_segment_root_v2",
    "publication_campaign_reason",
}
SUPERSESSION_FIELDS = (
    "supersedes_run_revision_refs",
    "supersedes_episode_revision_refs",
    "supersedes_topic_revision_refs",
    "supersedes_turn_finding_revision_refs",
)
SUPERSESSION_KEYS = frozenset({"reason", *SUPERSESSION_FIELDS})
GAP_SUMMARY_KEYS = frozenset(
    {
        "source_repairable_gap_count",
        "semantic_repairable_gap_count",
        "terminal_gap_count",
        "terminal_authorization_usage_refs",
        "unaccounted_source_unit_count",
        "privacy_breach_count",
    }
)

EXPECTED_ARTIFACT_INVENTORY = [
    {
        "basename": "coverage.json",
        "media_type": "application/json",
        "encoding": "utf-8",
        "canonicalization": "canonical-json-v2",
        "schema_target": "coverage",
    },
    {
        "basename": "episodes.jsonl",
        "media_type": "application/x-ndjson",
        "encoding": "utf-8",
        "canonicalization": "canonical-jsonl-v2",
        "schema_target": "episode_record",
    },
    {
        "basename": "manifest.json",
        "media_type": "application/json",
        "encoding": "utf-8",
        "canonicalization": "canonical-json-projection-v2",
        "schema_target": "manifest",
    },
    {
        "basename": "report.md",
        "media_type": "text/markdown",
        "encoding": "utf-8",
        "canonicalization": "renderer-exact-markdown-v2",
        "schema_target": "report_markdown",
    },
    {
        "basename": "summary.json",
        "media_type": "application/json",
        "encoding": "utf-8",
        "canonicalization": "canonical-json-v2",
        "schema_target": "summary",
    },
    {
        "basename": "topics.jsonl",
        "media_type": "application/x-ndjson",
        "encoding": "utf-8",
        "canonicalization": "canonical-jsonl-v2",
        "schema_target": "topic_record",
    },
    {
        "basename": "trend_report.json",
        "media_type": "application/json",
        "encoding": "utf-8",
        "canonicalization": "canonical-json-v2",
        "schema_target": "trend_report",
    },
    {
        "basename": "turn_findings.jsonl",
        "media_type": "application/x-ndjson",
        "encoding": "utf-8",
        "canonicalization": "canonical-jsonl-v2",
        "schema_target": "turn_finding_record",
    },
]

SORTED_REFERENCE_FIELDS = frozenset(
    {
        "basis_refs",
        "calibration_receipt_refs",
        "containment_receipt_refs",
        "episode_revision_refs",
        "evidence_commitment_refs",
        "evidence_refs",
        "gap_refs",
        "job_refs",
        "key_ids",
        "leaf_root_refs",
        "metric_refs",
        "model_era_refs",
        "page_root_refs",
        "policy_era_refs",
        "provider_policy_refs",
        "request_egress_receipt_refs",
        "source_snapshot_refs",
        "storage_control_receipt_refs",
        "supersedes_coverage_revision_refs",
        "supersedes_episode_revision_refs",
        "supersedes_run_revision_refs",
        "supersedes_summary_revision_refs",
        "supersedes_topic_revision_refs",
        "supersedes_trend_revision_refs",
        "supersedes_turn_finding_revision_refs",
        "target_session_refs",
        "terminal_authorization_usage_refs",
    }
)
UNIQUE_REFERENCE_FIELDS = frozenset({*SORTED_REFERENCE_FIELDS, "turn_refs"})


@dataclass(frozen=True)
class RevisionSpec:
    family: str
    current_field: str
    predecessor_field: str
    supersedes_field: str
    entity_field: str | None
    current_pattern: re.Pattern[str]


REVISION_SPECS = {
    "coverage.json": RevisionSpec(
        "coverage",
        "coverage_revision_ref",
        "predecessor_coverage_revision_ref",
        "supersedes_coverage_revision_refs",
        None,
        re.compile(r"^coverage_revision_ref_v2:[0-9a-f]{32}$"),
    ),
    "episodes.jsonl": RevisionSpec(
        "episode",
        "episode_revision_ref",
        "predecessor_episode_revision_ref",
        "supersedes_episode_revision_refs",
        "episode_ref",
        re.compile(r"^episode_revision_ref_v2:[0-9a-f]{32}$"),
    ),
    "summary.json": RevisionSpec(
        "summary",
        "summary_revision_ref",
        "predecessor_summary_revision_ref",
        "supersedes_summary_revision_refs",
        None,
        re.compile(r"^summary_revision_ref_v2:[0-9a-f]{32}$"),
    ),
    "topics.jsonl": RevisionSpec(
        "topic",
        "topic_revision_ref",
        "predecessor_topic_revision_ref",
        "supersedes_topic_revision_refs",
        "topic_ref",
        re.compile(r"^topic_revision_ref_v2:[0-9a-f]{32}$"),
    ),
    "trend_report.json": RevisionSpec(
        "trend",
        "trend_revision_ref",
        "predecessor_trend_revision_ref",
        "supersedes_trend_revision_refs",
        None,
        re.compile(r"^trend_revision_ref_v2:[0-9a-f]{32}$"),
    ),
    "turn_findings.jsonl": RevisionSpec(
        "turn_finding",
        "turn_finding_revision_ref",
        "predecessor_turn_finding_revision_ref",
        "supersedes_turn_finding_revision_refs",
        "turn_ref",
        re.compile(r"^turn_finding_revision_ref_v2:[0-9a-f]{32}$"),
    ),
}

EXPECTED_ARTIFACT_TYPES = {
    "coverage.json": "coverage",
    "episodes.jsonl": "episode_record",
    "manifest.json": "manifest",
    "summary.json": "summary",
    "topics.jsonl": "topic_record",
    "trend_report.json": "trend_report",
    "turn_findings.jsonl": "turn_finding_record",
}


@dataclass(frozen=True)
class RevisionNode:
    family: str
    current: str
    predecessors: tuple[str, ...]
    kind: str
    entity_ref: str | None
    transaction_ref: str
    label: str


@dataclass
class Bundle:
    label: str
    mode: str
    window_component: str
    run_id: str
    files: dict[str, Path]
    physical_parts: tuple[str, ...] = ()
    raw: dict[str, bytes] = field(default_factory=dict)
    documents: dict[str, Any] = field(default_factory=dict)
    rows: dict[str, list[tuple[int, Any]]] = field(default_factory=dict)
    manifest: dict[str, Any] | None = None
    revisions: list[RevisionNode] = field(default_factory=list)

    @property
    def transaction_ref(self) -> str:
        if self.manifest is not None:
            value = self.manifest.get("run_revision_ref")
            if isinstance(value, str) and RUN_REVISION_REF_RE.fullmatch(value):
                return value
        return self.label


@dataclass(frozen=True)
class _TrendComparison:
    metric_ref: str
    key: tuple[str, str, str]
    prior_run_revision_ref: str
    claimed_delta: Decimal


@dataclass(frozen=True)
class _SummaryComparison:
    prior_run_revision_ref: str
    direction: str
    metric_refs: tuple[str, ...]


@dataclass(frozen=True)
class _TrendSnapshot:
    label: str
    run_revision_ref: str
    mode: str
    publication_time: dt.datetime
    window_start: dt.datetime
    window_end: dt.datetime
    supersedes_run_revision_refs: tuple[str, ...]
    rates: dict[tuple[str, str, str], Decimal]
    comparisons: tuple[_TrendComparison, ...]
    summary: _SummaryComparison | None


@dataclass(frozen=True)
class _PhysicalArtifactPath:
    relative: Path
    mode: str
    window_route: tuple[str, ...]
    window_component: str
    run_route: tuple[str, ...]
    run_id: str
    basename: str

    @property
    def directory_parts(self) -> tuple[str, ...]:
        return self.relative.parts[:-1]


class DuplicateJSONKeyError(ValueError):
    pass


class NonFiniteJSONNumberError(ValueError):
    pass


class _ReadLimitExceeded(Exception):
    pass


class _IssueCollector(list[str]):
    def __init__(self) -> None:
        super().__init__()
        self._seen: set[str] = set()
        self._truncated = False

    def append(self, issue: str) -> None:
        if issue in self._seen or self._truncated:
            return
        self._seen.add(issue)
        if len(self) < MAX_DIAGNOSTICS - 1:
            super().append(issue)
            return
        super().append(DIAGNOSTIC_LIMIT_ISSUE)
        self._truncated = True

    @property
    def full(self) -> bool:
        return self._truncated


@dataclass(frozen=True)
class _OpenedArtifact:
    basename: str
    descriptor: int
    initial_stat: os.stat_result
    byte_limit: int


@dataclass(frozen=True)
class _OpenedDirectoryChain:
    descriptors: tuple[int, ...]
    identities: tuple[tuple[int, int], ...]

    @property
    def leaf_descriptor(self) -> int:
        return self.descriptors[-1]


@dataclass
class _ReadBudget:
    remaining: int


@dataclass(frozen=True)
class _PrivacyValidator:
    validate: Callable[[Path, bytes], list[str]]
    allowed_issues: frozenset[str]


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKeyError("duplicate JSON key is not allowed")
        result[key] = value
    return result


def _reject_non_finite_number(value: str) -> None:
    raise NonFiniteJSONNumberError("non-finite JSON number is not allowed")


def _parse_json_bytes(raw: bytes) -> Any:
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_object,
        parse_constant=_reject_non_finite_number,
    )


def _json_bytes_within_preparse_limits(raw: bytes) -> bool:
    """Bound JSON structure before the standard decoder materializes its graph."""

    whitespace = b" \t\r\n"
    scalar_delimiters = b" \t\r\n,]}:"
    stack: list[list[Any]] = []
    root_state = "value"
    nodes = 0
    index = 0

    def register_value() -> bool:
        nonlocal nodes, root_state
        nodes += 1
        if nodes > MAX_JSON_NODES:
            return False
        if not stack:
            if root_state != "value":
                return True
            root_state = "done"
            return True
        frame = stack[-1]
        if frame[0] == "array" and frame[1] == "value_or_end":
            frame[1] = "comma_or_end"
        elif frame[0] == "object" and frame[1] == "value":
            frame[1] = "comma_or_end"
        else:
            return True
        frame[2] += 1
        return frame[2] <= MAX_JSON_CONTAINER_ITEMS

    def skip_string(start: int) -> int:
        cursor = start + 1
        while cursor < len(raw):
            byte = raw[cursor]
            if byte == 0x22:
                return cursor + 1
            if byte == 0x5C:
                cursor += 2
            else:
                cursor += 1
        return len(raw)

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
                        return True
                    index = skip_string(index)
                    frame[1] = "colon"
                    continue
                if frame[1] == "colon":
                    if byte != 0x3A:
                        return True
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
                    return True
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
                return True
        elif root_state == "done":
            return True

        byte = raw[index]
        if byte in (0x7B, 0x5B):
            if not register_value():
                return False
            if len(stack) + 1 > MAX_JSON_DEPTH:
                return False
            stack.append(
                ["object", "key_or_end", 0]
                if byte == 0x7B
                else ["array", "value_or_end", 0]
            )
            index += 1
            continue
        if byte == 0x22:
            if not register_value():
                return False
            index = skip_string(index)
            continue
        if byte in (0x2C, 0x3A, 0x5D, 0x7D):
            return True
        if not register_value():
            return False
        index += 1
        while index < len(raw) and raw[index] not in scalar_delimiters:
            index += 1
    return True


def _json_error_message(exc: Exception) -> str:
    if isinstance(exc, DuplicateJSONKeyError):
        return "duplicate JSON key is not allowed"
    if isinstance(exc, NonFiniteJSONNumberError):
        return "non-finite JSON number is not allowed"
    if isinstance(exc, UnicodeDecodeError):
        return "must be valid UTF-8"
    if isinstance(exc, json.JSONDecodeError):
        return "invalid JSON"
    if isinstance(exc, (RecursionError, MemoryError, ValueError)):
        return JSON_RESOURCE_ISSUE
    return "invalid JSON"


def _issues_full(issues: list[str]) -> bool:
    return isinstance(issues, _IssueCollector) and issues.full


def _json_within_resource_limits(value: Any) -> bool:
    try:
        nodes = 0
        stack: list[tuple[Any, int]] = [(value, 1)]
        while stack:
            current, depth = stack.pop()
            nodes += 1
            if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
                return False
            if isinstance(current, dict):
                if len(current) > MAX_JSON_CONTAINER_ITEMS:
                    return False
                stack.extend((child, depth + 1) for child in current.values())
            elif isinstance(current, list):
                if len(current) > MAX_JSON_CONTAINER_ITEMS:
                    return False
                stack.extend((child, depth + 1) for child in current)
        return True
    except (MemoryError, RecursionError):
        return False


def _read_fd_bounded(descriptor: int, byte_limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = byte_limit + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        remaining -= len(chunk)
    raise _ReadLimitExceeded


def _same_file_snapshot(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _path_identity_status(path: Path, opened_stat: os.stat_result) -> str | None:
    try:
        path_stat = os.lstat(path)
    except OSError:
        return "changed"
    if stat.S_ISLNK(path_stat.st_mode):
        return "symlink"
    if not stat.S_ISREG(path_stat.st_mode):
        return "changed"
    if (path_stat.st_dev, path_stat.st_ino) != (opened_stat.st_dev, opened_stat.st_ino):
        return "changed"
    return None


def _read_schema_bytes(path: Path) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 0
            or before.st_size > MAX_SCHEMA_BYTES
        ):
            raise ValueError
        if _path_identity_status(path, before) is not None:
            raise ValueError
        raw = _read_fd_bounded(descriptor, MAX_SCHEMA_BYTES)
        after = os.fstat(descriptor)
        if (
            len(raw) != before.st_size
            or not _same_file_snapshot(before, after)
            or _path_identity_status(path, after) is not None
        ):
            raise ValueError
        return raw
    finally:
        os.close(descriptor)


def _valid_json_date_time(value: Any) -> bool:
    if not isinstance(value, str):
        return True
    if not value.endswith("Z"):
        return False
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None


@lru_cache(maxsize=1)
def _load_schema_validators() -> dict[str, Any] | None:
    if _Draft202012Validator is None or _FormatChecker is None:
        return None
    try:
        session_schema = _parse_json_bytes(_read_schema_bytes(SESSION_SCHEMA_PATH))
        retained_manifest_schema = _parse_json_bytes(
            _read_schema_bytes(RETAINED_MANIFEST_SCHEMA_PATH)
        )
        if not isinstance(session_schema, dict) or not isinstance(
            retained_manifest_schema, dict
        ):
            return None

        _Draft202012Validator.check_schema(session_schema)
        _Draft202012Validator.check_schema(retained_manifest_schema)
        definitions = session_schema.get("$defs")
        if not isinstance(definitions, dict):
            return None
        targets = frozenset(SCHEMA_TARGETS.values())
        if not targets.issubset(definitions):
            return None

        draft_uri = session_schema.get("$schema")
        if (
            draft_uri != "https://json-schema.org/draft/2020-12/schema"
            or retained_manifest_schema.get("$schema") != draft_uri
        ):
            return None
        format_checker = _FormatChecker()
        format_checker.checks("date-time")(_valid_json_date_time)
        return {
            target: _Draft202012Validator(
                {
                    "$schema": draft_uri,
                    "$defs": definitions,
                    "$ref": f"#/$defs/{target}",
                },
                format_checker=format_checker,
            )
            for target in sorted(targets)
        }
    except Exception:
        return None


@lru_cache(maxsize=1)
def _load_privacy_validator() -> _PrivacyValidator | None:
    try:
        spec = importlib.util.spec_from_file_location(
            "_retrospective_history_privacy_v2_for_history",
            PRIVACY_VALIDATOR_PATH,
        )
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if hasattr(module, "RUN_ID_RE"):
            module.RUN_ID_RE = RUN_ID_RE
        if hasattr(module, "_valid_retained_path"):

            def valid_retained_path(relative: Path) -> bool:
                parsed = _parse_physical_artifact_path(relative)
                return parsed is not None and parsed.basename in ARTIFACT_BASENAME_SET

            module._valid_retained_path = valid_retained_path
        if hasattr(module, "TYPED_REF_DEFS") and hasattr(module, "_load_schema_policy"):
            module.TYPED_REF_DEFS = frozenset(module.TYPED_REF_DEFS) | {
                "campaign_leaf_root_ref",
                "campaign_page_root_ref",
                "campaign_ref",
                "quarantine_generation_ref",
            }
            (
                module._SCHEMA_POLICY_AVAILABLE,
                module._ALLOWED_JSON_KEYS,
                module._FIELD_LITERALS,
                module._FIELD_REF_DEFS,
                module._ALL_CLOSED_LITERALS,
            ) = module._load_schema_policy()
            module._PROSE_VOCABULARY = module._build_prose_vocabulary()
        if hasattr(module, "_allowed_json_string"):
            original_allowed_json_string = module._allowed_json_string

            def allowed_json_string(
                field: str | None, value: str, parent: Any
            ) -> tuple[bool, bool, bool]:
                allowed = original_allowed_json_string(field, value, parent)
                if allowed[0]:
                    return allowed
                if field == "run_id" and RUN_ID_RE.fullmatch(value):
                    return (True, True, False)
                if field == "run_ref" and RUN_REF_RE.fullmatch(value):
                    return (True, True, False)
                if (
                    field == "production_configuration_root_v2"
                    and PRODUCTION_CONFIGURATION_ROOT_RE.fullmatch(value)
                ):
                    return (True, True, False)
                if field == "campaign_segment_root_v2" and re.fullmatch(
                    r"campaign_segment_root_v2:sha256:[0-9a-f]{64}", value
                ):
                    return (True, True, False)
                return allowed

            module._allowed_json_string = allowed_json_string
        validator = getattr(module, "validate_v2_privacy", None)
        allowed_issues = frozenset(
            value
            for name, value in vars(module).items()
            if name.startswith("ISSUE_") and isinstance(value, str)
        )
        if not callable(validator) or not allowed_issues:
            return None
        return _PrivacyValidator(validator, allowed_issues)
    except Exception:
        return None


def _validate_schema_instance(
    instance: Any,
    target: str,
    label: str,
    validators: dict[str, Any],
    issues: list[str],
) -> None:
    if _issues_full(issues):
        return
    try:
        for index, error in enumerate(validators[target].iter_errors(instance)):
            if _issues_full(issues):
                break
            if index >= MAX_SCHEMA_ERRORS_PER_INSTANCE:
                issues.append(
                    f"{label}: schema target {target} has additional violations omitted"
                )
                break
            validator = error.validator
            keyword = (
                validator
                if isinstance(validator, str)
                and validator in SCHEMA_DIAGNOSTIC_KEYWORDS
                else "constraint"
            )
            issues.append(f"{label}: schema target {target} failed keyword {keyword}")
    except Exception:
        issues.append(SCHEMA_UNAVAILABLE_ISSUE)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _render_report_markdown(summary: dict[str, Any]) -> bytes | None:
    lines = ["# Session Retrospective"]
    for field_name, heading in REPORT_TEMPLATE_SECTIONS:
        templates = summary.get(field_name)
        if not isinstance(templates, list):
            return None
        rendered: list[str] = []
        for template in templates:
            rendered_text = validate_and_render_template(
                template,
                allowed_template_ids=TEMPLATE_IDS_BY_SECTION[field_name],
            )
            if rendered_text is None:
                return None
            rendered.append(f"- {rendered_text}")
        lines.extend(("", f"## {heading}"))
        lines.extend(rendered or ["- No observation was retained."])

    confidence = summary.get("confidence")
    if not isinstance(confidence, dict):
        return None
    lines.extend(("", "## Confidence"))
    for field_name, label in REPORT_CONFIDENCE_ORDER:
        dimension = confidence.get(field_name)
        if not isinstance(dimension, dict):
            return None
        level = dimension.get("level")
        basis = dimension.get("basis")
        if not isinstance(level, str) or not isinstance(basis, str):
            return None
        lines.append(
            f"- {label}: {level.replace('_', ' ')} ({basis.replace('_', ' ')})."
        )

    change = summary.get("change_from_prior")
    if not isinstance(change, dict) or not isinstance(change.get("status"), str):
        return None
    status = change["status"]
    if status == "available" and isinstance(change.get("direction"), str):
        change_line = f"- Available ({change['direction'].replace('_', ' ')})."
    elif status == "unavailable" and isinstance(change.get("reason"), str):
        change_line = f"- Unavailable ({change['reason'].replace('_', ' ')})."
    else:
        return None
    lines.extend(("", "## Change From Prior Compatible Period", change_line))
    return ("\n".join(lines) + "\n").encode("utf-8")


def _update_typed_frame(hasher: Any, frame_type: bytes, value: bytes) -> None:
    # One-byte type discriminator, unsigned 64-bit big-endian length, then bytes.
    hasher.update(frame_type)
    hasher.update(len(value).to_bytes(8, byteorder="big", signed=False))
    hasher.update(value)


def _compute_production_configuration_root(provenance: Any) -> str:
    if not isinstance(provenance, dict):
        raise TypeError("provenance must be an object")
    hasher = hashlib.sha256()
    hasher.update(PRODUCTION_CONFIGURATION_DOMAIN_TAG)
    for field_name in PRODUCTION_CONFIGURATION_FIELDS:
        value = provenance.get(field_name)
        if not isinstance(value, str):
            raise TypeError(f"{field_name} must be a string")
        _update_typed_frame(hasher, b"N", field_name.encode("ascii"))
        _update_typed_frame(hasher, b"V", value.encode("ascii"))
    return f"production_configuration_root_v2:sha256:{hasher.hexdigest()}"


def _compute_campaign_segment_root(
    campaign_ref: str,
    segment_count: int,
    segments: Iterable[tuple[int, str, str]],
) -> str:
    if not isinstance(campaign_ref, str) or not _is_int(segment_count):
        raise TypeError("campaign root inputs are invalid")
    ordered = sorted(segments, key=lambda item: item[0])
    if len(ordered) != segment_count:
        raise ValueError("campaign segment cardinality is invalid")
    hasher = hashlib.sha256()
    hasher.update(CAMPAIGN_SEGMENT_DOMAIN_TAG)
    _update_typed_frame(hasher, b"C", campaign_ref.encode("ascii"))
    _update_typed_frame(hasher, b"N", segment_count.to_bytes(8, "big"))
    for expected_ordinal, (ordinal, run_ref, bundle_digest) in enumerate(
        ordered, start=1
    ):
        if (
            ordinal != expected_ordinal
            or not isinstance(run_ref, str)
            or not isinstance(bundle_digest, str)
        ):
            raise ValueError("campaign segment coordinates are invalid")
        _update_typed_frame(hasher, b"O", ordinal.to_bytes(8, "big"))
        _update_typed_frame(hasher, b"R", run_ref.encode("ascii"))
        _update_typed_frame(hasher, b"D", bundle_digest.encode("ascii"))
    return f"campaign_segment_root_v2:sha256:{hasher.hexdigest()}"


def _window_route_components(mode: bytes, window: bytes) -> tuple[str, ...]:
    hasher = hashlib.sha256()
    hasher.update(WINDOW_ROUTE_DOMAIN)
    _update_typed_frame(hasher, b"M", mode)
    _update_typed_frame(hasher, b"W", window)
    digest = hasher.hexdigest()
    return tuple(digest[offset : offset + 2] for offset in range(0, 64, 2))


def _compute_retained_bundle_digest(
    raw: dict[str, bytes], manifest: dict[str, Any]
) -> str:
    projection = dict(manifest)
    projection.pop("retained_bundle_digest_v2")
    manifest_projection = _canonical_json(projection)

    hasher = hashlib.sha256()
    hasher.update(BUNDLE_DOMAIN_TAG)
    for basename in ARTIFACT_BASENAMES:
        name_bytes = basename.encode("ascii")
        content = manifest_projection if basename == "manifest.json" else raw[basename]
        _update_typed_frame(hasher, b"N", name_bytes)
        _update_typed_frame(hasher, b"B", content)
    return f"retained_bundle_digest_v2:sha256:{hasher.hexdigest()}"


def _valid_window_component(value: str) -> bool:
    if WINDOW_COMPONENT_RE.fullmatch(value) is None:
        return False
    components = value.split("_to_")
    try:
        dates = [dt.date.fromisoformat(component) for component in components]
    except ValueError:
        return False
    return len(dates) == 1 or dates[0] < dates[1]


def _bundle_directory_parts(
    mode: str, window_component: str, run_id: str
) -> tuple[str, ...]:
    return (
        "runs",
        mode,
        *_window_route_components(
            mode.encode("ascii"), window_component.encode("ascii")
        ),
        window_component,
        *(run_id[offset : offset + 2] for offset in range(0, 64, 2)),
    )


def _parse_physical_artifact_path(relative: Path) -> _PhysicalArtifactPath | None:
    if relative.is_absolute():
        return None
    parts = relative.parts
    if len(parts) != RUN_ARTIFACT_PATH_COMPONENT_COUNT or parts[0] != "runs":
        return None
    try:
        encoded_path = relative.as_posix().encode("ascii")
    except UnicodeEncodeError:
        return None
    if len(encoded_path) > MAX_DISCOVERY_PATH_BYTES or any(
        part in {"", ".", ".."}
        or "\\" in part
        or any(ord(character) < 32 or ord(character) == 127 for character in part)
        for part in parts
    ):
        return None

    mode = parts[1]
    window_route = tuple(parts[2 : 2 + WINDOW_ROUTE_COMPONENT_COUNT])
    window_index = 2 + WINDOW_ROUTE_COMPONENT_COUNT
    window_component = parts[window_index]
    run_route_start = window_index + 1
    run_route = tuple(
        parts[run_route_start : run_route_start + RUN_ROUTE_COMPONENT_COUNT]
    )
    basename = parts[-1]
    if mode not in MODES or not _valid_window_component(window_component):
        return None
    if any(
        ROUTE_COMPONENT_RE.fullmatch(component) is None
        for component in (*window_route, *run_route)
    ):
        return None
    if window_route != _window_route_components(
        mode.encode("ascii"), window_component.encode("ascii")
    ):
        return None
    run_id = "".join(run_route)
    if RUN_ID_RE.fullmatch(run_id) is None:
        return None
    return _PhysicalArtifactPath(
        relative=relative,
        mode=mode,
        window_route=window_route,
        window_component=window_component,
        run_route=run_route,
        run_id=run_id,
        basename=basename,
    )


def _parse_coarse_timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:00Z").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError:
        return None


def _expected_window_component(start: dt.datetime, end: dt.datetime) -> str | None:
    if start >= end:
        return None
    first = start.date()
    last = (end - dt.timedelta(microseconds=1)).date()
    if first == last:
        return first.isoformat()
    return f"{first.isoformat()}_to_{last.isoformat()}"


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_non_negative_int(value: Any) -> bool:
    return _is_int(value) and value >= 0


def _valid_schema_version(value: Any) -> bool:
    return _is_int(value) and value == 2


def _is_sorted_unique_strings(value: Any) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(item, str) for item in value)
        and value == sorted(value)
        and len(value) == len(set(value))
    )


def _validate_reference_collections(value: Any, label: str, issues: list[str]) -> None:
    has_duplicate = False
    has_unstable_order = False

    def visit(current: Any) -> None:
        nonlocal has_duplicate, has_unstable_order
        if _issues_full(issues):
            return
        if isinstance(current, dict):
            for key in sorted(current):
                child = current[key]
                if (
                    key in UNIQUE_REFERENCE_FIELDS
                    and isinstance(child, list)
                    and all(isinstance(item, str) for item in child)
                ):
                    if len(child) != len(set(child)):
                        has_duplicate = True
                    if key in SORTED_REFERENCE_FIELDS and child != sorted(child):
                        has_unstable_order = True
                visit(child)
        elif isinstance(current, list):
            for child in current:
                visit(child)

    visit(value)
    if has_duplicate:
        issues.append(
            f"{label}: stable reference collections must contain unique items"
        )
    if has_unstable_order:
        issues.append(f"{label}: stable reference collections must use bytewise order")


def _validate_stable_object_collection(
    value: Any,
    field_name: str,
    key_fields: tuple[str, ...],
    label: str,
    issues: list[str],
) -> None:
    if not isinstance(value, dict) or field_name not in value:
        return
    rows = value[field_name]
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        issues.append(f"{label}: {field_name} must be an array of objects")
        return
    identities = [_canonical_json(row) for row in rows]
    if len(identities) != len(set(identities)):
        issues.append(f"{label}: {field_name} must contain unique objects")
    keys = [tuple(str(row.get(field, "")) for field in key_fields) for row in rows]
    if len(keys) != len(set(keys)):
        issues.append(f"{label}: {field_name} must contain unique reference keys")
    if keys != sorted(keys):
        issues.append(f"{label}: {field_name} must use stable bytewise reference order")


def _validate_manifest_eras(
    manifest: dict[str, Any], label: str, issues: list[str]
) -> None:
    eras = manifest.get("eras")
    if not isinstance(eras, dict):
        issues.append(f"{label}: eras must be an object")
        return
    definitions = (
        ("policy_eras", "policy_era_ref", POLICY_ERA_REF_RE),
        ("model_eras", "model_era_ref", MODEL_ERA_REF_RE),
    )
    for field_name, ref_field, pattern in definitions:
        rows = eras.get(field_name)
        if (
            not isinstance(rows, list)
            or not rows
            or not all(isinstance(row, dict) for row in rows)
        ):
            issues.append(f"{label}: {field_name} must be a non-empty array of objects")
            continue
        refs = [row.get(ref_field) for row in rows]
        if not all(
            isinstance(ref, str) and pattern.fullmatch(ref) is not None for ref in refs
        ):
            issues.append(f"{label}: {field_name} contains an invalid era reference")
            continue
        if refs != sorted(refs) or len(refs) != len(set(refs)):
            issues.append(
                f"{label}: {field_name} must use bytewise-sorted unique references"
            )


def _valid_physical_path_prefix(parts: tuple[str, ...]) -> bool:
    if (
        not parts
        or parts[0] != "runs"
        or len(parts) > RUN_ARTIFACT_PATH_COMPONENT_COUNT - 1
    ):
        return False
    if len(parts) >= 2 and parts[1] not in MODES:
        return False
    window_route_end = 2 + WINDOW_ROUTE_COMPONENT_COUNT
    if any(
        ROUTE_COMPONENT_RE.fullmatch(component) is None
        for component in parts[2 : min(len(parts), window_route_end)]
    ):
        return False
    if len(parts) > window_route_end:
        mode = parts[1]
        window_component = parts[window_route_end]
        if not _valid_window_component(window_component):
            return False
        if tuple(parts[2:window_route_end]) != _window_route_components(
            mode.encode("ascii"), window_component.encode("ascii")
        ):
            return False
    run_route_start = window_route_end + 1
    if any(
        ROUTE_COMPONENT_RE.fullmatch(component) is None
        for component in parts[run_route_start:]
    ):
        return False
    return True


def _scan_run_files_no_follow(root_descriptor: int, issues: list[str]) -> list[Path]:
    flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        runs_descriptor = os.open("runs", flags, dir_fd=root_descriptor)
    except FileNotFoundError:
        return []
    except OSError:
        issues.append("runs/[invalid]: invalid v2 retained-run path")
        return []

    by_relative: dict[str, Path] = {}
    entry_count = 1
    file_count = 0
    invalid_layout = False
    stopped = False

    def walk(directory_descriptor: int, parent_parts: tuple[str, ...]) -> None:
        nonlocal entry_count, file_count, invalid_layout, stopped
        if stopped or _issues_full(issues):
            return
        try:
            iterator = os.scandir(directory_descriptor)
        except OSError:
            invalid_layout = True
            return
        with iterator:
            for entry in iterator:
                if stopped or _issues_full(issues):
                    break
                entry_count += 1
                if entry_count > MAX_DISCOVERY_ENTRIES:
                    issues.append(DISCOVERY_LIMIT_ISSUE)
                    stopped = True
                    break
                name = entry.name
                if not isinstance(name, str):
                    try:
                        name = os.fsdecode(name)
                    except Exception:
                        invalid_layout = True
                        continue
                child_parts = (*parent_parts, name)
                try:
                    relative = Path(*child_parts)
                    encoded_path = relative.as_posix().encode("ascii")
                    child_stat = entry.stat(follow_symlinks=False)
                except (OSError, UnicodeEncodeError):
                    invalid_layout = True
                    continue
                if len(encoded_path) > MAX_DISCOVERY_PATH_BYTES:
                    invalid_layout = True
                    continue

                if stat.S_ISREG(child_stat.st_mode) or stat.S_ISLNK(child_stat.st_mode):
                    if len(child_parts) != RUN_ARTIFACT_PATH_COMPONENT_COUNT:
                        invalid_layout = True
                        continue
                    file_count += 1
                    if file_count > MAX_DISCOVERY_FILES:
                        issues.append(DISCOVERY_LIMIT_ISSUE)
                        stopped = True
                        break
                    by_relative.setdefault(relative.as_posix(), relative)
                    continue

                if not stat.S_ISDIR(
                    child_stat.st_mode
                ) or not _valid_physical_path_prefix(child_parts):
                    invalid_layout = True
                    continue
                try:
                    child_descriptor = os.open(name, flags, dir_fd=directory_descriptor)
                    if not stat.S_ISDIR(os.fstat(child_descriptor).st_mode):
                        raise OSError(
                            errno.ENOTDIR, "discovered child is not a directory"
                        )
                except OSError:
                    invalid_layout = True
                    continue
                try:
                    walk(child_descriptor, child_parts)
                finally:
                    os.close(child_descriptor)

    try:
        walk(runs_descriptor, ("runs",))
    finally:
        os.close(runs_descriptor)
    if invalid_layout:
        issues.append("runs/[invalid]: invalid v2 retained-run path")
    if stopped:
        return []
    return [by_relative[key] for key in sorted(by_relative)]


def _visible_run_files(
    root: Path,
    root_descriptor: int,
    visible_files: Sequence[Path] | None,
    issues: list[str],
) -> list[Path]:
    if visible_files is None:
        return _scan_run_files_no_follow(root_descriptor, issues)

    by_relative: dict[str, Path] = {}
    outside_root = False
    for entry_count, supplied in enumerate(visible_files, start=1):
        if _issues_full(issues):
            break
        if entry_count > MAX_DISCOVERY_ENTRIES:
            issues.append(DISCOVERY_LIMIT_ISSUE)
            return []
        try:
            candidate = supplied if supplied.is_absolute() else root / supplied
            absolute = Path(os.path.abspath(candidate))
            relative = absolute.relative_to(root)
        except (OSError, TypeError, ValueError):
            outside_root = True
            continue
        if not relative.parts or relative.parts[0] != "runs":
            continue
        key = relative.as_posix()
        if key in by_relative:
            continue
        if len(by_relative) >= MAX_DISCOVERY_FILES:
            issues.append(DISCOVERY_LIMIT_ISSUE)
            return []
        by_relative[key] = relative
    if outside_root:
        issues.append("visible file list contains a path outside the validation root")
    return [by_relative[key] for key in sorted(by_relative)]


def _discover_bundles(
    root: Path,
    root_descriptor: int,
    visible_files: Sequence[Path] | None,
    issues: list[str],
) -> list[Bundle]:
    grouped: dict[tuple[str, str, str], dict[str, Path]] = defaultdict(dict)
    physical_parts: dict[tuple[str, str, str], tuple[str, ...]] = {}
    route_owners: dict[str, tuple[str, str, tuple[str, str, str]]] = {}
    run_owners: dict[str, tuple[str, str, str]] = {}
    invalid_layout = False
    collision = False
    for relative in _visible_run_files(root, root_descriptor, visible_files, issues):
        if _issues_full(issues):
            break
        parsed = _parse_physical_artifact_path(relative)
        if parsed is None:
            invalid_layout = True
            continue
        key = (parsed.mode, parsed.window_component, parsed.run_id)
        route_digest = "".join(parsed.window_route)
        route_owner = route_owners.setdefault(
            route_digest,
            (parsed.mode, parsed.window_component, key),
        )
        if route_owner[:2] != (parsed.mode, parsed.window_component):
            collision = True
        run_owner = run_owners.setdefault(parsed.run_id, key)
        if run_owner != key:
            collision = True
        if key not in grouped and len(grouped) >= MAX_BUNDLES:
            issues.append(DISCOVERY_LIMIT_ISSUE)
            return []
        grouped[key][parsed.basename] = relative
        physical_parts[key] = parsed.directory_parts

    if invalid_layout:
        issues.append("runs/[invalid]: invalid v2 retained-run path")
    if collision:
        issues.append(PATH_COLLISION_ISSUE)
        return []
    if DISCOVERY_LIMIT_ISSUE in issues:
        return []

    bundles: list[Bundle] = []
    for (mode, window_component, run_id), files in sorted(grouped.items()):
        if _issues_full(issues):
            break
        parts = physical_parts[(mode, window_component, run_id)]
        label = "/".join(parts)
        if frozenset(files) != ARTIFACT_BASENAME_SET:
            issues.append(
                f"{label}: run directory must contain exactly the eight required artifacts"
            )
        bundles.append(
            Bundle(
                label,
                mode,
                window_component,
                run_id,
                files,
                physical_parts=parts,
            )
        )
    return bundles


def _close_opened_artifacts(opened: dict[str, _OpenedArtifact]) -> None:
    for artifact in opened.values():
        try:
            os.close(artifact.descriptor)
        except OSError:
            pass
    opened.clear()


def _open_validation_root(root: Path) -> int:
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise OSError(errno.ENOTSUP, "safe directory traversal is unavailable")
    flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(root, flags)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError(errno.ENOTDIR, "validation root is not a directory")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _directory_identity(value: os.stat_result) -> tuple[int, int]:
    return (value.st_dev, value.st_ino)


def _close_directory_chain(chain: _OpenedDirectoryChain | None) -> None:
    if chain is None:
        return
    for descriptor in reversed(chain.descriptors):
        try:
            os.close(descriptor)
        except OSError:
            pass


def _open_bundle_directory(
    root_descriptor: int, bundle: Bundle
) -> _OpenedDirectoryChain:
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise OSError(errno.ENOTSUP, "safe directory traversal is unavailable")
    flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_NONBLOCK", 0)
    )
    expected_parts = _bundle_directory_parts(
        bundle.mode,
        bundle.window_component,
        bundle.run_id,
    )
    physical_parts = bundle.physical_parts or expected_parts
    if physical_parts != expected_parts:
        raise OSError(
            errno.EINVAL, "bundle path does not match its normalized identity"
        )
    descriptors = [os.dup(root_descriptor)]
    identities: list[tuple[int, int]] = []
    try:
        root_stat = os.fstat(descriptors[0])
        if not stat.S_ISDIR(root_stat.st_mode):
            raise OSError(errno.ENOTDIR, "validation root is not a directory")
        identities.append(_directory_identity(root_stat))
        for component in physical_parts:
            descriptor = os.open(component, flags, dir_fd=descriptors[-1])
            descriptors.append(descriptor)
            opened_stat = os.fstat(descriptor)
            if not stat.S_ISDIR(opened_stat.st_mode):
                raise OSError(errno.ENOTDIR, "bundle component is not a directory")
            identities.append(_directory_identity(opened_stat))
        return _OpenedDirectoryChain(tuple(descriptors), tuple(identities))
    except Exception:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _bundle_directory_chain_matches(
    root_descriptor: int, bundle: Bundle, opened: _OpenedDirectoryChain
) -> bool:
    flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_NONBLOCK", 0)
    )
    physical_parts = bundle.physical_parts or _bundle_directory_parts(
        bundle.mode, bundle.window_component, bundle.run_id
    )
    if len(opened.identities) != len(physical_parts) + 1:
        return False
    try:
        for descriptor, expected in zip(
            opened.descriptors, opened.identities, strict=True
        ):
            if _directory_identity(os.fstat(descriptor)) != expected:
                return False
    except OSError:
        return False

    descriptor = os.dup(root_descriptor)
    try:
        root_stat = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(root_stat.st_mode)
            or _directory_identity(root_stat) != opened.identities[0]
        ):
            return False
        for component, expected in zip(
            physical_parts, opened.identities[1:], strict=True
        ):
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            reopened_stat = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(reopened_stat.st_mode)
                or _directory_identity(reopened_stat) != expected
            ):
                return False
        return True
    except OSError:
        return False
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _named_artifact_identity_status(
    directory_descriptor: int,
    basename: str,
    opened_stat: os.stat_result,
) -> str | None:
    try:
        named_stat = os.stat(
            basename, dir_fd=directory_descriptor, follow_symlinks=False
        )
    except OSError:
        return "changed"
    if stat.S_ISLNK(named_stat.st_mode):
        return "symlink"
    if not stat.S_ISREG(named_stat.st_mode):
        return "changed"
    if (named_stat.st_dev, named_stat.st_ino) != (
        opened_stat.st_dev,
        opened_stat.st_ino,
    ):
        return "changed"
    return None


def _read_bundle_artifacts(
    bundle: Bundle,
    root_descriptor: int,
    issues: list[str],
    budget: _ReadBudget,
) -> bool:
    if budget.remaining <= 0:
        issues.append(f"{bundle.label}: retained bundle exceeds the total byte limit")
        return False

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_NOFOLLOW
        | getattr(os, "O_NONBLOCK", 0)
    )
    opened: dict[str, _OpenedArtifact] = {}
    preflight_failed = False
    directory_chain: _OpenedDirectoryChain | None = None
    try:
        directory_chain = _open_bundle_directory(root_descriptor, bundle)
    except Exception:
        issues.append(f"{bundle.label}: run directory could not be opened safely")
        return False
    directory_descriptor = directory_chain.leaf_descriptor

    try:
        for basename in ARTIFACT_BASENAMES:
            if _issues_full(issues):
                preflight_failed = True
                break
            if basename not in bundle.files:
                preflight_failed = True
                continue
            label = f"{bundle.label}/{basename}"
            descriptor = -1
            try:
                descriptor = os.open(basename, flags, dir_fd=directory_descriptor)
                opened_stat = os.fstat(descriptor)
            except OSError as exc:
                if descriptor >= 0:
                    os.close(descriptor)
                if exc.errno == errno.ELOOP:
                    issues.append(f"{label}: symlink artifact is not allowed")
                else:
                    issues.append(f"{label}: artifact could not be opened safely")
                preflight_failed = True
                continue

            identity_status = _named_artifact_identity_status(
                directory_descriptor, basename, opened_stat
            )
            if identity_status == "symlink":
                issues.append(f"{label}: symlink artifact is not allowed")
                os.close(descriptor)
                preflight_failed = True
                continue
            if identity_status is not None:
                issues.append(f"{label}: artifact path changed during open")
                os.close(descriptor)
                preflight_failed = True
                continue
            if not stat.S_ISREG(opened_stat.st_mode):
                issues.append(f"{label}: artifact must be a regular file")
                os.close(descriptor)
                preflight_failed = True
                continue

            byte_limit = MAX_ARTIFACT_BYTES[basename]
            if opened_stat.st_size < 0 or opened_stat.st_size > byte_limit:
                issues.append(f"{label}: artifact exceeds its byte limit")
                os.close(descriptor)
                preflight_failed = True
                continue
            opened[basename] = _OpenedArtifact(
                basename=basename,
                descriptor=descriptor,
                initial_stat=opened_stat,
                byte_limit=byte_limit,
            )

        if preflight_failed:
            return False

        declared_bytes = sum(
            artifact.initial_stat.st_size for artifact in opened.values()
        )
        if declared_bytes > budget.remaining:
            issues.append(
                f"{bundle.label}: retained bundle exceeds the total byte limit"
            )
            budget.remaining = 0
            return False

        raw: dict[str, bytes] = {}
        for basename in ARTIFACT_BASENAMES:
            artifact = opened.pop(basename)
            read_limit = min(artifact.byte_limit, budget.remaining)
            content: bytes | None = None
            after: os.stat_result | None = None
            try:
                content = _read_fd_bounded(artifact.descriptor, read_limit)
                after = os.fstat(artifact.descriptor)
            except _ReadLimitExceeded:
                if read_limit < artifact.byte_limit:
                    issues.append(
                        f"{bundle.label}: retained bundle exceeds the total byte limit"
                    )
                else:
                    issues.append(
                        f"{bundle.label}/{basename}: artifact exceeds its byte limit"
                    )
                budget.remaining = 0
            except OSError:
                issues.append(
                    f"{bundle.label}/{basename}: artifact could not be read safely"
                )
                budget.remaining = 0
            finally:
                try:
                    os.close(artifact.descriptor)
                except OSError:
                    pass

            if content is None or after is None:
                return False

            budget.remaining -= len(content)
            if (
                len(content) != artifact.initial_stat.st_size
                or not _same_file_snapshot(artifact.initial_stat, after)
                or _named_artifact_identity_status(
                    directory_descriptor, basename, after
                )
                is not None
            ):
                issues.append(
                    f"{bundle.label}/{basename}: artifact changed while being read"
                )
                return False
            raw[basename] = content

        if not _bundle_directory_chain_matches(root_descriptor, bundle, directory_chain):
            issues.append(
                f"{bundle.label}: run directory identity changed while artifacts were read"
            )
            return False
        bundle.raw = raw
        return True
    finally:
        _close_opened_artifacts(opened)
        _close_directory_chain(directory_chain)


def _scan_bundle_privacy(
    bundle: Bundle,
    privacy_validator: _PrivacyValidator,
    issues: list[str],
) -> None:
    for basename in ARTIFACT_BASENAMES:
        if _issues_full(issues):
            break
        raw = bundle.raw.get(basename)
        if raw is None:
            continue
        relative = Path(bundle.label) / basename
        try:
            findings = privacy_validator.validate(relative, raw)
        except Exception:
            issues.append(PRIVACY_UNAVAILABLE_ISSUE)
            continue
        if not isinstance(findings, list) or any(
            not isinstance(finding, str)
            or finding not in privacy_validator.allowed_issues
            for finding in findings
        ):
            issues.append(PRIVACY_UNAVAILABLE_ISSUE)
            continue
        prefix = relative.as_posix()
        for finding in findings:
            if _issues_full(issues):
                break
            issues.append(f"{prefix}: {finding}")


def _read_bundle(
    bundle: Bundle,
    root_descriptor: int,
    issues: list[str],
    validators: dict[str, Any],
    privacy_validator: _PrivacyValidator,
    budget: _ReadBudget,
) -> None:
    if not _read_bundle_artifacts(bundle, root_descriptor, issues, budget):
        return
    _scan_bundle_privacy(bundle, privacy_validator, issues)
    if _issues_full(issues):
        return

    for basename in ARTIFACT_BASENAMES:
        if basename not in bundle.raw:
            return

    for basename in sorted(JSON_ARTIFACTS):
        if _issues_full(issues):
            return
        raw = bundle.raw.get(basename)
        if raw is None:
            continue
        label = f"{bundle.label}/{basename}"
        if not _json_bytes_within_preparse_limits(raw):
            issues.append(f"{label}: {JSON_RESOURCE_ISSUE}")
            continue
        try:
            value = _parse_json_bytes(raw)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            DuplicateJSONKeyError,
            NonFiniteJSONNumberError,
            RecursionError,
            MemoryError,
            ValueError,
        ) as exc:
            issues.append(f"{label}: {_json_error_message(exc)}")
            continue
        if not _json_within_resource_limits(value):
            issues.append(f"{label}: {JSON_RESOURCE_ISSUE}")
            continue
        try:
            canonical = _canonical_json(value)
        except (MemoryError, RecursionError, TypeError, ValueError, OverflowError):
            issues.append(f"{label}: {JSON_RESOURCE_ISSUE}")
            continue
        if raw != canonical:
            issues.append(f"{label}: JSON must use exact canonical bytes")
        bundle.documents[basename] = value
        _validate_schema_instance(
            value, SCHEMA_TARGETS[basename], label, validators, issues
        )

    bundle_row_count = 0
    for basename in sorted(JSONL_ARTIFACTS):
        if _issues_full(issues):
            return
        raw = bundle.raw.get(basename)
        if raw is None:
            continue
        label = f"{bundle.label}/{basename}"
        if b"\r" in raw:
            issues.append(f"{label}: JSONL must use LF line endings")
        if raw and not raw.endswith(b"\n"):
            issues.append(f"{label}: JSONL must end with LF")
        line_count = raw.count(b"\n") + (1 if raw and not raw.endswith(b"\n") else 0)
        bundle_row_count += line_count
        if bundle_row_count > MAX_BUNDLE_JSONL_ROWS:
            issues.append(f"{bundle.label}: JSONL row count exceeds the bundle limit")
            return
        if line_count > MAX_JSONL_ROWS:
            issues.append(f"{label}: JSONL row count exceeds the limit")
            continue
        rows: list[tuple[int, Any]] = []
        lines = [] if not raw else raw.split(b"\n")
        if raw.endswith(b"\n"):
            lines.pop()
        for line_no, line in enumerate(lines, 1):
            if _issues_full(issues):
                return
            if not line.strip():
                issues.append(f"{label}:{line_no}: blank JSONL line is not allowed")
                continue
            if not _json_bytes_within_preparse_limits(line):
                issues.append(f"{label}:{line_no}: {JSON_RESOURCE_ISSUE}")
                continue
            try:
                row = _parse_json_bytes(line)
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                DuplicateJSONKeyError,
                NonFiniteJSONNumberError,
                RecursionError,
                MemoryError,
                ValueError,
            ) as exc:
                issues.append(f"{label}:{line_no}: {_json_error_message(exc)}")
                continue
            if not _json_within_resource_limits(row):
                issues.append(f"{label}:{line_no}: {JSON_RESOURCE_ISSUE}")
                continue
            try:
                canonical = _canonical_json(row)
            except (MemoryError, RecursionError, TypeError, ValueError, OverflowError):
                issues.append(f"{label}:{line_no}: {JSON_RESOURCE_ISSUE}")
                continue
            if line != canonical:
                issues.append(
                    f"{label}:{line_no}: JSONL row must use exact canonical bytes"
                )
            rows.append((line_no, row))
            _validate_schema_instance(
                row,
                SCHEMA_TARGETS[basename],
                f"{label}:{line_no}",
                validators,
                issues,
            )
        bundle.rows[basename] = rows

    report = bundle.raw.get("report.md")
    if report is not None and not _issues_full(issues):
        try:
            report_text = report.decode("utf-8")
        except UnicodeDecodeError:
            issues.append(f"{bundle.label}/report.md: must be valid UTF-8")
        else:
            _validate_schema_instance(
                report_text,
                SCHEMA_TARGETS["report.md"],
                f"{bundle.label}/report.md",
                validators,
                issues,
            )


def _validate_reference_array(
    value: Any,
    pattern: re.Pattern[str],
    label: str,
    issues: list[str],
) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and pattern.fullmatch(item) is not None for item in value
    ):
        issues.append(f"{label}: revision reference collection is invalid")
        return ()
    return tuple(value)


def _validate_revision_record(
    record: Any,
    spec: RevisionSpec,
    bundle: Bundle,
    label: str,
    issues: list[str],
) -> RevisionNode | None:
    if not isinstance(record, dict):
        return None
    current = record.get(spec.current_field)
    predecessor = record.get(spec.predecessor_field)
    supersedes = _validate_reference_array(
        record.get(spec.supersedes_field), spec.current_pattern, label, issues
    )
    kind = record.get("revision_kind")

    valid_current = (
        isinstance(current, str) and spec.current_pattern.fullmatch(current) is not None
    )
    if not valid_current:
        issues.append(f"{label}: current revision reference is invalid")
    if predecessor is not None and not (
        isinstance(predecessor, str)
        and spec.current_pattern.fullmatch(predecessor) is not None
    ):
        issues.append(f"{label}: predecessor revision reference is invalid")
        predecessor = None
    if not isinstance(kind, str) or kind not in REVISION_KINDS:
        issues.append(f"{label}: revision_kind is invalid")
        kind = "invalid"

    predecessors = tuple(
        ([predecessor] if isinstance(predecessor, str) else []) + list(supersedes)
    )
    if len(predecessors) != len(set(predecessors)):
        issues.append(
            f"{label}: predecessor revision may be closed only once per record"
        )
    if valid_current and current in predecessors:
        issues.append(f"{label}: revision cannot supersede itself")
    if kind == "initial":
        if predecessor is not None or supersedes:
            issues.append(f"{label}: initial revision must not name a predecessor")
    elif kind != "invalid" and not predecessors:
        issues.append(f"{label}: non-initial revision must name a predecessor")

    entity_ref = (
        record.get(spec.entity_field) if spec.entity_field is not None else None
    )
    if spec.entity_field is not None and not isinstance(entity_ref, str):
        issues.append(f"{label}: entity reference is invalid")
        entity_ref = None
    if not valid_current:
        return None
    return RevisionNode(
        family=spec.family,
        current=current,
        predecessors=tuple(dict.fromkeys(predecessors)),
        kind=kind,
        entity_ref=entity_ref,
        transaction_ref=bundle.transaction_ref,
        label=label,
    )


def _validate_manifest(bundle: Bundle, issues: list[str]) -> None:
    label = f"{bundle.label}/manifest.json"
    value = bundle.documents.get("manifest.json")
    if not isinstance(value, dict):
        if value is not None:
            issues.append(f"{label}: manifest must be an object")
        return
    bundle.manifest = value
    fields = frozenset(value)
    if not MANIFEST_REQUIRED_KEYS.issubset(fields) or not fields.issubset(
        MANIFEST_KEYS
    ):
        issues.append(f"{label}: manifest fields do not match the v2 contract")
    if value.get("artifact_type") != "manifest":
        issues.append(f"{label}: artifact_type must be manifest")
    if not _valid_schema_version(value.get("schema_version")):
        issues.append(f"{label}: schema_version must be 2")
    execution_kind = value.get("execution_kind")
    if not isinstance(execution_kind, str) or execution_kind not in EXECUTION_KINDS:
        issues.append(f"{label}: execution_kind is invalid")
    publication_role = value.get("publication_role")
    if (
        not isinstance(publication_role, str)
        or publication_role not in PUBLICATION_ROLES
    ):
        issues.append(f"{label}: publication_role is invalid")
    campaign_only_fields = frozenset(
        {
            "publication_campaign_reason",
            "campaign_ref",
            "campaign_segment_count",
            "campaign_segment_metadata",
            "campaign_segment_root_v2",
        }
    )
    if publication_role == "standalone":
        if campaign_only_fields.intersection(value):
            issues.append(
                f"{label}: standalone publication must not contain campaign fields"
            )
    elif publication_role in {"campaign_segment", "campaign_root"}:
        required_campaign_fields = {
            "publication_campaign_reason",
            "campaign_ref",
            "campaign_segment_count",
        }
        if publication_role == "campaign_segment":
            required_campaign_fields.add("campaign_segment_metadata")
            forbidden_campaign_field = "campaign_segment_root_v2"
            if execution_kind != "retrospective":
                issues.append(
                    f"{label}: campaign segment execution_kind must be retrospective"
                )
        else:
            required_campaign_fields.add("campaign_segment_root_v2")
            forbidden_campaign_field = "campaign_segment_metadata"
        if (
            not required_campaign_fields.issubset(value)
            or forbidden_campaign_field in value
        ):
            issues.append(f"{label}: campaign fields do not match publication_role")
        campaign_reason = value.get("publication_campaign_reason")
        manifest_mode = value.get("mode")
        expected_reason = None
        if manifest_mode == "baseline":
            expected_reason = "baseline_window"
        elif isinstance(manifest_mode, str) and manifest_mode in MODES:
            expected_reason = "size_partition"
        if (
            not isinstance(campaign_reason, str)
            or campaign_reason not in PUBLICATION_CAMPAIGN_REASONS
            or (expected_reason is not None and campaign_reason != expected_reason)
        ):
            issues.append(f"{label}: publication campaign reason does not match mode")
    if value.get("mode") != bundle.mode:
        issues.append(f"{label}: mode must match the run path")
    logical_run_id = value.get("run_id")
    if logical_run_id != bundle.run_id:
        issues.append(f"{label}: run_id must match the run path")

    window = value.get("window")
    if not isinstance(window, dict):
        issues.append(f"{label}: window must be an object")
    else:
        if window.get("mode") != bundle.mode:
            issues.append(f"{label}: window.mode must match the run path")
        if window.get("path_component") != bundle.window_component:
            issues.append(f"{label}: window.path_component must match the run path")
        start = _parse_coarse_timestamp(window.get("start"))
        end = _parse_coarse_timestamp(window.get("end"))
        if start is not None and end is not None:
            expected_component = _expected_window_component(start, end)
            if expected_component is None:
                issues.append(f"{label}: window.start must be earlier than window.end")
            elif expected_component != bundle.window_component:
                issues.append(f"{label}: window dates must match the run path")

    run_ref = value.get("run_ref")
    if not isinstance(run_ref, str) or RUN_REF_RE.fullmatch(run_ref) is None:
        issues.append(f"{label}: run_ref is invalid")
    elif (
        not isinstance(logical_run_id, str)
        or run_ref.removeprefix("run_ref_v2:") != logical_run_id
    ):
        issues.append(f"{label}: run_ref payload must match run_id")
    run_revision_ref = value.get("run_revision_ref")
    if (
        not isinstance(run_revision_ref, str)
        or RUN_REVISION_REF_RE.fullmatch(run_revision_ref) is None
    ):
        issues.append(f"{label}: run_revision_ref is invalid")

    key_ids = value.get("key_ids")
    if not (
        _is_sorted_unique_strings(key_ids)
        and bool(key_ids)
        and all(KEY_ID_RE.fullmatch(item) is not None for item in key_ids)
    ):
        issues.append(
            f"{label}: key_ids must be a non-empty bytewise-sorted unique collection"
        )

    status = value.get("status")
    if not isinstance(status, str) or status not in PUBLICATION_STATUSES:
        issues.append(f"{label}: status is invalid")
    if bundle.mode == "baseline" and status == "partial":
        issues.append(f"{label}: baseline runs must not publish partial revisions")

    gap_summary = value.get("gap_summary")
    if not isinstance(gap_summary, dict) or frozenset(gap_summary) != GAP_SUMMARY_KEYS:
        issues.append(f"{label}: gap_summary fields do not match the v2 contract")
    else:
        count_fields = (
            "source_repairable_gap_count",
            "semantic_repairable_gap_count",
            "terminal_gap_count",
            "unaccounted_source_unit_count",
            "privacy_breach_count",
        )
        if not all(
            _is_non_negative_int(gap_summary.get(field)) for field in count_fields
        ):
            issues.append(f"{label}: gap_summary counts must be non-negative integers")
        usage_refs = gap_summary.get("terminal_authorization_usage_refs")
        if not _is_sorted_unique_strings(usage_refs):
            issues.append(
                f"{label}: terminal authorization usage references must be bytewise-sorted and unique"
            )
        source_count = gap_summary.get("source_repairable_gap_count")
        semantic_count = gap_summary.get("semantic_repairable_gap_count")
        terminal_count = gap_summary.get("terminal_gap_count")
        if all(
            _is_non_negative_int(item)
            for item in (source_count, semantic_count, terminal_count)
        ):
            if status == "partial" and source_count + semantic_count == 0:
                issues.append(f"{label}: partial status requires a repairable gap")
            if status == "complete" and (
                source_count or semantic_count or terminal_count or usage_refs
            ):
                issues.append(
                    f"{label}: complete status must not retain gaps or authorizations"
                )
            if status == "complete_with_terminal_gaps":
                invalid_terminal = source_count or semantic_count or terminal_count == 0
                if execution_kind == "compliance_retraction":
                    invalid_terminal = invalid_terminal or bool(usage_refs)
                else:
                    invalid_terminal = invalid_terminal or not usage_refs
                if invalid_terminal:
                    issues.append(
                        f"{label}: complete_with_terminal_gaps has inconsistent gap_summary"
                    )
        if gap_summary.get("unaccounted_source_unit_count") != 0:
            issues.append(
                f"{label}: retained publication must not contain unaccounted source units"
            )
        privacy_breach_count = gap_summary.get("privacy_breach_count")
        if execution_kind == "retrospective" and privacy_breach_count != 0:
            issues.append(
                f"{label}: retrospective publication must not contain privacy breaches"
            )
        if execution_kind == "compliance_retraction" and not (
            _is_non_negative_int(privacy_breach_count) and privacy_breach_count > 0
        ):
            issues.append(f"{label}: compliance retraction requires a privacy breach")

    supersession = value.get("supersession")
    supersession_refs: dict[str, tuple[str, ...]] = {}
    if (
        not isinstance(supersession, dict)
        or frozenset(supersession) != SUPERSESSION_KEYS
    ):
        issues.append(f"{label}: supersession fields do not match the v2 contract")
    else:
        reason = supersession.get("reason")
        if not isinstance(reason, str) or reason not in SUPERSESSION_REASONS:
            issues.append(f"{label}: supersession reason is invalid")
        patterns = {
            "supersedes_run_revision_refs": RUN_REVISION_REF_RE,
            "supersedes_episode_revision_refs": REVISION_SPECS[
                "episodes.jsonl"
            ].current_pattern,
            "supersedes_topic_revision_refs": REVISION_SPECS[
                "topics.jsonl"
            ].current_pattern,
            "supersedes_turn_finding_revision_refs": REVISION_SPECS[
                "turn_findings.jsonl"
            ].current_pattern,
        }
        for field_name in SUPERSESSION_FIELDS:
            refs = _validate_reference_array(
                supersession.get(field_name), patterns[field_name], label, issues
            )
            supersession_refs[field_name] = refs
        has_refs = any(supersession_refs.values())
        if reason == "initial" and has_refs:
            issues.append(
                f"{label}: initial run revision must not supersede prior revisions"
            )
        if (
            isinstance(reason, str)
            and reason in SUPERSESSION_REASONS - {"initial"}
            and not has_refs
        ):
            issues.append(
                f"{label}: superseding run revision must name a prior revision"
            )
        run_refs = supersession_refs.get("supersedes_run_revision_refs", ())
        if reason == "backfill" and (
            not run_refs or status not in FULL_PUBLICATION_STATUSES
        ):
            issues.append(
                f"{label}: backfill must publish a full revision over a partial run"
            )

    if publication_role == "campaign_segment":
        segment_count = value.get("campaign_segment_count")
        metadata = value.get("campaign_segment_metadata")
        if (
            isinstance(metadata, dict)
            and _is_int(metadata.get("segment_ordinal"))
            and _is_int(segment_count)
            and metadata["segment_ordinal"] > segment_count
        ):
            issues.append(
                f"{label}: campaign segment ordinal exceeds campaign segment count"
            )

    if value.get("artifact_inventory") != EXPECTED_ARTIFACT_INVENTORY:
        issues.append(
            f"{label}: artifact_inventory must match the fixed bytewise basename order"
        )
    if value.get("bundle_digest_contract") != BUNDLE_DIGEST_CONTRACT:
        issues.append(f"{label}: bundle_digest_contract is invalid")
    digest = value.get("retained_bundle_digest_v2")
    if not isinstance(digest, str) or DIGEST_RE.fullmatch(digest) is None:
        issues.append(f"{label}: retained_bundle_digest_v2 is invalid")
    production_root = value.get("production_configuration_root_v2")
    if (
        not isinstance(production_root, str)
        or PRODUCTION_CONFIGURATION_ROOT_RE.fullmatch(production_root) is None
    ):
        issues.append(f"{label}: production_configuration_root_v2 is invalid")
    else:
        try:
            expected_production_root = _compute_production_configuration_root(
                value.get("provenance")
            )
        except (TypeError, UnicodeEncodeError):
            issues.append(
                f"{label}: active production provenance references are invalid"
            )
        else:
            if production_root != expected_production_root:
                issues.append(
                    f"{label}: production_configuration_root_v2 does not bind the active provenance references"
                )

    _validate_manifest_eras(value, label, issues)

    if isinstance(run_revision_ref, str) and RUN_REVISION_REF_RE.fullmatch(
        run_revision_ref
    ):
        predecessors = supersession_refs.get("supersedes_run_revision_refs", ())
        reason = (
            supersession.get("reason") if isinstance(supersession, dict) else "invalid"
        )
        if run_revision_ref in predecessors:
            issues.append(f"{label}: run revision cannot supersede itself")
        bundle.revisions.append(
            RevisionNode(
                family="run",
                current=run_revision_ref,
                predecessors=predecessors,
                kind=reason if isinstance(reason, str) else "invalid",
                entity_ref=None,
                transaction_ref=run_revision_ref,
                label=label,
            )
        )

    _validate_reference_collections(value, label, issues)

    if (
        len(bundle.raw) == len(ARTIFACT_BASENAMES)
        and all(name in bundle.raw for name in ARTIFACT_BASENAMES)
        and "retained_bundle_digest_v2" in value
    ):
        try:
            expected_digest = _compute_retained_bundle_digest(bundle.raw, value)
        except (KeyError, TypeError, ValueError, OverflowError):
            issues.append(f"{label}: canonical manifest projection is invalid")
        else:
            if digest != expected_digest:
                issues.append(
                    f"{label}: retained_bundle_digest_v2 does not match the retained bundle"
                )


def _validate_artifact_identity(
    record: Any,
    basename: str,
    bundle: Bundle,
    label: str,
    issues: list[str],
) -> None:
    if not isinstance(record, dict):
        issues.append(f"{label}: retained artifact record must be an object")
        return
    if record.get("artifact_type") != EXPECTED_ARTIFACT_TYPES[basename]:
        issues.append(f"{label}: artifact_type does not match the artifact basename")
    if not _valid_schema_version(record.get("schema_version")):
        issues.append(f"{label}: schema_version must be 2")
    if bundle.manifest is not None and record.get("run_ref") != bundle.manifest.get(
        "run_ref"
    ):
        issues.append(f"{label}: run_ref must match manifest.json")


def _validate_rows(bundle: Bundle, basename: str, issues: list[str]) -> None:
    spec = REVISION_SPECS[basename]
    rows = bundle.rows.get(basename, [])
    sortable: list[tuple[str, str]] = []
    entity_refs: list[str] = []
    revision_refs: list[str] = []
    for line_no, row in rows:
        if _issues_full(issues):
            return
        label = f"{bundle.label}/{basename}:{line_no}"
        _validate_artifact_identity(row, basename, bundle, label, issues)
        if not isinstance(row, dict):
            continue
        node = _validate_revision_record(row, spec, bundle, label, issues)
        if node is not None:
            bundle.revisions.append(node)
            revision_refs.append(node.current)
        entity = row.get(spec.entity_field) if spec.entity_field is not None else None
        current = row.get(spec.current_field)
        if isinstance(entity, str) and isinstance(current, str):
            sortable.append((entity, current))
            entity_refs.append(entity)
        _validate_reference_collections(row, label, issues)

    if sortable != sorted(sortable):
        issues.append(
            f"{bundle.label}/{basename}: JSONL records must use stable bytewise entity/revision order"
        )
    if len(entity_refs) != len(set(entity_refs)):
        issues.append(
            f"{bundle.label}/{basename}: entity references must be unique within the run"
        )
    if len(revision_refs) != len(set(revision_refs)):
        issues.append(
            f"{bundle.label}/{basename}: revision references must be unique within the run"
        )


def _manifest_era_refs(manifest: dict[str, Any], key: str, ref_field: str) -> set[str]:
    eras = manifest.get("eras")
    if not isinstance(eras, dict) or not isinstance(eras.get(key), list):
        return set()
    return {
        row[ref_field]
        for row in eras[key]
        if isinstance(row, dict) and isinstance(row.get(ref_field), str)
    }


def _validate_era_and_key_refs(
    bundle: Bundle, label: str, value: dict[str, Any], issues: list[str]
) -> None:
    if bundle.manifest is None:
        return
    key_ids = bundle.manifest.get("key_ids")
    if "key_id" in value and (
        not isinstance(key_ids, list) or value.get("key_id") not in key_ids
    ):
        issues.append(f"{label}: key_id must be declared by manifest.json")
    policy_refs = _manifest_era_refs(bundle.manifest, "policy_eras", "policy_era_ref")
    model_refs = _manifest_era_refs(bundle.manifest, "model_eras", "model_era_ref")
    if "policy_era_ref" in value and (
        not isinstance(value.get("policy_era_ref"), str)
        or value.get("policy_era_ref") not in policy_refs
    ):
        issues.append(f"{label}: policy_era_ref must be declared by manifest.json")
    if "model_era_ref" in value and (
        not isinstance(value.get("model_era_ref"), str)
        or value.get("model_era_ref") not in model_refs
    ):
        issues.append(f"{label}: model_era_ref must be declared by manifest.json")
    for field_name, allowed in (
        ("policy_era_refs", policy_refs),
        ("model_era_refs", model_refs),
    ):
        refs = value.get(field_name)
        if isinstance(refs, list) and any(
            not isinstance(ref, str) or ref not in allowed for ref in refs
        ):
            issues.append(f"{label}: {field_name} must be declared by manifest.json")


def _validate_gap_consistency(
    bundle: Bundle, coverage: dict[str, Any], issues: list[str]
) -> None:
    if bundle.manifest is None:
        return
    label = f"{bundle.label}/coverage.json"
    gaps = coverage.get("gaps")
    if not isinstance(gaps, list) or not all(isinstance(gap, dict) for gap in gaps):
        issues.append(f"{label}: gaps must be an array of objects")
        return

    gap_order = [
        (str(gap.get("gap_ref", "")), str(gap.get("gap_revision_ref", "")))
        for gap in gaps
    ]
    if gap_order != sorted(gap_order):
        issues.append(f"{label}: gaps must use stable bytewise reference order")
    gap_revisions = [
        gap.get("gap_revision_ref")
        for gap in gaps
        if isinstance(gap.get("gap_revision_ref"), str)
    ]
    if len(gap_revisions) != len(set(gap_revisions)):
        issues.append(f"{label}: gap revisions must be unique within the run")
    gap_entities = [
        gap.get("gap_ref") for gap in gaps if isinstance(gap.get("gap_ref"), str)
    ]
    if len(gap_entities) != len(set(gap_entities)):
        issues.append(f"{label}: gap references must be unique within the run")

    source_repairable = 0
    semantic_repairable = 0
    terminal = 0
    privacy_breaches = 0
    authorization_refs: list[str] = []
    for index, gap in enumerate(gaps, 1):
        if _issues_full(issues):
            return
        gap_label = f"{label}:gap[{index}]"
        repairability = gap.get("repairability")
        if repairability == "repairable":
            if isinstance(gap.get("scope"), str) and gap.get("scope") in {
                "host_source_cell",
                "source_unit",
            }:
                source_repairable += 1
            else:
                semantic_repairable += 1
        elif repairability == "terminal_policy":
            terminal += 1
            if (
                isinstance(gap.get("reason"), str)
                and gap.get("reason") in PRIVACY_BREACH_REASONS
            ):
                privacy_breaches += 1
            usage_ref = gap.get("authorization_usage_ref")
            if isinstance(usage_ref, str):
                authorization_refs.append(usage_ref)
        else:
            issues.append(f"{gap_label}: repairability is invalid")

        current = gap.get("gap_revision_ref")
        predecessor = gap.get("predecessor_gap_revision_ref")
        if isinstance(current, str) and re.fullmatch(
            r"gap_revision_ref_v2:[0-9a-f]{32}", current
        ):
            predecessors: tuple[str, ...] = ()
            if predecessor is not None:
                if isinstance(predecessor, str) and re.fullmatch(
                    r"gap_revision_ref_v2:[0-9a-f]{32}", predecessor
                ):
                    predecessors = (predecessor,)
                else:
                    issues.append(
                        f"{gap_label}: predecessor revision reference is invalid"
                    )
            bundle.revisions.append(
                RevisionNode(
                    family="gap",
                    current=current,
                    predecessors=predecessors,
                    kind="initial" if predecessor is None else "correction",
                    entity_ref=gap.get("gap_ref")
                    if isinstance(gap.get("gap_ref"), str)
                    else None,
                    transaction_ref=bundle.transaction_ref,
                    label=gap_label,
                )
            )
        else:
            issues.append(f"{gap_label}: current revision reference is invalid")

    summary = bundle.manifest.get("gap_summary")
    if isinstance(summary, dict):
        expected = {
            "source_repairable_gap_count": source_repairable,
            "semantic_repairable_gap_count": semantic_repairable,
            "terminal_gap_count": terminal,
            "terminal_authorization_usage_refs": sorted(authorization_refs),
            "privacy_breach_count": privacy_breaches,
        }
        if any(summary.get(key) != value for key, value in expected.items()):
            issues.append(f"{label}: gaps must match manifest.json gap_summary")

    status = bundle.manifest.get("status")
    if status == "complete" and gaps:
        issues.append(f"{label}: complete status must have no gaps")
    if status == "partial" and source_repairable + semantic_repairable == 0:
        issues.append(f"{label}: partial status requires a repairable gap")
    if status == "complete_with_terminal_gaps" and (
        source_repairable
        or semantic_repairable
        or terminal == 0
        or terminal != len(gaps)
    ):
        issues.append(
            f"{label}: complete_with_terminal_gaps must contain only terminal gaps"
        )


def _validate_bundle(
    bundle: Bundle,
    root_descriptor: int,
    issues: list[str],
    validators: dict[str, Any],
    privacy_validator: _PrivacyValidator,
    budget: _ReadBudget,
) -> None:
    _read_bundle(bundle, root_descriptor, issues, validators, privacy_validator, budget)
    if _issues_full(issues):
        return
    _validate_manifest(bundle, issues)

    for basename in ("coverage.json", "summary.json", "trend_report.json"):
        if _issues_full(issues):
            return
        value = bundle.documents.get(basename)
        label = f"{bundle.label}/{basename}"
        if value is None:
            continue
        _validate_artifact_identity(value, basename, bundle, label, issues)
        if not isinstance(value, dict):
            continue
        node = _validate_revision_record(
            value, REVISION_SPECS[basename], bundle, label, issues
        )
        if node is not None:
            bundle.revisions.append(node)
        _validate_reference_collections(value, label, issues)
        _validate_era_and_key_refs(bundle, label, value, issues)

    for basename in ("episodes.jsonl", "topics.jsonl", "turn_findings.jsonl"):
        if _issues_full(issues):
            return
        _validate_rows(bundle, basename, issues)
        for line_no, row in bundle.rows.get(basename, []):
            if isinstance(row, dict):
                _validate_era_and_key_refs(
                    bundle, f"{bundle.label}/{basename}:{line_no}", row, issues
                )

    if bundle.manifest is None:
        return
    status = bundle.manifest.get("status")
    window = bundle.manifest.get("window")
    coverage = bundle.documents.get("coverage.json")
    summary = bundle.documents.get("summary.json")
    trend = bundle.documents.get("trend_report.json")
    if isinstance(coverage, dict):
        if coverage.get("publication_status") != status:
            issues.append(
                f"{bundle.label}/coverage.json: publication_status must match manifest.json"
            )
        _validate_stable_object_collection(
            coverage,
            "source_cells",
            ("cell_ref",),
            f"{bundle.label}/coverage.json",
            issues,
        )
        _validate_gap_consistency(bundle, coverage, issues)
    if isinstance(summary, dict):
        if summary.get("publication_status") != status:
            issues.append(
                f"{bundle.label}/summary.json: publication_status must match manifest.json"
            )
        expected_report = _render_report_markdown(summary)
        if expected_report is None:
            issues.append(
                f"{bundle.label}/summary.json: report renderer input is invalid"
            )
        elif bundle.raw.get("report.md") != expected_report:
            issues.append(
                f"{bundle.label}/report.md: bytes must exactly match the summary.json rendering"
            )
    if isinstance(trend, dict):
        if trend.get("publication_status") != status:
            issues.append(
                f"{bundle.label}/trend_report.json: publication_status must match manifest.json"
            )
        if trend.get("window") != window:
            issues.append(
                f"{bundle.label}/trend_report.json: window must match manifest.json"
            )
        _validate_stable_object_collection(
            trend,
            "strata",
            ("policy_era_ref", "model_era_ref"),
            f"{bundle.label}/trend_report.json",
            issues,
        )

    _validate_bundle_references(bundle, issues)
    if not _issues_full(issues):
        _validate_cross_artifact_consistency(bundle, issues)
    _validate_manifest_entity_supersession(bundle, issues)


def _validate_bundle_references(bundle: Bundle, issues: list[str]) -> None:
    episodes = [
        row for _, row in bundle.rows.get("episodes.jsonl", []) if isinstance(row, dict)
    ]
    topics = [
        row for _, row in bundle.rows.get("topics.jsonl", []) if isinstance(row, dict)
    ]
    findings = [
        row
        for _, row in bundle.rows.get("turn_findings.jsonl", [])
        if isinstance(row, dict)
    ]
    coverage = bundle.documents.get("coverage.json")

    episodes_by_ref = {
        row["episode_ref"]: row
        for row in episodes
        if isinstance(row.get("episode_ref"), str)
    }
    episode_revision_refs = {
        row["episode_revision_ref"]
        for row in episodes
        if isinstance(row.get("episode_revision_ref"), str)
    }
    topic_refs = {
        row["topic_ref"] for row in topics if isinstance(row.get("topic_ref"), str)
    }
    gap_refs = set()
    if isinstance(coverage, dict) and isinstance(coverage.get("gaps"), list):
        gap_refs = {
            gap["gap_ref"]
            for gap in coverage["gaps"]
            if isinstance(gap, dict) and isinstance(gap.get("gap_ref"), str)
        }

    assigned_episode_revisions: set[str] = set()
    for index, topic in enumerate(topics, 1):
        if _issues_full(issues):
            return
        label = f"{bundle.label}/topics.jsonl:{index}"
        members = topic.get("episode_revision_refs")
        if isinstance(members, list):
            if any(
                not isinstance(member, str) or member not in episode_revision_refs
                for member in members
            ):
                issues.append(
                    f"{label}: episode_revision_refs must resolve within episodes.jsonl"
                )
            overlap = assigned_episode_revisions.intersection(
                member for member in members if isinstance(member, str)
            )
            if overlap:
                issues.append(
                    f"{label}: episode revision must belong to at most one topic"
                )
            assigned_episode_revisions.update(
                member for member in members if isinstance(member, str)
            )

    for index, episode in enumerate(episodes, 1):
        if _issues_full(issues):
            return
        label = f"{bundle.label}/episodes.jsonl:{index}"
        primary_topic = episode.get("primary_topic_ref")
        if primary_topic is not None and (
            not isinstance(primary_topic, str) or primary_topic not in topic_refs
        ):
            issues.append(
                f"{label}: primary_topic_ref must resolve within topics.jsonl"
            )
        refs = episode.get("gap_refs")
        if isinstance(refs, list) and any(
            not isinstance(ref, str) or ref not in gap_refs for ref in refs
        ):
            issues.append(f"{label}: gap_refs must resolve within coverage.json")

    for index, finding in enumerate(findings, 1):
        if _issues_full(issues):
            return
        label = f"{bundle.label}/turn_findings.jsonl:{index}"
        episode_ref = finding.get("episode_ref")
        episode = (
            episodes_by_ref.get(episode_ref) if isinstance(episode_ref, str) else None
        )
        if episode is None:
            issues.append(f"{label}: episode_ref must resolve within episodes.jsonl")
        else:
            turn_refs = episode.get("turn_refs")
            if isinstance(turn_refs, list) and finding.get("turn_ref") not in turn_refs:
                issues.append(
                    f"{label}: turn_ref must belong to the referenced episode"
                )
        refs = finding.get("gap_refs")
        if isinstance(refs, list) and any(
            not isinstance(ref, str) or ref not in gap_refs for ref in refs
        ):
            issues.append(f"{label}: gap_refs must resolve within coverage.json")

    for index, topic in enumerate(topics, 1):
        if _issues_full(issues):
            return
        refs = topic.get("gap_refs")
        if isinstance(refs, list) and any(
            not isinstance(ref, str) or ref not in gap_refs for ref in refs
        ):
            issues.append(
                f"{bundle.label}/topics.jsonl:{index}: gap_refs must resolve within coverage.json"
            )


def _count_map(value: Any, fields: Iterable[str]) -> dict[str, int] | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, int] = {}
    for field_name in fields:
        count = value.get(field_name)
        if not _is_non_negative_int(count):
            return None
        result[field_name] = count
    return result


def _gap_unit_total(gaps: list[dict[str, Any]], scopes: set[str]) -> int:
    return sum(
        gap["affected_unit_count"]
        for gap in gaps
        if isinstance(gap.get("scope"), str)
        and gap.get("scope") in scopes
        and _is_non_negative_int(gap.get("affected_unit_count"))
    )


def _era_pair(value: dict[str, Any]) -> tuple[str, str] | None:
    policy_ref = value.get("policy_era_ref")
    model_ref = value.get("model_era_ref")
    if not isinstance(policy_ref, str) or not isinstance(model_ref, str):
        return None
    return (policy_ref, model_ref)


def _validate_cross_artifact_consistency(bundle: Bundle, issues: list[str]) -> None:
    manifest = bundle.manifest
    coverage = bundle.documents.get("coverage.json")
    summary = bundle.documents.get("summary.json")
    trend = bundle.documents.get("trend_report.json")
    if not all(
        isinstance(value, dict) for value in (manifest, coverage, summary, trend)
    ):
        return
    assert isinstance(manifest, dict)
    assert isinstance(coverage, dict)
    assert isinstance(summary, dict)
    assert isinstance(trend, dict)

    coverage_label = f"{bundle.label}/coverage.json"
    trend_label = f"{bundle.label}/trend_report.json"
    episodes = [
        row for _, row in bundle.rows.get("episodes.jsonl", []) if isinstance(row, dict)
    ]
    topics = [
        row for _, row in bundle.rows.get("topics.jsonl", []) if isinstance(row, dict)
    ]
    findings = [
        row
        for _, row in bundle.rows.get("turn_findings.jsonl", [])
        if isinstance(row, dict)
    ]
    source_cells = (
        [row for row in coverage.get("source_cells", []) if isinstance(row, dict)]
        if isinstance(coverage.get("source_cells"), list)
        else []
    )
    gaps = (
        [row for row in coverage.get("gaps", []) if isinstance(row, dict)]
        if isinstance(coverage.get("gaps"), list)
        else []
    )

    head_bindings = manifest.get("head_bindings")
    if (
        manifest.get("publication_role") != "campaign_segment"
        and isinstance(head_bindings, dict)
        and coverage.get("source_accounting") != head_bindings.get("source_accounting")
    ):
        issues.append(
            f"{coverage_label}: source_accounting must match manifest.json head_bindings"
        )

    cell_keys = [
        (cell.get("host_ref"), cell.get("source_kind"))
        for cell in source_cells
        if isinstance(cell.get("host_ref"), str)
        and isinstance(cell.get("source_kind"), str)
    ]
    if len(cell_keys) != len(set(cell_keys)):
        issues.append(
            f"{coverage_label}: each host and source kind must have exactly one source cell"
        )
    host_kinds: dict[str, set[str]] = defaultdict(set)
    for host_ref, source_kind in cell_keys:
        host_kinds[host_ref].add(source_kind)
    if any(kinds != SOURCE_KINDS for kinds in host_kinds.values()):
        issues.append(f"{coverage_label}: every host must cover all fixed source kinds")

    gap_by_ref = {
        gap["gap_ref"]: gap for gap in gaps if isinstance(gap.get("gap_ref"), str)
    }
    cells_by_source = {
        (cell.get("host_ref"), cell.get("source_ref")): cell
        for cell in source_cells
        if isinstance(cell.get("host_ref"), str)
        and isinstance(cell.get("source_ref"), str)
    }
    source_gap_refs: set[str] = set()
    for cell in source_cells:
        if _issues_full(issues):
            return
        refs = cell.get("gap_refs")
        if not isinstance(refs, list):
            continue
        for gap_ref in refs:
            if not isinstance(gap_ref, str):
                continue
            gap = gap_by_ref.get(gap_ref)
            if gap is None:
                issues.append(
                    f"{coverage_label}: source cell gap_refs must resolve within coverage.json"
                )
                continue
            source_gap_refs.add(gap_ref)
            scope = gap.get("scope")
            if (
                not isinstance(scope, str)
                or scope not in {"host_source_cell", "source_unit"}
                or gap.get("host_ref") != cell.get("host_ref")
                or gap.get("source_ref") != cell.get("source_ref")
            ):
                issues.append(
                    f"{coverage_label}: source cell gap_refs must target their source cell"
                )
    expected_source_gap_refs = {
        gap["gap_ref"]
        for gap in gaps
        if isinstance(gap.get("scope"), str)
        and gap.get("scope") in {"host_source_cell", "source_unit"}
        and isinstance(gap.get("gap_ref"), str)
    }
    if source_gap_refs != expected_source_gap_refs:
        issues.append(f"{coverage_label}: source gaps must be covered by source_cells")
    for gap in gaps:
        if _issues_full(issues):
            return
        host_ref = gap.get("host_ref")
        source_ref = gap.get("source_ref")
        if (
            isinstance(gap.get("scope"), str)
            and gap.get("scope")
            in {
                "host_source_cell",
                "source_unit",
            }
            and (
                not isinstance(host_ref, str)
                or not isinstance(source_ref, str)
                or (host_ref, source_ref) not in cells_by_source
            )
        ):
            issues.append(f"{coverage_label}: source gap must resolve to a source cell")

    dispositions = coverage.get("dispositions")
    if not isinstance(dispositions, dict):
        return
    source_unit = _count_map(
        dispositions.get("source_unit"), ("consumed", "structurally_excluded", "gap")
    )
    parent_record = _count_map(
        dispositions.get("parent_record"),
        ("fully_consumed", "fully_excluded", "mixed_consumed_excluded", "has_gap"),
    )
    structural = _count_map(
        dispositions.get("structural_exclusion"),
        (
            "deterministic_wrapper",
            "heartbeat",
            "empty_unit",
            "duplicate_of",
            "retrospective_coordinator",
            "worker_attempt",
            "out_of_window",
            "source_policy_exclusion",
        ),
    )
    semantic = _count_map(
        dispositions.get("semantic_turn"),
        ("meaningful", "context_only", "meaningfulness_gap"),
    )
    episode_review = _count_map(
        dispositions.get("episode_review"),
        ("reviewed", "review_not_required", "review_gap"),
    )
    turn_review = _count_map(
        dispositions.get("turn_review"),
        ("high_impact", "not_high_impact", "turn_review_gap"),
    )
    topic_counts = _count_map(
        dispositions.get("topic"), ("reviewed", "topic_decision_gap")
    )
    synthesis = _count_map(dispositions.get("synthesis"), ("complete", "synthesis_gap"))

    unit_total = sum(
        cell["unit_count"]
        for cell in source_cells
        if _is_non_negative_int(cell.get("unit_count"))
    )
    record_total = sum(
        cell["record_count"]
        for cell in source_cells
        if _is_non_negative_int(cell.get("record_count"))
    )
    if source_unit is not None:
        if sum(source_unit.values()) != unit_total:
            issues.append(
                f"{coverage_label}: source_unit dispositions must total source cell units"
            )
        if source_unit["gap"] != _gap_unit_total(
            gaps, {"host_source_cell", "source_unit"}
        ):
            issues.append(
                f"{coverage_label}: source_unit gap count must match source gaps"
            )
    if parent_record is not None and sum(parent_record.values()) != record_total:
        issues.append(
            f"{coverage_label}: parent_record dispositions must total source cell records"
        )
    if (
        source_unit is not None
        and structural is not None
        and (sum(structural.values()) != source_unit["structurally_excluded"])
    ):
        issues.append(
            f"{coverage_label}: structural exclusions must match excluded source units"
        )
    if (
        source_unit is not None
        and semantic is not None
        and (sum(semantic.values()) != source_unit["consumed"])
    ):
        issues.append(
            f"{coverage_label}: semantic turn dispositions must match consumed source units"
        )

    meaningful_turns = 0
    context_turns = 0
    all_turn_refs: list[str] = []
    for episode in episodes:
        if _issues_full(issues):
            return
        meaningful = episode.get("meaningful_turn_count")
        context = episode.get("context_turn_count")
        turn_refs = episode.get("turn_refs")
        if _is_non_negative_int(meaningful):
            meaningful_turns += meaningful
        if _is_non_negative_int(context):
            context_turns += context
        if (
            _is_non_negative_int(meaningful)
            and _is_non_negative_int(context)
            and isinstance(turn_refs, list)
            and meaningful + context != len(turn_refs)
        ):
            issues.append(
                f"{bundle.label}/episodes.jsonl: turn counts must match turn_refs cardinality"
            )
        if isinstance(turn_refs, list):
            all_turn_refs.extend(ref for ref in turn_refs if isinstance(ref, str))
    if len(all_turn_refs) != len(set(all_turn_refs)):
        issues.append(
            f"{bundle.label}/episodes.jsonl: turn_refs must be unique across episodes"
        )
    if semantic is not None and (
        semantic["meaningful"] != meaningful_turns
        or semantic["context_only"] != context_turns
        or semantic["meaningfulness_gap"] != _gap_unit_total(gaps, {"meaningfulness"})
    ):
        issues.append(
            f"{coverage_label}: semantic turn counts must match episodes and gaps"
        )

    actual_episode_review = Counter(
        disposition
        for episode in episodes
        if isinstance((disposition := episode.get("review_disposition")), str)
    )
    if episode_review is not None and any(
        episode_review[name] != actual_episode_review[name] for name in episode_review
    ):
        issues.append(
            f"{coverage_label}: episode_review counts must match episodes.jsonl"
        )
    if episode_review is not None and episode_review["review_gap"] != _gap_unit_total(
        gaps, {"episode_review"}
    ):
        issues.append(f"{coverage_label}: episode review gaps must match coverage gaps")
    actual_turn_review = Counter(
        disposition
        for finding in findings
        if isinstance((disposition := finding.get("disposition")), str)
    )
    if turn_review is not None and any(
        turn_review[name] != actual_turn_review[name] for name in turn_review
    ):
        issues.append(
            f"{coverage_label}: turn_review counts must match turn_findings.jsonl"
        )
    if turn_review is not None and turn_review["turn_review_gap"] != _gap_unit_total(
        gaps, {"turn_review"}
    ):
        issues.append(f"{coverage_label}: turn review gaps must match coverage gaps")
    actual_topic_counts = Counter(
        disposition
        for topic in topics
        if isinstance((disposition := topic.get("disposition")), str)
    )
    if topic_counts is not None and any(
        topic_counts[name] != actual_topic_counts[name] for name in topic_counts
    ):
        issues.append(f"{coverage_label}: topic counts must match topics.jsonl")
    if topic_counts is not None and topic_counts[
        "topic_decision_gap"
    ] != _gap_unit_total(gaps, {"topic"}):
        issues.append(f"{coverage_label}: topic decision gaps must match coverage gaps")
    if turn_review is not None and sum(turn_review.values()) != meaningful_turns:
        issues.append(
            f"{coverage_label}: every meaningful turn must have one turn finding"
        )

    findings_by_episode = Counter(
        finding.get("episode_ref")
        for finding in findings
        if isinstance(finding.get("episode_ref"), str)
    )
    for episode in episodes:
        if _issues_full(issues):
            return
        meaningful = episode.get("meaningful_turn_count")
        episode_ref = episode.get("episode_ref")
        if (
            _is_non_negative_int(meaningful)
            and isinstance(episode_ref, str)
            and (findings_by_episode[episode_ref] != meaningful)
        ):
            issues.append(
                f"{bundle.label}/turn_findings.jsonl: finding cardinality must match each episode"
            )
            break

    episodes_by_revision = {
        episode["episode_revision_ref"]: episode
        for episode in episodes
        if isinstance(episode.get("episode_revision_ref"), str)
    }
    assigned_revisions: set[str] = set()
    for topic in topics:
        if _issues_full(issues):
            return
        members = topic.get("episode_revision_refs")
        if not isinstance(members, list):
            continue
        for member in members:
            if not isinstance(member, str):
                continue
            episode = episodes_by_revision.get(member)
            if episode is None:
                continue
            assigned_revisions.add(member)
            if episode.get("primary_topic_ref") != topic.get("topic_ref"):
                issues.append(
                    f"{bundle.label}/topics.jsonl: topic membership must match primary_topic_ref"
                )
            if episode.get("workstream_ref") != topic.get("workstream_ref"):
                issues.append(
                    f"{bundle.label}/topics.jsonl: topic members must share the topic workstream"
                )
            if episode.get("policy_era_ref") != topic.get(
                "policy_era_ref"
            ) or episode.get("model_era_ref") != topic.get("model_era_ref"):
                issues.append(
                    f"{bundle.label}/topics.jsonl: topic members must share the topic eras"
                )
    expected_assigned = {
        episode["episode_revision_ref"]
        for episode in episodes
        if isinstance(episode.get("episode_revision_ref"), str)
        and episode.get("primary_topic_ref") is not None
    }
    if assigned_revisions != expected_assigned:
        issues.append(
            f"{bundle.label}/topics.jsonl: topic membership must cover primary episode assignments"
        )
    meaningful_revisions = {
        episode["episode_revision_ref"]
        for episode in episodes
        if isinstance(episode.get("episode_revision_ref"), str)
        and _is_non_negative_int(episode.get("meaningful_turn_count"))
        and episode["meaningful_turn_count"] > 0
    }
    if not meaningful_revisions.issubset(assigned_revisions):
        issues.append(
            f"{bundle.label}/topics.jsonl: every meaningful episode must belong to one topic"
        )

    synthesis_gap_count = _gap_unit_total(gaps, {"synthesis"})
    if synthesis is not None and (
        synthesis["synthesis_gap"] != synthesis_gap_count
        or synthesis["complete"] != (0 if synthesis_gap_count else 1)
    ):
        issues.append(
            f"{coverage_label}: synthesis counts must describe one completed or gapped synthesis"
        )

    coverage_policy_refs = coverage.get("policy_era_refs")
    coverage_model_refs = coverage.get("model_era_refs")
    summary_policy_refs = summary.get("policy_era_refs")
    summary_model_refs = summary.get("model_era_refs")
    if (
        isinstance(coverage_policy_refs, list)
        and coverage_policy_refs != summary_policy_refs
    ):
        issues.append(
            f"{bundle.label}/summary.json: policy era coverage must match coverage.json"
        )
    if (
        isinstance(coverage_model_refs, list)
        and coverage_model_refs != summary_model_refs
    ):
        issues.append(
            f"{bundle.label}/summary.json: model era coverage must match coverage.json"
        )

    strata = (
        [row for row in trend.get("strata", []) if isinstance(row, dict)]
        if isinstance(trend.get("strata"), list)
        else []
    )
    stratum_pairs = {pair for row in strata if (pair := _era_pair(row)) is not None}
    if (
        isinstance(coverage_policy_refs, list)
        and all(isinstance(ref, str) for ref in coverage_policy_refs)
        and {pair[0] for pair in stratum_pairs} != set(coverage_policy_refs)
    ):
        issues.append(f"{trend_label}: strata must cover every coverage policy era")
    if (
        isinstance(coverage_model_refs, list)
        and all(isinstance(ref, str) for ref in coverage_model_refs)
        and {pair[1] for pair in stratum_pairs} != set(coverage_model_refs)
    ):
        issues.append(f"{trend_label}: strata must cover every coverage model era")

    episode_counts_by_pair: dict[tuple[Any, Any], list[int]] = defaultdict(
        lambda: [0, 0]
    )
    for episode in episodes:
        if _issues_full(issues):
            return
        pair = _era_pair(episode)
        if pair is None:
            continue
        meaningful = episode.get("meaningful_turn_count")
        if _is_non_negative_int(meaningful):
            episode_counts_by_pair[pair][0] += meaningful
            episode_counts_by_pair[pair][1] += int(meaningful > 0)
        if pair not in stratum_pairs:
            issues.append(f"{trend_label}: every episode era pair must have a stratum")

    episode_by_ref = {
        episode["episode_ref"]: episode
        for episode in episodes
        if isinstance(episode.get("episode_ref"), str)
    }
    observed_by_pair: dict[tuple[Any, Any], Counter[str]] = defaultdict(Counter)
    for finding in findings:
        if _issues_full(issues):
            return
        pair = _era_pair(finding)
        if pair is None:
            continue
        if pair not in stratum_pairs:
            issues.append(
                f"{trend_label}: every turn finding era pair must have a stratum"
            )
        finding_episode_ref = finding.get("episode_ref")
        episode = (
            episode_by_ref.get(finding_episode_ref)
            if isinstance(finding_episode_ref, str)
            else None
        )
        if episode is not None and pair != _era_pair(episode):
            issues.append(
                f"{bundle.label}/turn_findings.jsonl: finding eras must match the episode eras"
            )
        taxonomy = finding.get("taxonomy")
        if not isinstance(taxonomy, dict):
            continue
        for category in ("events", "findings", "strengths"):
            vector = taxonomy.get(category)
            if isinstance(vector, dict):
                observed_by_pair[pair].update(
                    metric for metric, state in vector.items() if state == "observed"
                )
    for topic in topics:
        if _issues_full(issues):
            return
        pair = _era_pair(topic)
        if pair is None:
            continue
        if pair not in stratum_pairs:
            issues.append(f"{trend_label}: every topic era pair must have a stratum")

    for stratum in strata:
        if _issues_full(issues):
            return
        pair = _era_pair(stratum)
        if pair is None:
            continue
        expected_turns, expected_episodes = episode_counts_by_pair[pair]
        if (
            stratum.get("meaningful_turn_count") != expected_turns
            or stratum.get("meaningful_episode_count") != expected_episodes
        ):
            issues.append(f"{trend_label}: stratum counts must match episodes.jsonl")
        metrics = stratum.get("metrics")
        if not isinstance(metrics, list) or not all(
            isinstance(metric, dict) for metric in metrics
        ):
            continue
        metric_ids = [metric.get("metric") for metric in metrics]
        if all(isinstance(metric_id, str) for metric_id in metric_ids) and (
            metric_ids != sorted(metric_ids) or len(metric_ids) != len(set(metric_ids))
        ):
            issues.append(
                f"{trend_label}: stratum metrics must use stable unique metric order"
            )
        for metric in metrics:
            if metric.get("status") != "available":
                continue
            metric_id = metric.get("metric")
            numerator = metric.get("numerator")
            denominator = metric.get("denominator")
            rate = metric.get("rate_per_100")
            if (
                not isinstance(metric_id, str)
                or not _is_non_negative_int(numerator)
                or not _is_non_negative_int(denominator)
                or denominator == 0
                or isinstance(rate, bool)
                or not isinstance(rate, (int, float))
                or denominator != expected_turns
                or numerator != observed_by_pair[pair][metric_id]
                or abs(rate - (numerator * 100 / denominator)) > 1e-9
            ):
                issues.append(
                    f"{trend_label}: available metric must match retained turn findings"
                )
            if not isinstance(metric_id, str):
                continue
            normalized = metric.get("normalized_change")
            if (
                not isinstance(normalized, dict)
                or normalized.get("status") != "available"
            ):
                continue
            delta = normalized.get("delta_per_100")
            direction = normalized.get("direction")
            if isinstance(delta, bool) or not isinstance(delta, (int, float)):
                continue
            expected_direction = "unchanged"
            if delta:
                improves = (
                    delta < 0 if metric_id in NEGATIVE_TREND_METRICS else delta > 0
                )
                expected_direction = "improved" if improves else "regressed"
            if direction != expected_direction:
                issues.append(
                    f"{trend_label}: normalized change direction must match its delta"
                )

    window = manifest.get("window")
    if isinstance(window, dict):
        window_start = _parse_coarse_timestamp(window.get("start"))
        window_end = _parse_coarse_timestamp(window.get("end"))
        for episode in episodes:
            if _issues_full(issues):
                return
            start = _parse_coarse_timestamp(episode.get("start_time"))
            end = _parse_coarse_timestamp(episode.get("end_time"))
            if start is not None and end is not None and start > end:
                issues.append(
                    f"{bundle.label}/episodes.jsonl: start_time must not follow end_time"
                )
            if (
                window_start is not None
                and window_end is not None
                and (
                    (start is not None and not (window_start <= start < window_end))
                    or (end is not None and not (window_start <= end <= window_end))
                )
            ):
                issues.append(
                    f"{bundle.label}/episodes.jsonl: episode timestamps must stay within the run window"
                )


def _validate_manifest_entity_supersession(bundle: Bundle, issues: list[str]) -> None:
    if bundle.manifest is None or not isinstance(
        bundle.manifest.get("supersession"), dict
    ):
        return
    supersession = bundle.manifest["supersession"]
    mappings = (
        ("episode", "supersedes_episode_revision_refs"),
        ("topic", "supersedes_topic_revision_refs"),
        ("turn_finding", "supersedes_turn_finding_revision_refs"),
    )
    for family, field_name in mappings:
        actual = sorted(
            {
                predecessor
                for node in bundle.revisions
                if node.family == family
                for predecessor in node.predecessors
            }
        )
        expected = supersession.get(field_name)
        if isinstance(expected, list) and actual != expected:
            issues.append(
                f"{bundle.label}/manifest.json: {field_name} must match the revisions closed by bundle records"
            )


def _validate_run_supersession(bundles: list[Bundle], issues: list[str]) -> None:
    manifests_by_revision: dict[str, Bundle] = {}
    duplicate_run_ids: dict[str, list[Bundle]] = defaultdict(list)
    for bundle in bundles:
        if _issues_full(issues):
            return
        duplicate_run_ids[bundle.run_id].append(bundle)
        if bundle.manifest is None:
            continue
        revision = bundle.manifest.get("run_revision_ref")
        if isinstance(revision, str) and RUN_REVISION_REF_RE.fullmatch(revision):
            if revision not in manifests_by_revision:
                manifests_by_revision[revision] = bundle

    for same_id in duplicate_run_ids.values():
        if len(same_id) > 1:
            for bundle in same_id:
                issues.append(
                    f"{bundle.label}/manifest.json: run_id must be globally unique"
                )

    aggregate_families = {
        "coverage": "coverage.json",
        "summary": "summary.json",
        "trend": "trend_report.json",
    }
    for bundle in bundles:
        if _issues_full(issues):
            return
        manifest = bundle.manifest
        if manifest is None or not isinstance(manifest.get("supersession"), dict):
            continue
        supersession = manifest["supersession"]
        target_refs = supersession.get("supersedes_run_revision_refs")
        if not isinstance(target_refs, list):
            continue
        targets = [
            manifests_by_revision[ref]
            for ref in target_refs
            if isinstance(ref, str) and ref in manifests_by_revision
        ]
        for target in targets:
            if _issues_full(issues):
                return
            if (target.mode, target.window_component) != (
                bundle.mode,
                bundle.window_component,
            ):
                issues.append(
                    f"{bundle.label}/manifest.json: superseded run must share mode and window"
                )
            target_status = (
                target.manifest.get("status") if target.manifest is not None else None
            )
            if supersession.get("reason") == "backfill" and target_status != "partial":
                issues.append(
                    f"{bundle.label}/manifest.json: backfill predecessor must be partial"
                )
            if (
                manifest.get("status") == "partial"
                and isinstance(target_status, str)
                and target_status in FULL_PUBLICATION_STATUSES
            ):
                issues.append(
                    f"{bundle.label}/manifest.json: partial revision must not supersede a full run"
                )

        if not targets or len(targets) != len(target_refs):
            continue
        for family, basename in aggregate_families.items():
            current_nodes = [node for node in bundle.revisions if node.family == family]
            expected: set[str] = set()
            for target in targets:
                expected.update(
                    node.current for node in target.revisions if node.family == family
                )
            actual = {
                predecessor
                for node in current_nodes
                for predecessor in node.predecessors
            }
            if actual != expected:
                issues.append(
                    f"{bundle.label}/{basename}: aggregate predecessor revisions must match manifest run supersession"
                )
            if target_refs and any(node.kind == "initial" for node in current_nodes):
                issues.append(
                    f"{bundle.label}/{basename}: superseding aggregate revision must not be initial"
                )


def _validate_campaign_consistency(bundles: list[Bundle], issues: list[str]) -> None:
    campaigns: dict[str, list[Bundle]] = defaultdict(list)
    for bundle in bundles:
        if bundle.manifest is None:
            continue
        campaign_ref = bundle.manifest.get("campaign_ref")
        if isinstance(campaign_ref, str):
            campaigns[campaign_ref].append(bundle)

    for campaign_ref, campaign_bundles in campaigns.items():
        if _issues_full(issues):
            return
        roots = [
            bundle
            for bundle in campaign_bundles
            if bundle.manifest is not None
            and bundle.manifest.get("publication_role") == "campaign_root"
        ]
        segments = [
            bundle
            for bundle in campaign_bundles
            if bundle.manifest is not None
            and bundle.manifest.get("publication_role") == "campaign_segment"
        ]
        coordinates = {
            (
                bundle.mode,
                bundle.window_component,
                bundle.manifest.get("publication_campaign_reason")
                if isinstance(bundle.manifest.get("publication_campaign_reason"), str)
                else None,
            )
            for bundle in campaign_bundles
            if bundle.manifest is not None
        }
        if len(coordinates) != 1:
            issues.append(
                "runs: campaign bundles must share mode, window, and campaign reason"
            )
        if len(roots) > 1:
            issues.append("runs: campaign must contain at most one campaign root")
        if roots and not segments:
            issues.append(
                "runs: campaign root must not exist without campaign segments"
            )
            continue
        if not segments:
            continue

        segment_counts = {
            bundle.manifest.get("campaign_segment_count")
            for bundle in segments
            if bundle.manifest is not None
            and _is_int(bundle.manifest.get("campaign_segment_count"))
        }
        root_counts = {
            bundle.manifest.get("campaign_segment_count")
            for bundle in roots
            if bundle.manifest is not None
            and _is_int(bundle.manifest.get("campaign_segment_count"))
        }
        if len(segment_counts) != 1 or (roots and root_counts != segment_counts):
            issues.append(
                "runs: campaign segment counts must agree with the campaign root"
            )
            continue
        segment_count = next(iter(segment_counts))
        assert isinstance(segment_count, int)

        ordinals: list[int] = []
        leaf_refs: list[str] = []
        page_refs: list[str] = []
        generations: set[str] = set()
        segment_commitments: list[tuple[int, str, str]] = []
        for bundle in segments:
            if _issues_full(issues):
                return
            assert bundle.manifest is not None
            metadata = bundle.manifest.get("campaign_segment_metadata")
            if isinstance(metadata, dict):
                ordinal = metadata.get("segment_ordinal")
                if _is_int(ordinal):
                    ordinals.append(ordinal)
                    run_ref = bundle.manifest.get("run_ref")
                    bundle_digest = bundle.manifest.get("retained_bundle_digest_v2")
                    if isinstance(run_ref, str) and isinstance(bundle_digest, str):
                        segment_commitments.append((ordinal, run_ref, bundle_digest))
                leaves = metadata.get("leaf_root_refs")
                pages = metadata.get("page_root_refs")
                if isinstance(leaves, list):
                    leaf_refs.extend(ref for ref in leaves if isinstance(ref, str))
                if isinstance(pages, list):
                    page_refs.extend(ref for ref in pages if isinstance(ref, str))
            head_bindings = bundle.manifest.get("head_bindings")
            if isinstance(head_bindings, dict):
                generation = head_bindings.get("bound_quarantine_generation_ref")
                if isinstance(generation, str):
                    generations.add(generation)
        for bundle in roots:
            assert bundle.manifest is not None
            head_bindings = bundle.manifest.get("head_bindings")
            if isinstance(head_bindings, dict):
                generation = head_bindings.get("bound_quarantine_generation_ref")
                if isinstance(generation, str):
                    generations.add(generation)

        invalid_ordinals = (
            len(ordinals) != len(segments)
            or len(ordinals) != len(set(ordinals))
            or any(ordinal < 1 or ordinal > segment_count for ordinal in ordinals)
        )
        if (
            not invalid_ordinals
            and not roots
            and set(ordinals) != set(range(1, len(segments) + 1))
        ):
            invalid_ordinals = True
        if invalid_ordinals or (
            roots
            and (
                len(segments) != segment_count
                or set(ordinals) != set(range(1, segment_count + 1))
            )
        ):
            issues.append(
                "runs: campaign segments must cover every unique bounded ordinal"
            )
        if len(leaf_refs) != len(set(leaf_refs)) or len(page_refs) != len(
            set(page_refs)
        ):
            issues.append("runs: campaign tree roots must be unique across segments")
        if len(generations) != 1:
            issues.append("runs: campaign bundles must bind one quarantine generation")
        if len(roots) == 1 and not invalid_ordinals and len(segments) == segment_count:
            root_manifest = roots[0].manifest
            assert root_manifest is not None
            declared_root = root_manifest.get("campaign_segment_root_v2")
            if (
                not isinstance(declared_root, str)
                or CAMPAIGN_SEGMENT_ROOT_RE.fullmatch(declared_root) is None
            ):
                issues.append(
                    "runs: campaign_segment_root_v2 is invalid on the campaign root"
                )
                continue
            try:
                expected_root = _compute_campaign_segment_root(
                    campaign_ref, segment_count, segment_commitments
                )
            except (TypeError, ValueError, UnicodeEncodeError, OverflowError):
                issues.append(
                    "runs: campaign segment commitments cannot be canonicalized"
                )
            else:
                if declared_root != expected_root:
                    issues.append(
                        "runs: campaign_segment_root_v2 does not bind the ordered segment run refs and bundle digests"
                    )


def _validate_revision_graph(bundles: list[Bundle], issues: list[str]) -> None:
    by_family: dict[str, dict[str, RevisionNode]] = defaultdict(dict)
    duplicates: dict[str, set[str]] = defaultdict(set)
    all_nodes = [node for bundle in bundles for node in bundle.revisions]
    for node in sorted(
        all_nodes, key=lambda item: (item.family, item.current, item.label)
    ):
        if _issues_full(issues):
            return
        if node.current in by_family[node.family]:
            duplicates[node.family].add(node.current)
            issues.append(
                f"{node.label}: {node.family} revision reference is not globally unique"
            )
        else:
            by_family[node.family][node.current] = node

    for family in sorted(duplicates):
        for current in duplicates[family]:
            first = by_family[family][current]
            issues.append(
                f"{first.label}: {family} revision reference is not globally unique"
            )

    for family, nodes in sorted(by_family.items()):
        if _issues_full(issues):
            return
        closed_by: dict[str, list[RevisionNode]] = defaultdict(list)
        edges: dict[str, set[str]] = {current: set() for current in nodes}
        successors: dict[str, set[str]] = defaultdict(set)
        for node in nodes.values():
            if _issues_full(issues):
                return
            for predecessor in node.predecessors:
                target = nodes.get(predecessor)
                if target is None:
                    issues.append(
                        f"{node.label}: {family} predecessor revision is not present in retained v2 history"
                    )
                    continue
                if target.transaction_ref == node.transaction_ref:
                    issues.append(
                        f"{node.label}: {family} predecessor must come from an earlier run"
                    )
                closed_by[predecessor].append(node)
                edges[node.current].add(predecessor)
                successors[predecessor].add(node.current)

                if (
                    node.entity_ref is not None
                    and target.entity_ref is not None
                    and node.kind not in {"split", "merge", "identity_reconciliation"}
                    and node.entity_ref != target.entity_ref
                ):
                    issues.append(
                        f"{node.label}: ordinary revision must preserve its entity reference"
                    )

        for closers in closed_by.values():
            transactions = {node.transaction_ref for node in closers}
            if len(transactions) > 1:
                for node in closers:
                    issues.append(
                        f"{node.label}: {family} predecessor revision was already closed by another run"
                    )
            elif len(closers) > 1 and not all(node.kind == "split" for node in closers):
                for node in closers:
                    issues.append(
                        f"{node.label}: {family} predecessor may have multiple successors only in one split"
                    )

        indegree = {
            current: len(predecessors) for current, predecessors in edges.items()
        }
        ready = [current for current, degree in indegree.items() if degree == 0]
        heapq.heapify(ready)
        visited = 0
        while ready:
            current = heapq.heappop(ready)
            visited += 1
            for successor in sorted(successors.get(current, ())):
                indegree[successor] -= 1
                if indegree[successor] == 0:
                    heapq.heappush(ready, successor)
        if visited != len(nodes):
            issues.append(f"runs: {family} revision graph contains a cycle")


def _collect_trend_comparison_state(
    bundle: Bundle,
    snapshots: dict[str, _TrendSnapshot],
) -> None:
    manifest = bundle.documents.get("manifest.json")
    summary = bundle.documents.get("summary.json")
    trend = bundle.documents.get("trend_report.json")
    if (
        not isinstance(manifest, dict)
        or not isinstance(summary, dict)
        or not isinstance(trend, dict)
        or manifest.get("publication_role") == "campaign_segment"
    ):
        return
    run_revision_ref = manifest.get("run_revision_ref")
    mode = manifest.get("mode")
    publication_time = _parse_coarse_timestamp(manifest.get("prepared_at"))
    window = manifest.get("window")
    supersession = manifest.get("supersession")
    strata = trend.get("strata")
    if (
        not isinstance(run_revision_ref, str)
        or RUN_REVISION_REF_RE.fullmatch(run_revision_ref) is None
        or not isinstance(mode, str)
        or mode not in MODES
        or publication_time is None
        or not isinstance(window, dict)
        or not isinstance(supersession, dict)
        or not isinstance(strata, list)
        or len(strata) > 128
    ):
        return
    supersedes_run_revision_refs = supersession.get(
        "supersedes_run_revision_refs"
    )
    if (
        not isinstance(supersedes_run_revision_refs, list)
        or len(supersedes_run_revision_refs) > 32
        or not all(
            isinstance(reference, str)
            and RUN_REVISION_REF_RE.fullmatch(reference) is not None
            for reference in supersedes_run_revision_refs
        )
    ):
        return
    window_start = _parse_coarse_timestamp(window.get("start"))
    window_end = _parse_coarse_timestamp(window.get("end"))
    if window_start is None or window_end is None or window_start >= window_end:
        return
    rates: dict[tuple[str, str, str], Decimal] = {}
    comparisons: list[_TrendComparison] = []
    for stratum in strata:
        if not isinstance(stratum, dict):
            continue
        policy_ref = stratum.get("policy_era_ref")
        model_ref = stratum.get("model_era_ref")
        metrics = stratum.get("metrics")
        if (
            not isinstance(policy_ref, str)
            or not isinstance(model_ref, str)
            or not isinstance(metrics, list)
        ):
            continue
        if len(metrics) > 64:
            continue
        for metric in metrics:
            if not isinstance(metric, dict) or metric.get("status") != "available":
                continue
            metric_id = metric.get("metric")
            metric_ref = metric.get("metric_ref")
            rate = metric.get("rate_per_100")
            if (
                not isinstance(metric_id, str)
                or not isinstance(metric_ref, str)
                or isinstance(rate, bool)
                or not isinstance(rate, (int, float))
            ):
                continue
            key = (policy_ref, model_ref, metric_id)
            rate_decimal = Decimal(str(rate))
            rates[key] = rate_decimal
            normalized = metric.get("normalized_change")
            if (
                not isinstance(normalized, dict)
                or normalized.get("status") != "available"
            ):
                continue
            prior_ref = normalized.get("prior_run_revision_ref")
            delta = normalized.get("delta_per_100")
            if (
                isinstance(prior_ref, str)
                and not isinstance(delta, bool)
                and isinstance(delta, (int, float))
            ):
                comparisons.append(
                    _TrendComparison(
                        metric_ref=metric_ref,
                        key=key,
                        prior_run_revision_ref=prior_ref,
                        claimed_delta=Decimal(str(delta)),
                    )
                )

    summary_comparison: _SummaryComparison | None = None
    change = summary.get("change_from_prior")
    if isinstance(change, dict) and change.get("status") == "available":
        prior_ref = change.get("prior_run_revision_ref")
        direction = change.get("direction")
        metric_refs = change.get("metric_refs")
        if (
            isinstance(prior_ref, str)
            and isinstance(direction, str)
            and isinstance(metric_refs, list)
            and len(metric_refs) <= 64
            and all(isinstance(metric_ref, str) for metric_ref in metric_refs)
        ):
            summary_comparison = _SummaryComparison(
                prior_run_revision_ref=prior_ref,
                direction=direction,
                metric_refs=tuple(metric_refs),
            )

    snapshots[run_revision_ref] = _TrendSnapshot(
        label=bundle.label,
        run_revision_ref=run_revision_ref,
        mode=mode,
        publication_time=publication_time,
        window_start=window_start,
        window_end=window_end,
        supersedes_run_revision_refs=tuple(supersedes_run_revision_refs),
        rates=rates,
        comparisons=tuple(comparisons),
        summary=summary_comparison,
    )


def _resolve_compatible_prior(
    current: _TrendSnapshot,
    prior_ref: str,
    snapshots: dict[str, _TrendSnapshot],
    superseders: dict[str, list[_TrendSnapshot]],
    artifact: str,
    issues: list[str],
) -> _TrendSnapshot | None:
    prior = snapshots.get(prior_ref)
    if prior is None or prior_ref == current.run_revision_ref:
        issues.append(
            f"{current.label}/{artifact}: prior run revision is not present as an eligible trend observation"
        )
        return None
    if prior.publication_time > current.publication_time:
        issues.append(
            f"{current.label}/{artifact}: prior run was not published by the current publication point"
        )
        return None
    if (
        prior.mode != current.mode
        or prior.window_start >= current.window_start
        or prior.window_end > current.window_start
    ):
        issues.append(
            f"{current.label}/{artifact}: prior run must share mode and use a strictly earlier non-overlapping window"
        )
        return None
    if any(
        replacement.publication_time <= current.publication_time
        for replacement in superseders.get(prior_ref, ())
    ):
        issues.append(
            f"{current.label}/{artifact}: prior run revision was not active at the current publication point"
        )
        return None
    return prior


def _exact_comparison_delta(
    current: _TrendSnapshot,
    prior: _TrendSnapshot,
    comparison: _TrendComparison,
) -> Decimal | None:
    current_rate = current.rates.get(comparison.key)
    prior_rate = prior.rates.get(comparison.key)
    if current_rate is None or prior_rate is None:
        return None
    return current_rate - prior_rate


def _trend_direction(metric_id: str, delta: Decimal) -> str:
    if delta == 0:
        return "unchanged"
    improves = delta < 0 if metric_id in NEGATIVE_TREND_METRICS else delta > 0
    return "improved" if improves else "regressed"


def _validate_trend_comparisons(
    snapshots: dict[str, _TrendSnapshot],
    issues: list[str],
) -> None:
    superseders: dict[str, list[_TrendSnapshot]] = defaultdict(list)
    for snapshot in snapshots.values():
        for predecessor in snapshot.supersedes_run_revision_refs:
            superseders[predecessor].append(snapshot)

    for current in snapshots.values():
        for comparison in current.comparisons:
            if _issues_full(issues):
                return
            prior = _resolve_compatible_prior(
                current,
                comparison.prior_run_revision_ref,
                snapshots,
                superseders,
                "trend_report.json",
                issues,
            )
            if prior is None:
                continue
            exact_delta = _exact_comparison_delta(current, prior, comparison)
            if exact_delta is None:
                issues.append(
                    f"{current.label}/trend_report.json: normalized change requires an available compatible prior metric"
                )
                continue
            if comparison.claimed_delta != exact_delta:
                issues.append(
                    f"{current.label}/trend_report.json: normalized change delta must exactly match the compatible prior metric"
                )

        summary = current.summary
        if summary is None or _issues_full(issues):
            continue
        prior = _resolve_compatible_prior(
            current,
            summary.prior_run_revision_ref,
            snapshots,
            superseders,
            "summary.json",
            issues,
        )
        comparisons_by_ref: dict[str, list[_TrendComparison]] = defaultdict(list)
        for comparison in current.comparisons:
            comparisons_by_ref[comparison.metric_ref].append(comparison)

        exact_directions: list[str] = []
        complete = prior is not None
        for metric_ref in summary.metric_refs:
            matches = comparisons_by_ref.get(metric_ref, [])
            if len(matches) != 1:
                issues.append(
                    f"{current.label}/summary.json: metric_refs must resolve uniquely to available normalized trend comparisons"
                )
                complete = False
                continue
            comparison = matches[0]
            if comparison.prior_run_revision_ref != summary.prior_run_revision_ref:
                issues.append(
                    f"{current.label}/summary.json: change_from_prior must bind to the same prior comparison as trend_report.json"
                )
                complete = False
                continue
            if prior is None:
                complete = False
                continue
            exact_delta = _exact_comparison_delta(current, prior, comparison)
            if exact_delta is None:
                issues.append(
                    f"{current.label}/summary.json: referenced trend comparison lacks a compatible prior metric"
                )
                complete = False
                continue
            exact_directions.append(_trend_direction(comparison.key[2], exact_delta))

        if not complete or not exact_directions:
            continue
        direction_set = set(exact_directions)
        if {"improved", "regressed"}.issubset(direction_set):
            issues.append(
                f"{current.label}/summary.json: change_from_prior cannot collapse mixed exact normalized deltas"
            )
            continue
        if "improved" in direction_set:
            expected_direction = "improved"
        elif "regressed" in direction_set:
            expected_direction = "regressed"
        else:
            expected_direction = "unchanged"
        if summary.direction != expected_direction:
            issues.append(
                f"{current.label}/summary.json: change_from_prior direction must match exact normalized trend deltas"
            )


def validate_v2_runs(
    root: Path, visible_files: Sequence[Path] | None = None
) -> list[str]:
    """Validate immutable Session Retrospective v2 retained-run bundles.

    Diagnostics intentionally avoid JSON values and unvalidated path components.
    The returned list is de-duplicated and lexicographically sorted.
    """

    root = Path(os.path.abspath(os.fspath(root)))
    try:
        root_descriptor = _open_validation_root(root)
    except OSError as exc:
        if exc.errno in {errno.ENOENT, errno.ENOTDIR}:
            return ["root must be an existing directory"]
        return ["root could not be opened safely"]

    issues = _IssueCollector()
    try:
        validators = _load_schema_validators()
        if validators is None:
            issues.append(SCHEMA_UNAVAILABLE_ISSUE)
            return sorted(issues)
        privacy_validator = _load_privacy_validator()
        if privacy_validator is None:
            issues.append(PRIVACY_UNAVAILABLE_ISSUE)
            return sorted(issues)

        bundles = _discover_bundles(root, root_descriptor, visible_files, issues)
        revision_count = 0
        work_limit_reached = False
        trend_snapshots: dict[str, _TrendSnapshot] = {}
        for bundle in bundles:
            if _issues_full(issues):
                break
            budget = _ReadBudget(MAX_BUNDLE_ARTIFACT_BYTES)
            _validate_bundle(
                bundle,
                root_descriptor,
                issues,
                validators,
                privacy_validator,
                budget,
            )
            revision_count += len(bundle.revisions)
            _collect_trend_comparison_state(bundle, trend_snapshots)
            bundle.raw.clear()
            bundle.documents.clear()
            bundle.rows.clear()
            if revision_count > MAX_HISTORY_REVISIONS:
                issues.append(VALIDATION_WORK_LIMIT_ISSUE)
                work_limit_reached = True
                break
        if not _issues_full(issues) and not work_limit_reached:
            _validate_run_supersession(bundles, issues)
        if not _issues_full(issues) and not work_limit_reached:
            _validate_campaign_consistency(bundles, issues)
        if not _issues_full(issues) and not work_limit_reached:
            _validate_trend_comparisons(trend_snapshots, issues)
        if not _issues_full(issues) and not work_limit_reached:
            _validate_revision_graph(bundles, issues)
        return sorted(issues)
    finally:
        os.close(root_descriptor)


__all__ = ["validate_v2_runs"]
