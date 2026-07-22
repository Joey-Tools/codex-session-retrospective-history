#!/usr/bin/env python3
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import base64
import binascii
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
import sqlite3
import stat
import tempfile
from typing import Any, Callable, Iterable, Iterator

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
MODEL_EXECUTION_KINDS = frozenset({"retrospective"})
PUBLICATION_ROLES = frozenset({"standalone", "campaign_segment", "campaign_root"})
CAMPAIGN_SEGMENT_REVISION_FAMILIES = frozenset(
    {
        "run",
        "coverage",
        "summary",
        "trend",
        "gap",
        "episode",
        "topic",
        "turn_finding",
    }
)
CAMPAIGN_SEGMENT_AGGREGATE_FAMILIES = frozenset({"coverage", "summary", "trend"})
CAMPAIGN_SEGMENT_MANIFEST_SUPERSESSION_FIELDS = {
    "run": "supersedes_run_revision_refs",
    "episode": "supersedes_episode_revision_refs",
    "topic": "supersedes_topic_revision_refs",
    "turn_finding": "supersedes_turn_finding_revision_refs",
}
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
EPISODE_REVISION_OPERATIONS = frozenset(
    {"create", "extend", "backfill", "split", "merge"}
)
EPISODE_OPERATION_REVISION_KINDS = {
    "create": "initial",
    "extend": "correction",
    "backfill": "backfill",
    "split": "split",
    "merge": "merge",
}
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
RUN_ID_RE = re.compile(r"^[a-z2-7]{25}[aeimquy4]$")
RUN_REF_RE = re.compile(r"^run_ref_v2:[a-z2-7]{25}[aeimquy4]$")
RUN_REVISION_REF_RE = re.compile(r"^run_revision_ref_v2:[0-9a-f]{32}$")
KEY_ID_RE = re.compile(r"^key_id_v2:[0-9a-f]{16}$")
POLICY_ERA_REF_RE = re.compile(r"^policy_era_ref_v2:[0-9a-f]{32}$")
MODEL_ERA_REF_RE = re.compile(r"^model_era_ref_v2:[0-9a-f]{32}$")
DIGEST_RE = re.compile(r"^retained_bundle_digest_v2:sha256:[0-9a-f]{64}$")
PRODUCTION_CONFIGURATION_ROOT_RE = re.compile(
    r"^production_configuration_root_v2:sha256:[0-9a-f]{64}$"
)
CAMPAIGN_SEGMENT_ROOT_RE = re.compile(r"^campaign_segment_root_v2:sha256:[0-9a-f]{64}$")
EPISODE_ANCHOR_RE = re.compile(r"^episode_anchor_v2:[0-9a-f]{32}$")
EPISODE_LINEAGE_ID_RE = re.compile(r"^episode_lineage_id_v2:[0-9a-f]{32}$")
EPISODE_TRANSITION_GROUP_ID_RE = re.compile(
    r"^episode_transition_group_id_v2:[0-9a-f]{32}$"
)
EPISODE_MEMBER_TURN_ROOT_RE = re.compile(
    r"^episode_member_turn_root_v2:sha256:[0-9a-f]{64}$"
)
EPISODE_CONTENT_DIGEST_RE = re.compile(
    r"^episode_generalized_content_v2:sha256:[0-9a-f]{64}$"
)

EPISODE_GENERALIZED_CONTENT_FIELDS = (
    "host_ref",
    "session_ref",
    "workstream_ref",
    "primary_topic_ref",
    "continuation_of_episode_ref",
    "start_time",
    "end_time",
    "meaningful_turn_count",
    "context_turn_count",
    "review_disposition",
    "taxonomy",
    "summary",
    "strengths",
    "findings",
    "recommendations",
    "evidence_refs",
    "gap_refs",
    "confidence",
    "policy_era_ref",
    "model_era_ref",
)

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
MAX_DIRECTORY_ENTRIES = 4096
MAX_DISCOVERY_PAGE_FILES = 4096
MAX_BUNDLE_PAGE_SIZE = 512
MAX_INDEX_QUERY_ROWS = 512
MAX_DISCOVERY_PATH_BYTES = 256
MAX_VISIBLE_PATH_BYTES = 4096
MAX_JSONL_ROWS = 100_000
MAX_BUNDLE_JSONL_ROWS = 200_000
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 200_000
MAX_JSON_CONTAINER_ITEMS = 100_000
MAX_SCHEMA_ERRORS_PER_INSTANCE = 8
MAX_DIAGNOSTICS = 64
READ_CHUNK_BYTES = 64 * 1024

RUN_ARTIFACT_PATH_COMPONENT_COUNT = 5

SCHEMA_UNAVAILABLE_ISSUE = "schema: Draft 2020-12 validation is unavailable"
PRIVACY_UNAVAILABLE_ISSUE = "privacy: retained v2 privacy validation is unavailable"
DIAGNOSTIC_LIMIT_ISSUE = "validation: additional issues omitted"
DISCOVERY_LIMIT_ISSUE = "runs: discovery work limit exceeded"
PATH_COLLISION_ISSUE = "runs: run_id is reused by another retained-run path"
HISTORY_IDENTITY_ISSUE = (
    "runs: retained history must use one identity key generation; "
    "explicit generation transitions are unsupported"
)
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
    "manifest_projection": "omit-digest-and-publisher-attestation-v2",
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
        "key_id",
        "prepared_at",
        "status",
        "gap_summary",
        "supersession",
        "artifact_inventory",
        "retained_bundle_digest_v2",
        "publisher_attestation",
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
class EpisodePredecessorMetadata:
    revision_ref: str
    lineage_id: str
    anchor: str
    segmentation_major: int
    policy_major: int
    member_turn_root: str
    member_turn_count: int


@dataclass(frozen=True)
class RevisionNode:
    family: str
    current: str
    predecessors: tuple[str, ...]
    kind: str
    entity_ref: str | None
    transaction_ref: str
    label: str
    episode_operation: str | None = None
    episode_lineage_id: str | None = None
    episode_anchor: str | None = None
    segmentation_major: int | None = None
    episode_policy_major: int | None = None
    member_turn_root: str | None = None
    member_turn_count: int | None = None
    member_turn_refs: tuple[str, ...] = ()
    presentation_turn_refs: tuple[str, ...] = ()
    transition_group_id: str | None = None
    transition_group_ordinal: int | None = None
    generalized_content_digest: str | None = None
    predecessor_lineage_metadata: tuple[EpisodePredecessorMetadata, ...] = ()
    backfill_membership_evidence: tuple[tuple[str, str], ...] = ()


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


class _ValidationIndex:
    """Disk-backed index for bounded discovery and cross-bundle validation."""

    def __init__(self, path: Path) -> None:
        self.connection = sqlite3.connect(path)
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = OFF")
        self.connection.execute("PRAGMA synchronous = OFF")
        self.connection.execute("PRAGMA temp_store = FILE")
        self.connection.execute("PRAGMA trusted_schema = OFF")
        self.connection.executescript(
            """
            CREATE TABLE discovered_bundles (
                id INTEGER PRIMARY KEY,
                mode TEXT NOT NULL,
                window_component TEXT NOT NULL,
                run_id TEXT NOT NULL,
                UNIQUE (mode, window_component, run_id)
            );
            CREATE TABLE artifacts (
                bundle_id INTEGER NOT NULL REFERENCES discovered_bundles(id),
                basename TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                PRIMARY KEY (bundle_id, basename)
            ) WITHOUT ROWID;
            CREATE TABLE run_owners (
                run_id TEXT PRIMARY KEY,
                mode TEXT NOT NULL,
                window_component TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE bundle_facts (
                bundle_id INTEGER PRIMARY KEY REFERENCES discovered_bundles(id),
                label TEXT NOT NULL,
                mode TEXT NOT NULL,
                window_component TEXT NOT NULL,
                run_id TEXT NOT NULL,
                manifest_path TEXT,
                run_revision_ref TEXT,
                run_ref TEXT,
                bundle_digest TEXT,
                status TEXT,
                supersession_reason TEXT,
                publication_role TEXT,
                campaign_ref TEXT,
                campaign_reason TEXT,
                campaign_segment_count INTEGER,
                segment_ordinal INTEGER,
                campaign_segment_root TEXT,
                key_id TEXT,
                generation_ref TEXT,
                segment_has_head_successor INTEGER NOT NULL
            );
            CREATE TABLE revisions (
                id INTEGER PRIMARY KEY,
                bundle_id INTEGER NOT NULL REFERENCES discovered_bundles(id),
                family TEXT NOT NULL,
                current_ref TEXT NOT NULL,
                kind TEXT NOT NULL,
                entity_ref TEXT,
                transaction_ref TEXT NOT NULL,
                label TEXT NOT NULL
            );
            CREATE TABLE revision_predecessors (
                revision_id INTEGER NOT NULL REFERENCES revisions(id),
                family TEXT NOT NULL,
                predecessor_ref TEXT NOT NULL
            );
            CREATE TABLE episode_revision_facts (
                revision_id INTEGER PRIMARY KEY REFERENCES revisions(id),
                operation TEXT,
                lineage_id TEXT,
                anchor TEXT,
                segmentation_major INTEGER,
                policy_major INTEGER,
                member_turn_root TEXT,
                member_turn_count INTEGER,
                transition_group_id TEXT,
                transition_group_ordinal INTEGER,
                content_digest TEXT
            );
            CREATE TABLE episode_members (
                revision_id INTEGER NOT NULL REFERENCES revisions(id),
                turn_ref TEXT NOT NULL,
                presentation_ordinal INTEGER NOT NULL,
                PRIMARY KEY (revision_id, turn_ref)
            ) WITHOUT ROWID;
            CREATE TABLE episode_predecessor_metadata (
                revision_id INTEGER NOT NULL REFERENCES revisions(id),
                predecessor_ref TEXT NOT NULL,
                lineage_id TEXT NOT NULL,
                anchor TEXT NOT NULL,
                segmentation_major INTEGER NOT NULL,
                policy_major INTEGER NOT NULL,
                member_turn_root TEXT NOT NULL,
                member_turn_count INTEGER NOT NULL,
                PRIMARY KEY (revision_id, predecessor_ref)
            ) WITHOUT ROWID;
            CREATE TABLE episode_backfill_evidence (
                revision_id INTEGER NOT NULL REFERENCES revisions(id),
                turn_ref TEXT NOT NULL,
                gap_ref TEXT NOT NULL,
                PRIMARY KEY (revision_id, turn_ref, gap_ref)
            ) WITHOUT ROWID;
            CREATE TABLE run_supersession (
                bundle_id INTEGER NOT NULL REFERENCES discovered_bundles(id),
                target_ref TEXT NOT NULL
            );
            CREATE TABLE manifest_supersession (
                bundle_id INTEGER NOT NULL REFERENCES discovered_bundles(id),
                family TEXT NOT NULL,
                target_ref TEXT NOT NULL
            );
            CREATE TABLE campaign_tree_refs (
                bundle_id INTEGER NOT NULL REFERENCES discovered_bundles(id),
                ref_kind TEXT NOT NULL,
                tree_ref TEXT NOT NULL
            );
            CREATE TABLE head_binding_refs (
                bundle_id INTEGER NOT NULL REFERENCES discovered_bundles(id),
                binding_ref TEXT NOT NULL
            );
            CREATE TABLE trend_snapshots (
                id INTEGER PRIMARY KEY,
                bundle_id INTEGER NOT NULL REFERENCES discovered_bundles(id),
                run_revision_ref TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE trend_supersession (
                snapshot_id INTEGER NOT NULL REFERENCES trend_snapshots(id),
                predecessor_ref TEXT NOT NULL
            );
            CREATE INDEX artifacts_bundle ON artifacts(bundle_id, basename);
            CREATE INDEX facts_run_revision ON bundle_facts(run_revision_ref);
            CREATE INDEX facts_campaign ON bundle_facts(campaign_ref, publication_role);
            CREATE INDEX revisions_identity ON revisions(family, current_ref);
            CREATE INDEX revisions_bundle_family ON revisions(bundle_id, family);
            CREATE INDEX predecessors_target ON revision_predecessors(family, predecessor_ref);
            CREATE INDEX predecessors_revision ON revision_predecessors(revision_id);
            CREATE INDEX episode_groups
                ON episode_revision_facts(transition_group_id, operation);
            CREATE INDEX episode_lineages
                ON episode_revision_facts(lineage_id, operation);
            CREATE INDEX episode_member_owners ON episode_members(turn_ref, revision_id);
            CREATE INDEX run_supersession_target ON run_supersession(target_ref);
            CREATE INDEX manifest_supersession_target
                ON manifest_supersession(family, target_ref);
            CREATE INDEX campaign_tree_ref_identity
                ON campaign_tree_refs(ref_kind, tree_ref);
            CREATE INDEX head_binding_ref_identity ON head_binding_refs(binding_ref);
            CREATE INDEX trend_snapshot_revision ON trend_snapshots(run_revision_ref);
            CREATE INDEX trend_supersession_target ON trend_supersession(predecessor_ref);
            """
        )
        self._pending_artifacts = 0

    def close(self) -> None:
        self.connection.close()

    def flush_discovery_page(self) -> None:
        self.connection.commit()
        self._pending_artifacts = 0

    def add_artifact(self, parsed: _PhysicalArtifactPath) -> bool:
        """Index one path and return whether its run ID has another owner."""

        run_owner = self.connection.execute(
            "SELECT mode, window_component FROM run_owners WHERE run_id = ?",
            (parsed.run_id,),
        ).fetchone()
        collision = run_owner is not None and tuple(run_owner) != (
            parsed.mode,
            parsed.window_component,
        )
        if run_owner is None:
            self.connection.execute(
                "INSERT INTO run_owners VALUES (?, ?, ?)",
                (parsed.run_id, parsed.mode, parsed.window_component),
            )

        self.connection.execute(
            """
            INSERT OR IGNORE INTO discovered_bundles(mode, window_component, run_id)
            VALUES (?, ?, ?)
            """,
            (parsed.mode, parsed.window_component, parsed.run_id),
        )
        bundle_id = self.connection.execute(
            """
            SELECT id FROM discovered_bundles
            WHERE mode = ? AND window_component = ? AND run_id = ?
            """,
            (parsed.mode, parsed.window_component, parsed.run_id),
        ).fetchone()[0]
        cursor = self.connection.execute(
            """
            INSERT OR IGNORE INTO artifacts(bundle_id, basename, relative_path)
            VALUES (?, ?, ?)
            """,
            (bundle_id, parsed.basename, parsed.relative.as_posix()),
        )
        if cursor.rowcount:
            self._pending_artifacts += 1
            if self._pending_artifacts >= MAX_DISCOVERY_PAGE_FILES:
                self.flush_discovery_page()
        return collision

    def iter_bundle_pages(self) -> Iterator[list[tuple[int, Bundle]]]:
        cursor_key: tuple[str, str, str] | None = None
        while True:
            if cursor_key is None:
                rows = self.connection.execute(
                    """
                    SELECT id, mode, window_component, run_id
                    FROM discovered_bundles
                    ORDER BY mode, window_component, run_id
                    LIMIT ?
                    """,
                    (MAX_BUNDLE_PAGE_SIZE,),
                ).fetchall()
            else:
                rows = self.connection.execute(
                    """
                    SELECT id, mode, window_component, run_id
                    FROM discovered_bundles
                    WHERE (mode, window_component, run_id) > (?, ?, ?)
                    ORDER BY mode, window_component, run_id
                    LIMIT ?
                    """,
                    (*cursor_key, MAX_BUNDLE_PAGE_SIZE),
                ).fetchall()
            if not rows:
                return
            page: list[tuple[int, Bundle]] = []
            for bundle_id, mode, window_component, run_id in rows:
                files = {
                    basename: Path(relative_path)
                    for basename, relative_path in self.connection.execute(
                        """
                        SELECT basename, relative_path FROM artifacts
                        WHERE bundle_id = ? ORDER BY basename
                        """,
                        (bundle_id,),
                    )
                }
                parts = _bundle_directory_parts(mode, window_component, run_id)
                page.append(
                    (
                        bundle_id,
                        Bundle(
                            "/".join(parts),
                            mode,
                            window_component,
                            run_id,
                            files,
                            physical_parts=parts,
                        ),
                    )
                )
            cursor_key = (rows[-1][1], rows[-1][2], rows[-1][3])
            yield page

    def record_bundle(self, bundle_id: int, bundle: Bundle) -> None:
        manifest = bundle.manifest if isinstance(bundle.manifest, dict) else {}
        supersession = manifest.get("supersession")
        if not isinstance(supersession, dict):
            supersession = {}
        segment_metadata = manifest.get("campaign_segment_metadata")
        if not isinstance(segment_metadata, dict):
            segment_metadata = {}
        head_bindings = manifest.get("head_bindings")
        if not isinstance(head_bindings, dict):
            head_bindings = {}

        def text_value(value: Any) -> str | None:
            return value if isinstance(value, str) else None

        def integer_value(value: Any) -> int | None:
            return value if _is_int(value) else None

        has_head_successor = False
        for field_name, value in head_bindings.items():
            if field_name == "bound_quarantine_generation_ref":
                continue
            if field_name == "cursor_heads":
                has_head_successor = value not in (None, [])
            else:
                has_head_successor = value is not None
            if has_head_successor:
                break

        self.connection.execute(
            """
            INSERT INTO bundle_facts VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                bundle_id,
                bundle.label,
                bundle.mode,
                bundle.window_component,
                bundle.run_id,
                bundle.files.get("manifest.json", None).as_posix()
                if "manifest.json" in bundle.files
                else None,
                text_value(manifest.get("run_revision_ref")),
                text_value(manifest.get("run_ref")),
                text_value(manifest.get("retained_bundle_digest_v2")),
                text_value(manifest.get("status")),
                text_value(supersession.get("reason")),
                text_value(manifest.get("publication_role")),
                text_value(manifest.get("campaign_ref")),
                text_value(manifest.get("publication_campaign_reason")),
                integer_value(manifest.get("campaign_segment_count")),
                integer_value(segment_metadata.get("segment_ordinal")),
                text_value(manifest.get("campaign_segment_root_v2")),
                text_value(manifest.get("key_id")),
                text_value(head_bindings.get("bound_quarantine_generation_ref")),
                int(has_head_successor),
            ),
        )

        for node in bundle.revisions:
            revision_cursor = self.connection.execute(
                """
                INSERT INTO revisions(
                    bundle_id, family, current_ref, kind, entity_ref,
                    transaction_ref, label
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    bundle_id,
                    node.family,
                    node.current,
                    node.kind,
                    node.entity_ref,
                    node.transaction_ref,
                    node.label,
                ),
            )
            revision_id = revision_cursor.lastrowid
            self.connection.executemany(
                """
                INSERT INTO revision_predecessors(
                    revision_id, family, predecessor_ref
                ) VALUES (?, ?, ?)
                """,
                (
                    (revision_id, node.family, predecessor)
                    for predecessor in node.predecessors
                ),
            )
            if node.family == "episode":
                self.connection.execute(
                    """
                    INSERT INTO episode_revision_facts VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        revision_id,
                        node.episode_operation,
                        node.episode_lineage_id,
                        node.episode_anchor,
                        node.segmentation_major,
                        node.episode_policy_major,
                        node.member_turn_root,
                        node.member_turn_count,
                        node.transition_group_id,
                        node.transition_group_ordinal,
                        node.generalized_content_digest,
                    ),
                )
                self.connection.executemany(
                    """
                    INSERT OR IGNORE INTO episode_members(
                        revision_id, turn_ref, presentation_ordinal
                    ) VALUES (?, ?, ?)
                    """,
                    (
                        (revision_id, turn_ref, ordinal)
                        for ordinal, turn_ref in enumerate(
                            node.presentation_turn_refs, start=1
                        )
                    ),
                )
                self.connection.executemany(
                    """
                    INSERT OR IGNORE INTO episode_predecessor_metadata VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        (
                            revision_id,
                            metadata.revision_ref,
                            metadata.lineage_id,
                            metadata.anchor,
                            metadata.segmentation_major,
                            metadata.policy_major,
                            metadata.member_turn_root,
                            metadata.member_turn_count,
                        )
                        for metadata in node.predecessor_lineage_metadata
                    ),
                )
                self.connection.executemany(
                    """
                    INSERT OR IGNORE INTO episode_backfill_evidence VALUES (?, ?, ?)
                    """,
                    (
                        (revision_id, turn_ref, gap_ref)
                        for turn_ref, gap_ref in node.backfill_membership_evidence
                    ),
                )

        run_targets = supersession.get("supersedes_run_revision_refs")
        if isinstance(run_targets, list):
            self.connection.executemany(
                "INSERT INTO run_supersession VALUES (?, ?)",
                (
                    (bundle_id, target)
                    for target in run_targets
                    if isinstance(target, str)
                ),
            )
        for family, field_name in CAMPAIGN_SEGMENT_MANIFEST_SUPERSESSION_FIELDS.items():
            targets = supersession.get(field_name)
            if not isinstance(targets, list):
                continue
            self.connection.executemany(
                "INSERT INTO manifest_supersession VALUES (?, ?, ?)",
                (
                    (bundle_id, family, target)
                    for target in targets
                    if isinstance(target, str)
                ),
            )

        for ref_kind, field_name in (
            ("leaf", "leaf_root_refs"),
            ("page", "page_root_refs"),
        ):
            values = segment_metadata.get(field_name)
            if isinstance(values, list):
                self.connection.executemany(
                    "INSERT INTO campaign_tree_refs VALUES (?, ?, ?)",
                    (
                        (bundle_id, ref_kind, value)
                        for value in values
                        if isinstance(value, str)
                    ),
                )

        stack: list[Any] = [head_bindings]
        visited = 0
        binding_refs: list[tuple[int, str]] = []
        while stack and visited <= MAX_JSON_NODES:
            current = stack.pop()
            visited += 1
            if isinstance(current, dict):
                stack.extend(current.values())
            elif isinstance(current, list):
                stack.extend(current)
            elif isinstance(current, str):
                binding_refs.append((bundle_id, current))
        self.connection.executemany(
            "INSERT INTO head_binding_refs VALUES (?, ?)", binding_refs
        )

    def record_trend_snapshot(self, bundle_id: int, snapshot: _TrendSnapshot) -> None:
        payload = json.dumps(
            {
                "label": snapshot.label,
                "run_revision_ref": snapshot.run_revision_ref,
                "mode": snapshot.mode,
                "publication_time": snapshot.publication_time.isoformat(),
                "window_start": snapshot.window_start.isoformat(),
                "window_end": snapshot.window_end.isoformat(),
                "supersedes_run_revision_refs": list(
                    snapshot.supersedes_run_revision_refs
                ),
                "rates": [
                    [*key, str(value)] for key, value in sorted(snapshot.rates.items())
                ],
                "comparisons": [
                    {
                        "metric_ref": comparison.metric_ref,
                        "key": list(comparison.key),
                        "prior_run_revision_ref": comparison.prior_run_revision_ref,
                        "claimed_delta": str(comparison.claimed_delta),
                    }
                    for comparison in snapshot.comparisons
                ],
                "summary": None
                if snapshot.summary is None
                else {
                    "prior_run_revision_ref": snapshot.summary.prior_run_revision_ref,
                    "direction": snapshot.summary.direction,
                    "metric_refs": list(snapshot.summary.metric_refs),
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        cursor = self.connection.execute(
            """
            INSERT INTO trend_snapshots(bundle_id, run_revision_ref, payload)
            VALUES (?, ?, ?)
            """,
            (bundle_id, snapshot.run_revision_ref, payload),
        )
        snapshot_id = cursor.lastrowid
        self.connection.executemany(
            "INSERT INTO trend_supersession VALUES (?, ?)",
            (
                (snapshot_id, predecessor)
                for predecessor in snapshot.supersedes_run_revision_refs
            ),
        )

    def iter_manifest_paths(self) -> Iterator[Path]:
        cursor = self.connection.execute(
            """
            SELECT manifest_path FROM bundle_facts
            WHERE manifest_path IS NOT NULL
            ORDER BY mode, window_component, run_id
            """
        )
        while True:
            rows = cursor.fetchmany(MAX_INDEX_QUERY_ROWS)
            if not rows:
                return
            for (manifest_path,) in rows:
                yield Path(manifest_path)


class _ManifestInventory:
    """Re-iterable disk spool for admitted manifests with bounded memory."""

    def __init__(self, paths: Iterable[Path]) -> None:
        self._stream = tempfile.TemporaryFile(mode="w+t", encoding="utf-8")
        self._count = 0
        for path in paths:
            self._stream.write(path.as_posix())
            self._stream.write("\n")
            self._count += 1
        self._stream.flush()

    def __iter__(self) -> Iterator[Path]:
        self._stream.seek(0)
        for line in self._stream:
            yield Path(line.removesuffix("\n"))

    def __len__(self) -> int:
        return self._count

    def close(self) -> None:
        self._stream.close()


@dataclass(frozen=True)
class _PhysicalArtifactPath:
    relative: Path
    mode: str
    window_component: str
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
    validate_bundle: Callable[[dict[Path, bytes]], dict[str, list[str]]]
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
        if hasattr(module, "RUN_REF_RE"):
            module.RUN_REF_RE = RUN_REF_RE
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
                if field == "run_id" and _valid_run_id(value):
                    return (True, True, False)
                if field == "run_ref" and _valid_run_ref(value):
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
        validator = getattr(module, "validate_v2_bundle_privacy", None)
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


def _compute_retained_bundle_digest(
    raw: dict[str, bytes], manifest: dict[str, Any]
) -> str:
    projection = dict(manifest)
    projection.pop("retained_bundle_digest_v2")
    projection.pop("publisher_attestation")
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


def _valid_run_id(value: str) -> bool:
    if RUN_ID_RE.fullmatch(value) is None:
        return False
    try:
        decoded = base64.b32decode(value.upper() + "======", casefold=False)
    except (binascii.Error, ValueError):
        return False
    canonical = base64.b32encode(decoded).decode("ascii").lower().rstrip("=")
    return len(decoded) == 16 and canonical == value


def _valid_run_ref(value: str) -> bool:
    return RUN_REF_RE.fullmatch(value) is not None and _valid_run_id(
        value.removeprefix("run_ref_v2:")
    )


def _bundle_directory_parts(
    mode: str, window_component: str, run_id: str
) -> tuple[str, ...]:
    return ("runs", mode, window_component, run_id)


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
    window_component = parts[2]
    run_id = parts[3]
    basename = parts[-1]
    if mode not in MODES or not _valid_window_component(window_component):
        return None
    if not _valid_run_id(run_id):
        return None
    return _PhysicalArtifactPath(
        relative=relative,
        mode=mode,
        window_component=window_component,
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
        requires_non_empty = (
            field_name != "model_eras"
            or manifest.get("execution_kind") in MODEL_EXECUTION_KINDS
        )
        if (
            not isinstance(rows, list)
            or (requires_non_empty and not rows)
            or not all(isinstance(row, dict) for row in rows)
        ):
            requirement = "a non-empty" if requires_non_empty else "an"
            issues.append(
                f"{label}: {field_name} must be {requirement} array of objects"
            )
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
    if len(parts) >= 3 and not _valid_window_component(parts[2]):
        return False
    if len(parts) >= 4 and not _valid_run_id(parts[3]):
        return False
    return True


def _index_run_files_no_follow(
    root_descriptor: int,
    index: _ValidationIndex,
    issues: list[str],
) -> None:
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
        return
    except OSError:
        issues.append("runs/[invalid]: invalid v2 retained-run path")
        return

    invalid_layout = False
    stopped = False
    collision = False

    def walk(directory_descriptor: int, parent_parts: tuple[str, ...]) -> None:
        nonlocal collision, invalid_layout, stopped
        if stopped or _issues_full(issues):
            return
        try:
            iterator = os.scandir(directory_descriptor)
        except OSError:
            invalid_layout = True
            return
        with iterator:
            directory_entries = 0
            for entry in iterator:
                if stopped or _issues_full(issues):
                    break
                directory_entries += 1
                if directory_entries > MAX_DIRECTORY_ENTRIES:
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
                    parsed = _parse_physical_artifact_path(relative)
                    if parsed is None:
                        invalid_layout = True
                        continue
                    collision = index.add_artifact(parsed) or collision
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
    index.flush_discovery_page()
    if invalid_layout:
        issues.append("runs/[invalid]: invalid v2 retained-run path")
    if collision:
        issues.append(PATH_COLLISION_ISSUE)


def _index_visible_run_files(
    root: Path,
    visible_files: Iterable[Path] | None,
    index: _ValidationIndex,
    issues: list[str],
) -> None:
    assert visible_files is not None
    outside_root = False
    invalid_path = False
    invalid_run_path = False
    collision = False
    for supplied in visible_files:
        if _issues_full(issues):
            break
        try:
            supplied_value = os.fspath(supplied)
            if len(os.fsencode(supplied_value)) > MAX_VISIBLE_PATH_BYTES:
                invalid_path = True
                continue
            supplied_path = Path(supplied_value)
            candidate = (
                supplied_path if supplied_path.is_absolute() else root / supplied_path
            )
            absolute = Path(os.path.abspath(candidate))
            relative = absolute.relative_to(root)
        except (OSError, TypeError, ValueError):
            outside_root = True
            continue
        if not relative.parts or relative.parts[0] != "runs":
            continue
        if (
            len(relative.parts) != RUN_ARTIFACT_PATH_COMPONENT_COUNT
            or relative.parts[1] not in MODES
        ):
            invalid_run_path = True
            continue
        try:
            encoded_relative = relative.as_posix().encode("ascii")
        except UnicodeEncodeError:
            invalid_run_path = True
            continue
        if len(encoded_relative) > MAX_DISCOVERY_PATH_BYTES:
            invalid_run_path = True
            continue
        parsed = _parse_physical_artifact_path(relative)
        if parsed is None:
            invalid_run_path = True
            continue
        collision = index.add_artifact(parsed) or collision
    index.flush_discovery_page()
    if outside_root:
        issues.append("visible file list contains a path outside the validation root")
    if invalid_path:
        issues.append("visible file list contains an invalid or oversized path")
    if invalid_run_path:
        issues.append("runs/[invalid]: invalid v2 retained-run path")
    if collision:
        issues.append(PATH_COLLISION_ISSUE)


def _populate_validation_index(
    root: Path,
    root_descriptor: int,
    visible_files: Iterable[Path] | None,
    index: _ValidationIndex,
    issues: list[str],
) -> None:
    if visible_files is None:
        _index_run_files_no_follow(root_descriptor, index, issues)
    else:
        _index_visible_run_files(root, visible_files, index, issues)


def _discover_bundles(
    root: Path,
    root_descriptor: int,
    visible_files: Iterable[Path] | None,
    issues: list[str],
) -> list[Bundle]:
    # The compatibility helper is used only for one-bundle publication commits.
    # Whole-history validation consumes iter_bundle_pages() directly.
    with tempfile.TemporaryDirectory(
        prefix="retrospective-history-v2-discovery-"
    ) as temporary:
        index = _ValidationIndex(Path(temporary) / "index.sqlite3")
        try:
            _populate_validation_index(
                root, root_descriptor, visible_files, index, issues
            )
            pages = index.iter_bundle_pages()
            first_page = next(pages, [])
            if next(pages, None) is not None:
                issues.append(VALIDATION_WORK_LIMIT_ISSUE)
                return []
            bundles = [bundle for _, bundle in first_page]
            for bundle in bundles:
                if frozenset(bundle.files) != ARTIFACT_BASENAME_SET:
                    issues.append(
                        f"{bundle.label}: run directory must contain exactly the eight required artifacts"
                    )
            return bundles
        finally:
            index.close()


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

        if not _bundle_directory_chain_matches(
            root_descriptor, bundle, directory_chain
        ):
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
    artifacts = {
        Path(bundle.label) / basename: bundle.raw[basename]
        for basename in ARTIFACT_BASENAMES
        if basename in bundle.raw
    }
    try:
        findings = privacy_validator.validate_bundle(artifacts)
    except Exception:
        issues.append(PRIVACY_UNAVAILABLE_ISSUE)
        return
    if not isinstance(findings, dict) or any(
        not isinstance(scope, str)
        or scope not in {*ARTIFACT_BASENAME_SET, "__bundle__"}
        or not isinstance(scope_findings, list)
        or any(
            not isinstance(finding, str)
            or finding not in privacy_validator.allowed_issues
            for finding in scope_findings
        )
        for scope, scope_findings in findings.items()
    ):
        issues.append(PRIVACY_UNAVAILABLE_ISSUE)
        return
    for scope in (*ARTIFACT_BASENAMES, "__bundle__"):
        prefix = bundle.label if scope == "__bundle__" else f"{bundle.label}/{scope}"
        for finding in findings.get(scope, []):
            if _issues_full(issues):
                return
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


def _episode_member_turn_root(turn_refs: Iterable[str]) -> str:
    members = tuple(sorted(turn_refs))
    leaves: list[bytes] = []
    for turn_ref in members:
        leaf = hashlib.sha256()
        leaf.update(b"session-retrospective-episode-member-turn-leaf-v2")
        _update_typed_frame(leaf, b"R", turn_ref.encode("ascii"))
        leaves.append(leaf.digest())
    if not leaves:
        raise ValueError("episode membership cannot be empty")
    while len(leaves) > 1:
        next_level: list[bytes] = []
        for offset in range(0, len(leaves), 2):
            if offset + 1 == len(leaves):
                next_level.append(leaves[offset])
                continue
            node = hashlib.sha256()
            node.update(b"session-retrospective-episode-member-turn-node-v2")
            node.update(leaves[offset])
            node.update(leaves[offset + 1])
            next_level.append(node.digest())
        leaves = next_level
    return f"episode_member_turn_root_v2:sha256:{leaves[0].hex()}"


def _episode_generalized_content_digest(record: dict[str, Any]) -> str:
    projection = {
        field_name: record.get(field_name)
        for field_name in EPISODE_GENERALIZED_CONTENT_FIELDS
    }
    hasher = hashlib.sha256()
    hasher.update(b"session-retrospective-episode-generalized-content-v2")
    _update_typed_frame(hasher, b"J", _canonical_json(projection))
    return f"episode_generalized_content_v2:sha256:{hasher.hexdigest()}"


def _derive_episode_transition_value(
    prefix: str,
    domain: bytes,
    frames: Iterable[tuple[bytes, str]],
) -> str:
    hasher = hashlib.sha256()
    hasher.update(domain)
    for frame_type, value in frames:
        _update_typed_frame(hasher, frame_type, value.encode("ascii"))
    return f"{prefix}{hasher.hexdigest()[:32]}"


def _derive_split_episode_identity(
    predecessor_anchor: str,
    partition_roots: Iterable[str],
    ordinal: int,
) -> tuple[str, str]:
    ordered_roots = tuple(sorted(partition_roots))
    frames = [(b"A", predecessor_anchor)]
    frames.extend((b"P", root) for root in ordered_roots)
    frames.append((b"O", str(ordinal)))
    anchor = _derive_episode_transition_value(
        "episode_anchor_v2:",
        b"session-retrospective-episode-split-anchor-v2",
        frames,
    )
    lineage_id = _derive_episode_transition_value(
        "episode_lineage_id_v2:",
        b"session-retrospective-episode-split-lineage-v2",
        frames,
    )
    return anchor, lineage_id


def _derive_merge_episode_identity(
    predecessors: Iterable[tuple[str, str]],
) -> tuple[str, str]:
    frames: list[tuple[bytes, str]] = []
    for anchor, revision_ref in sorted(predecessors):
        frames.extend(((b"A", anchor), (b"R", revision_ref)))
    anchor = _derive_episode_transition_value(
        "episode_anchor_v2:",
        b"session-retrospective-episode-merge-anchor-v2",
        frames,
    )
    lineage_id = _derive_episode_transition_value(
        "episode_lineage_id_v2:",
        b"session-retrospective-episode-merge-lineage-v2",
        frames,
    )
    return anchor, lineage_id


def _parse_episode_transition_metadata(
    record: dict[str, Any], label: str, issues: list[str]
) -> dict[str, Any]:
    invalid = False
    operation = record.get("episode_revision_operation")
    lineage_id = record.get("episode_lineage_id")
    anchor = record.get("episode_anchor")
    segmentation_major = record.get("segmentation_major")
    policy_major = record.get("episode_policy_major")
    member_turn_root = record.get("member_turn_root")
    member_turn_count = record.get("member_turn_count")
    transition_group_id = record.get("transition_group_id")
    transition_group_ordinal = record.get("transition_group_ordinal")
    content_digest = record.get("generalized_content_digest")
    turn_refs = record.get("turn_refs")

    if not isinstance(operation, str) or operation not in EPISODE_REVISION_OPERATIONS:
        invalid = True
        operation = None
    if not isinstance(lineage_id, str) or EPISODE_LINEAGE_ID_RE.fullmatch(lineage_id) is None:
        invalid = True
        lineage_id = None
    if not isinstance(anchor, str) or EPISODE_ANCHOR_RE.fullmatch(anchor) is None:
        invalid = True
        anchor = None
    if not _is_int(segmentation_major) or segmentation_major < 1:
        invalid = True
        segmentation_major = None
    if not _is_int(policy_major) or policy_major < 1:
        invalid = True
        policy_major = None
    if (
        not isinstance(member_turn_root, str)
        or EPISODE_MEMBER_TURN_ROOT_RE.fullmatch(member_turn_root) is None
    ):
        invalid = True
        member_turn_root = None
    if not _is_int(member_turn_count) or member_turn_count < 1:
        invalid = True
        member_turn_count = None
    if transition_group_id is not None and (
        not isinstance(transition_group_id, str)
        or EPISODE_TRANSITION_GROUP_ID_RE.fullmatch(transition_group_id) is None
    ):
        invalid = True
        transition_group_id = None
    if transition_group_ordinal is not None and (
        not _is_int(transition_group_ordinal) or transition_group_ordinal < 1
    ):
        invalid = True
        transition_group_ordinal = None
    if (
        not isinstance(content_digest, str)
        or EPISODE_CONTENT_DIGEST_RE.fullmatch(content_digest) is None
    ):
        invalid = True
        content_digest = None
    if not isinstance(turn_refs, list) or not all(
        isinstance(turn_ref, str) for turn_ref in turn_refs
    ):
        invalid = True
        members: tuple[str, ...] = ()
    else:
        members = tuple(turn_refs)
        if members != tuple(sorted(set(members))):
            issues.append(
                f"{label}: episode member turn refs must be bytewise-sorted and unique"
            )
        if member_turn_count != len(members):
            issues.append(f"{label}: episode member turn count does not match turn_refs")
        try:
            expected_root = _episode_member_turn_root(members)
        except (UnicodeEncodeError, ValueError):
            invalid = True
        else:
            if member_turn_root != expected_root:
                issues.append(f"{label}: episode member turn root does not match turn_refs")

    presentation: list[str] = []
    ranges = record.get("presentation_ranges")
    if not isinstance(ranges, list) or not ranges:
        invalid = True
    else:
        for range_record in ranges:
            range_members = (
                range_record.get("turn_refs")
                if isinstance(range_record, dict)
                else None
            )
            if not isinstance(range_members, list) or not range_members or not all(
                isinstance(turn_ref, str) for turn_ref in range_members
            ):
                invalid = True
                continue
            presentation.extend(range_members)
    if (
        len(presentation) != len(set(presentation))
        or set(presentation) != set(members)
    ):
        issues.append(
            f"{label}: episode presentation ranges must partition the member turns"
        )

    predecessor_metadata: list[EpisodePredecessorMetadata] = []
    raw_metadata = record.get("predecessor_lineage_metadata")
    if not isinstance(raw_metadata, list):
        invalid = True
    else:
        for metadata in raw_metadata:
            if not isinstance(metadata, dict):
                invalid = True
                continue
            values = (
                metadata.get("episode_revision_ref"),
                metadata.get("episode_lineage_id"),
                metadata.get("episode_anchor"),
                metadata.get("segmentation_major"),
                metadata.get("episode_policy_major"),
                metadata.get("member_turn_root"),
                metadata.get("member_turn_count"),
            )
            if not (
                isinstance(values[0], str)
                and REVISION_SPECS["episodes.jsonl"].current_pattern.fullmatch(values[0])
                and isinstance(values[1], str)
                and EPISODE_LINEAGE_ID_RE.fullmatch(values[1])
                and isinstance(values[2], str)
                and EPISODE_ANCHOR_RE.fullmatch(values[2])
                and _is_int(values[3])
                and values[3] >= 1
                and _is_int(values[4])
                and values[4] >= 1
                and isinstance(values[5], str)
                and EPISODE_MEMBER_TURN_ROOT_RE.fullmatch(values[5])
                and _is_int(values[6])
                and values[6] >= 1
            ):
                invalid = True
                continue
            predecessor_metadata.append(
                EpisodePredecessorMetadata(
                    revision_ref=values[0],
                    lineage_id=values[1],
                    anchor=values[2],
                    segmentation_major=values[3],
                    policy_major=values[4],
                    member_turn_root=values[5],
                    member_turn_count=values[6],
                )
            )
    if predecessor_metadata != sorted(
        predecessor_metadata, key=lambda item: item.revision_ref
    ) or len({item.revision_ref for item in predecessor_metadata}) != len(
        predecessor_metadata
    ):
        issues.append(
            f"{label}: predecessor lineage metadata must be sorted and unique"
        )

    evidence: list[tuple[str, str]] = []
    raw_evidence = record.get("backfill_membership_evidence")
    if not isinstance(raw_evidence, list):
        invalid = True
    else:
        for evidence_record in raw_evidence:
            if not isinstance(evidence_record, dict):
                invalid = True
                continue
            turn_ref = evidence_record.get("turn_ref")
            gap_ref = evidence_record.get("gap_ref")
            if not (
                isinstance(turn_ref, str)
                and re.fullmatch(r"turn_ref_v2:[0-9a-f]{32}", turn_ref)
                and isinstance(gap_ref, str)
                and re.fullmatch(r"gap_ref_v2:[0-9a-f]{32}", gap_ref)
            ):
                invalid = True
                continue
            evidence.append((turn_ref, gap_ref))
    if evidence != sorted(set(evidence)):
        issues.append(
            f"{label}: backfill membership evidence must be sorted and unique"
        )
    if len({turn_ref for turn_ref, _gap_ref in evidence}) != len(evidence):
        issues.append(
            f"{label}: backfill membership evidence must bind one gap per turn"
        )
    declared_gap_refs = record.get("gap_refs")
    if isinstance(declared_gap_refs, list) and any(
        gap_ref not in declared_gap_refs for _turn_ref, gap_ref in evidence
    ):
        issues.append(
            f"{label}: backfill membership evidence must use declared gap_refs"
        )

    if content_digest is not None:
        try:
            expected_digest = _episode_generalized_content_digest(record)
        except (TypeError, UnicodeEncodeError, ValueError):
            invalid = True
        else:
            if content_digest != expected_digest:
                issues.append(
                    f"{label}: generalized episode content digest does not match the record"
                )
    if invalid:
        issues.append(f"{label}: episode transition metadata is invalid")
    return {
        "episode_operation": operation,
        "episode_lineage_id": lineage_id,
        "episode_anchor": anchor,
        "segmentation_major": segmentation_major,
        "episode_policy_major": policy_major,
        "member_turn_root": member_turn_root,
        "member_turn_count": member_turn_count,
        "member_turn_refs": members,
        "presentation_turn_refs": tuple(presentation),
        "transition_group_id": transition_group_id,
        "transition_group_ordinal": transition_group_ordinal,
        "generalized_content_digest": content_digest,
        "predecessor_lineage_metadata": tuple(predecessor_metadata),
        "backfill_membership_evidence": tuple(evidence),
    }


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
    episode_metadata = (
        _parse_episode_transition_metadata(record, label, issues)
        if spec.family == "episode"
        else {}
    )
    return RevisionNode(
        family=spec.family,
        current=current,
        predecessors=tuple(dict.fromkeys(predecessors)),
        kind=kind,
        entity_ref=entity_ref,
        transaction_ref=bundle.transaction_ref,
        label=label,
        **episode_metadata,
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
    if not isinstance(logical_run_id, str) or not _valid_run_id(logical_run_id):
        issues.append(f"{label}: run_id is not canonical Base32")
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
    if not isinstance(run_ref, str) or not _valid_run_ref(run_ref):
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

    key_id = value.get("key_id")
    if not isinstance(key_id, str) or KEY_ID_RE.fullmatch(key_id) is None:
        issues.append(f"{label}: key_id is invalid")

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
    manifest_key_id = bundle.manifest.get("key_id")
    if "key_id" in value and value.get("key_id") != manifest_key_id:
        issues.append(f"{label}: key_id must match manifest.json")
    policy_refs = _manifest_era_refs(bundle.manifest, "policy_eras", "policy_era_ref")
    model_refs = _manifest_era_refs(bundle.manifest, "model_eras", "model_era_ref")
    bind_model_refs = bundle.manifest.get("execution_kind") in MODEL_EXECUTION_KINDS
    if "policy_era_ref" in value and (
        not isinstance(value.get("policy_era_ref"), str)
        or value.get("policy_era_ref") not in policy_refs
    ):
        issues.append(f"{label}: policy_era_ref must be declared by manifest.json")
    if (
        bind_model_refs
        and "model_era_ref" in value
        and (
            not isinstance(value.get("model_era_ref"), str)
            or value.get("model_era_ref") not in model_refs
        )
    ):
        issues.append(f"{label}: model_era_ref must be declared by manifest.json")
    era_ref_collections = [("policy_era_refs", policy_refs)]
    if bind_model_refs:
        era_ref_collections.append(("model_era_refs", model_refs))
    for field_name, allowed in era_ref_collections:
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


def _validate_campaign_revision_ownership(
    bundles: list[Bundle], issues: list[str]
) -> None:
    def segment_head_successor_is_present(manifest: dict[str, Any]) -> bool:
        bindings = manifest.get("head_bindings")
        if not isinstance(bindings, dict):
            return False
        for field, value in bindings.items():
            if field == "bound_quarantine_generation_ref":
                continue
            if field == "cursor_heads":
                if value not in (None, []):
                    return True
            elif value is not None:
                return True
        return False

    segment_owned: dict[str, set[str]] = defaultdict(set)
    for bundle in bundles:
        if _issues_full(issues):
            return
        role = (
            bundle.manifest.get("publication_role")
            if bundle.manifest is not None
            else None
        )
        if role != "campaign_segment":
            continue
        invalid_families: set[str] = set()
        for node in bundle.revisions:
            if node.family not in CAMPAIGN_SEGMENT_REVISION_FAMILIES:
                continue
            segment_owned[node.family].add(node.current)
            if node.kind != "initial" or node.predecessors:
                invalid_families.add(node.family)
        supersession = bundle.manifest.get("supersession")
        if isinstance(supersession, dict):
            for family, field in CAMPAIGN_SEGMENT_MANIFEST_SUPERSESSION_FIELDS.items():
                targets = supersession.get(field)
                if isinstance(targets, list) and targets:
                    invalid_families.add(family)
        for family in sorted(invalid_families):
            issues.append(
                f"{bundle.label}: campaign segment {family} revision must be initial and predecessor-free"
            )
        if segment_head_successor_is_present(bundle.manifest):
            issues.append(
                f"{bundle.label}/manifest.json: campaign segment must not propose retained state or head successors"
            )

    segment_family_by_revision = {
        revision: family
        for family, revisions in segment_owned.items()
        for revision in revisions
    }

    for bundle in bundles:
        if _issues_full(issues):
            return
        role = (
            bundle.manifest.get("publication_role")
            if bundle.manifest is not None
            else None
        )
        if role not in {"standalone", "campaign_root"}:
            continue
        invalid_target_families: set[str] = set()
        for node in bundle.revisions:
            if node.family in CAMPAIGN_SEGMENT_REVISION_FAMILIES and any(
                predecessor in segment_owned[node.family]
                for predecessor in node.predecessors
            ):
                invalid_target_families.add(node.family)
        assert bundle.manifest is not None
        supersession = bundle.manifest.get("supersession")
        if isinstance(supersession, dict):
            for family, field in CAMPAIGN_SEGMENT_MANIFEST_SUPERSESSION_FIELDS.items():
                targets = supersession.get(field)
                if isinstance(targets, list) and any(
                    isinstance(target, str) and target in segment_owned[family]
                    for target in targets
                ):
                    invalid_target_families.add(family)
        head_bindings = bundle.manifest.get("head_bindings")
        stack = [head_bindings] if isinstance(head_bindings, (dict, list)) else []
        visited = 0
        while stack and visited <= MAX_JSON_NODES:
            current = stack.pop()
            visited += 1
            if isinstance(current, dict):
                stack.extend(current.values())
            elif isinstance(current, list):
                stack.extend(current)
            elif isinstance(current, str):
                family = segment_family_by_revision.get(current)
                if family is not None:
                    invalid_target_families.add(family)
        for family in sorted(invalid_target_families):
            issues.append(
                f"{bundle.label}: {role} {family} revision must not target a campaign-segment-owned predecessor"
            )


def _validate_episode_transition_graph(
    nodes: dict[str, RevisionNode], issues: list[str]
) -> None:
    split_groups: dict[tuple[str, str | None], list[RevisionNode]] = defaultdict(list)
    transition_groups: dict[str, list[RevisionNode]] = defaultdict(list)
    split_closers: dict[str, list[RevisionNode]] = defaultdict(list)
    lineage_roots: dict[str, list[RevisionNode]] = defaultdict(list)
    anchor_roots: dict[str, list[RevisionNode]] = defaultdict(list)
    for node in nodes.values():
        if _issues_full(issues):
            return
        predecessors = tuple(
            nodes[predecessor]
            for predecessor in node.predecessors
            if predecessor in nodes
        )
        _validate_episode_transition_node(node, predecessors, issues)
        if node.episode_operation == "split":
            split_groups[(node.transaction_ref, node.transition_group_id)].append(node)
            for predecessor_ref in node.predecessors:
                split_closers[predecessor_ref].append(node)
        if (
            node.episode_operation in {"split", "merge"}
            and node.transition_group_id is not None
        ):
            transition_groups[node.transition_group_id].append(node)
        if (
            node.episode_operation in {"create", "split", "merge"}
            and node.episode_lineage_id is not None
            and node.episode_anchor is not None
        ):
            lineage_roots[node.episode_lineage_id].append(node)
            anchor_roots[node.episode_anchor].append(node)
        if node.episode_operation == "merge" and len(predecessors) == len(
            node.predecessors
        ):
            owned: set[str] = set()
            overlap = False
            for predecessor in predecessors:
                members = set(predecessor.member_turn_refs)
                overlap = overlap or bool(owned.intersection(members))
                owned.update(members)
            if overlap or owned != set(node.member_turn_refs):
                issues.append(
                    f"{node.label}: episode merge members must equal the disjoint predecessor union"
                )
            expected_anchor, expected_lineage = _derive_merge_episode_identity(
                (
                    (predecessor.episode_anchor or "", predecessor.current)
                    for predecessor in predecessors
                )
            )
            if (
                node.episode_anchor != expected_anchor
                or node.episode_lineage_id != expected_lineage
                or node.episode_lineage_id
                in {predecessor.episode_lineage_id for predecessor in predecessors}
            ):
                issues.append(
                    f"{node.label}: episode merge successor identity is not deterministic"
                )

    consumed_heads = {
        predecessor_ref
        for node in nodes.values()
        for predecessor_ref in node.predecessors
    }
    member_owners: dict[tuple[int | None, int | None, str], RevisionNode] = {}
    reported_owner_pairs: set[tuple[str, str]] = set()
    for node in sorted(nodes.values(), key=lambda item: item.current):
        if node.current in consumed_heads:
            continue
        for turn_ref in node.member_turn_refs:
            owner_key = (
                node.segmentation_major,
                node.episode_policy_major,
                turn_ref,
            )
            prior = member_owners.setdefault(owner_key, node)
            if prior.current == node.current:
                continue
            pair = tuple(sorted((prior.current, node.current)))
            if pair in reported_owner_pairs:
                continue
            reported_owner_pairs.add(pair)
            issues.append(
                f"{prior.label}: compatible current episode heads must not share member turns"
            )
            if not _issues_full(issues):
                issues.append(
                    f"{node.label}: compatible current episode heads must not share member turns"
                )
            if _issues_full(issues):
                return

    for roots in lineage_roots.values():
        if len(roots) > 1:
            for node in roots:
                issues.append(
                    f"{node.label}: episode lineage may have only one root transition"
                )
                if _issues_full(issues):
                    return
    for roots in anchor_roots.values():
        if len(roots) > 1:
            for node in roots:
                issues.append(
                    f"{node.label}: episode anchor may have only one root transition"
                )
                if _issues_full(issues):
                    return
    for group_nodes in transition_groups.values():
        group_owners = {
            (node.transaction_ref, node.episode_operation) for node in group_nodes
        }
        invalid = len(group_owners) != 1
        if not invalid:
            _transaction_ref, operation = next(iter(group_owners))
            invalid = operation == "merge" and len(group_nodes) != 1
        if invalid:
            for node in group_nodes:
                issues.append(
                    f"{node.label}: episode transition group must identify one atomic split or merge"
                )
                if _issues_full(issues):
                    return
    for closers in split_closers.values():
        group_owners = {
            (node.transaction_ref, node.transition_group_id) for node in closers
        }
        if len(group_owners) > 1:
            for node in closers:
                issues.append(
                    f"{node.label}: episode predecessor may be consumed by only one split group"
                )
                if _issues_full(issues):
                    return
    for group_nodes in split_groups.values():
        if len(group_nodes) < 2:
            for node in group_nodes:
                issues.append(
                    f"{node.label}: episode split transition group must contain at least two successors"
                )
            continue
        ordered = sorted(
            group_nodes,
            key=lambda item: (item.transition_group_ordinal or 0, item.current),
        )
        majors = {
            (node.segmentation_major, node.episode_policy_major)
            for node in ordered
        }
        if [node.transition_group_ordinal for node in ordered] != list(
            range(1, len(ordered) + 1)
        ):
            for node in ordered:
                issues.append(
                    f"{node.label}: episode split ordinals must be contiguous and unique"
                )
        if len(majors) != 1:
            for node in ordered:
                issues.append(
                    f"{node.label}: episode split successors must share one reviewed major pair"
                )
        predecessor_sets = {node.predecessors for node in ordered}
        if len(predecessor_sets) != 1 or len(next(iter(predecessor_sets), ())) != 1:
            for node in ordered:
                issues.append(
                    f"{node.label}: episode split successors must consume the same one current head"
                )
            continue
        predecessor_ref = next(iter(next(iter(predecessor_sets))))
        predecessor = nodes.get(predecessor_ref)
        if predecessor is None:
            continue
        owned: set[str] = set()
        overlap = False
        for node in ordered:
            members = set(node.member_turn_refs)
            overlap = overlap or not members or bool(owned.intersection(members))
            owned.update(members)
        if overlap or owned != set(predecessor.member_turn_refs):
            for node in ordered:
                issues.append(
                    f"{node.label}: episode split members must be nonempty disjoint partitions of the predecessor"
                )
        roots = [node.member_turn_root or "" for node in ordered]
        if roots != sorted(roots) or len(set(roots)) != len(roots):
            for node in ordered:
                issues.append(
                    f"{node.label}: episode split ordinal must match canonical partition-root order"
                )
                if _issues_full(issues):
                    return
        for node in ordered:
            if node.transition_group_ordinal is None:
                continue
            anchor, lineage_id = _derive_split_episode_identity(
                predecessor.episode_anchor or "", roots, node.transition_group_ordinal
            )
            if (
                node.episode_anchor != anchor
                or node.episode_lineage_id != lineage_id
                or node.episode_lineage_id == predecessor.episode_lineage_id
            ):
                issues.append(
                    f"{node.label}: episode split successor identity is not deterministic"
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
        if family == "episode" and not _issues_full(issues):
            _validate_episode_transition_graph(nodes, issues)


def _build_trend_snapshot(bundle: Bundle) -> _TrendSnapshot | None:
    manifest = bundle.documents.get("manifest.json")
    summary = bundle.documents.get("summary.json")
    trend = bundle.documents.get("trend_report.json")
    if (
        not isinstance(manifest, dict)
        or not isinstance(summary, dict)
        or not isinstance(trend, dict)
        or manifest.get("publication_role") == "campaign_segment"
    ):
        return None
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
        return None
    supersedes_run_revision_refs = supersession.get("supersedes_run_revision_refs")
    if (
        not isinstance(supersedes_run_revision_refs, list)
        or len(supersedes_run_revision_refs) > 32
        or not all(
            isinstance(reference, str)
            and RUN_REVISION_REF_RE.fullmatch(reference) is not None
            for reference in supersedes_run_revision_refs
        )
    ):
        return None
    window_start = _parse_coarse_timestamp(window.get("start"))
    window_end = _parse_coarse_timestamp(window.get("end"))
    if window_start is None or window_end is None or window_start >= window_end:
        return None
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

    return _TrendSnapshot(
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


def _collect_trend_comparison_state(
    bundle: Bundle,
    snapshots: dict[str, _TrendSnapshot],
) -> None:
    snapshot = _build_trend_snapshot(bundle)
    if snapshot is not None:
        snapshots[snapshot.run_revision_ref] = snapshot


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


def _validate_indexed_run_supersession(
    index: _ValidationIndex, issues: list[str]
) -> None:
    connection = index.connection
    bundles = connection.execute(
        """
        SELECT bundle_id, label, mode, window_component, status,
               supersession_reason
        FROM bundle_facts
        WHERE run_revision_ref IS NOT NULL
        ORDER BY bundle_id
        """
    )
    aggregate_families = {
        "coverage": "coverage.json",
        "summary": "summary.json",
        "trend": "trend_report.json",
    }
    for bundle_id, label, mode, window_component, status, reason in bundles:
        if _issues_full(issues):
            return
        target_refs = [
            row[0]
            for row in connection.execute(
                """
                SELECT target_ref FROM run_supersession
                WHERE bundle_id = ? ORDER BY target_ref
                """,
                (bundle_id,),
            )
        ]
        resolved_targets: list[tuple[int, str, str, str | None]] = []
        for target_ref in target_refs:
            target_rows = connection.execute(
                """
                SELECT bundle_id, mode, window_component, status
                FROM bundle_facts
                WHERE run_revision_ref = ?
                ORDER BY bundle_id LIMIT 2
                """,
                (target_ref,),
            ).fetchall()
            if len(target_rows) == 1:
                resolved_targets.append(tuple(target_rows[0]))

        for _target_id, target_mode, target_window, target_status in resolved_targets:
            if (target_mode, target_window) != (mode, window_component):
                issues.append(
                    f"{label}/manifest.json: superseded run must share mode and window"
                )
            if reason == "backfill" and target_status != "partial":
                issues.append(
                    f"{label}/manifest.json: backfill predecessor must be partial"
                )
            if status == "partial" and target_status in FULL_PUBLICATION_STATUSES:
                issues.append(
                    f"{label}/manifest.json: partial revision must not supersede a full run"
                )

        if not resolved_targets or len(resolved_targets) != len(target_refs):
            continue
        for family, basename in aggregate_families.items():
            current_predecessors = {
                row[0]
                for row in connection.execute(
                    """
                    SELECT DISTINCT p.predecessor_ref
                    FROM revisions AS r
                    JOIN revision_predecessors AS p ON p.revision_id = r.id
                    WHERE r.bundle_id = ? AND r.family = ?
                    """,
                    (bundle_id, family),
                )
            }
            expected = {
                row[0]
                for target_id, *_ in resolved_targets
                for row in connection.execute(
                    """
                    SELECT current_ref FROM revisions
                    WHERE bundle_id = ? AND family = ?
                    """,
                    (target_id, family),
                )
            }
            if current_predecessors != expected:
                issues.append(
                    f"{label}/{basename}: aggregate predecessor revisions must match manifest run supersession"
                )
            has_initial = connection.execute(
                """
                SELECT 1 FROM revisions
                WHERE bundle_id = ? AND family = ? AND kind = 'initial'
                LIMIT 1
                """,
                (bundle_id, family),
            ).fetchone()
            if target_refs and has_initial is not None:
                issues.append(
                    f"{label}/{basename}: superseding aggregate revision must not be initial"
                )


def _compute_indexed_campaign_segment_root(
    campaign_ref: str,
    segment_count: int,
    segments: Iterable[tuple[int, str, str]],
) -> str:
    if not isinstance(campaign_ref, str) or not _is_int(segment_count):
        raise TypeError("campaign root inputs are invalid")
    hasher = hashlib.sha256()
    hasher.update(CAMPAIGN_SEGMENT_DOMAIN_TAG)
    _update_typed_frame(hasher, b"C", campaign_ref.encode("ascii"))
    _update_typed_frame(hasher, b"N", segment_count.to_bytes(8, "big"))
    observed = 0
    for observed, (ordinal, run_ref, bundle_digest) in enumerate(segments, start=1):
        if (
            ordinal != observed
            or not isinstance(run_ref, str)
            or not isinstance(bundle_digest, str)
        ):
            raise ValueError("campaign segment coordinates are invalid")
        _update_typed_frame(hasher, b"O", ordinal.to_bytes(8, "big"))
        _update_typed_frame(hasher, b"R", run_ref.encode("ascii"))
        _update_typed_frame(hasher, b"D", bundle_digest.encode("ascii"))
    if observed != segment_count:
        raise ValueError("campaign segment cardinality is invalid")
    return f"campaign_segment_root_v2:sha256:{hasher.hexdigest()}"


def _validate_one_indexed_campaign(
    index: _ValidationIndex,
    campaign_ref: str,
    issues: list[str],
) -> None:
    connection = index.connection
    coordinates = connection.execute(
        """
        SELECT COUNT(*) FROM (
            SELECT DISTINCT mode, window_component, campaign_reason
            FROM bundle_facts WHERE campaign_ref = ?
        )
        """,
        (campaign_ref,),
    ).fetchone()[0]
    if coordinates != 1:
        issues.append(
            "runs: campaign bundles must share mode, window, and campaign reason"
        )

    root_count = connection.execute(
        """
        SELECT COUNT(*) FROM bundle_facts
        WHERE campaign_ref = ? AND publication_role = 'campaign_root'
        """,
        (campaign_ref,),
    ).fetchone()[0]
    segment_count_actual = connection.execute(
        """
        SELECT COUNT(*) FROM bundle_facts
        WHERE campaign_ref = ? AND publication_role = 'campaign_segment'
        """,
        (campaign_ref,),
    ).fetchone()[0]
    if root_count > 1:
        issues.append("runs: campaign must contain at most one campaign root")
    if root_count and not segment_count_actual:
        issues.append("runs: campaign root must not exist without campaign segments")
        return
    if not segment_count_actual:
        return

    segment_counts = [
        row[0]
        for row in connection.execute(
            """
            SELECT DISTINCT campaign_segment_count FROM bundle_facts
            WHERE campaign_ref = ?
              AND publication_role = 'campaign_segment'
              AND campaign_segment_count IS NOT NULL
            ORDER BY campaign_segment_count
            """,
            (campaign_ref,),
        )
    ]
    root_counts = [
        row[0]
        for row in connection.execute(
            """
            SELECT DISTINCT campaign_segment_count FROM bundle_facts
            WHERE campaign_ref = ?
              AND publication_role = 'campaign_root'
              AND campaign_segment_count IS NOT NULL
            ORDER BY campaign_segment_count
            """,
            (campaign_ref,),
        )
    ]
    if len(segment_counts) != 1 or (root_count and root_counts != segment_counts):
        issues.append("runs: campaign segment counts must agree with the campaign root")
        return
    segment_count = segment_counts[0]

    ordinal_count, ordinal_distinct, minimum, maximum = connection.execute(
        """
        SELECT COUNT(segment_ordinal), COUNT(DISTINCT segment_ordinal),
               MIN(segment_ordinal), MAX(segment_ordinal)
        FROM bundle_facts
        WHERE campaign_ref = ? AND publication_role = 'campaign_segment'
        """,
        (campaign_ref,),
    ).fetchone()
    required_count = segment_count if root_count else segment_count_actual
    invalid_ordinals = (
        ordinal_count != segment_count_actual
        or ordinal_distinct != segment_count_actual
        or minimum != 1
        or maximum != required_count
        or segment_count_actual != required_count
    )
    if invalid_ordinals:
        issues.append("runs: campaign segments must cover every unique bounded ordinal")

    duplicate_tree_ref = connection.execute(
        """
        SELECT 1
        FROM campaign_tree_refs AS refs
        JOIN bundle_facts AS facts ON facts.bundle_id = refs.bundle_id
        WHERE facts.campaign_ref = ?
          AND facts.publication_role = 'campaign_segment'
        GROUP BY refs.ref_kind, refs.tree_ref
        HAVING COUNT(*) > 1
        LIMIT 1
        """,
        (campaign_ref,),
    ).fetchone()
    if duplicate_tree_ref is not None:
        issues.append("runs: campaign tree roots must be unique across segments")

    generations = connection.execute(
        """
        SELECT COUNT(DISTINCT generation_ref)
        FROM bundle_facts
        WHERE campaign_ref = ? AND generation_ref IS NOT NULL
        """,
        (campaign_ref,),
    ).fetchone()[0]
    missing_generation = connection.execute(
        """
        SELECT 1 FROM bundle_facts
        WHERE campaign_ref = ? AND generation_ref IS NULL
        LIMIT 1
        """,
        (campaign_ref,),
    ).fetchone()
    if generations != 1 or missing_generation is not None:
        issues.append("runs: campaign bundles must bind one quarantine generation")

    if root_count == 1 and not invalid_ordinals:
        declared_root = connection.execute(
            """
            SELECT campaign_segment_root FROM bundle_facts
            WHERE campaign_ref = ? AND publication_role = 'campaign_root'
            LIMIT 1
            """,
            (campaign_ref,),
        ).fetchone()[0]
        if (
            not isinstance(declared_root, str)
            or CAMPAIGN_SEGMENT_ROOT_RE.fullmatch(declared_root) is None
        ):
            issues.append(
                "runs: campaign_segment_root_v2 is invalid on the campaign root"
            )
            return
        segment_rows = connection.execute(
            """
            SELECT segment_ordinal, run_ref, bundle_digest
            FROM bundle_facts
            WHERE campaign_ref = ? AND publication_role = 'campaign_segment'
            ORDER BY segment_ordinal
            """,
            (campaign_ref,),
        )
        try:
            expected_root = _compute_indexed_campaign_segment_root(
                campaign_ref, segment_count, segment_rows
            )
        except (TypeError, ValueError, UnicodeEncodeError, OverflowError):
            issues.append("runs: campaign segment commitments cannot be canonicalized")
        else:
            if declared_root != expected_root:
                issues.append(
                    "runs: campaign_segment_root_v2 does not bind the ordered segment run refs and bundle digests"
                )


def _validate_indexed_campaign_consistency(
    index: _ValidationIndex, issues: list[str]
) -> None:
    cursor_ref: str | None = None
    while not _issues_full(issues):
        if cursor_ref is None:
            rows = index.connection.execute(
                """
                SELECT DISTINCT campaign_ref FROM bundle_facts
                WHERE campaign_ref IS NOT NULL
                ORDER BY campaign_ref LIMIT ?
                """,
                (MAX_INDEX_QUERY_ROWS,),
            ).fetchall()
        else:
            rows = index.connection.execute(
                """
                SELECT DISTINCT campaign_ref FROM bundle_facts
                WHERE campaign_ref > ?
                ORDER BY campaign_ref LIMIT ?
                """,
                (cursor_ref, MAX_INDEX_QUERY_ROWS),
            ).fetchall()
        if not rows:
            return
        for (campaign_ref,) in rows:
            _validate_one_indexed_campaign(index, campaign_ref, issues)
            if _issues_full(issues):
                return
        cursor_ref = rows[-1][0]


def _validate_indexed_campaign_revision_ownership(
    index: _ValidationIndex, issues: list[str]
) -> None:
    connection = index.connection

    invalid_segment_revisions = connection.execute(
        """
        SELECT DISTINCT facts.label, revisions.family
        FROM bundle_facts AS facts
        JOIN revisions ON revisions.bundle_id = facts.bundle_id
        LEFT JOIN revision_predecessors AS predecessors
          ON predecessors.revision_id = revisions.id
        WHERE facts.publication_role = 'campaign_segment'
          AND (revisions.kind != 'initial' OR predecessors.revision_id IS NOT NULL)
        ORDER BY facts.label, revisions.family
        """
    )
    for label, family in invalid_segment_revisions:
        if _issues_full(issues):
            return
        if family in CAMPAIGN_SEGMENT_REVISION_FAMILIES:
            issues.append(
                f"{label}: campaign segment {family} revision must be initial and predecessor-free"
            )

    invalid_segment_manifest_targets = connection.execute(
        """
        SELECT DISTINCT facts.label, targets.family
        FROM bundle_facts AS facts
        JOIN manifest_supersession AS targets
          ON targets.bundle_id = facts.bundle_id
        WHERE facts.publication_role = 'campaign_segment'
        ORDER BY facts.label, targets.family
        """
    )
    for label, family in invalid_segment_manifest_targets:
        if _issues_full(issues):
            return
        issues.append(
            f"{label}: campaign segment {family} revision must be initial and predecessor-free"
        )

    for (label,) in connection.execute(
        """
        SELECT label FROM bundle_facts
        WHERE publication_role = 'campaign_segment'
          AND segment_has_head_successor = 1
        ORDER BY label
        """
    ):
        if _issues_full(issues):
            return
        issues.append(
            f"{label}/manifest.json: campaign segment must not propose retained state or head successors"
        )

    invalid_revision_targets = connection.execute(
        """
        SELECT DISTINCT current_facts.label, current_facts.publication_role,
                        current_revision.family
        FROM bundle_facts AS current_facts
        JOIN revisions AS current_revision
          ON current_revision.bundle_id = current_facts.bundle_id
        JOIN revision_predecessors AS predecessor
          ON predecessor.revision_id = current_revision.id
        JOIN revisions AS segment_revision
          ON segment_revision.family = current_revision.family
         AND segment_revision.current_ref = predecessor.predecessor_ref
        JOIN bundle_facts AS segment_facts
          ON segment_facts.bundle_id = segment_revision.bundle_id
        WHERE current_facts.publication_role IN ('standalone', 'campaign_root')
          AND segment_facts.publication_role = 'campaign_segment'
        ORDER BY current_facts.label, current_revision.family
        """
    )
    for label, role, family in invalid_revision_targets:
        if _issues_full(issues):
            return
        if family in CAMPAIGN_SEGMENT_REVISION_FAMILIES:
            issues.append(
                f"{label}: {role} {family} revision must not target a campaign-segment-owned predecessor"
            )

    invalid_manifest_targets = connection.execute(
        """
        SELECT DISTINCT current_facts.label, current_facts.publication_role,
                        target.family
        FROM bundle_facts AS current_facts
        JOIN manifest_supersession AS target
          ON target.bundle_id = current_facts.bundle_id
        JOIN revisions AS segment_revision
          ON segment_revision.family = target.family
         AND segment_revision.current_ref = target.target_ref
        JOIN bundle_facts AS segment_facts
          ON segment_facts.bundle_id = segment_revision.bundle_id
        WHERE current_facts.publication_role IN ('standalone', 'campaign_root')
          AND segment_facts.publication_role = 'campaign_segment'
        ORDER BY current_facts.label, target.family
        """
    )
    for label, role, family in invalid_manifest_targets:
        if _issues_full(issues):
            return
        issues.append(
            f"{label}: {role} {family} revision must not target a campaign-segment-owned predecessor"
        )

    invalid_head_targets = connection.execute(
        """
        SELECT DISTINCT current_facts.label, current_facts.publication_role,
                        segment_revision.family
        FROM bundle_facts AS current_facts
        JOIN head_binding_refs AS binding
          ON binding.bundle_id = current_facts.bundle_id
        JOIN revisions AS segment_revision
          ON segment_revision.current_ref = binding.binding_ref
        JOIN bundle_facts AS segment_facts
          ON segment_facts.bundle_id = segment_revision.bundle_id
        WHERE current_facts.publication_role IN ('standalone', 'campaign_root')
          AND segment_facts.publication_role = 'campaign_segment'
        ORDER BY current_facts.label, segment_revision.family
        """
    )
    for label, role, family in invalid_head_targets:
        if _issues_full(issues):
            return
        if family in CAMPAIGN_SEGMENT_REVISION_FAMILIES:
            issues.append(
                f"{label}: {role} {family} revision must not target a campaign-segment-owned predecessor"
            )


def _indexed_episode_node_from_row(
    connection: sqlite3.Connection, row: tuple[Any, ...]
) -> RevisionNode:
    (
        revision_id,
        current,
        kind,
        entity_ref,
        transaction_ref,
        label,
        operation,
        lineage_id,
        anchor,
        segmentation_major,
        policy_major,
        member_turn_root,
        member_turn_count,
        transition_group_id,
        transition_group_ordinal,
        content_digest,
    ) = row
    predecessors = tuple(
        predecessor_ref
        for (predecessor_ref,) in connection.execute(
            """
            SELECT predecessor_ref FROM revision_predecessors
            WHERE revision_id = ? ORDER BY predecessor_ref
            """,
            (revision_id,),
        )
    )
    presentation = tuple(
        turn_ref
        for turn_ref, _ordinal in connection.execute(
            """
            SELECT turn_ref, presentation_ordinal FROM episode_members
            WHERE revision_id = ? ORDER BY presentation_ordinal, turn_ref
            """,
            (revision_id,),
        )
    )
    metadata = tuple(
        EpisodePredecessorMetadata(
            revision_ref=metadata_row[0],
            lineage_id=metadata_row[1],
            anchor=metadata_row[2],
            segmentation_major=metadata_row[3],
            policy_major=metadata_row[4],
            member_turn_root=metadata_row[5],
            member_turn_count=metadata_row[6],
        )
        for metadata_row in connection.execute(
            """
            SELECT predecessor_ref, lineage_id, anchor, segmentation_major,
                   policy_major, member_turn_root, member_turn_count
            FROM episode_predecessor_metadata
            WHERE revision_id = ? ORDER BY predecessor_ref
            """,
            (revision_id,),
        )
    )
    evidence = tuple(
        (turn_ref, gap_ref)
        for turn_ref, gap_ref in connection.execute(
            """
            SELECT turn_ref, gap_ref FROM episode_backfill_evidence
            WHERE revision_id = ? ORDER BY turn_ref, gap_ref
            """,
            (revision_id,),
        )
    )
    return RevisionNode(
        family="episode",
        current=current,
        predecessors=predecessors,
        kind=kind,
        entity_ref=entity_ref,
        transaction_ref=transaction_ref,
        label=label,
        episode_operation=operation,
        episode_lineage_id=lineage_id,
        episode_anchor=anchor,
        segmentation_major=segmentation_major,
        episode_policy_major=policy_major,
        member_turn_root=member_turn_root,
        member_turn_count=member_turn_count,
        member_turn_refs=tuple(sorted(presentation)),
        presentation_turn_refs=presentation,
        transition_group_id=transition_group_id,
        transition_group_ordinal=transition_group_ordinal,
        generalized_content_digest=content_digest,
        predecessor_lineage_metadata=metadata,
        backfill_membership_evidence=evidence,
    )


def _indexed_episode_rows(connection: sqlite3.Connection) -> sqlite3.Cursor:
    return connection.execute(
        """
        SELECT revision.id, revision.current_ref, revision.kind,
               revision.entity_ref, revision.transaction_ref, revision.label,
               fact.operation, fact.lineage_id, fact.anchor,
               fact.segmentation_major, fact.policy_major,
               fact.member_turn_root, fact.member_turn_count,
               fact.transition_group_id, fact.transition_group_ordinal,
               fact.content_digest
        FROM revisions AS revision
        JOIN episode_revision_facts AS fact ON fact.revision_id = revision.id
        ORDER BY revision.id
        """
    )


def _load_indexed_episode_by_ref(
    connection: sqlite3.Connection, revision_ref: str
) -> RevisionNode | None:
    rows = connection.execute(
        """
        SELECT revision.id, revision.current_ref, revision.kind,
               revision.entity_ref, revision.transaction_ref, revision.label,
               fact.operation, fact.lineage_id, fact.anchor,
               fact.segmentation_major, fact.policy_major,
               fact.member_turn_root, fact.member_turn_count,
               fact.transition_group_id, fact.transition_group_ordinal,
               fact.content_digest
        FROM revisions AS revision
        JOIN episode_revision_facts AS fact ON fact.revision_id = revision.id
        WHERE revision.family = 'episode' AND revision.current_ref = ?
        ORDER BY revision.id LIMIT 2
        """,
        (revision_ref,),
    ).fetchall()
    if len(rows) != 1:
        return None
    return _indexed_episode_node_from_row(connection, rows[0])


def _episode_metadata_matches(
    metadata: EpisodePredecessorMetadata, predecessor: RevisionNode
) -> bool:
    return (
        metadata.revision_ref == predecessor.current
        and metadata.lineage_id == predecessor.episode_lineage_id
        and metadata.anchor == predecessor.episode_anchor
        and metadata.segmentation_major == predecessor.segmentation_major
        and metadata.policy_major == predecessor.episode_policy_major
        and metadata.member_turn_root == predecessor.member_turn_root
        and metadata.member_turn_count == predecessor.member_turn_count
    )


def _is_subsequence(needle: tuple[str, ...], haystack: tuple[str, ...]) -> bool:
    if not needle:
        return True
    iterator = iter(haystack)
    return all(any(candidate == item for candidate in iterator) for item in needle)


def _validate_episode_transition_node(
    node: RevisionNode,
    predecessors: tuple[RevisionNode, ...],
    issues: list[str],
) -> None:
    operation = node.episode_operation
    expected_kind = EPISODE_OPERATION_REVISION_KINDS.get(operation or "")
    if expected_kind is None or node.kind != expected_kind:
        issues.append(
            f"{node.label}: episode operation does not match revision_kind"
        )

    expected_predecessor_count = {
        "create": 0,
        "extend": 1,
        "backfill": 1,
        "split": 1,
    }.get(operation)
    if expected_predecessor_count is not None and len(node.predecessors) != expected_predecessor_count:
        issues.append(
            f"{node.label}: episode operation has an invalid predecessor-head count"
        )
    if operation == "merge" and len(node.predecessors) < 2:
        issues.append(
            f"{node.label}: episode merge must consume at least two current heads"
        )

    metadata = node.predecessor_lineage_metadata
    if tuple(item.revision_ref for item in metadata) != node.predecessors:
        issues.append(
            f"{node.label}: predecessor lineage metadata must match predecessor heads"
        )
    elif len(predecessors) == len(metadata) and any(
        not _episode_metadata_matches(item, predecessor)
        for item, predecessor in zip(metadata, predecessors, strict=True)
    ):
        issues.append(
            f"{node.label}: predecessor lineage metadata does not match retained history"
        )

    if operation in {"create", "extend", "backfill"}:
        if node.transition_group_id is not None or node.transition_group_ordinal is not None:
            issues.append(
                f"{node.label}: ordinary episode operation must not name a transition group"
            )
    elif operation == "split":
        if node.transition_group_id is None or node.transition_group_ordinal is None:
            issues.append(
                f"{node.label}: episode split must name its transition group and ordinal"
            )
    elif operation == "merge":
        if node.transition_group_id is None or node.transition_group_ordinal is not None:
            issues.append(
                f"{node.label}: episode merge must name one transition group without an ordinal"
            )

    if operation != "backfill" and node.backfill_membership_evidence:
        issues.append(
            f"{node.label}: backfill membership evidence is valid only for backfill"
        )

    if operation in {"extend", "backfill"} and len(predecessors) == 1:
        predecessor = predecessors[0]
        if (
            node.episode_lineage_id != predecessor.episode_lineage_id
            or node.episode_anchor != predecessor.episode_anchor
            or node.segmentation_major != predecessor.segmentation_major
            or node.episode_policy_major != predecessor.episode_policy_major
            or node.entity_ref != predecessor.entity_ref
        ):
            issues.append(
                f"{node.label}: ordinary episode transition must preserve lineage, anchor, majors, and episode_ref"
            )
        predecessor_members = set(predecessor.member_turn_refs)
        current_members = set(node.member_turn_refs)
        added = current_members - predecessor_members
        if not added or not predecessor_members.issubset(current_members):
            issues.append(
                f"{node.label}: ordinary episode transition must retain every predecessor member and add at least one"
            )
        if operation == "extend" and node.presentation_turn_refs[: len(predecessor.presentation_turn_refs)] != predecessor.presentation_turn_refs:
            issues.append(
                f"{node.label}: episode extend must append later contiguous presentation turns"
            )
        if operation == "backfill":
            if not _is_subsequence(
                predecessor.presentation_turn_refs, node.presentation_turn_refs
            ):
                issues.append(
                    f"{node.label}: episode backfill must preserve predecessor presentation order"
                )
            else:
                first_predecessor_index = min(
                    (
                        node.presentation_turn_refs.index(turn_ref)
                        for turn_ref in predecessor.presentation_turn_refs
                    ),
                    default=len(node.presentation_turn_refs),
                )
                explicit_gap_turns = {
                    turn_ref for turn_ref, _gap_ref in node.backfill_membership_evidence
                }
                non_earlier_added = {
                    turn_ref
                    for index, turn_ref in enumerate(node.presentation_turn_refs)
                    if turn_ref in added
                    and index >= first_predecessor_index
                }
                if explicit_gap_turns != non_earlier_added:
                    issues.append(
                        f"{node.label}: non-earlier backfill members require exact explicit-gap evidence"
                    )


def _validate_indexed_episode_split_groups(
    index: _ValidationIndex, issues: list[str]
) -> None:
    connection = index.connection
    groups = connection.execute(
        """
        SELECT revision.transaction_ref, fact.transition_group_id
        FROM episode_revision_facts AS fact
        JOIN revisions AS revision ON revision.id = fact.revision_id
        WHERE fact.operation = 'split'
        GROUP BY revision.transaction_ref, fact.transition_group_id
        ORDER BY revision.transaction_ref, fact.transition_group_id
        """
    )
    for transaction_ref, group_id in groups:
        if _issues_full(issues):
            return
        rows = connection.execute(
            """
            SELECT revision.id, revision.current_ref, revision.kind,
                   revision.entity_ref, revision.transaction_ref, revision.label,
                   fact.operation, fact.lineage_id, fact.anchor,
                   fact.segmentation_major, fact.policy_major,
                   fact.member_turn_root, fact.member_turn_count,
                   fact.transition_group_id, fact.transition_group_ordinal,
                   fact.content_digest
            FROM revisions AS revision
            JOIN episode_revision_facts AS fact ON fact.revision_id = revision.id
            WHERE revision.transaction_ref = ? AND fact.transition_group_id = ?
                  AND fact.operation = 'split'
            ORDER BY fact.transition_group_ordinal, revision.current_ref
            """,
            (transaction_ref, group_id),
        ).fetchall()
        nodes = tuple(_indexed_episode_node_from_row(connection, row) for row in rows)
        labels = [node.label for node in nodes]
        if len(nodes) < 2:
            issues.extend(
                f"{label}: episode split transition group must contain at least two successors"
                for label in labels
            )
            continue
        ordinals = [node.transition_group_ordinal for node in nodes]
        predecessor_refs = {node.predecessors for node in nodes}
        majors = {
            (node.segmentation_major, node.episode_policy_major) for node in nodes
        }
        if ordinals != list(range(1, len(nodes) + 1)):
            issues.extend(
                f"{label}: episode split ordinals must be contiguous and unique"
                for label in labels
            )
        if len(predecessor_refs) != 1 or len(next(iter(predecessor_refs), ())) != 1:
            issues.extend(
                f"{label}: episode split successors must consume the same one current head"
                for label in labels
            )
            continue
        if len(majors) != 1:
            issues.extend(
                f"{label}: episode split successors must share one reviewed major pair"
                for label in labels
            )
        predecessor_ref = next(iter(next(iter(predecessor_refs))))
        predecessor = _load_indexed_episode_by_ref(connection, predecessor_ref)
        if predecessor is None:
            continue
        owned: set[str] = set()
        overlap = False
        for node in nodes:
            members = set(node.member_turn_refs)
            if not members or owned.intersection(members):
                overlap = True
            owned.update(members)
        if overlap or owned != set(predecessor.member_turn_refs):
            issues.extend(
                f"{label}: episode split members must be nonempty disjoint partitions of the predecessor"
                for label in labels
            )
        partition_roots = [node.member_turn_root or "" for node in nodes]
        if partition_roots != sorted(partition_roots) or len(
            set(partition_roots)
        ) != len(partition_roots):
            issues.extend(
                f"{label}: episode split ordinal must match canonical partition-root order"
                for label in labels
            )
        for node in nodes:
            if node.transition_group_ordinal is None:
                continue
            expected_anchor, expected_lineage = _derive_split_episode_identity(
                predecessor.episode_anchor or "", partition_roots, node.transition_group_ordinal
            )
            if (
                node.episode_anchor != expected_anchor
                or node.episode_lineage_id != expected_lineage
                or node.episode_lineage_id == predecessor.episode_lineage_id
            ):
                issues.append(
                    f"{node.label}: episode split successor identity is not deterministic"
                )


def _validate_indexed_episode_transitions(
    index: _ValidationIndex, issues: list[str]
) -> None:
    connection = index.connection
    cursor = _indexed_episode_rows(connection)
    while True:
        rows = cursor.fetchmany(MAX_INDEX_QUERY_ROWS)
        if not rows:
            break
        for row in rows:
            if _issues_full(issues):
                return
            node = _indexed_episode_node_from_row(connection, row)
            predecessors = tuple(
                predecessor
                for predecessor_ref in node.predecessors
                if (
                    predecessor := _load_indexed_episode_by_ref(
                        connection, predecessor_ref
                    )
                )
                is not None
            )
            _validate_episode_transition_node(node, predecessors, issues)
            if node.episode_operation == "merge" and len(predecessors) == len(
                node.predecessors
            ):
                member_sets = [set(item.member_turn_refs) for item in predecessors]
                union: set[str] = set()
                overlap = False
                for member_set in member_sets:
                    if union.intersection(member_set):
                        overlap = True
                    union.update(member_set)
                if overlap or union != set(node.member_turn_refs):
                    issues.append(
                        f"{node.label}: episode merge members must equal the disjoint predecessor union"
                    )
                expected_anchor, expected_lineage = _derive_merge_episode_identity(
                    (
                        (predecessor.episode_anchor or "", predecessor.current)
                        for predecessor in predecessors
                    )
                )
                if (
                    node.episode_anchor != expected_anchor
                    or node.episode_lineage_id != expected_lineage
                    or node.episode_lineage_id
                    in {predecessor.episode_lineage_id for predecessor in predecessors}
                ):
                    issues.append(
                        f"{node.label}: episode merge successor identity is not deterministic"
                    )

    _validate_indexed_episode_split_groups(index, issues)
    if _issues_full(issues):
        return

    invalid_transition_groups = connection.execute(
        """
        SELECT fact.transition_group_id
        FROM episode_revision_facts AS fact
        JOIN revisions AS revision ON revision.id = fact.revision_id
        WHERE fact.operation IN ('split', 'merge')
          AND fact.transition_group_id IS NOT NULL
        GROUP BY fact.transition_group_id
        HAVING COUNT(DISTINCT revision.transaction_ref) != 1
            OR COUNT(DISTINCT fact.operation) != 1
            OR (
                SUM(CASE WHEN fact.operation = 'merge' THEN 1 ELSE 0 END) > 0
                AND COUNT(*) != 1
            )
        ORDER BY fact.transition_group_id
        """
    )
    for (group_id,) in invalid_transition_groups:
        for (label,) in connection.execute(
            """
            SELECT revision.label
            FROM episode_revision_facts AS fact
            JOIN revisions AS revision ON revision.id = fact.revision_id
            WHERE fact.transition_group_id = ?
              AND fact.operation IN ('split', 'merge')
            ORDER BY revision.label
            """,
            (group_id,),
        ):
            if _issues_full(issues):
                return
            issues.append(
                f"{label}: episode transition group must identify one atomic split or merge"
            )

    multiply_split_predecessors = connection.execute(
        """
        SELECT predecessor.predecessor_ref
        FROM revision_predecessors AS predecessor
        JOIN revisions AS revision ON revision.id = predecessor.revision_id
        JOIN episode_revision_facts AS fact ON fact.revision_id = revision.id
        WHERE predecessor.family = 'episode' AND fact.operation = 'split'
        GROUP BY predecessor.predecessor_ref
        HAVING COUNT(DISTINCT revision.transaction_ref) > 1
            OR COUNT(DISTINCT fact.transition_group_id) > 1
        ORDER BY predecessor.predecessor_ref
        """
    )
    for (predecessor_ref,) in multiply_split_predecessors:
        for (label,) in connection.execute(
            """
            SELECT revision.label
            FROM revision_predecessors AS predecessor
            JOIN revisions AS revision ON revision.id = predecessor.revision_id
            JOIN episode_revision_facts AS fact ON fact.revision_id = revision.id
            WHERE predecessor.family = 'episode'
              AND predecessor.predecessor_ref = ?
              AND fact.operation = 'split'
            ORDER BY revision.label
            """,
            (predecessor_ref,),
        ):
            if _issues_full(issues):
                return
            issues.append(
                f"{label}: episode predecessor may be consumed by only one split group"
            )

    duplicate_lineage_roots = connection.execute(
        """
        SELECT fact.lineage_id
        FROM episode_revision_facts AS fact
        WHERE fact.operation IN ('create', 'split', 'merge')
        GROUP BY fact.lineage_id HAVING COUNT(*) > 1
        ORDER BY fact.lineage_id
        """
    )
    for (lineage_id,) in duplicate_lineage_roots:
        for (label,) in connection.execute(
            """
            SELECT revision.label
            FROM episode_revision_facts AS fact
            JOIN revisions AS revision ON revision.id = fact.revision_id
            WHERE fact.lineage_id = ? AND fact.operation IN ('create', 'split', 'merge')
            ORDER BY revision.label
            """,
            (lineage_id,),
        ):
            if _issues_full(issues):
                return
            issues.append(
                f"{label}: episode lineage may have only one root transition"
            )

    duplicate_anchor_roots = connection.execute(
        """
        SELECT fact.anchor
        FROM episode_revision_facts AS fact
        WHERE fact.operation IN ('create', 'split', 'merge')
        GROUP BY fact.anchor HAVING COUNT(*) > 1
        ORDER BY fact.anchor
        """
    )
    for (anchor,) in duplicate_anchor_roots:
        for (label,) in connection.execute(
            """
            SELECT revision.label
            FROM episode_revision_facts AS fact
            JOIN revisions AS revision ON revision.id = fact.revision_id
            WHERE fact.anchor = ? AND fact.operation IN ('create', 'split', 'merge')
            ORDER BY revision.label
            """,
            (anchor,),
        ):
            if _issues_full(issues):
                return
            issues.append(
                f"{label}: episode anchor may have only one root transition"
            )

    overlapping_current_heads = connection.execute(
        """
        SELECT DISTINCT left_revision.label, right_revision.label
        FROM episode_revision_facts AS left_fact
        JOIN revisions AS left_revision ON left_revision.id = left_fact.revision_id
        JOIN episode_members AS left_member
          ON left_member.revision_id = left_fact.revision_id
        JOIN episode_members AS right_member
          ON right_member.turn_ref = left_member.turn_ref
        JOIN episode_revision_facts AS right_fact
          ON right_fact.revision_id = right_member.revision_id
        JOIN revisions AS right_revision ON right_revision.id = right_fact.revision_id
        WHERE left_fact.revision_id < right_fact.revision_id
          AND left_fact.segmentation_major = right_fact.segmentation_major
          AND left_fact.policy_major = right_fact.policy_major
          AND NOT EXISTS (
              SELECT 1 FROM revision_predecessors AS left_successor
              WHERE left_successor.family = 'episode'
                AND left_successor.predecessor_ref = left_revision.current_ref
          )
          AND NOT EXISTS (
              SELECT 1 FROM revision_predecessors AS right_successor
              WHERE right_successor.family = 'episode'
                AND right_successor.predecessor_ref = right_revision.current_ref
          )
        ORDER BY left_revision.label, right_revision.label
        """
    )
    while True:
        rows = overlapping_current_heads.fetchmany(MAX_INDEX_QUERY_ROWS)
        if not rows:
            break
        for left_label, right_label in rows:
            if _issues_full(issues):
                return
            issues.append(
                f"{left_label}: compatible current episode heads must not share member turns"
            )
            if not _issues_full(issues):
                issues.append(
                    f"{right_label}: compatible current episode heads must not share member turns"
                )


def _validate_indexed_revision_relationships(
    index: _ValidationIndex, issues: list[str]
) -> bool:
    """Validate cross-run edges and return whether revision IDs are unique."""

    connection = index.connection
    duplicate_groups = connection.execute(
        """
        SELECT family, current_ref FROM revisions
        GROUP BY family, current_ref HAVING COUNT(*) > 1
        ORDER BY family, current_ref
        """
    )
    unique = True
    for family, current_ref in duplicate_groups:
        unique = False
        for (label,) in connection.execute(
            """
            SELECT label FROM revisions
            WHERE family = ? AND current_ref = ? ORDER BY label
            """,
            (family, current_ref),
        ):
            if _issues_full(issues):
                return False
            issues.append(
                f"{label}: {family} revision reference is not globally unique"
            )

    missing_predecessors = connection.execute(
        """
        SELECT revision.label, revision.family
        FROM revision_predecessors AS predecessor
        JOIN revisions AS revision ON revision.id = predecessor.revision_id
        LEFT JOIN revisions AS target
          ON target.family = predecessor.family
         AND target.current_ref = predecessor.predecessor_ref
        WHERE target.id IS NULL
        ORDER BY revision.label, predecessor.predecessor_ref
        """
    )
    for label, family in missing_predecessors:
        if _issues_full(issues):
            return unique
        issues.append(
            f"{label}: {family} predecessor revision is not present in retained v2 history"
        )

    invalid_edges = connection.execute(
        """
        SELECT revision.label, revision.family,
               revision.transaction_ref = target.transaction_ref AS same_transaction,
               revision.entity_ref, target.entity_ref, revision.kind
        FROM revision_predecessors AS predecessor
        JOIN revisions AS revision ON revision.id = predecessor.revision_id
        JOIN revisions AS target
          ON target.family = predecessor.family
         AND target.current_ref = predecessor.predecessor_ref
        ORDER BY revision.label, predecessor.predecessor_ref
        """
    )
    for (
        label,
        family,
        same_transaction,
        entity_ref,
        target_entity_ref,
        kind,
    ) in invalid_edges:
        if _issues_full(issues):
            return unique
        if same_transaction:
            issues.append(
                f"{label}: {family} predecessor must come from an earlier run"
            )
        if (
            entity_ref is not None
            and target_entity_ref is not None
            and kind not in {"split", "merge", "identity_reconciliation"}
            and entity_ref != target_entity_ref
        ):
            issues.append(
                f"{label}: ordinary revision must preserve its entity reference"
            )

    closure_groups = connection.execute(
        """
        SELECT predecessor.family, predecessor.predecessor_ref,
               COUNT(*) AS closer_count,
               COUNT(DISTINCT revision.transaction_ref) AS transaction_count,
               MIN(revision.kind = 'split') AS all_split
        FROM revision_predecessors AS predecessor
        JOIN revisions AS revision ON revision.id = predecessor.revision_id
        GROUP BY predecessor.family, predecessor.predecessor_ref
        HAVING transaction_count > 1 OR (closer_count > 1 AND all_split = 0)
        ORDER BY predecessor.family, predecessor.predecessor_ref
        """
    )
    for family, predecessor_ref, _count, transaction_count, all_split in closure_groups:
        if _issues_full(issues):
            return unique
        for (label,) in connection.execute(
            """
            SELECT revision.label
            FROM revision_predecessors AS predecessor
            JOIN revisions AS revision ON revision.id = predecessor.revision_id
            WHERE predecessor.family = ? AND predecessor.predecessor_ref = ?
            ORDER BY revision.label
            """,
            (family, predecessor_ref),
        ):
            if _issues_full(issues):
                return unique
            if transaction_count > 1:
                issues.append(
                    f"{label}: {family} predecessor revision was already closed by another run"
                )
            elif not all_split:
                issues.append(
                    f"{label}: {family} predecessor may have multiple successors only in one split"
                )
    return unique


def _validate_indexed_revision_cycles(
    index: _ValidationIndex, issues: list[str]
) -> None:
    connection = index.connection
    families = [
        row[0]
        for row in connection.execute(
            "SELECT DISTINCT family FROM revisions ORDER BY family"
        )
    ]
    for family in families:
        if _issues_full(issues):
            return
        connection.executescript(
            """
            DROP TABLE IF EXISTS temp.graph_work;
            DROP TABLE IF EXISTS temp.graph_ready;
            CREATE TEMP TABLE graph_work (
                revision_id INTEGER PRIMARY KEY,
                current_ref TEXT NOT NULL,
                remaining INTEGER NOT NULL,
                processed INTEGER NOT NULL DEFAULT 0
            );
            CREATE TEMP TABLE graph_ready (
                revision_id INTEGER PRIMARY KEY
            );
            """
        )
        connection.execute(
            """
            INSERT INTO graph_work(revision_id, current_ref, remaining)
            SELECT revision.id, revision.current_ref,
                   COUNT(target.id)
            FROM revisions AS revision
            LEFT JOIN revision_predecessors AS predecessor
              ON predecessor.revision_id = revision.id
            LEFT JOIN revisions AS target
              ON target.family = predecessor.family
             AND target.current_ref = predecessor.predecessor_ref
            WHERE revision.family = ?
            GROUP BY revision.id, revision.current_ref
            """,
            (family,),
        )
        connection.execute(
            "INSERT INTO graph_ready SELECT revision_id FROM graph_work WHERE remaining = 0"
        )
        total = connection.execute("SELECT COUNT(*) FROM graph_work").fetchone()[0]
        processed = 0
        while True:
            ready = connection.execute(
                """
                SELECT revision_id, current_ref FROM graph_work
                WHERE revision_id IN (SELECT revision_id FROM graph_ready)
                ORDER BY revision_id LIMIT ?
                """,
                (MAX_INDEX_QUERY_ROWS,),
            ).fetchall()
            if not ready:
                break
            for revision_id, current_ref in ready:
                connection.execute(
                    "DELETE FROM graph_ready WHERE revision_id = ?", (revision_id,)
                )
                connection.execute(
                    "UPDATE graph_work SET processed = 1 WHERE revision_id = ?",
                    (revision_id,),
                )
                processed += 1
                successors = connection.execute(
                    """
                    SELECT DISTINCT successor.id
                    FROM revision_predecessors AS predecessor
                    JOIN revisions AS successor
                      ON successor.id = predecessor.revision_id
                    JOIN graph_work AS work ON work.revision_id = successor.id
                    WHERE predecessor.family = ?
                      AND predecessor.predecessor_ref = ?
                      AND work.processed = 0
                    ORDER BY successor.id
                    """,
                    (family, current_ref),
                )
                while True:
                    successor_page = successors.fetchmany(MAX_INDEX_QUERY_ROWS)
                    if not successor_page:
                        break
                    for (successor_id,) in successor_page:
                        connection.execute(
                            """
                            UPDATE graph_work SET remaining = remaining - 1
                            WHERE revision_id = ?
                            """,
                            (successor_id,),
                        )
                        remaining = connection.execute(
                            """
                            SELECT remaining FROM graph_work WHERE revision_id = ?
                            """,
                            (successor_id,),
                        ).fetchone()[0]
                        if remaining == 0:
                            connection.execute(
                                "INSERT OR IGNORE INTO graph_ready VALUES (?)",
                                (successor_id,),
                            )
        if processed != total:
            issues.append(f"runs: {family} revision graph contains a cycle")


def _validate_indexed_revision_graph(
    index: _ValidationIndex, issues: list[str]
) -> None:
    unique = _validate_indexed_revision_relationships(index, issues)
    if unique and not _issues_full(issues):
        _validate_indexed_revision_cycles(index, issues)
    if unique and not _issues_full(issues):
        _validate_indexed_episode_transitions(index, issues)


def _decode_indexed_trend_snapshot(payload: str) -> _TrendSnapshot:
    value = json.loads(payload)
    summary_value = value["summary"]
    summary = (
        None
        if summary_value is None
        else _SummaryComparison(
            prior_run_revision_ref=summary_value["prior_run_revision_ref"],
            direction=summary_value["direction"],
            metric_refs=tuple(summary_value["metric_refs"]),
        )
    )
    return _TrendSnapshot(
        label=value["label"],
        run_revision_ref=value["run_revision_ref"],
        mode=value["mode"],
        publication_time=dt.datetime.fromisoformat(value["publication_time"]),
        window_start=dt.datetime.fromisoformat(value["window_start"]),
        window_end=dt.datetime.fromisoformat(value["window_end"]),
        supersedes_run_revision_refs=tuple(value["supersedes_run_revision_refs"]),
        rates={
            (policy_ref, model_ref, metric_id): Decimal(rate)
            for policy_ref, model_ref, metric_id, rate in value["rates"]
        },
        comparisons=tuple(
            _TrendComparison(
                metric_ref=comparison["metric_ref"],
                key=tuple(comparison["key"]),
                prior_run_revision_ref=comparison["prior_run_revision_ref"],
                claimed_delta=Decimal(comparison["claimed_delta"]),
            )
            for comparison in value["comparisons"]
        ),
        summary=summary,
    )


def _resolve_indexed_compatible_prior(
    index: _ValidationIndex,
    current: _TrendSnapshot,
    prior_ref: str,
    artifact: str,
    issues: list[str],
) -> _TrendSnapshot | None:
    rows = index.connection.execute(
        """
        SELECT payload FROM trend_snapshots
        WHERE run_revision_ref = ? ORDER BY id LIMIT 2
        """,
        (prior_ref,),
    ).fetchall()
    if len(rows) != 1 or prior_ref == current.run_revision_ref:
        issues.append(
            f"{current.label}/{artifact}: prior run revision is not present as an eligible trend observation"
        )
        return None
    prior = _decode_indexed_trend_snapshot(rows[0][0])
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
    superseders = index.connection.execute(
        """
        SELECT snapshot.payload
        FROM trend_supersession AS supersession
        JOIN trend_snapshots AS snapshot
          ON snapshot.id = supersession.snapshot_id
        WHERE supersession.predecessor_ref = ?
        ORDER BY snapshot.id
        """,
        (prior_ref,),
    )
    for (payload,) in superseders:
        replacement = _decode_indexed_trend_snapshot(payload)
        if replacement.publication_time <= current.publication_time:
            issues.append(
                f"{current.label}/{artifact}: prior run revision was not active at the current publication point"
            )
            return None
    return prior


def _validate_indexed_trend_snapshot(
    index: _ValidationIndex,
    current: _TrendSnapshot,
    issues: list[str],
) -> None:
    for comparison in current.comparisons:
        if _issues_full(issues):
            return
        prior = _resolve_indexed_compatible_prior(
            index,
            current,
            comparison.prior_run_revision_ref,
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
        return
    prior = _resolve_indexed_compatible_prior(
        index,
        current,
        summary.prior_run_revision_ref,
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
        return
    direction_set = set(exact_directions)
    if {"improved", "regressed"}.issubset(direction_set):
        issues.append(
            f"{current.label}/summary.json: change_from_prior cannot collapse mixed exact normalized deltas"
        )
        return
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


def _validate_indexed_trend_comparisons(
    index: _ValidationIndex, issues: list[str]
) -> None:
    cursor = index.connection.execute("SELECT payload FROM trend_snapshots ORDER BY id")
    while not _issues_full(issues):
        rows = cursor.fetchmany(MAX_INDEX_QUERY_ROWS)
        if not rows:
            return
        for (payload,) in rows:
            _validate_indexed_trend_snapshot(
                index, _decode_indexed_trend_snapshot(payload), issues
            )
            if _issues_full(issues):
                return


def _validate_indexed_history_identity(
    index: _ValidationIndex, issues: list[str]
) -> None:
    bundle_count, keyed_count, first_key_id, last_key_id = index.connection.execute(
        """
        SELECT COUNT(*), COUNT(key_id), MIN(key_id), MAX(key_id)
        FROM bundle_facts
        """
    ).fetchone()
    if bundle_count and (keyed_count != bundle_count or first_key_id != last_key_id):
        issues.append(HISTORY_IDENTITY_ISSUE)


def _validate_indexed_history(index: _ValidationIndex, issues: list[str]) -> None:
    _validate_indexed_history_identity(index, issues)
    if not _issues_full(issues):
        _validate_indexed_run_supersession(index, issues)
    if not _issues_full(issues):
        _validate_indexed_campaign_consistency(index, issues)
    if not _issues_full(issues):
        _validate_indexed_campaign_revision_ownership(index, issues)
    if not _issues_full(issues):
        _validate_indexed_trend_comparisons(index, issues)
    if not _issues_full(issues):
        _validate_indexed_revision_graph(index, issues)


def validate_v2_runs_with_inventory(
    root: Path, visible_files: Iterable[Path] | None = None
) -> tuple[list[str], _ManifestInventory | tuple[Path, ...]]:
    """Validate immutable Session Retrospective v2 retained-run bundles.

    Diagnostics intentionally avoid JSON values and unvalidated path components.
    The inventory is returned only when the complete v2 tree is structurally valid.
    """

    root = Path(os.path.abspath(os.fspath(root)))
    try:
        root_descriptor = _open_validation_root(root)
    except OSError as exc:
        if exc.errno in {errno.ENOENT, errno.ENOTDIR}:
            return ["root must be an existing directory"], ()
        return ["root could not be opened safely"], ()

    issues = _IssueCollector()
    try:
        validators = _load_schema_validators()
        if validators is None:
            issues.append(SCHEMA_UNAVAILABLE_ISSUE)
            return sorted(issues), ()
        privacy_validator = _load_privacy_validator()
        if privacy_validator is None:
            issues.append(PRIVACY_UNAVAILABLE_ISSUE)
            return sorted(issues), ()

        with tempfile.TemporaryDirectory(
            prefix="retrospective-history-v2-index-"
        ) as temporary:
            index: _ValidationIndex | None = None
            try:
                index = _ValidationIndex(Path(temporary) / "history.sqlite3")
                _populate_validation_index(
                    root, root_descriptor, visible_files, index, issues
                )
                if PATH_COLLISION_ISSUE in issues or DISCOVERY_LIMIT_ISSUE in issues:
                    return sorted(issues), ()
                for page in index.iter_bundle_pages():
                    if _issues_full(issues):
                        break
                    for bundle_id, bundle in page:
                        if frozenset(bundle.files) != ARTIFACT_BASENAME_SET:
                            issues.append(
                                f"{bundle.label}: run directory must contain exactly the eight required artifacts"
                            )
                        budget = _ReadBudget(MAX_BUNDLE_ARTIFACT_BYTES)
                        _validate_bundle(
                            bundle,
                            root_descriptor,
                            issues,
                            validators,
                            privacy_validator,
                            budget,
                        )
                        snapshot = _build_trend_snapshot(bundle)
                        index.record_bundle(bundle_id, bundle)
                        if snapshot is not None:
                            index.record_trend_snapshot(bundle_id, snapshot)
                        bundle.raw.clear()
                        bundle.documents.clear()
                        bundle.rows.clear()
                        bundle.revisions.clear()
                        if _issues_full(issues):
                            break
                    index.connection.commit()
                if not _issues_full(issues):
                    _validate_indexed_history(index, issues)
                sorted_issues = sorted(issues)
                if sorted_issues:
                    return sorted_issues, ()
                return [], _ManifestInventory(index.iter_manifest_paths())
            except (OSError, sqlite3.Error):
                issues.append(VALIDATION_WORK_LIMIT_ISSUE)
                return sorted(issues), ()
            finally:
                if index is not None:
                    index.close()
    finally:
        os.close(root_descriptor)


def validate_v2_runs(
    root: Path, visible_files: Iterable[Path] | None = None
) -> list[str]:
    """Validate v2 runs without exposing the admitted manifest inventory."""

    issues, inventory = validate_v2_runs_with_inventory(root, visible_files)
    close_inventory = getattr(inventory, "close", None)
    if callable(close_inventory):
        close_inventory()
    return issues


__all__ = ["validate_v2_runs", "validate_v2_runs_with_inventory"]
