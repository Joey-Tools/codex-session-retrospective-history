#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass, fields
import datetime as dt
from email import utils as email_utils
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Iterable, Iterator
import unicodedata
from urllib import error, parse, request


OID_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GITHUB_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$"
)
MERGE_GROUP_SNAPSHOT_KIND = "retrospective-history-v2-merge-group-snapshot"
MERGE_GROUP_RUNTIME_EVIDENCE_KIND = (
    "retrospective-history-v2-merge-group-runtime-evidence"
)
MERGE_GROUP_LIVE_AUTHORITY_KIND = "retrospective-history-v2-merge-group-live-authority"
MERGE_GROUP_PREDECESSOR_AUTHORITY_KIND = (
    "retrospective-history-v2-merge-group-predecessor-authority"
)
MERGE_GROUP_ADMISSION_KIND = "retrospective-history-v2-merge-group-admission"
DEFAULT_AUTHORITY_RECEIPT_KIND = "retrospective-history-v2-default-authority"
RUNTIME_AUTHORITY_RECEIPT_KIND = "retrospective-history-v2-runtime-authority"
GITHUB_SQUASH_RECEIPT_KIND = "retrospective-history-v2-github-squash-verification"
DEFAULT_CANDIDATE_EVIDENCE_KIND = "retrospective-history-v2-default-candidate-evidence"
DEFAULT_ADMISSION_CHECK_KIND = "retrospective-history-v2-admission-check"
POST_MERGE_ADMISSION_BINDING_KIND = (
    "retrospective-history-v2-post-merge-admission-binding"
)
DEFAULT_BRANCH = "master"
DEFAULT_BRANCH_REF = f"refs/heads/{DEFAULT_BRANCH}"
REQUIRED_CHECK_CONTEXT = "Trusted history gate"
ADMISSION_RECORD_CHECK_CONTEXT = "Trusted history admission record"
ADMISSION_RECORD_OUTPUT_TITLE = "Retrospective history v2 admission"
ADMISSION_RECORD_EXTERNAL_ID_PREFIX = "retrospective-history-v2-admission:"
ADMISSION_RECORD_OUTPUT_SUMMARY_PREFIX = "Admission record SHA-256: "
ADMISSION_RECORD_APP_ID: int | None = None
ADMISSION_RECORD_APP_SLUG = "retrospective-history-admission"
POST_MERGE_AUDIT_CHECK_CONTEXT = "Post-merge default audit"
GITHUB_ACTIONS_APP_ID = 15368
GITHUB_ACTIONS_APP_SLUG = "github-actions"
PERMANENT_WORKFLOW_NAME = "CI"
PERMANENT_WORKFLOW_PATH = ".github/workflows/ci.yml"
BOOTSTRAP_CANDIDATE_REF = "wip/session-retrospective-v2-history-bootstrap"
GITHUB_PAGE_SIZE = 100
MAX_GITHUB_PAGES = 10
GITHUB_TERMINAL_CONCLUSIONS = frozenset(
    {
        "action_required",
        "cancelled",
        "failure",
        "neutral",
        "skipped",
        "stale",
        "startup_failure",
        "success",
        "timed_out",
    }
)
MERGE_GROUP_HEAD_REF_RE = re.compile(
    r"^refs/heads/gh-readonly-queue/master/"
    r"pr-(?P<number>[1-9][0-9]*)-"
    r"(?P<suffix>[A-Za-z0-9][A-Za-z0-9._-]{0,127})$"
)
PERMANENT_TRUST_GENERATION_PATHS = (
    ".github/workflows/ci.yml",
    ".gitignore",
    "AGENTS.md",
    "README.md",
    "data/README.md",
    "reports/README.md",
    "requirements-v2.in",
    "requirements-v2.txt",
    "retrospective-history-v2-admin-public.asc",
    "retrospective-history-v2-publisher.asc",
    "schemas/retained-manifest-v1.schema.json",
    "schemas/retained-manifest-v2.schema.json",
    "schemas/session-retrospective-v1.schema.json",
    "schemas/session-retrospective-v2.schema.json",
    "scripts/retrospective_history_attestation_v2.py",
    "scripts/retrospective_history_credentials_v2.py",
    "scripts/retrospective_history_git_v2.py",
    "scripts/retrospective_history_merge_v2.py",
    "scripts/retrospective_history_privacy_v2.py",
    "scripts/retrospective_history_templates_v2.py",
    "scripts/retrospective_history_v2.py",
    "scripts/trusted_history_ci.py",
    "scripts/validate_retained_history.py",
    "tests/test_retrospective_history_git_v2.py",
    "tests/test_retrospective_history_merge_v2.py",
    "tests/test_retrospective_history_privacy_v2.py",
    "tests/test_retrospective_history_v2.py",
    "tests/test_retrospective_history_v2_ci.py",
    "tests/test_retrospective_history_v2_schema_extensions.py",
    "tests/test_validate_retained_history.py",
)
MAX_POLICY_JSON_BYTES = 64 * 1024
MAX_GITHUB_SQUASH_RECEIPT_BYTES = 128 * 1024
MAX_PREFLIGHT_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_HTTP_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_LIVE_GITHUB_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_LIVE_GITHUB_REQUESTS = 160
MAX_COMMIT_BYTES = 64 * 1024
MAX_TREE_ENTRIES = 8192
MAX_RANGE_TREE_ENTRIES = 65_536
MAX_RANGE_TREE_PATH_BYTES = 8 * 1024 * 1024
MAX_BLOB_ENTRIES = 4096
MAX_BLOB_BYTES = 2 * 1024 * 1024
MAX_TREE_BYTES = 16 * 1024 * 1024
MAX_TREE_PATH_DEPTH = 32
GIT_TIMEOUT_SECONDS = 20.0
HTTP_TIMEOUT_SECONDS = 20.0
PROCESS_TERMINATE_GRACE_SECONDS = 0.5
MERGE_GROUP_LIVE_AUTHORITY_TTL_SECONDS = 30
QUEUE_RUNTIME_PROFILE = "credential-free-nonprivileged-exact-q-v1"
QUEUE_RUNTIME_PYTHON_VERSION = "3.13.12"
QUEUE_RUNTIME_COMPILE_COMMAND = (
    "-I",
    "-B",
    "-X",
    "pycache_prefix=<runtime-private>",
    "-m",
    "compileall",
    "-q",
    "-f",
    "scripts",
    "tests",
)
QUEUE_RUNTIME_TEST_COMMAND = (
    "-I",
    "-B",
    "-X",
    "pycache_prefix=<runtime-private>",
    "-m",
    "unittest",
    "discover",
    "-s",
    "tests",
)


def _runtime_command_sha256(arguments: tuple[str, ...]) -> str:
    return hashlib.sha256(
        b"\0".join(value.encode("ascii") for value in arguments)
    ).hexdigest()


QUEUE_RUNTIME_COMPILE_COMMAND_SHA256 = _runtime_command_sha256(
    QUEUE_RUNTIME_COMPILE_COMMAND
)
QUEUE_RUNTIME_TEST_COMMAND_SHA256 = _runtime_command_sha256(QUEUE_RUNTIME_TEST_COMMAND)
BOOTSTRAP_TEMPORARY_PATHS = (
    ".github/bootstrap/session-retrospective-v2-permanent-ci.yml",
    ".github/workflows/session-retrospective-v2-bootstrap.yml",
    "tests/test_session_retrospective_v2_bootstrap.py",
)
BOOTSTRAP_CI_PATH = ".github/workflows/ci.yml"
BOOTSTRAP_CI_TEMPLATE_PATH = (
    ".github/bootstrap/session-retrospective-v2-permanent-ci.yml"
)
LEGACY_CI_BLOB_OID = "145e8de8a055794b85af6461a69e50715913ea6f"
PERMANENT_CI_BLOB_OID = "ad0c20778d6e9c66e8537e5412554a1ff26b663c"
_TRUSTED_VALIDATOR_MODULE: Any | None = None
_FORBIDDEN_CANDIDATE_COMPONENTS = frozenset(
    {
        ".codex",
        ".codex-local",
        ".codex-tmp",
        "archived_sessions",
        "raw",
        "scratch",
        "sessions",
        "transient",
    }
)
_FORBIDDEN_CANDIDATE_FILENAMES = frozenset(
    {
        "auth.json",
        "config.toml",
        "history.jsonl",
        "retrospective-history-v2-admin.asc",
        "session_index.jsonl",
        "source_metadata.json",
        "shard_manifest.json",
        "shards.jsonl",
        "turn_summaries.jsonl",
    }
)
_FORBIDDEN_CANDIDATE_COMPACT_PARTS = frozenset(
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


class GateError(RuntimeError):
    pass


@dataclass
class GitHubReadBudget:
    deadline: float
    clock: Callable[[], float]
    remaining_requests: int = MAX_LIVE_GITHUB_REQUESTS
    remaining_bytes: int = MAX_LIVE_GITHUB_RESPONSE_BYTES

    def checkpoint(self) -> None:
        if self.clock() >= self.deadline:
            raise GateError("GitHub live revalidation exceeded its deadline")

    def begin_request(self) -> float:
        self.checkpoint()
        if self.remaining_requests <= 0:
            raise GateError("GitHub live revalidation request budget exceeded")
        self.remaining_requests -= 1
        return self.operation_timeout()

    def operation_timeout(self) -> float:
        remaining_seconds = self.deadline - self.clock()
        if remaining_seconds <= 0:
            raise GateError("GitHub live revalidation exceeded its deadline")
        return min(HTTP_TIMEOUT_SECONDS, remaining_seconds)

    def consume_bytes(self, count: int) -> None:
        if count < 0 or count > self.remaining_bytes:
            raise GateError("GitHub live revalidation byte budget exceeded")
        self.remaining_bytes -= count
        self.checkpoint()


_ACTIVE_GITHUB_READ_BUDGET: ContextVar[GitHubReadBudget | None] = ContextVar(
    "active_github_read_budget",
    default=None,
)


@contextmanager
def github_read_budget_scope(budget: GitHubReadBudget) -> Iterator[None]:
    if _ACTIVE_GITHUB_READ_BUDGET.get() is not None:
        raise GateError("GitHub live revalidation budget scope is nested")
    token = _ACTIVE_GITHUB_READ_BUDGET.set(budget)
    try:
        yield
    finally:
        _ACTIVE_GITHUB_READ_BUDGET.reset(token)


@dataclass(frozen=True)
class PullRequestSnapshot:
    number: int
    node_id: str
    state: str
    merged: bool
    merged_at: None
    draft: bool
    base_repository: str
    base_ref: str
    base_sha: str
    head_repository: str
    head_ref: str
    head_sha: str


@dataclass(frozen=True)
class TreeEntry:
    path: str
    mode: str
    object_type: str
    object_id: str
    size: int | None


@dataclass(frozen=True)
class CandidateCommit:
    object_id: str
    tree_oid: str
    parents: tuple[str, ...]


@dataclass(frozen=True)
class CandidateTree:
    tree_oid: str
    entries: tuple[TreeEntry, ...]


@dataclass(frozen=True)
class GitPreflight:
    schema_version: int
    policy: str
    base_sha: str
    head_sha: str
    head_tree_sha: str
    commit_count: int
    tree_entry_count: int
    blob_entry_count: int
    total_blob_bytes: int
    commits: tuple[CandidateCommit, ...]
    trees: tuple[CandidateTree, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy": self.policy,
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
            "head_tree_sha": self.head_tree_sha,
            "commit_count": self.commit_count,
            "tree_entry_count": self.tree_entry_count,
            "blob_entry_count": self.blob_entry_count,
            "total_blob_bytes": self.total_blob_bytes,
            "commits": [asdict(commit) for commit in self.commits],
            "trees": [
                {
                    "tree_oid": tree.tree_oid,
                    "entries": [asdict(entry) for entry in tree.entries],
                }
                for tree in self.trees
            ],
        }

    @property
    def entries(self) -> tuple[TreeEntry, ...]:
        for tree in self.trees:
            if tree.tree_oid == self.head_tree_sha:
                return tree.entries
        raise GateError("candidate preflight head tree is unavailable")


@dataclass(frozen=True)
class AuthoritySnapshot:
    head_sha: str
    tree_sha: str


@dataclass(frozen=True)
class RuntimeAuthoritySnapshot:
    head_sha: str
    tree_sha: str
    authority_uid: int
    execution_root_device: int
    execution_root_inode: int


@dataclass(frozen=True)
class MergeGroupSnapshot:
    repository: str
    repository_id: int
    base_ref: str
    base_sha: str
    queue_ref: str
    queue_sha: str
    workflow_sha: str
    pull_request_number: int
    pull_request_node_id: str
    pull_request_title: str
    candidate_ref: str
    candidate_sha: str
    required_check: str
    tcb_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "kind": MERGE_GROUP_SNAPSHOT_KIND,
            "repository": self.repository,
            "repository_id": self.repository_id,
            "base": {
                "ref": self.base_ref,
                "sha": self.base_sha,
            },
            "queue": {
                "ref": self.queue_ref,
                "sha": self.queue_sha,
            },
            "workflow_sha": self.workflow_sha,
            "pull_request": {
                "number": self.pull_request_number,
                "node_id": self.pull_request_node_id,
                "title": self.pull_request_title,
                "head_ref": self.candidate_ref,
                "head_sha": self.candidate_sha,
            },
            "tcb": {
                "required_check": self.required_check,
                "sha256": self.tcb_sha256,
            },
        }


@dataclass(frozen=True)
class PredecessorAuditEvidence:
    base_sha: str
    parent_sha: str
    pull_request_number: int
    pull_request_node_id: str
    candidate_sha: str
    merged_at: str
    check_run_id: int
    check_run_node_id: str
    check_suite_id: int
    workflow_run_id: int
    workflow_id: int
    workflow_run_attempt: int
    job_id: int
    workflow_created_at: str
    workflow_started_at: str
    workflow_updated_at: str
    started_at: str
    completed_at: str
    job_started_at: str
    job_completed_at: str
    sha256: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MergeGroupProjection:
    policy: str
    role: str
    candidate_base_sha: str
    queue_base_sha: str
    candidate_sha: str
    queue_sha: str
    candidate_tree_sha: str
    queue_tree_sha: str
    prospective_sha: str
    prospective_tree_sha: str
    squash_subject: str
    trust_generation: str
    changed_path_count: int
    delta_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": "retrospective-history-v2-merge-group-projection",
            "validation_mode": f"{self.policy}-prospective-squash",
            "policy": self.policy,
            "role": self.role,
            "candidate_base_sha": self.candidate_base_sha,
            "queue_base_sha": self.queue_base_sha,
            "candidate_sha": self.candidate_sha,
            "queue_sha": self.queue_sha,
            "candidate_tree_sha": self.candidate_tree_sha,
            "queue_tree_sha": self.queue_tree_sha,
            "prospective_sha": self.prospective_sha,
            "prospective_tree_sha": self.prospective_tree_sha,
            "squash_subject": self.squash_subject,
            "trust_generation": self.trust_generation,
            "changed_path_count": self.changed_path_count,
            "delta_sha256": self.delta_sha256,
        }


@dataclass(frozen=True)
class MergeGroupRuntimeEvidence:
    policy: str
    queue_base_sha: str
    candidate_sha: str
    queue_sha: str
    queue_tree_sha: str
    prospective_sha: str
    prospective_tree_sha: str
    projection_sha256: str
    python_version: str
    python_executable_sha256: str
    requirements_sha256: str
    runtime_profile: str
    compile_command_sha256: str
    test_command_sha256: str
    compile_exit_code: int
    test_exit_code: int
    authority_uid: int
    execution_uid: int
    credential_environment: str
    authority_write_access: bool
    source_authority_pristine: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": MERGE_GROUP_RUNTIME_EVIDENCE_KIND,
            **asdict(self),
        }


@dataclass(frozen=True)
class MergeGroupPredecessorAuthorityEvidence:
    mode: str
    base_sha: str
    queue_sha: str
    pull_request_number: int
    projection_sha256: str
    parent_sha: str | None
    audit: PredecessorAuditEvidence | None
    candidate_ref: str | None
    bootstrap_markers: tuple[str, ...]
    bootstrap_marker_sha256: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": MERGE_GROUP_PREDECESSOR_AUTHORITY_KIND,
            "mode": self.mode,
            "base_sha": self.base_sha,
            "queue_sha": self.queue_sha,
            "pull_request_number": self.pull_request_number,
            "projection_sha256": self.projection_sha256,
            "parent_sha": self.parent_sha,
            "audit": self.audit.as_dict() if self.audit is not None else None,
            "candidate_ref": self.candidate_ref,
            "bootstrap_markers": list(self.bootstrap_markers),
            "bootstrap_marker_sha256": self.bootstrap_marker_sha256,
        }


@dataclass(frozen=True)
class MergeGroupLiveAuthorityEvidence:
    snapshot_sha256: str
    tcb_sha256: str
    predecessor_authority: MergeGroupPredecessorAuthorityEvidence
    predecessor_authority_sha256: str
    observed_at: str
    valid_until: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": MERGE_GROUP_LIVE_AUTHORITY_KIND,
            "snapshot_sha256": self.snapshot_sha256,
            "tcb_sha256": self.tcb_sha256,
            "predecessor_authority": self.predecessor_authority.as_dict(),
            "predecessor_authority_sha256": self.predecessor_authority_sha256,
            "observed_at": self.observed_at,
            "valid_until": self.valid_until,
        }


def canonical_oid(value: Any, label: str) -> str:
    if not isinstance(value, str) or OID_RE.fullmatch(value) is None:
        raise GateError(f"{label} is not a canonical lowercase object ID")
    return value


def canonical_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise GateError(f"{label} is not a canonical SHA-256 digest")
    return value


def canonical_repository(value: Any) -> str:
    if not isinstance(value, str) or REPOSITORY_RE.fullmatch(value) is None:
        raise GateError("repository is not canonical")
    return value


def canonical_github_login(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?",
            value,
        )
        is None
    ):
        raise GateError(f"{label} login is invalid")
    return value


def canonical_positive_integer(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise GateError(f"{label} is not a positive integer")
    return value


def trusted_validator_module(*, contract: str = "bootstrap") -> Any:
    global _TRUSTED_VALIDATOR_MODULE
    module = _TRUSTED_VALIDATOR_MODULE
    if module is None:
        validator_path = (
            Path(__file__).resolve().with_name("validate_retained_history.py")
        )
        try:
            if not validator_path.is_file() or validator_path.is_symlink():
                raise GateError("trusted retained-history validator is unavailable")
            spec = importlib.util.spec_from_file_location(
                "_trusted_history_ci_validator",
                validator_path,
            )
            if spec is None or spec.loader is None:
                raise GateError("trusted retained-history validator is unavailable")
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
        except GateError:
            raise
        except Exception as exc:
            raise GateError(
                "trusted retained-history validator could not be loaded"
            ) from exc
    if contract == "bootstrap":
        required = (
            "parse_history_v2_commit_object",
            "HistoryV2SignatureVerifier",
            "history_v2_bootstrap_admission_app_id",
            "history_v2_bootstrap_markers",
            "validate_bootstrap_v2_candidate",
            "validate_history_v2_tree",
        )
    elif contract == "permanent":
        required = (
            "build_pull_request_candidate_plan",
            "history_v2_bootstrap_markers",
            "history_v2_mutable_artifact",
            "validate_fixed_head_snapshot",
            "validate_append_only_event_range",
            "validate_history_v2_tree",
        )
    elif contract == "github-squash":
        required = ("parse_history_v2_github_squash_commit",)
    else:
        raise GateError("trusted retained-history validator contract is invalid")
    if any(not callable(getattr(module, name, None)) for name in required):
        raise GateError("trusted retained-history validator contract is unavailable")
    _TRUSTED_VALIDATOR_MODULE = module
    return module


def object_value(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GateError(f"{label} is not an object")
    return value


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise GateError(f"{label} schema is invalid")


def reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise GateError("trusted JSON contains a duplicate object key")
        value[key] = child
    return value


def _read_policy_file_descriptor(descriptor: int, *, max_bytes: int) -> bytes:
    value = bytearray()
    while len(value) <= max_bytes:
        chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - len(value)))
        if not chunk:
            return bytes(value)
        value.extend(chunk)
    return bytes(value)


def read_stable_policy_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    expected_owner_uid: int | None = None,
) -> bytes:
    # The protected properties are path object identity, returned content, and
    # absence of group/other write access. Timestamps and link count are metadata
    # only and intentionally do not participate in the decision.
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except FileNotFoundError as exc:
        raise GateError(f"{label} is missing") from exc
    except PermissionError as exc:
        raise GateError(f"{label} is unreadable") from exc
    except OSError as exc:
        raise GateError(f"{label} could not be opened as a regular file") from exc

    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise GateError(f"{label} is not a regular file")
        if expected_owner_uid is not None and opened.st_uid != expected_owner_uid:
            raise GateError(f"{label} owner differs from the trusted authority")
        if opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise GateError(f"{label} access policy is unsafe")
        if opened.st_size <= 0 or opened.st_size > max_bytes:
            raise GateError(f"{label} exceeds the trusted size limit")

        first = _read_policy_file_descriptor(descriptor, max_bytes=max_bytes)
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_policy_file_descriptor(descriptor, max_bytes=max_bytes)
        final = os.fstat(descriptor)
    except GateError:
        raise
    except OSError as exc:
        raise GateError(f"{label} became unreadable while being read") from exc
    finally:
        os.close(descriptor)

    if len(first) != opened.st_size or len(second) != final.st_size or first != second:
        raise GateError(f"{label} content changed while being read")
    if (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino):
        raise GateError(f"{label} object identity changed while being read")
    if expected_owner_uid is not None and final.st_uid != expected_owner_uid:
        raise GateError(f"{label} owner changed while being read")
    if final.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise GateError(f"{label} access policy changed while being read")

    try:
        current = os.stat(path, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise GateError(f"{label} is missing after read") from exc
    except PermissionError as exc:
        raise GateError(
            f"{label} became unreadable during identity revalidation"
        ) from exc
    except OSError as exc:
        raise GateError(f"{label} identity could not be revalidated") from exc
    if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (
        opened.st_dev,
        opened.st_ino,
    ):
        raise GateError(f"{label} object identity changed while being read")
    if expected_owner_uid is not None and current.st_uid != expected_owner_uid:
        raise GateError(f"{label} owner changed during identity revalidation")
    if current.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise GateError(f"{label} access policy changed while being read")
    return first


def read_bounded_json_file(
    path: Path,
    label: str,
    *,
    max_bytes: int = MAX_POLICY_JSON_BYTES,
    expected_owner_uid: int | None = None,
) -> tuple[dict[str, Any], bytes]:
    raw = read_stable_policy_file(
        path,
        label,
        max_bytes=max_bytes,
        expected_owner_uid=expected_owner_uid,
    )
    try:
        payload = json.loads(raw, object_pairs_hook=reject_duplicate_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateError(f"{label} is not valid JSON") from exc
    return object_value(payload, label), raw


def _signal_process_group(
    process: subprocess.Popen[bytes], process_signal: signal.Signals
) -> None:
    try:
        os.killpg(process.pid, process_signal)
    except ProcessLookupError:
        return
    except OSError:
        try:
            process.send_signal(process_signal)
        except OSError:
            pass


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    _signal_process_group(process, signal.SIGTERM)
    grace_deadline = time.monotonic() + PROCESS_TERMINATE_GRACE_SECONDS
    while process.poll() is None and time.monotonic() < grace_deadline:
        time.sleep(0.01)
    _signal_process_group(process, signal.SIGKILL)
    try:
        process.wait(timeout=PROCESS_TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        process.wait()


def run_bounded(
    command: list[str],
    *,
    input_data: bytes | None = None,
    max_output_bytes: int = MAX_GIT_OUTPUT_BYTES,
    timeout_seconds: float = GIT_TIMEOUT_SECONDS,
    environment: dict[str, str] | None = None,
) -> bytes:
    if max_output_bytes < 0 or timeout_seconds <= 0:
        raise ValueError("bounded command limits are invalid")
    if input_data is not None and len(input_data) > MAX_GIT_OUTPUT_BYTES:
        raise GateError("trusted command input exceeded its limit")
    input_stream = tempfile.TemporaryFile()
    if input_data is not None:
        input_stream.write(input_data)
        input_stream.flush()
        input_stream.seek(0)
    try:
        process = subprocess.Popen(
            command,
            stdin=input_stream if input_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=environment,
        )
    except OSError as exc:
        input_stream.close()
        raise GateError("trusted command could not be started") from exc
    if process.stdout is None:
        _terminate_process_group(process)
        input_stream.close()
        raise GateError("trusted command output is unavailable")

    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    output = bytearray()
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GateError("trusted command exceeded its time limit")
            ready = selector.select(min(remaining, 0.25))
            if not ready:
                continue
            for key, _events in ready:
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(output) + len(chunk) > max_output_bytes:
                    raise GateError("trusted command exceeded its output limit")
                output.extend(chunk)
        remaining = max(0.01, deadline - time.monotonic())
        return_code = process.wait(timeout=remaining)
        if return_code != 0:
            raise GateError("trusted command rejected candidate metadata")
        return bytes(output)
    except (GateError, OSError, subprocess.TimeoutExpired) as exc:
        _terminate_process_group(process)
        drain_deadline = time.monotonic() + PROCESS_TERMINATE_GRACE_SECONDS
        while selector.get_map() and time.monotonic() < drain_deadline:
            ready = selector.select(0.05)
            for key, _events in ready:
                try:
                    chunk = os.read(key.fd, 64 * 1024)
                except OSError:
                    chunk = b""
                if not chunk:
                    selector.unregister(key.fileobj)
        raise GateError("trusted command did not complete within its bounds") from exc
    finally:
        selector.close()
        process.stdout.close()
        input_stream.close()
        if process.poll() is None:
            _terminate_process_group(process)


def closed_git_environment(*, home: Path | None = None) -> dict[str, str]:
    return {
        "GIT_CONFIG_COUNT": "0",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(home) if home is not None else "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", os.defpath),
        "TZ": "UTC",
    }


def closed_git_command(*arguments: str) -> list[str]:
    return [
        "git",
        "--no-replace-objects",
        "--literal-pathspecs",
        *arguments,
    ]


def validate_closed_git_object_store(git_dir: Path) -> None:
    # The protected access-policy property is that object reads use only this
    # store. Ambient object directories are absent from closed_git_environment;
    # exact on-disk alternate declarations are rejected here before Git runs.
    objects = git_dir / "objects"
    info = objects / "info"
    for path, label in (
        (objects, "trusted Git object directory"),
        (info, "trusted Git object policy directory"),
    ):
        try:
            metadata = os.lstat(path)
        except FileNotFoundError as exc:
            raise GateError(f"{label} is missing") from exc
        except PermissionError as exc:
            raise GateError(f"{label} is unreadable") from exc
        except OSError as exc:
            raise GateError(f"{label} could not be inspected") from exc
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise GateError(f"{label} is not a real directory")

    for name in ("alternates", "http-alternates"):
        path = info / name
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except FileNotFoundError:
            continue
        except PermissionError as exc:
            raise GateError("trusted Git alternate policy is unreadable") from exc
        except OSError as exc:
            raise GateError(
                "trusted Git alternate policy could not be inspected"
            ) from exc
        else:
            os.close(descriptor)
            raise GateError("trusted Git alternate object fallback is prohibited")


def git_output(
    git_dir: Path,
    *arguments: str,
    max_bytes: int = 64 * 1024,
    input_data: bytes | None = None,
) -> bytes:
    git_dir = git_dir.resolve()
    validate_closed_git_object_store(git_dir)
    return run_bounded(
        closed_git_command(f"--git-dir={git_dir}", *arguments),
        input_data=input_data,
        max_output_bytes=max_bytes,
        environment=closed_git_environment(),
    )


def git_text(git_dir: Path, *arguments: str, max_bytes: int = 64 * 1024) -> str:
    try:
        return git_output(git_dir, *arguments, max_bytes=max_bytes).decode("ascii")
    except UnicodeDecodeError as exc:
        raise GateError("Git metadata is not ASCII") from exc


def _local_git_config_names(git_dir: Path) -> tuple[str, ...]:
    try:
        raw = git_output(
            git_dir,
            "config",
            "--local",
            "--no-includes",
            "--name-only",
            "--null",
            "--list",
            max_bytes=64 * 1024,
        )
    except GateError as exc:
        raise GateError(
            "candidate Git config inventory could not be enumerated"
        ) from exc
    if not raw:
        return ()
    if raw[-1:] != b"\0":
        raise GateError("candidate Git config inventory is malformed")
    names: list[str] = []
    for encoded_name in raw[:-1].split(b"\0"):
        if (
            not encoded_name
            or b"." not in encoded_name
            or any(byte < 0x21 or byte > 0x7E for byte in encoded_name)
        ):
            raise GateError("candidate Git config inventory is malformed")
        try:
            name = encoded_name.decode("ascii")
        except UnicodeDecodeError as exc:
            raise GateError("candidate Git config inventory is malformed") from exc
        names.append(name)
    return tuple(names)


def _validate_no_replace_refs(git_dir: Path) -> None:
    try:
        raw = git_output(
            git_dir,
            "for-each-ref",
            "--format=%(refname)",
            "refs/replace/",
            max_bytes=64 * 1024,
        )
    except GateError as exc:
        raise GateError(
            "candidate Git replace ref inventory could not be enumerated"
        ) from exc
    if not raw:
        return
    if raw[-1:] != b"\n" or b"\r" in raw or b"\0" in raw:
        raise GateError("candidate Git replace ref inventory is malformed")
    refs = raw[:-1].split(b"\n")
    if any(
        not ref.startswith(b"refs/replace/")
        or len(ref) == len(b"refs/replace/")
        or any(byte < 0x21 or byte > 0x7E for byte in ref)
        for ref in refs
    ):
        raise GateError("candidate Git replace ref inventory is malformed")
    raise GateError("candidate Git replace refs are prohibited")


def validate_closed_candidate_repository(git_dir: Path) -> None:
    git_dir = git_dir.resolve()
    config_names = _local_git_config_names(git_dir)
    unsafe_names = tuple(
        name
        for name in config_names
        if (
            name.casefold() == "extensions.partialclone"
            or name.casefold().startswith("remote.")
            or name.casefold().startswith("url.")
            or name.casefold().startswith("http.")
            or name.casefold().startswith("credential.")
            or name.casefold().startswith("push.")
            or name.casefold().startswith("protocol.")
            or name.casefold() in {"core.gitproxy", "core.hookspath"}
            or name.casefold() == "include.path"
            or (
                name.casefold().startswith("includeif.")
                and name.casefold().endswith(".path")
            )
        )
    )
    if unsafe_names:
        raise GateError(
            "candidate object store retained unsafe partial-clone or remote config"
        )
    _validate_no_replace_refs(git_dir)


def validate_pull_request_payload(
    payload: Any,
    *,
    repository: str,
    number: int,
    node_id: str,
    base_ref: str,
    base_sha: str,
    head_repository: str,
    head_ref: str,
    head_sha: str,
) -> PullRequestSnapshot:
    repository = canonical_repository(repository)
    head_repository = canonical_repository(head_repository)
    number = canonical_positive_integer(number, "pull request number")
    base_sha = canonical_oid(base_sha, "pull request base")
    head_sha = canonical_oid(head_sha, "pull request head")
    if not isinstance(node_id, str) or not node_id or len(node_id) > 256:
        raise GateError("pull request node identity is invalid")
    if base_ref != "master" or not isinstance(head_ref, str) or not head_ref:
        raise GateError("pull request refs are outside the trusted scope")

    pull = object_value(payload, "pull request")
    base = object_value(pull.get("base"), "pull request base")
    head = object_value(pull.get("head"), "pull request head")
    base_repo = object_value(base.get("repo"), "pull request base repository")
    head_repo = object_value(head.get("repo"), "pull request head repository")
    exact = (
        pull.get("number") == number
        and pull.get("node_id") == node_id
        and pull.get("state") == "open"
        and pull.get("merged") is False
        and pull.get("merged_at") is None
        and pull.get("draft") is False
        and base_repo.get("full_name") == repository
        and base.get("ref") == base_ref
        and base.get("sha") == base_sha
        and head_repo.get("full_name") == head_repository
        and head.get("ref") == head_ref
        and head.get("sha") == head_sha
    )
    if not exact:
        raise GateError("pull request identity, lifecycle, base, or head changed")
    return PullRequestSnapshot(
        number=number,
        node_id=node_id,
        state="open",
        merged=False,
        merged_at=None,
        draft=False,
        base_repository=repository,
        base_ref=base_ref,
        base_sha=base_sha,
        head_repository=head_repository,
        head_ref=head_ref,
        head_sha=head_sha,
    )


def expected_pull_request_snapshot(
    *,
    repository: str,
    number: int,
    node_id: str,
    base_ref: str,
    base_sha: str,
    head_repository: str,
    head_ref: str,
    head_sha: str,
) -> PullRequestSnapshot:
    return validate_pull_request_payload(
        {
            "number": number,
            "node_id": node_id,
            "state": "open",
            "merged": False,
            "merged_at": None,
            "draft": False,
            "base": {
                "ref": base_ref,
                "sha": base_sha,
                "repo": {"full_name": repository},
            },
            "head": {
                "ref": head_ref,
                "sha": head_sha,
                "repo": {"full_name": head_repository},
            },
        },
        repository=repository,
        number=number,
        node_id=node_id,
        base_ref=base_ref,
        base_sha=base_sha,
        head_repository=head_repository,
        head_ref=head_ref,
        head_sha=head_sha,
    )


def _read_bounded_response(
    response: Any,
    *,
    max_bytes: int,
    shared_budget: GitHubReadBudget | None = None,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        if shared_budget is not None:
            _set_github_response_read_timeout(
                response,
                shared_budget.operation_timeout(),
            )
        read_limit = min(64 * 1024, max_bytes - total + 1)
        if shared_budget is not None:
            read_limit = min(read_limit, shared_budget.remaining_bytes + 1)
        chunk = response.read(read_limit)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise GateError("GitHub response exceeded the trusted byte limit")
        if shared_budget is not None:
            shared_budget.consume_bytes(len(chunk))
        chunks.append(chunk)
    if shared_budget is not None:
        shared_budget.checkpoint()
    return b"".join(chunks)


def _set_github_response_read_timeout(response: Any, timeout: float) -> None:
    fp = getattr(response, "fp", None)
    raw = getattr(fp, "raw", None)
    transport = getattr(raw, "_sock", None)
    setter = getattr(transport, "settimeout", None)
    if not callable(setter):
        raise GateError("GitHub response transport timeout is unavailable")
    try:
        setter(timeout)
    except (OSError, TypeError, ValueError) as exc:
        raise GateError("GitHub response transport timeout failed closed") from exc


def _canonical_github_http_date(value: Any) -> dt.datetime:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise GateError("GitHub response Date header is invalid")
    try:
        parsed = email_utils.parsedate_to_datetime(value)
    except (TypeError, ValueError) as exc:
        raise GateError("GitHub response Date header is invalid") from exc
    if parsed.tzinfo is None:
        raise GateError("GitHub response Date header is not UTC")
    normalized = parsed.astimezone(dt.timezone.utc)
    if normalized.microsecond != 0:
        raise GateError("GitHub response Date header precision is invalid")
    return normalized


def _github_api_response(
    method: str,
    repository: str,
    route: str,
    *,
    token: str,
    payload: dict[str, Any] | None = None,
    max_bytes: int = MAX_HTTP_RESPONSE_BYTES,
) -> tuple[bytes, dt.datetime]:
    repository = canonical_repository(repository)
    if method != "GET" or payload is not None:
        raise GateError("GitHub API mutation is prohibited")
    if not token or any(character in token for character in "\r\n"):
        raise GateError("GitHub token is unavailable")
    if route and not route.startswith("/"):
        raise GateError("GitHub route is invalid")
    data = None
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "trusted-history-ci",
    }
    url = f"https://api.github.com/repos/{repository}{route}"
    api_request = request.Request(url, data=data, headers=headers, method=method)
    shared_budget = _ACTIVE_GITHUB_READ_BUDGET.get()
    timeout = (
        shared_budget.begin_request()
        if shared_budget is not None
        else HTTP_TIMEOUT_SECONDS
    )
    try:
        with request.urlopen(api_request, timeout=timeout) as response:
            if response.status < 200 or response.status >= 300:
                raise GateError("GitHub API rejected the trusted request")
            server_time = _canonical_github_http_date(response.headers.get("Date"))
            raw = _read_bounded_response(
                response,
                max_bytes=max_bytes,
                shared_budget=shared_budget,
            )
    except (error.HTTPError, error.URLError, TimeoutError, OSError) as exc:
        raise GateError("GitHub API request failed closed") from exc
    if shared_budget is not None:
        shared_budget.checkpoint()
    return raw, server_time


def _decode_github_json(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateError("GitHub API response is not valid JSON") from exc


def github_json(
    method: str,
    repository: str,
    route: str,
    *,
    token: str,
    payload: dict[str, Any] | None = None,
    max_bytes: int = MAX_HTTP_RESPONSE_BYTES,
) -> Any:
    if not route.startswith("/"):
        raise GateError("GitHub route is invalid")
    raw, _server_time = _github_api_response(
        method,
        repository,
        route,
        token=token,
        payload=payload,
        max_bytes=max_bytes,
    )
    return _decode_github_json(raw)


def github_server_time(
    *,
    repository: str,
    repository_id: int,
    token: str,
) -> dt.datetime:
    repository_id = canonical_positive_integer(
        repository_id,
        "GitHub repository clock identity",
    )
    raw, server_time = _github_api_response(
        "GET",
        repository,
        "/",
        token=token,
        max_bytes=MAX_HTTP_RESPONSE_BYTES,
    )
    payload = object_value(_decode_github_json(raw), "GitHub repository clock response")
    if (
        payload.get("full_name") != canonical_repository(repository)
        or payload.get("id") != repository_id
    ):
        raise GateError("GitHub repository clock response is stale or lookalike")
    return server_time


def canonical_github_timestamp(value: Any, label: str) -> tuple[str, dt.datetime]:
    if not isinstance(value, str) or GITHUB_TIMESTAMP_RE.fullmatch(value) is None:
        raise GateError(f"{label} timestamp is invalid")
    try:
        parsed = dt.datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise GateError(f"{label} timestamp is invalid") from exc
    if parsed.tzinfo != dt.timezone.utc:
        raise GateError(f"{label} timestamp is not UTC")
    return value, parsed


def canonical_github_second_timestamp(
    value: Any,
    label: str,
) -> tuple[str, dt.datetime]:
    text, parsed = canonical_github_timestamp(value, label)
    expected = parsed.isoformat(timespec="seconds").replace("+00:00", "Z")
    if text != expected:
        raise GateError(f"{label} timestamp precision is invalid")
    return text, parsed


def verify_default_github_commit(
    *,
    repository: str,
    repository_id: int,
    git_dir: Path,
    trusted_base_root: Path,
    base_sha: str,
    head_sha: str,
    initial_candidate_evidence: dict[str, Any],
    token: str,
) -> dict[str, Any]:
    repository = canonical_repository(repository)
    repository_id = canonical_positive_integer(
        repository_id,
        "default event repository ID",
    )
    base_sha = canonical_oid(base_sha, "default event base")
    head_sha = canonical_oid(head_sha, "default event head")
    if base_sha == head_sha:
        raise GateError("default event commit range is empty")
    validator = trusted_validator_module(contract="github-squash")
    if (
        getattr(validator, "HISTORY_V2_GITHUB_SQUASH_RECEIPT_KIND", None)
        != GITHUB_SQUASH_RECEIPT_KIND
    ):
        raise GateError("trusted GitHub squash receipt contract is unavailable")
    candidate_evidence = resolve_default_candidate_evidence(
        repository=repository,
        repository_id=repository_id,
        trusted_base_root=trusted_base_root,
        base_sha=base_sha,
        head_sha=head_sha,
        token=token,
    )
    if candidate_evidence != initial_candidate_evidence:
        raise GateError("default candidate evidence changed before final validation")
    squash_configuration = {
        "squash_merge_commit_title": candidate_evidence["squash_merge_commit_title"],
        "squash_merge_commit_message": candidate_evidence[
            "squash_merge_commit_message"
        ],
    }
    raw_commit = git_output(
        git_dir.resolve(),
        "cat-file",
        "commit",
        head_sha,
        max_bytes=MAX_COMMIT_BYTES,
    )
    try:
        parsed = validator.parse_history_v2_github_squash_commit(
            raw_commit,
            expected_oid=head_sha,
        )
    except (UnicodeError, ValueError) as exc:
        raise GateError("default commit is not a valid GitHub squash") from exc
    if parsed.parents != (base_sha,):
        raise GateError("default commit parent differs from the push event")

    payload = object_value(
        github_json(
            "GET",
            repository,
            f"/commits/{parse.quote(head_sha, safe='')}",
            token=token,
            max_bytes=MAX_HTTP_RESPONSE_BYTES,
        ),
        "GitHub default commit",
    )
    commit = object_value(payload.get("commit"), "GitHub default commit metadata")
    tree = object_value(commit.get("tree"), "GitHub default commit tree")
    verification = object_value(
        commit.get("verification"),
        "GitHub default commit verification",
    )
    author = object_value(payload.get("author"), "GitHub default commit author")
    committer = object_value(
        payload.get("committer"),
        "GitHub default commit committer",
    )
    parents = payload.get("parents")
    if not isinstance(parents, list) or len(parents) != 1:
        raise GateError("GitHub default commit parent set is invalid")
    parent = object_value(parents[0], "GitHub default commit parent")
    author_metadata = object_value(
        commit.get("author"),
        "GitHub default commit author metadata",
    )
    committer_metadata = object_value(
        commit.get("committer"),
        "GitHub default commit committer metadata",
    )
    author_date_text, author_date = canonical_github_timestamp(
        author_metadata.get("date"),
        "GitHub default commit author",
    )
    committer_date_text, committer_date = canonical_github_timestamp(
        committer_metadata.get("date"),
        "GitHub default commit committer",
    )
    verified_at_text, verified_at = canonical_github_timestamp(
        verification.get("verified_at"),
        "GitHub default commit verification",
    )
    expected_author_date = dt.datetime.fromtimestamp(
        parsed.author_timestamp,
        tz=dt.timezone.utc,
    )
    expected_committer_date = dt.datetime.fromtimestamp(
        parsed.committer_timestamp,
        tz=dt.timezone.utc,
    )
    signature = verification.get("signature")
    signed_payload = verification.get("payload")
    if (
        payload.get("sha") != head_sha
        or parent.get("sha") != base_sha
        or tree.get("sha") != parsed.tree_oid
        or verification.get("verified") is not True
        or verification.get("reason") != "valid"
        or not isinstance(signature, str)
        or not isinstance(signed_payload, str)
        or signature.encode("utf-8") != parsed.signature_armor
        or signed_payload.encode("utf-8") != parsed.signed_payload
        or author_date != expected_author_date
        or committer_date != expected_committer_date
        or author_date_text != committer_date_text
        or verified_at < committer_date
    ):
        raise GateError(
            "GitHub verification differs from the exact local squash commit"
        )
    canonical_github_login(
        author.get("login"),
        "GitHub default commit author",
    )
    committer_login = canonical_github_login(
        committer.get("login"),
        "GitHub default commit committer",
    )
    if committer_login != "web-flow":
        raise GateError("GitHub default commit provider identity is invalid")
    if (
        parsed.pull_request_number is not None
        and parsed.pull_request_number != candidate_evidence["pull_request_number"]
    ):
        raise GateError(
            "GitHub squash subject pull request differs from the associated pull request"
        )
    if (
        parsed.pull_request_title_sha256
        != candidate_evidence["pull_request_title_sha256"]
    ):
        raise GateError(
            "GitHub squash subject differs from the associated pull request"
        )
    if (
        resolve_default_candidate_evidence(
            repository=repository,
            repository_id=repository_id,
            trusted_base_root=trusted_base_root,
            base_sha=base_sha,
            head_sha=head_sha,
            token=token,
        )
        != candidate_evidence
    ):
        raise GateError("default candidate evidence changed during final validation")
    candidate_evidence_sha256 = hashlib.sha256(
        compact_json_bytes(candidate_evidence)
    ).hexdigest()
    return {
        "schema_version": 3,
        "kind": GITHUB_SQUASH_RECEIPT_KIND,
        "repository": repository,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "tree_sha": parsed.tree_oid,
        "signed_payload_sha256": hashlib.sha256(parsed.signed_payload).hexdigest(),
        "signature_sha256": hashlib.sha256(parsed.signature_armor).hexdigest(),
        "author_identity_sha256": parsed.author_identity_sha256,
        "committer_identity_sha256": parsed.committer_identity_sha256,
        "github_committer_login": committer_login,
        "verification_reason": "valid",
        "verified_at": verified_at_text,
        "pull_request_number": candidate_evidence["pull_request_number"],
        "pull_request_title_sha256": candidate_evidence["pull_request_title_sha256"],
        "pull_request_node_identity_sha256": candidate_evidence[
            "pull_request_node_identity_sha256"
        ],
        "repository_identity_sha256": candidate_evidence["repository_identity_sha256"],
        "pull_request_provenance_sha256": candidate_evidence[
            "pull_request_provenance_sha256"
        ],
        "pull_request_merged_at": candidate_evidence["pull_request_merged_at"],
        **squash_configuration,
        "candidate_sha": candidate_evidence["candidate_sha"],
        "candidate_evidence_sha256": candidate_evidence_sha256,
        "candidate_evidence": candidate_evidence,
    }


def _paged_route(route: str, page: int) -> str:
    page = canonical_positive_integer(page, "GitHub page")
    separator = "&" if "?" in route else "?"
    return f"{route}{separator}per_page={GITHUB_PAGE_SIZE}&page={page}"


def github_paginated_object_items(
    *,
    repository: str,
    route: str,
    item_key: str,
    token: str,
    label: str,
) -> list[Any]:
    total_count: int | None = None
    items: list[Any] = []
    seen_ids: set[int] = set()
    terminal_page = 0
    for page in range(1, MAX_GITHUB_PAGES + 1):
        payload = object_value(
            github_json(
                "GET",
                repository,
                _paged_route(route, page),
                token=token,
            ),
            f"{label} page",
        )
        observed_total = payload.get("total_count")
        page_items = payload.get(item_key)
        if (
            type(observed_total) is not int
            or observed_total < 0
            or observed_total > GITHUB_PAGE_SIZE * MAX_GITHUB_PAGES
            or not isinstance(page_items, list)
            or len(page_items) > GITHUB_PAGE_SIZE
        ):
            raise GateError(f"{label} pagination is invalid")
        if total_count is None:
            total_count = observed_total
        elif observed_total != total_count:
            raise GateError(f"{label} pagination total changed")
        remaining = total_count - len(items)
        expected_size = min(GITHUB_PAGE_SIZE, max(remaining, 0))
        if len(page_items) != expected_size:
            raise GateError(f"{label} pagination is incomplete")
        for item in page_items:
            value = object_value(item, label)
            item_id = canonical_positive_integer(value.get("id"), f"{label} ID")
            if item_id in seen_ids:
                raise GateError(f"{label} pagination contains duplicate evidence")
            seen_ids.add(item_id)
            items.append(value)
        if len(items) == total_count:
            terminal_page = page + 1
            break
    if total_count is None or terminal_page == 0:
        raise GateError(f"{label} pagination exceeds the trusted limit")
    terminal = object_value(
        github_json(
            "GET",
            repository,
            _paged_route(route, terminal_page),
            token=token,
        ),
        f"{label} terminal page",
    )
    if terminal.get("total_count") != total_count or terminal.get(item_key) != []:
        raise GateError(f"{label} pagination is not terminal")
    return items


def github_paginated_list(
    *,
    repository: str,
    route: str,
    token: str,
    label: str,
) -> list[Any]:
    items: list[Any] = []
    first_page_bytes: bytes | None = None
    terminal_page = 0
    for page in range(1, MAX_GITHUB_PAGES + 1):
        page_items = github_json(
            "GET",
            repository,
            _paged_route(route, page),
            token=token,
        )
        if not isinstance(page_items, list) or len(page_items) > GITHUB_PAGE_SIZE:
            raise GateError(f"{label} pagination is invalid")
        if page == 1:
            first_page_bytes = compact_json_bytes(page_items)
        items.extend(object_value(item, label) for item in page_items)
        if len(page_items) < GITHUB_PAGE_SIZE:
            terminal_page = page + 1
            break
    if terminal_page == 0:
        raise GateError(f"{label} pagination exceeds the trusted limit")
    if (
        github_json(
            "GET",
            repository,
            _paged_route(route, terminal_page),
            token=token,
        )
        != []
    ):
        raise GateError(f"{label} pagination is not terminal")
    revalidated_first_page = github_json(
        "GET",
        repository,
        _paged_route(route, 1),
        token=token,
    )
    if (
        first_page_bytes is None
        or not isinstance(revalidated_first_page, list)
        or len(revalidated_first_page) > GITHUB_PAGE_SIZE
        or compact_json_bytes(revalidated_first_page) != first_page_bytes
    ):
        raise GateError(f"{label} pagination changed during collection")
    return items


def default_associated_pull_request_identity(
    associated: list[Any],
) -> tuple[int, str]:
    if len(associated) != 1:
        raise GateError("default squash pull request evidence is missing or ambiguous")
    associated_pull = object_value(
        associated[0],
        "default squash pull request evidence",
    )
    number = canonical_positive_integer(
        associated_pull.get("number"),
        "default squash pull request number",
    )
    node_id = associated_pull.get("node_id")
    if (
        not isinstance(node_id, str)
        or not node_id
        or len(node_id.encode("utf-8")) > 256
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in node_id)
    ):
        raise GateError("default squash pull request node identity is invalid")
    return number, node_id


def read_default_squash_configuration(
    *,
    repository: str,
    token: str,
) -> dict[str, str]:
    configuration = validate_repository_merge_configuration(
        github_json(
            "GET",
            repository,
            "/",
            token=token,
        ),
        repository=repository,
    )
    return {
        "squash_merge_commit_title": configuration["squash_merge_commit_title"],
        "squash_merge_commit_message": configuration["squash_merge_commit_message"],
    }


def _read_exact_admission_check(
    *,
    repository: str,
    head_sha: str,
    check_name: str,
    token: str,
    label: str,
) -> tuple[dict[str, Any], dict[str, Any], dt.datetime]:
    app_id = canonical_admission_app_id(ADMISSION_RECORD_APP_ID)
    head_sha = canonical_oid(head_sha, f"{label} head")
    encoded_sha = parse.quote(head_sha, safe="")
    encoded_name = parse.quote(check_name, safe="")
    checks = github_paginated_object_items(
        repository=repository,
        route=(
            f"/commits/{encoded_sha}/check-runs?check_name={encoded_name}&filter=all"
        ),
        item_key="check_runs",
        token=token,
        label=label,
    )
    if len(checks) != 1:
        raise GateError(f"{label} is missing or ambiguous")
    check = object_value(checks[0], label)
    app = object_value(check.get("app"), f"{label} App")
    suite = object_value(check.get("check_suite"), f"{label} suite")
    output = object_value(check.get("output"), f"{label} output")
    check_run_id = canonical_positive_integer(check.get("id"), f"{label} ID")
    check_suite_id = canonical_positive_integer(
        suite.get("id"),
        f"{label} suite ID",
    )
    node_id = check.get("node_id")
    external_id = check.get("external_id")
    raw_record = output.get("text")
    started_at, started_time = canonical_github_timestamp(
        check.get("started_at"),
        f"{label} start",
    )
    completed_at, completed_time = canonical_github_timestamp(
        check.get("completed_at"),
        f"{label} completion",
    )
    if (
        check.get("name") != check_name
        or check.get("head_sha") != head_sha
        or check.get("status") != "completed"
        or check.get("conclusion") != "success"
        or app.get("id") != app_id
        or app.get("slug") != ADMISSION_RECORD_APP_SLUG
        or not isinstance(node_id, str)
        or not node_id
        or len(node_id.encode("ascii", errors="ignore")) != len(node_id)
        or len(node_id) > 256
        or not isinstance(external_id, str)
        or not isinstance(raw_record, str)
        or output.get("title") != ADMISSION_RECORD_OUTPUT_TITLE
        or output.get("annotations_count") != 0
        or started_time > completed_time
    ):
        raise GateError(f"{label} is stale or lookalike")
    try:
        record_bytes = raw_record.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise GateError(f"{label} record is not UTF-8") from exc
    if len(record_bytes) > MAX_POLICY_JSON_BYTES:
        raise GateError(f"{label} record exceeds the trusted byte limit")
    try:
        admission = json.loads(
            record_bytes,
            object_pairs_hook=reject_duplicate_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateError(f"{label} record is not valid JSON") from exc
    admission = object_value(admission, f"{label} record")
    if compact_json_bytes(admission) != record_bytes:
        raise GateError(f"{label} record is not canonical")
    parse_merge_group_admission_payload(admission)
    admission_sha256 = hashlib.sha256(record_bytes).hexdigest()
    if (
        external_id != ADMISSION_RECORD_EXTERNAL_ID_PREFIX + admission_sha256
        or output.get("summary")
        != ADMISSION_RECORD_OUTPUT_SUMMARY_PREFIX + admission_sha256
    ):
        raise GateError(f"{label} output binding differs")
    return (
        {
            "schema_version": 1,
            "kind": DEFAULT_ADMISSION_CHECK_KIND,
            "check_name": check_name,
            "check_run_id": check_run_id,
            "check_run_node_id": node_id,
            "check_suite_id": check_suite_id,
            "head_sha": head_sha,
            "started_at": started_at,
            "completed_at": completed_at,
            "external_id": external_id,
            "output_title": ADMISSION_RECORD_OUTPUT_TITLE,
            "output_summary": (
                ADMISSION_RECORD_OUTPUT_SUMMARY_PREFIX + admission_sha256
            ),
            "admission_sha256": admission_sha256,
        },
        admission,
        completed_time,
    )


def read_post_merge_admission_binding(
    *,
    repository: str,
    repository_id: int,
    base_sha: str,
    candidate_sha: str,
    candidate_ref: str,
    pull_request_number: int,
    pull_request_node_id: str,
    merged_at: str,
    token: str,
) -> dict[str, Any]:
    repository = canonical_repository(repository)
    repository_id = canonical_positive_integer(
        repository_id,
        "post-merge admission repository identity",
    )
    base_sha = canonical_oid(base_sha, "post-merge admission base")
    candidate_sha = canonical_oid(candidate_sha, "post-merge admission candidate")
    if (
        not isinstance(candidate_ref, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", candidate_ref) is None
        or ".." in candidate_ref
        or "@{" in candidate_ref
        or candidate_ref.endswith(".lock")
    ):
        raise GateError("post-merge admission candidate ref is invalid")
    candidate_check, admission, candidate_completed = _read_exact_admission_check(
        repository=repository,
        head_sha=candidate_sha,
        check_name=ADMISSION_RECORD_CHECK_CONTEXT,
        token=token,
        label="candidate admission record check",
    )
    snapshot, projection, _runtime, live_authority = (
        parse_merge_group_admission_payload(admission)
    )
    queue_check, queue_admission, queue_completed = _read_exact_admission_check(
        repository=repository,
        head_sha=snapshot.queue_sha,
        check_name=REQUIRED_CHECK_CONTEXT,
        token=token,
        label="queue admission gate check",
    )
    if queue_check["admission_sha256"] != candidate_check["admission_sha256"]:
        raise GateError("candidate and queue checks do not bind the same admission")
    _observed_text, observed_time = canonical_github_timestamp(
        live_authority.observed_at,
        "post-merge admission live observation",
    )
    _valid_text, valid_until = canonical_github_timestamp(
        live_authority.valid_until,
        "post-merge admission live expiration",
    )
    _merged_text, merged_time = canonical_github_timestamp(
        merged_at,
        "post-merge admission merge",
    )
    if (
        snapshot.repository != repository
        or snapshot.repository_id != repository_id
        or snapshot.base_sha != base_sha
        or snapshot.candidate_sha != candidate_sha
        or snapshot.candidate_ref != candidate_ref
        or snapshot.pull_request_number != pull_request_number
        or snapshot.pull_request_node_id != pull_request_node_id
        or projection.queue_base_sha != base_sha
        or projection.candidate_sha != candidate_sha
        or projection.queue_sha != snapshot.queue_sha
        or projection.prospective_tree_sha != projection.queue_tree_sha
        or not (observed_time <= candidate_completed <= queue_completed < valid_until)
        or queue_completed > merged_time
    ):
        raise GateError("post-merge admission binding is stale or inconsistent")
    admission_sha256 = candidate_check["admission_sha256"]
    return {
        "schema_version": 1,
        "kind": POST_MERGE_ADMISSION_BINDING_KIND,
        "app": {
            "id": canonical_admission_app_id(ADMISSION_RECORD_APP_ID),
            "slug": ADMISSION_RECORD_APP_SLUG,
        },
        "admission_sha256": admission_sha256,
        "admission": admission,
        "candidate_record_check": candidate_check,
        "queue_gate_check": queue_check,
    }


def verify_default_merged_pull_request(
    *,
    repository: str,
    repository_id: int,
    base_sha: str,
    head_sha: str,
    squash_configuration: dict[str, str],
    authority_mode: str,
    token: str,
) -> dict[str, Any]:
    if authority_mode not in {"bootstrap-v2-migration", "history-v2-admission"}:
        raise GateError("default candidate authority mode is invalid")
    encoded_sha = parse.quote(head_sha, safe="")
    associated_before = github_paginated_list(
        repository=repository,
        route=f"/commits/{encoded_sha}/pulls",
        token=token,
        label="default squash pull request evidence",
    )
    number, node_id = default_associated_pull_request_identity(associated_before)

    pull = object_value(
        github_json(
            "GET",
            repository,
            f"/pulls/{number}",
            token=token,
        ),
        "default squash pull request",
    )
    base = object_value(pull.get("base"), "default squash pull request base")
    head = object_value(pull.get("head"), "default squash pull request head")
    base_repository = object_value(
        base.get("repo"),
        "default squash pull request base repository",
    )
    head_repository = object_value(
        head.get("repo"),
        "default squash pull request head repository",
    )
    merged_at, _merged_time = canonical_github_timestamp(
        pull.get("merged_at"),
        "default squash pull request merge",
    )
    candidate_sha = canonical_oid(
        head.get("sha"),
        "default squash candidate head",
    )
    candidate_ref = head.get("ref")
    title = pull.get("title")
    if (
        pull.get("number") != number
        or pull.get("node_id") != node_id
        or pull.get("state") != "closed"
        or pull.get("merged") is not True
        or pull.get("draft") is not False
        or pull.get("merge_commit_sha") != head_sha
        or base_repository.get("full_name") != repository
        or base_repository.get("id") != repository_id
        or base.get("ref") != DEFAULT_BRANCH
        or base.get("sha") != base_sha
        or head_repository.get("full_name") != repository
        or head_repository.get("id") != repository_id
        or not isinstance(candidate_ref, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", candidate_ref) is None
        or ".." in candidate_ref
        or "@{" in candidate_ref
        or candidate_ref.endswith(".lock")
        or (
            authority_mode == "bootstrap-v2-migration"
            and candidate_ref != BOOTSTRAP_CANDIDATE_REF
        )
        or candidate_sha in {base_sha, head_sha}
        or len(candidate_sha) != len(head_sha)
        or not isinstance(title, str)
        or not title
        or len(title.encode("utf-8")) > 256
        or any(character in title for character in "\r\n\0")
        or squash_configuration
        != {
            "squash_merge_commit_title": "PR_TITLE",
            "squash_merge_commit_message": "BLANK",
        }
    ):
        raise GateError("default squash pull request provenance is stale or lookalike")
    admission_binding = None
    if authority_mode == "history-v2-admission":
        admission_binding = read_post_merge_admission_binding(
            repository=repository,
            repository_id=repository_id,
            candidate_sha=candidate_sha,
            candidate_ref=candidate_ref,
            base_sha=base_sha,
            pull_request_number=number,
            pull_request_node_id=node_id,
            merged_at=merged_at,
            token=token,
        )
    associated_after = github_paginated_list(
        repository=repository,
        route=f"/commits/{encoded_sha}/pulls",
        token=token,
        label="default squash pull request evidence revalidation",
    )
    if default_associated_pull_request_identity(associated_after) != (
        number,
        node_id,
    ):
        raise GateError("default squash pull request association changed")
    node_identity_sha256 = hashlib.sha256(node_id.encode("utf-8")).hexdigest()
    title_sha256 = hashlib.sha256(title.encode("utf-8")).hexdigest()
    provenance = {
        "authority_mode": authority_mode,
        "base_ref": DEFAULT_BRANCH,
        "base_repository": repository,
        "base_repository_id": repository_id,
        "base_sha": base_sha,
        "head_repository": repository,
        "head_repository_id": repository_id,
        "head_ref": candidate_ref,
        "candidate_sha": candidate_sha,
        "merge_commit_sha": head_sha,
        "merged_at": merged_at,
        "node_identity_sha256": node_identity_sha256,
        "number": number,
        **squash_configuration,
        "title_sha256": title_sha256,
    }
    provenance_bytes = json.dumps(
        provenance,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "authority_mode": authority_mode,
        "pull_request_number": number,
        "candidate_ref": candidate_ref,
        "candidate_sha": candidate_sha,
        "pull_request_title_sha256": title_sha256,
        "pull_request_node_identity_sha256": node_identity_sha256,
        "repository_identity_sha256": hashlib.sha256(
            f"{repository_id}:{repository}".encode("utf-8")
        ).hexdigest(),
        "pull_request_provenance_sha256": hashlib.sha256(provenance_bytes).hexdigest(),
        "pull_request_merged_at": merged_at,
        "admission_binding": admission_binding,
        **squash_configuration,
    }


def default_candidate_authority_mode(
    trusted_base_root: Path,
    base_sha: str,
) -> str:
    base_sha = canonical_oid(base_sha, "default candidate trusted base")
    trusted_base_root = trusted_base_root.resolve()
    _worktree_head(trusted_base_root, base_sha, "trusted default predecessor")
    validator = trusted_validator_module(contract="github-squash")
    try:
        markers = validator.history_v2_bootstrap_markers(
            trusted_base_root,
            base_sha,
        )
    except Exception as exc:
        raise GateError("trusted predecessor marker classification failed") from exc
    expected_markers = frozenset(Path(value) for value in BOOTSTRAP_TEMPORARY_PATHS)
    if markers:
        if markers != expected_markers:
            raise GateError("trusted predecessor bootstrap markers are incomplete")
        return "bootstrap-v2-migration"
    return "history-v2-admission"


def resolve_default_candidate_evidence(
    *,
    repository: str,
    repository_id: int,
    trusted_base_root: Path,
    base_sha: str,
    head_sha: str,
    token: str,
) -> dict[str, Any]:
    repository = canonical_repository(repository)
    repository_id = canonical_positive_integer(
        repository_id,
        "default event repository ID",
    )
    base_sha = canonical_oid(base_sha, "default event base")
    head_sha = canonical_oid(head_sha, "default event head")
    authority_mode = default_candidate_authority_mode(
        trusted_base_root,
        base_sha,
    )
    squash_configuration = read_default_squash_configuration(
        repository=repository,
        token=token,
    )
    pull_evidence = verify_default_merged_pull_request(
        repository=repository,
        repository_id=repository_id,
        base_sha=base_sha,
        head_sha=head_sha,
        squash_configuration=squash_configuration,
        authority_mode=authority_mode,
        token=token,
    )
    if (
        read_default_squash_configuration(
            repository=repository,
            token=token,
        )
        != squash_configuration
    ):
        raise GateError("repository squash configuration changed during collection")
    return {
        "schema_version": 1,
        "kind": DEFAULT_CANDIDATE_EVIDENCE_KIND,
        "authority_mode": authority_mode,
        "repository": repository,
        "repository_id": repository_id,
        "base_sha": base_sha,
        "head_sha": head_sha,
        **pull_evidence,
    }


def load_default_candidate_evidence(path: Path) -> dict[str, Any]:
    payload, raw = read_bounded_json_file(
        path,
        "default candidate evidence",
        max_bytes=MAX_POLICY_JSON_BYTES,
        expected_owner_uid=os.geteuid(),
    )
    if raw != compact_json_bytes(payload):
        raise GateError("default candidate evidence is not canonical")
    return payload


def _validate_predecessor_pull_request(
    payload: Any,
    *,
    repository: str,
    base_sha: str,
    parent_sha: str,
    number: int,
    node_id: str,
    current_pr_number: int,
) -> tuple[str, str, str]:
    pull = object_value(payload, "predecessor pull request")
    base = object_value(pull.get("base"), "predecessor pull request base")
    head = object_value(pull.get("head"), "predecessor pull request head")
    base_repo = object_value(base.get("repo"), "predecessor base repository")
    head_repo = object_value(head.get("repo"), "predecessor head repository")
    merged_at, _merged_time = canonical_github_timestamp(
        pull.get("merged_at"),
        "predecessor merge",
    )
    candidate_sha = canonical_oid(
        head.get("sha"),
        "predecessor candidate head",
    )
    if (
        number == current_pr_number
        or pull.get("number") != number
        or pull.get("node_id") != node_id
        or pull.get("state") != "closed"
        or pull.get("merged") is not True
        or pull.get("draft") is not False
        or pull.get("merge_commit_sha") != base_sha
        or base_repo.get("full_name") != repository
        or base.get("ref") != DEFAULT_BRANCH
        or base.get("sha") != parent_sha
        or head_repo.get("full_name") != repository
        or candidate_sha in {base_sha, parent_sha}
    ):
        raise GateError("predecessor pull request provenance is stale or lookalike")
    return candidate_sha, merged_at, node_id


def read_trusted_predecessor_audit_evidence(
    *,
    repository: str,
    base_sha: str,
    parent_sha: str,
    current_pr_number: int,
    token: str,
) -> PredecessorAuditEvidence:
    repository = canonical_repository(repository)
    base_sha = canonical_oid(base_sha, "predecessor audited base")
    parent_sha = canonical_oid(parent_sha, "predecessor audited parent")
    current_pr_number = canonical_positive_integer(
        current_pr_number,
        "current merge-group pull request number",
    )
    encoded_sha = parse.quote(base_sha, safe="")
    associated = github_paginated_list(
        repository=repository,
        route=f"/commits/{encoded_sha}/pulls",
        token=token,
        label="predecessor pull request evidence",
    )
    if not associated:
        raise GateError("predecessor pull request evidence is missing")
    if len(associated) != 1:
        raise GateError("predecessor pull request evidence is ambiguous")
    associated_pull = object_value(
        associated[0],
        "predecessor pull request evidence",
    )
    predecessor_number = canonical_positive_integer(
        associated_pull.get("number"),
        "predecessor pull request number",
    )
    predecessor_node_id = associated_pull.get("node_id")
    if (
        not isinstance(predecessor_node_id, str)
        or not predecessor_node_id
        or len(predecessor_node_id) > 256
    ):
        raise GateError("predecessor pull request evidence is lookalike")
    candidate_sha, merged_at, predecessor_node_id = _validate_predecessor_pull_request(
        github_json(
            "GET",
            repository,
            f"/pulls/{predecessor_number}",
            token=token,
        ),
        repository=repository,
        base_sha=base_sha,
        parent_sha=parent_sha,
        number=predecessor_number,
        node_id=predecessor_node_id,
        current_pr_number=current_pr_number,
    )

    encoded_name = parse.quote(POST_MERGE_AUDIT_CHECK_CONTEXT, safe="")
    check_runs = github_paginated_object_items(
        repository=repository,
        route=(
            f"/commits/{encoded_sha}/check-runs?check_name={encoded_name}&filter=all"
        ),
        item_key="check_runs",
        token=token,
        label="predecessor audit check",
    )
    if not check_runs:
        raise GateError("predecessor audit evidence is missing")
    check_evidence: dict[int, dict[str, Any]] = {}
    workflow_run_ids: set[int] = set()
    check_suite_ids: set[int] = set()
    check_node_ids: set[str] = set()
    for raw_check_run in check_runs:
        check_run = object_value(raw_check_run, "predecessor audit check")
        app = object_value(check_run.get("app"), "predecessor audit check app")
        check_suite = object_value(
            check_run.get("check_suite"),
            "predecessor audit check suite",
        )
        check_run_id = canonical_positive_integer(
            check_run.get("id"),
            "predecessor audit check run ID",
        )
        check_suite_id = canonical_positive_integer(
            check_suite.get("id"),
            "predecessor audit check suite ID",
        )
        check_run_node_id = check_run.get("node_id")
        details_url = check_run.get("details_url")
        details_match = (
            re.fullmatch(
                rf"https://github\.com/{re.escape(repository)}/actions/runs/"
                r"(?P<run_id>[1-9][0-9]*)/job/(?P<job_id>[1-9][0-9]*)",
                details_url,
            )
            if isinstance(details_url, str)
            else None
        )
        if check_run_id in check_evidence or (
            isinstance(check_run_node_id, str) and check_run_node_id in check_node_ids
        ):
            raise GateError("predecessor audit evidence is ambiguous")
        if check_run.get("head_sha") != base_sha:
            raise GateError("predecessor audit evidence is stale")
        if (
            check_run.get("name") != POST_MERGE_AUDIT_CHECK_CONTEXT
            or app.get("id") != GITHUB_ACTIONS_APP_ID
            or app.get("slug") != GITHUB_ACTIONS_APP_SLUG
            or not isinstance(check_run_node_id, str)
            or not check_run_node_id
            or len(check_run_node_id) > 256
            or details_match is None
            or check_run.get("pull_requests") != []
        ):
            raise GateError("predecessor audit evidence is lookalike")
        if check_run.get("status") != "completed":
            raise GateError("predecessor audit evidence is nonterminal")
        if check_run.get("conclusion") not in GITHUB_TERMINAL_CONCLUSIONS:
            raise GateError("predecessor audit evidence is lookalike")
        check_started, check_started_time = canonical_github_timestamp(
            check_run.get("started_at"),
            "predecessor audit check start",
        )
        check_completed, check_completed_time = canonical_github_timestamp(
            check_run.get("completed_at"),
            "predecessor audit check completion",
        )
        if check_started_time > check_completed_time:
            raise GateError("predecessor audit evidence timestamps are inconsistent")
        workflow_run_id = int(details_match.group("run_id"))
        job_id = int(details_match.group("job_id"))
        check_node_ids.add(check_run_node_id)
        workflow_run_ids.add(workflow_run_id)
        check_suite_ids.add(check_suite_id)
        check_evidence[check_run_id] = {
            "check_run": check_run,
            "check_run_id": check_run_id,
            "check_run_node_id": check_run_node_id,
            "check_suite_id": check_suite_id,
            "workflow_run_id": workflow_run_id,
            "job_id": job_id,
            "details_url": details_url,
            "started": check_started,
            "started_time": check_started_time,
            "completed": check_completed,
            "completed_time": check_completed_time,
        }
    if len(workflow_run_ids) != 1 or len(check_suite_ids) != 1:
        raise GateError("predecessor audit evidence is ambiguous")
    workflow_run_id = next(iter(workflow_run_ids))
    check_suite_id = next(iter(check_suite_ids))

    workflow_run = object_value(
        github_json(
            "GET",
            repository,
            f"/actions/runs/{workflow_run_id}",
            token=token,
        ),
        "predecessor audit workflow run",
    )
    workflow_id = canonical_positive_integer(
        workflow_run.get("workflow_id"),
        "predecessor audit workflow ID",
    )
    workflow_created, workflow_created_time = canonical_github_timestamp(
        workflow_run.get("created_at"),
        "predecessor audit workflow creation",
    )
    workflow_started, workflow_started_time = canonical_github_timestamp(
        workflow_run.get("run_started_at"),
        "predecessor audit workflow start",
    )
    workflow_updated, workflow_updated_time = canonical_github_timestamp(
        workflow_run.get("updated_at"),
        "predecessor audit workflow update",
    )
    workflow_repository = object_value(
        workflow_run.get("repository"),
        "predecessor audit workflow repository",
    )
    workflow_head_repository = object_value(
        workflow_run.get("head_repository"),
        "predecessor audit workflow head repository",
    )
    expected_run_url = f"https://github.com/{repository}/actions/runs/{workflow_run_id}"
    expected_jobs_url = (
        f"https://api.github.com/repos/{repository}/actions/runs/{workflow_run_id}/jobs"
    )
    workflow_run_attempt = canonical_positive_integer(
        workflow_run.get("run_attempt"),
        "predecessor audit workflow attempt",
    )
    if workflow_run.get("head_sha") != base_sha:
        raise GateError("predecessor audit workflow evidence is stale")
    if (
        workflow_run.get("id") != workflow_run_id
        or workflow_run.get("name") != PERMANENT_WORKFLOW_NAME
        or workflow_run.get("path") != PERMANENT_WORKFLOW_PATH
        or workflow_run.get("event") != "push"
        or workflow_run.get("head_branch") != DEFAULT_BRANCH
        or workflow_run.get("status") != "completed"
        or workflow_run.get("conclusion") != "success"
        or workflow_run.get("check_suite_id") != check_suite_id
        or workflow_run.get("html_url") != expected_run_url
        or workflow_run.get("jobs_url") != expected_jobs_url
        or workflow_repository.get("full_name") != repository
        or workflow_head_repository.get("full_name") != repository
    ):
        raise GateError("predecessor audit workflow evidence is lookalike")

    jobs = github_paginated_object_items(
        repository=repository,
        route=f"/actions/runs/{workflow_run_id}/jobs?filter=all",
        item_key="jobs",
        token=token,
        label="predecessor audit job",
    )
    matching_jobs = [
        job
        for job in jobs
        if object_value(job, "predecessor audit job").get("name")
        == POST_MERGE_AUDIT_CHECK_CONTEXT
    ]
    if not matching_jobs:
        raise GateError("predecessor audit job evidence is missing")
    attempts: dict[int, dict[str, Any]] = {}
    matched_check_ids: set[int] = set()
    check_url_re = re.compile(
        rf"https://api\.github\.com/repos/{re.escape(repository)}/check-runs/"
        r"(?P<check_run_id>[1-9][0-9]*)"
    )
    for raw_job in matching_jobs:
        job = object_value(raw_job, "predecessor audit job")
        job_id = canonical_positive_integer(
            job.get("id"),
            "predecessor audit job ID",
        )
        job_attempt = canonical_positive_integer(
            job.get("run_attempt"),
            "predecessor audit job attempt",
        )
        check_url = job.get("check_run_url")
        check_url_match = (
            check_url_re.fullmatch(check_url) if isinstance(check_url, str) else None
        )
        if check_url_match is None:
            raise GateError("predecessor audit job evidence is lookalike")
        check_run_id = int(check_url_match.group("check_run_id"))
        check = check_evidence.get(check_run_id)
        if job.get("head_sha") != base_sha:
            raise GateError("predecessor audit job evidence is stale")
        if job.get("status") != "completed":
            raise GateError("predecessor audit job evidence is nonterminal")
        if job.get("conclusion") not in GITHUB_TERMINAL_CONCLUSIONS:
            raise GateError("predecessor audit job evidence is lookalike")
        if (
            check is None
            or job.get("run_id") != workflow_run_id
            or job.get("workflow_name") != PERMANENT_WORKFLOW_NAME
            or job.get("html_url") != check["details_url"]
            or job_id != check["job_id"]
            or job.get("conclusion") != check["check_run"].get("conclusion")
            or job_attempt in attempts
            or check_run_id in matched_check_ids
        ):
            raise GateError("predecessor audit evidence is ambiguous")
        job_started, job_started_time = canonical_github_timestamp(
            job.get("started_at"),
            "predecessor audit job start",
        )
        job_completed, job_completed_time = canonical_github_timestamp(
            job.get("completed_at"),
            "predecessor audit job completion",
        )
        if job_started_time > job_completed_time:
            raise GateError("predecessor audit evidence timestamps are inconsistent")
        matched_check_ids.add(check_run_id)
        attempts[job_attempt] = {
            "job": job,
            "job_id": job_id,
            "job_started": job_started,
            "job_started_time": job_started_time,
            "job_completed": job_completed,
            "job_completed_time": job_completed_time,
            "check": check,
        }
    expected_attempts = set(range(1, workflow_run_attempt + 1))
    if (
        set(attempts) != expected_attempts
        or matched_check_ids != set(check_evidence)
        or len(check_evidence) != workflow_run_attempt
    ):
        raise GateError("predecessor audit evidence is incomplete or ambiguous")
    for earlier, later in zip(
        range(1, workflow_run_attempt),
        range(2, workflow_run_attempt + 1),
    ):
        previous = attempts[earlier]
        current = attempts[later]
        if (
            previous["check"]["completed_time"] > current["check"]["started_time"]
            or previous["job_completed_time"] > current["job_started_time"]
        ):
            raise GateError("predecessor audit evidence timestamps are inconsistent")
    selected = attempts[workflow_run_attempt]
    selected_check = selected["check"]
    if (
        selected_check["check_run"].get("conclusion") != "success"
        or selected["job"].get("conclusion") != "success"
    ):
        raise GateError("predecessor audit evidence failed")
    check_run_id = selected_check["check_run_id"]
    check_run_node_id = selected_check["check_run_node_id"]
    details_url = selected_check["details_url"]
    check_started = selected_check["started"]
    check_started_time = selected_check["started_time"]
    check_completed = selected_check["completed"]
    check_completed_time = selected_check["completed_time"]
    job_id = selected["job_id"]
    job_started = selected["job_started"]
    job_started_time = selected["job_started_time"]
    job_completed = selected["job_completed"]
    job_completed_time = selected["job_completed_time"]

    _merged_text, merged_time = canonical_github_timestamp(
        merged_at,
        "predecessor merge",
    )
    if not (
        merged_time
        <= workflow_created_time
        <= workflow_started_time
        <= workflow_updated_time
        and merged_time <= check_started_time <= check_completed_time
        and merged_time <= job_started_time <= job_completed_time
    ):
        raise GateError("predecessor audit evidence timestamps are inconsistent")
    normalized = {
        "base_sha": base_sha,
        "parent_sha": parent_sha,
        "pull_request_number": predecessor_number,
        "pull_request_node_id": predecessor_node_id,
        "candidate_sha": candidate_sha,
        "merged_at": merged_at,
        "check_run_id": check_run_id,
        "check_run_node_id": check_run_node_id,
        "check_suite_id": check_suite_id,
        "workflow_run_id": workflow_run_id,
        "workflow_id": workflow_id,
        "workflow_run_attempt": workflow_run_attempt,
        "job_id": job_id,
        "workflow_created_at": workflow_created,
        "workflow_started_at": workflow_started,
        "workflow_updated_at": workflow_updated,
        "check_started_at": check_started,
        "check_completed_at": check_completed,
        "job_started_at": job_started,
        "job_completed_at": job_completed,
    }
    return PredecessorAuditEvidence(
        base_sha=base_sha,
        parent_sha=parent_sha,
        pull_request_number=predecessor_number,
        pull_request_node_id=predecessor_node_id,
        candidate_sha=candidate_sha,
        merged_at=merged_at,
        check_run_id=check_run_id,
        check_run_node_id=check_run_node_id,
        check_suite_id=check_suite_id,
        workflow_run_id=workflow_run_id,
        workflow_id=workflow_id,
        workflow_run_attempt=workflow_run_attempt,
        job_id=job_id,
        workflow_created_at=workflow_created,
        workflow_started_at=workflow_started,
        workflow_updated_at=workflow_updated,
        started_at=check_started,
        completed_at=check_completed,
        job_started_at=job_started,
        job_completed_at=job_completed,
        sha256=hashlib.sha256(compact_json_bytes(normalized)).hexdigest(),
    )


def read_live_pull_request(
    *,
    repository: str,
    number: int,
    node_id: str,
    base_ref: str,
    base_sha: str,
    head_repository: str,
    head_ref: str,
    head_sha: str,
    token: str,
) -> PullRequestSnapshot:
    encoded_number = canonical_positive_integer(number, "pull request number")
    payload = github_json(
        "GET",
        repository,
        f"/pulls/{encoded_number}",
        token=token,
    )
    return validate_pull_request_payload(
        payload,
        repository=repository,
        number=number,
        node_id=node_id,
        base_ref=base_ref,
        base_sha=base_sha,
        head_repository=head_repository,
        head_ref=head_ref,
        head_sha=head_sha,
    )


def _enabled(payload: Any, label: str) -> bool:
    value = object_value(payload, label)
    if value.get("enabled") is not True:
        raise GateError(f"{label} is not enabled")
    return True


def _disabled(payload: Any, label: str) -> bool:
    value = object_value(payload, label)
    if value.get("enabled") is not False:
        raise GateError(f"{label} is not disabled")
    return True


def _empty_actor_allowances(payload: Any, label: str) -> None:
    value = object_value(payload, label)
    exact_keys(value, {"apps", "teams", "users"}, label)
    for key in ("apps", "teams", "users"):
        actors = value.get(key)
        if not isinstance(actors, list) or actors:
            raise GateError(f"{label} is not empty")


def validate_repository_merge_configuration(
    payload: Any,
    *,
    repository: str,
    repository_id: int | None = None,
) -> dict[str, Any]:
    repository = canonical_repository(repository)
    if repository_id is not None:
        repository_id = canonical_positive_integer(
            repository_id,
            "repository configuration identity",
        )
    value = object_value(payload, "repository configuration")
    if (
        value.get("full_name") != repository
        or (repository_id is not None and value.get("id") != repository_id)
        or value.get("default_branch") != DEFAULT_BRANCH
        or value.get("allow_squash_merge") is not True
        or value.get("allow_merge_commit") is not False
        or value.get("allow_rebase_merge") is not False
        or value.get("squash_merge_commit_title") != "PR_TITLE"
        or value.get("squash_merge_commit_message") != "BLANK"
    ):
        raise GateError("repository is not PR-only, squash-only, and queue-compatible")
    return value


def _required_check_entries(
    raw: Any,
    *,
    integration_key: str,
    admission_app_id: int,
) -> None:
    if not isinstance(raw, list) or len(raw) != 1:
        raise GateError("required status check set is not exact")
    check = object_value(raw[0], "required status check")
    if (
        check.get("context") != REQUIRED_CHECK_CONTEXT
        or check.get(integration_key) != admission_app_id
    ):
        raise GateError("required status check is not current-Q bound")


def canonical_admission_app_id(value: Any) -> int:
    app_id = canonical_positive_integer(value, "external admission App ID")
    if ADMISSION_RECORD_APP_ID is None:
        raise GateError("external admission App identity is not pinned")
    if app_id != ADMISSION_RECORD_APP_ID:
        raise GateError("external admission App differs from the pinned identity")
    if app_id == GITHUB_ACTIONS_APP_ID:
        raise GateError("external admission App must not be GitHub Actions")
    return app_id


def bootstrap_admission_app_id(validator: Any) -> int:
    try:
        app_id = canonical_admission_app_id(ADMISSION_RECORD_APP_ID)
    except GateError as exc:
        raise GateError(
            "bootstrap migration requires a configured admission App ID"
        ) from exc
    try:
        validator_app_id = validator.history_v2_bootstrap_admission_app_id()
    except Exception as exc:
        raise GateError(
            "trusted validator admission App identity could not be read"
        ) from exc
    if (
        validator_app_id != app_id
        or getattr(validator, "HISTORY_V2_ADMISSION_RECORD_APP_SLUG", None)
        != ADMISSION_RECORD_APP_SLUG
    ):
        raise GateError("trusted bootstrap admission App identity differs")
    return app_id


def validate_active_branch_rules(
    payload: Any,
    *,
    admission_app_id: int,
) -> list[dict[str, Any]]:
    if not isinstance(payload, list) or not payload or len(payload) > 64:
        raise GateError("active branch rule inventory is invalid")
    rules: dict[str, dict[str, Any]] = {}
    normalized: list[dict[str, Any]] = []
    for raw_rule in payload:
        rule = object_value(raw_rule, "active branch rule")
        rule_type = rule.get("type")
        if not isinstance(rule_type, str) or not rule_type or rule_type in rules:
            raise GateError("active branch rule types are not exact")
        rules[rule_type] = rule
        normalized.append(rule)

    required_types = {
        "deletion",
        "merge_queue",
        "non_fast_forward",
        "pull_request",
        "required_linear_history",
        "required_status_checks",
    }
    if not required_types <= set(rules):
        raise GateError("active branch protections are incomplete")

    pull_parameters = object_value(
        rules["pull_request"].get("parameters"),
        "pull request rule parameters",
    )
    if (
        pull_parameters.get("allowed_merge_methods") != ["squash"]
        or pull_parameters.get("required_approving_review_count", 0) < 1
        or pull_parameters.get("dismiss_stale_reviews_on_push") is not True
        or pull_parameters.get("require_last_push_approval") is not True
        or pull_parameters.get("required_review_thread_resolution") is not True
    ):
        raise GateError("pull request rule permits an unsafe merge path")

    queue_parameters = object_value(
        rules["merge_queue"].get("parameters"),
        "merge queue rule parameters",
    )
    if (
        queue_parameters.get("merge_method") != "SQUASH"
        or queue_parameters.get("max_entries_to_build") != 1
        or queue_parameters.get("max_entries_to_merge") != 1
        or queue_parameters.get("min_entries_to_merge") != 1
    ):
        raise GateError("merge queue is not exact-one and squash-only")

    check_parameters = object_value(
        rules["required_status_checks"].get("parameters"),
        "required status check rule parameters",
    )
    if check_parameters.get("strict_required_status_checks_policy") is not True:
        raise GateError("required status checks are not strict")
    _required_check_entries(
        check_parameters.get("required_status_checks"),
        integration_key="integration_id",
        admission_app_id=admission_app_id,
    )
    return normalized


def validate_branch_protection(
    payload: Any,
    *,
    admission_app_id: int,
) -> dict[str, Any]:
    value = object_value(payload, "branch protection")
    required = object_value(
        value.get("required_status_checks"),
        "branch required status checks",
    )
    if required.get("strict") is not True:
        raise GateError("branch required status checks are not strict")
    if required.get("contexts") != [REQUIRED_CHECK_CONTEXT]:
        raise GateError("branch required status check contexts are not exact")
    _required_check_entries(
        required.get("checks"),
        integration_key="app_id",
        admission_app_id=admission_app_id,
    )

    reviews = object_value(
        value.get("required_pull_request_reviews"),
        "branch pull request review policy",
    )
    if (
        reviews.get("required_approving_review_count", 0) < 1
        or reviews.get("dismiss_stale_reviews") is not True
        or reviews.get("require_last_push_approval") is not True
    ):
        raise GateError("branch pull request review policy is unsafe")
    _empty_actor_allowances(
        reviews.get("bypass_pull_request_allowances"),
        "branch pull request bypass allowances",
    )
    _enabled(value.get("enforce_admins"), "branch admin enforcement")
    _enabled(
        value.get("required_linear_history"),
        "branch linear history requirement",
    )
    _enabled(
        value.get("required_conversation_resolution"),
        "branch conversation resolution requirement",
    )
    _disabled(value.get("allow_force_pushes"), "branch force pushes")
    _disabled(value.get("allow_deletions"), "branch deletion")
    return value


def validate_ruleset_inventory(
    summaries: Any,
    details: list[Any],
) -> list[dict[str, Any]]:
    if (
        not isinstance(summaries, list)
        or len(summaries) >= 100
        or len(details) != len(summaries)
    ):
        raise GateError("repository ruleset inventory is incomplete")
    summary_ids: list[int] = []
    for summary in summaries:
        value = object_value(summary, "repository ruleset summary")
        summary_ids.append(
            canonical_positive_integer(value.get("id"), "repository ruleset ID")
        )
    if len(set(summary_ids)) != len(summary_ids):
        raise GateError("repository ruleset inventory contains duplicate IDs")

    normalized: list[dict[str, Any]] = []
    for expected_id, raw_detail in zip(summary_ids, details, strict=True):
        detail = object_value(raw_detail, "repository ruleset")
        if detail.get("id") != expected_id:
            raise GateError("repository ruleset detail identity changed")
        bypass_actors = detail.get("bypass_actors")
        if not isinstance(bypass_actors, list) or bypass_actors:
            raise GateError("repository ruleset contains a bypass actor")
        enforcement = detail.get("enforcement")
        if enforcement not in {"active", "evaluate", "disabled"}:
            raise GateError("repository ruleset enforcement is invalid")
        normalized.append(detail)
    return normalized


def validate_merge_group_pull_request(
    payload: Any,
    *,
    repository: str,
    repository_id: int,
    number: int,
    base_sha: str,
) -> tuple[PullRequestSnapshot, str]:
    repository = canonical_repository(repository)
    repository_id = canonical_positive_integer(
        repository_id,
        "merge-group repository identity",
    )
    number = canonical_positive_integer(number, "merge-group pull request number")
    base_sha = canonical_oid(base_sha, "merge-group base")
    pull = object_value(payload, "merge-group pull request")
    base = object_value(pull.get("base"), "merge-group pull request base")
    head = object_value(pull.get("head"), "merge-group pull request head")
    base_repo = object_value(base.get("repo"), "merge-group base repository")
    head_repo = object_value(head.get("repo"), "merge-group head repository")
    node_id = pull.get("node_id")
    title = pull.get("title")
    head_ref = head.get("ref")
    head_sha = canonical_oid(head.get("sha"), "merge-group candidate head")
    if (
        pull.get("number") != number
        or not isinstance(node_id, str)
        or not node_id
        or len(node_id) > 256
    ):
        raise GateError("merge-group pull request identity changed")
    if (
        pull.get("state") != "open"
        or pull.get("merged") is not False
        or pull.get("merged_at") is not None
    ):
        raise GateError("merge-group pull request is not open")
    if pull.get("draft") is not False:
        raise GateError("merge-group pull request is draft")
    if (
        base_repo.get("full_name") != repository
        or base_repo.get("id") != repository_id
        or base.get("ref") != DEFAULT_BRANCH
        or base.get("sha") != base_sha
    ):
        raise GateError("merge-group pull request base changed")
    if (
        head_repo.get("full_name") != repository
        or head_repo.get("id") != repository_id
        or not isinstance(head_ref, str)
        or not head_ref
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", head_ref) is None
        or ".." in head_ref
        or "@{" in head_ref
        or head_ref.endswith(".lock")
    ):
        raise GateError("merge-group pull request head changed")
    if (
        not isinstance(title, str)
        or not title
        or len(title.encode("utf-8")) > 256
        or any(character in title for character in "\r\n\0")
    ):
        raise GateError("merge-group pull request title is invalid")
    return (
        PullRequestSnapshot(
            number=number,
            node_id=node_id,
            state="open",
            merged=False,
            merged_at=None,
            draft=False,
            base_repository=repository,
            base_ref=DEFAULT_BRANCH,
            base_sha=base_sha,
            head_repository=repository,
            head_ref=head_ref,
            head_sha=head_sha,
        ),
        title,
    )


def validate_merge_group_event(
    payload: Any,
    *,
    repository: str,
    repository_id: int,
    event_ref: str,
    event_sha: str,
    workflow_sha: str,
) -> tuple[int, str, str]:
    repository = canonical_repository(repository)
    repository_id = canonical_positive_integer(
        repository_id,
        "merge-group event repository identity",
    )
    event_sha = canonical_oid(event_sha, "merge-group event SHA")
    workflow_sha = canonical_oid(workflow_sha, "merge-group workflow SHA")
    event = object_value(payload, "merge-group event")
    event_repository = object_value(
        event.get("repository"),
        "merge-group event repository",
    )
    group = object_value(event.get("merge_group"), "merge-group event group")
    base_sha = canonical_oid(group.get("base_sha"), "merge-group base")
    queue_sha = canonical_oid(group.get("head_sha"), "merge-group queue head")
    base_ref = group.get("base_ref")
    queue_ref = group.get("head_ref")
    match = (
        MERGE_GROUP_HEAD_REF_RE.fullmatch(queue_ref)
        if isinstance(queue_ref, str)
        else None
    )
    if (
        event.get("action") != "checks_requested"
        or event_repository.get("full_name") != repository
        or event_repository.get("id") != repository_id
        or base_ref != DEFAULT_BRANCH_REF
        or match is None
        or event_ref != queue_ref
        or event_sha != queue_sha
        or workflow_sha != queue_sha
        or len({base_sha, queue_sha}) != 2
    ):
        raise GateError("merge-group event is not bound to the exact B1/Q pair")
    return int(match.group("number")), base_sha, queue_sha


def validate_live_merge_group_ref(
    payload: Any,
    *,
    queue_ref: str,
    queue_sha: str,
) -> None:
    value = object_value(payload, "live merge-group ref")
    target = object_value(value.get("object"), "live merge-group ref target")
    if (
        value.get("ref") != queue_ref
        or target.get("type") != "commit"
        or target.get("sha") != queue_sha
    ):
        raise GateError("live merge-group queue ref drifted")


def validate_trusted_branch_configuration(
    *,
    repository_payload: Any,
    active_rules_payload: Any,
    protection_payload: Any,
    ruleset_summaries: Any,
    ruleset_details: list[Any],
    repository: str,
    repository_id: int,
    admission_app_id: int,
) -> str:
    admission_app_id = canonical_admission_app_id(admission_app_id)
    normalized = {
        "repository": validate_repository_merge_configuration(
            repository_payload,
            repository=repository,
            repository_id=repository_id,
        ),
        "active_rules": validate_active_branch_rules(
            active_rules_payload,
            admission_app_id=admission_app_id,
        ),
        "branch_protection": validate_branch_protection(
            protection_payload,
            admission_app_id=admission_app_id,
        ),
        "rulesets": validate_ruleset_inventory(
            ruleset_summaries,
            ruleset_details,
        ),
    }
    return hashlib.sha256(compact_json_bytes(normalized)).hexdigest()


def read_live_merge_group_snapshot(
    *,
    repository: str,
    repository_id: int,
    event_path: Path,
    event_ref: str,
    event_sha: str,
    workflow_sha: str,
    admission_app_id: int,
    token: str,
) -> MergeGroupSnapshot:
    repository = canonical_repository(repository)
    repository_id = canonical_positive_integer(
        repository_id,
        "merge-group repository identity",
    )
    event_payload, _raw = read_bounded_json_file(
        event_path,
        "merge-group event payload",
        max_bytes=MAX_HTTP_RESPONSE_BYTES,
    )
    number, base_sha, queue_sha = validate_merge_group_event(
        event_payload,
        repository=repository,
        repository_id=repository_id,
        event_ref=event_ref,
        event_sha=event_sha,
        workflow_sha=workflow_sha,
    )
    try:
        pull_payload = github_json(
            "GET",
            repository,
            f"/pulls/{number}",
            token=token,
        )
    except GateError as exc:
        raise GateError("merge-group pull request is unavailable") from exc
    pull, title = validate_merge_group_pull_request(
        pull_payload,
        repository=repository,
        repository_id=repository_id,
        number=number,
        base_sha=base_sha,
    )
    encoded_queue_ref = parse.quote(
        event_ref.removeprefix("refs/"),
        safe="/",
    )
    validate_live_merge_group_ref(
        github_json(
            "GET",
            repository,
            f"/git/ref/{encoded_queue_ref}",
            token=token,
        ),
        queue_ref=event_ref,
        queue_sha=queue_sha,
    )
    repository_payload = github_json("GET", repository, "/", token=token)
    active_rules_payload = github_json(
        "GET",
        repository,
        f"/rules/branches/{parse.quote(DEFAULT_BRANCH, safe='')}",
        token=token,
    )
    protection_payload = github_json(
        "GET",
        repository,
        f"/branches/{parse.quote(DEFAULT_BRANCH, safe='')}/protection",
        token=token,
    )
    ruleset_summaries = github_json(
        "GET",
        repository,
        "/rulesets?per_page=100&includes_parents=true",
        token=token,
    )
    if not isinstance(ruleset_summaries, list) or len(ruleset_summaries) >= 100:
        raise GateError("repository ruleset inventory is incomplete")
    ruleset_details = [
        github_json(
            "GET",
            repository,
            f"/rulesets/{canonical_positive_integer(summary.get('id'), 'repository ruleset ID')}",
            token=token,
        )
        for summary in (
            object_value(item, "repository ruleset summary")
            for item in ruleset_summaries
        )
    ]
    tcb_sha256 = validate_trusted_branch_configuration(
        repository_payload=repository_payload,
        active_rules_payload=active_rules_payload,
        protection_payload=protection_payload,
        ruleset_summaries=ruleset_summaries,
        ruleset_details=ruleset_details,
        repository=repository,
        repository_id=repository_id,
        admission_app_id=admission_app_id,
    )
    return MergeGroupSnapshot(
        repository=repository,
        repository_id=repository_id,
        base_ref=DEFAULT_BRANCH_REF,
        base_sha=base_sha,
        queue_ref=event_ref,
        queue_sha=queue_sha,
        workflow_sha=workflow_sha,
        pull_request_number=pull.number,
        pull_request_node_id=pull.node_id,
        pull_request_title=title,
        candidate_ref=pull.head_ref,
        candidate_sha=pull.head_sha,
        required_check=REQUIRED_CHECK_CONTEXT,
        tcb_sha256=tcb_sha256,
    )


def _format_utc_timestamp(value: dt.datetime, label: str) -> str:
    if value.tzinfo != dt.timezone.utc or value.microsecond != 0:
        raise GateError(f"{label} is not UTC")
    encoded = value.isoformat(timespec="seconds").replace("+00:00", "Z")
    canonical_github_timestamp(encoded, label)
    return encoded


def _github_clock_second(value: dt.datetime, label: str) -> dt.datetime:
    if not isinstance(value, dt.datetime) or value.tzinfo != dt.timezone.utc:
        raise GateError(f"{label} is not UTC")
    return value.replace(microsecond=0)


def _predecessor_audit_normalized_payload(
    evidence: PredecessorAuditEvidence,
) -> dict[str, Any]:
    return {
        "base_sha": evidence.base_sha,
        "parent_sha": evidence.parent_sha,
        "pull_request_number": evidence.pull_request_number,
        "pull_request_node_id": evidence.pull_request_node_id,
        "candidate_sha": evidence.candidate_sha,
        "merged_at": evidence.merged_at,
        "check_run_id": evidence.check_run_id,
        "check_run_node_id": evidence.check_run_node_id,
        "check_suite_id": evidence.check_suite_id,
        "workflow_run_id": evidence.workflow_run_id,
        "workflow_id": evidence.workflow_id,
        "workflow_run_attempt": evidence.workflow_run_attempt,
        "job_id": evidence.job_id,
        "workflow_created_at": evidence.workflow_created_at,
        "workflow_started_at": evidence.workflow_started_at,
        "workflow_updated_at": evidence.workflow_updated_at,
        "check_started_at": evidence.started_at,
        "check_completed_at": evidence.completed_at,
        "job_started_at": evidence.job_started_at,
        "job_completed_at": evidence.job_completed_at,
    }


def _validate_predecessor_audit_digest(
    evidence: PredecessorAuditEvidence,
) -> None:
    if (
        evidence.sha256
        != hashlib.sha256(
            compact_json_bytes(_predecessor_audit_normalized_payload(evidence))
        ).hexdigest()
    ):
        raise GateError("predecessor audit evidence digest differs")


def _bootstrap_marker_payload(
    *,
    snapshot: MergeGroupSnapshot,
    projection: MergeGroupProjection,
    markers: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "base_sha": snapshot.base_sha,
        "queue_sha": snapshot.queue_sha,
        "pull_request_number": snapshot.pull_request_number,
        "projection_sha256": merge_group_projection_sha256(projection),
        "candidate_ref": snapshot.candidate_ref,
        "bootstrap_markers": list(markers),
    }


def _predecessor_authority_context(
    *,
    expected: MergeGroupSnapshot,
    projection: MergeGroupProjection,
    policy: str,
    trusted_base_root: Path,
) -> tuple[str | None, tuple[str, ...], str | None]:
    trusted_base_root = trusted_base_root.resolve()
    _worktree_head(trusted_base_root, expected.base_sha, "trusted B1")
    validator = trusted_validator_module(
        contract="bootstrap" if policy == "bootstrap-v2" else "permanent"
    )
    if policy == "bootstrap-v2":
        bootstrap_admission_app_id(validator)
    try:
        observed_markers = validator.history_v2_bootstrap_markers(
            trusted_base_root,
            expected.base_sha,
        )
    except Exception as exc:
        raise GateError("trusted B1 bootstrap markers could not be read") from exc
    markers = tuple(sorted(path.as_posix() for path in observed_markers))
    expected_markers = tuple(sorted(BOOTSTRAP_TEMPORARY_PATHS))
    if policy == "bootstrap-v2":
        if (
            markers != expected_markers
            or expected.candidate_ref != BOOTSTRAP_CANDIDATE_REF
            or projection.policy != policy
            or projection.role != "admin"
            or projection.candidate_base_sha != expected.base_sha
            or projection.queue_base_sha != expected.base_sha
            or projection.candidate_sha != expected.candidate_sha
            or projection.queue_sha != expected.queue_sha
        ):
            raise GateError("bootstrap predecessor migration exception is invalid")
        marker_sha256 = hashlib.sha256(
            compact_json_bytes(
                _bootstrap_marker_payload(
                    snapshot=expected,
                    projection=projection,
                    markers=markers,
                )
            )
        ).hexdigest()
        return None, markers, marker_sha256
    if policy != "history-v2":
        raise GateError("predecessor authority policy is invalid")
    if markers:
        raise GateError("history-v2 predecessor still contains bootstrap markers")
    if projection.policy != policy:
        raise GateError("predecessor authority projection policy differs")
    return _single_worktree_parent(trusted_base_root, expected.base_sha), (), None


def revalidate_external_merge_group_authority(
    *,
    expected: MergeGroupSnapshot,
    projection: MergeGroupProjection,
    policy: str,
    trusted_base_root: Path,
    event_path: Path,
    event_ref: str,
    event_sha: str,
    workflow_sha: str,
    admission_app_id: int,
    token: str,
    clock: Callable[[], dt.datetime] | None = None,
    monotonic_clock: Callable[[], float] = time.monotonic,
) -> MergeGroupLiveAuthorityEvidence:
    parent_sha, bootstrap_markers, bootstrap_marker_sha256 = (
        _predecessor_authority_context(
            expected=expected,
            projection=projection,
            policy=policy,
            trusted_base_root=trusted_base_root,
        )
    )
    live_budget = GitHubReadBudget(
        deadline=monotonic_clock() + MERGE_GROUP_LIVE_AUTHORITY_TTL_SECONDS,
        clock=monotonic_clock,
    )
    with github_read_budget_scope(live_budget):
        clock_source = (
            clock
            if clock is not None
            else lambda: github_server_time(
                repository=expected.repository,
                repository_id=expected.repository_id,
                token=token,
            )
        )
        observed_at = _github_clock_second(
            clock_source(),
            "live merge-group authority observation",
        )
        observed_at_text = _format_utc_timestamp(
            observed_at,
            "live merge-group authority observation",
        )
        valid_until = observed_at + dt.timedelta(
            seconds=MERGE_GROUP_LIVE_AUTHORITY_TTL_SECONDS
        )
        try:
            observed = read_live_merge_group_snapshot(
                repository=expected.repository,
                repository_id=expected.repository_id,
                event_path=event_path,
                event_ref=event_ref,
                event_sha=event_sha,
                workflow_sha=workflow_sha,
                admission_app_id=admission_app_id,
                token=token,
            )
        except GateError as exc:
            raise GateError(
                "live merge-group authority could not be revalidated after runtime"
            ) from exc
        audit = (
            read_trusted_predecessor_audit_evidence(
                repository=expected.repository,
                base_sha=expected.base_sha,
                parent_sha=parent_sha,
                current_pr_number=expected.pull_request_number,
                token=token,
            )
            if parent_sha is not None
            else None
        )
        completed_at = _github_clock_second(
            clock_source(),
            "live merge-group authority completion",
        )
        live_budget.checkpoint()
    _format_utc_timestamp(
        completed_at,
        "live merge-group authority completion",
    )
    if completed_at < observed_at or completed_at >= valid_until:
        raise GateError("live merge-group authority revalidation exceeded its window")
    if observed != expected:
        raise GateError("live merge-group authority changed after runtime validation")
    _worktree_head(trusted_base_root.resolve(), expected.base_sha, "trusted B1")
    if audit is not None:
        _validate_predecessor_audit_digest(audit)
        predecessor_authority = MergeGroupPredecessorAuthorityEvidence(
            mode="history-v2-required",
            base_sha=expected.base_sha,
            queue_sha=expected.queue_sha,
            pull_request_number=expected.pull_request_number,
            projection_sha256=merge_group_projection_sha256(projection),
            parent_sha=parent_sha,
            audit=audit,
            candidate_ref=None,
            bootstrap_markers=(),
            bootstrap_marker_sha256=None,
        )
    else:
        predecessor_authority = MergeGroupPredecessorAuthorityEvidence(
            mode="bootstrap-v2-migration-exception",
            base_sha=expected.base_sha,
            queue_sha=expected.queue_sha,
            pull_request_number=expected.pull_request_number,
            projection_sha256=merge_group_projection_sha256(projection),
            parent_sha=None,
            audit=None,
            candidate_ref=expected.candidate_ref,
            bootstrap_markers=bootstrap_markers,
            bootstrap_marker_sha256=bootstrap_marker_sha256,
        )
    predecessor_authority_sha256 = hashlib.sha256(
        compact_json_bytes(predecessor_authority.as_dict())
    ).hexdigest()
    return MergeGroupLiveAuthorityEvidence(
        snapshot_sha256=hashlib.sha256(
            compact_json_bytes(observed.as_dict())
        ).hexdigest(),
        tcb_sha256=observed.tcb_sha256,
        predecessor_authority=predecessor_authority,
        predecessor_authority_sha256=predecessor_authority_sha256,
        observed_at=observed_at_text,
        valid_until=_format_utc_timestamp(
            valid_until,
            "live merge-group authority expiration",
        ),
    )


def _safe_git_path(raw_path: bytes) -> str:
    try:
        value = raw_path.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GateError("candidate tree contains a non-UTF-8 path") from exc
    if (
        not value
        or "\x00" in value
        or "\\" in value
        or value.startswith("/")
        or unicodedata.normalize("NFC", value) != value
        or any(not character.isprintable() for character in value)
    ):
        raise GateError("candidate tree contains an invalid path")
    path = PurePosixPath(value)
    if (
        path.as_posix() != value
        or len(path.parts) > MAX_TREE_PATH_DEPTH
        or any(
            part in {"", ".", ".."} or part.casefold() == ".git" or part != part.strip()
            for part in path.parts
        )
    ):
        raise GateError("candidate tree contains a non-canonical path")
    if len(raw_path) > 1024 or any(
        len(part.encode("utf-8")) > 255 for part in path.parts
    ):
        raise GateError("candidate tree path exceeds the trusted length limit")
    return value


def _sensitive_candidate_path(path: str) -> bool:
    if path in PERMANENT_TRUST_GENERATION_PATHS:
        return False
    for component in PurePosixPath(path).parts:
        folded = unicodedata.normalize("NFKC", component).casefold()
        compact = re.sub(r"[^a-z0-9]+", "", folded)
        sensitive_tokens = {token for token in re.split(r"[^a-z0-9]+", folded) if token}
        if (
            folded in _FORBIDDEN_CANDIDATE_COMPONENTS
            or folded in _FORBIDDEN_CANDIDATE_FILENAMES
            or any(part in compact for part in _FORBIDDEN_CANDIDATE_COMPACT_PARTS)
            or compact.startswith("raw")
            or sensitive_tokens
            & {
                "apikey",
                "credential",
                "credentials",
                "password",
                "privatekey",
                "secret",
                "secrets",
                "token",
                "tokens",
            }
        ):
            return True
    return False


def reject_sensitive_candidate_path(path: str) -> None:
    if _sensitive_candidate_path(path):
        raise GateError("candidate tree contains a sensitive path")


def validate_complete_tree_entries(
    entries: tuple[TreeEntry, ...],
    *,
    expected_oid_length: int,
    require_blob_sizes: bool,
) -> tuple[TreeEntry, ...]:
    if expected_oid_length not in {40, 64}:
        raise GateError("candidate tree uses an unsupported hash format")
    if not entries:
        raise GateError("candidate tree contains no accepted blobs")

    seen_paths: set[str] = set()
    seen_casefolded_paths: set[str] = set()
    observed_tree_paths: set[str] = set()
    expected_tree_paths: set[str] = set()
    blob_count = 0
    total_size = 0
    for entry in entries:
        path = _safe_git_path(entry.path.encode("utf-8"))
        reject_sensitive_candidate_path(path)
        casefolded_path = path.casefold()
        if (
            path in seen_paths
            or casefolded_path in seen_casefolded_paths
            or OID_RE.fullmatch(entry.object_id) is None
            or len(entry.object_id) != expected_oid_length
        ):
            raise GateError("candidate tree metadata is invalid")
        if entry.object_type == "tree":
            if entry.mode != "040000" or entry.size is not None:
                raise GateError("candidate tree object metadata is malformed")
            observed_tree_paths.add(path)
        elif entry.object_type == "blob":
            if entry.mode not in {"100644", "100755"}:
                raise GateError("candidate blob mode is outside policy")
            if require_blob_sizes:
                if type(entry.size) is not int or not 0 <= entry.size <= MAX_BLOB_BYTES:
                    raise GateError("candidate blob size is invalid")
                total_size += entry.size
            elif entry.size is not None:
                raise GateError("candidate local blob metadata unexpectedly has a size")
            blob_count += 1
            parts = PurePosixPath(path).parts
            for depth in range(1, len(parts)):
                expected_tree_paths.add("/".join(parts[:depth]))
        else:
            raise GateError("candidate tree object type is prohibited")
        seen_paths.add(path)
        seen_casefolded_paths.add(casefolded_path)

    if blob_count == 0:
        raise GateError("candidate tree contains no accepted blobs")
    if blob_count > MAX_BLOB_ENTRIES:
        raise GateError("candidate tree blob count exceeds the trusted limit")
    if total_size > MAX_TREE_BYTES:
        raise GateError("candidate tree exceeds the trusted byte limit")
    if observed_tree_paths != expected_tree_paths:
        raise GateError("candidate tree contains an empty or unrepresented subtree")
    return entries


def parse_git_tree_records(
    raw: bytes, *, expected_oid_length: int
) -> tuple[TreeEntry, ...]:
    records = raw.split(b"\x00")
    if records[-1:] != [b""]:
        raise GateError("candidate tree metadata is not NUL terminated")
    entries: list[TreeEntry] = []
    for record in records[:-1]:
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            raise GateError("candidate tree metadata is malformed")
        raw_mode, raw_type, raw_oid = fields
        try:
            mode = raw_mode.decode("ascii")
            object_type = raw_type.decode("ascii")
            object_id = raw_oid.decode("ascii")
        except UnicodeDecodeError as exc:
            raise GateError("candidate tree metadata is not ASCII") from exc
        path = _safe_git_path(raw_path)
        entries.append(TreeEntry(path, mode, object_type, object_id, None))
        if len(entries) > MAX_TREE_ENTRIES:
            raise GateError("candidate tree entry count exceeds the trusted limit")
    return validate_complete_tree_entries(
        tuple(entries),
        expected_oid_length=expected_oid_length,
        require_blob_sizes=False,
    )


def git_tree_entries(git_dir: Path, revision: str) -> tuple[TreeEntry, ...]:
    revision = canonical_oid(revision, "tree revision")
    raw = git_output(
        git_dir,
        "ls-tree",
        "-r",
        "-t",
        "-z",
        "--full-tree",
        revision,
        max_bytes=MAX_GIT_OUTPUT_BYTES,
    )
    return parse_git_tree_records(raw, expected_oid_length=len(revision))


def validate_tree_api_payload(
    payload: Any,
    *,
    expected_tree_sha: str,
    local_entries: tuple[TreeEntry, ...],
) -> tuple[TreeEntry, ...]:
    expected_tree_sha = canonical_oid(expected_tree_sha, "candidate root tree")
    root = object_value(payload, "candidate tree response")
    if root.get("sha") != expected_tree_sha or root.get("truncated") is not False:
        raise GateError("candidate tree API inventory is incomplete or changed")
    raw_entries = root.get("tree")
    if not isinstance(raw_entries, list) or len(raw_entries) > MAX_TREE_ENTRIES:
        raise GateError("candidate tree API entry count exceeds the trusted limit")

    local_by_path = {entry.path: entry for entry in local_entries}
    api_entries: list[TreeEntry] = []
    seen: set[str] = set()
    blob_count = 0
    total_size = 0
    for raw_entry in raw_entries:
        entry = object_value(raw_entry, "candidate tree entry")
        raw_path = entry.get("path")
        if not isinstance(raw_path, str):
            raise GateError("candidate tree API path is invalid")
        try:
            encoded_path = raw_path.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise GateError("candidate tree API path is invalid") from exc
        path = _safe_git_path(encoded_path)
        reject_sensitive_candidate_path(path)
        mode = entry.get("mode")
        object_type = entry.get("type")
        object_id = canonical_oid(entry.get("sha"), "candidate tree object")
        size = entry.get("size")
        if (
            path in seen
            or not isinstance(mode, str)
            or object_type
            not in {
                "blob",
                "tree",
                "commit",
            }
        ):
            raise GateError("candidate tree API entry is invalid")
        seen.add(path)
        if object_type == "blob":
            if type(size) is not int or size < 0:
                raise GateError("candidate blob size is invalid")
            blob_count += 1
            total_size += size
            if size > MAX_BLOB_BYTES:
                raise GateError("candidate blob exceeds the trusted size limit")
            if blob_count > MAX_BLOB_ENTRIES:
                raise GateError("candidate blob count exceeds the trusted limit")
            if total_size > MAX_TREE_BYTES:
                raise GateError("candidate tree exceeds the trusted byte limit")
        elif size is not None:
            raise GateError("candidate non-blob entry unexpectedly has a size")
        normalized = TreeEntry(path, mode, object_type, object_id, size)
        local = local_by_path.get(path)
        if local is None or (
            local.mode,
            local.object_type,
            local.object_id,
        ) != (mode, object_type, object_id):
            raise GateError("candidate tree API inventory differs from bare Git")
        api_entries.append(normalized)
    if seen != set(local_by_path):
        raise GateError("candidate tree API inventory omits bare Git entries")
    normalized_entries = tuple(sorted(api_entries, key=lambda entry: entry.path))
    return validate_complete_tree_entries(
        normalized_entries,
        expected_oid_length=len(expected_tree_sha),
        require_blob_sizes=True,
    )


def validate_candidate_commit_object(
    git_dir: Path,
    head_sha: str,
    *,
    signature_verifier: Any | None = None,
    strict_bootstrap_metadata: bool = True,
) -> CandidateCommit:
    head_sha = canonical_oid(head_sha, "candidate commit")
    size_text = git_text(git_dir, "cat-file", "-s", head_sha, max_bytes=128).strip()
    if not size_text.isdecimal() or not 0 < int(size_text) <= MAX_COMMIT_BYTES:
        raise GateError("candidate commit object exceeds the trusted size limit")
    raw = git_output(
        git_dir,
        "cat-file",
        "commit",
        head_sha,
        max_bytes=MAX_COMMIT_BYTES,
    )
    if len(raw) != int(size_text):
        raise GateError("candidate commit object changed while being read")
    if strict_bootstrap_metadata or signature_verifier is not None:
        try:
            parsed = trusted_validator_module(
                contract="bootstrap"
            ).parse_history_v2_commit_object(
                raw,
                expected_oid=head_sha,
            )
            tree_oid = canonical_oid(parsed.tree_oid, "candidate commit tree")
            parents = tuple(
                canonical_oid(parent, "candidate commit parent")
                for parent in parsed.parents
            )
            if signature_verifier is not None:
                signature_verifier.verify(parsed.signature)
        except (AttributeError, TypeError, ValueError) as exc:
            raise GateError(
                "candidate commit object failed retained-history metadata policy"
            ) from exc
    else:
        header, separator, _message = raw.partition(b"\n\n")
        if not separator or not header:
            raise GateError("candidate commit object is malformed")
        tree_values: list[str] = []
        parent_values: list[str] = []
        previous_name: bytes | None = None
        for line in header.split(b"\n"):
            if line.startswith(b" "):
                if previous_name != b"gpgsig":
                    raise GateError("candidate commit continuation is malformed")
                continue
            name, space, value = line.partition(b" ")
            if not space or not name or not value:
                raise GateError("candidate commit header is malformed")
            previous_name = name
            try:
                decoded = value.decode("ascii")
            except UnicodeDecodeError as exc:
                if name in {b"tree", b"parent"}:
                    raise GateError("candidate commit coordinate is invalid") from exc
                continue
            if name == b"tree":
                tree_values.append(decoded)
            elif name == b"parent":
                parent_values.append(decoded)
        if len(tree_values) != 1 or not parent_values:
            raise GateError("candidate commit coordinates are incomplete")
        tree_oid = canonical_oid(tree_values[0], "candidate commit tree")
        parents = tuple(
            canonical_oid(parent, "candidate commit parent") for parent in parent_values
        )
        if len(parents) > 2 or len(set(parents)) != len(parents):
            raise GateError("candidate commit parent set is invalid")
    if any(len(object_id) != len(head_sha) for object_id in (tree_oid, *parents)):
        raise GateError("candidate commit object uses inconsistent hash formats")
    return CandidateCommit(
        object_id=head_sha,
        tree_oid=tree_oid,
        parents=parents,
    )


def candidate_signature_key_bytes(
    git_dir: Path,
    manifest: GitPreflight,
) -> tuple[bytes, Path]:
    validator = trusted_validator_module()
    try:
        relative = validator.HISTORY_V2_SIGNATURE_KEY_PATHS[manifest.policy]
        expected_digest = validator.BOOTSTRAP_V2_PUBLIC_KEY_SHA256[relative]
        max_bytes = validator.BOOTSTRAP_V2_MAX_PUBLIC_KEY_BYTES
    except (AttributeError, KeyError, TypeError) as exc:
        raise GateError("candidate signing key role is unavailable") from exc
    entry = next(
        (
            candidate
            for candidate in manifest.entries
            if candidate.path == relative.as_posix()
        ),
        None,
    )
    if (
        entry is None
        or entry.object_type != "blob"
        or entry.mode != "100644"
        or entry.size is None
        or not 0 < entry.size <= max_bytes
    ):
        raise GateError("candidate signing key artifact is outside policy")
    value = git_output(
        git_dir,
        "cat-file",
        "blob",
        entry.object_id,
        max_bytes=max_bytes,
    )
    if len(value) != entry.size or hashlib.sha256(value).hexdigest() != expected_digest:
        raise GateError("candidate signing key differs from trusted policy")
    return value, relative


def reconstruct_candidate_tree_oid(
    entries: tuple[TreeEntry, ...], *, expected_tree_sha: str
) -> None:
    expected_tree_sha = canonical_oid(expected_tree_sha, "candidate root tree")
    validate_complete_tree_entries(
        entries,
        expected_oid_length=len(expected_tree_sha),
        require_blob_sizes=all(
            entry.size is not None for entry in entries if entry.object_type == "blob"
        ),
    )
    index_records = b"".join(
        entry.mode.encode("ascii")
        + b" "
        + entry.object_id.encode("ascii")
        + b"\t"
        + entry.path.encode("utf-8")
        + b"\x00"
        for entry in entries
        if entry.object_type == "blob"
    )
    if len(index_records) > MAX_GIT_OUTPUT_BYTES:
        raise GateError("candidate tree index exceeds the trusted input limit")

    with tempfile.TemporaryDirectory(prefix="trusted-history-tree-") as raw:
        workspace = Path(raw)
        tree_root = workspace / "tree"
        git_dir = workspace / "git"
        home = workspace / "home"
        home.mkdir(mode=0o700)
        object_format = "sha256" if len(expected_tree_sha) == 64 else "sha1"
        environment = closed_git_environment(home=home)
        try:
            run_bounded(
                closed_git_command(
                    "init",
                    "--quiet",
                    f"--object-format={object_format}",
                    "--separate-git-dir",
                    str(git_dir),
                    str(tree_root),
                ),
                max_output_bytes=0,
                environment=environment,
            )
            run_bounded(
                closed_git_command(
                    "-C",
                    str(tree_root),
                    "update-index",
                    "--add",
                    "--info-only",
                    "-z",
                    "--index-info",
                ),
                input_data=index_records,
                max_output_bytes=0,
                environment=environment,
            )
            reconstructed_tree = canonical_oid(
                run_bounded(
                    closed_git_command(
                        "-C",
                        str(tree_root),
                        "write-tree",
                        "--missing-ok",
                    ),
                    max_output_bytes=128,
                    environment=environment,
                )
                .decode("ascii")
                .strip(),
                "reconstructed candidate tree",
            )
        except (GateError, UnicodeDecodeError) as exc:
            raise GateError(
                "candidate tree identity could not be reconstructed"
            ) from exc
    if reconstructed_tree != expected_tree_sha:
        raise GateError("reconstructed candidate tree differs from the original")


def _verify_bootstrap_deletions(git_dir: Path, base_sha: str, head_sha: str) -> None:
    raw = git_output(
        git_dir,
        "diff-tree",
        "--no-commit-id",
        "--name-status",
        "-z",
        "-r",
        "--no-renames",
        base_sha,
        head_sha,
        "--",
        *BOOTSTRAP_TEMPORARY_PATHS,
        max_bytes=64 * 1024,
    )
    fields = raw.split(b"\x00")
    if fields[-1:] != [b""]:
        raise GateError("bootstrap deletion diff is malformed")
    observed: dict[str, str] = {}
    index = 0
    while index < len(fields) - 1:
        try:
            status = fields[index].decode("ascii")
        except UnicodeDecodeError as exc:
            raise GateError("bootstrap deletion status is invalid") from exc
        if index + 1 >= len(fields) - 1:
            raise GateError("bootstrap deletion diff is incomplete")
        path = _safe_git_path(fields[index + 1])
        if path in observed:
            raise GateError("bootstrap deletion diff contains duplicate paths")
        observed[path] = status
        index += 2
    expected = {path: "D" for path in BOOTSTRAP_TEMPORARY_PATHS}
    if observed != expected:
        raise GateError("candidate must explicitly delete every bootstrap artifact")


def _verify_bootstrap_ci_transition(
    base_entries: tuple[TreeEntry, ...],
    head_entries: tuple[TreeEntry, ...],
) -> None:
    base = {entry.path: entry for entry in base_entries}
    head = {entry.path: entry for entry in head_entries}
    base_ci = base.get(BOOTSTRAP_CI_PATH)
    template = base.get(BOOTSTRAP_CI_TEMPLATE_PATH)
    head_ci = head.get(BOOTSTRAP_CI_PATH)
    if (
        base_ci is None
        or base_ci.mode != "100644"
        or base_ci.object_type != "blob"
        or base_ci.object_id not in {LEGACY_CI_BLOB_OID, PERMANENT_CI_BLOB_OID}
    ):
        raise GateError("event base CI is outside the authorized migration")
    if (
        template is None
        or template.mode != "100644"
        or template.object_type != "blob"
        or template.object_id != PERMANENT_CI_BLOB_OID
    ):
        raise GateError("event base permanent CI template changed")
    if (
        head_ci is None
        or head_ci.mode != "100644"
        or head_ci.object_type != "blob"
        or head_ci.object_id != PERMANENT_CI_BLOB_OID
    ):
        raise GateError("candidate CI is not the authorized permanent blob")


def candidate_commit_range(
    git_dir: Path,
    *,
    base_sha: str,
    head_sha: str,
    policy: str,
) -> tuple[CandidateCommit, ...]:
    base_sha = canonical_oid(base_sha, "event base")
    head_sha = canonical_oid(head_sha, "event head")
    if policy not in {"bootstrap-v2", "history-v2"}:
        raise GateError("candidate preflight policy is invalid")
    for label, revision in (("base", base_sha), ("head", head_sha)):
        if (
            git_text(git_dir, "cat-file", "-t", revision, max_bytes=64).strip()
            != "commit"
        ):
            raise GateError(f"candidate {label} object is not a commit")

    merge_bases = tuple(
        line
        for line in git_text(
            git_dir,
            "merge-base",
            "--all",
            base_sha,
            head_sha,
            max_bytes=1024,
        ).splitlines()
        if line
    )
    if merge_bases != (base_sha,):
        raise GateError("candidate must have one merge base equal to the event base")
    commit_count_text = git_text(
        git_dir,
        "rev-list",
        "--count",
        "--max-count=65",
        f"{base_sha}..{head_sha}",
        max_bytes=128,
    ).strip()
    if not commit_count_text.isdecimal():
        raise GateError("candidate commit count is invalid")
    commit_count = int(commit_count_text)
    if policy == "bootstrap-v2" and commit_count != 1:
        raise GateError("bootstrap candidate must contain exactly one commit")
    if policy == "history-v2" and not 1 <= commit_count <= 64:
        raise GateError("history candidate commit count exceeds the trusted limit")

    commit_oids = tuple(
        line
        for line in git_text(
            git_dir,
            "rev-list",
            "--reverse",
            "--topo-order",
            f"{base_sha}..{head_sha}",
            max_bytes=16 * 1024,
        ).splitlines()
        if line
    )
    if (
        len(commit_oids) != commit_count
        or len(set(commit_oids)) != len(commit_oids)
        or not commit_oids
        or commit_oids[-1] != head_sha
    ):
        raise GateError("candidate commit enumeration changed during preflight")

    commits: list[CandidateCommit] = []
    preceding = {base_sha}
    for object_id in commit_oids:
        object_id = canonical_oid(object_id, "candidate range commit")
        commit = validate_candidate_commit_object(
            git_dir,
            object_id,
            strict_bootstrap_metadata=policy == "bootstrap-v2",
        )
        if any(parent not in preceding for parent in commit.parents):
            raise GateError(
                "candidate commit graph is not bounded to the authorized range"
            )
        commits.append(commit)
        preceding.add(object_id)
    if policy == "bootstrap-v2" and commits[0].parents != (base_sha,):
        raise GateError(
            "bootstrap candidate must have exactly the event base as parent"
        )
    if policy == "bootstrap-v2":
        _verify_bootstrap_deletions(git_dir, base_sha, head_sha)
    return tuple(commits)


def candidate_local_trees(
    git_dir: Path,
    commits: tuple[CandidateCommit, ...],
) -> tuple[CandidateTree, ...]:
    trees: list[CandidateTree] = []
    observed: dict[str, tuple[TreeEntry, ...]] = {}
    tree_entry_count = 0
    tree_path_bytes = 0
    for commit in commits:
        entries = git_tree_entries(git_dir, commit.object_id)
        reconstruct_candidate_tree_oid(
            entries,
            expected_tree_sha=commit.tree_oid,
        )
        previous = observed.get(commit.tree_oid)
        if previous is not None:
            if previous != entries:
                raise GateError("candidate reused tree inventory changed")
            continue
        tree_entry_count += len(entries)
        tree_path_bytes += sum(len(entry.path.encode("utf-8")) for entry in entries)
        if (
            tree_entry_count > MAX_RANGE_TREE_ENTRIES
            or tree_path_bytes > MAX_RANGE_TREE_PATH_BYTES
        ):
            raise GateError("candidate range tree inventory exceeds the trusted limit")
        observed[commit.tree_oid] = entries
        trees.append(CandidateTree(commit.tree_oid, entries))
    return tuple(trees)


def _candidate_tree_payloads(
    tree_payload: Any | None,
    *,
    local_trees: tuple[CandidateTree, ...],
    tree_payload_loader: Callable[[str], Any] | None,
) -> dict[str, Any]:
    expected = tuple(tree.tree_oid for tree in local_trees)
    if tree_payload_loader is not None:
        if tree_payload is not None:
            raise GateError("candidate tree payload sources are ambiguous")
        return {tree_oid: tree_payload_loader(tree_oid) for tree_oid in expected}
    if tree_payload is None:
        raise GateError("candidate tree API inventory is unavailable")
    if len(expected) == 1 and isinstance(tree_payload, dict) and "tree" in tree_payload:
        return {expected[0]: tree_payload}
    if not isinstance(tree_payload, dict) or set(tree_payload) != set(expected):
        raise GateError("candidate range tree API inventory is incomplete")
    return dict(tree_payload)


def allowed_blob_entries(manifest: GitPreflight) -> tuple[TreeEntry, ...]:
    blobs: dict[str, TreeEntry] = {}
    for tree in manifest.trees:
        for entry in tree.entries:
            if entry.object_type != "blob" or entry.size is None:
                continue
            previous = blobs.setdefault(entry.object_id, entry)
            if previous.size != entry.size:
                raise GateError("candidate blob size changed across commit trees")
    return tuple(blobs[object_id] for object_id in sorted(blobs))


def git_object_metadata(
    git_dir: Path,
    object_ids: Iterable[str],
) -> dict[str, tuple[str, int] | None]:
    ordered = tuple(dict.fromkeys(object_ids))
    if any(
        canonical_oid(object_id, "candidate object") != object_id
        for object_id in ordered
    ):
        raise GateError("candidate object inventory is invalid")
    if not ordered:
        return {}
    input_data = "".join(f"{object_id}\n" for object_id in ordered).encode("ascii")
    output = git_output(
        git_dir,
        "cat-file",
        "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        input_data=input_data,
        max_bytes=MAX_GIT_OUTPUT_BYTES,
    )
    lines = output.split(b"\n")
    if lines[-1:] != [b""] or len(lines) != len(ordered) + 1:
        raise GateError("candidate object metadata result is incomplete")
    result: dict[str, tuple[str, int] | None] = {}
    for expected_oid, raw_line in zip(ordered, lines[:-1], strict=True):
        try:
            line = raw_line.decode("ascii")
        except UnicodeDecodeError as exc:
            raise GateError("candidate object metadata is not ASCII") from exc
        if line == f"{expected_oid} missing":
            result[expected_oid] = None
            continue
        fields = line.split(" ")
        if len(fields) != 3 or fields[0] != expected_oid or not fields[2].isdecimal():
            raise GateError("candidate object metadata changed during inspection")
        result[expected_oid] = (fields[1], int(fields[2]))
    return result


def reachable_base_blob_oids(git_dir: Path, base_sha: str) -> frozenset[str]:
    base_sha = canonical_oid(base_sha, "candidate base")
    raw = git_output(
        git_dir,
        "rev-list",
        "--objects",
        "--no-object-names",
        base_sha,
        max_bytes=MAX_GIT_OUTPUT_BYTES,
    )
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise GateError("authenticated base object inventory is not ASCII") from exc
    object_ids = tuple(dict.fromkeys(lines))
    if (
        not object_ids
        or len(object_ids) != len(lines)
        or len(object_ids) > MAX_RANGE_TREE_ENTRIES
        or any(
            canonical_oid(object_id, "authenticated base object") != object_id
            or len(object_id) != len(base_sha)
            for object_id in object_ids
        )
    ):
        raise GateError("authenticated base object inventory is invalid")
    metadata = git_object_metadata(git_dir, object_ids)
    if any(value is None for value in metadata.values()):
        raise GateError("authenticated base object closure is incomplete")
    return frozenset(
        object_id
        for object_id, value in metadata.items()
        if value is not None and value[0] == "blob"
    )


def validate_oid_only_candidate_store(
    git_dir: Path,
    *,
    base_sha: str,
    candidate_trees: tuple[CandidateTree, ...],
) -> frozenset[str]:
    # Base content is authenticated and intentionally present. Every blob OID
    # introduced by the candidate range must remain absent until its path and
    # size have been admitted to the complete per-commit API manifest.
    validate_closed_candidate_repository(git_dir)
    if git_text(git_dir, "remote", max_bytes=1024).strip():
        raise GateError("candidate object store retained a remote fallback")
    base_blob_oids = reachable_base_blob_oids(git_dir, base_sha)
    candidate_blob_oids = {
        entry.object_id
        for tree in candidate_trees
        for entry in tree.entries
        if entry.object_type == "blob"
    }
    candidate_only_oids = candidate_blob_oids - base_blob_oids
    metadata = git_object_metadata(
        git_dir,
        (*sorted(base_blob_oids), *sorted(candidate_only_oids)),
    )
    if any(
        metadata[object_id] is None or metadata[object_id][0] != "blob"
        for object_id in base_blob_oids
    ):
        raise GateError("authenticated base blob closure is incomplete")
    if any(metadata[object_id] is not None for object_id in candidate_only_oids):
        raise GateError("candidate blob was present before allowlisted acquisition")
    return frozenset(candidate_only_oids)


def preflight_git_candidate(
    git_dir: Path,
    *,
    base_sha: str,
    head_sha: str,
    tree_payload: Any | None,
    policy: str,
    tree_payload_loader: Callable[[str], Any] | None = None,
) -> GitPreflight:
    git_dir = git_dir.resolve()
    if not git_dir.is_dir():
        raise GateError("candidate bare Git directory is unavailable")
    base_sha = canonical_oid(base_sha, "event base")
    head_sha = canonical_oid(head_sha, "event head")
    validate_closed_candidate_repository(git_dir)
    commits = candidate_commit_range(
        git_dir,
        base_sha=base_sha,
        head_sha=head_sha,
        policy=policy,
    )
    local_trees = candidate_local_trees(git_dir, commits)
    base_entries = git_tree_entries(git_dir, base_sha)
    head_tree_sha = commits[-1].tree_oid
    local_by_oid = {tree.tree_oid: tree.entries for tree in local_trees}
    if policy == "bootstrap-v2":
        _verify_bootstrap_ci_transition(
            base_entries,
            local_by_oid[head_tree_sha],
        )
    validate_oid_only_candidate_store(
        git_dir,
        base_sha=base_sha,
        candidate_trees=local_trees,
    )

    # Finish all local range/path validation before the first API request.
    payloads = _candidate_tree_payloads(
        tree_payload,
        local_trees=local_trees,
        tree_payload_loader=tree_payload_loader,
    )
    trees: list[CandidateTree] = []
    for local_tree in local_trees:
        entries = validate_tree_api_payload(
            payloads[local_tree.tree_oid],
            expected_tree_sha=local_tree.tree_oid,
            local_entries=local_tree.entries,
        )
        reconstruct_candidate_tree_oid(
            entries,
            expected_tree_sha=local_tree.tree_oid,
        )
        trees.append(CandidateTree(local_tree.tree_oid, entries))

    provisional = GitPreflight(
        schema_version=2,
        policy=policy,
        base_sha=base_sha,
        head_sha=head_sha,
        head_tree_sha=head_tree_sha,
        commit_count=len(commits),
        tree_entry_count=sum(len(tree.entries) for tree in trees),
        blob_entry_count=0,
        total_blob_bytes=0,
        commits=commits,
        trees=tuple(trees),
    )
    blobs = allowed_blob_entries(provisional)
    total_blob_bytes = sum(entry.size or 0 for entry in blobs)
    if len(blobs) > MAX_BLOB_ENTRIES or total_blob_bytes > MAX_TREE_BYTES:
        raise GateError("candidate range blob set exceeds the trusted limit")
    manifest = GitPreflight(
        schema_version=provisional.schema_version,
        policy=provisional.policy,
        base_sha=provisional.base_sha,
        head_sha=provisional.head_sha,
        head_tree_sha=provisional.head_tree_sha,
        commit_count=provisional.commit_count,
        tree_entry_count=provisional.tree_entry_count,
        blob_entry_count=len(blobs),
        total_blob_bytes=total_blob_bytes,
        commits=provisional.commits,
        trees=provisional.trees,
    )
    if len(compact_json_bytes(manifest.as_dict())) > MAX_PREFLIGHT_MANIFEST_BYTES:
        raise GateError("candidate preflight manifest exceeds the trusted limit")
    return manifest


def _parse_preflight_entries(
    raw_entries: Any,
    *,
    expected_oid_length: int,
) -> tuple[TreeEntry, ...]:
    if not isinstance(raw_entries, list) or len(raw_entries) > MAX_TREE_ENTRIES:
        raise GateError("candidate preflight manifest entry count is invalid")
    entries: list[TreeEntry] = []
    for raw_entry in raw_entries:
        entry = object_value(raw_entry, "candidate preflight entry")
        exact_keys(
            entry,
            {"path", "mode", "object_type", "object_id", "size"},
            "candidate preflight entry",
        )
        raw_path = entry.get("path")
        if not isinstance(raw_path, str):
            raise GateError("candidate preflight manifest path is invalid")
        try:
            encoded_path = raw_path.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise GateError("candidate preflight manifest path is invalid") from exc
        path_value = _safe_git_path(encoded_path)
        reject_sensitive_candidate_path(path_value)
        mode = entry.get("mode")
        object_type = entry.get("object_type")
        size = entry.get("size")
        object_id = canonical_oid(entry.get("object_id"), "manifest object")
        if (
            not isinstance(mode, str)
            or re.fullmatch(r"[0-7]{6}", mode) is None
            or object_type not in {"blob", "tree"}
            or mode == "120000"
            or len(object_id) != expected_oid_length
        ):
            raise GateError("candidate preflight manifest entry is invalid")
        if object_type == "blob":
            if type(size) is not int or not 0 <= size <= MAX_BLOB_BYTES:
                raise GateError("candidate preflight manifest blob size is invalid")
        elif size is not None:
            raise GateError("candidate preflight manifest tree size is invalid")
        entries.append(TreeEntry(path_value, mode, object_type, object_id, size))
    return validate_complete_tree_entries(
        tuple(entries),
        expected_oid_length=expected_oid_length,
        require_blob_sizes=True,
    )


def load_preflight(path: Path) -> GitPreflight:
    payload, _raw = read_bounded_json_file(
        path,
        "candidate preflight manifest",
        max_bytes=MAX_PREFLIGHT_MANIFEST_BYTES,
    )
    root = object_value(payload, "candidate preflight manifest")
    exact_keys(
        root,
        {
            "schema_version",
            "policy",
            "base_sha",
            "head_sha",
            "head_tree_sha",
            "commit_count",
            "tree_entry_count",
            "blob_entry_count",
            "total_blob_bytes",
            "commits",
            "trees",
        },
        "candidate preflight manifest",
    )
    if type(root.get("schema_version")) is not int or root.get("schema_version") != 2:
        raise GateError("candidate preflight manifest schema is invalid")
    policy = root.get("policy")
    if policy not in {"bootstrap-v2", "history-v2"}:
        raise GateError("candidate preflight manifest policy is invalid")
    base_sha = canonical_oid(root.get("base_sha"), "manifest base")
    head_sha = canonical_oid(root.get("head_sha"), "manifest head")
    head_tree_sha = canonical_oid(root.get("head_tree_sha"), "manifest tree")
    expected_oid_length = len(head_sha)
    if base_sha == head_sha or any(
        len(object_id) != expected_oid_length for object_id in (base_sha, head_tree_sha)
    ):
        raise GateError("candidate preflight manifest hash formats differ")

    raw_commits = root.get("commits")
    if not isinstance(raw_commits, list) or not 1 <= len(raw_commits) <= 64:
        raise GateError("candidate preflight commit manifest is invalid")
    commits: list[CandidateCommit] = []
    preceding = {base_sha}
    for raw_commit in raw_commits:
        commit = object_value(raw_commit, "candidate preflight commit")
        exact_keys(
            commit,
            {"object_id", "tree_oid", "parents"},
            "candidate preflight commit",
        )
        object_id = canonical_oid(commit.get("object_id"), "manifest commit")
        tree_oid = canonical_oid(commit.get("tree_oid"), "manifest commit tree")
        raw_parents = commit.get("parents")
        if not isinstance(raw_parents, list):
            raise GateError("candidate preflight commit parents are invalid")
        parents = tuple(
            canonical_oid(parent, "manifest commit parent") for parent in raw_parents
        )
        if (
            any(
                len(candidate) != expected_oid_length
                for candidate in (object_id, tree_oid, *parents)
            )
            or object_id in preceding
            or any(parent not in preceding for parent in parents)
        ):
            raise GateError("candidate preflight commit graph is invalid")
        commits.append(CandidateCommit(object_id, tree_oid, parents))
        preceding.add(object_id)
    if commits[-1].object_id != head_sha or commits[-1].tree_oid != head_tree_sha:
        raise GateError("candidate preflight head commit changed")
    if policy == "bootstrap-v2" and (
        len(commits) != 1 or commits[0].parents != (base_sha,)
    ):
        raise GateError("candidate bootstrap commit manifest is invalid")

    raw_trees = root.get("trees")
    if not isinstance(raw_trees, list) or not raw_trees:
        raise GateError("candidate preflight tree manifest is invalid")
    trees: list[CandidateTree] = []
    seen_tree_oids: set[str] = set()
    for raw_tree in raw_trees:
        tree = object_value(raw_tree, "candidate preflight tree")
        exact_keys(
            tree,
            {"tree_oid", "entries"},
            "candidate preflight tree",
        )
        tree_oid = canonical_oid(tree.get("tree_oid"), "manifest tree")
        if len(tree_oid) != expected_oid_length or tree_oid in seen_tree_oids:
            raise GateError("candidate preflight tree manifest is invalid")
        entries = _parse_preflight_entries(
            tree.get("entries"),
            expected_oid_length=expected_oid_length,
        )
        reconstruct_candidate_tree_oid(entries, expected_tree_sha=tree_oid)
        trees.append(CandidateTree(tree_oid, entries))
        seen_tree_oids.add(tree_oid)
    expected_tree_order = tuple(dict.fromkeys(commit.tree_oid for commit in commits))
    if tuple(tree.tree_oid for tree in trees) != expected_tree_order:
        raise GateError("candidate preflight commit trees are incomplete")

    numeric_fields = (
        "commit_count",
        "tree_entry_count",
        "blob_entry_count",
        "total_blob_bytes",
    )
    if any(type(root.get(field)) is not int for field in numeric_fields):
        raise GateError("candidate preflight manifest counts are invalid")
    manifest = GitPreflight(
        schema_version=2,
        policy=policy,
        base_sha=base_sha,
        head_sha=head_sha,
        head_tree_sha=head_tree_sha,
        commit_count=root["commit_count"],
        tree_entry_count=root["tree_entry_count"],
        blob_entry_count=root["blob_entry_count"],
        total_blob_bytes=root["total_blob_bytes"],
        commits=tuple(commits),
        trees=tuple(trees),
    )
    blobs = allowed_blob_entries(manifest)
    tree_path_bytes = sum(
        len(entry.path.encode("utf-8")) for tree in trees for entry in tree.entries
    )
    if (
        manifest.commit_count != len(commits)
        or manifest.tree_entry_count != sum(len(tree.entries) for tree in trees)
        or manifest.tree_entry_count > MAX_RANGE_TREE_ENTRIES
        or tree_path_bytes > MAX_RANGE_TREE_PATH_BYTES
        or manifest.blob_entry_count != len(blobs)
        or manifest.total_blob_bytes != sum(entry.size or 0 for entry in blobs)
        or manifest.blob_entry_count > MAX_BLOB_ENTRIES
        or manifest.total_blob_bytes > MAX_TREE_BYTES
    ):
        raise GateError("candidate preflight manifest counts changed")
    return manifest


def verify_preflight_objects(git_dir: Path, manifest: GitPreflight) -> None:
    git_dir = git_dir.resolve()
    validate_closed_candidate_repository(git_dir)
    observed_commits = candidate_commit_range(
        git_dir,
        base_sha=manifest.base_sha,
        head_sha=manifest.head_sha,
        policy=manifest.policy,
    )
    if observed_commits != manifest.commits:
        raise GateError("candidate commit range differs from preflight")
    local_trees = candidate_local_trees(git_dir, observed_commits)
    if tuple(tree.tree_oid for tree in local_trees) != tuple(
        tree.tree_oid for tree in manifest.trees
    ):
        raise GateError("candidate tree range differs from preflight")
    for local_tree, manifest_tree in zip(
        local_trees,
        manifest.trees,
        strict=True,
    ):
        local_metadata = tuple(
            (entry.path, entry.mode, entry.object_type, entry.object_id)
            for entry in local_tree.entries
        )
        manifest_metadata = tuple(
            (entry.path, entry.mode, entry.object_type, entry.object_id)
            for entry in manifest_tree.entries
        )
        if local_metadata != manifest_metadata:
            raise GateError("candidate tree inventory differs from preflight")
        reconstruct_candidate_tree_oid(
            manifest_tree.entries,
            expected_tree_sha=manifest_tree.tree_oid,
        )

    blob_entries = allowed_blob_entries(manifest)
    try:
        metadata = git_object_metadata(
            git_dir.resolve(),
            (entry.object_id for entry in blob_entries),
        )
    except GateError as exc:
        raise GateError("candidate blob verification failed closed") from exc
    for entry in blob_entries:
        observed = metadata[entry.object_id]
        if observed is None or observed[0] != "blob":
            raise GateError("candidate blob object changed after preflight")
        if observed[1] != entry.size:
            raise GateError("candidate blob size changed after preflight")
    if manifest.policy == "bootstrap-v2":
        public_key, relative = candidate_signature_key_bytes(git_dir, manifest)
        try:
            with trusted_validator_module(
                contract="bootstrap"
            ).HistoryV2SignatureVerifier(
                public_key,
                relative=relative,
            ) as signature_verifier:
                for expected_commit in manifest.commits:
                    verified_commit = validate_candidate_commit_object(
                        git_dir,
                        expected_commit.object_id,
                        signature_verifier=signature_verifier,
                        strict_bootstrap_metadata=True,
                    )
                    if verified_commit != expected_commit:
                        raise GateError(
                            "candidate signed commit differs from preflight"
                        )
        except (OSError, ValueError) as exc:
            raise GateError("candidate commit signature verification failed") from exc


def parse_merge_group_snapshot(payload: Any) -> MergeGroupSnapshot:
    payload = object_value(payload, "merge-group snapshot")
    exact_keys(
        payload,
        {
            "schema_version",
            "kind",
            "repository",
            "repository_id",
            "base",
            "queue",
            "workflow_sha",
            "pull_request",
            "tcb",
        },
        "merge-group snapshot",
    )
    if (
        type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 2
        or payload.get("kind") != MERGE_GROUP_SNAPSHOT_KIND
    ):
        raise GateError("merge-group snapshot identity is invalid")
    repository = canonical_repository(payload.get("repository"))
    repository_id = canonical_positive_integer(
        payload.get("repository_id"),
        "merge-group snapshot repository identity",
    )
    base = object_value(payload.get("base"), "merge-group snapshot base")
    queue = object_value(payload.get("queue"), "merge-group snapshot queue")
    pull = object_value(
        payload.get("pull_request"),
        "merge-group snapshot pull request",
    )
    tcb = object_value(payload.get("tcb"), "merge-group snapshot TCB")
    exact_keys(base, {"ref", "sha"}, "merge-group snapshot base")
    exact_keys(queue, {"ref", "sha"}, "merge-group snapshot queue")
    exact_keys(
        pull,
        {"number", "node_id", "title", "head_ref", "head_sha"},
        "merge-group snapshot pull request",
    )
    exact_keys(tcb, {"required_check", "sha256"}, "merge-group snapshot TCB")
    base_sha = canonical_oid(base.get("sha"), "merge-group snapshot base")
    queue_sha = canonical_oid(queue.get("sha"), "merge-group snapshot queue")
    workflow_sha = canonical_oid(
        payload.get("workflow_sha"),
        "merge-group snapshot workflow",
    )
    queue_ref = queue.get("ref")
    match = (
        MERGE_GROUP_HEAD_REF_RE.fullmatch(queue_ref)
        if isinstance(queue_ref, str)
        else None
    )
    number = canonical_positive_integer(
        pull.get("number"),
        "merge-group snapshot pull request number",
    )
    node_id = pull.get("node_id")
    title = pull.get("title")
    candidate_ref = pull.get("head_ref")
    candidate_sha = canonical_oid(
        pull.get("head_sha"),
        "merge-group snapshot candidate",
    )
    tcb_sha256 = tcb.get("sha256")
    if (
        base.get("ref") != DEFAULT_BRANCH_REF
        or match is None
        or int(match.group("number")) != number
        or workflow_sha != queue_sha
        or not isinstance(node_id, str)
        or not node_id
        or len(node_id) > 256
        or not isinstance(candidate_ref, str)
        or not candidate_ref
        or not isinstance(title, str)
        or not title
        or len(title.encode("utf-8")) > 256
        or any(character in title for character in "\r\n\0")
        or tcb.get("required_check") != REQUIRED_CHECK_CONTEXT
        or not isinstance(tcb_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", tcb_sha256) is None
        or len({base_sha, queue_sha, candidate_sha}) != 3
    ):
        raise GateError("merge-group snapshot coordinates are invalid")
    return MergeGroupSnapshot(
        repository=repository,
        repository_id=repository_id,
        base_ref=DEFAULT_BRANCH_REF,
        base_sha=base_sha,
        queue_ref=queue_ref,
        queue_sha=queue_sha,
        workflow_sha=workflow_sha,
        pull_request_number=number,
        pull_request_node_id=node_id,
        pull_request_title=title,
        candidate_ref=candidate_ref,
        candidate_sha=candidate_sha,
        required_check=REQUIRED_CHECK_CONTEXT,
        tcb_sha256=tcb_sha256,
    )


def load_merge_group_snapshot(path: Path) -> MergeGroupSnapshot:
    payload, _raw = read_bounded_json_file(
        path,
        "merge-group snapshot",
    )
    return parse_merge_group_snapshot(payload)


def parse_merge_group_projection(payload: Any) -> MergeGroupProjection:
    payload = object_value(payload, "merge-group projection")
    exact_keys(
        payload,
        {
            "schema_version",
            "kind",
            "validation_mode",
            "policy",
            "role",
            "candidate_base_sha",
            "queue_base_sha",
            "candidate_sha",
            "queue_sha",
            "candidate_tree_sha",
            "queue_tree_sha",
            "prospective_sha",
            "prospective_tree_sha",
            "squash_subject",
            "trust_generation",
            "changed_path_count",
            "delta_sha256",
        },
        "merge-group projection",
    )
    policy = payload.get("policy")
    role = payload.get("role")
    subject = payload.get("squash_subject")
    changed_path_count = payload.get("changed_path_count")
    if (
        type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 1
        or payload.get("kind") != "retrospective-history-v2-merge-group-projection"
        or policy not in {"bootstrap-v2", "history-v2"}
        or payload.get("validation_mode") != f"{policy}-prospective-squash"
        or role not in {"admin", "publication"}
        or not isinstance(subject, str)
        or not subject
        or len(subject.encode("utf-8")) > 256
        or any(character in subject for character in "\r\n\0")
        or type(changed_path_count) is not int
        or changed_path_count < 0
    ):
        raise GateError("merge-group projection schema is invalid")
    oid_fields = (
        "candidate_base_sha",
        "queue_base_sha",
        "candidate_sha",
        "queue_sha",
        "candidate_tree_sha",
        "queue_tree_sha",
        "prospective_sha",
        "prospective_tree_sha",
    )
    oids = {
        field: canonical_oid(payload.get(field), f"merge-group projection {field}")
        for field in oid_fields
    }
    if len({len(value) for value in oids.values()}) != 1:
        raise GateError("merge-group projection hash formats differ")
    return MergeGroupProjection(
        policy=policy,
        role=role,
        candidate_base_sha=oids["candidate_base_sha"],
        queue_base_sha=oids["queue_base_sha"],
        candidate_sha=oids["candidate_sha"],
        queue_sha=oids["queue_sha"],
        candidate_tree_sha=oids["candidate_tree_sha"],
        queue_tree_sha=oids["queue_tree_sha"],
        prospective_sha=oids["prospective_sha"],
        prospective_tree_sha=oids["prospective_tree_sha"],
        squash_subject=subject,
        trust_generation=canonical_sha256(
            payload.get("trust_generation"),
            "merge-group projection trust generation",
        ),
        changed_path_count=changed_path_count,
        delta_sha256=canonical_sha256(
            payload.get("delta_sha256"),
            "merge-group projection delta",
        ),
    )


def load_merge_group_projection(path: Path) -> MergeGroupProjection:
    payload, _raw = read_bounded_json_file(path, "merge-group projection")
    return parse_merge_group_projection(payload)


def parse_merge_group_runtime_evidence(
    payload: Any,
    *,
    expected_authority_uid: int | None,
) -> MergeGroupRuntimeEvidence:
    payload = object_value(payload, "merge-group runtime evidence")
    field_names = {field.name for field in fields(MergeGroupRuntimeEvidence)}
    exact_keys(
        payload,
        {"schema_version", "kind", *field_names},
        "merge-group runtime evidence",
    )
    if (
        type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 1
        or payload.get("kind") != MERGE_GROUP_RUNTIME_EVIDENCE_KIND
    ):
        raise GateError("merge-group runtime evidence identity is invalid")
    policy = payload.get("policy")
    if policy not in {"bootstrap-v2", "history-v2"}:
        raise GateError("merge-group runtime evidence policy is invalid")
    oid_names = (
        "queue_base_sha",
        "candidate_sha",
        "queue_sha",
        "queue_tree_sha",
        "prospective_sha",
        "prospective_tree_sha",
    )
    oids = {
        name: canonical_oid(payload.get(name), f"runtime evidence {name}")
        for name in oid_names
    }
    if len({len(value) for value in oids.values()}) != 1:
        raise GateError("merge-group runtime evidence hash formats differ")
    integer_names = (
        "compile_exit_code",
        "test_exit_code",
        "authority_uid",
        "execution_uid",
    )
    integers = {name: payload.get(name) for name in integer_names}
    if any(type(value) is not int or value < 0 for value in integers.values()):
        raise GateError("merge-group runtime evidence integers are invalid")
    if (
        expected_authority_uid is not None
        and integers["authority_uid"] != expected_authority_uid
    ):
        raise GateError(
            "merge-group runtime evidence authority differs from the receipt owner"
        )
    boolean_names = ("authority_write_access", "source_authority_pristine")
    if any(type(payload.get(name)) is not bool for name in boolean_names):
        raise GateError("merge-group runtime evidence booleans are invalid")
    return MergeGroupRuntimeEvidence(
        policy=policy,
        **oids,
        projection_sha256=canonical_sha256(
            payload.get("projection_sha256"),
            "runtime evidence projection",
        ),
        python_version=payload.get("python_version"),
        python_executable_sha256=canonical_sha256(
            payload.get("python_executable_sha256"),
            "runtime evidence Python executable",
        ),
        requirements_sha256=canonical_sha256(
            payload.get("requirements_sha256"),
            "runtime evidence requirements",
        ),
        runtime_profile=payload.get("runtime_profile"),
        compile_command_sha256=canonical_sha256(
            payload.get("compile_command_sha256"),
            "runtime evidence compile command",
        ),
        test_command_sha256=canonical_sha256(
            payload.get("test_command_sha256"),
            "runtime evidence test command",
        ),
        compile_exit_code=integers["compile_exit_code"],
        test_exit_code=integers["test_exit_code"],
        authority_uid=integers["authority_uid"],
        execution_uid=integers["execution_uid"],
        credential_environment=payload.get("credential_environment"),
        authority_write_access=payload.get("authority_write_access"),
        source_authority_pristine=payload.get("source_authority_pristine"),
    )


def load_merge_group_runtime_evidence(path: Path) -> MergeGroupRuntimeEvidence:
    authority_uid = os.geteuid()
    payload, _raw = read_bounded_json_file(
        path,
        "merge-group runtime evidence",
        expected_owner_uid=authority_uid,
    )
    return parse_merge_group_runtime_evidence(
        payload,
        expected_authority_uid=authority_uid,
    )


def _parse_raw_diff(
    raw: bytes,
    *,
    expected_oid_length: int,
) -> tuple[tuple[str, str, str, str, str, str], ...]:
    fields = raw.split(b"\0")
    if fields[-1:] != [b""]:
        raise GateError("merge-group tree delta is not NUL terminated")
    records: list[tuple[str, str, str, str, str, str]] = []
    index = 0
    while index < len(fields) - 1:
        metadata = fields[index]
        if index + 1 >= len(fields) - 1:
            raise GateError("merge-group tree delta is incomplete")
        raw_path = fields[index + 1]
        values = metadata.split(b" ")
        if len(values) != 5 or not values[0].startswith(b":"):
            raise GateError("merge-group tree delta metadata is malformed")
        raw_old_mode = values[0][1:]
        raw_new_mode, raw_old_oid, raw_new_oid, raw_status = values[1:]
        try:
            old_mode = raw_old_mode.decode("ascii")
            new_mode = raw_new_mode.decode("ascii")
            old_oid = raw_old_oid.decode("ascii")
            new_oid = raw_new_oid.decode("ascii")
            status = raw_status.decode("ascii")
        except UnicodeDecodeError as exc:
            raise GateError("merge-group tree delta metadata is not ASCII") from exc
        path = _safe_git_path(raw_path)
        reject_sensitive_candidate_path(path)
        if (
            status not in {"A", "D", "M"}
            or re.fullmatch(r"[0-7]{6}", old_mode) is None
            or re.fullmatch(r"[0-7]{6}", new_mode) is None
            or len(old_oid) != expected_oid_length
            or len(new_oid) != expected_oid_length
            or any(
                re.fullmatch(r"[0-9a-f]+", oid) is None for oid in (old_oid, new_oid)
            )
        ):
            raise GateError("merge-group tree delta is outside policy")
        records.append((status, path, old_mode, new_mode, old_oid, new_oid))
        if len(records) > MAX_RANGE_TREE_ENTRIES:
            raise GateError("merge-group tree delta exceeds the trusted limit")
        index += 2
    if not records or len({record[1] for record in records}) != len(records):
        raise GateError("merge-group tree delta is empty or duplicated")
    return tuple(records)


def _exact_tree_delta(
    git_dir: Path,
    base_sha: str,
    head_sha: str,
) -> tuple[tuple[str, str, str, str, str, str], ...]:
    base_sha = canonical_oid(base_sha, "tree-delta base")
    head_sha = canonical_oid(head_sha, "tree-delta head")
    raw = git_output(
        git_dir,
        "diff-tree",
        "--no-commit-id",
        "--raw",
        "-r",
        "-z",
        "--no-renames",
        "--no-abbrev",
        base_sha,
        head_sha,
        "--",
        max_bytes=MAX_GIT_OUTPUT_BYTES,
    )
    return _parse_raw_diff(raw, expected_oid_length=len(head_sha))


def _single_merge_base(git_dir: Path, left: str, right: str) -> str:
    left = canonical_oid(left, "merge-base left")
    right = canonical_oid(right, "merge-base right")
    values = tuple(
        line
        for line in git_text(
            git_dir,
            "merge-base",
            "--all",
            left,
            right,
            max_bytes=1024,
        ).splitlines()
        if line
    )
    if len(values) != 1:
        raise GateError("candidate and queue base do not have one merge base")
    return canonical_oid(values[0], "candidate merge base")


def _trust_generation_entries(
    git_dir: Path,
    revision: str,
) -> tuple[tuple[str, str, str, str], ...]:
    revision = canonical_oid(revision, "trust-generation revision")
    raw = git_output(
        git_dir,
        "ls-tree",
        "-z",
        revision,
        "--",
        *PERMANENT_TRUST_GENERATION_PATHS,
        max_bytes=256 * 1024,
    )
    fields = raw.split(b"\0")
    if fields[-1:] != [b""]:
        raise GateError("trust-generation inventory is malformed")
    entries: list[tuple[str, str, str, str]] = []
    for field in fields[:-1]:
        metadata, separator, raw_path = field.partition(b"\t")
        values = metadata.split(b" ")
        if not separator or len(values) != 3:
            raise GateError("trust-generation inventory is malformed")
        try:
            mode, object_type, object_id = (value.decode("ascii") for value in values)
        except UnicodeDecodeError as exc:
            raise GateError("trust-generation inventory is not ASCII") from exc
        path = _safe_git_path(raw_path)
        entries.append((path, mode, object_type, object_id))
    if tuple(entry[0] for entry in entries) != tuple(
        sorted(PERMANENT_TRUST_GENERATION_PATHS)
    ) or any(
        mode != "100644" or object_type != "blob" or len(object_id) != len(revision)
        for _path, mode, object_type, object_id in entries
    ):
        raise GateError("trust-generation inventory is incomplete")
    return tuple(entries)


def _worktree_head(root: Path, expected: str, label: str) -> None:
    expected = canonical_oid(expected, f"{label} expected head")
    root = root.resolve()
    if not root.is_dir():
        raise GateError(f"{label} worktree is unavailable")
    observed = run_bounded(
        closed_git_command("-C", str(root), "rev-parse", "--verify", "HEAD"),
        max_output_bytes=128,
        environment=closed_git_environment(),
    )
    status = run_bounded(
        closed_git_command(
            "-C",
            str(root),
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ),
        max_output_bytes=MAX_GIT_OUTPUT_BYTES,
        environment=closed_git_environment(),
    )
    try:
        observed_head = observed.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise GateError(f"{label} worktree head is invalid") from exc
    if observed_head != expected or status:
        raise GateError(f"{label} worktree is not the exact pristine head")


def _single_worktree_parent(root: Path, head_sha: str) -> str:
    head_sha = canonical_oid(head_sha, "predecessor audited base")
    raw = run_bounded(
        closed_git_command(
            "-C",
            str(root.resolve()),
            "rev-list",
            "--parents",
            "--max-count=1",
            head_sha,
        ),
        max_output_bytes=512,
        environment=closed_git_environment(),
    )
    try:
        fields = raw.decode("ascii").strip().split()
    except UnicodeDecodeError as exc:
        raise GateError("predecessor audited base metadata is invalid") from exc
    if len(fields) != 2 or fields[0] != head_sha:
        raise GateError(
            "predecessor audited base is not one linear single-parent squash"
        )
    return canonical_oid(fields[1], "predecessor audited parent")


def verify_live_merge_group_authority(
    *,
    expected: MergeGroupSnapshot,
    event_path: Path,
    event_ref: str,
    event_sha: str,
    workflow_sha: str,
    policy: str,
    trusted_base_root: Path,
    token: str,
) -> dict[str, Any]:
    del (
        expected,
        event_path,
        event_ref,
        event_sha,
        workflow_sha,
        policy,
        trusted_base_root,
        token,
    )
    raise GateError("in-repository merge-group authority is prohibited")


def _normalized_merge_plan(plan: Any) -> dict[str, Any]:
    try:
        payload = plan.as_dict()
    except (AttributeError, TypeError) as exc:
        raise GateError("B1 validator did not return an immutable plan") from exc
    value = object_value(payload, "B1 immutable merge plan")
    exact_keys(
        value,
        {
            "schema_version",
            "base_oid",
            "head_oid",
            "head_tree_oid",
            "squash_subject",
            "trust_generation",
            "role",
            "changed_path_count",
            "delta_sha256",
        },
        "B1 immutable merge plan",
    )
    subject = value.get("squash_subject")
    trust_generation = value.get("trust_generation")
    role = value.get("role")
    changed_path_count = value.get("changed_path_count")
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or not isinstance(subject, str)
        or not subject
        or len(subject.encode("ascii", errors="ignore")) != len(subject)
        or len(subject.encode("ascii")) > 256
        or any(character in subject for character in "\r\n\0")
        or not isinstance(trust_generation, str)
        or re.fullmatch(r"[0-9a-f]{64}", trust_generation) is None
        or role not in {"publication", "admin"}
        or type(changed_path_count) is not int
        or changed_path_count < 0
    ):
        raise GateError("B1 immutable merge plan is malformed")
    canonical_sha256(
        value.get("delta_sha256"),
        "B1 immutable merge plan delta",
    )
    return value


def _write_publication_projection(
    git_dir: Path,
    *,
    tree_sha: str,
    parent_sha: str,
    squash_subject: str,
) -> str:
    tree_sha = canonical_oid(tree_sha, "projection tree")
    parent_sha = canonical_oid(parent_sha, "projection parent")
    if (
        len(tree_sha) != len(parent_sha)
        or not squash_subject
        or any(character in squash_subject for character in "\r\n\0")
    ):
        raise GateError("publication projection coordinates are invalid")
    identity = "Trusted Queue Projection <queue-projection@users.noreply.github.com>"
    raw = (
        f"tree {tree_sha}\n"
        f"parent {parent_sha}\n"
        f"author {identity} 1 +0000\n"
        f"committer {identity} 1 +0000\n"
        f"\n{squash_subject}\n"
    ).encode("ascii")
    if len(raw) > MAX_COMMIT_BYTES:
        raise GateError("publication projection commit is too large")
    validate_closed_candidate_repository(git_dir)
    try:
        prospective_sha = (
            git_output(
                git_dir,
                "hash-object",
                "-t",
                "commit",
                "-w",
                "--stdin",
                input_data=raw,
                max_bytes=128,
            )
            .decode("ascii")
            .strip()
        )
    except UnicodeDecodeError as exc:
        raise GateError("publication projection object ID is invalid") from exc
    prospective_sha = canonical_oid(
        prospective_sha,
        "publication projection commit",
    )
    observed = validate_candidate_commit_object(
        git_dir,
        prospective_sha,
        strict_bootstrap_metadata=False,
    )
    if observed.tree_oid != tree_sha or observed.parents != (parent_sha,):
        raise GateError("publication projection object changed")
    validate_closed_candidate_repository(git_dir)
    return prospective_sha


def _candidate_squash_subject(git_dir: Path, commit_sha: str) -> str:
    commit_sha = canonical_oid(commit_sha, "candidate subject commit")
    raw = git_output(
        git_dir,
        "cat-file",
        "commit",
        commit_sha,
        max_bytes=MAX_COMMIT_BYTES,
    )
    _headers, separator, message = raw.partition(b"\n\n")
    subject, line_separator, _remainder = message.partition(b"\n")
    if (
        not separator
        or not line_separator
        or not subject
        or len(subject) > 256
        or any(byte < 0x20 or byte > 0x7E for byte in subject)
    ):
        raise GateError("candidate squash subject is not canonical ASCII")
    return subject.decode("ascii")


def _validate_merge_group_graph(
    git_dir: Path,
    snapshot: MergeGroupSnapshot,
    *,
    policy: str,
    plan: dict[str, Any] | None,
) -> MergeGroupProjection:
    if policy not in {"bootstrap-v2", "history-v2"}:
        raise GateError("merge-group policy is invalid")
    git_dir = git_dir.resolve()
    validate_closed_candidate_repository(git_dir)
    for label, revision in (
        ("queue base", snapshot.base_sha),
        ("candidate", snapshot.candidate_sha),
        ("queue", snapshot.queue_sha),
    ):
        if (
            git_text(git_dir, "cat-file", "-t", revision, max_bytes=64).strip()
            != "commit"
        ):
            raise GateError(f"merge-group {label} object is not a commit")

    queue_commit = validate_candidate_commit_object(
        git_dir,
        snapshot.queue_sha,
        strict_bootstrap_metadata=False,
    )
    if queue_commit.parents != (snapshot.base_sha, snapshot.candidate_sha):
        raise GateError("merge-group Q does not have the exact B1/H parent-edge shape")
    candidate_commit = validate_candidate_commit_object(
        git_dir,
        snapshot.candidate_sha,
        strict_bootstrap_metadata=False,
    )
    candidate_base = _single_merge_base(
        git_dir,
        snapshot.base_sha,
        snapshot.candidate_sha,
    )
    candidate_delta = _exact_tree_delta(
        git_dir,
        candidate_base,
        snapshot.candidate_sha,
    )
    queue_delta = _exact_tree_delta(
        git_dir,
        snapshot.base_sha,
        snapshot.queue_sha,
    )
    if candidate_delta != queue_delta:
        raise GateError(
            "merge-group Q is not the exact candidate tree transaction on B1"
        )
    changed_paths = tuple(record[1] for record in candidate_delta)
    if policy == "bootstrap-v2":
        role = "admin"
        if role != "admin" or candidate_base != snapshot.base_sha:
            raise GateError("bootstrap merge group requires B1 == B0 and admin-only")
        subject = _candidate_squash_subject(git_dir, snapshot.candidate_sha)
        if subject != snapshot.pull_request_title:
            raise GateError("bootstrap pull request title differs from signed plan")
        trust_generation = "0" * 64
        prospective_sha = snapshot.candidate_sha
    else:
        if plan is None:
            raise GateError("permanent merge group requires a B1 validation plan")
        role = plan["role"]
        validator = trusted_validator_module(contract="permanent")
        publication_paths = tuple(
            validator.history_v2_mutable_artifact(Path(path)) for path in changed_paths
        )
        if (role == "publication" and not all(publication_paths)) or (
            role == "admin" and any(publication_paths)
        ):
            raise GateError(
                "B1 immutable plan role differs from the exact candidate paths"
            )
        if (
            plan.get("base_oid") != candidate_base
            or plan.get("head_oid") != snapshot.candidate_sha
            or plan.get("head_tree_oid") != candidate_commit.tree_oid
        ):
            raise GateError("B1 immutable plan does not bind B0/H/tree")
        observed_delta_sha256 = hashlib.sha256(
            compact_json_bytes(candidate_delta)
        ).hexdigest()
        if (
            plan.get("changed_path_count") != len(candidate_delta)
            or plan.get("delta_sha256") != observed_delta_sha256
        ):
            raise GateError("B1 immutable plan does not bind the exact delta")
        trust_at_candidate_base = _trust_generation_entries(
            git_dir,
            candidate_base,
        )
        trust_at_queue_base = _trust_generation_entries(
            git_dir,
            snapshot.base_sha,
        )
        if trust_at_candidate_base != trust_at_queue_base:
            raise GateError("trust generation changed between B0 and B1")
        observed_trust_generation = hashlib.sha256(
            compact_json_bytes(trust_at_candidate_base)
        ).hexdigest()
        if plan["trust_generation"] != observed_trust_generation:
            raise GateError("B1 immutable plan does not bind the trust generation")
        subject = plan["squash_subject"]
        trust_generation = plan["trust_generation"]
        if subject != snapshot.pull_request_title:
            raise GateError("pull request title differs from the B1 immutable plan")
        if role == "admin":
            if candidate_base != snapshot.base_sha:
                raise GateError(
                    "admin merge group requires B1 == B0 and a rebuilt signature"
                )
            prospective_sha = snapshot.candidate_sha
        else:
            prospective_sha = _write_publication_projection(
                git_dir,
                tree_sha=queue_commit.tree_oid,
                parent_sha=snapshot.base_sha,
                squash_subject=subject,
            )

    prospective_commit = validate_candidate_commit_object(
        git_dir,
        prospective_sha,
        strict_bootstrap_metadata=False,
    )
    if prospective_commit.tree_oid != queue_commit.tree_oid:
        raise GateError("prospective commit does not preserve the exact Q tree")

    delta_sha256 = hashlib.sha256(compact_json_bytes(candidate_delta)).hexdigest()
    return MergeGroupProjection(
        policy=policy,
        role=role,
        candidate_base_sha=candidate_base,
        queue_base_sha=snapshot.base_sha,
        candidate_sha=snapshot.candidate_sha,
        queue_sha=snapshot.queue_sha,
        candidate_tree_sha=candidate_commit.tree_oid,
        queue_tree_sha=queue_commit.tree_oid,
        prospective_sha=prospective_sha,
        prospective_tree_sha=prospective_commit.tree_oid,
        squash_subject=subject,
        trust_generation=trust_generation,
        changed_path_count=len(candidate_delta),
        delta_sha256=delta_sha256,
    )


def validate_merge_group_transaction(
    *,
    git_dir: Path,
    snapshot: MergeGroupSnapshot,
    candidate_root: Path,
    queue_root: Path,
    policy: str,
    trusted_base_root: Path | None = None,
) -> MergeGroupProjection:
    _worktree_head(candidate_root, snapshot.candidate_sha, "candidate")
    _worktree_head(queue_root, snapshot.queue_sha, "queue")
    if policy == "bootstrap-v2":
        if trusted_base_root is None:
            raise GateError("bootstrap trusted base root is unavailable")
        validator = trusted_validator_module(contract="bootstrap")
        candidate_issues = validator.validate_bootstrap_v2_candidate(
            trusted_base_root,
            candidate_root,
        )
        queue_issues = validator.validate_bootstrap_v2_candidate(
            trusted_base_root,
            queue_root,
        )
        if candidate_issues or queue_issues:
            raise GateError("B1 bootstrap validator rejected H or Q")
        return _validate_merge_group_graph(
            git_dir,
            snapshot,
            policy=policy,
            plan=None,
        )

    if policy != "history-v2":
        raise GateError("merge-group transaction policy is invalid")
    validator = trusted_validator_module(contract="permanent")
    candidate_base = _single_merge_base(
        git_dir,
        snapshot.base_sha,
        snapshot.candidate_sha,
    )
    try:
        plan, candidate_issues = validator.build_pull_request_candidate_plan(
            candidate_root,
            candidate_base,
            snapshot.candidate_sha,
        )
    except Exception as exc:
        raise GateError("B1 candidate validator failed closed") from exc
    if candidate_issues or plan is None:
        raise GateError("B1 candidate validator rejected B0/H")
    normalized_plan = _normalized_merge_plan(plan)
    projection = _validate_merge_group_graph(
        git_dir,
        snapshot,
        policy=policy,
        plan=normalized_plan,
    )
    try:
        queue_issues = validator.validate_fixed_head_snapshot(
            queue_root,
            snapshot.queue_sha,
        )
    except Exception as exc:
        raise GateError("B1 fixed-Q validator failed closed") from exc
    if queue_issues:
        raise GateError("B1 fixed-Q validator rejected the global tree")
    if projection.role == "publication":
        try:
            prospective_issues = validator.validate_append_only_event_range(
                queue_root,
                snapshot.base_sha,
                projection.prospective_sha,
                forced=False,
            )
        except Exception as exc:
            raise GateError("B1 prospective-squash validator failed closed") from exc
        if prospective_issues:
            raise GateError(
                "B1 validator rejected Q as an append-only publication transaction"
            )
    return projection


def merge_group_projection_sha256(projection: MergeGroupProjection) -> str:
    return hashlib.sha256(compact_json_bytes(projection.as_dict())).hexdigest()


def validate_merge_group_runtime_evidence(
    *,
    git_dir: Path,
    snapshot: MergeGroupSnapshot,
    projection: MergeGroupProjection,
    evidence: MergeGroupRuntimeEvidence,
    expected_python_executable_sha256: str,
) -> None:
    expected_python_executable_sha256 = canonical_sha256(
        expected_python_executable_sha256,
        "trusted runtime Python executable",
    )
    if (
        evidence.policy != projection.policy
        or evidence.queue_base_sha != snapshot.base_sha
        or evidence.candidate_sha != snapshot.candidate_sha
        or evidence.queue_sha != snapshot.queue_sha
        or evidence.queue_tree_sha != projection.queue_tree_sha
        or evidence.prospective_sha != projection.prospective_sha
        or evidence.prospective_tree_sha != projection.prospective_tree_sha
        or projection.queue_base_sha != snapshot.base_sha
        or projection.candidate_sha != snapshot.candidate_sha
        or projection.queue_sha != snapshot.queue_sha
        or projection.queue_tree_sha != projection.prospective_tree_sha
    ):
        raise GateError("merge-group runtime evidence is stale or cross-transaction")
    if evidence.projection_sha256 != merge_group_projection_sha256(projection):
        raise GateError("merge-group runtime evidence projection digest differs")
    if (
        evidence.python_version != QUEUE_RUNTIME_PYTHON_VERSION
        or evidence.python_executable_sha256 != expected_python_executable_sha256
        or evidence.runtime_profile != QUEUE_RUNTIME_PROFILE
        or evidence.compile_command_sha256 != QUEUE_RUNTIME_COMPILE_COMMAND_SHA256
        or evidence.test_command_sha256 != QUEUE_RUNTIME_TEST_COMMAND_SHA256
        or evidence.compile_exit_code != 0
        or evidence.test_exit_code != 0
        or evidence.execution_uid == 0
        or evidence.execution_uid == evidence.authority_uid
        or evidence.credential_environment != "empty"
        or evidence.authority_write_access is not False
        or evidence.source_authority_pristine is not True
    ):
        raise GateError("merge-group runtime evidence did not prove the exact profile")
    requirements = git_output(
        git_dir.resolve(),
        "cat-file",
        "blob",
        f"{snapshot.queue_sha}:requirements-v2.txt",
        max_bytes=MAX_BLOB_BYTES,
    )
    if hashlib.sha256(requirements).hexdigest() != evidence.requirements_sha256:
        raise GateError("merge-group runtime evidence requirements digest differs")


def _validate_predecessor_authority_evidence(
    *,
    snapshot: MergeGroupSnapshot,
    projection: MergeGroupProjection,
    evidence: MergeGroupPredecessorAuthorityEvidence,
) -> dict[str, Any]:
    expected_projection_sha256 = merge_group_projection_sha256(projection)
    if (
        evidence.base_sha != snapshot.base_sha
        or evidence.queue_sha != snapshot.queue_sha
        or evidence.pull_request_number != snapshot.pull_request_number
        or evidence.projection_sha256 != expected_projection_sha256
    ):
        raise GateError("predecessor authority evidence is stale or cross-transaction")
    if projection.policy == "history-v2":
        audit = evidence.audit
        if (
            evidence.mode != "history-v2-required"
            or evidence.parent_sha is None
            or audit is None
            or evidence.candidate_ref is not None
            or evidence.bootstrap_markers
            or evidence.bootstrap_marker_sha256 is not None
            or audit.base_sha != snapshot.base_sha
            or audit.parent_sha != evidence.parent_sha
            or audit.pull_request_number == snapshot.pull_request_number
        ):
            raise GateError("predecessor authority evidence is invalid")
        _validate_predecessor_audit_digest(audit)
    elif projection.policy == "bootstrap-v2":
        expected_markers = tuple(sorted(BOOTSTRAP_TEMPORARY_PATHS))
        if (
            evidence.mode != "bootstrap-v2-migration-exception"
            or evidence.parent_sha is not None
            or evidence.audit is not None
            or evidence.candidate_ref != BOOTSTRAP_CANDIDATE_REF
            or evidence.bootstrap_markers != expected_markers
        ):
            raise GateError("bootstrap predecessor migration exception is invalid")
        expected_marker_sha256 = hashlib.sha256(
            compact_json_bytes(
                _bootstrap_marker_payload(
                    snapshot=snapshot,
                    projection=projection,
                    markers=expected_markers,
                )
            )
        ).hexdigest()
        if evidence.bootstrap_marker_sha256 != expected_marker_sha256:
            raise GateError("bootstrap predecessor marker digest differs")
    else:
        raise GateError("predecessor authority evidence policy is invalid")
    return evidence.as_dict()


def merge_group_admission_payload(
    *,
    snapshot: MergeGroupSnapshot,
    projection: MergeGroupProjection,
    evidence: MergeGroupRuntimeEvidence,
    live_authority: MergeGroupLiveAuthorityEvidence,
) -> dict[str, Any]:
    snapshot_sha256 = hashlib.sha256(compact_json_bytes(snapshot.as_dict())).hexdigest()
    predecessor_authority = _validate_predecessor_authority_evidence(
        snapshot=snapshot,
        projection=projection,
        evidence=live_authority.predecessor_authority,
    )
    predecessor_authority_sha256 = hashlib.sha256(
        compact_json_bytes(predecessor_authority)
    ).hexdigest()
    observed_at_text, observed_at = canonical_github_timestamp(
        live_authority.observed_at,
        "live merge-group authority observation",
    )
    valid_until_text, valid_until = canonical_github_timestamp(
        live_authority.valid_until,
        "live merge-group authority expiration",
    )
    if (
        live_authority.snapshot_sha256 != snapshot_sha256
        or live_authority.tcb_sha256 != snapshot.tcb_sha256
        or live_authority.predecessor_authority_sha256 != predecessor_authority_sha256
        or valid_until - observed_at
        != dt.timedelta(seconds=MERGE_GROUP_LIVE_AUTHORITY_TTL_SECONDS)
    ):
        raise GateError("live merge-group authority evidence is invalid")
    live_authority_payload = {
        **live_authority.as_dict(),
        "observed_at": observed_at_text,
        "valid_until": valid_until_text,
    }
    return {
        "schema_version": 2,
        "kind": MERGE_GROUP_ADMISSION_KIND,
        "decision": "accepted",
        "policy": projection.policy,
        "queue_base_sha": snapshot.base_sha,
        "candidate_sha": snapshot.candidate_sha,
        "queue_sha": snapshot.queue_sha,
        "queue_tree_sha": projection.queue_tree_sha,
        "prospective_sha": projection.prospective_sha,
        "prospective_tree_sha": projection.prospective_tree_sha,
        "snapshot_sha256": snapshot_sha256,
        "projection_sha256": merge_group_projection_sha256(projection),
        "runtime_evidence_sha256": hashlib.sha256(
            compact_json_bytes(evidence.as_dict())
        ).hexdigest(),
        "predecessor_authority_sha256": predecessor_authority_sha256,
        "live_authority_sha256": hashlib.sha256(
            compact_json_bytes(live_authority_payload)
        ).hexdigest(),
        "snapshot": snapshot.as_dict(),
        "projection": projection.as_dict(),
        "runtime_evidence": evidence.as_dict(),
        "live_authority": live_authority_payload,
    }


def parse_predecessor_audit_evidence(payload: Any) -> PredecessorAuditEvidence:
    value = object_value(payload, "predecessor audit evidence")
    field_names = {field.name for field in fields(PredecessorAuditEvidence)}
    exact_keys(value, field_names, "predecessor audit evidence")
    oid_names = ("base_sha", "parent_sha", "candidate_sha")
    oids = {
        name: canonical_oid(value.get(name), f"predecessor audit {name}")
        for name in oid_names
    }
    integer_names = (
        "pull_request_number",
        "check_run_id",
        "check_suite_id",
        "workflow_run_id",
        "workflow_id",
        "workflow_run_attempt",
        "job_id",
    )
    integers = {
        name: canonical_positive_integer(
            value.get(name),
            f"predecessor audit {name}",
        )
        for name in integer_names
    }
    text_names = (
        "pull_request_node_id",
        "check_run_node_id",
    )
    texts = {name: value.get(name) for name in text_names}
    if any(
        not isinstance(item, str)
        or not item
        or len(item.encode("utf-8")) > 256
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in item)
        for item in texts.values()
    ):
        raise GateError("predecessor audit identity is invalid")
    timestamp_names = (
        "merged_at",
        "workflow_created_at",
        "workflow_started_at",
        "workflow_updated_at",
        "started_at",
        "completed_at",
        "job_started_at",
        "job_completed_at",
    )
    timestamps = {
        name: canonical_github_timestamp(
            value.get(name),
            f"predecessor audit {name}",
        )[0]
        for name in timestamp_names
    }
    evidence = PredecessorAuditEvidence(
        **oids,
        **integers,
        **texts,
        **timestamps,
        sha256=canonical_sha256(
            value.get("sha256"),
            "predecessor audit evidence",
        ),
    )
    _validate_predecessor_audit_digest(evidence)
    return evidence


def parse_merge_group_predecessor_authority(
    payload: Any,
) -> MergeGroupPredecessorAuthorityEvidence:
    value = object_value(payload, "predecessor authority evidence")
    exact_keys(
        value,
        {
            "schema_version",
            "kind",
            "mode",
            "base_sha",
            "queue_sha",
            "pull_request_number",
            "projection_sha256",
            "parent_sha",
            "audit",
            "candidate_ref",
            "bootstrap_markers",
            "bootstrap_marker_sha256",
        },
        "predecessor authority evidence",
    )
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("kind") != MERGE_GROUP_PREDECESSOR_AUTHORITY_KIND
    ):
        raise GateError("predecessor authority evidence identity is invalid")
    raw_markers = value.get("bootstrap_markers")
    if (
        not isinstance(raw_markers, list)
        or any(not isinstance(item, str) for item in raw_markers)
        or raw_markers != sorted(set(raw_markers))
    ):
        raise GateError("predecessor authority marker inventory is invalid")
    parent_sha = value.get("parent_sha")
    audit = value.get("audit")
    candidate_ref = value.get("candidate_ref")
    marker_sha256 = value.get("bootstrap_marker_sha256")
    return MergeGroupPredecessorAuthorityEvidence(
        mode=value.get("mode"),
        base_sha=canonical_oid(
            value.get("base_sha"),
            "predecessor authority base",
        ),
        queue_sha=canonical_oid(
            value.get("queue_sha"),
            "predecessor authority queue",
        ),
        pull_request_number=canonical_positive_integer(
            value.get("pull_request_number"),
            "predecessor authority pull request",
        ),
        projection_sha256=canonical_sha256(
            value.get("projection_sha256"),
            "predecessor authority projection",
        ),
        parent_sha=(
            canonical_oid(parent_sha, "predecessor authority parent")
            if parent_sha is not None
            else None
        ),
        audit=(parse_predecessor_audit_evidence(audit) if audit is not None else None),
        candidate_ref=(candidate_ref if isinstance(candidate_ref, str) else None),
        bootstrap_markers=tuple(raw_markers),
        bootstrap_marker_sha256=(
            canonical_sha256(
                marker_sha256,
                "predecessor authority marker",
            )
            if marker_sha256 is not None
            else None
        ),
    )


def parse_merge_group_live_authority(
    payload: Any,
) -> MergeGroupLiveAuthorityEvidence:
    value = object_value(payload, "live merge-group authority evidence")
    exact_keys(
        value,
        {
            "schema_version",
            "kind",
            "snapshot_sha256",
            "tcb_sha256",
            "predecessor_authority",
            "predecessor_authority_sha256",
            "observed_at",
            "valid_until",
        },
        "live merge-group authority evidence",
    )
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("kind") != MERGE_GROUP_LIVE_AUTHORITY_KIND
    ):
        raise GateError("live merge-group authority identity is invalid")
    predecessor = parse_merge_group_predecessor_authority(
        value.get("predecessor_authority")
    )
    observed_at = canonical_github_second_timestamp(
        value.get("observed_at"),
        "live merge-group authority observation",
    )[0]
    valid_until = canonical_github_second_timestamp(
        value.get("valid_until"),
        "live merge-group authority expiration",
    )[0]
    return MergeGroupLiveAuthorityEvidence(
        snapshot_sha256=canonical_sha256(
            value.get("snapshot_sha256"),
            "live merge-group authority snapshot",
        ),
        tcb_sha256=canonical_sha256(
            value.get("tcb_sha256"),
            "live merge-group authority TCB",
        ),
        predecessor_authority=predecessor,
        predecessor_authority_sha256=canonical_sha256(
            value.get("predecessor_authority_sha256"),
            "live merge-group predecessor authority",
        ),
        observed_at=observed_at,
        valid_until=valid_until,
    )


def parse_merge_group_admission_payload(
    payload: Any,
) -> tuple[
    MergeGroupSnapshot,
    MergeGroupProjection,
    MergeGroupRuntimeEvidence,
    MergeGroupLiveAuthorityEvidence,
]:
    value = object_value(payload, "merge-group admission record")
    exact_keys(
        value,
        {
            "schema_version",
            "kind",
            "decision",
            "policy",
            "queue_base_sha",
            "candidate_sha",
            "queue_sha",
            "queue_tree_sha",
            "prospective_sha",
            "prospective_tree_sha",
            "snapshot_sha256",
            "projection_sha256",
            "runtime_evidence_sha256",
            "predecessor_authority_sha256",
            "live_authority_sha256",
            "snapshot",
            "projection",
            "runtime_evidence",
            "live_authority",
        },
        "merge-group admission record",
    )
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != 2
        or value.get("kind") != MERGE_GROUP_ADMISSION_KIND
        or value.get("decision") != "accepted"
    ):
        raise GateError("merge-group admission record identity is invalid")
    snapshot = parse_merge_group_snapshot(value.get("snapshot"))
    projection = parse_merge_group_projection(value.get("projection"))
    evidence = parse_merge_group_runtime_evidence(
        value.get("runtime_evidence"),
        expected_authority_uid=None,
    )
    live_authority = parse_merge_group_live_authority(value.get("live_authority"))
    if (
        value.get("policy") != projection.policy
        or value.get("queue_base_sha") != snapshot.base_sha
        or value.get("candidate_sha") != snapshot.candidate_sha
        or value.get("queue_sha") != snapshot.queue_sha
        or value.get("queue_tree_sha") != projection.queue_tree_sha
        or value.get("prospective_sha") != projection.prospective_sha
        or value.get("prospective_tree_sha") != projection.prospective_tree_sha
        or value.get("snapshot_sha256")
        != hashlib.sha256(compact_json_bytes(snapshot.as_dict())).hexdigest()
        or value.get("projection_sha256") != merge_group_projection_sha256(projection)
        or value.get("runtime_evidence_sha256")
        != hashlib.sha256(compact_json_bytes(evidence.as_dict())).hexdigest()
        or value.get("predecessor_authority_sha256")
        != live_authority.predecessor_authority_sha256
        or value.get("live_authority_sha256")
        != hashlib.sha256(compact_json_bytes(live_authority.as_dict())).hexdigest()
        or evidence.policy != projection.policy
        or evidence.queue_base_sha != snapshot.base_sha
        or evidence.candidate_sha != snapshot.candidate_sha
        or evidence.queue_sha != snapshot.queue_sha
        or evidence.queue_tree_sha != projection.queue_tree_sha
        or evidence.prospective_sha != projection.prospective_sha
        or evidence.prospective_tree_sha != projection.prospective_tree_sha
        or evidence.projection_sha256 != merge_group_projection_sha256(projection)
        or evidence.python_version != QUEUE_RUNTIME_PYTHON_VERSION
        or evidence.runtime_profile != QUEUE_RUNTIME_PROFILE
        or evidence.compile_command_sha256 != QUEUE_RUNTIME_COMPILE_COMMAND_SHA256
        or evidence.test_command_sha256 != QUEUE_RUNTIME_TEST_COMMAND_SHA256
        or evidence.compile_exit_code != 0
        or evidence.test_exit_code != 0
        or evidence.execution_uid == 0
        or evidence.execution_uid == evidence.authority_uid
        or evidence.credential_environment != "empty"
        or evidence.authority_write_access is not False
        or evidence.source_authority_pristine is not True
    ):
        raise GateError("merge-group admission record is stale or inconsistent")
    canonical = merge_group_admission_payload(
        snapshot=snapshot,
        projection=projection,
        evidence=evidence,
        live_authority=live_authority,
    )
    if value != canonical:
        raise GateError("merge-group admission record is not canonical")
    return snapshot, projection, evidence, live_authority


def git_blob_object_id(value: bytes, *, expected_length: int) -> str:
    if expected_length == 40:
        digest = hashlib.sha1(usedforsecurity=False)
    elif expected_length == 64:
        digest = hashlib.sha256()
    else:
        raise GateError("candidate blob uses an unsupported hash format")
    digest.update(b"blob " + str(len(value)).encode("ascii") + b"\x00")
    digest.update(value)
    return digest.hexdigest()


def decode_github_blob_payload(
    payload: Any,
    *,
    expected_entry: TreeEntry,
) -> bytes:
    root = object_value(payload, "candidate blob response")
    content = root.get("content")
    if (
        root.get("sha") != expected_entry.object_id
        or root.get("size") != expected_entry.size
        or root.get("encoding") != "base64"
        or not isinstance(content, str)
        or any(
            character != "\n"
            and character
            not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
            for character in content
        )
    ):
        raise GateError("candidate blob API response differs from preflight")
    encoded = content.replace("\n", "")
    try:
        value = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise GateError("candidate blob API response is malformed") from exc
    if (
        len(value) != expected_entry.size
        or base64.b64encode(value).decode("ascii") != encoded
        or git_blob_object_id(
            value,
            expected_length=len(expected_entry.object_id),
        )
        != expected_entry.object_id
    ):
        raise GateError("candidate blob API content differs from its object ID")
    return value


def materialize_preflight_blobs(
    git_dir: Path,
    manifest: GitPreflight,
    *,
    repository: str,
    token: str,
    blob_loader: Callable[[str], Any] | None = None,
) -> None:
    git_dir = git_dir.resolve()
    if not git_dir.is_dir():
        raise GateError("candidate bare Git directory is unavailable")
    repository = canonical_repository(repository)
    validate_closed_candidate_repository(git_dir)
    candidate_only_oids = validate_oid_only_candidate_store(
        git_dir,
        base_sha=manifest.base_sha,
        candidate_trees=manifest.trees,
    )
    for entry in allowed_blob_entries(manifest):
        if entry.object_id not in candidate_only_oids:
            continue
        if blob_loader is None:
            encoded_oid = parse.quote(entry.object_id, safe="")
            payload = github_json(
                "GET",
                repository,
                f"/git/blobs/{encoded_oid}",
                token=token,
                max_bytes=min(
                    MAX_HTTP_RESPONSE_BYTES,
                    (entry.size or 0) * 2 + 64 * 1024,
                ),
            )
        else:
            payload = blob_loader(entry.object_id)
        value = decode_github_blob_payload(
            payload,
            expected_entry=entry,
        )
        observed = git_output(
            git_dir,
            "hash-object",
            "-w",
            "--stdin",
            input_data=value,
            max_bytes=128,
        )
        try:
            object_id = observed.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise GateError(
                "candidate blob materialization returned invalid metadata"
            ) from exc
        if object_id != entry.object_id:
            raise GateError("candidate blob materialization changed its object ID")


def _authority_git_output(
    root: Path,
    *arguments: str,
    max_bytes: int = 64 * 1024,
    input_data: bytes | None = None,
) -> bytes:
    root = root.resolve()
    validate_closed_git_object_store(root / ".git")
    return run_bounded(
        closed_git_command("-C", str(root), *arguments),
        input_data=input_data,
        max_output_bytes=max_bytes,
        timeout_seconds=GIT_TIMEOUT_SECONDS,
        environment=closed_git_environment(),
    )


def capture_pristine_authority(
    root: Path,
    *,
    expected_head: str,
) -> AuthoritySnapshot:
    # The protected properties are the exact Git top-level/HEAD/tree, tracked
    # content and Git modes, and absence of tracked, untracked, or ignored
    # changes. Inode/timestamp churn is benign. The workflow's separate
    # unprivileged test UID supplies the authority write-access boundary.
    root = root.resolve()
    expected_head = canonical_oid(expected_head, "default authority head")
    if not root.is_dir():
        raise GateError("default authority checkout is unavailable")
    try:
        top = Path(
            _authority_git_output(
                root,
                "rev-parse",
                "--show-toplevel",
                max_bytes=4096,
            )
            .decode("utf-8")
            .strip()
        ).resolve()
        head_sha = canonical_oid(
            _authority_git_output(
                root,
                "rev-parse",
                "--verify",
                "HEAD",
                max_bytes=128,
            )
            .decode("ascii")
            .strip(),
            "default authority observed head",
        )
        tree_sha = canonical_oid(
            _authority_git_output(
                root,
                "rev-parse",
                "--verify",
                "HEAD^{tree}",
                max_bytes=128,
            )
            .decode("ascii")
            .strip(),
            "default authority tree",
        )
    except UnicodeDecodeError as exc:
        raise GateError("default authority Git metadata is invalid") from exc
    status = _authority_git_output(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignored=matching",
        max_bytes=MAX_GIT_OUTPUT_BYTES,
    )
    if (
        top != root
        or head_sha != expected_head
        or len(tree_sha) != len(expected_head)
        or status
    ):
        raise GateError("default authority checkout is not pristine")
    return AuthoritySnapshot(head_sha, tree_sha)


def _read_authority_blob_objects(
    authority_root: Path,
    entries: tuple[TreeEntry, ...],
    *,
    expected_oid_length: int,
) -> dict[str, bytes]:
    object_ids = tuple(
        sorted({entry.object_id for entry in entries if entry.object_type == "blob"})
    )
    input_data = "".join(f"{object_id}\n" for object_id in object_ids).encode("ascii")
    raw = _authority_git_output(
        authority_root,
        "cat-file",
        "--batch",
        input_data=input_data,
        max_bytes=MAX_TREE_BYTES + len(object_ids) * 128 + 1,
    )
    return _decode_blob_batch(
        raw,
        object_ids=object_ids,
        expected_oid_length=expected_oid_length,
        label="default authority",
    )


def _read_candidate_blob_objects(
    git_dir: Path,
    entries: tuple[TreeEntry, ...],
    *,
    expected_oid_length: int,
) -> dict[str, bytes]:
    object_ids = tuple(
        sorted({entry.object_id for entry in entries if entry.object_type == "blob"})
    )
    raw = git_output(
        git_dir,
        "cat-file",
        "--batch",
        input_data="".join(f"{object_id}\n" for object_id in object_ids).encode(
            "ascii"
        ),
        max_bytes=MAX_TREE_BYTES + len(object_ids) * 128 + 1,
    )
    return _decode_blob_batch(
        raw,
        object_ids=object_ids,
        expected_oid_length=expected_oid_length,
        label="runtime authority",
    )


def _decode_blob_batch(
    raw: bytes,
    *,
    object_ids: tuple[str, ...],
    expected_oid_length: int,
    label: str,
) -> dict[str, bytes]:
    values: dict[str, bytes] = {}
    cursor = 0
    total_bytes = 0
    for expected_oid in object_ids:
        line_end = raw.find(b"\n", cursor)
        if line_end < 0:
            raise GateError(f"{label} blob metadata is incomplete")
        try:
            fields = raw[cursor:line_end].decode("ascii").split(" ")
        except UnicodeDecodeError as exc:
            raise GateError(f"{label} blob metadata is invalid") from exc
        if (
            len(fields) != 3
            or fields[0] != expected_oid
            or fields[1] != "blob"
            or not fields[2].isdecimal()
        ):
            raise GateError(f"{label} blob object is unavailable")
        size = int(fields[2])
        if size > MAX_BLOB_BYTES:
            raise GateError(f"{label} blob exceeds the trusted size limit")
        value_start = line_end + 1
        value_end = value_start + size
        if value_end >= len(raw) or raw[value_end : value_end + 1] != b"\n":
            raise GateError(f"{label} blob payload is incomplete")
        value = raw[value_start:value_end]
        if (
            git_blob_object_id(
                value,
                expected_length=expected_oid_length,
            )
            != expected_oid
        ):
            raise GateError(f"{label} blob content differs from its object ID")
        total_bytes += size
        if total_bytes > MAX_TREE_BYTES:
            raise GateError(f"{label} blob closure exceeds the trusted limit")
        values[expected_oid] = value
        cursor = value_end + 1
    if cursor != len(raw):
        raise GateError(f"{label} blob response contains trailing data")
    return values


def _read_stable_execution_blob(
    path: Path,
    *,
    expected_mode: int,
    expected_owner_uid: int | None = None,
) -> bytes:
    # Protected properties: regular-file identity, exact Git-derived access
    # mode, and stable bytes. Timestamps and other metadata-only churn are
    # deliberately ignored.
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except FileNotFoundError as exc:
        raise GateError("default execution blob is missing") from exc
    except PermissionError as exc:
        raise GateError("default execution blob is unreadable") from exc
    except OSError as exc:
        raise GateError("default execution blob could not be opened") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise GateError("default execution blob is not a regular file")
        if expected_owner_uid is not None and opened.st_uid != expected_owner_uid:
            raise GateError("default execution blob owner differs from the authority")
        if stat.S_IMODE(opened.st_mode) != expected_mode:
            raise GateError("default execution blob access policy changed")
        if not 0 <= opened.st_size <= MAX_BLOB_BYTES:
            raise GateError("default execution blob exceeds the trusted size limit")
        first = _read_policy_file_descriptor(
            descriptor,
            max_bytes=MAX_BLOB_BYTES,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_policy_file_descriptor(
            descriptor,
            max_bytes=MAX_BLOB_BYTES,
        )
        final = os.fstat(descriptor)
    except GateError:
        raise
    except OSError as exc:
        raise GateError(
            "default execution blob became unreadable while being read"
        ) from exc
    finally:
        os.close(descriptor)
    if len(first) != opened.st_size or len(second) != final.st_size or first != second:
        raise GateError("default execution blob content changed while being read")
    if (opened.st_dev, opened.st_ino) != (final.st_dev, final.st_ino):
        raise GateError("default execution blob was replaced while being read")
    if expected_owner_uid is not None and final.st_uid != expected_owner_uid:
        raise GateError("default execution blob owner changed while being read")
    if stat.S_IMODE(final.st_mode) != expected_mode:
        raise GateError("default execution blob access policy changed")
    try:
        current = os.stat(path, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise GateError("default execution blob is missing after read") from exc
    except PermissionError as exc:
        raise GateError(
            "default execution blob became unreadable during revalidation"
        ) from exc
    except OSError as exc:
        raise GateError(
            "default execution blob identity could not be revalidated"
        ) from exc
    if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (
        opened.st_dev,
        opened.st_ino,
    ):
        raise GateError("default execution blob was replaced while being read")
    if expected_owner_uid is not None and current.st_uid != expected_owner_uid:
        raise GateError("default execution blob owner changed during revalidation")
    if stat.S_IMODE(current.st_mode) != expected_mode:
        raise GateError("default execution blob access policy changed")
    return first


def _execution_tree_inventory(
    root: Path,
    *,
    expected_directory_mode: int = 0o700,
    expected_owner_uid: int | None = None,
) -> dict[str, tuple[str, int, int]]:
    try:
        root_metadata = os.lstat(root)
    except FileNotFoundError as exc:
        raise GateError("default execution tree is missing") from exc
    except PermissionError as exc:
        raise GateError("default execution tree is unreadable") from exc
    except OSError as exc:
        raise GateError("default execution tree could not be inspected") from exc
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise GateError("default execution tree is not a real directory")
    if stat.S_IMODE(root_metadata.st_mode) != expected_directory_mode:
        raise GateError("default execution root access policy changed")
    if expected_owner_uid is not None and root_metadata.st_uid != expected_owner_uid:
        raise GateError("default execution root owner differs from the authority")

    inventory: dict[str, tuple[str, int, int]] = {}
    pending = [(root, "")]
    while pending:
        directory, prefix = pending.pop()
        try:
            with os.scandir(directory) as children:
                for child in children:
                    relative = f"{prefix}/{child.name}" if prefix else child.name
                    try:
                        path = _safe_git_path(relative.encode("utf-8"))
                        metadata = child.stat(follow_symlinks=False)
                    except UnicodeEncodeError as exc:
                        raise GateError(
                            "default execution tree path is invalid"
                        ) from exc
                    except FileNotFoundError as exc:
                        raise GateError(
                            "default execution tree entry disappeared"
                        ) from exc
                    except PermissionError as exc:
                        raise GateError(
                            "default execution tree entry is unreadable"
                        ) from exc
                    except OSError as exc:
                        raise GateError(
                            "default execution tree entry could not be inspected"
                        ) from exc
                    reject_sensitive_candidate_path(path)
                    if path in inventory:
                        raise GateError(
                            "default execution tree contains duplicate paths"
                        )
                    if stat.S_ISDIR(metadata.st_mode):
                        kind = "tree"
                        pending.append((Path(child.path), path))
                    elif stat.S_ISREG(metadata.st_mode):
                        kind = "blob"
                    else:
                        raise GateError(
                            "default execution tree contains an unsupported object"
                        )
                    inventory[path] = (
                        kind,
                        stat.S_IMODE(metadata.st_mode),
                        metadata.st_uid,
                    )
                    if len(inventory) > MAX_TREE_ENTRIES:
                        raise GateError(
                            "default execution tree exceeds the trusted entry limit"
                        )
        except GateError:
            raise
        except FileNotFoundError as exc:
            raise GateError("default execution directory is missing") from exc
        except PermissionError as exc:
            raise GateError("default execution directory is unreadable") from exc
        except OSError as exc:
            raise GateError(
                "default execution directory could not be enumerated"
            ) from exc
    return inventory


def verify_default_execution_tree(
    root: Path,
    *,
    entries: tuple[TreeEntry, ...],
    expected_tree_sha: str,
    expected_directory_mode: int = 0o700,
    expected_regular_mode: int = 0o644,
    expected_executable_mode: int = 0o755,
    expected_owner_uid: int | None = None,
) -> None:
    expected_tree_sha = canonical_oid(
        expected_tree_sha,
        "default execution tree",
    )
    validate_complete_tree_entries(
        entries,
        expected_oid_length=len(expected_tree_sha),
        require_blob_sizes=False,
    )
    reconstruct_candidate_tree_oid(
        entries,
        expected_tree_sha=expected_tree_sha,
    )
    expected = {entry.path: entry for entry in entries}
    observed = _execution_tree_inventory(
        root,
        expected_directory_mode=expected_directory_mode,
        expected_owner_uid=expected_owner_uid,
    )
    if set(observed) - set(expected):
        raise GateError("default execution tree contains unexpected paths")
    if set(expected) - set(observed):
        raise GateError("default execution tree is missing authenticated paths")

    total_bytes = 0
    for path, entry in expected.items():
        observed_kind, observed_mode, observed_uid = observed[path]
        if expected_owner_uid is not None and observed_uid != expected_owner_uid:
            raise GateError("default execution entry owner differs from the authority")
        if entry.object_type == "tree":
            if observed_kind != "tree" or observed_mode != expected_directory_mode:
                raise GateError("default execution directory access policy changed")
            continue
        expected_mode = (
            expected_executable_mode
            if entry.mode == "100755"
            else expected_regular_mode
        )
        if observed_kind != "blob" or observed_mode != expected_mode:
            raise GateError("default execution blob access policy changed")
        value = _read_stable_execution_blob(
            root / Path(*PurePosixPath(path).parts),
            expected_mode=expected_mode,
            expected_owner_uid=expected_owner_uid,
        )
        total_bytes += len(value)
        if total_bytes > MAX_TREE_BYTES:
            raise GateError("default execution tree exceeds the trusted byte limit")
        if (
            git_blob_object_id(
                value,
                expected_length=len(entry.object_id),
            )
            != entry.object_id
        ):
            raise GateError("default execution blob content differs from its object ID")


def prepare_default_execution_tree(
    authority_root: Path,
    execution_root: Path,
    *,
    expected_head: str,
) -> AuthoritySnapshot:
    authority_root = authority_root.resolve()
    execution_root = execution_root.resolve()
    snapshot = capture_pristine_authority(
        authority_root,
        expected_head=expected_head,
    )
    if execution_root == authority_root or execution_root.is_relative_to(
        authority_root
    ):
        raise GateError("default execution tree overlaps the authority checkout")
    if execution_root.exists():
        raise GateError("default execution tree already exists")
    execution_root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    execution_root.mkdir(mode=0o700)
    execution_root.chmod(0o700)

    entries = parse_git_tree_records(
        _authority_git_output(
            authority_root,
            "ls-tree",
            "-r",
            "-t",
            "-z",
            "--full-tree",
            snapshot.head_sha,
            max_bytes=MAX_GIT_OUTPUT_BYTES,
        ),
        expected_oid_length=len(snapshot.head_sha),
    )
    reconstruct_candidate_tree_oid(
        entries,
        expected_tree_sha=snapshot.tree_sha,
    )
    blob_values = _read_authority_blob_objects(
        authority_root,
        entries,
        expected_oid_length=len(snapshot.head_sha),
    )

    try:
        for entry in sorted(
            (entry for entry in entries if entry.object_type == "tree"),
            key=lambda entry: (len(PurePosixPath(entry.path).parts), entry.path),
        ):
            destination = execution_root / Path(*PurePosixPath(entry.path).parts)
            destination.mkdir(mode=0o700)
            destination.chmod(0o700)
        total_bytes = 0
        for entry in sorted(
            (entry for entry in entries if entry.object_type == "blob"),
            key=lambda entry: entry.path,
        ):
            value = blob_values[entry.object_id]
            total_bytes += len(value)
            if total_bytes > MAX_TREE_BYTES:
                raise GateError("default execution tree exceeds the trusted byte limit")
            destination = execution_root / Path(*PurePosixPath(entry.path).parts)
            with destination.open("xb") as stream:
                stream.write(value)
            destination.chmod(0o755 if entry.mode == "100755" else 0o644)
    except OSError as exc:
        raise GateError("default execution tree could not be materialized") from exc
    verify_default_execution_tree(
        execution_root,
        entries=entries,
        expected_tree_sha=snapshot.tree_sha,
    )
    if (
        capture_pristine_authority(
            authority_root,
            expected_head=expected_head,
        )
        != snapshot
    ):
        raise GateError("default authority checkout changed during materialization")
    return snapshot


def capture_runtime_authority(
    git_dir: Path,
    *,
    expected_head: str,
) -> tuple[AuthoritySnapshot, tuple[TreeEntry, ...], dict[str, bytes]]:
    git_dir = git_dir.resolve()
    expected_head = canonical_oid(expected_head, "runtime authority head")
    validate_closed_candidate_repository(git_dir)
    if git_text(git_dir, "cat-file", "-t", expected_head, max_bytes=64).strip() != (
        "commit"
    ):
        raise GateError("runtime authority head is not a commit")
    tree_sha = canonical_oid(
        git_text(
            git_dir,
            "rev-parse",
            "--verify",
            f"{expected_head}^{{tree}}",
            max_bytes=128,
        ).strip(),
        "runtime authority tree",
    )
    entries = git_tree_entries(git_dir, expected_head)
    if any(entry.object_type not in {"blob", "tree"} for entry in entries):
        raise GateError("runtime authority tree contains an unsupported object")
    reconstruct_candidate_tree_oid(entries, expected_tree_sha=tree_sha)
    blobs = _read_candidate_blob_objects(
        git_dir,
        entries,
        expected_oid_length=len(expected_head),
    )
    validate_closed_candidate_repository(git_dir)
    return AuthoritySnapshot(expected_head, tree_sha), entries, blobs


def _require_runtime_authority_directory(path: Path, authority_uid: int) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError as exc:
        raise GateError("runtime authority directory is missing") from exc
    except PermissionError as exc:
        raise GateError("runtime authority directory is unreadable") from exc
    except OSError as exc:
        raise GateError("runtime authority directory could not be inspected") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise GateError("runtime authority directory is not a real directory")
    if metadata.st_uid != authority_uid:
        raise GateError("runtime authority directory owner differs")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise GateError("runtime authority directory access policy is unsafe")


def prepare_runtime_execution_tree(
    git_dir: Path,
    execution_root: Path,
    *,
    expected_head: str,
) -> RuntimeAuthoritySnapshot:
    git_dir = git_dir.resolve()
    execution_root = execution_root.resolve()
    snapshot, entries, blob_values = capture_runtime_authority(
        git_dir,
        expected_head=expected_head,
    )
    if execution_root == git_dir or execution_root.is_relative_to(git_dir):
        raise GateError("runtime execution tree overlaps the authority store")
    if execution_root.exists():
        raise GateError("runtime execution tree already exists")
    execution_root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    authority_uid = os.geteuid()
    _require_runtime_authority_directory(execution_root.parent, authority_uid)
    execution_root.mkdir(mode=0o700)

    directories = sorted(
        (entry for entry in entries if entry.object_type == "tree"),
        key=lambda entry: (len(PurePosixPath(entry.path).parts), entry.path),
    )
    try:
        for entry in directories:
            (execution_root / Path(*PurePosixPath(entry.path).parts)).mkdir(mode=0o700)
        total_bytes = 0
        for entry in sorted(
            (entry for entry in entries if entry.object_type == "blob"),
            key=lambda entry: entry.path,
        ):
            value = blob_values[entry.object_id]
            total_bytes += len(value)
            if total_bytes > MAX_TREE_BYTES:
                raise GateError("runtime execution tree exceeds the trusted byte limit")
            destination = execution_root / Path(*PurePosixPath(entry.path).parts)
            with destination.open("xb") as stream:
                stream.write(value)
            destination.chmod(0o555 if entry.mode == "100755" else 0o444)
        for entry in reversed(directories):
            (execution_root / Path(*PurePosixPath(entry.path).parts)).chmod(0o555)
        execution_root.chmod(0o555)
    except GateError:
        raise
    except OSError as exc:
        raise GateError("runtime execution tree could not be materialized") from exc
    verify_default_execution_tree(
        execution_root,
        entries=entries,
        expected_tree_sha=snapshot.tree_sha,
        expected_directory_mode=0o555,
        expected_regular_mode=0o444,
        expected_executable_mode=0o555,
        expected_owner_uid=authority_uid,
    )
    observed, _entries, _blobs = capture_runtime_authority(
        git_dir,
        expected_head=expected_head,
    )
    if observed != snapshot:
        raise GateError("runtime authority changed during materialization")
    try:
        root_metadata = os.lstat(execution_root)
    except OSError as exc:
        raise GateError("runtime execution root identity is unavailable") from exc
    return RuntimeAuthoritySnapshot(
        head_sha=snapshot.head_sha,
        tree_sha=snapshot.tree_sha,
        authority_uid=authority_uid,
        execution_root_device=root_metadata.st_dev,
        execution_root_inode=root_metadata.st_ino,
    )


def verify_runtime_authority(
    git_dir: Path,
    execution_root: Path,
    *,
    expected_head: str,
    receipt: RuntimeAuthoritySnapshot,
) -> None:
    if receipt.authority_uid != os.geteuid():
        raise GateError("runtime authority receipt owner differs")
    _require_runtime_authority_directory(
        execution_root.resolve().parent,
        receipt.authority_uid,
    )
    try:
        root_metadata = os.lstat(execution_root)
    except OSError as exc:
        raise GateError("runtime execution root identity is unavailable") from exc
    if (root_metadata.st_dev, root_metadata.st_ino) != (
        receipt.execution_root_device,
        receipt.execution_root_inode,
    ):
        raise GateError("runtime execution root object identity changed")
    observed, entries, _blobs = capture_runtime_authority(
        git_dir.resolve(),
        expected_head=expected_head,
    )
    if (observed.head_sha, observed.tree_sha) != (
        receipt.head_sha,
        receipt.tree_sha,
    ):
        raise GateError("runtime authority changed after candidate tests")
    verify_default_execution_tree(
        execution_root.resolve(),
        entries=entries,
        expected_tree_sha=receipt.tree_sha,
        expected_directory_mode=0o555,
        expected_regular_mode=0o444,
        expected_executable_mode=0o555,
        expected_owner_uid=receipt.authority_uid,
    )


def authority_snapshot_payload(snapshot: AuthoritySnapshot) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": DEFAULT_AUTHORITY_RECEIPT_KIND,
        "head_sha": snapshot.head_sha,
        "tree_sha": snapshot.tree_sha,
    }


def runtime_authority_snapshot_payload(
    snapshot: RuntimeAuthoritySnapshot,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": RUNTIME_AUTHORITY_RECEIPT_KIND,
        **asdict(snapshot),
    }


def load_authority_snapshot(path: Path) -> AuthoritySnapshot:
    payload, _raw = read_bounded_json_file(
        path,
        "default authority receipt",
    )
    exact_keys(
        payload,
        {"schema_version", "kind", "head_sha", "tree_sha"},
        "default authority receipt",
    )
    if (
        type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 1
        or payload.get("kind") != DEFAULT_AUTHORITY_RECEIPT_KIND
    ):
        raise GateError("default authority receipt schema is invalid")
    head_sha = canonical_oid(payload.get("head_sha"), "authority receipt head")
    tree_sha = canonical_oid(payload.get("tree_sha"), "authority receipt tree")
    if len(head_sha) != len(tree_sha):
        raise GateError("default authority receipt hash formats differ")
    return AuthoritySnapshot(head_sha, tree_sha)


def load_runtime_authority_snapshot(path: Path) -> RuntimeAuthoritySnapshot:
    authority_uid = os.geteuid()
    payload, _raw = read_bounded_json_file(
        path,
        "runtime authority receipt",
        expected_owner_uid=authority_uid,
    )
    exact_keys(
        payload,
        {
            "schema_version",
            "kind",
            "head_sha",
            "tree_sha",
            "authority_uid",
            "execution_root_device",
            "execution_root_inode",
        },
        "runtime authority receipt",
    )
    if (
        type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 1
        or payload.get("kind") != RUNTIME_AUTHORITY_RECEIPT_KIND
    ):
        raise GateError("runtime authority receipt schema is invalid")
    head_sha = canonical_oid(payload.get("head_sha"), "runtime receipt head")
    tree_sha = canonical_oid(payload.get("tree_sha"), "runtime receipt tree")
    if len(head_sha) != len(tree_sha):
        raise GateError("runtime authority receipt hash formats differ")
    integer_names = (
        "authority_uid",
        "execution_root_device",
        "execution_root_inode",
    )
    integers = {name: payload.get(name) for name in integer_names}
    if any(type(value) is not int or value < 0 for value in integers.values()):
        raise GateError("runtime authority receipt identity is invalid")
    if integers["authority_uid"] != authority_uid:
        raise GateError("runtime authority receipt owner differs")
    return RuntimeAuthoritySnapshot(
        head_sha=head_sha,
        tree_sha=tree_sha,
        authority_uid=integers["authority_uid"],
        execution_root_device=integers["execution_root_device"],
        execution_root_inode=integers["execution_root_inode"],
    )


def verify_default_authority(
    root: Path,
    *,
    expected_head: str,
    receipt: AuthoritySnapshot,
) -> None:
    observed = capture_pristine_authority(
        root,
        expected_head=expected_head,
    )
    if observed != receipt:
        raise GateError("default authority checkout changed after candidate tests")


def compact_json_bytes(payload: Any) -> bytes:
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )


def write_json(
    path: Path,
    payload: Any,
    *,
    max_bytes: int | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = compact_json_bytes(payload)
    if max_bytes is not None and len(encoded) > max_bytes:
        raise GateError("JSON output exceeds the trusted size limit")
    path.write_bytes(encoded)


def _common_pull_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pr-number", required=True, type=int)
    parser.add_argument("--pr-node-id", required=True)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-repository", required=True)
    parser.add_argument("--head-ref", required=True)
    parser.add_argument("--head-sha", required=True)


def _live_snapshot_from_args(args: argparse.Namespace) -> PullRequestSnapshot:
    return read_live_pull_request(
        repository=args.repository,
        number=args.pr_number,
        node_id=args.pr_node_id,
        base_ref=args.base_ref,
        base_sha=args.base_sha,
        head_repository=args.head_repository,
        head_ref=args.head_ref,
        head_sha=args.head_sha,
        token=os.environ.get("GH_TOKEN", ""),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Trusted retrospective history CI gate."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot_parser = subparsers.add_parser("snapshot")
    _common_pull_arguments(snapshot_parser)
    snapshot_parser.add_argument("--output", required=True, type=Path)

    merge_snapshot_parser = subparsers.add_parser("merge-group-snapshot")
    merge_snapshot_parser.add_argument("--repository", required=True)
    merge_snapshot_parser.add_argument(
        "--repository-id",
        required=True,
        type=int,
    )
    merge_snapshot_parser.add_argument("--event-path", required=True, type=Path)
    merge_snapshot_parser.add_argument("--event-ref", required=True)
    merge_snapshot_parser.add_argument("--event-sha", required=True)
    merge_snapshot_parser.add_argument("--workflow-sha", required=True)
    merge_snapshot_parser.add_argument(
        "--admission-app-id",
        required=True,
        type=int,
    )
    merge_snapshot_parser.add_argument("--output", required=True, type=Path)

    preflight_parser = subparsers.add_parser("preflight")
    preflight_parser.add_argument("--git-dir", required=True, type=Path)
    preflight_parser.add_argument("--base-sha", required=True)
    preflight_parser.add_argument("--head-sha", required=True)
    preflight_parser.add_argument(
        "--policy", required=True, choices=("bootstrap-v2", "history-v2")
    )
    preflight_parser.add_argument("--repository", required=True)
    preflight_parser.add_argument("--output", required=True, type=Path)

    verify_parser = subparsers.add_parser("verify-objects")
    verify_parser.add_argument("--git-dir", required=True, type=Path)
    verify_parser.add_argument("--manifest", required=True, type=Path)

    materialize_parser = subparsers.add_parser("materialize-blobs")
    materialize_parser.add_argument("--git-dir", required=True, type=Path)
    materialize_parser.add_argument("--manifest", required=True, type=Path)
    materialize_parser.add_argument("--repository", required=True)

    prepare_default_parser = subparsers.add_parser("prepare-default-execution")
    prepare_default_parser.add_argument(
        "--authority-root",
        required=True,
        type=Path,
    )
    prepare_default_parser.add_argument(
        "--execution-root",
        required=True,
        type=Path,
    )
    prepare_default_parser.add_argument("--expected-head", required=True)
    prepare_default_parser.add_argument("--output", required=True, type=Path)

    verify_default_parser = subparsers.add_parser("verify-default-authority")
    verify_default_parser.add_argument(
        "--authority-root",
        required=True,
        type=Path,
    )
    verify_default_parser.add_argument("--expected-head", required=True)
    verify_default_parser.add_argument("--receipt", required=True, type=Path)

    prepare_runtime_parser = subparsers.add_parser("prepare-runtime-execution")
    prepare_runtime_parser.add_argument("--git-dir", required=True, type=Path)
    prepare_runtime_parser.add_argument(
        "--execution-root",
        required=True,
        type=Path,
    )
    prepare_runtime_parser.add_argument("--expected-head", required=True)
    prepare_runtime_parser.add_argument("--output", required=True, type=Path)

    verify_runtime_parser = subparsers.add_parser("verify-runtime-authority")
    verify_runtime_parser.add_argument("--git-dir", required=True, type=Path)
    verify_runtime_parser.add_argument(
        "--execution-root",
        required=True,
        type=Path,
    )
    verify_runtime_parser.add_argument("--expected-head", required=True)
    verify_runtime_parser.add_argument("--receipt", required=True, type=Path)

    resolve_admitted_candidate_parser = subparsers.add_parser(
        "resolve-default-admitted-candidate"
    )
    resolve_admitted_candidate_parser.add_argument("--repository", required=True)
    resolve_admitted_candidate_parser.add_argument(
        "--repository-id",
        required=True,
        type=int,
    )
    resolve_admitted_candidate_parser.add_argument("--base-sha", required=True)
    resolve_admitted_candidate_parser.add_argument("--head-sha", required=True)
    resolve_admitted_candidate_parser.add_argument(
        "--trusted-base-root",
        required=True,
        type=Path,
    )
    resolve_admitted_candidate_parser.add_argument(
        "--output",
        required=True,
        type=Path,
    )

    verify_github_commit_parser = subparsers.add_parser("verify-default-github-commit")
    verify_github_commit_parser.add_argument("--repository", required=True)
    verify_github_commit_parser.add_argument(
        "--repository-id",
        required=True,
        type=int,
    )
    verify_github_commit_parser.add_argument("--git-dir", required=True, type=Path)
    verify_github_commit_parser.add_argument(
        "--trusted-base-root",
        required=True,
        type=Path,
    )
    verify_github_commit_parser.add_argument("--base-sha", required=True)
    verify_github_commit_parser.add_argument("--head-sha", required=True)
    verify_github_commit_parser.add_argument(
        "--initial-candidate-evidence",
        required=True,
        type=Path,
    )
    verify_github_commit_parser.add_argument("--output", required=True, type=Path)

    resolve_base_parser = subparsers.add_parser("resolve-merge-group-base")
    resolve_base_parser.add_argument("--snapshot", required=True, type=Path)
    resolve_base_parser.add_argument("--git-dir", required=True, type=Path)

    validate_group_parser = subparsers.add_parser("validate-merge-group")
    validate_group_parser.add_argument("--snapshot", required=True, type=Path)
    validate_group_parser.add_argument("--git-dir", required=True, type=Path)
    validate_group_parser.add_argument("--candidate-root", required=True, type=Path)
    validate_group_parser.add_argument("--queue-root", required=True, type=Path)
    validate_group_parser.add_argument(
        "--policy", required=True, choices=("bootstrap-v2", "history-v2")
    )
    validate_group_parser.add_argument("--trusted-base-root", type=Path)
    validate_group_parser.add_argument("--output", required=True, type=Path)

    admit_group_parser = subparsers.add_parser("admit-merge-group")
    admit_group_parser.add_argument("--snapshot", required=True, type=Path)
    admit_group_parser.add_argument("--git-dir", required=True, type=Path)
    admit_group_parser.add_argument("--candidate-root", required=True, type=Path)
    admit_group_parser.add_argument("--queue-root", required=True, type=Path)
    admit_group_parser.add_argument(
        "--policy", required=True, choices=("bootstrap-v2", "history-v2")
    )
    admit_group_parser.add_argument(
        "--trusted-base-root",
        required=True,
        type=Path,
    )
    admit_group_parser.add_argument(
        "--runtime-evidence",
        required=True,
        type=Path,
    )
    admit_group_parser.add_argument(
        "--expected-python-sha256",
        required=True,
    )
    admit_group_parser.add_argument("--event-path", required=True, type=Path)
    admit_group_parser.add_argument("--event-ref", required=True)
    admit_group_parser.add_argument("--event-sha", required=True)
    admit_group_parser.add_argument("--workflow-sha", required=True)
    admit_group_parser.add_argument(
        "--admission-app-id",
        required=True,
        type=int,
    )
    admit_group_parser.add_argument("--output", required=True, type=Path)

    finalize_group_parser = subparsers.add_parser("finalize-merge-group")
    finalize_group_parser.add_argument("--snapshot", required=True, type=Path)
    finalize_group_parser.add_argument("--event-path", required=True, type=Path)
    finalize_group_parser.add_argument("--event-ref", required=True)
    finalize_group_parser.add_argument("--event-sha", required=True)
    finalize_group_parser.add_argument("--workflow-sha", required=True)
    finalize_group_parser.add_argument(
        "--policy",
        required=True,
        choices=("bootstrap-v2", "history-v2"),
    )
    finalize_group_parser.add_argument(
        "--trusted-base-root",
        required=True,
        type=Path,
    )
    finalize_group_parser.add_argument("--output", required=True, type=Path)

    args = parser.parse_args(argv)
    try:
        if args.command == "snapshot":
            write_json(args.output, asdict(_live_snapshot_from_args(args)))
        elif args.command == "merge-group-snapshot":
            snapshot = read_live_merge_group_snapshot(
                repository=args.repository,
                repository_id=args.repository_id,
                event_path=args.event_path.resolve(),
                event_ref=args.event_ref,
                event_sha=args.event_sha,
                workflow_sha=args.workflow_sha,
                admission_app_id=args.admission_app_id,
                token=os.environ.get("GH_TOKEN", ""),
            )
            write_json(args.output, snapshot.as_dict())
        elif args.command == "preflight":
            git_dir = args.git_dir.resolve()

            def load_tree_payload(tree_oid: str) -> Any:
                encoded_tree = parse.quote(tree_oid, safe="")
                return github_json(
                    "GET",
                    args.repository,
                    f"/git/trees/{encoded_tree}?recursive=1",
                    token=os.environ.get("GH_TOKEN", ""),
                )

            preflight = preflight_git_candidate(
                git_dir,
                base_sha=args.base_sha,
                head_sha=args.head_sha,
                tree_payload=None,
                policy=args.policy,
                tree_payload_loader=load_tree_payload,
            )
            write_json(
                args.output,
                preflight.as_dict(),
                max_bytes=MAX_PREFLIGHT_MANIFEST_BYTES,
            )
        elif args.command == "verify-objects":
            verify_preflight_objects(
                args.git_dir.resolve(), load_preflight(args.manifest.resolve())
            )
        elif args.command == "materialize-blobs":
            materialize_preflight_blobs(
                args.git_dir.resolve(),
                load_preflight(args.manifest.resolve()),
                repository=args.repository,
                token=os.environ.get("GH_TOKEN", ""),
            )
        elif args.command == "prepare-default-execution":
            snapshot = prepare_default_execution_tree(
                args.authority_root,
                args.execution_root,
                expected_head=args.expected_head,
            )
            write_json(args.output, authority_snapshot_payload(snapshot))
        elif args.command == "verify-default-authority":
            verify_default_authority(
                args.authority_root,
                expected_head=args.expected_head,
                receipt=load_authority_snapshot(args.receipt.resolve()),
            )
        elif args.command == "prepare-runtime-execution":
            snapshot = prepare_runtime_execution_tree(
                args.git_dir.resolve(),
                args.execution_root.resolve(),
                expected_head=args.expected_head,
            )
            write_json(args.output, runtime_authority_snapshot_payload(snapshot))
        elif args.command == "verify-runtime-authority":
            verify_runtime_authority(
                args.git_dir.resolve(),
                args.execution_root.resolve(),
                expected_head=args.expected_head,
                receipt=load_runtime_authority_snapshot(args.receipt.resolve()),
            )
        elif args.command == "resolve-default-admitted-candidate":
            evidence = resolve_default_candidate_evidence(
                repository=args.repository,
                repository_id=args.repository_id,
                trusted_base_root=args.trusted_base_root,
                base_sha=args.base_sha,
                head_sha=args.head_sha,
                token=os.environ.get("GH_TOKEN", ""),
            )
            write_json(
                args.output,
                evidence,
                max_bytes=MAX_POLICY_JSON_BYTES,
            )
            print(evidence["candidate_sha"])
        elif args.command == "verify-default-github-commit":
            receipt = verify_default_github_commit(
                repository=args.repository,
                repository_id=args.repository_id,
                git_dir=args.git_dir,
                trusted_base_root=args.trusted_base_root,
                base_sha=args.base_sha,
                head_sha=args.head_sha,
                initial_candidate_evidence=load_default_candidate_evidence(
                    args.initial_candidate_evidence.resolve()
                ),
                token=os.environ.get("GH_TOKEN", ""),
            )
            write_json(
                args.output,
                receipt,
                max_bytes=MAX_GITHUB_SQUASH_RECEIPT_BYTES,
            )
        elif args.command == "resolve-merge-group-base":
            snapshot = load_merge_group_snapshot(args.snapshot.resolve())
            queue_commit = validate_candidate_commit_object(
                args.git_dir.resolve(),
                snapshot.queue_sha,
                strict_bootstrap_metadata=False,
            )
            if queue_commit.parents != (
                snapshot.base_sha,
                snapshot.candidate_sha,
            ):
                raise GateError(
                    "merge-group Q does not have the exact B1/H parent-edge shape"
                )
            print(
                _single_merge_base(
                    args.git_dir.resolve(),
                    snapshot.base_sha,
                    snapshot.candidate_sha,
                )
            )
        elif args.command == "validate-merge-group":
            projection = validate_merge_group_transaction(
                git_dir=args.git_dir.resolve(),
                snapshot=load_merge_group_snapshot(args.snapshot.resolve()),
                candidate_root=args.candidate_root.resolve(),
                queue_root=args.queue_root.resolve(),
                policy=args.policy,
                trusted_base_root=(
                    args.trusted_base_root.resolve()
                    if args.trusted_base_root is not None
                    else None
                ),
            )
            write_json(args.output, projection.as_dict())
        elif args.command == "admit-merge-group":
            snapshot = load_merge_group_snapshot(args.snapshot.resolve())
            projection = validate_merge_group_transaction(
                git_dir=args.git_dir.resolve(),
                snapshot=snapshot,
                candidate_root=args.candidate_root.resolve(),
                queue_root=args.queue_root.resolve(),
                policy=args.policy,
                trusted_base_root=(
                    args.trusted_base_root.resolve()
                    if args.trusted_base_root is not None
                    else None
                ),
            )
            evidence = load_merge_group_runtime_evidence(
                args.runtime_evidence.resolve()
            )
            validate_merge_group_runtime_evidence(
                git_dir=args.git_dir.resolve(),
                snapshot=snapshot,
                projection=projection,
                evidence=evidence,
                expected_python_executable_sha256=(args.expected_python_sha256),
            )
            live_authority = revalidate_external_merge_group_authority(
                expected=snapshot,
                projection=projection,
                policy=args.policy,
                trusted_base_root=args.trusted_base_root.resolve(),
                event_path=args.event_path.resolve(),
                event_ref=args.event_ref,
                event_sha=args.event_sha,
                workflow_sha=args.workflow_sha,
                admission_app_id=args.admission_app_id,
                token=os.environ.get("GH_TOKEN", ""),
            )
            write_json(
                args.output,
                merge_group_admission_payload(
                    snapshot=snapshot,
                    projection=projection,
                    evidence=evidence,
                    live_authority=live_authority,
                ),
            )
        elif args.command == "finalize-merge-group":
            payload = verify_live_merge_group_authority(
                expected=load_merge_group_snapshot(args.snapshot.resolve()),
                event_path=args.event_path.resolve(),
                event_ref=args.event_ref,
                event_sha=args.event_sha,
                workflow_sha=args.workflow_sha,
                policy=args.policy,
                trusted_base_root=args.trusted_base_root.resolve(),
                token=os.environ.get("GH_TOKEN", ""),
            )
            write_json(args.output, payload)
        else:
            raise GateError("unsupported trusted CI command")
    except (GateError, ValueError, UnicodeError) as exc:
        print(str(exc))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
