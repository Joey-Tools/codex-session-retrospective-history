#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from typing import Any, Callable, Protocol
from urllib import error, parse, request

try:
    from retrospective_history_git_v2 import (
        V2_TRUST_ROOT_PATHS,
        trust_generation_from_entries,
    )
except ModuleNotFoundError:  # Imported as scripts.retrospective_history_merge_v2.
    from scripts.retrospective_history_git_v2 import (
        V2_TRUST_ROOT_PATHS,
        trust_generation_from_entries,
    )


API_VERSION = "2022-11-28"
CHECK_NAME = "Retrospective history immutable candidate"
MAX_API_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_ERROR_RESPONSE_BYTES = 4096
MAX_RECONCILE_ATTEMPTS = 6
RECONCILE_DEADLINE_SECONDS = 10.0
RECONCILE_BACKOFF_SECONDS = (0.25, 0.5, 1.0, 2.0, 4.0)
OID_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
WAL_RECORD_RE = re.compile(r"(?P<generation>[0-9]{8})\.json")
WAL_SCHEMA = "retrospective_history_publication_wal_v2"
WAL_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
MAX_WAL_RECORD_BYTES = 64 * 1024
MAX_WAL_RECORDS = 32
MAX_CHECK_RUN_PAGES = 10
CHECK_RUNS_PER_PAGE = 100


class MergeTransactionError(RuntimeError):
    pass


class MergeRetrySafeError(MergeTransactionError):
    pass


class MergeReconciliationInconclusive(MergeTransactionError):
    pass


class ReconciliationOutcome(str, Enum):
    MERGED = "merged"
    NOT_MERGED_RETRY_SAFE = "not_merged_retry_safe"
    INCONCLUSIVE = "inconclusive"


class PublicationWALState(str, Enum):
    PREPARED = "prepared"
    CHECK_CREATED = "check_created"
    MERGE_INTENT = "merge_intent"
    RESPONSE_REJECTED = "response_rejected"
    RETRY_SAFE = "retry_safe"
    ABORTED_BEFORE_INTENT = "aborted_before_intent"
    COMPLETED = "completed"


WAL_TRANSITIONS = {
    PublicationWALState.PREPARED: frozenset(
        {
            PublicationWALState.CHECK_CREATED,
            PublicationWALState.ABORTED_BEFORE_INTENT,
            PublicationWALState.COMPLETED,
        }
    ),
    PublicationWALState.CHECK_CREATED: frozenset(
        {
            PublicationWALState.MERGE_INTENT,
            PublicationWALState.ABORTED_BEFORE_INTENT,
        }
    ),
    PublicationWALState.MERGE_INTENT: frozenset(
        {
            PublicationWALState.RESPONSE_REJECTED,
            PublicationWALState.RETRY_SAFE,
            PublicationWALState.COMPLETED,
        }
    ),
    PublicationWALState.RESPONSE_REJECTED: frozenset(
        {PublicationWALState.RETRY_SAFE, PublicationWALState.COMPLETED}
    ),
    PublicationWALState.RETRY_SAFE: frozenset(),
    PublicationWALState.ABORTED_BEFORE_INTENT: frozenset(),
    PublicationWALState.COMPLETED: frozenset(),
}


class _ReconciliationPending(RuntimeError):
    pass


class API(Protocol):
    def request(
        self,
        method: str,
        endpoint: str,
        payload: dict[str, Any] | None = None,
    ) -> Any: ...


class GitHubAPI:
    def __init__(self, base_url: str, token: str) -> None:
        if not token:
            raise MergeTransactionError("GitHub App token is unavailable")
        self._base_url = base_url.rstrip("/")
        self._token = token

    def request(
        self,
        method: str,
        endpoint: str,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        encoded_payload = None
        if payload is not None:
            encoded_payload = json.dumps(
                payload, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        api_request = request.Request(
            f"{self._base_url}{endpoint}",
            data=encoded_payload,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "User-Agent": "retrospective-history-merge-v2",
                "X-GitHub-Api-Version": API_VERSION,
            },
        )
        try:
            with request.urlopen(api_request, timeout=30) as response:
                declared = response.headers.get("Content-Length")
                if declared is not None and int(declared) > MAX_API_RESPONSE_BYTES:
                    raise MergeTransactionError("GitHub API response is too large")
                raw = response.read(MAX_API_RESPONSE_BYTES + 1)
        except error.HTTPError as exc:
            detail = exc.read(MAX_ERROR_RESPONSE_BYTES).decode(
                "utf-8", errors="replace"
            )
            raise MergeTransactionError(
                f"GitHub API {method} {endpoint} failed with HTTP {exc.code}: {detail}"
            ) from exc
        except (error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise MergeTransactionError(
                f"GitHub API {method} {endpoint} did not complete"
            ) from exc
        if len(raw) > MAX_API_RESPONSE_BYTES:
            raise MergeTransactionError("GitHub API response is too large")
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MergeTransactionError(
                "GitHub API response is not valid JSON"
            ) from exc


@dataclass(frozen=True)
class CandidateBinding:
    base_oid: str
    head_oid: str
    replay: bool

    def as_dict(self) -> dict[str, str | bool | int]:
        return {
            "schema_version": 1,
            "base_oid": self.base_oid,
            "head_oid": self.head_oid,
            "replay": self.replay,
        }


@dataclass(frozen=True)
class MergePlan:
    base_oid: str
    head_oid: str
    head_tree_oid: str
    squash_subject: str
    trust_generation: str


@dataclass(frozen=True)
class MergeReceipt:
    base_oid: str
    head_oid: str
    master_oid: str
    merge_oid: str
    squash_subject: str
    tree_oid: str
    trust_generation: str

    def as_dict(self) -> dict[str, str | int]:
        return {
            "schema_version": 1,
            "base_oid": self.base_oid,
            "head_oid": self.head_oid,
            "master_oid": self.master_oid,
            "merge_oid": self.merge_oid,
            "squash_subject": self.squash_subject,
            "tree_oid": self.tree_oid,
            "trust_generation": self.trust_generation,
        }


@dataclass(frozen=True)
class MergeReconciliation:
    outcome: ReconciliationOutcome
    receipt: MergeReceipt | None = None
    reason: str = ""


@dataclass(frozen=True)
class RemotePublicationCheck:
    check_id: int
    state: PublicationWALState


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _wal_scope(
    repository: str,
    pull_request_number: int,
    plan: MergePlan,
    expected_app_id: int,
    expected_app_slug: str,
) -> dict[str, Any]:
    scope = {
        "repository": repository,
        "pull_request_number": pull_request_number,
        "base_oid": plan.base_oid,
        "head_oid": plan.head_oid,
        "head_tree_oid": plan.head_tree_oid,
        "squash_subject": plan.squash_subject,
        "trust_generation": plan.trust_generation,
        "expected_app_id": expected_app_id,
        "expected_app_slug": expected_app_slug,
    }
    transaction = hashlib.sha256()
    transaction.update(b"retrospective-history-publication-wal-transaction-v2")
    transaction.update(_canonical_json_bytes(scope))
    scope["transaction_id"] = f"sha256:{transaction.hexdigest()}"
    return scope


def _wal_record_digest(payload: dict[str, Any]) -> str:
    projection = dict(payload)
    projection.pop("record_digest", None)
    hasher = hashlib.sha256()
    hasher.update(b"retrospective-history-publication-wal-record-v2")
    hasher.update(_canonical_json_bytes(projection))
    return f"sha256:{hasher.hexdigest()}"


def _receipt_from_payload(payload: Any) -> MergeReceipt:
    value = _object(payload, "publication WAL receipt")
    if value.get("schema_version") != 1 or set(value) != {
        "schema_version",
        "base_oid",
        "head_oid",
        "master_oid",
        "merge_oid",
        "squash_subject",
        "tree_oid",
        "trust_generation",
    }:
        raise MergeTransactionError("publication WAL receipt schema is invalid")
    subject = value.get("squash_subject")
    generation = value.get("trust_generation")
    if (
        not isinstance(subject, str)
        or not subject
        or not isinstance(generation, str)
        or WAL_DIGEST_RE.fullmatch(generation) is None
    ):
        raise MergeTransactionError("publication WAL receipt schema is invalid")
    return MergeReceipt(
        base_oid=_oid(value.get("base_oid"), "publication WAL receipt base"),
        head_oid=_oid(value.get("head_oid"), "publication WAL receipt head"),
        master_oid=_oid(value.get("master_oid"), "publication WAL receipt master"),
        merge_oid=_oid(value.get("merge_oid"), "publication WAL receipt merge"),
        squash_subject=subject,
        tree_oid=_oid(value.get("tree_oid"), "publication WAL receipt tree"),
        trust_generation=generation,
    )


class PublicationWAL:
    """Crash-safe, append-only local journal for one immutable merge plan."""

    _FIELDS = frozenset(
        {
            "schema",
            "generation",
            "previous_record_digest",
            "record_digest",
            "state",
            "repository",
            "pull_request_number",
            "base_oid",
            "head_oid",
            "head_tree_oid",
            "squash_subject",
            "trust_generation",
            "expected_app_id",
            "expected_app_slug",
            "transaction_id",
            "check_id",
            "response_sha",
            "receipt",
        }
    )

    def __init__(self, path: Path, scope: dict[str, Any]) -> None:
        self.path = Path(path)
        self.scope = dict(scope)
        self._records: list[dict[str, Any]] = []
        self._prepare_directory()
        self._load()
        if not self._records:
            self._append(PublicationWALState.PREPARED)
        elif any(self.latest.get(key) != value for key, value in self.scope.items()):
            raise MergeTransactionError(
                "publication WAL does not match the immutable merge plan"
            )

    @property
    def latest(self) -> dict[str, Any]:
        return self._records[-1]

    @property
    def state(self) -> PublicationWALState:
        return PublicationWALState(self.latest["state"])

    @property
    def receipt(self) -> MergeReceipt | None:
        if self.latest["receipt"] is None:
            return None
        return _receipt_from_payload(self.latest["receipt"])

    def _prepare_directory(self) -> None:
        try:
            self.path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise MergeTransactionError("publication WAL directory is unavailable") from exc
        try:
            metadata = self.path.lstat()
        except OSError as exc:
            raise MergeTransactionError("publication WAL directory is unavailable") from exc
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise MergeTransactionError("publication WAL path is not a directory")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise MergeTransactionError("publication WAL directory permissions are unsafe")
        for child in self.path.iterdir():
            if not child.name.startswith(".wal-tmp-"):
                continue
            try:
                child_metadata = child.lstat()
                if not stat.S_ISREG(child_metadata.st_mode):
                    raise MergeTransactionError(
                        "publication WAL temporary entry is unsafe"
                    )
                child.unlink()
            except OSError as exc:
                raise MergeTransactionError(
                    "publication WAL temporary entry cannot be recovered"
                ) from exc
        self._fsync_directory()

    def _fsync_directory(self) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(self.path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _load(self) -> None:
        paths: list[tuple[int, Path]] = []
        for child in self.path.iterdir():
            match = WAL_RECORD_RE.fullmatch(child.name)
            if match is None:
                raise MergeTransactionError("publication WAL contains an unknown entry")
            paths.append((int(match.group("generation")), child))
        paths.sort()
        if len(paths) > MAX_WAL_RECORDS:
            raise MergeTransactionError("publication WAL record limit is exceeded")
        previous_digest: str | None = None
        previous_state: PublicationWALState | None = None
        for expected_generation, (generation, path) in enumerate(paths):
            if generation != expected_generation:
                raise MergeTransactionError("publication WAL generations are not contiguous")
            try:
                metadata = path.lstat()
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or stat.S_ISLNK(metadata.st_mode)
                    or metadata.st_size > MAX_WAL_RECORD_BYTES
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                ):
                    raise MergeTransactionError("publication WAL record is unsafe")
                raw = path.read_bytes()
                if len(raw) > MAX_WAL_RECORD_BYTES or not raw.endswith(b"\n"):
                    raise MergeTransactionError("publication WAL record is incomplete")
                payload = json.loads(raw, object_pairs_hook=_strict_json_object)
            except (
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                ValueError,
            ) as exc:
                raise MergeTransactionError("publication WAL record is invalid") from exc
            record = self._validate_record(payload, expected_generation, previous_digest)
            state = PublicationWALState(record["state"])
            if previous_state is not None and state not in WAL_TRANSITIONS[previous_state]:
                raise MergeTransactionError("publication WAL transition is invalid")
            self._records.append(record)
            previous_digest = record["record_digest"]
            previous_state = state

    def _validate_record(
        self,
        payload: Any,
        generation: int,
        previous_digest: str | None,
    ) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != self._FIELDS:
            raise MergeTransactionError("publication WAL record schema is invalid")
        if (
            payload.get("schema") != WAL_SCHEMA
            or type(payload.get("generation")) is not int
            or payload["generation"] != generation
            or payload.get("previous_record_digest") != previous_digest
            or not isinstance(payload.get("record_digest"), str)
            or WAL_DIGEST_RE.fullmatch(payload["record_digest"]) is None
            or payload["record_digest"] != _wal_record_digest(payload)
        ):
            raise MergeTransactionError("publication WAL record authentication failed")
        try:
            state = PublicationWALState(payload.get("state"))
        except (TypeError, ValueError) as exc:
            raise MergeTransactionError("publication WAL state is invalid") from exc
        if generation == 0 and state is not PublicationWALState.PREPARED:
            raise MergeTransactionError(
                "publication WAL generation zero must be prepared"
            )
        if any(payload.get(key) != value for key, value in self.scope.items()):
            raise MergeTransactionError("publication WAL scope changed")
        check_id = payload.get("check_id")
        if check_id is not None and (type(check_id) is not int or check_id <= 0):
            raise MergeTransactionError("publication WAL check ID is invalid")
        response_sha = payload.get("response_sha")
        if response_sha is not None:
            _oid(response_sha, "publication WAL response")
        receipt = payload.get("receipt")
        if state is PublicationWALState.PREPARED:
            if check_id is not None or response_sha is not None or receipt is not None:
                raise MergeTransactionError("prepared publication WAL record is invalid")
        elif state in {
            PublicationWALState.CHECK_CREATED,
            PublicationWALState.MERGE_INTENT,
            PublicationWALState.RESPONSE_REJECTED,
        } and (check_id is None or receipt is not None):
            raise MergeTransactionError("publication WAL side-effect state is invalid")
        elif state is PublicationWALState.COMPLETED:
            parsed_receipt = _receipt_from_payload(receipt)
            if (
                parsed_receipt.base_oid != self.scope["base_oid"]
                or parsed_receipt.head_oid != self.scope["head_oid"]
                or parsed_receipt.tree_oid != self.scope["head_tree_oid"]
                or parsed_receipt.squash_subject != self.scope["squash_subject"]
                or parsed_receipt.trust_generation != self.scope["trust_generation"]
                or (
                    response_sha is not None
                    and parsed_receipt.merge_oid != response_sha
                )
            ):
                raise MergeTransactionError("publication WAL receipt changed scope")
        elif receipt is not None:
            raise MergeTransactionError("terminal publication WAL state is invalid")
        return payload

    def transition(
        self,
        state: PublicationWALState,
        *,
        check_id: int | None = None,
        response_sha: str | None = None,
        receipt: MergeReceipt | None = None,
    ) -> None:
        if state not in WAL_TRANSITIONS[self.state]:
            raise MergeTransactionError("publication WAL transition is invalid")
        inherited_check_id = self.latest["check_id"]
        self._append(
            state,
            check_id=inherited_check_id if check_id is None else check_id,
            response_sha=response_sha,
            receipt=receipt,
        )

    def _append(
        self,
        state: PublicationWALState,
        *,
        check_id: int | None = None,
        response_sha: str | None = None,
        receipt: MergeReceipt | None = None,
    ) -> None:
        generation = len(self._records)
        if generation >= MAX_WAL_RECORDS:
            raise MergeTransactionError("publication WAL record limit is exceeded")
        payload = {
            "schema": WAL_SCHEMA,
            "generation": generation,
            "previous_record_digest": (
                None if not self._records else self._records[-1]["record_digest"]
            ),
            "record_digest": "",
            "state": state.value,
            **self.scope,
            "check_id": check_id,
            "response_sha": response_sha,
            "receipt": None if receipt is None else receipt.as_dict(),
        }
        payload["record_digest"] = _wal_record_digest(payload)
        self._validate_record(
            payload,
            generation,
            payload["previous_record_digest"],
        )
        raw = _canonical_json_bytes(payload) + b"\n"
        if len(raw) > MAX_WAL_RECORD_BYTES:
            raise MergeTransactionError("publication WAL record is too large")
        descriptor, temporary = tempfile.mkstemp(prefix=".wal-tmp-", dir=self.path)
        temporary_path = Path(temporary)
        target = self.path / f"{generation:08d}.json"
        try:
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, raw[offset:])
                if written <= 0:
                    raise OSError("short publication WAL write")
                offset += written
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            if target.exists():
                raise MergeTransactionError("publication WAL generation already exists")
            os.replace(temporary_path, target)
            self._fsync_directory()
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary_path.unlink()
            except OSError:
                pass
            raise
        self._records.append(payload)


def _object(payload: Any, label: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise MergeTransactionError(f"{label} is not a JSON object")
    return payload


def _oid(value: Any, label: str) -> str:
    if not isinstance(value, str) or OID_RE.fullmatch(value) is None:
        raise MergeTransactionError(f"{label} is not a canonical commit OID")
    return value


def _repository(value: str) -> str:
    if REPOSITORY_RE.fullmatch(value) is None:
        raise MergeTransactionError("repository is not canonical")
    return value


def _pull_revisions(
    payload: Any, repository: str, pull_request_number: int
) -> tuple[dict[str, Any], str, str]:
    pull = _object(payload, "pull request")
    base = _object(pull.get("base"), "pull request base")
    head = _object(pull.get("head"), "pull request head")
    base_repository = _object(base.get("repo"), "pull request base repository")
    if (
        pull.get("number") != pull_request_number
        or base.get("ref") != "master"
        or base_repository.get("full_name") != repository
    ):
        raise MergeTransactionError(
            "pull request route does not target repository master"
        )
    return (
        pull,
        _oid(base.get("sha"), "pull request base"),
        _oid(head.get("sha"), "pull request head"),
    )


def _git_commit(api: API, repository: str, oid: str) -> dict[str, Any]:
    commit = _object(
        api.request("GET", f"/repos/{repository}/git/commits/{oid}"),
        "Git commit",
    )
    if _oid(commit.get("sha"), "Git commit") != oid:
        raise MergeTransactionError("Git commit response changed identity")
    return commit


def _single_parent(commit: dict[str, Any]) -> str:
    parents = commit.get("parents")
    if not isinstance(parents, list) or len(parents) != 1:
        raise MergeTransactionError("squash commit must have exactly one parent")
    return _oid(_object(parents[0], "commit parent").get("sha"), "commit parent")


def resolve_candidate(
    api: API,
    repository: str,
    pull_request_number: int,
    workflow_oid: str,
) -> CandidateBinding:
    repository = _repository(repository)
    workflow_oid = _oid(workflow_oid, "workflow source")
    pull, current_base, head_oid = _pull_revisions(
        api.request("GET", f"/repos/{repository}/pulls/{pull_request_number}"),
        repository,
        pull_request_number,
    )
    if pull.get("merged") is True:
        merge_oid = _oid(pull.get("merge_commit_sha"), "merged pull request commit")
        base_oid = _single_parent(_git_commit(api, repository, merge_oid))
        replay = True
    elif pull.get("merged") is False and pull.get("state") == "open":
        base_oid = current_base
        replay = False
    else:
        raise MergeTransactionError("pull request is closed without an exact merge")
    if base_oid != workflow_oid:
        raise MergeTransactionError(
            "workflow source does not equal the immutable candidate base"
        )
    return CandidateBinding(base_oid=base_oid, head_oid=head_oid, replay=replay)


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MergeTransactionError(f"{label} is not valid JSON") from exc
    return _object(payload, label)


def load_binding(path: Path) -> CandidateBinding:
    payload = _load_json_object(path, "candidate binding")
    if payload.get("schema_version") != 1 or not isinstance(
        payload.get("replay"), bool
    ):
        raise MergeTransactionError("candidate binding schema is invalid")
    return CandidateBinding(
        base_oid=_oid(payload.get("base_oid"), "candidate base"),
        head_oid=_oid(payload.get("head_oid"), "candidate head"),
        replay=payload["replay"],
    )


def load_plan(path: Path) -> MergePlan:
    payload = _load_json_object(path, "merge plan")
    subject = payload.get("squash_subject")
    generation = payload.get("trust_generation")
    if (
        payload.get("schema_version") != 1
        or not isinstance(subject, str)
        or not subject
        or len(subject.encode("ascii", errors="ignore")) != len(subject)
        or len(subject.encode("ascii")) > 256
        or any(character in subject for character in "\r\n\0")
        or not isinstance(generation, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", generation) is None
    ):
        raise MergeTransactionError("merge plan schema is invalid")
    return MergePlan(
        base_oid=_oid(payload.get("base_oid"), "planned base"),
        head_oid=_oid(payload.get("head_oid"), "planned head"),
        head_tree_oid=_oid(payload.get("head_tree_oid"), "planned head tree"),
        squash_subject=subject,
        trust_generation=generation,
    )


def _enabled(payload: dict[str, Any], key: str, expected: bool) -> None:
    value = payload.get(key)
    if not isinstance(value, dict) or value.get("enabled") is not expected:
        raise MergeTransactionError(f"branch protection {key} is unsafe")


def verify_merge_control(
    api: API,
    repository: str,
    expected_app_id: int,
    expected_app_slug: str,
) -> None:
    protection = _object(
        api.request("GET", f"/repos/{repository}/branches/master/protection"),
        "branch protection",
    )
    required = _object(
        protection.get("required_status_checks"), "required status checks"
    )
    checks = required.get("checks")
    if required.get("strict") is not True or not isinstance(checks, list):
        raise MergeTransactionError("strict required checks are not enforced")
    immutable_checks = [
        check
        for check in checks
        if isinstance(check, dict) and check.get("context") == CHECK_NAME
    ]
    if (
        len(immutable_checks) != 1
        or immutable_checks[0].get("app_id") != expected_app_id
    ):
        raise MergeTransactionError("immutable candidate check source is not pinned")

    _enabled(protection, "enforce_admins", True)
    _enabled(protection, "required_linear_history", True)
    _enabled(protection, "allow_force_pushes", False)
    _enabled(protection, "allow_deletions", False)
    if protection.get("required_pull_request_reviews") not in (None, {}):
        raise MergeTransactionError("mutable pull request review state is not allowed")

    restrictions = _object(protection.get("restrictions"), "branch restrictions")
    users = restrictions.get("users")
    teams = restrictions.get("teams")
    apps = restrictions.get("apps")
    if users != [] or teams != [] or not isinstance(apps, list) or len(apps) != 1:
        raise MergeTransactionError("master updates are not restricted to one App")
    app = _object(apps[0], "branch restriction App")
    if app.get("id") != expected_app_id or app.get("slug") != expected_app_slug:
        raise MergeTransactionError("branch restriction App identity does not match")

    active_rules = api.request("GET", f"/repos/{repository}/rules/branches/master")
    if not isinstance(active_rules, list) or active_rules:
        raise MergeTransactionError("active rulesets are not allowed on master")


def _branch_oid(api: API, repository: str) -> str:
    payload = _object(
        api.request("GET", f"/repos/{repository}/git/ref/heads/master"),
        "master reference",
    )
    target = _object(payload.get("object"), "master reference target")
    if target.get("type") != "commit":
        raise MergeTransactionError("master does not reference a commit")
    return _oid(target.get("sha"), "master reference")


def _tree_oid(commit: dict[str, Any]) -> str:
    return _oid(_object(commit.get("tree"), "commit tree").get("sha"), "commit tree")


def remote_trust_generation(api: API, repository: str, base_oid: str) -> str:
    root_tree_oid = _tree_oid(_git_commit(api, repository, base_oid))
    encoded_tree_oid = parse.quote(root_tree_oid, safe="")
    payload = _object(
        api.request(
            "GET",
            f"/repos/{repository}/git/trees/{encoded_tree_oid}?recursive=1",
        ),
        "base tree",
    )
    if payload.get("truncated") is not False or payload.get("sha") != root_tree_oid:
        raise MergeTransactionError("base tree inventory is incomplete")
    tree = payload.get("tree")
    if not isinstance(tree, list):
        raise MergeTransactionError("base tree inventory is invalid")
    trusted_paths = {path.decode("ascii") for path in V2_TRUST_ROOT_PATHS}
    entries: list[tuple[str, str, str, str]] = []
    for raw_entry in tree:
        if not isinstance(raw_entry, dict):
            raise MergeTransactionError("base tree entry is invalid")
        path = raw_entry.get("path")
        if isinstance(path, str) and path in trusted_paths:
            entries.append(
                (
                    path,
                    raw_entry.get("mode"),
                    raw_entry.get("type"),
                    raw_entry.get("sha"),
                )
            )
    try:
        return trust_generation_from_entries(entries)
    except (TypeError, ValueError) as exc:
        raise MergeTransactionError("remote trust generation is invalid") from exc


def verify_current_candidate(
    api: API,
    repository: str,
    pull_request_number: int,
    plan: MergePlan,
) -> None:
    pull, base_oid, head_oid = _pull_revisions(
        api.request("GET", f"/repos/{repository}/pulls/{pull_request_number}"),
        repository,
        pull_request_number,
    )
    if pull.get("merged") is not False or pull.get("state") != "open":
        raise MergeTransactionError("pull request is no longer an open candidate")
    if head_oid != plan.head_oid or base_oid != plan.base_oid:
        raise MergeTransactionError("pull request revisions changed before merge")
    if _branch_oid(api, repository) != plan.base_oid:
        raise MergeTransactionError("master changed before merge")
    head_tree_oid = _tree_oid(_git_commit(api, repository, plan.head_oid))
    if head_tree_oid != plan.head_tree_oid:
        raise MergeTransactionError("candidate tree changed before merge")
    if remote_trust_generation(api, repository, plan.base_oid) != plan.trust_generation:
        raise MergeTransactionError("trusted base generation changed before merge")


def _plan_digest(repository: str, pull_request_number: int, plan: MergePlan) -> str:
    payload = {
        "repository": repository,
        "pull_request_number": pull_request_number,
        "base_oid": plan.base_oid,
        "head_oid": plan.head_oid,
        "head_tree_oid": plan.head_tree_oid,
        "squash_subject": plan.squash_subject,
        "trust_generation": plan.trust_generation,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _check_external_id(
    repository: str, pull_request_number: int, plan: MergePlan
) -> str:
    return f"pr:{pull_request_number}:{_plan_digest(repository, pull_request_number, plan)}"


def _remote_check_from_payload(
    payload: Any,
    plan: MergePlan,
    external_id: str,
    expected_app_id: int,
    expected_app_slug: str,
) -> RemotePublicationCheck | None:
    check = _object(payload, "publication check run")
    if check.get("name") != CHECK_NAME or check.get("external_id") != external_id:
        return None
    app = _object(check.get("app"), "publication check App")
    if app.get("id") != expected_app_id or app.get("slug") != expected_app_slug:
        raise MergeTransactionError("publication check App identity changed")
    if _oid(check.get("head_sha"), "publication check head") != plan.head_oid:
        raise MergeTransactionError("publication check head changed")
    check_id = check.get("id")
    if type(check_id) is not int or check_id <= 0:
        raise MergeTransactionError("publication check has no identifier")
    status = check.get("status")
    conclusion = check.get("conclusion")
    if status in {"queued", "in_progress"} and conclusion is None:
        return RemotePublicationCheck(check_id, PublicationWALState.CHECK_CREATED)
    if status == "completed" and conclusion == "success":
        return RemotePublicationCheck(check_id, PublicationWALState.MERGE_INTENT)
    if status == "completed" and conclusion in {
        "failure",
        "cancelled",
        "neutral",
        "skipped",
        "stale",
        "timed_out",
        "action_required",
    }:
        return None
    raise MergeTransactionError("publication check has an unsupported state")


def find_publication_check(
    api: API,
    repository: str,
    pull_request_number: int,
    plan: MergePlan,
    expected_app_id: int,
    expected_app_slug: str,
) -> RemotePublicationCheck | None:
    external_id = _check_external_id(repository, pull_request_number, plan)
    active: list[RemotePublicationCheck] = []
    encoded_name = parse.quote(CHECK_NAME, safe="")
    for page in range(1, MAX_CHECK_RUN_PAGES + 1):
        payload = _object(
            api.request(
                "GET",
                f"/repos/{repository}/commits/{plan.head_oid}/check-runs"
                f"?check_name={encoded_name}&filter=all&per_page={CHECK_RUNS_PER_PAGE}"
                f"&page={page}",
            ),
            "publication check runs",
        )
        check_runs = payload.get("check_runs")
        total_count = payload.get("total_count")
        if (
            type(total_count) is not int
            or total_count < 0
            or not isinstance(check_runs, list)
            or len(check_runs) > CHECK_RUNS_PER_PAGE
        ):
            raise MergeTransactionError("publication check inventory is invalid")
        for raw_check in check_runs:
            check = _remote_check_from_payload(
                raw_check,
                plan,
                external_id,
                expected_app_id,
                expected_app_slug,
            )
            if check is not None:
                active.append(check)
        if page * CHECK_RUNS_PER_PAGE >= total_count:
            break
    else:
        raise MergeTransactionError("publication check inventory is too large")
    unique = {(check.check_id, check.state) for check in active}
    if len(unique) > 1:
        raise MergeTransactionError("multiple active publication checks exist")
    if not active:
        return None
    selected = active[0]
    confirmed = read_publication_check(
        api,
        repository,
        pull_request_number,
        plan,
        selected.check_id,
        expected_app_id,
        expected_app_slug,
    )
    if confirmed is not None and confirmed.check_id != selected.check_id:
        raise MergeTransactionError("publication check identity changed")
    return confirmed


def read_publication_check(
    api: API,
    repository: str,
    pull_request_number: int,
    plan: MergePlan,
    check_id: int,
    expected_app_id: int,
    expected_app_slug: str,
) -> RemotePublicationCheck | None:
    payload = _object(
        api.request("GET", f"/repos/{repository}/check-runs/{check_id}"),
        "publication check run",
    )
    expected_external_id = _check_external_id(
        repository, pull_request_number, plan
    )
    if (
        payload.get("name") != CHECK_NAME
        or payload.get("external_id") != expected_external_id
    ):
        raise MergeTransactionError("publication check identity changed")
    return _remote_check_from_payload(
        payload,
        plan,
        expected_external_id,
        expected_app_id,
        expected_app_slug,
    )


def require_unique_publication_check(
    api: API,
    repository: str,
    pull_request_number: int,
    plan: MergePlan,
    check_id: int,
    state: PublicationWALState,
    expected_app_id: int,
    expected_app_slug: str,
) -> RemotePublicationCheck:
    expected = RemotePublicationCheck(check_id, state)
    observed = find_publication_check(
        api,
        repository,
        pull_request_number,
        plan,
        expected_app_id,
        expected_app_slug,
    )
    if observed != expected:
        raise MergeTransactionError(
            "publication check is not unique in the expected state"
        )
    return observed


def create_immutable_check(
    api: API,
    repository: str,
    pull_request_number: int,
    plan: MergePlan,
    details_url: str,
) -> int:
    digest = _plan_digest(repository, pull_request_number, plan)
    payload = {
        "name": CHECK_NAME,
        "head_sha": plan.head_oid,
        "status": "in_progress",
        "external_id": f"pr:{pull_request_number}:{digest}",
        "details_url": details_url,
        "output": {
            "title": "Immutable candidate merge preparation",
            "summary": (
                f"The trusted App prepared immutable candidate plan {digest}."
            ),
        },
    }
    response = _object(
        api.request("POST", f"/repos/{repository}/check-runs", payload),
        "check run",
    )
    check_id = response.get("id")
    if type(check_id) is not int or check_id <= 0:
        raise MergeTransactionError("immutable candidate check has no identifier")
    return check_id


def authorize_immutable_check(api: API, repository: str, check_id: int) -> None:
    api.request(
        "PATCH",
        f"/repos/{repository}/check-runs/{check_id}",
        {
            "status": "completed",
            "conclusion": "success",
            "output": {
                "title": "Immutable candidate validated",
                "summary": "The trusted App recorded durable merge intent.",
            },
        },
    )


def fail_immutable_check(api: API, repository: str, check_id: int) -> None:
    api.request(
        "PATCH",
        f"/repos/{repository}/check-runs/{check_id}",
        {
            "status": "completed",
            "conclusion": "failure",
            "output": {
                "title": "Immutable candidate merge failed",
                "summary": "The App merge transaction failed closed.",
            },
        },
    )


def _master_contains(
    api: API, repository: str, merge_oid: str, master_oid: str
) -> bool:
    if merge_oid == master_oid:
        return True
    comparison = _object(
        api.request("GET", f"/repos/{repository}/compare/{merge_oid}...{master_oid}"),
        "master ancestry comparison",
    )
    merge_base = _object(comparison.get("merge_base_commit"), "merge base")
    return comparison.get("status") == "ahead" and merge_base.get("sha") == merge_oid


def _receipt_from_merged_pull(
    api: API,
    repository: str,
    pull: dict[str, Any],
    head_oid: str,
    plan: MergePlan,
    expected_app_slug: str,
    response_sha: str | None = None,
) -> MergeReceipt:
    if head_oid != plan.head_oid:
        raise MergeTransactionError("merged pull request head does not match the plan")
    merged_by = _object(pull.get("merged_by"), "merge actor")
    if (
        merged_by.get("type") != "Bot"
        or merged_by.get("login") != f"{expected_app_slug}[bot]"
    ):
        raise MergeTransactionError("pull request was not merged by the trusted App")

    merge_oid = _oid(pull.get("merge_commit_sha"), "merged commit")
    if response_sha is not None and _oid(response_sha, "merge response") != merge_oid:
        raise MergeTransactionError("merge response does not match the pull request")
    try:
        commit = _git_commit(api, repository, merge_oid)
    except MergeTransactionError as exc:
        raise _ReconciliationPending("merged commit is not visible yet") from exc
    if _single_parent(commit) != plan.base_oid:
        raise MergeTransactionError("merged commit parent does not match the plan")
    if _tree_oid(commit) != plan.head_tree_oid:
        raise MergeTransactionError("merged commit tree does not match the candidate")
    if commit.get("message") != plan.squash_subject:
        raise MergeTransactionError("merged commit message does not match the plan")
    try:
        master_oid = _branch_oid(api, repository)
        master_contains_merge = _master_contains(api, repository, merge_oid, master_oid)
    except MergeTransactionError as exc:
        raise _ReconciliationPending("master ancestry is not visible yet") from exc
    if not master_contains_merge:
        raise _ReconciliationPending("merged commit is not visible in master yet")
    return MergeReceipt(
        base_oid=plan.base_oid,
        head_oid=plan.head_oid,
        master_oid=master_oid,
        merge_oid=merge_oid,
        squash_subject=plan.squash_subject,
        tree_oid=plan.head_tree_oid,
        trust_generation=plan.trust_generation,
    )


def _observe_merge(
    api: API,
    repository: str,
    pull_request_number: int,
    plan: MergePlan,
    expected_app_slug: str,
    *,
    response_sha: str | None,
    response_rejected: bool,
) -> MergeReconciliation:
    try:
        payload = api.request("GET", f"/repos/{repository}/pulls/{pull_request_number}")
    except MergeTransactionError:
        return MergeReconciliation(
            ReconciliationOutcome.INCONCLUSIVE,
            reason="pull request state is not visible",
        )
    pull, base_oid, head_oid = _pull_revisions(payload, repository, pull_request_number)
    if pull.get("merged") is True:
        if pull.get("state") != "closed":
            return MergeReconciliation(
                ReconciliationOutcome.INCONCLUSIVE,
                reason="merged pull request closure is not visible",
            )
        try:
            receipt = _receipt_from_merged_pull(
                api,
                repository,
                pull,
                head_oid,
                plan,
                expected_app_slug,
                response_sha=response_sha,
            )
        except _ReconciliationPending as exc:
            return MergeReconciliation(
                ReconciliationOutcome.INCONCLUSIVE,
                reason=str(exc),
            )
        return MergeReconciliation(ReconciliationOutcome.MERGED, receipt=receipt)

    if pull.get("merged") is False:
        if pull.get("state") == "closed":
            return MergeReconciliation(
                ReconciliationOutcome.NOT_MERGED_RETRY_SAFE,
                reason="pull request is closed without a merge",
            )
        if pull.get("state") == "open" and (
            response_rejected or head_oid != plan.head_oid or base_oid != plan.base_oid
        ):
            return MergeReconciliation(
                ReconciliationOutcome.NOT_MERGED_RETRY_SAFE,
                reason="the exact candidate was not merged",
            )
    return MergeReconciliation(
        ReconciliationOutcome.INCONCLUSIVE,
        reason="the merge may not be visible yet",
    )


def reconcile_merge_eventually(
    api: API,
    repository: str,
    pull_request_number: int,
    plan: MergePlan,
    expected_app_slug: str,
    *,
    response_sha: str | None = None,
    response_rejected: bool = False,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> MergeReconciliation:
    started_at = monotonic()
    last_result = MergeReconciliation(
        ReconciliationOutcome.INCONCLUSIVE,
        reason="no reconciliation probe completed",
    )
    for attempt in range(MAX_RECONCILE_ATTEMPTS):
        if attempt:
            elapsed = monotonic() - started_at
            remaining = RECONCILE_DEADLINE_SECONDS - elapsed
            if remaining <= 0:
                break
            delay = min(RECONCILE_BACKOFF_SECONDS[attempt - 1], remaining)
            sleep(delay)
            if monotonic() - started_at > RECONCILE_DEADLINE_SECONDS:
                break
        last_result = _observe_merge(
            api,
            repository,
            pull_request_number,
            plan,
            expected_app_slug,
            response_sha=response_sha,
            response_rejected=response_rejected,
        )
        if last_result.outcome is not ReconciliationOutcome.INCONCLUSIVE:
            return last_result
    return last_result


def reconcile_merge(
    api: API,
    repository: str,
    pull_request_number: int,
    plan: MergePlan,
    expected_app_slug: str,
    response_sha: str | None = None,
) -> MergeReceipt:
    result = _observe_merge(
        api,
        repository,
        pull_request_number,
        plan,
        expected_app_slug,
        response_sha=response_sha,
        response_rejected=False,
    )
    if result.outcome is ReconciliationOutcome.MERGED:
        assert result.receipt is not None
        return result.receipt
    raise MergeTransactionError("pull request has no completed merge to reconcile")


def run_transaction(
    api: API,
    repository: str,
    pull_request_number: int,
    binding: CandidateBinding,
    plan: MergePlan,
    expected_app_id: int,
    expected_app_slug: str,
    details_url: str,
    *,
    wal_path: Path | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> MergeReceipt:
    repository = _repository(repository)
    if (binding.base_oid, binding.head_oid) != (plan.base_oid, plan.head_oid):
        raise MergeTransactionError("candidate binding does not match the merge plan")
    wal = (
        None
        if wal_path is None
        else PublicationWAL(
            wal_path,
            _wal_scope(
                repository,
                pull_request_number,
                plan,
                expected_app_id,
                expected_app_slug,
            ),
        )
    )

    if wal is not None and wal.state in {
        PublicationWALState.RETRY_SAFE,
        PublicationWALState.ABORTED_BEFORE_INTENT,
    }:
        raise MergeRetrySafeError(
            "the publication WAL is terminal before a merge; a new transaction is retry-safe"
        )

    if wal is not None and wal.state is PublicationWALState.COMPLETED:
        stored_receipt = wal.receipt
        assert stored_receipt is not None
        reconciliation = reconcile_merge_eventually(
            api,
            repository,
            pull_request_number,
            plan,
            expected_app_slug,
            response_sha=stored_receipt.merge_oid,
            monotonic=monotonic,
            sleep=sleep,
        )
        if (
            reconciliation.outcome is ReconciliationOutcome.MERGED
            and reconciliation.receipt == stored_receipt
        ):
            return stored_receipt
        raise MergeReconciliationInconclusive(
            "completed publication WAL cannot be reconciled to the exact merge"
        )

    if binding.replay:
        reconciliation = reconcile_merge_eventually(
            api,
            repository,
            pull_request_number,
            plan,
            expected_app_slug,
            monotonic=monotonic,
            sleep=sleep,
        )
        if reconciliation.outcome is ReconciliationOutcome.MERGED:
            assert reconciliation.receipt is not None
            if wal is not None:
                wal.transition(
                    PublicationWALState.COMPLETED,
                    receipt=reconciliation.receipt,
                )
            return reconciliation.receipt
        if reconciliation.outcome is ReconciliationOutcome.NOT_MERGED_RETRY_SAFE:
            if wal is not None:
                wal.transition(PublicationWALState.ABORTED_BEFORE_INTENT)
            raise MergeRetrySafeError(
                "squash merge definitively did not complete; a new transaction is retry-safe"
            )
        raise MergeReconciliationInconclusive(
            "squash merge outcome is inconclusive; it may have succeeded and must not be retried"
        )

    remote_check = find_publication_check(
        api,
        repository,
        pull_request_number,
        plan,
        expected_app_id,
        expected_app_slug,
    )
    wal_check_id = None if wal is None else wal.latest["check_id"]
    if wal_check_id is not None:
        direct_check = read_publication_check(
            api,
            repository,
            pull_request_number,
            plan,
            wal_check_id,
            expected_app_id,
            expected_app_slug,
        )
        if remote_check is not None and remote_check != direct_check:
            raise MergeTransactionError("publication check recovery is ambiguous")
        remote_check = direct_check

    if remote_check is not None and wal is not None:
        if wal.state is PublicationWALState.PREPARED:
            wal.transition(
                PublicationWALState.CHECK_CREATED,
                check_id=remote_check.check_id,
            )
        elif wal.latest["check_id"] != remote_check.check_id:
            raise MergeTransactionError("publication WAL check identity changed")
        if (
            remote_check.state is PublicationWALState.MERGE_INTENT
            and wal.state is PublicationWALState.CHECK_CREATED
        ):
            wal.transition(PublicationWALState.MERGE_INTENT)
        elif (
            remote_check.state is PublicationWALState.CHECK_CREATED
            and wal.state
            in {
                PublicationWALState.MERGE_INTENT,
                PublicationWALState.RESPONSE_REJECTED,
            }
        ):
            raise MergeTransactionError("publication check state rolled back")

    recovery_only = (
        remote_check is not None
        and remote_check.state is PublicationWALState.MERGE_INTENT
    ) or (
        wal is not None
        and wal.state
        in {
            PublicationWALState.MERGE_INTENT,
            PublicationWALState.RESPONSE_REJECTED,
        }
    )
    if wal_check_id is not None and remote_check is None and not recovery_only:
        raise MergeReconciliationInconclusive(
            "publication check recovery is inconclusive; no new side effect is allowed"
        )

    check_id = (
        remote_check.check_id if remote_check is not None else wal_check_id
    )
    authorized_here = False
    if not recovery_only:
        try:
            if remote_check is None:
                verify_merge_control(
                    api, repository, expected_app_id, expected_app_slug
                )
                verify_current_candidate(
                    api, repository, pull_request_number, plan
                )
                check_id = create_immutable_check(
                    api, repository, pull_request_number, plan, details_url
                )
                if wal is not None:
                    wal.transition(
                        PublicationWALState.CHECK_CREATED,
                        check_id=check_id,
                    )

            assert check_id is not None
            remote_check = require_unique_publication_check(
                api,
                repository,
                pull_request_number,
                plan,
                check_id,
                PublicationWALState.CHECK_CREATED,
                expected_app_id,
                expected_app_slug,
            )
            # These are the last authorization reads before durable merge intent.
            verify_merge_control(
                api, repository, expected_app_id, expected_app_slug
            )
            verify_current_candidate(api, repository, pull_request_number, plan)
            remote_check = require_unique_publication_check(
                api,
                repository,
                pull_request_number,
                plan,
                check_id,
                PublicationWALState.CHECK_CREATED,
                expected_app_id,
                expected_app_slug,
            )
            authorize_immutable_check(api, repository, check_id)
            confirmed = read_publication_check(
                api,
                repository,
                pull_request_number,
                plan,
                check_id,
                expected_app_id,
                expected_app_slug,
            )
            if (
                confirmed is None
                or confirmed.state is not PublicationWALState.MERGE_INTENT
            ):
                raise MergeReconciliationInconclusive(
                    "durable merge intent is not visible; no merge call is allowed"
                )
            confirmed = require_unique_publication_check(
                api,
                repository,
                pull_request_number,
                plan,
                check_id,
                PublicationWALState.MERGE_INTENT,
                expected_app_id,
                expected_app_slug,
            )
            if wal is not None:
                wal.transition(PublicationWALState.MERGE_INTENT)
            remote_check = confirmed
            authorized_here = True
        except MergeReconciliationInconclusive:
            raise
        except MergeTransactionError:
            if check_id is not None:
                fail_immutable_check(api, repository, check_id)
            if wal is not None and wal.state in {
                PublicationWALState.PREPARED,
                PublicationWALState.CHECK_CREATED,
            }:
                wal.transition(PublicationWALState.ABORTED_BEFORE_INTENT)
            raise

    response_sha: str | None = None
    response_rejected = (
        wal is not None and wal.state is PublicationWALState.RESPONSE_REJECTED
    )
    if authorized_here:
        try:
            response = _object(
                api.request(
                    "PUT",
                    f"/repos/{repository}/pulls/{pull_request_number}/merge",
                    {
                        "commit_title": plan.squash_subject,
                        "commit_message": "",
                        "merge_method": "squash",
                        "sha": plan.head_oid,
                    },
                ),
                "merge response",
            )
            if response.get("merged") is True:
                response_sha = _oid(response.get("sha"), "merge response")
            elif response.get("merged") is False:
                response_rejected = True
                if wal is not None:
                    wal.transition(PublicationWALState.RESPONSE_REJECTED)
            else:
                raise MergeTransactionError("merge response has no closed result")
        except MergeTransactionError:
            pass

    reconciliation = reconcile_merge_eventually(
        api,
        repository,
        pull_request_number,
        plan,
        expected_app_slug,
        response_sha=response_sha,
        response_rejected=response_rejected,
        monotonic=monotonic,
        sleep=sleep,
    )
    if reconciliation.outcome is ReconciliationOutcome.MERGED:
        assert reconciliation.receipt is not None
        if wal is not None:
            wal.transition(
                PublicationWALState.COMPLETED,
                response_sha=response_sha,
                receipt=reconciliation.receipt,
            )
        return reconciliation.receipt
    if reconciliation.outcome is ReconciliationOutcome.NOT_MERGED_RETRY_SAFE:
        assert check_id is not None
        fail_immutable_check(api, repository, check_id)
        if wal is not None:
            wal.transition(PublicationWALState.RETRY_SAFE)
        raise MergeRetrySafeError(
            "squash merge definitively did not complete; a new transaction is retry-safe"
        )
    raise MergeReconciliationInconclusive(
        "squash merge outcome is inconclusive; it may have succeeded and must not be retried"
    )


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    raw = _canonical_json_bytes(payload) + b"\n"
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.tmp-", dir=path.parent
    )
    temporary_path = Path(temporary)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise OSError("short JSON write")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary_path, path)
        directory = os.open(
            path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary_path.unlink()
        except OSError:
            pass
        raise MergeTransactionError("transaction JSON cannot be published") from exc
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary_path.unlink()
        except OSError:
            pass
        raise


def _api() -> GitHubAPI:
    return GitHubAPI(
        os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        os.environ.get("GH_TOKEN", ""),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the trusted App merge transaction."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    resolve = subparsers.add_parser("resolve")
    resolve.add_argument("--repository", required=True)
    resolve.add_argument("--pull-request", type=int, required=True)
    resolve.add_argument("--workflow-oid", required=True)
    resolve.add_argument("--output", type=Path, required=True)
    resolve.add_argument("--github-output", type=Path, required=True)

    transact = subparsers.add_parser("transact")
    transact.add_argument("--repository", required=True)
    transact.add_argument("--pull-request", type=int, required=True)
    transact.add_argument("--binding", type=Path, required=True)
    transact.add_argument("--plan", type=Path, required=True)
    transact.add_argument("--app-id", type=int, required=True)
    transact.add_argument("--app-slug", required=True)
    transact.add_argument("--details-url", required=True)
    transact.add_argument("--wal", type=Path, required=True)
    transact.add_argument("--receipt", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "resolve":
            binding = resolve_candidate(
                _api(), args.repository, args.pull_request, args.workflow_oid
            )
            _write_json(args.output, binding.as_dict())
            with args.github_output.open("a", encoding="utf-8") as stream:
                stream.write(f"base_oid={binding.base_oid}\n")
                stream.write(f"head_oid={binding.head_oid}\n")
                stream.write(f"replay={'true' if binding.replay else 'false'}\n")
            print("immutable candidate binding resolved")
            return 0
        receipt = run_transaction(
            _api(),
            args.repository,
            args.pull_request,
            load_binding(args.binding),
            load_plan(args.plan),
            args.app_id,
            args.app_slug,
            args.details_url,
            wal_path=args.wal,
        )
        _write_json(args.receipt, receipt.as_dict())
        print(f"trusted App squash merge reconciled at {receipt.merge_oid}")
        return 0
    except MergeTransactionError as exc:
        print(str(exc), file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
