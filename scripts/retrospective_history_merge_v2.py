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
        "status": "completed",
        "conclusion": "success",
        "external_id": f"pr:{pull_request_number}:{digest}",
        "details_url": details_url,
        "output": {
            "title": "Immutable candidate validated",
            "summary": (
                f"The trusted App validated immutable candidate plan {digest}."
            ),
        },
    }
    response = _object(
        api.request("POST", f"/repos/{repository}/check-runs", payload),
        "check run",
    )
    check_id = response.get("id")
    if not isinstance(check_id, int) or check_id <= 0:
        raise MergeTransactionError("immutable candidate check has no identifier")
    return check_id


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
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> MergeReceipt:
    repository = _repository(repository)
    if (binding.base_oid, binding.head_oid) != (plan.base_oid, plan.head_oid):
        raise MergeTransactionError("candidate binding does not match the merge plan")
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
            return reconciliation.receipt
        if reconciliation.outcome is ReconciliationOutcome.NOT_MERGED_RETRY_SAFE:
            raise MergeRetrySafeError(
                "squash merge definitively did not complete; a new transaction is retry-safe"
            )
        raise MergeReconciliationInconclusive(
            "squash merge outcome is inconclusive; it may have succeeded and must not be retried"
        )

    check_id: int | None = None
    try:
        verify_merge_control(api, repository, expected_app_id, expected_app_slug)
        verify_current_candidate(api, repository, pull_request_number, plan)
        check_id = create_immutable_check(
            api, repository, pull_request_number, plan, details_url
        )

        # These are the last authorization reads before GitHub's head-SHA CAS merge.
        verify_merge_control(api, repository, expected_app_id, expected_app_slug)
        verify_current_candidate(api, repository, pull_request_number, plan)
    except MergeTransactionError:
        if check_id is not None:
            fail_immutable_check(api, repository, check_id)
        raise

    response_sha: str | None = None
    response_rejected = False
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
    except MergeTransactionError:
        pass

    try:
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
    except MergeTransactionError:
        assert check_id is not None
        fail_immutable_check(api, repository, check_id)
        raise
    if reconciliation.outcome is ReconciliationOutcome.MERGED:
        assert reconciliation.receipt is not None
        return reconciliation.receipt
    if reconciliation.outcome is ReconciliationOutcome.NOT_MERGED_RETRY_SAFE:
        assert check_id is not None
        fail_immutable_check(api, repository, check_id)
        raise MergeRetrySafeError(
            "squash merge definitively did not complete; a new transaction is retry-safe"
        )
    raise MergeReconciliationInconclusive(
        "squash merge outcome is inconclusive; it may have succeeded and must not be retried"
    )


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


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
        )
        _write_json(args.receipt, receipt.as_dict())
        print(f"trusted App squash merge reconciled at {receipt.merge_oid}")
        return 0
    except MergeTransactionError as exc:
        print(str(exc), file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
