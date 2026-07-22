from __future__ import annotations

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from typing import Any
from unittest import mock

from scripts import retrospective_history_git_v2 as git_contract
from scripts import retrospective_history_merge_v2 as merge_contract


REPOSITORY = "Joey-Tools/history-fixture"
PULL_REQUEST_NUMBER = 7
APP_ID = 4242
APP_SLUG = "retrospective-history-merge"
BASE_OID = "a" * 40
HEAD_OID = "b" * 40
HEAD_TREE_OID = "c" * 40
BASE_TREE_OID = "d" * 40
MERGE_OID = "e" * 40
RACED_BASE_OID = "f" * 40
RACED_HEAD_OID = "1" * 40
SUBJECT = "Administer session retrospective history v2: update policy"


def trust_entries() -> list[tuple[str, str, str, str]]:
    return [
        (
            path.decode("ascii"),
            "100644",
            "blob",
            hashlib.sha1(path, usedforsecurity=False).hexdigest(),
        )
        for path in sorted(git_contract.V2_TRUST_ROOT_PATHS)
    ]


def merge_plan() -> merge_contract.MergePlan:
    return merge_contract.MergePlan(
        base_oid=BASE_OID,
        head_oid=HEAD_OID,
        head_tree_oid=HEAD_TREE_OID,
        squash_subject=SUBJECT,
        trust_generation=git_contract.trust_generation_from_entries(trust_entries()),
    )


class FakeAPI:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []
        self.pull_state = "open"
        self.pull_merged = False
        self.pull_base = BASE_OID
        self.pull_head = HEAD_OID
        self.pull_title = "arbitrary display title"
        self.pull_draft = True
        self.merge_oid: str | None = None
        self.merged_by = {"type": "Bot", "login": f"{APP_SLUG}[bot]"}
        self.master_oid = BASE_OID
        self.merge_behavior = "success"
        self.protection_users: list[dict[str, Any]] = []
        self.protection_apps = [{"id": APP_ID, "slug": APP_SLUG}]
        self.active_rules: list[dict[str, Any]] = []
        self.tree_reads = 0
        self.mutate_display_metadata_between_reads = False
        self.mutate_trust_generation_on_second_read = False
        self.merge_requested = False
        self.reconcile_pull_reads = 0
        self.delayed_visibility_after = 3
        self.check_runs: list[dict[str, Any]] = []
        self.next_check_id = 101
        self.crash_after_authorize = False
        self.inject_competing_check_on_post = False
        self.inject_competing_check_on_success = False

    def pull_payload(self) -> dict[str, Any]:
        payload = {
            "number": PULL_REQUEST_NUMBER,
            "state": self.pull_state,
            "merged": self.pull_merged,
            "merge_commit_sha": self.merge_oid,
            "merged_by": self.merged_by if self.pull_merged else None,
            "title": self.pull_title,
            "draft": self.pull_draft,
            "base": {
                "sha": self.pull_base,
                "ref": "master",
                "repo": {"full_name": REPOSITORY},
            },
            "head": {"sha": self.pull_head},
        }
        if self.mutate_display_metadata_between_reads:
            self.pull_title = f"edited display title {len(self.calls)}"
            self.pull_draft = not self.pull_draft
        return payload

    def protection_payload(self) -> dict[str, Any]:
        return {
            "required_status_checks": {
                "strict": True,
                "checks": [{"context": merge_contract.CHECK_NAME, "app_id": APP_ID}],
            },
            "enforce_admins": {"enabled": True},
            "required_linear_history": {"enabled": True},
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False},
            "required_pull_request_reviews": None,
            "restrictions": {
                "users": self.protection_users,
                "teams": [],
                "apps": self.protection_apps,
            },
        }

    def apply_merge(self, *, actor: dict[str, str] | None = None) -> None:
        self.pull_state = "closed"
        self.pull_merged = True
        self.merge_oid = MERGE_OID
        self.master_oid = MERGE_OID
        if actor is not None:
            self.merged_by = actor

    def request(
        self,
        method: str,
        endpoint: str,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        self.calls.append((method, endpoint, payload))
        if method == "GET" and endpoint.endswith(f"/pulls/{PULL_REQUEST_NUMBER}"):
            if self.merge_requested:
                self.reconcile_pull_reads += 1
                if (
                    self.merge_behavior == "delayed_visibility"
                    and self.reconcile_pull_reads >= self.delayed_visibility_after
                    and not self.pull_merged
                ):
                    self.apply_merge()
            return self.pull_payload()
        if method == "GET" and endpoint.endswith("/branches/master/protection"):
            return self.protection_payload()
        if method == "GET" and endpoint.endswith("/rules/branches/master"):
            return self.active_rules
        if method == "GET" and endpoint.endswith("/git/ref/heads/master"):
            return {"object": {"type": "commit", "sha": self.master_oid}}
        if (
            method == "GET"
            and "/commits/" in endpoint
            and "/check-runs?" in endpoint
        ):
            return {
                "total_count": len(self.check_runs),
                "check_runs": [dict(check) for check in self.check_runs],
            }
        if method == "GET" and "/check-runs/" in endpoint:
            check_id = int(endpoint.rsplit("/", 1)[1])
            return dict(self._check_run(check_id))
        if method == "GET" and "/git/commits/" in endpoint:
            oid = endpoint.rsplit("/", 1)[1]
            if oid == BASE_OID:
                return {
                    "sha": BASE_OID,
                    "tree": {"sha": BASE_TREE_OID},
                    "parents": [{"sha": "0" * 40}],
                    "message": "trusted base",
                }
            if oid == HEAD_OID:
                return {
                    "sha": HEAD_OID,
                    "tree": {"sha": HEAD_TREE_OID},
                    "parents": [{"sha": BASE_OID}],
                    "message": SUBJECT,
                }
            if oid == MERGE_OID:
                return {
                    "sha": MERGE_OID,
                    "tree": {"sha": HEAD_TREE_OID},
                    "parents": [{"sha": BASE_OID}],
                    "message": SUBJECT,
                }
        if method == "GET" and "/git/trees/" in endpoint:
            self.tree_reads += 1
            entries = trust_entries()
            if self.mutate_trust_generation_on_second_read and self.tree_reads >= 2:
                path, mode, object_type, _object_id = entries[0]
                entries[0] = (path, mode, object_type, "9" * 40)
            return {
                "sha": BASE_TREE_OID,
                "truncated": False,
                "tree": [
                    {"path": path, "mode": mode, "type": kind, "sha": oid}
                    for path, mode, kind, oid in entries
                ],
            }
        if method == "POST" and endpoint.endswith("/check-runs"):
            assert payload is not None
            check = {
                "id": self.next_check_id,
                "name": payload["name"],
                "head_sha": payload["head_sha"],
                "external_id": payload["external_id"],
                "details_url": payload["details_url"],
                "status": payload["status"],
                "conclusion": None,
                "output": payload["output"],
                "app": {"id": APP_ID, "slug": APP_SLUG},
            }
            self.next_check_id += 1
            self.check_runs.insert(0, check)
            if self.inject_competing_check_on_post:
                self.inject_competing_check_on_post = False
                self._add_competing_check(check)
            return dict(check)
        if method == "PATCH" and "/check-runs/" in endpoint:
            assert payload is not None
            check_id = int(endpoint.rsplit("/", 1)[1])
            check = self._check_run(check_id)
            check.update(payload)
            if (
                payload.get("conclusion") == "success"
                and self.inject_competing_check_on_success
            ):
                self.inject_competing_check_on_success = False
                self._add_competing_check(check)
            if payload.get("conclusion") == "success" and self.crash_after_authorize:
                self.crash_after_authorize = False
                raise KeyboardInterrupt("simulated crash after durable merge intent")
            return dict(check)
        if method == "PUT" and endpoint.endswith(f"/pulls/{PULL_REQUEST_NUMBER}/merge"):
            self.merge_requested = True
            if self.merge_behavior == "head_race":
                self.pull_head = RACED_HEAD_OID
                raise merge_contract.MergeTransactionError("head CAS rejected")
            if self.merge_behavior == "base_race":
                self.pull_base = RACED_BASE_OID
                self.master_oid = RACED_BASE_OID
                raise merge_contract.MergeTransactionError("strict base CAS rejected")
            if self.merge_behavior == "rejected":
                return {"merged": False, "message": "candidate was not merged"}
            if self.merge_behavior in {"delayed_visibility", "never_visible"}:
                raise merge_contract.MergeTransactionError("merge response was lost")
            self.apply_merge()
            if self.merge_behavior == "crash_after_put":
                raise KeyboardInterrupt("simulated crash after merge side effect")
            if self.merge_behavior == "lost_response":
                raise merge_contract.MergeTransactionError("merge response was lost")
            return {"merged": True, "sha": MERGE_OID}
        if method == "GET" and "/compare/" in endpoint:
            return {
                "status": "ahead",
                "merge_base_commit": {"sha": MERGE_OID},
            }
        raise AssertionError(f"unexpected API call: {method} {endpoint}")

    def _check_run(self, check_id: int) -> dict[str, Any]:
        for check in self.check_runs:
            if check["id"] == check_id:
                return check
        raise AssertionError(f"unknown check run: {check_id}")

    def _add_competing_check(
        self, template: dict[str, Any]
    ) -> dict[str, Any]:
        competitor = {
            **template,
            "id": self.next_check_id,
            "status": "in_progress",
            "conclusion": None,
            "output": dict(template["output"]),
            "app": dict(template["app"]),
        }
        self.next_check_id += 1
        self.check_runs.insert(0, competitor)
        return competitor


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, delay: float) -> None:
        self.sleeps.append(delay)
        self.now += delay


def run_transaction(
    api: FakeAPI,
    *,
    clock: FakeClock | None = None,
    wal_path: Path | None = None,
) -> merge_contract.MergeReceipt:
    timing = (
        {} if clock is None else {"monotonic": clock.monotonic, "sleep": clock.sleep}
    )
    return merge_contract.run_transaction(
        api,
        REPOSITORY,
        PULL_REQUEST_NUMBER,
        merge_contract.CandidateBinding(BASE_OID, HEAD_OID, False),
        merge_plan(),
        APP_ID,
        APP_SLUG,
        "https://github.example.invalid/actions/runs/1",
        wal_path=wal_path,
        **timing,
    )


def wal_states(path: Path) -> list[str]:
    return [
        json.loads(record.read_text(encoding="ascii"))["state"]
        for record in sorted(path.glob("*.json"))
    ]


class RetrospectiveHistoryMergeV2Tests(unittest.TestCase):
    def test_title_and_draft_edits_before_runner_start_are_informational(self) -> None:
        first = FakeAPI()
        first.pull_title = "first mutable title"
        first.pull_draft = True
        second = FakeAPI()
        second.pull_title = "second mutable title"
        second.pull_draft = False

        first_binding = merge_contract.resolve_candidate(
            first, REPOSITORY, PULL_REQUEST_NUMBER, BASE_OID
        )
        second_binding = merge_contract.resolve_candidate(
            second, REPOSITORY, PULL_REQUEST_NUMBER, BASE_OID
        )

        self.assertEqual(first_binding, second_binding)
        self.assertEqual(
            first_binding, merge_contract.CandidateBinding(BASE_OID, HEAD_OID, False)
        )

    def test_title_and_draft_edits_between_validation_and_merge_do_not_authorize(
        self,
    ) -> None:
        api = FakeAPI()
        api.mutate_display_metadata_between_reads = True

        receipt = run_transaction(api)

        merge_call = next(call for call in api.calls if call[0] == "PUT")
        self.assertEqual(
            merge_call[2],
            {
                "commit_title": SUBJECT,
                "commit_message": "",
                "merge_method": "squash",
                "sha": HEAD_OID,
            },
        )
        self.assertEqual(receipt.squash_subject, SUBJECT)

    def test_lost_merge_response_and_replay_reconcile_one_exact_commit(self) -> None:
        api = FakeAPI()
        api.merge_behavior = "lost_response"

        first_receipt = run_transaction(api)
        puts_after_first = sum(
            method == "PUT" for method, _endpoint, _body in api.calls
        )
        replay_receipt = merge_contract.run_transaction(
            api,
            REPOSITORY,
            PULL_REQUEST_NUMBER,
            merge_contract.CandidateBinding(BASE_OID, HEAD_OID, True),
            merge_plan(),
            APP_ID,
            APP_SLUG,
            "https://github.example.invalid/actions/runs/1",
        )

        self.assertEqual(first_receipt.merge_oid, MERGE_OID)
        self.assertEqual(replay_receipt, first_receipt)
        self.assertEqual(
            sum(method == "PUT" for method, _endpoint, _body in api.calls),
            puts_after_first,
        )

    def test_delayed_merge_visibility_is_reconciled_without_a_second_put(self) -> None:
        api = FakeAPI()
        api.merge_behavior = "delayed_visibility"
        api.delayed_visibility_after = 3
        clock = FakeClock()

        first_receipt = run_transaction(api, clock=clock)
        puts_after_first = sum(
            method == "PUT" for method, _endpoint, _body in api.calls
        )
        replay_receipt = merge_contract.run_transaction(
            api,
            REPOSITORY,
            PULL_REQUEST_NUMBER,
            merge_contract.CandidateBinding(BASE_OID, HEAD_OID, True),
            merge_plan(),
            APP_ID,
            APP_SLUG,
            "https://github.example.invalid/actions/runs/1",
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )

        self.assertEqual(first_receipt.merge_oid, MERGE_OID)
        self.assertEqual(replay_receipt, first_receipt)
        self.assertEqual(api.reconcile_pull_reads, 4)
        self.assertEqual(clock.sleeps, [0.25, 0.5])
        self.assertEqual(
            sum(method == "PUT" for method, _endpoint, _body in api.calls),
            puts_after_first,
        )

    def test_successful_transaction_persists_terminal_wal_and_replays_read_only(
        self,
    ) -> None:
        api = FakeAPI()
        with TemporaryDirectory() as temporary:
            wal_path = Path(temporary) / "publication-wal"

            receipt = run_transaction(api, wal_path=wal_path)
            replay = run_transaction(api, wal_path=wal_path)

            self.assertEqual(
                wal_states(wal_path),
                ["prepared", "check_created", "merge_intent", "completed"],
            )

        self.assertEqual(replay, receipt)
        self.assertEqual(
            sum(method == "PUT" for method, _endpoint, _body in api.calls), 1
        )

    def test_competing_check_after_post_fails_closed_before_merge(self) -> None:
        api = FakeAPI()
        api.inject_competing_check_on_post = True
        with TemporaryDirectory() as temporary:
            first_wal = Path(temporary) / "first-publication-wal"
            second_wal = Path(temporary) / "second-publication-wal"

            with self.assertRaisesRegex(
                merge_contract.MergeTransactionError,
                "multiple active publication checks",
            ):
                run_transaction(api, wal_path=first_wal)
            self.assertEqual(wal_states(first_wal)[-1], "aborted_before_intent")
            self.assertEqual(
                sum(method == "PUT" for method, _endpoint, _body in api.calls), 0
            )

            receipt = run_transaction(api, wal_path=second_wal)

        self.assertEqual(receipt.merge_oid, MERGE_OID)
        self.assertEqual(
            sum(method == "PUT" for method, _endpoint, _body in api.calls), 1
        )

    def test_competing_check_after_intent_fails_closed_before_merge(self) -> None:
        api = FakeAPI()
        api.inject_competing_check_on_success = True
        with TemporaryDirectory() as temporary:
            first_wal = Path(temporary) / "first-publication-wal"
            second_wal = Path(temporary) / "second-publication-wal"

            with self.assertRaisesRegex(
                merge_contract.MergeTransactionError,
                "multiple active publication checks",
            ):
                run_transaction(api, wal_path=first_wal)
            self.assertEqual(wal_states(first_wal)[-1], "aborted_before_intent")
            self.assertEqual(
                sum(method == "PUT" for method, _endpoint, _body in api.calls), 0
            )

            receipt = run_transaction(api, wal_path=second_wal)

        self.assertEqual(receipt.merge_oid, MERGE_OID)
        self.assertEqual(
            sum(method == "PUT" for method, _endpoint, _body in api.calls), 1
        )

    def test_independent_double_invocation_reconciles_without_second_merge(self) -> None:
        api = FakeAPI()
        with TemporaryDirectory() as temporary:
            first_receipt = run_transaction(
                api, wal_path=Path(temporary) / "first-publication-wal"
            )
            second_receipt = run_transaction(
                api, wal_path=Path(temporary) / "second-publication-wal"
            )

        self.assertEqual(second_receipt, first_receipt)
        self.assertEqual(
            sum(method == "PUT" for method, _endpoint, _body in api.calls), 1
        )

    def test_crash_after_remote_intent_recovers_without_merge_retry(self) -> None:
        api = FakeAPI()
        api.crash_after_authorize = True
        with TemporaryDirectory() as temporary:
            wal_path = Path(temporary) / "publication-wal"
            recovered_wal_path = Path(temporary) / "recovered-publication-wal"

            with self.assertRaisesRegex(
                KeyboardInterrupt, "durable merge intent"
            ):
                run_transaction(api, wal_path=wal_path)
            self.assertEqual(
                wal_states(wal_path), ["prepared", "check_created"]
            )

            with self.assertRaises(merge_contract.MergeReconciliationInconclusive):
                run_transaction(
                    api, wal_path=recovered_wal_path, clock=FakeClock()
                )
            self.assertEqual(
                wal_states(recovered_wal_path),
                ["prepared", "check_created", "merge_intent"],
            )

        self.assertEqual(
            sum(method == "PUT" for method, _endpoint, _body in api.calls), 0
        )

    def test_crash_after_merge_side_effect_reconciles_without_second_put(self) -> None:
        api = FakeAPI()
        api.merge_behavior = "crash_after_put"
        with TemporaryDirectory() as temporary:
            wal_path = Path(temporary) / "publication-wal"

            with self.assertRaisesRegex(KeyboardInterrupt, "merge side effect"):
                run_transaction(api, wal_path=wal_path)
            self.assertEqual(
                wal_states(wal_path),
                ["prepared", "check_created", "merge_intent"],
            )

            receipt = run_transaction(api, wal_path=wal_path)
            self.assertEqual(wal_states(wal_path)[-1], "completed")

        self.assertEqual(receipt.merge_oid, MERGE_OID)
        self.assertEqual(
            sum(method == "PUT" for method, _endpoint, _body in api.calls), 1
        )

    def test_inconclusive_merge_recovery_never_reissues_put(self) -> None:
        api = FakeAPI()
        api.merge_behavior = "never_visible"
        with TemporaryDirectory() as temporary:
            wal_path = Path(temporary) / "publication-wal"

            with self.assertRaises(merge_contract.MergeReconciliationInconclusive):
                run_transaction(api, wal_path=wal_path, clock=FakeClock())
            with self.assertRaises(merge_contract.MergeReconciliationInconclusive):
                run_transaction(api, wal_path=wal_path, clock=FakeClock())

            self.assertEqual(wal_states(wal_path)[-1], "merge_intent")

        self.assertEqual(
            sum(method == "PUT" for method, _endpoint, _body in api.calls), 1
        )

    def test_truncated_wal_record_is_rejected_before_recovery(self) -> None:
        plan = merge_plan()
        scope = merge_contract._wal_scope(
            REPOSITORY, PULL_REQUEST_NUMBER, plan, APP_ID, APP_SLUG
        )
        with TemporaryDirectory() as temporary:
            wal_path = Path(temporary) / "publication-wal"
            merge_contract.PublicationWAL(wal_path, scope)
            record = wal_path / "00000000.json"
            record.write_bytes(record.read_bytes()[:-1])

            with self.assertRaisesRegex(
                merge_contract.MergeTransactionError, "incomplete"
            ):
                merge_contract.PublicationWAL(wal_path, scope)

    def test_wal_generation_zero_must_be_prepared(self) -> None:
        plan = merge_plan()
        scope = merge_contract._wal_scope(
            REPOSITORY, PULL_REQUEST_NUMBER, plan, APP_ID, APP_SLUG
        )
        with TemporaryDirectory() as temporary:
            wal_path = Path(temporary) / "publication-wal"
            merge_contract.PublicationWAL(wal_path, scope)
            record = wal_path / "00000000.json"
            payload = json.loads(record.read_text(encoding="ascii"))
            payload["state"] = "check_created"
            payload["check_id"] = 101
            payload["record_digest"] = merge_contract._wal_record_digest(payload)
            record.write_bytes(merge_contract._canonical_json_bytes(payload) + b"\n")

            with self.assertRaisesRegex(
                merge_contract.MergeTransactionError,
                "generation zero must be prepared",
            ):
                merge_contract.PublicationWAL(wal_path, scope)

    def test_uncertain_merge_times_out_inconclusively_without_revoking_check(
        self,
    ) -> None:
        api = FakeAPI()
        api.merge_behavior = "never_visible"
        clock = FakeClock()

        with self.assertRaisesRegex(
            merge_contract.MergeReconciliationInconclusive,
            "may have succeeded",
        ):
            run_transaction(api, clock=clock)

        self.assertEqual(api.reconcile_pull_reads, 6)
        self.assertEqual(
            clock.sleeps,
            list(merge_contract.RECONCILE_BACKOFF_SECONDS),
        )
        self.assertLessEqual(clock.now, merge_contract.RECONCILE_DEADLINE_SECONDS)
        self.assertEqual(
            sum(method == "PUT" for method, _endpoint, _body in api.calls), 1
        )
        self.assertFalse(
            any(
                method == "PATCH"
                and body is not None
                and body.get("conclusion") == "failure"
                for method, _endpoint, body in api.calls
            )
        )

    def test_reconciliation_deadline_bounds_uncertain_visibility(self) -> None:
        api = FakeAPI()
        api.merge_behavior = "never_visible"
        clock = FakeClock()

        with (
            mock.patch.object(merge_contract, "RECONCILE_DEADLINE_SECONDS", 0.6),
            self.assertRaises(merge_contract.MergeReconciliationInconclusive),
        ):
            run_transaction(api, clock=clock)

        self.assertEqual(api.reconcile_pull_reads, 3)
        self.assertEqual(len(clock.sleeps), 2)
        self.assertEqual(clock.sleeps[0], 0.25)
        self.assertAlmostEqual(clock.sleeps[1], 0.35)
        self.assertAlmostEqual(clock.now, 0.6)
        self.assertEqual(
            sum(method == "PUT" for method, _endpoint, _body in api.calls), 1
        )
        self.assertFalse(
            any(
                method == "PATCH"
                and body is not None
                and body.get("conclusion") == "failure"
                for method, _endpoint, body in api.calls
            )
        )

    def test_explicit_merge_rejection_is_retry_safe_and_revokes_check(self) -> None:
        api = FakeAPI()
        api.merge_behavior = "rejected"
        clock = FakeClock()

        with self.assertRaisesRegex(merge_contract.MergeRetrySafeError, "retry-safe"):
            run_transaction(api, clock=clock)

        self.assertEqual(api.reconcile_pull_reads, 1)
        self.assertEqual(clock.sleeps, [])
        self.assertEqual(
            sum(method == "PUT" for method, _endpoint, _body in api.calls), 1
        )
        self.assertTrue(
            any(method == "PATCH" for method, _endpoint, _body in api.calls)
        )

    def test_head_and_base_races_fail_closed_and_revoke_check(self) -> None:
        for behavior in ("head_race", "base_race"):
            with self.subTest(behavior=behavior):
                api = FakeAPI()
                api.merge_behavior = behavior

                with self.assertRaises(merge_contract.MergeRetrySafeError):
                    run_transaction(api)

                failed_checks = [
                    body
                    for method, endpoint, body in api.calls
                    if method == "PATCH" and endpoint.endswith("/check-runs/101")
                ]
                self.assertEqual(failed_checks[-1]["conclusion"], "failure")
                self.assertFalse(api.pull_merged)

    def test_trust_generation_race_fails_before_merge_call(self) -> None:
        api = FakeAPI()
        api.mutate_trust_generation_on_second_read = True

        with self.assertRaisesRegex(
            merge_contract.MergeTransactionError, "trusted base generation"
        ):
            run_transaction(api)

        self.assertFalse(any(method == "PUT" for method, _endpoint, _body in api.calls))
        self.assertTrue(
            any(method == "PATCH" for method, _endpoint, _body in api.calls)
        )

    def test_direct_human_merge_or_human_branch_access_is_rejected(self) -> None:
        human_merge = FakeAPI()
        human_merge.apply_merge(actor={"type": "User", "login": "octocat"})
        with self.assertRaisesRegex(
            merge_contract.MergeTransactionError, "trusted App"
        ):
            merge_contract.run_transaction(
                human_merge,
                REPOSITORY,
                PULL_REQUEST_NUMBER,
                merge_contract.CandidateBinding(BASE_OID, HEAD_OID, True),
                merge_plan(),
                APP_ID,
                APP_SLUG,
                "https://github.example.invalid/actions/runs/1",
            )

        human_bypass = FakeAPI()
        human_bypass.protection_users = [{"id": 1, "login": "octocat"}]
        with self.assertRaisesRegex(
            merge_contract.MergeTransactionError, "restricted to one App"
        ):
            run_transaction(human_bypass)
        self.assertFalse(
            any(
                method in {"POST", "PUT"}
                for method, _endpoint, _body in human_bypass.calls
            )
        )

    def test_active_ruleset_bypass_is_rejected_before_success_check(self) -> None:
        api = FakeAPI()
        api.active_rules = [
            {
                "type": "required_status_checks",
                "ruleset_source_type": "Organization",
                "ruleset_source": "Joey-Tools",
                "ruleset_id": 73,
            }
        ]

        with self.assertRaisesRegex(
            merge_contract.MergeTransactionError, "active rulesets"
        ):
            run_transaction(api)

        self.assertFalse(
            any(method in {"POST", "PUT"} for method, _endpoint, _body in api.calls)
        )

    def test_result_binds_exact_squash_subject_tree_parent_and_actor(self) -> None:
        api = FakeAPI()

        receipt = run_transaction(api)

        rules_reads = [
            index
            for index, (method, endpoint, _body) in enumerate(api.calls)
            if method == "GET" and endpoint.endswith("/rules/branches/master")
        ]
        check_write = next(
            index
            for index, (method, endpoint, _body) in enumerate(api.calls)
            if method == "POST" and endpoint.endswith("/check-runs")
        )
        merge_write = next(
            index
            for index, (method, endpoint, _body) in enumerate(api.calls)
            if method == "PUT"
            and endpoint.endswith(f"/pulls/{PULL_REQUEST_NUMBER}/merge")
        )
        self.assertEqual(len(rules_reads), 2)
        self.assertLess(rules_reads[0], check_write)
        self.assertLess(check_write, rules_reads[1])
        self.assertLess(rules_reads[1], merge_write)

        self.assertEqual(receipt.base_oid, BASE_OID)
        self.assertEqual(receipt.head_oid, HEAD_OID)
        self.assertEqual(receipt.merge_oid, MERGE_OID)
        self.assertEqual(receipt.master_oid, MERGE_OID)
        self.assertEqual(receipt.tree_oid, HEAD_TREE_OID)
        self.assertEqual(receipt.squash_subject, SUBJECT)
        merge_commit = api.request(
            "GET", f"/repos/{REPOSITORY}/git/commits/{MERGE_OID}"
        )
        self.assertEqual(merge_commit["parents"], [{"sha": BASE_OID}])
        self.assertEqual(merge_commit["tree"], {"sha": HEAD_TREE_OID})
        self.assertEqual(merge_commit["message"], SUBJECT)


if __name__ == "__main__":
    unittest.main()
