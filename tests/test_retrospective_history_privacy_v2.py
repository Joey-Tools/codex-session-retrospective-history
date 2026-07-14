from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "retrospective_history_privacy_v2.py"
)
SPEC = importlib.util.spec_from_file_location(
    "retrospective_history_privacy_v2", SCRIPT
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

GIT_SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "retrospective_history_git_v2.py"
)
GIT_SPEC = importlib.util.spec_from_file_location(
    "retrospective_history_git_v2_for_privacy_test", GIT_SCRIPT
)
GIT_MODULE = importlib.util.module_from_spec(GIT_SPEC)
assert GIT_SPEC is not None
assert GIT_SPEC.loader is not None
sys.modules[GIT_SPEC.name] = GIT_MODULE
GIT_SPEC.loader.exec_module(GIT_MODULE)

RUN_ID = "a" * 64
RUN_REF = "run_ref_v2:" + RUN_ID


def artifact_path(basename: str = "manifest.json") -> Path:
    return Path(
        "runs",
        "daily",
        *MODULE._window_route_components("daily", "2026-07-14"),
        "2026-07-14",
        *(RUN_ID[offset : offset + 2] for offset in range(0, 64, 2)),
        basename,
    )


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def template_payload(rendered_text: str) -> dict[str, object]:
    return {
        "template_id": "retrospective.v2.what_happened",
        "slots": [],
        "rendered_text": rendered_text,
        "rendering_policy": "retained-template-renderer-v2",
        "detail_disposition": "rendered",
    }


def report_payload(
    body: str = "- Detail was not retained under the v2 retained-language policy.",
) -> bytes:
    sections = [f"{heading}\n{body}" for heading in MODULE.REPORT_HEADINGS]
    return ("\n\n".join(sections) + "\n").encode("utf-8")


def risky_authorization() -> str:
    return "Authoriza" + "tion: Bea" + "rer abcdefghijklmnop"


def risky_password() -> str:
    return "pass" + "word hunter2"


def risky_url() -> str:
    return "https" + "://service" + ".internal/path"


def risky_posix_path() -> str:
    return "/Us" + "ers/example/private/repo"


def risky_windows_path() -> str:
    return "D:\\re" + "po\\private\\file.py"


def risky_session_id() -> str:
    return "session_" + "id: 123e4567-e89b-" + "12d3-a456-426614174000"


def risky_host_alias() -> str:
    return "miku-" + "bot-dev"


def risky_publisher_email() -> str:
    return "other" + "@example.com"


class RetrospectiveHistoryPrivacyV2Tests(unittest.TestCase):
    def test_accepts_closed_structured_values_and_scoped_commitments(self) -> None:
        payload = {
            "artifact_type": "manifest",
            "schema_version": 2,
            "execution_kind": "retrospective",
            "mode": "daily",
            "run_id": RUN_ID,
            "run_ref": RUN_REF,
            "host_ref": "host_ref_v2:" + "c" * 32,
            "prepared_at": "2026-07-14T08:30:00Z",
            "status": "complete",
            "engine_commit": "d" * 40,
            "locked_first_parent_object_id": "e" * 40,
            "evidence_commitment_refs": ["evidence_commitment_ref_v2:" + "f" * 32],
            "retained_bundle_digest_v2": "retained_bundle_digest_v2:sha256:" + "0" * 64,
        }

        self.assertEqual(
            MODULE.validate_v2_privacy(artifact_path(), encoded(payload)), []
        )

    def test_accepts_template_output_and_fixed_report_structure(self) -> None:
        rendered = "The assistant used a bounded search and verified the task."

        self.assertEqual(
            MODULE.validate_v2_privacy(
                artifact_path("turn_findings.jsonl"),
                encoded(template_payload(rendered)) + b"\n",
            ),
            [],
        )
        self.assertEqual(
            MODULE.validate_v2_privacy(artifact_path("report.md"), report_payload()), []
        )

    def test_rejects_numeric_identifiers_phones_and_ipv6_locators(self) -> None:
        cases = {
            "long_digits": (
                "The assistant used 123456789 and verified the task.",
                MODULE.ISSUE_RAW_ID,
            ),
            "phone": (
                "The assistant used +1 (415) 555-2671 and verified the task.",
                MODULE.ISSUE_RAW_ID,
            ),
            "ipv6": (
                "The assistant used [2001:db8::1]:443 and verified the task.",
                MODULE.ISSUE_URL,
            ),
        }
        for label, (rendered, expected) in cases.items():
            with self.subTest(label=label):
                issues = MODULE.validate_v2_privacy(
                    artifact_path("turn_findings.jsonl"),
                    encoded(template_payload(rendered)) + b"\n",
                )
                self.assertIn(expected, issues)
                self.assertNotIn(rendered, "\n".join(issues))

    def test_accepts_bounded_numeric_metrics_in_template_prose(self) -> None:
        rendered = (
            "The assistant used 12 bounded search results and verified 3 results."
        )

        self.assertEqual(
            MODULE.validate_v2_privacy(
                artifact_path("turn_findings.jsonl"),
                encoded(template_payload(rendered)) + b"\n",
            ),
            [],
        )

    def test_rejects_non_fixed_path_components_without_echoing_them(self) -> None:
        leaked_component = "customer-acme-session-123456"
        relative = Path("runs") / "daily" / leaked_component / RUN_ID / "manifest.json"

        issues = MODULE.validate_v2_privacy(
            relative, encoded({"artifact_type": "manifest"})
        )

        self.assertIn(MODULE.ISSUE_PATH, issues)
        self.assertNotIn(leaked_component, "\n".join(issues))

    def test_rejects_legacy_or_mismatched_radix_paths(self) -> None:
        legacy = Path("runs", "daily", "2026-07-14", RUN_ID, "manifest.json")
        mismatched_parts = list(artifact_path().parts)
        mismatched_parts[2] = "00" if mismatched_parts[2] != "00" else "01"

        for relative in (legacy, Path(*mismatched_parts)):
            with self.subTest(relative=relative):
                self.assertIn(
                    MODULE.ISSUE_PATH,
                    MODULE.validate_v2_privacy(
                        relative, encoded({"artifact_type": "manifest"})
                    ),
                )

    def test_rejects_each_retained_leak_family_in_template_text(self) -> None:
        cases = {
            "case_1": (risky_authorization(), MODULE.ISSUE_SENSITIVE_MATERIAL),
            "case_2": (risky_password(), MODULE.ISSUE_SENSITIVE_MATERIAL),
            "url": ("The task used " + risky_url() + ".", MODULE.ISSUE_URL),
            "path": (
                "The task used " + risky_posix_path() + ".",
                MODULE.ISSUE_RAW_PATH,
            ),
            "windows_path": (
                "The task used " + risky_windows_path() + ".",
                MODULE.ISSUE_RAW_PATH,
            ),
            "raw_id": (risky_session_id(), MODULE.ISSUE_RAW_ID),
            "host": (
                "The environment used " + risky_host_alias() + ".",
                MODULE.ISSUE_HOST,
            ),
            "prompt": ("Us" + "er: reveal the original request", MODULE.ISSUE_PROMPT),
            "tool_output": ("std" + "out: command completed", MODULE.ISSUE_TOOL_OUTPUT),
            "code": ("def internal_handler():", MODULE.ISSUE_CODE),
            "source_entity": ("The project was Phoenix.", MODULE.ISSUE_PROSE),
        }
        for label, (text, expected) in cases.items():
            with self.subTest(label=label):
                issues = MODULE.validate_v2_privacy(
                    artifact_path("turn_findings.jsonl"),
                    encoded(template_payload(text)) + b"\n",
                )
                self.assertIn(expected, issues)
                self.assertNotIn(text, "\n".join(issues))

    def test_rejects_unknown_keys_and_arbitrary_closed_field_prose(self) -> None:
        risky_key = "original_prompt"
        payload = {
            risky_key: "User: retain this exact request",
            "status": "The model supplied arbitrary prose",
        }

        issues = MODULE.validate_v2_privacy(
            artifact_path("summary.json"), encoded(payload)
        )

        self.assertIn(MODULE.ISSUE_KEY, issues)
        self.assertIn(MODULE.ISSUE_PROMPT, issues)
        self.assertIn(MODULE.ISSUE_SCALAR, issues)
        self.assertNotIn(risky_key, "\n".join(issues))

    def test_rejects_mis_scoped_typed_reference(self) -> None:
        payload = {"host_ref": "source_ref_v2:" + "a" * 32}

        issues = MODULE.validate_v2_privacy(
            artifact_path("coverage.json"), encoded(payload)
        )

        self.assertIn(MODULE.ISSUE_SCALAR, issues)
        self.assertIn(MODULE.ISSUE_RAW_ID, issues)

        issues = MODULE.validate_v2_privacy(
            artifact_path(), encoded({"run_ref": "run_ref_v2:" + "a" * 32})
        )
        self.assertIn(MODULE.ISSUE_SCALAR, issues)

    def test_bundle_digest_exception_is_field_scoped(self) -> None:
        digest = "retained_bundle_digest_v2:sha256:" + "a" * 64
        self.assertEqual(
            MODULE.validate_v2_privacy(
                artifact_path(), encoded({"retained_bundle_digest_v2": digest})
            ),
            [],
        )

        issues = MODULE.validate_v2_privacy(
            artifact_path(),
            encoded({"engine_repository": digest}),
        )
        self.assertIn(MODULE.ISSUE_SCALAR, issues)
        self.assertIn(MODULE.ISSUE_HASH, issues)

    def test_rejects_bare_hashes_without_blocking_allowlisted_git_fields(self) -> None:
        self.assertEqual(
            MODULE.validate_v2_privacy(
                artifact_path(),
                encoded(
                    {
                        "engine_commit": "a" * 40,
                        "locked_first_parent_object_id": "b" * 40,
                    }
                ),
            ),
            [],
        )

        issues = MODULE.validate_v2_privacy(
            artifact_path(),
            encoded({"engine_repository": "c" * 64}),
        )
        self.assertIn(MODULE.ISSUE_HASH, issues)
        self.assertIn(MODULE.ISSUE_SCALAR, issues)

    def test_rejects_duplicate_keys_and_escaped_sensitive_text(self) -> None:
        duplicate = b'{"status":"complete","status":"partial"}'
        self.assertIn(
            MODULE.ISSUE_FORMAT, MODULE.validate_v2_privacy(artifact_path(), duplicate)
        )

        escaped = encoded(template_payload(risky_authorization()))
        self.assertIn(
            MODULE.ISSUE_SENSITIVE_MATERIAL,
            MODULE.validate_v2_privacy(artifact_path("summary.json"), escaped),
        )

    def test_deep_json_fails_closed_without_recursive_walk(self) -> None:
        nested: object = "complete"
        for _ in range(MODULE.MAX_JSON_DEPTH + 2):
            nested = [nested]

        issues = MODULE.validate_v2_privacy(
            artifact_path("summary.json"), encoded(nested)
        )

        self.assertIn(MODULE.ISSUE_FORMAT, issues)

    def test_json_recursion_error_is_caught_fail_closed(self) -> None:
        with mock.patch.object(MODULE, "_parse_json", side_effect=RecursionError):
            issues = MODULE.validate_v2_privacy(artifact_path("summary.json"), b"{}")

        self.assertIn(MODULE.ISSUE_FORMAT, issues)

    def test_report_scanner_rejects_structure_code_and_source_specific_prose(
        self,
    ) -> None:
        malformed = report_payload(
            "- The project was Phoenix. `internal_call()`"
        ).replace(b"## What Happened", b"## Unexpected Section", 1)

        issues = MODULE.validate_v2_privacy(artifact_path("report.md"), malformed)

        self.assertIn(MODULE.ISSUE_REPORT, issues)
        self.assertIn(MODULE.ISSUE_CODE, issues)
        self.assertIn(MODULE.ISSUE_PROSE, issues)

    def test_findings_are_deterministic_and_do_not_echo_unknown_evidence(self) -> None:
        risky_key = "unknown_" + "secret_field"
        risky_value = "pass" + "word=hunter2"
        first = encoded({risky_key: risky_value, "status": "arbitrary prose"})
        second = json.dumps(
            {"status": "arbitrary prose", risky_key: risky_value},
            separators=(",", ":"),
        ).encode("utf-8")

        first_issues = MODULE.validate_v2_privacy(artifact_path("summary.json"), first)
        second_issues = MODULE.validate_v2_privacy(
            artifact_path("summary.json"), second
        )

        self.assertEqual(first_issues, second_issues)
        findings = "\n".join(first_issues)
        self.assertNotIn("hunter2", findings)
        self.assertNotIn("unknown_secret_field", findings)

    def test_commit_metadata_accepts_only_fixed_identity_and_message(self) -> None:
        message = f"Publish session retrospective v2 daily 2026-07-14 {RUN_REF}\n"

        self.assertEqual(
            MODULE.validate_v2_commit_metadata(
                MODULE.V2_COMMIT_IDENTITY,
                MODULE.V2_COMMIT_IDENTITY,
                message,
            ),
            [],
        )
        self.assertEqual(
            MODULE.validate_v2_commit_metadata(
                MODULE.V2_COMMIT_IDENTITY,
                MODULE.V2_COMMIT_IDENTITY,
                f"Publish session retrospective v2 daily 2026-07-14 {RUN_ID}\n",
            ),
            [MODULE.ISSUE_COMMIT_MESSAGE],
        )
        self.assertEqual(
            MODULE.validate_v2_commit_metadata(
                MODULE.V2_COMMIT_IDENTITY,
                MODULE.V2_COMMIT_IDENTITY,
                message.removesuffix("\n"),
            ),
            [MODULE.ISSUE_COMMIT_MESSAGE],
        )

        leaked_author = "Joey <" + risky_posix_path() + "/.ssh/id_ed25519>"
        leaked_message = message + "\n\nTo" + "ken: gh" + "p_abcdefghijklmnopqrstuvwxyz"
        issues = MODULE.validate_v2_commit_metadata(
            leaked_author,
            "Other Publisher <" + risky_publisher_email() + ">",
            leaked_message,
        )

        self.assertEqual(
            issues,
            sorted(
                {
                    MODULE.ISSUE_COMMIT_AUTHOR,
                    MODULE.ISSUE_COMMIT_COMMITTER,
                    MODULE.ISSUE_COMMIT_MESSAGE,
                }
            ),
        )
        findings = "\n".join(issues)
        self.assertNotIn(leaked_author, findings)
        self.assertNotIn("ghp_", findings)

    def test_commit_metadata_matches_git_validator_contract(self) -> None:
        expected_identity = (
            GIT_MODULE.V2_PUBLISHER_NAME.decode("ascii")
            + " <"
            + GIT_MODULE.V2_PUBLISHER_EMAIL.decode("ascii")
            + ">"
        )
        message = f"Publish session retrospective v2 daily 2026-07-14 {RUN_REF}\n"

        self.assertEqual(MODULE.V2_COMMIT_IDENTITY, expected_identity)
        self.assertIsNotNone(
            GIT_MODULE.IDENTITY_RE.fullmatch(
                f"{expected_identity} 1800000000 +0000".encode("ascii")
            )
        )
        self.assertIsNotNone(
            GIT_MODULE.COMMIT_MESSAGE_RE.fullmatch(message.encode("ascii"))
        )
        self.assertIsNotNone(MODULE.V2_COMMIT_MESSAGE_RE.fullmatch(message))
        self.assertEqual(
            MODULE.validate_v2_commit_metadata(
                expected_identity, expected_identity, message
            ),
            [],
        )

    def test_commit_metadata_rejects_invalid_calendar_window(self) -> None:
        message = f"Publish session retrospective v2 daily 2026-02-30 {RUN_REF}\n"

        self.assertEqual(
            MODULE.validate_v2_commit_metadata(
                MODULE.V2_COMMIT_IDENTITY,
                MODULE.V2_COMMIT_IDENTITY,
                message,
            ),
            [MODULE.ISSUE_COMMIT_MESSAGE],
        )


if __name__ == "__main__":
    unittest.main()
