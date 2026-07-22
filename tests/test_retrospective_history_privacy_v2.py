from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
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

RUN_ID = "a" * 25 + "e"
RUN_REF = "run_ref_v2:" + RUN_ID
PUBLISHER_FINGERPRINT = "40FA5D05AC7A3D5C180B037FF6DCF7A06FFC9C52"
CANONICAL_PUBLISHER_SIGNATURE = (
    "-----BEGIN PGP SIGNATURE-----\n\n"
    "wjQEAAEIAB0FAgAAAAEWIQRA+l0FrHo9XBgLA3/23Pegb/ycUgAKCRD23Pegb/yc\n"
    "UgAAAAEB\n"
    "=pLXK\n"
    "-----END PGP SIGNATURE-----"
)


def artifact_path(basename: str = "manifest.json") -> Path:
    return Path("runs", "daily", "2026-07-14", RUN_ID, basename)


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def template_payload(
    rendered_text: str, *, slots: list[dict[str, object]] | None = None
) -> dict[str, object]:
    return {
        "template_id": "retrospective.v2.what_happened",
        "slots": [] if slots is None else slots,
        "rendered_text": rendered_text,
        "rendering_policy": "retained-template-renderer-v2",
        "detail_disposition": "rendered",
    }


def report_payload(
    body: str = "- Detail was not retained under the v2 retained-language policy.",
) -> bytes:
    sections = [f"{heading}\n{body}" for heading in MODULE.REPORT_HEADINGS]
    return ("\n\n".join(sections) + "\n").encode("utf-8")


def privacy_bundle() -> dict[Path, bytes]:
    payloads = {
        "coverage.json": b"{}",
        "episodes.jsonl": b"",
        "manifest.json": b"{}",
        "report.md": report_payload(),
        "summary.json": b"{}",
        "topics.jsonl": b"",
        "trend_report.json": b"{}",
        "turn_findings.jsonl": b"",
    }
    return {artifact_path(basename): payload for basename, payload in payloads.items()}


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
    def test_complete_bundle_privacy_api_requires_one_canonical_inventory(self) -> None:
        bundle = privacy_bundle()
        self.assertEqual(MODULE.validate_v2_bundle_privacy(bundle), {})

        missing = dict(bundle)
        missing.pop(artifact_path("summary.json"))
        self.assertEqual(
            MODULE.validate_v2_bundle_privacy(missing),
            {"__bundle__": [MODULE.ISSUE_BUNDLE_INVENTORY]},
        )

        mixed_parent = dict(bundle)
        payload = mixed_parent.pop(artifact_path("summary.json"))
        mixed_parent[Path("runs", "daily", "2026-07-13", RUN_ID, "summary.json")] = payload
        self.assertEqual(
            MODULE.validate_v2_bundle_privacy(mixed_parent),
            {"__bundle__": [MODULE.ISSUE_BUNDLE_INVENTORY]},
        )

    def test_bundle_privacy_carries_detectors_across_retained_boundaries(self) -> None:
        fragments = ("Authoriza", "tion: Bearer abcdefghijklmnop")
        cases: dict[str, dict[Path, bytes]] = {}

        json_values = privacy_bundle()
        json_values[artifact_path("coverage.json")] = encoded(
            [{"rendered_text": fragment} for fragment in fragments]
        )
        cases["json-values"] = json_values

        jsonl_rows = privacy_bundle()
        jsonl_rows[artifact_path("episodes.jsonl")] = b"".join(
            encoded({"rendered_text": fragment}) + b"\n" for fragment in fragments
        )
        cases["jsonl-rows"] = jsonl_rows

        markdown_lines = privacy_bundle()
        markdown_lines[artifact_path("report.md")] = report_payload(
            "\n".join(fragments)
        )
        cases["markdown-lines"] = markdown_lines

        file_boundary = privacy_bundle()
        file_boundary[artifact_path("coverage.json")] = encoded(
            {"rendered_text": fragments[0]}
        )
        file_boundary[artifact_path("episodes.jsonl")] = (
            encoded({"rendered_text": fragments[1]}) + b"\n"
        )
        cases["file-boundary"] = file_boundary

        for name, bundle in cases.items():
            with self.subTest(name=name):
                findings = MODULE.validate_v2_bundle_privacy(bundle)
                self.assertIn(
                    MODULE.ISSUE_SENSITIVE_MATERIAL,
                    findings.get("__bundle__", []),
                    findings,
                )
                for basename in MODULE.ARTIFACT_ORDER:
                    self.assertNotIn(
                        MODULE.ISSUE_SENSITIVE_MATERIAL,
                        findings.get(basename, []),
                        findings,
                    )

    def test_attestation_armor_is_canonical_and_header_free(self) -> None:
        canonical = {
            "signer_fingerprint": PUBLISHER_FINGERPRINT,
            "signature": CANONICAL_PUBLISHER_SIGNATURE,
        }
        self.assertEqual(
            MODULE.validate_v2_privacy(artifact_path(), encoded(canonical)), []
        )

        noncanonical = (
            "-----BEGIN PGP SIGNATURE-----\n"
            "Comment: retained-header-leak\n\n"
            + CANONICAL_PUBLISHER_SIGNATURE.split("\n\n", 1)[1]
        )
        issues = MODULE.validate_v2_privacy(
            artifact_path(),
            encoded(
                {
                    "signer_fingerprint": PUBLISHER_FINGERPRINT,
                    "signature": noncanonical,
                }
            ),
        )
        self.assertIn(MODULE.ISSUE_SCALAR, issues)

        bad_checksum = CANONICAL_PUBLISHER_SIGNATURE.replace("=pLXK", "=AAAA")
        issues = MODULE.validate_v2_privacy(
            artifact_path(),
            encoded(
                {
                    "signer_fingerprint": PUBLISHER_FINGERPRINT,
                    "signature": bad_checksum,
                }
            ),
        )
        self.assertIn(MODULE.ISSUE_SCALAR, issues)

    def test_canonical_attestation_payload_is_not_scanned_as_prose(self) -> None:
        canonical = {
            "signer_fingerprint": PUBLISHER_FINGERPRINT,
            "signature": CANONICAL_PUBLISHER_SIGNATURE,
        }
        armor_fragment = CANONICAL_PUBLISHER_SIGNATURE.splitlines()[2][4:16]
        with mock.patch.object(
            MODULE,
            "URL_PATTERNS",
            (re.compile(re.escape(armor_fragment)),),
        ):
            self.assertEqual(
                MODULE.validate_v2_privacy(artifact_path(), encoded(canonical)),
                [],
            )

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
        rendered = "What Happened: action use a bounded search."
        slots = [
            {
                "name": "action",
                "slot_type": "reviewed_clause",
                "value": "use_a_bounded_search",
            }
        ]

        self.assertEqual(
            MODULE.validate_v2_privacy(
                artifact_path("turn_findings.jsonl"),
                encoded(template_payload(rendered, slots=slots)) + b"\n",
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

    def test_accepts_bounded_numeric_metrics_in_typed_slots(self) -> None:
        rendered = "What Happened: metric available ledger count v2 count."
        slots = [
            {
                "name": "metric",
                "slot_type": "aggregate_metric",
                "metric": {
                    "status": "available",
                    "formula_id": "ledger_count_v2",
                    "value": 12,
                    "unit": "count",
                    "rounding": "integer",
                    "cohort_policy": "all_terminal_members",
                    "input_refs": ["aggregate_input_ref_v2:" + "a" * 32],
                },
            }
        ]

        self.assertEqual(
            MODULE.validate_v2_privacy(
                artifact_path("turn_findings.jsonl"),
                encoded(template_payload(rendered, slots=slots)) + b"\n",
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

    def test_rejects_legacy_radix_and_noncanonical_id_paths(self) -> None:
        legacy = Path(
            "runs",
            "daily",
            *("00" for _ in range(32)),
            "2026-07-14",
            *("00" for _ in range(32)),
            "manifest.json",
        )
        alias_parts = list(artifact_path().parts)
        alias_parts[3] = RUN_ID[:-1] + "f"

        for relative in (legacy, Path(*alias_parts)):
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

    def test_rejects_shared_high_confidence_credential_families(self) -> None:
        credentials = (
            "ASIA" + "A" * 16,
            "xoxb-" + "A" * 20,
            "xoxe-" + "A" * 20,
            "AIza" + "A" * 35,
            "glpat-" + "A" * 20,
            "npm_" + "A" * 36,
        )
        for credential in credentials:
            with self.subTest(prefix=credential[:6]):
                issues = MODULE.validate_v2_privacy(
                    artifact_path(),
                    encoded({"artifact_type": "manifest", "value": credential}),
                )

            self.assertIn(MODULE.ISSUE_SENSITIVE_MATERIAL, issues)

    def test_authorization_bearer_detection_covers_source_containers(self) -> None:
        token = "0123456789abcdef"
        values = (
            f"Authorization: Bearer {token}",
            f"curl -H 'Authorization: Bearer {token}' endpoint",
            f'headers = ["Authorization: Bearer {token}"]',
            f'- "Authorization: Bearer {token}"',
            f'{{"Authorization": "Bearer {token}"}}',
            f'AUTHORIZATION="Bearer {token}"',
        )
        for value in values:
            with self.subTest(value=value):
                self.assertTrue(
                    MODULE.contains_high_confidence_credential(value.encode("utf-8"))
                )
                issues = MODULE.validate_v2_privacy(
                    artifact_path(),
                    encoded({"artifact_type": "manifest", "value": value}),
                )
                self.assertIn(MODULE.ISSUE_SENSITIVE_MATERIAL, issues)

    def test_authorization_bearer_detection_preserves_bounded_false_positives(
        self,
    ) -> None:
        values = (
            "Use Bearer 0123456789abcdef in documentation.",
            "Explain Authorization: Bearer 0123456789abcdef in documentation.",
            "Authorization: Bearer <credential>",
            "X-Authorization: Bearer 0123456789abcdef",
            'SOME_AUTHORIZATION="Bearer 0123456789abcdef"',
            '{"Proxy-Authorization": "Bearer 0123456789abcdef"}',
            'headers = ["Authorization: Bearer 0123456789abc"]',
            f'headers = ["Authorization: Bearer {"a" * 4097}"]',
        )
        for value in values:
            with self.subTest(value=value[:80]):
                self.assertFalse(
                    MODULE.contains_high_confidence_credential(value.encode("utf-8"))
                )

    def test_binary_openpgp_secret_packet_detection_is_structured(self) -> None:
        key_prefix = b"\x04\x00\x00\x00\x00\x01"
        secret_packets = (
            b"\xc5\x06" + key_prefix,
            b"\xc7\x06" + key_prefix,
            b"\x94\x06" + key_prefix,
        )
        for packet in secret_packets:
            with self.subTest(header=packet[:1]):
                self.assertTrue(
                    MODULE.contains_high_confidence_credential(
                        b"reviewed-prefix\x00" + packet + b"\x00reviewed-suffix"
                    )
                )

        for payload in (
            b"\xc6\x06" + key_prefix,
            b"\xc5\x07" + key_prefix,
            b"\xc5\x06\x01\x00\x00\x00\x00\x01",
        ):
            with self.subTest(payload=payload[:2]):
                self.assertFalse(MODULE.contains_high_confidence_credential(payload))

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

    def test_wide_json_containers_fail_before_materializing_children(self) -> None:
        node_limit = 4
        cases = (
            ("list", [risky_password()] * node_limit, "reversed"),
            (
                "dict",
                {f"unknown_{index}": risky_password() for index in range(node_limit)},
                "sorted",
            ),
        )

        for label, value, enumerator in cases:
            with self.subTest(label=label):
                issues: set[str] = set()
                with mock.patch(
                    f"builtins.{enumerator}",
                    side_effect=AssertionError("wide children were enumerated"),
                ):
                    visited = MODULE._scan_json_value(
                        value, issues, node_limit=node_limit
                    )

                self.assertEqual(visited, node_limit + 1)
                self.assertEqual(issues, {MODULE.ISSUE_FORMAT})

    def test_wide_max_size_value_is_rejected_before_json_loads(self) -> None:
        max_line_bytes = 16 * 1024 * 1024
        prefix = b"[" + (b"0," * MODULE.MAX_JSON_NODES) + b"0]"
        payload = prefix + (b" " * (max_line_bytes - len(prefix) - 1)) + b"\n"
        self.assertEqual(len(payload), max_line_bytes)

        for basename in ("summary.json", "episodes.jsonl"):
            with self.subTest(basename=basename):
                with mock.patch.object(
                    MODULE.json,
                    "loads",
                    side_effect=AssertionError("json.loads must not be reached"),
                ) as loads:
                    issues = MODULE.validate_v2_privacy(
                        artifact_path(basename), payload
                    )

                self.assertIn(MODULE.ISSUE_FORMAT, issues)
                loads.assert_not_called()

    def test_json_recursion_error_is_caught_fail_closed(self) -> None:
        with mock.patch.object(MODULE, "_parse_json", side_effect=RecursionError):
            issues = MODULE.validate_v2_privacy(artifact_path("summary.json"), b"{}")

        self.assertIn(MODULE.ISSUE_FORMAT, issues)

    def test_jsonl_row_budget_is_enforced_while_streaming(self) -> None:
        payload = b"{}\n" * (MODULE.MAX_JSONL_ROWS + 1)

        with mock.patch.object(
            MODULE, "_parse_json", wraps=MODULE._parse_json
        ) as parse_json:
            issues = MODULE.validate_v2_privacy(
                artifact_path("episodes.jsonl"), payload
            )

        self.assertIn(MODULE.ISSUE_FORMAT, issues)
        self.assertEqual(parse_json.call_count, MODULE.MAX_JSONL_ROWS)

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

    def test_commit_metadata_accepts_safe_identity_and_fixed_message(self) -> None:
        message = f"Publish session retrospective v2 daily 2026-07-14 {RUN_REF}\n"
        author = "Joey Teng <12524680+JoeyTeng@users.noreply.github.com>"
        committer = "GitHub <noreply@github.com>"

        self.assertEqual(
            MODULE.validate_v2_commit_metadata(
                author,
                committer,
                message,
            ),
            [],
        )
        self.assertEqual(
            MODULE.validate_v2_commit_metadata(
                author,
                committer,
                f"Publish session retrospective v2 daily 2026-07-14 {RUN_ID}\n",
            ),
            [MODULE.ISSUE_COMMIT_MESSAGE],
        )
        self.assertEqual(
            MODULE.validate_v2_commit_metadata(
                author,
                committer,
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
                    MODULE.ISSUE_COMMIT_MESSAGE,
                }
            ),
        )
        findings = "\n".join(issues)
        self.assertNotIn(leaked_author, findings)
        self.assertNotIn("ghp_", findings)

    def test_commit_metadata_matches_git_validator_contract(self) -> None:
        expected_identity = "GitHub <noreply@github.com>"
        message = f"Publish session retrospective v2 daily 2026-07-14 {RUN_REF}\n"

        self.assertIsNotNone(
            GIT_MODULE.ADMIN_AUTHOR_IDENTITY_RE.fullmatch(
                f"{expected_identity} 1800000000 +0000".encode("ascii")
            )
        )
        self.assertIsNotNone(MODULE.V2_COMMIT_IDENTITY_RE.fullmatch(expected_identity))
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
        identity = "GitHub <noreply@github.com>"

        self.assertEqual(
            MODULE.validate_v2_commit_metadata(
                identity,
                identity,
                message,
            ),
            [MODULE.ISSUE_COMMIT_MESSAGE],
        )


if __name__ == "__main__":
    unittest.main()
