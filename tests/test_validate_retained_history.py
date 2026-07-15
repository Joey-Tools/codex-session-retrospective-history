from __future__ import annotations

from collections.abc import Callable
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "validate_retained_history.py"
)
SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "schemas"
    / "session-retrospective-v1.schema.json"
)
MANIFEST_SCHEMA = (
    Path(__file__).resolve().parents[1] / "schemas" / "retained-manifest-v1.schema.json"
)
SPEC = importlib.util.spec_from_file_location("validate_retained_history", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def valid_manifest() -> dict:
    return {
        "schema_version": 1,
        "mode": "daily",
        "window": {
            "mode": "daily",
            "start": "2026-05-21T00:00:00Z",
            "end": "2026-05-22T00:00:00Z",
        },
        "sources": [
            {
                "host": "local",
                "root_ref": "path_ref_v1:aaaaaaaaaaaaaaaa",
                "status": "ready",
                "rollout_count": 1,
                "summary_count": 0,
            }
        ],
        "coverage_gaps": [],
        "redaction_policy_version": 1,
        "retention_note": "Derived retained manifest; raw location fields removed and opaque refs preserved.",
        "retention_safe": True,
    }


def valid_episode() -> dict:
    return {
        "episode_id": "episode_ref_v1:" + "a" * 20,
        "host": "local",
        "session_id": "session_ref_v1:" + "b" * 20,
        "start": "2026-05-21T00:00:00Z",
        "end": "2026-05-21T01:00:00Z",
        "cwd": None,
        "model_era": "unknown",
        "topic": "Redacted topic",
        "turn_count": 1,
        "friction_flags": [],
        "outcome": "needs_review",
        "work_report_hint": None,
    }


def valid_turn_flag() -> dict:
    return {
        "turn_id": "turn_ref_v1:" + "a" * 20,
        "episode_id": "episode_ref_v1:" + "a" * 20,
        "host": "local",
        "session_id": "session_ref_v1:" + "b" * 20,
        "source_path": "path_ref_v1:" + "d" * 16,
        "source_hash": "source_hash_v1:" + "e" * 20,
        "timestamp": "2026-05-21T00:00:00Z",
        "cwd": None,
        "model": None,
        "model_era": "unknown",
        "redacted_user_prompt_summary": "Redacted prompt summary",
        "assistant_action_summary": "Redacted assistant summary",
        "issue_flags": ["verification_gap"],
        "prompt_improvement": None,
    }


def valid_trend() -> dict:
    return {
        "schema_version": 1,
        "window": {
            "mode": "daily",
            "start": "2026-05-21T00:00:00Z",
            "end": "2026-05-22T00:00:00Z",
        },
        "turn_count": 1,
        "flagged_turn_count": 1,
        "episode_count": 1,
        "flags": {"verification_gap": 1},
        "hosts": {"local": 1},
        "model_eras": {"unknown": 1},
        "coverage_gaps": [],
    }


def publisher_attestation_payload(run_ref: str, bundle_digest: str) -> bytes:
    def frame(frame_type: bytes, value: str) -> bytes:
        encoded = value.encode("ascii")
        return frame_type + len(encoded).to_bytes(8, "big") + encoded

    return b"".join(
        (
            b"session-retrospective-publisher-attestation-v2",
            frame(b"R", run_ref),
            frame(b"D", bundle_digest),
        )
    )


def window_for_mode(mode: str) -> dict:
    if mode == "daily":
        start = "2026-05-21T00:00:00Z"
    elif mode == "weekly":
        start = "2026-05-15T00:00:00Z"
    elif mode == "baseline-90d":
        start = "2026-02-21T00:00:00Z"
    else:
        start = "2026-05-21T00:00:00Z"
    return {"mode": mode, "start": start, "end": "2026-05-22T00:00:00Z"}


def write_retained_export(root: Path, export_dir: Path, *, mode: str = "daily") -> None:
    trend = valid_trend()
    trend["window"] = window_for_mode(mode)
    manifest = valid_manifest()
    manifest["mode"] = mode
    manifest["window"] = window_for_mode(mode)
    export_dir.mkdir(parents=True)
    (export_dir / "episodes.jsonl").write_text(
        json.dumps(valid_episode()) + "\n", encoding="utf-8"
    )
    (export_dir / "turn_flags.jsonl").write_text(
        json.dumps(valid_turn_flag()) + "\n", encoding="utf-8"
    )
    (export_dir / "trend_report.json").write_text(json.dumps(trend), encoding="utf-8")
    (export_dir / "retained_manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )


def write_monthly_export(root: Path, *, year: str = "2026", month: str = "05") -> None:
    episodes_path = root / "data" / "episodes" / year / month / "episodes.jsonl"
    turn_flags_path = root / "data" / "turn_flags" / year / month / "turn_flags.jsonl"
    trend_path = root / "data" / "trends" / year / month / "trend_report.json"
    episodes_path.parent.mkdir(parents=True)
    turn_flags_path.parent.mkdir(parents=True)
    trend_path.parent.mkdir(parents=True)
    episodes_path.write_text(json.dumps(valid_episode()) + "\n", encoding="utf-8")
    turn_flags_path.write_text(json.dumps(valid_turn_flag()) + "\n", encoding="utf-8")
    trend_path.write_text(json.dumps(valid_trend()), encoding="utf-8")


def risky_local_path() -> str:
    return "/Us" + "ers/hoteng/.cod" + "ex/sess" + "ions/2026/05/22/rollout.jsonl"


def risky_project_path() -> str:
    return "/Us" + "ers/hoteng/project"


def risky_internal_url() -> str:
    return "HTTPS://internal" + ".example/path"


def risky_localhost_url() -> str:
    return "http" + "://localhost:3000/status"


def risky_private_ip_url() -> str:
    return "http" + "://" + risky_bare_private_ip() + ":8080/status"


def risky_bare_private_ip() -> str:
    return "10" + ".0.0.5"


def risky_bare_private_lan_ip() -> str:
    return "192" + ".168.1.4"


def risky_link_local_ip() -> str:
    return "169" + ".254.169.254"


def risky_cgnat_ip() -> str:
    return "100" + ".64.0.1"


def risky_private_ipv6() -> str:
    return "fc00" + ":" + ":1"


def risky_link_local_ipv6() -> str:
    return "fe80" + ":" + ":1"


def risky_loopback_ipv6() -> str:
    return "::" + "1"


def risky_short_host_url() -> str:
    return "http" + "://miku-bot-dev:8080/status"


def risky_private_ip_ssh_url() -> str:
    return "ssh" + "://git@" + risky_bare_private_ip() + "/repo"


def risky_short_host_git_remote() -> str:
    return "git" + "@miku-bot-dev:repo.git"


def risky_ssh_url() -> str:
    return "ssh" + "://git@" + "example" + ".internal/repo"


def risky_internal_host() -> str:
    return "jira.cisco" + ".example"


def risky_email() -> str:
    return "operator" + "@" + "redacted" + ".com"


def risky_secret_token() -> str:
    return "s" + "k-" + "proj-" + "abcdefghijklmnop123456"


def risky_github_classic_token() -> str:
    return "gh" + "p_" + ("a" * 36)


def risky_github_oauth_token() -> str:
    return "gh" + "o_" + ("b" * 36)


def risky_fine_grained_github_token() -> str:
    return "github" + "_pat_" + ("c" * 24)


def risky_raw_hash() -> str:
    return "a" * 64


def risky_uuid() -> str:
    return "12345678-" + "1234-" + "1234-" + "1234-" + "123456789abc"


def risky_session_pointer() -> str:
    return "Session " + "ID: abc123456"


def risky_turn_pointer() -> str:
    return "turn-" + "id=abc123456"


def risky_episode_pointer() -> str:
    return "episode_" + "id=abc123456"


def risky_space_session_pointer() -> str:
    return "Session " + "ID abc123456"


def risky_dotted_session_pointer() -> str:
    return "session." + "id: abc123456"


def risky_space_turn_pointer() -> str:
    return "turn " + "id abc123456"


def risky_dotted_episode_pointer() -> str:
    return "episode." + "id: abc123456"


def risky_camel_session_pointer() -> str:
    return "session" + "Id: abc123456"


def risky_camel_turn_pointer() -> str:
    return "turn" + "Id=abc123456"


def risky_camel_episode_pointer() -> str:
    return "episode" + "ID abc123456"


def risky_compound_session_token() -> str:
    return "session_" + "id_abc123456"


def risky_compound_turn_token() -> str:
    return "turn-" + "id-abc123456"


def risky_compound_episode_token() -> str:
    return "episode." + "id.abc123456"


def risky_compound_camel_session_token() -> str:
    return "session" + "Id_abc123456"


def risky_compound_camel_turn_token() -> str:
    return "turn" + "Id-abc123456"


def risky_rollout_filename() -> str:
    return "rollout-" + "2026-05-22T10-00-00-abc.jsonl"


class ValidateRetainedHistoryTests(unittest.TestCase):
    def test_bundle_schema_includes_manifest_root(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

        self.assertIn({"$ref": "#/$defs/manifest"}, schema["oneOf"])

    def test_schema_host_allowlist_matches_validator(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        manifest_schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))
        expected = sorted(MODULE.RETAINED_EVIDENCE_HOSTS)
        coverage_expected = sorted(MODULE.RETAINED_HOSTS)

        self.assertEqual(sorted(schema["$defs"]["retained_host"]["enum"]), expected)
        self.assertEqual(
            sorted(schema["$defs"]["retained_coverage_host"]["enum"]), coverage_expected
        )
        self.assertEqual(
            sorted(manifest_schema["$defs"]["retained_host"]["enum"]), expected
        )
        self.assertEqual(
            sorted(manifest_schema["$defs"]["retained_coverage_host"]["enum"]),
            coverage_expected,
        )
        self.assertEqual(
            schema["$defs"]["episode"]["properties"]["host"],
            {"$ref": "#/$defs/retained_host"},
        )
        self.assertEqual(
            schema["$defs"]["turn_flag"]["properties"]["host"],
            {"$ref": "#/$defs/retained_host"},
        )
        self.assertEqual(
            schema["$defs"]["source_summary"]["properties"]["host"],
            {"$ref": "#/$defs/retained_host"},
        )
        self.assertEqual(
            schema["$defs"]["coverage_gap"]["properties"]["host"],
            {"$ref": "#/$defs/retained_coverage_host"},
        )
        self.assertEqual(
            schema["$defs"]["trend"]["properties"]["hosts"],
            {"$ref": "#/$defs/retained_host_count_map"},
        )
        self.assertEqual(
            manifest_schema["$defs"]["source_summary"]["properties"]["host"],
            {"$ref": "#/$defs/retained_host"},
        )
        self.assertEqual(
            manifest_schema["$defs"]["coverage_gap"]["properties"]["host"],
            {"$ref": "#/$defs/retained_coverage_host"},
        )

    def test_schema_coverage_gap_reasons_match_validator(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        manifest_schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))
        expected = sorted(MODULE.COVERAGE_REASONS)

        self.assertEqual(
            sorted(schema["$defs"]["coverage_gap"]["properties"]["reason"]["enum"]),
            expected,
        )
        self.assertEqual(
            sorted(
                manifest_schema["$defs"]["coverage_gap"]["properties"]["reason"]["enum"]
            ),
            expected,
        )

    def test_schema_issue_flags_match_validator(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        expected = sorted(MODULE.ISSUE_FLAGS)

        self.assertEqual(sorted(schema["$defs"]["issue_flag"]["enum"]), expected)
        self.assertEqual(
            schema["$defs"]["episode"]["properties"]["friction_flags"]["items"],
            {"$ref": "#/$defs/issue_flag"},
        )
        self.assertEqual(
            schema["$defs"]["turn_flag"]["properties"]["issue_flags"]["items"],
            {"$ref": "#/$defs/issue_flag"},
        )
        self.assertEqual(
            schema["$defs"]["trend"]["properties"]["flags"],
            {"$ref": "#/$defs/issue_flag_count_map"},
        )

    def test_schema_retained_text_patterns_cover_compound_secrets_and_case_paths(
        self,
    ) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        schema_patterns = [
            re.compile(item["pattern"])
            for item in schema["$defs"]["retained_text"]["not"]["anyOf"]
        ]
        patterns = "\n".join(pattern.pattern for pattern in schema_patterns)

        self.assertIn("[A-Za-z0-9._-]*(?:", patterns)
        self.assertIn("[Pp][Rr][Ii][Vv][Aa][Tt][Ee][\\s._-]*[Kk][Ee][Yy]", patterns)
        self.assertIn("[Uu][Ss][Ee][Rr][Ss]", patterns)
        self.assertIn("[Ww][Oo][Rr][Kk][Ss][Pp][Aa][Cc][Ee]", patterns)
        for sample in (
            "api" + "key: abc",
            "api " + "key: abc",
            "secret " + "key: abc",
            "private" + "key: abc",
            "private " + "key: abc",
            "api" + "Key: [REDACTED]",
            "private" + "Key = <redacted>",
            "GitHub token " + risky_github_classic_token(),
            "GitHub OAuth token " + risky_github_oauth_token(),
            "GitHub fine-grained token " + risky_fine_grained_github_token(),
            "customer data",
            "PII",
            "production",
        ):
            with self.subTest(sample=sample):
                self.assertTrue(
                    any(pattern.search(sample) for pattern in schema_patterns)
                )
        for sample in (
            risky_bare_private_ip(),
            risky_bare_private_lan_ip(),
            risky_link_local_ip(),
            risky_cgnat_ip(),
            risky_private_ipv6(),
            risky_link_local_ipv6(),
            risky_loopback_ipv6(),
            "FC00" + ":" + ":1",
            "FD00" + ":" + ":1",
            "FE80" + ":" + ":1",
        ):
            with self.subTest(sample=sample):
                self.assertTrue(
                    any(pattern.search(sample) for pattern in schema_patterns)
                )

    def test_schema_raw_id_pattern_is_fully_case_insensitive(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        raw_id_pattern = next(
            item["pattern"]
            for item in schema["$defs"]["retained_text"]["not"]["anyOf"]
            if "session_ref_v1" in item["pattern"]
        )
        raw_id_re = re.compile(raw_id_pattern)

        for text in (
            "SESS" + "ION_ID: abc123456",
            "TURN" + "_ID=abc123456",
            "EPIS" + "ODE ID: abc123456",
            risky_space_session_pointer(),
            risky_dotted_session_pointer(),
            risky_space_turn_pointer(),
            risky_dotted_episode_pointer(),
            risky_camel_session_pointer(),
            risky_camel_turn_pointer(),
            risky_camel_episode_pointer(),
        ):
            with self.subTest(text=text):
                self.assertIsNotNone(raw_id_re.search(text))

        self.assertIsNone(raw_id_re.search("session_id: session_ref_v1:" + "a" * 20))

    def test_schema_safe_token_patterns_cover_compound_secret_names(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        manifest_schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))
        schema_patterns = [
            re.compile(item["pattern"])
            for item in schema["$defs"]["safe_token"]["not"]["anyOf"]
        ]
        manifest_schema_patterns = [
            re.compile(item["pattern"])
            for item in manifest_schema["$defs"]["safe_token"]["not"]["anyOf"]
        ]
        patterns = "\n".join(pattern.pattern for pattern in schema_patterns)
        manifest_patterns = "\n".join(
            pattern.pattern for pattern in manifest_schema_patterns
        )

        self.assertIn("[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll][Ss]?", patterns)
        self.assertIn("[Pp][Rr][Ii][Vv][Aa][Tt][Ee][._-]?[Kk][Ee][Yy]", patterns)
        self.assertIn(
            "[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll][Ss]?", manifest_patterns
        )
        self.assertIn(
            "[Pp][Rr][Ii][Vv][Aa][Tt][Ee][._-]?[Kk][Ee][Yy]", manifest_patterns
        )
        for sample in (
            risky_compound_session_token(),
            risky_compound_turn_token(),
            risky_compound_episode_token(),
            risky_compound_camel_session_token(),
            risky_compound_camel_turn_token(),
            risky_github_classic_token(),
            risky_github_oauth_token(),
            risky_fine_grained_github_token(),
        ):
            with self.subTest(sample=sample):
                self.assertTrue(
                    any(pattern.search(sample) for pattern in schema_patterns)
                )
                self.assertTrue(
                    any(pattern.search(sample) for pattern in manifest_schema_patterns)
                )
        for sample in (
            risky_bare_private_ip(),
            risky_bare_private_lan_ip(),
            risky_link_local_ip(),
            risky_cgnat_ip(),
        ):
            with self.subTest(sample=sample):
                self.assertTrue(
                    any(pattern.search(sample) for pattern in schema_patterns)
                )
                self.assertTrue(
                    any(pattern.search(sample) for pattern in manifest_schema_patterns)
                )

    def test_schema_restricts_retained_modes_models_and_source_hashes(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        manifest_schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))

        self.assertEqual(
            sorted(schema["$defs"]["retained_mode"]["anyOf"][0]["enum"]),
            sorted(MODULE.RETAINED_FIXED_MODES),
        )
        self.assertEqual(
            schema["$defs"]["retained_mode"]["anyOf"][1]["pattern"],
            MODULE.BASELINE_MODE_RE.pattern,
        )
        self.assertEqual(
            sorted(manifest_schema["$defs"]["retained_mode"]["anyOf"][0]["enum"]),
            sorted(MODULE.RETAINED_FIXED_MODES),
        )
        self.assertEqual(
            manifest_schema["$defs"]["retained_mode"]["anyOf"][1]["pattern"],
            MODULE.BASELINE_MODE_RE.pattern,
        )
        self.assertEqual(
            sorted(schema["$defs"]["retained_model_id"]["enum"]),
            sorted(MODULE.RETAINED_MODEL_IDS),
        )
        self.assertEqual(
            sorted(schema["$defs"]["retained_model_era"]["enum"]),
            sorted(MODULE.RETAINED_MODEL_ERAS),
        )
        self.assertEqual(
            schema["$defs"]["turn_flag"]["properties"]["source_hash"]["pattern"],
            MODULE.SOURCE_HASH_RE.pattern,
        )
        self.assertEqual(
            schema["$defs"]["trend"]["properties"]["window"], {"$ref": "#/$defs/window"}
        )
        self.assertEqual(
            schema["$defs"]["manifest"]["properties"]["mode"],
            {"$ref": "#/$defs/retained_mode"},
        )
        self.assertEqual(
            manifest_schema["properties"]["mode"], {"$ref": "#/$defs/retained_mode"}
        )
        self.assertIs(
            schema["$defs"]["episode"]["properties"]["friction_flags"]["uniqueItems"],
            True,
        )
        self.assertIs(
            schema["$defs"]["turn_flag"]["properties"]["issue_flags"]["uniqueItems"],
            True,
        )

    def test_schema_timestamp_patterns_reject_non_calendar_dates(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        manifest_schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))

        for pattern in (
            schema["$defs"]["timestamp_required"]["pattern"],
            manifest_schema["$defs"]["timestamp_required"]["pattern"],
        ):
            timestamp_re = re.compile(pattern)
            with self.subTest(pattern=pattern[:40]):
                self.assertIsNone(timestamp_re.fullmatch("2025-02-29T00:00:00Z"))
                self.assertIsNone(timestamp_re.fullmatch("2026-04-31T00:00:00Z"))
                self.assertIsNotNone(
                    timestamp_re.fullmatch("2024-02-29T00:00:00.123456789Z")
                )

    def test_clean_report_passes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            report = root / "reports" / "weekly" / "2026" / "05" / "08.md"
            report.parent.mkdir(parents=True)
            report.write_text(
                "# Weekly retrospective\n\nNo raw transcript excerpts retained.\n",
                encoding="utf-8",
            )

            self.assertEqual(MODULE.validate_root(root), [])

    def test_flat_retained_export_layout_passes(self) -> None:
        for export_name, mode in (
            ("daily", "daily"),
            ("weekly", "weekly"),
            ("baseline", "baseline-90d"),
        ):
            with self.subTest(export_name=export_name, mode=mode):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_retained_export(
                        root, root / "retained" / export_name, mode=mode
                    )

                    self.assertEqual(MODULE.validate_root(root), [])

    def test_flat_retained_export_rejects_extra_or_missing_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            (export_dir / "retained_manifest.json").unlink()

            self.assertIn(
                "retained export directory is incomplete or has extra files",
                "\n".join(MODULE.validate_root(root)),
            )

    def test_flat_retained_export_rejects_inconsistent_rows_and_trend(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            turn_flag = valid_turn_flag()
            turn_flag["episode_id"] = "episode_ref_v1:" + "b" * 20
            (export_dir / "turn_flags.jsonl").write_text(
                json.dumps(turn_flag) + "\n", encoding="utf-8"
            )
            trend = valid_trend()
            trend["turn_count"] = 0
            trend["flagged_turn_count"] = 0
            trend["episode_count"] = 0
            trend["flags"] = {}
            trend["hosts"] = {}
            trend["model_eras"] = {}
            (export_dir / "trend_report.json").write_text(
                json.dumps(trend), encoding="utf-8"
            )

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/daily/turn_flags.jsonl:1: episode_id is missing from episodes export",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: episode_count must match episodes.jsonl",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: flagged_turn_count must match turn_flags.jsonl",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: turn_count must match episodes.jsonl turn_count total",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: hosts must match episodes.jsonl turn_count totals",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: model_eras must match episodes.jsonl turn_count totals",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: flags must match turn_flags.jsonl issue_flags",
            issues,
        )

    def test_flat_retained_export_rejects_turn_flag_episode_identity_mismatch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            turn_flag = valid_turn_flag()
            turn_flag["host"] = "miku-bot-dev"
            turn_flag["session_id"] = "session_ref_v1:" + "c" * 20
            (export_dir / "turn_flags.jsonl").write_text(
                json.dumps(turn_flag) + "\n", encoding="utf-8"
            )

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/daily/turn_flags.jsonl:1: host must match referenced episode",
            issues,
        )
        self.assertIn(
            "retained/daily/turn_flags.jsonl:1: session_id must match referenced episode",
            issues,
        )

    def test_flat_retained_export_rejects_turn_flag_outside_episode_window(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            turn_flag = valid_turn_flag()
            turn_flag["timestamp"] = "2026-05-21T23:00:00Z"
            (export_dir / "turn_flags.jsonl").write_text(
                json.dumps(turn_flag) + "\n", encoding="utf-8"
            )

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/daily/turn_flags.jsonl:1: timestamp must be within referenced episode",
            issues,
        )

    def test_flat_retained_export_rejects_flagged_turn_count_above_episode_turn_count(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            episode_one = valid_episode()
            episode_one["turn_count"] = 0
            episode_two = valid_episode()
            episode_two["episode_id"] = "episode_ref_v1:" + "b" * 20
            episode_two["turn_count"] = 2
            trend = valid_trend()
            trend["episode_count"] = 2
            trend["turn_count"] = 2
            trend["flagged_turn_count"] = 1
            trend["hosts"] = {"local": 2}
            trend["model_eras"] = {"unknown": 2}
            (export_dir / "episodes.jsonl").write_text(
                json.dumps(episode_one) + "\n" + json.dumps(episode_two) + "\n",
                encoding="utf-8",
            )
            (export_dir / "trend_report.json").write_text(
                json.dumps(trend), encoding="utf-8"
            )

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/daily/turn_flags.jsonl: flagged turns must not exceed referenced episode turn_count",
            issues,
        )

    def test_flat_retained_export_rejects_rows_outside_trend_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            episode = valid_episode()
            episode["start"] = "2026-06-01T00:00:00Z"
            episode["end"] = "2026-06-01T01:00:00Z"
            turn_flag = valid_turn_flag()
            turn_flag["timestamp"] = "2026-06-01T00:00:00Z"
            (export_dir / "episodes.jsonl").write_text(
                json.dumps(episode) + "\n", encoding="utf-8"
            )
            (export_dir / "turn_flags.jsonl").write_text(
                json.dumps(turn_flag) + "\n", encoding="utf-8"
            )

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/daily/episodes.jsonl:1: episode start/end must be within trend window",
            issues,
        )
        self.assertIn(
            "retained/daily/turn_flags.jsonl:1: timestamp must be within trend window",
            issues,
        )

    def test_flat_retained_export_rejects_single_sided_episode_times_outside_trend_window(
        self,
    ) -> None:
        for start_value, end_value in (
            ("2026-06-01T00:00:00Z", None),
            (None, "2026-04-30T23:59:59Z"),
        ):
            with self.subTest(start=start_value, end=end_value):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    export_dir = root / "retained" / "daily"
                    write_retained_export(root, export_dir)
                    episode = valid_episode()
                    episode["start"] = start_value
                    episode["end"] = end_value
                    (export_dir / "episodes.jsonl").write_text(
                        json.dumps(episode) + "\n", encoding="utf-8"
                    )

                    issues = "\n".join(MODULE.validate_root(root))

                self.assertIn(
                    "retained/daily/episodes.jsonl:1: episode start/end must be within trend window",
                    issues,
                )

    def test_flat_retained_export_rejects_duplicate_ids(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            episode = valid_episode()
            turn_flag = valid_turn_flag()
            (export_dir / "episodes.jsonl").write_text(
                json.dumps(episode) + "\n" + json.dumps(episode) + "\n",
                encoding="utf-8",
            )
            (export_dir / "turn_flags.jsonl").write_text(
                json.dumps(turn_flag) + "\n" + json.dumps(turn_flag) + "\n",
                encoding="utf-8",
            )
            trend = valid_trend()
            trend["turn_count"] = 2
            trend["flagged_turn_count"] = 2
            trend["episode_count"] = 2
            trend["flags"] = {"verification_gap": 2}
            trend["hosts"] = {"local": 2}
            trend["model_eras"] = {"unknown": 2}
            (export_dir / "trend_report.json").write_text(
                json.dumps(trend), encoding="utf-8"
            )

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("retained/daily/episodes.jsonl:2: duplicate episode_id", issues)
        self.assertIn("retained/daily/turn_flags.jsonl:2: duplicate turn_id", issues)

    def test_empty_retained_exports_reject_nonzero_trends(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            (export_dir / "episodes.jsonl").write_text("", encoding="utf-8")
            (export_dir / "turn_flags.jsonl").write_text("", encoding="utf-8")
            flat_trend = valid_trend()
            (export_dir / "trend_report.json").write_text(
                json.dumps(flat_trend), encoding="utf-8"
            )
            write_monthly_export(root)
            monthly_episodes = (
                root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            )
            monthly_turn_flags = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            monthly_trend = (
                root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            )
            monthly_episodes.write_text("", encoding="utf-8")
            monthly_turn_flags.write_text("", encoding="utf-8")
            monthly_trend.write_text(json.dumps(valid_trend()), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/daily/trend_report.json: episode_count must match episodes.jsonl",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: flagged_turn_count must match turn_flags.jsonl",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: turn_count must match episodes.jsonl turn_count total",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: hosts must match episodes.jsonl turn_count totals",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: model_eras must match episodes.jsonl turn_count totals",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: flags must match turn_flags.jsonl issue_flags",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: episode_count must match episodes.jsonl",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: flagged_turn_count must match turn_flags.jsonl",
            issues,
        )

    def test_monthly_trend_without_row_files_rejects_nonzero_counts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(valid_trend()), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/trends/2026/05/trend_report.json: episode_count must match episodes.jsonl",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: flagged_turn_count must match turn_flags.jsonl",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: turn_count must match episodes.jsonl turn_count total",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: hosts must match episodes.jsonl turn_count totals",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: model_eras must match episodes.jsonl turn_count totals",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: flags must match turn_flags.jsonl issue_flags",
            issues,
        )

    def test_monthly_artifact_windows_must_belong_to_path_month(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            trend = valid_trend()
            trend["turn_count"] = 0
            trend["flagged_turn_count"] = 0
            trend["episode_count"] = 0
            trend["flags"] = {}
            trend["hosts"] = {}
            trend["model_eras"] = {}
            trend["window"] = {
                "mode": "daily",
                "start": "2026-06-01T00:00:00Z",
                "end": "2026-06-02T00:00:00Z",
            }
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            manifest = valid_manifest()
            manifest["window"] = {
                "mode": "daily",
                "start": "2026-04-29T00:00:00Z",
                "end": "2026-04-30T00:00:00Z",
            }
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            manifest_path.parent.mkdir(parents=True)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/trends/2026/05/trend_report.json: window must overlap data month",
            issues,
        )
        self.assertIn(
            "data/manifests/2026/05/retained_manifest.json: window must overlap data month",
            issues,
        )

    def test_monthly_cross_month_weekly_export_allows_full_window_rows(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            window = {
                "mode": "weekly",
                "start": "2026-04-28T00:00:00Z",
                "end": "2026-05-05T00:00:00Z",
            }
            episode = valid_episode()
            episode["start"] = "2026-04-30T10:00:00Z"
            episode["end"] = "2026-04-30T11:00:00Z"
            turn_flag = valid_turn_flag()
            turn_flag["timestamp"] = "2026-04-30T10:30:00Z"
            trend = valid_trend()
            trend["window"] = window
            manifest = valid_manifest()
            manifest["mode"] = "weekly"
            manifest["window"] = window

            episode_path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            turn_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            episode_path.parent.mkdir(parents=True)
            turn_path.parent.mkdir(parents=True)
            trend_path.parent.mkdir(parents=True)
            manifest_path.parent.mkdir(parents=True)
            episode_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")
            turn_path.write_text(json.dumps(turn_flag) + "\n", encoding="utf-8")
            trend_path.write_text(json.dumps(trend), encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertNotIn("episode start/end must be within data month", issues)
        self.assertNotIn("timestamp must be within data month", issues)
        self.assertNotIn("must match episodes.jsonl", issues)
        self.assertNotIn("must match turn_flags.jsonl", issues)

    def test_invalid_data_month_paths_report_errors_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode_path = root / "data" / "episodes" / "0000" / "05" / "episodes.jsonl"
            episode_path.parent.mkdir(parents=True)
            episode_path.write_text(
                json.dumps(valid_episode()) + "\n", encoding="utf-8"
            )
            trend_path = root / "data" / "trends" / "9999" / "12" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(valid_trend()), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/episodes/0000/05/episodes.jsonl: unexpected JSONL artifact", issues
        )
        self.assertIn(
            "data/trends/9999/12/trend_report.json: unexpected JSON artifact", issues
        )

    def test_schema_version_rejects_bool(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_monthly_export(root)
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend = json.loads(trend_path.read_text(encoding="utf-8"))
            trend["schema_version"] = True
            trend_path.write_text(json.dumps(trend), encoding="utf-8")
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            manifest_path.parent.mkdir(parents=True)
            manifest = valid_manifest()
            manifest["schema_version"] = True
            manifest["redaction_policy_version"] = True
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/trends/2026/05/trend_report.json: trend schema_version must be 1",
            issues,
        )
        self.assertIn(
            "data/manifests/2026/05/retained_manifest.json: manifest schema_version must be 1",
            issues,
        )
        self.assertIn(
            "data/manifests/2026/05/retained_manifest.json: manifest redaction_policy_version must be 1",
            issues,
        )

    def test_monthly_turn_flags_check_episode_refs_without_trend(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            turn_flags_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            turn_flags_path.parent.mkdir(parents=True)
            turn_flags_path.write_text(
                json.dumps(valid_turn_flag()) + "\n", encoding="utf-8"
            )

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/turn_flags/2026/05/turn_flags.jsonl:1: episode_id is missing from episodes export",
            issues,
        )

    def test_monthly_rows_without_trend_must_match_path_month(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = valid_episode()
            episode["start"] = "2026-06-01T00:00:00Z"
            episode["end"] = "2026-06-01T01:00:00Z"
            episodes_path = (
                root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            )
            episodes_path.parent.mkdir(parents=True)
            episodes_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            turn_flag = valid_turn_flag()
            turn_flag["timestamp"] = "2026-04-30T23:59:59Z"
            turn_flags_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            turn_flags_path.parent.mkdir(parents=True)
            turn_flags_path.write_text(json.dumps(turn_flag) + "\n", encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/episodes/2026/05/episodes.jsonl:1: episode start/end must be within data month",
            issues,
        )
        self.assertIn(
            "data/turn_flags/2026/05/turn_flags.jsonl:1: timestamp must be within data month",
            issues,
        )

    def test_monthly_retained_artifacts_reject_inconsistent_rows_and_duplicates(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_monthly_export(root)
            episodes_path = (
                root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            )
            turn_flags_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            episode = valid_episode()
            turn_flag = valid_turn_flag()
            turn_flag["episode_id"] = "episode_ref_v1:" + "c" * 20
            episodes_path.write_text(
                json.dumps(episode) + "\n" + json.dumps(episode) + "\n",
                encoding="utf-8",
            )
            turn_flags_path.write_text(
                json.dumps(turn_flag) + "\n" + json.dumps(turn_flag) + "\n",
                encoding="utf-8",
            )
            trend = valid_trend()
            trend["turn_count"] = 0
            trend["flagged_turn_count"] = 0
            trend["episode_count"] = 0
            trend["flags"] = {}
            trend["hosts"] = {}
            trend["model_eras"] = {}
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/episodes/2026/05/episodes.jsonl:2: duplicate episode_id", issues
        )
        self.assertIn(
            "data/turn_flags/2026/05/turn_flags.jsonl:2: duplicate turn_id", issues
        )
        self.assertIn(
            "data/turn_flags/2026/05/turn_flags.jsonl:1: episode_id is missing from episodes export",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: episode_count must match episodes.jsonl",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: flagged_turn_count must match turn_flags.jsonl",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: turn_count must match episodes.jsonl turn_count total",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: hosts must match episodes.jsonl turn_count totals",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: model_eras must match episodes.jsonl turn_count totals",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: flags must match turn_flags.jsonl issue_flags",
            issues,
        )

    def test_forbidden_raw_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "history.jsonl").write_text("{}\n", encoding="utf-8")

            self.assertIn(
                "forbidden raw/transient artifact",
                "\n".join(MODULE.validate_root(root)),
            )

    def test_forced_raw_session_directories_are_rejected(self) -> None:
        for relative_path in (
            "sess" + "ions/prompt.txt",
            "archived_" + "sess" + "ions/raw.txt",
            "Sess" + "ions/prompt.txt",
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    subprocess.run(
                        ["git", "init"], cwd=root, check=True, stdout=subprocess.DEVNULL
                    )
                    (root / ".gitignore").write_text(
                        "sess"
                        + "ions/\narchived_"
                        + "sess"
                        + "ions/\nSess"
                        + "ions/\n",
                        encoding="utf-8",
                    )
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text("raw prompt text\n", encoding="utf-8")
                    subprocess.run(
                        ["git", "add", "-f", relative_path], cwd=root, check=True
                    )

                    self.assertIn(
                        "forbidden raw/transient artifact",
                        "\n".join(MODULE.validate_root(root)),
                    )

    def test_compressed_raw_artifact_names_are_rejected(self) -> None:
        for relative_path in (
            "rollout-" + "2026-05-22.jsonl.gz",
            "session_index.jsonl.gz",
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    (root / relative_path).write_text(
                        "raw prompt text\n", encoding="utf-8"
                    )

                    self.assertIn(
                        "forbidden raw/transient artifact",
                        "\n".join(MODULE.validate_root(root)),
                    )

    def test_symlink_artifacts_are_rejected_without_following_target(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            link = root / "reports" / "weekly" / "linked.md"
            link.parent.mkdir(parents=True)
            os.symlink(risky_local_path(), link)

            self.assertIn(
                "symlink artifact is not allowed", "\n".join(MODULE.validate_root(root))
            )

    def test_retained_text_risks_are_rejected(self) -> None:
        risky_examples = (
            "Upper-case URL " + risky_internal_url(),
            "SSH URL " + risky_ssh_url(),
            "Raw session pointer " + risky_session_pointer(),
            "Raw turn pointer " + risky_turn_pointer(),
            "Raw episode pointer " + risky_episode_pointer(),
            "Raw session pointer " + risky_space_session_pointer(),
            "Raw dotted session pointer " + risky_dotted_session_pointer(),
            "Raw turn pointer " + risky_space_turn_pointer(),
            "Raw dotted episode pointer " + risky_dotted_episode_pointer(),
            "Raw camel session pointer " + risky_camel_session_pointer(),
            "Raw camel turn pointer " + risky_camel_turn_pointer(),
            "Raw camel episode pointer " + risky_camel_episode_pointer(),
            "Raw compound session pointer " + risky_compound_session_token(),
            "Raw compound turn pointer " + risky_compound_turn_token(),
            "Raw compound episode pointer " + risky_compound_episode_token(),
            "Raw compound camel session pointer "
            + risky_compound_camel_session_token(),
            "Raw compound camel turn pointer " + risky_compound_camel_turn_token(),
            '{"to' + 'ken":"redactedvalue"}',
            '{"api' + 'Key":"[REDACTED]"}',
            '{"private' + 'Key":""}',
            "private" + "Key = <redacted>",
            '{"access_to' + 'ken":"redactedvalue"}',
            '{"refresh-to' + 'ken":"redactedvalue"}',
            '{"client_sec' + 'ret":"redactedvalue"}',
            '{"db_pass' + 'word":"redactedvalue"}',
            '{"api' + 'key":"abc"}',
            '{"api_' + 'key":"abc"}',
            '{"private' + 'key":"abc"}',
            "api " + "key: abc",
            "secret " + "key: abc",
            "private " + "key: abc",
            "Contains customer data",
            "Contains PII",
            "Touching production",
            "Potentially destructive",
            "pass" + "word=12345",
            '{"private_' + 'key":"redactedvalue"}',
            '{"session_' + 'id":"abc123456"}',
            "Private key block -----BEGIN PRIVATE " + "KEY-----\nredacted",
            "PGP private key block -----BEGIN PGP PRIVATE "
            + "KEY BLOCK-----\nredacted",
            "Relative source path ./.cod" + "ex/sess" + "ions/2026/05/22/rollout.jsonl",
            "Case-variant source path ./.Cod"
            + "ex/Sess"
            + "ions/2026/05/22/Rollout-"
            + "ABC.JSONL",
            "Relative local source path .codex"
            + "-local/session-retrospective/out/state.json",
            "Relative temp source path .codex" + "-tmp/isolated-review/stdout.log",
            "Lower-case POSIX path /us" + "ers/hoteng/project",
            "Windows path C:\\Users\\hoteng\\project",
            "Lower-case Windows path C:\\users\\hoteng\\project",
            "Internal hostname " + risky_internal_host(),
            "Link local IP " + risky_link_local_ip(),
            "CGNAT IP " + risky_cgnat_ip(),
            "Private IPv6 " + risky_private_ipv6(),
            "Link local IPv6 " + risky_link_local_ipv6(),
            "Loopback IPv6 " + risky_loopback_ipv6(),
            "Rollout file " + risky_rollout_filename(),
            "Classic GitHub token " + risky_github_classic_token(),
            "OAuth GitHub token " + risky_github_oauth_token(),
            "Fine grained GitHub token " + risky_fine_grained_github_token(),
        )
        for text in risky_examples:
            with self.subTest(text=text):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    report = root / "reports" / "weekly" / "2026" / "05" / "08.md"
                    report.parent.mkdir(parents=True)
                    report.write_text(text + "\n", encoding="utf-8")

                    self.assertIn(
                        "retained text contains raw/sensitive evidence",
                        "\n".join(MODULE.validate_root(root)),
                    )

    def test_retained_readme_policy_language_can_name_safety_markers(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            data_readme = root / "data" / "README.md"
            reports_readme = root / "reports" / "README.md"
            weekly_report = root / "reports" / "weekly" / "2026" / "05" / "08.md"
            data_readme.parent.mkdir(parents=True)
            reports_readme.parent.mkdir(parents=True)
            weekly_report.parent.mkdir(parents=True)
            data_readme.write_text(
                "Retained summaries may count safety/privacy flags.\n", encoding="utf-8"
            )
            reports_readme.write_text(
                "Do not retain customer data or PII in report text.\n", encoding="utf-8"
            )
            weekly_report.write_text(
                "Summarized safety/privacy flags without raw evidence.\n",
                encoding="utf-8",
            )

            self.assertEqual(MODULE.validate_root(root), [])

    def test_forbidden_compact_artifact_names_are_rejected(self) -> None:
        for relative_path in (
            "reports/weekly/fullprompt.md",
            "reports/weekly/promptlog.md",
            "reports/weekly/rawTranscript.md",
            "reports/weekly/rawdata.md",
            "reports/weekly/rawdump.md",
            "reports/weekly/rawcopy.md",
            "reports/weekly/raw.transcript.md",
            "reports/weekly/full.prompt.md",
            "reports/weekly/tool.output.md",
            "reports/weekly/turn.summaries.jsonl",
            "reports/raw.transcripts/summary.md",
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text("Summarized text.\n", encoding="utf-8")

                    self.assertIn(
                        "forbidden raw/transient artifact",
                        "\n".join(MODULE.validate_root(root)),
                    )

    def test_manifest_extra_risky_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = valid_manifest() | {"worklist": [risky_local_path()]}
            path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn("unexpected field is not allowed", issues)
            self.assertIn(
                "manifest retained text contains raw/sensitive evidence", issues
            )

    def test_manifest_unknown_risky_key_is_rejected_without_echoing_key(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            risky_key = risky_local_path()
            manifest = valid_manifest() | {risky_key: "opaque"}
            path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn("unexpected field is not allowed", issues)
            self.assertIn("manifest JSON key contains raw/sensitive evidence", issues)
            self.assertNotIn(risky_key, issues)

    def test_jsonl_extra_raw_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            row = {
                "episode_id": "episode_ref_v1:" + "a" * 20,
                "host": "local",
                "session_id": "session_ref_v1:" + "b" * 20,
                "start": "2026-05-21T00:00:00Z",
                "end": "2026-05-21T01:00:00Z",
                "cwd": None,
                "model_era": "unknown",
                "topic": "Redacted topic",
                "turn_count": 1,
                "friction_flags": [],
                "outcome": "needs_review",
                "work_report_hint": None,
                "raw_path": risky_local_path(),
            }
            path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(row) + "\n", encoding="utf-8")

            self.assertIn(
                "unexpected field is not allowed", "\n".join(MODULE.validate_root(root))
            )

    def test_jsonl_unknown_risky_key_is_rejected_without_echoing_key(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            risky_key = risky_internal_url()
            row = {
                "episode_id": "episode_ref_v1:" + "a" * 20,
                "host": "local",
                "session_id": "session_ref_v1:" + "b" * 20,
                "start": "2026-05-21T00:00:00Z",
                "end": "2026-05-21T01:00:00Z",
                "cwd": None,
                "model_era": "unknown",
                "topic": "Redacted topic",
                "turn_count": 1,
                "friction_flags": [],
                "outcome": "needs_review",
                "work_report_hint": None,
                risky_key: "opaque",
            }
            path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(row) + "\n", encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn("unexpected field is not allowed", issues)
            self.assertIn("episode JSON key contains raw/sensitive evidence", issues)
            self.assertNotIn(risky_key, issues)

    def test_unexpected_text_artifact_locations_are_rejected_and_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifact = root / "evidence" / "notes.md"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(risky_local_path() + "\n", encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn("unexpected retained artifact location", issues)
            self.assertIn("retained text contains raw/sensitive evidence", issues)

    def test_unexpected_infrastructure_text_artifacts_are_rejected_and_scanned(
        self,
    ) -> None:
        for relative_path in (".github/notes.md", "tests/fixtures/source.json"):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    if artifact.suffix == ".json":
                        artifact.write_text(
                            json.dumps({"source": risky_internal_url()}),
                            encoding="utf-8",
                        )
                    else:
                        artifact.write_text(
                            risky_internal_url() + "\n", encoding="utf-8"
                        )

                    issues = "\n".join(MODULE.validate_root(root))
                    self.assertIn("unexpected", issues)
                    self.assertIn(
                        "retained text contains raw/sensitive evidence", issues
                    )

    def test_unexpected_retained_text_artifacts_are_rejected_without_risky_text(
        self,
    ) -> None:
        for relative_path in (
            "data/source-map.txt",
            "data/manifests/2026/05/worklist.txt",
            "reports/misc/notes.md",
            "reports/daily/2026/05/08.txt",
            "reports/daily/2026/13/08.md",
            "reports/weekly/0000/05/08.md",
            "reports/weekly/2026/02/31.md",
            "reports/baseline/90-day-windows/customer-acme.md",
            "reports/baseline/90-day-windows/2026-02-31_to_2026-03-01.md",
            "reports/baseline/90-day-windows/2026-03-01_to_2026-02-28.md",
            "reports/baseline/90-day-windows/2026-05-01_to_2026-05-02.md",
            "reports/baseline/90-day-windows/2026-01-01_to_2026-05-01.md",
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text(
                        "path_ref_v1:aaaaaaaaaaaaaaaa\n", encoding="utf-8"
                    )

                    self.assertIn(
                        "unexpected retained text artifact location",
                        "\n".join(MODULE.validate_root(root)),
                    )

    def test_unknown_json_artifacts_are_rejected(self) -> None:
        for relative_path in (
            "data/worklist.json",
            "data/source-map.JSON",
            "reports/weekly/notes.json",
            "data/trends/customer-acme/trend_report.json",
            "data/trends/2026/05/customer-acme.json",
            "data/manifests/2026/05/customer-acme.json",
            "schemas/customer-acme.schema.json",
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text(
                        json.dumps({"items": [{"source": "opaque"}]}), encoding="utf-8"
                    )

                    self.assertIn(
                        "unexpected JSON artifact",
                        "\n".join(MODULE.validate_root(root)),
                    )

    def test_unknown_jsonl_artifacts_are_rejected(self) -> None:
        for relative_path in (
            "data/episodes/customer-acme/episodes.jsonl",
            "data/episodes/2026/05/customer-acme.jsonl",
            "data/turn_flags/customer-acme/turn_flags.jsonl",
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text("\n", encoding="utf-8")

                    self.assertIn(
                        "unexpected JSONL artifact",
                        "\n".join(MODULE.validate_root(root)),
                    )

    def test_raw_identifier_path_components_are_redacted_in_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            raw_component = "session_" + "id-rawabcdef123456.jsonl"
            artifact = root / "data" / "turn_flags" / "2026" / "05" / raw_component
            artifact.parent.mkdir(parents=True)
            artifact.write_text("\n", encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/turn_flags/2026/05/[redacted].jsonl: forbidden raw/transient artifact",
            issues,
        )
        self.assertNotIn(raw_component, issues)

    def test_risky_value_path_components_are_redacted_in_diagnostics(self) -> None:
        for leaked_component in (
            risky_github_classic_token() + ".json",
            risky_fine_grained_github_token() + ".jsonl",
            risky_secret_token() + ".md",
        ):
            with self.subTest(leaked_component=leaked_component):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    artifact = (
                        root / "data" / "episodes" / "2026" / "05" / leaked_component
                    )
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text("{}\n", encoding="utf-8")

                    issues = "\n".join(MODULE.validate_root(root))

                self.assertIn("data/episodes/2026/05/[redacted]", issues)
                self.assertNotIn(leaked_component, issues)

    def test_invalid_jsonl_errors_do_not_include_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifact = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("{bad json\n", encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn(
                "data/episodes/2026/05/episodes.jsonl: line 1: invalid JSONL", issues
            )
            self.assertNotIn(str(root), issues)

    def test_os_errors_do_not_include_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifact = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("{}", encoding="utf-8")

            with mock.patch.object(
                MODULE,
                "parse_json",
                side_effect=PermissionError(13, "Permission denied", str(artifact)),
            ):
                issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/trends/2026/05/trend_report.json: PermissionError: Permission denied",
            issues,
        )
        self.assertNotIn(str(root), issues)
        self.assertNotIn(str(artifact), issues)

    def test_duplicate_jsonl_keys_are_rejected_before_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            row = valid_episode()
            entries = [
                ("episode_id", row["episode_id"]),
                ("host", row["host"]),
                ("session_id", row["session_id"]),
                ("start", row["start"]),
                ("end", row["end"]),
                ("cwd", row["cwd"]),
                ("model_era", row["model_era"]),
                ("topic", risky_local_path()),
                ("topic", row["topic"]),
                ("turn_count", row["turn_count"]),
                ("friction_flags", row["friction_flags"]),
                ("outcome", row["outcome"]),
                ("work_report_hint", row["work_report_hint"]),
            ]
            artifact = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(
                "{"
                + ",".join(
                    json.dumps(key) + ":" + json.dumps(value) for key, value in entries
                )
                + "}\n",
                encoding="utf-8",
            )

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn(
                "line 1: invalid JSONL: duplicate JSON key is not allowed", issues
            )
            self.assertNotIn(str(root), issues)

    def test_duplicate_json_keys_are_rejected_before_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            trend = valid_trend()
            hidden_key = "raw_" + "secret"
            entries = [
                ("schema_version", trend["schema_version"]),
                ("window", trend["window"]),
                ("turn_count", trend["turn_count"]),
                ("flagged_turn_count", trend["flagged_turn_count"]),
                ("episode_count", trend["episode_count"]),
                ("flags", {hidden_key: 1}),
                ("flags", trend["flags"]),
                ("hosts", trend["hosts"]),
                ("model_eras", trend["model_eras"]),
                ("coverage_gaps", trend["coverage_gaps"]),
            ]
            artifact = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(
                "{"
                + ",".join(
                    json.dumps(key) + ":" + json.dumps(value) for key, value in entries
                )
                + "}\n",
                encoding="utf-8",
            )

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn("duplicate JSON key is not allowed", issues)
            self.assertNotIn(str(root), issues)

    def test_unknown_retained_artifact_suffixes_are_rejected(self) -> None:
        for relative_path in ("data/source-map.csv", "reports/weekly/notes.yaml"):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text("opaque,summary\n", encoding="utf-8")

                    self.assertIn(
                        "unexpected retained artifact suffix",
                        "\n".join(MODULE.validate_root(root)),
                    )

    def test_boolean_count_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            row = {
                "episode_id": "episode_ref_v1:" + "a" * 20,
                "host": "local",
                "session_id": "session_ref_v1:" + "b" * 20,
                "start": "2026-05-21T00:00:00Z",
                "end": "2026-05-21T01:00:00Z",
                "cwd": None,
                "model_era": "unknown",
                "topic": "Redacted topic",
                "turn_count": True,
                "friction_flags": [],
                "outcome": "needs_review",
                "work_report_hint": None,
            }
            path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(row) + "\n", encoding="utf-8")

            self.assertIn(
                "turn_count must be a bounded non-negative integer",
                "\n".join(MODULE.validate_root(root)),
            )

    def test_token_arrays_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            row = {
                "episode_id": "episode_ref_v1:" + "a" * 20,
                "host": "local",
                "session_id": "session_ref_v1:" + "b" * 20,
                "start": "2026-05-21T00:00:00Z",
                "end": "2026-05-21T01:00:00Z",
                "cwd": None,
                "model_era": "unknown",
                "topic": "Redacted topic",
                "turn_count": 1,
                "friction_flags": [f"flag{index}" for index in range(17)],
                "outcome": "needs_review",
                "work_report_hint": None,
            }
            path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(row) + "\n", encoding="utf-8")

            self.assertIn(
                "friction_flags must contain at most 16 items",
                "\n".join(MODULE.validate_root(root)),
            )

    def test_safe_tokens_are_length_limited(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            row = {
                "turn_id": "turn_ref_v1:" + "a" * 20,
                "episode_id": "episode_ref_v1:" + "b" * 20,
                "host": "local",
                "session_id": "session_ref_v1:" + "c" * 20,
                "source_path": "path_ref_v1:" + "d" * 16,
                "source_hash": "source_hash_v1:" + "e" * 20,
                "timestamp": "2026-05-21T00:00:00Z",
                "cwd": None,
                "model": None,
                "model_era": "unknown",
                "redacted_user_prompt_summary": "Redacted prompt summary",
                "assistant_action_summary": "Redacted assistant summary",
                "issue_flags": ["x" * 65],
                "prompt_improvement": None,
            }
            path = root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(row) + "\n", encoding="utf-8")

            self.assertIn(
                "issue_flags must be safe-token array",
                "\n".join(MODULE.validate_root(root)),
            )

    def test_retained_flags_reject_private_identifiers(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = valid_episode()
            episode["friction_flags"] = ["customer_acme"]
            episode_path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            episode_path.parent.mkdir(parents=True)
            episode_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")
            turn = valid_turn_flag()
            turn["issue_flags"] = ["incident_123"]
            turn_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            turn_path.parent.mkdir(parents=True)
            turn_path.write_text(json.dumps(turn) + "\n", encoding="utf-8")
            trend = valid_trend()
            trend["flags"] = {"customer_acme": 1}
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("friction_flags must use allowed issue flags", issues)
        self.assertIn("issue_flags must use allowed issue flags", issues)
        self.assertIn("flags keys must use allowed issue flags", issues)

    def test_retained_flags_allow_collaboration_friction_categories(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = valid_episode()
            episode["friction_flags"] = ["over_exploration", "under_asking"]
            episode_path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            episode_path.parent.mkdir(parents=True)
            episode_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            turn = valid_turn_flag()
            turn["issue_flags"] = ["over_exploration", "under_asking"]
            turn_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            turn_path.parent.mkdir(parents=True)
            turn_path.write_text(json.dumps(turn) + "\n", encoding="utf-8")

            trend = valid_trend()
            trend["flags"] = {"over_exploration": 1, "under_asking": 1}
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            issues = MODULE.validate_root(root)

        self.assertEqual(issues, [])

    def test_retained_flags_reject_duplicate_issue_flags(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = valid_episode()
            episode["friction_flags"] = ["verification_gap", "verification_gap"]
            episode_path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            episode_path.parent.mkdir(parents=True)
            episode_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            turn = valid_turn_flag()
            turn["issue_flags"] = ["verification_gap", "verification_gap"]
            turn_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            turn_path.parent.mkdir(parents=True)
            turn_path.write_text(json.dumps(turn) + "\n", encoding="utf-8")

            trend = valid_trend()
            trend["flags"] = {"verification_gap": 1}
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("friction_flags must not contain duplicate issue flags", issues)
        self.assertIn("issue_flags must not contain duplicate issue flags", issues)

    def test_nested_issue_flags_report_errors_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = valid_episode()
            episode["friction_flags"] = [[]]
            episode_path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            episode_path.parent.mkdir(parents=True)
            episode_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            turn = valid_turn_flag()
            turn["issue_flags"] = [{}]
            turn_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            turn_path.parent.mkdir(parents=True)
            turn_path.write_text(json.dumps(turn) + "\n", encoding="utf-8")

            trend = valid_trend()
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("friction_flags must be safe-token array", issues)
        self.assertIn("friction_flags must use allowed issue flags", issues)
        self.assertIn("issue_flags must be safe-token array", issues)
        self.assertIn("issue_flags must use allowed issue flags", issues)

    def test_safe_tokens_reject_compound_secret_names(self) -> None:
        for sample in (
            "client_secret",
            "refresh-token",
            "private_key",
            "db_password",
            "OPENAI_API_KEY",
            risky_compound_session_token(),
            risky_compound_turn_token(),
            risky_compound_episode_token(),
            risky_compound_camel_session_token(),
            risky_compound_camel_turn_token(),
            risky_bare_private_ip(),
            risky_bare_private_lan_ip(),
            risky_link_local_ip(),
            risky_cgnat_ip(),
            risky_github_classic_token(),
            risky_github_oauth_token(),
            risky_fine_grained_github_token(),
        ):
            with self.subTest(sample=sample):
                self.assertFalse(MODULE.valid_safe_token(sample))

    def test_window_start_must_be_before_end(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            trend = valid_trend()
            trend["window"] = {
                "mode": "daily",
                "start": "2026-05-22T00:00:00Z",
                "end": "2026-05-21T00:00:00Z",
            }
            path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(trend), encoding="utf-8")

            self.assertIn(
                "window.start must be before window.end",
                "\n".join(MODULE.validate_root(root)),
            )

    def test_window_duration_must_match_retained_mode(self) -> None:
        cases = (
            ("daily", "2026-05-21T00:00:00Z", "2026-05-23T00:00:00Z"),
            ("weekly", "2026-05-21T00:00:00Z", "2026-05-22T00:00:00Z"),
            ("baseline-90d", "2026-05-01T00:00:00Z", "2026-05-22T00:00:00Z"),
        )
        for mode, start, end in cases:
            with self.subTest(mode=mode):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    trend = valid_trend()
                    trend["window"] = {"mode": mode, "start": start, "end": end}
                    path = (
                        root / "data" / "trends" / "2026" / "05" / "trend_report.json"
                    )
                    path.parent.mkdir(parents=True)
                    path.write_text(json.dumps(trend), encoding="utf-8")

                    issues = "\n".join(MODULE.validate_root(root))

                self.assertIn("window duration must match window.mode", issues)

    def test_window_accepts_nanosecond_precision_timestamps(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            trend = valid_trend()
            trend["window"] = {
                "mode": "daily",
                "start": "2026-05-21T00:00:00.123456789Z",
                "end": "2026-05-22T00:00:00.123456789Z",
            }
            trend["turn_count"] = 0
            trend["flagged_turn_count"] = 0
            trend["episode_count"] = 0
            trend["flags"] = {}
            trend["hosts"] = {}
            trend["model_eras"] = {}
            path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(trend), encoding="utf-8")

            self.assertEqual(MODULE.validate_root(root), [])

    def test_episode_start_must_not_be_after_end(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = valid_episode()
            episode["start"] = "2026-05-21T02:00:00Z"
            episode["end"] = "2026-05-21T01:00:00Z"
            path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            self.assertIn(
                "episode start must be before or equal to end",
                "\n".join(MODULE.validate_root(root)),
            )

    def test_trend_flagged_turn_count_cannot_exceed_turn_count(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            trend = valid_trend()
            trend["turn_count"] = 1
            trend["flagged_turn_count"] = 2
            path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(trend), encoding="utf-8")

            self.assertIn(
                "flagged_turn_count must be less than or equal to turn_count",
                "\n".join(MODULE.validate_root(root)),
            )

    def test_timestamps_reject_non_calendar_dates(self) -> None:
        self.assertFalse(MODULE.valid_timestamp("2025-02-29T00:00:00Z"))
        self.assertFalse(MODULE.valid_timestamp("2026-04-31T00:00:00Z"))
        self.assertTrue(MODULE.valid_timestamp("2024-02-29T00:00:00.123456789Z"))

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            trend = valid_trend()
            trend["window"]["start"] = "2025-02-29T00:00:00Z"
            path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(trend), encoding="utf-8")

            self.assertIn(
                "window.start must be timestamp", "\n".join(MODULE.validate_root(root))
            )

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = valid_episode()
            episode["start"] = "2026-04-31T00:00:00Z"
            path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            self.assertIn(
                "start must be timestamp or null", "\n".join(MODULE.validate_root(root))
            )

    def test_retained_mode_allows_daily_weekly_and_baseline_windows(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = valid_manifest()
            manifest["mode"] = "baseline-90d"
            manifest["window"] = window_for_mode("baseline-90d")
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            manifest_path.parent.mkdir(parents=True)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            self.assertEqual(MODULE.validate_root(root), [])

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_monthly_export(root)
            trend = valid_trend()
            trend["window"] = window_for_mode("weekly")
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            self.assertEqual(MODULE.validate_root(root), [])

    def test_monthly_manifest_only_export_bounds_rows_to_manifest_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = valid_episode()
            episode["start"] = "2026-05-20T00:00:00Z"
            episode["end"] = "2026-05-20T01:00:00Z"
            episode_path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            episode_path.parent.mkdir(parents=True)
            episode_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            turn = valid_turn_flag()
            turn["timestamp"] = "2026-05-20T00:00:00Z"
            turn_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            turn_path.parent.mkdir(parents=True)
            turn_path.write_text(json.dumps(turn) + "\n", encoding="utf-8")

            manifest = valid_manifest()
            manifest["mode"] = "weekly"
            manifest["window"] = {
                "mode": "weekly",
                "start": "2026-04-28T00:00:00Z",
                "end": "2026-05-05T00:00:00Z",
            }
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            manifest_path.parent.mkdir(parents=True)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/episodes/2026/05/episodes.jsonl:1: episode start/end must be within manifest window",
            issues,
        )
        self.assertIn(
            "data/turn_flags/2026/05/turn_flags.jsonl:1: timestamp must be within manifest window",
            issues,
        )

    def test_retained_mode_rejects_non_90_day_baselines(self) -> None:
        self.assertFalse(MODULE.valid_retained_mode("baseline-30d"))

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            trend = valid_trend()
            trend["window"] = {
                "mode": "baseline-30d",
                "start": "2026-04-22T00:00:00Z",
                "end": "2026-05-22T00:00:00Z",
            }
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("window.mode must be an allowed retained mode", issues)

    def test_manifest_mode_must_match_window_mode(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            manifest_path = export_dir / "retained_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["window"]["mode"] = "weekly"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/daily/retained_manifest.json: manifest mode must match window.mode",
            issues,
        )

    def test_flat_retained_export_mode_must_match_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            trend_path = export_dir / "trend_report.json"
            trend = json.loads(trend_path.read_text(encoding="utf-8"))
            trend["window"]["mode"] = "weekly"
            trend_path.write_text(json.dumps(trend), encoding="utf-8")
            manifest_path = export_dir / "retained_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["mode"] = "weekly"
            manifest["window"]["mode"] = "weekly"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/daily/trend_report.json: trend window.mode must match retained/daily export directory",
            issues,
        )
        self.assertIn(
            "retained/daily/retained_manifest.json: manifest mode must match retained/daily export directory",
            issues,
        )

    def test_baseline_retained_export_requires_single_concrete_mode(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "baseline"
            write_retained_export(root, export_dir)
            trend_path = export_dir / "trend_report.json"
            trend = json.loads(trend_path.read_text(encoding="utf-8"))
            trend["window"]["mode"] = "baseline-30d"
            trend_path.write_text(json.dumps(trend), encoding="utf-8")
            manifest_path = export_dir / "retained_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["mode"] = "baseline-90d"
            manifest["window"]["mode"] = "baseline-90d"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/baseline: retained export mode differs between trend and manifest",
            issues,
        )

    def test_flat_retained_export_window_must_match_between_manifest_and_trend(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            manifest_path = export_dir / "retained_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["window"]["end"] = "2026-05-23T00:00:00Z"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/daily: retained export window differs between trend and manifest",
            issues,
        )

    def test_monthly_retained_export_window_must_match_between_manifest_and_trend(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_monthly_export(root)
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            manifest_path.parent.mkdir(parents=True)
            manifest = valid_manifest()
            manifest["window"]["start"] = "2026-05-20T00:00:00Z"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/2026/05: retained export window differs between trend and manifest",
            issues,
        )

    def test_customer_like_modes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = valid_manifest()
            manifest["mode"] = "customer-acme"
            manifest["window"]["mode"] = "customer-acme"
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            manifest_path.parent.mkdir(parents=True)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            trend = valid_trend()
            trend["window"]["mode"] = "customer-acme"
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn("manifest mode must be an allowed retained mode", issues)
            self.assertIn("window.mode must be an allowed retained mode", issues)

    def test_retained_models_are_restricted_to_allowed_labels(self) -> None:
        self.assertTrue(MODULE.valid_retained_model_id("gpt-5.6-sol"))
        self.assertTrue(MODULE.valid_retained_model_era("gpt-5.6-sol"))
        self.assertTrue(MODULE.valid_retained_model_id("gpt-5.6-terra"))
        self.assertTrue(MODULE.valid_retained_model_era("gpt-5.6-terra"))
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = valid_episode()
            episode["model_era"] = "customer-model"
            episode_path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            episode_path.parent.mkdir(parents=True)
            episode_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            turn_flag = valid_turn_flag()
            turn_flag["model"] = "customer-model"
            turn_flag["model_era"] = "customer-model"
            turn_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            turn_path.parent.mkdir(parents=True)
            turn_path.write_text(json.dumps(turn_flag) + "\n", encoding="utf-8")

            trend = valid_trend()
            trend["model_eras"] = {"customer-model": 1}
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn("model_era must be an allowed retained model era", issues)
            self.assertIn("model must be an allowed retained model id or null", issues)
            self.assertIn(
                "model_eras key must be an allowed retained model era", issues
            )

    def test_source_hashes_must_use_retained_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            row = valid_turn_flag()
            row["source_hash"] = "e" * 64
            path = root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(row) + "\n", encoding="utf-8")

            self.assertIn(
                "source_hash must be source_hash_v1",
                "\n".join(MODULE.validate_root(root)),
            )

    def test_admin_infrastructure_rejects_high_confidence_secrets(self) -> None:
        for relative_path, text in (
            ("README.md", risky_github_classic_token() + "\n"),
            (".github/workflows/ci.yml", "# " + risky_github_classic_token() + "\n"),
            ("scripts/probe.py", "# " + risky_github_classic_token() + "\n"),
            (
                "schemas/session-retrospective-v1.schema.json",
                json.dumps({"value": risky_github_classic_token()}) + "\n",
            ),
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    path = root / relative_path
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(text, encoding="utf-8")

                    self.assertIn(
                        "admin infrastructure contains a high-confidence secret",
                        "\n".join(MODULE.validate_root(root)),
                    )

    def test_admin_infrastructure_rejects_standard_private_key_blocks(
        self,
    ) -> None:
        for marker in ("PRIVATE KEY", "ENCRYPTED PRIVATE KEY"):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                (root / "README.md").write_text(
                    f"-----BEGIN {marker}-----\nfixture\n",
                    encoding="utf-8",
                )

                issues = MODULE.validate_root(root)

            self.assertIn(
                "README.md: admin infrastructure contains a high-confidence secret",
                issues,
            )

    def test_current_tree_rejects_authorization_bearer_credential(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(
                ["git", "init", "--quiet"],
                cwd=root,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            (root / "README.md").write_bytes(
                b"Authorization: " + b"Bearer " + b"0123456789abcdef\n"
            )
            subprocess.run(
                ["git", "add", "README.md"],
                cwd=root,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            issues = MODULE.validate_root(root)

        self.assertIn(
            "README.md: admin infrastructure contains a high-confidence secret",
            issues,
        )

    def test_current_tree_rejects_binary_openpgp_secret_key_packet(self) -> None:
        key_prefix = b"\x04\x00\x00\x00\x00\x01"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(
                ["git", "init", "--quiet"],
                cwd=root,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            (root / "README.md").write_bytes(
                b"reviewed-prefix\x00\xc5\x06" + key_prefix + b"\x00reviewed-suffix"
            )
            subprocess.run(
                ["git", "add", "README.md"],
                cwd=root,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            issues = MODULE.validate_root(root)

        self.assertIn(
            "README.md: admin infrastructure contains a high-confidence secret",
            issues,
        )

    def test_openpgp_partial_body_chains_detect_secret_packets(self) -> None:
        key_prefix = b"\x04\x00\x00\x00\x00\x01"
        fragmented_body = (
            b"\xe0"
            + key_prefix[:1]
            + b"\xe1"
            + key_prefix[1:3]
            + b"\x03"
            + key_prefix[3:]
        )

        for tag in (5, 7):
            with self.subTest(tag=tag):
                packet = bytes((0xC0 | tag,)) + fragmented_body
                self.assertTrue(MODULE.contains_high_confidence_credential(packet))

    def test_openpgp_partial_body_chains_fail_closed_when_malformed(self) -> None:
        malformed_packets = (
            b"\xc5\xe0",
            b"\xc5\xe0\x04",
            b"\xc5\xe0\x04\xc0",
            b"\xc7\xe0\x04\x02\x00",
            b"\xc7\xfe\x04",
            b"\xc5" + (b"\xe0\x00" * 65) + b"\x00",
        )

        for packet in malformed_packets:
            with self.subTest(packet=packet[:8]):
                self.assertTrue(MODULE.contains_high_confidence_credential(packet))

    def test_openpgp_partial_body_chains_allow_benign_packets(self) -> None:
        key_prefix = b"\x04\x00\x00\x00\x00\x01"
        fragmented_body = b"\xe0" + key_prefix[:1] + b"\x05" + key_prefix[1:]
        benign_packets = (
            b"\xc6" + fragmented_body,
            b"\xc5\xe0\x01\x05\x00\x00\x00\x00\x00",
            b"\xc5\xe0\x04\x00",
            b"\xc6\xe0",
        )

        for packet in benign_packets:
            with self.subTest(packet=packet):
                self.assertFalse(MODULE.contains_high_confidence_credential(packet))

    def test_retained_text_rejects_common_service_credentials(self) -> None:
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
                self.assertEqual(
                    MODULE.validate_retained_text(credential, "fixture"),
                    ["fixture contains retained-text risk"],
                )

    def test_admin_infrastructure_rejects_common_service_credentials(self) -> None:
        credentials = (
            b"ASIA" + b"A" * 16,
            b"xoxb-" + b"A" * 20,
            b"xoxe-" + b"A" * 20,
            b"AIza" + b"A" * 35,
            b"glpat-" + b"A" * 20,
            b"npm_" + b"A" * 36,
        )
        for credential in credentials:
            with (
                self.subTest(prefix=credential[:6]),
                tempfile.TemporaryDirectory() as raw,
            ):
                root = Path(raw)
                (root / "README.md").write_bytes(b"credential=" + credential + b"\n")

                issues = MODULE.validate_root(root)

            self.assertIn(
                "README.md: admin infrastructure contains a high-confidence secret",
                issues,
            )

    def test_admin_infrastructure_does_not_claim_source_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "README.md").write_text(
                "\n".join(
                    (
                        "Internal example: " + risky_internal_url(),
                        "Operator: " + risky_email(),
                        "customer_data = ['reviewed source fixture']",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "retrospective-history-v2-admin-public.asc").write_text(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
                "reviewed-public-key-fixture\n"
                "-----END PGP PUBLIC KEY BLOCK-----\n",
                encoding="utf-8",
            )

            self.assertEqual(MODULE.validate_root(root), [])

    def test_sensitive_name_heuristic_does_not_hide_allowlisted_infrastructure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            helper = root / "scripts" / "retrospective_history_credentials_v2.py"
            helper.parent.mkdir(parents=True)
            helper.write_text(
                "def is_safe() -> bool:\n    return True\n", encoding="utf-8"
            )

            self.assertEqual(MODULE.validate_root(root), [])

            ordinary = root / "credentials.py"
            ordinary.write_text("reviewed = True\n", encoding="utf-8")
            issues = MODULE.validate_root(root)

        self.assertTrue(
            any("forbidden raw/transient artifact" in issue for issue in issues)
        )

    def test_admin_infrastructure_file_budget_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "README.md").write_bytes(b"x" * (MODULE.MAX_ADMIN_BLOB_BYTES + 1))

            self.assertIn(
                "admin infrastructure exceeds the file byte limit",
                "\n".join(MODULE.validate_root(root)),
            )

    def test_validate_root_dispatches_v2_once(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with (
                mock.patch.object(MODULE, "iter_files", return_value=[]) as iter_files,
                mock.patch.object(
                    MODULE,
                    "validate_v2_runs_with_inventory",
                    return_value=(["v2 issue"], ()),
                ) as validate_v2,
                mock.patch.object(MODULE, "_verify_publisher_attestation") as verifier,
            ):
                self.assertEqual(MODULE.validate_root(root), ["v2 issue"])

            iter_files.assert_called_once_with(root.resolve())
            validate_v2.assert_called_once_with(root.resolve(), [])
            verifier.assert_not_called()

    def test_validate_root_does_not_verify_candidate_paths_after_structural_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for index in range(200):
                path = root / "runs" / f"malformed-{index:03d}" / "manifest.json"
                path.parent.mkdir(parents=True)
                path.write_text("{}\n", encoding="ascii")

            with mock.patch.object(MODULE, "_verify_publisher_attestation") as verifier:
                issues = MODULE.validate_root(root)

        self.assertTrue(issues)
        verifier.assert_not_called()

    def test_publisher_attestation_budget_is_checked_before_verifier_launches(
        self,
    ) -> None:
        admitted = tuple(
            Path("runs") / f"bundle-{index:03d}" / "manifest.json"
            for index in range(MODULE.MAX_BUNDLES + 1)
        )
        with tempfile.TemporaryDirectory() as raw:
            with mock.patch.object(MODULE, "_verify_publisher_attestation") as verifier:
                issues = MODULE.validate_v2_publisher_attestations(Path(raw), admitted)

        self.assertEqual(
            issues, ["v2 publisher attestation verification budget exceeded"]
        )
        verifier.assert_not_called()

    def test_validate_root_rejects_each_invalid_publisher_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifests = (
                root / "runs" / "first" / "manifest.json",
                root / "runs" / "second" / "manifest.json",
            )
            for index, path in enumerate(manifests):
                path.parent.mkdir(parents=True)
                path.write_bytes(f'{{"fixture":{index}}}\n'.encode("ascii"))

            with (
                mock.patch.object(
                    MODULE,
                    "validate_v2_runs_with_inventory",
                    return_value=(
                        [],
                        tuple(path.relative_to(root) for path in manifests),
                    ),
                ),
                mock.patch.object(
                    MODULE,
                    "_verify_publisher_attestation",
                    side_effect=(True, False),
                ) as verifier,
            ):
                issues = MODULE.validate_root(root)

        self.assertEqual(
            issues,
            ["runs/second/manifest.json: publisher attestation is invalid"],
        )
        self.assertEqual(
            [call.args[0] for call in verifier.call_args_list],
            [
                {"manifest.json": b'{"fixture":0}\n'},
                {"manifest.json": b'{"fixture":1}\n'},
            ],
        )

    def test_validate_root_cryptographically_verifies_every_publisher_attestation(
        self,
    ) -> None:
        from tests.test_retrospective_history_v2 import write_bundle

        gpg = shutil.which("gpg")
        gpgconf = shutil.which("gpgconf")
        if gpg is None or gpgconf is None:
            self.skipTest("gpg and gpgconf are required")

        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            gnupg_home = temporary / "gnupg"
            gnupg_home.mkdir(mode=0o700)

            def run_gpg(*arguments: str) -> bytes:
                result = subprocess.run(
                    [gpg, *arguments],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=60,
                )
                if result.returncode != 0:
                    raise AssertionError(
                        result.stderr.decode("utf-8", errors="replace")
                    )
                return result.stdout

            try:
                try:
                    run_gpg(
                        "--batch",
                        "--homedir",
                        str(gnupg_home),
                        "--pinentry-mode",
                        "loopback",
                        "--passphrase",
                        "",
                        "--quick-generate-key",
                        "History Publisher Test <history-publisher@example.invalid>",
                        "ed25519",
                        "sign",
                        "0",
                    )
                except AssertionError as exc:
                    self.skipTest(f"gpg agent is unavailable: {exc}")

                listing = run_gpg(
                    "--batch",
                    "--homedir",
                    str(gnupg_home),
                    "--with-colons",
                    "--list-secret-keys",
                )
                fingerprints = [
                    line.split(b":")[9]
                    for line in listing.splitlines()
                    if line.startswith(b"fpr:")
                ]
                self.assertTrue(fingerprints)
                fingerprint = fingerprints[0]

                root = temporary / "repository"
                refs = write_bundle(root, 1)
                manifest_path = refs.directory / "manifest.json"
                manifest = json.loads(manifest_path.read_bytes())
                coordinates = (
                    (
                        manifest["run_ref"],
                        manifest["retained_bundle_digest_v2"],
                    ),
                    (
                        manifest["run_ref"],
                        "retained_bundle_digest_v2:sha256:" + "c" * 64,
                    ),
                )
                signatures: list[str] = []
                for index, (run_ref, bundle_digest) in enumerate(coordinates):
                    payload_path = temporary / f"publisher-payload-{index}.bin"
                    signature_path = temporary / f"publisher-signature-{index}.asc"
                    payload_path.write_bytes(
                        publisher_attestation_payload(run_ref, bundle_digest)
                    )
                    run_gpg(
                        "--batch",
                        "--homedir",
                        str(gnupg_home),
                        "--pinentry-mode",
                        "loopback",
                        "--passphrase",
                        "",
                        "--armor",
                        "--local-user",
                        fingerprint.decode("ascii"),
                        "--output",
                        str(signature_path),
                        "--detach-sign",
                        str(payload_path),
                    )
                    signatures.append(
                        signature_path.read_text(encoding="ascii").rstrip("\n")
                    )

                manifest["publisher_attestation"] = {
                    "scheme": "openpgp-detached-v1",
                    "signer_fingerprint": fingerprint.decode("ascii"),
                    "signature": signatures[0],
                }
                manifest_path.write_text(
                    json.dumps(
                        manifest,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    encoding="utf-8",
                )
                attestation_issue = (
                    f"{manifest_path.relative_to(root).as_posix()}: "
                    "publisher attestation is invalid"
                )

                verifier_module = sys.modules[
                    MODULE._verify_publisher_attestation.__module__
                ]
                with (
                    mock.patch.dict(
                        os.environ, {"GNUPGHOME": str(gnupg_home)}, clear=False
                    ),
                    mock.patch.object(
                        verifier_module,
                        "V2_SIGNING_FINGERPRINTS",
                        frozenset({fingerprint}),
                    ),
                ):
                    self.assertEqual(MODULE.validate_root(root), [])

                    replaced_attestation = json.loads(json.dumps(manifest))
                    replaced_attestation["publisher_attestation"]["signature"] = (
                        signatures[1]
                    )
                    manifest_path.write_text(
                        json.dumps(
                            replaced_attestation,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        encoding="utf-8",
                    )
                    self.assertEqual(
                        MODULE.validate_root(root),
                        [attestation_issue],
                    )

                    manifest_path.write_text(
                        json.dumps(
                            manifest,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        encoding="utf-8",
                    )
                    empty_gnupg_home = temporary / "empty-gnupg"
                    empty_gnupg_home.mkdir(mode=0o700)
                    with mock.patch.dict(
                        os.environ,
                        {"GNUPGHOME": str(empty_gnupg_home)},
                        clear=False,
                    ):
                        self.assertEqual(
                            MODULE.validate_root(root), [attestation_issue]
                        )

                    with mock.patch.object(
                        verifier_module,
                        "_run_process_bounded",
                        side_effect=OSError("gpg is unavailable"),
                    ):
                        self.assertEqual(
                            MODULE.validate_root(root), [attestation_issue]
                        )
            finally:
                subprocess.run(
                    [gpgconf, "--homedir", str(gnupg_home), "--kill", "gpg-agent"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=60,
                )

    def test_main_requires_a_complete_revision_pair(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(SystemExit) as raised:
                MODULE.main(["--root", raw, "--base-rev", "base"])

        self.assertEqual(raised.exception.code, 2)

    def test_main_runs_tree_and_append_only_validation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with (
                mock.patch.object(
                    MODULE, "validate_fixed_head_snapshot", return_value=[]
                ) as validate_snapshot,
                mock.patch.object(
                    MODULE, "validate_append_only_range", return_value=[]
                ) as validate_range,
                mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
            ):
                result = MODULE.main(
                    ["--root", str(root), "--base-rev", "base", "--head-rev", "head"]
                )

            self.assertEqual(result, 0)
            self.assertEqual(stdout.getvalue(), "retained history is valid\n")
            validate_snapshot.assert_called_once_with(root, "head")
            validate_range.assert_called_once_with(root, "base", "head")

    def test_main_uses_event_range_validation(self) -> None:
        base_rev = "a" * 40
        head_rev = "b" * 40
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with (
                mock.patch.object(
                    MODULE, "validate_fixed_head_snapshot", return_value=[]
                ) as validate_snapshot,
                mock.patch.object(
                    MODULE, "validate_append_only_event_range", return_value=[]
                ) as validate_event_range,
                mock.patch("sys.stdout", new_callable=io.StringIO),
            ):
                result = MODULE.main(
                    [
                        "--root",
                        str(root),
                        "--base-rev",
                        base_rev,
                        "--head-rev",
                        head_rev,
                        "--event-forced",
                        "false",
                    ]
                )

        self.assertEqual(result, 0)
        validate_snapshot.assert_called_once_with(root, head_rev)
        validate_event_range.assert_called_once_with(
            root, base_rev, head_rev, forced=False
        )

    def test_pull_request_candidate_runs_global_head_checks_before_squash(self) -> None:
        root = Path.cwd()
        with (
            mock.patch.object(
                MODULE, "validate_fixed_head_snapshot", return_value=[]
            ) as validate_snapshot,
            mock.patch.object(
                MODULE,
                "build_pull_request_merge_plan",
                return_value=(mock.sentinel.plan, []),
            ) as build_plan,
        ):
            self.assertEqual(
                MODULE.validate_pull_request_candidate(
                    root,
                    "base",
                    "head",
                ),
                [],
            )

        validate_snapshot.assert_called_once_with(root, "head")
        build_plan.assert_called_once_with(root, "base", "head")

        with (
            mock.patch.object(
                MODULE,
                "validate_fixed_head_snapshot",
                return_value=["global revision closure failed"],
            ),
            mock.patch.object(MODULE, "build_pull_request_merge_plan") as build_plan,
        ):
            self.assertEqual(
                MODULE.validate_pull_request_candidate(root, "base", "head"),
                ["global revision closure failed"],
            )
        build_plan.assert_not_called()

    def test_main_writes_canonical_immutable_merge_plan(self) -> None:
        plan = MODULE.PullRequestMergePlan(
            base_oid="a" * 40,
            head_oid="b" * 40,
            head_tree_oid="c" * 40,
            squash_subject="Administer session retrospective history v2: policy",
            trust_generation="sha256:" + "d" * 64,
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            output = root / "merge-plan.json"
            with (
                mock.patch.object(
                    MODULE,
                    "build_pull_request_candidate_plan",
                    return_value=(plan, []),
                ) as build_plan,
                mock.patch("sys.stdout", new_callable=io.StringIO),
            ):
                result = MODULE.main(
                    [
                        "--root",
                        str(root),
                        "--base-rev",
                        plan.base_oid,
                        "--head-rev",
                        plan.head_oid,
                        "--write-merge-plan",
                        str(output),
                    ]
                )
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(result, 0)
        build_plan.assert_called_once_with(root, plan.base_oid, plan.head_oid)
        self.assertEqual(payload, plan.as_dict())

    def test_main_rejects_mismatched_checkout_before_tree_validation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with (
                mock.patch.object(
                    MODULE,
                    "validate_fixed_head_snapshot",
                    return_value=["range: checkout mismatch"],
                ),
                mock.patch.object(
                    MODULE, "validate_append_only_range"
                ) as validate_range,
                mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
            ):
                result = MODULE.main(
                    ["--root", str(root), "--base-rev", "base", "--head-rev", "head"]
                )

        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "range: checkout mismatch\n")
        validate_range.assert_not_called()

    def test_event_range_rejects_force_push_zero_and_invalid_shas(self) -> None:
        valid_base = "a" * 40
        valid_head = "b" * 40
        with mock.patch.object(
            MODULE, "validate_default_branch_update"
        ) as validate_range:
            self.assertEqual(
                MODULE.validate_append_only_event_range(
                    Path.cwd(), valid_base, valid_head, forced=True
                ),
                ["range: force-push event is not append-only"],
            )
            self.assertEqual(
                MODULE.validate_append_only_event_range(
                    Path.cwd(), "0" * 40, valid_head, forced=False
                ),
                ["range: base event SHA is zero"],
            )
            self.assertEqual(
                MODULE.validate_append_only_event_range(
                    Path.cwd(), valid_base, "HEAD", forced=False
                ),
                ["range: head event SHA is invalid"],
            )

        validate_range.assert_not_called()

    def test_event_range_preserves_non_descendant_failure(self) -> None:
        base_rev = "a" * 40
        head_rev = "b" * 40
        expected = ["range: head is not a fast-forward descendant of base"]
        with mock.patch.object(
            MODULE, "validate_default_branch_update", return_value=expected
        ) as validate_range:
            self.assertEqual(
                MODULE.validate_append_only_event_range(
                    Path.cwd(), base_rev, head_rev, forced=False
                ),
                expected,
            )

        validate_range.assert_called_once_with(Path.cwd(), base_rev, head_rev)

    def test_retained_text_rejects_bare_private_ip_addresses(self) -> None:
        for report_sample, row_sample in (
            (risky_bare_private_ip(), risky_bare_private_lan_ip()),
            (risky_link_local_ip(), risky_cgnat_ip()),
            (risky_private_ipv6(), risky_link_local_ipv6()),
            (risky_loopback_ipv6(), risky_bare_private_ip()),
        ):
            with self.subTest(report_sample=report_sample, row_sample=row_sample):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    report = root / "reports" / "daily" / "2026" / "05" / "22.md"
                    report.parent.mkdir(parents=True)
                    report.write_text(
                        "Investigated host " + report_sample + "\n", encoding="utf-8"
                    )

                    turn = valid_turn_flag()
                    turn["redacted_user_prompt_summary"] = (
                        "Investigated host " + row_sample
                    )
                    turn_path = (
                        root
                        / "data"
                        / "turn_flags"
                        / "2026"
                        / "05"
                        / "turn_flags.jsonl"
                    )
                    turn_path.parent.mkdir(parents=True)
                    turn_path.write_text(json.dumps(turn) + "\n", encoding="utf-8")

                    issues = "\n".join(MODULE.validate_root(root))

                self.assertIn(
                    "reports/daily/2026/05/22.md: retained text contains raw/sensitive evidence",
                    issues,
                )
                self.assertIn(
                    "data/turn_flags/2026/05/turn_flags.jsonl:1: redacted_user_prompt_summary contains retained-text risk",
                    issues,
                )

    def test_safe_tokens_reject_risky_structured_values(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = {
                "episode_id": "episode_ref_v1:" + "a" * 20,
                "host": risky_internal_host(),
                "session_id": "session_ref_v1:" + "b" * 20,
                "start": "2026-05-21T00:00:00Z",
                "end": "2026-05-21T01:00:00Z",
                "cwd": None,
                "model_era": "unknown",
                "topic": "Redacted topic",
                "turn_count": 1,
                "friction_flags": [],
                "outcome": "needs_review",
                "work_report_hint": None,
            }
            episode_path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            episode_path.parent.mkdir(parents=True)
            episode_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")
            trend = {
                "schema_version": 1,
                "window": {
                    "mode": "daily",
                    "start": "2026-05-21T00:00:00Z",
                    "end": "2026-05-22T00:00:00Z",
                },
                "turn_count": 1,
                "flagged_turn_count": 1,
                "episode_count": 1,
                "flags": {risky_secret_token(): 1},
                "hosts": {risky_internal_host(): 1},
                "model_eras": {risky_uuid(): 1},
                "coverage_gaps": [],
            }
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")
            manifest = valid_manifest()
            manifest["sources"][0]["host"] = risky_internal_host()
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            manifest_path.parent.mkdir(parents=True)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn("host must be an allowed retained host", issues)
            self.assertIn("flags key must be a safe token", issues)
            self.assertIn("hosts key must be a safe token", issues)
            self.assertIn("hosts key must be an allowed retained host", issues)
            self.assertIn("model_eras key must be a safe token", issues)
            self.assertIn("source host must be an allowed retained host", issues)

    def test_customer_like_host_labels_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = valid_episode()
            episode["host"] = "customer-acme"
            episode_path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            episode_path.parent.mkdir(parents=True)
            episode_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            trend = valid_trend()
            trend["hosts"] = {"customer-acme": 1}
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            manifest = valid_manifest()
            manifest["sources"][0]["host"] = "customer-acme"
            manifest["coverage_gaps"] = [
                {"host": "customer-acme", "reason": "stale_host"}
            ]
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            manifest_path.parent.mkdir(parents=True)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn("host must be an allowed retained host", issues)
            self.assertIn("hosts key must be an allowed retained host", issues)
            self.assertIn("source host must be an allowed retained host", issues)
            self.assertIn("coverage gap host must be an allowed retained host", issues)

    def test_scope_is_only_allowed_for_coverage_gap_host(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = valid_manifest()
            manifest["coverage_gaps"] = [
                {"host": "scope", "reason": "partial_host_scope"}
            ]
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            manifest_path.parent.mkdir(parents=True)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(MODULE.validate_root(root), [])

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            trend = valid_trend()
            trend["hosts"] = {"scope": 1}
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            self.assertIn(
                "hosts key must be an allowed retained host",
                "\n".join(MODULE.validate_root(root)),
            )

    def test_source_safety_coverage_reasons_are_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = valid_manifest()
            manifest["coverage_gaps"] = [
                {
                    "host": "local",
                    "reason": "source_root_symlink",
                    "root_ref": "path_ref_v1:aaaaaaaaaaaaaaaa",
                },
                {
                    "host": "custom_source",
                    "reason": "unsafe_source_artifact",
                    "root_ref": "path_ref_v1:aaaaaaaaaaaaaaaa",
                },
                {
                    "host": "local",
                    "reason": "truncated_rollout_summary",
                    "root_ref": "path_ref_v1:aaaaaaaaaaaaaaaa",
                },
            ]
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            manifest_path.parent.mkdir(parents=True)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            self.assertEqual(MODULE.validate_root(root), [])

    def test_missing_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "missing"

            self.assertEqual(
                MODULE.validate_root(root), ["root must be an existing directory"]
            )

    def test_count_maps_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            trend = {
                "schema_version": 1,
                "window": {
                    "mode": "daily",
                    "start": "2026-05-21T00:00:00Z",
                    "end": "2026-05-22T00:00:00Z",
                },
                "turn_count": 1,
                "flagged_turn_count": 1,
                "episode_count": 1,
                "flags": {f"flag{index}": 1 for index in range(65)},
                "hosts": {"local": 1_000_001},
                "model_eras": {"unknown": 1},
                "coverage_gaps": [],
            }
            path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(trend), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn("flags must contain at most 64 keys", issues)
            self.assertIn("hosts value must be a bounded non-negative integer", issues)

    def test_manifest_max_item_limits_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = valid_manifest()
            manifest["sources"] = [
                {
                    "host": f"host{index}",
                    "root_ref": f"path_ref_v1:{index:016x}",
                    "status": "ready",
                    "rollout_count": 1,
                    "summary_count": 0,
                }
                for index in range(17)
            ]
            manifest["coverage_gaps"] = [
                {"host": "local", "reason": "unreachable"} for _index in range(101)
            ]
            path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn("manifest sources must contain at most 16 items", issues)
            self.assertIn("coverage_gaps must contain at most 100 items", issues)

    def test_invalid_ready_source_counts_do_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = valid_manifest()
            manifest["sources"][0]["rollout_count"] = "1"
            manifest["sources"][0]["summary_count"] = None
            path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn(
                "source rollout_count must be a bounded non-negative integer", issues
            )
            self.assertIn(
                "source summary_count must be a bounded non-negative integer", issues
            )
            self.assertIn(
                "ready source must have rollout_count or summary_count", issues
            )

    def test_git_visible_invalid_runs_entries_fail_closed_without_disclosure(
        self,
    ) -> None:
        for case in (
            "legacy-sensitive-file",
            "short-symlink",
            "tracked-missing-file",
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                subprocess.run(
                    ["git", "init", "--quiet"],
                    cwd=root,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if case == "legacy-sensitive-file":
                    artifact = root / "runs" / "v1" / "raw-session.jsonl"
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text(
                        json.dumps({"to" + "ken": risky_secret_token()}) + "\n",
                        encoding="utf-8",
                    )
                    undisclosed = ("raw-session", risky_secret_token())
                else:
                    if case == "short-symlink":
                        artifact = root / "runs" / "latest"
                        artifact.parent.mkdir(parents=True)
                        os.symlink(risky_local_path(), artifact)
                        undisclosed = ("latest", risky_local_path())
                    else:
                        artifact = root / "runs" / "v1" / "deleted.jsonl"
                        artifact.parent.mkdir(parents=True)
                        artifact.write_text("{}\n", encoding="utf-8")
                        subprocess.run(
                            ["git", "add", "--", str(artifact.relative_to(root))],
                            cwd=root,
                            check=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                        artifact.unlink()
                        undisclosed = ("deleted.jsonl",)

                issues = MODULE.validate_root(root)

                self.assertIn(
                    "runs/[invalid]: invalid v2 retained-run path",
                    issues,
                )
                rendered = "\n".join(issues)
                for value in undisclosed:
                    self.assertNotIn(value, rendered)

    def test_git_visible_inventory_byte_and_entry_caps_fail_closed(self) -> None:
        for limit in ("bytes", "entries"):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                subprocess.run(
                    ["git", "init", "--quiet"],
                    cwd=root,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                (root / "first.txt").write_text("first\n", encoding="utf-8")
                (root / "second.txt").write_text("second\n", encoding="utf-8")
                patcher = (
                    mock.patch.object(MODULE, "MAX_GIT_VISIBLE_OUTPUT_BYTES", 1)
                    if limit == "bytes"
                    else mock.patch.object(MODULE, "MAX_GIT_VISIBLE_FILE_ENTRIES", 1)
                )

                with patcher:
                    issues = MODULE.validate_root(root)

                self.assertEqual(issues, [MODULE.GIT_VISIBLE_INVENTORY_ISSUE])
                self.assertNotIn("first.txt", issues[0])
                self.assertNotIn("second.txt", issues[0])

    def test_git_visible_inventory_rejects_malformed_nul_stream(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()

            def fake_stream(
                command: list[str],
                *,
                byte_limit: int,
                consume_chunk: Callable[[bytes], None],
            ) -> int:
                del byte_limit
                if "rev-parse" in command:
                    consume_chunk(f"{root}\n".encode("utf-8"))
                else:
                    consume_chunk(b"runs/v1/raw-session.jsonl")
                return 0

            with mock.patch.object(
                MODULE,
                "_stream_process_stdout",
                side_effect=fake_stream,
            ):
                issues = MODULE.validate_root(root)

        self.assertEqual(issues, [MODULE.GIT_VISIBLE_INVENTORY_ISSUE])
        self.assertNotIn("raw-session", issues[0])

    def test_git_visible_inventory_timeout_and_process_failure_fail_closed(
        self,
    ) -> None:
        with self.subTest(failure="timeout"):
            with mock.patch.object(MODULE, "GIT_INVENTORY_TIMEOUT_SECONDS", 0.01):
                with self.assertRaises(MODULE.GitVisibleInventoryError):
                    MODULE._stream_process_stdout(
                        [
                            sys.executable,
                            "-c",
                            "import time; time.sleep(1)",
                        ],
                        byte_limit=1,
                        consume_chunk=lambda _chunk: None,
                    )

        with self.subTest(failure="process"):
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve()

                def fake_stream(
                    command: list[str],
                    *,
                    byte_limit: int,
                    consume_chunk: Callable[[bytes], None],
                ) -> int:
                    del byte_limit
                    if "rev-parse" in command:
                        consume_chunk(f"{root}\n".encode("utf-8"))
                        return 0
                    return 7

                with mock.patch.object(
                    MODULE,
                    "_stream_process_stdout",
                    side_effect=fake_stream,
                ):
                    issues = MODULE.validate_root(root)

            self.assertEqual(issues, [MODULE.GIT_VISIBLE_INVENTORY_ISSUE])

    def test_git_ignored_local_temp_dirs_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(
                ["git", "init"], cwd=root, check=True, stdout=subprocess.DEVNULL
            )
            (root / ".gitignore").write_text(".codex" + "-tmp/\n", encoding="utf-8")
            helper_state = root / ".codex-tmp" / "isolated-review" / "state.json"
            helper_state.parent.mkdir(parents=True)
            helper_state.write_text(
                json.dumps({"raw": risky_internal_url()}) + "\n", encoding="utf-8"
            )
            report = root / "reports" / "weekly" / "2026" / "05" / "08.md"
            report.parent.mkdir(parents=True)
            report.write_text(
                "# Weekly retrospective\n\nNo raw transcript excerpts retained.\n",
                encoding="utf-8",
            )

            self.assertEqual(MODULE.validate_root(root), [])

    def test_git_inventory_strips_hostile_repository_environment(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            root = temporary / "repository"
            root.mkdir()
            subprocess.run(
                ["git", "init", "--quiet"],
                cwd=root,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            (root / "README.md").write_text("retained history\n", encoding="utf-8")
            subprocess.run(
                ["git", "add", "README.md"],
                cwd=root,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            captured_environments: list[dict[str, str]] = []
            original_popen = subprocess.Popen

            def capture_popen(
                *args: object, **kwargs: object
            ) -> subprocess.Popen[bytes]:
                environment = kwargs.get("env")
                if isinstance(environment, dict):
                    captured_environments.append(dict(environment))
                return original_popen(*args, **kwargs)  # type: ignore[arg-type]

            hostile = {
                "GIT_DIR": str(temporary / "hostile-git-dir"),
                "GIT_INDEX_FILE": str(temporary / "hostile-index"),
                "GIT_WORK_TREE": str(temporary / "hostile-work-tree"),
            }
            with (
                mock.patch.dict(os.environ, hostile, clear=False),
                mock.patch.object(
                    MODULE.subprocess,
                    "Popen",
                    side_effect=capture_popen,
                ),
            ):
                visible = MODULE.git_visible_files(root)

        self.assertEqual(visible, [root.resolve() / "README.md"])
        self.assertGreaterEqual(len(captured_environments), 2)
        for environment in captured_environments:
            for variable in hostile:
                self.assertNotIn(variable, environment)
            self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
            self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")

    def test_stable_reader_rejects_same_size_atomic_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifact = root / "report.txt"
            replacement = root / "replacement.txt"
            artifact.write_bytes(b"safe\n")
            replacement.write_bytes(b"evil\n")
            original_read = os.read
            replaced = False

            def replace_after_read(descriptor: int, count: int) -> bytes:
                nonlocal replaced
                payload = original_read(descriptor, count)
                if not replaced:
                    replaced = True
                    os.replace(replacement, artifact)
                return payload

            with mock.patch.object(MODULE.os, "read", side_effect=replace_after_read):
                with self.assertRaises(MODULE.RetainedFileChangedError):
                    MODULE.read_file_bytes_stable(artifact)

        self.assertTrue(replaced)

    def test_fixed_snapshot_rejects_same_size_atomic_worktree_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            root = temporary / "repository"
            root.mkdir()
            subprocess.run(
                ["git", "init", "--quiet"],
                cwd=root,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["git", "config", "user.name", "Fixture"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "fixture@example.invalid"],
                cwd=root,
                check=True,
            )
            (root / "README.md").write_bytes(b"safe\n")
            subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "--quiet", "--no-gpg-sign", "-m", "Fixture"],
                cwd=root,
                check=True,
            )
            head = subprocess.run(
                ["git", "rev-parse", "HEAD^{commit}"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            def replace_worktree(snapshot: Path) -> list[str]:
                self.assertEqual((snapshot / "README.md").read_bytes(), b"safe\n")
                replacement = temporary / "replacement.txt"
                replacement.write_bytes(b"evil\n")
                os.replace(replacement, root / "README.md")
                return []

            with mock.patch.object(
                MODULE,
                "validate_root",
                side_effect=replace_worktree,
            ):
                issues = MODULE.validate_fixed_head_snapshot(root, head)

        self.assertIn(
            "range: checkout must be clean before retained tree validation",
            issues,
        )

    def test_fixed_snapshot_rechecks_head_after_validation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(
                ["git", "init", "--quiet"],
                cwd=root,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["git", "config", "user.name", "Fixture"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "fixture@example.invalid"],
                cwd=root,
                check=True,
            )
            (root / "README.md").write_text("first\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "--quiet", "--no-gpg-sign", "-m", "First"],
                cwd=root,
                check=True,
            )
            first = subprocess.run(
                ["git", "rev-parse", "HEAD^{commit}"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            (root / "README.md").write_text("second\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "--quiet", "--no-gpg-sign", "-m", "Second"],
                cwd=root,
                check=True,
            )
            second = subprocess.run(
                ["git", "rev-parse", "HEAD^{commit}"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            subprocess.run(
                ["git", "checkout", "--quiet", "--detach", first],
                cwd=root,
                check=True,
            )

            def switch_head(_snapshot: Path) -> list[str]:
                subprocess.run(
                    ["git", "update-ref", "HEAD", second],
                    cwd=root,
                    check=True,
                )
                return []

            with mock.patch.object(
                MODULE,
                "validate_root",
                side_effect=switch_head,
            ):
                issues = MODULE.validate_fixed_head_snapshot(root, first)

        self.assertIn(
            "range: checkout HEAD does not match the requested head revision",
            issues,
        )


if __name__ == "__main__":
    unittest.main()
