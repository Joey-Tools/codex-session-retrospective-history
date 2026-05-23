from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "validate_retained_history.py"
SCHEMA = Path(__file__).resolve().parents[1] / "schemas" / "session-retrospective-v1.schema.json"
MANIFEST_SCHEMA = Path(__file__).resolve().parents[1] / "schemas" / "retained-manifest-v1.schema.json"
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
    (export_dir / "episodes.jsonl").write_text(json.dumps(valid_episode()) + "\n", encoding="utf-8")
    (export_dir / "turn_flags.jsonl").write_text(json.dumps(valid_turn_flag()) + "\n", encoding="utf-8")
    (export_dir / "trend_report.json").write_text(json.dumps(trend), encoding="utf-8")
    (export_dir / "retained_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


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


def risky_secret_token() -> str:
    return "s" + "k-" + "proj-" + "abcdefghijklmnop123456"


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


def risky_compound_session_token() -> str:
    return "session_" + "id_abc123456"


def risky_compound_turn_token() -> str:
    return "turn-" + "id-abc123456"


def risky_compound_episode_token() -> str:
    return "episode." + "id.abc123456"


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
        self.assertEqual(sorted(schema["$defs"]["retained_coverage_host"]["enum"]), coverage_expected)
        self.assertEqual(sorted(manifest_schema["$defs"]["retained_host"]["enum"]), expected)
        self.assertEqual(sorted(manifest_schema["$defs"]["retained_coverage_host"]["enum"]), coverage_expected)
        self.assertEqual(schema["$defs"]["episode"]["properties"]["host"], {"$ref": "#/$defs/retained_host"})
        self.assertEqual(schema["$defs"]["turn_flag"]["properties"]["host"], {"$ref": "#/$defs/retained_host"})
        self.assertEqual(schema["$defs"]["source_summary"]["properties"]["host"], {"$ref": "#/$defs/retained_host"})
        self.assertEqual(schema["$defs"]["coverage_gap"]["properties"]["host"], {"$ref": "#/$defs/retained_coverage_host"})
        self.assertEqual(schema["$defs"]["trend"]["properties"]["hosts"], {"$ref": "#/$defs/retained_host_count_map"})
        self.assertEqual(manifest_schema["$defs"]["source_summary"]["properties"]["host"], {"$ref": "#/$defs/retained_host"})
        self.assertEqual(manifest_schema["$defs"]["coverage_gap"]["properties"]["host"], {"$ref": "#/$defs/retained_coverage_host"})

    def test_schema_coverage_gap_reasons_match_validator(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        manifest_schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))
        expected = sorted(MODULE.COVERAGE_REASONS)

        self.assertEqual(sorted(schema["$defs"]["coverage_gap"]["properties"]["reason"]["enum"]), expected)
        self.assertEqual(sorted(manifest_schema["$defs"]["coverage_gap"]["properties"]["reason"]["enum"]), expected)

    def test_schema_issue_flags_match_validator(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        expected = sorted(MODULE.ISSUE_FLAGS)

        self.assertEqual(sorted(schema["$defs"]["issue_flag"]["enum"]), expected)
        self.assertEqual(schema["$defs"]["episode"]["properties"]["friction_flags"]["items"], {"$ref": "#/$defs/issue_flag"})
        self.assertEqual(schema["$defs"]["turn_flag"]["properties"]["issue_flags"]["items"], {"$ref": "#/$defs/issue_flag"})
        self.assertEqual(schema["$defs"]["trend"]["properties"]["flags"], {"$ref": "#/$defs/issue_flag_count_map"})

    def test_schema_retained_text_patterns_cover_compound_secrets_and_case_paths(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        schema_patterns = [re.compile(item["pattern"]) for item in schema["$defs"]["retained_text"]["not"]["anyOf"]]
        patterns = "\n".join(pattern.pattern for pattern in schema_patterns)

        self.assertIn("[A-Za-z0-9._-]*(?:", patterns)
        self.assertIn("[Pp][Rr][Ii][Vv][Aa][Tt][Ee][\\s._-]+[Kk][Ee][Yy]", patterns)
        self.assertIn("[Uu][Ss][Ee][Rr][Ss]", patterns)
        self.assertIn("[Ww][Oo][Rr][Kk][Ss][Pp][Aa][Cc][Ee]", patterns)
        for sample in ("api " + "key: abc", "secret " + "key: abc", "private " + "key: abc"):
            with self.subTest(sample=sample):
                self.assertTrue(any(pattern.search(sample) for pattern in schema_patterns))
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
                self.assertTrue(any(pattern.search(sample) for pattern in schema_patterns))

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
        ):
            with self.subTest(text=text):
                self.assertIsNotNone(raw_id_re.search(text))

        self.assertIsNone(raw_id_re.search("session_id: session_ref_v1:" + "a" * 20))

    def test_schema_safe_token_patterns_cover_compound_secret_names(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        manifest_schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))
        schema_patterns = [re.compile(item["pattern"]) for item in schema["$defs"]["safe_token"]["not"]["anyOf"]]
        manifest_schema_patterns = [re.compile(item["pattern"]) for item in manifest_schema["$defs"]["safe_token"]["not"]["anyOf"]]
        patterns = "\n".join(pattern.pattern for pattern in schema_patterns)
        manifest_patterns = "\n".join(pattern.pattern for pattern in manifest_schema_patterns)

        self.assertIn("[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll][Ss]?", patterns)
        self.assertIn("[Pp][Rr][Ii][Vv][Aa][Tt][Ee][._-]?[Kk][Ee][Yy]", patterns)
        self.assertIn("[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll][Ss]?", manifest_patterns)
        self.assertIn("[Pp][Rr][Ii][Vv][Aa][Tt][Ee][._-]?[Kk][Ee][Yy]", manifest_patterns)
        for sample in (risky_compound_session_token(), risky_compound_turn_token(), risky_compound_episode_token()):
            with self.subTest(sample=sample):
                self.assertTrue(any(pattern.search(sample) for pattern in schema_patterns))
                self.assertTrue(any(pattern.search(sample) for pattern in manifest_schema_patterns))

    def test_schema_restricts_retained_modes_models_and_source_hashes(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        manifest_schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))

        self.assertEqual(sorted(schema["$defs"]["retained_mode"]["anyOf"][0]["enum"]), sorted(MODULE.RETAINED_FIXED_MODES))
        self.assertEqual(schema["$defs"]["retained_mode"]["anyOf"][1]["pattern"], MODULE.BASELINE_MODE_RE.pattern)
        self.assertEqual(
            sorted(manifest_schema["$defs"]["retained_mode"]["anyOf"][0]["enum"]),
            sorted(MODULE.RETAINED_FIXED_MODES),
        )
        self.assertEqual(manifest_schema["$defs"]["retained_mode"]["anyOf"][1]["pattern"], MODULE.BASELINE_MODE_RE.pattern)
        self.assertEqual(sorted(schema["$defs"]["retained_model_id"]["enum"]), sorted(MODULE.RETAINED_MODEL_IDS))
        self.assertEqual(sorted(schema["$defs"]["retained_model_era"]["enum"]), sorted(MODULE.RETAINED_MODEL_ERAS))
        self.assertEqual(schema["$defs"]["turn_flag"]["properties"]["source_hash"]["pattern"], MODULE.SOURCE_HASH_RE.pattern)
        self.assertEqual(schema["$defs"]["trend"]["properties"]["window"], {"$ref": "#/$defs/window"})
        self.assertEqual(schema["$defs"]["manifest"]["properties"]["mode"], {"$ref": "#/$defs/retained_mode"})
        self.assertEqual(manifest_schema["properties"]["mode"], {"$ref": "#/$defs/retained_mode"})
        self.assertIs(schema["$defs"]["episode"]["properties"]["friction_flags"]["uniqueItems"], True)
        self.assertIs(schema["$defs"]["turn_flag"]["properties"]["issue_flags"]["uniqueItems"], True)

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
                self.assertIsNotNone(timestamp_re.fullmatch("2024-02-29T00:00:00.123456789Z"))

    def test_clean_report_passes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            report = root / "reports" / "weekly" / "2026" / "05" / "08.md"
            report.parent.mkdir(parents=True)
            report.write_text("# Weekly retrospective\n\nNo raw transcript excerpts retained.\n", encoding="utf-8")

            self.assertEqual(MODULE.validate_root(root), [])

    def test_flat_retained_export_layout_passes(self) -> None:
        for export_name, mode in (("daily", "daily"), ("weekly", "weekly"), ("baseline", "baseline-90d")):
            with self.subTest(export_name=export_name, mode=mode):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_retained_export(root, root / "retained" / export_name, mode=mode)

                    self.assertEqual(MODULE.validate_root(root), [])

    def test_flat_retained_export_rejects_extra_or_missing_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            (export_dir / "retained_manifest.json").unlink()

            self.assertIn("retained export directory is incomplete or has extra files", "\n".join(MODULE.validate_root(root)))

    def test_flat_retained_export_rejects_inconsistent_rows_and_trend(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            turn_flag = valid_turn_flag()
            turn_flag["episode_id"] = "episode_ref_v1:" + "b" * 20
            (export_dir / "turn_flags.jsonl").write_text(json.dumps(turn_flag) + "\n", encoding="utf-8")
            trend = valid_trend()
            trend["turn_count"] = 0
            trend["flagged_turn_count"] = 0
            trend["episode_count"] = 0
            trend["flags"] = {}
            trend["hosts"] = {}
            trend["model_eras"] = {}
            (export_dir / "trend_report.json").write_text(json.dumps(trend), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("retained/daily/turn_flags.jsonl:1: episode_id is missing from episodes export", issues)
        self.assertIn("retained/daily/trend_report.json: episode_count must match episodes.jsonl", issues)
        self.assertIn("retained/daily/trend_report.json: flagged_turn_count must match turn_flags.jsonl", issues)
        self.assertIn("retained/daily/trend_report.json: turn_count must match episodes.jsonl turn_count total", issues)
        self.assertIn("retained/daily/trend_report.json: hosts must match episodes.jsonl turn_count totals", issues)
        self.assertIn("retained/daily/trend_report.json: model_eras must match episodes.jsonl turn_count totals", issues)
        self.assertIn("retained/daily/trend_report.json: flags must match turn_flags.jsonl issue_flags", issues)

    def test_flat_retained_export_rejects_turn_flag_episode_identity_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            turn_flag = valid_turn_flag()
            turn_flag["host"] = "miku-bot-dev"
            turn_flag["session_id"] = "session_ref_v1:" + "c" * 20
            (export_dir / "turn_flags.jsonl").write_text(json.dumps(turn_flag) + "\n", encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("retained/daily/turn_flags.jsonl:1: host must match referenced episode", issues)
        self.assertIn("retained/daily/turn_flags.jsonl:1: session_id must match referenced episode", issues)

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
            (export_dir / "episodes.jsonl").write_text(json.dumps(episode) + "\n", encoding="utf-8")
            (export_dir / "turn_flags.jsonl").write_text(json.dumps(turn_flag) + "\n", encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("retained/daily/episodes.jsonl:1: episode start/end must be within trend window", issues)
        self.assertIn("retained/daily/turn_flags.jsonl:1: timestamp must be within trend window", issues)

    def test_flat_retained_export_rejects_single_sided_episode_times_outside_trend_window(self) -> None:
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
                    (export_dir / "episodes.jsonl").write_text(json.dumps(episode) + "\n", encoding="utf-8")

                    issues = "\n".join(MODULE.validate_root(root))

                self.assertIn("retained/daily/episodes.jsonl:1: episode start/end must be within trend window", issues)

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
            (export_dir / "trend_report.json").write_text(json.dumps(trend), encoding="utf-8")

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
            (export_dir / "trend_report.json").write_text(json.dumps(flat_trend), encoding="utf-8")
            write_monthly_export(root)
            monthly_episodes = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            monthly_turn_flags = root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            monthly_trend = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            monthly_episodes.write_text("", encoding="utf-8")
            monthly_turn_flags.write_text("", encoding="utf-8")
            monthly_trend.write_text(json.dumps(valid_trend()), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("retained/daily/trend_report.json: episode_count must match episodes.jsonl", issues)
        self.assertIn("retained/daily/trend_report.json: flagged_turn_count must match turn_flags.jsonl", issues)
        self.assertIn("retained/daily/trend_report.json: turn_count must match episodes.jsonl turn_count total", issues)
        self.assertIn("retained/daily/trend_report.json: hosts must match episodes.jsonl turn_count totals", issues)
        self.assertIn("retained/daily/trend_report.json: model_eras must match episodes.jsonl turn_count totals", issues)
        self.assertIn("retained/daily/trend_report.json: flags must match turn_flags.jsonl issue_flags", issues)
        self.assertIn("data/trends/2026/05/trend_report.json: episode_count must match episodes.jsonl", issues)
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

        self.assertIn("data/trends/2026/05/trend_report.json: episode_count must match episodes.jsonl", issues)
        self.assertIn("data/trends/2026/05/trend_report.json: flagged_turn_count must match turn_flags.jsonl", issues)
        self.assertIn("data/trends/2026/05/trend_report.json: turn_count must match episodes.jsonl turn_count total", issues)
        self.assertIn("data/trends/2026/05/trend_report.json: hosts must match episodes.jsonl turn_count totals", issues)
        self.assertIn("data/trends/2026/05/trend_report.json: model_eras must match episodes.jsonl turn_count totals", issues)
        self.assertIn("data/trends/2026/05/trend_report.json: flags must match turn_flags.jsonl issue_flags", issues)

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
            manifest_path = root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            manifest_path.parent.mkdir(parents=True)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("data/trends/2026/05/trend_report.json: window must overlap data month", issues)
        self.assertIn("data/manifests/2026/05/retained_manifest.json: window must overlap data month", issues)

    def test_invalid_data_month_paths_report_errors_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode_path = root / "data" / "episodes" / "0000" / "05" / "episodes.jsonl"
            episode_path.parent.mkdir(parents=True)
            episode_path.write_text(json.dumps(valid_episode()) + "\n", encoding="utf-8")
            trend_path = root / "data" / "trends" / "9999" / "12" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(valid_trend()), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("data/episodes/0000/05/episodes.jsonl: unexpected JSONL artifact", issues)
        self.assertIn("data/trends/9999/12/trend_report.json: unexpected JSON artifact", issues)

    def test_schema_version_rejects_bool(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_monthly_export(root)
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend = json.loads(trend_path.read_text(encoding="utf-8"))
            trend["schema_version"] = True
            trend_path.write_text(json.dumps(trend), encoding="utf-8")
            manifest_path = root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            manifest_path.parent.mkdir(parents=True)
            manifest = valid_manifest()
            manifest["schema_version"] = True
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("data/trends/2026/05/trend_report.json: trend schema_version must be 1", issues)
        self.assertIn("data/manifests/2026/05/retained_manifest.json: manifest schema_version must be 1", issues)

    def test_monthly_turn_flags_check_episode_refs_without_trend(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            turn_flags_path = root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            turn_flags_path.parent.mkdir(parents=True)
            turn_flags_path.write_text(json.dumps(valid_turn_flag()) + "\n", encoding="utf-8")

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
            episodes_path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            episodes_path.parent.mkdir(parents=True)
            episodes_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            turn_flag = valid_turn_flag()
            turn_flag["timestamp"] = "2026-04-30T23:59:59Z"
            turn_flags_path = root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            turn_flags_path.parent.mkdir(parents=True)
            turn_flags_path.write_text(json.dumps(turn_flag) + "\n", encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("data/episodes/2026/05/episodes.jsonl:1: episode start/end must be within data month", issues)
        self.assertIn("data/turn_flags/2026/05/turn_flags.jsonl:1: timestamp must be within data month", issues)

    def test_monthly_retained_artifacts_reject_inconsistent_rows_and_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_monthly_export(root)
            episodes_path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            turn_flags_path = root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            episode = valid_episode()
            turn_flag = valid_turn_flag()
            turn_flag["episode_id"] = "episode_ref_v1:" + "c" * 20
            episodes_path.write_text(json.dumps(episode) + "\n" + json.dumps(episode) + "\n", encoding="utf-8")
            turn_flags_path.write_text(json.dumps(turn_flag) + "\n" + json.dumps(turn_flag) + "\n", encoding="utf-8")
            trend = valid_trend()
            trend["turn_count"] = 0
            trend["flagged_turn_count"] = 0
            trend["episode_count"] = 0
            trend["flags"] = {}
            trend["hosts"] = {}
            trend["model_eras"] = {}
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("data/episodes/2026/05/episodes.jsonl:2: duplicate episode_id", issues)
        self.assertIn("data/turn_flags/2026/05/turn_flags.jsonl:2: duplicate turn_id", issues)
        self.assertIn(
            "data/turn_flags/2026/05/turn_flags.jsonl:1: episode_id is missing from episodes export",
            issues,
        )
        self.assertIn("data/trends/2026/05/trend_report.json: episode_count must match episodes.jsonl", issues)
        self.assertIn(
            "data/trends/2026/05/trend_report.json: flagged_turn_count must match turn_flags.jsonl",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: turn_count must match episodes.jsonl turn_count total",
            issues,
        )
        self.assertIn("data/trends/2026/05/trend_report.json: hosts must match episodes.jsonl turn_count totals", issues)
        self.assertIn(
            "data/trends/2026/05/trend_report.json: model_eras must match episodes.jsonl turn_count totals",
            issues,
        )
        self.assertIn("data/trends/2026/05/trend_report.json: flags must match turn_flags.jsonl issue_flags", issues)

    def test_forbidden_raw_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "history.jsonl").write_text("{}\n", encoding="utf-8")

            self.assertIn("forbidden raw/transient artifact", "\n".join(MODULE.validate_root(root)))

    def test_forced_raw_session_directories_are_rejected(self) -> None:
        for relative_path in (
            "sess" + "ions/prompt.txt",
            "archived_" + "sess" + "ions/raw.txt",
            "Sess" + "ions/prompt.txt",
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    subprocess.run(["git", "init"], cwd=root, check=True, stdout=subprocess.DEVNULL)
                    (root / ".gitignore").write_text(
                        "sess" + "ions/\narchived_" + "sess" + "ions/\nSess" + "ions/\n",
                        encoding="utf-8",
                    )
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text("raw prompt text\n", encoding="utf-8")
                    subprocess.run(["git", "add", "-f", relative_path], cwd=root, check=True)

                    self.assertIn("forbidden raw/transient artifact", "\n".join(MODULE.validate_root(root)))

    def test_compressed_raw_artifact_names_are_rejected(self) -> None:
        for relative_path in ("rollout-" + "2026-05-22.jsonl.gz", "session_index.jsonl.gz"):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    (root / relative_path).write_text("raw prompt text\n", encoding="utf-8")

                    self.assertIn("forbidden raw/transient artifact", "\n".join(MODULE.validate_root(root)))

    def test_symlink_artifacts_are_rejected_without_following_target(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            link = root / "reports" / "weekly" / "linked.md"
            link.parent.mkdir(parents=True)
            os.symlink(risky_local_path(), link)

            self.assertIn("symlink artifact is not allowed", "\n".join(MODULE.validate_root(root)))

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
            "Raw compound session pointer " + risky_compound_session_token(),
            "Raw compound turn pointer " + risky_compound_turn_token(),
            "Raw compound episode pointer " + risky_compound_episode_token(),
            '{"to' + 'ken":"redactedvalue"}',
            '{"access_to' + 'ken":"redactedvalue"}',
            '{"refresh-to' + 'ken":"redactedvalue"}',
            '{"client_sec' + 'ret":"redactedvalue"}',
            '{"db_pass' + 'word":"redactedvalue"}',
            '{"api_' + 'key":"abc"}',
            "api " + "key: abc",
            "secret " + "key: abc",
            "private " + "key: abc",
            "pass" + "word=12345",
            '{"private_' + 'key":"redactedvalue"}',
            '{"session_' + 'id":"abc123456"}',
            "Private key block -----BEGIN PRIVATE " + "KEY-----\nredacted",
            "PGP private key block -----BEGIN PGP PRIVATE " + "KEY BLOCK-----\nredacted",
            "Relative source path ./.cod" + "ex/sess" + "ions/2026/05/22/rollout.jsonl",
            "Case-variant source path ./.Cod" + "ex/Sess" + "ions/2026/05/22/Rollout-" + "ABC.JSONL",
            "Relative local source path .codex" + "-local/session-retrospective/out/state.json",
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
        )
        for text in risky_examples:
            with self.subTest(text=text):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    report = root / "reports" / "weekly" / "2026" / "05" / "08.md"
                    report.parent.mkdir(parents=True)
                    report.write_text(text + "\n", encoding="utf-8")

                    self.assertIn("retained text contains raw/sensitive evidence", "\n".join(MODULE.validate_root(root)))

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

                    self.assertIn("forbidden raw/transient artifact", "\n".join(MODULE.validate_root(root)))

    def test_manifest_extra_risky_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = valid_manifest() | {"worklist": [risky_local_path()]}
            path = root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn("unexpected field is not allowed", issues)
            self.assertIn("manifest retained text contains raw/sensitive evidence", issues)

    def test_manifest_unknown_risky_key_is_rejected_without_echoing_key(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            risky_key = risky_local_path()
            manifest = valid_manifest() | {risky_key: "opaque"}
            path = root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
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

            self.assertIn("unexpected field is not allowed", "\n".join(MODULE.validate_root(root)))

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

    def test_unexpected_infrastructure_text_artifacts_are_rejected_and_scanned(self) -> None:
        for relative_path in (".github/notes.md", "tests/fixtures/source.json"):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    if artifact.suffix == ".json":
                        artifact.write_text(json.dumps({"source": risky_internal_url()}), encoding="utf-8")
                    else:
                        artifact.write_text(risky_internal_url() + "\n", encoding="utf-8")

                    issues = "\n".join(MODULE.validate_root(root))
                    self.assertIn("unexpected", issues)
                    self.assertIn("retained text contains raw/sensitive evidence", issues)

    def test_unexpected_retained_text_artifacts_are_rejected_without_risky_text(self) -> None:
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
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text("path_ref_v1:aaaaaaaaaaaaaaaa\n", encoding="utf-8")

                    self.assertIn("unexpected retained text artifact location", "\n".join(MODULE.validate_root(root)))

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
                    artifact.write_text(json.dumps({"items": [{"source": "opaque"}]}), encoding="utf-8")

                    self.assertIn("unexpected JSON artifact", "\n".join(MODULE.validate_root(root)))

    def test_unknown_jsonl_artifacts_are_rejected(self) -> None:
        for relative_path in (
            "data/episodes/customer-acme/episodes.jsonl",
            "data/episodes/2026/05/customer-acme.jsonl",
            "data/turn_flags/customer-acme/turn_flags.jsonl",
            "data/turn_flags/2026/05/" + "session_" + "id-rawabcdef123456.jsonl",
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text("\n", encoding="utf-8")

                    self.assertIn("unexpected JSONL artifact", "\n".join(MODULE.validate_root(root)))

    def test_invalid_jsonl_errors_do_not_include_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifact = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("{bad json\n", encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn("data/episodes/2026/05/episodes.jsonl: line 1: invalid JSONL", issues)
            self.assertNotIn(str(root), issues)

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
            artifact.write_text("{" + ",".join(json.dumps(key) + ":" + json.dumps(value) for key, value in entries) + "}\n", encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn("line 1: invalid JSONL: duplicate JSON key is not allowed", issues)
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
            artifact.write_text("{" + ",".join(json.dumps(key) + ":" + json.dumps(value) for key, value in entries) + "}\n", encoding="utf-8")

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

                    self.assertIn("unexpected retained artifact suffix", "\n".join(MODULE.validate_root(root)))

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

            self.assertIn("turn_count must be a bounded non-negative integer", "\n".join(MODULE.validate_root(root)))

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

            self.assertIn("friction_flags must contain at most 16 items", "\n".join(MODULE.validate_root(root)))

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

            self.assertIn("issue_flags must be safe-token array", "\n".join(MODULE.validate_root(root)))

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
            turn_path = root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
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
            turn_path = root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
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
            turn_path = root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
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
            turn_path = root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
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

            self.assertIn("window.start must be before window.end", "\n".join(MODULE.validate_root(root)))

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
                    path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
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

            self.assertIn("episode start must be before or equal to end", "\n".join(MODULE.validate_root(root)))

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

            self.assertIn("window.start must be timestamp", "\n".join(MODULE.validate_root(root)))

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = valid_episode()
            episode["start"] = "2026-04-31T00:00:00Z"
            path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            self.assertIn("start must be timestamp or null", "\n".join(MODULE.validate_root(root)))

    def test_retained_mode_allows_daily_weekly_and_baseline_windows(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = valid_manifest()
            manifest["mode"] = "baseline-90d"
            manifest["window"] = window_for_mode("baseline-90d")
            manifest_path = root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
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

        self.assertIn("retained/daily/retained_manifest.json: manifest mode must match window.mode", issues)

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

        self.assertIn("retained/daily/trend_report.json: trend window.mode must match retained/daily export directory", issues)
        self.assertIn("retained/daily/retained_manifest.json: manifest mode must match retained/daily export directory", issues)

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

        self.assertIn("retained/baseline: retained export mode differs between trend and manifest", issues)

    def test_flat_retained_export_window_must_match_between_manifest_and_trend(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            manifest_path = export_dir / "retained_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["window"]["end"] = "2026-05-23T00:00:00Z"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("retained/daily: retained export window differs between trend and manifest", issues)

    def test_monthly_retained_export_window_must_match_between_manifest_and_trend(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_monthly_export(root)
            manifest_path = root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            manifest_path.parent.mkdir(parents=True)
            manifest = valid_manifest()
            manifest["window"]["start"] = "2026-05-20T00:00:00Z"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("data/2026/05: retained export window differs between trend and manifest", issues)

    def test_customer_like_modes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = valid_manifest()
            manifest["mode"] = "customer-acme"
            manifest["window"]["mode"] = "customer-acme"
            manifest_path = root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
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
            turn_path = root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
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
            self.assertIn("model_eras key must be an allowed retained model era", issues)

    def test_source_hashes_must_use_retained_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            row = valid_turn_flag()
            row["source_hash"] = "e" * 64
            path = root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(row) + "\n", encoding="utf-8")

            self.assertIn("source_hash must be source_hash_v1", "\n".join(MODULE.validate_root(root)))

    def test_root_docs_and_workflows_are_content_scanned(self) -> None:
        for relative_path, text in (
            ("README.md", "Leaked URL " + risky_internal_url() + "\n"),
            (".github/workflows/ci.yml", "name: CI\n# " + risky_project_path() + "\n"),
            ("scripts/probe.py", "# " + risky_secret_token() + "\n"),
            ("schemas/session-retrospective-v1.schema.json", json.dumps({"source": risky_project_path()}) + "\n"),
            ("tests/probe.py", "# " + risky_internal_host() + "\n"),
            (".gitignore", ".codex" + "-tmp/\n# " + risky_project_path() + "\n"),
            ("README.md", "Raw pointer " + risky_session_pointer() + "\n"),
            ("scripts/probe.py", "# " + risky_rollout_filename() + "\n"),
            ("README.md", "Internal localhost URL " + risky_localhost_url() + "\n"),
            ("README.md", "Internal private IP URL " + risky_private_ip_url() + "\n"),
            ("README.md", "Internal metadata URL http://" + risky_link_local_ip() + "/latest/meta-data\n"),
            ("README.md", "Internal IPv6 URL http://[" + risky_private_ipv6() + "]/status\n"),
            ("README.md", "Internal short host URL " + risky_short_host_url() + "\n"),
            ("README.md", "Internal SSH URL " + risky_private_ip_ssh_url() + "\n"),
            ("README.md", "Internal Git remote " + risky_short_host_git_remote() + "\n"),
            ("README.md", "Short secret api_" + "key: abc\n"),
            ("README.md", "Short secret to" + "ken = abcdefghijklmnop\n"),
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    path = root / relative_path
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(text, encoding="utf-8")

                    self.assertIn("infrastructure text contains raw/sensitive evidence", "\n".join(MODULE.validate_root(root)))

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
                    report.write_text("Investigated host " + report_sample + "\n", encoding="utf-8")

                    turn = valid_turn_flag()
                    turn["redacted_user_prompt_summary"] = "Investigated host " + row_sample
                    turn_path = root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
                    turn_path.parent.mkdir(parents=True)
                    turn_path.write_text(json.dumps(turn) + "\n", encoding="utf-8")

                    issues = "\n".join(MODULE.validate_root(root))

                self.assertIn("reports/daily/2026/05/22.md: retained text contains raw/sensitive evidence", issues)
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
                "model_eras": {"01234567-89ab-cdef-0123-456789abcdef": 1},
                "coverage_gaps": [],
            }
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")
            manifest = valid_manifest()
            manifest["sources"][0]["host"] = risky_internal_host()
            manifest_path = root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
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
            manifest["coverage_gaps"] = [{"host": "customer-acme", "reason": "stale_host"}]
            manifest_path = root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
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
            manifest["coverage_gaps"] = [{"host": "scope", "reason": "partial_host_scope"}]
            manifest_path = root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
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

            self.assertIn("hosts key must be an allowed retained host", "\n".join(MODULE.validate_root(root)))

    def test_source_safety_coverage_reasons_are_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = valid_manifest()
            manifest["coverage_gaps"] = [
                {"host": "local", "reason": "source_root_symlink", "root_ref": "path_ref_v1:aaaaaaaaaaaaaaaa"},
                {"host": "custom_source", "reason": "unsafe_source_artifact", "root_ref": "path_ref_v1:aaaaaaaaaaaaaaaa"},
                {"host": "local", "reason": "truncated_rollout_summary", "root_ref": "path_ref_v1:aaaaaaaaaaaaaaaa"},
            ]
            manifest_path = root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            manifest_path.parent.mkdir(parents=True)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            self.assertEqual(MODULE.validate_root(root), [])

    def test_missing_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "missing"

            self.assertEqual(MODULE.validate_root(root), ["root must be an existing directory"])

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
                {"host": "local", "reason": "unreachable"}
                for _index in range(101)
            ]
            path = root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
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
            path = root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn("source rollout_count must be a bounded non-negative integer", issues)
            self.assertIn("source summary_count must be a bounded non-negative integer", issues)
            self.assertIn("ready source must have rollout_count or summary_count", issues)

    def test_git_ignored_local_temp_dirs_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(["git", "init"], cwd=root, check=True, stdout=subprocess.DEVNULL)
            (root / ".gitignore").write_text(".codex" + "-tmp/\n", encoding="utf-8")
            helper_state = root / ".codex-tmp" / "isolated-review" / "state.json"
            helper_state.parent.mkdir(parents=True)
            helper_state.write_text(json.dumps({"raw": risky_internal_url()}) + "\n", encoding="utf-8")
            report = root / "reports" / "weekly" / "2026" / "05" / "08.md"
            report.parent.mkdir(parents=True)
            report.write_text("# Weekly retrospective\n\nNo raw transcript excerpts retained.\n", encoding="utf-8")

            self.assertEqual(MODULE.validate_root(root), [])


if __name__ == "__main__":
    unittest.main()
