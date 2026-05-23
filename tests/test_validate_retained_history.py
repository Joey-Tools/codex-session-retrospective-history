from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
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


def write_retained_export(root: Path, export_dir: Path) -> None:
    export_dir.mkdir(parents=True)
    (export_dir / "episodes.jsonl").write_text(json.dumps(valid_episode()) + "\n", encoding="utf-8")
    (export_dir / "turn_flags.jsonl").write_text(json.dumps(valid_turn_flag()) + "\n", encoding="utf-8")
    (export_dir / "trend_report.json").write_text(json.dumps(valid_trend()), encoding="utf-8")
    (export_dir / "retained_manifest.json").write_text(json.dumps(valid_manifest()), encoding="utf-8")


def risky_local_path() -> str:
    return "/Us" + "ers/hoteng/.cod" + "ex/sess" + "ions/2026/05/22/rollout.jsonl"


def risky_project_path() -> str:
    return "/Us" + "ers/hoteng/project"


def risky_internal_url() -> str:
    return "HTTPS://internal" + ".example/path"


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

    def test_schema_retained_text_patterns_cover_compound_secrets_and_case_paths(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        patterns = "\n".join(item["pattern"] for item in schema["$defs"]["retained_text"]["not"]["anyOf"])

        self.assertIn("[A-Za-z0-9._-]*(?:", patterns)
        self.assertIn("[Pp][Rr][Ii][Vv][Aa][Tt][Ee][._-]?[Kk][Ee][Yy]", patterns)
        self.assertIn("[Uu][Ss][Ee][Rr][Ss]", patterns)
        self.assertIn("[Ww][Oo][Rr][Kk][Ss][Pp][Aa][Cc][Ee]", patterns)

    def test_schema_safe_token_patterns_cover_compound_secret_names(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        manifest_schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))
        patterns = "\n".join(item["pattern"] for item in schema["$defs"]["safe_token"]["not"]["anyOf"])
        manifest_patterns = "\n".join(item["pattern"] for item in manifest_schema["$defs"]["safe_token"]["not"]["anyOf"])

        self.assertIn("[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll][Ss]?", patterns)
        self.assertIn("[Pp][Rr][Ii][Vv][Aa][Tt][Ee][._-]?[Kk][Ee][Yy]", patterns)
        self.assertIn("[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll][Ss]?", manifest_patterns)
        self.assertIn("[Pp][Rr][Ii][Vv][Aa][Tt][Ee][._-]?[Kk][Ee][Yy]", manifest_patterns)

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

    def test_clean_report_passes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            report = root / "reports" / "weekly" / "2026" / "05" / "08.md"
            report.parent.mkdir(parents=True)
            report.write_text("# Weekly retrospective\n\nNo raw transcript excerpts retained.\n", encoding="utf-8")

            self.assertEqual(MODULE.validate_root(root), [])

    def test_flat_retained_export_layout_passes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_retained_export(root, root / "retained" / "daily")

            self.assertEqual(MODULE.validate_root(root), [])

    def test_flat_retained_export_rejects_extra_or_missing_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            (export_dir / "retained_manifest.json").unlink()

            self.assertIn("retained export directory is incomplete or has extra files", "\n".join(MODULE.validate_root(root)))

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
            '{"to' + 'ken":"redactedvalue"}',
            '{"access_to' + 'ken":"redactedvalue"}',
            '{"refresh-to' + 'ken":"redactedvalue"}',
            '{"client_sec' + 'ret":"redactedvalue"}',
            '{"db_pass' + 'word":"redactedvalue"}',
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
            "reports/baseline/90-day-windows/customer-acme.md",
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
            "data/turn_flags/2026/05/session_id-rawabcdef123456.jsonl",
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

    def test_safe_tokens_reject_compound_secret_names(self) -> None:
        for token in ("client_secret", "refresh-token", "private_key", "db_password", "OPENAI_API_KEY"):
            with self.subTest(token=token):
                self.assertFalse(MODULE.valid_safe_token(token))

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

    def test_retained_mode_allows_daily_weekly_and_baseline_windows(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = valid_manifest()
            manifest["mode"] = "baseline-90d"
            manifest["window"]["mode"] = "baseline-90d"
            manifest_path = root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            manifest_path.parent.mkdir(parents=True)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            trend = valid_trend()
            trend["window"]["mode"] = "weekly"
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            self.assertEqual(MODULE.validate_root(root), [])

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
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    path = root / relative_path
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(text, encoding="utf-8")

                    self.assertIn("infrastructure text contains raw/sensitive evidence", "\n".join(MODULE.validate_root(root)))

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
