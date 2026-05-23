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


class ValidateRetainedHistoryTests(unittest.TestCase):
    def test_bundle_schema_includes_manifest_root(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

        self.assertIn({"$ref": "#/$defs/manifest"}, schema["oneOf"])

    def test_clean_report_passes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            report = root / "reports" / "weekly" / "2026" / "05" / "08.md"
            report.parent.mkdir(parents=True)
            report.write_text("# Weekly retrospective\n\nNo raw transcript excerpts retained.\n", encoding="utf-8")

            self.assertEqual(MODULE.validate_root(root), [])

    def test_forbidden_raw_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "history.jsonl").write_text("{}\n", encoding="utf-8")

            self.assertIn("forbidden raw/transient artifact", "\n".join(MODULE.validate_root(root)))

    def test_forced_raw_session_directories_are_rejected(self) -> None:
        for relative_path in ("sessions/prompt.txt", "archived_sessions/raw.txt", "Sessions/prompt.txt"):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    subprocess.run(["git", "init"], cwd=root, check=True, stdout=subprocess.DEVNULL)
                    (root / ".gitignore").write_text("sessions/\narchived_sessions/\nSessions/\n", encoding="utf-8")
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text("raw prompt text\n", encoding="utf-8")
                    subprocess.run(["git", "add", "-f", relative_path], cwd=root, check=True)

                    self.assertIn("forbidden raw/transient artifact", "\n".join(MODULE.validate_root(root)))

    def test_compressed_raw_artifact_names_are_rejected(self) -> None:
        for relative_path in ("rollout-2026-05-22.jsonl.gz", "session_index.jsonl.gz"):
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
            os.symlink("/Users/hoteng/.codex/sessions/raw.txt", link)

            self.assertIn("symlink artifact is not allowed", "\n".join(MODULE.validate_root(root)))

    def test_retained_text_risks_are_rejected(self) -> None:
        risky_examples = (
            "Upper-case URL HTTPS://internal.example/path",
            "SSH URL ssh://git@example.internal/repo",
            "Raw session pointer Session ID: abc123456",
            "Raw turn pointer turn-id=abc123456",
            "Private key block -----BEGIN PRIVATE KEY-----\nredacted",
            "PGP private key block -----BEGIN PGP PRIVATE KEY BLOCK-----\nredacted",
            "Relative source path ./.codex/sessions/2026/05/22/rollout.jsonl",
            "Case-variant source path ./.Codex/Sessions/2026/05/22/Rollout-ABC.JSONL",
            "Relative local source path .codex-local/session-retrospective/out/state.json",
            "Relative temp source path .codex-tmp/isolated-review/stdout.log",
            "Windows path C:\\Users\\hoteng\\project",
            "Internal hostname jira.cisco.example",
            "Rollout file rollout-2026-05-22T10-00-00-abc.jsonl",
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
            manifest = valid_manifest() | {"worklist": ["/Users/hoteng/.codex/sessions/2026/05/22/rollout.jsonl"]}
            path = root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn("unexpected field: worklist", issues)
            self.assertIn("manifest retained text contains raw/sensitive evidence", issues)

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
                "raw_path": "/Users/hoteng/.codex/sessions/2026/05/22/rollout.jsonl",
            }
            path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(row) + "\n", encoding="utf-8")

            self.assertIn("unexpected field: raw_path", "\n".join(MODULE.validate_root(root)))

    def test_unexpected_text_artifact_locations_are_rejected_and_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifact = root / "evidence" / "notes.md"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("/Users/hoteng/.codex/sessions/2026/05/22/rollout.jsonl\n", encoding="utf-8")

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
                        artifact.write_text(json.dumps({"source": "HTTPS://internal.example/path"}), encoding="utf-8")
                    else:
                        artifact.write_text("HTTPS://internal.example/path\n", encoding="utf-8")

                    issues = "\n".join(MODULE.validate_root(root))
                    self.assertIn("unexpected", issues)
                    self.assertIn("retained text contains raw/sensitive evidence", issues)

    def test_unexpected_retained_text_artifacts_are_rejected_without_risky_text(self) -> None:
        for relative_path in (
            "data/source-map.txt",
            "data/manifests/2026/05/worklist.txt",
            "reports/misc/notes.md",
            "reports/daily/2026/05/08.txt",
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text("path_ref_v1:aaaaaaaaaaaaaaaa\n", encoding="utf-8")

                    self.assertIn("unexpected retained text artifact location", "\n".join(MODULE.validate_root(root)))

    def test_unknown_json_artifacts_are_rejected(self) -> None:
        for relative_path in ("data/worklist.json", "data/source-map.JSON", "reports/weekly/notes.json", "data/trends/customer-acme/trend_report.json"):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text(json.dumps({"items": [{"source": "opaque"}]}), encoding="utf-8")

                    self.assertIn("unexpected JSON artifact", "\n".join(MODULE.validate_root(root)))

    def test_unknown_jsonl_artifacts_are_rejected(self) -> None:
        for relative_path in ("data/episodes/customer-acme/episodes.jsonl", "data/turn_flags/customer-acme/turn_flags.jsonl"):
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
                "source_hash": "e" * 64,
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

    def test_safe_tokens_reject_risky_structured_values(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = {
                "episode_id": "episode_ref_v1:" + "a" * 20,
                "host": "jira.cisco.example",
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
                "flags": {"sk-proj-abcdefghijklmnop123456": 1},
                "hosts": {"jira.cisco.example": 1},
                "model_eras": {"01234567-89ab-cdef-0123-456789abcdef": 1},
                "coverage_gaps": [],
            }
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")
            manifest = valid_manifest()
            manifest["sources"][0]["host"] = "jira.cisco.example"
            manifest_path = root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            manifest_path.parent.mkdir(parents=True)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn("host must be a safe token", issues)
            self.assertIn("flags key must be a safe token", issues)
            self.assertIn("hosts key must be a safe token", issues)
            self.assertIn("model_eras key must be a safe token", issues)
            self.assertIn("source host must be a safe token", issues)

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
            (root / ".gitignore").write_text(".codex-tmp/\n", encoding="utf-8")
            helper_state = root / ".codex-tmp" / "isolated-review" / "state.json"
            helper_state.parent.mkdir(parents=True)
            helper_state.write_text('{"raw":"HTTPS://internal.example/path"}\n', encoding="utf-8")
            report = root / "reports" / "weekly" / "2026" / "05" / "08.md"
            report.parent.mkdir(parents=True)
            report.write_text("# Weekly retrospective\n\nNo raw transcript excerpts retained.\n", encoding="utf-8")

            self.assertEqual(MODULE.validate_root(root), [])


if __name__ == "__main__":
    unittest.main()
