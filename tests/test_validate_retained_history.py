from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "validate_retained_history.py"
SPEC = importlib.util.spec_from_file_location("validate_retained_history", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ValidateRetainedHistoryTests(unittest.TestCase):
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

    def test_retained_text_risks_are_rejected(self) -> None:
        risky_examples = (
            "Upper-case URL HTTPS://internal.example/path",
            "SSH URL ssh://git@example.internal/repo",
            "Raw session pointer Session ID: abc123456",
            "Raw turn pointer turn-id=abc123456",
            "Relative source path ./.codex/sessions/2026/05/22/rollout.jsonl",
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
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text("Summarized text.\n", encoding="utf-8")

                    self.assertIn("forbidden raw/transient artifact", "\n".join(MODULE.validate_root(root)))

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
