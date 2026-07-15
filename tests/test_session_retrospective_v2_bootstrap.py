from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/session-retrospective-v2-bootstrap.yml"


class SessionRetrospectiveV2BootstrapTests(unittest.TestCase):
    def test_bootstrap_is_read_only_same_repo_and_secret_free(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("pull_request_target:", workflow)
        self.assertIn("\n  pull_request:\n", workflow)
        self.assertEqual(workflow.count("contents: read"), 2)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("pull-requests: write", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertIn(
            "github.event.pull_request.head.repo.full_name == github.repository",
            workflow,
        )
        self.assertIn("github.event.pull_request.base.ref == 'master'", workflow)
        self.assertIn(
            "github.event.pull_request.head.ref == "
            "'wip/session-retrospective-v2-history'",
            workflow,
        )
        self.assertIn("github.event_name == 'pull_request_target'", workflow)
        self.assertIn("github.event_name == 'pull_request'", workflow)
        self.assertIn(
            "'wip/session-retrospective-v2-ci-bootstrap'",
            workflow,
        )
        self.assertIn(
            ".github/workflows/session-retrospective-v2-bootstrap.yml",
            workflow,
        )
        self.assertIn("timeout-minutes: 30", workflow)

    def test_bootstrap_binds_and_scrubs_candidate_execution(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn(
            "CANDIDATE_SHA: ${{ github.event.pull_request.head.sha }}", workflow
        )
        self.assertIn('actual="$(git -C candidate rev-parse --verify HEAD)"', workflow)
        self.assertIn('if [ "$actual" != "$CANDIDATE_SHA" ]', workflow)
        self.assertIn('"persist-\\u0063redentials": false', workflow)
        self.assertIn("credential\\.helper", workflow)
        self.assertEqual(workflow.count("env -i \\"), 4)
        self.assertIn("GIT_CONFIG_GLOBAL=/dev/null", workflow)
        self.assertIn("GIT_CONFIG_NOSYSTEM=1", workflow)
        self.assertIn("PIP_CONFIG_FILE=/dev/null", workflow)

    def test_bootstrap_pins_actions_and_dependency_hashes(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn(
            "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
            workflow,
        )
        self.assertIn(
            "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
            workflow,
        )
        self.assertIn("if: github.event_name == 'pull_request_target'", workflow)
        self.assertIn("python -m pip --isolated install --require-hashes", workflow)


if __name__ == "__main__":
    unittest.main()
