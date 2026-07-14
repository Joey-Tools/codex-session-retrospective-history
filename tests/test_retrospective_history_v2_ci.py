from __future__ import annotations

import ast
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
VALIDATOR = ROOT / "scripts" / "validate_retained_history.py"
PUBLIC_KEY_NAME = "retrospective-history-v2-publisher.asc"
PUBLIC_KEY = ROOT / PUBLIC_KEY_NAME
EXPECTED_FINGERPRINT = "40FA5D05AC7A3D5C180B037FF6DCF7A06FFC9C52"
EXPECTED_UID = (
    "Codex Session Retrospective Publisher "
    "<12524680+JoeyTeng@users.noreply.github.com>"
)


def workflow_step(name: str) -> str:
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    marker = f"      - name: {name}"
    start = lines.index(marker)
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith(("      - name: ", "      - uses: ")):
            end = index
            break
    return "\n".join(lines[start:end])


def workflow_run_script(name: str) -> str:
    lines = workflow_step(name).splitlines()
    run_index = lines.index("        run: |")
    return textwrap.dedent("\n".join(lines[run_index + 1 :]))


def run_workflow_script(
    name: str, root: Path, *, base_tip: str, head_rev: str
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update({"BASE_TIP": base_tip, "HEAD_REV": head_rev})
    return subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-c", workflow_run_script(name)],
        cwd=root,
        check=False,
        capture_output=True,
        env=environment,
        text=True,
        timeout=10,
    )


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip()


def initialize_git_repository(root: Path) -> str:
    git(root, "init", "--quiet")
    git(root, "config", "user.name", "CI Contract")
    fixture_email = "ci-contract" + "@users.noreply.github.com"
    git(root, "config", "user.email", fixture_email)
    (root / "README.md").write_text("base\n", encoding="utf-8")
    git(root, "add", "README.md")
    git(root, "commit", "--quiet", "--no-gpg-sign", "-m", "Initialize fixture")
    return git(root, "rev-parse", "HEAD")


def commit_file(root: Path, relative: str, content: str, message: str) -> str:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    git(root, "add", "--", relative)
    git(root, "commit", "--quiet", "--no-gpg-sign", "-m", message)
    return git(root, "rev-parse", "HEAD")


def frozen_string_collection(module_path: Path, name: str) -> frozenset[str]:
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            continue
        if not (
            isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "frozenset"
            and len(node.value.args) == 1
        ):
            break
        return frozenset(ast.literal_eval(node.value.args[0]))
    raise AssertionError(f"unable to read {name} from {module_path}")


def primary_fingerprints(colon_output: str) -> list[str]:
    fingerprints: list[str] = []
    awaiting_fingerprint = False
    for line in colon_output.splitlines():
        fields = line.split(":")
        if fields[0] == "pub":
            awaiting_fingerprint = True
        elif fields[0] == "fpr" and awaiting_fingerprint:
            fingerprints.append(fields[9])
            awaiting_fingerprint = False
    return fingerprints


def public_key_uids(colon_output: str) -> list[str]:
    return [
        fields[9]
        for line in colon_output.splitlines()
        if len(fields := line.split(":")) > 9 and fields[0] == "uid"
    ]


class RetrospectiveHistoryV2CITests(unittest.TestCase):
    def test_workflow_checks_out_the_exact_event_head(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("fetch-depth: 0", workflow)
        self.assertIn(
            "ref: ${{ github.event_name == 'pull_request' && "
            "github.event.pull_request.head.sha || github.sha }}",
            workflow,
        )

    def test_push_range_uses_base_pinned_validator_and_key_first(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        prepare = workflow_step("Prepare trusted push validator")
        key_import = workflow_step("Import trusted push publisher key")
        validation = workflow_step("Validate push range with trusted base")

        self.assertIn("BASE_REV: ${{ github.event.before }}", prepare)
        self.assertIn(
            'git worktree add --quiet --detach "$TRUSTED_VALIDATOR_ROOT" "$BASE_REV"',
            prepare,
        )
        self.assertIn(
            '"$TRUSTED_VALIDATOR_ROOT/retrospective-history-v2-publisher.asc"',
            key_import,
        )
        self.assertIn('cd "$TRUSTED_VALIDATOR_ROOT"', validation)
        self.assertIn(
            'PYTHONPATH="$TRUSTED_VALIDATOR_ROOT" PYTHONNOUSERSITE=1 python -P -',
            validation,
        )
        self.assertIn(
            "from scripts.retrospective_history_git_v2 import validate_append_only_range",
            validation,
        )
        self.assertIn('Path(os.environ["GITHUB_WORKSPACE"])', validation)
        self.assertNotIn("git diff", validation)
        self.assertNotIn("--name-only", validation)

        trusted_index = workflow.index(
            "      - name: Validate push range with trusted base"
        )
        self.assertLess(
            workflow.index("      - name: Prepare trusted push validator"),
            trusted_index,
        )
        self.assertLess(
            workflow.index("      - name: Import trusted push publisher key"),
            trusted_index,
        )
        self.assertLess(
            trusted_index,
            workflow.index("      - name: Import v2 publisher public key"),
        )
        self.assertLess(
            trusted_index,
            workflow.index("      - name: Install v2 validation dependencies"),
        )
        self.assertLess(
            trusted_index,
            workflow.index("      - name: Run tests"),
        )

    def test_publisher_public_key_is_ascii_armored_and_allowlisted(self) -> None:
        armor = PUBLIC_KEY.read_text(encoding="ascii")

        self.assertTrue(armor.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"))
        self.assertTrue(armor.endswith("-----END PGP PUBLIC KEY BLOCK-----\n"))
        self.assertNotIn("PRIVATE KEY", armor)
        self.assertIn(
            PUBLIC_KEY_NAME, frozen_string_collection(VALIDATOR, "ROOT_DOC_FILES")
        )

    def test_publisher_public_key_imports_with_expected_primary_fingerprint(
        self,
    ) -> None:
        gpg = shutil.which("gpg")
        if gpg is None:
            self.skipTest("gpg is unavailable")
        gpgconf = shutil.which("gpgconf")

        with tempfile.TemporaryDirectory() as raw:
            gnupg_home = Path(raw) / "gnupg"
            gnupg_home.mkdir(mode=0o700)
            environment = os.environ.copy()
            environment["GNUPGHOME"] = str(gnupg_home)
            try:
                subprocess.run(
                    [
                        gpg,
                        "--quiet",
                        "--no-options",
                        "--no-autostart",
                        "--batch",
                        "--import",
                        str(PUBLIC_KEY),
                    ],
                    check=True,
                    capture_output=True,
                    env=environment,
                    text=True,
                    timeout=10,
                )
                result = subprocess.run(
                    [
                        gpg,
                        "--quiet",
                        "--no-options",
                        "--no-autostart",
                        "--batch",
                        "--with-colons",
                        "--fingerprint",
                    ],
                    check=True,
                    capture_output=True,
                    env=environment,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(
                    primary_fingerprints(result.stdout), [EXPECTED_FINGERPRINT]
                )
                self.assertEqual(public_key_uids(result.stdout), [EXPECTED_UID])
            finally:
                if gpgconf is not None:
                    subprocess.run(
                        [gpgconf, "--homedir", str(gnupg_home), "--kill", "gpg-agent"],
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )

    def test_workflow_imports_key_into_isolated_gnupg_home(self) -> None:
        step = workflow_step("Import v2 publisher public key")
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn(f"EXPECTED_FINGERPRINT: {EXPECTED_FINGERPRINT}", step)
        self.assertIn(f"EXPECTED_UID: {EXPECTED_UID}", step)
        self.assertIn(f"PUBLISHER_PUBLIC_KEY: {PUBLIC_KEY_NAME}", step)
        self.assertIn('GNUPGHOME="$RUNNER_TEMP/retrospective-history-v2-gnupg"', step)
        self.assertIn('install -d -m 700 "$GNUPGHOME"', step)
        self.assertIn(
            "gpg --quiet --no-options --no-autostart --batch \\",
            step,
        )
        self.assertIn('--import "$PUBLISHER_PUBLIC_KEY" >/dev/null 2>&1', step)
        self.assertIn('test "$PRIMARY_KEY_COUNT" = 1', step)
        self.assertIn('test "$ACTUAL_FINGERPRINT" = "$EXPECTED_FINGERPRINT"', step)
        self.assertIn('test "$UID_COUNT" = 1', step)
        self.assertIn('test "$ACTUAL_UID" = "$EXPECTED_UID"', step)
        self.assertIn('echo "GNUPGHOME=$GNUPGHOME" >> "$GITHUB_ENV"', step)
        self.assertLess(
            workflow.index("      - name: Import v2 publisher public key"),
            workflow.index("      - name: Validate append-only pull request range"),
        )

    def test_pull_request_tree_requires_exact_event_base_ancestry(self) -> None:
        step = workflow_step("Require current pull request base")
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("BASE_TIP: ${{ github.event.pull_request.base.sha }}", step)
        self.assertIn('git merge-base --is-ancestor "$BASE_TIP" "$HEAD_REV"', step)
        self.assertLess(
            workflow.index("      - name: Require current pull request base"),
            workflow.index("      - name: Validate retained history tree"),
        )

        range_step = workflow_step("Validate append-only pull request range")
        self.assertIn("BASE_REV: ${{ github.event.pull_request.base.sha }}", range_step)
        self.assertNotIn("git merge-base", range_step)
        self.assertNotIn("BASE_TIP", range_step)
        self.assertIn('--base-rev "$BASE_REV" --head-rev "$HEAD_REV"', range_step)

    def test_stale_pull_request_base_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            common = initialize_git_repository(root)
            head = commit_file(root, "infra.txt", "head\n", "Add infrastructure")
            git(root, "switch", "--quiet", "--detach", common)
            base_tip = commit_file(root, "base.txt", "base tip\n", "Advance base")

            result = run_workflow_script(
                "Require current pull request base",
                root,
                base_tip=base_tip,
                head_rev=head,
            )
            current = run_workflow_script(
                "Require current pull request base",
                root,
                base_tip=common,
                head_rev=head,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not contain the current event base", result.stderr)
        self.assertEqual(current.returncode, 0, current.stderr)

    def test_pull_requests_reject_runs_but_allow_infrastructure(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base = initialize_git_repository(root)
            infrastructure_head = commit_file(
                root, ".github/policy.txt", "policy\n", "Add policy"
            )
            infrastructure = run_workflow_script(
                "Reject pull request publication changes",
                root,
                base_tip=base,
                head_rev=infrastructure_head,
            )

            git(root, "switch", "--quiet", "--detach", base)
            publication_head = commit_file(
                root, "runs/private-name.json", "{}\n", "Add publication"
            )
            publication = run_workflow_script(
                "Reject pull request publication changes",
                root,
                base_tip=base,
                head_rev=publication_head,
            )

        step = workflow_step("Reject pull request publication changes")
        self.assertIn('git diff --quiet "$BASE_TIP" "$HEAD_REV" -- runs', step)
        self.assertNotIn("--name-only", step)
        self.assertEqual(infrastructure.returncode, 0, infrastructure.stderr)
        self.assertNotEqual(publication.returncode, 0)
        self.assertIn("must not modify formal retained-history publications", publication.stderr)
        self.assertNotIn("private-name", publication.stdout + publication.stderr)


if __name__ == "__main__":
    unittest.main()
