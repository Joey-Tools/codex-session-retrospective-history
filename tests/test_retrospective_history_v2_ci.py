from __future__ import annotations

import ast
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
VALIDATOR = ROOT / "scripts" / "validate_retained_history.py"
PUBLIC_KEY_NAME = "retrospective-history-v2-publisher.asc"
PUBLIC_KEY = ROOT / PUBLIC_KEY_NAME
EXPECTED_FINGERPRINT = "EFBBC913F49A5F6E0AF0D248F70246143DC28F32"


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


class RetrospectiveHistoryV2CITests(unittest.TestCase):
    def test_workflow_checks_out_the_exact_event_head(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("fetch-depth: 0", workflow)
        self.assertIn(
            "ref: ${{ github.event_name == 'pull_request' && "
            "github.event.pull_request.head.sha || github.sha }}",
            workflow,
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
                        "--no-options",
                        "--no-autostart",
                        "--batch",
                        "--with-colons",
                        "--fingerprint",
                        EXPECTED_FINGERPRINT,
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
        self.assertIn(f"PUBLISHER_PUBLIC_KEY: {PUBLIC_KEY_NAME}", step)
        self.assertIn('GNUPGHOME="$RUNNER_TEMP/retrospective-history-v2-gnupg"', step)
        self.assertIn('install -d -m 700 "$GNUPGHOME"', step)
        self.assertIn(
            'gpg --no-options --no-autostart --batch --import "$PUBLISHER_PUBLIC_KEY"',
            step,
        )
        self.assertIn('test "$ACTUAL_FINGERPRINT" = "$EXPECTED_FINGERPRINT"', step)
        self.assertIn('echo "GNUPGHOME=$GNUPGHOME" >> "$GITHUB_ENV"', step)
        self.assertLess(
            workflow.index("      - name: Import v2 publisher public key"),
            workflow.index("      - name: Validate append-only pull request range"),
        )

    def test_workflow_uses_merge_base_for_pull_request_range(self) -> None:
        step = workflow_step("Validate append-only pull request range")

        self.assertIn("BASE_TIP: ${{ github.event.pull_request.base.sha }}", step)
        self.assertNotIn("BASE_REV: ${{ github.event.pull_request.base.sha }}", step)
        self.assertIn('BASE_REV="$(git merge-base "$BASE_TIP" "$HEAD_REV")"', step)
        self.assertIn('--base-rev "$BASE_REV" --head-rev "$HEAD_REV"', step)


if __name__ == "__main__":
    unittest.main()
