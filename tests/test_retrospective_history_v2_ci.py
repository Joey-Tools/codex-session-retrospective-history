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
VALIDATOR_NAME = "retrospective_history_git_v2.py"
PUBLIC_KEY = ROOT / PUBLIC_KEY_NAME
EXPECTED_FINGERPRINT = "40FA5D05AC7A3D5C180B037FF6DCF7A06FFC9C52"
EXPECTED_UID = (
    "Codex Session Retrospective Publisher "
    "<12524680+JoeyTeng@users.noreply.github.com>"
)
MAX_BOOTSTRAP_KEY_BYTES = 65536
MAX_BOOTSTRAP_VALIDATOR_BYTES = 1048576


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
    name: str,
    root: Path,
    *,
    base_tip: str | None = None,
    head_rev: str | None = None,
    extra_environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    if base_tip is not None:
        environment["BASE_TIP"] = base_tip
    if head_rev is not None:
        environment["HEAD_REV"] = head_rev
    if extra_environment is not None:
        environment.update(extra_environment)
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


def git_object(root: Path, object_type: str, payload: bytes) -> str:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "hash-object",
            "-w",
            "-t",
            object_type,
            "--stdin",
        ],
        check=True,
        capture_output=True,
        input=payload,
        timeout=10,
    )
    return result.stdout.decode("ascii").strip()


def git_tree(
    root: Path, entries: list[tuple[str, str, str, str]]
) -> str:
    tree_input = "".join(
        f"{mode} {object_type} {object_id}\t{name}\n"
        for mode, object_type, object_id, name in sorted(
            entries, key=lambda entry: entry[3].encode("utf-8")
        )
    )
    result = subprocess.run(
        ["git", "-C", str(root), "mktree"],
        check=True,
        capture_output=True,
        input=tree_input,
        text=True,
        timeout=10,
    )
    return result.stdout.strip()


def bootstrap_head_commit(
    root: Path,
    base: str,
    *,
    key_entries: list[tuple[str, str, str, str]] | None = None,
    validator_entries: list[tuple[str, str, str, str]] | None = None,
    extra_root_entries: list[tuple[str, str, str, str]] | None = None,
    scripts_entry: tuple[str, str, str, str] | None = None,
) -> str:
    if validator_entries is not None and scripts_entry is not None:
        raise AssertionError("scripts tree and override are mutually exclusive")
    policy_blob = git_object(root, "blob", b"bootstrap policy\n")
    root_entries = [("100644", "blob", policy_blob, "policy.txt")]
    root_entries.extend(key_entries or [])
    root_entries.extend(extra_root_entries or [])
    if validator_entries is not None:
        scripts_tree = git_tree(root, validator_entries)
        root_entries.append(("040000", "tree", scripts_tree, "scripts"))
    elif scripts_entry is not None:
        root_entries.append(scripts_entry)
    root_tree = git_tree(root, root_entries)
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "commit-tree",
            root_tree,
            "-p",
            base,
            "-m",
            "Bootstrap validation infrastructure",
        ],
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


def install_trusted_artifacts(
    root: Path, *, include_key: bool = True, include_validator: bool = True
) -> None:
    if include_key:
        shutil.copy2(PUBLIC_KEY, root / PUBLIC_KEY_NAME)
    if include_validator:
        validator = root / "scripts" / "retrospective_history_git_v2.py"
        validator.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "scripts" / validator.name, validator)


def commit_all(root: Path, message: str) -> str:
    git(root, "add", "--all")
    git(root, "commit", "--quiet", "--no-gpg-sign", "-m", message)
    return git(root, "rev-parse", "HEAD")


def workflow_environment(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        name, separator, value = line.partition("=")
        if not separator or not name:
            raise AssertionError("invalid workflow environment fixture")
        result[name] = value
    return result


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
            workflow.index("      - name: Validate first push bootstrap range"),
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

    def test_first_push_bootstrap_accepts_infrastructure_only_range(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary_root = Path(raw)
            root = temporary_root / "repository"
            root.mkdir()
            base = initialize_git_repository(root)
            install_trusted_artifacts(root)
            head = commit_all(root, "Install retrospective validation infrastructure")
            runner_temp = temporary_root / "runner"
            runner_temp.mkdir()
            github_environment = temporary_root / "github-environment"

            prepare = run_workflow_script(
                "Prepare trusted push validator",
                root,
                extra_environment={
                    "BASE_REV": base,
                    "GITHUB_ENV": str(github_environment),
                    "RUNNER_TEMP": str(runner_temp),
                },
            )
            prepared_environment = workflow_environment(github_environment)
            validation = run_workflow_script(
                "Validate first push bootstrap range",
                root,
                extra_environment={
                    "BASE_REV": base,
                    "EVENT_FORCED": "false",
                    "HEAD_REV": head,
                    "PUSH_VALIDATION_MODE": prepared_environment[
                        "PUSH_VALIDATION_MODE"
                    ],
                },
            )

        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        self.assertEqual(prepared_environment["PUSH_VALIDATION_MODE"], "bootstrap")
        self.assertEqual(validation.returncode, 0, validation.stderr)

    def test_first_push_bootstrap_accepts_exact_pair_from_head_tree(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base = initialize_git_repository(root)
            key_blob = git_object(root, "blob", b"key fixture\n")
            validator_blob = git_object(root, "blob", b"validator fixture\n")
            head = bootstrap_head_commit(
                root,
                base,
                key_entries=[("100644", "blob", key_blob, PUBLIC_KEY_NAME)],
                validator_entries=[
                    ("100644", "blob", validator_blob, VALIDATOR_NAME)
                ],
            )

            validation = run_workflow_script(
                "Validate first push bootstrap range",
                root,
                extra_environment={
                    "BASE_REV": base,
                    "EVENT_FORCED": "false",
                    "HEAD_REV": head,
                    "PUSH_VALIDATION_MODE": "bootstrap",
                },
            )

        self.assertEqual(validation.returncode, 0, validation.stderr)

    def test_first_push_bootstrap_reads_bounded_exact_head_tree_metadata(self) -> None:
        bootstrap = workflow_run_script("Validate first push bootstrap range")

        self.assertIn('git rev-parse --verify "$HEAD_REV^{tree}"', bootstrap)
        self.assertIn('git ls-tree -z "$HEAD_TREE"', bootstrap)
        self.assertIn('git cat-file -t "$object_id"', bootstrap)
        self.assertIn('git cat-file -s "$object_id"', bootstrap)
        self.assertIn("MAX_BOOTSTRAP_TREE_ENTRIES=65536", bootstrap)
        self.assertIn("MAX_BOOTSTRAP_KEY_BYTES=65536", bootstrap)
        self.assertIn("MAX_BOOTSTRAP_VALIDATOR_BYTES=1048576", bootstrap)
        self.assertNotIn("python", bootstrap)

    def test_first_push_bootstrap_requires_complete_pair_in_head_tree(self) -> None:
        for name, include_key, include_validator in (
            ("neither", False, False),
            ("key-only", True, False),
            ("validator-only", False, True),
        ):
            with self.subTest(case=name), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                base = initialize_git_repository(root)
                install_trusted_artifacts(root)
                key_blob = git_object(root, "blob", b"key fixture\n")
                validator_blob = git_object(root, "blob", b"validator fixture\n")
                head = bootstrap_head_commit(
                    root,
                    base,
                    key_entries=(
                        [("100644", "blob", key_blob, PUBLIC_KEY_NAME)]
                        if include_key
                        else []
                    ),
                    validator_entries=(
                        [("100644", "blob", validator_blob, VALIDATOR_NAME)]
                        if include_validator
                        else None
                    ),
                )

                validation = run_workflow_script(
                    "Validate first push bootstrap range",
                    root,
                    extra_environment={
                        "BASE_REV": base,
                        "EVENT_FORCED": "false",
                        "HEAD_REV": head,
                        "PUSH_VALIDATION_MODE": "bootstrap",
                    },
                )

            diagnostics = validation.stdout + validation.stderr
            self.assertNotEqual(validation.returncode, 0)
            self.assertIn("complete trusted validation pair", diagnostics)
            self.assertNotIn(PUBLIC_KEY_NAME, diagnostics)
            self.assertNotIn(VALIDATOR_NAME, diagnostics)

    def test_first_push_bootstrap_rejects_unsafe_head_artifact_types(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base = initialize_git_repository(root)
            regular_blob = git_object(root, "blob", b"artifact fixture\n")
            empty_tree = git_tree(root, [])
            regular_key = [("100644", "blob", regular_blob, PUBLIC_KEY_NAME)]
            regular_validator = [
                ("100644", "blob", regular_blob, VALIDATOR_NAME)
            ]
            unsafe_cases = (
                (
                    "key-symlink",
                    [("120000", "blob", regular_blob, PUBLIC_KEY_NAME)],
                    regular_validator,
                    None,
                ),
                (
                    "key-gitlink",
                    [("160000", "commit", base, PUBLIC_KEY_NAME)],
                    regular_validator,
                    None,
                ),
                (
                    "key-tree",
                    [("040000", "tree", empty_tree, PUBLIC_KEY_NAME)],
                    regular_validator,
                    None,
                ),
                (
                    "validator-symlink",
                    regular_key,
                    [("120000", "blob", regular_blob, VALIDATOR_NAME)],
                    None,
                ),
                (
                    "validator-gitlink",
                    regular_key,
                    [("160000", "commit", base, VALIDATOR_NAME)],
                    None,
                ),
                (
                    "validator-tree",
                    regular_key,
                    [("040000", "tree", empty_tree, VALIDATOR_NAME)],
                    None,
                ),
                (
                    "scripts-parent-blob",
                    regular_key,
                    None,
                    ("100644", "blob", regular_blob, "scripts"),
                ),
            )
            for name, key_entries, validator_entries, scripts_entry in unsafe_cases:
                with self.subTest(case=name):
                    head = bootstrap_head_commit(
                        root,
                        base,
                        key_entries=list(key_entries),
                        validator_entries=(
                            list(validator_entries)
                            if validator_entries is not None
                            else None
                        ),
                        scripts_entry=scripts_entry,
                    )
                    validation = run_workflow_script(
                        "Validate first push bootstrap range",
                        root,
                        extra_environment={
                            "BASE_REV": base,
                            "EVENT_FORCED": "false",
                            "HEAD_REV": head,
                            "PUSH_VALIDATION_MODE": "bootstrap",
                        },
                    )

                diagnostics = validation.stdout + validation.stderr
                self.assertNotEqual(validation.returncode, 0)
                self.assertIn("complete trusted validation pair", diagnostics)
                self.assertNotIn(PUBLIC_KEY_NAME, diagnostics)
                self.assertNotIn(VALIDATOR_NAME, diagnostics)

    def test_first_push_bootstrap_rejects_case_ambiguous_head_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base = initialize_git_repository(root)
            regular_blob = git_object(root, "blob", b"artifact fixture\n")
            regular_key = ("100644", "blob", regular_blob, PUBLIC_KEY_NAME)
            regular_validator = (
                "100644",
                "blob",
                regular_blob,
                VALIDATOR_NAME,
            )
            scripts_tree = git_tree(root, [regular_validator])
            ambiguous_cases = (
                (
                    "key",
                    [
                        regular_key,
                        ("100644", "blob", regular_blob, PUBLIC_KEY_NAME.upper()),
                    ],
                    [regular_validator],
                    [],
                ),
                (
                    "validator",
                    [regular_key],
                    [
                        regular_validator,
                        ("100644", "blob", regular_blob, VALIDATOR_NAME.upper()),
                    ],
                    [],
                ),
                (
                    "scripts",
                    [regular_key],
                    [regular_validator],
                    [("040000", "tree", scripts_tree, "Scripts")],
                ),
            )
            for name, key_entries, validator_entries, extra_root_entries in (
                ambiguous_cases
            ):
                with self.subTest(case=name):
                    head = bootstrap_head_commit(
                        root,
                        base,
                        key_entries=list(key_entries),
                        validator_entries=list(validator_entries),
                        extra_root_entries=list(extra_root_entries),
                    )
                    validation = run_workflow_script(
                        "Validate first push bootstrap range",
                        root,
                        extra_environment={
                            "BASE_REV": base,
                            "EVENT_FORCED": "false",
                            "HEAD_REV": head,
                            "PUSH_VALIDATION_MODE": "bootstrap",
                        },
                    )

                diagnostics = validation.stdout + validation.stderr
                self.assertNotEqual(validation.returncode, 0)
                self.assertIn("complete trusted validation pair", diagnostics)
                self.assertNotIn(PUBLIC_KEY_NAME, diagnostics)
                self.assertNotIn(VALIDATOR_NAME, diagnostics)

    def test_first_push_bootstrap_rejects_oversized_head_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base = initialize_git_repository(root)
            regular_blob = git_object(root, "blob", b"artifact fixture\n")
            oversized_key = git_object(
                root, "blob", b"k" * (MAX_BOOTSTRAP_KEY_BYTES + 1)
            )
            oversized_validator = git_object(
                root, "blob", b"v" * (MAX_BOOTSTRAP_VALIDATOR_BYTES + 1)
            )
            cases = (
                (
                    "key",
                    [("100644", "blob", oversized_key, PUBLIC_KEY_NAME)],
                    [("100644", "blob", regular_blob, VALIDATOR_NAME)],
                ),
                (
                    "validator",
                    [("100644", "blob", regular_blob, PUBLIC_KEY_NAME)],
                    [("100644", "blob", oversized_validator, VALIDATOR_NAME)],
                ),
            )
            for name, key_entries, validator_entries in cases:
                with self.subTest(artifact=name):
                    head = bootstrap_head_commit(
                        root,
                        base,
                        key_entries=key_entries,
                        validator_entries=validator_entries,
                    )
                    validation = run_workflow_script(
                        "Validate first push bootstrap range",
                        root,
                        extra_environment={
                            "BASE_REV": base,
                            "EVENT_FORCED": "false",
                            "HEAD_REV": head,
                            "PUSH_VALIDATION_MODE": "bootstrap",
                        },
                    )

                diagnostics = validation.stdout + validation.stderr
                self.assertNotEqual(validation.returncode, 0)
                self.assertIn("complete trusted validation pair", diagnostics)
                self.assertNotIn(PUBLIC_KEY_NAME, diagnostics)
                self.assertNotIn(VALIDATOR_NAME, diagnostics)

    def test_first_push_bootstrap_rejects_any_run_change_in_the_range(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base = initialize_git_repository(root)
            install_trusted_artifacts(root)
            commit_all(root, "Install retrospective validation infrastructure")
            private_component = "retained-" + "private.json"
            publication = Path("runs", private_component)
            commit_file(root, publication.as_posix(), "{}\n", "Add publication fixture")
            (root / publication).unlink()
            head = commit_all(root, "Delete publication fixture")

            validation = run_workflow_script(
                "Validate first push bootstrap range",
                root,
                extra_environment={
                    "BASE_REV": base,
                    "EVENT_FORCED": "false",
                    "HEAD_REV": head,
                    "PUSH_VALIDATION_MODE": "bootstrap",
                },
            )

        diagnostics = validation.stdout + validation.stderr
        self.assertNotEqual(validation.returncode, 0)
        self.assertIn("must not change retained publications", diagnostics)
        self.assertNotIn(private_component, diagnostics)

    def test_partially_initialized_trusted_base_fails_closed(self) -> None:
        for name, include_key, include_validator in (
            ("key", True, False),
            ("validator", False, True),
        ):
            with self.subTest(artifact=name), tempfile.TemporaryDirectory() as raw:
                temporary_root = Path(raw)
                root = temporary_root / "repository"
                root.mkdir()
                initialize_git_repository(root)
                install_trusted_artifacts(
                    root,
                    include_key=include_key,
                    include_validator=include_validator,
                )
                base = commit_all(root, "Install partial validation infrastructure")
                commit_file(root, "policy.txt", "policy\n", "Advance infrastructure")
                runner_temp = temporary_root / "runner"
                runner_temp.mkdir()
                github_environment = temporary_root / "github-environment"

                prepare = run_workflow_script(
                    "Prepare trusted push validator",
                    root,
                    extra_environment={
                        "BASE_REV": base,
                        "GITHUB_ENV": str(github_environment),
                        "RUNNER_TEMP": str(runner_temp),
                    },
                )

            self.assertNotEqual(prepare.returncode, 0)
            self.assertIn("partially initialized", prepare.stderr)
            self.assertNotIn(PUBLIC_KEY_NAME, prepare.stdout + prepare.stderr)
            self.assertNotIn(
                "retrospective_history_git_v2.py", prepare.stdout + prepare.stderr
            )

    def test_subsequent_push_uses_base_validator_for_mixed_publication(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary_root = Path(raw)
            root = temporary_root / "repository"
            root.mkdir()
            initialize_git_repository(root)
            install_trusted_artifacts(root)
            base = commit_all(root, "Install trusted validation infrastructure")
            validator = root / "scripts" / "retrospective_history_git_v2.py"
            validator.write_text(
                "def validate_append_only_range(root, base_rev, head_rev):\n"
                "    return []\n",
                encoding="utf-8",
            )
            commit_all(root, "Replace head validation fixture")
            private_component = "publication-" + "private.json"
            publication = Path("runs", private_component)
            head = commit_file(
                root,
                publication.as_posix(),
                "{}\n",
                "Add publication fixture",
            )

            runner_temp = temporary_root / "runner"
            runner_temp.mkdir()
            github_environment = temporary_root / "github-environment"
            prepare = run_workflow_script(
                "Prepare trusted push validator",
                root,
                extra_environment={
                    "BASE_REV": base,
                    "GITHUB_ENV": str(github_environment),
                    "RUNNER_TEMP": str(runner_temp),
                },
            )
            prepared_environment = workflow_environment(github_environment)
            trusted_gnupg_home = runner_temp / "trusted-gnupg"
            trusted_gnupg_home.mkdir(mode=0o700)
            validation = run_workflow_script(
                "Validate push range with trusted base",
                root,
                extra_environment={
                    **prepared_environment,
                    "BASE_REV": base,
                    "EVENT_FORCED": "false",
                    "GITHUB_WORKSPACE": str(root),
                    "HEAD_REV": head,
                    "TRUSTED_GNUPGHOME": str(trusted_gnupg_home),
                },
            )

        diagnostics = validation.stdout + validation.stderr
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        self.assertEqual(prepared_environment["PUSH_VALIDATION_MODE"], "trusted")
        self.assertNotEqual(validation.returncode, 0)
        self.assertIn("must not include infrastructure", diagnostics)
        self.assertNotIn(private_component, diagnostics)

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
