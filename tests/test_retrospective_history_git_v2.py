from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "retrospective_history_git_v2.py"
)
SPEC = importlib.util.spec_from_file_location("retrospective_history_git_v2", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

PUBLISHER_NAME = "Codex Session Retrospective Publisher"
PUBLISHER_EMAIL = "12524680+JoeyTeng@users.noreply.github.com"
ADMIN_NAME = "Joey Teng"
ADMIN_EMAIL = "joey.teng.dev@gmail.com"
RUN_ID = "0" * 63 + "1"
SECOND_RUN_ID = "0" * 63 + "2"
THIRD_RUN_ID = "0" * 63 + "3"
COMMIT_TIMESTAMP = 1_800_000_000
FAKE_GPG_SIGNATURE = (
    b"-----BEGIN PGP SIGNATURE-----\n\n"
    b"wjQEAAEIAB0FAgAAAAEWIQRA+l0FrHo9XBgLA3/23Pegb/ycUgAKCRD23Pegb/yc\n"
    b"UgAAAAEB\n"
    b"=pLXK\n"
    b"-----END PGP SIGNATURE-----"
)


def fixture_text(*parts: str) -> str:
    return "".join(parts)


def git(
    root: Path,
    *arguments: str,
    env: dict[str, str] | None = None,
    input_data: bytes | None = None,
) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        shell=False,
        env=env,
        timeout=60,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr.decode("utf-8", errors="replace"))
    return result.stdout


def command(*arguments: str) -> bytes:
    result = subprocess.run(
        list(arguments),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        shell=False,
        timeout=60,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr.decode("utf-8", errors="replace"))
    return result.stdout


def commit_environment(
    *, name: str = PUBLISHER_NAME, email: str = PUBLISHER_EMAIL
) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": name,
            "GIT_AUTHOR_EMAIL": email,
            "GIT_AUTHOR_DATE": f"@{COMMIT_TIMESTAMP} +0000",
            "GIT_COMMITTER_NAME": name,
            "GIT_COMMITTER_EMAIL": email,
            "GIT_COMMITTER_DATE": f"@{COMMIT_TIMESTAMP} +0000",
        }
    )
    return environment


def commit(
    root: Path,
    message: str,
    *,
    name: str = PUBLISHER_NAME,
    email: str = PUBLISHER_EMAIL,
) -> str:
    git(
        root,
        "commit",
        "--quiet",
        "--no-gpg-sign",
        "-m",
        message,
        env=commit_environment(name=name, email=email),
    )
    return git(root, "rev-parse", "HEAD").decode("ascii").strip()


def signed_commit(
    root: Path,
    message: str,
    *,
    name: str = PUBLISHER_NAME,
    email: str = PUBLISHER_EMAIL,
    signature: bytes = FAKE_GPG_SIGNATURE,
    author_identity: bytes | None = None,
    committer_identity: bytes | None = None,
) -> str:
    tree_oid = git(root, "write-tree").strip()
    parent_oid = git(root, "rev-parse", "HEAD").strip()
    identity = f"{name} <{email}> {COMMIT_TIMESTAMP} +0000".encode("ascii")
    author_identity = identity if author_identity is None else author_identity
    committer_identity = identity if committer_identity is None else committer_identity
    gpgsig_header = b"gpgsig " + signature.replace(b"\n", b"\n ")
    raw_commit = (
        b"\n".join(
            (
                b"tree " + tree_oid,
                b"parent " + parent_oid,
                b"author " + author_identity,
                b"committer " + committer_identity,
                gpgsig_header,
            )
        )
        + b"\n\n"
        + message.encode("ascii")
        + b"\n"
    )
    commit_oid = git(
        root,
        "hash-object",
        "-t",
        "commit",
        "-w",
        "--stdin",
        input_data=raw_commit,
    ).strip()
    git(
        root,
        "update-ref",
        "HEAD",
        commit_oid.decode("ascii"),
        parent_oid.decode("ascii"),
    )
    return commit_oid.decode("ascii")


def initialize_repository(
    root: Path, *, include_trust_root: bool = False
) -> tuple[str, str]:
    git(root, "init", "--quiet")
    git(root, "config", "user.name", PUBLISHER_NAME)
    git(root, "config", "user.email", PUBLISHER_EMAIL)
    (root / "README.md").write_text("history fixture\n", encoding="utf-8")
    git(root, "add", "README.md")
    if include_trust_root:
        for encoded_path in MODULE.V2_TRUST_ROOT_PATHS:
            path = root / encoded_path.decode("ascii")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("trusted fixture\n", encoding="utf-8")
        git(
            root,
            "add",
            "--",
            *(path.decode("ascii") for path in sorted(MODULE.V2_TRUST_ROOT_PATHS)),
        )
    base = commit(root, "Initialize history fixture")
    branch = git(root, "branch", "--show-current").decode("utf-8").strip()
    return base, branch


def run_path(
    *,
    mode: str = "daily",
    window: str = "2026-07-14",
    run_id: str = RUN_ID,
    artifact: str = "manifest.json",
) -> Path:
    hasher = hashlib.sha256()
    hasher.update(b"session-retrospective-retained-window-route-v2")
    for frame_type, value in ((b"M", mode.encode()), (b"W", window.encode())):
        hasher.update(frame_type)
        hasher.update(len(value).to_bytes(8, "big"))
        hasher.update(value)
    window_digest = hasher.hexdigest()
    window_route = [window_digest[offset : offset + 2] for offset in range(0, 64, 2)]
    if len(run_id) != 64 or any(
        character not in "0123456789abcdef" for character in run_id
    ):
        raise ValueError("run_id must contain 256 bits")
    run_route = [run_id[offset : offset + 2] for offset in range(0, 64, 2)]
    return Path("runs", mode, *window_route, window, *run_route, artifact)


def publication_message_for(
    *, mode: str = "daily", window: str = "2026-07-14", run_id: str = RUN_ID
) -> str:
    return f"Publish session retrospective v2 {mode} {window} run_ref_v2:{run_id}"


def publication_message(path: Path) -> str:
    window_index = 2 + MODULE.WINDOW_ROUTE_COMPONENT_COUNT
    run_route_start = window_index + 1
    run_id = "".join(
        path.parts[run_route_start : run_route_start + MODULE.RUN_ROUTE_COMPONENT_COUNT]
    )
    return publication_message_for(
        mode=path.parts[1], window=path.parts[window_index], run_id=run_id
    )


def write_artifact(root: Path, relative: Path, content: bytes = b"{}\n") -> None:
    artifact = root / relative
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_bytes(content)


def write_run(
    root: Path,
    *,
    mode: str = "daily",
    window: str = "2026-07-14",
    run_id: str = RUN_ID,
    contents: dict[str, bytes] | None = None,
) -> Path:
    supplied_contents = contents or {}
    for artifact in sorted(MODULE.RUN_ARTIFACTS):
        default_content = b"{}\n"
        if artifact == "manifest.json":
            default_content = (
                json.dumps({"run_id": run_id}, separators=(",", ":")).encode() + b"\n"
            )
        write_artifact(
            root,
            run_path(
                mode=mode,
                window=window,
                run_id=run_id,
                artifact=artifact,
            ),
            supplied_contents.get(artifact, default_content),
        )
    return run_path(mode=mode, window=window, run_id=run_id)


def write_near_semantic_limit_run(root: Path, shape: str) -> tuple[Path, int]:
    if shape == "deep":
        core = (
            b"[" * (MODULE.MAX_SEMANTIC_JSON_DEPTH + 1)
            + b"0"
            + b"]" * (MODULE.MAX_SEMANTIC_JSON_DEPTH + 1)
        )
    elif shape == "wide":
        core = b"[" + b"0," * MODULE.MAX_SEMANTIC_JSON_CONTAINER_ITEMS + b"0]"
    else:
        raise ValueError("unsupported semantic fixture shape")

    padded_artifacts = (
        "coverage.json",
        "episodes.jsonl",
        "manifest.json",
        "summary.json",
        "topics.jsonl",
        "trend_report.json",
    )
    semantic_bytes = 0
    for artifact in sorted(MODULE.RUN_ARTIFACTS):
        if artifact in padded_artifacts:
            target_size = MODULE.MAX_ARTIFACT_BYTES[artifact] - 256
            if len(core) > target_size:
                raise AssertionError(
                    "semantic fixture core exceeds its artifact budget"
                )
            content = core + b" " * (target_size - len(core))
            semantic_bytes += len(content)
        elif artifact == "report.md":
            content = b"# Retained report\n"
        else:
            content = b""
        write_artifact(root, run_path(artifact=artifact), content)
    return run_path(), semantic_bytes


def semantic_blobs(root: Path, artifact: Path) -> dict[str, bytes]:
    return {
        name: (root / artifact.parent / name).read_bytes()
        for name in MODULE.SEMANTIC_ARTIFACTS
    }


def semantic_line_count(blobs: dict[str, bytes]) -> int:
    return sum(
        value.count(b"\n") + (not value.endswith(b"\n"))
        for value in blobs.values()
        if value
    )


def validate_with_trusted_signature(root: Path, base: str, head: str) -> list[str]:
    with (
        mock.patch.object(MODULE, "_verify_commit_signature", return_value=True),
        mock.patch.object(MODULE, "_verify_publisher_attestation", return_value=True),
        mock.patch.object(
            MODULE, "_strict_validate_publication_bundle", return_value=[]
        ),
    ):
        return MODULE.validate_append_only_range(root, base, head)


def validate_prospective_publication(
    root: Path,
    base: str,
    head: str,
) -> list[str]:
    with (
        mock.patch.object(MODULE, "_verify_publisher_attestation", return_value=True),
        mock.patch.object(
            MODULE, "_strict_validate_publication_bundle", return_value=[]
        ),
    ):
        return MODULE.validate_pull_request_squash(root, base, head)


def validate_admin_pull_request(root: Path, base: str, head: str) -> list[str]:
    with (
        mock.patch.object(MODULE, "_validate_admin_commit_metadata", return_value=True),
        mock.patch.object(
            MODULE,
            "_validate_prospective_squash",
            return_value=b"Administer session retrospective history v2: fixture",
        ),
    ):
        return MODULE.validate_admin_pull_request_range(root, base, head)


def validsig_status(
    signer_fingerprint: bytes, *, primary_fingerprint: bytes | None = None
) -> bytes:
    fields = [
        signer_fingerprint,
        b"2026-07-14",
        b"1783987200",
        b"0",
        b"4",
        b"0",
        b"1",
        b"10",
        b"00",
    ]
    if primary_fingerprint is not None:
        fields.append(primary_fingerprint)
    return MODULE.VALIDSIG_STATUS_PREFIX + b" ".join(fields) + b"\n"


def empty_commit_object(
    root: Path, tree_oid: bytes, parent_oid: bytes, index: int
) -> bytes:
    identity = f"{PUBLISHER_NAME} <{PUBLISHER_EMAIL}> {COMMIT_TIMESTAMP} +0000".encode(
        "ascii"
    )
    raw_commit = (
        b"tree "
        + tree_oid
        + b"\nparent "
        + parent_oid
        + b"\nauthor "
        + identity
        + b"\ncommitter "
        + identity
        + b"\n\nCampaign segment "
        + str(index).encode("ascii")
        + b"\n"
    )
    return git(
        root,
        "hash-object",
        "-t",
        "commit",
        "-w",
        "--stdin",
        input_data=raw_commit,
    ).strip()


def tree_with_empty_root_entry(root: Path, tree_oid: bytes, name: bytes) -> bytes:
    empty_tree_oid = git(root, "mktree", input_data=b"").strip()
    entries = git(root, "ls-tree", "-z", tree_oid.decode("ascii"))
    return git(
        root,
        "mktree",
        "-z",
        input_data=(entries + b"040000 tree " + empty_tree_oid + b"\t" + name + b"\0"),
    ).strip()


def commit_tree(root: Path, tree_oid: bytes, parent_oid: str, message: str) -> str:
    return (
        git(
            root,
            "commit-tree",
            tree_oid.decode("ascii"),
            "-p",
            parent_oid,
            "-m",
            message,
            env=commit_environment(name=ADMIN_NAME, email=ADMIN_EMAIL),
        )
        .decode("ascii")
        .strip()
    )


class RetrospectiveHistoryGitV2Tests(unittest.TestCase):
    def test_direct_script_import_loads_the_structured_bundle_validator(self) -> None:
        script = (
            "import retrospective_history_git_v2 as module; "
            "print(module._load_structured_publication_validator().__name__)"
        )
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(SCRIPT.parent)
        with tempfile.TemporaryDirectory() as raw:
            result = subprocess.run(
                [sys.executable, "-c", script],
                cwd=raw,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                shell=False,
                timeout=60,
            )

        self.assertEqual(
            result.returncode,
            0,
            result.stderr.decode("utf-8", errors="replace"),
        )
        self.assertEqual(
            result.stdout,
            b"retrospective_history_v2\n",
        )

    def test_bounded_process_kills_on_output_cap_and_timeout(self) -> None:
        environment = os.environ.copy()
        for stream_name in ("stdout", "stderr"):
            with self.subTest(stream=stream_name):
                script = (
                    "import sys; "
                    f"sys.{stream_name}.write('x' * 10000000); "
                    f"sys.{stream_name}.flush()"
                )
                started = time.monotonic()
                with self.assertRaises(MODULE._GitFailure):
                    MODULE._run_process_bounded(
                        [sys.executable, "-c", script],
                        input_data=None,
                        environment=environment,
                        max_stdout_bytes=32,
                        max_stderr_bytes=32,
                        timeout_seconds=5,
                    )
                self.assertLess(time.monotonic() - started, 2)

        started = time.monotonic()
        with self.assertRaises(MODULE._GitFailure):
            MODULE._run_process_bounded(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                input_data=None,
                environment=environment,
                max_stdout_bytes=0,
                max_stderr_bytes=0,
                timeout_seconds=0.05,
            )
        self.assertLess(time.monotonic() - started, 2)

    def test_diagnostics_limit_includes_omission_marker(self) -> None:
        issues = MODULE._IssueCollector()
        for index in range(MODULE.MAX_DIAGNOSTICS + 10):
            issues.add(f"issue {index}")

        self.assertEqual(len(issues.items), MODULE.MAX_DIAGNOSTICS)
        self.assertEqual(issues.items[-1], MODULE.DIAGNOSTIC_OMISSION)
        self.assertLessEqual(len(issues._seen), MODULE.MAX_DIAGNOSTICS)

    def test_fixed_depth_run_path_fits_the_git_path_budget(self) -> None:
        path = run_path(
            mode="baseline",
            window="2026-01-01_to_2026-12-31",
            run_id="f" * 64,
            artifact="turn_findings.jsonl",
        )
        parsed = MODULE._parse_run_path(path.as_posix().encode("ascii"))

        self.assertEqual(len(path.parts), MODULE.RUN_PATH_COMPONENT_COUNT)
        self.assertLessEqual(
            len(path.as_posix().encode("ascii")), MODULE.MAX_PATH_BYTES
        )
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed.mode, "baseline")
        self.assertEqual(parsed.window, "2026-01-01_to_2026-12-31")
        self.assertEqual(parsed.run_id, "f" * 64)

    def test_linear_history_crosses_backward_page_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            tree_oid = git(root, "rev-parse", "HEAD^{tree}").strip()
            parent_oid = base.encode("ascii")
            for index in range(MODULE.COMMIT_PAGE_SIZE + 2):
                parent_oid = empty_commit_object(root, tree_oid, parent_oid, index)
            head = parent_oid.decode("ascii")
            git(root, "update-ref", "HEAD", head, base)

            commits = MODULE._linear_commits(
                root, base.encode("ascii"), head.encode("ascii")
            )

        self.assertEqual(len(commits), MODULE.COMMIT_PAGE_SIZE + 2)
        self.assertEqual(commits[0][1], base.encode("ascii"))
        self.assertEqual(commits[-1][0], head.encode("ascii"))

    def test_linear_history_rejects_more_than_the_total_commit_limit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            tree_oid = git(root, "rev-parse", "HEAD^{tree}").strip()
            parent_oid = base.encode("ascii")
            for index in range(3):
                parent_oid = empty_commit_object(root, tree_oid, parent_oid, index)
            head = parent_oid.decode("ascii")
            git(root, "update-ref", "HEAD", head, base)

            with mock.patch.object(MODULE, "MAX_RANGE_COMMITS", 2):
                issues = MODULE.validate_append_only_range(root, base, head)

        self.assertEqual(issues, ["range: commit count exceeds the validation limit"])

    def test_checkout_binding_requires_exact_clean_head(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            (root / "next.txt").write_text("next\n", encoding="utf-8")
            git(root, "add", "next.txt")
            head = commit(root, "Next")

            self.assertEqual(MODULE.validate_checkout_matches_revision(root, head), [])
            self.assertEqual(
                MODULE.validate_checkout_matches_revision(root, base),
                ["range: checkout HEAD does not match the requested head revision"],
            )

            (root / "untracked.txt").write_text("dirty\n", encoding="utf-8")
            self.assertEqual(
                MODULE.validate_checkout_matches_revision(root, head),
                ["range: checkout must be clean before retained tree validation"],
            )

    def test_valid_append_across_intermediate_commits(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            first_run = write_run(root)
            git(root, "add", "--", first_run.parent.as_posix())
            signed_commit(root, publication_message(first_run))

            second_run = write_run(root, run_id=SECOND_RUN_ID)
            git(root, "add", "--", second_run.parent.as_posix())
            head = signed_commit(root, publication_message(second_run))

            self.assertEqual(validate_with_trusted_signature(root, base, head), [])

    def test_range_runtime_model_era_requirement_matches_execution_kind(self) -> None:
        from tests.test_retrospective_history_v2 import (
            remove_model_execution_provenance,
            write_bundle,
        )

        cases = (
            ("bootstrap_v2", "complete", True),
            ("compliance_retraction", "complete_with_terminal_gaps", True),
            ("retrospective", "complete", False),
        )
        for execution_kind, status, expected_valid in cases:
            with (
                self.subTest(execution_kind=execution_kind),
                tempfile.TemporaryDirectory() as raw,
            ):
                root = Path(raw)
                base, _ = initialize_repository(root)
                predecessor = None
                reason = "initial"
                number = 1
                if execution_kind == "compliance_retraction":
                    predecessor = write_bundle(root, 1)
                    predecessor_manifest = (
                        predecessor.directory.relative_to(root) / "manifest.json"
                    )
                    git(
                        root,
                        "add",
                        "--",
                        predecessor.directory.relative_to(root).as_posix(),
                    )
                    base = signed_commit(
                        root, publication_message(predecessor_manifest)
                    )
                    reason = "compliance_retraction"
                    number = 2
                refs = write_bundle(
                    root,
                    number,
                    status=status,
                    reason=reason,
                    predecessor=predecessor,
                    execution_kind=execution_kind,
                )
                remove_model_execution_provenance(refs)
                manifest_path = refs.directory.relative_to(root) / "manifest.json"
                git(
                    root,
                    "add",
                    "--",
                    refs.directory.relative_to(root).as_posix(),
                )
                head = signed_commit(root, publication_message(manifest_path))

                with (
                    mock.patch.object(
                        MODULE, "_verify_commit_signature", return_value=True
                    ),
                    mock.patch.object(
                        MODULE, "_verify_publisher_attestation", return_value=True
                    ),
                ):
                    issues = MODULE.validate_append_only_range(root, base, head)

            if expected_valid:
                self.assertEqual(issues, [])
            else:
                self.assertTrue(
                    any(
                        "model_eras must be a non-empty array" in issue
                        for issue in issues
                    ),
                    issues,
                )

    def test_publication_range_rejects_earlier_admin_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            (root / "README.md").write_text("policy\n", encoding="utf-8")
            git(root, "add", "--", "README.md")
            signed_commit(
                root,
                "Administer session retrospective history v2: update policy",
                name=ADMIN_NAME,
                email=ADMIN_EMAIL,
            )

            publication = write_run(root)
            git(root, "add", "--", publication.parent.as_posix())
            head = signed_commit(root, publication_message(publication))

            issues = validate_with_trusted_signature(root, base, head)

        self.assertIn(
            "range: admin and publication roles must not be mixed",
            issues,
        )
        self.assertNotIn("README.md", "\n".join(issues))

    def test_clean_admin_blobs_are_scanned_across_pull_request_range(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            (root / "README.md").write_text(
                "Retained history policy.\n", encoding="utf-8"
            )
            git(root, "add", "README.md")
            commit(root, "Update retained history policy")

            helper = root / "AGENTS.md"
            helper.write_text("Retained history review policy.\n", encoding="utf-8")
            git(root, "add", helper.relative_to(root).as_posix())
            head = commit(root, "Add history helper")

            issues = validate_admin_pull_request(root, base, head)

        self.assertEqual(issues, [])

    def test_trust_root_upgrade_requires_single_maintainer_signed_role(self) -> None:
        upgrade_subject = MODULE.TRUST_ROOT_UPGRADE_MESSAGE.decode("ascii").rstrip("\n")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            trust_root_path = Path("scripts", "retrospective_history_credentials_v2.py")
            write_artifact(root, trust_root_path, b"SCANNER_VERSION = 2\n")
            git(root, "add", trust_root_path.as_posix())
            head = signed_commit(
                root,
                upgrade_subject,
                name=ADMIN_NAME,
                email=ADMIN_EMAIL,
            )

            verified_fingerprint_sets: list[frozenset[bytes] | None] = []

            def verify(
                _root: Path,
                _commit_oid: bytes,
                allowed_fingerprints: frozenset[bytes] | None = None,
            ) -> bool:
                verified_fingerprint_sets.append(allowed_fingerprints)
                return (
                    allowed_fingerprints
                    == MODULE.V2_ADMIN_MAINTAINER_SIGNING_FINGERPRINTS
                )

            with mock.patch.object(
                MODULE, "_verify_commit_signature", side_effect=verify
            ):
                accepted = MODULE.validate_pull_request_squash(root, base, head)
                post_merge = MODULE.validate_default_branch_update(root, base, head)

        self.assertEqual(accepted, [])
        self.assertIn(
            "range: candidate-controlled post-merge workflow cannot authorize a trust-root upgrade",
            post_merge,
        )
        self.assertTrue(verified_fingerprint_sets)
        self.assertEqual(
            set(verified_fingerprint_sets),
            {MODULE.V2_ADMIN_MAINTAINER_SIGNING_FINGERPRINTS},
        )

    def test_admin_merge_plan_subject_comes_from_identical_signed_commits(
        self,
    ) -> None:
        subject = "Administer session retrospective history v2: update policy"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root, include_trust_root=True)
            (root / "README.md").write_text("first policy update\n", encoding="utf-8")
            git(root, "add", "README.md")
            signed_commit(root, subject, name=ADMIN_NAME, email=ADMIN_EMAIL)
            (root / "AGENTS.md").write_text("second policy update\n", encoding="utf-8")
            git(root, "add", "AGENTS.md")
            matching_head = signed_commit(
                root, subject, name=ADMIN_NAME, email=ADMIN_EMAIL
            )

            with mock.patch.object(
                MODULE, "_verify_commit_signature", return_value=True
            ):
                plan, issues = MODULE.build_pull_request_merge_plan(
                    root, base, matching_head
                )

            (root / "AGENTS.md").write_text("third policy update\n", encoding="utf-8")
            git(root, "add", "AGENTS.md")
            mismatched_head = signed_commit(
                root,
                "Administer session retrospective history v2: different subject",
                name=ADMIN_NAME,
                email=ADMIN_EMAIL,
            )
            with mock.patch.object(
                MODULE, "_verify_commit_signature", return_value=True
            ):
                mismatched = MODULE.validate_pull_request_squash(
                    root, base, mismatched_head
                )
                admin_route_mismatched = MODULE.validate_admin_pull_request_range(
                    root, base, mismatched_head
                )

        self.assertEqual(issues, [])
        self.assertIsNotNone(plan)
        assert plan is not None
        self.assertEqual(plan.squash_subject, subject)
        mismatch_issue = (
            "range: admin commits must carry one identical immutable squash subject"
        )
        self.assertIn(mismatch_issue, mismatched)
        self.assertIn(mismatch_issue, admin_route_mismatched)

    def test_maintainer_candidate_accepts_independent_git_timestamps(self) -> None:
        subject = "Administer session retrospective history v2: update policy"
        author_identity = (
            b"Joey Teng <joey.teng.dev@gmail.com> "
            + str(COMMIT_TIMESTAMP + 17).encode("ascii")
            + b" -0700"
        )
        committer_identity = (
            b"Joey Teng <joey.teng.dev@gmail.com> "
            + str(COMMIT_TIMESTAMP + 29).encode("ascii")
            + b" +0530"
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root, include_trust_root=True)
            (root / "README.md").write_text("policy update\n", encoding="utf-8")
            git(root, "add", "README.md")
            head = signed_commit(
                root,
                subject,
                author_identity=author_identity,
                committer_identity=committer_identity,
            )

            verified_fingerprint_sets: list[frozenset[bytes] | None] = []

            def verify(
                _root: Path,
                _commit_oid: bytes,
                allowed_fingerprints: frozenset[bytes] | None = None,
            ) -> bool:
                verified_fingerprint_sets.append(allowed_fingerprints)
                return (
                    allowed_fingerprints
                    == MODULE.V2_ADMIN_MAINTAINER_SIGNING_FINGERPRINTS
                )

            with mock.patch.object(
                MODULE, "_verify_commit_signature", side_effect=verify
            ):
                plan, issues = MODULE.build_pull_request_merge_plan(root, base, head)
                admin_route_issues = MODULE.validate_admin_pull_request_range(
                    root, base, head
                )

        self.assertEqual(issues, [])
        self.assertIsNotNone(plan)
        self.assertEqual(admin_route_issues, [])
        self.assertEqual(
            verified_fingerprint_sets,
            [
                MODULE.V2_ADMIN_MAINTAINER_SIGNING_FINGERPRINTS,
                MODULE.V2_ADMIN_MAINTAINER_SIGNING_FINGERPRINTS,
            ],
        )

    def test_admin_merge_plan_rejects_sensitive_signed_subject(self) -> None:
        subject = (
            "Administer session retrospective history v2: rotate github_pat_" + "A" * 40
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root, include_trust_root=True)
            (root / "README.md").write_text("policy update\n", encoding="utf-8")
            git(root, "add", "README.md")
            head = signed_commit(root, subject, name=ADMIN_NAME, email=ADMIN_EMAIL)

            with (
                mock.patch.object(
                    MODULE, "_verify_commit_signature", return_value=True
                ),
                mock.patch.object(
                    MODULE,
                    "contains_high_confidence_credential",
                    wraps=MODULE.contains_high_confidence_credential,
                ) as scanner,
            ):
                plan, issues = MODULE.build_pull_request_merge_plan(root, base, head)
                admin_route_issues = MODULE.validate_admin_pull_request_range(
                    root, base, head
                )

        self.assertIsNone(plan)
        self.assertEqual(
            issues,
            ["range: immutable admin squash subject contains sensitive material"],
        )
        self.assertEqual(admin_route_issues, issues)
        self.assertIn(
            subject.encode("ascii"), [call.args[0] for call in scanner.call_args_list]
        )

    def test_candidate_admin_routes_reject_github_signed_author(self) -> None:
        subject = "Administer session retrospective history v2: update policy"
        github_author = (
            b"Unauthorized User <unauthorized@example.com> "
            + str(COMMIT_TIMESTAMP + 17).encode("ascii")
            + b" -0700"
        )
        github_committer = (
            b"GitHub <noreply@github.com> "
            + str(COMMIT_TIMESTAMP + 29).encode("ascii")
            + b" +0000"
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root, include_trust_root=True)
            (root / "README.md").write_text("policy update\n", encoding="utf-8")
            git(root, "add", "README.md")
            head = signed_commit(
                root,
                subject,
                author_identity=github_author,
                committer_identity=github_committer,
            )

            verified_fingerprint_sets: list[frozenset[bytes] | None] = []

            def verify(
                _root: Path,
                _commit_oid: bytes,
                allowed_fingerprints: frozenset[bytes] | None = None,
            ) -> bool:
                verified_fingerprint_sets.append(allowed_fingerprints)
                return (
                    allowed_fingerprints == MODULE.V2_ADMIN_GITHUB_SIGNING_FINGERPRINTS
                )

            with mock.patch.object(
                MODULE, "_verify_commit_signature", side_effect=verify
            ):
                candidate_issues = MODULE.validate_pull_request_squash(root, base, head)
                admin_route_issues = MODULE.validate_admin_pull_request_range(
                    root, base, head
                )
                plan, plan_issues = MODULE.build_pull_request_merge_plan(
                    root, base, head
                )
                final_issues = MODULE.validate_default_branch_update(root, base, head)

        metadata_issue = "commit 1: v2 admin commit metadata is unsafe"
        self.assertIn(metadata_issue, candidate_issues)
        self.assertIn(metadata_issue, admin_route_issues)
        self.assertIsNone(plan)
        self.assertIn(metadata_issue, plan_issues)
        self.assertEqual(final_issues, [])
        self.assertEqual(
            verified_fingerprint_sets,
            [MODULE.V2_ADMIN_GITHUB_SIGNING_FINGERPRINTS],
        )

    def test_trust_root_upgrade_rejects_github_signer_and_multi_commit_range(
        self,
    ) -> None:
        upgrade_subject = MODULE.TRUST_ROOT_UPGRADE_MESSAGE.decode("ascii").rstrip("\n")
        github_author = (
            b"Joey Teng <12524680+JoeyTeng@users.noreply.github.com> "
            + str(COMMIT_TIMESTAMP + 17).encode("ascii")
            + b" -0700"
        )
        github_committer = (
            b"GitHub <noreply@github.com> "
            + str(COMMIT_TIMESTAMP + 29).encode("ascii")
            + b" +0000"
        )

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            trust_root_path = Path("scripts", "retrospective_history_credentials_v2.py")
            write_artifact(root, trust_root_path, b"SCANNER_VERSION = 2\n")
            git(root, "add", trust_root_path.as_posix())
            github_head = signed_commit(
                root,
                upgrade_subject,
                author_identity=github_author,
                committer_identity=github_committer,
            )
            with mock.patch.object(
                MODULE, "_verify_commit_signature", return_value=True
            ):
                github_issues = MODULE.validate_pull_request_squash(
                    root, base, github_head
                )

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            (root / "README.md").write_text("Reviewed policy.\n", encoding="utf-8")
            git(root, "add", "README.md")
            signed_commit(
                root,
                "Administer session retrospective history v2: update policy",
                name=ADMIN_NAME,
                email=ADMIN_EMAIL,
            )
            trust_root_path = Path("scripts", "retrospective_history_credentials_v2.py")
            write_artifact(root, trust_root_path, b"SCANNER_VERSION = 2\n")
            git(root, "add", trust_root_path.as_posix())
            multi_head = signed_commit(
                root,
                upgrade_subject,
                name=ADMIN_NAME,
                email=ADMIN_EMAIL,
            )
            with mock.patch.object(
                MODULE, "_verify_commit_signature", return_value=True
            ):
                multi_issues = MODULE.validate_pull_request_squash(
                    root, base, multi_head
                )
                admin_route_multi_issues = MODULE.validate_admin_pull_request_range(
                    root, base, multi_head
                )

        self.assertIn("commit 1: v2 admin commit metadata is unsafe", github_issues)
        self.assertIn(
            "range: trust-root upgrade must be exactly one maintainer-signed commit",
            multi_issues,
        )
        self.assertIn(
            "range: trust-root upgrade must be exactly one maintainer-signed commit",
            admin_route_multi_issues,
        )

    def test_empty_tree_entry_is_inventoried_by_admin_range(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            (root / "README.md").write_text("policy update\n", encoding="utf-8")
            git(root, "add", "README.md")
            indexed_tree = git(root, "write-tree").strip()
            malicious_tree = tree_with_empty_root_entry(root, indexed_tree, b"runs")
            head = commit_tree(
                root,
                malicious_tree,
                base,
                "Update policy with hidden tree",
            )

            issues = validate_admin_pull_request(root, base, head)

        self.assertIn(
            "commit 1: admin and publication paths must not be mixed",
            issues,
        )
        self.assertIn("range: admin and publication roles must not be mixed", issues)

    def test_authorization_bearer_is_rejected_across_admin_range(self) -> None:
        token = b"0123456789abcdef"
        payloads = (
            b"Authorization: Bearer " + token + b"\n",
            b"curl -H 'Authorization: Bearer " + token + b"' endpoint\n",
            b'headers = ["Authorization: Bearer ' + token + b'"]\n',
            b'- "Authorization: Bearer ' + token + b'"\n',
            b'{"Authorization": "Bearer ' + token + b'"}\n',
            b'AUTHORIZATION="Bearer ' + token + b'"\n',
        )
        for payload in payloads:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                base, _ = initialize_repository(root)
                (root / "README.md").write_bytes(payload)
                git(root, "add", "README.md")
                head = commit(root, "Update admin fixture")

                issues = validate_admin_pull_request(root, base, head)

            self.assertEqual(
                issues,
                ["commit 1: admin path, object, or secret gate failed"],
            )

    def test_common_service_credentials_are_rejected_across_admin_range(
        self,
    ) -> None:
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
                base, _ = initialize_repository(root)
                (root / "README.md").write_bytes(b"credential=" + credential + b"\n")
                git(root, "add", "README.md")
                head = commit(root, "Update admin fixture")

                issues = validate_admin_pull_request(root, base, head)

            self.assertEqual(
                issues,
                ["commit 1: admin path, object, or secret gate failed"],
            )

    def test_standard_private_key_blocks_are_rejected_across_admin_range(
        self,
    ) -> None:
        markers = (
            b"PRIVATE " + b"KEY",
            b"ENCRYPTED " + b"PRIVATE " + b"KEY",
        )
        for marker in markers:
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                base, _ = initialize_repository(root)
                (root / "README.md").write_bytes(
                    b"-----BEGIN " + marker + b"-----\nfixture\n"
                )
                git(root, "add", "README.md")
                head = commit(root, "Update admin fixture")

                issues = validate_admin_pull_request(root, base, head)

            self.assertEqual(
                issues,
                ["commit 1: admin path, object, or secret gate failed"],
            )

    def test_short_non_header_bearer_examples_are_not_admin_secrets(self) -> None:
        examples = (
            b"Use " + b"Bearer " + b"0123456789abcdef in documentation.\n",
            b"Use "
            + b"Bearer "
            + b"0123456789abcdef0123456789abcdef in documentation.\n",
            b"Authorization: " + b"Bearer " + b"<credential>\n",
            b"X-Authorization: " + b"Bearer " + b"0123456789abcdef\n",
            b'SOME_AUTHORIZATION="Bearer 0123456789abcdef"\n',
            b'{"Proxy-Authorization": "Bearer 0123456789abcdef"}\n',
            b"Explain Authorization: Bearer 0123456789abcdef in documentation.\n",
            b'headers = ["Authorization: Bearer 0123456789abc"]\n',
            b'headers = ["Authorization: Bearer ' + b"a" * 4097 + b'"]\n',
        )
        for payload in examples:
            with self.subTest(payload=payload):
                self.assertTrue(MODULE._admin_blob_is_safe(payload))

    def test_binary_openpgp_secret_packets_are_rejected_across_admin_range(
        self,
    ) -> None:
        key_prefix = b"\x04\x00\x00\x00\x00\x01"
        packets = (
            b"\xc5\x06" + key_prefix,
            b"\xc7\x06" + key_prefix,
            b"\x94\x06" + key_prefix,
        )
        for packet in packets:
            with self.subTest(header=packet[:1]), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                base, _ = initialize_repository(root)
                (root / "README.md").write_bytes(b"prefix\x00" + packet + b"\x00suffix")
                git(root, "add", "README.md")
                head = commit(root, "Update admin fixture")

                issues = validate_admin_pull_request(root, base, head)

            self.assertEqual(
                issues,
                ["commit 1: admin path, object, or secret gate failed"],
            )

        self.assertTrue(MODULE._admin_blob_is_safe(b"\xc6\x06" + key_prefix))

    def test_shared_admin_blob_is_scanned_once_across_range(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            payload = b"def validate() -> bool:\n    return True\n"
            first_paths = (Path("README.md"), Path("AGENTS.md"))
            for relative in first_paths:
                write_artifact(root, relative, payload)
            git(root, "add", *(path.as_posix() for path in first_paths))
            commit(root, "Add shared infrastructure blob")

            final_path = Path("data", "README.md")
            write_artifact(root, final_path, payload)
            git(root, "add", final_path.as_posix())
            head = commit(root, "Reuse shared infrastructure blob")

            with (
                mock.patch.object(
                    MODULE,
                    "MAX_ADMIN_SCAN_BYTES",
                    len(payload),
                ),
                mock.patch.object(
                    MODULE,
                    "MAX_ADMIN_SCAN_OBJECTS",
                    1,
                ),
                mock.patch.object(
                    MODULE,
                    "_admin_blob_is_safe",
                    wraps=MODULE._admin_blob_is_safe,
                ) as scanner,
            ):
                issues = validate_admin_pull_request(root, base, head)

        self.assertEqual(issues, [])
        self.assertEqual(scanner.call_count, 1)

    def test_aggregate_work_limits_stop_512_commit_shared_and_unique_oid_ranges(
        self,
    ) -> None:
        commit_count = 512
        paths_per_commit = 8
        commits = [
            (
                f"{index + 2:040x}".encode("ascii"),
                f"{index + 1:040x}".encode("ascii"),
            )
            for index in range(commit_count)
        ]
        allowed_paths = tuple(sorted(MODULE.V2_ADMIN_PATHS))[:paths_per_commit]
        zero_oid = b"0" * 40
        safe_payload = b"SAFE_FIXTURE = True\n"

        for (
            oid_mode,
            entry_limit,
            unique_oid_limit,
            expected_diff_calls,
            processed_commits,
        ) in (
            ("shared", 32, MODULE.MAX_RANGE_UNIQUE_OIDS, 5, 4),
            ("unique", MODULE.MAX_RANGE_DIFF_ENTRIES, 16, 3, 2),
        ):
            with self.subTest(oid_mode=oid_mode), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                diff_call_count = 0
                object_query_batches: list[tuple[bytes, ...]] = []

                def diff_for_commit(commit_index: int) -> bytes:
                    entries = []
                    for path_index, path in enumerate(allowed_paths):
                        object_index = commit_index * paths_per_commit + path_index + 1
                        object_id = (
                            b"f" * 40
                            if oid_mode == "shared"
                            else f"{(1 << 156) + object_index:040x}".encode("ascii")
                        )
                        entries.append(
                            b":000000 100644 "
                            + zero_oid
                            + b" "
                            + object_id
                            + b" A\0"
                            + path
                            + b"\0"
                        )
                    return b"".join(entries)

                def fake_run_git(
                    _root: Path,
                    arguments: list[str],
                    **_kwargs: object,
                ) -> subprocess.CompletedProcess[bytes]:
                    nonlocal diff_call_count
                    if arguments[:2] == ["rev-parse", "--is-inside-work-tree"]:
                        return subprocess.CompletedProcess(
                            arguments, 0, stdout=b"true\n", stderr=b""
                        )
                    if arguments[:2] == ["merge-base", "--is-ancestor"]:
                        return subprocess.CompletedProcess(
                            arguments, 0, stdout=b"", stderr=b""
                        )
                    if arguments[0] == "diff-tree":
                        output = diff_for_commit(diff_call_count)
                        diff_call_count += 1
                        return subprocess.CompletedProcess(
                            arguments, 0, stdout=output, stderr=b""
                        )
                    if arguments[0] == "ls-tree":
                        return subprocess.CompletedProcess(
                            arguments, 0, stdout=b"", stderr=b""
                        )
                    raise AssertionError(f"unexpected Git call: {arguments}")

                def fake_object_info(
                    _root: Path, object_ids: object
                ) -> dict[bytes, object]:
                    ordered = tuple(sorted(set(object_ids)))  # type: ignore[arg-type]
                    object_query_batches.append(ordered)
                    return {
                        object_id: MODULE._ObjectInfo(b"blob", len(safe_payload))
                        for object_id in ordered
                    }

                def fake_blob_contents(
                    _root: Path, object_infos: dict[bytes, object]
                ) -> dict[bytes, bytes]:
                    return {object_id: safe_payload for object_id in object_infos}

                with (
                    mock.patch.object(
                        MODULE, "_resolve_commit", side_effect=[b"a" * 40, b"b" * 40]
                    ),
                    mock.patch.object(MODULE, "_linear_commits", return_value=commits),
                    mock.patch.object(MODULE, "_run_git", side_effect=fake_run_git),
                    mock.patch.object(
                        MODULE, "_batch_object_info", side_effect=fake_object_info
                    ) as object_info,
                    mock.patch.object(
                        MODULE, "_batch_blob_contents", side_effect=fake_blob_contents
                    ) as blob_contents,
                    mock.patch.object(
                        MODULE,
                        "_is_forbidden_transient_path",
                        wraps=MODULE._is_forbidden_transient_path,
                    ) as path_classifier,
                    mock.patch.object(MODULE, "MAX_RANGE_DIFF_ENTRIES", entry_limit),
                    mock.patch.object(
                        MODULE, "MAX_RANGE_UNIQUE_OIDS", unique_oid_limit
                    ),
                    mock.patch.object(
                        MODULE, "_validate_admin_commit_metadata", return_value=True
                    ),
                    mock.patch.object(
                        MODULE,
                        "_load_commit_message",
                        return_value=(
                            b"Administer session retrospective history v2: "
                            b"bounded fixture\n"
                        ),
                    ),
                ):
                    issues = MODULE.validate_admin_pull_request_range(
                        root, "base", "head"
                    )

            self.assertEqual(issues, [MODULE.RANGE_WORK_LIMIT_DIAGNOSTIC])
            self.assertEqual(diff_call_count, expected_diff_calls)
            self.assertEqual(
                path_classifier.call_count, processed_commits * paths_per_commit * 2
            )
            if oid_mode == "shared":
                self.assertEqual(object_info.call_count, 1)
                self.assertEqual(blob_contents.call_count, 1)
                self.assertEqual(sum(map(len, object_query_batches)), 1)
            else:
                self.assertEqual(object_info.call_count, 2)
                self.assertEqual(blob_contents.call_count, 2)
                self.assertEqual(sum(map(len, object_query_batches)), 16)

    def test_admin_blob_size_and_high_confidence_secret_fail_closed(self) -> None:
        cases = (
            (
                "oversized",
                b"x" * (MODULE.MAX_ADMIN_BLOB_BYTES + 1),
            ),
            (
                "token",
                fixture_text("github", "_pat_", "A" * 40).encode("ascii"),
            ),
        )
        for name, content in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                base, _ = initialize_repository(root)
                write_artifact(root, Path("README.md"), content)
                git(root, "add", "README.md")
                head = commit(root, "Update admin fixture")

                issues = validate_admin_pull_request(root, base, head)

            self.assertEqual(
                issues,
                ["commit 1: admin path, object, or secret gate failed"],
            )
            self.assertNotIn("README.md", "\n".join(issues))

    def test_admin_source_content_is_opaque_outside_high_confidence_secret_gate(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            content = (
                b"raw_prompt = {'text': 'reviewed source fixture'}\n"
                b"customer_data = ['reviewed fixture']\n"
                b"https://internal.example.invalid/path\n"
                b"author@example.invalid\n"
                b"\xff\n"
            )
            write_artifact(root, Path("README.md"), content)
            git(root, "add", "README.md")
            head = commit(root, "Update reviewed source fixture")

            issues = validate_admin_pull_request(root, base, head)

        self.assertEqual(issues, [])

    def test_admin_noncanonical_git_entries_fail_closed(self) -> None:
        for name in ("symlink", "gitlink", "tree", "executable"):
            with self.subTest(case=name), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                base, _ = initialize_repository(root)
                relative = Path("scripts", "retrospective_history_git_v2.py")
                (root / relative).parent.mkdir(parents=True, exist_ok=True)
                if name == "symlink":
                    (root / relative).symlink_to("../README.md")
                    git(root, "add", relative.as_posix())
                elif name == "gitlink":
                    git(
                        root,
                        "update-index",
                        "--add",
                        "--cacheinfo",
                        f"160000,{base},{relative.as_posix()}",
                    )
                elif name == "tree":
                    write_artifact(root, relative / "payload.txt", b"safe\n")
                    git(root, "add", (relative / "payload.txt").as_posix())
                else:
                    write_artifact(
                        root, relative, b"def validate():\n    return True\n"
                    )
                    (root / relative).chmod(0o755)
                    git(root, "add", relative.as_posix())
                head = commit(root, "Add noncanonical infrastructure entry")

                issues = validate_admin_pull_request(root, base, head)

            self.assertEqual(
                issues,
                ["commit 1: admin path, object, or secret gate failed"],
            )
            self.assertNotIn(relative.as_posix(), "\n".join(issues))

    def test_transient_suffix_normalization_is_iterative_and_specific(self) -> None:
        forbidden = (
            b"scripts/Auth.PY",
            b"scripts/SessionData.pY",
            b".github/workflows/SessionIndex.YML",
            b"scripts/sessiondata.py",
            b"scripts/SESSIONINDEX.PY.BAK",
            b"scripts/sourcemetadata.py",
            b"scripts/ShardManifest.Py.Backup",
            b"scripts/archivedsessions.py.old",
            b"auth.json.bak",
            b"history.jsonl.bak",
            b"config.toml~",
            b"history.jsonl.1",
            b"history.jsonl.1.bak",
            b"history.jsonl.~1~",
            b"auth.json.2.gz",
            b"history.jsonl.gz.bak.old~",
            b"auth.json.zst.backup.save",
            b"history.jsonl.swp",
            b"auth.json.tmp.123",
            b".config.toml.swo",
            b"nested/" + b"roll" + b"out/private.jsonl",
            b"nested/Session.BAK/private.jsonl",
            b"nested/.Co" + b"dex-cache.old/private.jsonl",
            b"nested/Auth.json.backup/private.jsonl",
            b"nested/History.gz.old/private.jsonl",
            b"nested/Index.tmp/private.jsonl",
            b"nested/source-" + b"metadata.json.gz.backup/private.jsonl",
            b"nested/Shard_Cache.old/private.jsonl",
            b"nested/tool-" + b"output.jsonl~/private.jsonl",
        )
        ordinary = (
            b"docs/backup-strategy.md",
            b"docs/history-notes.md",
            b"docs/old-design.md",
            b"docs/save-points.txt",
            b"docs/temporary-files.md",
            b"docs/history-notes.md.1.bak",
            b"docs/release.2026.1.md",
            b"docs/authorship.md",
            b"docs/project-index.md",
            b"docs/sharding-strategy.md",
            b"scripts/retrospective_history_git_v2.py",
            b"schemas/session-retrospective-v2.schema.json",
            b"tests/test_retrospective_history_git_v2.py",
            b"retrospective-history-v2-publisher.asc",
            run_path(mode="session").as_posix().encode("ascii"),
        )

        for path in forbidden:
            with self.subTest(path=path):
                self.assertTrue(MODULE._is_forbidden_transient_path(path))
        for path in ordinary:
            with self.subTest(path=path):
                self.assertFalse(MODULE._is_forbidden_transient_path(path))

    def test_add_then_delete_sensitive_allowed_extension_aliases_are_rejected(
        self,
    ) -> None:
        relative_names = (
            "scripts/Auth.PY",
            "scripts/SessionData.pY",
            ".github/workflows/SessionIndex.YML",
            "scripts/sessiondata.py",
            "scripts/SESSIONINDEX.PY.BAK",
            "scripts/sourcemetadata.py",
            "scripts/ShardManifest.Py.Backup",
            "scripts/archivedsessions.py.old",
        )
        for relative_name in relative_names:
            with self.subTest(path=relative_name), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                base, _ = initialize_repository(root)
                write_artifact(root, Path(relative_name), b"safe fixture\n")
                git(root, "add", "--", relative_name)
                commit(root, "Add sensitive extension alias")

                (root / relative_name).unlink()
                git(root, "add", "--all")
                head = commit(root, "Delete sensitive extension alias")

                issues = validate_admin_pull_request(root, base, head)

            self.assertEqual(
                issues,
                [
                    "commit 1: forbidden raw or transient path changed",
                    "commit 2: forbidden raw or transient path changed",
                ],
            )
            diagnostics = "\n".join(issues)
            self.assertNotIn(relative_name, diagnostics)

    def test_add_then_delete_raw_artifact_is_rejected_per_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            raw_component = fixture_text("r", "aw")
            artifact_stem = fixture_text("roll", "out-private")
            artifact = root / raw_component / (artifact_stem + ".jsonl")
            artifact.parent.mkdir()
            artifact.write_text("{}\n", encoding="utf-8")
            git(root, "add", "--", artifact.relative_to(root).as_posix())
            commit(root, "Add temporary artifact")

            artifact.unlink()
            artifact.parent.rmdir()
            git(root, "add", "--all")
            head = commit(root, "Delete temporary artifact")

            self.assertFalse(artifact.exists())
            issues = validate_admin_pull_request(root, base, head)

        self.assertEqual(
            issues,
            [
                "commit 1: forbidden raw or transient path changed",
                "commit 2: forbidden raw or transient path changed",
            ],
        )
        self.assertNotIn(artifact_stem, "\n".join(issues))

    def test_add_then_delete_transient_aliases_are_rejected_per_commit(self) -> None:
        relative_names = (
            "auth.json.bak",
            "history.jsonl.bak",
            "config.toml~",
            "history.jsonl.1",
            "history.jsonl.1.bak",
            "history.jsonl.~1~",
            "auth.json.2.gz",
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            for relative_name in relative_names:
                (root / relative_name).write_text("{}\n", encoding="utf-8")
            git(root, "add", "--", *relative_names)
            commit(root, "Add temporary aliases")

            for relative_name in relative_names:
                (root / relative_name).unlink()
            git(root, "add", "--all")
            head = commit(root, "Delete temporary aliases")

            issues = validate_admin_pull_request(root, base, head)

        self.assertEqual(
            issues,
            [
                "commit 1: forbidden raw or transient path changed",
                "commit 2: forbidden raw or transient path changed",
            ],
        )
        diagnostics = "\n".join(issues)
        for relative_name in relative_names:
            self.assertNotIn(relative_name, diagnostics)

    def test_add_then_delete_nested_sensitive_components_are_rejected(self) -> None:
        sensitive_components = (
            "Roll" + "Out.backup",
            "Session.BAK",
            ".Co" + "dex-cache.old",
            "Auth.json.backup",
            "Index.tmp",
            "source-" + "metadata.json.gz.backup",
            "Shard_" + "Cache.old",
            "tool-" + "output.jsonl~",
        )
        infrastructure_roots = ("scripts", ".github/workflows", "tests", "schemas")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            artifacts = [
                Path(
                    infrastructure_roots[index % len(infrastructure_roots)],
                    component,
                    f"fixture-{index}.jsonl",
                )
                for index, component in enumerate(sensitive_components)
            ]
            for artifact in artifacts:
                write_artifact(root, artifact)
            git(root, "add", "--", *(artifact.as_posix() for artifact in artifacts))
            commit(root, "Add temporary nested artifacts")

            for artifact in artifacts:
                (root / artifact).unlink()
            git(root, "add", "--all")
            head = commit(root, "Delete temporary nested artifacts")

            issues = validate_admin_pull_request(root, base, head)

        self.assertEqual(
            issues,
            [
                "commit 1: forbidden raw or transient path changed",
                "commit 2: forbidden raw or transient path changed",
            ],
        )
        diagnostics = "\n".join(issues)
        for component in sensitive_components:
            self.assertNotIn(component, diagnostics)

    def test_campaign_root_must_follow_every_segment_commit(self) -> None:
        campaign_ref = "campaign_ref_v2:" + "a" * 32

        def manifest(
            run_id: str, publication_role: str, segment_ordinal: int | None = None
        ) -> bytes:
            value: dict[str, object] = {
                "run_id": run_id,
                "publication_role": publication_role,
                "campaign_ref": campaign_ref,
                "campaign_segment_count": 2,
            }
            if segment_ordinal is not None:
                value["campaign_segment_metadata"] = {
                    "segment_ordinal": segment_ordinal
                }
            return json.dumps(value, separators=(",", ":")).encode() + b"\n"

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            first_segment = write_run(
                root,
                run_id=RUN_ID,
                contents={"manifest.json": manifest(RUN_ID, "campaign_segment", 1)},
            )
            git(root, "add", "--", first_segment.parent.as_posix())
            signed_commit(root, publication_message(first_segment))

            campaign_root = write_run(
                root,
                run_id=SECOND_RUN_ID,
                contents={"manifest.json": manifest(SECOND_RUN_ID, "campaign_root")},
            )
            git(root, "add", "--", campaign_root.parent.as_posix())
            signed_commit(root, publication_message(campaign_root))

            second_segment = write_run(
                root,
                run_id=THIRD_RUN_ID,
                contents={
                    "manifest.json": manifest(THIRD_RUN_ID, "campaign_segment", 2)
                },
            )
            git(root, "add", "--", second_segment.parent.as_posix())
            head = signed_commit(root, publication_message(second_segment))

            issues = "\n".join(validate_with_trusted_signature(root, base, head))

        self.assertIn(
            "commit 2: campaign root must be published after all campaign segments",
            issues,
        )

    def test_revision_predecessor_must_not_first_appear_in_a_later_commit(
        self,
    ) -> None:
        current_revision = "summary_revision_ref_v2:" + "1" * 32
        future_revision = "summary_revision_ref_v2:" + "2" * 32

        def summary(current: str, predecessor: str | None) -> bytes:
            value = {
                "summary_revision_ref": current,
                "predecessor_summary_revision_ref": predecessor,
                "supersedes_summary_revision_refs": [],
            }
            return json.dumps(value, separators=(",", ":")).encode() + b"\n"

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            forward_reference = write_run(
                root,
                run_id=RUN_ID,
                contents={"summary.json": summary(current_revision, future_revision)},
            )
            git(root, "add", "--", forward_reference.parent.as_posix())
            signed_commit(root, publication_message(forward_reference))

            predecessor = write_run(
                root,
                run_id=SECOND_RUN_ID,
                contents={"summary.json": summary(future_revision, None)},
            )
            git(root, "add", "--", predecessor.parent.as_posix())
            head = signed_commit(root, publication_message(predecessor))

            issues = "\n".join(validate_with_trusted_signature(root, base, head))

        self.assertIn(
            "commit 1: v2 revision predecessor must be published by an earlier commit",
            issues,
        )

    def test_publication_commit_rejects_multiple_complete_runs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            first_run = write_run(root)
            second_run = write_run(root, run_id=SECOND_RUN_ID)
            git(root, "add", "--", "runs")
            head = signed_commit(root, publication_message(first_run))

            issues = "\n".join(validate_with_trusted_signature(root, base, head))

        self.assertIn("publication commit must add exactly one complete v2 run", issues)
        self.assertNotIn(second_run.as_posix(), issues)

    def test_pull_request_validates_one_exact_prospective_squash(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root, include_trust_root=True)
            artifact = write_run(root)
            git(root, "add", "--", artifact.parent.as_posix())
            head = commit(root, publication_message(artifact))

            with (
                mock.patch.object(
                    MODULE, "_verify_publisher_attestation", return_value=True
                ),
                mock.patch.object(
                    MODULE, "_strict_validate_publication_bundle", return_value=[]
                ),
            ):
                plan, issues = MODULE.build_pull_request_merge_plan(root, base, head)
            expected_tree = git(root, "rev-parse", "HEAD^{tree}").decode().strip()

        self.assertEqual(issues, [])
        self.assertIsNotNone(plan)
        assert plan is not None
        self.assertEqual(plan.squash_subject, publication_message(artifact))
        self.assertEqual(plan.head_tree_oid, expected_tree)
        self.assertRegex(plan.trust_generation, r"^sha256:[0-9a-f]{64}$")

    def test_pull_request_rejects_multiple_publications_before_squash(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            first = write_run(root)
            git(root, "add", "--", first.parent.as_posix())
            commit(root, publication_message(first))
            second = write_run(
                root,
                window="2026-07-15",
                run_id=SECOND_RUN_ID,
            )
            git(root, "add", "--", second.parent.as_posix())
            head = commit(root, publication_message(second))

            issues = validate_prospective_publication(
                root,
                base,
                head,
            )

        self.assertIn(
            "range: publication pull request must contain exactly one v2 run",
            issues,
        )
        self.assertTrue(
            any(
                "publication commit must add exactly one complete v2 run" in issue
                for issue in issues
            )
        )

    def test_default_branch_update_requires_one_actual_squash_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            for relative in ("README.md", "AGENTS.md"):
                (root / relative).write_text(
                    f"{relative} update\n",
                    encoding="utf-8",
                )
                git(root, "add", relative)
                commit(root, f"Update {relative}")
            head = git(root, "rev-parse", "HEAD").decode("ascii").strip()

            issues = MODULE.validate_default_branch_update(root, base, head)

        self.assertEqual(
            issues,
            ["range: default-branch update must be exactly one squash commit"],
        )

    def test_publication_commit_rejects_non_run_companion_changes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            artifact = write_run(root)
            (root / "README.md").write_text("mixed publication\n", encoding="utf-8")
            git(root, "add", "--", artifact.parent.as_posix(), "README.md")
            head = signed_commit(root, publication_message(artifact))

            issues = "\n".join(validate_with_trusted_signature(root, base, head))

        self.assertIn("publication commit must add exactly one complete v2 run", issues)

    def test_publication_message_must_match_the_only_run(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            artifact = write_run(root)
            git(root, "add", "--", artifact.parent.as_posix())
            mismatched = run_path(window="2026-07-15")
            head = signed_commit(root, publication_message(mismatched))

            issues = "\n".join(validate_with_trusted_signature(root, base, head))

        self.assertIn("publication commit metadata is unsafe", issues)

    def test_publication_message_run_ref_must_match_the_run_route(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            artifact = write_run(root)
            git(root, "add", "--", artifact.parent.as_posix())
            head = signed_commit(root, publication_message_for(run_id=SECOND_RUN_ID))

            issues = "\n".join(validate_with_trusted_signature(root, base, head))

        self.assertIn("publication commit metadata is unsafe", issues)

    def test_manifest_run_id_must_match_the_run_route(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            mismatched_manifest = (
                json.dumps({"run_id": SECOND_RUN_ID}, separators=(",", ":")).encode()
                + b"\n"
            )
            artifact = write_run(root, contents={"manifest.json": mismatched_manifest})
            git(root, "add", "--", artifact.parent.as_posix())
            head = signed_commit(root, publication_message(artifact))

            issues = "\n".join(validate_with_trusted_signature(root, base, head))

        self.assertIn(
            "manifest run_id does not match the physical v2 run route", issues
        )

    def test_partial_run_introduction_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            artifact = run_path()
            write_artifact(root, artifact)
            git(root, "add", "--", artifact.as_posix())
            head = signed_commit(root, publication_message(artifact))

            issues = "\n".join(validate_with_trusted_signature(root, base, head))

        self.assertIn(
            "new v2 run must atomically add exactly the eight required artifacts",
            issues,
        )

    def test_later_fill_of_partial_run_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            initialize_repository(root)
            artifact = run_path()
            write_artifact(root, artifact)
            git(root, "add", "--", artifact.as_posix())
            partial_base = commit(root, publication_message(artifact))

            for missing_artifact in sorted(MODULE.RUN_ARTIFACTS - {artifact.name}):
                write_artifact(root, run_path(artifact=missing_artifact))
            git(root, "add", "--", artifact.parent.as_posix())
            head = signed_commit(root, publication_message(artifact))

            issues = "\n".join(
                validate_with_trusted_signature(root, partial_base, head)
            )

        self.assertIn("adding artifacts to an existing v2 run is not allowed", issues)

    def test_intermediate_modification_then_revert_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            artifact = run_path()

            write_run(root)
            write_artifact(root, artifact, b"original\n")
            git(root, "add", "--", artifact.parent.as_posix())
            signed_commit(root, publication_message(artifact))
            write_artifact(root, artifact, b"mutated\n")
            git(root, "add", "--", artifact.as_posix())
            signed_commit(root, publication_message(artifact))
            write_artifact(root, artifact, b"original\n")
            git(root, "add", "--", artifact.as_posix())
            head = signed_commit(root, publication_message(artifact))

            issues = "\n".join(validate_with_trusted_signature(root, base, head))

        self.assertIn("commit 2", issues)
        self.assertIn("modification is not allowed", issues)

    def test_deletion_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            _, _ = initialize_repository(root)
            artifact = run_path()
            write_artifact(root, artifact)
            git(root, "add", artifact.as_posix())
            base = commit(root, publication_message(artifact))

            (root / artifact).unlink()
            git(root, "add", "-A", "--", artifact.as_posix())
            head = signed_commit(root, publication_message(artifact))

            issues = "\n".join(validate_with_trusted_signature(root, base, head))

        self.assertIn("deletion is not allowed", issues)

    def test_rename_is_rejected_as_delete_and_add(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            _, _ = initialize_repository(root)
            source = run_path(artifact="manifest.json")
            destination = run_path(artifact="coverage.json")
            write_artifact(root, source)
            git(root, "add", source.as_posix())
            base = commit(root, publication_message(source))

            (root / source).rename(root / destination)
            git(root, "add", "-A", "--", source.as_posix(), destination.as_posix())
            head = signed_commit(root, publication_message(destination))

            issues = "\n".join(validate_with_trusted_signature(root, base, head))

        self.assertIn("rename is not allowed", issues)

    def test_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            artifact = run_path()
            (root / artifact).parent.mkdir(parents=True)
            os.symlink("opaque-target", root / artifact)
            git(root, "add", artifact.as_posix())
            head = signed_commit(root, publication_message(artifact))

            issues = "\n".join(validate_with_trusted_signature(root, base, head))

        self.assertIn("symlink is not allowed", issues)

    def test_gitlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            artifact = run_path()
            git(
                root,
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{base},{artifact.as_posix()}",
            )
            head = signed_commit(root, publication_message(artifact))

            issues = "\n".join(validate_with_trusted_signature(root, base, head))

        self.assertIn("gitlink is not allowed", issues)

    def test_mode_change_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            _, _ = initialize_repository(root)
            artifact = run_path(artifact="report.md")
            write_artifact(root, artifact, b"# Report\n")
            git(root, "add", artifact.as_posix())
            base = commit(root, publication_message(artifact))

            git(root, "update-index", "--chmod=+x", artifact.as_posix())
            head = signed_commit(root, publication_message(artifact))

            issues = "\n".join(validate_with_trusted_signature(root, base, head))

        self.assertIn("mode or type change is not allowed", issues)

    def test_oversized_blob_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            artifact = run_path(artifact="report.md")
            write_artifact(
                root,
                artifact,
                b"x" * (MODULE.MAX_ARTIFACT_BYTES[artifact.name] + 1),
            )
            git(root, "add", artifact.as_posix())
            head = signed_commit(root, publication_message(artifact))

            issues = "\n".join(validate_with_trusted_signature(root, base, head))

        self.assertIn("Git object exceeds the size limit", issues)

    def test_artifact_size_limits_match_tree_validator(self) -> None:
        self.assertEqual(
            MODULE.MAX_ARTIFACT_BYTES,
            {
                "coverage.json": 8 * 1024 * 1024,
                "episodes.jsonl": 16 * 1024 * 1024,
                "manifest.json": 8 * 1024 * 1024,
                "report.md": 256 * 1024,
                "summary.json": 8 * 1024 * 1024,
                "topics.jsonl": 16 * 1024 * 1024,
                "trend_report.json": 8 * 1024 * 1024,
                "turn_findings.jsonl": 16 * 1024 * 1024,
            },
        )

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            bounded_row = b'"' + b"x" * (900 * 1024) + b'"\n'
            artifact = write_run(
                root,
                contents={"episodes.jsonl": bounded_row * 10},
            )
            git(root, "add", "--", artifact.parent.as_posix())
            head = signed_commit(root, publication_message(artifact))

            self.assertEqual(validate_with_trusted_signature(root, base, head), [])

    def test_malformed_run_path_is_rejected_without_echoing_it(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            unsafe_component = "customer-secret"
            parts = list(run_path().parts)
            parts[3 + MODULE.WINDOW_ROUTE_COMPONENT_COUNT] = unsafe_component
            artifact = Path(*parts)
            write_artifact(root, artifact)
            git(root, "add", artifact.as_posix())
            head = signed_commit(root, publication_message_for())

            issues = "\n".join(validate_with_trusted_signature(root, base, head))

        self.assertIn("malformed v2 run path", issues)
        self.assertNotIn(unsafe_component, issues)

    def test_old_direct_run_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            old_directory = Path("runs", "daily", "2026-07-14", RUN_ID)
            for artifact in MODULE.RUN_ARTIFACTS:
                write_artifact(root, old_directory / artifact)
            git(root, "add", "--", old_directory.as_posix())
            head = signed_commit(root, publication_message_for())

            issues = "\n".join(validate_with_trusted_signature(root, base, head))

        self.assertIn("malformed v2 run path", issues)
        self.assertIn("publication commit must add exactly one complete v2 run", issues)

    def test_malformed_route_depth_is_rejected(self) -> None:
        parts = list(run_path().parts)
        del parts[2]
        artifact = Path(*parts)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            write_artifact(root, artifact)
            git(root, "add", "--", artifact.as_posix())
            head = signed_commit(root, publication_message_for())

            issues = "\n".join(validate_with_trusted_signature(root, base, head))

        self.assertIn("malformed v2 run path", issues)

    def test_window_route_must_match_mode_and_window(self) -> None:
        canonical_parts = list(run_path().parts)
        window_index = 2 + MODULE.WINDOW_ROUTE_COMPONENT_COUNT
        wrong_route_parts = canonical_parts.copy()
        wrong_route_parts[2] = "00" if wrong_route_parts[2] != "00" else "01"
        wrong_mode_parts = canonical_parts.copy()
        wrong_mode_parts[1] = "weekly"
        wrong_window_parts = canonical_parts.copy()
        wrong_window_parts[window_index] = "2026-07-15"
        cases = (
            ("route", Path(*wrong_route_parts), publication_message_for()),
            (
                "mode",
                Path(*wrong_mode_parts),
                publication_message_for(mode="weekly"),
            ),
            (
                "window",
                Path(*wrong_window_parts),
                publication_message_for(window="2026-07-15"),
            ),
        )

        for name, artifact, message in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                base, _ = initialize_repository(root)
                write_artifact(root, artifact)
                git(root, "add", "--", artifact.as_posix())
                head = signed_commit(root, message)

                issues = "\n".join(validate_with_trusted_signature(root, base, head))

            self.assertIn("malformed v2 run path", issues)

    def test_non_fast_forward_range_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, main_branch = initialize_repository(root)
            git(root, "switch", "--quiet", "-c", "side")
            (root / "side.txt").write_text("side\n", encoding="utf-8")
            git(root, "add", "side.txt")
            side_head = commit(root, "Side history")

            git(root, "switch", "--quiet", "-c", "other", base)
            (root / "other.txt").write_text("other\n", encoding="utf-8")
            git(root, "add", "other.txt")
            other_head = commit(root, "Other history")
            self.assertNotEqual(main_branch, "")

            issues = MODULE.validate_append_only_range(root, side_head, other_head)

        self.assertEqual(
            issues, ["range: head is not a fast-forward descendant of base"]
        )

    def test_merge_ambiguity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, main_branch = initialize_repository(root)
            git(root, "switch", "--quiet", "-c", "feature")
            (root / "feature.txt").write_text("feature\n", encoding="utf-8")
            git(root, "add", "feature.txt")
            commit(root, "Feature history")

            git(root, "switch", "--quiet", main_branch)
            (root / "main.txt").write_text("main\n", encoding="utf-8")
            git(root, "add", "main.txt")
            commit(root, "Main history")
            git(
                root,
                "merge",
                "--quiet",
                "--no-ff",
                "--no-gpg-sign",
                "feature",
                "-m",
                "Merge feature history",
                env=commit_environment(),
            )
            head = git(root, "rev-parse", "HEAD").decode("ascii").strip()

            issues = MODULE.validate_append_only_range(root, base, head)

        self.assertEqual(
            issues, ["range: commit graph is not a bounded linear ancestry path"]
        )

    def test_unsafe_metadata_near_limit_deep_and_wide_blobs_are_not_parsed(
        self,
    ) -> None:
        for shape in ("deep", "wide"):
            with self.subTest(shape=shape), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                base, _ = initialize_repository(root)
                artifact, semantic_bytes = write_near_semantic_limit_run(root, shape)
                git(root, "add", "--", artifact.parent.as_posix())
                head = commit(
                    root,
                    publication_message(artifact),
                    email="not-an-email",
                )

                with (
                    mock.patch.object(
                        MODULE,
                        "_batch_blob_contents",
                        side_effect=AssertionError("semantic blobs were read"),
                    ) as blob_reader,
                    mock.patch.object(
                        MODULE.json,
                        "loads",
                        side_effect=AssertionError("semantic JSON was decoded"),
                    ) as decoder,
                ):
                    issues = MODULE.validate_append_only_range(root, base, head)

            self.assertLess(semantic_bytes, MODULE.MAX_SEMANTIC_BUNDLE_BYTES)
            self.assertLessEqual(
                MODULE.MAX_SEMANTIC_BUNDLE_BYTES - semantic_bytes,
                2048,
            )
            self.assertIn("commit 1: v2 publication commit metadata is unsafe", issues)
            blob_reader.assert_not_called()
            decoder.assert_not_called()

    def test_signed_over_budget_manifest_is_rejected_before_json_decode(self) -> None:
        prefix = b'{"run_id":"' + RUN_ID.encode("ascii") + b'","value":'
        suffix = b"}"
        row = b"[" + b"0," * 199 + b"0]"
        node_rows = MODULE.MAX_SEMANTIC_JSON_NODES // 200 + 1
        cases = {
            "depth": (
                prefix
                + b"[" * (MODULE.MAX_SEMANTIC_JSON_DEPTH + 1)
                + b"0"
                + b"]" * (MODULE.MAX_SEMANTIC_JSON_DEPTH + 1)
                + suffix
            ),
            "nodes": prefix + b"[" + b",".join([row] * node_rows) + b"]" + suffix,
            "width": (
                prefix
                + b"["
                + b"0," * MODULE.MAX_SEMANTIC_JSON_CONTAINER_ITEMS
                + b"0]"
                + suffix
            ),
            "string": (
                prefix
                + b'"'
                + b"x" * (MODULE.MAX_SEMANTIC_JSON_STRING_BYTES + 1)
                + b'"'
                + suffix
            ),
            "scalar": (
                prefix + b"1" * (MODULE.MAX_SEMANTIC_JSON_SCALAR_BYTES + 1) + suffix
            ),
        }

        for budget, manifest in cases.items():
            with self.subTest(budget=budget), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                base, _ = initialize_repository(root)
                artifact = write_run(root, contents={"manifest.json": manifest + b"\n"})
                git(root, "add", "--", artifact.parent.as_posix())
                head = signed_commit(root, publication_message(artifact))

                with (
                    mock.patch.object(
                        MODULE, "_verify_commit_signature", return_value=True
                    ),
                    mock.patch.object(
                        MODULE.json,
                        "loads",
                        side_effect=AssertionError("over-budget JSON was decoded"),
                    ) as decoder,
                ):
                    issues = MODULE.validate_append_only_range(root, base, head)

            self.assertIn(
                "commit 1: bounded publication semantic inspection failed", issues
            )
            decoder.assert_not_called()

    def test_semantic_jsonl_budgets_precede_row_decode(self) -> None:
        oversized_row = b" " * (MODULE.MAX_SEMANTIC_JSONL_ROW_BYTES + 1)
        for budget_name, payload, node_limit in (
            ("row bytes", oversized_row, MODULE.MAX_RANGE_SEMANTIC_NODES),
            ("node count", b"[0]", 1),
        ):
            budget = MODULE._SemanticRangeBudget()
            with (
                self.subTest(budget=budget_name),
                mock.patch.object(MODULE, "MAX_RANGE_SEMANTIC_NODES", node_limit),
                mock.patch.object(
                    MODULE,
                    "_decode_semantic_json",
                    wraps=MODULE._decode_semantic_json,
                ) as decoder,
            ):
                with self.assertRaises(MODULE._SemanticFailure):
                    list(MODULE._semantic_jsonl_values(payload, budget))

            decoder.assert_not_called()

        invalid_budget = MODULE._SemanticRangeBudget()
        self.assertEqual(
            list(MODULE._semantic_jsonl_values(b"}\n{}", invalid_budget)),
            [None, {}],
        )
        self.assertEqual(invalid_budget.nodes_attempted, 3)

    def test_semantic_budget_is_range_global_for_all_attempted_rows(self) -> None:
        contents = {
            "episodes.jsonl": b"}\n{}\n",
            "topics.jsonl": b"{}\n",
        }
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            first_artifact = write_run(root, run_id=RUN_ID, contents=contents)
            git(root, "add", "--", first_artifact.parent.as_posix())
            signed_commit(root, publication_message(first_artifact))

            second_artifact = write_run(root, run_id=SECOND_RUN_ID, contents=contents)
            git(root, "add", "--", second_artifact.parent.as_posix())
            head = signed_commit(root, publication_message(second_artifact))

            first_blobs = semantic_blobs(root, first_artifact)
            second_blobs = semantic_blobs(root, second_artifact)
            expected_bytes = sum(map(len, first_blobs.values())) + sum(
                map(len, second_blobs.values())
            )
            expected_lines = semantic_line_count(first_blobs) + semantic_line_count(
                second_blobs
            )
            snapshots: list[tuple[int, int, int, int]] = []
            original_extract = MODULE._extract_publication_facts

            def capture_budget(
                commit_index: int,
                blobs: dict[str, bytes],
                budget: MODULE._SemanticRangeBudget,
            ) -> MODULE._PublicationFacts:
                facts = original_extract(commit_index, blobs, budget)
                snapshots.append(
                    (
                        id(budget),
                        budget.bytes_attempted,
                        budget.lines_attempted,
                        budget.nodes_attempted,
                    )
                )
                return facts

            with (
                mock.patch.object(
                    MODULE, "_verify_commit_signature", return_value=True
                ),
                mock.patch.object(
                    MODULE, "_strict_validate_publication_bundle", return_value=[]
                ),
                mock.patch.object(
                    MODULE, "_verify_publisher_attestation", return_value=True
                ),
                mock.patch.object(
                    MODULE,
                    "_extract_publication_facts",
                    side_effect=capture_budget,
                ),
            ):
                issues = MODULE.validate_append_only_range(root, base, head)

        self.assertEqual(issues, [])
        self.assertEqual(len(snapshots), 2)
        self.assertEqual(snapshots[0][0], snapshots[1][0])
        self.assertGreaterEqual(snapshots[1][1], expected_bytes)
        self.assertGreaterEqual(snapshots[1][2], expected_lines)
        self.assertEqual(snapshots[1][3], snapshots[0][3] * 2)
        self.assertGreater(snapshots[0][3], semantic_line_count(first_blobs))

    def test_semantic_budget_exhaustion_stops_later_git_and_blob_work(
        self,
    ) -> None:
        contents = {
            "episodes.jsonl": b"}\n{}\n",
            "topics.jsonl": b"{}\n",
        }
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            heads = []
            for run_id in (RUN_ID, SECOND_RUN_ID, THIRD_RUN_ID):
                artifact = write_run(root, run_id=run_id, contents=contents)
                git(root, "add", "--", artifact.parent.as_posix())
                heads.append(signed_commit(root, publication_message(artifact)))
            head = heads[-1]

            snapshots: list[tuple[int, int, int]] = []
            original_extract = MODULE._extract_publication_facts

            def capture_first_budget(
                commit_index: int,
                blobs: dict[str, bytes],
                budget: MODULE._SemanticRangeBudget,
            ) -> MODULE._PublicationFacts:
                facts = original_extract(commit_index, blobs, budget)
                snapshots.append(
                    (
                        budget.bytes_attempted,
                        budget.lines_attempted,
                        budget.nodes_attempted,
                    )
                )
                return facts

            with (
                mock.patch.object(
                    MODULE, "_verify_commit_signature", return_value=True
                ),
                mock.patch.object(
                    MODULE, "_strict_validate_publication_bundle", return_value=[]
                ),
                mock.patch.object(
                    MODULE, "_verify_publisher_attestation", return_value=True
                ),
                mock.patch.object(
                    MODULE,
                    "_extract_publication_facts",
                    side_effect=capture_first_budget,
                ),
            ):
                probe_issues = MODULE.validate_append_only_range(root, base, heads[0])
            self.assertEqual(probe_issues, [])
            self.assertEqual(len(snapshots), 1)
            first_bytes, first_lines, first_nodes = snapshots[0]

            for budget_name, constant_name, limit, expected_blob_calls in (
                ("bytes", "MAX_RANGE_SEMANTIC_BYTES", first_bytes, 1),
                ("lines", "MAX_RANGE_SEMANTIC_LINES", first_lines, 2),
                ("nodes", "MAX_RANGE_SEMANTIC_NODES", first_nodes, 2),
            ):
                with (
                    self.subTest(budget=budget_name),
                    mock.patch.object(MODULE, constant_name, limit),
                    mock.patch.object(
                        MODULE, "_verify_commit_signature", return_value=True
                    ),
                    mock.patch.object(
                        MODULE, "_strict_validate_publication_bundle", return_value=[]
                    ),
                    mock.patch.object(
                        MODULE, "_verify_publisher_attestation", return_value=True
                    ),
                    mock.patch.object(
                        MODULE,
                        "_batch_blob_contents",
                        wraps=MODULE._batch_blob_contents,
                    ) as blob_reader,
                    mock.patch.object(
                        MODULE, "_run_git", wraps=MODULE._run_git
                    ) as git_runner,
                ):
                    issues = MODULE.validate_append_only_range(root, base, head)

                diff_calls = sum(
                    call.args[1][0] == "diff-tree"
                    for call in git_runner.call_args_list
                    if len(call.args) > 1 and call.args[1]
                )
                self.assertEqual(
                    issues,
                    ["commit 2: bounded publication semantic inspection failed"],
                )
                self.assertEqual(blob_reader.call_count, expected_blob_calls)
                self.assertEqual(diff_calls, 2)

    def test_github_signed_admin_metadata_requires_final_squash_route(self) -> None:
        author_identity = (
            b"Joey Teng <12524680+JoeyTeng@users.noreply.github.com> "
            + str(COMMIT_TIMESTAMP + 17).encode("ascii")
            + b" -0700"
        )
        committer_identity = (
            b"GitHub <noreply@github.com> "
            + str(COMMIT_TIMESTAMP + 29).encode("ascii")
            + b" +0000"
        )
        cases = (
            (
                False,
                "Administer session retrospective history v2: update policy",
            ),
            (True, MODULE.V2_ADMIN_BOOTSTRAP_MESSAGE.decode("ascii").rstrip("\n")),
        )
        for bootstrap, message in cases:
            with (
                self.subTest(bootstrap=bootstrap),
                tempfile.TemporaryDirectory() as raw,
            ):
                root = Path(raw)
                base, _ = initialize_repository(root)
                (root / "README.md").write_text(
                    "GitHub-administered policy\n",
                    encoding="utf-8",
                )
                git(root, "add", "README.md")
                head = signed_commit(
                    root,
                    message,
                    author_identity=author_identity,
                    committer_identity=committer_identity,
                )

                with mock.patch.object(
                    MODULE,
                    "_verify_commit_signature",
                    return_value=True,
                ) as verifier:
                    candidate_valid = MODULE._validate_admin_commit_metadata(
                        root,
                        head.encode("ascii"),
                        base.encode("ascii"),
                        bootstrap=bootstrap,
                    )
                    final_valid = MODULE._validate_admin_commit_metadata(
                        root,
                        head.encode("ascii"),
                        base.encode("ascii"),
                        bootstrap=bootstrap,
                        allow_github_final_squash=True,
                    )

            self.assertFalse(candidate_valid)
            self.assertTrue(final_valid)
            self.assertEqual(verifier.call_count, 1)
            self.assertEqual(
                verifier.call_args.args[2],
                MODULE.V2_ADMIN_GITHUB_SIGNING_FINGERPRINTS,
            )

    def test_admin_metadata_rejects_crossed_identity_and_signer_fingerprints(
        self,
    ) -> None:
        github_author = (
            b"Joey Teng <12524680+JoeyTeng@users.noreply.github.com> "
            + str(COMMIT_TIMESTAMP + 17).encode("ascii")
            + b" -0700"
        )
        github_committer = (
            b"GitHub <noreply@github.com> "
            + str(COMMIT_TIMESTAMP + 29).encode("ascii")
            + b" +0000"
        )
        cases = (
            (
                "maintainer_metadata_github_signer",
                None,
                None,
                next(iter(MODULE.V2_ADMIN_GITHUB_SIGNING_FINGERPRINTS)),
                MODULE.V2_ADMIN_MAINTAINER_SIGNING_FINGERPRINTS,
            ),
            (
                "github_metadata_maintainer_signer",
                github_author,
                github_committer,
                next(iter(MODULE.V2_ADMIN_MAINTAINER_SIGNING_FINGERPRINTS)),
                MODULE.V2_ADMIN_GITHUB_SIGNING_FINGERPRINTS,
            ),
        )
        for (
            label,
            author_identity,
            committer_identity,
            signer_fingerprint,
            expected_fingerprints,
        ) in cases:
            for bootstrap in (False, True):
                with (
                    self.subTest(label=label, bootstrap=bootstrap),
                    tempfile.TemporaryDirectory() as raw,
                ):
                    root = Path(raw)
                    base, _ = initialize_repository(root)
                    (root / "README.md").write_text(
                        "Administered policy\n",
                        encoding="utf-8",
                    )
                    git(root, "add", "README.md")
                    message = (
                        MODULE.V2_ADMIN_BOOTSTRAP_MESSAGE.decode("ascii").rstrip("\n")
                        if bootstrap
                        else "Administer session retrospective history v2: update policy"
                    )
                    head = signed_commit(
                        root,
                        message,
                        name=ADMIN_NAME,
                        email=ADMIN_EMAIL,
                        author_identity=author_identity,
                        committer_identity=committer_identity,
                    )

                    def verify(
                        _root: Path,
                        _commit_oid: bytes,
                        allowed_fingerprints: frozenset[bytes] | None = None,
                    ) -> bool:
                        return (
                            allowed_fingerprints is not None
                            and signer_fingerprint in allowed_fingerprints
                        )

                    with mock.patch.object(
                        MODULE,
                        "_verify_commit_signature",
                        side_effect=verify,
                    ) as verifier:
                        valid = MODULE._validate_admin_commit_metadata(
                            root,
                            head.encode("ascii"),
                            base.encode("ascii"),
                            bootstrap=bootstrap,
                            allow_github_final_squash=(committer_identity is not None),
                        )

                self.assertFalse(valid)
                self.assertEqual(verifier.call_args.args[2], expected_fingerprints)

    def test_unsigned_publication_commit_can_use_detached_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            artifact = write_run(root)
            git(root, "add", "--", artifact.parent.as_posix())
            head = commit(root, publication_message(artifact))

            issues = validate_with_trusted_signature(root, base, head)

        self.assertEqual(issues, [])

    def test_publication_requires_valid_detached_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            artifact = write_run(root)
            git(root, "add", "--", artifact.parent.as_posix())
            head = commit(root, publication_message(artifact))

            with mock.patch.object(
                MODULE,
                "_strict_validate_publication_bundle",
                return_value=[],
            ):
                issues = MODULE.validate_append_only_range(root, base, head)

        self.assertEqual(issues, ["commit 1: publisher attestation is invalid"])

    def test_publisher_attestation_binds_run_digest_and_declared_signer(
        self,
    ) -> None:
        run_ref = "run_ref_v2:" + RUN_ID
        bundle_digest = "retained_bundle_digest_v2:sha256:" + "a" * 64
        signer = next(iter(MODULE.V2_SIGNING_FINGERPRINTS))
        signature = FAKE_GPG_SIGNATURE.decode("ascii")
        manifest = {
            "run_ref": run_ref,
            "retained_bundle_digest_v2": bundle_digest,
            "publisher_attestation": {
                "scheme": "openpgp-detached-v1",
                "signer_fingerprint": signer.decode("ascii"),
                "signature": signature,
            },
        }
        blobs = {
            "manifest.json": json.dumps(
                manifest,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        }

        with mock.patch.object(
            MODULE,
            "_verify_detached_openpgp_signature",
            return_value=True,
        ) as verifier:
            self.assertTrue(MODULE._verify_publisher_attestation(blobs))

        verifier.assert_called_once_with(
            FAKE_GPG_SIGNATURE,
            MODULE.publisher_attestation_payload(run_ref, bundle_digest),
            signer,
        )

    def test_publisher_attestation_rejects_unbound_armor_bytes(self) -> None:
        signer = next(iter(MODULE.V2_SIGNING_FINGERPRINTS))
        self.assertEqual(
            MODULE.canonical_openpgp_detached_signature(
                FAKE_GPG_SIGNATURE,
                signer.decode("ascii"),
            ),
            FAKE_GPG_SIGNATURE,
        )
        noncanonical = FAKE_GPG_SIGNATURE.replace(
            b"\n\n",
            b"\nComment: retained-header-leak\n\n",
            1,
        )
        with mock.patch.object(MODULE, "_run_process_bounded") as verifier:
            self.assertFalse(
                MODULE._verify_detached_openpgp_signature(
                    noncanonical,
                    b"payload",
                    signer,
                )
            )
        verifier.assert_not_called()

        bad_checksum = FAKE_GPG_SIGNATURE.replace(b"=pLXK", b"=AAAA")
        with mock.patch.object(MODULE, "_run_process_bounded") as verifier:
            self.assertFalse(
                MODULE._verify_detached_openpgp_signature(
                    bad_checksum,
                    b"payload",
                    signer,
                )
            )
        verifier.assert_not_called()

    def test_malformed_gpgsig_is_rejected_before_verification(self) -> None:
        malformed_signature = (
            b"-----BEGIN PGP SIGNATURE-----\n\n"
            b"not-valid-base64*\n"
            b"-----END PGP SIGNATURE-----"
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            artifact = write_run(root)
            git(root, "add", "--", artifact.parent.as_posix())
            head = signed_commit(
                root,
                publication_message(artifact),
                signature=malformed_signature,
            )

            with mock.patch.object(
                MODULE, "_verify_commit_signature", return_value=True
            ) as verifier:
                issues = "\n".join(MODULE.validate_append_only_range(root, base, head))

        self.assertIn("publication commit metadata is unsafe", issues)
        verifier.assert_not_called()

    def test_commit_signature_is_not_publisher_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            artifact = write_run(root)
            git(root, "add", "--", artifact.parent.as_posix())
            head = signed_commit(root, publication_message(artifact))

            with mock.patch.object(
                MODULE, "_verify_commit_signature", return_value=False
            ) as commit_verifier:
                issues = validate_with_trusted_signature(root, base, head)

        self.assertEqual(issues, [])
        commit_verifier.assert_not_called()

    def test_ephemeral_gpg_key_passes_detached_attestation_verification(self) -> None:
        gpg = shutil.which("gpg")
        if gpg is None:
            self.skipTest("gpg is unavailable")
        gpgconf = shutil.which("gpgconf")
        self.assertIsNotNone(gpgconf)
        assert gpgconf is not None

        with tempfile.TemporaryDirectory() as raw:
            temporary_root = Path(raw)
            gnupg_home = temporary_root / "gnupg"
            gnupg_home.mkdir(mode=0o700)
            try:
                try:
                    command(
                        gpg,
                        "--batch",
                        "--homedir",
                        str(gnupg_home),
                        "--pinentry-mode",
                        "loopback",
                        "--passphrase",
                        "",
                        "--quick-generate-key",
                        "Retrospective V2 Test <retrospective-v2-test@example.invalid>",
                        "ed25519",
                        "sign",
                        "0",
                    )
                except AssertionError as exc:
                    self.skipTest(f"gpg agent is unavailable: {exc}")
                listing = command(
                    gpg,
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

                run_ref = "run_ref_v2:" + RUN_ID
                bundle_digest = "retained_bundle_digest_v2:sha256:" + "a" * 64
                payload_path = temporary_root / "publisher-attestation.bin"
                signature_path = temporary_root / "publisher-signature.asc"
                payload_path.write_bytes(
                    MODULE.publisher_attestation_payload(run_ref, bundle_digest)
                )
                command(
                    gpg,
                    "--batch",
                    "--homedir",
                    str(gnupg_home),
                    "--armor",
                    "--local-user",
                    fingerprint.decode("ascii"),
                    "--output",
                    str(signature_path),
                    "--detach-sign",
                    str(payload_path),
                )
                manifest = {
                    "run_id": RUN_ID,
                    "run_ref": run_ref,
                    "retained_bundle_digest_v2": bundle_digest,
                    "publisher_attestation": {
                        "scheme": "openpgp-detached-v1",
                        "signer_fingerprint": fingerprint.decode("ascii"),
                        "signature": signature_path.read_text(encoding="ascii").rstrip(
                            "\n"
                        ),
                    },
                }

                root = temporary_root / "repository"
                root.mkdir()
                base, _ = initialize_repository(root)
                artifact = write_run(
                    root,
                    contents={
                        "manifest.json": json.dumps(
                            manifest,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                        + b"\n"
                    },
                )
                git(root, "add", "--", artifact.parent.as_posix())
                head = commit(
                    root,
                    publication_message(artifact),
                    name="GitHub",
                    email="noreply@github.com",
                )

                with (
                    mock.patch.dict(
                        os.environ, {"GNUPGHOME": str(gnupg_home)}, clear=False
                    ),
                    mock.patch.object(
                        MODULE,
                        "V2_SIGNING_FINGERPRINTS",
                        frozenset({fingerprint}),
                    ),
                    mock.patch.object(
                        MODULE,
                        "_strict_validate_publication_bundle",
                        return_value=[],
                    ),
                ):
                    encoded_manifest = (
                        json.dumps(
                            manifest,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                        + b"\n"
                    )
                    self.assertTrue(
                        MODULE._verify_publisher_attestation(
                            {"manifest.json": encoded_manifest}
                        )
                    )
                    tampered_manifest = json.loads(encoded_manifest)
                    tampered_manifest["retained_bundle_digest_v2"] = (
                        "retained_bundle_digest_v2:sha256:" + "b" * 64
                    )
                    self.assertFalse(
                        MODULE._verify_publisher_attestation(
                            {
                                "manifest.json": json.dumps(
                                    tampered_manifest,
                                    sort_keys=True,
                                    separators=(",", ":"),
                                ).encode("utf-8")
                                + b"\n"
                            }
                        )
                    )
                    issues = MODULE.validate_append_only_range(root, base, head)
            finally:
                command(
                    gpgconf,
                    "--homedir",
                    str(gnupg_home),
                    "--kill",
                    "gpg-agent",
                )

        self.assertEqual(issues, [])

    def test_validsig_status_requires_allowlisted_fingerprint(self) -> None:
        self.assertEqual(
            MODULE.V2_SIGNING_FINGERPRINTS,
            frozenset({b"40FA5D05AC7A3D5C180B037FF6DCF7A06FFC9C52"}),
        )
        allowed_fingerprint = next(iter(MODULE.V2_SIGNING_FINGERPRINTS))
        disallowed_fingerprint = b"0" * 40

        self.assertTrue(
            MODULE._validsig_matches_allowlist(validsig_status(allowed_fingerprint))
        )
        self.assertFalse(
            MODULE._validsig_matches_allowlist(validsig_status(disallowed_fingerprint))
        )
        self.assertFalse(
            MODULE._validsig_matches_allowlist(
                validsig_status(
                    disallowed_fingerprint,
                    primary_fingerprint=allowed_fingerprint,
                )
            )
        )

    def test_publication_commit_identity_is_not_publisher_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            artifact = write_run(root)
            git(root, "add", "--", artifact.parent.as_posix())
            unexpected_email = fixture_text(
                "other-publisher@", "users.noreply.github.com"
            )
            head = signed_commit(
                root, publication_message(artifact), email=unexpected_email
            )

            issues = validate_with_trusted_signature(root, base, head)

        self.assertEqual(issues, [])


if __name__ == "__main__":
    unittest.main()
