from __future__ import annotations

import base64
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
PUBLISHER_EMAIL = "codex-session-retrospective@users.noreply.github.com"
RUN_ID = "0" * 63 + "1"
SECOND_RUN_ID = "0" * 63 + "2"
THIRD_RUN_ID = "0" * 63 + "3"
COMMIT_TIMESTAMP = 1_800_000_000
FAKE_GPG_SIGNATURE = (
    b"-----BEGIN PGP SIGNATURE-----\n\n"
    + base64.b64encode(b"\x89fake-signature-packet")
    + b"\n-----END PGP SIGNATURE-----"
)


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


def commit_environment(*, email: str = PUBLISHER_EMAIL) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": PUBLISHER_NAME,
            "GIT_AUTHOR_EMAIL": email,
            "GIT_AUTHOR_DATE": f"@{COMMIT_TIMESTAMP} +0000",
            "GIT_COMMITTER_NAME": PUBLISHER_NAME,
            "GIT_COMMITTER_EMAIL": email,
            "GIT_COMMITTER_DATE": f"@{COMMIT_TIMESTAMP} +0000",
        }
    )
    return environment


def commit(root: Path, message: str, *, email: str = PUBLISHER_EMAIL) -> str:
    git(
        root,
        "commit",
        "--quiet",
        "--no-gpg-sign",
        "-m",
        message,
        env=commit_environment(email=email),
    )
    return git(root, "rev-parse", "HEAD").decode("ascii").strip()


def signed_commit(
    root: Path,
    message: str,
    *,
    email: str = PUBLISHER_EMAIL,
    signature: bytes = FAKE_GPG_SIGNATURE,
) -> str:
    tree_oid = git(root, "write-tree").strip()
    parent_oid = git(root, "rev-parse", "HEAD").strip()
    identity = f"{PUBLISHER_NAME} <{email}> {COMMIT_TIMESTAMP} +0000".encode("ascii")
    gpgsig_header = b"gpgsig " + signature.replace(b"\n", b"\n ")
    raw_commit = (
        b"\n".join(
            (
                b"tree " + tree_oid,
                b"parent " + parent_oid,
                b"author " + identity,
                b"committer " + identity,
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


def initialize_repository(root: Path) -> tuple[str, str]:
    git(root, "init", "--quiet")
    git(root, "config", "user.name", PUBLISHER_NAME)
    git(root, "config", "user.email", PUBLISHER_EMAIL)
    (root / "README.md").write_text("history fixture\n", encoding="utf-8")
    git(root, "add", "README.md")
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


def validate_with_trusted_signature(root: Path, base: str, head: str) -> list[str]:
    with mock.patch.object(MODULE, "_verify_commit_signature", return_value=True):
        return MODULE.validate_append_only_range(root, base, head)


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


class RetrospectiveHistoryGitV2Tests(unittest.TestCase):
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

            self.assertEqual(MODULE.validate_append_only_range(root, base, head), [])

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
            artifact = write_run(
                root,
                contents={"episodes.jsonl": b"x" * (8 * 1024 * 1024 + 1)},
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

    def test_unsigned_publication_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            artifact = write_run(root)
            git(root, "add", "--", artifact.parent.as_posix())
            head = commit(root, publication_message(artifact))

            issues = "\n".join(MODULE.validate_append_only_range(root, base, head))

        self.assertIn("publication commit metadata is unsafe", issues)

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

    def test_structural_gpgsig_failing_git_verifier_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            artifact = write_run(root)
            git(root, "add", "--", artifact.parent.as_posix())
            head = signed_commit(root, publication_message(artifact))

            issues = "\n".join(MODULE.validate_append_only_range(root, base, head))

        self.assertIn("publication commit metadata is unsafe", issues)

    def test_ephemeral_gpg_key_passes_actual_git_verification(self) -> None:
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
                    "rsa2048",
                    "sign",
                    "0",
                )
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

                root = temporary_root / "repository"
                root.mkdir()
                base, _ = initialize_repository(root)
                artifact = write_run(root)
                git(root, "add", "--", artifact.parent.as_posix())
                git(root, "config", "gpg.program", gpg)
                signing_environment = commit_environment()
                signing_environment["GNUPGHOME"] = str(gnupg_home)
                git(
                    root,
                    "commit",
                    "--quiet",
                    f"-S{fingerprint.decode('ascii')}",
                    "-m",
                    publication_message(artifact),
                    env=signing_environment,
                )
                head = git(root, "rev-parse", "HEAD").decode("ascii").strip()

                with (
                    mock.patch.dict(
                        os.environ, {"GNUPGHOME": str(gnupg_home)}, clear=False
                    ),
                    mock.patch.object(
                        MODULE,
                        "V2_SIGNING_FINGERPRINTS",
                        frozenset({fingerprint}),
                    ),
                ):
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

    def test_unsafe_publication_metadata_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _ = initialize_repository(root)
            artifact = write_run(root)
            git(root, "add", "--", artifact.parent.as_posix())
            unexpected_email = "other-publisher@" + "users.noreply.github.com"
            head = signed_commit(
                root, publication_message(artifact), email=unexpected_email
            )

            issues = "\n".join(validate_with_trusted_signature(root, base, head))

        self.assertIn("publication commit metadata is unsafe", issues)
        self.assertNotIn(unexpected_email, issues)


if __name__ == "__main__":
    unittest.main()
