from __future__ import annotations

import base64
import contextlib
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/session-retrospective-v2-bootstrap.yml"
PERMANENT_CI = ROOT / ".github/bootstrap/session-retrospective-v2-permanent-ci.yml"
VALIDATOR = ROOT / "scripts/validate_retained_history.py"
CI_HELPER = ROOT / "scripts/trusted_history_ci.py"
EXPECTED_WORKFLOW_POLICY_SHA256 = (
    "177e02a02952b41a438a94f73af95c46aee1b4640a32e95e306e20ae559a6100"
)
CLOSED_GIT_WORKFLOW_ENV = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES": "",
    "GIT_CONFIG_COUNT": "0",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_LITERAL_PATHSPECS": "1",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
}
FIXTURE_TIMESTAMP = 1_784_073_600
FIXTURE_SIGNER_FINGERPRINT = "0123456789ABCDEF0123456789ABCDEF01234567"
ACTUAL_BASE_SHA = "97f236c56cbbf24776899178175e2603ecf30fb0"
LEGACY_CI = (
    "name: CI\n"
    "\n"
    "on:\n"
    "  pull_request:\n"
    "  push:\n"
    "    branches: [master]\n"
    "\n"
    "jobs:\n"
    "  test:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: actions/checkout@v4\n"
    "      - uses: actions/setup-python@v5\n"
    "        with:\n"
    '          python-version: "3.12"\n'
    "      - name: Validate JSON syntax\n"
    "        run: |\n"
    "          python -m json.tool schemas/session-retrospective-v1.schema.json >/dev/null\n"
    "          python -m json.tool schemas/retained-manifest-v1.schema.json >/dev/null\n"
    "      - name: Run tests\n"
    "        run: python -m unittest discover -s tests\n"
    "      - name: Validate retained history tree\n"
    "        run: python scripts/validate_retained_history.py --root .\n"
)


def load_module(name: str, path: Path) -> object:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def linux_process_state(pid: int) -> str:
    raw = Path(f"/proc/{pid}/stat").read_bytes()
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AssertionError("Linux process state is not ASCII") from exc
    command_end = value.rfind(") ")
    if command_end < 0 or len(value) <= command_end + 2:
        raise AssertionError("Linux process state is malformed")
    state = value[command_end + 2 : command_end + 3]
    if len(state) != 1 or not state.isalpha():
        raise AssertionError("Linux process state is malformed")
    return state


def process_is_executing_for_test(pid: int) -> bool:
    if sys.platform.startswith("linux"):
        try:
            state = linux_process_state(pid)
        except FileNotFoundError:
            return False
        return state not in {"X", "Z", "x"}
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


VALIDATOR_MODULE = load_module("bootstrap_workflow_validator", VALIDATOR)
CI_MODULE = load_module("trusted_history_ci", CI_HELPER)


def load_workflow(path: Path = WORKFLOW) -> dict:
    return VALIDATOR_MODULE.parse_strict_workflow_yaml(path.read_text(encoding="utf-8"))


def workflow_job() -> dict:
    return load_workflow()["jobs"]["trusted_history_gate"]


def steps_by_name(job: dict | None = None) -> dict[str, dict]:
    steps = (job or workflow_job())["steps"]
    named = {step["name"]: step for step in steps}
    if len(named) != len(steps):
        raise AssertionError("workflow step names must be unique")
    return named


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        env={
            **os.environ,
            "TZ": "UTC",
            "GIT_AUTHOR_DATE": f"{FIXTURE_TIMESTAMP} +0000",
            "GIT_COMMITTER_DATE": f"{FIXTURE_TIMESTAMP} +0000",
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def configure_git(root: Path) -> None:
    git(root, "config", "commit.gpgsign", "false")
    git(root, "config", "tag.gpgsign", "false")
    name, email = VALIDATOR_MODULE.HISTORY_V2_CANONICAL_IDENTITY.rsplit(" <", 1)
    git(root, "config", "user.name", name)
    git(root, "config", "user.email", email.removesuffix(">"))


def fixture_signature_armor(
    *,
    timestamp: int = FIXTURE_TIMESTAMP,
    signer_fingerprint: str = FIXTURE_SIGNER_FINGERPRINT,
) -> bytes:
    fingerprint = bytes.fromhex(signer_fingerprint)
    hashed = b"\x05\x02" + timestamp.to_bytes(4, "big") + b"\x16\x21\x04" + fingerprint
    unhashed = b"\x09\x10" + fingerprint[-8:]
    mpi = bytes((0, 1, 1))
    body = (
        bytes(
            (
                4,
                0,
                22,
                VALIDATOR_MODULE.HISTORY_V2_SIGNATURE_HASH_ALGORITHM,
            )
        )
        + len(hashed).to_bytes(2, "big")
        + hashed
        + len(unhashed).to_bytes(2, "big")
        + unhashed
        + bytes((0, 0))
        + mpi
        + mpi
    )
    packet = VALIDATOR_MODULE.encode_history_v2_signature_packet(body)
    encoded = base64.b64encode(packet).decode("ascii")
    checksum = base64.b64encode(VALIDATOR_MODULE.bootstrap_v2_crc24(packet)).decode(
        "ascii"
    )
    return (
        "-----BEGIN PGP SIGNATURE-----\n"
        "\n"
        + "\n".join(encoded[index : index + 64] for index in range(0, len(encoded), 64))
        + "\n="
        + checksum
        + "\n-----END PGP SIGNATURE-----\n"
    ).encode("ascii")


def fixture_raw_commit(
    root: Path,
    *,
    tree_oid: str,
    parents: tuple[str, ...],
    message: str,
    author: str = VALIDATOR_MODULE.HISTORY_V2_CANONICAL_IDENTITY,
    committer: str = VALIDATOR_MODULE.HISTORY_V2_CANONICAL_IDENTITY,
    author_timestamp: int = FIXTURE_TIMESTAMP,
    committer_timestamp: int = FIXTURE_TIMESTAMP,
    author_timezone: str = "+0000",
    committer_timezone: str = "+0000",
    extra_headers: tuple[bytes, ...] = (),
    signature_armor: bytes | None = None,
    include_signature: bool = True,
    message_trailing_newline: bool = True,
    signature_trailing_blank_continuation: bool = False,
) -> str:
    armor = signature_armor or fixture_signature_armor(timestamp=committer_timestamp)
    armor_lines = armor.removesuffix(b"\n").split(b"\n")
    signature_headers = (
        b"gpgsig " + armor_lines[0],
        *(b" " + line for line in armor_lines[1:]),
    )
    headers = (
        f"tree {tree_oid}".encode("ascii"),
        *(f"parent {parent}".encode("ascii") for parent in parents),
        f"author {author} {author_timestamp} {author_timezone}".encode("utf-8"),
        (f"committer {committer} {committer_timestamp} {committer_timezone}").encode(
            "utf-8"
        ),
        *extra_headers,
        *(
            (
                *signature_headers,
                *((b" ",) if signature_trailing_blank_continuation else ()),
            )
            if include_signature
            else ()
        ),
    )
    raw_commit = b"\n".join(headers) + b"\n\n" + message.encode("utf-8")
    if message_trailing_newline:
        raw_commit += b"\n"
    result = subprocess.run(
        ["git", "-C", str(root), "hash-object", "-t", "commit", "-w", "--stdin"],
        env={
            **os.environ,
            "TZ": "UTC",
            "GIT_AUTHOR_DATE": f"{FIXTURE_TIMESTAMP} +0000",
            "GIT_COMMITTER_DATE": f"{FIXTURE_TIMESTAMP} +0000",
        },
        input=raw_commit,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return result.stdout.decode("ascii").strip()


def fixture_commit_bytes(root: Path, commit_oid: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), "cat-file", "commit", commit_oid],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout


def fixture_store_commit(root: Path, raw_commit: bytes) -> str:
    return (
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "hash-object",
                "--literally",
                "-t",
                "commit",
                "-w",
                "--stdin",
            ],
            input=raw_commit,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        .stdout.decode("ascii")
        .strip()
    )


def commit_all(
    root: Path,
    message: str,
    *,
    parents: tuple[str, ...] | None = None,
) -> str:
    git(root, "add", "--all")
    tree_oid = git(root, "write-tree")
    if parents is None:
        current = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
            env={
                **os.environ,
                "TZ": "UTC",
                "GIT_AUTHOR_DATE": f"{FIXTURE_TIMESTAMP} +0000",
                "GIT_COMMITTER_DATE": f"{FIXTURE_TIMESTAMP} +0000",
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        parents = (current.stdout.strip(),) if current.returncode == 0 else ()
    commit_oid = fixture_raw_commit(
        root,
        tree_oid=tree_oid,
        parents=parents,
        message=message,
    )
    git(root, "update-ref", "HEAD", commit_oid)
    git(root, "reset", "--hard", "--quiet", commit_oid)
    return commit_oid


def tree_api_payload(root: Path, revision: str) -> dict:
    raw = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-tree",
            "-r",
            "-t",
            "-z",
            "--full-tree",
            revision,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout
    entries = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, path = record.split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split()
        entry = {
            "path": path.decode("utf-8"),
            "mode": mode,
            "type": object_type,
            "sha": object_id,
        }
        if object_type == "blob":
            entry["size"] = int(git(root, "cat-file", "-s", object_id))
        entries.append(entry)
    return {
        "sha": git(root, "rev-parse", f"{revision}^{{tree}}"),
        "truncated": False,
        "tree": entries,
    }


def tree_api_payloads(root: Path, revisions: tuple[str, ...]) -> dict[str, dict]:
    payloads = (tree_api_payload(root, revision) for revision in revisions)
    return {payload["sha"]: payload for payload in payloads}


def blob_api_payload(root: Path, object_id: str) -> dict[str, object]:
    value = subprocess.run(
        ["git", "-C", str(root), "cat-file", "blob", object_id],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout
    encoded = base64.b64encode(value).decode("ascii")
    return {
        "sha": object_id,
        "size": len(value),
        "encoding": "base64",
        "content": "\n".join(
            encoded[index : index + 76] for index in range(0, len(encoded), 76)
        ),
    }


def bare_object_exists_without_lazy_fetch(git_dir: Path, object_id: str) -> bool:
    result = subprocess.run(
        CI_MODULE.closed_git_command(
            f"--git-dir={git_dir}",
            "cat-file",
            "-e",
            object_id,
        ),
        env=CI_MODULE.closed_git_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return result.returncode == 0


def seal_partial_bare_store(git_dir: Path, *, expected_url: str) -> None:
    remotes = subprocess.run(
        CI_MODULE.closed_git_command(
            f"--git-dir={git_dir}",
            "remote",
        ),
        env=CI_MODULE.closed_git_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout.splitlines()
    if len(remotes) == 1:
        observed_url = subprocess.run(
            CI_MODULE.closed_git_command(
                f"--git-dir={git_dir}",
                "remote",
                "get-url",
                remotes[0],
            ),
            env=CI_MODULE.closed_git_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        ).stdout.strip()
        if observed_url != expected_url:
            raise AssertionError(f"unexpected synthetic promisor URL: {observed_url!r}")
        subprocess.run(
            CI_MODULE.closed_git_command(
                f"--git-dir={git_dir}",
                "remote",
                "remove",
                remotes[0],
            ),
            env=CI_MODULE.closed_git_environment(),
            check=True,
        )
    elif remotes:
        raise AssertionError(f"unexpected synthetic promisor remotes: {remotes!r}")
    cleanup = subprocess.run(
        CI_MODULE.closed_git_command(
            f"--git-dir={git_dir}",
            "config",
            "--unset-all",
            "extensions.partialClone",
        ),
        env=CI_MODULE.closed_git_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if cleanup.returncode not in (0, 5):
        raise subprocess.CalledProcessError(
            cleanup.returncode,
            cleanup.args,
            output=cleanup.stdout,
            stderr=cleanup.stderr,
        )


def preflight_complete_fixture(
    git_dir: Path,
    **arguments: object,
) -> object:
    with mock.patch.object(
        CI_MODULE,
        "validate_oid_only_candidate_store",
    ):
        return CI_MODULE.preflight_git_candidate(git_dir, **arguments)


def fetch_synthetic_candidate_store(
    temporary: Path,
    graph: BootstrapGraph,
    *,
    head: str,
    depth: int,
    filtered: bool,
    sealed: bool = True,
) -> Path:
    bare = temporary / "candidate.git"
    subprocess.run(
        ["git", "init", "--bare", "--quiet", str(bare)],
        check=True,
    )
    subprocess.run(
        [
            "git",
            f"--git-dir={bare}",
            "fetch",
            "--quiet",
            "--no-tags",
            "--depth=1",
            graph.root.as_uri(),
            graph.base,
        ],
        check=True,
    )
    command = [
        "git",
        f"--git-dir={bare}",
        "fetch",
        "--quiet",
        "--no-tags",
        f"--depth={depth}",
    ]
    if filtered:
        command.append("--filter=blob:none")
    command.extend(
        (
            graph.root.as_uri(),
            f"+{head}:refs/synthetic/candidate",
        )
    )
    subprocess.run(command, check=True)
    if sealed:
        seal_partial_bare_store(
            bare,
            expected_url=graph.root.as_uri(),
        )
    return bare


class StructuralSignatureVerifier:
    def __init__(self, _public_key: bytes, *, relative: Path) -> None:
        self.relative = relative
        self.verified_signer_fingerprints: set[str] = set()

    def __enter__(self) -> StructuralSignatureVerifier:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def verify(self, signature: object) -> None:
        if not hasattr(signature, "signer_fingerprint"):
            raise AssertionError("commit signature was not structurally validated")
        self.verified_signer_fingerprints.add(signature.signer_fingerprint)


class BootstrapGraph:
    def __init__(self, root: Path) -> None:
        self.root = root
        subprocess.run(
            ["git", "init", "--quiet", str(root)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        configure_git(root)
        self.write(".github/workflows/ci.yml", LEGACY_CI)
        self.write("AGENTS.md", "Synthetic tracked guidance.\n")
        self.write(
            "retrospective-history-v2-admin-public.asc",
            "Synthetic admin public key fixture.\n",
        )
        self.write(
            "retrospective-history-v2-publisher.asc",
            "Synthetic publisher public key fixture.\n",
        )
        self.actual_base = commit_all(root, "actual base")

        self.write(
            ".github/bootstrap/session-retrospective-v2-permanent-ci.yml",
            PERMANENT_CI.read_text(encoding="utf-8"),
        )
        self.write(
            ".github/workflows/session-retrospective-v2-bootstrap.yml",
            WORKFLOW.read_text(encoding="utf-8"),
        )
        self.write(
            "tests/test_session_retrospective_v2_bootstrap.py",
            '"""Synthetic bootstrap test."""\n',
        )
        self.write(
            "scripts/trusted_history_ci.py",
            CI_HELPER.read_text(encoding="utf-8"),
        )
        self.base = commit_all(root, "install bootstrap")

    @property
    def git_dir(self) -> Path:
        return self.root / ".git"

    def write(self, relative: str, value: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")

    def remove_bootstrap(self, *, retain: set[str] | None = None) -> None:
        retain = retain or set()
        for relative in CI_MODULE.BOOTSTRAP_TEMPORARY_PATHS:
            if relative not in retain:
                (self.root / relative).unlink()

    def create_candidate(
        self,
        *,
        retain: set[str] | None = None,
        message: str = "candidate",
    ) -> str:
        self.remove_bootstrap(retain=retain)
        self.write(
            ".github/workflows/ci.yml",
            PERMANENT_CI.read_text(encoding="utf-8"),
        )
        self.write("candidate.txt", "candidate\n")
        return commit_all(self.root, message)

    def preflight(self, head: str, *, base: str | None = None) -> object:
        return preflight_complete_fixture(
            self.git_dir,
            base_sha=base or self.base,
            head_sha=head,
            tree_payload=tree_api_payload(self.root, head),
            policy="bootstrap-v2",
        )


def pull_payload(*, base_sha: str = "b" * 40, head_sha: str = "a" * 40) -> dict:
    return {
        "number": 17,
        "node_id": "PR_kwDO_bootstrap",
        "state": "open",
        "merged": False,
        "merged_at": None,
        "draft": False,
        "base": {
            "ref": "master",
            "sha": base_sha,
            "repo": {
                "full_name": "Joey-Tools/codex-session-retrospective-history",
                "id": TEST_REPOSITORY_ID,
            },
        },
        "head": {
            "ref": "wip/session-retrospective-v2-history-bootstrap",
            "sha": head_sha,
            "repo": {
                "full_name": "Joey-Tools/codex-session-retrospective-history",
                "id": TEST_REPOSITORY_ID,
            },
        },
    }


def validate_pull(payload: dict) -> object:
    return CI_MODULE.validate_pull_request_payload(
        payload,
        repository="Joey-Tools/codex-session-retrospective-history",
        number=17,
        node_id="PR_kwDO_bootstrap",
        base_ref="master",
        base_sha="b" * 40,
        head_repository="Joey-Tools/codex-session-retrospective-history",
        head_ref="wip/session-retrospective-v2-history-bootstrap",
        head_sha="a" * 40,
    )


TEST_REPOSITORY = "Joey-Tools/codex-session-retrospective-history"
TEST_REPOSITORY_ID = 1_246_526_548
TEST_ADMISSION_APP_ID = 424_242


def merge_group_ref(number: int = 17) -> str:
    return f"refs/heads/gh-readonly-queue/master/pr-{number}-synthetic"


def merge_group_event_payload(
    *,
    base_sha: str,
    queue_sha: str,
    number: int = 17,
) -> dict:
    return {
        "action": "checks_requested",
        "repository": {
            "full_name": TEST_REPOSITORY,
            "id": TEST_REPOSITORY_ID,
        },
        "merge_group": {
            "base_ref": "refs/heads/master",
            "base_sha": base_sha,
            "head_ref": merge_group_ref(number),
            "head_sha": queue_sha,
        },
    }


def merge_group_pull_payload(
    *,
    base_sha: str,
    head_sha: str,
    title: str,
    number: int = 17,
) -> dict:
    payload = pull_payload(base_sha=base_sha, head_sha=head_sha)
    payload["number"] = number
    payload["title"] = title
    return payload


def repository_configuration_payload() -> dict:
    return {
        "full_name": TEST_REPOSITORY,
        "id": TEST_REPOSITORY_ID,
        "default_branch": "master",
        "allow_squash_merge": True,
        "allow_merge_commit": False,
        "allow_rebase_merge": False,
        "squash_merge_commit_title": "PR_TITLE",
        "squash_merge_commit_message": "BLANK",
    }


def live_merge_group_ref_payload(*, queue_sha: str, number: int = 17) -> dict:
    return {
        "ref": merge_group_ref(number),
        "object": {
            "type": "commit",
            "sha": queue_sha,
        },
    }


def predecessor_audit_payloads(
    *,
    base_sha: str,
    parent_sha: str,
    candidate_sha: str,
) -> dict[str, dict]:
    run_id = 701
    job_id = 801
    check_run_id = 501
    check_suite_id = 601
    predecessor_number = 16
    node_id = "PR_kwDO_predecessor"
    details_url = (
        f"https://github.com/{TEST_REPOSITORY}/actions/runs/{run_id}/job/{job_id}"
    )
    return {
        "associated": {
            "number": predecessor_number,
            "node_id": node_id,
        },
        "pull": {
            "number": predecessor_number,
            "node_id": node_id,
            "state": "closed",
            "merged": True,
            "merged_at": "2026-07-15T00:00:00Z",
            "draft": False,
            "merge_commit_sha": base_sha,
            "base": {
                "ref": "master",
                "sha": parent_sha,
                "repo": {"full_name": TEST_REPOSITORY},
            },
            "head": {
                "ref": "wip/predecessor",
                "sha": candidate_sha,
                "repo": {"full_name": TEST_REPOSITORY},
            },
        },
        "check": {
            "id": check_run_id,
            "node_id": "CR_kwDO_predecessor",
            "name": CI_MODULE.POST_MERGE_AUDIT_CHECK_CONTEXT,
            "head_sha": base_sha,
            "status": "completed",
            "conclusion": "success",
            "started_at": "2026-07-15T00:02:00Z",
            "completed_at": "2026-07-15T00:04:00Z",
            "details_url": details_url,
            "pull_requests": [],
            "app": {
                "id": CI_MODULE.GITHUB_ACTIONS_APP_ID,
                "slug": CI_MODULE.GITHUB_ACTIONS_APP_SLUG,
            },
            "check_suite": {"id": check_suite_id},
        },
        "run": {
            "id": run_id,
            "workflow_id": 901,
            "name": CI_MODULE.PERMANENT_WORKFLOW_NAME,
            "path": CI_MODULE.PERMANENT_WORKFLOW_PATH,
            "event": "push",
            "head_branch": "master",
            "head_sha": base_sha,
            "status": "completed",
            "conclusion": "success",
            "run_attempt": 1,
            "check_suite_id": check_suite_id,
            "created_at": "2026-07-15T00:01:00Z",
            "run_started_at": "2026-07-15T00:02:00Z",
            "updated_at": "2026-07-15T00:05:00Z",
            "html_url": (f"https://github.com/{TEST_REPOSITORY}/actions/runs/{run_id}"),
            "jobs_url": (
                f"https://api.github.com/repos/{TEST_REPOSITORY}/actions/"
                f"runs/{run_id}/jobs"
            ),
            "repository": {"full_name": TEST_REPOSITORY},
            "head_repository": {"full_name": TEST_REPOSITORY},
        },
        "job": {
            "id": job_id,
            "run_id": run_id,
            "run_attempt": 1,
            "workflow_name": CI_MODULE.PERMANENT_WORKFLOW_NAME,
            "name": CI_MODULE.POST_MERGE_AUDIT_CHECK_CONTEXT,
            "head_sha": base_sha,
            "status": "completed",
            "conclusion": "success",
            "started_at": "2026-07-15T00:02:30Z",
            "completed_at": "2026-07-15T00:03:30Z",
            "html_url": details_url,
            "check_run_url": (
                f"https://api.github.com/repos/{TEST_REPOSITORY}/"
                f"check-runs/{check_run_id}"
            ),
        },
    }


def synthetic_merge_group_projection(
    snapshot: object,
    *,
    policy: str = "history-v2",
    role: str = "publication",
    candidate_tree_sha: str = "1" * 40,
    queue_tree_sha: str = "2" * 40,
) -> object:
    signature_policy = "history-v2" if role == "publication" else "bootstrap-v2"
    signature_key_path = VALIDATOR_MODULE.HISTORY_V2_SIGNATURE_KEY_PATHS[
        signature_policy
    ]
    return CI_MODULE.MergeGroupProjection(
        policy=policy,
        role=role,
        candidate_base_sha=snapshot.base_sha,
        queue_base_sha=snapshot.base_sha,
        candidate_sha=snapshot.candidate_sha,
        queue_sha=snapshot.queue_sha,
        candidate_tree_sha=candidate_tree_sha,
        queue_tree_sha=queue_tree_sha,
        prospective_sha="3" * 40,
        prospective_tree_sha=queue_tree_sha,
        squash_subject="Publish retained history",
        trust_generation="7" * 64,
        changed_path_count=1,
        delta_sha256="4" * 64,
        candidate_signature=CI_MODULE.CandidateSignatureBinding(
            policy=signature_policy,
            key_path=signature_key_path.as_posix(),
            key_sha256=VALIDATOR_MODULE.BOOTSTRAP_V2_PUBLIC_KEY_SHA256[
                signature_key_path
            ],
            signer_fingerprint=FIXTURE_SIGNER_FINGERPRINT,
        ),
    )


def synthetic_predecessor_audit(
    *,
    base_sha: str,
    parent_sha: str,
) -> object:
    values = {
        "base_sha": base_sha,
        "parent_sha": parent_sha,
        "pull_request_number": 16,
        "pull_request_node_id": "PR_kwDO_predecessor",
        "candidate_sha": "d" * 40,
        "merged_at": "2026-07-15T00:00:00Z",
        "check_run_id": 501,
        "check_run_node_id": "CR_kwDO_predecessor",
        "check_suite_id": 601,
        "workflow_run_id": 701,
        "workflow_id": 901,
        "workflow_run_attempt": 1,
        "job_id": 801,
        "workflow_created_at": "2026-07-15T00:01:00Z",
        "workflow_started_at": "2026-07-15T00:02:00Z",
        "workflow_updated_at": "2026-07-15T00:05:00Z",
        "started_at": "2026-07-15T00:02:00Z",
        "completed_at": "2026-07-15T00:04:00Z",
        "job_started_at": "2026-07-15T00:02:30Z",
        "job_completed_at": "2026-07-15T00:03:30Z",
        "sha256": "0" * 64,
    }
    evidence = CI_MODULE.PredecessorAuditEvidence(**values)
    values["sha256"] = hashlib.sha256(
        CI_MODULE.compact_json_bytes(
            CI_MODULE._predecessor_audit_normalized_payload(evidence)
        )
    ).hexdigest()
    return CI_MODULE.PredecessorAuditEvidence(**values)


def synthetic_admission_check_evidence(
    *,
    check_name: str,
    head_sha: str,
    check_run_id: int,
    check_suite_id: int,
    node_id: str,
    started_at: str,
    completed_at: str,
    admission_sha256: str,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": CI_MODULE.DEFAULT_ADMISSION_CHECK_KIND,
        "check_name": check_name,
        "check_run_id": check_run_id,
        "check_run_node_id": node_id,
        "check_suite_id": check_suite_id,
        "head_sha": head_sha,
        "started_at": started_at,
        "completed_at": completed_at,
        "external_id": (
            CI_MODULE.ADMISSION_RECORD_EXTERNAL_ID_PREFIX + admission_sha256
        ),
        "output_title": CI_MODULE.ADMISSION_RECORD_OUTPUT_TITLE,
        "output_summary": (
            CI_MODULE.ADMISSION_RECORD_OUTPUT_SUMMARY_PREFIX + admission_sha256
        ),
        "admission_sha256": admission_sha256,
    }


def synthetic_external_admission(
    *,
    repository: str,
    repository_id: int,
    base_sha: str,
    head_sha: str,
    candidate_sha: str,
    candidate_tree_sha: str,
    queue_tree_sha: str,
    pull_request_number: int,
    pull_request_node_id: str,
    pull_request_title: str,
    admission_app_id: int = TEST_ADMISSION_APP_ID,
) -> dict[str, object]:
    snapshot = CI_MODULE.MergeGroupSnapshot(
        repository=repository,
        repository_id=repository_id,
        base_ref="refs/heads/master",
        base_sha=base_sha,
        queue_ref=merge_group_ref(pull_request_number),
        queue_sha="c" * len(base_sha),
        workflow_sha="c" * len(base_sha),
        pull_request_number=pull_request_number,
        pull_request_node_id=pull_request_node_id,
        pull_request_title=pull_request_title,
        candidate_ref="wip/session-retrospective-v2-history",
        candidate_sha=candidate_sha,
        required_check=CI_MODULE.REQUIRED_CHECK_CONTEXT,
        tcb_sha256="d" * 64,
    )
    projection = synthetic_merge_group_projection(
        snapshot,
        candidate_tree_sha=candidate_tree_sha,
        queue_tree_sha=queue_tree_sha,
    )
    runtime = CI_MODULE.MergeGroupRuntimeEvidence(
        policy="history-v2",
        queue_base_sha=base_sha,
        candidate_sha=candidate_sha,
        queue_sha=snapshot.queue_sha,
        queue_tree_sha=queue_tree_sha,
        prospective_sha=projection.prospective_sha,
        prospective_tree_sha=queue_tree_sha,
        projection_sha256=CI_MODULE.merge_group_projection_sha256(projection),
        python_version=CI_MODULE.QUEUE_RUNTIME_PYTHON_VERSION,
        python_executable_sha256="5" * 64,
        requirements_sha256="6" * 64,
        runtime_profile=CI_MODULE.QUEUE_RUNTIME_PROFILE,
        compile_command_sha256=CI_MODULE.QUEUE_RUNTIME_COMPILE_COMMAND_SHA256,
        test_command_sha256=CI_MODULE.QUEUE_RUNTIME_TEST_COMMAND_SHA256,
        compile_exit_code=0,
        test_exit_code=0,
        authority_uid=501,
        execution_uid=65534,
        credential_environment="empty",
        authority_write_access=False,
        source_authority_pristine=True,
    )
    audit = synthetic_predecessor_audit(
        base_sha=base_sha,
        parent_sha="9" * len(base_sha),
    )
    predecessor = CI_MODULE.MergeGroupPredecessorAuthorityEvidence(
        mode="history-v2-required",
        base_sha=base_sha,
        queue_sha=snapshot.queue_sha,
        pull_request_number=pull_request_number,
        projection_sha256=CI_MODULE.merge_group_projection_sha256(projection),
        parent_sha=audit.parent_sha,
        audit=audit,
        candidate_ref=None,
        bootstrap_markers=(),
        bootstrap_marker_sha256=None,
    )
    observed_at = dt.datetime(2026, 7, 15, 0, 0, tzinfo=dt.timezone.utc)
    live = CI_MODULE.MergeGroupLiveAuthorityEvidence(
        snapshot_sha256=hashlib.sha256(
            CI_MODULE.compact_json_bytes(snapshot.as_dict())
        ).hexdigest(),
        tcb_sha256=snapshot.tcb_sha256,
        predecessor_authority=predecessor,
        predecessor_authority_sha256=hashlib.sha256(
            CI_MODULE.compact_json_bytes(predecessor.as_dict())
        ).hexdigest(),
        observed_at=observed_at.isoformat().replace("+00:00", "Z"),
        valid_until=(observed_at + dt.timedelta(seconds=30))
        .isoformat()
        .replace("+00:00", "Z"),
    )
    admission = CI_MODULE.merge_group_admission_payload(
        snapshot=snapshot,
        projection=projection,
        evidence=runtime,
        live_authority=live,
    )
    admission_sha256 = hashlib.sha256(
        CI_MODULE.compact_json_bytes(admission)
    ).hexdigest()
    merged_at = "2026-07-15T00:00:20Z"
    title_sha256 = hashlib.sha256(pull_request_title.encode("utf-8")).hexdigest()
    node_sha256 = hashlib.sha256(pull_request_node_id.encode("utf-8")).hexdigest()
    candidate_ref = "wip/session-retrospective-v2-history"
    provenance = {
        "authority_mode": "history-v2-admission",
        "base_ref": "master",
        "base_repository": repository,
        "base_repository_id": repository_id,
        "base_sha": base_sha,
        "head_repository": repository,
        "head_repository_id": repository_id,
        "head_ref": candidate_ref,
        "candidate_sha": candidate_sha,
        "merge_commit_sha": head_sha,
        "merged_at": merged_at,
        "node_identity_sha256": node_sha256,
        "number": pull_request_number,
        "squash_merge_commit_message": "BLANK",
        "squash_merge_commit_title": "PR_TITLE",
        "title_sha256": title_sha256,
    }
    return {
        "schema_version": 1,
        "kind": CI_MODULE.DEFAULT_CANDIDATE_EVIDENCE_KIND,
        "authority_mode": "history-v2-admission",
        "repository": repository,
        "repository_id": repository_id,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "pull_request_number": pull_request_number,
        "candidate_ref": candidate_ref,
        "candidate_sha": candidate_sha,
        "pull_request_title_sha256": title_sha256,
        "pull_request_node_identity_sha256": node_sha256,
        "repository_identity_sha256": hashlib.sha256(
            f"{repository_id}:{repository}".encode("utf-8")
        ).hexdigest(),
        "pull_request_provenance_sha256": hashlib.sha256(
            json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest(),
        "pull_request_merged_at": merged_at,
        "admission_binding": {
            "schema_version": 1,
            "kind": CI_MODULE.POST_MERGE_ADMISSION_BINDING_KIND,
            "app": {
                "id": admission_app_id,
                "slug": CI_MODULE.ADMISSION_RECORD_APP_SLUG,
            },
            "admission_sha256": admission_sha256,
            "admission": admission,
            "candidate_record_check": synthetic_admission_check_evidence(
                check_name=CI_MODULE.ADMISSION_RECORD_CHECK_CONTEXT,
                head_sha=candidate_sha,
                check_run_id=701,
                check_suite_id=702,
                node_id="CR_kwDO_admission_candidate",
                started_at="2026-07-15T00:00:05Z",
                completed_at="2026-07-15T00:00:10Z",
                admission_sha256=admission_sha256,
            ),
            "queue_gate_check": synthetic_admission_check_evidence(
                check_name=CI_MODULE.REQUIRED_CHECK_CONTEXT,
                head_sha=snapshot.queue_sha,
                check_run_id=703,
                check_suite_id=704,
                node_id="CR_kwDO_admission_queue",
                started_at="2026-07-15T00:00:11Z",
                completed_at="2026-07-15T00:00:15Z",
                admission_sha256=admission_sha256,
            ),
        },
        "squash_merge_commit_title": "PR_TITLE",
        "squash_merge_commit_message": "BLANK",
    }


def rebind_synthetic_external_admission(evidence: dict[str, object]) -> None:
    binding = evidence["admission_binding"]
    assert isinstance(binding, dict)
    admission = binding["admission"]
    assert isinstance(admission, dict)
    snapshot = admission["snapshot"]
    projection = admission["projection"]
    runtime = admission["runtime_evidence"]
    live = admission["live_authority"]
    assert all(
        isinstance(value, dict) for value in (snapshot, projection, runtime, live)
    )
    predecessor = live["predecessor_authority"]
    assert isinstance(predecessor, dict)
    projection_sha256 = hashlib.sha256(
        CI_MODULE.compact_json_bytes(projection)
    ).hexdigest()
    runtime["projection_sha256"] = projection_sha256
    predecessor["projection_sha256"] = projection_sha256
    predecessor_sha256 = hashlib.sha256(
        CI_MODULE.compact_json_bytes(predecessor)
    ).hexdigest()
    live["snapshot_sha256"] = hashlib.sha256(
        CI_MODULE.compact_json_bytes(snapshot)
    ).hexdigest()
    live["predecessor_authority_sha256"] = predecessor_sha256
    admission["snapshot_sha256"] = live["snapshot_sha256"]
    admission["projection_sha256"] = projection_sha256
    admission["runtime_evidence_sha256"] = hashlib.sha256(
        CI_MODULE.compact_json_bytes(runtime)
    ).hexdigest()
    admission["predecessor_authority_sha256"] = predecessor_sha256
    admission["live_authority_sha256"] = hashlib.sha256(
        CI_MODULE.compact_json_bytes(live)
    ).hexdigest()
    admission_sha256 = hashlib.sha256(
        CI_MODULE.compact_json_bytes(admission)
    ).hexdigest()
    binding["admission_sha256"] = admission_sha256
    for key in ("candidate_record_check", "queue_gate_check"):
        check = binding[key]
        assert isinstance(check, dict)
        check["external_id"] = (
            CI_MODULE.ADMISSION_RECORD_EXTERNAL_ID_PREFIX + admission_sha256
        )
        check["output_summary"] = (
            CI_MODULE.ADMISSION_RECORD_OUTPUT_SUMMARY_PREFIX + admission_sha256
        )
        check["admission_sha256"] = admission_sha256


def active_branch_rules_payload(
    *,
    admission_app_id: int = TEST_ADMISSION_APP_ID,
) -> list[dict]:
    return [
        {"type": "deletion"},
        {
            "type": "merge_queue",
            "parameters": {
                "merge_method": "SQUASH",
                "max_entries_to_build": 1,
                "max_entries_to_merge": 1,
                "min_entries_to_merge": 1,
            },
        },
        {"type": "non_fast_forward"},
        {
            "type": "pull_request",
            "parameters": {
                "allowed_merge_methods": ["squash"],
                "required_approving_review_count": 1,
                "dismiss_stale_reviews_on_push": True,
                "require_last_push_approval": True,
                "required_review_thread_resolution": True,
            },
        },
        {"type": "required_linear_history"},
        {
            "type": "required_status_checks",
            "parameters": {
                "strict_required_status_checks_policy": True,
                "required_status_checks": [
                    {
                        "context": CI_MODULE.REQUIRED_CHECK_CONTEXT,
                        "integration_id": admission_app_id,
                    }
                ],
            },
        },
    ]


def branch_protection_payload(
    *,
    admission_app_id: int = TEST_ADMISSION_APP_ID,
) -> dict:
    return {
        "required_status_checks": {
            "strict": True,
            "contexts": [CI_MODULE.REQUIRED_CHECK_CONTEXT],
            "checks": [
                {
                    "context": CI_MODULE.REQUIRED_CHECK_CONTEXT,
                    "app_id": admission_app_id,
                }
            ],
        },
        "required_pull_request_reviews": {
            "required_approving_review_count": 1,
            "dismiss_stale_reviews": True,
            "require_last_push_approval": True,
            "bypass_pull_request_allowances": {
                "apps": [],
                "teams": [],
                "users": [],
            },
        },
        "enforce_admins": {"enabled": True},
        "required_linear_history": {"enabled": True},
        "required_conversation_resolution": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
    }


class MergeGroupGraph:
    def __init__(self, root: Path) -> None:
        self.root = root
        subprocess.run(
            ["git", "init", "--quiet", str(root)],
            check=True,
        )
        configure_git(root)
        for relative in CI_MODULE.PERMANENT_TRUST_GENERATION_PATHS:
            self.write(relative, f"Synthetic trusted file: {relative}\n")
        self.base = commit_all(root, "base")

    @property
    def git_dir(self) -> Path:
        return self.root / ".git"

    def write(self, relative: str, value: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")

    def reset(self, revision: str) -> None:
        git(self.root, "reset", "--hard", "--quiet", revision)

    def candidate(self, *, role: str, message: str) -> str:
        self.reset(self.base)
        if role == "publication":
            self.write(
                "retained/daily/episodes.jsonl",
                '{"episode":"candidate"}\n',
            )
        elif role == "admin":
            self.write("README.md", "Signed admin candidate.\n")
        else:
            raise AssertionError(f"unsupported fixture role: {role}")
        return commit_all(self.root, message)

    def queue(
        self,
        *,
        candidate: str,
        role: str,
        advance_base: bool,
    ) -> tuple[str, str]:
        self.reset(self.base)
        if advance_base:
            self.write(
                "retained/weekly/episodes.jsonl",
                '{"episode":"concurrent"}\n',
            )
            queue_base = commit_all(self.root, "concurrent publication")
        else:
            queue_base = self.base
        candidate_path = (
            "retained/daily/episodes.jsonl" if role == "publication" else "README.md"
        )
        git(self.root, "checkout", candidate, "--", candidate_path)
        git(self.root, "add", "--all")
        queue_tree = git(self.root, "write-tree")
        queue = fixture_raw_commit(
            self.root,
            tree_oid=queue_tree,
            parents=(queue_base, candidate),
            message="queue",
            include_signature=False,
        )
        git(self.root, "update-ref", "HEAD", queue)
        git(self.root, "reset", "--hard", "--quiet", queue)
        return queue_base, queue

    def plan(self, *, candidate: str, role: str, subject: str) -> dict:
        entries = CI_MODULE._trust_generation_entries(
            self.git_dir,
            self.base,
        )
        candidate_delta = CI_MODULE._exact_tree_delta(
            self.git_dir,
            self.base,
            candidate,
        )
        return {
            "schema_version": 1,
            "base_oid": self.base,
            "head_oid": candidate,
            "head_tree_oid": git(
                self.root,
                "rev-parse",
                f"{candidate}^{{tree}}",
            ),
            "squash_subject": subject,
            "trust_generation": hashlib.sha256(
                CI_MODULE.compact_json_bytes(entries)
            ).hexdigest(),
            "role": role,
            "changed_path_count": len(candidate_delta),
            "delta_sha256": hashlib.sha256(
                CI_MODULE.compact_json_bytes(candidate_delta)
            ).hexdigest(),
        }

    def snapshot(
        self,
        *,
        candidate: str,
        queue_base: str,
        queue: str,
        title: str,
    ) -> object:
        return CI_MODULE.MergeGroupSnapshot(
            repository=TEST_REPOSITORY,
            repository_id=TEST_REPOSITORY_ID,
            base_ref="refs/heads/master",
            base_sha=queue_base,
            queue_ref=merge_group_ref(),
            queue_sha=queue,
            workflow_sha=queue,
            pull_request_number=17,
            pull_request_node_id="PR_kwDO_bootstrap",
            pull_request_title=title,
            candidate_ref="wip/history-publication",
            candidate_sha=candidate,
            required_check=CI_MODULE.REQUIRED_CHECK_CONTEXT,
            tcb_sha256="1" * 64,
        )


class SessionRetrospectiveV2BootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        app_pin = mock.patch.object(
            CI_MODULE,
            "ADMISSION_RECORD_APP_ID",
            TEST_ADMISSION_APP_ID,
        )
        app_pin.start()
        self.addCleanup(app_pin.stop)
        validator_app_pin = mock.patch.object(
            VALIDATOR_MODULE,
            "HISTORY_V2_ADMISSION_RECORD_APP_ID",
            TEST_ADMISSION_APP_ID,
        )
        validator_app_pin.start()
        self.addCleanup(validator_app_pin.stop)

    def test_workflow_policy_is_duplicate_key_safe_and_exact(self) -> None:
        workflow_text = WORKFLOW.read_text(encoding="utf-8")
        workflow = load_workflow()
        observed = VALIDATOR_MODULE.bootstrap_workflow_policy_fingerprint(workflow)
        self.assertEqual(observed, EXPECTED_WORKFLOW_POLICY_SHA256)
        self.assertEqual(
            VALIDATOR_MODULE.BOOTSTRAP_WORKFLOW_POLICY_SHA256,
            EXPECTED_WORKFLOW_POLICY_SHA256,
        )
        duplicate = workflow_text.replace(
            "name: Session Retrospective v2 Bootstrap\n",
            "name: Session Retrospective v2 Bootstrap\nname: Shadow\n",
            1,
        )
        with self.assertRaisesRegex(ValueError, "duplicate key: name"):
            VALIDATOR_MODULE.parse_strict_workflow_yaml(duplicate)

    def test_trigger_permissions_identity_outputs_and_timeout_are_exact(self) -> None:
        workflow = load_workflow()
        self.assertEqual(
            workflow["on"],
            {
                "pull_request_target": {
                    "branches": ["master"],
                    "types": [
                        "opened",
                        "reopened",
                        "synchronize",
                        "ready_for_review",
                        "converted_to_draft",
                        "edited",
                    ],
                },
            },
        )
        self.assertEqual(workflow["permissions"], {})
        self.assertEqual(
            {key: workflow["env"][key] for key in CLOSED_GIT_WORKFLOW_ENV},
            CLOSED_GIT_WORKFLOW_ENV,
        )
        self.assertEqual(
            workflow["env"]["RETROSPECTIVE_HISTORY_MUTATION_MODEL"],
            "external-admission-cas-only",
        )
        self.assertEqual(
            workflow["env"]["RETROSPECTIVE_HISTORY_TCB"],
            "baseline-owned-pr-feedback_external-admission-cas",
        )
        self.assertNotIn("pull_request", workflow["on"])
        self.assertNotIn("merge_group", workflow["on"])
        job = workflow_job()
        self.assertEqual(job["runs-on"], "ubuntu-24.04")
        self.assertEqual(job["timeout-minutes"], 45)
        self.assertEqual(job["name"], "Trusted history gate")
        self.assertEqual(
            job["permissions"],
            {"contents": "read", "pull-requests": "read"},
        )
        self.assertNotIn("outputs", job)
        self.assertNotIn("MERGE_GROUP_SNAPSHOT", job["env"])
        self.assertNotIn("QUEUE_ROOT", job["env"])
        self.assertIn("github.event.pull_request.draft == false", job["if"])
        self.assertNotIn("merge_group", job["if"])

    def test_permanent_workflow_separates_candidate_feedback_from_push_audit(
        self,
    ) -> None:
        bootstrap = load_workflow()
        permanent = load_workflow(PERMANENT_CI)
        self.assertEqual(
            permanent["on"],
            {
                "pull_request_target": bootstrap["on"]["pull_request_target"],
                "push": {"branches": ["master"]},
            },
        )
        self.assertEqual(
            permanent["env"]["RETROSPECTIVE_HISTORY_MUTATION_MODEL"],
            "external-admission-cas-only",
        )
        self.assertEqual(
            permanent["env"]["RETROSPECTIVE_HISTORY_S_AUDIT"],
            "post-mutation-detection-only",
        )
        self.assertEqual(
            set(permanent["jobs"]),
            {"trusted_history_gate", "trusted_default_audit"},
        )
        candidate = permanent["jobs"]["trusted_history_gate"]
        audit = permanent["jobs"]["trusted_default_audit"]
        self.assertEqual(candidate["timeout-minutes"], 45)
        self.assertEqual(
            candidate["permissions"],
            {"contents": "read", "pull-requests": "read"},
        )
        self.assertEqual(
            audit["permissions"],
            {"checks": "read", "contents": "read", "pull-requests": "read"},
        )
        self.assertEqual(audit["name"], "Post-merge default audit")
        self.assertEqual(audit["timeout-minutes"], 45)
        self.assertEqual(
            audit["env"]["DEFAULT_AUTHORITY_ROOT"],
            "${{ github.workspace }}/candidate-default",
        )
        self.assertEqual(
            audit["env"]["TRUSTED_BASELINE_ROOT"],
            "${{ github.workspace }}/trusted-default",
        )
        self.assertEqual(
            audit["env"]["ADMITTED_CANDIDATE_ROOT"],
            "${{ github.workspace }}/admitted-candidate",
        )
        self.assertNotIn("ADMISSION_APP_ID", audit["env"])
        self.assertEqual(
            audit["env"]["EVENT_REPOSITORY_ID"],
            "${{ github.repository_id }}",
        )
        self.assertEqual(
            audit["if"],
            "${{ github.event_name == 'push' && github.ref == 'refs/heads/master' }}",
        )
        audit_steps = steps_by_name(audit)
        candidate_steps = steps_by_name(candidate)
        self.assertEqual(
            candidate_steps["Set up trusted Python"]["with"],
            {"python-version": "3.13.12", "cache": False},
        )
        candidate_control_binding = candidate_steps["Bind trusted control Python"][
            "run"
        ]
        self.assertIn(
            '[ "$control_version" != "Python 3.13.12" ]',
            candidate_control_binding,
        )
        candidate_names = [step["name"] for step in candidate["steps"]]
        candidate_runtime_order = (
            "Validate B0/H candidate feedback",
            "Prepare sealed candidate runtime tree",
            "Install sealed candidate test dependencies",
            "Run sealed candidate compile and tests",
            "Verify candidate runtime authority remains pristine",
            "Release read-only H mount",
            "Publish gate evidence",
        )
        candidate_offsets = [
            candidate_names.index(name) for name in candidate_runtime_order
        ]
        self.assertEqual(candidate_offsets, sorted(candidate_offsets))
        permanent_fetch = candidate_steps["Fetch bounded graph without checkout"]["run"]
        self.assertIn('--depth=65 "$TRUSTED_ROOT"', permanent_fetch)
        self.assertIn(
            "authenticated_fetch --depth=66 --filter=blob:none",
            permanent_fetch,
        )
        step_names = [step["name"] for step in audit["steps"]]
        ordered = (
            "Checkout exact default S",
            "Checkout exact trusted B0",
            "Bind trusted control Python",
            "Resolve exact admitted candidate H",
            "Checkout exact admitted candidate H",
            "Verify exact GitHub squash commit",
            "Detect invalid S tree or transaction",
            "Remove temporary provider receipt",
            "Prepare disposable default test tree",
            "Install validated default test dependencies",
            "Run tests after dropping UID and cwd",
        )
        offsets = [step_names.index(name) for name in ordered]
        self.assertEqual(offsets, sorted(offsets))
        baseline_checkout = audit_steps["Checkout exact trusted B0"]
        self.assertEqual(baseline_checkout["with"]["ref"], "${{ github.event.before }}")
        self.assertEqual(baseline_checkout["with"]["path"], "trusted-default")
        self.assertIs(baseline_checkout["with"]["persist-credentials"], False)
        action_steps = [step for step in audit["steps"] if "uses" in step]
        self.assertEqual(
            [step["uses"] for step in action_steps],
            [
                "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
                "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
                "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
                "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
            ],
        )
        self.assertFalse(any(step["uses"].startswith("./") for step in action_steps))
        trusted_setup = audit_steps["Set up trusted Python"]
        self.assertEqual(
            trusted_setup["with"],
            {"python-version": "3.13.12", "cache": False},
        )
        control_binding = audit_steps["Bind trusted control Python"]["run"]
        self.assertIn(
            'control_version="$("$control_python" -I -B --version 2>&1)"',
            control_binding,
        )
        self.assertIn('[ "$control_version" != "Python 3.13.12" ]', control_binding)
        resolver = audit_steps["Resolve exact admitted candidate H"]
        self.assertEqual(resolver["env"], {"GH_TOKEN": "${{ github.token }}"})
        self.assertIn("resolve-default-admitted-candidate", resolver["run"])
        self.assertIn(
            '--trusted-base-root "$TRUSTED_BASELINE_ROOT"',
            resolver["run"],
        )
        self.assertNotIn("--admission-app-id", resolver["run"])
        candidate_checkout = audit_steps["Checkout exact admitted candidate H"]
        self.assertEqual(candidate_checkout["with"]["path"], "admitted-candidate")
        self.assertEqual(candidate_checkout["with"]["fetch-depth"], 65)
        self.assertEqual(
            candidate_checkout["with"]["ref"],
            "${{ steps.resolve-admitted-candidate.outputs.candidate-sha }}",
        )
        verification = audit_steps["Verify exact GitHub squash commit"]
        self.assertEqual(verification["env"], {"GH_TOKEN": "${{ github.token }}"})
        token_steps = [
            step
            for step in audit["steps"]
            if {"GH_TOKEN", "GITHUB_TOKEN"} & set(step.get("env", {}))
        ]
        self.assertEqual(token_steps, [resolver, verification])
        self.assertIn("verify-default-github-commit", verification["run"])
        self.assertIn("/usr/bin/env -i", verification["run"])
        self.assertIn('"$CONTROL_PYTHON" -I -B', verification["run"])
        self.assertEqual(verification["run"].count('"$CONTROL_PYTHON"'), 1)
        self.assertIn(
            '"$TRUSTED_BASELINE_ROOT/scripts/trusted_history_ci.py"',
            verification["run"],
        )
        self.assertEqual(
            verification["run"].count(
                '"$TRUSTED_BASELINE_ROOT/scripts/trusted_history_ci.py"'
            ),
            1,
        )
        self.assertNotIn(
            '"$DEFAULT_AUTHORITY_ROOT/scripts/trusted_history_ci.py"',
            verification["run"],
        )
        self.assertIn('--repository "$GITHUB_REPOSITORY"', verification["run"])
        self.assertIn('--repository-id "$EVENT_REPOSITORY_ID"', verification["run"])
        self.assertIn('--base-sha "$EVENT_BEFORE_SHA"', verification["run"])
        self.assertIn('--head-sha "$GITHUB_SHA"', verification["run"])
        self.assertIn(
            '--trusted-base-root "$TRUSTED_BASELINE_ROOT"',
            verification["run"],
        )
        self.assertNotIn("--candidate-root", verification["run"])
        self.assertIn(
            '--initial-candidate-evidence "$INITIAL_CANDIDATE_EVIDENCE"',
            verification["run"],
        )
        self.assertIn("timeout --signal=TERM --kill-after=5s", verification["run"])
        detector_gate = audit_steps["Detect invalid S tree or transaction"]["run"]
        self.assertIn(
            '"$TRUSTED_BASELINE_ROOT/scripts/validate_retained_history.py"',
            detector_gate,
        )
        self.assertIn('--root "$DEFAULT_AUTHORITY_ROOT"', detector_gate)
        self.assertIn('--base-root "$TRUSTED_BASELINE_ROOT"', detector_gate)
        self.assertIn('--candidate-root "$ADMITTED_CANDIDATE_ROOT"', detector_gate)
        self.assertIn('--repository "$GITHUB_REPOSITORY"', detector_gate)
        self.assertIn('--repository-id "$EVENT_REPOSITORY_ID"', detector_gate)
        self.assertIn(
            '--github-commit-receipt "$GITHUB_COMMIT_RECEIPT"',
            detector_gate,
        )
        self.assertNotIn("GH_TOKEN", detector_gate)
        dependency_step = audit_steps["Install validated default test dependencies"][
            "run"
        ]
        self.assertIn(
            '--requirement "$DEFAULT_EXECUTION_ROOT/requirements-v2.txt"',
            dependency_step,
        )
        self.assertNotIn("GH_TOKEN=", dependency_step)
        self.assertIn("-u GH_TOKEN -u GITHUB_TOKEN", dependency_step)
        for step in audit["steps"][
            : step_names.index("Detect invalid S tree or transaction")
        ]:
            script = step.get("run", "")
            self.assertNotIn("pip install", script)
            self.assertNotIn("TEST_PYTHON", script)
            self.assertNotIn(
                '"$DEFAULT_AUTHORITY_ROOT/scripts/trusted_history_ci.py"',
                script,
            )
            self.assertNotIn(
                '"$DEFAULT_AUTHORITY_ROOT/scripts/validate_retained_history.py"',
                script,
            )
        cleanup = audit_steps["Remove temporary provider receipt"]
        self.assertEqual(cleanup["if"], "${{ always() }}")
        self.assertIn("github-commit-receipt.json", cleanup["run"])
        self.assertIn("initial-candidate-evidence.json", cleanup["run"])
        self.assertIn("rm -f --", cleanup["run"])
        self.assertLess(
            step_names.index("Remove temporary provider receipt"),
            step_names.index("Prepare disposable default test tree"),
        )
        for step_name in (
            "Detect invalid S tree or transaction",
            "Install validated default test dependencies",
            "Run tests after dropping UID and cwd",
        ):
            script = audit_steps[step_name]["run"]
            self.assertNotIn("tail -n", script)
            self.assertIn("/usr/bin/tail -c 65536", script)
            self.assertIn("/usr/bin/base64 -w 76", script)
            self.assertIn("diagnostic-base64: ", script)
        detector = steps_by_name(audit)["Document detector scope"]["run"]
        self.assertIn("does not prevent that write", detector)
        self.assertIn("never authorizes mutation", detector)

    def _legacy_provider_receipt_v2_reference(self) -> None:
        repository = "Joey-Tools/codex-session-retrospective-history"
        repository_id = 1_246_526_548
        pull_number = 4
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            configure_git(root)
            (root / "payload.txt").write_text("base\n", encoding="utf-8")
            base = commit_all(root, "provider receipt base")
            tree_oid = git(root, "rev-parse", f"{base}^{{tree}}")
            head = fixture_raw_commit(
                root,
                tree_oid=tree_oid,
                parents=(base,),
                message=f"Publish retained history (#{pull_number})",
                author=VALIDATOR_MODULE.HISTORY_V2_CANONICAL_IDENTITY,
                committer="GitHub <noreply@github.com>",
                author_timezone="+0100",
                committer_timezone="+0100",
                message_trailing_newline=False,
                signature_trailing_blank_continuation=True,
            )
            parsed = VALIDATOR_MODULE.parse_history_v2_github_squash_commit(
                fixture_commit_bytes(root, head),
                expected_oid=head,
            )
            self.assertEqual(parsed.pull_request_number, pull_number)
            commit_date = CI_MODULE.dt.datetime.fromtimestamp(
                FIXTURE_TIMESTAMP,
                tz=CI_MODULE.dt.timezone.utc,
            )
            date_text = commit_date.strftime("%Y-%m-%dT%H:%M:%SZ")
            verified_at = (commit_date + CI_MODULE.dt.timedelta(seconds=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            api_payload = {
                "sha": head,
                "parents": [{"sha": base}],
                "author": {"login": "SyntheticMaintainer"},
                "committer": {"login": "web-flow"},
                "commit": {
                    "tree": {"sha": tree_oid},
                    "author": {"date": date_text},
                    "committer": {"date": date_text},
                    "verification": {
                        "verified": True,
                        "reason": "valid",
                        "signature": parsed.signature_armor.decode("ascii"),
                        "payload": parsed.signed_payload.decode("utf-8"),
                        "verified_at": verified_at,
                    },
                },
            }
            pull_node_id = "PR_kwDOSyntheticReceipt"
            candidate_head = "d" * len(head)
            merged_at = verified_at
            associated = [{"number": pull_number, "node_id": pull_node_id}]
            pull_payload = {
                "number": pull_number,
                "node_id": pull_node_id,
                "title": "Publish retained history",
                "state": "closed",
                "merged": True,
                "merged_at": merged_at,
                "draft": False,
                "merge_commit_sha": head,
                "base": {
                    "ref": "master",
                    "sha": base,
                    "repo": {"full_name": repository, "id": repository_id},
                },
                "head": {
                    "ref": "wip/session-retrospective-v2-history",
                    "sha": candidate_head,
                    "repo": {"full_name": repository, "id": repository_id},
                },
            }
            squash_configuration = {
                "squash_merge_commit_title": "PR_TITLE",
                "squash_merge_commit_message": "BLANK",
            }
            with (
                mock.patch.object(
                    CI_MODULE,
                    "github_json",
                    side_effect=[
                        api_payload,
                        associated,
                        [],
                        associated,
                        pull_payload,
                        associated,
                        [],
                        associated,
                    ],
                ) as github_api,
                mock.patch.object(
                    CI_MODULE,
                    "read_default_squash_configuration",
                    return_value=squash_configuration,
                ) as squash_configuration_reader,
            ):
                receipt = CI_MODULE.verify_default_github_commit(
                    repository=repository,
                    repository_id=repository_id,
                    git_dir=root / ".git",
                    base_sha=base,
                    head_sha=head,
                    token="synthetic-read-token",
                )
            with (
                mock.patch.object(
                    CI_MODULE,
                    "github_json",
                    return_value=api_payload,
                ),
                mock.patch.object(
                    CI_MODULE,
                    "read_default_squash_configuration",
                    return_value=squash_configuration,
                ),
                mock.patch.object(
                    CI_MODULE,
                    "verify_default_merged_pull_request",
                    return_value={"pull_request_number": pull_number + 1},
                ),
                self.assertRaisesRegex(
                    CI_MODULE.GateError,
                    "subject pull request differs from the associated pull request",
                ),
            ):
                CI_MODULE.verify_default_github_commit(
                    repository=repository,
                    repository_id=repository_id,
                    git_dir=root / ".git",
                    base_sha=base,
                    head_sha=head,
                    token="synthetic-read-token",
                )
            unnumbered = fixture_raw_commit(
                root,
                tree_oid=tree_oid,
                parents=(base,),
                message="Publish retained history",
                author=VALIDATOR_MODULE.HISTORY_V2_CANONICAL_IDENTITY,
                committer="GitHub <noreply@github.com>",
                author_timezone="+0100",
                committer_timezone="+0100",
                message_trailing_newline=False,
                signature_trailing_blank_continuation=True,
            )
            parsed_unnumbered = VALIDATOR_MODULE.parse_history_v2_github_squash_commit(
                fixture_commit_bytes(root, unnumbered),
                expected_oid=unnumbered,
            )
            self.assertIsNone(parsed_unnumbered.pull_request_number)
            unnumbered_payload = copy.deepcopy(api_payload)
            unnumbered_payload["sha"] = unnumbered
            unnumbered_payload["commit"]["verification"].update(
                {
                    "signature": parsed_unnumbered.signature_armor.decode("ascii"),
                    "payload": parsed_unnumbered.signed_payload.decode("utf-8"),
                }
            )
            pull_evidence = {
                key: receipt[key]
                for key in (
                    "pull_request_number",
                    "candidate_ref",
                    "pull_request_title_sha256",
                    "pull_request_node_identity_sha256",
                    "repository_identity_sha256",
                    "pull_request_provenance_sha256",
                    "pull_request_merged_at",
                    "squash_merge_commit_title",
                    "squash_merge_commit_message",
                )
            }
            with (
                mock.patch.object(
                    CI_MODULE,
                    "github_json",
                    return_value=unnumbered_payload,
                ),
                mock.patch.object(
                    CI_MODULE,
                    "verify_default_merged_pull_request",
                    return_value=pull_evidence,
                ),
                mock.patch.object(
                    CI_MODULE,
                    "read_default_squash_configuration",
                    return_value=squash_configuration,
                ),
            ):
                unnumbered_receipt = CI_MODULE.verify_default_github_commit(
                    repository=repository,
                    repository_id=repository_id,
                    git_dir=root / ".git",
                    base_sha=base,
                    head_sha=unnumbered,
                    token="synthetic-read-token",
                )
            self.assertEqual(
                unnumbered_receipt["pull_request_number"],
                pull_number,
            )
            self.assertEqual(receipt["base_sha"], base)
            self.assertEqual(receipt["head_sha"], head)
            self.assertEqual(receipt["tree_sha"], tree_oid)
            self.assertEqual(receipt["schema_version"], 2)
            self.assertEqual(receipt["github_committer_login"], "web-flow")
            self.assertEqual(receipt["verification_reason"], "valid")
            self.assertEqual(receipt["pull_request_number"], pull_number)
            self.assertEqual(
                receipt["pull_request_title_sha256"],
                hashlib.sha256(b"Publish retained history").hexdigest(),
            )
            self.assertEqual(
                receipt["squash_merge_commit_title"],
                "PR_TITLE",
            )
            self.assertEqual(
                receipt["squash_merge_commit_message"],
                "BLANK",
            )
            self.assertEqual(
                receipt["repository_identity_sha256"],
                hashlib.sha256(
                    f"{repository_id}:{repository}".encode("utf-8")
                ).hexdigest(),
            )
            expected_provenance = {
                "base_ref": "master",
                "base_repository": repository,
                "base_repository_id": repository_id,
                "base_sha": base,
                "head_repository": repository,
                "head_repository_id": repository_id,
                "merge_commit_sha": head,
                "merged_at": merged_at,
                "node_identity_sha256": hashlib.sha256(
                    pull_node_id.encode("utf-8")
                ).hexdigest(),
                "number": pull_number,
                **squash_configuration,
                "title_sha256": hashlib.sha256(b"Publish retained history").hexdigest(),
            }
            self.assertEqual(
                receipt["pull_request_provenance_sha256"],
                hashlib.sha256(
                    json.dumps(
                        expected_provenance,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest(),
            )
            self.assertEqual(receipt["pull_request_merged_at"], merged_at)
            self.assertEqual(
                receipt["pull_request_node_identity_sha256"],
                hashlib.sha256(pull_node_id.encode("utf-8")).hexdigest(),
            )
            VALIDATOR_MODULE.validate_history_v2_github_squash_receipt(
                receipt,
                commit=parsed,
                repository=repository,
                repository_id=repository_id,
                before_rev=base,
                head_rev=head,
            )
            serialized_receipt = json.dumps(receipt, sort_keys=True)
            self.assertNotIn("maintainer@example.net", serialized_receipt)
            self.assertNotIn("SyntheticMaintainer", serialized_receipt)
            self.assertNotIn(pull_node_id, serialized_receipt)
            self.assertNotIn(candidate_head, serialized_receipt)
            self.assertEqual(
                github_api.call_args_list,
                [
                    mock.call(
                        "GET",
                        repository,
                        f"/commits/{head}",
                        token="synthetic-read-token",
                        max_bytes=CI_MODULE.MAX_HTTP_RESPONSE_BYTES,
                    ),
                    mock.call(
                        "GET",
                        repository,
                        f"/commits/{head}/pulls?per_page=100&page=1",
                        token="synthetic-read-token",
                    ),
                    mock.call(
                        "GET",
                        repository,
                        f"/commits/{head}/pulls?per_page=100&page=2",
                        token="synthetic-read-token",
                    ),
                    mock.call(
                        "GET",
                        repository,
                        f"/commits/{head}/pulls?per_page=100&page=1",
                        token="synthetic-read-token",
                    ),
                    mock.call(
                        "GET",
                        repository,
                        f"/pulls/{pull_number}",
                        token="synthetic-read-token",
                    ),
                    mock.call(
                        "GET",
                        repository,
                        f"/commits/{head}/pulls?per_page=100&page=1",
                        token="synthetic-read-token",
                    ),
                    mock.call(
                        "GET",
                        repository,
                        f"/commits/{head}/pulls?per_page=100&page=2",
                        token="synthetic-read-token",
                    ),
                    mock.call(
                        "GET",
                        repository,
                        f"/commits/{head}/pulls?per_page=100&page=1",
                        token="synthetic-read-token",
                    ),
                ],
            )
            self.assertEqual(squash_configuration_reader.call_count, 2)

            mutations = (
                (
                    "payload",
                    lambda value: value["commit"]["verification"].__setitem__(
                        "payload", "mismatch"
                    ),
                ),
                (
                    "signature",
                    lambda value: value["commit"]["verification"].__setitem__(
                        "signature", "mismatch"
                    ),
                ),
                (
                    "verification",
                    lambda value: value["commit"]["verification"].__setitem__(
                        "verified", False
                    ),
                ),
                (
                    "reason",
                    lambda value: value["commit"]["verification"].__setitem__(
                        "reason", "unknown_key"
                    ),
                ),
                (
                    "parent",
                    lambda value: value["parents"][0].__setitem__("sha", "a" * 40),
                ),
                (
                    "tree",
                    lambda value: value["commit"]["tree"].__setitem__("sha", "b" * 40),
                ),
                (
                    "provider",
                    lambda value: value["committer"].__setitem__(
                        "login", "not-web-flow"
                    ),
                ),
            )
            for label, mutate in mutations:
                with self.subTest(mutation=label):
                    changed = copy.deepcopy(api_payload)
                    mutate(changed)
                    with (
                        mock.patch.object(
                            CI_MODULE,
                            "github_json",
                            side_effect=[
                                changed,
                                associated,
                                [],
                                associated,
                                pull_payload,
                                associated,
                                [],
                                associated,
                            ],
                        ),
                        mock.patch.object(
                            CI_MODULE,
                            "read_default_squash_configuration",
                            return_value=squash_configuration,
                        ),
                        self.assertRaises(CI_MODULE.GateError),
                    ):
                        CI_MODULE.verify_default_github_commit(
                            repository=repository,
                            repository_id=repository_id,
                            git_dir=root / ".git",
                            base_sha=base,
                            head_sha=head,
                            token="synthetic-read-token",
                        )

            pull_mutations = (
                ("open", lambda value: value.__setitem__("state", "open")),
                ("unmerged", lambda value: value.__setitem__("merged", False)),
                ("draft", lambda value: value.__setitem__("draft", True)),
                (
                    "merge commit",
                    lambda value: value.__setitem__(
                        "merge_commit_sha", "a" * len(head)
                    ),
                ),
                (
                    "base ref",
                    lambda value: value["base"].__setitem__("ref", "other"),
                ),
                (
                    "base sha",
                    lambda value: value["base"].__setitem__("sha", "b" * len(base)),
                ),
                (
                    "base repository",
                    lambda value: value["base"]["repo"].__setitem__(
                        "full_name", "Joey-Tools/other-history"
                    ),
                ),
                (
                    "head repository",
                    lambda value: value["head"]["repo"].__setitem__(
                        "full_name", "Joey-Tools/other-history"
                    ),
                ),
                (
                    "base repository identity",
                    lambda value: value["base"]["repo"].__setitem__(
                        "id", repository_id + 1
                    ),
                ),
                (
                    "head repository identity",
                    lambda value: value["head"]["repo"].__setitem__(
                        "id", repository_id + 1
                    ),
                ),
                (
                    "node identity",
                    lambda value: value.__setitem__("node_id", "different-node"),
                ),
                ("number", lambda value: value.__setitem__("number", pull_number + 1)),
                (
                    "title",
                    lambda value: value.__setitem__(
                        "title", "Different retained history title"
                    ),
                ),
                (
                    "multiline title",
                    lambda value: value.__setitem__(
                        "title", "Publish retained history\nInjected body"
                    ),
                ),
            )
            for label, mutate in pull_mutations:
                with self.subTest(pull_mutation=label):
                    changed_pull = copy.deepcopy(pull_payload)
                    mutate(changed_pull)
                    with (
                        mock.patch.object(
                            CI_MODULE,
                            "github_json",
                            side_effect=[
                                api_payload,
                                associated,
                                [],
                                associated,
                                changed_pull,
                                associated,
                                [],
                                associated,
                            ],
                        ),
                        mock.patch.object(
                            CI_MODULE,
                            "read_default_squash_configuration",
                            return_value=squash_configuration,
                        ),
                        self.assertRaises(CI_MODULE.GateError),
                    ):
                        CI_MODULE.verify_default_github_commit(
                            repository=repository,
                            repository_id=repository_id,
                            git_dir=root / ".git",
                            base_sha=base,
                            head_sha=head,
                            token="synthetic-read-token",
                        )

            ambiguous_associations = (
                [],
                [
                    *associated,
                    {"number": pull_number + 1, "node_id": "PR_other"},
                ],
            )
            for associated_pulls in ambiguous_associations:
                with (
                    self.subTest(associated_count=len(associated_pulls)),
                    mock.patch.object(
                        CI_MODULE,
                        "github_json",
                        side_effect=[
                            api_payload,
                            associated_pulls,
                            [],
                            associated_pulls,
                        ],
                    ),
                    mock.patch.object(
                        CI_MODULE,
                        "read_default_squash_configuration",
                        return_value=squash_configuration,
                    ),
                    self.assertRaisesRegex(
                        CI_MODULE.GateError,
                        "missing or ambiguous",
                    ),
                ):
                    CI_MODULE.verify_default_github_commit(
                        repository=repository,
                        repository_id=repository_id,
                        git_dir=root / ".git",
                        base_sha=base,
                        head_sha=head,
                        token="synthetic-read-token",
                    )

            changed_association = [
                *associated,
                {"number": pull_number + 1, "node_id": "PR_inserted"},
            ]
            with (
                mock.patch.object(
                    CI_MODULE,
                    "github_json",
                    side_effect=[
                        api_payload,
                        associated,
                        [],
                        associated,
                        pull_payload,
                        associated,
                        [],
                        changed_association,
                    ],
                ),
                mock.patch.object(
                    CI_MODULE,
                    "read_default_squash_configuration",
                    return_value=squash_configuration,
                ),
                self.assertRaisesRegex(
                    CI_MODULE.GateError,
                    "missing or ambiguous|association changed|changed during collection",
                ),
            ):
                CI_MODULE.verify_default_github_commit(
                    repository=repository,
                    repository_id=repository_id,
                    git_dir=root / ".git",
                    base_sha=base,
                    head_sha=head,
                    token="synthetic-read-token",
                )

            changed_squash_configuration = {
                **squash_configuration,
                "squash_merge_commit_message": "COMMIT_MESSAGES",
            }
            with (
                mock.patch.object(
                    CI_MODULE,
                    "github_json",
                    side_effect=[
                        api_payload,
                        associated,
                        [],
                        associated,
                        pull_payload,
                        associated,
                        [],
                        associated,
                    ],
                ),
                mock.patch.object(
                    CI_MODULE,
                    "read_default_squash_configuration",
                    side_effect=[
                        squash_configuration,
                        changed_squash_configuration,
                    ],
                ),
                self.assertRaisesRegex(
                    CI_MODULE.GateError,
                    "configuration changed during collection",
                ),
            ):
                CI_MODULE.verify_default_github_commit(
                    repository=repository,
                    repository_id=repository_id,
                    git_dir=root / ".git",
                    base_sha=base,
                    head_sha=head,
                    token="synthetic-read-token",
                )

    def test_default_github_commit_receipt_binds_admitted_candidate_and_projection(
        self,
    ) -> None:
        repository = TEST_REPOSITORY
        repository_id = 1_246_526_548
        pull_number = 4
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            configure_git(root)
            (root / "payload.txt").write_text("base\n", encoding="utf-8")
            base = commit_all(root, "provider receipt base")
            tree_oid = git(root, "rev-parse", f"{base}^{{tree}}")
            head = fixture_raw_commit(
                root,
                tree_oid=tree_oid,
                parents=(base,),
                message=f"Publish retained history (#{pull_number})",
                author=VALIDATOR_MODULE.HISTORY_V2_CANONICAL_IDENTITY,
                committer="GitHub <noreply@github.com>",
                author_timezone="+0100",
                committer_timezone="+0100",
                message_trailing_newline=False,
                signature_trailing_blank_continuation=True,
            )
            parsed = VALIDATOR_MODULE.parse_history_v2_github_squash_commit(
                fixture_commit_bytes(root, head),
                expected_oid=head,
            )
            commit_date = CI_MODULE.dt.datetime.fromtimestamp(
                FIXTURE_TIMESTAMP,
                tz=CI_MODULE.dt.timezone.utc,
            )
            date_text = commit_date.strftime("%Y-%m-%dT%H:%M:%SZ")
            api_payload = {
                "sha": head,
                "parents": [{"sha": base}],
                "author": {"login": "SyntheticMaintainer"},
                "committer": {"login": "web-flow"},
                "commit": {
                    "tree": {"sha": tree_oid},
                    "author": {"date": date_text},
                    "committer": {"date": date_text},
                    "verification": {
                        "verified": True,
                        "reason": "valid",
                        "signature": parsed.signature_armor.decode("ascii"),
                        "payload": parsed.signed_payload.decode("utf-8"),
                        "verified_at": date_text,
                    },
                },
            }
            candidate_sha = "d" * len(head)
            external = synthetic_external_admission(
                repository=repository,
                repository_id=repository_id,
                base_sha=base,
                head_sha=head,
                candidate_sha=candidate_sha,
                candidate_tree_sha="e" * len(head),
                queue_tree_sha=tree_oid,
                pull_request_number=pull_number,
                pull_request_node_id="PR_kwDOSyntheticReceipt",
                pull_request_title="Publish retained history",
            )
            with (
                mock.patch.object(
                    CI_MODULE,
                    "resolve_default_candidate_evidence",
                    return_value=external,
                ) as resolver,
                mock.patch.object(
                    CI_MODULE,
                    "github_json",
                    return_value=api_payload,
                ),
            ):
                receipt = CI_MODULE.verify_default_github_commit(
                    repository=repository,
                    repository_id=repository_id,
                    git_dir=root / ".git",
                    trusted_base_root=root,
                    base_sha=base,
                    head_sha=head,
                    initial_candidate_evidence=external,
                    token="synthetic-read-token",
                )
            self.assertEqual(resolver.call_count, 2)
            self.assertEqual(receipt["schema_version"], 3)
            self.assertEqual(receipt["candidate_sha"], candidate_sha)
            self.assertEqual(receipt["candidate_evidence"], external)
            self.assertEqual(
                receipt["candidate_evidence_sha256"],
                hashlib.sha256(CI_MODULE.compact_json_bytes(external)).hexdigest(),
            )
            self.assertEqual(receipt["tree_sha"], tree_oid)
            with mock.patch.object(
                VALIDATOR_MODULE,
                "validate_history_v2_candidate_reproof",
                return_value=("history-v2", "publication"),
            ) as candidate_reproof:
                self.assertEqual(
                    VALIDATOR_MODULE.validate_history_v2_github_squash_receipt(
                        receipt,
                        commit=parsed,
                        repository=repository,
                        repository_id=repository_id,
                        before_rev=base,
                        head_rev=head,
                        base_root=root,
                        candidate_root=root,
                    ),
                    ("history-v2", "publication"),
                )
            candidate_reproof.assert_called_once()

            for label, mutate in (
                (
                    "signed payload",
                    lambda value: value["commit"]["verification"].__setitem__(
                        "payload",
                        "mismatch",
                    ),
                ),
                (
                    "provider",
                    lambda value: value["committer"].__setitem__(
                        "login",
                        "not-web-flow",
                    ),
                ),
            ):
                changed_payload = copy.deepcopy(api_payload)
                mutate(changed_payload)
                with (
                    self.subTest(label=label),
                    mock.patch.object(
                        CI_MODULE,
                        "resolve_default_candidate_evidence",
                        return_value=external,
                    ),
                    mock.patch.object(
                        CI_MODULE,
                        "github_json",
                        return_value=changed_payload,
                    ),
                    self.assertRaises(CI_MODULE.GateError),
                ):
                    CI_MODULE.verify_default_github_commit(
                        repository=repository,
                        repository_id=repository_id,
                        git_dir=root / ".git",
                        trusted_base_root=root,
                        base_sha=base,
                        head_sha=head,
                        initial_candidate_evidence=external,
                        token="synthetic-read-token",
                    )

            changed = copy.deepcopy(external)
            changed["candidate_sha"] = "f" * len(candidate_sha)
            with (
                mock.patch.object(
                    CI_MODULE,
                    "resolve_default_candidate_evidence",
                    return_value=changed,
                ),
                self.assertRaisesRegex(
                    CI_MODULE.GateError,
                    "changed before final validation",
                ),
            ):
                CI_MODULE.verify_default_github_commit(
                    repository=repository,
                    repository_id=repository_id,
                    git_dir=root / ".git",
                    trusted_base_root=root,
                    base_sha=base,
                    head_sha=head,
                    initial_candidate_evidence=external,
                    token="synthetic-read-token",
                )

    def test_bootstrap_default_candidate_binds_the_designated_head_ref(self) -> None:
        repository = TEST_REPOSITORY
        repository_id = 1_246_526_548
        base_sha = "b" * 40
        head_sha = "a" * 40
        candidate_sha = "d" * 40
        number = 4
        node_id = "PR_kwDOSyntheticBootstrap"
        associated = [{"number": number, "node_id": node_id}]
        pull = {
            "number": number,
            "node_id": node_id,
            "title": "Publish retained history",
            "state": "closed",
            "merged": True,
            "merged_at": "2026-07-15T00:00:20Z",
            "draft": False,
            "merge_commit_sha": head_sha,
            "base": {
                "ref": CI_MODULE.DEFAULT_BRANCH,
                "sha": base_sha,
                "repo": {"full_name": repository, "id": repository_id},
            },
            "head": {
                "ref": CI_MODULE.BOOTSTRAP_CANDIDATE_REF,
                "sha": candidate_sha,
                "repo": {"full_name": repository, "id": repository_id},
            },
        }
        squash = {
            "squash_merge_commit_title": "PR_TITLE",
            "squash_merge_commit_message": "BLANK",
        }
        with (
            mock.patch.object(
                CI_MODULE,
                "github_paginated_list",
                side_effect=[associated, associated],
            ),
            mock.patch.object(CI_MODULE, "github_json", return_value=pull),
        ):
            evidence = CI_MODULE.verify_default_merged_pull_request(
                repository=repository,
                repository_id=repository_id,
                base_sha=base_sha,
                head_sha=head_sha,
                squash_configuration=squash,
                authority_mode="bootstrap-v2-migration",
                token="synthetic-read-token",
            )
        self.assertEqual(evidence["candidate_ref"], CI_MODULE.BOOTSTRAP_CANDIDATE_REF)

        wrong_ref = copy.deepcopy(pull)
        wrong_ref["head"]["ref"] = "wip/unrelated-history-migration"
        with (
            mock.patch.object(
                CI_MODULE,
                "github_paginated_list",
                side_effect=[associated, associated],
            ),
            mock.patch.object(CI_MODULE, "github_json", return_value=wrong_ref),
            self.assertRaisesRegex(CI_MODULE.GateError, "stale or lookalike"),
        ):
            CI_MODULE.verify_default_merged_pull_request(
                repository=repository,
                repository_id=repository_id,
                base_sha=base_sha,
                head_sha=head_sha,
                squash_configuration=squash,
                authority_mode="bootstrap-v2-migration",
                token="synthetic-read-token",
            )

    def test_candidate_admission_check_is_unique_canonical_and_exact(self) -> None:
        repository = TEST_REPOSITORY
        repository_id = 1_246_526_548
        base_sha = "b" * 40
        head_sha = "a" * 40
        candidate_sha = "d" * 40
        node_id = "PR_kwDOSyntheticReceipt"
        external = synthetic_external_admission(
            repository=repository,
            repository_id=repository_id,
            base_sha=base_sha,
            head_sha=head_sha,
            candidate_sha=candidate_sha,
            candidate_tree_sha="e" * 40,
            queue_tree_sha="f" * 40,
            pull_request_number=4,
            pull_request_node_id=node_id,
            pull_request_title="Publish retained history",
        )
        expected = external["admission_binding"]
        admission = expected["admission"]

        def api_check(check: dict[str, object]) -> dict[str, object]:
            return {
                "id": check["check_run_id"],
                "node_id": check["check_run_node_id"],
                "name": check["check_name"],
                "head_sha": check["head_sha"],
                "status": "completed",
                "conclusion": "success",
                "started_at": check["started_at"],
                "completed_at": check["completed_at"],
                "external_id": check["external_id"],
                "app": expected["app"],
                "check_suite": {"id": check["check_suite_id"]},
                "output": {
                    "title": check["output_title"],
                    "summary": check["output_summary"],
                    "text": CI_MODULE.compact_json_bytes(admission).decode("utf-8"),
                    "annotations_count": 0,
                },
            }

        candidate_api_check = api_check(expected["candidate_record_check"])
        queue_api_check = api_check(expected["queue_gate_check"])
        with mock.patch.object(
            CI_MODULE,
            "github_paginated_object_items",
            side_effect=[[candidate_api_check], [queue_api_check]],
        ):
            observed = CI_MODULE.read_post_merge_admission_binding(
                repository=repository,
                repository_id=TEST_REPOSITORY_ID,
                candidate_sha=candidate_sha,
                candidate_ref="wip/session-retrospective-v2-history",
                base_sha=base_sha,
                pull_request_number=4,
                pull_request_node_id=node_id,
                merged_at=external["pull_request_merged_at"],
                token="synthetic-read-token",
            )
        self.assertEqual(observed, expected)

        with (
            mock.patch.object(
                CI_MODULE,
                "github_paginated_object_items",
                side_effect=[[candidate_api_check], [queue_api_check]],
            ),
            self.assertRaisesRegex(CI_MODULE.GateError, "stale or inconsistent"),
        ):
            CI_MODULE.read_post_merge_admission_binding(
                repository=repository,
                repository_id=TEST_REPOSITORY_ID + 1,
                candidate_sha=candidate_sha,
                candidate_ref="wip/session-retrospective-v2-history",
                base_sha=base_sha,
                pull_request_number=4,
                pull_request_node_id=node_id,
                merged_at=external["pull_request_merged_at"],
                token="synthetic-read-token",
            )

        ref_drift = copy.deepcopy(external)
        ref_binding = ref_drift["admission_binding"]
        assert isinstance(ref_binding, dict)
        ref_admission = ref_binding["admission"]
        assert isinstance(ref_admission, dict)
        ref_admission["snapshot"]["pull_request"]["head_ref"] = (
            "wip/different-history-candidate"
        )
        rebind_synthetic_external_admission(ref_drift)
        ref_candidate_check = api_check(ref_binding["candidate_record_check"])
        ref_queue_check = api_check(ref_binding["queue_gate_check"])
        for check in (ref_candidate_check, ref_queue_check):
            check["output"]["text"] = CI_MODULE.compact_json_bytes(
                ref_admission
            ).decode("utf-8")
        with (
            mock.patch.object(
                CI_MODULE,
                "github_paginated_object_items",
                side_effect=[
                    [ref_candidate_check],
                    [ref_queue_check],
                ],
            ),
            self.assertRaisesRegex(CI_MODULE.GateError, "stale or inconsistent"),
        ):
            CI_MODULE.read_post_merge_admission_binding(
                repository=repository,
                repository_id=TEST_REPOSITORY_ID,
                candidate_sha=candidate_sha,
                candidate_ref="wip/session-retrospective-v2-history",
                base_sha=base_sha,
                pull_request_number=4,
                pull_request_node_id=node_id,
                merged_at=external["pull_request_merged_at"],
                token="synthetic-read-token",
            )

        mutations = (
            ("app", lambda value: value["app"].__setitem__("id", 999)),
            (
                "candidate",
                lambda value: value.__setitem__("head_sha", "0" * 40),
            ),
            (
                "record",
                lambda value: value["output"].__setitem__(
                    "text", value["output"]["text"] + " "
                ),
            ),
        )
        for label, mutate in mutations:
            changed = copy.deepcopy(candidate_api_check)
            mutate(changed)
            with (
                self.subTest(label=label),
                mock.patch.object(
                    CI_MODULE,
                    "github_paginated_object_items",
                    side_effect=[[changed], [queue_api_check]],
                ),
                self.assertRaises(CI_MODULE.GateError),
            ):
                CI_MODULE.read_post_merge_admission_binding(
                    repository=repository,
                    repository_id=TEST_REPOSITORY_ID,
                    candidate_sha=candidate_sha,
                    candidate_ref="wip/session-retrospective-v2-history",
                    base_sha=base_sha,
                    pull_request_number=4,
                    pull_request_node_id=node_id,
                    merged_at=external["pull_request_merged_at"],
                    token="synthetic-read-token",
                )

        non_integer_schema = copy.deepcopy(queue_api_check)
        non_integer_admission = copy.deepcopy(admission)
        non_integer_admission["schema_version"] = 2.0
        non_integer_bytes = CI_MODULE.compact_json_bytes(non_integer_admission)
        non_integer_sha256 = hashlib.sha256(non_integer_bytes).hexdigest()
        non_integer_schema["external_id"] = (
            CI_MODULE.ADMISSION_RECORD_EXTERNAL_ID_PREFIX + non_integer_sha256
        )
        non_integer_schema["output"].update(
            {
                "summary": (
                    CI_MODULE.ADMISSION_RECORD_OUTPUT_SUMMARY_PREFIX
                    + non_integer_sha256
                ),
                "text": non_integer_bytes.decode("utf-8"),
            }
        )
        with (
            mock.patch.object(
                CI_MODULE,
                "github_paginated_object_items",
                side_effect=[[candidate_api_check], [non_integer_schema]],
            ),
            self.assertRaisesRegex(CI_MODULE.GateError, "schema|identity"),
        ):
            CI_MODULE.read_post_merge_admission_binding(
                repository=repository,
                repository_id=TEST_REPOSITORY_ID,
                candidate_sha=candidate_sha,
                candidate_ref="wip/session-retrospective-v2-history",
                base_sha=base_sha,
                pull_request_number=4,
                pull_request_node_id=node_id,
                merged_at=external["pull_request_merged_at"],
                token="synthetic-read-token",
            )

    def test_offline_admission_rejects_self_consistent_ref_and_title_drift(
        self,
    ) -> None:
        repository = TEST_REPOSITORY
        repository_id = TEST_REPOSITORY_ID
        base_sha = "b" * 40
        head_sha = "a" * 40
        candidate_sha = "d" * 40
        original = synthetic_external_admission(
            repository=repository,
            repository_id=repository_id,
            base_sha=base_sha,
            head_sha=head_sha,
            candidate_sha=candidate_sha,
            candidate_tree_sha="e" * 40,
            queue_tree_sha="f" * 40,
            pull_request_number=4,
            pull_request_node_id="PR_kwDOSyntheticReceipt",
            pull_request_title="Publish retained history",
        )
        mutations = (
            (
                "candidate ref",
                lambda admission: admission["snapshot"]["pull_request"].__setitem__(
                    "head_ref",
                    "wip/different-history-candidate",
                ),
            ),
            (
                "pull request title",
                lambda admission: admission["snapshot"]["pull_request"].__setitem__(
                    "title",
                    "Different retained history",
                ),
            ),
            (
                "projection subject",
                lambda admission: admission["projection"].__setitem__(
                    "squash_subject",
                    "Different retained history",
                ),
            ),
        )
        for label, mutate in mutations:
            changed = copy.deepcopy(original)
            binding = changed["admission_binding"]
            assert isinstance(binding, dict)
            admission = binding["admission"]
            assert isinstance(admission, dict)
            mutate(admission)
            rebind_synthetic_external_admission(changed)
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(
                    ValueError,
                    "transaction timing or scope differs",
                ),
            ):
                VALIDATOR_MODULE.validate_history_v2_candidate_evidence(
                    changed,
                    repository=repository,
                    repository_id=repository_id,
                    before_rev=base_sha,
                    head_rev=head_sha,
                )

    def test_offline_admission_rejects_candidate_signature_binding_drift(
        self,
    ) -> None:
        repository = TEST_REPOSITORY
        repository_id = TEST_REPOSITORY_ID
        base_sha = "b" * 40
        head_sha = "a" * 40
        candidate_sha = "d" * 40
        original = synthetic_external_admission(
            repository=repository,
            repository_id=repository_id,
            base_sha=base_sha,
            head_sha=head_sha,
            candidate_sha=candidate_sha,
            candidate_tree_sha="e" * 40,
            queue_tree_sha="f" * 40,
            pull_request_number=4,
            pull_request_node_id="PR_kwDOSyntheticReceipt",
            pull_request_title="Publish retained history",
        )
        mutations = (
            (
                "policy",
                lambda projection: projection["candidate_signature"].__setitem__(
                    "policy",
                    "bootstrap-v2",
                ),
                "candidate signature differs",
            ),
            (
                "key path",
                lambda projection: projection["candidate_signature"].__setitem__(
                    "key_path",
                    "retrospective-history-v2-admin-public.asc",
                ),
                "candidate signature differs",
            ),
            (
                "key digest",
                lambda projection: projection["candidate_signature"].__setitem__(
                    "key_sha256",
                    "f" * 64,
                ),
                "candidate signature differs",
            ),
            (
                "fingerprint format",
                lambda projection: projection["candidate_signature"].__setitem__(
                    "signer_fingerprint",
                    FIXTURE_SIGNER_FINGERPRINT.lower(),
                ),
                "candidate signature differs",
            ),
            (
                "legacy projection",
                lambda projection: projection.__setitem__("schema_version", 1),
                "admission projection differs",
            ),
        )
        for label, mutate, expected in mutations:
            changed = copy.deepcopy(original)
            binding = changed["admission_binding"]
            assert isinstance(binding, dict)
            admission = binding["admission"]
            assert isinstance(admission, dict)
            projection = admission["projection"]
            assert isinstance(projection, dict)
            mutate(projection)
            rebind_synthetic_external_admission(changed)
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(ValueError, expected),
            ):
                VALIDATOR_MODULE.validate_history_v2_candidate_evidence(
                    changed,
                    repository=repository,
                    repository_id=repository_id,
                    before_rev=base_sha,
                    head_rev=head_sha,
                )

    def test_only_trusted_base_is_checked_out_and_actions_are_pinned(self) -> None:
        action_steps = [step for step in workflow_job()["steps"] if "uses" in step]
        self.assertEqual(len(action_steps), 2)
        checkout, setup = action_steps
        self.assertEqual(checkout["name"], "Checkout exact trusted B0")
        self.assertEqual(checkout["with"]["path"], "trusted")
        self.assertEqual(checkout["with"]["ref"], "${{ env.TRUSTED_SHA }}")
        self.assertIs(checkout["with"]["persist-credentials"], False)
        self.assertNotIn("candidate", checkout["with"]["path"])
        self.assertEqual(
            setup["with"],
            {"python-version": "3.13.12", "cache": False},
        )
        control_binding = steps_by_name()["Bind trusted control Python"]["run"]
        self.assertIn(
            'control_version="$("$control_python" -I -B --version 2>&1)"',
            control_binding,
        )
        self.assertIn('[ "$control_version" != "Python 3.13.12" ]', control_binding)
        for step in action_steps:
            self.assertRegex(
                step["uses"], r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$"
            )

    def test_candidate_is_preflighted_before_blob_fetch_and_materialization(
        self,
    ) -> None:
        names = [step["name"] for step in workflow_job()["steps"]]
        ordered = (
            "Bind trusted control Python",
            "Fetch bounded bootstrap graph without checkout",
            "Preflight exact signed bootstrap H",
            "Materialize only preflight-bounded blobs",
            "Verify signature and materialize H as data",
            "Establish read-only H mount",
            "Validate B0/H candidate feedback",
            "Prepare sealed candidate runtime tree",
            "Install sealed candidate test dependencies",
            "Run sealed candidate compile and tests",
            "Verify candidate runtime authority remains pristine",
        )
        offsets = [names.index(name) for name in ordered]
        self.assertEqual(offsets, sorted(offsets))
        named = steps_by_name()
        metadata_fetch = named["Fetch bounded bootstrap graph without checkout"]["run"]
        blob_fetch = named["Materialize only preflight-bounded blobs"]["run"]
        materialize = named["Verify signature and materialize H as data"]["run"]
        self.assertIn("--filter=blob:none", metadata_fetch)
        self.assertIn('--depth=2 "$TRUSTED_ROOT"', metadata_fetch)
        self.assertIn(
            "authenticated_fetch --depth=3 --filter=blob:none",
            metadata_fetch,
        )
        self.assertIn("remote get-url", metadata_fetch)
        self.assertIn('remote remove "${remotes[0]}"', metadata_fetch)
        self.assertIn(
            "config --unset-all extensions.partialClone",
            metadata_fetch,
        )
        self.assertIn("clear_partial_clone()", metadata_fetch)
        self.assertNotIn("|| :", metadata_fetch)
        self.assertIn("materialize-blobs", blob_fetch)
        self.assertIn('--manifest "$PREFLIGHT_MANIFEST"', blob_fetch)
        self.assertNotIn("--filter=blob:limit", blob_fetch)
        self.assertNotIn("--refetch", blob_fetch)
        self.assertIn("verify-objects", materialize)
        self.assertLess(
            materialize.index("verify-objects"), materialize.index("worktree add")
        )

    def test_partial_clone_cleanup_distinguishes_absent_from_failure(self) -> None:
        cleanup_scripts: list[tuple[Path, str, str]] = []
        for workflow_path in (WORKFLOW, PERMANENT_CI):
            workflow = load_workflow(workflow_path)
            for job in workflow["jobs"].values():
                for step in job["steps"]:
                    script = step.get("run")
                    if isinstance(script, str) and "clear_partial_clone() {" in script:
                        cleanup_scripts.append((workflow_path, step["name"], script))
        self.assertEqual(len(cleanup_scripts), 2)

        for workflow_path, step_name, script in cleanup_scripts:
            with self.subTest(workflow=workflow_path.name, step=step_name):
                self.assertIn(
                    "config --unset-all extensions.partialClone",
                    script,
                )
                self.assertIn('[ "$cleanup_status" -ne 5 ]', script)
                self.assertIn("Partial clone cleanup failed.", script)
                self.assertNotIn("|| :", script)

    def test_candidate_code_executes_only_in_the_sealed_runtime_profile(self) -> None:
        for workflow_path in (WORKFLOW, PERMANENT_CI):
            with self.subTest(workflow=workflow_path.name):
                workflow = load_workflow(workflow_path)
                job = workflow["jobs"]["trusted_history_gate"]
                named = steps_by_name(job)
                run_scripts = "\n".join(
                    step["run"] for step in job["steps"] if "run" in step
                )
                for forbidden in (
                    "candidate/scripts/",
                    "$CANDIDATE_ROOT/scripts/",
                    "working-directory:",
                    "actions/cache",
                ):
                    self.assertNotIn(forbidden, run_scripts)
                validation = named["Validate B0/H candidate feedback"]["run"]
                expected_validator_python = (
                    '"$CONTROL_PYTHON" -I -B'
                    if workflow_path == WORKFLOW
                    else '"$TRUSTED_PYTHON" -I'
                )
                self.assertIn(expected_validator_python, validation)
                self.assertIn(
                    '"$TRUSTED_ROOT/scripts/validate_retained_history.py"',
                    validation,
                )
                candidate_root_argument = (
                    '--candidate-root "$CANDIDATE_ROOT"'
                    if workflow_path == WORKFLOW
                    else '--root "$CANDIDATE_ROOT"'
                )
                self.assertIn(candidate_root_argument, validation)
                self.assertIn("env -i", validation)
                self.assertNotIn("GH_TOKEN", validation)
                self.assertNotIn("GITHUB_TOKEN", validation)

                dependencies = named["Install sealed candidate test dependencies"][
                    "run"
                ]
                self.assertGreaterEqual(
                    dependencies.count("verify_runtime_python"),
                    3,
                )
                self.assertIn('readlink -f -- "$runtime_python"', dependencies)
                self.assertIn("/usr/bin/sha256sum", dependencies)
                self.assertIn("runtime_venv_config_sha256", dependencies)
                self.assertIn("chmod -R a-w", dependencies)
                self.assertIn("RUNTIME_TEST_PYTHON_TARGET", dependencies)
                self.assertIn("RUNTIME_TEST_PYTHON_SHA256", dependencies)
                self.assertIn("RUNTIME_TEST_VENV_CONFIG_SHA256", dependencies)

                runtime = named["Run sealed candidate compile and tests"]["run"]
                self.assertIn("sudo -u nobody --", runtime)
                self.assertIn("/usr/bin/env -i -C", runtime)
                self.assertIn(
                    '-I -B -X "pycache_prefix=$RUNTIME_PYCACHE_ROOT"',
                    runtime,
                )
                self.assertIn("-m compileall -q -f scripts tests", runtime)
                self.assertIn("-m unittest discover -s tests", runtime)
                self.assertIn("RUNTIME_TEST_PYTHON_TARGET", runtime)
                self.assertIn("RUNTIME_TEST_PYTHON_SHA256", runtime)
                self.assertIn("RUNTIME_TEST_VENV_CONFIG_SHA256", runtime)
                self.assertNotIn("PYTHONPYCACHEPREFIX=", runtime)
                self.assertNotIn("GH_TOKEN", runtime)
                self.assertNotIn("GITHUB_TOKEN", runtime)
                preparation = named["Prepare sealed candidate runtime tree"]["run"]
                self.assertIn("prepare-runtime-execution", preparation)
                self.assertIn("test ! -w", preparation)
                verification = named[
                    "Verify candidate runtime authority remains pristine"
                ]["run"]
                self.assertIn("verify-runtime-authority", verification)

    def test_network_and_validation_steps_have_explicit_resource_bounds(self) -> None:
        named = steps_by_name()
        for name in (
            "Fetch bounded bootstrap graph without checkout",
            "Materialize only preflight-bounded blobs",
            "Validate B0/H candidate feedback",
            "Install sealed candidate test dependencies",
            "Run sealed candidate compile and tests",
        ):
            script = named[name]["run"]
            self.assertIn("timeout --signal=TERM --kill-after=5s", script)
            self.assertIn("ulimit -f", script)
            self.assertIn("ulimit -n", script)
        validation = named["Validate B0/H candidate feedback"]["run"]
        self.assertIn("ulimit -t", validation)
        self.assertIn('>"$output" 2>&1', validation)
        self.assertIn('tail -n 120 "$output"', validation)

    def test_candidate_evidence_is_non_authoritative_and_has_no_commit_status(
        self,
    ) -> None:
        evidence = steps_by_name()["Publish bootstrap gate evidence"]
        script = evidence["run"]
        for identity in ("B0_SHA", "CANDIDATE_SHA"):
            self.assertIn(identity, script)
        self.assertIn("candidate feedback only", script)
        self.assertIn("external admission", script)
        self.assertIn("history authority CAS", script)
        self.assertIn("credential-free, nonprivileged compile and tests", script)
        for outcome in (
            "RUNTIME_PREPARE_OUTCOME",
            "RUNTIME_DEPENDENCIES_OUTCOME",
            "RUNTIME_TESTS_OUTCOME",
            "RUNTIME_AUTHORITY_OUTCOME",
        ):
            self.assertIn(f'[ "${outcome}" = success ]', script)
        self.assertNotIn("QUEUE_SHA", script)
        self.assertNotIn("finalize-merge-group", script)
        self.assertNotIn(" status \\", script)
        bind = steps_by_name()["Bind live PR"]["run"]
        self.assertIn("snapshot", bind)
        self.assertNotIn("merge-group-snapshot", bind)
        self.assertEqual(evidence["if"], "${{ always() }}")

    def test_success_summaries_report_only_event_specific_evidence(self) -> None:
        cases = (
            (WORKFLOW, "Publish bootstrap gate evidence", False),
            (PERMANENT_CI, "Publish gate evidence", True),
        )
        for workflow_path, step_name, has_role in cases:
            workflow = load_workflow(workflow_path)
            script = steps_by_name(workflow["jobs"]["trusted_history_gate"])[step_name][
                "run"
            ]
            with self.subTest(workflow=workflow_path.name):
                with tempfile.TemporaryDirectory() as raw:
                    temporary = Path(raw)
                    summary = temporary / "summary.md"
                    result = temporary / "result.json"
                    result.write_text(
                        json.dumps({"role": "publication"}) + "\n",
                        encoding="utf-8",
                    )
                    environment = {
                        **os.environ,
                        "B0_SHA": "a" * 40,
                        "CANDIDATE_SHA": "b" * 40,
                        "EVENT_KIND": "candidate",
                        "GITHUB_STEP_SUMMARY": str(summary),
                        "PREFLIGHT_OUTCOME": "success",
                        "RELEASE_OUTCOME": "success",
                        "RESULT_PATH": str(result),
                        "RUNTIME_AUTHORITY_OUTCOME": "success",
                        "RUNTIME_DEPENDENCIES_OUTCOME": "success",
                        "RUNTIME_PREPARE_OUTCOME": "success",
                        "RUNTIME_TESTS_OUTCOME": "success",
                        "VALIDATION_OUTCOME": "success",
                    }
                    completed = subprocess.run(
                        ["bash", "-c", script],
                        env=environment,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(
                        completed.returncode,
                        0,
                        completed.stderr,
                    )
                    rendered = summary.read_text(encoding="utf-8")
                    self.assertIn("candidate feedback only", rendered)
                    self.assertIn("external admission", rendered)
                    self.assertIn("history authority CAS", rendered)
                    self.assertNotIn("Queue base B1", rendered)
                    self.assertNotIn("merge-group authority", rendered)
                    if has_role:
                        self.assertIn(
                            "Validated role: `publication`",
                            rendered,
                        )

    def test_pull_request_payload_binds_identity_lifecycle_base_and_head(self) -> None:
        snapshot = validate_pull(pull_payload())
        self.assertEqual(snapshot.number, 17)
        self.assertEqual(snapshot.node_id, "PR_kwDO_bootstrap")
        self.assertEqual(snapshot.state, "open")
        self.assertIs(snapshot.merged, False)
        self.assertIsNone(snapshot.merged_at)
        self.assertIs(snapshot.draft, False)
        mutations = (
            ("number", lambda value: value.__setitem__("number", 18)),
            ("node", lambda value: value.__setitem__("node_id", "PR_other")),
            ("state", lambda value: value.__setitem__("state", "closed")),
            ("merged", lambda value: value.__setitem__("merged", True)),
            (
                "merged_at",
                lambda value: value.__setitem__("merged_at", "2026-07-23T00:00:00Z"),
            ),
            ("draft", lambda value: value.__setitem__("draft", True)),
            ("base", lambda value: value["base"].__setitem__("sha", "c" * 40)),
            ("head", lambda value: value["head"].__setitem__("sha", "d" * 40)),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                payload = copy.deepcopy(pull_payload())
                mutate(payload)
                with self.assertRaisesRegex(
                    CI_MODULE.GateError, "identity, lifecycle, base, or head"
                ):
                    validate_pull(payload)

    def test_validation_jobs_publish_no_commit_status_and_have_no_write_token(
        self,
    ) -> None:
        for workflow_path in (WORKFLOW, PERMANENT_CI):
            workflow = load_workflow(workflow_path)
            for name, job in workflow["jobs"].items():
                scripts = "\n".join(
                    step["run"] for step in job["steps"] if "run" in step
                )
                self.assertNotIn("/statuses/", scripts)
                self.assertFalse(
                    any(value == "write" for value in job["permissions"].values())
                )

    def test_policy_file_reads_protect_selected_filesystem_properties(self) -> None:
        readers = (
            (
                "authorization",
                CI_MODULE,
                "_read_policy_file_descriptor",
                lambda path: CI_MODULE.read_stable_policy_file(
                    path,
                    "authorization",
                    max_bytes=1024,
                ),
                CI_MODULE.GateError,
            ),
            (
                "signing key",
                VALIDATOR_MODULE,
                "_read_history_v2_policy_file_descriptor",
                lambda path: VALIDATOR_MODULE.read_history_v2_stable_policy_file(
                    path,
                    label="signing key",
                    max_bytes=1024,
                ),
                ValueError,
            ),
        )
        original_value = b'{"value":1}\n'
        replacement_value = b'{"value":2}\n'

        for label, module, helper_name, reader, error_type in readers:
            with self.subTest(reader=label, transition="benign metadata"):
                with tempfile.TemporaryDirectory() as raw:
                    path = Path(raw) / "policy.json"
                    path.write_bytes(original_value)
                    path.chmod(0o644)
                    helper = getattr(module, helper_name)
                    calls = 0

                    def benign_transition(
                        descriptor: int,
                        *,
                        max_bytes: int,
                    ) -> bytes:
                        nonlocal calls
                        value = helper(descriptor, max_bytes=max_bytes)
                        calls += 1
                        if calls == 1:
                            os.utime(path, ns=(1_700_000_000_000_000_000,) * 2)
                            path.chmod(0o600)
                        return value

                    with mock.patch.object(
                        module,
                        helper_name,
                        side_effect=benign_transition,
                    ):
                        self.assertEqual(reader(path), original_value)

            with self.subTest(reader=label, transition="replacement"):
                with tempfile.TemporaryDirectory() as raw:
                    directory = Path(raw)
                    path = directory / "policy.json"
                    replacement = directory / "replacement.json"
                    path.write_bytes(original_value)
                    helper = getattr(module, helper_name)
                    calls = 0

                    def replace_after_first_read(
                        descriptor: int,
                        *,
                        max_bytes: int,
                    ) -> bytes:
                        nonlocal calls
                        value = helper(descriptor, max_bytes=max_bytes)
                        calls += 1
                        if calls == 1:
                            replacement.write_bytes(original_value)
                            os.replace(replacement, path)
                        return value

                    with (
                        mock.patch.object(
                            module,
                            helper_name,
                            side_effect=replace_after_first_read,
                        ),
                        self.assertRaisesRegex(
                            error_type,
                            "object identity changed",
                        ),
                    ):
                        reader(path)

            with self.subTest(reader=label, transition="content"):
                with tempfile.TemporaryDirectory() as raw:
                    path = Path(raw) / "policy.json"
                    path.write_bytes(original_value)
                    helper = getattr(module, helper_name)
                    calls = 0

                    def mutate_after_first_read(
                        descriptor: int,
                        *,
                        max_bytes: int,
                    ) -> bytes:
                        nonlocal calls
                        value = helper(descriptor, max_bytes=max_bytes)
                        calls += 1
                        if calls == 1:
                            path.write_bytes(replacement_value)
                        return value

                    with (
                        mock.patch.object(
                            module,
                            helper_name,
                            side_effect=mutate_after_first_read,
                        ),
                        self.assertRaisesRegex(error_type, "content changed"),
                    ):
                        reader(path)

            with self.subTest(reader=label, transition="access policy"):
                with tempfile.TemporaryDirectory() as raw:
                    path = Path(raw) / "policy.json"
                    path.write_bytes(original_value)
                    path.chmod(0o600)
                    helper = getattr(module, helper_name)
                    calls = 0

                    def widen_after_first_read(
                        descriptor: int,
                        *,
                        max_bytes: int,
                    ) -> bytes:
                        nonlocal calls
                        value = helper(descriptor, max_bytes=max_bytes)
                        calls += 1
                        if calls == 1:
                            path.chmod(0o666)
                        return value

                    with (
                        mock.patch.object(
                            module,
                            helper_name,
                            side_effect=widen_after_first_read,
                        ),
                        self.assertRaisesRegex(
                            error_type,
                            "access policy changed",
                        ),
                    ):
                        reader(path)

            with self.subTest(reader=label, state="missing"):
                with tempfile.TemporaryDirectory() as raw:
                    with self.assertRaisesRegex(error_type, "is missing"):
                        reader(Path(raw) / "missing.json")

            with self.subTest(reader=label, state="unreadable"):
                with tempfile.TemporaryDirectory() as raw:
                    path = Path(raw) / "policy.json"
                    path.write_bytes(original_value)
                    with (
                        mock.patch.object(
                            module.os,
                            "open",
                            side_effect=PermissionError("denied"),
                        ),
                        self.assertRaisesRegex(error_type, "is unreadable"),
                    ):
                        reader(path)

    def test_in_repository_workflows_are_not_master_mutation_authority(self) -> None:
        for workflow_path in (WORKFLOW, PERMANENT_CI):
            workflow = load_workflow(workflow_path)
            self.assertNotIn("merge_group", workflow["on"])
            self.assertEqual(
                workflow["env"]["RETROSPECTIVE_HISTORY_MUTATION_MODEL"],
                "external-admission-cas-only",
            )
            gate = workflow["jobs"]["trusted_history_gate"]
            self.assertEqual(gate["name"], CI_MODULE.REQUIRED_CHECK_CONTEXT)
            expected_permissions = {
                "contents": "read",
                "pull-requests": "read",
            }
            self.assertEqual(
                gate["permissions"],
                expected_permissions,
            )
            for job in workflow["jobs"].values():
                self.assertFalse(
                    any(value == "write" for value in job["permissions"].values())
                )

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("must not handle `merge_group` events", readme)
        self.assertIn("an external admission service must be installed", readme)
        self.assertIn("merge-group-snapshot --repository-id", readme)
        self.assertIn("--admission-app-id", readme)
        self.assertIn("`admit-merge-group`", readme)
        self.assertIn("`--expected-python-sha256`", readme)
        self.assertIn("parent-owned runtime receipt", readme)
        self.assertIn("exact `Q` tree", readme)
        self.assertIn("must reread the live pull request, queue ref", readme)
        self.assertIn("30-second validity", readme)
        self.assertIn("full response bodies", readme)
        self.assertIn("starts before the first live read", readme)
        self.assertIn("GitHub Actions App is explicitly ineligible", readme)
        self.assertIn(
            "Until that external producer and receipt flow are proven, cutover is blocked",
            readme.replace("\n", " "),
        )

        workflow_text = "\n".join(
            (
                WORKFLOW.read_text(encoding="utf-8"),
                PERMANENT_CI.read_text(encoding="utf-8"),
            )
        )
        for prohibited in (
            "contents: write",
            "merge_group:",
            "finalize-merge-group",
            "CONFIG_READ_TOKEN",
            "QUEUE_SHA",
            "authorize-merge",
            "consume-merge",
            "force-with-lease",
            "exact-ref-updated",
            "already-converged",
        ):
            self.assertNotIn(prohibited, workflow_text)
        helper_text = CI_HELPER.read_text(encoding="utf-8")
        self.assertIn('subparsers.add_parser("admit-merge-group")', helper_text)
        self.assertIn('"--runtime-evidence"', helper_text)
        self.assertIn('"--admission-app-id"', helper_text)
        self.assertIn("revalidate_external_merge_group_authority", helper_text)
        for obsolete in (
            "create_merge_authorization",
            "consume_merge_authorization",
            "push_exact_authorized_ref",
        ):
            self.assertFalse(hasattr(CI_MODULE, obsolete))
        with (
            mock.patch.object(CI_MODULE.request, "urlopen") as urlopen,
            self.assertRaisesRegex(
                CI_MODULE.GateError,
                "mutation is prohibited",
            ),
        ):
            CI_MODULE.github_json(
                "PUT",
                TEST_REPOSITORY,
                "/git/refs/heads/master",
                token="synthetic",
                payload={"sha": "a" * 40},
            )
        urlopen.assert_not_called()

        with (
            mock.patch.object(
                CI_MODULE,
                "read_live_merge_group_snapshot",
            ) as live_snapshot,
            self.assertRaisesRegex(
                CI_MODULE.GateError,
                "in-repository merge-group authority is prohibited",
            ),
        ):
            CI_MODULE.verify_live_merge_group_authority(
                expected=mock.sentinel.snapshot,
                event_path=Path("/synthetic/event.json"),
                event_ref=merge_group_ref(),
                event_sha="c" * 40,
                workflow_sha="c" * 40,
                policy="history-v2",
                trusted_base_root=Path("/synthetic/trusted"),
                token="read-only",
            )
        live_snapshot.assert_not_called()

    def test_trusted_branch_configuration_is_exact_and_fail_closed(self) -> None:
        with mock.patch.object(
            CI_MODULE,
            "github_json",
            return_value=repository_configuration_payload(),
        ) as github_api:
            self.assertEqual(
                CI_MODULE.read_default_squash_configuration(
                    repository=TEST_REPOSITORY,
                    token="synthetic-read-token",
                ),
                {
                    "squash_merge_commit_title": "PR_TITLE",
                    "squash_merge_commit_message": "BLANK",
                },
            )
        github_api.assert_called_once_with(
            "GET",
            TEST_REPOSITORY,
            "/",
            token="synthetic-read-token",
        )

        digest = CI_MODULE.validate_trusted_branch_configuration(
            repository_payload=repository_configuration_payload(),
            active_rules_payload=active_branch_rules_payload(),
            protection_payload=branch_protection_payload(),
            ruleset_summaries=[],
            ruleset_details=[],
            repository=TEST_REPOSITORY,
            repository_id=TEST_REPOSITORY_ID,
            admission_app_id=TEST_ADMISSION_APP_ID,
        )
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

        with (
            mock.patch.object(
                CI_MODULE,
                "ADMISSION_RECORD_APP_ID",
                CI_MODULE.GITHUB_ACTIONS_APP_ID,
            ),
            self.assertRaisesRegex(
                CI_MODULE.GateError,
                "must not be GitHub Actions",
            ),
        ):
            CI_MODULE.validate_trusted_branch_configuration(
                repository_payload=repository_configuration_payload(),
                active_rules_payload=active_branch_rules_payload(
                    admission_app_id=CI_MODULE.GITHUB_ACTIONS_APP_ID,
                ),
                protection_payload=branch_protection_payload(
                    admission_app_id=CI_MODULE.GITHUB_ACTIONS_APP_ID,
                ),
                ruleset_summaries=[],
                ruleset_details=[],
                repository=TEST_REPOSITORY,
                repository_id=TEST_REPOSITORY_ID,
                admission_app_id=CI_MODULE.GITHUB_ACTIONS_APP_ID,
            )

        cases = []
        repository_identity = repository_configuration_payload()
        repository_identity["id"] = TEST_REPOSITORY_ID + 1
        cases.append(
            (
                "repository identity",
                repository_identity,
                active_branch_rules_payload(),
                branch_protection_payload(),
                [],
                [],
            )
        )
        repository = repository_configuration_payload()
        repository["allow_merge_commit"] = True
        cases.append(
            (
                "non-squash merge",
                repository,
                active_branch_rules_payload(),
                branch_protection_payload(),
                [],
                [],
            )
        )

        rules = active_branch_rules_payload()
        next(rule for rule in rules if rule["type"] == "merge_queue")["parameters"][
            "max_entries_to_merge"
        ] = 2
        cases.append(
            (
                "multi-PR queue",
                repository_configuration_payload(),
                rules,
                branch_protection_payload(),
                [],
                [],
            )
        )

        rules = active_branch_rules_payload()
        next(rule for rule in rules if rule["type"] == "merge_queue")["parameters"][
            "max_entries_to_build"
        ] = 2
        cases.append(
            (
                "multi-PR queue build",
                repository_configuration_payload(),
                rules,
                branch_protection_payload(),
                [],
                [],
            )
        )

        rules = active_branch_rules_payload()
        next(rule for rule in rules if rule["type"] == "required_status_checks")[
            "parameters"
        ]["required_status_checks"][0]["context"] = "stale check"
        cases.append(
            (
                "stale check",
                repository_configuration_payload(),
                rules,
                branch_protection_payload(),
                [],
                [],
            )
        )

        protection = branch_protection_payload()
        protection["allow_force_pushes"]["enabled"] = True
        cases.append(
            (
                "force push",
                repository_configuration_payload(),
                active_branch_rules_payload(),
                protection,
                [],
                [],
            )
        )

        protection = branch_protection_payload()
        del protection["required_pull_request_reviews"][
            "bypass_pull_request_allowances"
        ]
        cases.append(
            (
                "missing bypass allowances",
                repository_configuration_payload(),
                active_branch_rules_payload(),
                protection,
                [],
                [],
            )
        )
        protection = branch_protection_payload()
        del protection["required_pull_request_reviews"][
            "bypass_pull_request_allowances"
        ]["apps"]
        cases.append(
            (
                "missing bypass actor class",
                repository_configuration_payload(),
                active_branch_rules_payload(),
                protection,
                [],
                [],
            )
        )
        for label, allowances in (
            ("null bypass allowances", None),
            (
                "wrong bypass actor type",
                {"apps": {}, "teams": [], "users": []},
            ),
        ):
            protection = branch_protection_payload()
            protection["required_pull_request_reviews"][
                "bypass_pull_request_allowances"
            ] = allowances
            cases.append(
                (
                    label,
                    repository_configuration_payload(),
                    active_branch_rules_payload(),
                    protection,
                    [],
                    [],
                )
            )

        cases.append(
            (
                "bypass actor",
                repository_configuration_payload(),
                active_branch_rules_payload(),
                branch_protection_payload(),
                [{"id": 9}],
                [
                    {
                        "id": 9,
                        "enforcement": "active",
                        "bypass_actors": [{"actor_id": 1}],
                    }
                ],
            )
        )
        for label, repo, rules, protection, summaries, details in cases:
            with self.subTest(label=label), self.assertRaises(CI_MODULE.GateError):
                CI_MODULE.validate_trusted_branch_configuration(
                    repository_payload=repo,
                    active_rules_payload=rules,
                    protection_payload=protection,
                    ruleset_summaries=summaries,
                    ruleset_details=details,
                    repository=TEST_REPOSITORY,
                    repository_id=TEST_REPOSITORY_ID,
                    admission_app_id=TEST_ADMISSION_APP_ID,
                )

        with (
            mock.patch.object(
                CI_MODULE,
                "ADMISSION_RECORD_APP_ID",
                TEST_ADMISSION_APP_ID + 1,
            ),
            self.assertRaisesRegex(
                CI_MODULE.GateError,
                "required status check is not current-Q bound",
            ),
        ):
            CI_MODULE.validate_trusted_branch_configuration(
                repository_payload=repository_configuration_payload(),
                active_rules_payload=active_branch_rules_payload(),
                protection_payload=branch_protection_payload(),
                ruleset_summaries=[],
                ruleset_details=[],
                repository=TEST_REPOSITORY,
                repository_id=TEST_REPOSITORY_ID,
                admission_app_id=TEST_ADMISSION_APP_ID + 1,
            )

    def test_github_server_clock_is_repository_bound_and_second_precision(
        self,
    ) -> None:
        class Response:
            def __init__(
                self,
                *,
                date: str | None,
                full_name: str = TEST_REPOSITORY,
                repository_id: int = TEST_REPOSITORY_ID,
            ) -> None:
                self.status = 200
                self.headers = {} if date is None else {"Date": date}
                self._value = json.dumps(
                    {"full_name": full_name, "id": repository_id}
                ).encode("utf-8")
                self._socket = mock.Mock()
                self.fp = mock.Mock()
                self.fp.raw._sock = self._socket

            def __enter__(self) -> object:
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self, size: int) -> bytes:
                value, self._value = self._value[:size], self._value[size:]
                return value

        server_date = "Thu, 06 Aug 2026 17:30:00 GMT"
        with mock.patch.object(
            CI_MODULE.request,
            "urlopen",
            return_value=Response(date=server_date),
        ) as urlopen:
            observed = CI_MODULE.github_server_time(
                repository=TEST_REPOSITORY,
                repository_id=TEST_REPOSITORY_ID,
                token="synthetic-read-token",
            )
        self.assertEqual(
            observed,
            dt.datetime(2026, 8, 6, 17, 30, tzinfo=dt.timezone.utc),
        )
        request_value = urlopen.call_args.args[0]
        self.assertEqual(
            request_value.full_url,
            f"https://api.github.com/repos/{TEST_REPOSITORY}/",
        )
        self.assertEqual(request_value.get_method(), "GET")

        with (
            mock.patch.object(
                CI_MODULE.request,
                "urlopen",
                return_value=Response(date=None),
            ),
            self.assertRaisesRegex(CI_MODULE.GateError, "Date header"),
        ):
            CI_MODULE.github_server_time(
                repository=TEST_REPOSITORY,
                repository_id=TEST_REPOSITORY_ID,
                token="synthetic-read-token",
            )

        for response in (
            Response(
                date=server_date,
                full_name="Joey-Tools/lookalike-history",
            ),
            Response(
                date=server_date,
                repository_id=TEST_REPOSITORY_ID + 1,
            ),
        ):
            with (
                mock.patch.object(
                    CI_MODULE.request,
                    "urlopen",
                    return_value=response,
                ),
                self.assertRaisesRegex(CI_MODULE.GateError, "stale or lookalike"),
            ):
                CI_MODULE.github_server_time(
                    repository=TEST_REPOSITORY,
                    repository_id=TEST_REPOSITORY_ID,
                    token="synthetic-read-token",
                )

    def test_live_github_reads_share_request_byte_and_deadline_budgets(self) -> None:
        class Response:
            def __init__(
                self,
                value: bytes,
                *,
                clock: list[float] | None = None,
                clock_step: float | None = None,
                max_chunk: int | None = None,
            ) -> None:
                self.status = 200
                self.headers = {"Date": "Thu, 06 Aug 2026 17:30:00 GMT"}
                self._value = value
                self._clock = clock
                self._clock_step = clock_step
                self._max_chunk = max_chunk
                self.read_sizes: list[int] = []
                self._socket = mock.Mock()
                self.fp = mock.Mock()
                self.fp.raw._sock = self._socket

            def __enter__(self) -> object:
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self, size: int) -> bytes:
                self.read_sizes.append(size)
                if self._max_chunk is not None:
                    size = min(size, self._max_chunk)
                value, self._value = self._value[:size], self._value[size:]
                if value and self._clock is not None:
                    if self._clock_step is None:
                        self._clock[0] = 30.0
                    else:
                        self._clock[0] += self._clock_step
                return value

        monotonic = [0.0]
        deadline_budget = CI_MODULE.GitHubReadBudget(
            deadline=30.0,
            clock=lambda: monotonic[0],
        )
        with (
            mock.patch.object(
                CI_MODULE.request,
                "urlopen",
                return_value=Response(b"{}", clock=monotonic),
            ),
            CI_MODULE.github_read_budget_scope(deadline_budget),
            self.assertRaisesRegex(CI_MODULE.GateError, "deadline"),
        ):
            CI_MODULE.github_json(
                "GET",
                TEST_REPOSITORY,
                "/",
                token="synthetic-read-token",
            )

        request_budget = CI_MODULE.GitHubReadBudget(
            deadline=30.0,
            clock=lambda: 0.0,
            remaining_requests=1,
        )
        with (
            mock.patch.object(
                CI_MODULE.request,
                "urlopen",
                side_effect=[Response(b"{}")],
            ) as urlopen,
            CI_MODULE.github_read_budget_scope(request_budget),
        ):
            self.assertEqual(
                CI_MODULE.github_json(
                    "GET",
                    TEST_REPOSITORY,
                    "/",
                    token="synthetic-read-token",
                ),
                {},
            )
            with self.assertRaisesRegex(CI_MODULE.GateError, "request budget"):
                CI_MODULE.github_json(
                    "GET",
                    TEST_REPOSITORY,
                    "/rulesets/1",
                    token="synthetic-read-token",
                )
        self.assertEqual(urlopen.call_count, 1)

        slow_clock = [0.0]
        slow_response = Response(
            b"{}",
            clock=slow_clock,
            clock_step=11.0,
            max_chunk=1,
        )
        slow_budget = CI_MODULE.GitHubReadBudget(
            deadline=30.0,
            clock=lambda: slow_clock[0],
        )
        with (
            mock.patch.object(
                CI_MODULE.request,
                "urlopen",
                return_value=slow_response,
            ),
            CI_MODULE.github_read_budget_scope(slow_budget),
        ):
            self.assertEqual(
                CI_MODULE.github_json(
                    "GET",
                    TEST_REPOSITORY,
                    "/",
                    token="synthetic-read-token",
                ),
                {},
            )
        self.assertEqual(
            [call.args[0] for call in slow_response._socket.settimeout.call_args_list],
            [20.0, 19.0, 8.0],
        )

        byte_budget = CI_MODULE.GitHubReadBudget(
            deadline=30.0,
            clock=lambda: 0.0,
            remaining_bytes=1,
        )
        byte_response = Response(b"{}")
        with (
            mock.patch.object(
                CI_MODULE.request,
                "urlopen",
                return_value=byte_response,
            ),
            CI_MODULE.github_read_budget_scope(byte_budget),
            self.assertRaisesRegex(CI_MODULE.GateError, "byte budget"),
        ):
            CI_MODULE.github_json(
                "GET",
                TEST_REPOSITORY,
                "/",
                token="synthetic-read-token",
            )
        self.assertEqual(byte_response.read_sizes, [2])

    def test_merge_group_event_proves_exact_single_pr_queue_coordinates(self) -> None:
        base = "b" * 40
        queue = "c" * 40
        payload = merge_group_event_payload(base_sha=base, queue_sha=queue)
        self.assertEqual(
            CI_MODULE.validate_merge_group_event(
                payload,
                repository=TEST_REPOSITORY,
                repository_id=TEST_REPOSITORY_ID,
                event_ref=merge_group_ref(),
                event_sha=queue,
                workflow_sha=queue,
            ),
            (17, base, queue),
        )
        with self.assertRaisesRegex(CI_MODULE.GateError, "exact B1/Q pair"):
            CI_MODULE.validate_merge_group_event(
                payload,
                repository=TEST_REPOSITORY,
                repository_id=TEST_REPOSITORY_ID,
                event_ref=merge_group_ref(),
                event_sha=queue,
                workflow_sha=base,
            )
        mutations = (
            ("action", lambda value: value.__setitem__("action", "destroyed")),
            (
                "repository identity",
                lambda value: value["repository"].__setitem__(
                    "id",
                    TEST_REPOSITORY_ID + 1,
                ),
            ),
            (
                "base ref",
                lambda value: value["merge_group"].__setitem__(
                    "base_ref",
                    "refs/heads/release",
                ),
            ),
            (
                "queue ref",
                lambda value: value["merge_group"].__setitem__(
                    "head_ref",
                    "refs/heads/gh-readonly-queue/master/pr-17-a/pr-18-b",
                ),
            ),
            (
                "queue sha",
                lambda value: value["merge_group"].__setitem__(
                    "head_sha",
                    "d" * 40,
                ),
            ),
        )
        for label, mutate in mutations:
            changed = copy.deepcopy(payload)
            mutate(changed)
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(
                    CI_MODULE.GateError,
                    "exact B1/Q pair",
                ),
            ):
                CI_MODULE.validate_merge_group_event(
                    changed,
                    repository=TEST_REPOSITORY,
                    repository_id=TEST_REPOSITORY_ID,
                    event_ref=merge_group_ref(),
                    event_sha=queue,
                    workflow_sha=queue,
                )

    def test_merge_group_snapshot_loader_requires_queue_workflow_sha(self) -> None:
        snapshot = CI_MODULE.MergeGroupSnapshot(
            repository=TEST_REPOSITORY,
            repository_id=TEST_REPOSITORY_ID,
            base_ref="refs/heads/master",
            base_sha="b" * 40,
            queue_ref=merge_group_ref(),
            queue_sha="c" * 40,
            workflow_sha="c" * 40,
            pull_request_number=17,
            pull_request_node_id="PR_kwDO_bootstrap",
            pull_request_title="Publish retained history",
            candidate_ref="wip/history-publication",
            candidate_sha="a" * 40,
            required_check=CI_MODULE.REQUIRED_CHECK_CONTEXT,
            tcb_sha256="d" * 64,
        )
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "snapshot.json"
            payload = snapshot.as_dict()
            path.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(CI_MODULE.load_merge_group_snapshot(path), snapshot)

            payload["workflow_sha"] = snapshot.base_sha
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "coordinates are invalid",
            ):
                CI_MODULE.load_merge_group_snapshot(path)

    def test_get_to_queue_mutation_lifecycle_races_fail_without_a_writer(
        self,
    ) -> None:
        base = "b" * 40
        head = "a" * 40
        valid = merge_group_pull_payload(
            base_sha=base,
            head_sha=head,
            title="Publish retained history",
        )
        CI_MODULE.validate_merge_group_pull_request(
            valid,
            repository=TEST_REPOSITORY,
            repository_id=TEST_REPOSITORY_ID,
            number=17,
            base_sha=base,
        )
        mutations = (
            (
                "closed",
                "not open",
                lambda value: value.__setitem__("state", "closed"),
            ),
            (
                "draft",
                "is draft",
                lambda value: value.__setitem__("draft", True),
            ),
            (
                "retargeted",
                "base changed",
                lambda value: value["base"].__setitem__("ref", "release"),
            ),
            (
                "head repository changed",
                "head changed",
                lambda value: value["head"]["repo"].__setitem__(
                    "full_name",
                    "Joey-Tools/other",
                ),
            ),
            (
                "base repository identity changed",
                "base changed",
                lambda value: value["base"]["repo"].__setitem__(
                    "id",
                    TEST_REPOSITORY_ID + 1,
                ),
            ),
            (
                "head repository identity changed",
                "head changed",
                lambda value: value["head"]["repo"].__setitem__(
                    "id",
                    TEST_REPOSITORY_ID + 1,
                ),
            ),
        )
        for label, expected, mutate in mutations:
            changed = copy.deepcopy(valid)
            mutate(changed)
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(
                    CI_MODULE.GateError,
                    expected,
                ),
            ):
                CI_MODULE.validate_merge_group_pull_request(
                    changed,
                    repository=TEST_REPOSITORY,
                    repository_id=TEST_REPOSITORY_ID,
                    number=17,
                    base_sha=base,
                )

        with tempfile.TemporaryDirectory() as raw:
            event_path = Path(raw) / "event.json"
            event_path.write_text(
                json.dumps(
                    merge_group_event_payload(
                        base_sha=base,
                        queue_sha="c" * 40,
                    )
                ),
                encoding="utf-8",
            )
            with mock.patch.object(
                CI_MODULE,
                "github_json",
                side_effect=[
                    valid,
                    live_merge_group_ref_payload(queue_sha="c" * 40),
                    repository_configuration_payload(),
                    active_branch_rules_payload(),
                    branch_protection_payload(),
                    [],
                ],
            ) as github_api:
                observed = CI_MODULE.read_live_merge_group_snapshot(
                    repository=TEST_REPOSITORY,
                    repository_id=TEST_REPOSITORY_ID,
                    event_path=event_path,
                    event_ref=merge_group_ref(),
                    event_sha="c" * 40,
                    workflow_sha="c" * 40,
                    admission_app_id=TEST_ADMISSION_APP_ID,
                    token="read-only",
                )
            self.assertEqual(observed.repository_id, TEST_REPOSITORY_ID)
            self.assertEqual(observed.pull_request_number, 17)
            self.assertEqual(
                github_api.call_args_list[2],
                mock.call("GET", TEST_REPOSITORY, "/", token="read-only"),
            )
            with (
                mock.patch.object(
                    CI_MODULE,
                    "github_json",
                    side_effect=CI_MODULE.GateError("synthetic 404"),
                ),
                self.assertRaisesRegex(
                    CI_MODULE.GateError,
                    "pull request is unavailable",
                ),
            ):
                CI_MODULE.read_live_merge_group_snapshot(
                    repository=TEST_REPOSITORY,
                    repository_id=TEST_REPOSITORY_ID,
                    event_path=event_path,
                    event_ref=merge_group_ref(),
                    event_sha="c" * 40,
                    workflow_sha="c" * 40,
                    admission_app_id=TEST_ADMISSION_APP_ID,
                    token="read-only",
                )

    def test_external_admission_revalidates_live_authority_after_runtime(
        self,
    ) -> None:
        snapshot = CI_MODULE.MergeGroupSnapshot(
            repository=TEST_REPOSITORY,
            repository_id=TEST_REPOSITORY_ID,
            base_ref="refs/heads/master",
            base_sha="b" * 40,
            queue_ref=merge_group_ref(),
            queue_sha="c" * 40,
            workflow_sha="c" * 40,
            pull_request_number=17,
            pull_request_node_id="PR_kwDO_bootstrap",
            pull_request_title="Publish retained history",
            candidate_ref="wip/history-publication",
            candidate_sha="a" * 40,
            required_check=CI_MODULE.REQUIRED_CHECK_CONTEXT,
            tcb_sha256="d" * 64,
        )
        projection = synthetic_merge_group_projection(snapshot)
        parent_sha = "9" * 40
        audit = synthetic_predecessor_audit(
            base_sha=snapshot.base_sha,
            parent_sha=parent_sha,
        )
        observed_at = dt.datetime(2026, 8, 6, 17, 30, tzinfo=dt.timezone.utc)

        def invoke(
            *,
            live_result: object = snapshot,
            live_error: Exception | None = None,
            audit_error: Exception | None = None,
            times: tuple[dt.datetime, ...] = (observed_at, observed_at),
            monotonic_times: tuple[float, ...] = (0.0, 0.0),
        ) -> tuple[object, object, object]:
            clock_values = iter(times)
            monotonic_values = iter(monotonic_times)
            with (
                mock.patch.object(
                    CI_MODULE,
                    "_predecessor_authority_context",
                    return_value=(parent_sha, (), None),
                ),
                mock.patch.object(CI_MODULE, "_worktree_head"),
                mock.patch.object(
                    CI_MODULE,
                    "read_live_merge_group_snapshot",
                    return_value=live_result,
                    side_effect=live_error,
                ) as live_snapshot,
                mock.patch.object(
                    CI_MODULE,
                    "read_trusted_predecessor_audit_evidence",
                    return_value=audit,
                    side_effect=audit_error,
                ) as predecessor_audit,
            ):
                evidence = CI_MODULE.revalidate_external_merge_group_authority(
                    expected=snapshot,
                    projection=projection,
                    policy="history-v2",
                    trusted_base_root=Path("/synthetic/trusted-base"),
                    event_path=Path("/synthetic/event.json"),
                    event_ref=snapshot.queue_ref,
                    event_sha=snapshot.queue_sha,
                    workflow_sha=snapshot.workflow_sha,
                    admission_app_id=TEST_ADMISSION_APP_ID,
                    token="read-only",
                    clock=lambda: next(clock_values),
                    monotonic_clock=lambda: next(monotonic_values),
                )
            return evidence, live_snapshot, predecessor_audit

        evidence, live_snapshot, predecessor_audit = invoke()
        live_snapshot.assert_called_once_with(
            repository=snapshot.repository,
            repository_id=snapshot.repository_id,
            event_path=Path("/synthetic/event.json"),
            event_ref=snapshot.queue_ref,
            event_sha=snapshot.queue_sha,
            workflow_sha=snapshot.workflow_sha,
            admission_app_id=TEST_ADMISSION_APP_ID,
            token="read-only",
        )
        predecessor_audit.assert_called_once_with(
            repository=snapshot.repository,
            base_sha=snapshot.base_sha,
            parent_sha=parent_sha,
            current_pr_number=snapshot.pull_request_number,
            token="read-only",
        )
        self.assertEqual(evidence.tcb_sha256, snapshot.tcb_sha256)
        self.assertEqual(
            evidence.predecessor_authority.audit,
            audit,
        )
        self.assertEqual(
            evidence.snapshot_sha256,
            hashlib.sha256(
                CI_MODULE.compact_json_bytes(snapshot.as_dict())
            ).hexdigest(),
        )
        _observed_text, observed_time = CI_MODULE.canonical_github_timestamp(
            evidence.observed_at,
            "test observation",
        )
        _valid_text, valid_until = CI_MODULE.canonical_github_timestamp(
            evidence.valid_until,
            "test expiration",
        )
        self.assertEqual(
            valid_until - observed_time,
            dt.timedelta(seconds=CI_MODULE.MERGE_GROUP_LIVE_AUTHORITY_TTL_SECONDS),
        )

        fractional = observed_at.replace(microsecond=800_000)
        fractional_evidence, _live_snapshot, _predecessor_audit = invoke(
            times=(fractional, fractional.replace(microsecond=900_000)),
        )
        self.assertEqual(
            fractional_evidence.observed_at,
            observed_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
        )
        noncanonical_time = fractional_evidence.as_dict()
        noncanonical_time["observed_at"] = noncanonical_time["observed_at"].replace(
            "Z", ".0Z"
        )
        with self.assertRaisesRegex(CI_MODULE.GateError, "precision"):
            CI_MODULE.parse_merge_group_live_authority(noncanonical_time)

        with self.assertRaisesRegex(
            CI_MODULE.GateError,
            "revalidation exceeded its window",
        ):
            invoke(
                times=(
                    observed_at,
                    observed_at
                    + dt.timedelta(
                        seconds=CI_MODULE.MERGE_GROUP_LIVE_AUTHORITY_TTL_SECONDS
                    ),
                ),
            )

        with self.assertRaisesRegex(CI_MODULE.GateError, "deadline"):
            invoke(monotonic_times=(0.0, 30.0))

        for field, value in (
            ("pull_request_title", "Changed after runtime"),
            ("queue_ref", merge_group_ref().replace("queue", "changed")),
            ("tcb_sha256", "e" * 64),
        ):
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    CI_MODULE.GateError,
                    "changed after runtime validation",
                ),
            ):
                invoke(
                    live_result=type(snapshot)(
                        **{**snapshot.__dict__, field: value},
                    )
                )

        with self.assertRaisesRegex(
            CI_MODULE.GateError,
            "could not be revalidated after runtime",
        ):
            invoke(
                live_error=CI_MODULE.GateError("queue ref missing"),
                times=(observed_at,),
            )

        with self.assertRaisesRegex(
            CI_MODULE.GateError,
            "predecessor audit evidence is missing",
        ):
            invoke(
                audit_error=CI_MODULE.GateError(
                    "predecessor audit evidence is missing"
                ),
                times=(observed_at,),
            )

    def test_predecessor_authority_context_allows_only_closed_migration_exception(
        self,
    ) -> None:
        snapshot = CI_MODULE.MergeGroupSnapshot(
            repository=TEST_REPOSITORY,
            repository_id=TEST_REPOSITORY_ID,
            base_ref="refs/heads/master",
            base_sha="b" * 40,
            queue_ref=merge_group_ref(),
            queue_sha="c" * 40,
            workflow_sha="c" * 40,
            pull_request_number=17,
            pull_request_node_id="PR_kwDO_bootstrap",
            pull_request_title="Publish retained history",
            candidate_ref="wip/history-publication",
            candidate_sha="a" * 40,
            required_check=CI_MODULE.REQUIRED_CHECK_CONTEXT,
            tcb_sha256="d" * 64,
        )
        projection = synthetic_merge_group_projection(snapshot)
        validator = mock.Mock()
        validator.history_v2_bootstrap_markers.return_value = frozenset()
        with (
            mock.patch.object(
                CI_MODULE,
                "trusted_validator_module",
                return_value=validator,
            ) as trusted_validator,
            mock.patch.object(CI_MODULE, "_worktree_head") as worktree_head,
            mock.patch.object(
                CI_MODULE,
                "_single_worktree_parent",
                return_value="9" * 40,
            ) as single_parent,
        ):
            self.assertEqual(
                CI_MODULE._predecessor_authority_context(
                    expected=snapshot,
                    projection=projection,
                    policy="history-v2",
                    trusted_base_root=Path("/synthetic/trusted-base"),
                ),
                ("9" * 40, (), None),
            )
        trusted_validator.assert_called_once_with(contract="permanent")
        worktree_head.assert_called_once()
        single_parent.assert_called_once()

        bootstrap_snapshot = type(snapshot)(
            **{
                **snapshot.__dict__,
                "candidate_ref": CI_MODULE.BOOTSTRAP_CANDIDATE_REF,
            }
        )
        bootstrap_projection = synthetic_merge_group_projection(
            bootstrap_snapshot,
            policy="bootstrap-v2",
            role="admin",
        )
        validator.history_v2_bootstrap_admission_app_id.return_value = (
            TEST_ADMISSION_APP_ID
        )
        validator.HISTORY_V2_ADMISSION_RECORD_APP_SLUG = (
            CI_MODULE.ADMISSION_RECORD_APP_SLUG
        )
        validator.history_v2_bootstrap_markers.return_value = frozenset(
            Path(path) for path in CI_MODULE.BOOTSTRAP_TEMPORARY_PATHS
        )
        with (
            mock.patch.object(
                CI_MODULE,
                "trusted_validator_module",
                return_value=validator,
            ),
            mock.patch.object(CI_MODULE, "_worktree_head"),
            mock.patch.object(CI_MODULE, "_single_worktree_parent") as single_parent,
        ):
            parent, markers, marker_sha256 = CI_MODULE._predecessor_authority_context(
                expected=bootstrap_snapshot,
                projection=bootstrap_projection,
                policy="bootstrap-v2",
                trusted_base_root=Path("/synthetic/trusted-base"),
            )
        self.assertIsNone(parent)
        self.assertEqual(markers, tuple(sorted(CI_MODULE.BOOTSTRAP_TEMPORARY_PATHS)))
        self.assertRegex(marker_sha256, r"^[0-9a-f]{64}$")
        single_parent.assert_not_called()

        for helper_app_id, validator_app_id, validator_slug, expected_error in (
            (
                None,
                TEST_ADMISSION_APP_ID,
                CI_MODULE.ADMISSION_RECORD_APP_SLUG,
                "requires a configured admission App ID",
            ),
            (
                TEST_ADMISSION_APP_ID,
                TEST_ADMISSION_APP_ID + 1,
                CI_MODULE.ADMISSION_RECORD_APP_SLUG,
                "trusted bootstrap admission App identity differs",
            ),
            (
                TEST_ADMISSION_APP_ID,
                TEST_ADMISSION_APP_ID,
                "lookalike-admission",
                "trusted bootstrap admission App identity differs",
            ),
        ):
            with (
                self.subTest(
                    helper_app_id=helper_app_id,
                    validator_app_id=validator_app_id,
                    validator_slug=validator_slug,
                ),
                mock.patch.object(
                    CI_MODULE,
                    "ADMISSION_RECORD_APP_ID",
                    helper_app_id,
                ),
                mock.patch.object(
                    CI_MODULE,
                    "trusted_validator_module",
                    return_value=validator,
                ),
                mock.patch.object(CI_MODULE, "_worktree_head"),
                self.assertRaisesRegex(CI_MODULE.GateError, expected_error),
            ):
                validator.history_v2_bootstrap_admission_app_id.return_value = (
                    validator_app_id
                )
                validator.HISTORY_V2_ADMISSION_RECORD_APP_SLUG = validator_slug
                CI_MODULE._predecessor_authority_context(
                    expected=bootstrap_snapshot,
                    projection=bootstrap_projection,
                    policy="bootstrap-v2",
                    trusted_base_root=Path("/synthetic/trusted-base"),
                )
        validator.history_v2_bootstrap_admission_app_id.return_value = (
            TEST_ADMISSION_APP_ID
        )
        validator.HISTORY_V2_ADMISSION_RECORD_APP_SLUG = (
            CI_MODULE.ADMISSION_RECORD_APP_SLUG
        )

        invalid_bootstrap_snapshot = type(bootstrap_snapshot)(
            **{
                **bootstrap_snapshot.__dict__,
                "candidate_ref": "wip/lookalike-bootstrap",
            }
        )
        with (
            mock.patch.object(
                CI_MODULE,
                "trusted_validator_module",
                return_value=validator,
            ),
            mock.patch.object(CI_MODULE, "_worktree_head"),
            self.assertRaisesRegex(
                CI_MODULE.GateError,
                "migration exception is invalid",
            ),
        ):
            CI_MODULE._predecessor_authority_context(
                expected=invalid_bootstrap_snapshot,
                projection=bootstrap_projection,
                policy="bootstrap-v2",
                trusted_base_root=Path("/synthetic/trusted-base"),
            )

    def test_external_admission_revalidates_live_authority_after_runtime_order(
        self,
    ) -> None:
        snapshot = mock.sentinel.snapshot
        projection = mock.sentinel.projection
        runtime_evidence = mock.sentinel.runtime_evidence
        live_authority = mock.sentinel.live_authority
        calls: list[str] = []

        with (
            mock.patch.object(
                CI_MODULE,
                "load_merge_group_snapshot",
                return_value=snapshot,
            ),
            mock.patch.object(
                CI_MODULE,
                "validate_merge_group_transaction",
                return_value=projection,
            ),
            mock.patch.object(
                CI_MODULE,
                "load_merge_group_runtime_evidence",
                return_value=runtime_evidence,
            ),
            mock.patch.object(
                CI_MODULE,
                "validate_merge_group_runtime_evidence",
                side_effect=lambda **_kwargs: calls.append("runtime"),
            ),
            mock.patch.object(
                CI_MODULE,
                "revalidate_external_merge_group_authority",
                side_effect=lambda **_kwargs: (calls.append("live") or live_authority),
            ),
            mock.patch.object(
                CI_MODULE,
                "merge_group_admission_payload",
                side_effect=lambda **_kwargs: (
                    calls.append("payload") or {"decision": "accepted"}
                ),
            ),
            mock.patch.object(
                CI_MODULE,
                "write_json",
                side_effect=lambda *_args, **_kwargs: calls.append("write"),
            ),
            mock.patch.dict(os.environ, {"GH_TOKEN": "read-only"}),
        ):
            result = CI_MODULE.main(
                [
                    "admit-merge-group",
                    "--snapshot",
                    "/synthetic/snapshot.json",
                    "--git-dir",
                    "/synthetic/repo.git",
                    "--candidate-root",
                    "/synthetic/candidate",
                    "--queue-root",
                    "/synthetic/queue",
                    "--policy",
                    "history-v2",
                    "--trusted-base-root",
                    "/synthetic/trusted-base",
                    "--runtime-evidence",
                    "/synthetic/runtime.json",
                    "--expected-python-sha256",
                    "a" * 64,
                    "--event-path",
                    "/synthetic/event.json",
                    "--event-ref",
                    merge_group_ref(),
                    "--event-sha",
                    "c" * 40,
                    "--workflow-sha",
                    "c" * 40,
                    "--admission-app-id",
                    str(TEST_ADMISSION_APP_ID),
                    "--output",
                    "/synthetic/admission.json",
                ]
            )
        self.assertEqual(result, 0)
        self.assertEqual(calls, ["runtime", "live", "payload", "write"])

    def test_predecessor_audit_fuse_requires_exact_external_evidence(
        self,
    ) -> None:
        base = "b" * 40
        parent = "a" * 40
        candidate = "c" * 40
        payloads = predecessor_audit_payloads(
            base_sha=base,
            parent_sha=parent,
            candidate_sha=candidate,
        )

        def github_payload(
            _method: str,
            _repository: str,
            route: str,
            *,
            token: str,
        ) -> dict:
            self.assertEqual(token, "read-only")
            if route == "/pulls/16":
                return payloads["pull"]
            if route == "/actions/runs/701":
                return payloads["run"]
            raise AssertionError(f"unexpected route: {route}")

        def object_inventory(**kwargs: object) -> list[dict]:
            item_key = kwargs["item_key"]
            if item_key == "check_runs":
                return [payloads["check"]]
            if item_key == "jobs":
                return [payloads["job"]]
            raise AssertionError(f"unexpected item key: {item_key}")

        with (
            mock.patch.object(
                CI_MODULE,
                "github_paginated_list",
                return_value=[payloads["associated"]],
            ),
            mock.patch.object(
                CI_MODULE,
                "github_paginated_object_items",
                side_effect=object_inventory,
            ),
            mock.patch.object(
                CI_MODULE,
                "github_json",
                side_effect=github_payload,
            ),
        ):
            evidence = CI_MODULE.read_trusted_predecessor_audit_evidence(
                repository=TEST_REPOSITORY,
                base_sha=base,
                parent_sha=parent,
                current_pr_number=17,
                token="read-only",
            )
        self.assertEqual(evidence.base_sha, base)
        self.assertEqual(evidence.parent_sha, parent)
        self.assertEqual(evidence.candidate_sha, candidate)
        self.assertRegex(evidence.sha256, r"^[0-9a-f]{64}$")

        cases: list[tuple[str, str, list[dict], list[dict]]] = []
        cases.append(("missing", "missing", [], [payloads["job"]]))
        cases.append(
            (
                "ambiguous",
                "ambiguous",
                [payloads["check"], copy.deepcopy(payloads["check"])],
                [payloads["job"]],
            )
        )
        for label, field, replacement, expected in (
            ("failed", "conclusion", "failure", "failed"),
            ("nonterminal", "status", "in_progress", "nonterminal"),
            ("stale", "head_sha", "d" * 40, "stale"),
        ):
            changed = copy.deepcopy(payloads["check"])
            changed[field] = replacement
            changed_job = copy.deepcopy(payloads["job"])
            if field == "conclusion":
                changed_job[field] = replacement
            cases.append((label, expected, [changed], [changed_job]))
        lookalike = copy.deepcopy(payloads["check"])
        lookalike["app"]["slug"] = "lookalike-actions"
        cases.append(("lookalike", "lookalike", [lookalike], [payloads["job"]]))

        for label, expected, checks, jobs in cases:

            def changed_inventory(
                *,
                item_key: str,
                **_kwargs: object,
            ) -> list[dict]:
                return checks if item_key == "check_runs" else jobs

            with (
                self.subTest(label=label),
                mock.patch.object(
                    CI_MODULE,
                    "github_paginated_list",
                    return_value=[payloads["associated"]],
                ),
                mock.patch.object(
                    CI_MODULE,
                    "github_paginated_object_items",
                    side_effect=changed_inventory,
                ),
                mock.patch.object(
                    CI_MODULE,
                    "github_json",
                    side_effect=github_payload,
                ),
                self.assertRaisesRegex(CI_MODULE.GateError, expected),
            ):
                CI_MODULE.read_trusted_predecessor_audit_evidence(
                    repository=TEST_REPOSITORY,
                    base_sha=base,
                    parent_sha=parent,
                    current_pr_number=17,
                    token="read-only",
                )

    def test_predecessor_audit_selects_one_exact_successful_rerun_attempt(
        self,
    ) -> None:
        base = "b" * 40
        parent = "a" * 40
        candidate = "c" * 40
        payloads = predecessor_audit_payloads(
            base_sha=base,
            parent_sha=parent,
            candidate_sha=candidate,
        )
        first_check = copy.deepcopy(payloads["check"])
        first_check["conclusion"] = "failure"
        first_job = copy.deepcopy(payloads["job"])
        first_job["conclusion"] = "failure"

        second_check = copy.deepcopy(payloads["check"])
        second_check.update(
            {
                "id": 502,
                "node_id": "CR_kwDO_predecessor_retry",
                "started_at": "2026-07-15T00:06:00Z",
                "completed_at": "2026-07-15T00:08:00Z",
                "details_url": (
                    f"https://github.com/{TEST_REPOSITORY}/actions/runs/701/job/802"
                ),
            }
        )
        second_job = copy.deepcopy(payloads["job"])
        second_job.update(
            {
                "id": 802,
                "run_attempt": 2,
                "started_at": "2026-07-15T00:06:30Z",
                "completed_at": "2026-07-15T00:07:30Z",
                "html_url": second_check["details_url"],
                "check_run_url": (
                    f"https://api.github.com/repos/{TEST_REPOSITORY}/check-runs/502"
                ),
            }
        )
        rerun = copy.deepcopy(payloads["run"])
        rerun.update(
            {
                "run_attempt": 2,
                "run_started_at": "2026-07-15T00:06:00Z",
                "updated_at": "2026-07-15T00:09:00Z",
            }
        )

        def github_payload(
            _method: str,
            _repository: str,
            route: str,
            *,
            token: str,
        ) -> dict:
            self.assertEqual(token, "read-only")
            if route == "/pulls/16":
                return payloads["pull"]
            if route == "/actions/runs/701":
                return rerun
            raise AssertionError(f"unexpected route: {route}")

        def read_evidence(
            checks: list[dict],
            jobs: list[dict],
        ) -> CI_MODULE.PredecessorAuditEvidence:
            def object_inventory(**kwargs: object) -> list[dict]:
                return checks if kwargs["item_key"] == "check_runs" else jobs

            with (
                mock.patch.object(
                    CI_MODULE,
                    "github_paginated_list",
                    return_value=[payloads["associated"]],
                ),
                mock.patch.object(
                    CI_MODULE,
                    "github_paginated_object_items",
                    side_effect=object_inventory,
                ),
                mock.patch.object(
                    CI_MODULE,
                    "github_json",
                    side_effect=github_payload,
                ),
            ):
                return CI_MODULE.read_trusted_predecessor_audit_evidence(
                    repository=TEST_REPOSITORY,
                    base_sha=base,
                    parent_sha=parent,
                    current_pr_number=17,
                    token="read-only",
                )

        evidence = read_evidence(
            [first_check, second_check],
            [first_job, second_job],
        )
        self.assertEqual(evidence.workflow_run_attempt, 2)
        self.assertEqual(evidence.check_run_id, 502)
        self.assertEqual(evidence.job_id, 802)

        duplicate_attempt = copy.deepcopy(first_job)
        duplicate_attempt["run_attempt"] = 2
        malformed_cases = (
            (
                "duplicate attempt",
                [first_check, second_check],
                [duplicate_attempt, second_job],
                "ambiguous",
            ),
            (
                "missing first attempt",
                [second_check],
                [second_job],
                "incomplete or ambiguous",
            ),
            (
                "cross-attempt association",
                [first_check, second_check],
                [
                    first_job,
                    {
                        **second_job,
                        "check_run_url": first_job["check_run_url"],
                    },
                ],
                "ambiguous",
            ),
        )
        for label, checks, jobs, expected in malformed_cases:
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(
                    CI_MODULE.GateError,
                    expected,
                ),
            ):
                read_evidence(checks, jobs)

    def test_predecessor_evidence_pagination_is_exact_and_terminal(
        self,
    ) -> None:
        item = {"id": 501}
        with mock.patch.object(
            CI_MODULE,
            "github_json",
            side_effect=(
                {"total_count": 1, "check_runs": [item]},
                {"total_count": 1, "check_runs": []},
            ),
        ) as request_json:
            self.assertEqual(
                CI_MODULE.github_paginated_object_items(
                    repository=TEST_REPOSITORY,
                    route="/commits/" + "a" * 40 + "/check-runs",
                    item_key="check_runs",
                    token="read-only",
                    label="synthetic check",
                ),
                [item],
            )
        self.assertEqual(request_json.call_count, 2)

        pagination_cases = (
            (
                "duplicate",
                ({"total_count": 2, "check_runs": [item, item]},),
                "duplicate",
            ),
            (
                "incomplete",
                ({"total_count": 2, "check_runs": [item]},),
                "incomplete",
            ),
            (
                "nonterminal",
                (
                    {"total_count": 1, "check_runs": [item]},
                    {"total_count": 1, "check_runs": [{"id": 777}]},
                ),
                "not terminal",
            ),
        )
        for label, responses, expected in pagination_cases:
            with (
                self.subTest(label=label),
                mock.patch.object(
                    CI_MODULE,
                    "github_json",
                    side_effect=responses,
                ),
                self.assertRaisesRegex(CI_MODULE.GateError, expected),
            ):
                CI_MODULE.github_paginated_object_items(
                    repository=TEST_REPOSITORY,
                    route="/commits/" + "a" * 40 + "/check-runs",
                    item_key="check_runs",
                    token="read-only",
                    label="synthetic check",
                )

        with (
            mock.patch.object(
                CI_MODULE,
                "github_json",
                side_effect=([{"number": 16}], [{"number": 99}]),
            ),
            self.assertRaisesRegex(CI_MODULE.GateError, "not terminal"),
        ):
            CI_MODULE.github_paginated_list(
                repository=TEST_REPOSITORY,
                route="/commits/" + "a" * 40 + "/pulls",
                token="read-only",
                label="synthetic pull",
            )

        first_page = [{"number": 16, "node_id": "PR_original"}]
        changed_first_page = [
            {"number": 99, "node_id": "PR_inserted"},
            *first_page,
        ]
        with (
            mock.patch.object(
                CI_MODULE,
                "github_json",
                side_effect=(first_page, [], changed_first_page),
            ),
            self.assertRaisesRegex(CI_MODULE.GateError, "changed during collection"),
        ):
            CI_MODULE.github_paginated_list(
                repository=TEST_REPOSITORY,
                route="/commits/" + "a" * 40 + "/pulls",
                token="read-only",
                label="synthetic pull",
            )

    def test_offline_projection_revalidates_full_queue_after_base_advance(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            graph = MergeGroupGraph(temporary / "repo")
            subject = "Publish retained history"
            candidate = graph.candidate(
                role="publication",
                message=subject,
            )
            queue_base, queue = graph.queue(
                candidate=candidate,
                role="publication",
                advance_base=True,
            )
            plan = graph.plan(
                candidate=candidate,
                role="publication",
                subject=subject,
            )
            snapshot = graph.snapshot(
                candidate=candidate,
                queue_base=queue_base,
                queue=queue,
                title=subject,
            )
            candidate_root = temporary / "candidate"
            queue_root = temporary / "queue"
            git(
                graph.root,
                "worktree",
                "add",
                "--quiet",
                "--detach",
                str(candidate_root),
                candidate,
            )
            git(
                graph.root,
                "worktree",
                "add",
                "--quiet",
                "--detach",
                str(queue_root),
                queue,
            )
            calls: list[tuple[object, ...]] = []

            class Plan:
                @staticmethod
                def as_dict() -> dict:
                    return plan

            class Validator:
                history_v2_mutable_artifact = staticmethod(
                    VALIDATOR_MODULE.history_v2_mutable_artifact
                )
                HISTORY_V2_SIGNATURE_KEY_PATHS = (
                    VALIDATOR_MODULE.HISTORY_V2_SIGNATURE_KEY_PATHS
                )
                BOOTSTRAP_V2_PUBLIC_KEY_SHA256 = {
                    relative: hashlib.sha256(
                        f"Synthetic trusted file: {relative}\n".encode("utf-8")
                    ).hexdigest()
                    for relative in HISTORY_V2_SIGNATURE_KEY_PATHS.values()
                }
                BOOTSTRAP_V2_MAX_PUBLIC_KEY_BYTES = (
                    VALIDATOR_MODULE.BOOTSTRAP_V2_MAX_PUBLIC_KEY_BYTES
                )
                HistoryV2SignatureVerifier = StructuralSignatureVerifier
                parse_history_v2_commit_object = staticmethod(
                    VALIDATOR_MODULE.parse_history_v2_commit_object
                )

                @staticmethod
                def build_pull_request_candidate_plan(
                    root: Path,
                    base_sha: str,
                    head_sha: str,
                ) -> tuple[Plan, list[str]]:
                    calls.append(("candidate", root, base_sha, head_sha))
                    return Plan(), []

                @staticmethod
                def validate_fixed_head_snapshot(
                    root: Path,
                    head_sha: str,
                ) -> list[str]:
                    calls.append(("fixed-q", root, head_sha))
                    return []

                @staticmethod
                def validate_append_only_event_range(
                    root: Path,
                    base_sha: str,
                    head_sha: str,
                    *,
                    forced: bool,
                ) -> list[str]:
                    calls.append(("prospective", root, base_sha, head_sha, forced))
                    return []

            with mock.patch.object(
                CI_MODULE,
                "trusted_validator_module",
                return_value=Validator,
            ):
                projection = CI_MODULE.validate_merge_group_transaction(
                    git_dir=graph.git_dir,
                    snapshot=snapshot,
                    candidate_root=candidate_root,
                    queue_root=queue_root,
                    policy="history-v2",
                )
            self.assertEqual(projection.role, "publication")
            self.assertEqual(projection.candidate_base_sha, graph.base)
            self.assertEqual(projection.queue_base_sha, queue_base)
            self.assertNotEqual(projection.prospective_sha, candidate)
            for field, value in (
                ("changed_path_count", plan["changed_path_count"] + 1),
                ("delta_sha256", "0" * 64),
            ):
                with (
                    self.subTest(plan_field=field),
                    self.assertRaisesRegex(
                        CI_MODULE.GateError,
                        "does not bind the exact delta",
                    ),
                ):
                    CI_MODULE._validate_merge_group_graph(
                        graph.git_dir,
                        snapshot,
                        policy="history-v2",
                        plan={**plan, field: value},
                        candidate_signature=projection.candidate_signature,
                    )
            self.assertEqual(
                [call[0] for call in calls],
                ["candidate", "fixed-q", "prospective"],
            )
            self.assertEqual(calls[1][2], queue)
            self.assertEqual(calls[2][2], queue_base)
            self.assertEqual(calls[2][3], projection.prospective_sha)
            self.assertIs(calls[2][4], False)
            self.assertEqual(
                projection.prospective_tree_sha,
                projection.queue_tree_sha,
            )
            self.assertEqual(
                projection.candidate_signature,
                CI_MODULE.CandidateSignatureBinding(
                    policy="history-v2",
                    key_path=(
                        VALIDATOR_MODULE.HISTORY_V2_SIGNATURE_KEY_PATHS[
                            "history-v2"
                        ].as_posix()
                    ),
                    key_sha256=Validator.BOOTSTRAP_V2_PUBLIC_KEY_SHA256[
                        VALIDATOR_MODULE.HISTORY_V2_SIGNATURE_KEY_PATHS["history-v2"]
                    ],
                    signer_fingerprint=FIXTURE_SIGNER_FINGERPRINT,
                ),
            )
            requirements = CI_MODULE.git_output(
                graph.git_dir,
                "cat-file",
                "blob",
                f"{queue}:requirements-v2.txt",
                max_bytes=CI_MODULE.MAX_BLOB_BYTES,
            )
            evidence = CI_MODULE.MergeGroupRuntimeEvidence(
                policy="history-v2",
                queue_base_sha=queue_base,
                candidate_sha=candidate,
                queue_sha=queue,
                queue_tree_sha=projection.queue_tree_sha,
                prospective_sha=projection.prospective_sha,
                prospective_tree_sha=projection.prospective_tree_sha,
                projection_sha256=CI_MODULE.merge_group_projection_sha256(projection),
                python_version=CI_MODULE.QUEUE_RUNTIME_PYTHON_VERSION,
                python_executable_sha256="a" * 64,
                requirements_sha256=hashlib.sha256(requirements).hexdigest(),
                runtime_profile=CI_MODULE.QUEUE_RUNTIME_PROFILE,
                compile_command_sha256=(CI_MODULE.QUEUE_RUNTIME_COMPILE_COMMAND_SHA256),
                test_command_sha256=CI_MODULE.QUEUE_RUNTIME_TEST_COMMAND_SHA256,
                compile_exit_code=0,
                test_exit_code=0,
                authority_uid=os.geteuid(),
                execution_uid=65534,
                credential_environment="empty",
                authority_write_access=False,
                source_authority_pristine=True,
            )
            CI_MODULE.validate_merge_group_runtime_evidence(
                git_dir=graph.git_dir,
                snapshot=snapshot,
                projection=projection,
                evidence=evidence,
                expected_python_executable_sha256=(evidence.python_executable_sha256),
            )
            observed_at = dt.datetime(2026, 8, 6, 17, 30, tzinfo=dt.timezone.utc)
            predecessor_audit = synthetic_predecessor_audit(
                base_sha=snapshot.base_sha,
                parent_sha="9" * 40,
            )
            predecessor_authority = CI_MODULE.MergeGroupPredecessorAuthorityEvidence(
                mode="history-v2-required",
                base_sha=snapshot.base_sha,
                queue_sha=snapshot.queue_sha,
                pull_request_number=snapshot.pull_request_number,
                projection_sha256=(CI_MODULE.merge_group_projection_sha256(projection)),
                parent_sha=predecessor_audit.parent_sha,
                audit=predecessor_audit,
                candidate_ref=None,
                bootstrap_markers=(),
                bootstrap_marker_sha256=None,
            )
            live_authority = CI_MODULE.MergeGroupLiveAuthorityEvidence(
                snapshot_sha256=hashlib.sha256(
                    CI_MODULE.compact_json_bytes(snapshot.as_dict())
                ).hexdigest(),
                tcb_sha256=snapshot.tcb_sha256,
                predecessor_authority=predecessor_authority,
                predecessor_authority_sha256=hashlib.sha256(
                    CI_MODULE.compact_json_bytes(predecessor_authority.as_dict())
                ).hexdigest(),
                observed_at=observed_at.isoformat().replace("+00:00", "Z"),
                valid_until=(
                    observed_at
                    + dt.timedelta(
                        seconds=CI_MODULE.MERGE_GROUP_LIVE_AUTHORITY_TTL_SECONDS
                    )
                )
                .isoformat()
                .replace("+00:00", "Z"),
            )
            admission = CI_MODULE.merge_group_admission_payload(
                snapshot=snapshot,
                projection=projection,
                evidence=evidence,
                live_authority=live_authority,
            )
            self.assertEqual(admission["kind"], CI_MODULE.MERGE_GROUP_ADMISSION_KIND)
            self.assertEqual(admission["decision"], "accepted")
            self.assertEqual(
                admission["live_authority"],
                live_authority.as_dict(),
            )
            for field, value in (
                ("snapshot_sha256", "f" * 64),
                ("tcb_sha256", "f" * 64),
                (
                    "valid_until",
                    (observed_at + dt.timedelta(seconds=31))
                    .isoformat()
                    .replace("+00:00", "Z"),
                ),
            ):
                with (
                    self.subTest(live_authority_field=field),
                    self.assertRaisesRegex(
                        CI_MODULE.GateError,
                        "live merge-group authority evidence is invalid",
                    ),
                ):
                    CI_MODULE.merge_group_admission_payload(
                        snapshot=snapshot,
                        projection=projection,
                        evidence=evidence,
                        live_authority=type(live_authority)(
                            **{**live_authority.__dict__, field: value}
                        ),
                    )

            invalid = (
                ("queue_sha", "f" * 40, "stale or cross-transaction"),
                ("test_exit_code", 1, "exact profile"),
                ("authority_write_access", True, "exact profile"),
                ("requirements_sha256", "b" * 64, "requirements digest"),
            )
            for field, value, expected in invalid:
                with (
                    self.subTest(field=field),
                    self.assertRaisesRegex(CI_MODULE.GateError, expected),
                ):
                    changed = type(evidence)(
                        **{**evidence.__dict__, field: value},
                    )
                    CI_MODULE.validate_merge_group_runtime_evidence(
                        git_dir=graph.git_dir,
                        snapshot=snapshot,
                        projection=projection,
                        evidence=changed,
                        expected_python_executable_sha256=(
                            evidence.python_executable_sha256
                        ),
                    )
            with self.assertRaisesRegex(CI_MODULE.GateError, "exact profile"):
                CI_MODULE.validate_merge_group_runtime_evidence(
                    git_dir=graph.git_dir,
                    snapshot=snapshot,
                    projection=projection,
                    evidence=evidence,
                    expected_python_executable_sha256="f" * 64,
                )
            with mock.patch.object(
                CI_MODULE,
                "trusted_validator_module",
                return_value=Validator,
            ):
                self.assertEqual(
                    CI_MODULE.parse_merge_group_projection(projection.as_dict()),
                    projection,
                )
            for field, value in (
                ("policy", "bootstrap-v2"),
                ("key_path", "retrospective-history-v2-admin-public.asc"),
                ("key_sha256", "f" * 64),
                ("signer_fingerprint", FIXTURE_SIGNER_FINGERPRINT.lower()),
            ):
                invalid_projection = projection.as_dict()
                invalid_projection["candidate_signature"][field] = value
                with (
                    self.subTest(candidate_signature_field=field),
                    mock.patch.object(
                        CI_MODULE,
                        "trusted_validator_module",
                        return_value=Validator,
                    ),
                    self.assertRaisesRegex(
                        CI_MODULE.GateError,
                        "candidate signature binding is invalid",
                    ),
                ):
                    CI_MODULE.parse_merge_group_projection(invalid_projection)
            evidence_path = temporary / "runtime-evidence.json"
            CI_MODULE.write_json(evidence_path, evidence.as_dict())
            self.assertEqual(
                CI_MODULE.load_merge_group_runtime_evidence(evidence_path),
                evidence,
            )
            mismatched_owner = type(evidence)(
                **{
                    **evidence.__dict__,
                    "authority_uid": os.geteuid() + 1,
                }
            )
            CI_MODULE.write_json(evidence_path, mismatched_owner.as_dict())
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "authority differs from the receipt owner",
            ):
                CI_MODULE.load_merge_group_runtime_evidence(evidence_path)
            unknown = evidence.as_dict()
            unknown["untrusted"] = True
            CI_MODULE.write_json(evidence_path, unknown)
            with self.assertRaisesRegex(CI_MODULE.GateError, "schema is invalid"):
                CI_MODULE.load_merge_group_runtime_evidence(evidence_path)

    def test_bootstrap_merge_group_requires_admin_signature_binding(self) -> None:
        class RejectingSignatureVerifier(StructuralSignatureVerifier):
            def verify(self, _signature: object) -> None:
                raise ValueError("synthetic signature rejected")

        cases = (
            ("signed", True, StructuralSignatureVerifier, False),
            ("unsigned", False, StructuralSignatureVerifier, True),
            ("wrong signature", True, RejectingSignatureVerifier, True),
        )
        for label, include_signature, verifier_type, should_reject in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw:
                temporary = Path(raw)
                graph = MergeGroupGraph(temporary / "repo")
                subject = "Update trusted history policy"
                signed_candidate = graph.candidate(role="admin", message=subject)
                candidate = signed_candidate
                if not include_signature:
                    candidate = fixture_raw_commit(
                        graph.root,
                        tree_oid=git(
                            graph.root,
                            "rev-parse",
                            f"{signed_candidate}^{{tree}}",
                        ),
                        parents=(graph.base,),
                        message=subject,
                        include_signature=False,
                    )
                queue_base, queue = graph.queue(
                    candidate=candidate,
                    role="admin",
                    advance_base=False,
                )
                snapshot = graph.snapshot(
                    candidate=candidate,
                    queue_base=queue_base,
                    queue=queue,
                    title=subject,
                )
                candidate_root = temporary / "candidate"
                queue_root = temporary / "queue"
                trusted_base_root = temporary / "trusted-base"
                for destination, revision in (
                    (candidate_root, candidate),
                    (queue_root, queue),
                    (trusted_base_root, graph.base),
                ):
                    git(
                        graph.root,
                        "worktree",
                        "add",
                        "--quiet",
                        "--detach",
                        str(destination),
                        revision,
                    )

                key_paths = VALIDATOR_MODULE.HISTORY_V2_SIGNATURE_KEY_PATHS

                class Validator:
                    HISTORY_V2_SIGNATURE_KEY_PATHS = key_paths
                    BOOTSTRAP_V2_PUBLIC_KEY_SHA256 = {
                        relative: hashlib.sha256(
                            f"Synthetic trusted file: {relative}\n".encode("utf-8")
                        ).hexdigest()
                        for relative in key_paths.values()
                    }
                    BOOTSTRAP_V2_MAX_PUBLIC_KEY_BYTES = (
                        VALIDATOR_MODULE.BOOTSTRAP_V2_MAX_PUBLIC_KEY_BYTES
                    )
                    HistoryV2SignatureVerifier = verifier_type
                    parse_history_v2_commit_object = staticmethod(
                        VALIDATOR_MODULE.parse_history_v2_commit_object
                    )

                    @staticmethod
                    def validate_bootstrap_v2_candidate(
                        _trusted_root: Path,
                        _candidate_root: Path,
                    ) -> list[str]:
                        return []

                context = (
                    self.assertRaisesRegex(
                        CI_MODULE.GateError,
                        "candidate commit signature verification failed",
                    )
                    if should_reject
                    else contextlib.nullcontext()
                )
                with (
                    mock.patch.object(
                        CI_MODULE,
                        "trusted_validator_module",
                        return_value=Validator,
                    ),
                    context,
                ):
                    projection = CI_MODULE.validate_merge_group_transaction(
                        git_dir=graph.git_dir,
                        snapshot=snapshot,
                        candidate_root=candidate_root,
                        queue_root=queue_root,
                        policy="bootstrap-v2",
                        trusted_base_root=trusted_base_root,
                    )
                if not should_reject:
                    admin_key = key_paths["bootstrap-v2"]
                    self.assertEqual(
                        projection.candidate_signature,
                        CI_MODULE.CandidateSignatureBinding(
                            policy="bootstrap-v2",
                            key_path=admin_key.as_posix(),
                            key_sha256=Validator.BOOTSTRAP_V2_PUBLIC_KEY_SHA256[
                                admin_key
                            ],
                            signer_fingerprint=FIXTURE_SIGNER_FINGERPRINT,
                        ),
                    )

    def test_permanent_admin_merge_group_binds_base_admin_signature(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            graph = MergeGroupGraph(temporary / "repo")
            subject = "Update trusted history policy"
            candidate = graph.candidate(role="admin", message=subject)
            queue_base, queue = graph.queue(
                candidate=candidate,
                role="admin",
                advance_base=False,
            )
            plan = graph.plan(
                candidate=candidate,
                role="admin",
                subject=subject,
            )
            snapshot = graph.snapshot(
                candidate=candidate,
                queue_base=queue_base,
                queue=queue,
                title=subject,
            )
            candidate_root = temporary / "candidate"
            queue_root = temporary / "queue"
            for destination, revision in (
                (candidate_root, candidate),
                (queue_root, queue),
            ):
                git(
                    graph.root,
                    "worktree",
                    "add",
                    "--quiet",
                    "--detach",
                    str(destination),
                    revision,
                )

            key_paths = VALIDATOR_MODULE.HISTORY_V2_SIGNATURE_KEY_PATHS

            class Plan:
                @staticmethod
                def as_dict() -> dict:
                    return plan

            class Validator:
                history_v2_mutable_artifact = staticmethod(
                    VALIDATOR_MODULE.history_v2_mutable_artifact
                )
                HISTORY_V2_SIGNATURE_KEY_PATHS = key_paths
                BOOTSTRAP_V2_PUBLIC_KEY_SHA256 = {
                    relative: hashlib.sha256(
                        f"Synthetic trusted file: {relative}\n".encode("utf-8")
                    ).hexdigest()
                    for relative in key_paths.values()
                }
                BOOTSTRAP_V2_MAX_PUBLIC_KEY_BYTES = (
                    VALIDATOR_MODULE.BOOTSTRAP_V2_MAX_PUBLIC_KEY_BYTES
                )
                HistoryV2SignatureVerifier = StructuralSignatureVerifier
                parse_history_v2_commit_object = staticmethod(
                    VALIDATOR_MODULE.parse_history_v2_commit_object
                )

                @staticmethod
                def build_pull_request_candidate_plan(
                    _root: Path,
                    _base_sha: str,
                    _head_sha: str,
                ) -> tuple[Plan, list[str]]:
                    return Plan(), []

                @staticmethod
                def validate_fixed_head_snapshot(
                    _root: Path,
                    _head_sha: str,
                ) -> list[str]:
                    return []

                @staticmethod
                def validate_append_only_event_range(
                    *_args: object, **_kwargs: object
                ) -> list[str]:
                    raise AssertionError(
                        "admin transaction must not enter publication validation"
                    )

            with mock.patch.object(
                CI_MODULE,
                "trusted_validator_module",
                return_value=Validator,
            ):
                projection = CI_MODULE.validate_merge_group_transaction(
                    git_dir=graph.git_dir,
                    snapshot=snapshot,
                    candidate_root=candidate_root,
                    queue_root=queue_root,
                    policy="history-v2",
                )
            admin_key = key_paths["bootstrap-v2"]
            self.assertEqual(projection.role, "admin")
            self.assertEqual(projection.policy, "history-v2")
            self.assertEqual(
                projection.candidate_signature,
                CI_MODULE.CandidateSignatureBinding(
                    policy="bootstrap-v2",
                    key_path=admin_key.as_posix(),
                    key_sha256=Validator.BOOTSTRAP_V2_PUBLIC_KEY_SHA256[admin_key],
                    signer_fingerprint=FIXTURE_SIGNER_FINGERPRINT,
                ),
            )

    def test_admin_and_bootstrap_require_queue_base_to_equal_candidate_base(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            graph = MergeGroupGraph(Path(raw) / "repo")
            subject = "Update trusted history policy"
            candidate = graph.candidate(role="admin", message=subject)
            queue_base, queue = graph.queue(
                candidate=candidate,
                role="admin",
                advance_base=True,
            )
            snapshot = graph.snapshot(
                candidate=candidate,
                queue_base=queue_base,
                queue=queue,
                title=subject,
            )
            plan = graph.plan(
                candidate=candidate,
                role="admin",
                subject=subject,
            )
            for policy, supplied_plan, expected in (
                ("history-v2", plan, "admin merge group requires B1 == B0"),
                ("bootstrap-v2", None, "bootstrap merge group requires B1 == B0"),
            ):
                with (
                    self.subTest(policy=policy),
                    self.assertRaisesRegex(
                        CI_MODULE.GateError,
                        expected,
                    ),
                ):
                    CI_MODULE._validate_merge_group_graph(
                        graph.git_dir,
                        snapshot,
                        policy=policy,
                        plan=supplied_plan,
                        candidate_signature=synthetic_merge_group_projection(
                            snapshot,
                            policy=policy,
                            role="admin",
                        ).candidate_signature,
                    )

    def test_queue_rejects_head_update_after_snapshot_and_leaves_refs_unchanged(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            graph = MergeGroupGraph(Path(raw) / "repo")
            original = graph.candidate(
                role="publication",
                message="Publish original history",
            )
            queue_base, queue = graph.queue(
                candidate=original,
                role="publication",
                advance_base=False,
            )
            graph.reset(graph.base)
            graph.write(
                "retained/daily/episodes.jsonl",
                '{"episode":"updated"}\n',
            )
            updated = commit_all(graph.root, "Publish updated history")
            snapshot = graph.snapshot(
                candidate=updated,
                queue_base=queue_base,
                queue=queue,
                title="Publish updated history",
            )
            before = git(graph.root, "rev-parse", "refs/heads/master")
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "exact B1/H parent-edge shape",
            ):
                CI_MODULE._validate_merge_group_graph(
                    graph.git_dir,
                    snapshot,
                    policy="history-v2",
                    plan=graph.plan(
                        candidate=updated,
                        role="publication",
                        subject="Publish updated history",
                    ),
                    candidate_signature=synthetic_merge_group_projection(
                        snapshot,
                    ).candidate_signature,
                )
            self.assertEqual(
                git(graph.root, "rev-parse", "refs/heads/master"),
                before,
            )

    def test_real_base_ci_blob_and_authorized_permanent_blob_are_exact(self) -> None:
        actual_base = subprocess.run(
            [
                "git",
                "-C",
                str(ROOT),
                "show",
                f"{ACTUAL_BASE_SHA}:.github/workflows/ci.yml",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if actual_base.returncode != 0:
            self.skipTest("actual base object is unavailable in this checkout")
        self.assertEqual(actual_base.stdout, LEGACY_CI.encode("utf-8"))
        with tempfile.TemporaryDirectory() as raw:
            graph = BootstrapGraph(Path(raw) / "repo")
            legacy_blob = git(
                graph.root, "rev-parse", f"{graph.actual_base}:.github/workflows/ci.yml"
            )
            template_blob = git(
                graph.root,
                "rev-parse",
                f"{graph.base}:.github/bootstrap/session-retrospective-v2-permanent-ci.yml",
            )
        self.assertEqual(legacy_blob, VALIDATOR_MODULE.BOOTSTRAP_V2_LEGACY_CI_BLOB_OID)
        self.assertEqual(
            template_blob, VALIDATOR_MODULE.BOOTSTRAP_V2_PERMANENT_CI_BLOB_OID
        )

    def test_trust_seed_precedes_the_first_base_owned_cutover_and_audit(
        self,
    ) -> None:
        seeded_paths = (
            ".github/workflows/session-retrospective-v2-bootstrap.yml",
            ".github/bootstrap/session-retrospective-v2-permanent-ci.yml",
            "scripts/trusted_history_ci.py",
            "retrospective-history-v2-admin-public.asc",
            "retrospective-history-v2-publisher.asc",
        )
        for relative in seeded_paths:
            with self.subTest(relative=relative):
                before = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(ROOT),
                        "cat-file",
                        "-e",
                        f"{ACTUAL_BASE_SHA}:{relative}",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                if before.returncode not in {0, 1, 128}:
                    self.fail(f"unexpected git cat-file status: {before.returncode}")
                self.assertNotEqual(0, before.returncode)
                self.assertTrue((ROOT / relative).is_file())

        self.assertEqual(
            (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"),
            LEGACY_CI,
        )
        self.assertEqual(
            CI_MODULE.BOOTSTRAP_CANDIDATE_REF,
            "wip/session-retrospective-v2-history-bootstrap",
        )
        permanent = load_workflow(PERMANENT_CI)
        audit = permanent["jobs"]["trusted_default_audit"]
        baseline_checkout = steps_by_name(audit)["Checkout exact trusted B0"]
        self.assertEqual(
            baseline_checkout["with"]["ref"],
            "${{ github.event.before }}",
        )
        self.assertEqual(
            set(VALIDATOR_MODULE.BOOTSTRAP_V2_PUBLIC_KEY_SHA256),
            {
                Path("retrospective-history-v2-admin-public.asc"),
                Path("retrospective-history-v2-publisher.asc"),
            },
        )

    def test_trust_seed_does_not_change_retained_history_artifacts(self) -> None:
        changed = subprocess.run(
            [
                "git",
                "-C",
                str(ROOT),
                "diff",
                "--name-only",
                "-z",
                ACTUAL_BASE_SHA,
                "--",
                "data",
                "reports",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout
        self.assertEqual(changed, b"")

    def test_bootstrap_preflight_rejects_raw_commit_metadata_attacks(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            graph = BootstrapGraph(Path(raw) / "repo")
            canonical_head = graph.create_candidate(message="Canonical candidate")
            canonical = fixture_commit_bytes(graph.root, canonical_head)
            header = canonical.partition(b"\n\n")[0]
            cases = (
                (
                    "unknown header",
                    canonical.replace(
                        b"\ngpgsig ",
                        b"\nx-private hidden\ngpgsig ",
                        1,
                    ),
                ),
                (
                    "multiline header",
                    canonical.replace(
                        b"\ngpgsig ",
                        b"\n hidden-continuation\ngpgsig ",
                        1,
                    ),
                ),
                (
                    "signature alias",
                    canonical.replace(
                        b"\ngpgsig ",
                        b"\ngpgsig-sha256 ",
                        1,
                    ),
                ),
                (
                    "encoding",
                    canonical.replace(
                        b"\ngpgsig ",
                        b"\nencoding UTF-8\ngpgsig ",
                        1,
                    ),
                ),
                ("CR", canonical.replace(b"\n", b"\r\n", 1)),
                (
                    "noncanonical identity",
                    canonical.replace(
                        VALIDATOR_MODULE.HISTORY_V2_CANONICAL_IDENTITY.encode("ascii"),
                        b"Synthetic Test <synthetic@example.invalid>",
                        1,
                    ),
                ),
                (
                    "non-UTC",
                    canonical.replace(b" +0000\ncommitter", b" +0800\ncommitter", 1),
                ),
                (
                    "noncanonical message",
                    header + b"\n\n Candidate\n",
                ),
                (
                    "sensitive message",
                    header + b"\n\nLeaked token ghp_ABCDEFGHIJKLMNOPQRST\n",
                ),
            )
            for label, raw_commit in cases:
                with self.subTest(label=label):
                    head = fixture_store_commit(graph.root, raw_commit)
                    with self.assertRaisesRegex(
                        CI_MODULE.GateError,
                        "metadata policy",
                    ):
                        CI_MODULE.validate_candidate_commit_object(
                            graph.git_dir,
                            head,
                        )

    def test_candidate_tree_closure_and_original_oid_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            graph = BootstrapGraph(Path(raw) / "repo")
            head = graph.create_candidate()
            preflight = graph.preflight(head)
            CI_MODULE.reconstruct_candidate_tree_oid(
                preflight.entries,
                expected_tree_sha=preflight.head_tree_sha,
            )

            entries = preflight.entries
            first_tree = next(entry for entry in entries if entry.object_type == "tree")
            nested_empty = (
                *entries,
                CI_MODULE.TreeEntry(
                    "placeholder",
                    "040000",
                    "tree",
                    first_tree.object_id,
                    None,
                ),
                CI_MODULE.TreeEntry(
                    "placeholder/nested",
                    "040000",
                    "tree",
                    first_tree.object_id,
                    None,
                ),
            )
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "empty or unrepresented subtree",
            ):
                CI_MODULE.validate_complete_tree_entries(
                    nested_empty,
                    expected_oid_length=40,
                    require_blob_sizes=True,
                )

            sensitive = (
                *entries,
                CI_MODULE.TreeEntry(
                    "archive/raw",
                    "040000",
                    "tree",
                    first_tree.object_id,
                    None,
                ),
            )
            with self.assertRaisesRegex(CI_MODULE.GateError, "sensitive path"):
                CI_MODULE.validate_complete_tree_entries(
                    sensitive,
                    expected_oid_length=40,
                    require_blob_sizes=True,
                )

            case_collision = (
                *entries,
                CI_MODULE.TreeEntry(
                    first_tree.path.swapcase(),
                    "040000",
                    "tree",
                    first_tree.object_id,
                    None,
                ),
            )
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "metadata is invalid",
            ):
                CI_MODULE.validate_complete_tree_entries(
                    case_collision,
                    expected_oid_length=40,
                    require_blob_sizes=True,
                )

            without_tree = tuple(
                entry for entry in entries if entry.path != first_tree.path
            )
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "empty or unrepresented subtree",
            ):
                CI_MODULE.validate_complete_tree_entries(
                    without_tree,
                    expected_oid_length=40,
                    require_blob_sizes=True,
                )
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "differs from the original",
            ):
                CI_MODULE.reconstruct_candidate_tree_oid(
                    entries,
                    expected_tree_sha="f" * 40,
                )

            payload = tree_api_payload(graph.root, head)
            payload["tree"] = [
                entry for entry in payload["tree"] if entry["path"] != first_tree.path
            ]
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "omits bare Git entries",
            ):
                CI_MODULE.validate_tree_api_payload(
                    payload,
                    expected_tree_sha=preflight.head_tree_sha,
                    local_entries=CI_MODULE.git_tree_entries(
                        graph.git_dir,
                        head,
                    ),
                )

    def test_bootstrap_preflight_rejects_sensitive_leaf_blob_before_dispatch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            graph = BootstrapGraph(Path(raw) / "repo")
            graph.remove_bootstrap()
            graph.write(
                ".github/workflows/ci.yml",
                PERMANENT_CI.read_text(encoding="utf-8"),
            )
            graph.write("reports/api-token.txt", "must not be fetched\n")
            head = commit_all(graph.root, "sensitive leaf probe")
            payload = tree_api_payload(graph.root, head)

            with (
                mock.patch.object(
                    CI_MODULE,
                    "validate_tree_api_payload",
                    side_effect=AssertionError(
                        "sensitive leaf reached API type dispatch"
                    ),
                ) as api_validation,
                mock.patch.object(
                    CI_MODULE,
                    "reconstruct_candidate_tree_oid",
                    side_effect=AssertionError(
                        "sensitive leaf reached tree reconstruction"
                    ),
                ) as reconstruction,
                self.assertRaisesRegex(CI_MODULE.GateError, "sensitive path"),
            ):
                CI_MODULE.preflight_git_candidate(
                    graph.git_dir,
                    base_sha=graph.base,
                    head_sha=head,
                    tree_payload=payload,
                    policy="bootstrap-v2",
                )
            api_validation.assert_not_called()
            reconstruction.assert_not_called()

    def test_bootstrap_preflight_rejects_admin_armor_path_variants_before_fetch(
        self,
    ) -> None:
        forbidden_leaf = "retrospective-history-v2-admin.asc"
        fullwidth_leaf = "".join(
            chr(ord(character) + 0xFEE0)
            if 0x21 <= ord(character) <= 0x7E
            else character
            for character in forbidden_leaf
        )
        variants = (
            forbidden_leaf,
            forbidden_leaf.upper(),
            fullwidth_leaf,
            f"archive/{forbidden_leaf}/report.md",
        )
        with tempfile.TemporaryDirectory() as raw:
            graph = BootstrapGraph(Path(raw) / "repo")
            head = graph.create_candidate()
            existing_blob = git(graph.root, "rev-parse", f"{head}:AGENTS.md")
            original_git_output = CI_MODULE.git_output

            for path in variants:
                with self.subTest(path=path):
                    record = (
                        f"100644 blob {existing_blob}\t{path}".encode("utf-8") + b"\x00"
                    )

                    def injected_git_output(
                        git_dir: Path,
                        *arguments: str,
                        **kwargs: object,
                    ) -> bytes:
                        output = original_git_output(
                            git_dir,
                            *arguments,
                            **kwargs,
                        )
                        if (
                            arguments
                            and arguments[0] == "ls-tree"
                            and arguments[-1] == head
                        ):
                            return record + output
                        return output

                    tree_loader = mock.Mock(
                        side_effect=AssertionError(
                            "forbidden armor path reached tree API fetch"
                        )
                    )
                    with (
                        mock.patch.object(
                            CI_MODULE,
                            "git_output",
                            side_effect=injected_git_output,
                        ),
                        mock.patch.object(
                            CI_MODULE,
                            "reconstruct_candidate_tree_oid",
                            side_effect=AssertionError(
                                "forbidden armor path reached tree materialization"
                            ),
                        ) as tree_materialization,
                        mock.patch.object(
                            CI_MODULE,
                            "materialize_preflight_blobs",
                            side_effect=AssertionError(
                                "forbidden armor path reached blob fetch"
                            ),
                        ) as blob_fetch,
                        self.assertRaisesRegex(
                            CI_MODULE.GateError,
                            "sensitive path",
                        ),
                    ):
                        preflight = CI_MODULE.preflight_git_candidate(
                            graph.git_dir,
                            base_sha=graph.base,
                            head_sha=head,
                            tree_payload=None,
                            tree_payload_loader=tree_loader,
                            policy="bootstrap-v2",
                        )
                        CI_MODULE.materialize_preflight_blobs(
                            graph.git_dir,
                            preflight,
                            repository=(
                                "Joey-Tools/codex-session-retrospective-history"
                            ),
                            token="synthetic",
                        )
                    tree_loader.assert_not_called()
                    tree_materialization.assert_not_called()
                    blob_fetch.assert_not_called()

    def test_bootstrap_preflight_verifies_admin_signature_before_execution(
        self,
    ) -> None:
        expected_roles = {
            "bootstrap-v2": Path("retrospective-history-v2-admin-public.asc"),
            "history-v2": Path("retrospective-history-v2-publisher.asc"),
        }
        for policy, expected_relative in expected_roles.items():
            with self.subTest(policy=policy), tempfile.TemporaryDirectory() as raw:
                graph = BootstrapGraph(Path(raw) / "repo")
                head = graph.create_candidate()
                preflight = preflight_complete_fixture(
                    graph.git_dir,
                    base_sha=graph.base,
                    head_sha=head,
                    tree_payload=tree_api_payload(graph.root, head),
                    policy=policy,
                )
                trusted_validator = CI_MODULE.trusted_validator_module()
                key_digests = dict(trusted_validator.BOOTSTRAP_V2_PUBLIC_KEY_SHA256)
                for relative in expected_roles.values():
                    key_digests[relative] = hashlib.sha256(
                        (graph.root / relative).read_bytes()
                    ).hexdigest()
                observed_roles: list[Path] = []

                class CapturingVerifier(StructuralSignatureVerifier):
                    def __init__(
                        self,
                        public_key: bytes,
                        *,
                        relative: Path,
                    ) -> None:
                        super().__init__(public_key, relative=relative)
                        observed_roles.append(relative)

                with (
                    mock.patch.object(
                        trusted_validator,
                        "BOOTSTRAP_V2_PUBLIC_KEY_SHA256",
                        key_digests,
                    ),
                    mock.patch.object(
                        trusted_validator,
                        "HistoryV2SignatureVerifier",
                        CapturingVerifier,
                    ),
                ):
                    CI_MODULE.verify_preflight_objects(
                        graph.git_dir,
                        preflight,
                    )
                self.assertEqual(
                    observed_roles,
                    [expected_relative] if policy == "bootstrap-v2" else [],
                )

    def test_shared_git_graph_accepts_only_one_direct_candidate_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            graph = BootstrapGraph(Path(raw) / "valid")
            head = graph.create_candidate()
            preflight = graph.preflight(head)
            self.assertEqual(preflight.base_sha, graph.base)
            self.assertEqual(preflight.head_sha, head)
            self.assertEqual(preflight.commit_count, 1)

        with tempfile.TemporaryDirectory() as raw:
            graph = BootstrapGraph(Path(raw) / "stale")
            head = graph.create_candidate()
            with self.assertRaises(CI_MODULE.GateError):
                graph.preflight(head, base=graph.actual_base)

        with tempfile.TemporaryDirectory() as raw:
            graph = BootstrapGraph(Path(raw) / "multi")
            graph.write("intermediate.txt", "intermediate\n")
            commit_all(graph.root, "intermediate")
            head = graph.create_candidate()
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "exactly one commit",
            ):
                graph.preflight(head)

        with tempfile.TemporaryDirectory() as raw:
            graph = BootstrapGraph(Path(raw) / "merge")
            git(graph.root, "switch", "--quiet", "-c", "side")
            graph.write("side.txt", "side\n")
            side = commit_all(graph.root, "side")
            git(graph.root, "switch", "--quiet", "--detach", graph.base)
            head = graph.create_candidate(message="candidate side")
            git(
                graph.root,
                "merge",
                "--quiet",
                "--no-ff",
                "--no-commit",
                "side",
            )
            merge_head = commit_all(
                graph.root,
                "merge",
                parents=(head, side),
            )
            self.assertNotEqual(head, merge_head)
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "exactly one commit",
            ):
                graph.preflight(merge_head)

    def test_shared_git_graph_requires_explicit_bootstrap_deletions(self) -> None:
        for retained in CI_MODULE.BOOTSTRAP_TEMPORARY_PATHS:
            with self.subTest(retained=retained):
                with tempfile.TemporaryDirectory() as raw:
                    graph = BootstrapGraph(Path(raw) / "repo")
                    head = graph.create_candidate(retain={retained})
                    with self.assertRaisesRegex(
                        CI_MODULE.GateError, "explicitly delete"
                    ):
                        graph.preflight(head)

    def test_shared_git_graph_rejects_size_count_and_api_identity_attacks(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            graph = BootstrapGraph(Path(raw) / "ci")
            graph.remove_bootstrap()
            graph.write(".github/workflows/ci.yml", LEGACY_CI)
            head = commit_all(graph.root, "wrong CI")
            with self.assertRaisesRegex(
                CI_MODULE.GateError, "authorized permanent blob"
            ):
                graph.preflight(head)

        with tempfile.TemporaryDirectory() as raw:
            graph = BootstrapGraph(Path(raw) / "large")
            graph.remove_bootstrap()
            graph.write(".github/workflows/ci.yml", PERMANENT_CI.read_text())
            oversized = graph.root / "oversized.bin"
            oversized.write_bytes(b"x" * (CI_MODULE.MAX_BLOB_BYTES + 1))
            head = commit_all(graph.root, "oversized")
            with self.assertRaisesRegex(CI_MODULE.GateError, "blob exceeds"):
                graph.preflight(head)

        with tempfile.TemporaryDirectory() as raw:
            graph = BootstrapGraph(Path(raw) / "count")
            head = graph.create_candidate()
            with mock.patch.object(CI_MODULE, "MAX_BLOB_ENTRIES", 1):
                with self.assertRaisesRegex(CI_MODULE.GateError, "blob count"):
                    graph.preflight(head)

        with tempfile.TemporaryDirectory() as raw:
            graph = BootstrapGraph(Path(raw) / "api")
            head = graph.create_candidate()
            payload = tree_api_payload(graph.root, head)
            payload["sha"] = "f" * 40
            with self.assertRaisesRegex(CI_MODULE.GateError, "incomplete or changed"):
                preflight_complete_fixture(
                    graph.git_dir,
                    base_sha=graph.base,
                    head_sha=head,
                    tree_payload=payload,
                    policy="bootstrap-v2",
                )

    def test_bounded_command_stops_on_output_and_time_limits(self) -> None:
        with self.assertRaises(CI_MODULE.GateError):
            CI_MODULE.run_bounded(
                [
                    sys.executable,
                    "-c",
                    "import os; os.write(1, b'x' * (8 * 1024 * 1024))",
                ],
                max_output_bytes=128,
                timeout_seconds=2,
            )
        with self.assertRaises(CI_MODULE.GateError):
            CI_MODULE.run_bounded(
                [sys.executable, "-c", "import time; time.sleep(2)"],
                max_output_bytes=128,
                timeout_seconds=0.05,
            )
        self.assertEqual(
            CI_MODULE.run_bounded(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())",
                ],
                input_data=b"bounded input",
                max_output_bytes=128,
                timeout_seconds=2,
            ),
            b"bounded input",
        )

    def test_bounded_command_kills_descendants_holding_output_pipe(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            child_pid_path = Path(raw) / "child.pid"
            program = (
                "import os, pathlib, time\n"
                f"path = pathlib.Path({str(child_pid_path)!r})\n"
                "child = os.fork()\n"
                "if child == 0:\n"
                "    time.sleep(60)\n"
                "else:\n"
                "    path.write_text(str(child), encoding='ascii')\n"
                "    os.write(1, b'x' * (8 * 1024 * 1024))\n"
                "    time.sleep(60)\n"
            )
            with self.assertRaises(CI_MODULE.GateError):
                CI_MODULE.run_bounded(
                    [sys.executable, "-c", program],
                    max_output_bytes=1024,
                    timeout_seconds=5,
                )
            child_pid = int(child_pid_path.read_text(encoding="ascii"))
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if not process_is_executing_for_test(child_pid):
                    break
                time.sleep(0.02)
            else:
                self.fail("bounded command descendant remained alive")

    @unittest.skipUnless(
        sys.platform.startswith("linux") and hasattr(os, "fork"),
        "Linux /proc process-state contract is unavailable",
    )
    def test_linux_process_liveness_treats_zombie_as_terminal(self) -> None:
        child_pid = os.fork()
        if child_pid == 0:
            os._exit(0)
        try:
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if linux_process_state(child_pid) == "Z":
                    break
                time.sleep(0.01)
            else:
                self.fail("child did not enter the Linux zombie state")
            self.assertFalse(process_is_executing_for_test(child_pid))
        finally:
            os.waitpid(child_pid, 0)

    def test_linux_process_state_contract_distinguishes_terminal_state(self) -> None:
        with (
            mock.patch.object(sys, "platform", "linux"),
            mock.patch.object(
                Path,
                "read_bytes",
                return_value=b"123 (worker) name) Z 1 2 3\n",
            ),
        ):
            self.assertEqual(linux_process_state(123), "Z")
            self.assertFalse(process_is_executing_for_test(123))

        with (
            mock.patch.object(sys, "platform", "linux"),
            mock.patch.object(
                Path,
                "read_bytes",
                return_value=b"123 (worker) name) S 1 2 3\n",
            ),
        ):
            self.assertTrue(process_is_executing_for_test(123))

        with (
            mock.patch.object(sys, "platform", "linux"),
            mock.patch.object(Path, "read_bytes", side_effect=FileNotFoundError),
        ):
            self.assertFalse(process_is_executing_for_test(123))

        with mock.patch.object(Path, "read_bytes", return_value=b"malformed\n"):
            with self.assertRaisesRegex(AssertionError, "malformed"):
                linux_process_state(123)

    def test_history_preflight_manifest_covers_every_new_commit_tree(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            graph = BootstrapGraph(temporary / "source")
            first_path = graph.root / "reports" / "daily" / "2026" / "07" / "15.md"
            first_path.parent.mkdir(parents=True, exist_ok=True)
            first_path.write_text("first retained report\n", encoding="utf-8")
            first = commit_all(graph.root, "append first retained report")
            first_blob = git(
                graph.root,
                "rev-parse",
                f"{first}:reports/daily/2026/07/15.md",
            )
            first_path.unlink()
            second_path = graph.root / "reports" / "daily" / "2026" / "07" / "16.md"
            second_path.write_text("second retained report\n", encoding="utf-8")
            second = commit_all(graph.root, "replace retained report")

            preflight = preflight_complete_fixture(
                graph.git_dir,
                base_sha=graph.base,
                head_sha=second,
                tree_payload=tree_api_payloads(
                    graph.root,
                    (first, second),
                ),
                policy="history-v2",
            )
            self.assertEqual(
                tuple(commit.object_id for commit in preflight.commits),
                (first, second),
            )
            self.assertEqual(preflight.commit_count, 2)
            self.assertEqual(
                tuple(tree.tree_oid for tree in preflight.trees),
                tuple(dict.fromkeys(commit.tree_oid for commit in preflight.commits)),
            )
            self.assertIn(
                first_blob,
                {
                    entry.object_id
                    for entry in CI_MODULE.allowed_blob_entries(preflight)
                },
            )

            manifest = temporary / "preflight.json"
            CI_MODULE.write_json(manifest, preflight.as_dict())
            self.assertEqual(CI_MODULE.load_preflight(manifest), preflight)

    def test_history_preflight_manifest_has_an_independent_bounded_size(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            graph = BootstrapGraph(temporary / "repo")
            for index in range(700):
                graph.write(
                    f"bulk/file-{index:04d}.txt",
                    f"bounded manifest entry {index}\n",
                )
            head = commit_all(graph.root, "bounded manifest")
            preflight = preflight_complete_fixture(
                graph.git_dir,
                base_sha=graph.base,
                head_sha=head,
                tree_payload=tree_api_payload(graph.root, head),
                policy="history-v2",
            )
            encoded = CI_MODULE.compact_json_bytes(preflight.as_dict())
            self.assertGreater(len(encoded), CI_MODULE.MAX_POLICY_JSON_BYTES)
            self.assertLessEqual(
                len(encoded),
                CI_MODULE.MAX_PREFLIGHT_MANIFEST_BYTES,
            )

            manifest = temporary / "preflight.json"
            CI_MODULE.write_json(
                manifest,
                preflight.as_dict(),
                max_bytes=CI_MODULE.MAX_PREFLIGHT_MANIFEST_BYTES,
            )
            self.assertEqual(CI_MODULE.load_preflight(manifest), preflight)

    def test_history_preflight_rejects_deleted_sensitive_intermediate_before_fetch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            graph = BootstrapGraph(temporary / "source")
            sensitive = graph.root / "reports" / "api-token.txt"
            sensitive.parent.mkdir(parents=True, exist_ok=True)
            sensitive.write_text("intermediate secret-shaped data\n", encoding="utf-8")
            first = commit_all(graph.root, "add sensitive intermediate")
            sensitive_oid = git(
                graph.root,
                "rev-parse",
                f"{first}:reports/api-token.txt",
            )
            sensitive.unlink()
            second = commit_all(graph.root, "delete sensitive intermediate")
            git(graph.root, "config", "uploadpack.allowFilter", "true")

            bare = temporary / "candidate.git"
            subprocess.run(
                ["git", "init", "--bare", "--quiet", str(bare)],
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    f"--git-dir={bare}",
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "--depth=1",
                    graph.root.as_uri(),
                    graph.base,
                ],
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    f"--git-dir={bare}",
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "--depth=65",
                    "--filter=blob:none",
                    graph.root.as_uri(),
                    f"+{second}:refs/trusted-history/candidate",
                ],
                check=True,
            )
            seal_partial_bare_store(
                bare,
                expected_url=graph.root.as_uri(),
            )
            self.assertFalse(bare_object_exists_without_lazy_fetch(bare, sensitive_oid))

            payloads = tree_api_payloads(graph.root, (first, second))
            tree_requests: list[str] = []

            def load_tree(tree_oid: str) -> dict:
                tree_requests.append(tree_oid)
                return payloads[tree_oid]

            materialize_worktree = mock.Mock()
            with (
                mock.patch.object(
                    CI_MODULE,
                    "materialize_preflight_blobs",
                    side_effect=AssertionError(
                        "sensitive intermediate reached blob acquisition"
                    ),
                ) as blob_acquisition,
                self.assertRaisesRegex(CI_MODULE.GateError, "sensitive path"),
            ):
                preflight = CI_MODULE.preflight_git_candidate(
                    bare,
                    base_sha=graph.base,
                    head_sha=second,
                    tree_payload=None,
                    tree_payload_loader=load_tree,
                    policy="history-v2",
                )
                CI_MODULE.materialize_preflight_blobs(
                    bare,
                    preflight,
                    repository=("Joey-Tools/codex-session-retrospective-history"),
                    token="synthetic",
                )
                materialize_worktree()

            self.assertEqual(tree_requests, [])
            blob_acquisition.assert_not_called()
            materialize_worktree.assert_not_called()
            self.assertFalse(bare_object_exists_without_lazy_fetch(bare, sensitive_oid))

    def test_partial_bare_preflight_precedes_blob_refetch_and_materialization(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            graph = BootstrapGraph(temporary / "source")
            head = graph.create_candidate()
            git(graph.root, "config", "uploadpack.allowFilter", "true")
            bare = temporary / "candidate.git"
            subprocess.run(["git", "init", "--bare", "--quiet", str(bare)], check=True)
            subprocess.run(
                [
                    "git",
                    f"--git-dir={bare}",
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "--depth=1",
                    graph.root.as_uri(),
                    graph.base,
                ],
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    f"--git-dir={bare}",
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "--depth=2",
                    "--filter=blob:none",
                    graph.root.as_uri(),
                    f"+{head}:refs/bootstrap/candidate",
                ],
                check=True,
            )
            seal_partial_bare_store(
                bare,
                expected_url=graph.root.as_uri(),
            )
            preflight = CI_MODULE.preflight_git_candidate(
                bare,
                base_sha=graph.base,
                head_sha=head,
                tree_payload=tree_api_payload(graph.root, head),
                policy="bootstrap-v2",
            )
            manifest = temporary / "preflight.json"
            CI_MODULE.write_json(manifest, preflight.as_dict())

            candidate_only_oid = git(
                graph.root,
                "rev-parse",
                f"{head}:candidate.txt",
            )
            self.assertFalse(
                bare_object_exists_without_lazy_fetch(
                    bare,
                    candidate_only_oid,
                )
            )
            requested_oids: list[str] = []

            def load_blob(object_id: str) -> dict[str, object]:
                requested_oids.append(object_id)
                return blob_api_payload(graph.root, object_id)

            CI_MODULE.materialize_preflight_blobs(
                bare,
                CI_MODULE.load_preflight(manifest),
                repository="Joey-Tools/codex-session-retrospective-history",
                token="synthetic",
                blob_loader=load_blob,
            )
            self.assertEqual(
                requested_oids,
                [
                    entry.object_id
                    for entry in CI_MODULE.allowed_blob_entries(preflight)
                    if entry.object_id
                    not in {
                        base_entry.object_id
                        for base_entry in CI_MODULE.git_tree_entries(
                            bare,
                            graph.base,
                        )
                        if base_entry.object_type == "blob"
                    }
                ],
            )
            self.assertTrue(
                bare_object_exists_without_lazy_fetch(
                    bare,
                    candidate_only_oid,
                )
            )
            trusted_validator = CI_MODULE.trusted_validator_module()
            key_digests = dict(trusted_validator.BOOTSTRAP_V2_PUBLIC_KEY_SHA256)
            for relative in trusted_validator.HISTORY_V2_SIGNATURE_KEY_PATHS.values():
                key_digests[relative] = hashlib.sha256(
                    (graph.root / relative).read_bytes()
                ).hexdigest()
            with (
                mock.patch.object(
                    trusted_validator,
                    "BOOTSTRAP_V2_PUBLIC_KEY_SHA256",
                    key_digests,
                ),
                mock.patch.object(
                    trusted_validator,
                    "HistoryV2SignatureVerifier",
                    StructuralSignatureVerifier,
                ),
            ):
                CI_MODULE.verify_preflight_objects(
                    bare, CI_MODULE.load_preflight(manifest)
                )
            materialized = temporary / "candidate"
            subprocess.run(
                [
                    "git",
                    f"--git-dir={bare}",
                    "worktree",
                    "add",
                    "--quiet",
                    "--detach",
                    str(materialized),
                    head,
                ],
                check=True,
            )

            self.assertEqual(git(materialized, "rev-parse", "HEAD"), head)
            self.assertEqual(git(materialized, "status", "--porcelain=v1"), "")

            tampered = preflight.as_dict()
            tampered["total_blob_bytes"] += 1
            manifest.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaisesRegex(CI_MODULE.GateError, "counts changed"):
                CI_MODULE.load_preflight(manifest)

    def test_oid_only_preflight_rejects_filter_downgrade_and_early_blob(
        self,
    ) -> None:
        for attack in ("filter-downgrade", "early-blob"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as raw:
                temporary = Path(raw)
                graph = BootstrapGraph(temporary / "source")
                head = graph.create_candidate()
                git(graph.root, "config", "uploadpack.allowFilter", "true")
                bare = fetch_synthetic_candidate_store(
                    temporary,
                    graph,
                    head=head,
                    depth=2,
                    filtered=attack == "early-blob",
                )
                candidate_oid = git(
                    graph.root,
                    "rev-parse",
                    f"{head}:candidate.txt",
                )
                if attack == "early-blob":
                    self.assertFalse(
                        bare_object_exists_without_lazy_fetch(
                            bare,
                            candidate_oid,
                        )
                    )
                    observed = (
                        CI_MODULE.git_output(
                            bare,
                            "hash-object",
                            "-w",
                            "--stdin",
                            input_data=(graph.root / "candidate.txt").read_bytes(),
                            max_bytes=128,
                        )
                        .decode("ascii")
                        .strip()
                    )
                    self.assertEqual(observed, candidate_oid)
                else:
                    self.assertTrue(
                        bare_object_exists_without_lazy_fetch(
                            bare,
                            candidate_oid,
                        )
                    )

                tree_loader = mock.Mock(
                    side_effect=AssertionError(
                        "early candidate blob reached the tree API"
                    )
                )
                with self.assertRaisesRegex(
                    CI_MODULE.GateError,
                    "present before allowlisted acquisition",
                ):
                    CI_MODULE.preflight_git_candidate(
                        bare,
                        base_sha=graph.base,
                        head_sha=head,
                        tree_payload=None,
                        tree_payload_loader=tree_loader,
                        policy="bootstrap-v2",
                    )
                tree_loader.assert_not_called()

    def test_oid_only_preflight_rejects_promisor_remote_before_api(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            graph = BootstrapGraph(temporary / "source")
            head = graph.create_candidate()
            git(graph.root, "config", "uploadpack.allowFilter", "true")
            bare = fetch_synthetic_candidate_store(
                temporary,
                graph,
                head=head,
                depth=2,
                filtered=True,
                sealed=False,
            )
            tree_loader = mock.Mock(
                side_effect=AssertionError("promisor fallback reached the tree API")
            )
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "unsafe partial-clone or remote config",
            ):
                CI_MODULE.preflight_git_candidate(
                    bare,
                    base_sha=graph.base,
                    head_sha=head,
                    tree_payload=None,
                    tree_payload_loader=tree_loader,
                    policy="bootstrap-v2",
                )
            tree_loader.assert_not_called()

    def test_preflight_rejects_real_replace_ref_before_object_and_api_loaders(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            graph = BootstrapGraph(temporary / "source")
            head = graph.create_candidate()
            git(graph.root, "config", "uploadpack.allowFilter", "true")
            bare = fetch_synthetic_candidate_store(
                temporary,
                graph,
                head=head,
                depth=2,
                filtered=True,
            )
            subprocess.run(
                [
                    "git",
                    f"--git-dir={bare}",
                    "replace",
                    head,
                    graph.base,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            tree_loader = mock.Mock(
                side_effect=AssertionError("replace ref reached the tree API")
            )
            with (
                mock.patch.object(
                    CI_MODULE,
                    "candidate_commit_range",
                    side_effect=AssertionError(
                        "replace ref reached candidate object loading"
                    ),
                ) as object_loader,
                self.assertRaisesRegex(
                    CI_MODULE.GateError,
                    "replace refs are prohibited",
                ),
            ):
                CI_MODULE.preflight_git_candidate(
                    bare,
                    base_sha=graph.base,
                    head_sha=head,
                    tree_payload=None,
                    tree_payload_loader=tree_loader,
                    policy="bootstrap-v2",
                )
            object_loader.assert_not_called()
            tree_loader.assert_not_called()

    def test_preflight_fails_closed_on_replace_ref_inventory_uncertainty(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            graph = BootstrapGraph(temporary / "source")
            head = graph.create_candidate()
            bare = fetch_synthetic_candidate_store(
                temporary,
                graph,
                head=head,
                depth=2,
                filtered=False,
            )
            original_git_output = CI_MODULE.git_output
            attacks = {
                "enumeration-failure": CI_MODULE.GateError(
                    "synthetic enumeration failure"
                ),
                "malformed-output": b"refs/replace/not-canonical\r\n",
            }
            for label, outcome in attacks.items():
                with self.subTest(attack=label):
                    tree_loader = mock.Mock(
                        side_effect=AssertionError(
                            "uncertain replace refs reached the tree API"
                        )
                    )

                    def injected_git_output(
                        git_dir: Path,
                        *arguments: str,
                        **kwargs: object,
                    ) -> bytes:
                        if arguments[:1] == ("for-each-ref",):
                            if isinstance(outcome, Exception):
                                raise outcome
                            return outcome
                        return original_git_output(
                            git_dir,
                            *arguments,
                            **kwargs,
                        )

                    with (
                        mock.patch.object(
                            CI_MODULE,
                            "git_output",
                            side_effect=injected_git_output,
                        ),
                        mock.patch.object(
                            CI_MODULE,
                            "candidate_commit_range",
                            side_effect=AssertionError(
                                "uncertain replace refs reached object loading"
                            ),
                        ) as object_loader,
                        self.assertRaisesRegex(
                            CI_MODULE.GateError,
                            "replace ref inventory",
                        ),
                    ):
                        CI_MODULE.preflight_git_candidate(
                            bare,
                            base_sha=graph.base,
                            head_sha=head,
                            tree_payload=None,
                            tree_payload_loader=tree_loader,
                            policy="bootstrap-v2",
                        )
                    object_loader.assert_not_called()
                    tree_loader.assert_not_called()

    def test_preflight_rejects_partial_clone_config_before_api(self) -> None:
        unsafe_config = {
            "extension": ("extensions.partialClone", "origin"),
            "promisor": ("remote.origin.promisor", "true"),
            "partial-clone-filter": (
                "remote.origin.partialCloneFilter",
                "blob:none",
            ),
            "filter": ("remote.origin.filter", "blob:none"),
            "push-follow-tags": ("push.followTags", "true"),
            "url-rewrite": (
                "url.file:///tmp/untrusted/.insteadOf",
                "https://github.com/",
            ),
        }
        for label, (key, value) in unsafe_config.items():
            with self.subTest(config=label), tempfile.TemporaryDirectory() as raw:
                temporary = Path(raw)
                graph = BootstrapGraph(temporary / "source")
                head = graph.create_candidate()
                git(graph.root, "config", "uploadpack.allowFilter", "true")
                bare = fetch_synthetic_candidate_store(
                    temporary,
                    graph,
                    head=head,
                    depth=2,
                    filtered=True,
                )
                subprocess.run(
                    [
                        "git",
                        f"--git-dir={bare}",
                        "config",
                        key,
                        value,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                )
                tree_loader = mock.Mock(
                    side_effect=AssertionError(
                        "unsafe candidate config reached the tree API"
                    )
                )
                with (
                    mock.patch.object(
                        CI_MODULE,
                        "candidate_commit_range",
                        side_effect=AssertionError(
                            "unsafe candidate config reached object loading"
                        ),
                    ) as object_loader,
                    self.assertRaisesRegex(
                        CI_MODULE.GateError,
                        "unsafe partial-clone or remote config",
                    ),
                ):
                    CI_MODULE.preflight_git_candidate(
                        bare,
                        base_sha=graph.base,
                        head_sha=head,
                        tree_payload=None,
                        tree_payload_loader=tree_loader,
                        policy="bootstrap-v2",
                    )
                object_loader.assert_not_called()
                tree_loader.assert_not_called()

    def test_preflight_fails_closed_when_config_inventory_is_uncertain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            graph = BootstrapGraph(temporary / "source")
            head = graph.create_candidate()
            bare = fetch_synthetic_candidate_store(
                temporary,
                graph,
                head=head,
                depth=2,
                filtered=False,
            )
            tree_loader = mock.Mock(
                side_effect=AssertionError(
                    "uncertain candidate config reached the tree API"
                )
            )
            original_git_output = CI_MODULE.git_output

            def fail_config_inventory(
                git_dir: Path,
                *arguments: str,
                **kwargs: object,
            ) -> bytes:
                if arguments[:2] == ("config", "--local"):
                    raise CI_MODULE.GateError("synthetic config read failure")
                return original_git_output(git_dir, *arguments, **kwargs)

            with (
                mock.patch.object(
                    CI_MODULE,
                    "git_output",
                    side_effect=fail_config_inventory,
                ),
                mock.patch.object(
                    CI_MODULE,
                    "candidate_commit_range",
                    side_effect=AssertionError(
                        "uncertain candidate config reached object loading"
                    ),
                ) as object_loader,
                self.assertRaisesRegex(
                    CI_MODULE.GateError,
                    "config inventory could not be enumerated",
                ),
            ):
                CI_MODULE.preflight_git_candidate(
                    bare,
                    base_sha=graph.base,
                    head_sha=head,
                    tree_payload=None,
                    tree_payload_loader=tree_loader,
                    policy="bootstrap-v2",
                )
            object_loader.assert_not_called()
            tree_loader.assert_not_called()

    def test_blob_materialization_rechecks_replace_refs_and_config_before_api(
        self,
    ) -> None:
        for attack in ("replace-ref", "promisor-config"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as raw:
                temporary = Path(raw)
                graph = BootstrapGraph(temporary / "source")
                head = graph.create_candidate()
                git(graph.root, "config", "uploadpack.allowFilter", "true")
                bare = fetch_synthetic_candidate_store(
                    temporary,
                    graph,
                    head=head,
                    depth=2,
                    filtered=True,
                )
                preflight = CI_MODULE.preflight_git_candidate(
                    bare,
                    base_sha=graph.base,
                    head_sha=head,
                    tree_payload=tree_api_payload(graph.root, head),
                    policy="bootstrap-v2",
                )
                if attack == "replace-ref":
                    subprocess.run(
                        [
                            "git",
                            f"--git-dir={bare}",
                            "replace",
                            head,
                            graph.base,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=True,
                    )
                    expected_error = "replace refs are prohibited"
                else:
                    subprocess.run(
                        [
                            "git",
                            f"--git-dir={bare}",
                            "config",
                            "remote.origin.promisor",
                            "true",
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=True,
                    )
                    expected_error = "unsafe partial-clone or remote config"

                blob_loader = mock.Mock(
                    side_effect=AssertionError(
                        "unsafe repository policy reached the blob API"
                    )
                )
                with (
                    mock.patch.object(
                        CI_MODULE,
                        "git_tree_entries",
                        side_effect=AssertionError(
                            "unsafe repository policy reached tree loading"
                        ),
                    ) as tree_loader,
                    self.assertRaisesRegex(
                        CI_MODULE.GateError,
                        expected_error,
                    ),
                ):
                    CI_MODULE.materialize_preflight_blobs(
                        bare,
                        preflight,
                        repository=("Joey-Tools/codex-session-retrospective-history"),
                        token="synthetic",
                        blob_loader=blob_loader,
                    )
                tree_loader.assert_not_called()
                blob_loader.assert_not_called()

    def test_oid_only_preflight_accepts_unchanged_blob_metadata_transition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            graph = BootstrapGraph(temporary / "source")
            (graph.root / "AGENTS.md").chmod(0o755)
            head = commit_all(graph.root, "change tracked executable mode")
            git(graph.root, "config", "uploadpack.allowFilter", "true")
            bare = fetch_synthetic_candidate_store(
                temporary,
                graph,
                head=head,
                depth=65,
                filtered=True,
            )
            preflight = CI_MODULE.preflight_git_candidate(
                bare,
                base_sha=graph.base,
                head_sha=head,
                tree_payload=tree_api_payload(graph.root, head),
                policy="history-v2",
            )
            entry = next(
                candidate
                for candidate in preflight.entries
                if candidate.path == "AGENTS.md"
            )
            self.assertEqual(entry.mode, "100755")
            base_oids = {
                candidate.object_id
                for candidate in CI_MODULE.git_tree_entries(
                    bare,
                    graph.base,
                )
                if candidate.object_type == "blob"
            }
            self.assertTrue(
                all(
                    candidate.object_id in base_oids
                    for candidate in CI_MODULE.allowed_blob_entries(preflight)
                )
            )
            blob_loader = mock.Mock(
                side_effect=AssertionError("base blob reached the GitHub blob API")
            )
            CI_MODULE.materialize_preflight_blobs(
                bare,
                preflight,
                repository="Joey-Tools/codex-session-retrospective-history",
                token="synthetic",
                blob_loader=blob_loader,
            )
            blob_loader.assert_not_called()
            CI_MODULE.verify_preflight_objects(bare, preflight)

    def test_oid_only_preflight_reuses_blob_reachable_from_base_history(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            source = temporary / "source"
            subprocess.run(["git", "init", "--quiet", str(source)], check=True)
            configure_git(source)
            (source / "stable.txt").write_text("stable base blob\n", encoding="utf-8")
            historical = source / "historical.txt"
            historical.write_text("authenticated historical blob\n", encoding="utf-8")
            historical_commit = commit_all(source, "retain historical blob")
            historical_oid = git(
                source, "rev-parse", f"{historical_commit}:historical.txt"
            )
            historical.unlink()
            base = commit_all(source, "remove historical blob")
            historical.write_text("authenticated historical blob\n", encoding="utf-8")
            candidate = commit_all(source, "restore historical blob")
            git(source, "config", "uploadpack.allowFilter", "true")

            bare = temporary / "candidate.git"
            subprocess.run(["git", "init", "--bare", "--quiet", str(bare)], check=True)
            subprocess.run(
                [
                    "git",
                    f"--git-dir={bare}",
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "--depth=2",
                    source.as_uri(),
                    base,
                ],
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    f"--git-dir={bare}",
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "--depth=3",
                    "--filter=blob:none",
                    source.as_uri(),
                    f"+{candidate}:refs/candidate/head",
                ],
                check=True,
            )
            seal_partial_bare_store(bare, expected_url=source.as_uri())
            self.assertTrue(bare_object_exists_without_lazy_fetch(bare, historical_oid))
            self.assertNotIn(
                historical_oid,
                {
                    entry.object_id
                    for entry in CI_MODULE.git_tree_entries(bare, base)
                    if entry.object_type == "blob"
                },
            )

            preflight = CI_MODULE.preflight_git_candidate(
                bare,
                base_sha=base,
                head_sha=candidate,
                tree_payload=tree_api_payload(source, candidate),
                policy="history-v2",
            )
            blob_loader = mock.Mock(
                side_effect=AssertionError(
                    "authenticated base-history blob reached the GitHub API"
                )
            )
            CI_MODULE.materialize_preflight_blobs(
                bare,
                preflight,
                repository="Joey-Tools/codex-session-retrospective-history",
                token="synthetic",
                blob_loader=blob_loader,
            )
            blob_loader.assert_not_called()
            CI_MODULE.verify_preflight_objects(bare, preflight)

    def test_git_object_access_policy_is_closed_and_rejects_alternates(
        self,
    ) -> None:
        dangerous = {
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/tmp/untrusted-alternates",
            "GIT_CONFIG_PARAMETERS": "'remote.origin.promisor'='true'",
            "GIT_OBJECT_DIRECTORY": "/tmp/untrusted-objects",
            "GIT_REPLACE_REF_BASE": "refs/untrusted/",
        }
        with mock.patch.dict(os.environ, dangerous, clear=False):
            for module in (CI_MODULE, VALIDATOR_MODULE):
                with self.subTest(module=module.__name__):
                    environment = module.closed_git_environment()
                    self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
                    self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
                    self.assertEqual(environment["GIT_CONFIG_COUNT"], "0")
                    for name in dangerous:
                        self.assertNotIn(name, environment)

        with tempfile.TemporaryDirectory() as raw:
            bare = Path(raw) / "candidate.git"
            subprocess.run(
                ["git", "init", "--bare", "--quiet", str(bare)],
                check=True,
            )
            alternate = bare / "objects" / "info" / "alternates"
            alternate.write_text("/tmp/untrusted-objects\n", encoding="utf-8")
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "alternate object fallback is prohibited",
            ):
                CI_MODULE.git_text(bare, "remote")

            real_open = CI_MODULE.os.open
            resolved_alternate = alternate.resolve()

            def deny_alternate(path: object, *arguments: object) -> int:
                if Path(path).resolve() == resolved_alternate:
                    raise PermissionError("synthetic denial")
                return real_open(path, *arguments)

            with (
                mock.patch.object(
                    CI_MODULE.os,
                    "open",
                    side_effect=deny_alternate,
                ),
                self.assertRaisesRegex(
                    CI_MODULE.GateError,
                    "alternate policy is unreadable",
                ),
            ):
                CI_MODULE.git_text(bare, "remote")
            alternate.unlink()
            self.assertEqual(CI_MODULE.git_text(bare, "remote"), "")

    @unittest.skipIf(
        sys.platform == "darwin",
        "Darwin does not provide the Linux runner UID/sudo contract",
    )
    def test_linux_sudo_env_chdir_enters_nobody_owned_0700_execution_root(
        self,
    ) -> None:
        if not sys.platform.startswith("linux"):
            self.skipTest("requires Linux UID semantics")
        sudo = shutil.which("sudo")
        env_command = Path("/usr/bin/env")
        pwd_command = Path("/usr/bin/pwd")
        if sudo is None or not env_command.is_file() or not pwd_command.is_file():
            self.skipTest("sudo, /usr/bin/env, and /usr/bin/pwd are required")
        privilege_probe = subprocess.run(
            [sudo, "-n", "true"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if privilege_probe.returncode != 0:
            self.skipTest("passwordless sudo is unavailable")
        nobody = pwd.getpwnam("nobody")
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            temporary.chmod(0o755)
            execution = temporary / "execution"
            execution.mkdir(mode=0o700)
            subprocess.run(
                [
                    sudo,
                    "-n",
                    "chown",
                    f"{nobody.pw_uid}:{nobody.pw_gid}",
                    str(execution),
                ],
                check=True,
            )
            try:
                result = subprocess.run(
                    [
                        sudo,
                        "-n",
                        "-u",
                        "nobody",
                        "--",
                        str(env_command),
                        "-i",
                        "-C",
                        str(execution),
                        "PATH=/usr/bin:/bin",
                        str(pwd_command),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(Path(result.stdout.strip()), execution)
            finally:
                subprocess.run(
                    [
                        sudo,
                        "-n",
                        "chown",
                        f"{os.getuid()}:{os.getgid()}",
                        str(execution),
                    ],
                    check=True,
                )

    def test_permanent_ci_uses_env_chdir_after_uid_drop(self) -> None:
        permanent_job = load_workflow(PERMANENT_CI)["jobs"]["trusted_default_audit"]
        script = steps_by_name(permanent_job)["Run tests after dropping UID and cwd"][
            "run"
        ]
        self.assertNotIn("sudo -u nobody --chdir", script)
        self.assertEqual(
            script.count('/usr/bin/env -i -C "$DEFAULT_EXECUTION_ROOT"'),
            2,
        )

    def test_default_branch_execution_copy_preserves_exact_authority_tree(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            authority = temporary / "authority"
            subprocess.run(
                ["git", "init", "--quiet", str(authority)],
                check=True,
            )
            configure_git(authority)
            source = authority / "scripts" / "example.py"
            source.parent.mkdir(parents=True)
            source.write_text("VALUE = 1\n", encoding="utf-8")
            (authority / ".gitattributes").write_text(
                "scripts/example.py export-ignore\nmetadata.txt export-subst\n",
                encoding="utf-8",
            )
            metadata = authority / "metadata.txt"
            metadata.write_text("$Format:%H$\n", encoding="utf-8")
            executable = authority / "bin" / "run.sh"
            executable.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
            (authority / "empty.txt").write_bytes(b"")
            test_file = authority / "tests" / "test_execution_mutation.py"
            test_file.parent.mkdir(parents=True)
            test_file.write_text(
                "from pathlib import Path\n"
                "import unittest\n"
                "\n"
                "class ExecutionMutationTest(unittest.TestCase):\n"
                "    def test_mutates_only_disposable_tree(self) -> None:\n"
                "        Path('scripts/example.py').write_text(\n"
                "            'VALUE = 2\\n', encoding='utf-8'\n"
                "        )\n"
                "        Path('generated-by-test.txt').write_text(\n"
                "            'generated\\n', encoding='utf-8'\n"
                "        )\n",
                encoding="utf-8",
            )
            head = commit_all(authority, "default authority fixture")
            original_tree = git(authority, "rev-parse", "HEAD^{tree}")
            original_source = source.read_bytes()
            snapshot = CI_MODULE.capture_pristine_authority(
                authority,
                expected_head=head,
            )

            execution = temporary / "execution"
            prepared = CI_MODULE.prepare_default_execution_tree(
                authority,
                execution,
                expected_head=head,
            )
            self.assertEqual(prepared, snapshot)
            for relative in (
                ".gitattributes",
                "scripts/example.py",
                "metadata.txt",
                "bin/run.sh",
                "empty.txt",
            ):
                expected_bytes = (authority / relative).read_bytes()
                observed_bytes = (execution / relative).read_bytes()
                expected_oid = git(
                    authority,
                    "rev-parse",
                    f"{head}:{relative}",
                )
                self.assertEqual(observed_bytes, expected_bytes)
                self.assertEqual(
                    CI_MODULE.git_blob_object_id(
                        observed_bytes,
                        expected_length=len(expected_oid),
                    ),
                    expected_oid,
                )
            self.assertEqual(
                stat.S_IMODE((execution / "bin/run.sh").stat().st_mode),
                0o755,
            )
            self.assertEqual(
                stat.S_IMODE((execution / "scripts/example.py").stat().st_mode),
                0o644,
            )
            receipt_path = temporary / "authority-receipt.json"
            CI_MODULE.write_json(
                receipt_path,
                CI_MODULE.authority_snapshot_payload(prepared),
            )
            pycache = temporary / "pycache"
            pycache.mkdir(mode=0o700)
            environment = {
                **os.environ,
                "PYTHONHASHSEED": "0",
            }
            subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-X",
                    f"pycache_prefix={pycache}",
                    "-m",
                    "compileall",
                    "-q",
                    "-f",
                    "scripts",
                    "tests",
                ],
                cwd=execution,
                env=environment,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-X",
                    f"pycache_prefix={pycache}",
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    "tests",
                ],
                cwd=execution,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )

            CI_MODULE.verify_default_authority(
                authority,
                expected_head=head,
                receipt=CI_MODULE.load_authority_snapshot(receipt_path),
            )
            self.assertEqual(git(authority, "rev-parse", "HEAD"), head)
            self.assertEqual(
                git(authority, "rev-parse", "HEAD^{tree}"),
                original_tree,
            )
            self.assertEqual(git(authority, "status", "--porcelain=v1"), "")
            self.assertEqual(source.read_bytes(), original_source)
            self.assertFalse((authority / "generated-by-test.txt").exists())
            self.assertTrue((execution / "generated-by-test.txt").is_file())
            self.assertTrue(pycache.is_dir())
            self.assertFalse(any(authority.rglob("*.pyc")))

            source_stat = source.stat()
            os.utime(
                source,
                ns=(
                    source_stat.st_atime_ns,
                    source_stat.st_mtime_ns + 1_000_000,
                ),
            )
            CI_MODULE.verify_default_authority(
                authority,
                expected_head=head,
                receipt=prepared,
            )
            source.write_text("VALUE = 9\n", encoding="utf-8")
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "not pristine",
            ):
                CI_MODULE.verify_default_authority(
                    authority,
                    expected_head=head,
                    receipt=prepared,
                )

    def test_default_execution_copy_rejects_blob_bytes_not_bound_to_oid(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            authority = temporary / "authority"
            subprocess.run(
                ["git", "init", "--quiet", str(authority)],
                check=True,
            )
            configure_git(authority)
            (authority / "payload.txt").write_text(
                "authenticated payload\n",
                encoding="utf-8",
            )
            head = commit_all(authority, "authority blob fixture")
            original_output = CI_MODULE._authority_git_output

            def corrupt_blob_batch(
                root: Path,
                *arguments: str,
                **kwargs: object,
            ) -> bytes:
                value = original_output(root, *arguments, **kwargs)
                if arguments != ("cat-file", "--batch"):
                    return value
                header_end = value.find(b"\n")
                if header_end < 0 or header_end + 1 >= len(value):
                    raise AssertionError("synthetic blob batch was malformed")
                corrupted = bytearray(value)
                corrupted[header_end + 1] ^= 1
                return bytes(corrupted)

            execution = temporary / "execution"
            with (
                mock.patch.object(
                    CI_MODULE,
                    "_authority_git_output",
                    side_effect=corrupt_blob_batch,
                ),
                self.assertRaisesRegex(
                    CI_MODULE.GateError,
                    "content differs from its object ID",
                ),
            ):
                CI_MODULE.prepare_default_execution_tree(
                    authority,
                    execution,
                    expected_head=head,
                )
            self.assertFalse((execution / "payload.txt").exists())

    def test_runtime_execution_tree_is_exact_sealed_and_revalidated(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            source = temporary / "source"
            subprocess.run(["git", "init", "--quiet", str(source)], check=True)
            configure_git(source)
            (source / "requirements-v2.txt").write_text("", encoding="utf-8")
            scripts = source / "scripts"
            scripts.mkdir()
            executable = scripts / "tool.py"
            executable.write_text("VALUE = 1\n", encoding="utf-8")
            executable.chmod(0o755)
            tests = source / "tests"
            tests.mkdir()
            (tests / "test_smoke.py").write_text(
                "import unittest\n\n"
                "class SmokeTests(unittest.TestCase):\n"
                "    def test_smoke(self):\n"
                "        self.assertTrue(True)\n",
                encoding="utf-8",
            )
            head = commit_all(source, "runtime authority fixture")
            bare = temporary / "authority.git"
            subprocess.run(["git", "init", "--bare", "--quiet", str(bare)], check=True)
            subprocess.run(
                [
                    "git",
                    f"--git-dir={bare}",
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    str(source),
                    head,
                ],
                check=True,
            )
            execution = temporary / "execution"
            receipt = CI_MODULE.prepare_runtime_execution_tree(
                bare,
                execution,
                expected_head=head,
            )
            self.assertEqual(receipt.authority_uid, os.geteuid())
            self.assertEqual(stat.S_IMODE(execution.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(scripts.stat().st_mode), 0o755)
            self.assertEqual(
                stat.S_IMODE((execution / "scripts").stat().st_mode),
                0o555,
            )
            self.assertEqual(
                stat.S_IMODE((execution / "scripts/tool.py").stat().st_mode),
                0o555,
            )
            self.assertEqual(
                stat.S_IMODE((execution / "requirements-v2.txt").stat().st_mode),
                0o444,
            )
            pycache_root = temporary / "pycache"
            pycache_root.mkdir(mode=0o700)
            runtime_commands = (
                (
                    "-I",
                    "-B",
                    "-X",
                    f"pycache_prefix={pycache_root}",
                    "-m",
                    "compileall",
                    "-q",
                    "-f",
                    "scripts",
                    "tests",
                ),
                (
                    "-I",
                    "-B",
                    "-X",
                    f"pycache_prefix={pycache_root}",
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    "tests",
                ),
            )
            for arguments in runtime_commands:
                completed = subprocess.run(
                    [sys.executable, *arguments],
                    cwd=execution,
                    env={
                        "HOME": str(temporary / "home"),
                        "LANG": "C",
                        "LC_ALL": "C",
                        "PATH": "/usr/bin:/bin",
                        "TMPDIR": str(temporary),
                    },
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(
                    completed.returncode,
                    0,
                    completed.stderr.decode("utf-8", errors="replace"),
                )
            self.assertTrue(any(pycache_root.rglob("*.pyc")))
            self.assertFalse(any(execution.rglob("__pycache__")))
            CI_MODULE.verify_runtime_authority(
                bare,
                execution,
                expected_head=head,
                receipt=receipt,
            )
            receipt_path = temporary / "runtime-authority.json"
            CI_MODULE.write_json(
                receipt_path,
                CI_MODULE.runtime_authority_snapshot_payload(receipt),
            )
            self.assertEqual(
                CI_MODULE.load_runtime_authority_snapshot(receipt_path),
                receipt,
            )
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "root owner differs from the authority",
            ):
                CI_MODULE._execution_tree_inventory(
                    execution,
                    expected_directory_mode=0o555,
                    expected_owner_uid=os.geteuid() + 1,
                )
            (execution / "requirements-v2.txt").chmod(0o644)
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "access policy changed",
            ):
                CI_MODULE.verify_runtime_authority(
                    bare,
                    execution,
                    expected_head=head,
                    receipt=receipt,
                )
            (execution / "requirements-v2.txt").chmod(0o444)
            original_execution = temporary / "original-execution"
            execution.rename(original_execution)
            shutil.copytree(original_execution, execution)
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "root object identity changed",
            ):
                CI_MODULE.verify_runtime_authority(
                    bare,
                    execution,
                    expected_head=head,
                    receipt=receipt,
                )

    def test_default_execution_verifier_distinguishes_protected_properties(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            authority = temporary / "authority"
            subprocess.run(
                ["git", "init", "--quiet", str(authority)],
                check=True,
            )
            configure_git(authority)
            source = authority / "payload.txt"
            source.write_text("stable payload\n", encoding="utf-8")
            head = commit_all(authority, "execution verifier fixture")
            entries = CI_MODULE.git_tree_entries(authority / ".git", head)
            tree_oid = git(authority, "rev-parse", f"{head}^{{tree}}")
            execution = temporary / "execution"
            CI_MODULE.prepare_default_execution_tree(
                authority,
                execution,
                expected_head=head,
            )
            payload = execution / "payload.txt"
            original = payload.read_bytes()

            metadata = payload.stat()
            os.utime(
                payload,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000),
            )
            CI_MODULE.verify_default_execution_tree(
                execution,
                entries=entries,
                expected_tree_sha=tree_oid,
            )

            unexpected = execution / "unexpected.txt"
            unexpected.write_text("unexpected\n", encoding="utf-8")
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "unexpected paths",
            ):
                CI_MODULE.verify_default_execution_tree(
                    execution,
                    entries=entries,
                    expected_tree_sha=tree_oid,
                )
            unexpected.unlink()

            payload.chmod(0o600)
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "access policy changed",
            ):
                CI_MODULE.verify_default_execution_tree(
                    execution,
                    entries=entries,
                    expected_tree_sha=tree_oid,
                )
            payload.chmod(0o644)

            payload.write_bytes(b"mutated payload\n")
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "content differs from its object ID",
            ):
                CI_MODULE.verify_default_execution_tree(
                    execution,
                    entries=entries,
                    expected_tree_sha=tree_oid,
                )
            payload.write_bytes(original)
            payload.chmod(0o644)

            current = payload.stat()
            replaced = mock.Mock(
                st_mode=current.st_mode,
                st_dev=current.st_dev,
                st_ino=current.st_ino + 1,
            )
            with (
                mock.patch.object(
                    CI_MODULE.os,
                    "stat",
                    return_value=replaced,
                ),
                self.assertRaisesRegex(
                    CI_MODULE.GateError,
                    "replaced while being read",
                ),
            ):
                CI_MODULE._read_stable_execution_blob(
                    payload,
                    expected_mode=0o644,
                )

            real_open = CI_MODULE.os.open

            def deny_payload(path: object, *arguments: object) -> int:
                if Path(path) == payload:
                    raise PermissionError("synthetic denial")
                return real_open(path, *arguments)

            with (
                mock.patch.object(
                    CI_MODULE.os,
                    "open",
                    side_effect=deny_payload,
                ),
                self.assertRaisesRegex(
                    CI_MODULE.GateError,
                    "blob is unreadable",
                ),
            ):
                CI_MODULE._read_stable_execution_blob(
                    payload,
                    expected_mode=0o644,
                )

            payload.unlink()
            with self.assertRaisesRegex(
                CI_MODULE.GateError,
                "missing authenticated paths",
            ):
                CI_MODULE.verify_default_execution_tree(
                    execution,
                    entries=entries,
                    expected_tree_sha=tree_oid,
                )

    def test_all_inline_shell_scripts_pass_bash_and_shellcheck(self) -> None:
        for workflow_path in (WORKFLOW, PERMANENT_CI):
            workflow = load_workflow(workflow_path)
            for job in workflow["jobs"].values():
                for step in job["steps"]:
                    if "run" not in step:
                        continue
                    with self.subTest(workflow=workflow_path.name, step=step["name"]):
                        syntax = subprocess.run(
                            ["bash", "-n"],
                            input=step["run"],
                            text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            check=False,
                        )
                        self.assertEqual(syntax.returncode, 0, syntax.stderr)
                        if shutil.which("shellcheck"):
                            checked = subprocess.run(
                                [
                                    "shellcheck",
                                    "--shell=bash",
                                    "--severity=warning",
                                    "-",
                                ],
                                input=step["run"],
                                text=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                check=False,
                            )
                            self.assertEqual(
                                checked.returncode, 0, checked.stdout + checked.stderr
                            )


if __name__ == "__main__":
    unittest.main()
