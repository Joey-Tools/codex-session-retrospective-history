from __future__ import annotations

import ast
import base64
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "validate_retained_history.py"
)
BOOTSTRAP_WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "session-retrospective-v2-bootstrap.yml"
)
PERMANENT_CI_TEMPLATE = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "bootstrap"
    / "session-retrospective-v2-permanent-ci.yml"
)
TRUSTED_CI_HELPER = (
    Path(__file__).resolve().parents[1] / "scripts" / "trusted_history_ci.py"
)
FIXTURE_TIMESTAMP = 1_784_073_600
FIXTURE_SIGNER_FINGERPRINT = (
    "0123456789ABCDEF0123456789ABCDEF01234567"
)
SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "schemas"
    / "session-retrospective-v1.schema.json"
)
MANIFEST_SCHEMA = (
    Path(__file__).resolve().parents[1] / "schemas" / "retained-manifest-v1.schema.json"
)
SPEC = importlib.util.spec_from_file_location("validate_retained_history", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

EXPECTED_BOOTSTRAP_V2_FILES = frozenset(
    Path(path)
    for path in (
        ".github/workflows/ci.yml",
        ".gitignore",
        "AGENTS.md",
        "README.md",
        "data/README.md",
        "reports/README.md",
        "requirements-v2.in",
        "requirements-v2.txt",
        "retrospective-history-v2-admin-public.asc",
        "retrospective-history-v2-publisher.asc",
        "schemas/retained-manifest-v1.schema.json",
        "schemas/retained-manifest-v2.schema.json",
        "schemas/session-retrospective-v1.schema.json",
        "schemas/session-retrospective-v2.schema.json",
        "scripts/retrospective_history_attestation_v2.py",
        "scripts/retrospective_history_credentials_v2.py",
        "scripts/retrospective_history_git_v2.py",
        "scripts/retrospective_history_merge_v2.py",
        "scripts/retrospective_history_privacy_v2.py",
        "scripts/retrospective_history_templates_v2.py",
        "scripts/retrospective_history_v2.py",
        "scripts/validate_retained_history.py",
        "tests/test_retrospective_history_git_v2.py",
        "tests/test_retrospective_history_merge_v2.py",
        "tests/test_retrospective_history_privacy_v2.py",
        "tests/test_retrospective_history_v2.py",
        "tests/test_retrospective_history_v2_ci.py",
        "tests/test_retrospective_history_v2_schema_extensions.py",
        "tests/test_validate_retained_history.py",
    )
)

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
    "          python-version: \"3.12\"\n"
    "      - name: Validate JSON syntax\n"
    "        run: |\n"
    "          python -m json.tool schemas/session-retrospective-v1.schema.json >/dev/null\n"
    "          python -m json.tool schemas/retained-manifest-v1.schema.json >/dev/null\n"
    "      - name: Run tests\n"
    "        run: python -m unittest discover -s tests\n"
    "      - name: Validate retained history tree\n"
    "        run: python scripts/validate_retained_history.py --root .\n"
)


def synthetic_openpgp_packet(tag: int, body: bytes) -> bytes:
    if len(body) >= 192:
        raise ValueError("synthetic OpenPGP packet body is too large")
    return bytes((0xC0 | tag, len(body))) + body


def synthetic_openpgp_mpi(value: bytes) -> bytes:
    bit_length = (len(value) - 1) * 8 + value[0].bit_length()
    return bit_length.to_bytes(2, "big") + value


def synthetic_openpgp_subpacket(subpacket_type: int, payload: bytes) -> bytes:
    body = bytes((subpacket_type,)) + payload
    length = len(body)
    if length < 192:
        encoded_length = bytes((length,))
    elif length <= 8383:
        adjusted = length - 192
        encoded_length = bytes(((adjusted >> 8) + 192, adjusted & 0xFF))
    else:
        encoded_length = bytes((0xFF,)) + length.to_bytes(4, "big")
    return encoded_length + body


def synthetic_openpgp_user_attribute(payload: bytes) -> bytes:
    image_header = bytes((16, 0, 1, 1)) + bytes(12)
    return synthetic_openpgp_subpacket(1, image_header + payload)


def synthetic_bootstrap_v2_key_body() -> bytes:
    point = bytes((0x40,)) + bytes(range(1, 33))
    return (
        bytes((4, 0, 0, 0, 0, 22, len(MODULE.BOOTSTRAP_V2_ED25519_OID)))
        + MODULE.BOOTSTRAP_V2_ED25519_OID
        + synthetic_openpgp_mpi(point)
    )


def synthetic_bootstrap_v2_signature_body(
    *,
    hashed_subpackets: bytes = b"",
    unhashed_subpackets: bytes = b"",
) -> bytes:
    signature_mpi = synthetic_openpgp_mpi(b"\x01")
    return (
        bytes((4, 0x13, 22, 8))
        + len(hashed_subpackets).to_bytes(2, "big")
        + hashed_subpackets
        + len(unhashed_subpackets).to_bytes(2, "big")
        + unhashed_subpackets
        + bytes(2)
        + signature_mpi
        + signature_mpi
    )


def synthetic_workflow_with_step(step: str) -> str:
    return (
        "name: CI\n"
        "on: {}\n"
        "permissions: {}\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n" + step
    )


def synthetic_bootstrap_v2_public_key(
    *,
    user_id: str = "Synthetic Bootstrap",
    packets: tuple[tuple[int, bytes], ...] | None = None,
) -> bytes:
    if packets is None:
        packets = (
            (6, synthetic_bootstrap_v2_key_body()),
            (13, user_id.encode("utf-8")),
            (2, synthetic_bootstrap_v2_signature_body()),
        )
    encoded_packets = b"".join(
        synthetic_openpgp_packet(tag, body) for tag, body in packets
    )
    payload = base64.b64encode(encoded_packets).decode("ascii")
    return (
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
        "\n"
        + "\n".join(payload[index : index + 64] for index in range(0, len(payload), 64))
        + "\n"
        "-----END PGP PUBLIC KEY BLOCK-----\n"
    ).encode("ascii")


def run_fixture_git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
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


def run_fixture_git_bytes(
    root: Path, *arguments: str, input_data: bytes = b""
) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        env={
            **os.environ,
            "TZ": "UTC",
            "GIT_AUTHOR_DATE": f"{FIXTURE_TIMESTAMP} +0000",
            "GIT_COMMITTER_DATE": f"{FIXTURE_TIMESTAMP} +0000",
        },
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout


def fixture_mktree(root: Path, records: bytes) -> str:
    return run_fixture_git_bytes(root, "mktree", "-z", input_data=records).decode(
        "ascii"
    ).strip()


def fixture_signature_armor(
    *,
    timestamp: int = FIXTURE_TIMESTAMP,
    signer_fingerprint: str = FIXTURE_SIGNER_FINGERPRINT,
    public_key_algorithm: int = 22,
    hash_algorithm: int = MODULE.HISTORY_V2_SIGNATURE_HASH_ALGORITHM,
    hashed_subpackets: bytes | None = None,
    extra_hashed_subpackets: bytes = b"",
    noncanonical_creation_length: bool = False,
    unhashed_subpackets: bytes | None = None,
) -> bytes:
    fingerprint = bytes.fromhex(signer_fingerprint)
    creation_length = (
        bytes((255, 0, 0, 0, 5))
        if noncanonical_creation_length
        else b"\x05"
    )
    hashed = (
        hashed_subpackets
        if hashed_subpackets is not None
        else (
            creation_length
            + b"\x02"
            + timestamp.to_bytes(4, "big")
            + b"\x16\x21\x04"
            + fingerprint
        )
    ) + extra_hashed_subpackets
    unhashed = (
        unhashed_subpackets
        if unhashed_subpackets is not None
        else b"\x09\x10" + fingerprint[-8:]
    )
    mpi = bytes((0, 1, 1))
    body = (
        bytes((4, 0, public_key_algorithm, hash_algorithm))
        + len(hashed).to_bytes(2, "big")
        + hashed
        + len(unhashed).to_bytes(2, "big")
        + unhashed
        + bytes((0, 0))
        + mpi
        + (mpi if public_key_algorithm == 22 else b"")
    )
    packet = MODULE.encode_history_v2_signature_packet(body)
    encoded = base64.b64encode(packet).decode("ascii")
    payload_lines = [
        encoded[index : index + 64]
        for index in range(0, len(encoded), 64)
    ]
    checksum = base64.b64encode(MODULE.bootstrap_v2_crc24(packet)).decode(
        "ascii"
    )
    return (
        "-----BEGIN PGP SIGNATURE-----\n"
        "\n"
        + "\n".join(payload_lines)
        + "\n="
        + checksum
        + "\n-----END PGP SIGNATURE-----\n"
    ).encode("ascii")


def fixture_signature_headers(armor: bytes) -> tuple[bytes, ...]:
    lines = armor.removesuffix(b"\n").split(b"\n")
    return (
        b"gpgsig " + lines[0],
        *(b" " + line for line in lines[1:]),
    )


def fixture_store_commit(root: Path, raw_commit: bytes) -> str:
    return run_fixture_git_bytes(
        root,
        "hash-object",
        "-t",
        "commit",
        "-w",
        "--stdin",
        input_data=raw_commit,
    ).decode("ascii").strip()


def fixture_raw_commit(
    root: Path,
    *,
    tree_oid: str,
    parents: tuple[str, ...],
    message: str,
    author: str = MODULE.HISTORY_V2_CANONICAL_IDENTITY,
    committer: str = MODULE.HISTORY_V2_CANONICAL_IDENTITY,
    author_timestamp: int = FIXTURE_TIMESTAMP,
    committer_timestamp: int = FIXTURE_TIMESTAMP,
    author_timezone: str = "+0000",
    committer_timezone: str = "+0000",
    extra_headers: tuple[bytes, ...] = (),
    signature_armor: bytes | None = None,
    include_signature: bool = True,
) -> str:
    signature = signature_armor or fixture_signature_armor(
        timestamp=committer_timestamp
    )
    headers = [
        f"tree {tree_oid}".encode("ascii"),
        *(f"parent {parent}".encode("ascii") for parent in parents),
        (
            f"author {author} {author_timestamp} {author_timezone}"
        ).encode("utf-8"),
        (
            f"committer {committer} {committer_timestamp} {committer_timezone}"
        ).encode("utf-8"),
        *extra_headers,
        *(fixture_signature_headers(signature) if include_signature else ()),
    ]
    raw_commit = b"\n".join(headers) + b"\n\n" + message.encode("utf-8") + b"\n"
    return fixture_store_commit(root, raw_commit)


def fixture_set_head(root: Path, commit_oid: str) -> None:
    run_fixture_git(root, "update-ref", "HEAD", commit_oid)
    run_fixture_git(root, "reset", "--hard", "--quiet", commit_oid)


def parse_fixture_commit(root: Path, commit_oid: str) -> object:
    raw_commit = fixture_commit_bytes(root, commit_oid)
    return MODULE.parse_history_v2_commit_object(
        raw_commit,
        expected_oid=commit_oid,
    )


def fixture_commit_bytes(root: Path, commit_oid: str) -> bytes:
    return run_fixture_git_bytes(
        root,
        "cat-file",
        "commit",
        commit_oid,
    )


def fixture_commit_all(
    root: Path,
    message: str,
    *,
    parents: tuple[str, ...] | None = None,
    include_signature: bool = True,
) -> str:
    run_fixture_git(root, "add", "--all")
    tree_oid = run_fixture_git(root, "write-tree").stdout.strip()
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
        include_signature=include_signature,
    )
    fixture_set_head(root, commit_oid)
    return commit_oid


def git_cacheinfo_argument(object_id: str, relative: Path) -> str:
    return f"100644,{object_id},{relative.as_posix()}"


def initialize_bootstrap_v2_git_index(root: Path) -> None:
    subprocess.run(
        ["git", "init", "--quiet", str(root)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    run_fixture_git(root, "config", "commit.gpgsign", "false")
    run_fixture_git(root, "config", "tag.gpgsign", "false")
    name, email = MODULE.HISTORY_V2_CANONICAL_IDENTITY.rsplit(" <", 1)
    run_fixture_git(root, "config", "user.name", name)
    run_fixture_git(
        root,
        "config",
        "user.email",
        email.removesuffix(">"),
    )
    run_fixture_git(root, "add", "--all")


def write_bootstrap_v2_candidate(root: Path, *, initialize_git: bool = True) -> None:
    schema = {
        "$schema": MODULE.BOOTSTRAP_V2_JSON_SCHEMA_DIALECT,
        "title": "Synthetic bootstrap v2 schema",
        "type": "object",
    }
    for relative in EXPECTED_BOOTSTRAP_V2_FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative in MODULE.BOOTSTRAP_V2_PUBLIC_KEY_FILES:
            path.write_bytes(synthetic_bootstrap_v2_public_key())
        elif relative.suffix == ".json":
            path.write_text(json.dumps(schema), encoding="utf-8")
        elif relative == Path(".github/workflows/ci.yml"):
            path.write_text(
                PERMANENT_CI_TEMPLATE.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
        elif relative == Path(".gitignore"):
            path.write_text("build/\n", encoding="utf-8")
        elif relative.suffix == ".py":
            path.write_text(
                '"""Synthetic bootstrap v2 infrastructure."""\n', encoding="utf-8"
            )
        elif relative.name.startswith("requirements-v2"):
            path.write_text("jsonschema==4.23.0\n", encoding="utf-8")
        else:
            path.write_text(
                "Synthetic bootstrap v2 infrastructure.\n", encoding="utf-8"
            )
    helper = root / "scripts" / "trusted_history_ci.py"
    helper.write_text(TRUSTED_CI_HELPER.read_text(encoding="utf-8"), encoding="utf-8")
    if initialize_git:
        initialize_bootstrap_v2_git_index(root)


def write_bootstrap_v2_base(root: Path) -> None:
    files = {
        MODULE.BOOTSTRAP_V2_CI_PATH: LEGACY_CI,
        MODULE.BOOTSTRAP_V2_PERMANENT_CI_TEMPLATE_PATH: (
            PERMANENT_CI_TEMPLATE.read_text(encoding="utf-8")
        ),
        MODULE.BOOTSTRAP_WORKFLOW_PATH: BOOTSTRAP_WORKFLOW.read_text(
            encoding="utf-8"
        ),
        Path("tests/test_session_retrospective_v2_bootstrap.py"): (
            '"""Synthetic temporary bootstrap test."""\n'
        ),
        Path("scripts/trusted_history_ci.py"): TRUSTED_CI_HELPER.read_text(
            encoding="utf-8"
        ),
    }
    for relative, value in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
    initialize_bootstrap_v2_git_index(root)


def add_matching_bootstrap_v2_base_artifact(
    base_root: Path,
    candidate_root: Path,
    relative: Path,
) -> None:
    base_path = base_root / relative
    base_path.parent.mkdir(parents=True, exist_ok=True)
    base_path.write_bytes((candidate_root / relative).read_bytes())
    run_fixture_git(base_root, "add", relative.as_posix())


def write_tracked_append_only_artifact(root: Path, value: str) -> Path:
    relative = Path("retained/daily/2026-07-15/episodes.jsonl")
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    run_fixture_git(root, "add", relative.as_posix())
    return path


def write_synthetic_history_v2_domain_sources(root: Path) -> None:
    sources = {
        Path("scripts/retrospective_history_attestation_v2.py"): (
            'VALUE = "attestation"\n'
        ),
        Path("scripts/retrospective_history_credentials_v2.py"): (
            'VALUE = "credentials"\n'
        ),
        Path("scripts/retrospective_history_git_v2.py"): (
            'MAX_ARTIFACT_BYTES = {"manifest.json": 1024}\n'
            "def _verify_publisher_attestation(_blobs):\n"
            "    return True\n"
            "def build_pull_request_merge_plan(*_args):\n"
            "    return None, []\n"
            "def validate_default_branch_update(root, _base, _head):\n"
            "    return [] if (root / 'runs').is_dir() else ['missing runs']\n"
        ),
        Path("scripts/retrospective_history_privacy_v2.py"): (
            'VALUE = "privacy"\n'
        ),
        Path("scripts/retrospective_history_templates_v2.py"): (
            'VALUE = "templates"\n'
        ),
        Path("scripts/retrospective_history_v2.py"): (
            "def validate_v2_runs_with_inventory(*_args):\n"
            "    return [], ()\n"
        ),
    }
    for relative in MODULE.HISTORY_V2_DOMAIN_MODULE_PATHS:
        (root / relative).write_text(sources[relative], encoding="utf-8")
    run_fixture_git(
        root,
        "add",
        *(relative.as_posix() for relative in MODULE.HISTORY_V2_DOMAIN_MODULE_PATHS),
    )


def validate_synthetic_bootstrap_v2_candidate(
    root: Path,
    *,
    base_root: Path | None = None,
    synchronize_allowed_index: bool = True,
) -> list[str]:
    if synchronize_allowed_index:
        run_fixture_git(
            root,
            "add",
            "--all",
            "--",
            *(
                relative.as_posix()
                for relative in sorted(MODULE.BOOTSTRAP_V2_ALLOWED_FILES)
            ),
        )
    digests = {
        relative: hashlib.sha256((root / relative).read_bytes()).hexdigest()
        for relative in MODULE.BOOTSTRAP_V2_PUBLIC_KEY_FILES
    }
    with mock.patch.object(MODULE, "BOOTSTRAP_V2_PUBLIC_KEY_SHA256", digests):
        if base_root is not None:
            return MODULE.validate_bootstrap_v2_candidate(base_root, root)
        with tempfile.TemporaryDirectory() as raw_base:
            synthetic_base = Path(raw_base)
            write_bootstrap_v2_base(synthetic_base)
            # Scanner-focused fixtures may intentionally replace ci.yml. Authorize
            # that exact synthetic blob here; production migration coverage uses an
            # explicit base_root and never takes this test-only path.
            candidate_ci = root / MODULE.BOOTSTRAP_V2_CI_PATH
            candidate_ci_blob = MODULE.git_blob_object_id(
                candidate_ci,
                size=candidate_ci.stat().st_size,
                expected_length=40,
            )
            template = (
                synthetic_base / MODULE.BOOTSTRAP_V2_PERMANENT_CI_TEMPLATE_PATH
            )
            template.write_bytes(candidate_ci.read_bytes())
            run_fixture_git(synthetic_base, "add", "--all")
            with mock.patch.object(
                MODULE,
                "BOOTSTRAP_V2_PERMANENT_CI_BLOB_OID",
                candidate_ci_blob,
            ):
                return MODULE.validate_bootstrap_v2_candidate(synthetic_base, root)


def validate_synthetic_history_v2_tree(root: Path) -> list[str]:
    digests = {
        relative: hashlib.sha256((root / relative).read_bytes()).hexdigest()
        for relative in MODULE.BOOTSTRAP_V2_PUBLIC_KEY_FILES
    }
    with mock.patch.object(MODULE, "BOOTSTRAP_V2_PUBLIC_KEY_SHA256", digests):
        return MODULE.validate_history_v2_tree(root)


class FixtureStructuralSignatureVerifier:
    def __enter__(self) -> FixtureStructuralSignatureVerifier:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    @staticmethod
    def verify(signature: object) -> None:
        if not isinstance(signature, MODULE.HistoryV2CommitSignature):
            raise AssertionError("commit signature was not structurally validated")


def validate_synthetic_history_v2_merge_range(
    root: Path,
    *,
    base_rev: str,
    head_rev: str,
) -> dict[str, object]:
    digests = {
        relative: hashlib.sha256((root / relative).read_bytes()).hexdigest()
        for relative in MODULE.BOOTSTRAP_V2_PUBLIC_KEY_FILES
    }
    with (
        mock.patch.object(MODULE, "BOOTSTRAP_V2_PUBLIC_KEY_SHA256", digests),
        mock.patch.object(
            MODULE,
            "history_v2_signature_verifier_for_root",
            return_value=FixtureStructuralSignatureVerifier(),
        ),
    ):
        return MODULE.validate_history_v2_merge_range(
            root,
            base_rev=base_rev,
            head_rev=head_rev,
        )


def validate_synthetic_history_v2_default_transaction(
    root: Path,
    *,
    before_rev: str,
    head_rev: str,
    event_created: bool = False,
    event_deleted: bool = False,
    event_forced: bool = False,
) -> dict[str, object]:
    digests = {
        relative: hashlib.sha256((root / relative).read_bytes()).hexdigest()
        for relative in MODULE.BOOTSTRAP_V2_PUBLIC_KEY_FILES
    }
    with (
        mock.patch.object(MODULE, "BOOTSTRAP_V2_PUBLIC_KEY_SHA256", digests),
        mock.patch.object(
            MODULE,
            "history_v2_signature_verifier_for_root",
            return_value=FixtureStructuralSignatureVerifier(),
        ),
    ):
        return MODULE.validate_history_v2_default_transaction(
            root,
            before_rev=before_rev,
            head_rev=head_rev,
            event_created=event_created,
            event_deleted=event_deleted,
            event_forced=event_forced,
        )


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
        "episode_id": "episode_ref_v1:" + "a" * 20,
        "host": "local",
        "session_id": "session_ref_v1:" + "b" * 20,
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


def window_for_mode(mode: str) -> dict:
    if mode == "daily":
        start = "2026-05-21T00:00:00Z"
    elif mode == "weekly":
        start = "2026-05-15T00:00:00Z"
    elif mode == "baseline-90d":
        start = "2026-02-21T00:00:00Z"
    else:
        start = "2026-05-21T00:00:00Z"
    return {"mode": mode, "start": start, "end": "2026-05-22T00:00:00Z"}


def write_retained_export(root: Path, export_dir: Path, *, mode: str = "daily") -> None:
    trend = valid_trend()
    trend["window"] = window_for_mode(mode)
    manifest = valid_manifest()
    manifest["mode"] = mode
    manifest["window"] = window_for_mode(mode)
    export_dir.mkdir(parents=True)
    (export_dir / "episodes.jsonl").write_text(
        json.dumps(valid_episode()) + "\n", encoding="utf-8"
    )
    (export_dir / "turn_flags.jsonl").write_text(
        json.dumps(valid_turn_flag()) + "\n", encoding="utf-8"
    )
    (export_dir / "trend_report.json").write_text(json.dumps(trend), encoding="utf-8")
    (export_dir / "retained_manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )


def write_monthly_export(root: Path, *, year: str = "2026", month: str = "05") -> None:
    episodes_path = root / "data" / "episodes" / year / month / "episodes.jsonl"
    turn_flags_path = root / "data" / "turn_flags" / year / month / "turn_flags.jsonl"
    trend_path = root / "data" / "trends" / year / month / "trend_report.json"
    episodes_path.parent.mkdir(parents=True)
    turn_flags_path.parent.mkdir(parents=True)
    trend_path.parent.mkdir(parents=True)
    episodes_path.write_text(json.dumps(valid_episode()) + "\n", encoding="utf-8")
    turn_flags_path.write_text(json.dumps(valid_turn_flag()) + "\n", encoding="utf-8")
    trend_path.write_text(json.dumps(valid_trend()), encoding="utf-8")


def risky_local_path() -> str:
    return "/Us" + "ers/hoteng/.cod" + "ex/sess" + "ions/2026/05/22/rollout.jsonl"


def risky_project_path() -> str:
    return "/Us" + "ers/hoteng/project"


def risky_internal_url() -> str:
    return "HTTPS://internal" + ".example/path"


def risky_localhost_url() -> str:
    return "http" + "://localhost:3000/status"


def risky_private_ip_url() -> str:
    return "http" + "://" + risky_bare_private_ip() + ":8080/status"


def risky_bare_private_ip() -> str:
    return "10" + ".0.0.5"


def risky_bare_private_lan_ip() -> str:
    return "192" + ".168.1.4"


def risky_link_local_ip() -> str:
    return "169" + ".254.169.254"


def risky_cgnat_ip() -> str:
    return "100" + ".64.0.1"


def risky_private_ipv6() -> str:
    return "fc00" + ":" + ":1"


def risky_link_local_ipv6() -> str:
    return "fe80" + ":" + ":1"


def risky_loopback_ipv6() -> str:
    return "::" + "1"


def risky_short_host_url() -> str:
    return "http" + "://miku-bot-dev:8080/status"


def risky_private_ip_ssh_url() -> str:
    return "ssh" + "://git@" + risky_bare_private_ip() + "/repo"


def risky_short_host_git_remote() -> str:
    return "git" + "@miku-bot-dev:repo.git"


def risky_ssh_url() -> str:
    return "ssh" + "://git@" + "example" + ".internal/repo"


def risky_internal_host() -> str:
    return "jira.cisco" + ".example"


def risky_email() -> str:
    return "operator" + "@" + "redacted" + ".com"


def risky_single_label_internal_email() -> str:
    return "operator" + "@" + "corp"


def risky_home_arpa_domain() -> str:
    return "service" + ".home" + ".arpa"


def risky_srv_private_path() -> str:
    return "/" + "srv/private/report"


def risky_repeated_slash_srv_private_path() -> str:
    return "/" + "srv/" + "/" + "private/report"


def risky_cloud_access_key_id() -> str:
    return "AK" + "IA" + ("A" * 16)


def risky_temporary_cloud_access_key_id() -> str:
    return "AS" + "IA" + ("B" * 16)


def risky_legacy_cloud_access_key_id() -> str:
    return "A3" + "T" + ("C" * 17)


def risky_action_reference(ref: str) -> str:
    return "owner/action" + "@" + ref


def risky_action_like_internal_email() -> str:
    return "owner/" + risky_single_label_internal_email()


def risky_action_like_version_email() -> str:
    return "owner/operator" + "@" + "v4"


def risky_long_action_like_email() -> str:
    return "owner/operator" + "@" + "v4/private"


def risky_multilabel_internal_email(suffix: str) -> str:
    return "operator" + "@" + "corp." + suffix


def risky_secret_token() -> str:
    return "s" + "k-" + "proj-" + "abcdefghijklmnop123456"


def risky_github_classic_token() -> str:
    return "gh" + "p_" + ("a" * 36)


def risky_github_oauth_token() -> str:
    return "gh" + "o_" + ("b" * 36)


def risky_fine_grained_github_token() -> str:
    return "github" + "_pat_" + ("c" * 24)


def risky_raw_hash() -> str:
    return "a" * 64


def risky_uuid() -> str:
    return "12345678-" + "1234-" + "1234-" + "1234-" + "123456789abc"


def risky_session_pointer() -> str:
    return "Session " + "ID: abc123456"


def risky_turn_pointer() -> str:
    return "turn-" + "id=abc123456"


def risky_episode_pointer() -> str:
    return "episode_" + "id=abc123456"


def risky_space_session_pointer() -> str:
    return "Session " + "ID abc123456"


def risky_dotted_session_pointer() -> str:
    return "session." + "id: abc123456"


def risky_space_turn_pointer() -> str:
    return "turn " + "id abc123456"


def risky_dotted_episode_pointer() -> str:
    return "episode." + "id: abc123456"


def risky_camel_session_pointer() -> str:
    return "session" + "Id: abc123456"


def risky_camel_turn_pointer() -> str:
    return "turn" + "Id=abc123456"


def risky_camel_episode_pointer() -> str:
    return "episode" + "ID abc123456"


def risky_compound_session_token() -> str:
    return "session_" + "id_abc123456"


def risky_compound_turn_token() -> str:
    return "turn-" + "id-abc123456"


def risky_compound_episode_token() -> str:
    return "episode." + "id.abc123456"


def risky_compound_camel_session_token() -> str:
    return "session" + "Id_abc123456"


def risky_compound_camel_turn_token() -> str:
    return "turn" + "Id-abc123456"


def risky_rollout_filename() -> str:
    return "rollout-" + "2026-05-22T10-00-00-abc.jsonl"


class ValidateRetainedHistoryTests(unittest.TestCase):
    def assert_python_privacy_layers_reject(
        self,
        source: str,
        expected: str,
    ) -> None:
        relative = Path("tests/test_retrospective_history_v2.py")
        self.assertFalse(
            MODULE.contains_bootstrap_v2_privacy_risk_text(
                source,
                relative=relative,
            )
        )
        with self.assertRaisesRegex(ValueError, expected):
            MODULE.bootstrap_v2_python_privacy_risk_values(source)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_bootstrap_v2_candidate(root)
            (root / relative).write_text(source, encoding="utf-8")

            issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

        self.assertIn(expected, issues)

    def test_bundle_schema_includes_manifest_root(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

        self.assertIn({"$ref": "#/$defs/manifest"}, schema["oneOf"])

    def test_schema_host_allowlist_matches_validator(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        manifest_schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))
        expected = sorted(MODULE.RETAINED_EVIDENCE_HOSTS)
        coverage_expected = sorted(MODULE.RETAINED_HOSTS)

        self.assertEqual(sorted(schema["$defs"]["retained_host"]["enum"]), expected)
        self.assertEqual(
            sorted(schema["$defs"]["retained_coverage_host"]["enum"]), coverage_expected
        )
        self.assertEqual(
            sorted(manifest_schema["$defs"]["retained_host"]["enum"]), expected
        )
        self.assertEqual(
            sorted(manifest_schema["$defs"]["retained_coverage_host"]["enum"]),
            coverage_expected,
        )
        self.assertEqual(
            schema["$defs"]["episode"]["properties"]["host"],
            {"$ref": "#/$defs/retained_host"},
        )
        self.assertEqual(
            schema["$defs"]["turn_flag"]["properties"]["host"],
            {"$ref": "#/$defs/retained_host"},
        )
        self.assertEqual(
            schema["$defs"]["source_summary"]["properties"]["host"],
            {"$ref": "#/$defs/retained_host"},
        )
        self.assertEqual(
            schema["$defs"]["coverage_gap"]["properties"]["host"],
            {"$ref": "#/$defs/retained_coverage_host"},
        )
        self.assertEqual(
            schema["$defs"]["trend"]["properties"]["hosts"],
            {"$ref": "#/$defs/retained_host_count_map"},
        )
        self.assertEqual(
            manifest_schema["$defs"]["source_summary"]["properties"]["host"],
            {"$ref": "#/$defs/retained_host"},
        )
        self.assertEqual(
            manifest_schema["$defs"]["coverage_gap"]["properties"]["host"],
            {"$ref": "#/$defs/retained_coverage_host"},
        )

    def test_schema_coverage_gap_reasons_match_validator(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        manifest_schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))
        expected = sorted(MODULE.COVERAGE_REASONS)

        self.assertEqual(
            sorted(schema["$defs"]["coverage_gap"]["properties"]["reason"]["enum"]),
            expected,
        )
        self.assertEqual(
            sorted(
                manifest_schema["$defs"]["coverage_gap"]["properties"]["reason"]["enum"]
            ),
            expected,
        )

    def test_schema_issue_flags_match_validator(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        expected = sorted(MODULE.ISSUE_FLAGS)

        self.assertEqual(sorted(schema["$defs"]["issue_flag"]["enum"]), expected)
        self.assertEqual(
            schema["$defs"]["episode"]["properties"]["friction_flags"]["items"],
            {"$ref": "#/$defs/issue_flag"},
        )
        self.assertEqual(
            schema["$defs"]["turn_flag"]["properties"]["issue_flags"]["items"],
            {"$ref": "#/$defs/issue_flag"},
        )
        self.assertEqual(
            schema["$defs"]["trend"]["properties"]["flags"],
            {"$ref": "#/$defs/issue_flag_count_map"},
        )

    def test_schema_retained_text_patterns_cover_compound_secrets_and_case_paths(
        self,
    ) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        schema_patterns = [
            re.compile(item["pattern"])
            for item in schema["$defs"]["retained_text"]["not"]["anyOf"]
        ]
        patterns = "\n".join(pattern.pattern for pattern in schema_patterns)

        self.assertIn("[A-Za-z0-9._-]*(?:", patterns)
        self.assertIn("[Pp][Rr][Ii][Vv][Aa][Tt][Ee][\\s._-]*[Kk][Ee][Yy]", patterns)
        self.assertIn("[Uu][Ss][Ee][Rr][Ss]", patterns)
        self.assertIn("[Ww][Oo][Rr][Kk][Ss][Pp][Aa][Cc][Ee]", patterns)
        for sample in (
            "api" + "key: abc",
            "api " + "key: abc",
            "secret " + "key: abc",
            "private" + "key: abc",
            "private " + "key: abc",
            "api" + "Key: [REDACTED]",
            "private" + "Key = <redacted>",
            "GitHub token " + risky_github_classic_token(),
            "GitHub OAuth token " + risky_github_oauth_token(),
            "GitHub fine-grained token " + risky_fine_grained_github_token(),
            "customer data",
            "PII",
            "production",
        ):
            with self.subTest(sample=sample):
                self.assertTrue(
                    any(pattern.search(sample) for pattern in schema_patterns)
                )
        for sample in (
            risky_bare_private_ip(),
            risky_bare_private_lan_ip(),
            risky_link_local_ip(),
            risky_cgnat_ip(),
            risky_private_ipv6(),
            risky_link_local_ipv6(),
            risky_loopback_ipv6(),
            "FC00" + ":" + ":1",
            "FD00" + ":" + ":1",
            "FE80" + ":" + ":1",
        ):
            with self.subTest(sample=sample):
                self.assertTrue(
                    any(pattern.search(sample) for pattern in schema_patterns)
                )

    def test_schema_raw_id_pattern_is_fully_case_insensitive(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        raw_id_pattern = next(
            item["pattern"]
            for item in schema["$defs"]["retained_text"]["not"]["anyOf"]
            if "session_ref_v1" in item["pattern"]
        )
        raw_id_re = re.compile(raw_id_pattern)

        for text in (
            "SESS" + "ION_ID: abc123456",
            "TURN" + "_ID=abc123456",
            "EPIS" + "ODE ID: abc123456",
            risky_space_session_pointer(),
            risky_dotted_session_pointer(),
            risky_space_turn_pointer(),
            risky_dotted_episode_pointer(),
            risky_camel_session_pointer(),
            risky_camel_turn_pointer(),
            risky_camel_episode_pointer(),
        ):
            with self.subTest(text=text):
                self.assertIsNotNone(raw_id_re.search(text))

        self.assertIsNone(raw_id_re.search("session_id: session_ref_v1:" + "a" * 20))

    def test_schema_safe_token_patterns_cover_compound_secret_names(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        manifest_schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))
        schema_patterns = [
            re.compile(item["pattern"])
            for item in schema["$defs"]["safe_token"]["not"]["anyOf"]
        ]
        manifest_schema_patterns = [
            re.compile(item["pattern"])
            for item in manifest_schema["$defs"]["safe_token"]["not"]["anyOf"]
        ]
        patterns = "\n".join(pattern.pattern for pattern in schema_patterns)
        manifest_patterns = "\n".join(
            pattern.pattern for pattern in manifest_schema_patterns
        )

        self.assertIn("[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll][Ss]?", patterns)
        self.assertIn("[Pp][Rr][Ii][Vv][Aa][Tt][Ee][._-]?[Kk][Ee][Yy]", patterns)
        self.assertIn(
            "[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll][Ss]?", manifest_patterns
        )
        self.assertIn(
            "[Pp][Rr][Ii][Vv][Aa][Tt][Ee][._-]?[Kk][Ee][Yy]", manifest_patterns
        )
        for sample in (
            risky_compound_session_token(),
            risky_compound_turn_token(),
            risky_compound_episode_token(),
            risky_compound_camel_session_token(),
            risky_compound_camel_turn_token(),
            risky_github_classic_token(),
            risky_github_oauth_token(),
            risky_fine_grained_github_token(),
        ):
            with self.subTest(sample=sample):
                self.assertTrue(
                    any(pattern.search(sample) for pattern in schema_patterns)
                )
                self.assertTrue(
                    any(pattern.search(sample) for pattern in manifest_schema_patterns)
                )
        for sample in (
            risky_bare_private_ip(),
            risky_bare_private_lan_ip(),
            risky_link_local_ip(),
            risky_cgnat_ip(),
        ):
            with self.subTest(sample=sample):
                self.assertTrue(
                    any(pattern.search(sample) for pattern in schema_patterns)
                )
                self.assertTrue(
                    any(pattern.search(sample) for pattern in manifest_schema_patterns)
                )

    def test_schema_restricts_retained_modes_models_and_source_hashes(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        manifest_schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))

        self.assertEqual(
            sorted(schema["$defs"]["retained_mode"]["anyOf"][0]["enum"]),
            sorted(MODULE.RETAINED_FIXED_MODES),
        )
        self.assertEqual(
            schema["$defs"]["retained_mode"]["anyOf"][1]["pattern"],
            MODULE.BASELINE_MODE_RE.pattern,
        )
        self.assertEqual(
            sorted(manifest_schema["$defs"]["retained_mode"]["anyOf"][0]["enum"]),
            sorted(MODULE.RETAINED_FIXED_MODES),
        )
        self.assertEqual(
            manifest_schema["$defs"]["retained_mode"]["anyOf"][1]["pattern"],
            MODULE.BASELINE_MODE_RE.pattern,
        )
        self.assertEqual(
            sorted(schema["$defs"]["retained_model_id"]["enum"]),
            sorted(MODULE.RETAINED_MODEL_IDS),
        )
        self.assertEqual(
            sorted(schema["$defs"]["retained_model_era"]["enum"]),
            sorted(MODULE.RETAINED_MODEL_ERAS),
        )
        self.assertEqual(
            schema["$defs"]["turn_flag"]["properties"]["source_hash"]["pattern"],
            MODULE.SOURCE_HASH_RE.pattern,
        )
        self.assertEqual(
            schema["$defs"]["trend"]["properties"]["window"], {"$ref": "#/$defs/window"}
        )
        self.assertEqual(
            schema["$defs"]["manifest"]["properties"]["mode"],
            {"$ref": "#/$defs/retained_mode"},
        )
        self.assertEqual(
            manifest_schema["properties"]["mode"], {"$ref": "#/$defs/retained_mode"}
        )
        self.assertIs(
            schema["$defs"]["episode"]["properties"]["friction_flags"]["uniqueItems"],
            True,
        )
        self.assertIs(
            schema["$defs"]["turn_flag"]["properties"]["issue_flags"]["uniqueItems"],
            True,
        )

    def test_schema_timestamp_patterns_reject_non_calendar_dates(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        manifest_schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))

        for pattern in (
            schema["$defs"]["timestamp_required"]["pattern"],
            manifest_schema["$defs"]["timestamp_required"]["pattern"],
        ):
            timestamp_re = re.compile(pattern)
            with self.subTest(pattern=pattern[:40]):
                self.assertIsNone(timestamp_re.fullmatch("2025-02-29T00:00:00Z"))
                self.assertIsNone(timestamp_re.fullmatch("2026-04-31T00:00:00Z"))
                self.assertIsNotNone(
                    timestamp_re.fullmatch("2024-02-29T00:00:00.123456789Z")
                )

    def test_clean_report_passes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            report = root / "reports" / "weekly" / "2026" / "05" / "08.md"
            report.parent.mkdir(parents=True)
            report.write_text(
                "# Weekly retrospective\n\nNo raw transcript excerpts retained.\n",
                encoding="utf-8",
            )

            self.assertEqual(MODULE.validate_root(root), [])

    def test_flat_retained_export_layout_passes(self) -> None:
        for export_name, mode in (
            ("daily", "daily"),
            ("weekly", "weekly"),
            ("baseline", "baseline-90d"),
        ):
            with self.subTest(export_name=export_name, mode=mode):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_retained_export(
                        root, root / "retained" / export_name, mode=mode
                    )

                    self.assertEqual(MODULE.validate_root(root), [])

    def test_flat_retained_export_rejects_extra_or_missing_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            (export_dir / "retained_manifest.json").unlink()

            self.assertIn(
                "retained export directory is incomplete or has extra files",
                "\n".join(MODULE.validate_root(root)),
            )

    def test_flat_retained_export_rejects_inconsistent_rows_and_trend(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            turn_flag = valid_turn_flag()
            turn_flag["episode_id"] = "episode_ref_v1:" + "b" * 20
            (export_dir / "turn_flags.jsonl").write_text(
                json.dumps(turn_flag) + "\n", encoding="utf-8"
            )
            trend = valid_trend()
            trend["turn_count"] = 0
            trend["flagged_turn_count"] = 0
            trend["episode_count"] = 0
            trend["flags"] = {}
            trend["hosts"] = {}
            trend["model_eras"] = {}
            (export_dir / "trend_report.json").write_text(
                json.dumps(trend), encoding="utf-8"
            )

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/daily/turn_flags.jsonl:1: episode_id is missing from episodes export",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: episode_count must match episodes.jsonl",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: flagged_turn_count must match turn_flags.jsonl",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: turn_count must match episodes.jsonl turn_count total",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: hosts must match episodes.jsonl turn_count totals",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: model_eras must match episodes.jsonl turn_count totals",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: flags must match turn_flags.jsonl issue_flags",
            issues,
        )

    def test_flat_retained_export_rejects_turn_flag_episode_identity_mismatch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            turn_flag = valid_turn_flag()
            turn_flag["host"] = "miku-bot-dev"
            turn_flag["session_id"] = "session_ref_v1:" + "c" * 20
            (export_dir / "turn_flags.jsonl").write_text(
                json.dumps(turn_flag) + "\n", encoding="utf-8"
            )

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/daily/turn_flags.jsonl:1: host must match referenced episode",
            issues,
        )
        self.assertIn(
            "retained/daily/turn_flags.jsonl:1: session_id must match referenced episode",
            issues,
        )

    def test_flat_retained_export_rejects_turn_flag_outside_episode_window(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            turn_flag = valid_turn_flag()
            turn_flag["timestamp"] = "2026-05-21T23:00:00Z"
            (export_dir / "turn_flags.jsonl").write_text(
                json.dumps(turn_flag) + "\n", encoding="utf-8"
            )

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/daily/turn_flags.jsonl:1: timestamp must be within referenced episode",
            issues,
        )

    def test_flat_retained_export_rejects_flagged_turn_count_above_episode_turn_count(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            episode_one = valid_episode()
            episode_one["turn_count"] = 0
            episode_two = valid_episode()
            episode_two["episode_id"] = "episode_ref_v1:" + "b" * 20
            episode_two["turn_count"] = 2
            trend = valid_trend()
            trend["episode_count"] = 2
            trend["turn_count"] = 2
            trend["flagged_turn_count"] = 1
            trend["hosts"] = {"local": 2}
            trend["model_eras"] = {"unknown": 2}
            (export_dir / "episodes.jsonl").write_text(
                json.dumps(episode_one) + "\n" + json.dumps(episode_two) + "\n",
                encoding="utf-8",
            )
            (export_dir / "trend_report.json").write_text(
                json.dumps(trend), encoding="utf-8"
            )

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/daily/turn_flags.jsonl: flagged turns must not exceed referenced episode turn_count",
            issues,
        )

    def test_flat_retained_export_rejects_rows_outside_trend_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            episode = valid_episode()
            episode["start"] = "2026-06-01T00:00:00Z"
            episode["end"] = "2026-06-01T01:00:00Z"
            turn_flag = valid_turn_flag()
            turn_flag["timestamp"] = "2026-06-01T00:00:00Z"
            (export_dir / "episodes.jsonl").write_text(
                json.dumps(episode) + "\n", encoding="utf-8"
            )
            (export_dir / "turn_flags.jsonl").write_text(
                json.dumps(turn_flag) + "\n", encoding="utf-8"
            )

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/daily/episodes.jsonl:1: episode start/end must be within trend window",
            issues,
        )
        self.assertIn(
            "retained/daily/turn_flags.jsonl:1: timestamp must be within trend window",
            issues,
        )

    def test_flat_retained_export_rejects_single_sided_episode_times_outside_trend_window(
        self,
    ) -> None:
        for start_value, end_value in (
            ("2026-06-01T00:00:00Z", None),
            (None, "2026-04-30T23:59:59Z"),
        ):
            with self.subTest(start=start_value, end=end_value):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    export_dir = root / "retained" / "daily"
                    write_retained_export(root, export_dir)
                    episode = valid_episode()
                    episode["start"] = start_value
                    episode["end"] = end_value
                    (export_dir / "episodes.jsonl").write_text(
                        json.dumps(episode) + "\n", encoding="utf-8"
                    )

                    issues = "\n".join(MODULE.validate_root(root))

                self.assertIn(
                    "retained/daily/episodes.jsonl:1: episode start/end must be within trend window",
                    issues,
                )

    def test_flat_retained_export_rejects_duplicate_ids(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            episode = valid_episode()
            turn_flag = valid_turn_flag()
            (export_dir / "episodes.jsonl").write_text(
                json.dumps(episode) + "\n" + json.dumps(episode) + "\n",
                encoding="utf-8",
            )
            (export_dir / "turn_flags.jsonl").write_text(
                json.dumps(turn_flag) + "\n" + json.dumps(turn_flag) + "\n",
                encoding="utf-8",
            )
            trend = valid_trend()
            trend["turn_count"] = 2
            trend["flagged_turn_count"] = 2
            trend["episode_count"] = 2
            trend["flags"] = {"verification_gap": 2}
            trend["hosts"] = {"local": 2}
            trend["model_eras"] = {"unknown": 2}
            (export_dir / "trend_report.json").write_text(
                json.dumps(trend), encoding="utf-8"
            )

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("retained/daily/episodes.jsonl:2: duplicate episode_id", issues)
        self.assertIn("retained/daily/turn_flags.jsonl:2: duplicate turn_id", issues)

    def test_empty_retained_exports_reject_nonzero_trends(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            (export_dir / "episodes.jsonl").write_text("", encoding="utf-8")
            (export_dir / "turn_flags.jsonl").write_text("", encoding="utf-8")
            flat_trend = valid_trend()
            (export_dir / "trend_report.json").write_text(
                json.dumps(flat_trend), encoding="utf-8"
            )
            write_monthly_export(root)
            monthly_episodes = (
                root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            )
            monthly_turn_flags = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            monthly_trend = (
                root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            )
            monthly_episodes.write_text("", encoding="utf-8")
            monthly_turn_flags.write_text("", encoding="utf-8")
            monthly_trend.write_text(json.dumps(valid_trend()), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/daily/trend_report.json: episode_count must match episodes.jsonl",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: flagged_turn_count must match turn_flags.jsonl",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: turn_count must match episodes.jsonl turn_count total",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: hosts must match episodes.jsonl turn_count totals",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: model_eras must match episodes.jsonl turn_count totals",
            issues,
        )
        self.assertIn(
            "retained/daily/trend_report.json: flags must match turn_flags.jsonl issue_flags",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: episode_count must match episodes.jsonl",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: flagged_turn_count must match turn_flags.jsonl",
            issues,
        )

    def test_monthly_trend_without_row_files_rejects_nonzero_counts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(valid_trend()), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/trends/2026/05/trend_report.json: episode_count must match episodes.jsonl",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: flagged_turn_count must match turn_flags.jsonl",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: turn_count must match episodes.jsonl turn_count total",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: hosts must match episodes.jsonl turn_count totals",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: model_eras must match episodes.jsonl turn_count totals",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: flags must match turn_flags.jsonl issue_flags",
            issues,
        )

    def test_monthly_artifact_windows_must_belong_to_path_month(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            trend = valid_trend()
            trend["turn_count"] = 0
            trend["flagged_turn_count"] = 0
            trend["episode_count"] = 0
            trend["flags"] = {}
            trend["hosts"] = {}
            trend["model_eras"] = {}
            trend["window"] = {
                "mode": "daily",
                "start": "2026-06-01T00:00:00Z",
                "end": "2026-06-02T00:00:00Z",
            }
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            manifest = valid_manifest()
            manifest["window"] = {
                "mode": "daily",
                "start": "2026-04-29T00:00:00Z",
                "end": "2026-04-30T00:00:00Z",
            }
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            manifest_path.parent.mkdir(parents=True)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/trends/2026/05/trend_report.json: window must overlap data month",
            issues,
        )
        self.assertIn(
            "data/manifests/2026/05/retained_manifest.json: window must overlap data month",
            issues,
        )

    def test_monthly_cross_month_weekly_export_allows_full_window_rows(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            window = {
                "mode": "weekly",
                "start": "2026-04-28T00:00:00Z",
                "end": "2026-05-05T00:00:00Z",
            }
            episode = valid_episode()
            episode["start"] = "2026-04-30T10:00:00Z"
            episode["end"] = "2026-04-30T11:00:00Z"
            turn_flag = valid_turn_flag()
            turn_flag["timestamp"] = "2026-04-30T10:30:00Z"
            trend = valid_trend()
            trend["window"] = window
            manifest = valid_manifest()
            manifest["mode"] = "weekly"
            manifest["window"] = window

            episode_path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            turn_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            episode_path.parent.mkdir(parents=True)
            turn_path.parent.mkdir(parents=True)
            trend_path.parent.mkdir(parents=True)
            manifest_path.parent.mkdir(parents=True)
            episode_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")
            turn_path.write_text(json.dumps(turn_flag) + "\n", encoding="utf-8")
            trend_path.write_text(json.dumps(trend), encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertNotIn("episode start/end must be within data month", issues)
        self.assertNotIn("timestamp must be within data month", issues)
        self.assertNotIn("must match episodes.jsonl", issues)
        self.assertNotIn("must match turn_flags.jsonl", issues)

    def test_invalid_data_month_paths_report_errors_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode_path = root / "data" / "episodes" / "0000" / "05" / "episodes.jsonl"
            episode_path.parent.mkdir(parents=True)
            episode_path.write_text(
                json.dumps(valid_episode()) + "\n", encoding="utf-8"
            )
            trend_path = root / "data" / "trends" / "9999" / "12" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(valid_trend()), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/episodes/0000/05/episodes.jsonl: unexpected JSONL artifact", issues
        )
        self.assertIn(
            "data/trends/9999/12/trend_report.json: unexpected JSON artifact", issues
        )

    def test_schema_version_rejects_bool(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_monthly_export(root)
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend = json.loads(trend_path.read_text(encoding="utf-8"))
            trend["schema_version"] = True
            trend_path.write_text(json.dumps(trend), encoding="utf-8")
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            manifest_path.parent.mkdir(parents=True)
            manifest = valid_manifest()
            manifest["schema_version"] = True
            manifest["redaction_policy_version"] = True
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/trends/2026/05/trend_report.json: trend schema_version must be 1",
            issues,
        )
        self.assertIn(
            "data/manifests/2026/05/retained_manifest.json: manifest schema_version must be 1",
            issues,
        )
        self.assertIn(
            "data/manifests/2026/05/retained_manifest.json: manifest redaction_policy_version must be 1",
            issues,
        )

    def test_monthly_turn_flags_check_episode_refs_without_trend(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            turn_flags_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            turn_flags_path.parent.mkdir(parents=True)
            turn_flags_path.write_text(
                json.dumps(valid_turn_flag()) + "\n", encoding="utf-8"
            )

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/turn_flags/2026/05/turn_flags.jsonl:1: episode_id is missing from episodes export",
            issues,
        )

    def test_monthly_rows_without_trend_must_match_path_month(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = valid_episode()
            episode["start"] = "2026-06-01T00:00:00Z"
            episode["end"] = "2026-06-01T01:00:00Z"
            episodes_path = (
                root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            )
            episodes_path.parent.mkdir(parents=True)
            episodes_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            turn_flag = valid_turn_flag()
            turn_flag["timestamp"] = "2026-04-30T23:59:59Z"
            turn_flags_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            turn_flags_path.parent.mkdir(parents=True)
            turn_flags_path.write_text(json.dumps(turn_flag) + "\n", encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/episodes/2026/05/episodes.jsonl:1: episode start/end must be within data month",
            issues,
        )
        self.assertIn(
            "data/turn_flags/2026/05/turn_flags.jsonl:1: timestamp must be within data month",
            issues,
        )

    def test_monthly_retained_artifacts_reject_inconsistent_rows_and_duplicates(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_monthly_export(root)
            episodes_path = (
                root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            )
            turn_flags_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            episode = valid_episode()
            turn_flag = valid_turn_flag()
            turn_flag["episode_id"] = "episode_ref_v1:" + "c" * 20
            episodes_path.write_text(
                json.dumps(episode) + "\n" + json.dumps(episode) + "\n",
                encoding="utf-8",
            )
            turn_flags_path.write_text(
                json.dumps(turn_flag) + "\n" + json.dumps(turn_flag) + "\n",
                encoding="utf-8",
            )
            trend = valid_trend()
            trend["turn_count"] = 0
            trend["flagged_turn_count"] = 0
            trend["episode_count"] = 0
            trend["flags"] = {}
            trend["hosts"] = {}
            trend["model_eras"] = {}
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/episodes/2026/05/episodes.jsonl:2: duplicate episode_id", issues
        )
        self.assertIn(
            "data/turn_flags/2026/05/turn_flags.jsonl:2: duplicate turn_id", issues
        )
        self.assertIn(
            "data/turn_flags/2026/05/turn_flags.jsonl:1: episode_id is missing from episodes export",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: episode_count must match episodes.jsonl",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: flagged_turn_count must match turn_flags.jsonl",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: turn_count must match episodes.jsonl turn_count total",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: hosts must match episodes.jsonl turn_count totals",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: model_eras must match episodes.jsonl turn_count totals",
            issues,
        )
        self.assertIn(
            "data/trends/2026/05/trend_report.json: flags must match turn_flags.jsonl issue_flags",
            issues,
        )

    def test_forbidden_raw_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "history.jsonl").write_text("{}\n", encoding="utf-8")

            self.assertIn(
                "forbidden raw/transient artifact",
                "\n".join(MODULE.validate_root(root)),
            )

    def test_forced_raw_session_directories_are_rejected(self) -> None:
        for relative_path in (
            "sess" + "ions/prompt.txt",
            "archived_" + "sess" + "ions/raw.txt",
            "Sess" + "ions/prompt.txt",
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    subprocess.run(
                        ["git", "init"], cwd=root, check=True, stdout=subprocess.DEVNULL
                    )
                    (root / ".gitignore").write_text(
                        "sess"
                        + "ions/\narchived_"
                        + "sess"
                        + "ions/\nSess"
                        + "ions/\n",
                        encoding="utf-8",
                    )
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text("raw prompt text\n", encoding="utf-8")
                    subprocess.run(
                        ["git", "add", "-f", relative_path], cwd=root, check=True
                    )

                    self.assertIn(
                        "forbidden raw/transient artifact",
                        "\n".join(MODULE.validate_root(root)),
                    )

    def test_compressed_raw_artifact_names_are_rejected(self) -> None:
        for relative_path in (
            "rollout-" + "2026-05-22.jsonl.gz",
            "session_index.jsonl.gz",
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    (root / relative_path).write_text(
                        "raw prompt text\n", encoding="utf-8"
                    )

                    self.assertIn(
                        "forbidden raw/transient artifact",
                        "\n".join(MODULE.validate_root(root)),
                    )

    def test_symlink_artifacts_are_rejected_without_following_target(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            link = root / "reports" / "weekly" / "linked.md"
            link.parent.mkdir(parents=True)
            os.symlink(risky_local_path(), link)

            self.assertIn(
                "symlink artifact is not allowed", "\n".join(MODULE.validate_root(root))
            )

    def test_retained_text_risks_are_rejected(self) -> None:
        risky_examples = (
            "Upper-case URL " + risky_internal_url(),
            "SSH URL " + risky_ssh_url(),
            "Raw session pointer " + risky_session_pointer(),
            "Raw turn pointer " + risky_turn_pointer(),
            "Raw episode pointer " + risky_episode_pointer(),
            "Raw session pointer " + risky_space_session_pointer(),
            "Raw dotted session pointer " + risky_dotted_session_pointer(),
            "Raw turn pointer " + risky_space_turn_pointer(),
            "Raw dotted episode pointer " + risky_dotted_episode_pointer(),
            "Raw camel session pointer " + risky_camel_session_pointer(),
            "Raw camel turn pointer " + risky_camel_turn_pointer(),
            "Raw camel episode pointer " + risky_camel_episode_pointer(),
            "Raw compound session pointer " + risky_compound_session_token(),
            "Raw compound turn pointer " + risky_compound_turn_token(),
            "Raw compound episode pointer " + risky_compound_episode_token(),
            "Raw compound camel session pointer "
            + risky_compound_camel_session_token(),
            "Raw compound camel turn pointer " + risky_compound_camel_turn_token(),
            '{"to' + 'ken":"redactedvalue"}',
            '{"api' + 'Key":"[REDACTED]"}',
            '{"private' + 'Key":""}',
            "private" + "Key = <redacted>",
            '{"access_to' + 'ken":"redactedvalue"}',
            '{"refresh-to' + 'ken":"redactedvalue"}',
            '{"client_sec' + 'ret":"redactedvalue"}',
            '{"db_pass' + 'word":"redactedvalue"}',
            '{"api' + 'key":"abc"}',
            '{"api_' + 'key":"abc"}',
            '{"private' + 'key":"abc"}',
            "api " + "key: abc",
            "secret " + "key: abc",
            "private " + "key: abc",
            "Contains customer data",
            "Contains PII",
            "Touching production",
            "Potentially destructive",
            "pass" + "word=12345",
            '{"private_' + 'key":"redactedvalue"}',
            '{"session_' + 'id":"abc123456"}',
            "Private key block -----BEGIN PRIVATE " + "KEY-----\nredacted",
            "PGP private key block -----BEGIN PGP PRIVATE "
            + "KEY BLOCK-----\nredacted",
            "Relative source path ./.cod" + "ex/sess" + "ions/2026/05/22/rollout.jsonl",
            "Case-variant source path ./.Cod"
            + "ex/Sess"
            + "ions/2026/05/22/Rollout-"
            + "ABC.JSONL",
            "Relative local source path .codex"
            + "-local/session-retrospective/out/state.json",
            "Relative temp source path .codex" + "-tmp/isolated-review/stdout.log",
            "Lower-case POSIX path /us" + "ers/hoteng/project",
            "Windows path C:\\Users\\hoteng\\project",
            "Lower-case Windows path C:\\users\\hoteng\\project",
            "Internal hostname " + risky_internal_host(),
            "Link local IP " + risky_link_local_ip(),
            "CGNAT IP " + risky_cgnat_ip(),
            "Private IPv6 " + risky_private_ipv6(),
            "Link local IPv6 " + risky_link_local_ipv6(),
            "Loopback IPv6 " + risky_loopback_ipv6(),
            "Rollout file " + risky_rollout_filename(),
            "Classic GitHub token " + risky_github_classic_token(),
            "OAuth GitHub token " + risky_github_oauth_token(),
            "Fine grained GitHub token " + risky_fine_grained_github_token(),
        )
        for text in risky_examples:
            with self.subTest(text=text):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    report = root / "reports" / "weekly" / "2026" / "05" / "08.md"
                    report.parent.mkdir(parents=True)
                    report.write_text(text + "\n", encoding="utf-8")

                    self.assertIn(
                        "retained text contains raw/sensitive evidence",
                        "\n".join(MODULE.validate_root(root)),
                    )

    def test_retained_readme_policy_language_can_name_safety_markers(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            data_readme = root / "data" / "README.md"
            reports_readme = root / "reports" / "README.md"
            weekly_report = root / "reports" / "weekly" / "2026" / "05" / "08.md"
            data_readme.parent.mkdir(parents=True)
            reports_readme.parent.mkdir(parents=True)
            weekly_report.parent.mkdir(parents=True)
            data_readme.write_text(
                "Retained summaries may count safety/privacy flags.\n", encoding="utf-8"
            )
            reports_readme.write_text(
                "Do not retain customer data or PII in report text.\n", encoding="utf-8"
            )
            weekly_report.write_text(
                "Summarized safety/privacy flags without raw evidence.\n",
                encoding="utf-8",
            )

            self.assertEqual(MODULE.validate_root(root), [])

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

                    self.assertIn(
                        "forbidden raw/transient artifact",
                        "\n".join(MODULE.validate_root(root)),
                    )

    def test_manifest_extra_risky_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = valid_manifest() | {"worklist": [risky_local_path()]}
            path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn("unexpected field is not allowed", issues)
            self.assertIn(
                "manifest retained text contains raw/sensitive evidence", issues
            )

    def test_manifest_unknown_risky_key_is_rejected_without_echoing_key(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            risky_key = risky_local_path()
            manifest = valid_manifest() | {risky_key: "opaque"}
            path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
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
            path.write_text(json.dumps(row), encoding="utf-8")

            self.assertIn(
                "unexpected field is not allowed", "\n".join(MODULE.validate_root(root))
            )

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
            path.write_text(json.dumps(row), encoding="utf-8")

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

    def test_unexpected_infrastructure_text_artifacts_are_rejected_and_scanned(
        self,
    ) -> None:
        for relative_path in (".github/notes.md", "tests/fixtures/source.json"):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    if artifact.suffix == ".json":
                        artifact.write_text(
                            json.dumps({"source": risky_internal_url()}),
                            encoding="utf-8",
                        )
                    else:
                        artifact.write_text(
                            risky_internal_url() + "\n", encoding="utf-8"
                        )

                    issues = "\n".join(MODULE.validate_root(root))
                    self.assertIn("unexpected", issues)
                    self.assertIn(
                        "retained text contains raw/sensitive evidence", issues
                    )

    def test_unexpected_retained_text_artifacts_are_rejected_without_risky_text(
        self,
    ) -> None:
        for relative_path in (
            "data/source-map.txt",
            "data/manifests/2026/05/worklist.txt",
            "reports/misc/notes.md",
            "reports/daily/2026/05/08.txt",
            "reports/daily/2026/13/08.md",
            "reports/weekly/0000/05/08.md",
            "reports/weekly/2026/02/31.md",
            "reports/baseline/90-day-windows/customer-acme.md",
            "reports/baseline/90-day-windows/2026-02-31_to_2026-03-01.md",
            "reports/baseline/90-day-windows/2026-03-01_to_2026-02-28.md",
            "reports/baseline/90-day-windows/2026-05-01_to_2026-05-02.md",
            "reports/baseline/90-day-windows/2026-01-01_to_2026-05-01.md",
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text(
                        "path_ref_v1:aaaaaaaaaaaaaaaa\n", encoding="utf-8"
                    )

                    self.assertIn(
                        "unexpected retained text artifact location",
                        "\n".join(MODULE.validate_root(root)),
                    )

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
                    artifact.write_text(
                        json.dumps({"items": [{"source": "opaque"}]}), encoding="utf-8"
                    )

                    self.assertIn(
                        "unexpected JSON artifact",
                        "\n".join(MODULE.validate_root(root)),
                    )

    def test_unknown_jsonl_artifacts_are_rejected(self) -> None:
        for relative_path in (
            "data/episodes/customer-acme/episodes.jsonl",
            "data/episodes/2026/05/customer-acme.jsonl",
            "data/turn_flags/customer-acme/turn_flags.jsonl",
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text("\n", encoding="utf-8")

                    self.assertIn(
                        "unexpected JSONL artifact",
                        "\n".join(MODULE.validate_root(root)),
                    )

    def test_raw_identifier_path_components_are_redacted_in_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            raw_component = "session_" + "id-rawabcdef123456.jsonl"
            artifact = root / "data" / "turn_flags" / "2026" / "05" / raw_component
            artifact.parent.mkdir(parents=True)
            artifact.write_text("\n", encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/turn_flags/2026/05/[redacted].jsonl: forbidden raw/transient artifact",
            issues,
        )
        self.assertNotIn(raw_component, issues)

    def test_risky_value_path_components_are_redacted_in_diagnostics(self) -> None:
        for leaked_component in (
            risky_github_classic_token() + ".json",
            risky_fine_grained_github_token() + ".jsonl",
            risky_secret_token() + ".md",
            risky_cloud_access_key_id() + ".json",
            risky_temporary_cloud_access_key_id() + ".json",
            risky_legacy_cloud_access_key_id() + ".json",
            risky_single_label_internal_email() + ".json",
            risky_home_arpa_domain() + ".json",
            risky_internal_host() + ".json",
        ):
            with self.subTest(leaked_component=leaked_component):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    artifact = (
                        root / "data" / "episodes" / "2026" / "05" / leaked_component
                    )
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text("{}\n", encoding="utf-8")

                    issues = "\n".join(MODULE.validate_root(root))

                self.assertIn("data/episodes/2026/05/[redacted]", issues)
                self.assertNotIn(leaked_component, issues)

    def test_path_diagnostic_redaction_tracks_bootstrap_privacy_patterns(self) -> None:
        synthetic_pattern = re.compile(r"future-private-category")
        patterns = (*MODULE.BOOTSTRAP_V2_PRIVACY_RISK_PATTERNS, synthetic_pattern)
        with mock.patch.object(MODULE, "BOOTSTRAP_V2_PRIVACY_RISK_PATTERNS", patterns):
            displayed = MODULE.display_relative_path(
                Path("data/episodes/2026/05/future-private-category.json")
            )

        self.assertEqual(displayed, "data/episodes/2026/05/[redacted].json")

    def test_path_diagnostics_reversibly_escape_nonprintable_characters(self) -> None:
        raw_component = (
            "\n::error::injected\r\x1b[31m\\literal"
            + chr(0x7F)
            + chr(0x200B)
            + chr(0x1D173)
            + ".txt"
        )

        displayed = MODULE.display_relative_path(Path(raw_component))

        self.assertEqual(
            displayed,
            "\\x0a::error::injected\\x0d\\x1b[31m\\\\literal"
            "\\x7f\\u200b\\U0001d173.txt",
        )
        self.assertEqual(
            bytes(displayed, "ascii").decode("unicode_escape"),
            raw_component,
        )
        self.assertTrue(all(character.isprintable() for character in displayed))

    def test_path_diagnostics_escape_direct_workflow_command_prefixes(self) -> None:
        for command_prefix in (
            "::error::",
            "::add-mask::",
            "::stop-commands::",
        ):
            with self.subTest(command_prefix=command_prefix):
                raw_component = command_prefix + "injected.txt"

                displayed = MODULE.display_relative_path(Path(raw_component))

                self.assertEqual(displayed, "\\x3a" + raw_component[1:])
                self.assertEqual(
                    bytes(displayed, "ascii").decode("unicode_escape"),
                    raw_component,
                )
                self.assertFalse(displayed.startswith("::"))
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    (root / raw_component).write_text("unexpected\n", encoding="utf-8")

                    issues = MODULE.validate_root(root)

                self.assertTrue(
                    any(issue.startswith(f"{displayed}: ") for issue in issues)
                )
                self.assertFalse(any(issue.startswith("::") for issue in issues))

    def test_invalid_jsonl_errors_do_not_include_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifact = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("{bad json\n", encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn(
                "data/episodes/2026/05/episodes.jsonl: line 1: invalid JSONL", issues
            )
            self.assertNotIn(str(root), issues)

    def test_os_errors_do_not_include_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifact = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("{}", encoding="utf-8")

            with mock.patch.object(
                MODULE,
                "parse_json_bytes",
                side_effect=PermissionError(13, "Permission denied", str(artifact)),
            ):
                issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/trends/2026/05/trend_report.json: PermissionError: Permission denied",
            issues,
        )
        self.assertNotIn(str(root), issues)
        self.assertNotIn(str(artifact), issues)

    def test_duplicate_jsonl_keys_are_rejected_before_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            row = valid_episode()
            entries = list(row.items())
            entries.insert(0, ("topic", risky_local_path()))
            artifact = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(
                "{"
                + ",".join(
                    json.dumps(key) + ":" + json.dumps(value) for key, value in entries
                )
                + "}\n",
                encoding="utf-8",
            )

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn(
                "line 1: invalid JSONL: duplicate JSON key is not allowed", issues
            )
            self.assertNotIn(str(root), issues)

    def test_duplicate_json_keys_are_rejected_before_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            trend = valid_trend()
            hidden_key = "raw_" + "secret"
            entries = list(trend.items())
            entries.insert(0, ("flags", {hidden_key: 1}))
            artifact = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(
                "{"
                + ",".join(
                    json.dumps(key) + ":" + json.dumps(value) for key, value in entries
                )
                + "}\n",
                encoding="utf-8",
            )

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn("duplicate JSON key is not allowed", issues)
            self.assertNotIn(str(root), issues)

    def test_non_finite_json_numbers_are_rejected_in_json_and_jsonl(self) -> None:
        for constant in ("NaN", "Infinity", "-Infinity", "1e10000", "-1e10000"):
            with self.subTest(constant=constant):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    json_path = root / "value.json"
                    json_path.write_text(
                        '{"value":' + constant + "}\n", encoding="utf-8"
                    )
                    with self.assertRaisesRegex(
                        ValueError,
                        "non-finite JSON numbers are not allowed",
                    ):
                        MODULE.parse_json(json_path)

                    jsonl_path = root / "value.jsonl"
                    jsonl_path.write_text(
                        '{"value":' + constant + "}\n", encoding="utf-8"
                    )
                    with self.assertRaisesRegex(
                        ValueError,
                        "line 1: invalid JSONL: non-finite JSON numbers are not allowed",
                    ):
                        MODULE.parse_jsonl(jsonl_path)

    def test_bootstrap_v2_json_rejects_non_finite_numbers(self) -> None:
        schema_path = Path("schemas/retained-manifest-v2.schema.json")
        for constant in ("NaN", "Infinity", "-Infinity", "1e10000", "-1e10000"):
            with self.subTest(constant=constant):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    (root / schema_path).write_text(
                        '{"$schema":'
                        + json.dumps(MODULE.BOOTSTRAP_V2_JSON_SCHEMA_DIALECT)
                        + ',"value":'
                        + constant
                        + "}\n",
                        encoding="utf-8",
                    )

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn("non-finite JSON numbers are not allowed", issues)

    def test_strict_json_preserves_finite_float_values(self) -> None:
        for value in ("0.0", "-0.0", "1.25", "1e308", "-1e-10000"):
            with self.subTest(value=value):
                self.assertEqual(
                    repr(MODULE.parse_strict_json(value)),
                    repr(json.loads(value)),
                )

    def test_unknown_retained_artifact_suffixes_are_rejected(self) -> None:
        for relative_path in ("data/source-map.csv", "reports/weekly/notes.yaml"):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text("opaque,summary\n", encoding="utf-8")

                    self.assertIn(
                        "unexpected retained artifact suffix",
                        "\n".join(MODULE.validate_root(root)),
                    )

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

            self.assertIn(
                "turn_count must be a bounded non-negative integer",
                "\n".join(MODULE.validate_root(root)),
            )

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
            path.write_text(json.dumps(row), encoding="utf-8")

            self.assertIn(
                "friction_flags must contain at most 16 items",
                "\n".join(MODULE.validate_root(root)),
            )

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

            self.assertIn(
                "issue_flags must be safe-token array",
                "\n".join(MODULE.validate_root(root)),
            )

    def test_retained_flags_reject_private_identifiers(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = valid_episode()
            episode["friction_flags"] = ["customer_acme"]
            episode_path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            episode_path.parent.mkdir(parents=True)
            episode_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")
            turn = valid_turn_flag()
            turn["issue_flags"] = ["incident_123"]
            turn_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            turn_path.parent.mkdir(parents=True)
            turn_path.write_text(json.dumps(turn) + "\n", encoding="utf-8")
            trend = valid_trend()
            trend["flags"] = {"customer_acme": 1}
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("friction_flags must use allowed issue flags", issues)
        self.assertIn("issue_flags must use allowed issue flags", issues)
        self.assertIn("flags keys must use allowed issue flags", issues)

    def test_retained_flags_allow_collaboration_friction_categories(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = valid_episode()
            episode["friction_flags"] = ["over_exploration", "under_asking"]
            episode_path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            episode_path.parent.mkdir(parents=True)
            episode_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            turn = valid_turn_flag()
            turn["issue_flags"] = ["over_exploration", "under_asking"]
            turn_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            turn_path.parent.mkdir(parents=True)
            turn_path.write_text(json.dumps(turn) + "\n", encoding="utf-8")

            trend = valid_trend()
            trend["flags"] = {"over_exploration": 1, "under_asking": 1}
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            issues = MODULE.validate_root(root)

        self.assertEqual(issues, [])

    def test_retained_flags_reject_duplicate_issue_flags(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = valid_episode()
            episode["friction_flags"] = ["verification_gap", "verification_gap"]
            episode_path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            episode_path.parent.mkdir(parents=True)
            episode_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            turn = valid_turn_flag()
            turn["issue_flags"] = ["verification_gap", "verification_gap"]
            turn_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            turn_path.parent.mkdir(parents=True)
            turn_path.write_text(json.dumps(turn) + "\n", encoding="utf-8")

            trend = valid_trend()
            trend["flags"] = {"verification_gap": 1}
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("friction_flags must not contain duplicate issue flags", issues)
        self.assertIn("issue_flags must not contain duplicate issue flags", issues)

    def test_nested_issue_flags_report_errors_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = valid_episode()
            episode["friction_flags"] = [[]]
            episode_path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            episode_path.parent.mkdir(parents=True)
            episode_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            turn = valid_turn_flag()
            turn["issue_flags"] = [{}]
            turn_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            turn_path.parent.mkdir(parents=True)
            turn_path.write_text(json.dumps(turn) + "\n", encoding="utf-8")

            trend = valid_trend()
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("friction_flags must be safe-token array", issues)
        self.assertIn("friction_flags must use allowed issue flags", issues)
        self.assertIn("issue_flags must be safe-token array", issues)
        self.assertIn("issue_flags must use allowed issue flags", issues)

    def test_safe_tokens_reject_compound_secret_names(self) -> None:
        for sample in (
            "client_secret",
            "refresh-token",
            "private_key",
            "db_password",
            "OPENAI_API_KEY",
            risky_compound_session_token(),
            risky_compound_turn_token(),
            risky_compound_episode_token(),
            risky_compound_camel_session_token(),
            risky_compound_camel_turn_token(),
            risky_bare_private_ip(),
            risky_bare_private_lan_ip(),
            risky_link_local_ip(),
            risky_cgnat_ip(),
            risky_github_classic_token(),
            risky_github_oauth_token(),
            risky_fine_grained_github_token(),
        ):
            with self.subTest(sample=sample):
                self.assertFalse(MODULE.valid_safe_token(sample))

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

            self.assertIn(
                "window.start must be before window.end",
                "\n".join(MODULE.validate_root(root)),
            )

    def test_window_duration_must_match_retained_mode(self) -> None:
        cases = (
            ("daily", "2026-05-21T00:00:00Z", "2026-05-23T00:00:00Z"),
            ("weekly", "2026-05-21T00:00:00Z", "2026-05-22T00:00:00Z"),
            ("baseline-90d", "2026-05-01T00:00:00Z", "2026-05-22T00:00:00Z"),
        )
        for mode, start, end in cases:
            with self.subTest(mode=mode):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    trend = valid_trend()
                    trend["window"] = {"mode": mode, "start": start, "end": end}
                    path = (
                        root / "data" / "trends" / "2026" / "05" / "trend_report.json"
                    )
                    path.parent.mkdir(parents=True)
                    path.write_text(json.dumps(trend), encoding="utf-8")

                    issues = "\n".join(MODULE.validate_root(root))

                self.assertIn("window duration must match window.mode", issues)

    def test_window_accepts_nanosecond_precision_timestamps(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            trend = valid_trend()
            trend["window"] = {
                "mode": "daily",
                "start": "2026-05-21T00:00:00.123456789Z",
                "end": "2026-05-22T00:00:00.123456789Z",
            }
            trend["turn_count"] = 0
            trend["flagged_turn_count"] = 0
            trend["episode_count"] = 0
            trend["flags"] = {}
            trend["hosts"] = {}
            trend["model_eras"] = {}
            path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(trend), encoding="utf-8")

            self.assertEqual(MODULE.validate_root(root), [])

    def test_episode_start_must_not_be_after_end(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = valid_episode()
            episode["start"] = "2026-05-21T02:00:00Z"
            episode["end"] = "2026-05-21T01:00:00Z"
            path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            self.assertIn(
                "episode start must be before or equal to end",
                "\n".join(MODULE.validate_root(root)),
            )

    def test_trend_flagged_turn_count_cannot_exceed_turn_count(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            trend = valid_trend()
            trend["turn_count"] = 1
            trend["flagged_turn_count"] = 2
            path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(trend), encoding="utf-8")

            self.assertIn(
                "flagged_turn_count must be less than or equal to turn_count",
                "\n".join(MODULE.validate_root(root)),
            )

    def test_timestamps_reject_non_calendar_dates(self) -> None:
        self.assertFalse(MODULE.valid_timestamp("2025-02-29T00:00:00Z"))
        self.assertFalse(MODULE.valid_timestamp("2026-04-31T00:00:00Z"))
        self.assertTrue(MODULE.valid_timestamp("2024-02-29T00:00:00.123456789Z"))

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            trend = valid_trend()
            trend["window"]["start"] = "2025-02-29T00:00:00Z"
            path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(trend), encoding="utf-8")

            self.assertIn(
                "window.start must be timestamp", "\n".join(MODULE.validate_root(root))
            )

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = valid_episode()
            episode["start"] = "2026-04-31T00:00:00Z"
            path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            self.assertIn(
                "start must be timestamp or null", "\n".join(MODULE.validate_root(root))
            )

    def test_retained_mode_allows_daily_weekly_and_baseline_windows(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = valid_manifest()
            manifest["mode"] = "baseline-90d"
            manifest["window"] = window_for_mode("baseline-90d")
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            manifest_path.parent.mkdir(parents=True)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            self.assertEqual(MODULE.validate_root(root), [])

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_monthly_export(root)
            trend = valid_trend()
            trend["window"] = window_for_mode("weekly")
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            self.assertEqual(MODULE.validate_root(root), [])

    def test_monthly_manifest_only_export_bounds_rows_to_manifest_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            episode = valid_episode()
            episode["start"] = "2026-05-20T00:00:00Z"
            episode["end"] = "2026-05-20T01:00:00Z"
            episode_path = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            episode_path.parent.mkdir(parents=True)
            episode_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            turn = valid_turn_flag()
            turn["timestamp"] = "2026-05-20T00:00:00Z"
            turn_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
            turn_path.parent.mkdir(parents=True)
            turn_path.write_text(json.dumps(turn) + "\n", encoding="utf-8")

            manifest = valid_manifest()
            manifest["mode"] = "weekly"
            manifest["window"] = {
                "mode": "weekly",
                "start": "2026-04-28T00:00:00Z",
                "end": "2026-05-05T00:00:00Z",
            }
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            manifest_path.parent.mkdir(parents=True)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/episodes/2026/05/episodes.jsonl:1: episode start/end must be within manifest window",
            issues,
        )
        self.assertIn(
            "data/turn_flags/2026/05/turn_flags.jsonl:1: timestamp must be within manifest window",
            issues,
        )

    def test_retained_mode_rejects_non_90_day_baselines(self) -> None:
        self.assertFalse(MODULE.valid_retained_mode("baseline-30d"))

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            trend = valid_trend()
            trend["window"] = {
                "mode": "baseline-30d",
                "start": "2026-04-22T00:00:00Z",
                "end": "2026-05-22T00:00:00Z",
            }
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("window.mode must be an allowed retained mode", issues)

    def test_manifest_mode_must_match_window_mode(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            manifest_path = export_dir / "retained_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["window"]["mode"] = "weekly"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/daily/retained_manifest.json: manifest mode must match window.mode",
            issues,
        )

    def test_flat_retained_export_mode_must_match_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            trend_path = export_dir / "trend_report.json"
            trend = json.loads(trend_path.read_text(encoding="utf-8"))
            trend["window"]["mode"] = "weekly"
            trend_path.write_text(json.dumps(trend), encoding="utf-8")
            manifest_path = export_dir / "retained_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["mode"] = "weekly"
            manifest["window"]["mode"] = "weekly"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/daily/trend_report.json: trend window.mode must match retained/daily export directory",
            issues,
        )
        self.assertIn(
            "retained/daily/retained_manifest.json: manifest mode must match retained/daily export directory",
            issues,
        )

    def test_baseline_retained_export_requires_single_concrete_mode(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "baseline"
            write_retained_export(root, export_dir)
            trend_path = export_dir / "trend_report.json"
            trend = json.loads(trend_path.read_text(encoding="utf-8"))
            trend["window"]["mode"] = "baseline-30d"
            trend_path.write_text(json.dumps(trend), encoding="utf-8")
            manifest_path = export_dir / "retained_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["mode"] = "baseline-90d"
            manifest["window"]["mode"] = "baseline-90d"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/baseline: retained export mode differs between trend and manifest",
            issues,
        )

    def test_flat_retained_export_window_must_match_between_manifest_and_trend(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            export_dir = root / "retained" / "daily"
            write_retained_export(root, export_dir)
            manifest_path = export_dir / "retained_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["window"]["end"] = "2026-05-23T00:00:00Z"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "retained/daily: retained export window differs between trend and manifest",
            issues,
        )

    def test_monthly_retained_export_window_must_match_between_manifest_and_trend(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_monthly_export(root)
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            manifest_path.parent.mkdir(parents=True)
            manifest = valid_manifest()
            manifest["window"]["start"] = "2026-05-20T00:00:00Z"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn(
            "data/2026/05: retained export window differs between trend and manifest",
            issues,
        )

    def test_customer_like_modes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = valid_manifest()
            manifest["mode"] = "customer-acme"
            manifest["window"]["mode"] = "customer-acme"
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
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
        self.assertTrue(MODULE.valid_retained_model_id("gpt-5.6-sol"))
        self.assertTrue(MODULE.valid_retained_model_era("gpt-5.6-sol"))
        self.assertTrue(MODULE.valid_retained_model_id("gpt-5.6-terra"))
        self.assertTrue(MODULE.valid_retained_model_era("gpt-5.6-terra"))
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
            turn_path = (
                root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            )
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
            self.assertIn(
                "model_eras key must be an allowed retained model era", issues
            )

    def test_source_hashes_must_use_retained_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            row = valid_turn_flag()
            row["source_hash"] = "e" * 64
            path = root / "data" / "turn_flags" / "2026" / "05" / "turn_flags.jsonl"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(row) + "\n", encoding="utf-8")

            self.assertIn(
                "source_hash must be source_hash_v1",
                "\n".join(MODULE.validate_root(root)),
            )

    def test_root_docs_and_workflows_are_content_scanned(self) -> None:
        for relative_path, text in (
            ("README.md", "Leaked URL " + risky_internal_url() + "\n"),
            (".github/workflows/ci.yml", "name: CI\n# " + risky_project_path() + "\n"),
            ("scripts/probe.py", "# " + risky_secret_token() + "\n"),
            (
                "schemas/session-retrospective-v1.schema.json",
                json.dumps({"source": risky_project_path()}) + "\n",
            ),
            (
                "schemas/session-retrospective-v1.schema.json",
                '{"source": "\\u002fUs'
                + "ers\\u002fhoteng\\u002f.codex\\u002fsess"
                + 'ions\\u002fraw.jsonl"}\n',
            ),
            ("tests/probe.py", "# " + risky_internal_host() + "\n"),
            (".gitignore", ".codex" + "-tmp/\n# " + risky_project_path() + "\n"),
            ("README.md", "Raw pointer " + risky_session_pointer() + "\n"),
            ("scripts/probe.py", "# " + risky_rollout_filename() + "\n"),
            ("README.md", "Internal localhost URL " + risky_localhost_url() + "\n"),
            ("README.md", "Internal private IP URL " + risky_private_ip_url() + "\n"),
            (
                "README.md",
                "Internal metadata URL http://"
                + risky_link_local_ip()
                + "/latest/meta-data\n",
            ),
            (
                "README.md",
                "Internal IPv6 URL http://[" + risky_private_ipv6() + "]/status\n",
            ),
            ("README.md", "Internal short host URL " + risky_short_host_url() + "\n"),
            ("README.md", "Internal SSH URL " + risky_private_ip_ssh_url() + "\n"),
            (
                "README.md",
                "Internal Git remote " + risky_short_host_git_remote() + "\n",
            ),
            ("README.md", "Operator email " + risky_email() + "\n"),
            ("README.md", "Short secret api_" + "key: abc\n"),
            ("README.md", "Short secret to" + "ken = abcdefghijklmnop\n"),
            ("README.md", "Redacted-looking api" + "Key: [REDACTED]\n"),
            ("README.md", "Empty private" + 'Key = ""\n'),
            ("README.md", "Placeholder private" + "Key = <redacted>\n"),
            ("README.md", "Raw hash " + risky_raw_hash() + "\n"),
            ("README.md", "Raw UUID " + risky_uuid() + "\n"),
            ("scripts/probe.py", "# Raw hash " + risky_raw_hash() + "\n"),
            ("tests/probe.py", "# Raw UUID " + risky_uuid() + "\n"),
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    path = root / relative_path
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(text, encoding="utf-8")

                    self.assertIn(
                        "infrastructure text contains raw/sensitive evidence",
                        "\n".join(MODULE.validate_root(root)),
                    )

    def test_ordinary_mode_rejects_v2_only_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "requirements-v2.in").write_text(
                "jsonschema==4.23.0\n", encoding="utf-8"
            )

            issues = "\n".join(MODULE.validate_root(root))

        self.assertIn("unexpected retained artifact location", issues)

    def test_post_migration_tree_and_cli_merge_plan_are_fully_validated(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            root = workspace / "post-migration"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()

            report = root / "reports" / "daily" / "2026" / "07" / "15.md"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text("# Daily retrospective\n\nNo issue observed.\n", encoding="utf-8")
            run_fixture_git(root, "add", "--all")
            fixture_commit_all(root, "append report")
            head = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()

            self.assertIn(
                "unexpected retained artifact location",
                "\n".join(MODULE.validate_root(root)),
            )
            self.assertEqual(validate_synthetic_history_v2_tree(root), [])
            plan = validate_synthetic_history_v2_merge_range(
                root,
                base_rev=base,
                head_rev=head,
            )
            self.assertEqual(
                set(plan),
                {
                    "schema_version",
                    "kind",
                    "validation_mode",
                    "base_sha",
                    "head_sha",
                    "head_tree_sha",
                    "head_subject",
                    "commit_count",
                    "changed_path_count",
                    "transaction_role",
                },
            )
            self.assertEqual(plan["base_sha"], base)
            self.assertEqual(plan["head_sha"], head)
            self.assertEqual(plan["head_subject"], "append report")
            self.assertEqual(plan["commit_count"], 1)
            self.assertEqual(plan["changed_path_count"], 1)
            with mock.patch.object(
                MODULE,
                "HISTORY_V2_MAX_REACHABLE_BLOB_BYTES",
                1,
            ):
                with self.assertRaisesRegex(ValueError, "reachable blob set"):
                    validate_synthetic_history_v2_merge_range(
                        root,
                        base_rev=base,
                        head_rev=head,
                    )
            with self.assertRaisesRegex(ValueError, "outside the candidate root"):
                MODULE.write_history_v2_merge_plan(
                    root / "merge-plan.json",
                    plan,
                    root=root,
                )

            cli_plan = workspace / "merge-plan.json"
            digests = {
                relative: hashlib.sha256((root / relative).read_bytes()).hexdigest()
                for relative in MODULE.BOOTSTRAP_V2_PUBLIC_KEY_FILES
            }
            with (
                mock.patch.object(MODULE, "BOOTSTRAP_V2_PUBLIC_KEY_SHA256", digests),
                mock.patch.object(
                    MODULE,
                    "history_v2_signature_verifier_for_root",
                    return_value=FixtureStructuralSignatureVerifier(),
                ),
            ):
                self.assertEqual(
                    MODULE.main(
                        [
                            "--root",
                            str(root),
                            "--mode",
                            "history-v2-candidate-range",
                            "--base-rev",
                            base,
                            "--head-rev",
                            head,
                            "--write-merge-plan",
                            str(cli_plan),
                        ]
                    ),
                    0,
                )
            persisted_plan = json.loads(cli_plan.read_text(encoding="utf-8"))
            self.assertEqual(
                set(persisted_plan),
                {
                    "schema_version",
                    "base_oid",
                    "head_oid",
                    "head_tree_oid",
                    "squash_subject",
                    "trust_generation",
                    "role",
                },
            )
            self.assertEqual(persisted_plan["base_oid"], base)
            self.assertEqual(persisted_plan["head_oid"], head)
            self.assertEqual(
                persisted_plan["head_tree_oid"],
                plan["head_tree_sha"],
            )
            self.assertEqual(persisted_plan["squash_subject"], "append report")
            self.assertEqual(persisted_plan["role"], "publication")
            self.assertRegex(
                persisted_plan["trust_generation"],
                r"^[0-9a-f]{64}$",
            )

            with mock.patch.object(MODULE, "BOOTSTRAP_V2_MAX_TREE_BYTES", 1):
                bounded_issues = "\n".join(
                    validate_synthetic_history_v2_tree(root)
                )
            self.assertIn("history-v2 tree exceeds the trusted size limit", bounded_issues)

            report.write_text(
                "Leaked endpoint " + risky_internal_url() + "\n",
                encoding="utf-8",
            )
            run_fixture_git(root, "add", report.relative_to(root).as_posix())
            issues = "\n".join(validate_synthetic_history_v2_tree(root))
            self.assertIn("retained text contains raw/sensitive evidence", issues)

    def test_candidate_plan_binds_publication_and_admin_authority_roles(
        self,
    ) -> None:
        for role in ("publication", "admin"):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as raw:
                root = Path(raw) / "repo"
                write_bootstrap_v2_candidate(root)
                fixture_commit_all(root, "post migration base")
                base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
                if role == "publication":
                    target = (
                        root
                        / "reports"
                        / "daily"
                        / "2026"
                        / "07"
                        / "15.md"
                    )
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(
                        "# Daily retrospective\n",
                        encoding="utf-8",
                    )
                    subject = "Publish retained history"
                else:
                    target = root / "README.md"
                    target.write_text(
                        "Signed trusted policy update.\n",
                        encoding="utf-8",
                    )
                    subject = "Update trusted history policy"
                run_fixture_git(root, "add", target.relative_to(root).as_posix())
                head = fixture_commit_all(root, subject)
                digests = {
                    relative: hashlib.sha256(
                        (root / relative).read_bytes()
                    ).hexdigest()
                    for relative in MODULE.BOOTSTRAP_V2_PUBLIC_KEY_FILES
                }
                with (
                    mock.patch.object(
                        MODULE,
                        "BOOTSTRAP_V2_PUBLIC_KEY_SHA256",
                        digests,
                    ),
                    mock.patch.object(
                        MODULE,
                        "history_v2_signature_verifier_for_root",
                        return_value=FixtureStructuralSignatureVerifier(),
                    ) as verifier,
                ):
                    plan, issues = MODULE.build_pull_request_candidate_plan(
                        root,
                        base,
                        head,
                    )
                self.assertEqual(issues, [])
                self.assertIsNotNone(plan)
                assert plan is not None
                self.assertEqual(plan.base_oid, base)
                self.assertEqual(plan.head_oid, head)
                self.assertEqual(plan.role, role)
                self.assertEqual(plan.squash_subject, subject)
                self.assertRegex(plan.trust_generation, r"^[0-9a-f]{64}$")
                expected_policy = (
                    "history-v2" if role == "publication" else "bootstrap-v2"
                )
                self.assertTrue(
                    any(
                        call.kwargs.get("policy") == expected_policy
                        and call.kwargs.get("revision") == base
                        for call in verifier.call_args_list
                    )
                )

    def test_candidate_plan_rejects_mixed_admin_and_publication_paths(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            (root / "README.md").write_text(
                "Mixed trusted update.\n",
                encoding="utf-8",
            )
            report = root / "reports" / "daily" / "2026" / "07" / "15.md"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text("# Daily retrospective\n", encoding="utf-8")
            run_fixture_git(root, "add", "--all")
            head = fixture_commit_all(root, "Mixed authority update")

            digests = {
                relative: hashlib.sha256(
                    (root / relative).read_bytes()
                ).hexdigest()
                for relative in MODULE.BOOTSTRAP_V2_PUBLIC_KEY_FILES
            }
            with (
                mock.patch.object(
                    MODULE,
                    "BOOTSTRAP_V2_PUBLIC_KEY_SHA256",
                    digests,
                ),
                mock.patch.object(
                    MODULE,
                    "history_v2_signature_verifier_for_root",
                    return_value=FixtureStructuralSignatureVerifier(),
                ),
            ):
                plan, issues = MODULE.build_pull_request_candidate_plan(
                    root,
                    base,
                    head,
                )
            self.assertIsNone(plan)
            self.assertIn("mixes publication and admin paths", "\n".join(issues))

    def test_domain_helpers_execute_only_frozen_source_with_closed_dependencies(
        self,
    ) -> None:
        sources = {
            Path("scripts/retrospective_history_attestation_v2.py"): (
                'VALUE = "frozen-attestation"\n'
            ),
            Path("scripts/retrospective_history_credentials_v2.py"): (
                'VALUE = "frozen-credentials"\n'
            ),
            Path("scripts/retrospective_history_git_v2.py"): (
                "from retrospective_history_attestation_v2 import VALUE\n"
                'MAX_ARTIFACT_BYTES = {"manifest.json": 1024}\n'
                "def _verify_publisher_attestation(_blobs):\n"
                '    return VALUE == "frozen-attestation"\n'
                "def build_pull_request_merge_plan(*_args):\n"
                "    from scripts import retrospective_history_v2 as validator\n"
                "    return validator.PLAN, []\n"
                "def validate_default_branch_update(*_args):\n"
                "    return []\n"
            ),
            Path("scripts/retrospective_history_privacy_v2.py"): (
                'VALUE = "frozen-privacy"\n'
            ),
            Path("scripts/retrospective_history_templates_v2.py"): (
                'VALUE = "frozen-template"\n'
            ),
            Path("scripts/retrospective_history_v2.py"): (
                "import importlib.util\n"
                "from pathlib import Path\n"
                "from retrospective_history_templates_v2 import VALUE\n"
                "PRIVACY_VALIDATOR_PATH = Path(__file__).with_name("
                '"retrospective_history_privacy_v2.py")\n'
                "PLAN = VALUE\n"
                "def validate_v2_runs_with_inventory(*_args):\n"
                "    spec = importlib.util.spec_from_file_location("
                '"_retrospective_history_privacy_v2_for_history", '
                "PRIVACY_VALIDATOR_PATH)\n"
                "    module = importlib.util.module_from_spec(spec)\n"
                "    spec.loader.exec_module(module)\n"
                "    return [VALUE, module.VALUE], ()\n"
            ),
        }
        snapshots = tuple(
            MODULE.HistoryV2FileSnapshot(
                relative=relative,
                value=sources[relative].encode("utf-8"),
                mode=stat.S_IFREG | 0o444,
                device=1,
                inode=index,
                uid=1,
                gid=1,
                size=len(sources[relative].encode("utf-8")),
                mtime_ns=1,
            )
            for index, relative in enumerate(
                MODULE.HISTORY_V2_DOMAIN_MODULE_PATHS,
                1,
            )
        )

        with tempfile.TemporaryDirectory() as raw:
            trusted_root = Path(raw)
            candidate_source = (
                trusted_root / "retrospective_history_attestation_v2.py"
            )
            candidate_source.write_text(
                'VALUE = "candidate-path"\n',
                encoding="utf-8",
            )
            candidate_pyc = (
                trusted_root / "retrospective_history_attestation_v2.pyc"
            )
            py_compile.compile(
                str(candidate_source),
                cfile=str(candidate_pyc),
                doraise=True,
            )
            candidate_source.unlink()

            preloaded_attestation = type(sys)(
                "retrospective_history_attestation_v2"
            )
            preloaded_attestation.VALUE = "preloaded"
            preloaded_package = type(sys)("scripts")
            preloaded_runtime = type(sys)(
                "scripts.retrospective_history_v2"
            )
            preloaded_runtime.PLAN = "preloaded"
            preloaded_package.retrospective_history_v2 = preloaded_runtime
            previous_modules = set(sys.modules)
            try:
                with (
                    mock.patch.dict(
                        sys.modules,
                        {
                            "retrospective_history_attestation_v2": (
                                preloaded_attestation
                            ),
                            "scripts": preloaded_package,
                            "scripts.retrospective_history_v2": (
                                preloaded_runtime
                            ),
                        },
                    ),
                    mock.patch.object(
                        sys,
                        "path",
                        [str(trusted_root), *sys.path],
                    ),
                ):
                    git_module, runtime_module = (
                        MODULE._history_v2_load_frozen_domain_modules(
                            trusted_root,
                            snapshots,
                        )
                    )
                    self.assertTrue(
                        git_module._verify_publisher_attestation({})
                    )
                    self.assertEqual(
                        runtime_module.validate_v2_runs_with_inventory(),
                        (["frozen-template", "frozen-privacy"], ()),
                    )
                    plan, issues = git_module.build_pull_request_merge_plan()
                    self.assertEqual(plan, "frozen-template")
                    self.assertEqual(issues, [])
            finally:
                for name in set(sys.modules) - previous_modules:
                    if name.startswith("_history_v2_frozen_"):
                        sys.modules.pop(name, None)

    def test_domain_tree_validates_global_v2_closure_and_attestations(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            relative = (
                Path("runs")
                / "daily"
                / "2026-07-15"
                / "aaaaaaaaaaaaaaaaaaaaaaaaaa"
                / "manifest.json"
            )
            manifest = root / relative
            manifest.parent.mkdir(parents=True)
            manifest.write_bytes(b'{"schema_version":2}\n')
            calls: list[tuple[object, ...]] = []

            def validate_domain(
                supplied_root: Path,
                visible_files: list[Path],
            ) -> tuple[list[str], tuple[Path, ...]]:
                calls.append(("global", supplied_root, tuple(visible_files)))
                return [], (relative,)

            def verify_attestation(blobs: dict[str, bytes]) -> bool:
                calls.append(("attestation", blobs))
                return True

            contract = MODULE.HistoryV2DomainContract(
                validate_v2_runs_with_inventory=validate_domain,
                verify_publisher_attestation=verify_attestation,
                build_pull_request_merge_plan=lambda *_args: (None, []),
                validate_default_branch_update=lambda *_args: [],
                max_manifest_bytes=1024,
            )
            with mock.patch.object(
                MODULE,
                "trusted_history_v2_domain_contract",
                return_value=contract,
            ):
                self.assertEqual(
                    MODULE.validate_history_v2_domain_tree(
                        root,
                        visible_files=[manifest],
                    ),
                    [],
                )
            self.assertEqual(
                [call[0] for call in calls],
                ["attestation", "global"],
            )
            self.assertEqual(
                calls[0][1],
                {"manifest.json": b'{"schema_version":2}\n'},
            )

            calls.clear()

            def reject_global(
                _root: Path,
                _visible_files: list[Path],
            ) -> tuple[list[str], tuple[Path, ...]]:
                calls.append(("global",))
                return ["runs: revision/campaign/supersession closure failed"], ()

            rejected = MODULE.HistoryV2DomainContract(
                validate_v2_runs_with_inventory=reject_global,
                verify_publisher_attestation=verify_attestation,
                build_pull_request_merge_plan=lambda *_args: (None, []),
                validate_default_branch_update=lambda *_args: [],
                max_manifest_bytes=1024,
            )
            with mock.patch.object(
                MODULE,
                "trusted_history_v2_domain_contract",
                return_value=rejected,
            ):
                self.assertEqual(
                    MODULE.validate_history_v2_domain_tree(
                        root,
                        visible_files=[manifest],
                    ),
                    [
                        "trusted history-v2 domain validator rejected "
                        "the frozen snapshot"
                    ],
                )
            self.assertEqual(
                [call[0] for call in calls],
                ["attestation", "global"],
            )

    def test_domain_manifest_inventory_and_attestation_are_exact_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            relatives = tuple(
                Path("runs")
                / "daily"
                / "2026-07-15"
                / run_ref
                / "manifest.json"
                for run_ref in (
                    "aaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "bbbbbbbbbbbbbbbbbbbbbbbbbb",
                )
            )
            visible_files: list[Path] = []
            for relative in relatives:
                manifest = root / relative
                manifest.parent.mkdir(parents=True)
                manifest.write_bytes(b'{"schema_version":2}\n')
                visible_files.append(manifest)

            extra = (
                Path("runs")
                / "daily"
                / "2026-07-15"
                / "cccccccccccccccccccccccccc"
                / "manifest.json"
            )
            inventory_cases = (
                ("missing", relatives[:1]),
                ("extra", (*relatives, extra)),
                ("duplicate", (relatives[0], relatives[0], relatives[1])),
                ("reordered", tuple(reversed(relatives))),
            )
            for label, inventory in inventory_cases:
                verifier = mock.Mock(return_value=True)
                contract = MODULE.HistoryV2DomainContract(
                    validate_v2_runs_with_inventory=(
                        lambda *_args, inventory=inventory: ([], inventory)
                    ),
                    verify_publisher_attestation=verifier,
                    build_pull_request_merge_plan=lambda *_args: (None, []),
                    validate_default_branch_update=lambda *_args: [],
                    max_manifest_bytes=1024,
                )
                with (
                    self.subTest(label=label),
                    mock.patch.object(
                        MODULE,
                        "trusted_history_v2_domain_contract",
                        return_value=contract,
                    ),
                ):
                    issues = MODULE.validate_history_v2_domain_tree(
                        root,
                        visible_files=visible_files,
                    )
                self.assertIn("manifest inventory", "\n".join(issues))
                self.assertEqual(verifier.call_count, len(relatives))

            for label, result in (
                ("false", False),
                ("truthy integer", 1),
                ("truthy object", {"accepted": True}),
            ):
                validator = mock.Mock(return_value=([], relatives))
                contract = MODULE.HistoryV2DomainContract(
                    validate_v2_runs_with_inventory=validator,
                    verify_publisher_attestation=lambda _blobs, result=result: result,
                    build_pull_request_merge_plan=lambda *_args: (None, []),
                    validate_default_branch_update=lambda *_args: [],
                    max_manifest_bytes=1024,
                )
                with (
                    self.subTest(label=label),
                    mock.patch.object(
                        MODULE,
                        "trusted_history_v2_domain_contract",
                        return_value=contract,
                    ),
                ):
                    issues = MODULE.validate_history_v2_domain_tree(
                        root,
                        visible_files=visible_files,
                    )
                self.assertIn("publisher attestation is invalid", "\n".join(issues))
                validator.assert_not_called()

            def fail_attestation(_blobs: dict[str, bytes]) -> bool:
                raise RuntimeError("rejected-value-must-not-escape")

            failed_validator = mock.Mock(return_value=([], relatives))
            failed_contract = MODULE.HistoryV2DomainContract(
                validate_v2_runs_with_inventory=failed_validator,
                verify_publisher_attestation=fail_attestation,
                build_pull_request_merge_plan=lambda *_args: (None, []),
                validate_default_branch_update=lambda *_args: [],
                max_manifest_bytes=1024,
            )
            with mock.patch.object(
                MODULE,
                "trusted_history_v2_domain_contract",
                return_value=failed_contract,
            ):
                failed = MODULE.validate_history_v2_domain_tree(
                    root,
                    visible_files=visible_files,
                )
            self.assertIn("failed closed", "\n".join(failed))
            self.assertNotIn("rejected-value", "\n".join(failed))
            failed_validator.assert_not_called()

    def test_domain_inventory_and_contents_are_frozen_before_helper_call(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            relative = (
                Path("runs")
                / "daily"
                / "2026-07-15"
                / "aaaaaaaaaaaaaaaaaaaaaaaaaa"
                / "manifest.json"
            )
            manifest = root / relative
            manifest.parent.mkdir(parents=True)
            original = b'{"schema_version":2}\n'
            replacement = b'{"schema_version":999}\n'
            manifest.write_bytes(original)
            visible_files = [manifest]
            attested: list[dict[str, bytes]] = []

            def validate_domain(
                _root: Path,
                supplied_files: tuple[Path, ...],
            ) -> tuple[list[str], tuple[Path, ...]]:
                self.assertIsInstance(supplied_files, tuple)
                visible_files.clear()
                manifest.write_bytes(replacement)
                return [], (relative,)

            contract = MODULE.HistoryV2DomainContract(
                validate_v2_runs_with_inventory=validate_domain,
                verify_publisher_attestation=lambda blobs: (
                    attested.append(blobs) is None
                ),
                build_pull_request_merge_plan=lambda *_args: (None, []),
                validate_default_branch_update=lambda *_args: [],
                max_manifest_bytes=1024,
            )
            with mock.patch.object(
                MODULE,
                "trusted_history_v2_domain_contract",
                return_value=contract,
            ):
                issues = MODULE.validate_history_v2_domain_tree(
                    root,
                    visible_files=visible_files,
                )
            self.assertEqual(issues, [])
            self.assertEqual(visible_files, [])
            self.assertEqual(attested, [{"manifest.json": original}])
            self.assertEqual(manifest.read_bytes(), replacement)

            def mutate_snapshot(
                _root: Path,
                supplied_files: tuple[Path, ...],
            ) -> tuple[list[str], tuple[Path, ...]]:
                supplied_files[0].chmod(0o600)
                return [], (relative,)

            manifest.write_bytes(original)
            mutating_contract = MODULE.HistoryV2DomainContract(
                validate_v2_runs_with_inventory=mutate_snapshot,
                verify_publisher_attestation=lambda _blobs: True,
                build_pull_request_merge_plan=lambda *_args: (None, []),
                validate_default_branch_update=lambda *_args: [],
                max_manifest_bytes=1024,
            )
            with mock.patch.object(
                MODULE,
                "trusted_history_v2_domain_contract",
                return_value=mutating_contract,
            ):
                snapshot_mutation_issues = MODULE.validate_history_v2_domain_tree(
                    root,
                    visible_files=[manifest],
                )
            self.assertEqual(
                snapshot_mutation_issues,
                [
                    "trusted history-v2 domain snapshot changed "
                    "during validation"
                ],
            )

    def test_domain_helper_diagnostics_are_closed_bounded_and_normalized(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            relative = (
                Path("runs")
                / "daily"
                / "2026-07-15"
                / "aaaaaaaaaaaaaaaaaaaaaaaaaa"
                / "manifest.json"
            )
            manifest = root / relative
            manifest.parent.mkdir(parents=True)
            manifest.write_bytes(b'{"schema_version":2}\n')
            raw_session = risky_session_pointer()
            raw_url = risky_internal_url()
            raw_issue = (
                risky_local_path()
                + " "
                + raw_session
                + " "
                + raw_url
            )
            cases: tuple[tuple[str, object, str], ...] = (
                (
                    "valid but unsafe",
                    [raw_issue],
                    "trusted history-v2 domain validator rejected "
                    "the frozen snapshot",
                ),
                (
                    "truthy object",
                    {"issue": raw_issue},
                    "trusted history-v2 domain validator result is invalid",
                ),
                (
                    "non-ASCII",
                    ["unsafe \u2603"],
                    "trusted history-v2 domain validator result is invalid",
                ),
                (
                    "oversized",
                    ["x" * 300],
                    "trusted history-v2 domain validator result is invalid",
                ),
            )
            for label, helper_issues, expected in cases:
                contract = MODULE.HistoryV2DomainContract(
                    validate_v2_runs_with_inventory=lambda *_args, helper_issues=helper_issues: (
                        helper_issues,
                        (relative,),
                    ),
                    verify_publisher_attestation=lambda _blobs: True,
                    build_pull_request_merge_plan=lambda *_args: (None, []),
                    validate_default_branch_update=lambda *_args: [],
                    max_manifest_bytes=1024,
                )
                with (
                    self.subTest(label=label),
                    mock.patch.object(
                        MODULE,
                        "trusted_history_v2_domain_contract",
                        return_value=contract,
                    ),
                ):
                    issues = MODULE.validate_history_v2_domain_tree(
                        root,
                        visible_files=[manifest],
                    )
                self.assertEqual(issues, [expected])

    def test_history_tree_structural_failures_bar_domain_reads(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            target = Path(raw) / "outside-target.json"
            target.write_text('{"must_not_be_read":true}\n', encoding="utf-8")
            relative = (
                Path("runs")
                / "daily"
                / "2026-07-15"
                / "aaaaaaaaaaaaaaaaaaaaaaaaaa"
                / "manifest.json"
            )
            link = root / relative
            link.parent.mkdir(parents=True)
            link.symlink_to(target)
            run_fixture_git(root, "add", "--all")

            with (
                mock.patch.object(
                    MODULE,
                    "trusted_history_v2_domain_contract",
                    side_effect=AssertionError("domain helper must not load"),
                ) as domain,
                mock.patch.object(
                    MODULE,
                    "read_history_v2_stable_policy_file",
                    side_effect=AssertionError("symlink target must not be read"),
                ) as stable_read,
            ):
                issues = MODULE.validate_history_v2_tree(
                    root,
                    verify_head_tree=False,
                )
            self.assertIn("symlink artifact is not allowed", "\n".join(issues))
            domain.assert_not_called()
            stable_read.assert_not_called()

            with (
                mock.patch.object(
                    MODULE,
                    "git_index_entries",
                    return_value=(None, "candidate Git index is damaged"),
                ),
                mock.patch.object(
                    MODULE,
                    "trusted_history_v2_domain_contract",
                    side_effect=AssertionError("domain helper must not load"),
                ) as domain,
            ):
                damaged = MODULE.validate_history_v2_tree(
                    root,
                    verify_head_tree=False,
                )
            self.assertIn("Git index is damaged", "\n".join(damaged))
            domain.assert_not_called()

    def test_git_visible_enumeration_is_bounded_and_has_no_fallback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with (
                mock.patch.object(
                    MODULE,
                    "bounded_process_output",
                    return_value=(str(root) + "\n").encode("utf-8"),
                ),
                mock.patch.object(
                    MODULE,
                    "bounded_git_nul_records",
                    return_value=(
                        None,
                        "trusted Git file enumeration exceeds the trusted entry limit",
                    ),
                ) as bounded,
                mock.patch.object(
                    Path,
                    "rglob",
                    side_effect=AssertionError("unbounded fallback used"),
                ) as fallback,
            ):
                files, issue = MODULE.git_visible_files(
                    root,
                    max_entries=2,
                )
            self.assertIsNone(files)
            self.assertEqual(
                issue,
                "trusted Git file enumeration exceeds the trusted entry limit",
            )
            bounded.assert_called_once()
            fallback.assert_not_called()

    def test_frozen_file_reads_detect_identity_content_and_access_changes(
        self,
    ) -> None:
        def snapshot(root: Path) -> tuple[
            tuple[object, ...] | None,
            str | None,
        ]:
            return MODULE.snapshot_explicit_history_v2_files(
                root,
                (Path("artifact.json"),),
                max_entries=1,
                max_file_bytes=1024,
                max_tree_bytes=1024,
            )

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifact = root / "artifact.json"
            artifact.write_bytes(b"stable")
            original_open = os.open
            replaced = False

            def replace_before_open(
                path: object,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal replaced
                if path == "artifact.json" and dir_fd is not None and not replaced:
                    replaced = True
                    artifact.rename(root / "replaced.json")
                    artifact.write_bytes(b"stable")
                return original_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(
                MODULE.os,
                "open",
                side_effect=replace_before_open,
            ):
                files, issue = snapshot(root)
            self.assertIsNone(files)
            self.assertIn("object identity changed", issue or "")

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifact = root / "artifact.json"
            artifact.write_bytes(b"stable")
            original_read = os.read
            mutated = False

            def grow_while_reading(descriptor: int, size: int) -> bytes:
                nonlocal mutated
                value = original_read(descriptor, size)
                if value and not mutated:
                    mutated = True
                    with artifact.open("ab") as stream:
                        stream.write(b"-growth")
                return value

            with mock.patch.object(
                MODULE.os,
                "read",
                side_effect=grow_while_reading,
            ):
                files, issue = snapshot(root)
            self.assertIsNone(files)
            self.assertIn("content changed", issue or "")

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifact = root / "artifact.json"
            artifact.write_bytes(b"stable")
            original_read = os.read
            changed = False

            def chmod_while_reading(descriptor: int, size: int) -> bytes:
                nonlocal changed
                value = original_read(descriptor, size)
                if value and not changed:
                    changed = True
                    artifact.chmod(0o600)
                return value

            artifact.chmod(0o644)
            with mock.patch.object(
                MODULE.os,
                "read",
                side_effect=chmod_while_reading,
            ):
                files, issue = snapshot(root)
            self.assertIsNone(files)
            self.assertIn("access policy changed", issue or "")

    def test_frozen_file_reads_allow_benign_atime_churn(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifact = root / "artifact.json"
            artifact.write_bytes(b"stable")
            original = artifact.stat()
            original_read = os.read
            changed = False

            def touch_atime(descriptor: int, size: int) -> bytes:
                nonlocal changed
                value = original_read(descriptor, size)
                if value and not changed:
                    changed = True
                    os.utime(
                        artifact,
                        ns=(
                            original.st_atime_ns + 1_000_000_000,
                            original.st_mtime_ns,
                        ),
                    )
                return value

            with mock.patch.object(
                MODULE.os,
                "read",
                side_effect=touch_atime,
            ):
                files, issue = MODULE.snapshot_explicit_history_v2_files(
                    root,
                    (Path("artifact.json"),),
                    max_entries=1,
                    max_file_bytes=1024,
                    max_tree_bytes=1024,
                )
            self.assertIsNone(issue)
            self.assertIsNotNone(files)
            assert files is not None
            self.assertEqual(files[0].value, b"stable")

    def test_frozen_file_reads_revalidate_mtime_against_bytes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifact = root / "artifact.json"
            artifact.write_bytes(b"stable")
            original = artifact.stat()
            original_read = os.read
            rewritten = False
            nonempty_reads = 0

            def rewrite_same_bytes(descriptor: int, size: int) -> bytes:
                nonlocal rewritten, nonempty_reads
                value = original_read(descriptor, size)
                if value:
                    nonempty_reads += 1
                if value and not rewritten:
                    rewritten = True
                    artifact.write_bytes(b"stable")
                    os.utime(
                        artifact,
                        ns=(
                            original.st_atime_ns,
                            original.st_mtime_ns + 1_000_000_000,
                        ),
                    )
                return value

            with mock.patch.object(
                MODULE.os,
                "read",
                side_effect=rewrite_same_bytes,
            ):
                files, issue = MODULE.snapshot_explicit_history_v2_files(
                    root,
                    (Path("artifact.json"),),
                    max_entries=1,
                    max_file_bytes=1024,
                    max_tree_bytes=1024,
                )
            self.assertIsNone(issue)
            self.assertIsNotNone(files)
            assert files is not None
            self.assertEqual(files[0].value, b"stable")
            self.assertGreaterEqual(nonempty_reads, 3)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifact = root / "artifact.json"
            artifact.write_bytes(b"stable")
            original_read = os.read
            rewritten = False

            def rewrite_different_bytes(descriptor: int, size: int) -> bytes:
                nonlocal rewritten
                value = original_read(descriptor, size)
                if value and not rewritten:
                    rewritten = True
                    artifact.write_bytes(b"mutate")
                return value

            with mock.patch.object(
                MODULE.os,
                "read",
                side_effect=rewrite_different_bytes,
            ):
                files, issue = MODULE.snapshot_explicit_history_v2_files(
                    root,
                    (Path("artifact.json"),),
                    max_entries=1,
                    max_file_bytes=1024,
                    max_tree_bytes=1024,
                )
            self.assertIsNone(files)
            self.assertIn("content changed", issue or "")

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifact = root / "artifact.json"
            artifact.write_bytes(b"stable")
            original_read = os.read
            original_revalidate = MODULE._history_v2_revalidate_open_file
            touched = False

            def trigger_revalidation(descriptor: int, size: int) -> bytes:
                nonlocal touched
                value = original_read(descriptor, size)
                if value and not touched:
                    touched = True
                    metadata = artifact.stat()
                    os.utime(
                        artifact,
                        ns=(
                            metadata.st_atime_ns,
                            metadata.st_mtime_ns + 1_000_000_000,
                        ),
                    )
                return value

            def keep_mtime_churning(
                descriptor: int,
                *,
                baseline: bytes,
                opened: os.stat_result,
                label: str,
            ) -> os.stat_result:
                result = original_revalidate(
                    descriptor,
                    baseline=baseline,
                    opened=opened,
                    label=label,
                )
                metadata = artifact.stat()
                os.utime(
                    artifact,
                    ns=(
                        metadata.st_atime_ns,
                        metadata.st_mtime_ns + 1_000_000_000,
                    ),
                )
                return result

            with (
                mock.patch.object(
                    MODULE.os,
                    "read",
                    side_effect=trigger_revalidation,
                ),
                mock.patch.object(
                    MODULE,
                    "_history_v2_revalidate_open_file",
                    side_effect=keep_mtime_churning,
                ),
            ):
                files, issue = MODULE.snapshot_explicit_history_v2_files(
                    root,
                    (Path("artifact.json"),),
                    max_entries=1,
                    max_file_bytes=1024,
                    max_tree_bytes=1024,
                )
            self.assertIsNone(files)
            self.assertIn("could not be revalidated", issue or "")
            self.assertNotIn("content changed", issue or "")

    def test_frozen_file_errors_distinguish_missing_unreadable_and_operational(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "artifact.json").write_bytes(b"stable")
            cases = (
                (errno.ENOENT, "is missing"),
                (errno.EACCES, "is unreadable"),
                (errno.EIO, "could not be inspected"),
            )
            for error_number, expected in cases:
                error = OSError(error_number, os.strerror(error_number))
                with (
                    self.subTest(error=error_number),
                    mock.patch.object(MODULE.os, "stat", side_effect=error),
                ):
                    files, issue = MODULE.snapshot_explicit_history_v2_files(
                        root,
                        (Path("artifact.json"),),
                        max_entries=1,
                        max_file_bytes=1024,
                        max_tree_bytes=1024,
                    )
                self.assertIsNone(files)
                self.assertEqual(issue, f"candidate artifact {expected}")

    def test_stable_policy_file_reader_revalidates_selected_properties(
        self,
    ) -> None:
        original_value = b'{"value":1}\n'
        replacement_value = b'{"value":2}\n'

        def read_policy(path: Path) -> bytes:
            return MODULE.read_history_v2_stable_policy_file(
                path,
                label="signing key",
                max_bytes=1024,
            )

        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "policy.json"
            path.write_bytes(original_value)
            helper = MODULE._read_history_v2_policy_file_descriptor
            with mock.patch.object(
                MODULE,
                "_read_history_v2_policy_file_descriptor",
                wraps=helper,
            ) as descriptor_read:
                self.assertEqual(read_policy(path), original_value)
            self.assertEqual(descriptor_read.call_count, 2)

        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "policy.json"
            path.write_bytes(original_value)
            path.chmod(0o644)
            original = path.stat()
            helper = MODULE._read_history_v2_policy_file_descriptor
            calls = 0

            def tighten_after_first_read(
                descriptor: int,
                *,
                max_bytes: int,
            ) -> bytes:
                nonlocal calls
                value = helper(descriptor, max_bytes=max_bytes)
                calls += 1
                if calls == 1:
                    os.utime(
                        path,
                        ns=(
                            original.st_atime_ns,
                            original.st_mtime_ns + 1_000_000_000,
                        ),
                    )
                    path.chmod(0o600)
                return value

            with mock.patch.object(
                MODULE,
                "_read_history_v2_policy_file_descriptor",
                side_effect=tighten_after_first_read,
            ):
                self.assertEqual(read_policy(path), original_value)
            self.assertGreaterEqual(calls, 3)

        transitions = (
            ("replacement", "object identity changed"),
            ("content", "content changed"),
            ("access", "access policy changed"),
        )
        for transition, expected in transitions:
            with self.subTest(transition=transition):
                with tempfile.TemporaryDirectory() as raw:
                    directory = Path(raw)
                    path = directory / "policy.json"
                    path.write_bytes(original_value)
                    if transition == "access":
                        path.chmod(0o600)
                    helper = MODULE._read_history_v2_policy_file_descriptor
                    calls = 0

                    def mutate_after_first_read(
                        descriptor: int,
                        *,
                        max_bytes: int,
                    ) -> bytes:
                        nonlocal calls
                        value = helper(descriptor, max_bytes=max_bytes)
                        calls += 1
                        if calls != 1:
                            return value
                        if transition == "replacement":
                            replacement = directory / "replacement.json"
                            replacement.write_bytes(original_value)
                            os.replace(replacement, path)
                        elif transition == "content":
                            path.write_bytes(replacement_value)
                        else:
                            path.chmod(0o666)
                        return value

                    with (
                        mock.patch.object(
                            MODULE,
                            "_read_history_v2_policy_file_descriptor",
                            side_effect=mutate_after_first_read,
                        ),
                        self.assertRaisesRegex(ValueError, expected),
                    ):
                        read_policy(path)

        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "missing.json"
            with self.assertRaisesRegex(ValueError, "is missing"):
                read_policy(path)

        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "policy.json"
            path.write_bytes(original_value)
            with (
                mock.patch.object(
                    MODULE.os,
                    "open",
                    side_effect=PermissionError("denied"),
                ),
                self.assertRaisesRegex(ValueError, "is unreadable"),
            ):
                read_policy(path)

        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "policy.json"
            path.write_bytes(original_value)
            helper = MODULE._read_history_v2_policy_file_descriptor

            def keep_mtime_churning(
                descriptor: int,
                *,
                max_bytes: int,
            ) -> bytes:
                value = helper(descriptor, max_bytes=max_bytes)
                metadata = path.stat()
                os.utime(
                    path,
                    ns=(
                        metadata.st_atime_ns,
                        metadata.st_mtime_ns + 1_000_000_000,
                    ),
                )
                return value

            with (
                mock.patch.object(
                    MODULE,
                    "_read_history_v2_policy_file_descriptor",
                    side_effect=keep_mtime_churning,
                ),
                self.assertRaisesRegex(ValueError, "could not be revalidated"),
            ):
                read_policy(path)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO fixtures require mkfifo")
    def test_frozen_tree_rejects_fifo_without_blocking(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.mkfifo(root / "pipe")
            started = time.monotonic()
            files, issue = MODULE.snapshot_bootstrap_v2_files(
                root,
                max_entries=1,
            )
            self.assertLess(time.monotonic() - started, 1)
            self.assertIsNone(files)
            self.assertIn("unsupported filesystem entry", issue or "")

    def test_global_diagnostic_and_jsonl_amplification_budgets_are_fixed(
        self,
    ) -> None:
        with (
            mock.patch.object(MODULE, "HISTORY_V2_MAX_DIAGNOSTIC_ITEMS", 3),
            mock.patch.object(MODULE, "HISTORY_V2_MAX_DIAGNOSTIC_BYTES", 128),
        ):
            diagnostics = MODULE.BoundedDiagnosticList(
                ("first", "second", "third", "fourth")
            )
        self.assertTrue(diagnostics.saturated)
        self.assertLessEqual(len(diagnostics), 3)
        self.assertLessEqual(
            sum(len(item.encode("utf-8")) for item in diagnostics),
            128,
        )

        snapshots = tuple(
            MODULE.HistoryV2FileSnapshot(
                relative=Path(f"synthetic-{index}.jsonl"),
                value=b"{}\n" * 5,
                mode=stat.S_IFREG | 0o644,
                device=1,
                inode=index,
                uid=1,
                gid=1,
                size=15,
                mtime_ns=1,
            )
            for index in (1, 2)
        )
        with (
            mock.patch.object(MODULE, "HISTORY_V2_MAX_JSONL_ROWS", 8),
            mock.patch.object(MODULE, "HISTORY_V2_MAX_TOTAL_JSONL_ROWS", 8),
        ):
            issues = MODULE.validate_root(
                Path("/synthetic/frozen"),
                file_snapshots=snapshots,
            )
        self.assertIn(
            "JSONL total row count exceeds the trusted limit",
            "\n".join(issues),
        )

        sensitive = risky_session_pointer()
        displayed = MODULE.display_relative_path(
            Path("runs") / sensitive / "manifest.json"
        )
        self.assertNotIn(sensitive, displayed)
        self.assertIn("[redacted]", displayed)

    def test_domain_range_contract_binds_candidate_and_default_transaction(
        self,
    ) -> None:
        base = "a" * 40
        head = "b" * 40
        tree = "c" * 40
        subject = "Publish session retrospective v2 daily 2026-07-15 run_ref_v2:aaaaaaaaaaaaaaaaaaaaaaaaaa"
        changed = [
            (
                "A",
                Path("runs/daily/2026-07-15/aaaaaaaaaaaaaaaaaaaaaaaaaa/manifest.json"),
            )
        ]
        calls: list[tuple[object, ...]] = []

        class Plan:
            @staticmethod
            def as_dict() -> dict[str, object]:
                return {
                    "schema_version": 1,
                    "base_oid": base,
                    "head_oid": head,
                    "head_tree_oid": tree,
                    "squash_subject": subject,
                    "trust_generation": "sha256:" + "d" * 64,
                }

        def build_plan(
            root: Path,
            base_rev: str,
            head_rev: str,
        ) -> tuple[Plan, list[str]]:
            calls.append(("candidate", root, base_rev, head_rev))
            return Plan(), []

        def validate_default(
            root: Path,
            base_rev: str,
            head_rev: str,
        ) -> list[str]:
            calls.append(("default", root, base_rev, head_rev))
            return []

        contract = MODULE.HistoryV2DomainContract(
            validate_v2_runs_with_inventory=lambda *_args: ([], ()),
            verify_publisher_attestation=lambda _blobs: True,
            build_pull_request_merge_plan=build_plan,
            validate_default_branch_update=validate_default,
            max_manifest_bytes=1024,
        )
        root = Path("/synthetic/trusted-history")
        with (
            mock.patch.object(
                MODULE,
                "trusted_history_v2_domain_contract",
                return_value=contract,
            ),
            mock.patch.object(
                MODULE,
                "trusted_history_v2_domain_revision_contract",
                return_value=contract,
            ),
        ):
            self.assertEqual(
                MODULE.validate_history_v2_domain_candidate_range(
                    root,
                    base_rev=base,
                    head_rev=head,
                    changed=changed,
                    expected_tree=tree,
                    expected_subject=subject,
                    expected_trust_generation="sha256:" + "d" * 64,
                ),
                [],
            )
            self.assertEqual(
                MODULE.validate_history_v2_domain_default_range(
                    root,
                    base_rev=base,
                    head_rev=head,
                    changed=changed,
                    work_budget=MODULE.HistoryV2WorkBudget(),
                ),
                [],
            )
        self.assertEqual(
            [call[0] for call in calls],
            ["candidate", "default"],
        )

    def test_default_runs_publication_loads_domain_from_before_revision(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            write_synthetic_history_v2_domain_sources(root)
            base = fixture_commit_all(root, "trusted domain base")
            manifest = (
                root
                / "runs"
                / "daily"
                / "2026-07-15"
                / "aaaaaaaaaaaaaaaaaaaaaaaaaa"
                / "manifest.json"
            )
            manifest.parent.mkdir(parents=True)
            manifest.write_text('{"schema_version":2}\n', encoding="utf-8")
            head = fixture_commit_all(
                root,
                "Publish session retrospective v2 daily 2026-07-15 "
                "run_ref_v2:aaaaaaaaaaaaaaaaaaaaaaaaaa",
                include_signature=False,
            )

            candidate_contract = MODULE.HistoryV2DomainContract(
                validate_v2_runs_with_inventory=lambda *_args: ([], ()),
                verify_publisher_attestation=lambda _blobs: True,
                build_pull_request_merge_plan=lambda *_args: (None, []),
                validate_default_branch_update=lambda *_args: [],
                max_manifest_bytes=1024,
                trusted_root=root,
                trusted_revision=head,
                trusted_generation="sha256:" + "f" * 64,
            )
            previous = MODULE._TRUSTED_HISTORY_V2_DOMAIN
            MODULE._TRUSTED_HISTORY_V2_DOMAIN = candidate_contract
            try:
                transaction = MODULE.validate_history_v2_default_transaction(
                    root,
                    before_rev=base,
                    head_rev=head,
                    event_created=False,
                    event_deleted=False,
                    event_forced=False,
                )
            finally:
                MODULE._TRUSTED_HISTORY_V2_DOMAIN = previous

        self.assertEqual(transaction["transaction_role"], "publication")
        self.assertEqual(transaction["base_sha"], base)
        self.assertEqual(transaction["head_sha"], head)

    def test_actual_default_rejects_nonparent_domain_before_execution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            write_synthetic_history_v2_domain_sources(root)
            base = fixture_commit_all(root, "trusted domain base")
            manifest = (
                root
                / "runs"
                / "daily"
                / "2026-07-15"
                / "aaaaaaaaaaaaaaaaaaaaaaaaaa"
                / "manifest.json"
            )
            manifest.parent.mkdir(parents=True)
            manifest.write_text('{"schema_version":2}\n', encoding="utf-8")
            head = fixture_commit_all(
                root,
                "Publish session retrospective v2 daily 2026-07-15 "
                "run_ref_v2:aaaaaaaaaaaaaaaaaaaaaaaaaa",
                include_signature=False,
            )

            marker = Path(raw) / "untrusted-domain-code-ran"
            malicious_source = (
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('ran', encoding='utf-8')\n"
                'VALUE = "attestation"\n'
            )
            malicious_path = (
                root / "scripts" / "retrospective_history_attestation_v2.py"
            )
            malicious_path.write_text(malicious_source, encoding="utf-8")
            malicious_base = fixture_commit_all(
                root,
                "untrusted nonparent domain",
                parents=(base,),
                include_signature=False,
            )
            fixture_set_head(root, head)

            with self.assertRaisesRegex(
                ValueError,
                "domain revision was not authorized by the default-event barrier",
            ):
                MODULE.trusted_history_v2_domain_revision_contract(
                    root,
                    malicious_base,
                    work_budget=MODULE.HistoryV2WorkBudget(),
                )
            self.assertFalse(marker.exists())

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--root",
                    str(root),
                    "--mode",
                    "history-v2-actual-default-squash",
                    "--base-rev",
                    malicious_base,
                    "--head-rev",
                    head,
                    "--event-created",
                    "false",
                    "--event-deleted",
                    "false",
                    "--event-forced",
                    "false",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "history-v2 head is not based on the exact authorized base",
            result.stdout,
        )
        self.assertEqual(result.stderr, "")
        self.assertFalse(marker.exists())

    def test_candidate_authorization_barrier_precedes_all_domain_control(
        self,
    ) -> None:
        root = Path("/synthetic/candidate")
        base = "a" * 40
        head = "b" * 40
        barrier_cases = (
            "history-v2 worktree head differs from the authorized head",
            "history-v2 worktree must exactly match the authorized head",
            "history-v2 head is not based on the exact authorized base",
        )
        for barrier_issue in barrier_cases:
            with (
                self.subTest(barrier=barrier_issue),
                mock.patch.object(
                    MODULE,
                    "validated_history_v2_range_checkout",
                    side_effect=ValueError(barrier_issue),
                ),
                mock.patch.object(
                    MODULE,
                    "history_v2_diff_output",
                    side_effect=AssertionError("range diff ran before barrier"),
                ) as diff,
                mock.patch.object(
                    MODULE,
                    "validate_history_v2_merge_range",
                    side_effect=AssertionError("physical range ran before barrier"),
                ) as physical,
                mock.patch.object(
                    MODULE,
                    "validate_history_v2_tree",
                    side_effect=AssertionError("candidate tree ran before barrier"),
                ) as tree,
                mock.patch.object(
                    MODULE,
                    "trusted_history_v2_domain_contract",
                    side_effect=AssertionError("domain control loaded before barrier"),
                ) as domain,
            ):
                plan, issues = MODULE.build_pull_request_candidate_plan(
                    root,
                    base,
                    head,
                )
            self.assertIsNone(plan)
            self.assertEqual(issues, [barrier_issue])
            diff.assert_not_called()
            physical.assert_not_called()
            tree.assert_not_called()
            domain.assert_not_called()

    def test_candidate_role_barrier_precedes_domain_control(
        self,
    ) -> None:
        root = Path("/synthetic/candidate")
        base = "a" * 40
        head = "b" * 40
        mixed = [
            ("A", Path("README.md")),
            (
                "A",
                Path(
                    "runs/daily/2026-07-15/"
                    "aaaaaaaaaaaaaaaaaaaaaaaaaa/manifest.json"
                ),
            ),
        ]
        with (
            mock.patch.object(
                MODULE,
                "validated_history_v2_range_checkout",
                return_value=(root, base, head),
            ),
            mock.patch.object(
                MODULE,
                "history_v2_diff_output",
                return_value=b"",
            ),
            mock.patch.object(
                MODULE,
                "parse_history_v2_changed_paths",
                return_value=mixed,
            ),
            mock.patch.object(
                MODULE,
                "validate_history_v2_merge_range",
                side_effect=AssertionError("physical range ran before role barrier"),
            ) as physical,
            mock.patch.object(
                MODULE,
                "trusted_history_v2_domain_contract",
                side_effect=AssertionError("domain control loaded before role barrier"),
            ) as domain,
        ):
            plan, issues = MODULE.build_pull_request_candidate_plan(
                root,
                base,
                head,
            )
        self.assertIsNone(plan)
        self.assertIn("mixes publication and admin paths", "\n".join(issues))
        physical.assert_not_called()
        domain.assert_not_called()

    def test_domain_candidate_plan_schema_and_authoritative_values_are_exact(
        self,
    ) -> None:
        base = "a" * 40
        head = "b" * 40
        tree = "c" * 40
        subject = (
            "Publish session retrospective v2 daily 2026-07-15 "
            "run_ref_v2:aaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        generation = "sha256:" + "d" * 64
        changed = [
            (
                "A",
                Path(
                    "runs/daily/2026-07-15/"
                    "aaaaaaaaaaaaaaaaaaaaaaaaaa/manifest.json"
                ),
            )
        ]

        class Plan:
            def __init__(self, payload: object) -> None:
                self.payload = payload

            def as_dict(self) -> object:
                return self.payload

        valid = {
            "schema_version": 1,
            "base_oid": base,
            "head_oid": head,
            "head_tree_oid": tree,
            "squash_subject": subject,
            "trust_generation": generation,
        }
        malformed = (
            ("boolean version", {**valid, "schema_version": True}),
            ("extra key", {**valid, "unexpected": "value"}),
            ("mapping subclass", type("PlanPayload", (dict,), {})(valid)),
            ("truthy issues", (valid, {"accepted": True})),
        )
        for label, value in malformed:
            payload, helper_issues = (
                value if isinstance(value, tuple) else (value, [])
            )
            contract = MODULE.HistoryV2DomainContract(
                validate_v2_runs_with_inventory=lambda *_args: ([], ()),
                verify_publisher_attestation=lambda _blobs: True,
                build_pull_request_merge_plan=lambda *_args, payload=payload, helper_issues=helper_issues: (
                    Plan(payload),
                    helper_issues,
                ),
                validate_default_branch_update=lambda *_args: [],
                max_manifest_bytes=1024,
            )
            with (
                self.subTest(label=label),
                mock.patch.object(
                    MODULE,
                    "trusted_history_v2_domain_contract",
                    return_value=contract,
                ),
            ):
                issues = MODULE.validate_history_v2_domain_candidate_range(
                    Path("/synthetic/trusted-history"),
                    base_rev=base,
                    head_rev=head,
                    changed=changed,
                    expected_tree=tree,
                    expected_subject=subject,
                    expected_trust_generation=generation,
                )
            self.assertIn(
                "result is invalid"
                if label == "truthy issues"
                else "plan is inconsistent",
                "\n".join(issues),
            )

        for label, mutation in (
            ("tree", {"head_tree_oid": "e" * 40}),
            ("subject", {"squash_subject": "Publish a different snapshot"}),
            ("generation", {"trust_generation": "sha256:" + "f" * 64}),
        ):
            payload = {**valid, **mutation}
            contract = MODULE.HistoryV2DomainContract(
                validate_v2_runs_with_inventory=lambda *_args: ([], ()),
                verify_publisher_attestation=lambda _blobs: True,
                build_pull_request_merge_plan=lambda *_args, payload=payload: (
                    Plan(payload),
                    [],
                ),
                validate_default_branch_update=lambda *_args: [],
                max_manifest_bytes=1024,
            )
            with (
                self.subTest(authority=label),
                mock.patch.object(
                    MODULE,
                    "trusted_history_v2_domain_contract",
                    return_value=contract,
                ),
            ):
                issues = MODULE.validate_history_v2_domain_candidate_range(
                    Path("/synthetic/trusted-history"),
                    base_rev=base,
                    head_rev=head,
                    changed=changed,
                    expected_tree=tree,
                    expected_subject=subject,
                    expected_trust_generation=generation,
                )
            self.assertEqual(
                issues,
                ["trusted history-v2 candidate range plan is inconsistent"],
            )

    def test_v2_bundle_candidate_validates_physical_range_before_domain_plan(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            manifest = (
                root
                / "runs"
                / "daily"
                / "2026-07-15"
                / "aaaaaaaaaaaaaaaaaaaaaaaaaa"
                / "manifest.json"
            )
            manifest.parent.mkdir(parents=True)
            manifest.write_text('{"schema_version":2}\n', encoding="utf-8")
            run_fixture_git(root, "add", manifest.relative_to(root).as_posix())
            tree = run_fixture_git(root, "write-tree").stdout.strip()
            subject = (
                "Publish session retrospective v2 daily 2026-07-15 "
                "run_ref_v2:aaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
            head = fixture_raw_commit(
                root,
                tree_oid=tree,
                parents=(base,),
                message=subject,
                include_signature=False,
            )
            fixture_set_head(root, head)
            with (
                mock.patch.object(
                    MODULE,
                    "validate_history_v2_tree",
                    return_value=[],
                ) as tree_validation,
                mock.patch.object(
                    MODULE,
                    "validate_history_v2_domain_candidate_range",
                    return_value=[],
                ) as domain,
                mock.patch.object(
                    MODULE,
                    "validate_history_v2_merge_range",
                    return_value={
                        "head_tree_sha": tree,
                        "head_subject": subject,
                    },
                ) as physical_range,
                mock.patch.object(
                    MODULE,
                    "history_v2_trust_generation_digest",
                    return_value="d" * 64,
                ),
            ):
                plan, issues = MODULE.build_pull_request_candidate_plan(
                    root,
                    base,
                    head,
                )
            self.assertEqual(issues, [])
            self.assertIsNotNone(plan)
            assert plan is not None
            self.assertEqual(plan.role, "publication")
            self.assertEqual(plan.head_tree_oid, tree)
            self.assertEqual(plan.squash_subject, subject)
            domain.assert_called_once()
            physical_range.assert_called_once()
            self.assertIs(
                physical_range.call_args.kwargs["verify_candidate_signature"],
                True,
            )
            self.assertEqual(
                domain.call_args.kwargs["expected_tree"],
                tree,
            )
            self.assertEqual(
                domain.call_args.kwargs["expected_subject"],
                subject,
            )
            self.assertEqual(
                domain.call_args.kwargs["expected_trust_generation"],
                "sha256:" + "d" * 64,
            )
            self.assertEqual(
                tree_validation.call_args.kwargs["trusted_base_rev"],
                base,
            )

    def test_domain_candidate_rejects_raw_commit_message_before_helper(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            manifest = (
                root
                / "runs"
                / "daily"
                / "2026-07-15"
                / "aaaaaaaaaaaaaaaaaaaaaaaaaa"
                / "manifest.json"
            )
            manifest.parent.mkdir(parents=True)
            manifest.write_text('{"schema_version":2}\n', encoding="utf-8")
            run_fixture_git(root, "add", manifest.relative_to(root).as_posix())
            tree_oid = run_fixture_git(root, "write-tree").stdout.strip()
            rejected_message = "Raw user prompt: retain this transcript"
            head = fixture_raw_commit(
                root,
                tree_oid=tree_oid,
                parents=(base,),
                message=rejected_message,
            )
            fixture_set_head(root, head)
            with (
                mock.patch.object(
                    MODULE,
                    "history_v2_signature_verifier_for_root",
                    return_value=FixtureStructuralSignatureVerifier(),
                ),
                mock.patch.object(
                    MODULE,
                    "validate_history_v2_tree",
                    side_effect=AssertionError(
                        "candidate tree ran after invalid commit metadata"
                    ),
                ) as tree_validation,
                mock.patch.object(
                    MODULE,
                    "trusted_history_v2_domain_contract",
                    side_effect=AssertionError(
                        "domain helper loaded after invalid commit metadata"
                    ),
                ) as domain,
            ):
                plan, issues = MODULE.build_pull_request_candidate_plan(
                    root,
                    base,
                    head,
                )
            self.assertIsNone(plan)
            self.assertIn(
                "commit message contains raw/sensitive evidence",
                "\n".join(issues),
            )
            self.assertNotIn(rejected_message, "\n".join(issues))
            tree_validation.assert_not_called()
            domain.assert_not_called()

    def test_fixed_q_and_prospective_squash_validate_current_global_tree(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            report = root / "reports" / "daily" / "2026" / "07" / "15.md"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text("# Daily retrospective\n", encoding="utf-8")
            run_fixture_git(root, "add", report.relative_to(root).as_posix())
            queue = fixture_commit_all(root, "queue projection")
            queue_tree = run_fixture_git(
                root,
                "rev-parse",
                f"{queue}^{{tree}}",
            ).stdout.strip()
            prospective = fixture_raw_commit(
                root,
                tree_oid=queue_tree,
                parents=(base,),
                message="Publish retained history",
                include_signature=False,
            )
            digests = {
                relative: hashlib.sha256(
                    (root / relative).read_bytes()
                ).hexdigest()
                for relative in MODULE.BOOTSTRAP_V2_PUBLIC_KEY_FILES
            }
            with mock.patch.object(
                MODULE,
                "BOOTSTRAP_V2_PUBLIC_KEY_SHA256",
                digests,
            ):
                self.assertEqual(
                    MODULE.validate_fixed_head_snapshot(root, queue),
                    [],
                )
            self.assertEqual(
                MODULE.validate_append_only_event_range(
                    root,
                    base,
                    prospective,
                    forced=False,
                ),
                [],
            )
            self.assertIn(
                "forced",
                "\n".join(
                    MODULE.validate_append_only_event_range(
                        root,
                        base,
                        prospective,
                        forced=True,
                    )
                ),
            )
            report.write_text(
                "Leaked endpoint " + risky_internal_url() + "\n",
                encoding="utf-8",
            )
            self.assertIn(
                "not pristine",
                "\n".join(MODULE.validate_fixed_head_snapshot(root, queue)),
            )

    def test_actual_default_admin_squash_is_linear_and_unsigned_by_design(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            (root / "README.md").write_text(
                "Authorized admin result.\n",
                encoding="utf-8",
            )
            run_fixture_git(root, "add", "README.md")
            tree_oid = run_fixture_git(root, "write-tree").stdout.strip()
            squash = fixture_raw_commit(
                root,
                tree_oid=tree_oid,
                parents=(base,),
                message="Update trusted history policy",
                include_signature=False,
            )
            fixture_set_head(root, squash)

            transaction = validate_synthetic_history_v2_default_transaction(
                root,
                before_rev=base,
                head_rev=squash,
            )
            self.assertEqual(transaction["transaction_role"], "admin")
            self.assertIs(transaction["candidate_signature_retained"], False)
            self.assertEqual(transaction["commit_count"], 1)

    def test_unsigned_squash_metadata_is_exact_and_privacy_scanned(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            tree_oid = run_fixture_git(
                root,
                "rev-parse",
                f"{base}^{{tree}}",
            ).stdout.strip()
            benign = fixture_raw_commit(
                root,
                tree_oid=tree_oid,
                parents=(base,),
                message="Publish retained history",
                author=(
                    "Joey Teng "
                    "<12345+JoeyTeng@users.noreply.github.com>"
                ),
                committer="GitHub <noreply@github.com>",
                include_signature=False,
            )
            self.assertEqual(
                MODULE.parse_history_v2_unsigned_squash_commit(
                    fixture_commit_bytes(root, benign),
                    expected_oid=benign,
                ),
                (tree_oid, (base,)),
            )

            forbidden_messages = (
                ("path", "Publish " + risky_local_path()),
                ("secret", "Publish " + risky_secret_token()),
                ("raw ID", "Publish " + risky_session_pointer()),
                ("internal URL", "Publish " + risky_internal_url()),
                ("raw prompt", "Raw user prompt: summarize this"),
                ("tool output", "Tool output: retained bytes"),
                (
                    "transcript",
                    "Conversation transcript: user said hello",
                ),
            )
            for label, message in forbidden_messages:
                commit_oid = fixture_raw_commit(
                    root,
                    tree_oid=tree_oid,
                    parents=(base,),
                    message=message,
                    include_signature=False,
                )
                with self.subTest(label=label), self.assertRaises(
                    ValueError
                ) as caught:
                    MODULE.parse_history_v2_unsigned_squash_commit(
                        fixture_commit_bytes(root, commit_oid),
                        expected_oid=commit_oid,
                    )
                self.assertIn("prohibited retained evidence", str(caught.exception))
                self.assertNotIn(message, str(caught.exception))

            header_cases = (
                (
                    "unexpected",
                    {"extra_headers": (b"x-provider safe",), "include_signature": False},
                ),
                (
                    "encoding",
                    {"extra_headers": (b"encoding UTF-8",), "include_signature": False},
                ),
                ("signature", {"include_signature": True}),
            )
            for label, options in header_cases:
                commit_oid = fixture_raw_commit(
                    root,
                    tree_oid=tree_oid,
                    parents=(base,),
                    message="Publish retained history",
                    **options,
                )
                with self.subTest(label=label), self.assertRaisesRegex(
                    ValueError,
                    "header set",
                ):
                    MODULE.parse_history_v2_unsigned_squash_commit(
                        fixture_commit_bytes(root, commit_oid),
                        expected_oid=commit_oid,
                    )

            for field, name in (
                ("author", "Raw user prompt"),
                ("committer", "Tool output"),
            ):
                squash_identity = (
                    name
                    + " <12345+Synthetic@users.noreply.github.com>"
                )
                options = {
                    field: squash_identity,
                    "include_signature": False,
                }
                commit_oid = fixture_raw_commit(
                    root,
                    tree_oid=tree_oid,
                    parents=(base,),
                    message="Publish retained history",
                    **options,
                )
                with self.subTest(field=field), self.assertRaises(
                    ValueError
                ) as caught:
                    MODULE.parse_history_v2_unsigned_squash_commit(
                        fixture_commit_bytes(root, commit_oid),
                        expected_oid=commit_oid,
                    )
                self.assertIn(
                    "identity contains prohibited retained evidence",
                    str(caught.exception),
                )
                self.assertNotIn(name, str(caught.exception))

            private_identity = (
                "Synthetic Publisher <" + risky_email() + ">"
            )
            private_identity_oid = fixture_raw_commit(
                root,
                tree_oid=tree_oid,
                parents=(base,),
                message="Publish retained history",
                author=private_identity,
                include_signature=False,
            )
            with self.assertRaises(ValueError) as caught:
                MODULE.parse_history_v2_unsigned_squash_commit(
                    fixture_commit_bytes(root, private_identity_oid),
                    expected_oid=private_identity_oid,
                )
            self.assertIn("identity is outside privacy policy", str(caught.exception))
            self.assertNotIn(private_identity, str(caught.exception))

            identity = MODULE.HISTORY_V2_CANONICAL_IDENTITY
            invalid_utf8_raw = (
                f"tree {tree_oid}\n"
                f"parent {base}\n"
                f"author {identity} {FIXTURE_TIMESTAMP} +0000\n"
                f"committer {identity} {FIXTURE_TIMESTAMP} +0000\n"
                "\n"
            ).encode("ascii") + bytes((0xFF, 0x0A))
            invalid_utf8_oid = fixture_store_commit(root, invalid_utf8_raw)
            with self.assertRaisesRegex(ValueError, "not UTF-8"):
                MODULE.parse_history_v2_unsigned_squash_commit(
                    invalid_utf8_raw,
                    expected_oid=invalid_utf8_oid,
                )

    def test_default_transaction_accepts_append_and_rejects_event_force_flags(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            report = root / "reports" / "daily" / "2026" / "07" / "15.md"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text("# Daily retrospective\n", encoding="utf-8")
            run_fixture_git(root, "add", report.relative_to(root).as_posix())
            head = fixture_commit_all(
                root,
                "append daily report",
                include_signature=False,
            )

            transaction = validate_synthetic_history_v2_default_transaction(
                root,
                before_rev=base,
                head_rev=head,
            )
            self.assertEqual(transaction["transaction_kind"], "history-v2")
            self.assertEqual(transaction["base_sha"], base)
            self.assertEqual(transaction["head_sha"], head)

            with self.assertRaisesRegex(ValueError, "force-push is prohibited"):
                validate_synthetic_history_v2_default_transaction(
                    root,
                    before_rev=base,
                    head_rev=head,
                    event_forced=True,
                )
            with self.assertRaisesRegex(ValueError, "zero-before"):
                validate_synthetic_history_v2_default_transaction(
                    root,
                    before_rev="0" * len(base),
                    head_rev=head,
                )
            with self.assertRaisesRegex(ValueError, "branch creation/bootstrap"):
                validate_synthetic_history_v2_default_transaction(
                    root,
                    before_rev=base,
                    head_rev=head,
                    event_created=True,
                )
            with self.assertRaisesRegex(ValueError, "deletion is prohibited"):
                validate_synthetic_history_v2_default_transaction(
                    root,
                    before_rev=base,
                    head_rev="0" * len(head),
                    event_deleted=True,
                )

    def test_default_transaction_rejects_deletes_and_jsonl_rewrites(self) -> None:
        for mutation in ("delete", "rewrite"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = Path(raw) / "repo"
                write_bootstrap_v2_candidate(root)
                episodes = (
                    root
                    / "data"
                    / "episodes"
                    / "2026"
                    / "07"
                    / "episodes.jsonl"
                )
                episodes.parent.mkdir(parents=True, exist_ok=True)
                first = valid_episode()
                episodes.write_text(json.dumps(first) + "\n", encoding="utf-8")
                run_fixture_git(root, "add", "--all")
                fixture_commit_all(root, "post migration base")
                base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
                if mutation == "delete":
                    episodes.unlink()
                else:
                    replacement = {
                        **first,
                        "topic": "Rewritten retained topic",
                    }
                    episodes.write_text(
                        json.dumps(replacement) + "\n",
                        encoding="utf-8",
                    )
                run_fixture_git(root, "add", "--all")
                head = fixture_commit_all(
                    root,
                    f"{mutation} retained history",
                    include_signature=False,
                )

                expected = (
                    "changed-path metadata is outside policy"
                    if mutation == "delete"
                    else "strict append-only"
                )
                with self.assertRaisesRegex(ValueError, expected):
                    validate_synthetic_history_v2_default_transaction(
                        root,
                        before_rev=base,
                        head_rev=head,
                    )

    def test_default_transaction_rejects_non_linear_and_rewritten_graphs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "non-linear"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            base_tree = run_fixture_git(
                root,
                "rev-parse",
                f"{base}^{{tree}}",
            ).stdout.strip()
            first = fixture_raw_commit(
                root,
                tree_oid=base_tree,
                parents=(base,),
                message="first side",
            )
            second = fixture_raw_commit(
                root,
                tree_oid=base_tree,
                parents=(base,),
                message="second side",
            )
            fixture_set_head(root, first)
            report = root / "reports" / "daily" / "2026" / "07" / "15.md"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text("# Daily retrospective\n", encoding="utf-8")
            run_fixture_git(root, "add", report.relative_to(root).as_posix())
            merge_tree = run_fixture_git(root, "write-tree").stdout.strip()
            head = fixture_raw_commit(
                root,
                tree_oid=merge_tree,
                parents=(first, second),
                message="merge side histories",
                include_signature=False,
            )
            fixture_set_head(root, head)

            with self.assertRaisesRegex(ValueError, "linear single-parent squash"):
                validate_synthetic_history_v2_default_transaction(
                    root,
                    before_rev=base,
                    head_rev=head,
                )

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "rewritten"
            write_bootstrap_v2_candidate(root)
            original = fixture_commit_all(root, "original root")
            report = root / "reports" / "daily" / "2026" / "07" / "15.md"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text("# Daily retrospective\n", encoding="utf-8")
            run_fixture_git(root, "add", report.relative_to(root).as_posix())
            tree_oid = run_fixture_git(root, "write-tree").stdout.strip()
            rewritten = fixture_raw_commit(
                root,
                tree_oid=tree_oid,
                parents=(),
                message="rewritten root",
                include_signature=False,
            )
            fixture_set_head(root, rewritten)
            with self.assertRaisesRegex(ValueError, "exact authorized base"):
                validate_synthetic_history_v2_default_transaction(
                    root,
                    before_rev=original,
                    head_rev=rewritten,
                )

    def test_default_transaction_explicitly_validates_bootstrap_shape(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            write_bootstrap_v2_base(root)
            fixture_commit_all(root, "bootstrap base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            (root / MODULE.BOOTSTRAP_V2_CI_PATH).write_bytes(
                PERMANENT_CI_TEMPLATE.read_bytes()
            )
            for relative in MODULE.BOOTSTRAP_V2_TEMPORARY_PATHS:
                (root / relative).unlink()
            run_fixture_git(root, "add", "--all")
            head = fixture_commit_all(
                root,
                "complete bootstrap migration",
                include_signature=False,
            )

            self.assertEqual(validate_synthetic_history_v2_tree(root), [])
            transaction = validate_synthetic_history_v2_default_transaction(
                root,
                before_rev=base,
                head_rev=head,
            )
            self.assertEqual(transaction["transaction_kind"], "bootstrap-v2")
            self.assertEqual(transaction["commit_count"], 1)

    def test_history_v2_merge_plan_rejects_infrastructure_changes(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside policy"):
            MODULE.parse_history_v2_changed_paths(
                MODULE.NUL_BYTE.join(
                    (
                        b"M",
                        b"reports/daily/2026/07/15.md",
                        b"M",
                        b"reports/daily/2026/07/15.md",
                        b"",
                    )
                )
            )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            readme = root / "README.md"
            readme.write_text("Synthetic trusted rewrite.\n", encoding="utf-8")
            run_fixture_git(root, "add", "README.md")
            fixture_commit_all(root, "rewrite infrastructure")
            head = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()

            with self.assertRaisesRegex(ValueError, "different authority role"):
                validate_synthetic_history_v2_merge_range(
                    root,
                    base_rev=base,
                    head_rev=head,
                )

    def test_history_v2_merge_plan_rejects_jsonl_rewrites(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            episodes = root / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            episodes.parent.mkdir(parents=True, exist_ok=True)
            first = valid_episode()
            episodes.write_text(json.dumps(first) + "\n", encoding="utf-8")
            run_fixture_git(root, "add", "--all")
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            replacement = {**first, "topic": "Rewritten retained topic"}
            episodes.write_text(json.dumps(replacement) + "\n", encoding="utf-8")
            run_fixture_git(root, "add", episodes.relative_to(root).as_posix())
            fixture_commit_all(root, "rewrite history")
            head = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()

            with self.assertRaisesRegex(ValueError, "strict append-only"):
                validate_synthetic_history_v2_merge_range(
                    root,
                    base_rev=base,
                    head_rev=head,
                )

    def test_history_v2_rejects_sensitive_intermediate_tree_restored_at_head(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            report = root / "reports" / "daily" / "2026" / "07" / "15.md"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(
                "Temporary raw endpoint " + risky_internal_url() + "\n",
                encoding="utf-8",
            )
            run_fixture_git(root, "add", report.relative_to(root).as_posix())
            fixture_commit_all(root, "temporary report")
            report.unlink()
            run_fixture_git(root, "add", "--all")
            fixture_commit_all(root, "remove temporary report")
            head = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()

            self.assertEqual(validate_synthetic_history_v2_tree(root), [])
            with self.assertRaisesRegex(ValueError, "newly reachable commit tree"):
                validate_synthetic_history_v2_merge_range(
                    root,
                    base_rev=base,
                    head_rev=head,
                )

    def test_history_v2_rejects_intermediate_infrastructure_restored_at_head(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            readme = root / "README.md"
            original = readme.read_bytes()
            readme.write_text("Temporary infrastructure rewrite.\n", encoding="utf-8")
            run_fixture_git(root, "add", "README.md")
            fixture_commit_all(root, "temporary rewrite")
            readme.write_bytes(original)
            report = root / "reports" / "daily" / "2026" / "07" / "15.md"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text("# Daily retrospective\n", encoding="utf-8")
            run_fixture_git(root, "add", "--all")
            fixture_commit_all(root, "restore infrastructure")
            head = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()

            self.assertEqual(validate_synthetic_history_v2_tree(root), [])
            with self.assertRaisesRegex(ValueError, "intermediate commit changes"):
                validate_synthetic_history_v2_merge_range(
                    root,
                    base_rev=base,
                    head_rev=head,
                )

    def test_history_v2_rejects_sensitive_message_on_side_branch(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            run_fixture_git(root, "switch", "--quiet", "-c", "side")
            report = root / "reports" / "daily" / "2026" / "07" / "15.md"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text("# Daily retrospective\n", encoding="utf-8")
            run_fixture_git(root, "add", report.relative_to(root).as_posix())
            side = fixture_commit_all(
                root,
                "temporary source " + risky_internal_url(),
            )
            run_fixture_git(root, "switch", "--quiet", "--detach", base)
            other = root / "reports" / "daily" / "2026" / "07" / "16.md"
            other.parent.mkdir(parents=True, exist_ok=True)
            other.write_text("# Daily retrospective\n", encoding="utf-8")
            run_fixture_git(root, "add", other.relative_to(root).as_posix())
            main = fixture_commit_all(root, "main report")
            run_fixture_git(
                root,
                "merge",
                "--quiet",
                "--no-ff",
                "--no-commit",
                "side",
            )
            head = fixture_commit_all(
                root,
                "merge retained reports",
                parents=(main, side),
            )

            self.assertEqual(validate_synthetic_history_v2_tree(root), [])
            with self.assertRaisesRegex(ValueError, "commit message contains"):
                validate_synthetic_history_v2_merge_range(
                    root,
                    base_rev=base,
                    head_rev=head,
                )

    def test_history_v2_rejects_empty_subtree_added_then_removed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            base_records = run_fixture_git_bytes(
                root, "ls-tree", "-z", f"{base}^{{tree}}"
            )
            empty_tree = fixture_mktree(root, b"")
            intermediate_tree = fixture_mktree(
                root,
                base_records
                + f"040000 tree {empty_tree}\tplaceholder".encode("ascii")
                + MODULE.NUL_BYTE,
            )
            intermediate = fixture_raw_commit(
                root,
                tree_oid=intermediate_tree,
                parents=(base,),
                message="temporary empty subtree",
            )
            fixture_set_head(root, intermediate)
            report = root / "reports" / "daily" / "2026" / "07" / "15.md"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text("# Daily retrospective\n", encoding="utf-8")
            run_fixture_git(root, "add", report.relative_to(root).as_posix())
            fixture_commit_all(root, "append report")
            head = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()

            self.assertEqual(validate_synthetic_history_v2_tree(root), [])
            with self.assertRaisesRegex(ValueError, "empty or unrepresented subtree"):
                validate_synthetic_history_v2_merge_range(
                    root,
                    base_rev=base,
                    head_rev=head,
                )

    def test_history_v2_rejects_nested_sensitive_empty_tree_at_final_head(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            base_records = run_fixture_git_bytes(
                root, "ls-tree", "-z", f"{base}^{{tree}}"
            )
            empty_tree = fixture_mktree(root, b"")
            sensitive_tree = fixture_mktree(
                root,
                f"040000 tree {empty_tree}\tnested".encode("ascii")
                + MODULE.NUL_BYTE,
            )
            outer_tree = fixture_mktree(
                root,
                f"040000 tree {sensitive_tree}\traw".encode("ascii")
                + MODULE.NUL_BYTE,
            )
            root_tree = fixture_mktree(
                root,
                base_records
                + f"040000 tree {outer_tree}\tarchive".encode("ascii")
                + MODULE.NUL_BYTE,
            )
            head = fixture_raw_commit(
                root,
                tree_oid=root_tree,
                parents=(base,),
                message="nested tree probe",
            )
            fixture_set_head(root, head)

            issues = "\n".join(validate_synthetic_history_v2_tree(root))
            self.assertIn("commit tree contains a sensitive path", issues)

    def test_history_v2_rejects_sensitive_leaf_blob_before_read_or_materialize(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            sensitive = (
                root
                / "reports"
                / "daily"
                / "2026"
                / "07"
                / "api-token.txt"
            )
            sensitive.parent.mkdir(parents=True, exist_ok=True)
            sensitive.write_text("must not be read\n", encoding="utf-8")
            run_fixture_git(root, "add", sensitive.relative_to(root).as_posix())
            head = fixture_commit_all(root, "sensitive leaf probe")

            with (
                mock.patch.object(
                    MODULE,
                    "history_v2_read_blob",
                    side_effect=AssertionError(
                        "sensitive leaf reached blob read"
                    ),
                ) as blob_read,
                mock.patch.object(
                    MODULE,
                    "validate_history_v2_commit_tree",
                    side_effect=AssertionError(
                        "sensitive leaf reached tree materialization"
                    ),
                ) as materialization,
                self.assertRaisesRegex(ValueError, "sensitive path"),
            ):
                validate_synthetic_history_v2_merge_range(
                    root,
                    base_rev=base,
                    head_rev=head,
                )
            blob_read.assert_not_called()
            materialization.assert_not_called()

    def test_history_v2_rejects_admin_armor_path_variants_before_blob_read(
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
        for path in variants:
            with self.subTest(path=path):
                raw_tree = (
                    b"100644 blob "
                    + b"a" * 40
                    + b" 12\t"
                    + path.encode("utf-8")
                    + MODULE.NUL_BYTE
                )
                with (
                    mock.patch.object(
                        MODULE,
                        "history_v2_git_output",
                        return_value=raw_tree,
                    ),
                    mock.patch.object(
                        MODULE,
                        "history_v2_read_blob",
                        side_effect=AssertionError(
                            "forbidden armor path reached blob read"
                        ),
                    ) as blob_read,
                    mock.patch.object(
                        MODULE,
                        "validate_history_v2_commit_tree",
                        side_effect=AssertionError(
                            "forbidden armor path reached tree materialization"
                        ),
                    ) as materialization,
                    self.assertRaisesRegex(ValueError, "sensitive path"),
                ):
                    entries = MODULE.history_v2_tree_entries(
                        Path("/synthetic/repository"),
                        "b" * 40,
                        tree_oid="c" * 40,
                        work_budget=MODULE.HistoryV2WorkBudget(),
                    )
                    for entry in entries:
                        MODULE.history_v2_read_blob(
                            Path("/synthetic/repository"),
                            entry,
                            work_budget=MODULE.HistoryV2WorkBudget(),
                        )
                    MODULE.validate_history_v2_commit_tree()
                blob_read.assert_not_called()
                materialization.assert_not_called()

    def test_history_v2_canonical_signed_commit_metadata_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            tree_oid = run_fixture_git(root, "rev-parse", "HEAD^{tree}").stdout.strip()
            commit_oid = fixture_raw_commit(
                root,
                tree_oid=tree_oid,
                parents=(base,),
                message=(
                    "Canonical retained history\n\n"
                    "Co-authored-by: Codex "
                    "(tool=Codex CLI; model=GPT-5.6 Sol) "
                    "<codex@openai.com>"
                ),
            )
            parsed = parse_fixture_commit(root, commit_oid)

            self.assertEqual(parsed.tree_oid, tree_oid)
            self.assertEqual(parsed.parents, (base,))
            self.assertEqual(
                parsed.signature.signer_fingerprint,
                FIXTURE_SIGNER_FINGERPRINT,
            )
            self.assertEqual(parsed.signature.created_at, FIXTURE_TIMESTAMP)
            self.assertNotIn(b"gpgsig ", parsed.signature.signed_payload)

    def test_history_v2_commit_identity_time_and_timezone_are_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            tree_oid = run_fixture_git(root, "rev-parse", "HEAD^{tree}").stdout.strip()
            cases = (
                (
                    "author secret",
                    {
                        "author": "Synthetic "
                        + risky_secret_token()
                        + " <synthetic@example.invalid>"
                    },
                    "author identity",
                ),
                (
                    "committer PII",
                    {
                        "committer": "Synthetic Test <" + risky_email() + ">"
                    },
                    "committer identity",
                ),
                (
                    "synthetic author",
                    {
                        "author": "Synthetic Test <synthetic@example.invalid>",
                    },
                    "author identity",
                ),
                (
                    "author timezone",
                    {"author_timezone": "+0800"},
                    "author identity",
                ),
                (
                    "committer timezone",
                    {"committer_timezone": "-0000"},
                    "committer identity",
                ),
                (
                    "zero timestamp",
                    {
                        "author_timestamp": 0,
                        "committer_timestamp": 0,
                    },
                    "author identity",
                ),
                (
                    "mismatched timestamps",
                    {"author_timestamp": FIXTURE_TIMESTAMP - 1},
                    "timestamps must match",
                ),
            )
            for label, identity_arguments, expected in cases:
                with self.subTest(label=label):
                    commit_oid = fixture_raw_commit(
                        root,
                        tree_oid=tree_oid,
                        parents=(base,),
                        message="identity probe",
                        **identity_arguments,
                    )
                    with self.assertRaisesRegex(
                        ValueError, expected + ".*retained privacy policy"
                        if "identity" in expected
                        else expected
                    ):
                        parse_fixture_commit(root, commit_oid)
            with self.assertRaisesRegex(ValueError, "timestamp is outside policy"):
                MODULE.validate_history_v2_commit_identity(
                    (
                        MODULE.HISTORY_V2_CANONICAL_IDENTITY
                        + " 4294967296 +0000"
                    ).encode("ascii"),
                    "author",
                )

    def test_history_v2_raw_commit_headers_and_messages_are_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            tree_oid = run_fixture_git(root, "rev-parse", "HEAD^{tree}").stdout.strip()
            canonical_oid = fixture_raw_commit(
                root,
                tree_oid=tree_oid,
                parents=(base,),
                message="Canonical message",
            )
            canonical = fixture_commit_bytes(root, canonical_oid)
            header = canonical.partition(b"\n\n")[0]
            cases = (
                (
                    "unknown header",
                    canonical.replace(
                        b"\ngpgsig ",
                        b"\nx-private hidden\ngpgsig ",
                        1,
                    ),
                    "header is outside policy",
                ),
                (
                    "multiline header",
                    canonical.replace(
                        b"\ngpgsig ",
                        b"\n hidden-continuation\ngpgsig ",
                        1,
                    ),
                    "header continuation is prohibited",
                ),
                (
                    "encoding header",
                    canonical.replace(
                        b"\ngpgsig ",
                        b"\nencoding UTF-8\ngpgsig ",
                        1,
                    ),
                    "header is outside policy",
                ),
                (
                    "alternate signature header",
                    canonical.replace(
                        b"\ngpgsig ",
                        b"\ngpgsig-sha256 ",
                        1,
                    ),
                    "alternate signature headers are prohibited",
                ),
                (
                    "CR byte",
                    canonical.replace(b"\n", b"\r\n", 1),
                    "prohibited CR bytes",
                ),
                (
                    "missing final LF",
                    canonical[:-1],
                    "message is not canonical",
                ),
                (
                    "extra final LF",
                    canonical + b"\n",
                    "message is not canonical",
                ),
                (
                    "leading blank message",
                    header + b"\n\n\nCanonical message\n",
                    "message is not canonical",
                ),
                (
                    "trailing whitespace",
                    header + b"\n\nCanonical message \n",
                    "message is not canonical",
                ),
                (
                    "non-UTF-8 message",
                    header + b"\n\nCanonical " + bytes((255,)) + b"\n",
                    "message is not UTF-8",
                ),
                (
                    "sensitive message",
                    (
                        header
                        + b"\n\nSensitive endpoint "
                        + risky_internal_url().encode("utf-8")
                        + b"\n"
                    ),
                    "message contains raw/sensitive evidence",
                ),
                (
                    "unapproved Codex trailer",
                    (
                        header
                        + b"\n\nCanonical message\n\n"
                        + b"Co-authored-by: Codex "
                        + b"(tool=Codex CLI; model=Experimental) "
                        + b"<codex@openai.com>\n"
                    ),
                    "message contains raw/sensitive evidence",
                ),
            )
            for label, raw_commit, expected in cases:
                with self.subTest(label=label):
                    commit_oid = MODULE.history_v2_commit_object_id(
                        raw_commit,
                        expected_length=40,
                    )
                    with self.assertRaisesRegex(ValueError, expected):
                        MODULE.parse_history_v2_commit_object(
                            raw_commit,
                            expected_oid=commit_oid,
                        )

            for label, message in (
                ("raw prompt", "Raw user prompt: summarize this"),
                ("tool output", "Tool output: retained bytes"),
                (
                    "transcript",
                    "Conversation transcript: user said hello",
                ),
            ):
                raw_commit = (
                    header
                    + b"\n\n"
                    + message.encode("ascii")
                    + b"\n"
                )
                commit_oid = MODULE.history_v2_commit_object_id(
                    raw_commit,
                    expected_length=40,
                )
                with self.subTest(label=label), self.assertRaisesRegex(
                    ValueError,
                    "message contains raw/sensitive evidence",
                ) as caught:
                    MODULE.parse_history_v2_commit_object(
                        raw_commit,
                        expected_oid=commit_oid,
                    )
                self.assertNotIn(message, str(caught.exception))

    def test_history_v2_commit_signature_profile_rejects_privacy_channels(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            tree_oid = run_fixture_git(root, "rev-parse", "HEAD^{tree}").stdout.strip()
            cases = (
                (
                    "unsigned",
                    {"include_signature": False},
                    "header order is invalid",
                ),
                (
                    "alternate signature",
                    {
                        "include_signature": False,
                        "extra_headers": (
                            b"gpgsig-sha256 -----BEGIN PGP SIGNATURE-----",
                        ),
                    },
                    "alternate signature headers are prohibited",
                ),
                (
                    "duplicate signature",
                    {
                        "extra_headers": (
                            b"gpgsig -----BEGIN PGP SIGNATURE-----",
                        ),
                    },
                    "duplicate signatures",
                ),
                (
                    "armor comment",
                    {
                        "signature_armor": fixture_signature_armor().replace(
                            b"-----BEGIN PGP SIGNATURE-----\n\n",
                            b"-----BEGIN PGP SIGNATURE-----\nComment: hidden\n\n",
                        )
                    },
                    "armor is not canonical",
                ),
                (
                    "text notation subpacket",
                    {
                        "signature_armor": fixture_signature_armor(
                            extra_hashed_subpackets=b"\x09\x14abcdefgh"
                        )
                    },
                    "hashed subpackets are outside policy",
                ),
                (
                    "signature time channel",
                    {
                        "signature_armor": fixture_signature_armor(
                            timestamp=FIXTURE_TIMESTAMP + 1
                        )
                    },
                    "signature time differs",
                ),
                (
                    "noncanonical subpacket length",
                    {
                        "signature_armor": fixture_signature_armor(
                            noncanonical_creation_length=True
                        )
                    },
                    "subpacket length is not canonical",
                ),
                (
                    "alternate hash",
                    {
                        "signature_armor": fixture_signature_armor(
                            hash_algorithm=8
                        )
                    },
                    "signature packet is outside policy",
                ),
                (
                    "randomized public key algorithm",
                    {
                        "signature_armor": fixture_signature_armor(
                            public_key_algorithm=19
                        )
                    },
                    "signature packet is outside policy",
                ),
                (
                    "unbound issuer",
                    {
                        "signature_armor": fixture_signature_armor(
                            unhashed_subpackets=b"\x09\x1012345678"
                        )
                    },
                    "unhashed subpackets are outside policy",
                ),
            )
            for label, arguments, expected in cases:
                with self.subTest(label=label):
                    commit_oid = fixture_raw_commit(
                        root,
                        tree_oid=tree_oid,
                        parents=(base,),
                        message="Signature profile probe",
                        **arguments,
                    )
                    with self.assertRaisesRegex(ValueError, expected):
                        parse_fixture_commit(root, commit_oid)
            for label, separator in (
                ("VT", bytes((0x0B,))),
                ("FF", bytes((0x0C,))),
                ("FS", bytes((0x1C,))),
                ("GS", bytes((0x1D,))),
                ("RS", bytes((0x1E,))),
            ):
                with self.subTest(label=label):
                    attacked_armor = fixture_signature_armor().replace(
                        b"\n",
                        separator,
                        1,
                    )
                    commit_oid = fixture_raw_commit(
                        root,
                        tree_oid=tree_oid,
                        parents=(base,),
                        message="Armor separator probe",
                        signature_armor=attacked_armor,
                    )
                    with self.assertRaisesRegex(
                        ValueError,
                        "armor contains prohibited control bytes",
                    ):
                        parse_fixture_commit(root, commit_oid)

    def test_history_v2_signature_status_binds_exact_role_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            base = fixture_commit_all(root, "post migration base")
            tree_oid = run_fixture_git(root, "rev-parse", "HEAD^{tree}").stdout.strip()
            commit_oid = fixture_raw_commit(
                root,
                tree_oid=tree_oid,
                parents=(base,),
                message="Signature status probe",
            )
            signature = parse_fixture_commit(root, commit_oid).signature
            valid_status = (
                "[GNUPG:] NEWSIG\n"
                f"[GNUPG:] VALIDSIG {FIXTURE_SIGNER_FINGERPRINT} "
                f"2026-07-15 {FIXTURE_TIMESTAMP} 0 4 0 22 10 00 "
                f"{FIXTURE_SIGNER_FINGERPRINT}\n"
            ).encode("ascii")
            MODULE.validate_history_v2_gpg_status(
                valid_status,
                signature=signature,
                allowed_fingerprints=frozenset({FIXTURE_SIGNER_FINGERPRINT}),
            )
            with tempfile.TemporaryDirectory() as verifier_raw:
                verifier = MODULE.HistoryV2SignatureVerifier(
                    b"fixture public key",
                    relative=Path("retrospective-history-v2-publisher.asc"),
                )
                verifier.home = Path(verifier_raw)
                verifier.environment = {"LC_ALL": "C"}
                verifier.allowed_fingerprints = frozenset(
                    {FIXTURE_SIGNER_FINGERPRINT}
                )
                with mock.patch.object(
                    MODULE,
                    "bounded_process_output",
                    return_value=valid_status,
                ) as verify_process:
                    verifier.verify(signature)
                command = verify_process.call_args.args[0]
                self.assertEqual(command[-3], "--verify")
                self.assertEqual(command[-1], "-")
                self.assertEqual(
                    verify_process.call_args.kwargs["input_data"],
                    signature.signed_payload,
                )
                self.assertFalse(
                    (verifier.home / "commit-signature.asc").exists()
                )
            for label, status, allowed in (
                (
                    "wrong role",
                    valid_status,
                    frozenset({"F" * 40}),
                ),
                (
                    "bad signature",
                    b"[GNUPG:] BADSIG 0123456789ABCDEF Synthetic\n",
                    frozenset({FIXTURE_SIGNER_FINGERPRINT}),
                ),
                (
                    "ambiguous signature",
                    valid_status + valid_status,
                    frozenset({FIXTURE_SIGNER_FINGERPRINT}),
                ),
            ):
                with self.subTest(label=label):
                    with self.assertRaises(ValueError):
                        MODULE.validate_history_v2_gpg_status(
                            status,
                            signature=signature,
                            allowed_fingerprints=allowed,
                        )
            self.assertEqual(
                MODULE.HISTORY_V2_SIGNATURE_KEY_PATHS,
                {
                    "bootstrap-v2": Path(
                        "retrospective-history-v2-admin-public.asc"
                    ),
                    "history-v2": Path(
                        "retrospective-history-v2-publisher.asc"
                    ),
                },
            )

    def test_history_v2_bounded_output_kills_descendants_and_reaps_pipes(self) -> None:
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
            with self.assertRaisesRegex(
                MODULE.BoundedProcessError, "output limit"
            ):
                MODULE.bounded_process_output(
                    [sys.executable, "-c", program],
                    max_output_bytes=1024,
                    timeout_seconds=5,
                )
            child_pid = int(child_pid_path.read_text(encoding="ascii"))
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.02)
            else:
                self.fail("bounded process descendant remained alive")

    def test_history_v2_duplicate_blob_paths_hit_path_budget_and_cache_reads(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            created: list[Path] = []
            for year in range(2000, 2040):
                report = root / "reports" / "daily" / str(year) / "07" / "15.md"
                report.parent.mkdir(parents=True, exist_ok=True)
                report.write_text("# Daily retrospective\n", encoding="utf-8")
                created.append(report)
            run_fixture_git(root, "add", "--all")
            fixture_commit_all(root, "append reports")
            head = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            blob_oids = {
                run_fixture_git(
                    root,
                    "rev-parse",
                    f"{head}:{path.relative_to(root).as_posix()}",
                ).stdout.strip()
                for path in created
            }
            self.assertEqual(len(blob_oids), 1)
            with mock.patch.object(MODULE, "HISTORY_V2_MAX_PATH_REFERENCES", 64):
                with self.assertRaisesRegex(ValueError, "path-reference budget"):
                    validate_synthetic_history_v2_merge_range(
                        root,
                        base_rev=base,
                        head_rev=head,
                    )

            payload = b"cached retained payload\n"
            object_id = run_fixture_git_bytes(
                root, "hash-object", "-w", "--stdin", input_data=payload
            ).decode("ascii").strip()
            budget = MODULE.HistoryV2WorkBudget()
            for relative in (Path("first.md"), Path("second.md")):
                entry = MODULE.HistoryV2TreeEntry(
                    "100644", "blob", object_id, len(payload), relative
                )
                self.assertEqual(
                    MODULE.history_v2_read_blob(root, entry, work_budget=budget),
                    payload,
                )
            self.assertEqual(budget.blob_read_operations, 1)
            self.assertEqual(budget.blob_read_bytes, len(payload))

    def test_history_v2_dense_parent_graph_fails_before_diff_work(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            write_bootstrap_v2_candidate(root)
            fixture_commit_all(root, "post migration base")
            base = run_fixture_git(root, "rev-parse", "HEAD").stdout.strip()
            tree_oid = run_fixture_git(root, "rev-parse", "HEAD^{tree}").stdout.strip()
            parents = [base]
            for index in range(20):
                parents.append(
                    fixture_raw_commit(
                        root,
                        tree_oid=tree_oid,
                        parents=tuple(parents),
                        message=f"dense graph node {index}",
                    )
                )
            head = parents[-1]
            fixture_set_head(root, head)

            with mock.patch.object(
                MODULE, "history_v2_diff_output", wraps=MODULE.history_v2_diff_output
            ) as diff_output:
                with self.assertRaisesRegex(ValueError, "parent-edge budget"):
                    validate_synthetic_history_v2_merge_range(
                        root,
                        base_rev=base,
                        head_rev=head,
                    )
            diff_output.assert_not_called()

    def test_bootstrap_v2_inventory_is_exact_and_accepts_synthetic_tree(self) -> None:
        self.assertEqual(len(EXPECTED_BOOTSTRAP_V2_FILES), 29)
        self.assertEqual(
            MODULE.BOOTSTRAP_V2_REQUIRED_FILES, EXPECTED_BOOTSTRAP_V2_FILES
        )
        self.assertEqual(MODULE.BOOTSTRAP_V2_ALLOWED_FILES, EXPECTED_BOOTSTRAP_V2_FILES)
        self.assertEqual(
            MODULE.BOOTSTRAP_V2_PRIVACY_RISK_PATTERNS,
            (
                *MODULE.INFRASTRUCTURE_RISK_PATTERNS,
                *MODULE.BOOTSTRAP_V2_ADDITIONAL_PRIVACY_RISK_PATTERNS,
            ),
        )
        self.assertEqual(len(MODULE.BOOTSTRAP_V2_ADDITIONAL_PRIVACY_RISK_PATTERNS), 4)
        self.assertLessEqual(
            set(MODULE.BOOTSTRAP_V2_TRUSTED_RISK_LINES_SHA256),
            EXPECTED_BOOTSTRAP_V2_FILES,
        )
        self.assertLessEqual(
            set(MODULE.BOOTSTRAP_V2_TRUSTED_DECODED_RISK_VALUES_SHA256),
            MODULE.BOOTSTRAP_V2_SCHEMA_FILES,
        )
        python_files = {
            relative
            for relative in EXPECTED_BOOTSTRAP_V2_FILES
            if relative.suffix == ".py"
        }
        self.assertLessEqual(
            set(MODULE.BOOTSTRAP_V2_TRUSTED_PYTHON_RISK_VALUES_SHA256),
            python_files,
        )
        self.assertEqual(
            set(MODULE.BOOTSTRAP_V2_TRUSTED_OPENPGP_RISK_VALUES_SHA256),
            MODULE.BOOTSTRAP_V2_PUBLIC_KEY_FILES,
        )
        self.assertTrue(
            all(
                re.fullmatch(r"[0-9a-f]{64}", digest)
                for digest in (
                    *MODULE.BOOTSTRAP_V2_TRUSTED_RISK_LINES_SHA256.values(),
                    *MODULE.BOOTSTRAP_V2_TRUSTED_DECODED_RISK_VALUES_SHA256.values(),
                    *MODULE.BOOTSTRAP_V2_TRUSTED_PYTHON_RISK_VALUES_SHA256.values(),
                    *MODULE.BOOTSTRAP_V2_TRUSTED_OPENPGP_RISK_VALUES_SHA256.values(),
                )
            )
        )
        self.assertEqual(
            MODULE.BOOTSTRAP_V2_TEMPORARY_PATHS,
            {
                Path(
                    ".github/bootstrap/session-retrospective-v2-permanent-ci.yml"
                ),
                Path(".github/workflows/session-retrospective-v2-bootstrap.yml"),
                Path("tests/test_session_retrospective_v2_bootstrap.py"),
            },
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_bootstrap_v2_candidate(root)

            self.assertEqual(validate_synthetic_bootstrap_v2_candidate(root), [])

    def test_bootstrap_v2_ci_migration_is_exact_for_the_actual_base_blob(self) -> None:
        self.assertEqual(
            MODULE.git_blob_bytes_object_id(
                LEGACY_CI.encode("utf-8"), expected_length=40
            ),
            MODULE.BOOTSTRAP_V2_LEGACY_CI_BLOB_OID,
        )
        self.assertEqual(
            MODULE.git_blob_bytes_object_id(
                PERMANENT_CI_TEMPLATE.read_bytes(), expected_length=40
            ),
            MODULE.BOOTSTRAP_V2_PERMANENT_CI_BLOB_OID,
        )
        cases = (
            ("base CI", MODULE.BOOTSTRAP_V2_CI_PATH, "base", "outside the authorized"),
            (
                "base template",
                MODULE.BOOTSTRAP_V2_PERMANENT_CI_TEMPLATE_PATH,
                "base",
                "template does not match",
            ),
            (
                "candidate CI",
                MODULE.BOOTSTRAP_V2_CI_PATH,
                "candidate",
                "candidate CI must equal",
            ),
        )
        for label, relative, side, expected in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    workspace = Path(raw)
                    base = workspace / "base"
                    candidate = workspace / "candidate"
                    write_bootstrap_v2_base(base)
                    write_bootstrap_v2_candidate(candidate)
                    target = (base if side == "base" else candidate) / relative
                    target.write_bytes(target.read_bytes() + b"\n")
                    run_fixture_git(base if side == "base" else candidate, "add", "--all")

                    issues = "\n".join(
                        validate_synthetic_bootstrap_v2_candidate(
                            candidate,
                            base_root=base,
                            synchronize_allowed_index=False,
                        )
                    )

                self.assertIn(expected, issues)

    def test_bootstrap_v2_python_ast_fingerprints_match_validator_sources(self) -> None:
        repository_root = SCRIPT.parents[1]
        relatives = (
            Path("scripts/validate_retained_history.py"),
            Path("tests/test_validate_retained_history.py"),
        )
        self.assertEqual(
            set(relatives),
            set(MODULE.BOOTSTRAP_V2_TRUSTED_PYTHON_RISK_VALUES_SHA256),
        )
        for relative in relatives:
            with self.subTest(relative=relative.as_posix()):
                source = (repository_root / relative).read_text(encoding="utf-8")
                risky_values = MODULE.bootstrap_v2_python_privacy_risk_values(source)
                observed = MODULE.bootstrap_v2_privacy_risk_lines_fingerprint(
                    risky_values
                )

                self.assertTrue(risky_values)
                self.assertEqual(
                    observed,
                    MODULE.BOOTSTRAP_V2_TRUSTED_PYTHON_RISK_VALUES_SHA256[relative],
                )
                self.assertFalse(
                    MODULE.contains_bootstrap_v2_python_privacy_risk(
                        source,
                        relative=relative,
                    )
                )
                mutated = source + '\nvalue = "ghp_" + "ABCDEFGHIJKLMNOP"\n'
                self.assertTrue(
                    MODULE.contains_bootstrap_v2_python_privacy_risk(
                        mutated,
                        relative=relative,
                    )
                )

    def test_bootstrap_v2_self_fingerprints_have_constrained_ast_shapes(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        trusted_table_names = frozenset(
            {
                "INFRASTRUCTURE_TRUSTED_RISK_LINES_SHA256",
                "BOOTSTRAP_V2_PUBLIC_KEY_SHA256",
                "BOOTSTRAP_V2_TRUSTED_RISK_LINES_SHA256",
                "BOOTSTRAP_V2_TRUSTED_DECODED_RISK_VALUES_SHA256",
                "BOOTSTRAP_V2_TRUSTED_PYTHON_RISK_VALUES_SHA256",
                "BOOTSTRAP_V2_TRUSTED_OPENPGP_RISK_VALUES_SHA256",
            }
        )
        mutator_names = frozenset(
            {
                "__delitem__",
                "__ior__",
                "__setitem__",
                "clear",
                "pop",
                "popitem",
                "setdefault",
                "update",
            }
        )

        def trust_table_shape_issues(candidate_source: str) -> list[str]:
            candidate_tree = ast.parse(candidate_source, mode="exec")
            candidate_nodes = tuple(ast.walk(candidate_tree))
            issues: list[str] = []
            expected_target_ids: set[int] = set()
            alias_roots: dict[str, set[str]] = {
                name: {name} for name in trusted_table_names
            }
            mutator_alias_roots: dict[str, set[str]] = {}

            def target_bindings(
                target: ast.AST,
                value: ast.AST,
            ) -> tuple[tuple[str, ast.AST], ...]:
                if isinstance(target, ast.Name):
                    return ((target.id, value),)
                if isinstance(target, (ast.Tuple, ast.List)) and isinstance(
                    value, (ast.Tuple, ast.List)
                ):
                    if len(target.elts) != len(value.elts):
                        return ()
                    return tuple(
                        binding
                        for child_target, child_value in zip(
                            target.elts, value.elts, strict=True
                        )
                        for binding in target_bindings(child_target, child_value)
                    )
                return ()

            binding_pairs: list[tuple[str, ast.AST]] = []
            for node in candidate_nodes:
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        binding_pairs.extend(target_bindings(target, node.value))
                elif isinstance(node, ast.AnnAssign) and node.value is not None:
                    binding_pairs.extend(target_bindings(node.target, node.value))
                elif isinstance(node, ast.NamedExpr):
                    binding_pairs.extend(target_bindings(node.target, node.value))

            binding_values_by_name: dict[str, list[ast.AST]] = {}
            for name, value in binding_pairs:
                binding_values_by_name.setdefault(name, []).append(value)

            selection_cache: dict[
                tuple[int, tuple[type[object], object]], tuple[ast.AST, ...]
            ] = {}
            selection_stack: set[tuple[int, tuple[type[object], object]]] = set()
            selection_steps = 0
            selection_limit = max(len(candidate_nodes) * 8, 1)
            selection_exhausted = False

            def unique_nodes(values: list[ast.AST]) -> tuple[ast.AST, ...]:
                return tuple({id(value): value for value in values}.values())

            def literal_selector(node: ast.AST) -> tuple[bool, object]:
                if isinstance(node, ast.Constant):
                    return True, node.value
                if (
                    isinstance(node, ast.UnaryOp)
                    and isinstance(node.op, (ast.UAdd, ast.USub))
                    and isinstance(node.operand, ast.Constant)
                    and type(node.operand.value) is int
                ):
                    value = node.operand.value
                    return True, value if isinstance(node.op, ast.UAdd) else -value
                return False, None

            def select_from_container(
                container: ast.AST,
                selector: object,
                selector_key: tuple[type[object], object],
            ) -> tuple[ast.AST, ...]:
                nonlocal selection_exhausted, selection_steps
                cache_key = (id(container), selector_key)
                if cache_key in selection_cache:
                    return selection_cache[cache_key]
                if cache_key in selection_stack or selection_exhausted:
                    return ()
                selection_steps += 1
                if selection_steps > selection_limit:
                    selection_exhausted = True
                    issues.append(
                        "trusted table container selection exceeded its bound"
                    )
                    return ()
                selection_stack.add(cache_key)
                selected: list[ast.AST] = []
                try:
                    if (
                        isinstance(container, (ast.Tuple, ast.List))
                        and type(selector) is int
                    ):
                        index = selector
                        if -len(container.elts) <= index < len(container.elts):
                            selected.append(container.elts[index])
                    elif isinstance(container, ast.Dict):
                        for key, value in zip(
                            container.keys, container.values, strict=True
                        ):
                            key_supported, key_value = literal_selector(key)
                            if (
                                key_supported
                                and key_value == selector
                                and type(key_value) is type(selector)
                            ):
                                selected.append(value)
                    elif isinstance(container, ast.Name):
                        for value in binding_values_by_name.get(container.id, ()):
                            selected.extend(
                                select_from_container(value, selector, selector_key)
                            )
                    elif isinstance(container, ast.NamedExpr):
                        selected.extend(
                            select_from_container(
                                container.value, selector, selector_key
                            )
                        )
                    elif isinstance(container, ast.IfExp):
                        for value in (container.body, container.orelse):
                            selected.extend(
                                select_from_container(value, selector, selector_key)
                            )
                    elif isinstance(container, ast.BoolOp):
                        for value in container.values:
                            selected.extend(
                                select_from_container(value, selector, selector_key)
                            )
                    elif isinstance(container, ast.Subscript):
                        for value in selected_values(container):
                            selected.extend(
                                select_from_container(value, selector, selector_key)
                            )
                finally:
                    selection_stack.remove(cache_key)
                result = unique_nodes(selected)
                selection_cache[cache_key] = result
                return result

            def selected_values(node: ast.Subscript) -> tuple[ast.AST, ...]:
                selector_supported, selector = literal_selector(node.slice)
                if not selector_supported:
                    return ()
                selector_key: tuple[type[object], object] = (
                    type(selector),
                    selector,
                )
                try:
                    hash(selector_key)
                except TypeError:
                    return ()
                return select_from_container(node.value, selector, selector_key)

            def expression_alias_source_names(node: ast.AST) -> set[str]:
                if isinstance(node, ast.Name):
                    return {node.id}
                if isinstance(node, ast.NamedExpr):
                    return expression_alias_source_names(node.value)
                if isinstance(node, ast.IfExp):
                    return expression_alias_source_names(
                        node.body
                    ) | expression_alias_source_names(node.orelse)
                if isinstance(node, ast.BoolOp):
                    return set().union(
                        *(expression_alias_source_names(value) for value in node.values)
                    )
                if isinstance(node, ast.Subscript):
                    return set().union(
                        *(
                            expression_alias_source_names(value)
                            for value in selected_values(node)
                        )
                    )
                return set()

            def expression_mutator_source_names(
                node: ast.AST,
            ) -> tuple[set[str], set[str]]:
                if isinstance(node, ast.Name):
                    return set(), {node.id}
                if isinstance(node, ast.Attribute) and node.attr in mutator_names:
                    return expression_alias_source_names(node.value), set()
                if isinstance(node, ast.NamedExpr):
                    return expression_mutator_source_names(node.value)
                if isinstance(node, ast.IfExp):
                    body_aliases, body_mutators = expression_mutator_source_names(
                        node.body
                    )
                    else_aliases, else_mutators = expression_mutator_source_names(
                        node.orelse
                    )
                    return (
                        body_aliases | else_aliases,
                        body_mutators | else_mutators,
                    )
                if isinstance(node, ast.BoolOp):
                    alias_sources: set[str] = set()
                    mutator_sources: set[str] = set()
                    for value in node.values:
                        value_aliases, value_mutators = expression_mutator_source_names(
                            value
                        )
                        alias_sources.update(value_aliases)
                        mutator_sources.update(value_mutators)
                    return alias_sources, mutator_sources
                if isinstance(node, ast.Subscript):
                    alias_sources = set()
                    mutator_sources = set()
                    for value in selected_values(node):
                        value_aliases, value_mutators = expression_mutator_source_names(
                            value
                        )
                        alias_sources.update(value_aliases)
                        mutator_sources.update(value_mutators)
                    return alias_sources, mutator_sources
                return set(), set()

            alias_dependents: dict[str, set[str]] = {}
            mutator_dependents: dict[str, set[str]] = {}
            alias_to_mutator_dependents: dict[str, set[str]] = {}
            dependency_edges = 0
            dependency_edge_limit = max(len(candidate_nodes) * 8, 1)

            def add_dependency(
                graph: dict[str, set[str]],
                source_name: str,
                target_name: str,
            ) -> None:
                nonlocal dependency_edges
                targets = graph.setdefault(source_name, set())
                if target_name in targets:
                    return
                targets.add(target_name)
                dependency_edges += 1
                if dependency_edges > dependency_edge_limit:
                    issues.append("trusted table alias graph exceeded its bound")

            for name, value in binding_pairs:
                for source_name in expression_alias_source_names(value):
                    add_dependency(alias_dependents, source_name, name)
                alias_sources, mutator_sources = expression_mutator_source_names(value)
                for source_name in alias_sources:
                    add_dependency(alias_to_mutator_dependents, source_name, name)
                for source_name in mutator_sources:
                    add_dependency(mutator_dependents, source_name, name)

            pending_facts = [
                (False, name, name) for name in sorted(trusted_table_names)
            ]
            propagation_steps = 0
            propagation_limit = max(len(candidate_nodes) * 32, 1)
            while pending_facts:
                is_mutator, name, root = pending_facts.pop()
                if is_mutator:
                    dependents = ((mutator_dependents.get(name, ()), True),)
                else:
                    dependents = (
                        (alias_dependents.get(name, ()), False),
                        (alias_to_mutator_dependents.get(name, ()), True),
                    )
                for target_names, target_is_mutator in dependents:
                    for target_name in target_names:
                        propagation_steps += 1
                        if propagation_steps > propagation_limit:
                            issues.append(
                                "trusted table alias propagation exceeded its bound"
                            )
                            pending_facts.clear()
                            break
                        target_roots = (
                            mutator_alias_roots if target_is_mutator else alias_roots
                        ).setdefault(target_name, set())
                        if root not in target_roots:
                            target_roots.add(root)
                            pending_facts.append((target_is_mutator, target_name, root))
                    else:
                        continue
                    break

            def expression_alias_roots(node: ast.AST) -> set[str]:
                return set().union(
                    *(
                        alias_roots.get(name, set())
                        for name in expression_alias_source_names(node)
                    )
                )

            def expression_mutator_roots(node: ast.AST) -> set[str]:
                alias_sources, mutator_sources = expression_mutator_source_names(node)
                return set().union(
                    *(alias_roots.get(name, set()) for name in alias_sources),
                    *(mutator_alias_roots.get(name, set()) for name in mutator_sources),
                )

            def mutated_table_roots(node: ast.AST) -> set[str]:
                roots = expression_alias_roots(node)
                while not roots and isinstance(node, ast.Subscript):
                    node = node.value
                    roots = expression_alias_roots(node)
                return roots

            for table_name in trusted_table_names:
                bindings = [
                    (statement, target)
                    for statement in candidate_tree.body
                    if isinstance(statement, ast.Assign)
                    for target in statement.targets
                    if isinstance(target, ast.Name) and target.id == table_name
                ]
                if len(bindings) != 1:
                    issues.append(
                        f"{table_name}: expected exactly one top-level binding"
                    )
                for statement, _ in bindings:
                    if len(statement.targets) != 1 or not isinstance(
                        statement.value, ast.Dict
                    ):
                        issues.append(f"{table_name}: binding must be one dictionary")
                        continue
                    if any(key is None for key in statement.value.keys):
                        issues.append(
                            f"{table_name}: dictionary unpacking is forbidden"
                        )
                if len(bindings) == 1:
                    expected_target_ids.add(id(bindings[0][1]))

            for node in candidate_nodes:
                if (
                    isinstance(node, ast.Name)
                    and node.id in trusted_table_names
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                    and id(node) not in expected_target_ids
                ):
                    issues.append(f"{node.id}: rebinding is forbidden")
                if isinstance(node, (ast.Global, ast.Nonlocal)):
                    for name in trusted_table_names.intersection(node.names):
                        issues.append(f"{name}: scope rebinding is forbidden")
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    if node.name in trusted_table_names:
                        issues.append(f"{node.name}: rebinding is forbidden")
                if isinstance(node, ast.alias):
                    bound_name = node.asname or node.name.split(".", 1)[0]
                    if bound_name in trusted_table_names:
                        issues.append(f"{bound_name}: rebinding is forbidden")
                if isinstance(node, ast.arg) and node.arg in trusted_table_names:
                    issues.append(f"{node.arg}: rebinding is forbidden")
                if isinstance(node, (ast.MatchAs, ast.MatchStar)):
                    if node.name in trusted_table_names:
                        issues.append(f"{node.name}: rebinding is forbidden")
                if (
                    isinstance(node, ast.MatchMapping)
                    and node.rest in trusted_table_names
                ):
                    issues.append(f"{node.rest}: rebinding is forbidden")
                if (
                    isinstance(node, ast.ExceptHandler)
                    and node.name in trusted_table_names
                ):
                    issues.append(f"{node.name}: rebinding is forbidden")
                if isinstance(node, ast.Subscript) and isinstance(
                    node.ctx, (ast.Store, ast.Del)
                ):
                    for root in mutated_table_roots(node.value):
                        issues.append(f"{root}: subscript writes are forbidden")
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in mutator_names
                ):
                    for root in expression_alias_roots(node.func.value):
                        issues.append(f"{root}: mutator calls are forbidden")
                if isinstance(node, ast.Call):
                    for root in expression_mutator_roots(node.func):
                        issues.append(f"{root}: mutator calls are forbidden")
            return issues

        self.assertEqual(trust_table_shape_issues(source), [])
        tree = ast.parse(source, mode="exec")
        tables = {
            target.id: statement.value
            for statement in tree.body
            if isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance((target := statement.targets[0]), ast.Name)
            and target.id in trusted_table_names
            and isinstance(statement.value, ast.Dict)
        }
        self.assertEqual(set(tables), trusted_table_names)

        def path_key(node: ast.AST) -> str | None:
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "Path"
                and len(node.args) == 1
                and not node.keywords
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                return node.args[0].value
            return None

        entries: dict[tuple[str, str], ast.AST] = {}
        for table_name, table in tables.items():
            for key, child in zip(table.keys, table.values, strict=True):
                if (relative := path_key(key)) is not None:
                    entries[table_name, relative] = child

        binary_entries = {
            (
                "INFRASTRUCTURE_TRUSTED_RISK_LINES_SHA256",
                ".github/bootstrap/session-retrospective-v2-permanent-ci.yml",
            ),
            (
                "INFRASTRUCTURE_TRUSTED_RISK_LINES_SHA256",
                ".github/workflows/session-retrospective-v2-bootstrap.yml",
            ),
            (
                "INFRASTRUCTURE_TRUSTED_RISK_LINES_SHA256",
                "scripts/trusted_history_ci.py",
            ),
            (
                "INFRASTRUCTURE_TRUSTED_RISK_LINES_SHA256",
                "scripts/validate_retained_history.py",
            ),
            (
                "INFRASTRUCTURE_TRUSTED_RISK_LINES_SHA256",
                "tests/test_session_retrospective_v2_bootstrap.py",
            ),
            (
                "INFRASTRUCTURE_TRUSTED_RISK_LINES_SHA256",
                "tests/test_validate_retained_history.py",
            ),
            (
                "BOOTSTRAP_V2_TRUSTED_RISK_LINES_SHA256",
                "tests/test_validate_retained_history.py",
            ),
        }
        trusted_python_entries = {
            (
                "BOOTSTRAP_V2_TRUSTED_PYTHON_RISK_VALUES_SHA256",
                "scripts/validate_retained_history.py",
            ),
            (
                "BOOTSTRAP_V2_TRUSTED_PYTHON_RISK_VALUES_SHA256",
                "tests/test_validate_retained_history.py",
            ),
        }

        def assert_digest_tuple(node: ast.AST) -> None:
            self.assertIsInstance(node, ast.Tuple)
            assert isinstance(node, ast.Tuple)
            self.assertEqual(len(node.elts), 32)
            self.assertTrue(
                all(
                    isinstance(element, ast.Constant)
                    and type(element.value) is int
                    and 0 <= element.value <= 255
                    for element in node.elts
                )
            )

        binary_value_ids: set[int] = set()
        for entry in binary_entries:
            with self.subTest(table=entry[0], relative=entry[1]):
                value = entries[entry]
                self.assertIsInstance(value, ast.Call)
                assert isinstance(value, ast.Call)
                self.assertFalse(value.args)
                self.assertFalse(value.keywords)
                self.assertIsInstance(value.func, ast.Attribute)
                assert isinstance(value.func, ast.Attribute)
                self.assertEqual(value.func.attr, "hex")
                byte_call = value.func.value
                self.assertIsInstance(byte_call, ast.Call)
                assert isinstance(byte_call, ast.Call)
                self.assertIsInstance(byte_call.func, ast.Name)
                assert isinstance(byte_call.func, ast.Name)
                self.assertEqual(byte_call.func.id, "bytes")
                self.assertEqual(len(byte_call.args), 1)
                self.assertFalse(byte_call.keywords)
                assert_digest_tuple(byte_call.args[0])
                binary_value_ids.add(id(value))

        for entry in trusted_python_entries:
            with self.subTest(table=entry[0], relative=entry[1]):
                value = entries[entry]
                self.assertIsInstance(value, ast.Call)
                assert isinstance(value, ast.Call)
                self.assertIsInstance(value.func, ast.Name)
                assert isinstance(value.func, ast.Name)
                self.assertEqual(value.func.id, "_trusted_sha256_values_hex")
                self.assertEqual(len(value.args), 1)
                self.assertFalse(value.keywords)
                assert_digest_tuple(value.args[0])

        helper_definitions = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_trusted_sha256_values_hex"
        ]
        self.assertEqual(len(helper_definitions), 1)
        helper_definition = helper_definitions[0]
        self.assertEqual(len(helper_definition.args.args), 1)
        self.assertEqual(helper_definition.args.args[0].arg, "values")
        self.assertFalse(helper_definition.args.defaults)
        self.assertIsNone(helper_definition.args.vararg)
        self.assertIsNone(helper_definition.args.kwarg)
        helper_returns = [
            node
            for node in ast.walk(helper_definition)
            if isinstance(node, ast.Return)
        ]
        self.assertEqual(len(helper_returns), 1)
        helper_hex_call = helper_returns[0].value
        self.assertIsInstance(helper_hex_call, ast.Call)
        assert isinstance(helper_hex_call, ast.Call)
        self.assertIsInstance(helper_hex_call.func, ast.Attribute)
        assert isinstance(helper_hex_call.func, ast.Attribute)
        self.assertEqual(helper_hex_call.func.attr, "hex")
        helper_byte_call = helper_hex_call.func.value
        self.assertIsInstance(helper_byte_call, ast.Call)
        assert isinstance(helper_byte_call, ast.Call)
        self.assertIsInstance(helper_byte_call.func, ast.Name)
        assert isinstance(helper_byte_call.func, ast.Name)
        self.assertEqual(helper_byte_call.func.id, "bytes")
        self.assertEqual(len(helper_byte_call.args), 1)
        self.assertIsInstance(helper_byte_call.args[0], ast.Name)
        assert isinstance(helper_byte_call.args[0], ast.Name)
        self.assertEqual(helper_byte_call.args[0].id, "values")
        self.assertFalse(helper_byte_call.keywords)
        self.assertFalse(helper_hex_call.args)
        self.assertFalse(helper_hex_call.keywords)
        binary_value_ids.add(id(helper_hex_call))

        observed_hex_call_ids = {
            id(node)
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "hex"
        }
        self.assertEqual(observed_hex_call_ids, binary_value_ids)
        self.assertEqual(MODULE._trusted_sha256_values_hex((0,) * 32), "00" * 32)
        for invalid in (
            (0,) * 31,
            (0,) * 33,
            (-1,) + ((0,) * 31),
            (256,) + ((0,) * 31),
            (True,) + ((0,) * 31),
        ):
            with self.subTest(invalid_digest=invalid[:1]):
                with self.assertRaisesRegex(RuntimeError, "SHA-256 value is invalid"):
                    MODULE._trusted_sha256_values_hex(invalid)

        for relative in ("scripts/validate_retained_history.py",):
            value = entries["BOOTSTRAP_V2_TRUSTED_RISK_LINES_SHA256", relative]
            self.assertIsInstance(value, ast.Subscript)
            assert isinstance(value, ast.Subscript)
            self.assertIsInstance(value.value, ast.Name)
            assert isinstance(value.value, ast.Name)
            self.assertEqual(
                value.value.id,
                "INFRASTRUCTURE_TRUSTED_RISK_LINES_SHA256",
            )
            self.assertEqual(path_key(value.slice), relative)

        self.assertFalse(
            any(
                (
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == "_trusted_fingerprint"
                )
                or (isinstance(node, ast.Name) and node.id == "_trusted_fingerprint")
                or (
                    isinstance(node, ast.Attribute)
                    and node.attr == "_trusted_fingerprint"
                )
                for node in ast.walk(tree)
            )
        )

        mutation_table_name = "BOOTSTRAP_V2_TRUSTED_PYTHON_RISK_VALUES_SHA256"
        binding_marker = f"{mutation_table_name} = {{\n"
        self.assertIn(binding_marker, source)
        mutations = (
            (
                "dictionary unpacking",
                source.replace(
                    binding_marker,
                    binding_marker + "    **{},\n",
                    1,
                ),
                "dictionary unpacking is forbidden",
            ),
            (
                "duplicate binding",
                source + f"\n{mutation_table_name} = {{}}\n",
                "expected exactly one top-level binding",
            ),
            (
                "subscript write",
                source + f'\n{mutation_table_name}[Path("extra.py")] = "0" * 64\n',
                "subscript writes are forbidden",
            ),
            (
                "update call",
                source + f"\n{mutation_table_name}.update({{}})\n",
                "mutator calls are forbidden",
            ),
            (
                "other mutator call",
                source + f"\n{mutation_table_name}.clear()\n",
                "mutator calls are forbidden",
            ),
            (
                "aliased subscript write",
                source + f"\ntrusted_alias = {mutation_table_name}\n"
                'trusted_alias[Path("extra.py")] = "0" * 64\n',
                "subscript writes are forbidden",
            ),
            (
                "aliased update call",
                source + f"\ntrusted_alias = {mutation_table_name}\n"
                "trusted_alias.update({})\n",
                "mutator calls are forbidden",
            ),
            (
                "conditional derived alias",
                source
                + f"\ntrusted_alias = {mutation_table_name} if enabled else {{}}\n"
                'trusted_alias[Path("extra.py")] = "0" * 64\n',
                "subscript writes are forbidden",
            ),
            (
                "boolean derived alias",
                source + f"\ntrusted_alias = {mutation_table_name} or {{}}\n"
                "trusted_alias.clear()\n",
                "mutator calls are forbidden",
            ),
            (
                "destructured alias",
                source + f"\ntrusted_alias, = ({mutation_table_name},)\n"
                'trusted_alias[Path("extra.py")] = "0" * 64\n',
                "subscript writes are forbidden",
            ),
            (
                "indexed wrapper alias",
                source + f"\ntrusted_alias = ({mutation_table_name},)[0]\n"
                "trusted_alias.update({})\n",
                "mutator calls are forbidden",
            ),
            (
                "named list wrapper alias",
                source + f"\ntrusted_box = [{mutation_table_name}]\n"
                "trusted_box[0].update({})\n",
                "mutator calls are forbidden",
            ),
            (
                "named dictionary wrapper alias",
                source + f'\ntrusted_box = {{"table": {mutation_table_name}}}\n'
                'trusted_box["table"][Path("extra.py")] = "0" * 64\n',
                "subscript writes are forbidden",
            ),
            (
                "negative indexed wrapper update",
                source + f"\ntrusted_box = [{{}}, {mutation_table_name}]\n"
                "trusted_box[-1].clear()\n",
                "mutator calls are forbidden",
            ),
            (
                "negative indexed wrapper write",
                source + f"\ntrusted_box = [{mutation_table_name}]\n"
                'trusted_box[-1][Path("extra.py")] = "0" * 64\n',
                "subscript writes are forbidden",
            ),
            (
                "bound mutator alias",
                source + f"\ntrusted_mutator = {mutation_table_name}.update\n"
                "trusted_mutator({})\n",
                "mutator calls are forbidden",
            ),
            (
                "transitive bound mutator alias",
                source + f"\ntrusted_mutator = {mutation_table_name}.clear\n"
                "mutator_alias = trusted_mutator\nmutator_alias()\n",
                "mutator calls are forbidden",
            ),
            (
                "bound mutator in named wrapper",
                source + f"\ntrusted_box = [{mutation_table_name}.update]\n"
                "trusted_box[0]({})\n",
                "mutator calls are forbidden",
            ),
        )
        for label, mutated_source, expected in mutations:
            with self.subTest(mutation=label):
                self.assertTrue(
                    any(
                        expected in issue
                        for issue in trust_table_shape_issues(mutated_source)
                    ),
                    expected,
                )

        new_object_transforms = (
            f"trusted_copy = {mutation_table_name}.copy()\n"
            'trusted_copy[Path("extra.py")] = "0" * 64\n',
            f"trusted_copy = dict({mutation_table_name})\ntrusted_copy.update({{}})\n",
            f"trusted_copy = {{**{mutation_table_name}}}\ntrusted_copy.clear()\n",
            f"trusted_copy = {mutation_table_name} | {{}}\ntrusted_copy.popitem()\n",
            f"trusted_box = [{mutation_table_name}.copy()]\n"
            "trusted_box[0].update({})\n",
        )
        for transform in new_object_transforms:
            with self.subTest(new_object_transform=transform.splitlines()[0]):
                self.assertEqual(
                    trust_table_shape_issues(source + "\n" + transform), []
                )

        alias_count = 2_000
        reverse_chain = (
            source
            + "\n"
            + "".join(
                f"trusted_alias_{index} = trusted_alias_{index + 1}\n"
                for index in range(alias_count)
            )
        )
        reverse_chain += (
            f"trusted_alias_{alias_count} = {mutation_table_name}\n"
            "trusted_alias_0.update({})\n"
        )
        started = time.perf_counter()
        reverse_chain_issues = trust_table_shape_issues(reverse_chain)
        elapsed = time.perf_counter() - started
        self.assertTrue(
            any(
                "mutator calls are forbidden" in issue for issue in reverse_chain_issues
            )
        )
        self.assertLess(elapsed, 5.0)

    def test_bootstrap_v2_rejects_missing_extra_and_temporary_artifacts(self) -> None:
        cases = (
            (
                "missing",
                Path("README.md"),
                "required bootstrap-v2 candidate artifact is missing",
            ),
            (
                "extra",
                Path("unexpected.txt"),
                "unexpected bootstrap-v2 candidate artifact",
            ),
            (
                "ignored extra",
                Path("build/ignored.txt"),
                "unexpected bootstrap-v2 candidate artifact",
            ),
            (
                "template retained",
                Path(
                    ".github/bootstrap/session-retrospective-v2-permanent-ci.yml"
                ),
                "temporary bootstrap artifact must be absent",
            ),
            (
                "workflow retained",
                Path(".github/workflows/session-retrospective-v2-bootstrap.yml"),
                "temporary bootstrap artifact must be absent",
            ),
            (
                "test retained",
                Path("tests/test_session_retrospective_v2_bootstrap.py"),
                "temporary bootstrap artifact must be absent",
            ),
        )
        for label, relative, expected in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    path = root / relative
                    if label == "missing":
                        path.unlink()
                    else:
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text(
                            "Unexpected bootstrap artifact.\n", encoding="utf-8"
                        )

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(expected, issues)

    def test_bootstrap_v2_escapes_unexpected_git_paths_in_diagnostics(self) -> None:
        raw_component = (
            "\n::error::injected\r\x1b[31m\\literal" + chr(0x7F) + chr(0x200B) + ".txt"
        )
        relative = Path(raw_component)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_bootstrap_v2_candidate(root)
            (root / relative).write_text(
                "Unexpected bootstrap artifact.\n",
                encoding="utf-8",
            )
            run_fixture_git(root, "add", "--", relative.as_posix())

            issues = validate_synthetic_bootstrap_v2_candidate(root)

        displayed = MODULE.display_relative_path(relative)
        self.assertIn(
            f"{displayed}: unexpected bootstrap-v2 candidate index entry",
            issues,
        )
        self.assertTrue(
            all(character.isprintable() for issue in issues for character in issue)
        )
        self.assertFalse(any(issue.startswith("::") for issue in issues))
        self.assertFalse(any(raw_component in issue for issue in issues))

    def test_bootstrap_v2_rejects_symlinks_and_gitlinks(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_bootstrap_v2_candidate(root)
            link = root / "README.md"
            link.unlink()
            link.symlink_to("AGENTS.md")
            run_fixture_git(root, "add", link.relative_to(root).as_posix())

            issues = "\n".join(
                validate_synthetic_bootstrap_v2_candidate(
                    root,
                    synchronize_allowed_index=False,
                )
            )

        self.assertIn("symlink artifact is not allowed", issues)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_bootstrap_v2_candidate(root)
            run_fixture_git(
                root,
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{'1' * 40},vendor/module",
            )

            issues = "\n".join(
                validate_synthetic_bootstrap_v2_candidate(
                    root,
                    synchronize_allowed_index=False,
                )
            )

        self.assertIn("gitlink artifact is not allowed", issues)

    def test_bootstrap_v2_requires_an_inspectable_git_index_and_regular_modes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_bootstrap_v2_candidate(root, initialize_git=False)

            issues = "\n".join(
                validate_synthetic_bootstrap_v2_candidate(
                    root,
                    synchronize_allowed_index=False,
                )
            )

        self.assertIn(
            "candidate root must be a Git worktree with an inspectable index", issues
        )

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_bootstrap_v2_candidate(root)
            (root / ".git" / "index").write_bytes(b"invalid synthetic index")

            issues = "\n".join(
                validate_synthetic_bootstrap_v2_candidate(
                    root,
                    synchronize_allowed_index=False,
                )
            )

        self.assertIn("candidate Git index could not be inspected", issues)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_bootstrap_v2_candidate(root)
            executable = root / "scripts" / "retrospective_history_v2.py"
            executable.chmod(0o755)
            run_fixture_git(root, "add", executable.relative_to(root).as_posix())

            issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

        self.assertIn("candidate file mode must be 100644", issues)

    def test_bootstrap_v2_binds_allowed_worktree_content_and_mode_to_index(
        self,
    ) -> None:
        cases = (
            (
                "changed worktree",
                "candidate worktree content does not match candidate index",
            ),
            (
                "worktree mode",
                "candidate worktree mode does not match candidate index",
            ),
            (
                "filter-style divergence",
                "candidate worktree content does not match candidate index",
            ),
        )
        for case, expected in cases:
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    relative = Path("README.md")
                    candidate_path = root / relative
                    if case == "changed worktree":
                        candidate_path.write_text(
                            "Synthetic changed worktree content.\n",
                            encoding="utf-8",
                        )
                    elif case == "worktree mode":
                        candidate_path.chmod(0o755)
                    else:
                        blob_result = subprocess.run(
                            ["git", "-C", str(root), "hash-object", "-w", "--stdin"],
                            input=b"Synthetic filtered index content.\n",
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            check=True,
                        )
                        object_id = blob_result.stdout.decode("ascii").strip()
                        run_fixture_git(
                            root,
                            "update-index",
                            "--cacheinfo",
                            git_cacheinfo_argument(object_id, relative),
                        )
                    issues = "\n".join(
                        validate_synthetic_bootstrap_v2_candidate(
                            root,
                            synchronize_allowed_index=False,
                        )
                    )

                self.assertIn(f"{relative.as_posix()}: {expected}", issues)

    def test_bootstrap_v2_append_only_preserves_existing_tracked_artifacts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            base_root = workspace / "base"
            candidate_root = workspace / "candidate"
            write_bootstrap_v2_base(base_root)
            write_bootstrap_v2_candidate(candidate_root)
            retained_value = '{"retained":"synthetic"}\n'
            write_tracked_append_only_artifact(base_root, retained_value)
            write_tracked_append_only_artifact(candidate_root, retained_value)

            self.assertEqual(
                validate_synthetic_bootstrap_v2_candidate(
                    candidate_root,
                    base_root=base_root,
                ),
                [],
            )

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_bootstrap_v2_candidate(root)
            self.assertEqual(
                MODULE.validate_bootstrap_v2_candidate(root, root),
                ["base and candidate roots must be distinct directories"],
            )

    def test_bootstrap_v2_append_only_rejects_rewrite_delete_and_mode_change(
        self,
    ) -> None:
        cases = (
            ("rewrite", "existing tracked artifact content must not be rewritten"),
            ("delete", "existing tracked artifact must not be deleted"),
            ("mode", "existing tracked artifact mode must not change"),
        )
        for mutation, expected in cases:
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as raw:
                    workspace = Path(raw)
                    base_root = workspace / "base"
                    candidate_root = workspace / "candidate"
                    write_bootstrap_v2_base(base_root)
                    write_bootstrap_v2_candidate(candidate_root)
                    retained_value = '{"retained":"synthetic"}\n'
                    write_tracked_append_only_artifact(base_root, retained_value)
                    candidate_path = write_tracked_append_only_artifact(
                        candidate_root,
                        retained_value,
                    )
                    if mutation == "rewrite":
                        candidate_path.write_text(
                            '{"retained":"rewritten"}\n',
                            encoding="utf-8",
                        )
                        run_fixture_git(
                            candidate_root,
                            "add",
                            candidate_path.relative_to(candidate_root).as_posix(),
                        )
                    elif mutation == "delete":
                        candidate_path.unlink()
                        run_fixture_git(candidate_root, "add", "--all")
                    else:
                        candidate_path.chmod(0o755)
                        run_fixture_git(
                            candidate_root,
                            "add",
                            candidate_path.relative_to(candidate_root).as_posix(),
                        )

                    issues = "\n".join(
                        validate_synthetic_bootstrap_v2_candidate(
                            candidate_root,
                            base_root=base_root,
                        )
                    )

                self.assertIn(expected, issues)

    def test_bootstrap_v2_append_only_protects_existing_allowed_artifacts(self) -> None:
        relatives = (
            Path("scripts/validate_retained_history.py"),
            Path("schemas/session-retrospective-v2.schema.json"),
            Path("README.md"),
        )
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            base_root = workspace / "base"
            candidate_root = workspace / "candidate"
            write_bootstrap_v2_base(base_root)
            write_bootstrap_v2_candidate(candidate_root)
            for relative in relatives:
                add_matching_bootstrap_v2_base_artifact(
                    base_root,
                    candidate_root,
                    relative,
                )

            self.assertEqual(
                validate_synthetic_bootstrap_v2_candidate(
                    candidate_root,
                    base_root=base_root,
                ),
                [],
            )

        mutations = (
            (
                "rewrite",
                True,
                "existing tracked artifact content must not be rewritten",
            ),
            (
                "rewrite unstaged",
                False,
                "existing tracked artifact content must not be rewritten",
            ),
            ("delete", True, "existing tracked artifact must not be deleted"),
            ("delete unstaged", False, "existing tracked artifact must not be deleted"),
            ("mode", True, "existing tracked artifact mode must not change"),
            ("mode unstaged", False, "existing tracked artifact mode must not change"),
        )
        for relative in relatives:
            for mutation, stage_change, expected in mutations:
                with self.subTest(relative=relative.as_posix(), mutation=mutation):
                    with tempfile.TemporaryDirectory() as raw:
                        workspace = Path(raw)
                        base_root = workspace / "base"
                        candidate_root = workspace / "candidate"
                        write_bootstrap_v2_base(base_root)
                        write_bootstrap_v2_candidate(candidate_root)
                        add_matching_bootstrap_v2_base_artifact(
                            base_root,
                            candidate_root,
                            relative,
                        )
                        candidate_path = candidate_root / relative
                        if mutation.startswith("rewrite"):
                            candidate_path.write_bytes(
                                candidate_path.read_bytes() + b"\n"
                            )
                        elif mutation.startswith("delete"):
                            candidate_path.unlink()
                        else:
                            candidate_path.chmod(0o755)
                        if stage_change:
                            run_fixture_git(candidate_root, "add", "--all")

                        issues = "\n".join(
                            validate_synthetic_bootstrap_v2_candidate(
                                candidate_root,
                                base_root=base_root,
                                synchronize_allowed_index=False,
                            )
                        )

                    self.assertIn(f"{relative.as_posix()}: {expected}", issues)

    def test_bootstrap_v2_candidate_bounds_count_unexpected_index_and_tree_entries(
        self,
    ) -> None:
        entry_limit = len(EXPECTED_BOOTSTRAP_V2_FILES) + 1
        cases = ("indexed", "untracked")
        for kind in cases:
            with self.subTest(kind=kind):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    extra = root / "build" / "overflow.txt"
                    extra.parent.mkdir(parents=True, exist_ok=True)
                    extra.write_text("overflow\n", encoding="utf-8")
                    if kind == "indexed":
                        run_fixture_git(
                            root, "add", "--force", extra.relative_to(root).as_posix()
                        )
                    expected = (
                        "candidate Git index enumeration exceeds the trusted entry limit"
                        if kind == "indexed"
                        else "candidate artifact enumeration exceeds the trusted entry limit"
                    )
                    with mock.patch.object(
                        MODULE,
                        "BOOTSTRAP_V2_MAX_CANDIDATE_ENTRIES",
                        entry_limit,
                    ):
                        issues = "\n".join(
                            validate_synthetic_bootstrap_v2_candidate(root)
                        )

                self.assertIn(expected, issues)

    def test_bootstrap_v2_enumerators_stop_consuming_after_the_bound(self) -> None:
        started = time.monotonic()
        records, issue = MODULE.bounded_git_nul_records(
            [
                sys.executable,
                "-c",
                "import os, time; separator = bytes((0,)); "
                "os.write(1, b'first' + separator + b'second' + separator); "
                "time.sleep(60)",
            ],
            max_records=1,
            failure_message="failed",
            limit_message="bounded",
        )
        self.assertIsNone(records)
        self.assertEqual(issue, "bounded")
        self.assertLess(time.monotonic() - started, 2)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            first = root / "first.txt"
            second = root / "second.txt"

            class SyntheticDirEntry:
                def __init__(self, path: Path) -> None:
                    self.name = path.name
                    self.path = str(path)

                def is_symlink(self) -> bool:
                    return False

                def is_dir(self, *, follow_symlinks: bool) -> bool:
                    self.assert_no_follow(follow_symlinks)
                    return False

                def is_file(self, *, follow_symlinks: bool) -> bool:
                    self.assert_no_follow(follow_symlinks)
                    return True

                @staticmethod
                def assert_no_follow(follow_symlinks: bool) -> None:
                    if follow_symlinks:
                        raise AssertionError(
                            "candidate enumeration must not follow links"
                        )

            class SyntheticScandir:
                def __enter__(self) -> SyntheticScandir:
                    return self

                def __exit__(self, *_args: object) -> None:
                    return None

                def __iter__(self) -> object:
                    yield SyntheticDirEntry(first)
                    yield SyntheticDirEntry(second)
                    raise AssertionError(
                        "bounded tree iterator consumed past the limit"
                    )

            with mock.patch.object(
                MODULE.os, "scandir", return_value=SyntheticScandir()
            ):
                paths_result, path_issue = MODULE.iter_bootstrap_v2_files(
                    root,
                    max_entries=1,
                )
        self.assertIsNone(paths_result)
        self.assertEqual(
            path_issue,
            "candidate artifact enumeration exceeds the trusted entry limit",
        )

    def test_bootstrap_v2_rejects_nonpublic_key_material_and_packet_types(self) -> None:
        marker = (
            "-----BEGIN PGP PRI"
            "VATE KEY BLOCK-----\n"
            "\n"
            "xQEE\n"
            "-----END PGP PRI"
            "VATE KEY BLOCK-----\n"
        ).encode("ascii")
        cases = (
            ("marker", marker, "non-public key marker"),
            (
                "invalid armor checksum",
                synthetic_bootstrap_v2_public_key().replace(
                    b"-----END PGP PUBLIC KEY BLOCK-----",
                    b"=AAAA\n-----END PGP PUBLIC KEY BLOCK-----",
                ),
                "checksum does not match",
            ),
            (
                "secret key packet",
                synthetic_bootstrap_v2_public_key(
                    packets=((5, synthetic_bootstrap_v2_key_body()),)
                ),
                "secret-key packet",
            ),
            (
                "secret subkey packet",
                synthetic_bootstrap_v2_public_key(
                    packets=((7, synthetic_bootstrap_v2_key_body()),)
                ),
                "secret-key packet",
            ),
            (
                "literal packet",
                synthetic_bootstrap_v2_public_key(packets=((11, b"literal payload"),)),
                "outside the trusted public-key grammar",
            ),
            (
                "compressed packet",
                synthetic_bootstrap_v2_public_key(
                    packets=((8, b"compressed payload"),)
                ),
                "outside the trusted public-key grammar",
            ),
            (
                "encrypted packet",
                synthetic_bootstrap_v2_public_key(packets=((9, b"encrypted payload"),)),
                "outside the trusted public-key grammar",
            ),
            (
                "integrity protected packet",
                synthetic_bootstrap_v2_public_key(
                    packets=((18, b"encrypted payload"),)
                ),
                "outside the trusted public-key grammar",
            ),
            (
                "unknown packet",
                synthetic_bootstrap_v2_public_key(packets=((63, b"unknown payload"),)),
                "outside the trusted public-key grammar",
            ),
            (
                "malformed public key body",
                synthetic_bootstrap_v2_public_key(
                    packets=(
                        (6, b"\x04"),
                        (13, b"Synthetic Bootstrap"),
                        (2, synthetic_bootstrap_v2_signature_body()),
                    )
                ),
                "version 4 public key body",
            ),
            (
                "empty curve point",
                synthetic_bootstrap_v2_public_key(
                    packets=(
                        (
                            6,
                            bytes(
                                (
                                    4,
                                    0,
                                    0,
                                    0,
                                    0,
                                    22,
                                    len(MODULE.BOOTSTRAP_V2_ED25519_OID),
                                )
                            )
                            + MODULE.BOOTSTRAP_V2_ED25519_OID
                            + synthetic_openpgp_mpi(bytes((0x40,)) + bytes(32)),
                        ),
                        (13, b"Synthetic Bootstrap"),
                        (2, synthetic_bootstrap_v2_signature_body()),
                    )
                ),
                "curve key material is malformed",
            ),
        )
        for label, key_value, expected in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    key_path = root / "retrospective-history-v2-publisher.asc"
                    key_path.write_bytes(key_value)

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(expected, issues)

    def test_bootstrap_v2_public_key_armor_has_lf_only_closed_grammar(self) -> None:
        canonical = synthetic_bootstrap_v2_public_key()
        decoded = MODULE.decode_bootstrap_v2_public_key_armor(canonical)
        checksum = base64.b64encode(
            MODULE.bootstrap_v2_crc24(decoded)
        )
        with_checksum = canonical.replace(
            b"\n-----END PGP PUBLIC KEY BLOCK-----\n",
            b"\n=" + checksum + b"\n-----END PGP PUBLIC KEY BLOCK-----\n",
            1,
        )
        self.assertEqual(
            MODULE.decode_bootstrap_v2_public_key_armor(with_checksum),
            decoded,
        )

        control_cases = (
            ("CRLF", canonical.replace(b"\n", b"\r\n")),
            ("CR", canonical.replace(b"\n", b"\r", 1)),
            ("VT", canonical.replace(b"\n", bytes((0x0B,)), 1)),
            ("FF", canonical.replace(b"\n", bytes((0x0C,)), 1)),
            ("FS", canonical.replace(b"\n", bytes((0x1C,)), 1)),
            ("GS", canonical.replace(b"\n", bytes((0x1D,)), 1)),
            ("RS", canonical.replace(b"\n", bytes((0x1E,)), 1)),
            ("DEL", canonical.replace(b"\n", bytes((0x7F,)) + b"\n", 1)),
        )
        for label, attacked in control_cases:
            with self.subTest(label=label), self.assertRaisesRegex(
                ValueError,
                "prohibited control bytes",
            ):
                MODULE.decode_bootstrap_v2_public_key_armor(attacked)

        malformed_cases = (
            (
                "missing final LF",
                canonical.removesuffix(b"\n"),
                "must end with one LF",
            ),
            (
                "armor header",
                canonical.replace(
                    b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n",
                    b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
                    b"Comment: hidden\n\n",
                    1,
                ),
                "exactly one public-key armor block",
            ),
            (
                "body alphabet",
                canonical.replace(b"\n\n", b"\n\n!", 1),
                "canonical base64",
            ),
            (
                "data after checksum",
                with_checksum.replace(
                    b"\n-----END PGP PUBLIC KEY BLOCK-----\n",
                    b"\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n",
                    1,
                ),
                "canonical base64",
            ),
        )
        for label, attacked, expected in malformed_cases:
            with self.subTest(label=label), self.assertRaisesRegex(
                ValueError,
                expected,
            ):
                MODULE.decode_bootstrap_v2_public_key_armor(attacked)

    def test_bootstrap_v2_pins_exact_public_key_artifact_digests(self) -> None:
        self.assertEqual(
            set(MODULE.BOOTSTRAP_V2_PUBLIC_KEY_SHA256),
            MODULE.BOOTSTRAP_V2_PUBLIC_KEY_FILES,
        )
        self.assertTrue(
            all(
                re.fullmatch(r"[0-9a-f]{64}", digest)
                for digest in MODULE.BOOTSTRAP_V2_PUBLIC_KEY_SHA256.values()
            )
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_bootstrap_v2_candidate(root)

            with tempfile.TemporaryDirectory() as raw_base:
                base_root = Path(raw_base)
                write_bootstrap_v2_base(base_root)
                issues = "\n".join(
                    MODULE.validate_bootstrap_v2_candidate(base_root, root)
                )

        self.assertIn(
            "public key artifact digest does not match trusted policy", issues
        )

    def test_bootstrap_v2_privacy_scans_decoded_public_key_identity(self) -> None:
        immutable_action_ref = "a" * 40
        cases = (
            (
                "sensitive identity",
                "Synthetic " + risky_project_path(),
                "public key human-readable content contains raw/sensitive evidence",
            ),
            (
                "email identity",
                "Synthetic <" + risky_email() + ">",
                "public key human-readable content contains raw/sensitive evidence",
            ),
            (
                "single-label email identity",
                "Synthetic <" + risky_single_label_internal_email() + ">",
                "public key human-readable content contains raw/sensitive evidence",
            ),
            (
                "sentence-final single-label email identity",
                "Synthetic " + risky_single_label_internal_email() + ".",
                "public key human-readable content contains raw/sensitive evidence",
            ),
            (
                "slash-prefixed single-label email identity",
                "Synthetic /" + risky_single_label_internal_email(),
                "public key human-readable content contains raw/sensitive evidence",
            ),
            (
                "home arpa identity",
                "Synthetic " + risky_home_arpa_domain(),
                "public key human-readable content contains raw/sensitive evidence",
            ),
            (
                "srv path identity",
                "Synthetic " + risky_srv_private_path(),
                "public key human-readable content contains raw/sensitive evidence",
            ),
            (
                "repeated-slash srv path identity",
                "Synthetic " + risky_repeated_slash_srv_private_path(),
                "public key human-readable content contains raw/sensitive evidence",
            ),
            (
                "cloud access key identity",
                "Synthetic " + risky_cloud_access_key_id(),
                "public key human-readable content contains raw/sensitive evidence",
            ),
            (
                "temporary cloud access key identity",
                "Synthetic " + risky_temporary_cloud_access_key_id(),
                "public key human-readable content contains raw/sensitive evidence",
            ),
            (
                "legacy cloud access key identity",
                "Synthetic " + risky_legacy_cloud_access_key_id(),
                "public key human-readable content contains raw/sensitive evidence",
            ),
            (
                "action-like internal email identity",
                "Synthetic " + risky_action_like_internal_email(),
                "public key human-readable content contains raw/sensitive evidence",
            ),
            (
                "action-like version email identity",
                "Synthetic " + risky_action_like_version_email(),
                "public key human-readable content contains raw/sensitive evidence",
            ),
            (
                "immutable uses identity",
                "uses: owner/action" + "@" + immutable_action_ref,
                "public key human-readable content contains raw/sensitive evidence",
            ),
            (
                "long action-like email identity",
                "Synthetic " + risky_long_action_like_email(),
                "public key human-readable content contains raw/sensitive evidence",
            ),
            (
                "multilabel internal email identity",
                "Synthetic " + risky_multilabel_internal_email("x"),
                "public key human-readable content contains raw/sensitive evidence",
            ),
            (
                "action access key identity",
                "Synthetic " + risky_action_reference(risky_cloud_access_key_id()),
                "public key human-readable content contains raw/sensitive evidence",
            ),
            (
                "action home arpa identity",
                "Synthetic " + risky_action_reference(risky_home_arpa_domain()),
                "public key human-readable content contains raw/sensitive evidence",
            ),
            (
                "nonpublic marker",
                "Synthetic SEC" + "RET-KEY PACKET",
                "public key human-readable content contains a non-public key marker",
            ),
        )
        for label, user_id, expected in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    key_path = root / "retrospective-history-v2-publisher.asc"
                    key_path.write_bytes(
                        synthetic_bootstrap_v2_public_key(user_id=user_id)
                    )

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(expected, issues)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_bootstrap_v2_candidate(root)
            short_email = ("a" + "@" + "corp").encode("ascii")
            user_attribute = synthetic_openpgp_user_attribute(
                bytes((0xFF, 0xD8)) + short_email + bytes((0xFF, 0xD9))
            )
            packets = (
                (6, synthetic_bootstrap_v2_key_body()),
                (17, user_attribute),
                (2, synthetic_bootstrap_v2_signature_body()),
            )
            key_path = root / "retrospective-history-v2-publisher.asc"
            key_path.write_bytes(synthetic_bootstrap_v2_public_key(packets=packets))

            issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

        self.assertIn(
            "public key human-readable content contains raw/sensitive evidence", issues
        )

    def test_bootstrap_v2_privacy_scans_hashed_and_unhashed_signature_identities(
        self,
    ) -> None:
        short_email = ("a" + "@" + "corp").encode("ascii")
        signer_user_id = synthetic_openpgp_subpacket(28, short_email)
        critical_signer_user_id = synthetic_openpgp_subpacket(0x80 | 28, short_email)
        cases = (
            ("hashed", {"hashed_subpackets": critical_signer_user_id}),
            ("unhashed", {"unhashed_subpackets": signer_user_id}),
        )
        for label, signature_arguments in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    packets = (
                        (6, synthetic_bootstrap_v2_key_body()),
                        (13, b"Synthetic Bootstrap"),
                        (
                            2,
                            synthetic_bootstrap_v2_signature_body(
                                **signature_arguments
                            ),
                        ),
                    )
                    key_path = root / "retrospective-history-v2-publisher.asc"
                    key_path.write_bytes(
                        synthetic_bootstrap_v2_public_key(packets=packets)
                    )

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(
                    "public key human-readable content contains raw/sensitive evidence",
                    issues,
                )

    def test_bootstrap_v2_rejects_malformed_openpgp_subpacket_boundaries(self) -> None:
        large_payload = b"x" * 8382
        two_octet_subpacket = synthetic_openpgp_subpacket(28, large_payload)
        self.assertEqual(two_octet_subpacket[:2], bytes((0xDF, 0xFF)))
        self.assertEqual(
            MODULE.parse_bootstrap_v2_subpackets(
                two_octet_subpacket,
                label="synthetic signature area",
                critical_type_bit=True,
            ),
            [(28, False, large_payload)],
        )
        five_octet_payload = b"x" * 8383
        five_octet_subpacket = synthetic_openpgp_subpacket(
            28,
            five_octet_payload,
        )
        self.assertEqual(five_octet_subpacket[:5], bytes((0xFF, 0, 0, 0x20, 0xC0)))
        self.assertEqual(
            MODULE.parse_bootstrap_v2_subpackets(
                five_octet_subpacket,
                label="synthetic signature area",
                critical_type_bit=True,
            ),
            [(28, False, five_octet_payload)],
        )

        notation_with_truncated_name = synthetic_openpgp_subpacket(
            20,
            bytes(4) + bytes((0, 5, 0, 0)),
        )
        malformed_image_header = synthetic_openpgp_subpacket(
            1,
            bytes((32, 0, 1, 1)) + bytes(12) + b"x",
        )
        cases = (
            (
                "hashed body boundary",
                (13, b"Synthetic Bootstrap"),
                synthetic_bootstrap_v2_signature_body(hashed_subpackets=b"\x08\x1cabc"),
                "signature hashed area subpacket body is truncated",
            ),
            (
                "unhashed length boundary",
                (13, b"Synthetic Bootstrap"),
                synthetic_bootstrap_v2_signature_body(
                    unhashed_subpackets=bytes((0xC0,))
                ),
                "signature unhashed area subpacket length is truncated",
            ),
            (
                "reserved signature type",
                (13, b"Synthetic Bootstrap"),
                synthetic_bootstrap_v2_signature_body(
                    hashed_subpackets=synthetic_openpgp_subpacket(0, b""),
                ),
                "signature hashed area subpacket type is reserved",
            ),
            (
                "reserved nonzero signature type",
                (13, b"Synthetic Bootstrap"),
                synthetic_bootstrap_v2_signature_body(
                    hashed_subpackets=synthetic_openpgp_subpacket(1, b""),
                ),
                "signature subpacket type is reserved",
            ),
            (
                "notation nested lengths",
                (13, b"Synthetic Bootstrap"),
                synthetic_bootstrap_v2_signature_body(
                    hashed_subpackets=notation_with_truncated_name
                ),
                "signature notation data subpacket lengths are malformed",
            ),
            (
                "user attribute body boundary",
                (17, b"\x05\x01abc"),
                synthetic_bootstrap_v2_signature_body(),
                "user attribute subpacket body is truncated",
            ),
            (
                "user attribute nested header length",
                (17, malformed_image_header),
                synthetic_bootstrap_v2_signature_body(),
                "public key image attribute header length is malformed",
            ),
            (
                "user attribute high type bit",
                (17, synthetic_openpgp_subpacket(0x81, bytes(16) + b"x")),
                synthetic_bootstrap_v2_signature_body(),
                "public key user attribute subpacket type is outside the trusted grammar",
            ),
        )
        for label, identity_packet, signature_body, expected in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    packets = (
                        (6, synthetic_bootstrap_v2_key_body()),
                        identity_packet,
                        (2, signature_body),
                    )
                    key_path = root / "retrospective-history-v2-publisher.asc"
                    key_path.write_bytes(
                        synthetic_bootstrap_v2_public_key(packets=packets)
                    )

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(expected, issues)

    def test_bootstrap_v2_rejects_malformed_and_duplicate_key_schemas(self) -> None:
        schema_path = Path("schemas/session-retrospective-v2.schema.json")
        dialect = json.dumps(MODULE.BOOTSTRAP_V2_JSON_SCHEMA_DIALECT)
        cases = (
            ("malformed", '{"$schema":', "JSONDecodeError"),
            (
                "duplicate key",
                f'{{"$schema":{dialect},"$schema":{dialect}}}',
                "duplicate JSON key is not allowed",
            ),
            (
                "wrong dialect",
                '{"$schema":"https://example.com/schema"}',
                "dialect is not trusted",
            ),
        )
        for label, schema_text, expected in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    (root / schema_path).write_text(schema_text, encoding="utf-8")

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(expected, issues)

    def test_bootstrap_v2_json_depth_overflow_is_a_structured_failure(self) -> None:
        safe_depth = min(64, max(sys.getrecursionlimit() // 4, 1))
        safe_json = "[" * safe_depth + "0" + "]" * safe_depth
        self.assertIsInstance(MODULE.parse_strict_json(safe_json), list)

        parser_overflow_depth = sys.getrecursionlimit() * 10
        parser_overflow_json = (
            "[" * parser_overflow_depth + "0" + "]" * parser_overflow_depth
        )
        self.assertLess(
            len(parser_overflow_json.encode("utf-8")),
            MODULE.BOOTSTRAP_V2_MAX_FILE_BYTES,
        )
        expected = "JSON nesting exceeds the trusted depth limit"
        with self.assertRaisesRegex(ValueError, expected):
            MODULE.parse_strict_json(parser_overflow_json)

        schema_path = Path("schemas/session-retrospective-v2.schema.json")
        candidate_depths = (
            sys.getrecursionlimit() + 100,
            parser_overflow_depth,
        )
        for depth in candidate_depths:
            with self.subTest(depth=depth), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                write_bootstrap_v2_candidate(root)
                nested_json = "[" * depth + "0" + "]" * depth
                self.assertLess(
                    len(nested_json.encode("utf-8")),
                    MODULE.BOOTSTRAP_V2_MAX_FILE_BYTES,
                )
                (root / schema_path).write_text(nested_json, encoding="utf-8")

                issues = validate_synthetic_bootstrap_v2_candidate(root)

                self.assertIn(f"{schema_path.as_posix()}: {expected}", issues)
                self.assertFalse(any(str(root) in issue for issue in issues))
                self.assertFalse(any("Traceback" in issue for issue in issues))

    def test_bootstrap_v2_privacy_scans_every_inventory_file(self) -> None:
        risk = risky_project_path()
        for relative in sorted(EXPECTED_BOOTSTRAP_V2_FILES):
            with self.subTest(relative=relative.as_posix()):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    path = root / relative
                    if relative in MODULE.BOOTSTRAP_V2_PUBLIC_KEY_FILES:
                        text = path.read_text(encoding="ascii")
                        text = text.replace(
                            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n",
                            f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: {risk}\n\n",
                            1,
                        )
                        path.write_text(text, encoding="ascii")
                    elif relative.suffix == ".json":
                        data = json.loads(path.read_text(encoding="utf-8"))
                        data["privacy_probe"] = risk
                        path.write_text(json.dumps(data), encoding="utf-8")
                    else:
                        with path.open("a", encoding="utf-8") as stream:
                            stream.write(f"Privacy probe: {risk}\n")

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(
                    "infrastructure text contains raw/sensitive evidence", issues
                )

    def test_bootstrap_v2_rejects_restored_global_privacy_categories(self) -> None:
        cases = (
            ("email", Path("AGENTS.md"), "Identity: " + risky_email() + "\n"),
            (
                "bare 64-hex",
                Path("requirements-v2.in"),
                "Digest: " + risky_raw_hash() + "\n",
            ),
            (
                "internal domain",
                Path("reports/README.md"),
                "Host: " + risky_internal_host() + "\n",
            ),
        )
        for label, relative, probe in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    with (root / relative).open("a", encoding="utf-8") as stream:
                        stream.write(probe)

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(
                    "infrastructure text contains raw/sensitive evidence", issues
                )

    def test_bootstrap_v2_decoded_json_rejects_restored_privacy_categories(
        self,
    ) -> None:
        schema_path = Path("schemas/retained-manifest-v2.schema.json")
        cases = (
            ("email", "operator" + "\\u0040" + "redacted" + "\\u002e" + "com"),
            ("bare 64-hex", "a" * 31 + "\\u0061" + "a" * 32),
            ("internal domain", "service" + "\\u002e" + "internal"),
        )
        for label, encoded_probe in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    schema_text = (
                        '{"$schema":'
                        + json.dumps(MODULE.BOOTSTRAP_V2_JSON_SCHEMA_DIALECT)
                        + ',"probe":"'
                        + encoded_probe
                        + '"}\n'
                    )
                    self.assertFalse(
                        MODULE.contains_bootstrap_v2_privacy_risk_text(
                            schema_text,
                            relative=schema_path,
                        )
                    )
                    (root / schema_path).write_text(schema_text, encoding="utf-8")

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(
                    "infrastructure text contains raw/sensitive evidence", issues
                )

    def test_bootstrap_v2_rejects_adjacent_sensitive_forms(self) -> None:
        immutable_action_ref = "a" * 40
        cases = (
            (
                "single-label internal email",
                Path("AGENTS.md"),
                "Identity: " + risky_single_label_internal_email() + "\n",
            ),
            (
                "sentence-final single-label internal email",
                Path("AGENTS.md"),
                "Identity: " + risky_single_label_internal_email() + ".\n",
            ),
            (
                "slash-prefixed single-label internal email",
                Path("AGENTS.md"),
                "Identity: /" + risky_single_label_internal_email() + "\n",
            ),
            (
                "home arpa domain",
                Path("README.md"),
                "Host: " + risky_home_arpa_domain() + "\n",
            ),
            (
                "srv path",
                Path("reports/README.md"),
                "Report: " + risky_srv_private_path() + "\n",
            ),
            (
                "repeated-slash srv path",
                Path("reports/README.md"),
                "Report: " + risky_repeated_slash_srv_private_path() + "\n",
            ),
            (
                "cloud access key",
                Path("requirements-v2.in"),
                "Identifier: " + risky_cloud_access_key_id() + "\n",
            ),
            (
                "temporary cloud access key",
                Path("requirements-v2.in"),
                "Identifier: " + risky_temporary_cloud_access_key_id() + "\n",
            ),
            (
                "legacy cloud access key",
                Path("requirements-v2.in"),
                "Identifier: " + risky_legacy_cloud_access_key_id() + "\n",
            ),
            (
                "action-like internal email",
                Path("AGENTS.md"),
                "Identity: " + risky_action_like_internal_email() + "\n",
            ),
            (
                "action-like version email prose",
                Path("README.md"),
                "Identity: " + risky_action_like_version_email() + "\n",
            ),
            (
                "immutable action-like prose",
                Path("README.md"),
                "uses: owner/action" + "@" + immutable_action_ref + "\n",
            ),
            (
                "mutable action uses",
                Path(".github/workflows/ci.yml"),
                "  - uses: attacker/action" + "@" + "v1\n",
            ),
            (
                "immutable action uses suffix",
                Path(".github/workflows/ci.yml"),
                "  - uses: owner/action" + "@" + immutable_action_ref + "-suffix\n",
            ),
            (
                "immutable action uses plus",
                Path(".github/workflows/ci.yml"),
                "  - uses: owner/action" + "@" + immutable_action_ref + "+suffix\n",
            ),
            (
                "immutable action uses ref path",
                Path(".github/workflows/ci.yml"),
                "  - uses: owner/action" + "@" + immutable_action_ref + "/path\n",
            ),
            (
                "uppercase immutable action uses",
                Path(".github/workflows/ci.yml"),
                "  - uses: owner/action" + "@" + immutable_action_ref.upper() + "\n",
            ),
            (
                "long action-like email",
                Path("AGENTS.md"),
                "Identity: " + risky_long_action_like_email() + "\n",
            ),
            (
                "numeric multilabel internal email",
                Path("AGENTS.md"),
                "Identity: " + risky_multilabel_internal_email("1") + "\n",
            ),
            (
                "action access key",
                Path("requirements-v2.in"),
                "Identifier: "
                + risky_action_reference(risky_legacy_cloud_access_key_id())
                + "\n",
            ),
            (
                "action home arpa",
                Path("README.md"),
                "Host: " + risky_action_reference(risky_home_arpa_domain()) + "\n",
            ),
        )
        for label, relative, probe in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    with (root / relative).open("a", encoding="utf-8") as stream:
                        stream.write(probe)

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(
                    "infrastructure text contains raw/sensitive evidence", issues
                )

    def test_bootstrap_v2_decoded_workflow_scalars_reject_mutable_or_misplaced_actions(
        self,
    ) -> None:
        immutable_action_ref = "a" * 40
        cases = (
            (
                "escaped at",
                '      - uses: "attacker/action\\u0040v1"\n',
            ),
            (
                "escaped ref",
                '      - uses: "attacker/action\\u0040\\u00761"\n',
            ),
            (
                "yaml hex escapes",
                '      - uses: "attacker/action\\x40\\x76\\x31"\n',
            ),
            (
                "escaped uses key",
                '      - "\\u0075ses": "attacker/action\\u0040v1"\n',
            ),
            (
                "pinned value under another key",
                '      - name: "owner/action\\u0040'
                + immutable_action_ref
                + '"\n        run: "true"\n',
            ),
            (
                "pinned value with suffix",
                '      - uses: "owner/action\\u0040'
                + immutable_action_ref
                + '\\u002dsuffix"\n',
            ),
            (
                "pinned value with risky comment",
                '      - uses: "owner/action\\u0040'
                + immutable_action_ref
                + '" # service'
                + ".internal\n",
            ),
        )
        for label, probe in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    (root / ".github/workflows/ci.yml").write_text(
                        synthetic_workflow_with_step(probe),
                        encoding="utf-8",
                    )

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(
                    "infrastructure text contains raw/sensitive evidence", issues
                )

    def test_bootstrap_v2_workflow_uses_parser_rejects_flow_and_multiline_mutable_refs(
        self,
    ) -> None:
        cases = (
            (
                "flow mapping",
                '      - {name: Synthetic, uses: "attacker/action\\u0040v1"}\n',
            ),
            (
                "quoted flow key",
                '      - {"\\u0075ses": "attacker/action\\x40\\x76\\x31"}\n',
            ),
            (
                "double quoted continuation",
                '      - uses: "attacker/action@' + "\\" + '\n          v1"\n',
            ),
            (
                "double quoted folded line",
                '      - uses: "attacker/action@\n          v1"\n',
            ),
            (
                "generic 64-hex ref",
                '      - uses: "owner/action@' + ("a" * 64) + '"\n',
            ),
            (
                "escaped generic 64-hex ref",
                '      - uses: "owner/action\\u0040\\u0061' + ("a" * 63) + '"\n',
            ),
        )
        for label, probe in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    (root / ".github/workflows/ci.yml").write_text(
                        synthetic_workflow_with_step(probe),
                        encoding="utf-8",
                    )

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(
                    "infrastructure text contains raw/sensitive evidence", issues
                )

    def test_bootstrap_v2_immutable_action_ref_does_not_exempt_action_path_or_comment(
        self,
    ) -> None:
        immutable_ref = "a" * 40
        cases = (
            (
                "credential owner",
                risky_github_classic_token() + "/action@" + immutable_ref,
            ),
            ("internal domain", "service" + ".internal/action@" + immutable_ref),
            ("sensitive path", "owner/api-token/action@" + immutable_ref),
            (
                "internal URL",
                "http" + "://service" + ".internal/action@" + immutable_ref,
            ),
        )
        for label, action_value in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    probe = f'      - uses: "{action_value}"\n'
                    (root / ".github/workflows/ci.yml").write_text(
                        synthetic_workflow_with_step(probe),
                        encoding="utf-8",
                    )

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(
                    "infrastructure text contains raw/sensitive evidence", issues
                )

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_bootstrap_v2_candidate(root)
            probe = (
                '      - uses: "owner/action@'
                + immutable_ref
                + '" # service'
                + ".internal\n"
            )
            (root / ".github/workflows/ci.yml").write_text(
                synthetic_workflow_with_step(probe),
                encoding="utf-8",
            )

            issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

        self.assertIn("infrastructure text contains raw/sensitive evidence", issues)

    def test_bootstrap_v2_workflow_uses_parser_accepts_flow_and_multiline_pinned_refs(
        self,
    ) -> None:
        probes = (
            '      - {"\\u0075ses": "owner/action\\u0040' + ("a" * 40) + '"}\n',
            '      - uses: "owner/action@' + "\\" + "\n          " + ("b" * 40) + '"\n',
            '      - uses: "owner/action@' + ("c" * 40) + '" # pinned action\n',
        )
        for probe in probes:
            with self.subTest(probe=probe[:40]):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    (root / ".github/workflows/ci.yml").write_text(
                        synthetic_workflow_with_step(probe),
                        encoding="utf-8",
                    )

                    self.assertEqual(
                        validate_synthetic_bootstrap_v2_candidate(root), []
                    )

    def test_bootstrap_v2_block_scalar_candidates_are_tokenized_in_linear_work(
        self,
    ) -> None:
        unit_width = 256
        marker_suffix = ": |x"
        unit = (" " * (unit_width - len(marker_suffix))) + marker_suffix
        marker_count = MODULE.BOOTSTRAP_V2_MAX_FILE_BYTES // len(unit)
        malformed = unit * marker_count
        self.assertEqual(
            len(malformed.encode("utf-8")), MODULE.BOOTSTRAP_V2_MAX_FILE_BYTES
        )

        operation_counts: dict[str, int] = {}
        tokens = MODULE.bootstrap_v2_yaml_tokens(
            malformed,
            operation_counts=operation_counts,
        )

        block_markers = [
            lexeme
            for lexeme in tokens
            if lexeme.value == "|"
            and lexeme.kind in {"indicator", "invalid_block_scalar"}
        ]
        self.assertEqual(len(block_markers), marker_count)
        self.assertEqual(
            sum(lexeme.kind == "invalid_block_scalar" for lexeme in block_markers),
            1,
        )
        self.assertEqual(operation_counts["line_prefix_characters"], len(malformed))
        self.assertEqual(operation_counts["block_scalar_context_checks"], marker_count)
        self.assertEqual(operation_counts.get("line_end_searches", 0), 1)
        self.assertLessEqual(
            operation_counts.get("block_scalar_header_characters", 0), unit_width + 1
        )

    def test_bootstrap_v2_block_scalar_tokenization_preserves_yaml_semantics(
        self,
    ) -> None:
        valid_cases = (
            (
                "mapping literal",
                "  run: |+\n    &literal *alias\nnext: value\n",
                (
                    ("scalar", "run"),
                    ("punctuation", ":"),
                    ("indicator", "|"),
                    ("scalar", "&literal *alias\n"),
                    ("scalar", "next"),
                    ("punctuation", ":"),
                    ("scalar", "value"),
                ),
            ),
            (
                "sequence folded",
                "  - >2-\n      &literal *alias\nnext: value\n",
                (
                    ("scalar", "-"),
                    ("indicator", ">"),
                    ("scalar", "  &literal *alias"),
                    ("scalar", "next"),
                    ("punctuation", ":"),
                    ("scalar", "value"),
                ),
            ),
            (
                "compact sequence mapping literal",
                "  - run: |+\n      &literal *alias\n    env: value\nnext: value\n",
                (
                    ("scalar", "-"),
                    ("scalar", "run"),
                    ("punctuation", ":"),
                    ("indicator", "|"),
                    ("scalar", "&literal *alias\n"),
                    ("scalar", "env"),
                    ("punctuation", ":"),
                    ("scalar", "value"),
                    ("scalar", "next"),
                    ("punctuation", ":"),
                    ("scalar", "value"),
                ),
            ),
            (
                "compact sequence mapping explicit indentation",
                "  - run: >2-\n      &literal *alias\n    with: value\nnext: value\n",
                (
                    ("scalar", "-"),
                    ("scalar", "run"),
                    ("punctuation", ":"),
                    ("indicator", ">"),
                    ("scalar", "&literal *alias"),
                    ("scalar", "with"),
                    ("punctuation", ":"),
                    ("scalar", "value"),
                    ("scalar", "next"),
                    ("punctuation", ":"),
                    ("scalar", "value"),
                ),
            ),
        )
        for label, source, expected in valid_cases:
            with self.subTest(label=label):
                operation_counts: dict[str, int] = {}
                tokens = MODULE.bootstrap_v2_yaml_tokens(
                    source,
                    operation_counts=operation_counts,
                )

                self.assertEqual(
                    tuple((token.kind, token.value) for token in tokens), expected
                )
                self.assertEqual(
                    operation_counts["line_prefix_characters"], len(source)
                )
                self.assertFalse(
                    MODULE.bootstrap_v2_workflow_has_yaml_anchors_or_aliases(source)
                )

        invalid_cases = (
            ("invalid context", "name |+\n  &anchor *alias\n", "|", "+"),
            ("invalid header", "run: | invalid\n  &anchor *alias\n", "|", "invalid"),
            ("spaced chomping indicator", "run: | +\n  &anchor *alias\n", "|", "+"),
            (
                "spaced indentation indicators",
                "run: | 2-\n  &anchor *alias\n",
                "|",
                "2-",
            ),
            (
                "tab-spaced chomping indicator",
                "run: >\t+\n  &anchor *alias\n",
                ">",
                "+",
            ),
        )
        for label, source, block_indicator, header_scalar in invalid_cases:
            with self.subTest(label=label):
                tokens = MODULE.bootstrap_v2_yaml_tokens(source)

                block_tokens = [
                    lexeme
                    for lexeme in tokens
                    if lexeme.value == block_indicator
                    and lexeme.kind in {"indicator", "invalid_block_scalar"}
                ]
                self.assertEqual(len(block_tokens), 1)
                self.assertEqual(
                    block_tokens[0].kind,
                    "indicator"
                    if label == "invalid context"
                    else "invalid_block_scalar",
                )
                self.assertEqual(
                    [
                        lexeme.value
                        for lexeme in tokens
                        if lexeme.kind == "indicator" and lexeme.value in {"&", "*"}
                    ],
                    ["&", "*"],
                )
                self.assertIn(
                    header_scalar,
                    [lexeme.value for lexeme in tokens if lexeme.kind == "scalar"],
                )
                self.assertTrue(
                    MODULE.bootstrap_v2_workflow_has_yaml_anchors_or_aliases(source)
                )

    def test_bootstrap_v2_block_scalar_node_properties_and_colon_keys_decode(
        self,
    ) -> None:
        token_prefix = "ghp_"
        token_suffix = "ABCDEFGHIJKLMNOP"
        bearer_prefix = "Bea"
        bearer_suffix = "rer AbCdEfGhIjKlMnOp"
        url_prefix = "https://internal."
        url_suffix = "example"
        cases = (
            (
                "mapping tag",
                f"run: !!str >-\n  {token_prefix}\n  {token_suffix}\nsibling: safe\n",
                f"{token_prefix} {token_suffix}",
                token_prefix + token_suffix,
                "sibling: safe",
            ),
            (
                "tag then anchor",
                f"run: !!str &payload >-\n  {bearer_prefix}\n  {bearer_suffix}\n"
                "sibling: safe\n",
                f"{bearer_prefix} {bearer_suffix}",
                bearer_prefix + bearer_suffix,
                "sibling: safe",
            ),
            (
                "anchor then tag",
                f"run: &payload !!str >-\n  {url_prefix}\n  {url_suffix}\n"
                "sibling: safe\n",
                f"{url_prefix} {url_suffix}",
                url_prefix + url_suffix,
                "sibling: safe",
            ),
            (
                "verbatim tag and quoted key",
                '"run:script": !<tag:yaml.org,2002:str> >-\n'
                f"  {token_prefix}\n  {token_suffix}\nsibling: safe\n",
                f"{token_prefix} {token_suffix}",
                token_prefix + token_suffix,
                "sibling: safe",
            ),
            (
                "single quoted key",
                "'run:script': >-\n"
                f"  {bearer_prefix}\n  {bearer_suffix}\nsibling: safe\n",
                f"{bearer_prefix} {bearer_suffix}",
                bearer_prefix + bearer_suffix,
                "sibling: safe",
            ),
            (
                "plain key colon",
                f"run:script: >-\n  {url_prefix}\n  {url_suffix}\nsibling: safe\n",
                f"{url_prefix} {url_suffix}",
                url_prefix + url_suffix,
                "sibling: safe",
            ),
            (
                "sequence value",
                "items:\n"
                "  - !!str >-\n"
                f"      {token_prefix}\n      {token_suffix}\n"
                "  - safe\n",
                f"{token_prefix} {token_suffix}",
                token_prefix + token_suffix,
                "  - safe",
            ),
            (
                "compact sequence mapping",
                "items:\n"
                '  - "run:script": !!str >-\n'
                f"      {bearer_prefix}\n      {bearer_suffix}\n"
                "    sibling: safe\n",
                f"{bearer_prefix} {bearer_suffix}",
                bearer_prefix + bearer_suffix,
                "    sibling: safe",
            ),
        )
        for label, source, decoded, privacy_value, boundary in cases:
            with self.subTest(label=label):
                self.assertEqual(MODULE.bootstrap_v2_privacy_risk_lines(source), [])
                self.assertTrue(MODULE.bootstrap_v2_privacy_risk_lines(privacy_value))
                block_tokens = [
                    token
                    for token in MODULE.bootstrap_v2_yaml_tokens(source)
                    if token.scan_value is not None
                ]
                self.assertEqual(
                    [(token.value, token.scan_value) for token in block_tokens],
                    [(decoded, privacy_value)],
                )
                self.assertLessEqual(block_tokens[0].end, source.index(boundary))
                risky_lines = MODULE.bootstrap_v2_privacy_risk_lines(
                    source,
                    relative=Path(".github/workflows/ci.yml"),
                )
                self.assertTrue(
                    any(
                        line.startswith("yaml_block_scalar_sha256:")
                        for line in risky_lines
                    )
                )

    def test_bootstrap_v2_unreliable_block_scalar_headers_fail_closed(self) -> None:
        cases = (
            "run: | invalid\n  safe\n",
            "run: !!str !!str >-\n  safe\n",
            "run: &first &second >-\n  safe\n",
        )
        for source in cases:
            with self.subTest(source=source.splitlines()[0]):
                tokens = MODULE.bootstrap_v2_yaml_tokens(source)
                self.assertTrue(
                    any(token.kind == "invalid_block_scalar" for token in tokens)
                )
                risky_lines = MODULE.bootstrap_v2_privacy_risk_lines(
                    source,
                    relative=Path(".github/workflows/ci.yml"),
                )
                self.assertTrue(
                    any(
                        line.startswith("yaml_block_scalar_invalid_sha256:")
                        for line in risky_lines
                    )
                )
                self.assertTrue(
                    MODULE.contains_bootstrap_v2_privacy_risk_text(
                        source,
                        relative=Path(".github/workflows/ci.yml"),
                    )
                )

    def test_bootstrap_v2_compact_block_scalars_scan_siblings_and_stay_linear(
        self,
    ) -> None:
        sibling_workflow = synthetic_workflow_with_step(
            "      - run: |+\n"
            "          printf '%s\\n' safe\n"
            "        env:\n"
            '          value: "\\u0067\\u0068\\u0070\\u005fABCDEFGHIJKLMNOP"\n'
        )
        self.assertTrue(
            MODULE.contains_bootstrap_v2_privacy_risk_text(
                sibling_workflow,
                relative=Path(".github/workflows/ci.yml"),
            )
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_bootstrap_v2_candidate(root)
            (root / ".github/workflows/ci.yml").write_text(
                sibling_workflow,
                encoding="utf-8",
            )
            issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))
        self.assertIn("infrastructure text contains raw/sensitive evidence", issues)

        header = "      - run: >2-\n"
        content = "          printf '%s\\n' safe\n"
        trailer = "        env: safe\n"
        content_count = (
            MODULE.BOOTSTRAP_V2_MAX_FILE_BYTES
            - len(header.encode("utf-8"))
            - len(trailer.encode("utf-8"))
        ) // len(content.encode("utf-8"))
        source = header + (content * content_count) + trailer
        self.assertLessEqual(
            len(source.encode("utf-8")), MODULE.BOOTSTRAP_V2_MAX_FILE_BYTES
        )

        operation_counts: dict[str, int] = {}
        tokens = MODULE.bootstrap_v2_yaml_tokens(
            source,
            operation_counts=operation_counts,
        )

        self.assertEqual(
            tuple((token.kind, token.value) for token in tokens[-3:]),
            (("scalar", "env"), ("punctuation", ":"), ("scalar", "safe")),
        )
        self.assertEqual(operation_counts["line_prefix_characters"], len(source))
        self.assertEqual(operation_counts["block_scalar_context_checks"], 1)
        self.assertLessEqual(
            operation_counts["block_scalar_content_characters"], len(source)
        )
        self.assertLessEqual(
            operation_counts["block_scalar_line_checks"], content_count + 1
        )
        self.assertLessEqual(
            operation_counts["block_scalar_decoded_characters"], 2 * len(source)
        )

    def test_bootstrap_v2_block_scalar_values_decode_and_scan_privacy_risk(
        self,
    ) -> None:
        credential_prefix = "api_"
        credential_suffix = "key = value"
        bearer_prefix = "Bea"
        bearer_suffix = "rer "
        bearer_value = "AbCdEfGhIjKlMnOp"
        url_prefix = "https://internal."
        url_suffix = "example"
        risk_fingerprints: list[str] = []
        cases = (
            (
                "literal credential",
                "      - run: |-\n"
                f"          {credential_prefix}\n"
                f"          {credential_suffix}\n",
                f"{credential_prefix}\n{credential_suffix}",
                f"{credential_prefix}\n{credential_suffix}",
            ),
            (
                "folded credential",
                "      - run: >-\n"
                f"          {credential_prefix}\n"
                f"          {credential_suffix}\n",
                f"{credential_prefix} {credential_suffix}",
                f"{credential_prefix}{credential_suffix}",
            ),
            (
                "folded bearer",
                "      - run: >-\n"
                f"          {bearer_prefix}\n"
                f"          {bearer_suffix}{bearer_value}\n",
                f"{bearer_prefix} {bearer_suffix}{bearer_value}",
                f"{bearer_prefix}{bearer_suffix}{bearer_value}",
            ),
            (
                "folded internal URL",
                f"      - run: >2-\n          {url_prefix}\n          {url_suffix}\n",
                f"{url_prefix} {url_suffix}",
                f"{url_prefix}{url_suffix}",
            ),
        )
        for label, step, decoded, privacy_value in cases:
            with self.subTest(label=label):
                workflow = synthetic_workflow_with_step(step)
                block_values = [
                    token
                    for token in MODULE.bootstrap_v2_yaml_tokens(workflow)
                    if token.scan_value is not None
                ]
                self.assertEqual(
                    [(token.value, token.scan_value) for token in block_values],
                    [(decoded, privacy_value)],
                )
                risky_lines = MODULE.bootstrap_v2_privacy_risk_lines(
                    workflow,
                    relative=Path(".github/workflows/ci.yml"),
                )
                self.assertTrue(risky_lines[-1].startswith("yaml_block_scalar_sha256:"))
                risk_fingerprints.append(
                    MODULE.bootstrap_v2_privacy_risk_lines_fingerprint(risky_lines)
                )
                self.assertTrue(
                    MODULE.contains_bootstrap_v2_privacy_risk_text(
                        workflow,
                        relative=Path(".github/workflows/ci.yml"),
                    )
                )
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    workflow_path = root / ".github/workflows/ci.yml"
                    workflow_path.write_text(workflow, encoding="utf-8")

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(
                    "infrastructure text contains raw/sensitive evidence", issues
                )
        self.assertEqual(len(set(risk_fingerprints)), len(cases))

    def test_bootstrap_v2_block_scalar_chomping_and_blank_lines(self) -> None:
        cases = (
            ("clip", "|", "  safe\n\n\n", "safe\n"),
            ("strip", "|-", "  safe\n\n\n", "safe"),
            ("keep", "|+", "  safe\n\n\n", "safe\n\n\n"),
            ("folded blank", ">-", "  safe\n\n  next\n", "safe\nnext"),
            ("folded keep", ">+", "  safe\n\n\n", "safe\n\n\n"),
            ("literal all blank", "|+", "\n\n", "\n\n"),
            ("folded all blank", ">+", "\n\n", "\n\n"),
            ("folded leading blank", ">-", "\n  safe\n", "\nsafe"),
        )
        for label, header, content, expected in cases:
            with self.subTest(label=label):
                source = f"run: {header}\n{content}sibling: value\n"
                block_values = [
                    token.value
                    for token in MODULE.bootstrap_v2_yaml_tokens(source)
                    if token.scan_value is not None
                ]
                self.assertEqual(block_values, [expected])

    def test_bootstrap_v2_unclosed_flow_items_are_precomputed_in_linear_work(
        self,
    ) -> None:
        prefix = synthetic_workflow_with_step("")
        item = "      - {name: SyntheticItem\n"
        item_count = (
            MODULE.BOOTSTRAP_V2_MAX_FILE_BYTES - len(prefix.encode("utf-8"))
        ) // len(item.encode("utf-8"))
        workflow = prefix + (item * item_count)
        workflow_size = len(workflow.encode("utf-8"))
        self.assertLessEqual(workflow_size, MODULE.BOOTSTRAP_V2_MAX_FILE_BYTES)
        self.assertGreater(
            workflow_size,
            MODULE.BOOTSTRAP_V2_MAX_FILE_BYTES - len(item.encode("utf-8")),
        )

        class SyntheticLexeme:
            def __init__(self, start: int) -> None:
                self.kind = "punctuation"
                self.value = "{"
                self.start = start
                self.end = start + 1

        class CountingLexemes(list):
            def __init__(self, values: list[object]) -> None:
                super().__init__(values)
                self.iteration_count = 0
                self.lookup_count = 0

            def __iter__(self) -> object:
                for lexeme in super().__iter__():
                    self.iteration_count += 1
                    yield lexeme

            def __getitem__(self, index: int | slice) -> object:
                self.lookup_count += 1
                return super().__getitem__(index)

        lexemes = CountingLexemes(
            [SyntheticLexeme(index) for index in range(item_count)]
        )
        flow_mappings = MODULE.bootstrap_v2_yaml_flow_mappings(lexemes)

        self.assertEqual(flow_mappings, {})
        self.assertEqual(lexemes.iteration_count, len(lexemes))
        self.assertLessEqual(lexemes.lookup_count, len(lexemes))

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_bootstrap_v2_candidate(root)
            (root / ".github/workflows/ci.yml").write_text(
                workflow,
                encoding="utf-8",
            )

            issues = validate_synthetic_bootstrap_v2_candidate(root)

        self.assertEqual(issues, [])

    def test_bootstrap_v2_workflows_reject_non_step_uses_hash_exemptions(self) -> None:
        ref40 = "a" * 40
        ref64 = "b" * 64
        cases = (
            (
                "root env",
                "name: CI\n"
                "on: {}\n"
                "permissions: {}\n"
                "env:\n"
                f"  uses: owner/action@{ref40}\n"
                "jobs: {}\n",
            ),
            (
                "job env",
                "name: CI\n"
                "on: {}\n"
                "permissions: {}\n"
                "jobs:\n"
                "  test:\n"
                "    runs-on: ubuntu-latest\n"
                "    env:\n"
                f"      uses: owner/action@{ref64}\n"
                "    steps:\n"
                '      - run: "true"\n',
            ),
            (
                "matrix include",
                "name: CI\n"
                "on: {}\n"
                "permissions: {}\n"
                "jobs:\n"
                "  test:\n"
                "    strategy:\n"
                "      matrix:\n"
                "        include:\n"
                f"          - uses: owner/action@{ref40}\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                '      - run: "true"\n',
            ),
            (
                "job outputs",
                "name: CI\n"
                "on: {}\n"
                "permissions: {}\n"
                "jobs:\n"
                "  test:\n"
                "    outputs:\n"
                f"      uses: owner/action@{ref64}\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                '      - run: "true"\n',
            ),
            (
                "nested step mapping",
                synthetic_workflow_with_step(
                    "      - name: Synthetic\n"
                    "        with:\n"
                    f"          uses: owner/action@{ref40}\n"
                    '        run: "true"\n'
                ),
            ),
            (
                "nested flow mapping",
                synthetic_workflow_with_step(
                    '      - {env: {uses: "owner/action@' + ref64 + '"}, run: "true"}\n'
                ),
            ),
            (
                "duplicate step key",
                synthetic_workflow_with_step(
                    f"      - uses: owner/action@{ref40}\n"
                    f"        uses: owner/action@{ref64}\n"
                ),
            ),
        )
        for label, workflow in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    (root / ".github/workflows/ci.yml").write_text(
                        workflow,
                        encoding="utf-8",
                    )

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(
                    "infrastructure text contains raw/sensitive evidence", issues
                )

    def test_bootstrap_v2_workflows_reject_yaml_anchors_and_aliases(self) -> None:
        immutable_ref = "a" * 40
        cases = (
            (
                "alias as uses key",
                '      - &uses_key "uses": "owner/action@' + immutable_ref + '"\n'
                '        *uses_key: "docker://alpine:latest"\n',
            ),
            (
                "mapping anchor",
                "      - &shared_step\n"
                '        name: "Synthetic"\n'
                '        run: "true"\n',
            ),
            (
                "merge alias",
                "      - &shared_step\n"
                '        name: "Synthetic"\n'
                '        run: "true"\n'
                "      - <<: *shared_step\n",
            ),
            (
                "anchored uses value",
                '      - uses: &action "owner/action@' + immutable_ref + '"\n',
            ),
        )
        for label, probe in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    workflow = synthetic_workflow_with_step(probe)
                    (root / ".github/workflows/ci.yml").write_text(
                        workflow,
                        encoding="utf-8",
                    )

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertTrue(
                    MODULE.bootstrap_v2_workflow_has_yaml_anchors_or_aliases(workflow)
                )
                self.assertIn(
                    "infrastructure text contains raw/sensitive evidence", issues
                )

    def test_bootstrap_v2_workflows_reject_all_yaml_tags(self) -> None:
        relative = Path(".github/workflows/ci.yml")
        cases = (
            ("non-specific mapping tag", "value: ! safe\n"),
            ("standard mapping tag", "value: !!str safe\n"),
            ("custom mapping tag", "value: !private safe\n"),
            (
                "verbatim tag after quoted key",
                '"value:key": !<tag:yaml.org,2002:str> safe\n',
            ),
            ("binary block", "payload: !!binary |-\n  c2FmZQ==\n"),
            ("binary flow", 'payload: !!binary "c2FmZQ=="\n'),
            ("sequence tag", "items:\n  - !!str safe\n"),
            (
                "tag and anchor sequence mapping",
                "items:\n  - value: !private &shared safe\n",
            ),
            (
                "anchor and tag block mapping",
                "value: &shared !!binary >-\n  c2FmZQ==\n",
            ),
        )
        for label, source in cases:
            with self.subTest(label=label):
                self.assertTrue(MODULE.bootstrap_v2_workflow_has_yaml_tags(source))
                self.assertTrue(
                    MODULE.contains_bootstrap_v2_privacy_risk_text(
                        source,
                        relative=relative,
                    )
                )

        workflow_cases = (
            '      - run: !!binary "c2FmZQ=="\n',
            "      - !!str safe\n",
            '      - "run:key": !private >-\n          safe\n',
        )
        for probe in workflow_cases:
            with self.subTest(workflow=probe.splitlines()[0]):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    workflow = synthetic_workflow_with_step(probe)
                    (root / relative).write_text(workflow, encoding="utf-8")

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(
                    "infrastructure text contains raw/sensitive evidence", issues
                )

        benign = (
            'value: "Literal !!binary and !private"\n',
            "value: safe # !!binary !private\n",
            "value: value!!binary\n",
            "run: |-\n  printf '%s\\n' '!!binary !private'\n",
        )
        for source in benign:
            with self.subTest(benign=source.splitlines()[0]):
                self.assertFalse(MODULE.bootstrap_v2_workflow_has_yaml_tags(source))
                self.assertFalse(
                    MODULE.contains_bootstrap_v2_privacy_risk_text(
                        source,
                        relative=relative,
                    )
                )

    def test_bootstrap_v2_workflows_allow_literal_anchor_alias_characters(self) -> None:
        probes = (
            '      - name: "Literal &anchor and *alias"\n        run: "true"\n',
            "      - name: R&D wildcard*literal # &anchor *alias\n"
            '        run: "true"\n',
            "      - name: Shell glob\n"
            "        run: |\n"
            "          printf '%s\\n' '&anchor *alias' *.py\n",
            "      - |\n        &anchor *alias\n",
        )
        for probe in probes:
            with self.subTest(probe=probe[:40]):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    workflow = synthetic_workflow_with_step(probe)
                    (root / ".github/workflows/ci.yml").write_text(
                        workflow,
                        encoding="utf-8",
                    )

                    issues = validate_synthetic_bootstrap_v2_candidate(root)

                self.assertFalse(
                    MODULE.bootstrap_v2_workflow_has_yaml_anchors_or_aliases(workflow)
                )
                self.assertEqual(issues, [])

    def test_bootstrap_v2_workflows_reject_cr_and_mixed_newline_bypasses(self) -> None:
        immutable_ref = "a" * 40
        cases = (
            (
                "cr-only docker uses",
                synthetic_workflow_with_step(
                    "      # Synthetic comment\n      - uses: docker://alpine:latest\n"
                ).replace("\n", "\r"),
                False,
            ),
            (
                "cr-only local uses",
                synthetic_workflow_with_step(
                    "      # Synthetic comment\n      - uses: ./local-action\n"
                ).replace("\n", "\r"),
                False,
            ),
            (
                "cr-only anchor",
                synthetic_workflow_with_step(
                    "      # Synthetic comment\n"
                    "      - &shared_step\n"
                    '        run: "true"\n'
                ).replace("\n", "\r"),
                True,
            ),
            (
                "cr-only alias as uses key",
                synthetic_workflow_with_step(
                    "      # Synthetic comment\n"
                    '      - &uses_key "uses": "owner/action@' + immutable_ref + '"\n'
                    '        *uses_key: "./local-action"\n'
                ).replace("\n", "\r"),
                True,
            ),
            (
                "mixed local uses",
                synthetic_workflow_with_step(
                    "      # Synthetic comment\r      - uses: ./local-action\r\n"
                ),
                False,
            ),
        )
        for label, workflow, has_references in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    (root / ".github/workflows/ci.yml").write_text(
                        workflow,
                        encoding="utf-8",
                    )

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertEqual(
                    MODULE.bootstrap_v2_workflow_has_yaml_anchors_or_aliases(workflow),
                    has_references,
                )
                self.assertIn(
                    "infrastructure text contains raw/sensitive evidence", issues
                )

    def test_bootstrap_v2_workflows_allow_benign_cr_and_mixed_newlines(self) -> None:
        immutable_ref = "a" * 40
        workflows = (
            synthetic_workflow_with_step(
                "      # Synthetic comment\n"
                '      - uses: "owner/action@' + immutable_ref + '"\n'
            ).replace("\n", "\r"),
            synthetic_workflow_with_step(
                '      - name: "Literal &anchor and *alias"\n'
                '        run: "true" # &comment *text\n'
            ).replace("\n", "\r\n"),
            synthetic_workflow_with_step(
                "      - name: Mixed newlines\r"
                "        run: |\r\n"
                "          printf '%s\\n' '&anchor *alias uses: ./local-action'\n"
            ),
        )
        for workflow in workflows:
            with self.subTest(workflow=workflow[:40]):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    (root / ".github/workflows/ci.yml").write_text(
                        workflow,
                        encoding="utf-8",
                    )

                    issues = validate_synthetic_bootstrap_v2_candidate(root)

                self.assertFalse(
                    MODULE.bootstrap_v2_workflow_has_yaml_anchors_or_aliases(workflow)
                )
                self.assertEqual(issues, [])

    def test_bootstrap_v2_decoded_workflow_scalars_accept_exact_pinned_actions(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_bootstrap_v2_candidate(root)
            encoded_ref = "\\u0061" + ("a" * 39)
            probe = '      - uses: "owner/action\\u0040' + encoded_ref + '"\n'
            (root / ".github/workflows/ci.yml").write_text(
                synthetic_workflow_with_step(probe),
                encoding="utf-8",
            )

            self.assertEqual(validate_synthetic_bootstrap_v2_candidate(root), [])

    def test_bootstrap_v2_decoded_json_rejects_adjacent_sensitive_forms(self) -> None:
        schema_path = Path("schemas/retained-manifest-v2.schema.json")
        immutable_action_ref = "a" * 40
        cases = (
            ("single-label internal email", "operator" + "\\u0040" + "corp"),
            (
                "sentence-final single-label internal email",
                "operator" + "\\u0040" + "corp\\u002e",
            ),
            (
                "slash-prefixed single-label internal email",
                "\\u002foperator" + "\\u0040" + "corp",
            ),
            ("home arpa domain", "service" + "\\u002ehome\\u002earpa"),
            ("srv path", "\\u002fsrv\\u002fprivate\\u002freport"),
            (
                "repeated-slash srv path",
                "\\u002fsrv\\u002f\\u002fprivate\\u002freport",
            ),
            ("cloud access key", "AK" + "\\u0049A" + ("A" * 16)),
            ("temporary cloud access key", "AS" + "\\u0049A" + ("B" * 16)),
            ("legacy cloud access key", "A3" + "\\u0054" + ("C" * 17)),
            (
                "action-like internal email",
                "owner\\u002foperator" + "\\u0040" + "corp",
            ),
            (
                "action-like version email",
                "owner\\u002foperator" + "\\u0040" + "v4",
            ),
            (
                "immutable uses string",
                "uses\\u003a owner\\u002faction\\u0040" + immutable_action_ref,
            ),
            (
                "long action-like email",
                "owner\\u002foperator\\u0040v4\\u002fprivate",
            ),
            (
                "multilabel internal email",
                "operator\\u0040corp\\u002ex",
            ),
            (
                "action access key",
                "owner\\u002faction\\u0040AK" + "\\u0049A" + ("A" * 16),
            ),
            (
                "action home arpa",
                "owner\\u002faction\\u0040service" + "\\u002ehome\\u002earpa",
            ),
        )
        for label, encoded_probe in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    schema_text = (
                        '{"$schema":'
                        + json.dumps(MODULE.BOOTSTRAP_V2_JSON_SCHEMA_DIALECT)
                        + ',"probe":"'
                        + encoded_probe
                        + '"}\n'
                    )
                    self.assertFalse(
                        MODULE.contains_bootstrap_v2_privacy_risk_text(
                            schema_text,
                            relative=schema_path,
                        )
                    )
                    (root / schema_path).write_text(schema_text, encoding="utf-8")

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(
                    "infrastructure text contains raw/sensitive evidence", issues
                )

    def test_bootstrap_v2_accepts_harmless_prose_and_route_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_bootstrap_v2_candidate(root)
            with (root / "README.md").open("a", encoding="utf-8") as stream:
                stream.write(
                    "Documentation uses docs/reports, input/output, and /api/v1.\n"
                )
            (root / ".github/workflows/ci.yml").write_text(
                synthetic_workflow_with_step(
                    "      - uses: owner/action" + "@" + ("a" * 40) + "\n"
                ),
                encoding="utf-8",
            )

            self.assertEqual(validate_synthetic_bootstrap_v2_candidate(root), [])

    def test_bootstrap_v2_test_files_reject_credential_ipv6_and_bearer_bypasses(
        self,
    ) -> None:
        cases = (
            ("credential assignment", "api_" + 'key = "abc"\n'),
            (
                "private IPv6",
                'endpoint = "http://[' + risky_private_ipv6() + ']/status"\n',
            ),
            (
                "Bearer value",
                "author" + 'ization = "Bea' + "rer " + risky_secret_token() + '"\n',
            ),
        )
        for label, probe in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    candidate_test = root / "tests" / "test_retrospective_history_v2.py"
                    candidate_test.write_text(probe, encoding="utf-8")

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(
                    "infrastructure text contains raw/sensitive evidence", issues
                )

    def test_bootstrap_v2_python_ast_rejects_interpreted_sensitive_strings(
        self,
    ) -> None:
        relative = Path("tests/test_retrospective_history_v2.py")
        cases = (
            (
                "implicit adjacent token",
                'value = (\n    "ghp_"\n    "ABCDEFGHIJKLMNOP"\n)\n',
            ),
            (
                "same-line adjacent bearer",
                'value = ("Bea" "rer " "AbCdEfGhIjKlMnOp")\n',
            ),
            (
                "hex escaped token",
                'value = "\\x67\\x68\\x70\\x5fABCDEFGHIJKLMNOP"\n',
            ),
            (
                "hex escaped bytes token",
                'value = b"\\x67\\x68\\x70\\x5fABCDEFGHIJKLMNOP"\n',
            ),
            (
                "implicit adjacent bytes token",
                'value = (\n    b"ghp_"\n    b"ABCDEFGHIJKLMNOP"\n)\n',
            ),
            (
                "same-line adjacent bytes bearer",
                'value = (b"Bea" b"rer " b"AbCdEfGhIjKlMnOp")\n',
            ),
            (
                "explicit string addition",
                'value = "ghp_" + "ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "explicit bytes addition",
                'value = b"ghp_" + b"ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "nested string addition",
                'value = (("g" + "hp_") + ("ABCDEFGH" + "IJKLMNOP"))\n',
            ),
            (
                "nested bytes addition",
                'value = ((b"g" + b"hp_") + (b"ABCDEFGH" + b"IJKLMNOP"))\n',
            ),
            (
                "string tuple join",
                'value = "".join(("ghp_", "ABCDEFGHIJKLMNOP"))\n',
            ),
            (
                "string list join",
                'value = "".join(["ghp_", "ABCDEFGHIJKLMNOP"])\n',
            ),
            (
                "bytes tuple join",
                'value = b"".join((b"ghp_", b"ABCDEFGHIJKLMNOP"))\n',
            ),
            (
                "bytes list join",
                'value = b"".join([b"ghp_", b"ABCDEFGHIJKLMNOP"])\n',
            ),
            (
                "nested string tuple join",
                'value = "".join(("ghp_", "".join(("ABCDEFGH", "IJKLMNOP"))))\n',
            ),
            (
                "composed string join receiver",
                'value = "".join(("",)).join(("ghp_", "ABCDEFGHIJKLMNOP"))\n',
            ),
            (
                "literal separator binding",
                'SEP = ""\nvalue = SEP.join(("ghp_", "ABCDEFGHIJKLMNOP"))\n',
            ),
            (
                "literal prefix binding",
                'PREFIX = "ghp_"\nvalue = PREFIX + "ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "constant f-string",
                "value = f\"{'ghp_'}{'ABCDEFGHIJKLMNOP'}\"\n",
            ),
            (
                "constant f-string around dynamic expression",
                "middle = get_middle()\n"
                "value = f\"{'ghp_'}{middle}{'ABCDEFGHIJKLMNOP'}\"\n",
            ),
            (
                "percent formatting",
                'value = "%s%s" % ("ghp_", "ABCDEFGHIJKLMNOP")\n',
            ),
            (
                "bytes percent formatting",
                'value = b"%s%s" % (b"ghp_", b"ABCDEFGHIJKLMNOP")\n',
            ),
            (
                "dot formatting",
                'value = "{}{}".format("ghp_", "ABCDEFGHIJKLMNOP")\n',
            ),
            (
                "starred dot formatting",
                'value = "{}{}".format(*("ghp_", "ABCDEFGHIJKLMNOP"))\n',
            ),
            (
                "format map",
                'value = "{prefix}{suffix}".format_map('
                '{"prefix": "ghp_", "suffix": "ABCDEFGHIJKLMNOP"})\n',
            ),
            (
                "multiline continued token",
                'value = """ghp_\\\nABCDEFGHIJKLMNOP"""\n',
            ),
            (
                "multiline continued credential",
                'value = """api_\\\nkey = abc"""\n',
            ),
        )
        for label, probe in cases:
            with self.subTest(label=label):
                self.assertFalse(
                    MODULE.contains_bootstrap_v2_privacy_risk_text(
                        probe,
                        relative=relative,
                    )
                )
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    (root / relative).write_text(probe, encoding="utf-8")

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(
                    "infrastructure text contains raw/sensitive evidence", issues
                )

    def test_bootstrap_v2_python_ast_accepts_benign_interpreted_strings(self) -> None:
        relative = Path("tests/test_retrospective_history_v2.py")
        probes = (
            'value = ("public " "summary")\n',
            'value = """Harmless multiline\nsummary."""\n',
            'value = """public\\\nsummary"""\n',
            'value = b"public summary"\n',
            'value = (b"public " b"summary")\n',
            'value = "caf\\u00e9"\npayload = b"caf\\xc3\\xa9"\n',
            'value = "public " + "summary"\n',
            'value = b"public " + b"summary"\n',
            'value = (("public" + " ") + ("sum" + "mary"))\n',
            "value = f\"{'public '}{'summary'}\"\n",
            'value = "%s%s" % ("public ", "summary")\n',
            'value = b"%s%s" % (b"public ", b"summary")\n',
            'value = "{}{}".format("public ", "summary")\n',
            'value = "{prefix}{suffix}".format_map('
            '{"prefix": "public ", "suffix": "summary"})\n',
            'value = " ".join(("public", "summary"))\n',
            'value = b" ".join([b"public", b"summary"])\n',
            'value = "".join(("public ", "".join(("sum", "mary"))))\n',
            'value = b"".join((b"public ", b"".join((b"sum", b"mary"))))\n',
            'value = "".join(("",)).join(("public", "summary"))\n',
            'value = b"".join((b"",)).join((b"public", b"summary"))\n',
            'SEP = ""\nvalue = SEP.join(("public ", "summary"))\n',
        )
        for probe in probes:
            with self.subTest(probe=probe[:40]):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    (root / relative).write_text(probe, encoding="utf-8")

                    issues = validate_synthetic_bootstrap_v2_candidate(root)

                self.assertEqual(issues, [])
                self.assertTrue(MODULE.bootstrap_v2_python_string_constants(probe))

    def test_bootstrap_v2_python_literal_text_transformations_are_scanned(
        self,
    ) -> None:
        relative = Path("tests/test_retrospective_history_v2.py")
        expected = risky_github_classic_token()
        escaped = "".join(f"\\x{value:02x}" for value in expected.encode("ascii"))
        integer_sequence = ", ".join(str(value) for value in expected.encode("ascii"))
        chr_expression = " + ".join(
            f"chr({value})" for value in expected.encode("ascii")
        )
        split_index = len(expected) // 2
        byte_fragment_expressions = tuple(
            "bytes((" + ", ".join(str(value) for value in fragment) + "))"
            for fragment in (
                expected[:split_index].encode("ascii"),
                expected[split_index:].encode("ascii"),
            )
        )
        cases = (
            (
                "replace",
                f'value = {expected.replace("p", "x", 1)!r}.replace("x", "p", 1)\n',
            ),
            (
                "replace across assignments",
                f'seed = {expected.replace("hp", "xy", 1)!r}\n'
                'middle = seed.replace("x", "h")\n'
                'value = middle.replace("y", "p")\n',
            ),
            (
                "reverse slice",
                f"value = {expected[::-1]!r}[::-1]\n",
            ),
            (
                "bound reverse slice",
                f"seed = {expected[::-1]!r}\nvalue = seed[::-1]\n",
            ),
            (
                "translate",
                f'value = {expected.replace("h", "x", 1)!r}.translate('
                'str.maketrans({"x": "h"}))\n',
            ),
            (
                "encode decode",
                f'value = r"{escaped}".encode("ascii").decode("unicode_escape")\n',
            ),
            (
                "fromhex",
                f'value = bytes.fromhex("{expected.encode("ascii").hex()}").decode('
                '"ascii")\n',
            ),
            (
                "bytes iterable",
                f"value = bytes(({integer_sequence})).decode('ascii')\n",
            ),
            (
                "bytearray iterable",
                f"value = bytearray(({integer_sequence})).decode('ascii')\n",
            ),
            (
                "str decode constructor",
                f"value = str(bytes(({integer_sequence})), 'ascii')\n",
            ),
            (
                "chr composition",
                f"value = {chr_expression}\n",
            ),
            (
                "zero-length bytes join",
                "value = bytes(0).join(("
                + ", ".join(byte_fragment_expressions)
                + ")).decode('ascii')\n",
            ),
        )
        for label, source in cases:
            with self.subTest(label=label):
                self.assertFalse(
                    MODULE.contains_bootstrap_v2_privacy_risk_text(
                        source,
                        relative=relative,
                    )
                )
                self.assertIn(
                    expected,
                    MODULE.bootstrap_v2_python_privacy_risk_values(source),
                )
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    (root / relative).write_text(source, encoding="utf-8")

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(
                    "infrastructure text contains raw/sensitive evidence",
                    issues,
                )

        opaque_hex = (bytes((0xFF, 0x20)) + expected.encode("ascii")).hex()
        opaque_byte_sources = (
            f'value = bytes.fromhex("{opaque_hex}")\n',
            f'value = [bytes.fromhex("{opaque_hex}")]\n',
        )
        for source in opaque_byte_sources:
            with self.subTest(opaque_bytes=source[:40]):
                risky_values = MODULE.bootstrap_v2_python_privacy_risk_values(source)
                self.assertTrue(any(expected in value for value in risky_values))
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    (root / relative).write_text(source, encoding="utf-8")

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(
                    "infrastructure text contains raw/sensitive evidence",
                    issues,
                )

    def test_bootstrap_v2_python_literal_text_transformations_accept_benign_values(
        self,
    ) -> None:
        cases = (
            ('value = "pxblic".replace("x", "u")\n', "public"),
            (
                'seed = "pxblic"\n'
                'middle = seed.replace("x", "u")\n'
                'value = middle.upper().lower()\n',
                "public",
            ),
            ('value = "cilbup"[::-1]\n', "public"),
            (
                'value = "pxblic".translate(str.maketrans({"x": "u"}))\n',
                "public",
            ),
            (
                'value = r"\\x70\\x75\\x62\\x6c\\x69\\x63".encode('
                '"ascii").decode("unicode_escape")\n',
                "public",
            ),
            ('value = bytes.fromhex("7075626c6963").decode("ascii")\n', "public"),
            ('value = bytes((112, 117, 98, 108, 105, 99)).decode("ascii")\n', "public"),
            (
                'value = bytearray((112, 117, 98, 108, 105, 99)).decode("ascii")\n',
                "public",
            ),
            (
                'value = chr(112) + chr(117) + chr(98) + chr(108) + chr(105) + chr(99)\n',
                "public",
            ),
            (
                'value = bytes(0).join((b"pub", b"lic")).decode("ascii")\n',
                "public",
            ),
        )
        for source, expected in cases:
            with self.subTest(source=source):
                constants = MODULE.bootstrap_v2_python_string_constants(source)
                self.assertIn(expected, constants)
                self.assertEqual(
                    MODULE.bootstrap_v2_python_privacy_risk_values(source),
                    [],
                )

        self.assertEqual(
            MODULE.bootstrap_v2_python_privacy_risk_values(
                'value = bytes.fromhex("ff207075626c6963")\n'
            ),
            [],
        )

    def test_bootstrap_v2_python_literal_text_transformations_fail_closed(
        self,
    ) -> None:
        self.assert_python_privacy_layers_reject(
            'value = "g%s_ABCDEFGHIJKLMNOP".__mod__("hp")\n',
            "text method is outside the trusted policy",
        )

        self.assert_python_privacy_layers_reject(
            'seed = "gxy_ABCDEFGHIJKLMNOP"\n'
            'if enabled:\n'
            '    middle = seed.replace("x", "h")\n'
            'else:\n'
            '    middle = seed\n'
            'alias = middle\n'
            'value = alias.replace("y", "p")\n',
            "string construction depends on an ambiguous name binding",
        )

        with mock.patch.object(
            MODULE,
            "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_BYTES",
            10,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "ambiguous text method results exceed the trusted byte limit",
            ):
                MODULE.bootstrap_v2_python_string_constants(
                    'if enabled:\n'
                    '    middle = "aaaa"\n'
                    'else:\n'
                    '    middle = "bbbb"\n'
                    'value = middle.replace("a", "cc")\n'
                )

        with self.assertRaisesRegex(ValueError, "codec is outside the trusted allowlist"):
            MODULE.bootstrap_v2_python_string_constants(
                'value = "public".encode("rot_13")\n'
            )

        self.assert_python_privacy_layers_reject(
            'payload = bytearray((112, 117, 98, 108, 105, 99))\n'
            'payload.extend((33,))\n'
            'value = payload.decode("ascii")\n',
            "bytearray text method uses a mutable aliased receiver",
        )
        self.assert_python_privacy_layers_reject(
            'payload = bytearray((112, 117, 98, 108, 105, 99))\n'
            "alias = payload\n"
            "alias[0] = 80\n"
            'value = payload.decode("ascii")\n',
            "bytearray text method uses a mutable aliased receiver",
        )
        self.assertEqual(
            MODULE.bootstrap_v2_python_string_constants(
                'changed = bytearray((112, 117, 98))\n'
                "changed.append(33)\n"
                'value = bytearray((112, 117, 98, 108, 105, 99)).decode("ascii")\n'
            )[-1],
            "public",
        )

        with mock.patch.object(
            MODULE,
            "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES",
            8,
        ):
            with self.assertRaisesRegex(ValueError, "replace exceeds"):
                MODULE.bootstrap_v2_python_string_constants(
                    'value = "aaaa".replace("a", "bbbb", count=4)\n'
                )
            with self.assertRaisesRegex(ValueError, "translate exceeds"):
                MODULE.bootstrap_v2_python_string_constants(
                    'value = "xx".translate(str.maketrans({"x": "abcde"}))\n'
                )
            with self.assertRaisesRegex(ValueError, "bytes allocation exceeds"):
                MODULE.bootstrap_v2_python_string_constants("value = bytes(9)\n")

    def test_bootstrap_v2_python_opaque_static_decoders_fail_closed(self) -> None:
        expected = risky_github_classic_token()
        encoded = base64.b64encode(expected.encode("ascii")).decode("ascii")
        encoded_hex = expected.encode("ascii").hex()
        cases = (
            f'import base64\nvalue = base64.b64decode("{encoded}").decode("ascii")\n',
            "from base64 import b64decode as reveal\n"
            f'value = reveal("{encoded}").decode("ascii")\n',
            "import base64\n"
            "reveal = base64.b64decode\n"
            f'value = reveal("{encoded}").decode("ascii")\n',
            f'import binascii\nvalue = binascii.unhexlify("{encoded_hex}").decode("ascii")\n',
            "import codecs\n"
            f'value = codecs.decode("{encoded}", "base64").decode("ascii")\n',
            f'import base64\npayload = base64.b64decode("{encoded}")\n',
            "from codecs import decode as reveal\n"
            f'value = reveal("{encoded}", "base64")\n',
        )
        for source in cases:
            with self.subTest(source=source.splitlines()[-1][:48]):
                self.assert_python_privacy_layers_reject(
                    source,
                    "unresolved binary decoder uses static text input",
                )

        for source in (
            'import base64\nvalue = base64.b64decode(payload).decode("ascii")\n',
            'value = match.group("name").decode("ascii")\n',
            'value = b"public".decode("ascii")\n',
        ):
            with self.subTest(dynamic=source.splitlines()[-1][:48]):
                self.assertEqual(
                    MODULE.bootstrap_v2_python_privacy_risk_values(source),
                    [],
                )

    def test_bootstrap_v2_python_opaque_iterables_fail_closed_without_risk_seeds(
        self,
    ) -> None:
        source = (
            'value = "".join(part for part in ("g", "hp_", "ABCDEFGH", "IJKLMNOP"))\n'
        )

        self.assert_python_privacy_layers_reject(
            source,
            "Python text construction uses an unsupported expression at line 1",
        )

    def test_bootstrap_v2_python_join_rejects_opaque_call_producers(self) -> None:
        codepoints = ", ".join(
            str(ord(character)) for character in risky_github_classic_token()
        )
        cases = (
            'value = "".join(reversed(("IJKLMNOP", "ABCDEFGH", "ghp_")))\n',
            f'value = "".join(map(chr, ({codepoints})))\n',
            f'value = "".join(filter(None, map(chr, ({codepoints}))))\n',
            f'value = "".join(iter(map(chr, ({codepoints}))))\n',
            f'value = "".join(list(map(chr, ({codepoints}))))\n',
            "producer = map\n"
            f"parts = producer(chr, ({codepoints}))\n"
            'value = "".join(parts)\n',
            "def reveal(parts):\n"
            '    return "".join(parts)\n'
            f"value = reveal(map(chr, ({codepoints})))\n",
            "def reveal(parts):\n"
            "    alias = parts\n"
            '    return "".join(alias)\n'
            f"value = reveal(map(chr, ({codepoints})))\n",
        )
        for source in cases:
            with self.subTest(source=source.splitlines()[0]):
                self.assert_python_privacy_layers_reject(
                    source,
                    "Python join uses an unsupported text-producing iterable",
                )

    def test_bootstrap_v2_python_literal_name_bindings_are_bounded_or_rejected(
        self,
    ) -> None:
        self.assertEqual(
            MODULE.BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_BYTES,
            2 * 1024 * 1024,
        )
        source = 'SEP = ""\nvalue = SEP.join(("ghp_", "ABCDEFGHIJKLMNOP"))\n'
        self.assertIn(
            "ghp_ABCDEFGHIJKLMNOP",
            MODULE.bootstrap_v2_python_string_constants(source),
        )

        bounds = (
            (
                "binding evaluated value budget",
                'SEP = "safe"\nvalue = SEP.join(("x", "y"))\n',
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES",
                3,
                "Python evaluated string exceeds the trusted byte limit",
            ),
            (
                "binding evaluated value count budget",
                'SEP = ""\nvalue = SEP.join(("safe", "value"))\n',
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUES",
                1,
                "Python AST exceeds the trusted evaluated value limit",
            ),
            (
                "binding cumulative byte budget",
                'SEP = "abcd"\nvalue = SEP.join(("ef", "gh"))\n',
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_BYTES",
                11,
                "Python AST evaluated strings exceed the trusted byte limit",
            ),
        )
        for label, probe, attribute, limit, expected in bounds:
            with self.subTest(label=label):
                with mock.patch.object(MODULE, attribute, limit):
                    with self.assertRaisesRegex(ValueError, expected):
                        MODULE.bootstrap_v2_python_string_constants(probe)

        rejected = (
            'SEP = ""\nSEP = get_separator()\nvalue = SEP.join(("safe", "value"))\n',
            'if enabled:\n    SEP = ""\nvalue = SEP.join(("safe", "value"))\n',
            'SEP = ""\nif enabled:\n    SEP = "-"\nvalue = SEP.join(("safe", "value"))\n',
        )
        for probe in rejected:
            with self.subTest(probe=probe):
                with self.assertRaisesRegex(
                    ValueError,
                    "string construction depends on an ambiguous name binding",
                ):
                    MODULE.bootstrap_v2_python_string_constants(probe)

    def test_bootstrap_v2_python_annassign_bindings_and_patterns_fail_closed(
        self,
    ) -> None:
        accepted = (
            'SEP: annotation_call() = ""\nvalue = SEP.join(("public ", "summary"))\n',
            'PREFIX: str = "ghp_"\nvalue = PREFIX + "ABCDEFGHIJKLMNOP"\n',
            'SEP = ""\nvalues = [SEP for SEP in ()]\n'
            'value = SEP.join(("public ", "summary"))\n',
        )
        for probe in accepted:
            with self.subTest(accepted=probe[:40]):
                self.assertTrue(MODULE.bootstrap_v2_python_string_constants(probe))

        rejected = (
            (
                "annotation without value",
                'SEP: str\nvalue = SEP.join(("safe", "value"))\n',
            ),
            (
                "annotation nonliteral value",
                'SEP: str = get_separator()\nvalue = SEP.join(("safe", "value"))\n',
            ),
            (
                "annotation complex target",
                'SEP = ""\nSEP[0]: str = ""\nvalue = SEP.join(("safe", "value"))\n',
            ),
            (
                "match as capture",
                'SEP = ""\nmatch subject:\n    case SEP:\n        pass\n'
                'value = SEP.join(("safe", "value"))\n',
            ),
            (
                "match star capture",
                'SEP = ""\nmatch subject:\n    case [*SEP]:\n        pass\n'
                'value = SEP.join(("safe", "value"))\n',
            ),
            (
                "match mapping rest",
                'SEP = ""\nmatch subject:\n    case {"key": _, **SEP}:\n        pass\n'
                'value = SEP.join(("safe", "value"))\n',
            ),
            (
                "nested sequence class capture",
                'SEP = ""\nmatch subject:\n    case [Point(SEP)]:\n        pass\n'
                'value = SEP.join(("safe", "value"))\n',
            ),
            (
                "nested or capture",
                'SEP = ""\nmatch subject:\n'
                '    case ("a" as SEP) | ("b" as SEP):\n        pass\n'
                'value = SEP.join(("safe", "value"))\n',
            ),
            (
                "store target",
                'SEP = ""\nfor SEP in ():\n    pass\n'
                'value = SEP.join(("safe", "value"))\n',
            ),
            (
                "delete target",
                'SEP = ""\ndel SEP\nvalue = SEP.join(("safe", "value"))\n',
            ),
            (
                "walrus target",
                'SEP = ""\nif (SEP := "-"):\n    pass\n'
                'value = SEP.join(("safe", "value"))\n',
            ),
            (
                "import target",
                'SEP = ""\nimport os as SEP\nvalue = SEP.join(("safe", "value"))\n',
            ),
            (
                "definition target",
                'SEP = ""\ndef SEP():\n    pass\nvalue = SEP.join(("safe", "value"))\n',
            ),
        )
        for label, probe in rejected:
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    ValueError,
                    "string construction depends on an ambiguous name binding",
                ):
                    MODULE.bootstrap_v2_python_string_constants(probe)

    def test_bootstrap_v2_python_unsupported_assignments_fail_closed_when_consumed(
        self,
    ) -> None:
        rejected = (
            (
                "conditional expression",
                'PART = "ghp_" if enabled else "public "\n'
                'value = PART + "ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "named starred container",
                'PARTS = (*dynamic_parts, "ghp_", "ABCDEFGHIJKLMNOP")\n'
                'value = "".join(PARTS)\n',
            ),
            (
                "starred assignment target",
                'head, *PARTS = ("public", "ghp_", "ABCDEFGHIJKLMNOP")\n'
                'value = "".join(PARTS)\n',
            ),
        )
        for label, source in rejected:
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    ValueError,
                    "string construction depends on an ambiguous name binding",
                ):
                    MODULE.bootstrap_v2_python_string_constants(source)

        unrelated = (
            'PART = "ghp_" if enabled else "public "\n'
            'head, *PARTS = ("public", "summary")\n'
            "consume(PART, PARTS)\n"
            'value = "public " + "summary"\n'
        )
        self.assertIn(
            "public summary",
            MODULE.bootstrap_v2_python_string_constants(unrelated),
        )

    def test_bootstrap_v2_python_unsupported_rhs_nested_text_seed_fails_closed(
        self,
    ) -> None:
        cases = (
            (
                "subscript",
                'PART = ("ghp_", dynamic)[index]\nvalue = PART + "ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "mapping get",
                'PART = {"selected": "ghp_"}.get(selected)\n'
                'value = PART + "ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "lambda wrapper",
                'PART = (lambda: "ghp_")()\nvalue = PART + "ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "nested call wrappers",
                'SEED = "ghp_"\n'
                "PART = outer(inner(wrapper(SEED)))\n"
                'value = PART + "ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "attribute wrapper",
                'WRAPPER = make_wrapper(value="ghp_")\n'
                "PART = WRAPPER.value\n"
                'value = PART + "ABCDEFGHIJKLMNOP"\n',
            ),
        )
        for label, source in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    ValueError,
                    "string construction depends on an ambiguous name binding",
                ):
                    MODULE.bootstrap_v2_python_string_constants(source)

        non_text = (
            "PART = {0: 1}.get(selected)\n"
            "alias = (lambda: PART)().real\n"
            "value = alias + 2\n"
        )
        self.assertEqual(MODULE.bootstrap_v2_python_string_constants(non_text), [])

    def test_bootstrap_v2_comprehension_namedexpr_targets_bind_outer_scope(
        self,
    ) -> None:
        cases = (
            (
                "module scope",
                'values = [(PART := "ghp_") for item in items]\n'
                'value = PART + "ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "function scope",
                "def reveal(items):\n"
                '    values = [(PART := "ghp_") for item in items]\n'
                '    return PART + "ABCDEFGHIJKLMNOP"\n',
            ),
        )
        for label, source in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    ValueError,
                    "string construction depends on an ambiguous name binding",
                ):
                    MODULE.bootstrap_v2_python_string_constants(source)

        unrelated = (
            'values = [(PART := "public ") for item in items]\n'
            "consume(PART)\n"
            'value = "public " + "summary"\n'
        )
        self.assertIn(
            "public summary",
            MODULE.bootstrap_v2_python_string_constants(unrelated),
        )

    def test_bootstrap_v2_python_ambiguous_binding_dependencies_fail_closed(
        self,
    ) -> None:
        relative = Path("tests/test_retrospective_history_v2.py")
        token_prefix = "ghp_"
        token_suffix = "ABCDEFGHIJKLMNOP"
        bearer_prefix = "Bea"
        bearer_suffix = "rer AbCdEfGhIjKlMnOp"
        url_prefix = "https://internal."
        url_suffix = "example"
        cases = (
            (
                "binary addition after no-value annotation",
                f'PART = "{token_prefix}"\nPART: str\n'
                f'value = PART + "{token_suffix}"\n',
                token_prefix + token_suffix,
            ),
            (
                "f-string after complex annotation",
                f'PART = "{bearer_prefix}"\nPART[0]: str = "safe"\n'
                f'value = f"{{PART}}{bearer_suffix}"\n',
                bearer_prefix + bearer_suffix,
            ),
            (
                "percent formatting after match-as capture",
                f'PART = "{url_prefix}"\nmatch subject:\n    case PART:\n'
                f'        pass\nvalue = "%s%s" % (PART, "{url_suffix}")\n',
                url_prefix + url_suffix,
            ),
            (
                "dot formatting after match-star capture",
                f'PART = "{token_prefix}"\nmatch subject:\n    case [*PART]:\n'
                f'        pass\nvalue = "{{}}{{}}".format(PART, "{token_suffix}")\n',
                token_prefix + token_suffix,
            ),
            (
                "join after match-mapping rest capture",
                f'PART = "{bearer_prefix}"\nmatch subject:\n'
                '    case {"key": _, **PART}:\n'
                f'        pass\nvalue = "".join((PART, "{bearer_suffix}"))\n',
                bearer_prefix + bearer_suffix,
            ),
            (
                "format-map after nested capture",
                f'PART = "{url_prefix}"\nmatch subject:\n'
                "    case [Point(PART)]:\n        pass\n"
                'value = "{left}{right}".format_map('
                f'{{"left": PART, "right": "{url_suffix}"}})\n',
                url_prefix + url_suffix,
            ),
            (
                "nested constructors after rebinding",
                f'PART = "{token_prefix}"\nPART = get_part()\n'
                f'value = "{{}}".format("".join((PART, "{token_suffix}")))\n',
                token_prefix + token_suffix,
            ),
            (
                "binary addition after global rebinding",
                f'PART = "{token_prefix}"\ndef rebind():\n    global PART\n'
                "    PART = get_part()\nrebind()\n"
                f'value = PART + "{token_suffix}"\n',
                token_prefix + token_suffix,
            ),
            (
                "function-local rebinding",
                f'def reveal():\n    PART = "{token_prefix}"\n'
                "    PART = get_part()\n"
                f'    return PART + "{token_suffix}"\n',
                token_prefix + token_suffix,
            ),
            (
                "function-local alias rebinding",
                f'SEED = "{token_prefix}"\ndef reveal():\n    PART = SEED\n'
                "    PART = get_part()\n"
                f'    return PART + "{token_suffix}"\n',
                token_prefix + token_suffix,
            ),
            (
                "closure rebinding",
                f'def outer():\n    PART = "{token_prefix}"\n'
                "    PART = get_part()\n"
                "    def reveal():\n"
                f'        return PART + "{token_suffix}"\n'
                "    return reveal\n",
                token_prefix + token_suffix,
            ),
            (
                "nonlocal rebinding",
                f'def outer():\n    PART = "{token_prefix}"\n'
                "    def rebind():\n"
                "        nonlocal PART\n"
                "        PART = get_part()\n"
                "    def reveal():\n"
                f'        return PART + "{token_suffix}"\n'
                "    return reveal\n",
                token_prefix + token_suffix,
            ),
        )
        for label, source, constructed_value in cases:
            with self.subTest(label=label):
                self.assertFalse(
                    MODULE.contains_bootstrap_v2_privacy_risk_text(
                        source,
                        relative=relative,
                    )
                )
                self.assertTrue(
                    MODULE.bootstrap_v2_privacy_risk_lines(constructed_value)
                )
                with self.assertRaisesRegex(
                    ValueError,
                    "string construction depends on an ambiguous name binding",
                ):
                    MODULE.bootstrap_v2_python_string_constants(source)

        unrelated = (
            'PART = "safe"\nPART = get_part()\nuse(PART)\n'
            'value = "{}".format("public summary")\n'
            'def render(PART):\n    return "{}".format(PART)\n'
            'def combine(PART):\n    return PART.join(("public", "summary"))\n'
        )
        self.assertTrue(MODULE.bootstrap_v2_python_string_constants(unrelated))

    def test_bootstrap_v2_python_ambiguous_binding_diagnostics_hide_identifiers(
        self,
    ) -> None:
        identifier = risky_github_classic_token()
        source = (
            f'{identifier} = "ghp_"\n'
            f"{identifier} = dynamic\n"
            f'value = {identifier} + "ABCDEFGHIJKLMNOP"\n'
        )

        with self.assertRaisesRegex(
            ValueError,
            "Python string construction depends on an ambiguous name binding at line 3",
        ) as raised:
            MODULE.bootstrap_v2_python_string_constants(source)

        self.assertNotIn(identifier, str(raised.exception))

        relative = Path("tests/test_retrospective_history_v2.py")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_bootstrap_v2_candidate(root)
            (root / relative).write_text(source, encoding="utf-8")

            issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

        self.assertIn(
            "Python string construction depends on an ambiguous name binding at line 3",
            issues,
        )
        self.assertNotIn(identifier, issues)

    def test_bootstrap_v2_python_binding_dataflow_propagates_transitively(
        self,
    ) -> None:
        cases = (
            (
                "conditional alias into nested format map",
                'if enabled:\n    ROOT = "ghp_"\nelse:\n    ROOT = dynamic\n'
                "ALIAS = ROOT\n"
                'fields = {"nested": {"prefix": ALIAS, '
                '"suffix": "ABCDEFGHIJKLMNOP"}}\n'
                'value = "{nested[prefix]}{nested[suffix]}".format_map(fields)\n',
            ),
            (
                "cyclic aliases",
                "LEFT = RIGHT\n"
                "if enabled:\n"
                "    RIGHT = LEFT\n"
                "else:\n"
                '    RIGHT = "ghp_"\n'
                'value = LEFT + "ABCDEFGHIJKLMNOP"\n',
            ),
        )
        for label, source in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    ValueError,
                    "string construction depends on an ambiguous name binding",
                ):
                    MODULE.bootstrap_v2_python_string_constants(source)

        non_text_cycle = (
            "LEFT = RIGHT\n"
            "if enabled:\n"
            "    RIGHT = LEFT\n"
            "else:\n"
            "    RIGHT = 1\n"
            "value = LEFT + 2\n"
        )
        self.assertEqual(
            MODULE.bootstrap_v2_python_privacy_risk_values(non_text_cycle),
            [],
        )

    def test_bootstrap_v2_python_text_output_dataflow_scales_with_node_count(
        self,
    ) -> None:
        for scale in (1_000, 4_000):
            with self.subTest(scale=scale):
                source = "".join(
                    f"if enabled_{index}:\n    PART = {index}\n"
                    for index in range(scale)
                ) + "".join(
                    f"value_{index} = PART + {index}\n" for index in range(scale)
                )
                with mock.patch.object(
                    MODULE,
                    "BOOTSTRAP_V2_MAX_PYTHON_TEXT_OUTPUT_OPERATIONS",
                    scale * 64,
                ):
                    self.assertEqual(
                        MODULE.bootstrap_v2_python_privacy_risk_values(source),
                        [],
                    )

        with mock.patch.object(
            MODULE,
            "BOOTSTRAP_V2_MAX_PYTHON_TEXT_OUTPUT_OPERATIONS",
            1,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "text output analysis exceeds the trusted operation limit",
            ):
                MODULE.bootstrap_v2_python_string_constants('value = "a" + "b"\n')

    def test_bootstrap_v2_python_loop_and_match_bindings_propagate_text_seeds(
        self,
    ) -> None:
        cases = (
            (
                "module loop target",
                'for part in [identity("htt")]:\n'
                '    value = part + "ps://internal.example"\n',
            ),
            (
                "supported list literal",
                'for part in ["htt"]:\n    value = part + "ps://internal.example"\n',
            ),
            (
                "function loop target",
                "def reveal():\n"
                '    for part in [identity("ghp_")]:\n'
                '        return part + "ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "module match capture",
                'match identity("Bea"):\n'
                "    case part:\n"
                '        value = part + "rer AbCdEfGhIjKlMnOp"\n',
            ),
            (
                "supported constant match capture",
                'match "Bea":\n'
                "    case part:\n"
                '        value = part + "rer AbCdEfGhIjKlMnOp"\n',
            ),
        )
        for label, source in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    ValueError,
                    "string construction depends on an ambiguous name binding",
                ):
                    MODULE.bootstrap_v2_python_string_constants(source)

    def test_bootstrap_v2_python_tuple_loop_and_match_bindings_fail_closed(
        self,
    ) -> None:
        cases = (
            (
                "tuple loop target",
                'for part in ("ghp_",):\n    value = part + "ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "tuple match capture",
                'match ("ghp_",):\n'
                "    case (part,):\n"
                '        value = part + "ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "computed match capture",
                'match "ghp" + "_":\n'
                "    case part:\n"
                '        value = part + "ABCDEFGHIJKLMNOP"\n',
            ),
        )
        for label, source in cases:
            with self.subTest(label=label):
                self.assert_python_privacy_layers_reject(
                    source,
                    "string construction depends on an ambiguous name binding",
                )

    def test_bootstrap_v2_python_augassign_string_construction_fails_closed(
        self,
    ) -> None:
        source = 'value = "ghp_"\nsuffix = "ABCDEFGHIJKLMNOP"\nvalue += suffix\n'
        with self.assertRaisesRegex(
            ValueError,
            "string construction depends on an ambiguous name binding",
        ):
            MODULE.bootstrap_v2_python_string_constants(source)

        numeric = "value = 1\nsuffix = 2\nvalue += suffix\n"
        self.assertEqual(
            MODULE.bootstrap_v2_python_privacy_risk_values(numeric),
            [],
        )

        subscript = (
            'parts = ["ghp_"]\nsuffix = "ABCDEFGHIJKLMNOP"\nparts[0] += suffix\n'
        )
        with self.assertRaisesRegex(
            ValueError,
            "string construction depends on an ambiguous name binding",
        ):
            MODULE.bootstrap_v2_python_string_constants(subscript)

        numeric_subscript = "parts = [1]\nsuffix = 2\nparts[0] += suffix\n"
        self.assertEqual(
            MODULE.bootstrap_v2_python_privacy_risk_values(numeric_subscript),
            [],
        )

    def test_bootstrap_v2_python_augassign_call_receiver_fails_closed(self) -> None:
        source = (
            '_parts = ["ghp_"]\n'
            "def parts():\n"
            "    return _parts\n"
            'suffix = "ABCDEFGHIJKLMNOP"\n'
            "parts()[0] += suffix\n"
        )
        self.assert_python_privacy_layers_reject(
            source,
            "string construction uses an unresolved augmented assignment receiver",
        )

    def test_bootstrap_v2_python_bound_string_methods_are_constructors(self) -> None:
        cases = (
            (
                'joiner = "".join\n'
                "alias = joiner\n"
                'parts = ("ghp_", "ABCDEFGHIJKLMNOP")\n'
                "value = alias(parts)\n",
                "ghp_ABCDEFGHIJKLMNOP",
            ),
            (
                'formatter = "{}{}".format\n'
                'value = formatter("Bea", "rer AbCdEfGhIjKlMnOp")\n',
                "Bearer AbCdEfGhIjKlMnOp",
            ),
            (
                'mapper = "{left}{right}".format_map\n'
                'fields = {"left": "https://internal.", "right": "example"}\n'
                "value = mapper(fields)\n",
                "https://internal.example",
            ),
            (
                'format_method = "{}{}".format\n'
                "methods = [format_method]\n"
                "formatter = methods[0]\n"
                'value = formatter("ghp_", "ABCDEFGHIJKLMNOP")\n',
                "ghp_ABCDEFGHIJKLMNOP",
            ),
        )
        for source, expected in cases:
            with self.subTest(expected=expected):
                self.assertIn(
                    expected,
                    MODULE.bootstrap_v2_python_string_constants(source),
                )

    def test_bootstrap_v2_python_subscript_selection_matches_runtime(self) -> None:
        relative = Path("tests/test_retrospective_history_v2.py")
        expected = risky_github_classic_token()
        arguments = f"({expected[:4]!r}, {expected[4:]!r})"
        risky_cases = (
            (
                "false list index",
                f'value = ["".join, None][False]({arguments})\n',
            ),
            (
                "true list index",
                f'value = [None, "".join][True]({arguments})\n',
            ),
            (
                "duplicate integer key",
                f'value = {{0: None, 0: "".join}}[0]({arguments})\n',
            ),
            (
                "equivalent boolean and integer keys",
                f'value = {{True: None, 1: "".join}}[True]({arguments})\n',
            ),
            (
                "equivalent integer and boolean keys",
                f'value = {{1: None, True: "".join}}[1]({arguments})\n',
            ),
        )
        for label, source in risky_cases:
            with self.subTest(label=label):
                self.assertFalse(
                    MODULE.contains_bootstrap_v2_privacy_risk_text(
                        source,
                        relative=relative,
                    )
                )
                self.assertIn(
                    expected,
                    MODULE.bootstrap_v2_python_privacy_risk_values(source),
                )
                self.assertTrue(
                    MODULE.contains_bootstrap_v2_python_privacy_risk(
                        source,
                        relative=relative,
                    )
                )

        benign_cases = (
            f'value = {{True: "".join, 1: None}}[True]({arguments})\n',
            f'value = {{0: "".join, 0: None}}[0]({arguments})\n',
        )
        for source in benign_cases:
            with self.subTest(benign=source[:48]):
                self.assertEqual(
                    MODULE.bootstrap_v2_python_privacy_risk_values(source),
                    [],
                )

        unresolved_source = (
            f'value = {{True: None, selector: "".join}}[True]({arguments})\n'
        )
        with self.assertRaisesRegex(
            ValueError,
            "string construction uses an unresolved bound string method",
        ):
            MODULE.bootstrap_v2_python_privacy_risk_values(unresolved_source)

    def test_bootstrap_v2_python_method_selectors_are_conservative(self) -> None:
        expected = risky_github_classic_token()
        arguments = repr(tuple(expected))
        risky_cases = (
            (
                "not false",
                f'value = [None, "".join][not False]({arguments})\n',
                expected,
            ),
            (
                "invert false",
                f'value = [None, "".join][~False]({arguments})\n',
                expected,
            ),
        )
        for label, source, constructed in risky_cases:
            with self.subTest(label=label):
                self.assertIn(
                    constructed,
                    MODULE.bootstrap_v2_python_privacy_risk_values(source),
                )

        benign_cases = (
            f'value = ["".join, None][not False]({arguments})\n',
            f'value = ["".join, None][~False]({arguments})\n',
        )
        for source in benign_cases:
            with self.subTest(benign=source[:48]):
                self.assertEqual(
                    MODULE.bootstrap_v2_python_privacy_risk_values(source),
                    [],
                )

        dynamic_source = (
            f'selector = dynamic\nvalue = [None, "".join][selector]({arguments})\n'
        )
        with self.assertRaisesRegex(
            ValueError,
            "string construction uses an unresolved bound string method",
        ):
            MODULE.bootstrap_v2_python_privacy_risk_values(dynamic_source)

    def test_bootstrap_v2_python_unknown_method_container_wrappers_fail_closed(
        self,
    ) -> None:
        cases = (
            (
                "join",
                'methods = list([None, "".join])\n'
                'value = methods[selector](("ghp_", "ABCDEFGHIJKLMNOP"))\n',
            ),
            (
                "format",
                'methods = list([None, "{}{}".format])\n'
                'value = methods[selector]("ghp_", "ABCDEFGHIJKLMNOP")\n',
            ),
            (
                "format_map",
                'methods = list([None, "{left}{right}".format_map])\n'
                "value = methods[selector]("
                '{"left": "ghp_", "right": "ABCDEFGHIJKLMNOP"})\n',
            ),
        )
        for label, source in cases:
            with self.subTest(label=label):
                self.assert_python_privacy_layers_reject(
                    source,
                    "string construction uses an unresolved bound string method",
                )

    def test_bootstrap_v2_python_method_candidate_selection_is_bounded(
        self,
    ) -> None:
        repetitions = 1_000
        benign_source = "".join(
            f'methods_{index} = [None, "".join]\n'
            f'value_{index} = methods_{index}[1](("public ", "summary"))\n'
            for index in range(repetitions)
        )

        with (
            mock.patch.object(
                MODULE,
                "BOOTSTRAP_V2_MAX_PYTHON_METHOD_SELECTION_STATES",
                repetitions * 3,
            ),
            mock.patch.object(
                MODULE,
                "BOOTSTRAP_V2_MAX_PYTHON_METHOD_SELECTION_OPERATIONS",
                repetitions * 8,
            ),
        ):
            self.assertEqual(
                MODULE.bootstrap_v2_python_privacy_risk_values(benign_source),
                [],
            )

        tiny_fragments = repr(tuple(risky_github_classic_token()))
        adversarial_source = (
            "methods = [None]\n"
            + "".join(
                f'if enabled_{index}:\n    methods = ["".join]\n'
                for index in range(repetitions)
            )
            + "methods = methods[0]\n"
            + f"value = methods[selector]({tiny_fragments})\n"
        )
        with mock.patch.object(
            MODULE,
            "BOOTSTRAP_V2_MAX_PYTHON_METHOD_SELECTION_OPERATIONS",
            repetitions * 2,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "bound string method selection exceeds the trusted operation limit",
            ):
                MODULE.bootstrap_v2_python_privacy_risk_values(adversarial_source)

        with mock.patch.object(
            MODULE,
            "BOOTSTRAP_V2_MAX_PYTHON_METHOD_SELECTION_STATES",
            1,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "bound string method selection exceeds the trusted candidate state limit",
            ):
                MODULE.bootstrap_v2_python_privacy_risk_values(
                    'methods = [None, "".join]\n'
                    f"value = methods[selector]({tiny_fragments})\n"
                )

    def test_bootstrap_v2_python_method_candidate_edges_are_deduplicated(
        self,
    ) -> None:
        repetitions = 8_000
        duplicate_targets = " = ".join("methods" for _ in range(repetitions))
        source = (
            f'{duplicate_targets} = [None, "".join]\n'
            + "".join(
                f"selected_{index} = methods[0]\n" for index in range(repetitions)
            )
            + 'probe = [None, "".join][1](("public ", "summary"))\n'
        )

        with (
            mock.patch.object(
                MODULE,
                "BOOTSTRAP_V2_MAX_PYTHON_METHOD_SELECTION_STATES",
                repetitions * 3,
            ),
            mock.patch.object(
                MODULE,
                "BOOTSTRAP_V2_MAX_PYTHON_METHOD_SELECTION_OPERATIONS",
                repetitions * 5,
            ),
        ):
            self.assertEqual(
                MODULE.bootstrap_v2_python_privacy_risk_values(source),
                [],
            )

    def test_bootstrap_v2_candidate_tree_rejects_method_selectors(self) -> None:
        relative = Path("tests/test_retrospective_history_v2.py")
        expected = risky_github_classic_token()
        arguments = repr(tuple(expected))
        cases = (
            (
                "not false",
                f'value = [None, "".join][not False]({arguments})\n',
                "infrastructure text contains raw/sensitive evidence",
            ),
            (
                "invert false",
                f'value = [None, "".join][~False]({arguments})\n',
                "infrastructure text contains raw/sensitive evidence",
            ),
            (
                "dynamic",
                f'selector = dynamic\nvalue = [None, "".join][selector]({arguments})\n',
                "Python string construction uses an unresolved bound string method",
            ),
        )
        for label, source, expected_issue in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                write_bootstrap_v2_candidate(root)
                (root / relative).write_text(source, encoding="utf-8")

                issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(
                    f"{relative.as_posix()}: {expected_issue}",
                    issues,
                )

        benign_source = f'value = ["".join, None][~False]({arguments})\n'
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_bootstrap_v2_candidate(root)
            (root / relative).write_text(benign_source, encoding="utf-8")

            issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

        self.assertNotIn(relative.as_posix(), issues)

    def test_bootstrap_v2_candidate_tree_rejects_subscript_selected_join(
        self,
    ) -> None:
        relative = Path("tests/test_retrospective_history_v2.py")
        expected = risky_github_classic_token()
        arguments = f"({expected[:4]!r}, {expected[4:]!r})"
        cases = (
            (
                "boolean list index",
                f'value = [None, "".join][True]({arguments})\n',
                "infrastructure text contains raw/sensitive evidence",
            ),
            (
                "equivalent mapping keys",
                f'value = {{True: None, 1: "".join}}[True]({arguments})\n',
                "infrastructure text contains raw/sensitive evidence",
            ),
            (
                "unresolved later mapping key",
                f'value = {{True: None, selector: "".join}}[True]({arguments})\n',
                "Python string construction uses an unresolved bound string method",
            ),
        )
        for label, source, expected_issue in cases:
            with self.subTest(label=label):
                self.assertFalse(
                    MODULE.contains_bootstrap_v2_privacy_risk_text(
                        source,
                        relative=relative,
                    )
                )
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    (root / relative).write_text(source, encoding="utf-8")

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(
                    f"{relative.as_posix()}: {expected_issue}",
                    issues,
                )

    def test_bootstrap_v2_python_ambiguous_method_container_fails_closed(
        self,
    ) -> None:
        source = (
            'methods = ["".join]\n'
            "if enabled:\n"
            "    methods = [print]\n"
            'suffix = "ABCDEFGHIJKLMNOP"\n'
            'value = methods[0](("ghp_", suffix))\n'
        )
        self.assert_python_privacy_layers_reject(
            source,
            "string construction depends on an ambiguous name binding",
        )

    def test_bootstrap_v2_python_ambiguous_method_aliases_fail_closed_without_risk_seeds(
        self,
    ) -> None:
        arguments = repr(tuple(risky_github_classic_token()))
        cases = (
            (
                "multi-binding direct alias",
                "if first:\n"
                '    method = "".join\n'
                "elif second:\n"
                '    method = "{}".format\n'
                "else:\n"
                '    method = "{value}".format_map\n'
                f"value = method({arguments})\n",
                "string construction depends on an ambiguous name binding",
            ),
            (
                "unresolved candidate",
                f'value = {{True: None, selector: "".join}}[True]({arguments})\n',
                "string construction uses an unresolved bound string method",
            ),
        )
        for label, source, expected_issue in cases:
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(
                    ValueError,
                    expected_issue,
                ),
            ):
                MODULE.bootstrap_v2_python_privacy_risk_values(source)

    def test_bootstrap_v2_candidate_tree_rejects_ambiguous_method_aliases_without_risk_seeds(
        self,
    ) -> None:
        relative = Path("tests/test_retrospective_history_v2.py")
        arguments = repr(tuple(risky_github_classic_token()))
        cases = (
            (
                "multi-binding direct alias",
                "if first:\n"
                '    method = "".join\n'
                "elif second:\n"
                '    method = "{}".format\n'
                "else:\n"
                '    method = "{value}".format_map\n'
                f"value = method({arguments})\n",
                "Python string construction depends on an ambiguous name binding",
            ),
            (
                "unresolved candidate",
                f'value = {{True: None, selector: "".join}}[True]({arguments})\n',
                "Python string construction uses an unresolved bound string method",
            ),
        )
        for label, source, expected_issue in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                write_bootstrap_v2_candidate(root)
                (root / relative).write_text(source, encoding="utf-8")

                issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(
                    f"{relative.as_posix()}: {expected_issue}",
                    issues,
                )

    def test_bootstrap_v2_python_definition_time_scopes_are_accurate(self) -> None:
        relative = Path("tests/test_retrospective_history_v2.py")
        cases = (
            (
                "decorator",
                'PART = "ghp_"\n@decorate(PART + "ABCDEFGHIJKLMNOP")\n'
                "def reveal(PART):\n    pass\n",
            ),
            (
                "positional default",
                'PART = "ghp_"\ndef reveal(PART=PART + "ABCDEFGHIJKLMNOP"):\n'
                "    pass\n",
            ),
            (
                "keyword default",
                'PART = "ghp_"\ndef reveal(*, PART=PART + "ABCDEFGHIJKLMNOP"):\n'
                "    pass\n",
            ),
            (
                "parameter annotation",
                'PART = "ghp_"\ndef reveal(PART: PART + "ABCDEFGHIJKLMNOP"):\n'
                "    pass\n",
            ),
            (
                "return annotation",
                'PART = "ghp_"\ndef reveal(PART) -> PART + "ABCDEFGHIJKLMNOP":\n'
                "    pass\n",
            ),
            (
                "lambda default",
                'PART = "ghp_"\nreveal = lambda PART=PART + "ABCDEFGHIJKLMNOP": PART\n',
            ),
            (
                "class base",
                'PART = "ghp_"\nclass Reveal(PART + "ABCDEFGHIJKLMNOP"):\n'
                '    PART = "public "\n',
            ),
            (
                "class keyword",
                'PART = "ghp_"\nclass Reveal(metaclass=PART + "ABCDEFGHIJKLMNOP"):\n'
                '    PART = "public "\n',
            ),
            (
                "comprehension first iterable",
                'PART = "ghp_"\nvalues = [item for PART in '
                '(PART + "ABCDEFGHIJKLMNOP",)]\n',
            ),
            (
                "method skips class namespace",
                'PART = "ghp_"\nclass Reveal:\n    PART = "public "\n'
                "    def value(self):\n"
                '        return PART + "ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "method closure skips class namespace",
                'def outer():\n    PART = "ghp_"\n    class Reveal:\n'
                '        PART = "public "\n'
                "        def value(self):\n"
                '            return PART + "ABCDEFGHIJKLMNOP"\n',
            ),
        )
        for label, source in cases:
            with self.subTest(label=label):
                self.assertFalse(
                    MODULE.contains_bootstrap_v2_privacy_risk_text(
                        source,
                        relative=relative,
                    )
                )
                self.assertIn(
                    "ghp_ABCDEFGHIJKLMNOP",
                    MODULE.bootstrap_v2_python_privacy_risk_values(source),
                )

        benign = (
            'PART = "public "\n@decorate(PART + "summary")\n'
            "def reveal(PART):\n    pass\n"
            "class Container:\n"
            '    PART = "ghp_"\n'
            "    def value(self):\n"
            '        return PART + "summary"\n'
            'values = [item for PART in (PART + "summary",)]\n'
        )
        self.assertEqual(
            MODULE.bootstrap_v2_python_privacy_risk_values(benign),
            [],
        )

    def test_bootstrap_v2_python_class_load_name_follows_statement_order(
        self,
    ) -> None:
        read_before_assignment = (
            'PART = "ghp_"\n'
            "class Reveal:\n"
            '    before = PART + "ABCDEFGHIJKLMNOP"\n'
            '    PART = "public "\n'
            '    after = PART + "summary"\n'
        )
        before_values = MODULE.bootstrap_v2_python_string_constants(
            read_before_assignment
        )
        self.assertIn("ghp_ABCDEFGHIJKLMNOP", before_values)
        self.assertNotIn("public ABCDEFGHIJKLMNOP", before_values)

        read_after_assignment = (
            'PART = "public "\n'
            "class Reveal:\n"
            '    before = PART + "summary"\n'
            '    PART = "ghp_"\n'
            '    after = PART + "ABCDEFGHIJKLMNOP"\n'
        )
        after_values = MODULE.bootstrap_v2_python_string_constants(
            read_after_assignment
        )
        self.assertIn("ghp_ABCDEFGHIJKLMNOP", after_values)
        self.assertNotIn("public ABCDEFGHIJKLMNOP", after_values)

        benign = (
            'PART = "public "\n'
            "class Reveal:\n"
            '    before = PART + "summary"\n'
            '    PART = "harmless "\n'
            '    after = PART + "summary"\n'
        )
        self.assertEqual(
            MODULE.bootstrap_v2_python_privacy_risk_values(benign),
            [],
        )

    def test_bootstrap_v2_python_class_conditional_bindings_preserve_fallback(
        self,
    ) -> None:
        empty_loop = (
            'PART = "ghp_"\n'
            "class Reveal:\n"
            "    for PART in ():\n"
            "        pass\n"
            '    value = PART + "ABCDEFGHIJKLMNOP"\n'
        )
        self.assertIn(
            "ghp_ABCDEFGHIJKLMNOP",
            MODULE.bootstrap_v2_python_string_constants(empty_loop),
        )

        conditional_assignment = (
            'PART = "public "\n'
            "class Reveal:\n"
            "    if enabled:\n"
            '        PART = "ghp_"\n'
            '    value = PART + "ABCDEFGHIJKLMNOP"\n'
        )
        with self.assertRaisesRegex(
            ValueError,
            "string construction depends on an ambiguous name binding",
        ):
            MODULE.bootstrap_v2_python_string_constants(conditional_assignment)

    def test_bootstrap_v2_python_class_loop_else_respects_break_paths(self) -> None:
        definite_break = (
            'PART = "ghp_"\n'
            "class Reveal:\n"
            "    for item in (1,):\n"
            "        break\n"
            "    else:\n"
            '        PART = "public "\n'
            '    value = PART + "ABCDEFGHIJKLMNOP"\n'
        )
        self.assertIn(
            "ghp_ABCDEFGHIJKLMNOP",
            MODULE.bootstrap_v2_python_string_constants(definite_break),
        )

        conditional_break = (
            'PART = "ghp_"\n'
            "class Reveal:\n"
            "    for item in (1,):\n"
            "        if enabled:\n"
            "            break\n"
            "    else:\n"
            '        PART = "public "\n'
            '    value = PART + "ABCDEFGHIJKLMNOP"\n'
        )
        with self.assertRaisesRegex(
            ValueError,
            "string construction depends on an ambiguous name binding",
        ):
            MODULE.bootstrap_v2_python_string_constants(conditional_break)

        unreachable_after_guaranteed_break = (
            'PART = "ghp_"\n'
            "class Reveal:\n"
            "    for item in (1,):\n"
            "        if True:\n"
            "            break\n"
            "        import harmless as PART\n"
            '    value = PART + "ABCDEFGHIJKLMNOP"\n'
        )
        self.assertIn(
            "ghp_ABCDEFGHIJKLMNOP",
            MODULE.bootstrap_v2_python_string_constants(
                unreachable_after_guaranteed_break
            ),
        )

    def test_bootstrap_v2_python_class_loop_break_paths_fail_closed(self) -> None:
        cases = (
            (
                "for loop",
                "class Reveal:\n"
                '    PART = "ghp_"\n'
                "    for item in (1,):\n"
                "        if enabled:\n"
                "            break\n"
                "        del PART\n"
                '    value = PART + "ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "while loop",
                "class Reveal:\n"
                '    PART = "ghp_"\n'
                "    while enabled:\n"
                "        if ready:\n"
                "            break\n"
                "        del PART\n"
                '    value = PART + "ABCDEFGHIJKLMNOP"\n',
            ),
        )
        for label, source in cases:
            with self.subTest(label=label):
                self.assert_python_privacy_layers_reject(
                    source,
                    "string construction depends on an ambiguous name binding",
                )

    def test_bootstrap_v2_python_class_load_name_tracks_compound_bindings(
        self,
    ) -> None:
        fallback_cases = (
            (
                "empty loop",
                'PART = "ghp_"\nclass Reveal:\n'
                "    for PART in ():\n        pass\n"
                '    value = PART + "ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "delete",
                'PART = "ghp_"\nclass Reveal:\n'
                '    PART = "public "\n    del PART\n'
                '    value = PART + "ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "annotation only",
                'PART = "ghp_"\nclass Reveal:\n'
                "    PART: str\n"
                '    value = PART + "ABCDEFGHIJKLMNOP"\n',
            ),
        )
        for label, source in fallback_cases:
            with self.subTest(fallback=label):
                self.assertIn(
                    "ghp_ABCDEFGHIJKLMNOP",
                    MODULE.bootstrap_v2_python_string_constants(source),
                )

        direct_cases = (
            (
                "direct assignment",
                'PART = "public "\nclass Reveal:\n'
                '    PART = "ghp_"\n'
                '    value = PART + "ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "valued annotation",
                'PART = "public "\nclass Reveal:\n'
                '    PART: str = "ghp_"\n'
                '    value = PART + "ABCDEFGHIJKLMNOP"\n',
            ),
        )
        for label, source in direct_cases:
            with self.subTest(direct=label):
                self.assertIn(
                    "ghp_ABCDEFGHIJKLMNOP",
                    MODULE.bootstrap_v2_python_string_constants(source),
                )

        ambiguous_cases = (
            (
                "nonempty loop",
                'PART = "public "\nclass Reveal:\n'
                '    for PART in ("ghp_",):\n        pass\n'
                '    value = PART + "ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "match capture",
                'PART = "public "\nclass Reveal:\n'
                '    match "ghp_":\n        case PART:\n            pass\n'
                '    value = PART + "ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "augmented assignment",
                'PART = "ghp_"\nclass Reveal:\n'
                '    PART += ""\n'
                '    value = PART + "ABCDEFGHIJKLMNOP"\n',
            ),
            (
                "conditional delete",
                'PART = "public "\nclass Reveal:\n'
                '    PART = "ghp_"\n    if enabled:\n        del PART\n'
                '    value = PART + "ABCDEFGHIJKLMNOP"\n',
            ),
        )
        for label, source in ambiguous_cases:
            with self.subTest(ambiguous=label):
                with self.assertRaisesRegex(
                    ValueError,
                    "string construction depends on an ambiguous name binding",
                ):
                    MODULE.bootstrap_v2_python_string_constants(source)

    def test_bootstrap_v2_python_class_binding_dataflow_is_bounded(self) -> None:
        repetitions = 2_000
        source = (
            'PART = "public "\nclass Reveal:\n'
            + "".join("    for PART in ():\n        pass\n" for _ in range(repetitions))
            + "".join(
                f'    value_{index} = PART + "summary"\n'
                for index in range(repetitions)
            )
        )

        started = time.perf_counter()
        values = MODULE.bootstrap_v2_python_string_constants(source)
        elapsed = time.perf_counter() - started

        self.assertIn("public summary", values)
        self.assertLess(elapsed, 5.0)

    def test_bootstrap_v2_python_scoped_and_compound_bindings_are_evaluated(
        self,
    ) -> None:
        relative = Path("tests/test_retrospective_history_v2.py")
        cases = (
            (
                "function-local addition",
                'def reveal():\n    prefix = "ghp_"\n'
                '    suffix = "ABCDEFGHIJKLMNOP"\n'
                "    return prefix + suffix\n",
                "ghp_ABCDEFGHIJKLMNOP",
            ),
            (
                "named tuple join",
                'parts = ("Bea", "rer AbCdEfGhIjKlMnOp")\nvalue = "".join(parts)\n',
                "Bearer AbCdEfGhIjKlMnOp",
            ),
            (
                "named dict format-map",
                'fields = {"host": "https://internal.", "zone": "example"}\n'
                'value = "{host}{zone}".format_map(fields)\n',
                "https://internal.example",
            ),
            (
                "computed chained and destructured bindings",
                'prefix = alias = "g" + "hp_"\n'
                'left, right = ("ABCDEFGH", "IJKLMNOP")\n'
                "value = alias + left + right\n",
                "ghp_ABCDEFGHIJKLMNOP",
            ),
            (
                "nested function with later globals",
                "def outer():\n"
                "    def reveal():\n"
                "        return prefix + suffix\n"
                "    return reveal\n"
                'prefix = "ghp_"\n'
                'suffix = "ABCDEFGHIJKLMNOP"\n'
                "callback = outer()\n"
                "value = callback()\n",
                "ghp_ABCDEFGHIJKLMNOP",
            ),
            (
                "nested function with enclosing tuple binding",
                "def outer():\n"
                '    parts = ("Bea", "rer AbCdEfGhIjKlMnOp")\n'
                "    def reveal():\n"
                '        return "".join(parts)\n'
                "    return reveal\n",
                "Bearer AbCdEfGhIjKlMnOp",
            ),
            (
                "dominating with-block binding",
                "def reveal():\n"
                "    with context():\n"
                '        prefix = "ghp_"\n'
                '        return prefix + "ABCDEFGHIJKLMNOP"\n',
                "ghp_ABCDEFGHIJKLMNOP",
            ),
        )
        for label, source, expected in cases:
            with self.subTest(label=label):
                self.assertFalse(
                    MODULE.contains_bootstrap_v2_privacy_risk_text(
                        source,
                        relative=relative,
                    )
                )
                constants = MODULE.bootstrap_v2_python_string_constants(source)
                self.assertIn(expected, constants)
                self.assertTrue(MODULE.bootstrap_v2_privacy_risk_lines(expected))

    def test_bootstrap_v2_python_dynamic_constructions_retain_sensitive_fragments(
        self,
    ) -> None:
        relative = Path("tests/test_retrospective_history_v2.py")
        cases = (
            (
                "binary addition",
                'value = "ghp_" + dynamic + "ABCDEFGHIJKLMNOP"\n',
                "ghp_ABCDEFGHIJKLMNOP",
            ),
            (
                "percent formatting",
                'value = "%s%s%s" % ("ghp_", dynamic, "ABCDEFGHIJKLMNOP")\n',
                "ghp_ABCDEFGHIJKLMNOP",
            ),
            (
                "join",
                'value = "".join(("Bea", dynamic, "rer AbCdEfGhIjKlMnOp"))\n',
                "Bearer AbCdEfGhIjKlMnOp",
            ),
            (
                "dot format",
                'value = "{}{}{}".format("ghp_", dynamic, "ABCDEFGHIJKLMNOP")\n',
                "ghp_ABCDEFGHIJKLMNOP",
            ),
            (
                "format-map",
                'value = "{host}{dynamic}{zone}".format_map('
                '{"host": "https://internal.", "dynamic": dynamic, '
                '"zone": "example"})\n',
                "https://internal.example",
            ),
            (
                "dynamic f-string format spec",
                "value = f'{\"ghp_\":{width}}ABCDEFGHIJKLMNOP'\n",
                "ghp_ABCDEFGHIJKLMNOP",
            ),
            (
                "nested join and format",
                'value = "{}{}".format('
                '"".join(("ghp_", dynamic)), "ABCDEFGHIJKLMNOP")\n',
                "ghp_ABCDEFGHIJKLMNOP",
            ),
            (
                "named dynamic tuple join",
                'parts = ("ghp_", dynamic, "ABCDEFGHIJKLMNOP")\n'
                'value = "".join(parts)\n',
                "ghp_ABCDEFGHIJKLMNOP",
            ),
            (
                "named dynamic dict format-map",
                'fields = {"left": "Bea", "middle": dynamic, '
                '"right": "rer AbCdEfGhIjKlMnOp"}\n'
                'value = "{left}{middle}{right}".format_map(fields)\n',
                "Bearer AbCdEfGhIjKlMnOp",
            ),
        )
        for label, source, expected in cases:
            with self.subTest(label=label):
                self.assertFalse(
                    MODULE.contains_bootstrap_v2_privacy_risk_text(
                        source,
                        relative=relative,
                    )
                )
                risky_values = MODULE.bootstrap_v2_python_privacy_risk_values(source)
                self.assertIn(expected, risky_values)

        benign = (
            'value = "public " + dynamic + "summary"\n',
            'value = "%s%s%s" % ("public ", dynamic, "summary")\n',
            'value = "".join(("public ", dynamic, "summary"))\n',
            'value = "{}{}{}".format("public ", dynamic, "summary")\n',
            'value = "{left}{middle}{right}".format_map('
            '{"left": "public ", "middle": dynamic, "right": "summary"})\n',
            "value = f'{\"public \":{width}}summary'\n",
            'parts = ("public ", dynamic, "summary")\nvalue = "".join(parts)\n',
            'fields = {"left": "public ", "middle": dynamic, '
            '"right": "summary"}\n'
            'value = "{left}{middle}{right}".format_map(fields)\n',
            "offset = 0\noffset += 1\nvalue = offset + 1\n",
        )
        for source in benign:
            with self.subTest(benign=source[:48]):
                self.assertEqual(
                    MODULE.bootstrap_v2_python_privacy_risk_values(source), []
                )

    def test_bootstrap_v2_python_partial_formatting_preserves_known_fragments(
        self,
    ) -> None:
        cases = (
            (
                "percent numeric conversion",
                'value = "%s%d%s" % ("ghp_", dynamic, "ABCDEFGHIJKLMNOP")\n',
            ),
            (
                "bytes percent numeric conversion",
                'value = b"%s%d%s" % (b"ghp_", dynamic, b"ABCDEFGHIJKLMNOP")\n',
            ),
            (
                "percent mapping numeric conversion",
                'value = "%(prefix)s%(number)d%(suffix)s" % '
                '{"prefix": "ghp_", "number": dynamic, '
                '"suffix": "ABCDEFGHIJKLMNOP"}\n',
            ),
            (
                "percent dynamic numeric width",
                'value = "%s%*d%s" % ("ghp_", width, dynamic, "ABCDEFGHIJKLMNOP")\n',
            ),
            (
                "dot numeric format spec",
                'value = "{}{:d}{}".format("ghp_", dynamic, "ABCDEFGHIJKLMNOP")\n',
            ),
            (
                "dot conversion",
                'value = "{}{!r}{}".format("ghp_", dynamic, "ABCDEFGHIJKLMNOP")\n',
            ),
            (
                "dot nested numeric format spec",
                'value = "{}{:{}d}{}".format("ghp_", dynamic, width, '
                '"ABCDEFGHIJKLMNOP")\n',
            ),
            (
                "format-map numeric format spec",
                'value = "{prefix}{number:d}{suffix}".format_map('
                '{"prefix": "ghp_", "number": dynamic, '
                '"suffix": "ABCDEFGHIJKLMNOP"})\n',
            ),
            (
                "f-string partial conversion and numeric format spec",
                "value = f'{(\"ghp_\" + dynamic)!r:d}ABCDEFGHIJKLMNOP'\n",
            ),
            (
                "f-string unknown converted field",
                'value = f\'{"ghp_"}{dynamic!a:20d}{"ABCDEFGHIJKLMNOP"}\'\n',
            ),
        )
        for label, source in cases:
            with self.subTest(label=label):
                self.assertIn(
                    "ghp_ABCDEFGHIJKLMNOP",
                    MODULE.bootstrap_v2_python_privacy_risk_values(source),
                )

        benign = tuple(
            source.replace("ghp_", "public ").replace(
                "ABCDEFGHIJKLMNOP",
                "summary",
            )
            for _, source in cases
        )
        for source in benign:
            with self.subTest(benign=source[:56]):
                self.assertEqual(
                    MODULE.bootstrap_v2_python_privacy_risk_values(source),
                    [],
                )

    def test_bootstrap_v2_python_partial_containers_recompute_after_dependencies(
        self,
    ) -> None:
        cases = (
            (
                "sequence binding",
                'parts = ("ghp_" + dynamic, "ABCDEFGHIJKLMNOP")\n'
                'value = "".join(parts)\n',
                "ghp_ABCDEFGHIJKLMNOP",
            ),
            (
                "mapping binding",
                'fields = {"left": "Bea" + dynamic, '
                '"right": "rer AbCdEfGhIjKlMnOp"}\n'
                'value = "{left}{right}".format_map(fields)\n',
                "Bearer AbCdEfGhIjKlMnOp",
            ),
            (
                "dynamic key before known items",
                'value = "{left}{right}".format_map('
                '{dynamic_key: dynamic_value, "left": "ghp_", '
                '"right": "ABCDEFGHIJKLMNOP"})\n',
                "ghp_ABCDEFGHIJKLMNOP",
            ),
            (
                "dynamic key between known items",
                'value = "%(left)s%(right)s" % '
                '{"left": "https://internal.", dynamic_key: dynamic_value, '
                '"right": "example"}\n',
                "https://internal.example",
            ),
            (
                "dynamic unpack before known items",
                'value = "{left}{right}".format('
                '**{**dynamic_fields, "left": "Bea", '
                '"right": "rer AbCdEfGhIjKlMnOp"})\n',
                "Bearer AbCdEfGhIjKlMnOp",
            ),
        )
        for label, source, expected in cases:
            with self.subTest(label=label):
                self.assertIn(
                    expected,
                    MODULE.bootstrap_v2_python_privacy_risk_values(source),
                )

        benign = (
            'parts = ("public " + dynamic, "summary")\n'
            'value = "".join(parts)\n'
            'fields = {"left": "public " + dynamic, "right": "summary"}\n'
            'other = "{left}{right}".format_map(fields)\n'
            'direct = "{left}{right}".format_map('
            '{dynamic_key: dynamic_value, "left": "public ", '
            '"right": "summary"})\n'
            'expanded = "{left}{right}".format('
            '**{**dynamic_fields, "left": "public ", "right": "summary"})\n'
        )
        self.assertEqual(
            MODULE.bootstrap_v2_python_privacy_risk_values(benign),
            [],
        )

    def test_bootstrap_v2_python_partial_mapping_preserves_nested_known_entries(
        self,
    ) -> None:
        source = (
            'fields = {"token": {"prefix": "ghp_", "dynamic": dynamic, '
            '"suffix": "ABCDEFGHIJKLMNOP"}}\n'
            'value = "{token[prefix]}{token[suffix]}".format_map(fields)\n'
        )
        self.assertIn(
            "ghp_ABCDEFGHIJKLMNOP",
            MODULE.bootstrap_v2_python_privacy_risk_values(source),
        )

        benign = source.replace("ghp_", "public ").replace(
            "ABCDEFGHIJKLMNOP",
            "summary",
        )
        self.assertEqual(
            MODULE.bootstrap_v2_python_privacy_risk_values(benign),
            [],
        )

    def test_bootstrap_v2_python_partial_values_consume_aggregate_budgets(
        self,
    ) -> None:
        count_source = (
            'first = "public " + first_dynamic\nsecond = "summary" + second_dynamic\n'
        )
        with mock.patch.object(
            MODULE,
            "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUES",
            1,
        ):
            with self.assertRaisesRegex(ValueError, "evaluated value limit"):
                MODULE.bootstrap_v2_python_string_constants(count_source)

        byte_source = (
            'first = "abcdefgh" + first_dynamic\nsecond = "ijklmnop" + second_dynamic\n'
        )
        with mock.patch.object(
            MODULE,
            "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_BYTES",
            15,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "evaluated strings exceed the trusted byte limit",
            ):
                MODULE.bootstrap_v2_python_string_constants(byte_source)

        value_limit = MODULE.BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES
        binding_count = 100
        binding_source = (
            "".join(f"value_{index} = f\"{{'x'}}\"\n" for index in range(binding_count))
            + "consume("
            + ", ".join(f"value_{index}" for index in range(binding_count))
            + ")\n"
        )
        formatter_calls = 0

        def max_sized_format(_value: object, _spec: str) -> str:
            nonlocal formatter_calls
            formatter_calls += 1
            if formatter_calls > 5:
                raise AssertionError("binding memory budget was enforced too late")
            suffix = str(formatter_calls)
            return ("x" * (value_limit - len(suffix))) + suffix

        with mock.patch("builtins.format", side_effect=max_sized_format):
            with self.assertRaisesRegex(
                ValueError,
                "evaluated strings exceed the trusted byte limit",
            ):
                MODULE.bootstrap_v2_python_string_constants(binding_source)
        self.assertEqual(formatter_calls, 5)

        many_fields = 'value = "' + ("{}" * 100) + '".format(*values)\n'
        with self.assertRaisesRegex(
            ValueError,
            "partial evaluation exceeds the trusted operation limit",
        ):
            MODULE.bootstrap_v2_python_string_constants(many_fields)

        self.assertEqual(
            MODULE.bootstrap_v2_python_privacy_risk_values(
                'first = "public " + first_dynamic\n'
                'second = "summary" + second_dynamic\n'
            ),
            [],
        )

    def test_bootstrap_v2_python_format_preflight_caches_shared_container_sizes(
        self,
    ) -> None:
        scale = 1_500
        shared_values = ", ".join(repr(f"item{index:04d}") for index in range(scale))
        repeated_arguments = ", ".join("shared" for _ in range(scale))
        source = (
            f'shared = [{shared_values}]\nvalue = "{{}}".format({repeated_arguments})\n'
        )
        linear_operation_budget = (scale * 2) + 1

        with mock.patch.object(
            MODULE,
            "BOOTSTRAP_V2_MAX_PYTHON_FORMAT_ANALYSIS_OPERATIONS",
            linear_operation_budget,
        ):
            constants = MODULE.bootstrap_v2_python_string_constants(source)

        self.assertTrue(any(value.startswith("['item0000'") for value in constants))

    def test_bootstrap_v2_python_literal_join_candidate_tree_boundaries(self) -> None:
        relative = Path("tests/test_retrospective_history_v2.py")
        cases = (
            (
                "mixed text and bytes",
                'value = "".join(("safe", b"safe"))\n',
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES",
                MODULE.BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES,
                "Python constant join mixes text and bytes literals",
            ),
            (
                "unsupported element type",
                'value = "".join(("safe", 1))\n',
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES",
                MODULE.BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES,
                "Python constant join uses an unsupported literal type",
            ),
            (
                "nested mixed text and bytes",
                'value = "".join(("safe", b"".join((b"safe", b"value"))))\n',
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES",
                MODULE.BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES,
                "Python constant join mixes text and bytes literals",
            ),
            (
                "composed receiver mixed text and bytes",
                'value = b"".join((b"",)).join(("safe", "value"))\n',
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES",
                MODULE.BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES,
                "Python constant join mixes text and bytes literals",
            ),
            (
                "per-value byte budget",
                'value = "----".join(("a", "b", "c"))\n',
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES",
                8,
                "Python constant join exceeds the trusted byte limit",
            ),
            (
                "nested child per-value byte budget",
                'value = "".join(("abcd", "".join(("ef", "gh"))))\n',
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES",
                3,
                "Python constant join exceeds the trusted byte limit",
            ),
            (
                "nested parent per-value byte budget",
                'value = "".join(("abcd", "".join(("ef", "gh"))))\n',
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES",
                7,
                "Python constant join exceeds the trusted byte limit",
            ),
            (
                "composed receiver per-value byte budget",
                'value = "".join(("----",)).join(("a", "b", "c"))\n',
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES",
                8,
                "Python constant join exceeds the trusted byte limit",
            ),
            (
                "cumulative byte budget",
                'first = "".join(("ab", "cd"))\nsecond = "".join(("ef", "gh"))\n',
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_BYTES",
                7,
                "Python AST evaluated strings exceed the trusted byte limit",
            ),
            (
                "nested cumulative byte budget",
                'value = "".join(("abcd", "".join(("ef", "gh"))))\n',
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_BYTES",
                11,
                "Python AST evaluated strings exceed the trusted byte limit",
            ),
            (
                "composed receiver cumulative byte budget",
                'value = "".join(("ab", "cd")).join(("e", "f"))\n',
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_BYTES",
                9,
                "Python AST evaluated strings exceed the trusted byte limit",
            ),
            (
                "evaluated value budget",
                'first = "".join(("a", "b"))\nsecond = "".join(("c", "d"))\n',
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUES",
                1,
                "Python AST exceeds the trusted evaluated value limit",
            ),
            (
                "nested evaluated value budget",
                'value = "".join(("abcd", "".join(("ef", "gh"))))\n',
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUES",
                1,
                "Python AST exceeds the trusted evaluated value limit",
            ),
            (
                "composed receiver evaluated value budget",
                'value = "".join(("",)).join(("a", "b"))\n',
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUES",
                1,
                "Python AST exceeds the trusted evaluated value limit",
            ),
            (
                "nested AST depth budget",
                'value = "".join(("a", "".join(("b", "".join(("c", "d"))))))\n',
                "BOOTSTRAP_V2_MAX_PYTHON_AST_DEPTH",
                8,
                "Python AST exceeds the trusted depth limit",
            ),
            (
                "composed receiver AST depth budget",
                'value = "".join(("",)).join(("a", "b"))\n',
                "BOOTSTRAP_V2_MAX_PYTHON_AST_DEPTH",
                6,
                "Python AST exceeds the trusted depth limit",
            ),
        )
        for label, source, attribute, limit, expected in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    (root / relative).write_text(source, encoding="utf-8")

                    with mock.patch.object(MODULE, attribute, limit):
                        issues = "\n".join(
                            validate_synthetic_bootstrap_v2_candidate(root)
                        )

                self.assertIn(expected, issues)

        dynamic_source = (
            "separator = get_separator()\n"
            'value = separator.join(("public", "summary"))\n'
            'items = ("ghp_", get_suffix())\n'
            'other = "".join(items)\n'
            'nested = "".join(("public", "".join(("summary", get_suffix()))))\n'
        )
        with self.assertRaisesRegex(
            ValueError,
            "string construction depends on an ambiguous name binding",
        ):
            MODULE.bootstrap_v2_python_string_constants(dynamic_source)

        non_text_seeded_source = (
            "separator = get_separator()\n"
            'value = separator.join(("public", "summary"))\n'
            'other = "".join(("public", get_suffix()))\n'
            'nested = "".join(("public", "".join(("summary", get_suffix()))))\n'
        )
        constants = MODULE.bootstrap_v2_python_string_constants(non_text_seeded_source)
        self.assertNotIn("publicsummary", constants)

    def test_bootstrap_v2_python_ast_fails_closed_on_parse_and_bounds(self) -> None:
        with self.assertRaisesRegex(ValueError, "could not be parsed safely"):
            MODULE.bootstrap_v2_python_string_constants("value = (\n")

        invalid_constants = (
            (
                "invalid UTF-8 bytes",
                'value = b"\\xff"\n',
                "bytes constant is not valid UTF-8 text",
            ),
            (
                "NUL bytes",
                'value = b"\\x00"\n',
                "text constant contains a NUL byte",
            ),
            (
                "surrogate string",
                'value = "\\ud800"\n',
                "string constant contains invalid Unicode",
            ),
        )
        for label, source, expected in invalid_constants:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, expected):
                    MODULE.bootstrap_v2_python_string_constants(source)

        invalid_additions = (
            (
                "mixed string and bytes",
                'value = "safe" + b"safe"\n',
                "mixes text and bytes literals",
            ),
            (
                "unsupported literal type",
                'value = "safe" + 1\n',
                "unsupported literal type",
            ),
        )
        for label, source, expected in invalid_additions:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, expected):
                    MODULE.bootstrap_v2_python_string_constants(source)

        invalid_formatting = (
            (
                "mixed bytes percent formatting",
                'value = b"%s" % "safe"\n',
                "percent formatting is unsupported",
            ),
            (
                "invalid percent value type",
                'value = "%d" % "safe"\n',
                "percent formatting is unsupported",
            ),
            (
                "bytes dot-format receiver",
                'value = b"{}".format(b"safe")\n',
                "unsupported receiver type",
            ),
        )
        for label, source, expected in invalid_formatting:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, expected):
                    MODULE.bootstrap_v2_python_string_constants(source)

        bounds = (
            (
                "BOOTSTRAP_V2_MAX_PYTHON_SOURCE_BYTES",
                1,
                "value = 1\n",
                "AST size limit",
            ),
            ("BOOTSTRAP_V2_MAX_PYTHON_AST_NODES", 1, "value = 1\n", "node limit"),
            ("BOOTSTRAP_V2_MAX_PYTHON_AST_DEPTH", 1, "value = 1\n", "depth limit"),
            (
                "BOOTSTRAP_V2_MAX_PYTHON_LITERAL_CONSTANTS",
                1,
                'text = "safe"\npayload = b"safe"\n',
                "literal constant limit",
            ),
            (
                "BOOTSTRAP_V2_MAX_PYTHON_LITERAL_BYTES",
                7,
                'text = "safe"\npayload = b"safe"\n',
                "literal constants exceed the trusted byte limit",
            ),
            (
                "BOOTSTRAP_V2_MAX_PYTHON_LITERAL_BYTES",
                7,
                'value = "safe" + "safe"\n',
                "literal constants exceed the trusted byte limit",
            ),
            (
                "BOOTSTRAP_V2_MAX_PYTHON_AST_DEPTH",
                5,
                'value = "a" + ("b" + ("c" + "d"))\n',
                "depth limit",
            ),
            (
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES",
                8,
                'value = "%20s" % "x"\n',
                "formatting exceeds the trusted byte limit",
            ),
            (
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES",
                8,
                'value = "{:20}".format("x")\n',
                "formatting exceeds the trusted byte limit",
            ),
            (
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES",
                8,
                "value = f\"{'x':20}\"\n",
                "formatting exceeds the trusted byte limit",
            ),
            (
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES",
                8,
                'value = "x" * 20\n',
                "repetition exceeds the trusted byte limit",
            ),
            (
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_BYTES",
                7,
                'first = "ab" + "cd"\nsecond = "ef" + "gh"\n',
                "evaluated strings exceed the trusted byte limit",
            ),
            (
                "BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUES",
                1,
                'first = "{}".format("a")\nsecond = "{}".format("b")\n',
                "evaluated value limit",
            ),
        )
        for attribute, limit, source, expected in bounds:
            with self.subTest(attribute=attribute):
                with mock.patch.object(MODULE, attribute, limit):
                    with self.assertRaisesRegex(ValueError, expected):
                        MODULE.bootstrap_v2_python_string_constants(source)

        candidate_failures = (
            ("value = (\n", "Python source could not be parsed safely"),
            ('value = b"\\xff"\n', "Python bytes constant is not valid UTF-8 text"),
        )
        for source, expected in candidate_failures:
            with self.subTest(candidate_failure=expected):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    write_bootstrap_v2_candidate(root)
                    relative = Path("tests/test_retrospective_history_v2.py")
                    (root / relative).write_text(source, encoding="utf-8")

                    issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

                self.assertIn(expected, issues)

    def test_bootstrap_v2_python_ast_preflights_cumulative_f_string_fields(
        self,
    ) -> None:
        limit = MODULE.BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES
        width = limit // 8
        source = 'value = f"' + (f"{{'x':{width}}}" * 10_000) + '"\n'
        formatted = chr(0x10FFFF) * width
        calls = 0

        def bounded_format(_value: object, _spec: str) -> str:
            nonlocal calls
            calls += 1
            if calls > 1:
                raise AssertionError("cumulative f-string preflight ran too late")
            return formatted

        with mock.patch("builtins.format", side_effect=bounded_format):
            with self.assertRaisesRegex(
                ValueError, "formatting exceeds the trusted byte limit"
            ):
                MODULE.bootstrap_v2_python_string_constants(source)

        self.assertEqual(calls, 1)

    def test_bootstrap_v2_never_executes_candidate_validator_or_tests(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_bootstrap_v2_candidate(root)
            violation = root / "README.md"
            violation.write_text(
                "Leaked path " + risky_project_path() + "\n", encoding="utf-8"
            )
            (root / "scripts" / "validate_retained_history.py").write_text(
                "raise SystemExit(0)\n",
                encoding="utf-8",
            )
            marker = root / "candidate-code-ran"
            (root / "tests" / "test_retrospective_history_v2.py").write_text(
                "from pathlib import Path\n"
                "Path('README.md').unlink()\n"
                "Path('candidate-code-ran').write_text('ran')\n",
                encoding="utf-8",
            )

            issues = "\n".join(validate_synthetic_bootstrap_v2_candidate(root))

            self.assertIn("infrastructure text contains raw/sensitive evidence", issues)
            self.assertTrue(violation.is_file())
            self.assertFalse(marker.exists())

    def test_bootstrap_workflow_matches_trusted_structural_policy(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            workflow = root / MODULE.BOOTSTRAP_WORKFLOW_PATH
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                BOOTSTRAP_WORKFLOW.read_text(encoding="utf-8"), encoding="utf-8"
            )

            self.assertEqual(MODULE.validate_root(root), [])

    def test_security_owned_files_are_content_scan_clean(self) -> None:
        repository_root = SCRIPT.parents[1]
        owned_files = (
            BOOTSTRAP_WORKFLOW,
            PERMANENT_CI_TEMPLATE,
            SCRIPT,
            TRUSTED_CI_HELPER,
            repository_root / "tests" / "test_session_retrospective_v2_bootstrap.py",
            Path(__file__).resolve(),
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for source in owned_files:
                destination = root / source.relative_to(repository_root)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)

            self.assertEqual(MODULE.validate_root(root), [])

    def test_security_owned_risk_line_fingerprints_fail_closed(self) -> None:
        repository_root = SCRIPT.parents[1]
        relatives = (
            Path(
                ".github/bootstrap/session-retrospective-v2-permanent-ci.yml"
            ),
            Path(".github/workflows/session-retrospective-v2-bootstrap.yml"),
            Path("scripts/trusted_history_ci.py"),
            Path("scripts/validate_retained_history.py"),
            Path("tests/test_session_retrospective_v2_bootstrap.py"),
            Path("tests/test_validate_retained_history.py"),
        )
        self.assertEqual(
            set(relatives),
            set(MODULE.INFRASTRUCTURE_TRUSTED_RISK_LINES_SHA256),
        )
        for relative in relatives:
            with self.subTest(relative=relative.as_posix()):
                source = (repository_root / relative).read_text(encoding="utf-8")
                risky_lines = MODULE.infrastructure_risk_lines(
                    source,
                    relative=relative,
                )
                self.assertTrue(risky_lines)
                self.assertEqual(
                    MODULE.bootstrap_v2_privacy_risk_lines_fingerprint(risky_lines),
                    MODULE.INFRASTRUCTURE_TRUSTED_RISK_LINES_SHA256[relative],
                )
                self.assertFalse(
                    MODULE.contains_infrastructure_risk_text(
                        source,
                        relative=relative,
                    )
                )
                mutated = source.replace(risky_lines[0], risky_lines[0] + "x", 1)
                self.assertTrue(
                    MODULE.contains_infrastructure_risk_text(
                        mutated,
                        relative=relative,
                    )
                )

    def test_bootstrap_workflow_safe_line_exemptions_fail_closed(self) -> None:
        bootstrap_path = MODULE.BOOTSTRAP_WORKFLOW_PATH.as_posix()
        safe_checkout_input = "          persist-credentials: false\n"
        safe_auth_input = '          GH_TOKEN: "${{ github.token }}"\n'
        cases = (
            (
                "true value",
                bootstrap_path,
                "          persist-credentials: true\n",
            ),
            (
                "other workflow path",
                ".github/workflows/ci.yml",
                safe_checkout_input,
            ),
            (
                "auth input in other workflow",
                ".github/workflows/ci.yml",
                safe_auth_input,
            ),
            (
                "other infrastructure path",
                "scripts/probe.py",
                safe_checkout_input,
            ),
            (
                "extra token content",
                bootstrap_path,
                safe_checkout_input + "          token: abcdefghijklmnop\n",
            ),
            (
                "extra secret content",
                bootstrap_path,
                safe_checkout_input + "          secret: abcdefghijklmnop\n",
            ),
            (
                "indentation drift",
                bootstrap_path,
                "        persist-credentials: false\n",
            ),
            (
                "quoted key drift",
                bootstrap_path,
                '          "persist-credentials": false\n',
            ),
            (
                "spacing drift",
                bootstrap_path,
                "          persist-credentials : false\n",
            ),
            (
                "ordinary credential finding",
                bootstrap_path,
                "          credential-helper: plaintext\n",
            ),
            (
                "auth value drift",
                bootstrap_path,
                '          GH_TOKEN: "${{ github.event.pull_request.title }}"\n',
            ),
        )
        for label, relative_path, text in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    artifact = root / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text(text, encoding="utf-8")

                    issues = "\n".join(MODULE.validate_root(root))

                self.assertIn(
                    "infrastructure text contains raw/sensitive evidence",
                    issues,
                )

    def test_bootstrap_workflow_rejects_duplicate_keys_and_policy_mutations(
        self,
    ) -> None:
        workflow_text = BOOTSTRAP_WORKFLOW.read_text(encoding="utf-8")
        mutations = (
            (
                "duplicate trigger",
                workflow_text.replace(
                    "  pull_request_target:\n",
                    "  pull_request_target:\n    branches:\n      - master\n",
                    1,
                ),
                "contains a duplicate mapping key",
            ),
            (
                "candidate validator",
                workflow_text.replace(
                    '"$TRUSTED_ROOT/scripts/validate_retained_history.py"',
                    '"$CANDIDATE_ROOT/scripts/validate_retained_history.py"',
                    1,
                ),
                "bootstrap workflow structure differs from the trusted policy",
            ),
            (
                "writable remount",
                workflow_text.replace("remount,bind,ro", "remount,bind,rw", 1),
                "bootstrap workflow structure differs from the trusted policy",
            ),
        )
        for label, mutated, expected in mutations:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    workflow = root / MODULE.BOOTSTRAP_WORKFLOW_PATH
                    workflow.parent.mkdir(parents=True)
                    workflow.write_text(mutated, encoding="utf-8")

                    issues = "\n".join(MODULE.validate_root(root))

                self.assertIn(expected, issues)

    def test_bootstrap_workflow_yaml_errors_do_not_echo_sensitive_keys(self) -> None:
        sensitive_key = risky_github_classic_token()
        cases = (
            (
                "duplicate key",
                f"{sensitive_key}: first\n{sensitive_key}: second\n",
                "line 2 column 1 contains a duplicate mapping key",
            ),
            (
                "invalid key syntax",
                f"{sensitive_key} value\n",
                "line 1 has an invalid mapping key",
            ),
            (
                "invalid indentation",
                f"{sensitive_key}:\n   child: value\n",
                "line 2 has invalid indentation",
            ),
            (
                "missing value",
                f"{sensitive_key}:\n",
                "line 1 column 1 has a mapping key without a value",
            ),
        )
        for label, source, expected in cases:
            with self.subTest(label=label):
                with self.assertRaises(ValueError) as raised:
                    MODULE.parse_strict_workflow_yaml(source)

                diagnostic = str(raised.exception)
                self.assertIn(expected, diagnostic)
                self.assertNotIn(sensitive_key, diagnostic)
                self.assertLess(len(diagnostic), 180)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            workflow = root / MODULE.BOOTSTRAP_WORKFLOW_PATH
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                f"{sensitive_key}: first\n{sensitive_key}: second\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(root)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("contains a duplicate mapping key", result.stdout)
        self.assertNotIn(sensitive_key, result.stdout)
        self.assertNotIn(sensitive_key, result.stderr)

    def test_candidate_validator_and_mutation_test_are_never_executed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            violation = root / "reports" / "daily" / "2026" / "05" / "22.md"
            violation.parent.mkdir(parents=True)
            violation.write_text(
                "Leaked URL " + risky_internal_url() + "\n", encoding="utf-8"
            )

            replacement = root / "scripts" / "validate_retained_history.py"
            replacement.parent.mkdir(parents=True)
            replacement.write_text("raise SystemExit(0)\n", encoding="utf-8")
            marker = root / "candidate-code-ran"
            mutation_test = root / "tests" / "test_mutate_candidate.py"
            mutation_test.parent.mkdir(parents=True)
            mutation_test.write_text(
                "from pathlib import Path\n"
                "Path('reports/daily/2026/05/22.md').unlink()\n"
                "Path('candidate-code-ran').write_text('ran')\n",
                encoding="utf-8",
            )

            issues = "\n".join(MODULE.validate_root(root))

            self.assertIn("retained text contains raw/sensitive evidence", issues)
            self.assertTrue(violation.is_file())
            self.assertFalse(marker.exists())

    def test_retained_text_rejects_bare_private_ip_addresses(self) -> None:
        for report_sample, row_sample in (
            (risky_bare_private_ip(), risky_bare_private_lan_ip()),
            (risky_link_local_ip(), risky_cgnat_ip()),
            (risky_private_ipv6(), risky_link_local_ipv6()),
            (risky_loopback_ipv6(), risky_bare_private_ip()),
        ):
            with self.subTest(report_sample=report_sample, row_sample=row_sample):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    report = root / "reports" / "daily" / "2026" / "05" / "22.md"
                    report.parent.mkdir(parents=True)
                    report.write_text(
                        "Investigated host " + report_sample + "\n", encoding="utf-8"
                    )

                    turn = valid_turn_flag()
                    turn["redacted_user_prompt_summary"] = (
                        "Investigated host " + row_sample
                    )
                    turn_path = (
                        root
                        / "data"
                        / "turn_flags"
                        / "2026"
                        / "05"
                        / "turn_flags.jsonl"
                    )
                    turn_path.parent.mkdir(parents=True)
                    turn_path.write_text(json.dumps(turn) + "\n", encoding="utf-8")

                    issues = "\n".join(MODULE.validate_root(root))

                self.assertIn(
                    "reports/daily/2026/05/22.md: retained text contains raw/sensitive evidence",
                    issues,
                )
                self.assertIn(
                    "data/turn_flags/2026/05/turn_flags.jsonl:1: redacted_user_prompt_summary contains retained-text risk",
                    issues,
                )

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
            episode_path.write_text(json.dumps(episode), encoding="utf-8")
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
                "model_eras": {risky_uuid(): 1},
                "coverage_gaps": [],
            }
            trend_path = root / "data" / "trends" / "2026" / "05" / "trend_report.json"
            trend_path.parent.mkdir(parents=True)
            trend_path.write_text(json.dumps(trend), encoding="utf-8")
            manifest = valid_manifest()
            manifest["sources"][0]["host"] = risky_internal_host()
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
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
            manifest["coverage_gaps"] = [
                {"host": "customer-acme", "reason": "stale_host"}
            ]
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
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
            manifest["coverage_gaps"] = [
                {"host": "scope", "reason": "partial_host_scope"}
            ]
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
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

            self.assertIn(
                "hosts key must be an allowed retained host",
                "\n".join(MODULE.validate_root(root)),
            )

    def test_source_safety_coverage_reasons_are_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = valid_manifest()
            manifest["coverage_gaps"] = [
                {
                    "host": "local",
                    "reason": "source_root_symlink",
                    "root_ref": "path_ref_v1:aaaaaaaaaaaaaaaa",
                },
                {
                    "host": "custom_source",
                    "reason": "unsafe_source_artifact",
                    "root_ref": "path_ref_v1:aaaaaaaaaaaaaaaa",
                },
                {
                    "host": "local",
                    "reason": "truncated_rollout_summary",
                    "root_ref": "path_ref_v1:aaaaaaaaaaaaaaaa",
                },
            ]
            manifest_path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            manifest_path.parent.mkdir(parents=True)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            self.assertEqual(MODULE.validate_root(root), [])

    def test_missing_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "missing"

            self.assertEqual(
                MODULE.validate_root(root), ["root must be an existing directory"]
            )

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
                {"host": "local", "reason": "unreachable"} for _index in range(101)
            ]
            path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
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
            path = (
                root / "data" / "manifests" / "2026" / "05" / "retained_manifest.json"
            )
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(manifest), encoding="utf-8")

            issues = "\n".join(MODULE.validate_root(root))
            self.assertIn(
                "source rollout_count must be a bounded non-negative integer", issues
            )
            self.assertIn(
                "source summary_count must be a bounded non-negative integer", issues
            )
            self.assertIn(
                "ready source must have rollout_count or summary_count", issues
            )

    def test_git_ignored_local_temp_dirs_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(
                ["git", "init"], cwd=root, check=True, stdout=subprocess.DEVNULL
            )
            (root / ".gitignore").write_text(".codex" + "-tmp/\n", encoding="utf-8")
            helper_state = root / ".codex-tmp" / "isolated-review" / "state.json"
            helper_state.parent.mkdir(parents=True)
            helper_state.write_text(
                json.dumps({"raw": risky_internal_url()}) + "\n", encoding="utf-8"
            )
            report = root / "reports" / "weekly" / "2026" / "05" / "08.md"
            report.parent.mkdir(parents=True)
            report.write_text(
                "# Weekly retrospective\n\nNo raw transcript excerpts retained.\n",
                encoding="utf-8",
            )

            self.assertEqual(MODULE.validate_root(root), [])


if __name__ == "__main__":
    unittest.main()
