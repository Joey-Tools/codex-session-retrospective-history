#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import base64
from bisect import bisect_right
import binascii
from collections import Counter
import contextlib
from dataclasses import dataclass, field
import datetime as dt
import errno
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import string
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Iterable, NamedTuple, Sequence
import unicodedata


NUL_TEXT = chr(0)
NUL_BYTE = bytes((0,))


FORBIDDEN_COMPONENTS = frozenset(
    ".codex .codex-local .codex-tmp archived_sessions raw scratch sessions "
    "transient".split()
)
FORBIDDEN_EXACT_PATH_COMPONENTS = frozenset({"retrospective-history-v2-admin.asc"})
FORBIDDEN_FILENAMES = frozenset(
    "auth.json config.toml history.jsonl session_index.jsonl source_metadata.json "
    "shard_manifest.json shards.jsonl turn_summaries.jsonl".split()
)
FORBIDDEN_COMPACT_NAME_PARTS = frozenset(
    "conversationlog fullprompt messagelog promptlog rawtranscript tooloutput "
    "turnsummaries userprompt".split()
)
FORBIDDEN_COMPACT_NAME_PREFIXES = frozenset({"raw"})
FORBIDDEN_NAME_STEMS = frozenset(
    "history session_index shard_manifest shards source_metadata turn_summaries".split()
)
COMPRESSED_ARTIFACT_SUFFIXES = frozenset({".bz2", ".gz", ".xz", ".zip", ".zst"})
PATH_REF_RE = re.compile(r"^path_ref_v1:[0-9a-f]{16}$")
SESSION_REF_RE = re.compile(r"^session_ref_v1:[0-9a-f]{20}$")
EPISODE_REF_RE = re.compile(r"^episode_ref_v1:[0-9a-f]{20}$")
TURN_REF_RE = re.compile(r"^turn_ref_v1:[0-9a-f]{20}$")
SOURCE_HASH_RE = re.compile(r"^source_hash_v1:[0-9a-f]{20}$")
SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
SENSITIVE_TOKEN_RE = re.compile(
    r"(^|[._-])(?:password|passwd|pwd|credentials?|secret|token|api[._-]?key|authorization|private[._-]?key)($|[._-])",
    re.I,
)
RAW_ID_TOKEN_RE = re.compile(
    r"\b(?:session|turn|episode)(?:[._-]?id)[._-][A-Za-z0-9][A-Za-z0-9_.-]{5,}\b", re.I
)
RAW_ID_VALUE_RE = re.compile(
    r"(?<![A-Za-z0-9_])[\"']?(?:session|turn|episode)(?:[._ -]?id)[\"']?(?:\s*[:=]\s*|\s+)[\"']?"
    r"(?!session_ref_v1:|turn_ref_v1:|episode_ref_v1:|row\.get\b|data\.get\b|value\.get\b)[A-Za-z0-9_.:-]{6,}\b",
    re.I,
)
BASELINE_MODE_RE = re.compile(r"^baseline-90d$")
PRIVATE_IPV4_RE = re.compile(
    r"(?<![\d.])(?:10(?:\.\d{1,3}){3}|100\.(?:6[4-9]|[78]\d|9\d|1[01]\d|12[0-7])(?:\.\d{1,3}){2}|127(?:\.\d{1,3}){3}|169\.254(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2})(?![\d.])"
)
PRIVATE_IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:::1|f[cd][0-9A-Fa-f]{0,2}(?::[0-9A-Fa-f]{0,4}){1,7}|fe[89abAB][0-9A-Fa-f]?(?::[0-9A-Fa-f]{0,4}){1,7})(?![0-9A-Fa-f:])",
    re.I,
)
TIMESTAMP_RE = re.compile(
    r"^(?:(?:\d{4}-(?:(?:01|03|05|07|08|10|12)-(?:0[1-9]|[12]\d|3[01])|(?:04|06|09|11)-(?:0[1-9]|[12]\d|30)|02-(?:0[1-9]|1\d|2[0-8])))|(?:(?:[0-9]{2}(?:0[48]|[2468][048]|[13579][26])|(?:[02468][048]|[13579][26])00)-02-29))T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?Z$"
)
TEXT_ARTIFACT_SUFFIXES = frozenset({".json", ".jsonl", ".md", ".txt"})
VALID_RETAINED_SUFFIXES = TEXT_ARTIFACT_SUFFIXES
STRIPPABLE_ARTIFACT_SUFFIXES = TEXT_ARTIFACT_SUFFIXES | COMPRESSED_ARTIFACT_SUFFIXES
ROOT_DOC_FILES = frozenset(
    ".gitignore AGENTS.md README.md data/README.md reports/README.md".split()
)
WORKFLOW_SUFFIXES = frozenset({".yaml", ".yml"})
BOOTSTRAP_WORKFLOW_PATH = Path(
    ".github/workflows/session-retrospective-v2-bootstrap.yml"
)
BOOTSTRAP_V2_CI_PATH = Path(".github/workflows/ci.yml")
BOOTSTRAP_V2_PERMANENT_CI_TEMPLATE_PATH = Path(
    ".github/bootstrap/session-retrospective-v2-permanent-ci.yml"
)
BOOTSTRAP_V2_LEGACY_CI_BLOB_OID = "145e8de8a055794b85af6461a69e50715913ea6f"
BOOTSTRAP_V2_PERMANENT_CI_BLOB_OID = "cf4bb43951954a2bca5603398baec84ff35f9cf0"
BOOTSTRAP_SECURITY_WORKFLOW_PATHS = frozenset(
    {BOOTSTRAP_WORKFLOW_PATH, BOOTSTRAP_V2_PERMANENT_CI_TEMPLATE_PATH}
)
BOOTSTRAP_SAFE_INFRASTRUCTURE_LINES = frozenset(
    {
        "          persist-credentials: false",
        '          GH_TOKEN: "${{ github.token }}"',
    }
)


def _trusted_sha256_values_hex(values: tuple[int, ...]) -> str:
    if len(values) != 32 or any(
        type(value) is not int or not 0 <= value <= 255 for value in values
    ):
        raise RuntimeError("trusted SHA-256 value is invalid")
    return bytes(values).hex()


INFRASTRUCTURE_TRUSTED_RISK_LINES_SHA256 = {
    BOOTSTRAP_V2_CI_PATH: (
        "bc1db63b7f477b5e87f0996d008c2f8951ee5c5ee518f6e22801870357fab92a"
    ),
    Path(".github/bootstrap/session-retrospective-v2-permanent-ci.yml"): bytes(
        (
            0xF4,
            0xE9,
            0xAD,
            0xD8,
            0x67,
            0xD2,
            0x62,
            0xE1,
            0xAA,
            0x1C,
            0xE4,
            0xCF,
            0x39,
            0xE1,
            0x89,
            0xC8,
            0x20,
            0xC6,
            0xA0,
            0x26,
            0x50,
            0x53,
            0xFC,
            0xCF,
            0x39,
            0x9E,
            0x82,
            0x08,
            0x24,
            0xDB,
            0x53,
            0xF8,
        )
    ).hex(),
    Path(".github/workflows/session-retrospective-v2-bootstrap.yml"): bytes(
        (
            0x49,
            0xA4,
            0xA1,
            0x10,
            0xCF,
            0xE8,
            0x30,
            0xF4,
            0x5D,
            0xA0,
            0xAB,
            0xC9,
            0x0D,
            0x27,
            0x2A,
            0x97,
            0x77,
            0xA9,
            0x43,
            0x89,
            0xF0,
            0xD7,
            0xB8,
            0xDA,
            0xD3,
            0x18,
            0x7A,
            0xB3,
            0xB6,
            0xE9,
            0xC4,
            0x78,
        )
    ).hex(),
    Path("scripts/trusted_history_ci.py"): bytes(
        (
            0xBB,
            0x76,
            0x2C,
            0x46,
            0x59,
            0x90,
            0xE5,
            0xB4,
            0xD6,
            0xB9,
            0x29,
            0xF5,
            0x55,
            0x4D,
            0xF5,
            0xDC,
            0x5E,
            0x0A,
            0x57,
            0xC2,
            0xEA,
            0xD4,
            0xB0,
            0x75,
            0x99,
            0xBD,
            0x0F,
            0xA0,
            0x58,
            0x4C,
            0x5C,
            0xF4,
        )
    ).hex(),
    Path("scripts/validate_retained_history.py"): bytes(
        (
            0xE5,
            0xC4,
            0x46,
            0x22,
            0xE3,
            0x93,
            0x01,
            0x15,
            0x79,
            0xE4,
            0x97,
            0x5F,
            0x34,
            0x5E,
            0xDB,
            0x51,
            0x6E,
            0xB7,
            0xB0,
            0x15,
            0xBF,
            0x2F,
            0x26,
            0x7E,
            0x9C,
            0x13,
            0x2E,
            0x7B,
            0xAC,
            0x55,
            0x4F,
            0xD8,
        )
    ).hex(),
    Path("tests/test_session_retrospective_v2_bootstrap.py"): bytes(
        (
            0xFE,
            0x48,
            0x6E,
            0xE9,
            0xB8,
            0xFE,
            0x0A,
            0x96,
            0xC2,
            0x23,
            0x38,
            0xED,
            0x19,
            0xB1,
            0xEA,
            0x17,
            0x72,
            0x1C,
            0x7C,
            0x0E,
            0xBD,
            0x50,
            0x99,
            0x3D,
            0xF0,
            0xC5,
            0x98,
            0x59,
            0xFD,
            0xE0,
            0x99,
            0xD5,
        )
    ).hex(),
    Path("tests/test_validate_retained_history.py"): bytes(
        (
            0x8D,
            0x6B,
            0xEC,
            0xEF,
            0x21,
            0x86,
            0x0C,
            0xD4,
            0xB0,
            0xFC,
            0x06,
            0xA7,
            0x1D,
            0x02,
            0x3B,
            0x94,
            0x95,
            0x1E,
            0xD0,
            0x53,
            0xE1,
            0x3F,
            0x14,
            0xC4,
            0xFE,
            0x05,
            0xDA,
            0x19,
            0x15,
            0x2C,
            0x0D,
            0x9E,
        )
    ).hex(),
}
BOOTSTRAP_WORKFLOW_POLICY_SHA256 = (
    "6d980fe19b516087fbc9e87273bdce9bf57d43e758bedfe2725e2eadce789d32"
)
BOOTSTRAP_V2_REQUIRED_FILES = frozenset(
    Path(path)
    for path in (
        ".github/workflows/ci.yml .gitignore AGENTS.md README.md data/README.md "
        "reports/README.md requirements-v2.in requirements-v2.txt "
        "retrospective-history-v2-admin-public.asc "
        "retrospective-history-v2-publisher.asc "
        "schemas/retained-manifest-v1.schema.json "
        "schemas/retained-manifest-v2.schema.json "
        "schemas/session-retrospective-v1.schema.json "
        "schemas/session-retrospective-v2.schema.json "
        "scripts/retrospective_history_attestation_v2.py "
        "scripts/retrospective_history_credentials_v2.py "
        "scripts/retrospective_history_git_v2.py "
        "scripts/retrospective_history_merge_v2.py "
        "scripts/retrospective_history_privacy_v2.py "
        "scripts/retrospective_history_templates_v2.py "
        "scripts/retrospective_history_v2.py scripts/validate_retained_history.py "
        "tests/test_retrospective_history_git_v2.py "
        "tests/test_retrospective_history_merge_v2.py "
        "tests/test_retrospective_history_privacy_v2.py "
        "tests/test_retrospective_history_v2.py "
        "tests/test_retrospective_history_v2_ci.py "
        "tests/test_retrospective_history_v2_schema_extensions.py "
        "tests/test_validate_retained_history.py"
    ).split()
)
BOOTSTRAP_V2_ALLOWED_FILES = BOOTSTRAP_V2_REQUIRED_FILES
HISTORY_V2_TRUST_GENERATION_PATHS = tuple(
    sorted(
        BOOTSTRAP_V2_ALLOWED_FILES | {Path("scripts/trusted_history_ci.py")},
        key=lambda path: path.as_posix(),
    )
)
BOOTSTRAP_V2_TEMPORARY_PATHS = frozenset(
    {
        BOOTSTRAP_V2_PERMANENT_CI_TEMPLATE_PATH,
        Path(".github/workflows/session-retrospective-v2-bootstrap.yml"),
        Path("tests/test_session_retrospective_v2_bootstrap.py"),
    }
)
BOOTSTRAP_V2_SCHEMA_FILES = frozenset(
    Path(path)
    for path in "schemas/retained-manifest-v2.schema.json "
    "schemas/session-retrospective-v2.schema.json".split()
)
BOOTSTRAP_V2_PUBLIC_KEY_FILES = frozenset(
    Path(path)
    for path in "retrospective-history-v2-admin-public.asc "
    "retrospective-history-v2-publisher.asc".split()
)
BOOTSTRAP_V2_PUBLIC_KEY_SHA256 = {
    Path("retrospective-history-v2-admin-public.asc"): (
        "35a01ede099cb17aaf11ef0174dad9519fb54ce7870bdcd9dfc4b87e071e50c7"
    ),
    Path("retrospective-history-v2-publisher.asc"): (
        "77e33dafc60ea63b23fafa90fdc03aae333cd226e25321aa2e6a77acac06d884"
    ),
}
BOOTSTRAP_V2_TRUSTED_RISK_LINES_SHA256 = {
    BOOTSTRAP_V2_CI_PATH: (
        "0134a3638edb3283afa51f74ba7f995454986c75f9e1c9098c96e940f126a3b4"
    ),
    Path("README.md"): (
        "e4ee136a3770d0ea019d7d389205ba4ed203a739ea9b2591caf8f2a2ee48e421"
    ),
    Path("requirements-v2.txt"): (
        "d2ca4a5ebd41c18889dc20a94b6739b6006519e9fe313abb3444541974b65153"
    ),
    Path("schemas/retained-manifest-v2.schema.json"): (
        "99b64ba88009557679baa524af662c260b87c199298dc57981139bb995e0d2e8"
    ),
    Path("schemas/session-retrospective-v2.schema.json"): (
        "088d879ad41bc984eb73aeb30c458bb05761905f11961b865d0c375b102a1e72"
    ),
    Path("scripts/retrospective_history_credentials_v2.py"): (
        "007592c9ab825463cf58c7bdbc595cc2b6689abb7d4de669a27b5a43d0cd0e93"
    ),
    Path("scripts/retrospective_history_git_v2.py"): (
        "4501a5c58af10a81e38da13f7321936d65882c389f66f3c870b9a506302fe282"
    ),
    Path("scripts/retrospective_history_merge_v2.py"): (
        "dbba9035dab3dac26b82630974288127e6efe7bb526b5390803922993b05556f"
    ),
    Path("scripts/retrospective_history_v2.py"): (
        "f79c070bc3a21ef0aa047332e18b408ff8958be13ccba628e7d658eb00afdd38"
    ),
    Path(
        "scripts/validate_retained_history.py"
    ): INFRASTRUCTURE_TRUSTED_RISK_LINES_SHA256[
        Path("scripts/validate_retained_history.py")
    ],
    Path("tests/test_retrospective_history_git_v2.py"): (
        "0af0bef1f0a3c1a7bd6f1b67486524051ee20245ddb38f0ecc6ef9b1f4266487"
    ),
    Path("tests/test_retrospective_history_merge_v2.py"): (
        "d4ff5ee000636437f27600bb748ae88b6beee01c71c714793fccb85a593d3319"
    ),
    Path("tests/test_retrospective_history_privacy_v2.py"): (
        "839b84ee4f906135c2a8d90567ad657a776da686f5d650aa695c0be7f3edffdd"
    ),
    Path("tests/test_retrospective_history_v2.py"): (
        "c84ef5b9fc895b9149c2f931aedff42d278bb1d84adf3e5dc702d421886f559c"
    ),
    Path("tests/test_retrospective_history_v2_ci.py"): (
        "1f276d39abc22de1b3ca99c45a2da1218f6245b6043848c0b4b127bddd34b81e"
    ),
    Path("tests/test_retrospective_history_v2_schema_extensions.py"): (
        "81de8b80e486f1617944aa4996d1aa3a0aaaa7b4434adc39a9e8c8381a2dff8a"
    ),
    Path("tests/test_validate_retained_history.py"): bytes(
        (
            0x30,
            0xA8,
            0x26,
            0x3F,
            0x00,
            0xDC,
            0x31,
            0x91,
            0x73,
            0x3A,
            0xC1,
            0xDD,
            0x9C,
            0x1A,
            0x57,
            0x02,
            0xD5,
            0xF1,
            0x1C,
            0xB3,
            0x0C,
            0xEA,
            0xB2,
            0xDD,
            0xE3,
            0x84,
            0xB1,
            0x11,
            0x62,
            0x4C,
            0xF9,
            0x9D,
        )
    ).hex(),
}
BOOTSTRAP_V2_TRUSTED_DECODED_RISK_VALUES_SHA256 = {
    Path("schemas/session-retrospective-v2.schema.json"): (
        "52e1822e52eef524d48ee8fd528860655d7825c2fd3f52d72502a86979b1c6d6"
    ),
}
BOOTSTRAP_V2_TRUSTED_PYTHON_RISK_VALUES_SHA256 = {
    Path("scripts/validate_retained_history.py"): _trusted_sha256_values_hex(
        (
            0x09,
            0x26,
            0x67,
            0x00,
            0xBF,
            0xE5,
            0xDB,
            0x27,
            0x7D,
            0x32,
            0x63,
            0xF2,
            0xCA,
            0xDF,
            0x5B,
            0x4A,
            0x94,
            0x80,
            0x1E,
            0xE7,
            0x02,
            0x52,
            0x22,
            0x4F,
            0xD5,
            0x68,
            0xD6,
            0x54,
            0xD5,
            0x5F,
            0x54,
            0x2C,
        )
    ),
    Path("tests/test_validate_retained_history.py"): _trusted_sha256_values_hex(
        (
            0x9E,
            0xFB,
            0xD2,
            0x04,
            0x07,
            0x6E,
            0x4E,
            0x30,
            0x27,
            0x2A,
            0xED,
            0x1A,
            0x50,
            0xAA,
            0x3E,
            0xD7,
            0xC7,
            0xEE,
            0x22,
            0x6A,
            0x8C,
            0xEB,
            0x9F,
            0x5E,
            0x86,
            0x80,
            0x29,
            0xD9,
            0x07,
            0xE1,
            0xED,
            0xBA,
        )
    ),
}
BOOTSTRAP_V2_TRUSTED_OPENPGP_RISK_VALUES_SHA256 = {
    Path("retrospective-history-v2-admin-public.asc"): (
        "223884eca8b1e2734ae319ef40223f00d6e59734c78ed42169aabe3db6ec0669"
    ),
    Path("retrospective-history-v2-publisher.asc"): (
        "4b64cfc23fe562248eacb12019e11754979160d52c60e0b121a643aa70e93688"
    ),
}
BOOTSTRAP_V2_JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
BOOTSTRAP_V2_MAX_FILE_BYTES = 2 * 1024 * 1024
BOOTSTRAP_V2_MAX_PYTHON_SOURCE_BYTES = 704 * 1024
BOOTSTRAP_V2_MAX_PYTHON_AST_NODES = 112_000
BOOTSTRAP_V2_MAX_PYTHON_AST_DEPTH = 100
BOOTSTRAP_V2_MAX_PYTHON_LITERAL_CONSTANTS = 20_000
BOOTSTRAP_V2_MAX_PYTHON_LITERAL_BYTES = 512 * 1024
BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUES = 20_000
BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES = 512 * 1024
BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_BYTES = 2 * 1024 * 1024
BOOTSTRAP_V2_MAX_PYTHON_FORMAT_ANALYSIS_OPERATIONS = 1_000_000
BOOTSTRAP_V2_MAX_PYTHON_TEXT_OUTPUT_OPERATIONS = 2_000_000
BOOTSTRAP_V2_MAX_PYTHON_METHOD_SELECTION_STATES = 200_000
BOOTSTRAP_V2_MAX_PYTHON_METHOD_SELECTION_OPERATIONS = 1_000_000
BOOTSTRAP_V2_MAX_PYTHON_BINDING_REACHABILITY_STEPS = 2_000_000
BOOTSTRAP_V2_MAX_DECODER_INPUT_OPS = 1_000_000
BOOTSTRAP_V2_MAX_PUBLIC_KEY_BYTES = 256 * 1024
BOOTSTRAP_V2_MAX_TREE_BYTES = 16 * 1024 * 1024
BOOTSTRAP_V2_MAX_CANDIDATE_ENTRIES = 4096
BOOTSTRAP_V2_MAX_GIT_METADATA_BYTES = 8 * 1024 * 1024
HISTORY_V2_MERGE_PLAN_KIND = "retrospective-history-v2-validation-plan"
HISTORY_V2_MAX_COMMITS = 64
HISTORY_V2_GIT_TIMEOUT_SECONDS = 20.0
HISTORY_V2_MAX_MERGE_PLAN_BYTES = 16 * 1024
HISTORY_V2_MAX_COMMIT_BYTES = 64 * 1024
HISTORY_V2_MAX_COMMIT_MESSAGE_BYTES = 16 * 1024
HISTORY_V2_MAX_SQUASH_COMMIT_MESSAGE_BYTES = 257
HISTORY_V2_MAX_COMMIT_SIGNATURE_BYTES = 16 * 1024
HISTORY_V2_MAX_GITHUB_COMMIT_RECEIPT_BYTES = 16 * 1024
HISTORY_V2_MAX_REACHABLE_BLOBS = 16 * 1024
HISTORY_V2_MAX_REACHABLE_BLOB_BYTES = 64 * 1024 * 1024
HISTORY_V2_MAX_PATH_REFERENCES = 65_536
HISTORY_V2_MAX_PATH_DEPTH = 32
HISTORY_V2_MAX_BLOB_READ_OPERATIONS = 16_384
HISTORY_V2_MAX_BLOB_READ_BYTES = 64 * 1024 * 1024
HISTORY_V2_MAX_PARENT_EDGES = 128
HISTORY_V2_MAX_DIFF_CALLS = 129
HISTORY_V2_MAX_DIFF_BYTES = 8 * 1024 * 1024
HISTORY_V2_MAX_MATERIALIZATIONS = HISTORY_V2_MAX_COMMITS + 1
HISTORY_V2_MAX_TEMP_DISK_BYTES = 256 * 1024 * 1024
HISTORY_V2_MAX_DOMAIN_MANIFESTS = 4096
HISTORY_V2_MAX_DOMAIN_ISSUES = 32
HISTORY_V2_MAX_DOMAIN_ISSUE_BYTES = 4096
HISTORY_V2_MAX_DOMAIN_ISSUE_CHARACTERS = 256
HISTORY_V2_MAX_DIAGNOSTIC_ITEMS = 256
HISTORY_V2_MAX_DIAGNOSTIC_BYTES = 64 * 1024
HISTORY_V2_MAX_DIAGNOSTIC_ITEM_BYTES = 1024
HISTORY_V2_MAX_JSONL_ROWS = 65_536
HISTORY_V2_MAX_TOTAL_JSONL_ROWS = 131_072
HISTORY_V2_PROCESS_TERMINATE_GRACE_SECONDS = 0.5
HISTORY_V2_OID_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
HISTORY_V2_IDENTITY_RE = re.compile(
    r"^(?P<identity>[^<>\r\n]+ <[^<>\s\r\n]+>) "
    r"(?P<timestamp>[1-9][0-9]{0,9}) \+0000$"
)
HISTORY_V2_UNSIGNED_SQUASH_IDENTITY_RE = re.compile(
    rb"^(?P<name>[A-Za-z0-9][A-Za-z0-9 ._'-]{0,127}) "
    rb"<(?P<email>(?:(?:[0-9]+\+)?[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}"
    rb"[A-Za-z0-9])?"
    rb"@users\.noreply\.github\.com|noreply"
    rb"@github\.com))> "
    rb"(?P<timestamp>[1-9][0-9]{0,9}) \+0000$"
)
HISTORY_V2_GITHUB_SQUASH_IDENTITY_RE = re.compile(
    rb"^(?P<name>[^<>\x00-\x1f\x7f]{1,256}) "
    rb"<(?P<email>[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,128}"
    rb"@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)> "
    rb"(?P<timestamp>[1-9][0-9]{0,9}) "
    rb"(?P<timezone>[+-](?:0[0-9]|1[0-4])[0-5][0-9])$"
)
HISTORY_V2_GITHUB_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
HISTORY_V2_DEFAULT_BRANCH = "master"
HISTORY_V2_GITHUB_COMMITTER_IDENTITY = b"GitHub <noreply@github.com>"
HISTORY_V2_GITHUB_SQUASH_RECEIPT_KIND = (
    "retrospective-history-v2-github-squash-verification"
)
HISTORY_V2_CANONICAL_IDENTITY = (
    "Retrospective History <retrospective-history-v2@users.noreply.github.com>"
)
HISTORY_V2_SIGNATURE_KEY_PATHS = {
    "bootstrap-v2": Path("retrospective-history-v2-admin-public.asc"),
    "history-v2": Path("retrospective-history-v2-publisher.asc"),
}
HISTORY_V2_SIGNATURE_PUBLIC_KEY_ALGORITHMS = frozenset({1, 22})
HISTORY_V2_SIGNATURE_HASH_ALGORITHM = 10
HISTORY_V2_DOMAIN_MODULE_PATHS = tuple(
    Path(f"scripts/retrospective_history_{name}_v2.py")
    for name in "attestation credentials git privacy templates".split()
) + (Path("scripts/retrospective_history_v2.py"),)
HISTORY_V2_CODEX_TRAILERS = frozenset(
    {
        "Co-authored-by: Codex (tool=Codex CLI; model=GPT-5) <codex@openai.com>",
        "Co-authored-by: Codex (tool=Codex CLI; model=GPT-5.6 Sol) <codex@openai.com>",
    }
)
HISTORY_V2_COMMIT_SUBJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .,:_+()'/-]{0,255}$")
HISTORY_V2_GITHUB_SQUASH_SUFFIX_RE = re.compile(
    r"^(?P<title>.+) \(#(?P<pull_request_number>[1-9][0-9]*)\)$"
)
HISTORY_V2_RAW_CONVERSATION_EVIDENCE_RE = re.compile(
    r"(?:^|[^a-z0-9])(?:"
    r"raw[ _-]+(?:user[ _-]+)?prompt|"
    r"user[ _-]+prompt(?:[ _-]+text)?|"
    r"tool[ _-]+(?:output|result|response|call)|"
    r"assistant[ _-]+(?:output|response)|"
    r"(?:raw[ _-]+)?(?:conversation[ _-]+)?transcript|"
    r"prompt[ _-]*[:=]|"
    r"<(?:user|assistant|tool(?:_output)?)>"
    r")(?:$|[^a-z0-9])",
    re.I,
)


@dataclass(frozen=True)
class HistoryV2DomainContract:
    validate_v2_runs_with_inventory: Callable[..., Any]
    verify_publisher_attestation: Callable[[dict[str, bytes]], bool]
    build_pull_request_merge_plan: Callable[..., Any]
    validate_default_branch_update: Callable[..., list[str]]
    max_manifest_bytes: int
    trusted_root: Path | None = None
    trusted_revision: str | None = None
    trusted_generation: str | None = None


@dataclass(frozen=True)
class HistoryV2FileSnapshot:
    relative: Path
    value: bytes | None
    mode: int
    device: int
    inode: int
    uid: int
    gid: int
    size: int
    mtime_ns: int

    @property
    def is_symlink(self) -> bool:
        return stat.S_ISLNK(self.mode)

    @property
    def is_regular(self) -> bool:
        return stat.S_ISREG(self.mode)


class BoundedDiagnosticList(list[str]):
    def __init__(self, values: Iterable[str] = ()) -> None:
        super().__init__()
        self._encoded_bytes = 0
        self._saturated = False
        self.extend(values)

    @property
    def saturated(self) -> bool:
        return self._saturated

    def append(self, value: str) -> None:
        if self._saturated:
            return
        if type(value) is not str:
            value = "history-v2 validation returned an invalid diagnostic"
        if not value or any(not character.isprintable() for character in value):
            value = "history-v2 validation returned an unsafe diagnostic"
        encoded = value.encode("utf-8")
        if len(encoded) > HISTORY_V2_MAX_DIAGNOSTIC_ITEM_BYTES:
            value = "history-v2 validation diagnostic exceeded its item limit"
            encoded = value.encode("ascii")
        if (
            len(self) >= HISTORY_V2_MAX_DIAGNOSTIC_ITEMS
            or self._encoded_bytes + len(encoded) > HISTORY_V2_MAX_DIAGNOSTIC_BYTES
        ):
            self._saturated = True
            marker = "history-v2 validation diagnostic budget was exhausted"
            marker_bytes = marker.encode("ascii")
            if (
                len(self) < HISTORY_V2_MAX_DIAGNOSTIC_ITEMS
                and self._encoded_bytes + len(marker_bytes)
                <= HISTORY_V2_MAX_DIAGNOSTIC_BYTES
            ):
                super().append(marker)
                self._encoded_bytes += len(marker_bytes)
            return
        super().append(value)
        self._encoded_bytes += len(encoded)

    def extend(self, values: Iterable[str]) -> None:
        for value in values:
            self.append(value)
            if self._saturated:
                break


_HISTORY_V2_DOMAIN_UNSET = object()
_TRUSTED_HISTORY_V2_DOMAIN: HistoryV2DomainContract | None | object = (
    _HISTORY_V2_DOMAIN_UNSET
)


class BoundedProcessError(RuntimeError):
    pass


class BoundedProcessLimitError(BoundedProcessError):
    pass


def _signal_bounded_process_group(
    process: subprocess.Popen[bytes], process_signal: signal.Signals
) -> None:
    try:
        os.killpg(process.pid, process_signal)
    except ProcessLookupError:
        return
    except OSError:
        try:
            process.send_signal(process_signal)
        except OSError:
            pass


def _stop_bounded_process_group(process: subprocess.Popen[bytes]) -> None:
    _signal_bounded_process_group(process, signal.SIGTERM)
    grace_deadline = time.monotonic() + HISTORY_V2_PROCESS_TERMINATE_GRACE_SECONDS
    while process.poll() is None and time.monotonic() < grace_deadline:
        time.sleep(0.01)
    # Kill the group even if the leader exited; descendants may still hold pipes.
    _signal_bounded_process_group(process, signal.SIGKILL)
    try:
        process.wait(timeout=HISTORY_V2_PROCESS_TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        process.wait()


def bounded_process_output(
    command: list[str],
    *,
    input_data: bytes | None = None,
    max_output_bytes: int = BOOTSTRAP_V2_MAX_GIT_METADATA_BYTES,
    timeout_seconds: float = HISTORY_V2_GIT_TIMEOUT_SECONDS,
    environment: dict[str, str] | None = None,
    chunk_validator: Callable[[bytes], None] | None = None,
) -> bytes:
    if max_output_bytes < 0 or timeout_seconds <= 0:
        raise ValueError("bounded process limits are invalid")
    if input_data is not None and len(input_data) > BOOTSTRAP_V2_MAX_GIT_METADATA_BYTES:
        raise BoundedProcessError("bounded process input exceeds policy")

    input_stream = tempfile.TemporaryFile()
    if input_data is not None:
        input_stream.write(input_data)
        input_stream.flush()
        input_stream.seek(0)
    try:
        process = subprocess.Popen(
            command,
            stdin=input_stream if input_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=environment,
        )
    except OSError as exc:
        input_stream.close()
        raise BoundedProcessError("bounded process could not be started") from exc
    if process.stdout is None:
        _stop_bounded_process_group(process)
        input_stream.close()
        raise BoundedProcessError("bounded process output is unavailable")

    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    output = bytearray()
    deadline = time.monotonic() + timeout_seconds
    failure: BoundedProcessError | None = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BoundedProcessError("bounded process exceeded its time limit")
            ready = selector.select(min(remaining, 0.25))
            if not ready:
                continue
            for key, _events in ready:
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(output) + len(chunk) > max_output_bytes:
                    raise BoundedProcessError(
                        "bounded process exceeded its output limit"
                    )
                if chunk_validator is not None:
                    chunk_validator(chunk)
                output.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BoundedProcessError("bounded process exceeded its time limit")
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise BoundedProcessError(
                "bounded process exceeded its time limit"
            ) from exc
        if return_code != 0:
            raise BoundedProcessError("bounded process returned a failure")
        return bytes(output)
    except (BoundedProcessError, OSError) as exc:
        failure = (
            exc
            if isinstance(exc, BoundedProcessError)
            else BoundedProcessError("bounded process output could not be read")
        )
        _stop_bounded_process_group(process)
        drain_deadline = time.monotonic() + HISTORY_V2_PROCESS_TERMINATE_GRACE_SECONDS
        while selector.get_map() and time.monotonic() < drain_deadline:
            ready = selector.select(0.05)
            for key, _events in ready:
                try:
                    chunk = os.read(key.fd, 64 * 1024)
                except OSError:
                    chunk = b""
                if not chunk:
                    selector.unregister(key.fileobj)
        if failure is exc:
            raise failure
        raise failure from exc
    finally:
        selector.close()
        process.stdout.close()
        input_stream.close()
        if process.poll() is None:
            _stop_bounded_process_group(process)


def closed_git_environment(*, home: Path | None = None) -> dict[str, str]:
    return {
        "GIT_CONFIG_COUNT": "0",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(home) if home is not None else "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", os.defpath),
        "TZ": "UTC",
    }


def closed_git_command(*arguments: str) -> list[str]:
    return [
        "git",
        "--no-replace-objects",
        "--literal-pathspecs",
        *arguments,
    ]


_HISTORY_V2_COMMON_GIT_DIRS: dict[Path, Path] = {}


def _history_v2_common_git_dir(root: Path) -> Path:
    resolved_root = root.resolve()
    cached = _HISTORY_V2_COMMON_GIT_DIRS.get(resolved_root)
    if cached is not None:
        return cached
    try:
        raw = bounded_process_output(
            closed_git_command(
                "-C",
                str(resolved_root),
                "rev-parse",
                "--git-common-dir",
            ),
            max_output_bytes=4096,
            timeout_seconds=HISTORY_V2_GIT_TIMEOUT_SECONDS,
            environment=closed_git_environment(),
        ).decode("utf-8")
    except (BoundedProcessError, UnicodeDecodeError) as exc:
        raise ValueError("history-v2 Git common directory is unavailable") from exc
    common = Path(raw.strip())
    if not common.is_absolute():
        common = resolved_root / common
    common = common.resolve()
    _HISTORY_V2_COMMON_GIT_DIRS[resolved_root] = common
    return common


def validate_history_v2_closed_object_store(root: Path) -> None:
    # The protected access-policy property is exclusive use of the repository's
    # own object directory. Ambient alternates are absent from the closed
    # environment and exact on-disk alternate declarations are rejected.
    common = _history_v2_common_git_dir(root)
    objects = common / "objects"
    info = objects / "info"
    for path, label in (
        (objects, "history-v2 Git object directory"),
        (info, "history-v2 Git object policy directory"),
    ):
        try:
            metadata = os.lstat(path)
        except FileNotFoundError as exc:
            raise ValueError(f"{label} is missing") from exc
        except PermissionError as exc:
            raise ValueError(f"{label} is unreadable") from exc
        except OSError as exc:
            raise ValueError(f"{label} could not be inspected") from exc
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"{label} is not a real directory")
    for name in ("alternates", "http-alternates"):
        path = info / name
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except FileNotFoundError:
            continue
        except PermissionError as exc:
            raise ValueError("history-v2 Git alternate policy is unreadable") from exc
        except OSError as exc:
            raise ValueError(
                "history-v2 Git alternate policy could not be inspected"
            ) from exc
        else:
            os.close(descriptor)
            raise ValueError("history-v2 Git alternate object fallback is prohibited")


BOOTSTRAP_V2_REJECTED_PACKET_TAGS = frozenset({5, 7})
BOOTSTRAP_V2_ALLOWED_PACKET_TAGS = frozenset({2, 6, 13, 14, 17})
BOOTSTRAP_V2_RESERVED_SIGNATURE_SUBPACKET_TYPES = frozenset(
    {0, 1, 8, 10, 13, 14, 15, 17, 18, 19, 34, 36, 37, 38}
)
BOOTSTRAP_V2_ED25519_OID = bytes.fromhex("2b06010401da470f01")
BOOTSTRAP_V2_CURVE25519_OID = bytes.fromhex("2b060104019755010501")
BOOTSTRAP_V2_ARMOR_BEGIN = "-----BEGIN "
BOOTSTRAP_V2_FORBIDDEN_ARMOR_MARKERS = (
    BOOTSTRAP_V2_ARMOR_BEGIN + "PGP PRIVATE KEY BLOCK-----",
    BOOTSTRAP_V2_ARMOR_BEGIN + "PRIVATE KEY-----",
    BOOTSTRAP_V2_ARMOR_BEGIN + "ENCRYPTED PRIVATE KEY-----",
    "SECRET-KEY PACKET",
    "SECRET-SUBKEY PACKET",
)
SCHEMA_FILES = frozenset(
    "retained-manifest-v1.schema.json session-retrospective-v1.schema.json".split()
)
RETAINED_EXPORT_DIRS = frozenset(
    {("retained", "daily"), ("retained", "weekly"), ("retained", "baseline")}
)
RETAINED_EXPORT_FILES = frozenset(
    "episodes.jsonl turn_flags.jsonl trend_report.json retained_manifest.json".split()
)
RETAINED_EVIDENCE_HOSTS = frozenset(
    "local miku-bot-dev hoteng-srv-01 custom_source".split()
)
RETAINED_HOSTS = frozenset((*RETAINED_EVIDENCE_HOSTS, "scope"))
RETAINED_FIXED_MODES = frozenset({"daily", "weekly"})
RETAINED_MODEL_IDS = frozenset(
    "gpt-5.6-sol gpt-5.6-terra gpt-5.5 gpt-5.4 gpt-5.3-codex".split()
)
RETAINED_MODEL_ERAS = frozenset(
    (*RETAINED_MODEL_IDS, "other-model", "pre-gpt-5.3-codex", "unknown")
)
EPISODE_KEYS = frozenset(
    "episode_id host session_id start end cwd model_era topic turn_count "
    "friction_flags outcome work_report_hint".split()
)
TURN_FLAG_KEYS = frozenset(
    "turn_id episode_id host session_id source_path source_hash timestamp cwd "
    "model model_era redacted_user_prompt_summary assistant_action_summary "
    "issue_flags prompt_improvement".split()
)
TREND_KEYS = frozenset(
    "schema_version window turn_count flagged_turn_count episode_count flags "
    "hosts model_eras coverage_gaps".split()
)
MANIFEST_KEYS = frozenset(
    "schema_version mode window sources coverage_gaps redaction_policy_version "
    "retention_note retention_safe".split()
)
WINDOW_KEYS = frozenset({"mode", "start", "end"})
SOURCE_SUMMARY_KEYS = frozenset(
    "host root_ref status rollout_count summary_count".split()
)
COVERAGE_GAP_KEYS = frozenset("host reason root_ref bytes".split())
SOURCE_STATUSES = frozenset("empty missing ready stale".split())
OUTCOMES = frozenset("needs_review no_issue_observed".split())
ISSUE_FLAGS = frozenset(
    "approval_auth_friction context_loss failed_command over_exploration "
    "safety_privacy_flag under_asking user_correction verification_gap".split()
)
COVERAGE_REASONS = frozenset(
    "auth_gated codex_missing history_missing history_unreadable host_unreachable "
    "invalid_jsonl missing_codex no_rollout_or_summary_files oversized_rollout_skipped "
    "partial_host_scope remote_source_not_materialized session_index_missing "
    "session_index_unreadable source_root_missing source_root_symlink stale_host "
    "truncated_rollout_summary unreachable unsafe_source_artifact".split()
)
MAX_MANIFEST_SOURCES = 16
MAX_COVERAGE_GAPS = 100
MAX_SAFE_TOKEN_LENGTH = 64
MAX_TOKEN_ARRAY_ITEMS = 16
MAX_COUNT_MAP_PROPERTIES = 64
MAX_COUNT = 1_000_000
RETAINED_SAFETY_TEXT_RE = re.compile(
    r"(?:\b(?:secret|token|credential|password|private key|production|destructive|rm -rf|reset --hard|customer data|pii)\b|"
    r"客户|客户数据|凭据|凭证|密钥|生产|破坏性)",
    re.I,
)
COMMON_BARE_TOKEN_RE = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})\b"
)
COMMON_PATH_RISK_PATTERNS = (
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(
        r"(^|[^A-Za-z0-9_])(?:~|/(?:Users|home|root|private|tmp|var|etc|opt|Volumes|workspace|workspaces))/",
        re.I,
    ),
    re.compile(r"(^|[^A-Za-z0-9_])(?:\./|\.\./)?\.codex(?:-local|-tmp)?(?:/|\\)", re.I),
    re.compile(r"(^|[^A-Za-z0-9_])(?:sessions|archived_sessions)(?:/|\\)", re.I),
    re.compile(
        r"\b[A-Za-z]:\\(?:Users|home|root|private|tmp|var|etc|opt|workspace|workspaces)\\",
        re.I,
    ),
)
COMMON_SECRET_RISK_PATTERNS = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b", re.I),
    re.compile(r"\b(?:sk|rk)[-_](?:proj[-_])?[A-Za-z0-9_-]{16,}\b"),
    COMMON_BARE_TOKEN_RE,
    re.compile(r"(^|[^0-9a-fA-F])[0-9a-fA-F]{64}([^0-9a-fA-F]|$)"),
    re.compile(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
    ),
    re.compile(r"\brollout(?:-summary)?-[A-Za-z0-9_.-]+\.jsonl\b", re.I),
    PRIVATE_IPV4_RE,
    PRIVATE_IPV6_RE,
    RAW_ID_VALUE_RE,
    RAW_ID_TOKEN_RE,
    re.compile(
        r"\b(?:[A-Za-z0-9-]+\.)+(?:internal|corp|local|lan|example|invalid|test)\b",
        re.I,
    ),
)
RISK_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----", re.I),
    re.compile(r"\b(?:https?|ssh)://", re.I),
    re.compile(r"\bgit@[A-Za-z0-9_.-]+:"),
    *COMMON_PATH_RISK_PATTERNS,
    re.compile(
        r"(?<![A-Za-z0-9_])[\"']?"
        r"[A-Za-z0-9._-]*(?:password|passwd|pwd|credential|secret(?:[\s._-]+key)?|token|api[\s._-]*key|authorization|private[\s._-]*key)[A-Za-z0-9._-]*[\"']?\s*[:=]\s*[\"']?"
        r"(?!(?:re\.compile|frozenset)\b)",
        re.I,
    ),
    *COMMON_SECRET_RISK_PATTERNS,
    RETAINED_SAFETY_TEXT_RE,
)
INFRASTRUCTURE_RISK_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----", re.I),
    re.compile(
        r"\bhttps?://(?:localhost|miku-bot-dev|hoteng-srv-01|(?:10|127)(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2})(?::\d{1,5})?(?:[/?#]|$)",
        re.I,
    ),
    re.compile(
        r"\bssh://(?:[A-Za-z0-9._-]+@)?(?:localhost|miku-bot-dev|hoteng-srv-01|(?:10|127)(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2}|[A-Za-z0-9-]+)(?::\d{1,5})?(?:[/:?#]|$)",
        re.I,
    ),
    re.compile(
        r"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9._-]+@)(?:localhost|miku-bot-dev|hoteng-srv-01|(?:10|127)(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2}|[A-Za-z0-9-]+):[A-Za-z0-9._~/-]+(?:\.git)?\b",
        re.I,
    ),
    *COMMON_PATH_RISK_PATTERNS,
    re.compile(
        r"(?<![A-Za-z0-9_])[\"']?"
        r"(?!(?:safe[._-]?token(?:[._-]?re)?|common[._-]?bare[._-]?token[._-]?re|max[._-]?safe[._-]?token[._-]?length|max[._-]?token[._-]?array[._-]?items|sensitive[._-]?token[._-]?re|raw[._-]?id[._-]?token[._-]?re|tokens|risk[._-]?patterns?|infrastructure[._-]?risk[._-]?patterns?|safe[._-]?infrastructure[._-]?lines)[\"']?\s*[:=])"
        r"[A-Za-z0-9._-]*(?:password|passwd|pwd|credential|secret(?:[\s._-]+key)?|token|api[\s._-]*key|authorization|private[\s._-]*key)[A-Za-z0-9._-]*[\"']?\s*[:=]\s*[\"']?"
        r"(?!(?:re\.compile|frozenset)\b)",
        re.I,
    ),
    *COMMON_SECRET_RISK_PATTERNS,
)
BOOTSTRAP_V2_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
    r"(?![A-Za-z0-9-]|\.[A-Za-z0-9-])"
)
BOOTSTRAP_V2_ADDITIONAL_PRIVACY_RISK_PATTERNS = (
    BOOTSTRAP_V2_EMAIL_RE,
    re.compile(r"\b(?:[A-Za-z0-9-]+\.)*home\.arpa\b", re.I),
    re.compile(r"(^|[^A-Za-z0-9_])/srv(?:/+[A-Za-z0-9._-]+)+", re.I),
    re.compile(r"\b(?:(?:AKIA|ASIA)[A-Z0-9]{16}|A3T[A-Z0-9]{17})\b"),
)
BOOTSTRAP_V2_IMMUTABLE_GITHUB_ACTION_USES_RE = re.compile(
    r"(?P<action_path>[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?"
    r"(?:/[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?)*)@"
    r"(?P<ref>[0-9a-f]{40})"
)
BOOTSTRAP_V2_PRIVACY_RISK_PATTERNS = (
    *INFRASTRUCTURE_RISK_PATTERNS,
    *BOOTSTRAP_V2_ADDITIONAL_PRIVACY_RISK_PATTERNS,
)
SAFE_INFRASTRUCTURE_LINES = frozenset(
    ".codex-local/ .codex-tmp/ .codex/ archived_sessions/ sessions/ auth.json "
    "config.toml history.jsonl session_index.jsonl rollout-*.jsonl "
    "rollout-summary*.jsonl source_metadata.json shard_manifest.json shards.jsonl "
    "turn_summaries.jsonl".split()
)


def _history_v2_entry_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
    )


def _history_v2_entry_access(
    metadata: os.stat_result,
) -> tuple[int, int, int]:
    return (
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
    )


def _history_v2_snapshot_protected_equal(
    first: HistoryV2FileSnapshot,
    second: HistoryV2FileSnapshot,
) -> bool:
    return (
        first.relative == second.relative
        and first.value == second.value
        and first.mode == second.mode
        and first.device == second.device
        and first.inode == second.inode
        and first.uid == second.uid
        and first.gid == second.gid
        and first.size == second.size
    )


def _history_v2_filesystem_error(
    *,
    label: str,
    operation: str,
    error: OSError,
) -> ValueError:
    if isinstance(error, FileNotFoundError) or error.errno == errno.ENOENT:
        return ValueError(f"{label} is missing")
    if isinstance(error, PermissionError) or error.errno in {
        errno.EACCES,
        errno.EPERM,
    }:
        return ValueError(f"{label} is unreadable")
    return ValueError(f"{label} could not be {operation}")


def _history_v2_open_directory(path: Path, *, label: str) -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("no-follow filesystem inspection is unavailable")
    flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _history_v2_filesystem_error(
            label=label,
            operation="opened",
            error=exc,
        ) from exc
    try:
        metadata = os.fstat(descriptor)
    except OSError as exc:
        os.close(descriptor)
        raise _history_v2_filesystem_error(
            label=label,
            operation="inspected",
            error=exc,
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise ValueError(f"{label} is not a directory")
    return descriptor


def _history_v2_read_exact_file(
    descriptor: int,
    *,
    expected_size: int,
) -> bytes:
    value = bytearray()
    while len(value) < expected_size:
        chunk = os.read(
            descriptor,
            min(64 * 1024, expected_size - len(value)),
        )
        if not chunk:
            break
        value.extend(chunk)
    extra = os.read(descriptor, 1)
    if len(value) != expected_size or extra:
        raise ValueError("candidate artifact content changed while being read")
    return bytes(value)


def _history_v2_revalidate_open_file(
    descriptor: int,
    *,
    baseline: bytes,
    opened: os.stat_result,
    label: str,
) -> os.stat_result:
    os.lseek(descriptor, 0, os.SEEK_SET)
    first = _history_v2_read_exact_file(
        descriptor,
        expected_size=opened.st_size,
    )
    os.lseek(descriptor, 0, os.SEEK_SET)
    second = _history_v2_read_exact_file(
        descriptor,
        expected_size=opened.st_size,
    )
    current = os.fstat(descriptor)
    if _history_v2_entry_identity(current) != _history_v2_entry_identity(opened):
        raise ValueError(f"{label} object identity changed while being read")
    if _history_v2_entry_access(current) != _history_v2_entry_access(opened):
        raise ValueError(f"{label} access policy changed while being read")
    if current.st_size != opened.st_size or first != baseline or second != baseline:
        raise ValueError(f"{label} content changed while being read")
    return current


def _history_v2_snapshot_entry(
    parent_descriptor: int,
    name: str,
    relative: Path,
    *,
    metadata: os.stat_result,
    max_file_bytes: int,
    label: str,
) -> HistoryV2FileSnapshot:
    if stat.S_ISLNK(metadata.st_mode):
        try:
            current = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise _history_v2_filesystem_error(
                label=label,
                operation="revalidated",
                error=exc,
            ) from exc
        if _history_v2_entry_identity(current) != _history_v2_entry_identity(metadata):
            raise ValueError(f"{label} object identity changed during inspection")
        if _history_v2_entry_access(current) != _history_v2_entry_access(metadata):
            raise ValueError(f"{label} access policy changed during inspection")
        return HistoryV2FileSnapshot(
            relative=relative,
            value=None,
            mode=metadata.st_mode,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            uid=metadata.st_uid,
            gid=metadata.st_gid,
            size=metadata.st_size,
            mtime_ns=metadata.st_mtime_ns,
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} is an unsupported filesystem entry")
    if metadata.st_size < 0 or metadata.st_size > max_file_bytes:
        raise ValueError(f"{label} exceeds the trusted size limit")

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(
            name,
            flags,
            dir_fd=parent_descriptor,
        )
    except OSError as exc:
        raise _history_v2_filesystem_error(
            label=label,
            operation="opened as a regular file",
            error=exc,
        ) from exc
    try:
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or _history_v2_entry_identity(
                opened
            ) != _history_v2_entry_identity(metadata):
                raise ValueError(f"{label} object identity changed while being opened")
            if _history_v2_entry_access(opened) != _history_v2_entry_access(metadata):
                raise ValueError(f"{label} access policy changed while being opened")
            if opened.st_size != metadata.st_size:
                raise ValueError(f"{label} content changed while being opened")
            mtime_changed = opened.st_mtime_ns != metadata.st_mtime_ns

            first = _history_v2_read_exact_file(
                descriptor,
                expected_size=opened.st_size,
            )
            os.lseek(descriptor, 0, os.SEEK_SET)
            second = _history_v2_read_exact_file(
                descriptor,
                expected_size=opened.st_size,
            )
            final = os.fstat(descriptor)
        except OSError as exc:
            raise _history_v2_filesystem_error(
                label=label,
                operation="read within its bounds",
                error=exc,
            ) from exc

        if _history_v2_entry_identity(final) != _history_v2_entry_identity(opened):
            raise ValueError(f"{label} object identity changed while being read")
        if _history_v2_entry_access(final) != _history_v2_entry_access(opened):
            raise ValueError(f"{label} access policy changed while being read")
        if first != second or final.st_size != opened.st_size:
            raise ValueError(f"{label} content changed while being read")
        if mtime_changed or final.st_mtime_ns != opened.st_mtime_ns:
            try:
                final = _history_v2_revalidate_open_file(
                    descriptor,
                    baseline=first,
                    opened=opened,
                    label=label,
                )
            except OSError as exc:
                raise _history_v2_filesystem_error(
                    label=label,
                    operation="revalidated",
                    error=exc,
                ) from exc
        for attempt in range(3):
            try:
                current = os.stat(
                    name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise _history_v2_filesystem_error(
                    label=label,
                    operation="revalidated",
                    error=exc,
                ) from exc
            if _history_v2_entry_identity(current) != _history_v2_entry_identity(
                opened
            ):
                raise ValueError(f"{label} object identity changed during revalidation")
            if _history_v2_entry_access(current) != _history_v2_entry_access(opened):
                raise ValueError(f"{label} access policy changed during revalidation")
            if current.st_size != opened.st_size:
                raise ValueError(f"{label} content changed during revalidation")
            if current.st_mtime_ns == final.st_mtime_ns:
                break
            if attempt == 2:
                raise ValueError(f"{label} could not be revalidated")
            try:
                final = _history_v2_revalidate_open_file(
                    descriptor,
                    baseline=first,
                    opened=opened,
                    label=label,
                )
            except OSError as exc:
                raise _history_v2_filesystem_error(
                    label=label,
                    operation="revalidated",
                    error=exc,
                ) from exc
        return HistoryV2FileSnapshot(
            relative=relative,
            value=first,
            mode=current.st_mode,
            device=current.st_dev,
            inode=current.st_ino,
            uid=current.st_uid,
            gid=current.st_gid,
            size=current.st_size,
            mtime_ns=current.st_mtime_ns,
        )
    finally:
        os.close(descriptor)


def _history_v2_validate_relative_file_path(relative: Path) -> None:
    path_text = relative.as_posix()
    if (
        not path_text
        or relative.is_absolute()
        or Path(path_text) != relative
        or any(part in {"", ".", ".."} for part in relative.parts)
        or len(relative.parts) > HISTORY_V2_MAX_PATH_DEPTH
        or len(path_text.encode("utf-8")) > 1024
    ):
        raise ValueError("candidate artifact path is outside policy")
    if any(
        unicodedata.normalize("NFKC", part).casefold()
        in FORBIDDEN_EXACT_PATH_COMPONENTS
        for part in relative.parts
    ):
        raise ValueError(
            "candidate artifact path contains prohibited sensitive material"
        )


def _history_v2_snapshot_relative_file(
    root_descriptor: int,
    relative: Path,
    *,
    max_file_bytes: int,
    label: str,
) -> HistoryV2FileSnapshot:
    _history_v2_validate_relative_file_path(relative)
    parent_descriptor = os.dup(root_descriptor)
    try:
        for component in relative.parts[:-1]:
            try:
                metadata = os.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise _history_v2_filesystem_error(
                    label=label,
                    operation="inspected",
                    error=exc,
                ) from exc
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError(f"{label} parent is not a directory")
            try:
                child_descriptor = os.open(
                    component,
                    os.O_RDONLY
                    | os.O_CLOEXEC
                    | os.O_DIRECTORY
                    | os.O_NOFOLLOW
                    | getattr(os, "O_NONBLOCK", 0),
                    dir_fd=parent_descriptor,
                )
            except OSError as exc:
                raise _history_v2_filesystem_error(
                    label=label,
                    operation="opened beneath the trusted root",
                    error=exc,
                ) from exc
            opened = os.fstat(child_descriptor)
            if not stat.S_ISDIR(opened.st_mode) or _history_v2_entry_identity(
                opened
            ) != _history_v2_entry_identity(metadata):
                os.close(child_descriptor)
                raise ValueError(
                    f"{label} parent object identity changed during inspection"
                )
            os.close(parent_descriptor)
            parent_descriptor = child_descriptor
        name = relative.parts[-1]
        try:
            metadata = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise _history_v2_filesystem_error(
                label=label,
                operation="inspected",
                error=exc,
            ) from exc
        return _history_v2_snapshot_entry(
            parent_descriptor,
            name,
            relative,
            metadata=metadata,
            max_file_bytes=max_file_bytes,
            label=label,
        )
    finally:
        os.close(parent_descriptor)


def snapshot_explicit_history_v2_files(
    root: Path,
    relatives: Sequence[Path],
    *,
    max_entries: int,
    max_file_bytes: int = BOOTSTRAP_V2_MAX_FILE_BYTES,
    max_tree_bytes: int = BOOTSTRAP_V2_MAX_TREE_BYTES,
    label: str = "candidate artifact",
) -> tuple[tuple[HistoryV2FileSnapshot, ...] | None, str | None]:
    if len(relatives) > max_entries or len(set(relatives)) != len(relatives):
        return None, f"{label} enumeration exceeds the trusted entry limit"
    try:
        root_descriptor = _history_v2_open_directory(root, label="candidate root")
    except ValueError as exc:
        return None, safe_exception_message(exc)
    snapshots: list[HistoryV2FileSnapshot] = []
    total_bytes = 0
    try:
        for relative in sorted(relatives, key=lambda value: value.as_posix()):
            try:
                snapshot = _history_v2_snapshot_relative_file(
                    root_descriptor,
                    relative,
                    max_file_bytes=max_file_bytes,
                    label=label,
                )
            except ValueError as exc:
                return None, safe_exception_message(exc)
            total_bytes += snapshot.size
            if total_bytes > max_tree_bytes:
                return None, "history-v2 tree exceeds the trusted size limit"
            snapshots.append(snapshot)
    finally:
        os.close(root_descriptor)
    return tuple(snapshots), None


def _git_visible_relatives(
    root: Path,
    *,
    max_entries: int,
) -> tuple[tuple[Path, ...] | None, str | None]:
    try:
        top_value = bounded_process_output(
            closed_git_command(
                "-C",
                str(root),
                "rev-parse",
                "--show-toplevel",
            ),
            max_output_bytes=4096,
            environment=closed_git_environment(),
        ).decode("utf-8")
    except (BoundedProcessError, UnicodeDecodeError):
        return None, "trusted Git file enumeration could not be initialized"
    top = Path(top_value.strip()).resolve()
    try:
        relative_root = root.resolve().relative_to(top)
    except ValueError:
        return None, "trusted Git file enumeration root is invalid"
    pathspec = "." if str(relative_root) == "." else relative_root.as_posix()
    records, record_issue = bounded_git_nul_records(
        closed_git_command(
            "-C",
            str(top),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            pathspec,
        ),
        max_records=max_entries,
        failure_message="trusted Git file enumeration failed closed",
        limit_message="trusted Git file enumeration exceeds the trusted entry limit",
    )
    if record_issue is not None or records is None:
        return None, record_issue or "trusted Git file enumeration failed closed"
    relatives: list[Path] = []
    for raw_path in records:
        try:
            decoded = raw_path.decode("utf-8")
        except UnicodeDecodeError:
            return None, "trusted Git file enumeration contains a non-UTF-8 path"
        relative = PurePosixPath(decoded)
        if (
            not decoded
            or relative.is_absolute()
            or relative.as_posix() != decoded
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            return None, "trusted Git file enumeration contains an invalid path"
        try:
            root_relative = Path(*relative.parts).relative_to(relative_root)
        except ValueError:
            return None, "trusted Git file enumeration escaped its root"
        relatives.append(root_relative)
    if len(set(relatives)) != len(relatives):
        return None, "trusted Git file enumeration contains duplicate paths"
    return tuple(sorted(relatives, key=lambda value: value.as_posix())), None


def git_visible_file_snapshots(
    root: Path,
    *,
    max_entries: int,
) -> tuple[tuple[HistoryV2FileSnapshot, ...] | None, str | None]:
    relatives, issue = _git_visible_relatives(
        root,
        max_entries=max_entries,
    )
    if issue is not None or relatives is None:
        return None, issue or "trusted Git file enumeration failed closed"
    return snapshot_explicit_history_v2_files(
        root,
        relatives,
        max_entries=max_entries,
        label="trusted Git file enumeration entry",
    )


def git_visible_files(
    root: Path,
    *,
    max_entries: int,
) -> tuple[list[Path] | None, str | None]:
    snapshots, issue = git_visible_file_snapshots(
        root,
        max_entries=max_entries,
    )
    if issue is not None or snapshots is None:
        return None, issue
    return [root / snapshot.relative for snapshot in snapshots], None


def iter_files(root: Path) -> list[Path]:
    snapshots, issue = snapshot_bootstrap_v2_files(
        root,
        max_entries=BOOTSTRAP_V2_MAX_CANDIDATE_ENTRIES,
    )
    if issue is not None or snapshots is None:
        raise ValueError(issue or "bounded file enumeration failed closed")
    return [root / snapshot.relative for snapshot in snapshots]


def git_control_path_present(root: Path) -> bool:
    for directory in (root, *root.parents):
        try:
            (directory / ".git").lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return True
        return True
    return False


def _history_v2_bounded_directory_names(
    directory_descriptor: int,
    *,
    max_names: int,
    skip_root_git: bool,
    operation: str,
    limit_message: str,
) -> tuple[str, ...]:
    if max_names < 0:
        raise ValueError(limit_message)
    names: list[str] = []
    try:
        with os.scandir(directory_descriptor) as entries:
            for entry in entries:
                name = entry.name
                if skip_root_git and name == ".git":
                    continue
                if len(names) >= max_names:
                    raise ValueError(limit_message)
                names.append(name)
    except ValueError:
        raise
    except OSError as exc:
        raise _history_v2_filesystem_error(
            label="candidate artifact directory",
            operation=operation,
            error=exc,
        ) from exc
    return tuple(sorted(names))


def snapshot_bootstrap_v2_files(
    root: Path,
    *,
    max_entries: int,
) -> tuple[tuple[HistoryV2FileSnapshot, ...] | None, str | None]:
    try:
        root_descriptor = _history_v2_open_directory(root, label="candidate root")
    except ValueError as exc:
        return None, safe_exception_message(exc)
    snapshots: list[HistoryV2FileSnapshot] = []
    entry_count = 0
    total_bytes = 0

    def walk(
        directory_descriptor: int,
        relative_directory: tuple[str, ...],
    ) -> None:
        nonlocal entry_count, total_bytes
        first_names = _history_v2_bounded_directory_names(
            directory_descriptor,
            max_names=max_entries - entry_count,
            skip_root_git=not relative_directory,
            operation="enumerated",
            limit_message=(
                "candidate artifact enumeration exceeds the trusted entry limit"
            ),
        )
        initial: dict[str, os.stat_result] = {}
        captured: dict[str, HistoryV2FileSnapshot] = {}
        for name in first_names:
            if not name or name in {".", ".."}:
                raise ValueError(
                    "candidate artifact enumeration contains an invalid entry"
                )
            try:
                name.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError(
                    "candidate artifact enumeration contains a non-UTF-8 path"
                ) from exc
            entry_count += 1
            relative = Path(*relative_directory, name)
            _history_v2_validate_relative_file_path(relative)
            try:
                metadata = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise _history_v2_filesystem_error(
                    label="candidate artifact entry",
                    operation="inspected",
                    error=exc,
                ) from exc
            initial[name] = metadata
            if stat.S_ISDIR(metadata.st_mode):
                if name == ".git":
                    raise ValueError(
                        "candidate artifact enumeration found nested Git metadata"
                    )
                try:
                    child_descriptor = os.open(
                        name,
                        os.O_RDONLY
                        | os.O_CLOEXEC
                        | os.O_DIRECTORY
                        | os.O_NOFOLLOW
                        | getattr(os, "O_NONBLOCK", 0),
                        dir_fd=directory_descriptor,
                    )
                except OSError as exc:
                    raise _history_v2_filesystem_error(
                        label="candidate artifact directory",
                        operation="opened beneath the trusted root",
                        error=exc,
                    ) from exc
                try:
                    opened = os.fstat(child_descriptor)
                    if not stat.S_ISDIR(opened.st_mode) or _history_v2_entry_identity(
                        opened
                    ) != _history_v2_entry_identity(metadata):
                        raise ValueError(
                            "candidate artifact directory object identity changed"
                        )
                    if _history_v2_entry_access(opened) != _history_v2_entry_access(
                        metadata
                    ):
                        raise ValueError(
                            "candidate artifact directory access policy changed"
                        )
                    walk(child_descriptor, (*relative_directory, name))
                    final = os.fstat(child_descriptor)
                finally:
                    os.close(child_descriptor)
                if _history_v2_entry_identity(final) != _history_v2_entry_identity(
                    opened
                ):
                    raise ValueError(
                        "candidate artifact directory object identity changed"
                    )
                if _history_v2_entry_access(final) != _history_v2_entry_access(opened):
                    raise ValueError(
                        "candidate artifact directory access policy changed"
                    )
            elif stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                snapshot = _history_v2_snapshot_entry(
                    directory_descriptor,
                    name,
                    relative,
                    metadata=metadata,
                    max_file_bytes=BOOTSTRAP_V2_MAX_FILE_BYTES,
                    label="candidate artifact",
                )
                total_bytes += snapshot.size
                if total_bytes > BOOTSTRAP_V2_MAX_TREE_BYTES:
                    raise ValueError("history-v2 tree exceeds the trusted size limit")
                captured[name] = snapshot
                snapshots.append(snapshot)
            else:
                raise ValueError(
                    "candidate artifact enumeration found an unsupported filesystem entry"
                )

        final_names = _history_v2_bounded_directory_names(
            directory_descriptor,
            max_names=len(first_names),
            skip_root_git=not relative_directory,
            operation="revalidated",
            limit_message=(
                "candidate artifact directory content changed during enumeration"
            ),
        )
        if final_names != first_names:
            raise ValueError(
                "candidate artifact directory content changed during enumeration"
            )
        for name, metadata in initial.items():
            try:
                current = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise _history_v2_filesystem_error(
                    label="candidate artifact entry",
                    operation="revalidated",
                    error=exc,
                ) from exc
            if _history_v2_entry_identity(current) != _history_v2_entry_identity(
                metadata
            ):
                raise ValueError(
                    "candidate artifact object identity changed during enumeration"
                )
            if _history_v2_entry_access(current) != _history_v2_entry_access(metadata):
                raise ValueError(
                    "candidate artifact access policy changed during enumeration"
                )
            if stat.S_ISREG(metadata.st_mode):
                if current.st_size != metadata.st_size:
                    raise ValueError(
                        "candidate artifact content changed during enumeration"
                    )
                if current.st_mtime_ns != metadata.st_mtime_ns:
                    refreshed = _history_v2_snapshot_entry(
                        directory_descriptor,
                        name,
                        Path(*relative_directory, name),
                        metadata=current,
                        max_file_bytes=BOOTSTRAP_V2_MAX_FILE_BYTES,
                        label="candidate artifact",
                    )
                    if not _history_v2_snapshot_protected_equal(
                        captured[name],
                        refreshed,
                    ):
                        raise ValueError(
                            "candidate artifact content changed during enumeration"
                        )

    try:
        walk(root_descriptor, ())
    except ValueError as exc:
        return None, safe_exception_message(exc)
    finally:
        os.close(root_descriptor)
    return (
        tuple(sorted(snapshots, key=lambda value: value.relative.as_posix())),
        None,
    )


def iter_bootstrap_v2_files(
    root: Path, *, max_entries: int
) -> tuple[list[Path] | None, str | None]:
    snapshots, issue = snapshot_bootstrap_v2_files(
        root,
        max_entries=max_entries,
    )
    if issue is not None or snapshots is None:
        return None, issue
    return [root / snapshot.relative for snapshot in snapshots], None


class GitIndexEntry(NamedTuple):
    mode: str
    object_id: str


def git_blob_object_id(path: Path, *, size: int, expected_length: int) -> str:
    snapshots, issue = snapshot_explicit_history_v2_files(
        path.parent,
        (Path(path.name),),
        max_entries=1,
        max_file_bytes=max(size, 0),
        max_tree_bytes=max(size, 0),
        label="Git blob source",
    )
    if issue is not None or snapshots is None:
        raise ValueError(issue or "Git blob source could not be read safely")
    snapshot = snapshots[0]
    if not snapshot.is_regular or snapshot.value is None or snapshot.size != size:
        raise ValueError("Git blob source size changed while being read")
    digest = git_blob_digest(size=size, expected_length=expected_length)
    digest.update(snapshot.value)
    return digest.hexdigest()


def git_blob_bytes_object_id(value: bytes, *, expected_length: int) -> str:
    digest = git_blob_digest(size=len(value), expected_length=expected_length)
    digest.update(value)
    return digest.hexdigest()


def git_blob_digest(*, size: int, expected_length: int) -> Any:
    if expected_length == 40:
        digest = hashlib.sha1(usedforsecurity=False)
    elif expected_length == 64:
        digest = hashlib.sha256()
    else:
        raise ValueError("Git object ID uses an unsupported hash format")
    digest.update(b"blob " + str(size).encode("ascii") + NUL_BYTE)
    return digest


def bounded_git_nul_records(
    command: list[str],
    *,
    max_records: int,
    failure_message: str,
    limit_message: str,
) -> tuple[list[bytes] | None, str | None]:
    pending = bytearray()
    record_count = 0

    def enforce_record_limit(chunk: bytes) -> None:
        nonlocal record_count
        pending.extend(chunk)
        while True:
            separator = pending.find(NUL_BYTE)
            if separator < 0:
                return
            record = bytes(pending[:separator])
            del pending[: separator + 1]
            if not record:
                continue
            record_count += 1
            if record_count > max_records:
                raise BoundedProcessLimitError(limit_message)

    try:
        output = bounded_process_output(
            command,
            max_output_bytes=BOOTSTRAP_V2_MAX_GIT_METADATA_BYTES,
            environment=closed_git_environment(),
            chunk_validator=enforce_record_limit,
        )
    except BoundedProcessLimitError:
        return None, limit_message
    except BoundedProcessError:
        return None, failure_message
    records: list[bytes] = []
    fields = output.split(NUL_BYTE)
    if fields[-1:] != [b""]:
        return None, failure_message
    for record in fields[:-1]:
        if not record:
            continue
        if len(records) >= max_records:
            return None, limit_message
        records.append(record)
    return records, None


def git_index_entries(
    root: Path, *, label: str, max_entries: int
) -> tuple[dict[Path, GitIndexEntry] | None, str | None]:
    try:
        top_value = bounded_process_output(
            closed_git_command(
                "-C",
                str(root),
                "rev-parse",
                "--show-toplevel",
            ),
            max_output_bytes=4096,
            environment=closed_git_environment(),
        ).decode("utf-8")
    except (BoundedProcessError, UnicodeDecodeError):
        return None, f"{label} root must be a Git worktree with an inspectable index"
    top = Path(top_value.strip()).resolve()
    resolved_root = root.resolve()
    try:
        relative_root = resolved_root.relative_to(top)
    except ValueError:
        return None, f"{label} root is outside its Git worktree"
    try:
        index_value = bounded_process_output(
            closed_git_command(
                "-C",
                str(top),
                "rev-parse",
                "--git-path",
                "index",
            ),
            max_output_bytes=4096,
            environment=closed_git_environment(),
        ).decode("utf-8")
    except (BoundedProcessError, UnicodeDecodeError):
        return None, f"{label} Git index path could not be inspected"
    index_path = Path(index_value.strip())
    if not index_path.is_absolute():
        index_path = top / index_path
    try:
        index_descriptor = os.open(
            index_path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
        )
        try:
            index_metadata = os.fstat(index_descriptor)
        finally:
            os.close(index_descriptor)
    except OSError:
        return None, f"{label} Git index must be an existing readable regular file"
    if not stat.S_ISREG(index_metadata.st_mode):
        return None, f"{label} Git index must be an existing regular file"
    pathspec = "." if str(relative_root) == "." else relative_root.as_posix()
    records, records_issue = bounded_git_nul_records(
        closed_git_command(
            "-C",
            str(top),
            "ls-files",
            "--stage",
            "-z",
            "--",
            pathspec,
        ),
        max_records=max_entries,
        failure_message=f"{label} Git index could not be inspected",
        limit_message=f"{label} Git index enumeration exceeds the trusted entry limit",
    )
    if records_issue is not None:
        return None, records_issue
    if records is None:
        return None, f"{label} Git index could not be inspected"

    entries: dict[Path, GitIndexEntry] = {}
    for record in records:
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            return None, f"{label} Git index returned malformed metadata"
        raw_mode, raw_object_id, raw_stage = fields
        if raw_stage != b"0":
            return None, f"{label} Git index contains unresolved entries"
        try:
            indexed_path = (top / raw_path.decode("utf-8")).relative_to(resolved_root)
            mode = raw_mode.decode("ascii")
            object_id = raw_object_id.decode("ascii")
        except (UnicodeDecodeError, ValueError):
            return None, f"{label} Git index contains invalid metadata"
        if (
            re.fullmatch(r"[0-9]{6}", mode) is None
            or re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", object_id) is None
        ):
            return None, f"{label} Git index contains invalid metadata"
        if indexed_path in entries:
            return None, f"{label} Git index contains duplicate paths"
        entries[indexed_path] = GitIndexEntry(mode, object_id)
    return entries, None


def forbidden_name(name: str) -> bool:
    if (
        unicodedata.normalize("NFKC", name).casefold()
        in FORBIDDEN_EXACT_PATH_COMPONENTS
    ):
        return True
    stem = name
    while Path(stem).suffix.lower() in STRIPPABLE_ARTIFACT_SUFFIXES:
        next_stem = Path(stem).with_suffix("").name
        if next_stem == stem:
            break
        stem = next_stem
    if sensitive_path_component(name, stem=stem):
        return True
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", stem)
    tokens = [token for token in re.split(r"[^a-z0-9]+", separated.lower()) if token]
    normalized = "_".join(tokens)
    if sensitive_path_component(normalized):
        return True
    if normalized in FORBIDDEN_NAME_STEMS:
        return True
    compacted = "".join(tokens)
    if any(compacted.startswith(prefix) for prefix in FORBIDDEN_COMPACT_NAME_PREFIXES):
        return True
    return any(part in compacted for part in FORBIDDEN_COMPACT_NAME_PARTS)


def sensitive_path_component(part: str, *, stem: str | None = None) -> bool:
    stem = part if stem is None else stem
    if RAW_ID_TOKEN_RE.search(part) or RAW_ID_TOKEN_RE.search(stem):
        return True
    if SENSITIVE_TOKEN_RE.search(stem):
        return True
    return any(
        pattern.search(part) or pattern.search(stem)
        for pattern in BOOTSTRAP_V2_PRIVACY_RISK_PATTERNS
    )


def forbidden_history_v2_path_component(part: str) -> bool:
    normalized = unicodedata.normalize("NFKC", part).casefold()
    return (
        normalized in FORBIDDEN_COMPONENTS
        or normalized in FORBIDDEN_EXACT_PATH_COMPONENTS
        or forbidden_name(part)
    )


def escape_diagnostic_path_text(value: str) -> str:
    escaped: list[str] = []
    for character in value:
        codepoint = ord(character)
        if character == "\\":
            escaped.append("\\\\")
        elif character.isprintable():
            escaped.append(character)
        elif codepoint <= 0xFF:
            escaped.append(f"\\x{codepoint:02x}")
        elif codepoint <= 0xFFFF:
            escaped.append(f"\\u{codepoint:04x}")
        else:
            escaped.append(f"\\U{codepoint:08x}")
    return "".join(escaped)


def display_path_component(part: str) -> str:
    stem = part
    suffixes: list[str] = []
    while Path(stem).suffix.lower() in STRIPPABLE_ARTIFACT_SUFFIXES:
        suffix = Path(stem).suffix
        next_stem = Path(stem).with_suffix("").name
        if next_stem == stem:
            break
        suffixes.insert(0, suffix)
        stem = next_stem
    displayed = (
        "[redacted]" + "".join(suffixes)
        if sensitive_path_component(part, stem=stem)
        else part
    )
    return escape_diagnostic_path_text(displayed)


def display_relative_path(relative: Path) -> str:
    displayed = "/".join(display_path_component(part) for part in relative.parts)
    if displayed.startswith("::"):
        return "\\x3a" + displayed[1:]
    return displayed


def safe_exception_message(exc: Exception) -> str:
    if isinstance(exc, OSError):
        reason = exc.strerror or exc.__class__.__name__
        return f"{exc.__class__.__name__}: {reason}"
    if isinstance(exc, UnicodeDecodeError):
        return "UnicodeDecodeError: failed to decode as UTF-8"
    if isinstance(exc, json.JSONDecodeError):
        return f"JSONDecodeError: {exc.msg}"
    return str(exc)


def forbidden_path(relative: Path) -> bool:
    parts = tuple(part.lower() for part in relative.parts)
    if any(part in FORBIDDEN_COMPONENTS or forbidden_name(part) for part in parts[:-1]):
        return True
    name = relative.name.lower()
    return (
        name in FORBIDDEN_FILENAMES
        or forbidden_name(name)
        or name.startswith("rollout")
    )


def reject_duplicate_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    parsed: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError("duplicate JSON key is not allowed")
        seen.add(key)
        parsed[key] = value
    return parsed


def reject_non_finite_json_constant(_value: str) -> Any:
    raise ValueError("non-finite JSON numbers are not allowed")


def parse_finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite JSON numbers are not allowed")
    return parsed


STRICT_JSON_NUMBER_CANDIDATE_RE = re.compile(
    r"[+-]?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?"
)
JSON_NESTING_ERROR = "JSON nesting exceeds the trusted depth limit"


def parse_strict_json(value: str) -> Any:
    try:
        return json.loads(
            value,
            object_pairs_hook=reject_duplicate_json_object,
            parse_constant=reject_non_finite_json_constant,
            parse_float=parse_finite_json_float,
        )
    except RecursionError:
        raise ValueError(JSON_NESTING_ERROR) from None


def _decode_bounded_utf8(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        raise


def parse_json_bytes(value: bytes) -> Any:
    return parse_strict_json(_decode_bounded_utf8(value))


def parse_jsonl_bytes(value: bytes) -> list[Any]:
    rows: list[Any] = []
    text = _decode_bounded_utf8(value)
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        if len(rows) >= HISTORY_V2_MAX_JSONL_ROWS:
            raise ValueError("JSONL row count exceeds the trusted limit")
        try:
            rows.append(parse_strict_json(line))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"line {line_no}: invalid JSONL: {exc}") from exc
    return rows


def _read_bounded_path_value(path: Path) -> bytes:
    snapshots, issue = snapshot_explicit_history_v2_files(
        path.parent,
        (Path(path.name),),
        max_entries=1,
        max_file_bytes=BOOTSTRAP_V2_MAX_FILE_BYTES,
        max_tree_bytes=BOOTSTRAP_V2_MAX_FILE_BYTES,
        label="retained artifact",
    )
    if issue is not None or snapshots is None:
        raise ValueError(issue or "retained artifact could not be read safely")
    snapshot = snapshots[0]
    if snapshot.value is None or not snapshot.is_regular:
        raise ValueError("retained artifact is not a regular file")
    return snapshot.value


def parse_json(path: Path) -> Any:
    return parse_json_bytes(_read_bounded_path_value(path))


def parse_jsonl(path: Path) -> list[Any]:
    return parse_jsonl_bytes(_read_bounded_path_value(path))


class StrictWorkflowYamlParser:
    """Parse the deliberately small YAML subset used by the trusted workflow."""

    def __init__(self, value: str) -> None:
        if "\t" in value:
            raise ValueError("bootstrap workflow YAML must not contain tabs")
        self.lines = value.splitlines()

    def parse(self) -> dict[str, Any]:
        index = self.next_nonempty(0)
        if index == len(self.lines):
            raise ValueError("bootstrap workflow YAML must not be empty")
        parsed, index = self.parse_node(index, 0)
        if self.next_nonempty(index) != len(self.lines):
            raise ValueError("bootstrap workflow YAML has trailing content")
        if not isinstance(parsed, dict):
            raise ValueError("bootstrap workflow YAML root must be a mapping")
        return parsed

    def next_nonempty(self, index: int) -> int:
        while index < len(self.lines) and not self.lines[index].strip():
            index += 1
        return index

    def split_line(self, index: int) -> tuple[int, str]:
        raw = self.lines[index]
        if raw.rstrip(" ") != raw:
            raise ValueError(
                f"bootstrap workflow YAML line {index + 1} has trailing whitespace"
            )
        indent = len(raw) - len(raw.lstrip(" "))
        if indent % 2:
            raise ValueError(
                f"bootstrap workflow YAML line {index + 1} has invalid indentation"
            )
        content = raw[indent:]
        if content.startswith("#") or content in {"---", "..."}:
            raise ValueError(
                f"bootstrap workflow YAML line {index + 1} uses unsupported syntax"
            )
        return indent, content

    def parse_node(self, index: int, indent: int) -> tuple[Any, int]:
        actual_indent, content = self.split_line(index)
        if actual_indent != indent:
            raise ValueError(
                f"bootstrap workflow YAML line {index + 1} has unexpected indentation"
            )
        if content == "-" or content.startswith("- "):
            return self.parse_sequence(index, indent)
        return self.parse_mapping(index, indent)

    def parse_mapping(self, index: int, indent: int) -> tuple[dict[str, Any], int]:
        parsed: dict[str, Any] = {}
        while True:
            index = self.next_nonempty(index)
            if index == len(self.lines):
                break
            actual_indent, content = self.split_line(index)
            if actual_indent < indent:
                break
            if actual_indent > indent:
                raise ValueError(
                    f"bootstrap workflow YAML line {index + 1} has unexpected indentation"
                )
            if content == "-" or content.startswith("- "):
                break
            key, separator, remainder = content.partition(":")
            if not separator or re.fullmatch(r"[A-Za-z0-9_-]+", key) is None:
                raise ValueError(
                    f"bootstrap workflow YAML line {index + 1} has an invalid mapping key"
                )
            if key in parsed:
                raise ValueError(
                    f"bootstrap workflow YAML line {index + 1} column {indent + 1} "
                    "contains a duplicate mapping key (duplicate key: name is withheld)"
                )
            if remainder and not remainder.startswith(" "):
                raise ValueError(
                    f"bootstrap workflow YAML line {index + 1} must separate values with a space"
                )
            remainder = remainder[1:] if remainder else ""
            if remainder == "|":
                value, index = self.parse_literal(index + 1, indent + 2)
            elif remainder:
                value = self.parse_scalar(remainder, index + 1)
                index += 1
            else:
                child_index = self.next_nonempty(index + 1)
                if child_index == len(self.lines):
                    raise ValueError(
                        f"bootstrap workflow YAML line {index + 1} column {indent + 1} "
                        "has a mapping key without a value"
                    )
                child_indent, _ = self.split_line(child_index)
                if child_indent != indent + 2:
                    raise ValueError(
                        f"bootstrap workflow YAML line {child_index + 1} column {child_indent + 1} "
                        "has invalid child indentation"
                    )
                value, index = self.parse_node(child_index, indent + 2)
            parsed[key] = value
        return parsed, index

    def parse_sequence(self, index: int, indent: int) -> tuple[list[Any], int]:
        parsed: list[Any] = []
        while True:
            index = self.next_nonempty(index)
            if index == len(self.lines):
                break
            actual_indent, content = self.split_line(index)
            if actual_indent < indent:
                break
            if actual_indent > indent:
                raise ValueError(
                    f"bootstrap workflow YAML line {index + 1} has unexpected indentation"
                )
            if content == "-":
                child_index = self.next_nonempty(index + 1)
                if child_index == len(self.lines):
                    raise ValueError(
                        "bootstrap workflow YAML sequence item must have a value"
                    )
                child_indent, _ = self.split_line(child_index)
                if child_indent != indent + 2:
                    raise ValueError(
                        f"bootstrap workflow YAML line {child_index + 1} has invalid sequence indentation"
                    )
                value, index = self.parse_node(child_index, indent + 2)
            elif content.startswith("- "):
                value = self.parse_scalar(content[2:], index + 1)
                index += 1
                child_index = self.next_nonempty(index)
                if child_index < len(self.lines):
                    child_indent, _ = self.split_line(child_index)
                    if child_indent > indent:
                        raise ValueError(
                            f"bootstrap workflow YAML line {child_index + 1} cannot extend a scalar sequence item"
                        )
            else:
                break
            parsed.append(value)
        return parsed, index

    def parse_literal(self, index: int, indent: int) -> tuple[str, int]:
        lines: list[str] = []
        has_content = False
        while index < len(self.lines):
            raw = self.lines[index]
            if not raw.strip():
                lines.append("")
                index += 1
                continue
            if raw.rstrip(" ") != raw:
                raise ValueError(
                    f"bootstrap workflow YAML line {index + 1} has trailing whitespace"
                )
            actual_indent = len(raw) - len(raw.lstrip(" "))
            if actual_indent < indent:
                break
            lines.append(raw[indent:])
            has_content = True
            index += 1
        if not has_content:
            raise ValueError("bootstrap workflow YAML literal block must not be empty")
        return "\n".join(lines) + "\n", index

    @staticmethod
    def parse_scalar(value: str, line_no: int) -> Any:
        if value.startswith('"'):
            try:
                parsed = parse_strict_json(value)
            except (json.JSONDecodeError, ValueError):
                raise ValueError(
                    f"bootstrap workflow YAML line {line_no} has an invalid quoted scalar"
                ) from None
            if not isinstance(parsed, str):
                raise ValueError(
                    f"bootstrap workflow YAML line {line_no} must use a string scalar"
                )
            return parsed
        if value == "{}":
            return {}
        if value == "true":
            return True
        if value == "false":
            return False
        if value == "null":
            return None
        if value in {"NaN", "Infinity", "+Infinity", "-Infinity"} or (
            STRICT_JSON_NUMBER_CANDIDATE_RE.fullmatch(value) is not None
        ):
            try:
                return parse_strict_json(value)
            except (json.JSONDecodeError, ValueError):
                raise ValueError(
                    f"bootstrap workflow YAML line {line_no} has an invalid numeric scalar"
                ) from None
        if value.startswith(("'", "[", "{", "&", "*", "!", "|", ">")) or " #" in value:
            raise ValueError(
                f"bootstrap workflow YAML line {line_no} uses unsupported scalar syntax"
            )
        return value


def parse_strict_workflow_yaml(value: str) -> dict[str, Any]:
    return StrictWorkflowYamlParser(value).parse()


def bootstrap_workflow_policy_fingerprint(value: Any) -> str:
    canonical = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_bootstrap_workflow(value: str) -> list[str]:
    parsed = parse_strict_workflow_yaml(value)
    if (
        bootstrap_workflow_policy_fingerprint(parsed)
        != BOOTSTRAP_WORKFLOW_POLICY_SHA256
    ):
        return ["bootstrap workflow structure differs from the trusted policy"]
    return []


def contains_risky_text(value: Any, *, include_safety_markers: bool = True) -> bool:
    if isinstance(value, str):
        return any(
            pattern.search(value)
            for pattern in RISK_PATTERNS
            if include_safety_markers or pattern is not RETAINED_SAFETY_TEXT_RE
        )
    if isinstance(value, dict):
        return any(
            contains_risky_text(child, include_safety_markers=include_safety_markers)
            for child in value.values()
        )
    if isinstance(value, list):
        return any(
            contains_risky_text(child, include_safety_markers=include_safety_markers)
            for child in value
        )
    return False


def infrastructure_risk_lines(value: str, *, relative: Path | None = None) -> list[str]:
    risky_lines: list[str] = []
    for line in value.splitlines():
        if (
            relative in BOOTSTRAP_SECURITY_WORKFLOW_PATHS
            and line in BOOTSTRAP_SAFE_INFRASTRUCTURE_LINES
        ):
            continue
        normalized_line = line.strip().rstrip(",").strip("\"'")
        if normalized_line in SAFE_INFRASTRUCTURE_LINES:
            continue
        if any(pattern.search(line) for pattern in INFRASTRUCTURE_RISK_PATTERNS):
            risky_lines.append(line)
    return risky_lines


def contains_infrastructure_risk_text(
    value: str, *, relative: Path | None = None
) -> bool:
    risky_lines = infrastructure_risk_lines(value, relative=relative)
    if not risky_lines:
        return False
    expected_fingerprint = INFRASTRUCTURE_TRUSTED_RISK_LINES_SHA256.get(relative)
    return (
        expected_fingerprint is None
        or bootstrap_v2_privacy_risk_lines_fingerprint(risky_lines)
        != expected_fingerprint
    )


def read_bootstrap_v2_yaml_folded_line_break(
    value: str, offset: int
) -> tuple[str, int]:
    if value.startswith("\r\n", offset):
        offset += 2
    else:
        offset += 1
    blank_lines = 0
    while offset < len(value):
        while offset < len(value) and value[offset] in {" ", "\t"}:
            offset += 1
        if value.startswith("\r\n", offset):
            blank_lines += 1
            offset += 2
            continue
        if offset < len(value) and value[offset] in {"\r", "\n"}:
            blank_lines += 1
            offset += 1
            continue
        break
    return ("\n" * blank_lines if blank_lines else " "), offset


def read_bootstrap_v2_yaml_quoted_scalar(
    value: str, offset: int
) -> tuple[str, int] | None:
    quote = value[offset]
    if quote == "'":
        decoded: list[str] = []
        offset += 1
        while offset < len(value):
            character = value[offset]
            if character in {"\r", "\n"}:
                folded, offset = read_bootstrap_v2_yaml_folded_line_break(value, offset)
                decoded.append(folded)
                continue
            if character != "'":
                decoded.append(character)
                offset += 1
                continue
            if offset + 1 < len(value) and value[offset + 1] == "'":
                decoded.append("'")
                offset += 2
                continue
            return "".join(decoded), offset + 1
        return None

    escapes = {
        "0": NUL_TEXT,
        "a": "\a",
        "b": "\b",
        "t": "\t",
        "n": "\n",
        "v": "\v",
        "f": "\f",
        "r": "\r",
        "e": "\x1b",
        " ": " ",
        '"': '"',
        "/": "/",
        "\\": "\\",
        "N": "\u0085",
        "_": "\u00a0",
        "L": "\u2028",
        "P": "\u2029",
    }
    decoded = []
    offset += 1
    while offset < len(value):
        character = value[offset]
        if character == '"':
            return "".join(decoded), offset + 1
        if character in {"\r", "\n"}:
            folded, offset = read_bootstrap_v2_yaml_folded_line_break(value, offset)
            decoded.append(folded)
            continue
        if character != "\\":
            decoded.append(character)
            offset += 1
            continue
        if offset + 1 >= len(value):
            return None
        if value[offset + 1] in {"\r", "\n"}:
            folded, offset = read_bootstrap_v2_yaml_folded_line_break(value, offset + 1)
            decoded.append(folded if "\n" in folded else "")
            continue
        escape = value[offset + 1]
        if escape in escapes:
            decoded.append(escapes[escape])
            offset += 2
            continue
        widths = {"x": 2, "u": 4, "U": 8}
        width = widths.get(escape)
        if width is None or offset + 2 + width > len(value):
            return None
        encoded_codepoint = value[offset + 2 : offset + 2 + width]
        if re.fullmatch(r"[0-9A-Fa-f]+", encoded_codepoint) is None:
            return None
        codepoint = int(encoded_codepoint, 16)
        if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
            return None
        decoded.append(chr(codepoint))
        offset += 2 + width
    return None


class BootstrapV2YamlToken(NamedTuple):
    kind: str
    value: str
    start: int
    end: int
    scan_value: str | None = None


class BootstrapV2YamlLinePrefix:
    __slots__ = (
        "_block_scalar_base_indent",
        "_block_scalar_candidate",
        "_header_state",
        "_indent_open",
        "_line_end",
        "_mapping_key_indent",
        "_node_context",
        "_operation_counts",
        "_property_characters",
        "_property_kind",
        "_seen_anchor_property",
        "_seen_tag_property",
        "header_indent",
        "line_start",
        "position",
    )

    def __init__(self, operation_counts: dict[str, int] | None) -> None:
        self._operation_counts = operation_counts
        self.position = 0
        self.line_start = 0
        self.header_indent = 0
        self._indent_open = True
        self._header_state = "leading"
        self._block_scalar_base_indent: int | None = None
        self._block_scalar_candidate = False
        self._mapping_key_indent: int | None = None
        self._node_context: str | None = None
        self._property_characters: list[str] = []
        self._property_kind: str | None = None
        self._seen_anchor_property = False
        self._seen_tag_property = False
        self._line_end: int | None = None

    def record_operation(self, name: str, amount: int = 1) -> None:
        if self._operation_counts is not None:
            self._operation_counts[name] = self._operation_counts.get(name, 0) + amount

    def consume(self, value: str, start: int, end: int) -> None:
        if start != self.position or end < start:
            raise AssertionError(
                "bootstrap workflow YAML tokenizer lost its line state"
            )
        self.record_operation("line_prefix_characters", end - start)
        for index in range(start, end):
            character = value[index]
            if character == "\n":
                self.line_start = index + 1
                self.header_indent = 0
                self._indent_open = True
                self._header_state = "leading"
                self._block_scalar_base_indent = None
                self._block_scalar_candidate = False
                self._mapping_key_indent = None
                self._node_context = None
                self._property_characters.clear()
                self._property_kind = None
                self._seen_anchor_property = False
                self._seen_tag_property = False
                self._line_end = None
                continue
            if self._indent_open:
                if character == " ":
                    self.header_indent += 1
                else:
                    self._indent_open = False
            self.consume_header_character(character, index - self.line_start)
        self.position = end

    def start_mapping_key(self, character: str, column: int) -> None:
        self._mapping_key_indent = column
        self._block_scalar_candidate = False
        if character == "'":
            self._header_state = "single_quoted_key"
        elif character == '"':
            self._header_state = "double_quoted_key"
        elif character == ":":
            self._header_state = "mapping_colon"
            self._block_scalar_candidate = True
        else:
            self._header_state = "plain_key"

    def start_node_property(
        self,
        character: str,
        *,
        context: str,
        base_indent: int,
    ) -> None:
        self._header_state = "node_property"
        self._node_context = context
        self._block_scalar_base_indent = base_indent
        self._block_scalar_candidate = True
        self._property_kind = "tag" if character == "!" else "anchor"
        self._property_characters.clear()
        self._property_characters.append(character)

    def finish_node_property(self) -> None:
        property_value = "".join(self._property_characters)
        if self._property_kind == "anchor":
            valid = (
                len(property_value) > 1
                and not self._seen_anchor_property
                and not any(
                    character.isspace() or character in "[]{},"
                    for character in property_value[1:]
                )
            )
            self._seen_anchor_property = True
        else:
            verbatim = property_value.startswith("!<")
            valid = not self._seen_tag_property and (
                property_value == "!"
                or (
                    verbatim
                    and len(property_value) > 3
                    and property_value.endswith(">")
                )
                or (
                    not verbatim
                    and len(property_value) > 1
                    and not any(
                        character.isspace() or character in "[]{},"
                        for character in property_value[1:]
                    )
                )
            )
            self._seen_tag_property = True
        self._property_characters.clear()
        self._property_kind = None
        self._header_state = "node_property_gap" if valid else "invalid_node_prefix"

    def enter_mapping_value(self) -> None:
        self._header_state = "mapping_value"
        self._block_scalar_base_indent = self._mapping_key_indent
        self._block_scalar_candidate = True
        self._node_context = "mapping"
        self._seen_anchor_property = False
        self._seen_tag_property = False

    def consume_header_character(self, character: str, column: int) -> None:
        if self._header_state == "leading":
            if character == " ":
                return
            if character == "-":
                self._header_state = "leading_dash"
            elif character == "\t":
                self._header_state = "invalid"
            elif character in {"!", "&"}:
                self.start_node_property(
                    character,
                    context="root",
                    base_indent=self.header_indent,
                )
            else:
                self.start_mapping_key(character, self.header_indent)
            return
        if self._header_state == "leading_dash":
            if character in {" ", "\t"}:
                self._header_state = "sequence_value"
                self._block_scalar_base_indent = self.header_indent
                self._block_scalar_candidate = True
                self._node_context = "sequence"
            else:
                self.start_mapping_key("-", self.header_indent)
                if character == ":":
                    self._header_state = "mapping_colon"
                    self._block_scalar_candidate = True
            return
        if self._header_state == "sequence_value":
            if character in {" ", "\t"}:
                return
            if character in {"!", "&"}:
                self.start_node_property(
                    character,
                    context="sequence",
                    base_indent=self.header_indent,
                )
            else:
                self.start_mapping_key(character, column)
            return
        if self._header_state == "plain_key":
            if character == ":":
                self._header_state = "mapping_colon"
            return
        if self._header_state == "single_quoted_key":
            if character == "'":
                self._header_state = "single_quoted_key_quote"
            return
        if self._header_state == "single_quoted_key_quote":
            if character == "'":
                self._header_state = "single_quoted_key"
            elif character == ":":
                self._header_state = "mapping_colon"
            elif character in {" ", "\t"}:
                self._header_state = "quoted_key_gap"
            else:
                self._header_state = "invalid"
            return
        if self._header_state == "double_quoted_key":
            if character == "\\":
                self._header_state = "double_quoted_key_escape"
            elif character == '"':
                self._header_state = "quoted_key_gap"
            return
        if self._header_state == "double_quoted_key_escape":
            self._header_state = "double_quoted_key"
            return
        if self._header_state == "quoted_key_gap":
            if character in {" ", "\t"}:
                return
            if character == ":":
                self._header_state = "mapping_colon"
            else:
                self._header_state = "invalid"
            return
        if self._header_state == "mapping_colon":
            if character in {" ", "\t"}:
                self.enter_mapping_value()
            elif character != ":":
                self._header_state = "plain_key"
                self._block_scalar_candidate = False
            return
        if self._header_state == "mapping_value":
            if character in {" ", "\t"}:
                return
            if character in {"!", "&"}:
                self.start_node_property(
                    character,
                    context="mapping",
                    base_indent=self._block_scalar_base_indent or 0,
                )
            else:
                self._header_state = "ordinary_value"
                self._block_scalar_candidate = False
            return
        if self._header_state == "node_property":
            if character in {" ", "\t"}:
                self.finish_node_property()
            else:
                self._property_characters.append(character)
            return
        if self._header_state == "node_property_gap":
            if character in {" ", "\t"}:
                return
            if character in {"!", "&"}:
                if self._node_context is None or self._block_scalar_base_indent is None:
                    self._header_state = "invalid_node_prefix"
                    return
                self.start_node_property(
                    character,
                    context=self._node_context,
                    base_indent=self._block_scalar_base_indent,
                )
            elif self._node_context in {"root", "sequence"}:
                self.start_mapping_key(character, column)
            else:
                self._header_state = "ordinary_value"
                self._block_scalar_candidate = False
            return
        if self._header_state == "invalid_node_prefix":
            if character not in {" ", "\t"}:
                self._header_state = "ordinary_value"
                self._block_scalar_candidate = False

    def block_scalar_base_indent(self) -> int | None:
        if self._header_state == "leading":
            return self.header_indent
        if self._header_state in {
            "mapping_value",
            "node_property_gap",
            "sequence_value",
        }:
            return self._block_scalar_base_indent
        return None

    def allows_block_scalar(self) -> bool:
        return self.block_scalar_base_indent() is not None

    def is_block_scalar_candidate(self) -> bool:
        return self.allows_block_scalar() or self._block_scalar_candidate

    def current_line_end(self, value: str) -> int:
        if self._line_end is None:
            self.record_operation("line_end_searches")
            line_end = value.find("\n", self.position)
            self._line_end = len(value) if line_end < 0 else line_end
        return self._line_end


class BootstrapV2YamlUsesValue(NamedTuple):
    scalar_index: int | None
    start: int
    end: int
    is_step_field: bool


class BootstrapV2YamlSourceLine(NamedTuple):
    start: int
    end: int
    indent: int | None
    lexeme_indexes: tuple[int, ...]


class BootstrapV2YamlFlowMapping(NamedTuple):
    key_indexes: tuple[int, ...]
    close_index: int


class BootstrapV2YamlFlowMappingFrame:
    __slots__ = ("bracket_depth", "expect_key", "key_indexes", "open_index", "valid")

    def __init__(self, open_index: int) -> None:
        self.open_index = open_index
        self.key_indexes: list[int] = []
        self.bracket_depth = 0
        self.expect_key = True
        self.valid = True


def bootstrap_v2_normalize_yaml_newlines(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def bootstrap_v2_yaml_block_scalar_header(
    value: str,
    start: int,
    end: int,
    line_prefix: BootstrapV2YamlLinePrefix,
) -> tuple[int, str] | None:
    header = ""
    trailing_whitespace = False
    cursor = start
    scanned = 0
    try:
        while cursor < end:
            character = value[cursor]
            cursor += 1
            scanned += 1
            if character == "#":
                break
            if character.isspace():
                trailing_whitespace = True
                continue
            if trailing_whitespace or len(header) >= 2:
                return None
            header += character
        if re.fullmatch(r"(?:[1-9][+-]?|[+-][1-9]?)?", header) is None:
            return None
        return (
            next((int(character) for character in header if character.isdigit()), 0),
            next((character for character in header if character in "+-"), ""),
        )
    finally:
        line_prefix.record_operation("block_scalar_header_characters", scanned)


def bootstrap_v2_yaml_chomp_block_scalar(value: str, chomping: str) -> str:
    if chomping == "-":
        return value.rstrip("\n")
    if chomping == "+" or not value.endswith("\n"):
        return value
    return value.rstrip("\n") + "\n"


def bootstrap_v2_yaml_folded_block_scalar(
    lines: list[str],
    more_indented: list[bool],
    *,
    join_folded_lines: str,
    ends_with_newline: bool,
) -> str:
    if not lines:
        return ""
    last_nonempty = next(
        (index for index in range(len(lines) - 1, -1, -1) if lines[index]),
        None,
    )
    if last_nonempty is None:
        trailing_breaks = len(lines) if ends_with_newline else len(lines) - 1
        return "\n" * trailing_breaks
    decoded = [lines[0]]
    for index in range(1, last_nonempty + 1):
        previous = lines[index - 1]
        current = lines[index]
        if previous == "":
            folded_break = "\n"
        elif current == "":
            folded_break = ""
        elif more_indented[index - 1] or more_indented[index]:
            folded_break = "\n"
        else:
            folded_break = join_folded_lines
        decoded.extend((folded_break, current))
    trailing_breaks = len(lines) - last_nonempty - 1
    if ends_with_newline:
        trailing_breaks += 1
    decoded.append("\n" * trailing_breaks)
    return "".join(decoded)


def bootstrap_v2_yaml_block_scalar(
    value: str,
    offset: int,
    line_prefix: BootstrapV2YamlLinePrefix,
) -> tuple[str, str, int] | None:
    line_prefix.record_operation("block_scalar_context_checks")
    base_indent = line_prefix.block_scalar_base_indent()
    if base_indent is None:
        return None

    line_end = line_prefix.current_line_end(value)
    header = bootstrap_v2_yaml_block_scalar_header(
        value, offset + 1, line_end, line_prefix
    )
    if header is None:
        return None
    explicit_indentation, chomping = header

    required_indent = (
        base_indent + explicit_indentation if explicit_indentation else None
    )
    inferred_indent: int | None = None
    content_lines: list[str] = []
    more_indented: list[bool] = []
    ends_with_newline = False
    cursor = min(line_end + 1, len(value))
    block_end = cursor
    while cursor < len(value):
        content_end = value.find("\n", cursor)
        if content_end < 0:
            content_end = len(value)
        content_line = value[cursor:content_end]
        line_prefix.record_operation("block_scalar_line_checks")
        line_prefix.record_operation(
            "block_scalar_content_characters", len(content_line)
        )
        if content_line.strip(" \t"):
            content_indent = len(content_line) - len(content_line.lstrip(" "))
            if required_indent is not None:
                if content_indent < required_indent:
                    break
            elif content_indent <= base_indent:
                break
            elif inferred_indent is None:
                inferred_indent = content_indent
            elif content_indent < inferred_indent:
                break
            content_indent = (
                required_indent if required_indent is not None else inferred_indent
            )
            content_lines.append(content_line[content_indent:])
            more_indented.append(
                content_indent < len(content_line) - len(content_line.lstrip(" "))
            )
        else:
            content_lines.append("")
            more_indented.append(False)
        block_end = min(content_end + 1, len(value))
        ends_with_newline = content_end < len(value)
        cursor = block_end
    literal = "\n".join(content_lines)
    if ends_with_newline:
        literal += "\n"
    if value[offset] == "|":
        decoded = literal
        privacy_value = literal
    else:
        decoded = bootstrap_v2_yaml_folded_block_scalar(
            content_lines,
            more_indented,
            join_folded_lines=" ",
            ends_with_newline=ends_with_newline,
        )
        privacy_value = bootstrap_v2_yaml_folded_block_scalar(
            content_lines,
            more_indented,
            join_folded_lines="",
            ends_with_newline=ends_with_newline,
        )
    decoded = bootstrap_v2_yaml_chomp_block_scalar(decoded, chomping)
    privacy_value = bootstrap_v2_yaml_chomp_block_scalar(privacy_value, chomping)
    line_prefix.record_operation(
        "block_scalar_decoded_characters", len(decoded) + len(privacy_value)
    )
    return decoded, privacy_value, block_end


def bootstrap_v2_yaml_tokens(
    value: str,
    *,
    operation_counts: dict[str, int] | None = None,
) -> list[BootstrapV2YamlToken]:
    value = bootstrap_v2_normalize_yaml_newlines(value)
    tokens: list[BootstrapV2YamlToken] = []
    offset = 0
    line_prefix = BootstrapV2YamlLinePrefix(operation_counts)
    punctuation = frozenset("{}[],:?")
    indicators = frozenset("&*!|>")
    while offset < len(value):
        character = value[offset]
        if character.isspace():
            line_prefix.consume(value, offset, offset + 1)
            offset += 1
            continue
        if character == "#":
            newline = value.find("\n", offset)
            end = len(value) if newline < 0 else newline + 1
            line_prefix.consume(value, offset, end)
            offset = end
            continue
        if character in {'"', "'"}:
            parsed = read_bootstrap_v2_yaml_quoted_scalar(value, offset)
            if parsed is None:
                newline = value.find("\n", offset)
                end = len(value) if newline < 0 else newline
                tokens.append(
                    BootstrapV2YamlToken("invalid", value[offset:end], offset, end)
                )
                next_offset = max(end, offset + 1)
                line_prefix.consume(value, offset, next_offset)
                offset = next_offset
                continue
            decoded, end = parsed
            tokens.append(BootstrapV2YamlToken("scalar", decoded, offset, end))
            line_prefix.consume(value, offset, end)
            offset = end
            continue
        if character in punctuation:
            tokens.append(
                BootstrapV2YamlToken("punctuation", character, offset, offset + 1)
            )
            line_prefix.consume(value, offset, offset + 1)
            offset += 1
            continue
        if character in {"|", ">"}:
            block_scalar_candidate = line_prefix.is_block_scalar_candidate()
            block_scalar = bootstrap_v2_yaml_block_scalar(value, offset, line_prefix)
            if block_scalar is not None:
                decoded, privacy_value, block_end = block_scalar
                tokens.append(
                    BootstrapV2YamlToken("indicator", character, offset, offset + 1)
                )
                tokens.append(
                    BootstrapV2YamlToken(
                        "scalar", decoded, offset, block_end, privacy_value
                    )
                )
                line_prefix.consume(value, offset, block_end)
                offset = block_end
                continue
            if block_scalar_candidate:
                tokens.append(
                    BootstrapV2YamlToken(
                        "invalid_block_scalar",
                        character,
                        offset,
                        offset + 1,
                    )
                )
                line_prefix.consume(value, offset, offset + 1)
                offset += 1
                continue
        if character in indicators:
            tokens.append(
                BootstrapV2YamlToken("indicator", character, offset, offset + 1)
            )
            line_prefix.consume(value, offset, offset + 1)
            offset += 1
            continue

        start = offset
        while offset < len(value):
            character = value[offset]
            if character.isspace() or character in punctuation:
                break
            offset += 1
        if offset == start:
            offset += 1
            line_prefix.consume(value, start, offset)
            continue
        line_prefix.consume(value, start, offset)
        tokens.append(
            BootstrapV2YamlToken("scalar", value[start:offset], start, offset)
        )
    return tokens


def bootstrap_v2_yaml_source_lines(
    value: str,
    tokens: list[BootstrapV2YamlToken],
) -> list[BootstrapV2YamlSourceLine]:
    line_starts = [0]
    line_starts.extend(
        index + 1 for index, character in enumerate(value) if character == "\n"
    )
    indexes_by_line: list[list[int]] = [[] for _ in line_starts]
    for index, lexeme in enumerate(tokens):
        line_index = bootstrap_v2_line_index(line_starts, lexeme.start)
        indexes_by_line[line_index].append(index)

    lines: list[BootstrapV2YamlSourceLine] = []
    prior_lexeme_end = 0
    for line_index, start in enumerate(line_starts):
        end = (
            line_starts[line_index + 1] - 1
            if line_index + 1 < len(line_starts)
            else len(value)
        )
        indexes = tuple(indexes_by_line[line_index])
        indent: int | None = None
        if indexes and prior_lexeme_end <= start:
            prefix = value[start : tokens[indexes[0]].start]
            if not prefix.strip(" "):
                indent = len(prefix)
        for lexeme_index in indexes:
            prior_lexeme_end = max(prior_lexeme_end, tokens[lexeme_index].end)
        lines.append(BootstrapV2YamlSourceLine(start, end, indent, indexes))
    return lines


def bootstrap_v2_yaml_block_key_index(
    line: BootstrapV2YamlSourceLine,
    tokens: list[BootstrapV2YamlToken],
    *,
    offset: int = 0,
) -> int | None:
    indexes = line.lexeme_indexes
    if len(indexes) < offset + 2:
        return None
    key_index = indexes[offset]
    separator = tokens[indexes[offset + 1]]
    if (
        tokens[key_index].kind != "scalar"
        or separator.kind != "punctuation"
        or separator.value != ":"
    ):
        return None
    return key_index


def bootstrap_v2_yaml_flow_mappings(
    tokens: list[BootstrapV2YamlToken],
) -> dict[int, BootstrapV2YamlFlowMapping]:
    mappings: dict[int, BootstrapV2YamlFlowMapping] = {}
    frames: list[BootstrapV2YamlFlowMappingFrame] = []
    for index, lexeme in enumerate(tokens):
        if lexeme.kind == "punctuation" and lexeme.value == "{":
            frames.append(BootstrapV2YamlFlowMappingFrame(index))
            continue
        if lexeme.kind == "punctuation" and lexeme.value == "}":
            if frames:
                frame = frames.pop()
                if frame.valid:
                    mappings[frame.open_index] = BootstrapV2YamlFlowMapping(
                        tuple(frame.key_indexes), index
                    )
            continue
        if not frames:
            continue
        frame = frames[-1]
        if not frame.valid:
            continue
        if lexeme.kind == "punctuation" and lexeme.value == "[":
            frame.bracket_depth += 1
            continue
        if lexeme.kind == "punctuation" and lexeme.value == "]":
            frame.bracket_depth = max(0, frame.bracket_depth - 1)
            continue
        if frame.bracket_depth:
            continue
        if lexeme.kind == "punctuation" and lexeme.value == ",":
            frame.expect_key = True
            continue
        if not frame.expect_key:
            continue
        if (
            lexeme.kind == "scalar"
            and index + 1 < len(tokens)
            and tokens[index + 1].kind == "punctuation"
            and tokens[index + 1].value == ":"
        ):
            frame.key_indexes.append(index)
            frame.expect_key = False
            continue
        frame.valid = False
    return mappings


def bootstrap_v2_yaml_step_uses_key_indexes(
    value: str,
    tokens: list[BootstrapV2YamlToken],
) -> set[int]:
    lines = bootstrap_v2_yaml_source_lines(value, tokens)
    source_line_starts = [line.start for line in lines]

    def significant(line: BootstrapV2YamlSourceLine) -> bool:
        return bool(line.lexeme_indexes) and line.indent is not None

    def region_end(start: int, limit: int, parent_indent: int) -> int:
        for line_index in range(start + 1, limit):
            line = lines[line_index]
            if significant(line) and line.indent <= parent_indent:
                return line_index
        return limit

    def direct_indent(start: int, end: int, parent_indent: int) -> int | None:
        candidates = [
            line.indent
            for line in lines[start:end]
            if significant(line) and line.indent > parent_indent
        ]
        return min(candidates) if candidates else None

    def mapping_keys_at_indent(start: int, end: int, indent: int) -> list[int] | None:
        keys: list[int] = []
        for line in lines[start:end]:
            if not significant(line) or line.indent != indent:
                continue
            key_index = bootstrap_v2_yaml_block_key_index(line, tokens)
            if key_index is None:
                return None
            keys.append(key_index)
        return keys

    def has_duplicate_keys(key_indexes: list[int] | tuple[int, ...]) -> bool:
        values = [tokens[index].value for index in key_indexes]
        return len(values) != len(set(values))

    root_keys = mapping_keys_at_indent(0, len(lines), 0)
    if root_keys is None or has_duplicate_keys(root_keys):
        return set()
    jobs_keys = [index for index in root_keys if tokens[index].value == "jobs"]
    if len(jobs_keys) != 1:
        return set()
    jobs_line_index = bootstrap_v2_line_index(
        source_line_starts, tokens[jobs_keys[0]].start
    )
    jobs_line = lines[jobs_line_index]
    if len(jobs_line.lexeme_indexes) != 2:
        return set()
    jobs_end = region_end(jobs_line_index, len(lines), 0)
    job_indent = direct_indent(jobs_line_index + 1, jobs_end, 0)
    if job_indent is None:
        return set()
    job_keys = mapping_keys_at_indent(jobs_line_index + 1, jobs_end, job_indent)
    if job_keys is None or has_duplicate_keys(job_keys):
        return set()
    flow_mappings = bootstrap_v2_yaml_flow_mappings(tokens)

    step_uses_keys: set[int] = set()
    for job_key in job_keys:
        job_line_index = bootstrap_v2_line_index(
            source_line_starts, tokens[job_key].start
        )
        job_line = lines[job_line_index]
        if len(job_line.lexeme_indexes) != 2:
            continue
        job_end = region_end(job_line_index, jobs_end, job_indent)
        job_child_indent = direct_indent(job_line_index + 1, job_end, job_indent)
        if job_child_indent is None:
            continue
        job_child_keys = mapping_keys_at_indent(
            job_line_index + 1, job_end, job_child_indent
        )
        if job_child_keys is None or has_duplicate_keys(job_child_keys):
            continue
        steps_keys = [
            index for index in job_child_keys if tokens[index].value == "steps"
        ]
        if len(steps_keys) != 1:
            continue
        steps_line_index = bootstrap_v2_line_index(
            source_line_starts, tokens[steps_keys[0]].start
        )
        steps_line = lines[steps_line_index]
        if len(steps_line.lexeme_indexes) != 2:
            continue
        steps_end = region_end(steps_line_index, job_end, job_child_indent)
        sequence_indent = direct_indent(
            steps_line_index + 1, steps_end, job_child_indent
        )
        if sequence_indent is None:
            continue
        item_lines = [
            line_index
            for line_index in range(steps_line_index + 1, steps_end)
            if significant(lines[line_index])
            and lines[line_index].indent == sequence_indent
        ]
        if not item_lines or any(
            tokens[lines[line_index].lexeme_indexes[0]].kind != "scalar"
            or tokens[lines[line_index].lexeme_indexes[0]].value != "-"
            for line_index in item_lines
        ):
            continue

        for item_offset, item_line_index in enumerate(item_lines):
            item_end = (
                item_lines[item_offset + 1]
                if item_offset + 1 < len(item_lines)
                else steps_end
            )
            item_line = lines[item_line_index]
            item_indexes = item_line.lexeme_indexes
            if len(item_indexes) == 1:
                item_mapping_indent = direct_indent(
                    item_line_index + 1, item_end, sequence_indent
                )
                if item_mapping_indent is None:
                    continue
                item_keys = mapping_keys_at_indent(
                    item_line_index + 1, item_end, item_mapping_indent
                )
            elif (
                tokens[item_indexes[1]].kind == "punctuation"
                and tokens[item_indexes[1]].value == "{"
            ):
                flow_mapping = flow_mappings.get(item_indexes[1])
                if flow_mapping is None:
                    continue
                item_keys = flow_mapping.key_indexes
                close_index = flow_mapping.close_index
                item_source_end = (
                    lines[item_end].start if item_end < len(lines) else len(value)
                )
                if tokens[close_index].start >= item_source_end or any(
                    index > close_index
                    for line in lines[item_line_index:item_end]
                    for index in line.lexeme_indexes
                ):
                    continue
            else:
                first_key = bootstrap_v2_yaml_block_key_index(
                    item_line, tokens, offset=1
                )
                if first_key is None:
                    continue
                item_mapping_indent = tokens[first_key].start - item_line.start
                continuation_keys = mapping_keys_at_indent(
                    item_line_index + 1, item_end, item_mapping_indent
                )
                if continuation_keys is None:
                    continue
                item_keys = [first_key, *continuation_keys]
            if item_keys is None or has_duplicate_keys(item_keys):
                continue
            step_uses_keys.update(
                index for index in item_keys if tokens[index].value == "uses"
            )
    return step_uses_keys


def bootstrap_v2_yaml_uses_values(
    value: str,
    tokens: list[BootstrapV2YamlToken],
) -> list[BootstrapV2YamlUsesValue]:
    step_uses_key_indexes = bootstrap_v2_yaml_step_uses_key_indexes(value, tokens)
    values: list[BootstrapV2YamlUsesValue] = []
    for index, token in enumerate(tokens):
        if token.kind != "scalar" or token.value != "uses":
            continue
        separator_index = index + 1
        if separator_index >= len(tokens):
            continue
        separator = tokens[separator_index]
        if separator.kind != "punctuation" or separator.value != ":":
            continue
        value_index = separator_index + 1
        if value_index >= len(tokens) or tokens[value_index].kind != "scalar":
            values.append(
                BootstrapV2YamlUsesValue(
                    None,
                    separator.end,
                    separator.end,
                    index in step_uses_key_indexes,
                )
            )
            continue
        scalar = tokens[value_index]
        values.append(
            BootstrapV2YamlUsesValue(
                value_index,
                scalar.start,
                scalar.end,
                index in step_uses_key_indexes,
            )
        )
    return values


def bootstrap_v2_line_index(line_starts: list[int], offset: int) -> int:
    return max(0, bisect_right(line_starts, offset) - 1)


def bootstrap_v2_workflow_has_yaml_anchors_or_aliases(value: str) -> bool:
    return any(
        token.kind in {"indicator"} and token.value in {"&", "*"}
        for token in bootstrap_v2_yaml_tokens(value)
    )


def bootstrap_v2_workflow_has_yaml_tags(value: str) -> bool:
    return any(
        token.kind == "indicator" and token.value == "!"
        for token in bootstrap_v2_yaml_tokens(value)
    )


def bootstrap_v2_privacy_risk_lines(
    value: str, *, relative: Path | None = None
) -> list[str]:
    lines = value.splitlines()
    is_workflow = relative is not None and relative.suffix.lower() in WORKFLOW_SUFFIXES
    if not is_workflow:
        return [
            line
            for line in lines
            if line.strip().rstrip(",").strip("\"'") not in SAFE_INFRASTRUCTURE_LINES
            and any(
                pattern.search(line) for pattern in BOOTSTRAP_V2_PRIVACY_RISK_PATTERNS
            )
        ]

    workflow_value = bootstrap_v2_normalize_yaml_newlines(value)
    line_starts = [0]
    line_starts.extend(
        index + 1 for index, character in enumerate(workflow_value) if character == "\n"
    )
    tokens = bootstrap_v2_yaml_tokens(workflow_value)
    risky_line_indexes: set[int] = set()
    decoded_block_markers: list[str] = []
    immutable_values: dict[int, str] = {}
    masked_source_spans: list[tuple[int, int]] = []

    for uses_value in bootstrap_v2_yaml_uses_values(workflow_value, tokens):
        source_line = bootstrap_v2_line_index(line_starts, uses_value.start)
        if uses_value.scalar_index is None:
            risky_line_indexes.add(source_line)
            continue
        action_value = tokens[uses_value.scalar_index].value
        match = BOOTSTRAP_V2_IMMUTABLE_GITHUB_ACTION_USES_RE.fullmatch(action_value)
        if match is None:
            risky_line_indexes.add(source_line)
            continue
        if not uses_value.is_step_field:
            risky_line_indexes.add(source_line)
            continue
        action_path = match.group("action_path")
        immutable_values[uses_value.scalar_index] = (
            action_value[: match.start("ref")] + action_value[match.end("ref") :]
        )
        masked_source_spans.append((uses_value.start, uses_value.end))
        if any(
            SENSITIVE_TOKEN_RE.search(component) for component in action_path.split("/")
        ) or any(
            pattern.search(action_path)
            for pattern in BOOTSTRAP_V2_PRIVACY_RISK_PATTERNS
        ):
            risky_line_indexes.add(source_line)
    for index, token in enumerate(tokens):
        if token.kind == "invalid_block_scalar":
            source_line = bootstrap_v2_line_index(line_starts, token.start)
            risky_line_indexes.add(source_line)
            line_end = workflow_value.find("\n", token.start)
            if line_end < 0:
                line_end = len(workflow_value)
            invalid_header = workflow_value[token.start : line_end]
            decoded_block_markers.append(
                "yaml_block_scalar_invalid_sha256:"
                + hashlib.sha256(invalid_header.encode("utf-8")).hexdigest()
            )
            continue
        if token.kind != "scalar":
            continue
        scan_value = immutable_values.get(index, token.value)
        scan_values = (scan_value, token.scan_value)
        if any(
            pattern.search(candidate)
            for candidate in scan_values
            if candidate is not None
            for pattern in BOOTSTRAP_V2_PRIVACY_RISK_PATTERNS
        ):
            risky_line_indexes.add(bootstrap_v2_line_index(line_starts, token.start))
            if token.scan_value is not None:
                canonical = json.dumps(
                    (token.value, token.scan_value),
                    ensure_ascii=True,
                    separators=(",", ":"),
                )
                decoded_block_markers.append(
                    "yaml_block_scalar_sha256:"
                    + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                )

    masked_chunks: list[str] = []
    cursor = 0
    for start, end in sorted(masked_source_spans):
        masked_chunks.append(workflow_value[cursor:start])
        masked_chunks.append(re.sub(r"[^\r\n]", " ", workflow_value[start:end]))
        cursor = end
    masked_chunks.append(workflow_value[cursor:])
    masked_lines = "".join(masked_chunks).splitlines()
    for index, (line, masked_line) in enumerate(zip(lines, masked_lines, strict=True)):
        normalized_line = line.strip().rstrip(",").strip("\"'")
        if normalized_line in SAFE_INFRASTRUCTURE_LINES:
            continue
        if any(
            pattern.search(masked_line)
            for pattern in BOOTSTRAP_V2_PRIVACY_RISK_PATTERNS
        ):
            risky_line_indexes.add(index)
    risky_lines = [
        line for index, line in enumerate(lines) if index in risky_line_indexes
    ]
    return [*risky_lines, *decoded_block_markers]


def bootstrap_v2_privacy_risk_lines_fingerprint(lines: list[str]) -> str:
    canonical = json.dumps(lines, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def contains_bootstrap_v2_privacy_risk_text(
    value: str, *, relative: Path | None = None
) -> bool:
    if (
        relative is not None
        and relative.suffix.lower() in WORKFLOW_SUFFIXES
        and (
            bootstrap_v2_workflow_has_yaml_anchors_or_aliases(value)
            or bootstrap_v2_workflow_has_yaml_tags(value)
        )
    ):
        return True
    risky_lines = bootstrap_v2_privacy_risk_lines(value, relative=relative)
    if not risky_lines:
        return False
    expected_fingerprint = BOOTSTRAP_V2_TRUSTED_RISK_LINES_SHA256.get(relative)
    return (
        expected_fingerprint is None
        or bootstrap_v2_privacy_risk_lines_fingerprint(risky_lines)
        != expected_fingerprint
    )


def bootstrap_v2_decoded_privacy_risk_values(value: Any) -> list[str]:
    risky_values: list[str] = []
    if isinstance(value, str):
        if bootstrap_v2_privacy_risk_lines(value):
            risky_values.append(value)
    elif isinstance(value, dict):
        for key, child in value.items():
            risky_values.extend(bootstrap_v2_decoded_privacy_risk_values(key))
            risky_values.extend(bootstrap_v2_decoded_privacy_risk_values(child))
    elif isinstance(value, list):
        for child in value:
            risky_values.extend(bootstrap_v2_decoded_privacy_risk_values(child))
    return risky_values


def contains_bootstrap_v2_decoded_privacy_risk(value: Any, *, relative: Path) -> bool:
    risky_values = bootstrap_v2_decoded_privacy_risk_values(value)
    if not risky_values:
        return False
    expected_fingerprint = BOOTSTRAP_V2_TRUSTED_DECODED_RISK_VALUES_SHA256.get(relative)
    return (
        expected_fingerprint is None
        or bootstrap_v2_privacy_risk_lines_fingerprint(risky_values)
        != expected_fingerprint
    )


def bootstrap_v2_python_payload_size(value: str | bytes) -> int:
    if isinstance(value, bytes):
        return len(value)
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ValueError("Python string constant contains invalid Unicode") from exc


def bootstrap_v2_python_constant_text(value: str | bytes) -> tuple[str, int]:
    if isinstance(value, bytes):
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Python bytes constant is not valid UTF-8 text") from exc
    else:
        text = value
    if NUL_TEXT in text:
        raise ValueError("Python text constant contains a NUL byte")
    return text, bootstrap_v2_python_payload_size(value)


class BootstrapV2PythonFormatAnalysis:
    def __init__(self, *, limit: int) -> None:
        self.limit = limit
        self.operations = 0
        self.value_size_cache: dict[int, int] = {}
        self.decimal_width_cache: dict[int, int] = {}
        self.active_value_sizes: set[int] = set()
        self.active_decimal_widths: set[int] = set()

    def consume_operation(self) -> None:
        self.operations += 1
        if self.operations > BOOTSTRAP_V2_MAX_PYTHON_FORMAT_ANALYSIS_OPERATIONS:
            raise ValueError(
                "Python format argument analysis exceeds the trusted operation limit"
            )

    def value_size_bound(self, value: Any) -> int:
        self.consume_operation()
        value_id = id(value)
        cached = self.value_size_cache.get(value_id)
        if cached is not None:
            return cached
        if value_id in self.active_value_sizes:
            raise ValueError("Python deterministic format value is recursive")
        self.active_value_sizes.add(value_id)
        try:
            if isinstance(value, str):
                try:
                    size = len(value.encode("utf-8"))
                except UnicodeEncodeError as exc:
                    raise ValueError(
                        "Python deterministic value contains invalid Unicode"
                    ) from exc
                result = min((size * 12) + 2, self.limit + 1)
            elif isinstance(value, bytes):
                result = min((len(value) * 4) + 3, self.limit + 1)
            elif value is None:
                result = 4
            elif type(value) is bool:
                result = 5
            elif type(value) is int:
                result = min((len(str(abs(value))) * 4) + 1, self.limit + 1)
            elif type(value) in {float, complex}:
                result = min(len(repr(value)) * 4, self.limit + 1)
            elif isinstance(value, (tuple, list)):
                total = 2
                for child in value:
                    total += self.value_size_bound(child) + 2
                    if total > self.limit:
                        total = self.limit + 1
                        break
                result = total
            elif isinstance(value, dict):
                total = 2
                for key, child in value.items():
                    total += self.value_size_bound(key) + 2
                    total += self.value_size_bound(child) + 2
                    if total > self.limit:
                        total = self.limit + 1
                        break
                result = total
            else:
                result = self.limit + 1
        finally:
            self.active_value_sizes.remove(value_id)
        self.value_size_cache[value_id] = result
        return result

    def decimal_width_bound(self, value: Any) -> int:
        self.consume_operation()
        value_id = id(value)
        cached = self.decimal_width_cache.get(value_id)
        if cached is not None:
            return cached
        if value_id in self.active_decimal_widths:
            raise ValueError("Python deterministic format value is recursive")
        self.active_decimal_widths.add(value_id)
        try:
            observed = 0
            if type(value) is int:
                result = min(abs(value), self.limit + 1)
            elif isinstance(value, str):
                result = self.decimal_width_in_text(value)
            elif isinstance(value, bytes):
                result = self.decimal_width_in_text(
                    value.decode("ascii", errors="ignore")
                )
            elif isinstance(value, (tuple, list)):
                for child in value:
                    observed = max(observed, self.decimal_width_bound(child))
                    if observed > self.limit:
                        break
                result = observed
            elif isinstance(value, dict):
                for key, child in value.items():
                    observed = max(
                        observed,
                        self.decimal_width_bound(key),
                        self.decimal_width_bound(child),
                    )
                    if observed > self.limit:
                        break
                result = observed
            else:
                result = 0
        finally:
            self.active_decimal_widths.remove(value_id)
        self.decimal_width_cache[value_id] = result
        return result

    def decimal_width_in_text(self, text: str) -> int:
        observed = 0
        limit_text = str(self.limit)
        for match in re.finditer(r"[0-9]+", text):
            digits = match.group(0).lstrip("0") or "0"
            if len(digits) > len(limit_text) or (
                len(digits) == len(limit_text) and digits > limit_text
            ):
                return self.limit + 1
            observed = max(observed, int(digits))
        return observed


def bootstrap_v2_python_value_size_bound(value: Any, *, limit: int) -> int:
    return BootstrapV2PythonFormatAnalysis(limit=limit).value_size_bound(value)


def bootstrap_v2_python_decimal_width_bound(value: Any, *, limit: int) -> int:
    return BootstrapV2PythonFormatAnalysis(limit=limit).decimal_width_bound(value)


def bootstrap_v2_python_preflight_format(
    template: str | bytes,
    arguments: tuple[Any, ...],
    *,
    field_marker: str | bytes,
    dynamic_widths: bool,
) -> None:
    _, template_size = bootstrap_v2_python_constant_text(template)
    limit = BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES
    analysis = BootstrapV2PythonFormatAnalysis(limit=limit)
    width_bound = analysis.decimal_width_bound(template)
    value_bound = 0
    for argument in arguments:
        value_bound = max(
            value_bound,
            analysis.value_size_bound(argument),
        )
        if dynamic_widths:
            width_bound = max(
                width_bound,
                analysis.decimal_width_bound(argument),
            )
    field_count = template.count(field_marker)
    estimated_size = template_size + field_count * max(value_bound, width_bound, 1)
    if value_bound > limit or width_bound > limit or estimated_size > limit:
        raise ValueError(
            "Python deterministic string formatting exceeds the trusted byte limit"
        )


def bootstrap_v2_python_percent_format(
    template: str | bytes,
    argument: Any,
) -> str | bytes:
    star = "*" if isinstance(template, str) else b"*"
    marker = "%" if isinstance(template, str) else b"%"
    bootstrap_v2_python_preflight_format(
        template,
        (argument,),
        field_marker=marker,
        dynamic_widths=star in template,
    )
    try:
        return template % argument
    except (KeyError, MemoryError, OverflowError, TypeError, ValueError) as exc:
        raise ValueError(
            "Python deterministic percent formatting is unsupported"
        ) from exc


def bootstrap_v2_python_dot_format(
    template: str,
    arguments: tuple[Any, ...],
    keywords: dict[str, Any],
    *,
    format_map: bool,
) -> str:
    format_values = arguments + tuple(keywords.values())
    bootstrap_v2_python_preflight_format(
        template,
        format_values,
        field_marker="{",
        dynamic_widths=re.search(r":[^{}]*{", template) is not None,
    )
    try:
        if format_map:
            if len(arguments) != 1 or keywords or not isinstance(arguments[0], dict):
                raise TypeError
            return template.format_map(arguments[0])
        return template.format(*arguments, **keywords)
    except (
        AttributeError,
        IndexError,
        KeyError,
        MemoryError,
        OverflowError,
        TypeError,
        ValueError,
    ) as exc:
        raise ValueError("Python deterministic dot formatting is unsupported") from exc


def bootstrap_v2_python_formatted_value(
    value: Any,
    *,
    conversion: int,
    format_spec: str,
    max_output_bytes: int,
) -> str:
    limit = BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES
    width_bound = bootstrap_v2_python_decimal_width_bound(format_spec, limit=limit)
    value_bound = bootstrap_v2_python_value_size_bound(value, limit=limit)
    if (
        width_bound > limit
        or value_bound > limit
        or (width_bound * 4) + value_bound > max_output_bytes
    ):
        raise ValueError(
            "Python deterministic string formatting exceeds the trusted byte limit"
        )
    if conversion == -1:
        converted = value
    elif conversion == ord("s"):
        converted = str(value)
    elif conversion == ord("r"):
        converted = repr(value)
    elif conversion == ord("a"):
        converted = ascii(value)
    else:
        raise ValueError("Python f-string uses an unsupported conversion")
    try:
        return format(converted, format_spec)
    except (MemoryError, OverflowError, TypeError, ValueError) as exc:
        raise ValueError(
            "Python deterministic f-string formatting is unsupported"
        ) from exc


def bootstrap_v2_python_literal_join(
    separator: str | bytes,
    elements: tuple[Any, ...],
) -> str | bytes:
    expected_type = type(separator)
    limit = BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES
    separator_size = bootstrap_v2_python_payload_size(separator)
    joined_size = 0
    for index, element in enumerate(elements):
        if type(element) is not expected_type:
            if isinstance(element, (str, bytes)):
                raise ValueError("Python constant join mixes text and bytes literals")
            raise ValueError("Python constant join uses an unsupported literal type")
        element_size = bootstrap_v2_python_payload_size(element)
        added_size = element_size + (separator_size if index else 0)
        if added_size > limit - joined_size:
            raise ValueError("Python constant join exceeds the trusted byte limit")
        joined_size += added_size
    try:
        buffer = io.StringIO() if expected_type is str else io.BytesIO()
        for index, element in enumerate(elements):
            if index:
                buffer.write(separator)
            buffer.write(element)
        return buffer.getvalue()
    except MemoryError as exc:
        raise ValueError("Python constant join could not be evaluated safely") from exc


def bootstrap_v2_python_string_constants(value: str) -> list[str]:
    try:
        source_size = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ValueError("Python source contains invalid Unicode") from exc
    if source_size > BOOTSTRAP_V2_MAX_PYTHON_SOURCE_BYTES:
        raise ValueError("Python source exceeds the trusted AST size limit")
    try:
        tree = ast.parse(value, mode="exec")
    except (MemoryError, OverflowError, RecursionError, SyntaxError, ValueError) as exc:
        raise ValueError("Python source could not be parsed safely") from exc

    constants: list[str] = []
    literal_bytes = 0
    node_count = 0
    nodes: list[ast.AST] = []
    stack: list[tuple[ast.AST, int]] = [(tree, 1)]
    while stack:
        node, depth = stack.pop()
        node_count += 1
        if node_count > BOOTSTRAP_V2_MAX_PYTHON_AST_NODES:
            raise ValueError("Python AST exceeds the trusted node limit")
        if depth > BOOTSTRAP_V2_MAX_PYTHON_AST_DEPTH:
            raise ValueError("Python AST exceeds the trusted depth limit")
        nodes.append(node)
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            constant_text, payload_size = bootstrap_v2_python_constant_text(node.value)
            constants.append(constant_text)
            if len(constants) > BOOTSTRAP_V2_MAX_PYTHON_LITERAL_CONSTANTS:
                raise ValueError(
                    "Python AST exceeds the trusted literal constant limit"
                )
            literal_bytes += payload_size
            if literal_bytes > BOOTSTRAP_V2_MAX_PYTHON_LITERAL_BYTES:
                raise ValueError(
                    "Python AST literal constants exceed the trusted byte limit"
                )
        children = list(ast.iter_child_nodes(node))
        stack.extend((child, depth + 1) for child in reversed(children))

    not_pure = object()
    evaluated: dict[int, Any] = {}
    constructed: dict[int, str | bytes] = {}
    nested_pure_adds: set[int] = set()
    evaluated_value_count = 0
    evaluated_bytes = 0

    module_scope = id(tree)
    scope_kinds: dict[int, str] = {module_scope: "module"}
    scope_by_node_id: dict[int, int] = {}
    scope_parent: dict[int, int] = {}
    scope_stack: list[tuple[ast.AST, int]] = [(tree, module_scope)]

    def closure_parent(scope: int) -> int:
        while scope_kinds.get(scope) == "class":
            scope = scope_parent[scope]
        return scope

    def register_arguments(
        arguments: ast.arguments,
        *,
        definition_scope: int,
        function_scope: int,
    ) -> None:
        scope_by_node_id[id(arguments)] = function_scope
        positional = (*arguments.posonlyargs, *arguments.args)
        for argument in (*positional, *arguments.kwonlyargs):
            scope_by_node_id[id(argument)] = function_scope
            if argument.annotation is not None:
                scope_stack.append((argument.annotation, definition_scope))
        if arguments.vararg is not None:
            scope_by_node_id[id(arguments.vararg)] = function_scope
            if arguments.vararg.annotation is not None:
                scope_stack.append((arguments.vararg.annotation, definition_scope))
        if arguments.kwarg is not None:
            scope_by_node_id[id(arguments.kwarg)] = function_scope
            if arguments.kwarg.annotation is not None:
                scope_stack.append((arguments.kwarg.annotation, definition_scope))
        for default in (*arguments.defaults, *arguments.kw_defaults):
            if default is not None:
                scope_stack.append((default, definition_scope))

    while scope_stack:
        scoped_node, enclosing_scope = scope_stack.pop()
        scope_by_node_id[id(scoped_node)] = enclosing_scope
        if isinstance(scoped_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_scope = id(scoped_node)
            scope_kinds[function_scope] = "function"
            scope_parent[function_scope] = closure_parent(enclosing_scope)
            register_arguments(
                scoped_node.args,
                definition_scope=enclosing_scope,
                function_scope=function_scope,
            )
            definition_nodes = [
                *scoped_node.decorator_list,
                *getattr(scoped_node, "type_params", ()),
            ]
            if scoped_node.returns is not None:
                definition_nodes.append(scoped_node.returns)
            scope_stack.extend(
                (child, enclosing_scope) for child in reversed(definition_nodes)
            )
            scope_stack.extend(
                (child, function_scope) for child in reversed(scoped_node.body)
            )
            continue
        if isinstance(scoped_node, ast.Lambda):
            function_scope = id(scoped_node)
            scope_kinds[function_scope] = "function"
            scope_parent[function_scope] = closure_parent(enclosing_scope)
            register_arguments(
                scoped_node.args,
                definition_scope=enclosing_scope,
                function_scope=function_scope,
            )
            scope_stack.append((scoped_node.body, function_scope))
            continue
        if isinstance(scoped_node, ast.ClassDef):
            class_scope = id(scoped_node)
            scope_kinds[class_scope] = "class"
            scope_parent[class_scope] = closure_parent(enclosing_scope)
            definition_nodes = [
                *scoped_node.decorator_list,
                *scoped_node.bases,
                *scoped_node.keywords,
                *getattr(scoped_node, "type_params", ()),
            ]
            scope_stack.extend(
                (child, enclosing_scope) for child in reversed(definition_nodes)
            )
            scope_stack.extend(
                (child, class_scope) for child in reversed(scoped_node.body)
            )
            continue
        if isinstance(
            scoped_node,
            (ast.DictComp, ast.GeneratorExp, ast.ListComp, ast.SetComp),
        ):
            comprehension_scope = id(scoped_node)
            scope_kinds[comprehension_scope] = "comprehension"
            scope_parent[comprehension_scope] = closure_parent(enclosing_scope)
            for generator in scoped_node.generators:
                scope_by_node_id[id(generator)] = comprehension_scope
            first_generator, *remaining_generators = scoped_node.generators
            scope_stack.append((first_generator.iter, enclosing_scope))
            for generator in reversed(scoped_node.generators):
                scope_stack.extend(
                    (condition, comprehension_scope)
                    for condition in reversed(generator.ifs)
                )
                scope_stack.append((generator.target, comprehension_scope))
            for generator in reversed(remaining_generators):
                scope_stack.append((generator.iter, comprehension_scope))
            if isinstance(scoped_node, ast.DictComp):
                scope_stack.append((scoped_node.value, comprehension_scope))
                scope_stack.append((scoped_node.key, comprehension_scope))
            else:
                scope_stack.append((scoped_node.elt, comprehension_scope))
            continue
        if isinstance(scoped_node, ast.NamedExpr):
            target_scope = enclosing_scope
            while scope_kinds.get(target_scope) == "comprehension":
                target_scope = scope_parent[target_scope]
            scope_stack.append((scoped_node.value, enclosing_scope))
            scope_stack.append((scoped_node.target, target_scope))
            continue
        scope_stack.extend(
            (child, enclosing_scope)
            for child in reversed(list(ast.iter_child_nodes(scoped_node)))
        )

    bound_names_by_scope: dict[int, set[str]] = {}
    global_names_by_scope: dict[int, set[str]] = {}
    nonlocal_names_by_scope: dict[int, set[str]] = {}

    def record_scope_binding(scope: int, name: str | None) -> None:
        if name is not None:
            bound_names_by_scope.setdefault(scope, set()).add(name)

    for node in nodes:
        scope = scope_by_node_id[id(node)]
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            record_scope_binding(scope, node.id)
        elif isinstance(node, ast.arg):
            record_scope_binding(scope, node.arg)
        elif isinstance(node, ast.MatchAs):
            record_scope_binding(scope, node.name)
        elif isinstance(node, ast.MatchStar):
            record_scope_binding(scope, node.name)
        elif isinstance(node, ast.MatchMapping):
            record_scope_binding(scope, node.rest)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            record_scope_binding(scope, node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                record_scope_binding(scope, alias.asname or alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ExceptHandler):
            record_scope_binding(scope, node.name)
        elif isinstance(node, ast.Global):
            global_names_by_scope.setdefault(scope, set()).update(node.names)
        elif isinstance(node, ast.Nonlocal):
            nonlocal_names_by_scope.setdefault(scope, set()).update(node.names)
    for scope, names in global_names_by_scope.items():
        bound_names_by_scope.setdefault(scope, set()).difference_update(names)
    for scope, names in nonlocal_names_by_scope.items():
        bound_names_by_scope.setdefault(scope, set()).difference_update(names)

    def binding_scope_for_name(scope: int, name: str) -> int:
        while scope != module_scope:
            if name in global_names_by_scope.get(scope, set()):
                return module_scope
            if name not in nonlocal_names_by_scope.get(scope, set()):
                return scope
            scope = scope_parent[scope]
        return module_scope

    class_name_unbound = 0
    class_name_bound = 1
    class_name_maybe_bound = 2
    class_load_binding_state_by_id: dict[int, int] = {}

    def name_load_binding_resolution(
        node: ast.Name,
    ) -> tuple[tuple[int, str], tuple[tuple[int, str], ...]]:
        scope = scope_by_node_id[id(node)]
        skipped_class_keys: list[tuple[int, str]] = []
        while scope != module_scope:
            if node.id in global_names_by_scope.get(scope, set()):
                return (module_scope, node.id), tuple(skipped_class_keys)
            if node.id in bound_names_by_scope.get(scope, set()):
                key = (scope, node.id)
                if scope_kinds.get(scope) == "class":
                    binding_state = class_load_binding_state_by_id.get(
                        id(node), class_name_maybe_bound
                    )
                    if binding_state == class_name_unbound:
                        scope = scope_parent[scope]
                        continue
                    if binding_state == class_name_maybe_bound:
                        skipped_class_keys.append(key)
                        scope = scope_parent[scope]
                        continue
                return key, tuple(skipped_class_keys)
            scope = scope_parent[scope]
        return (module_scope, node.id), tuple(skipped_class_keys)

    def name_load_binding_key(node: ast.Name) -> tuple[int, str]:
        return name_load_binding_resolution(node)[0]

    def name_load_skipped_class_keys(
        node: ast.Name,
    ) -> tuple[tuple[int, str], ...]:
        return name_load_binding_resolution(node)[1]

    direct_statement_ids_by_scope: dict[int, set[int]] = {
        module_scope: {id(statement) for statement in tree.body}
    }
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            direct_statement_ids_by_scope[id(node)] = {
                id(statement) for statement in node.body
            }

    parent_by_node_id: dict[int, ast.AST] = {}
    node_by_id = {id(node): node for node in nodes}
    statement_membership: dict[int, tuple[tuple[int, str], int]] = {}
    for parent in nodes:
        for child in ast.iter_child_nodes(parent):
            parent_by_node_id[id(child)] = parent
        for field_name, field_value in ast.iter_fields(parent):
            if not isinstance(field_value, list):
                continue
            block = (id(parent), field_name)
            for index, child in enumerate(field_value):
                if isinstance(child, ast.stmt):
                    statement_membership[id(child)] = (block, index)

    binding_reachability_steps = 0
    binding_reachability_step_limit = min(
        max(node_count * 32, 1),
        BOOTSTRAP_V2_MAX_PYTHON_BINDING_REACHABILITY_STEPS,
    )

    def consume_binding_reachability_step() -> None:
        nonlocal binding_reachability_steps
        binding_reachability_steps += 1
        if binding_reachability_steps > binding_reachability_step_limit:
            raise ValueError("Python binding reachability exceeds the trusted limit")

    def statement_dominates_load(statement: ast.stmt, load: ast.Name) -> bool:
        statement_location = statement_membership.get(id(statement))
        if statement_location is None:
            return False
        current: ast.AST | None = load
        while current is not None:
            consume_binding_reachability_step()
            if isinstance(current, ast.stmt):
                load_location = statement_membership.get(id(current))
                if (
                    load_location is not None
                    and load_location[0] == statement_location[0]
                    and statement_location[1] < load_location[1]
                ):
                    return True
            current = parent_by_node_id.get(id(current))
        return False

    class_dataflow_steps = 0
    class_dataflow_limit = max(node_count * 12, 1)

    def consume_class_dataflow_step() -> None:
        nonlocal class_dataflow_steps
        class_dataflow_steps += 1
        if class_dataflow_steps > class_dataflow_limit:
            raise ValueError("Python class binding dataflow exceeds the trusted limit")

    def precompute_class_load_bindings(class_node: ast.ClassDef) -> None:
        class_scope = id(class_node)
        states: dict[str, int] = {}
        transaction_logs: list[dict[str, int]] = []

        def state_for(name: str) -> int:
            return states.get(name, class_name_unbound)

        def set_state(name: str, state: int) -> None:
            if binding_scope_for_name(class_scope, name) != class_scope:
                return
            previous = state_for(name)
            if previous == state:
                return
            consume_class_dataflow_step()
            if transaction_logs:
                transaction_logs[-1].setdefault(name, previous)
            if state == class_name_unbound:
                states.pop(name, None)
            else:
                states[name] = state

        def record_load(node: ast.Name) -> None:
            observed = state_for(node.id)
            previous = class_load_binding_state_by_id.get(id(node))
            if previous is None or previous == observed:
                class_load_binding_state_by_id[id(node)] = observed
            else:
                class_load_binding_state_by_id[id(node)] = class_name_maybe_bound

        def process_argument_definitions(arguments: ast.arguments) -> None:
            positional = (*arguments.posonlyargs, *arguments.args)
            for argument in (*positional, *arguments.kwonlyargs):
                if argument.annotation is not None:
                    process_expression(argument.annotation)
            for argument in (arguments.vararg, arguments.kwarg):
                if argument is not None and argument.annotation is not None:
                    process_expression(argument.annotation)
            for default in (*arguments.defaults, *arguments.kw_defaults):
                if default is not None:
                    process_expression(default)

        def process_expression(node: ast.AST) -> None:
            consume_class_dataflow_step()
            if isinstance(node, ast.Lambda):
                process_argument_definitions(node.args)
                return
            if isinstance(
                node,
                (ast.DictComp, ast.GeneratorExp, ast.ListComp, ast.SetComp),
            ):
                process_expression(node.generators[0].iter)
                return
            if scope_by_node_id.get(id(node)) != class_scope:
                return
            if isinstance(node, ast.Name):
                if isinstance(node.ctx, ast.Load):
                    record_load(node)
                return
            if isinstance(node, ast.NamedExpr):
                process_expression(node.value)
                bind_target(node.target)
                return
            for child in ast.iter_child_nodes(node):
                if not isinstance(child, ast.stmt):
                    process_expression(child)

        def process_target_access(target: ast.AST) -> None:
            if isinstance(target, ast.Starred):
                process_target_access(target.value)
            elif isinstance(target, (ast.Tuple, ast.List)):
                for child in target.elts:
                    process_target_access(child)
            elif isinstance(target, ast.Attribute):
                process_expression(target.value)
            elif isinstance(target, ast.Subscript):
                process_expression(target.value)
                process_expression(target.slice)

        def bind_target(target: ast.AST) -> None:
            process_target_access(target)
            for child in ast.walk(target):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                    target_scope = binding_scope_for_name(
                        scope_by_node_id[id(child)], child.id
                    )
                    if target_scope == class_scope:
                        set_state(child.id, class_name_bound)

        def delete_target(target: ast.AST) -> None:
            process_target_access(target)
            for child in ast.walk(target):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Del):
                    target_scope = binding_scope_for_name(
                        scope_by_node_id[id(child)], child.id
                    )
                    if target_scope == class_scope:
                        set_state(child.id, class_name_unbound)

        def capture_names(pattern: ast.pattern) -> set[str]:
            captures: set[str] = set()
            for child in ast.walk(pattern):
                if isinstance(child, (ast.MatchAs, ast.MatchStar)):
                    if child.name is not None:
                        captures.add(child.name)
                elif isinstance(child, ast.MatchMapping) and child.rest is not None:
                    captures.add(child.rest)
            return captures

        def pattern_is_irrefutable(pattern: ast.pattern) -> bool:
            if isinstance(pattern, ast.MatchAs):
                return pattern.pattern is None or pattern_is_irrefutable(
                    pattern.pattern
                )
            if isinstance(pattern, ast.MatchOr):
                return any(pattern_is_irrefutable(child) for child in pattern.patterns)
            return False

        def run_path(
            statements: list[ast.stmt],
            setup: Any | None = None,
            *,
            stop_on_loop_termination: bool = False,
        ) -> dict[str, int]:
            log: dict[str, int] = {}
            transaction_logs.append(log)
            try:
                if setup is not None:
                    setup()
                process_statements(
                    statements,
                    stop_on_loop_termination=stop_on_loop_termination,
                )
                result = {name: state_for(name) for name in log}
            finally:
                transaction_logs.pop()
                for name, previous in log.items():
                    if previous == class_name_unbound:
                        states.pop(name, None)
                    else:
                        states[name] = previous
            return result

        def apply_path(result: dict[str, int]) -> None:
            for name, state in result.items():
                set_state(name, state)

        def apply_join(results: list[dict[str, int]]) -> None:
            names = set().union(*(result.keys() for result in results))
            for name in names:
                baseline = state_for(name)
                observed = {result.get(name, baseline) for result in results}
                if observed == {class_name_bound}:
                    joined = class_name_bound
                elif observed == {class_name_unbound}:
                    joined = class_name_unbound
                else:
                    joined = class_name_maybe_bound
                set_state(name, joined)

        def iterable_cardinality(node: ast.AST) -> int | None:
            if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
                if any(isinstance(child, ast.Starred) for child in node.elts):
                    return (
                        1
                        if any(
                            not isinstance(child, ast.Starred) for child in node.elts
                        )
                        else None
                    )
                return int(bool(node.elts))
            if isinstance(node, ast.Dict):
                if any(key is not None for key in node.keys):
                    return 1
                return None if node.keys else 0
            if isinstance(node, ast.Constant) and type(node.value) in {str, bytes}:
                return int(bool(node.value))
            return None

        loop_break_outcome = 1
        loop_continue_outcome = 2
        loop_fallthrough_outcome = 3
        loop_termination_path_collectors: list[dict[int, list[dict[str, int]]]] = []

        def current_transaction_result() -> dict[str, int]:
            names = sorted(
                {
                    name
                    for transaction_log in transaction_logs
                    for name in transaction_log
                }
            )
            return {name: state_for(name) for name in names}

        def block_loop_outcomes(statements: list[ast.stmt]) -> set[int]:
            outcomes: set[int] = set()
            falls_through = True
            for statement in statements:
                if not falls_through:
                    break
                statement_outcomes = statement_loop_outcomes(statement)
                outcomes.update(statement_outcomes - {loop_fallthrough_outcome})
                falls_through = loop_fallthrough_outcome in statement_outcomes
            if falls_through:
                outcomes.add(loop_fallthrough_outcome)
            return outcomes

        def statement_loop_outcomes(statement: ast.stmt) -> set[int]:
            if isinstance(statement, ast.Break):
                return {loop_break_outcome}
            if isinstance(statement, (ast.Continue, ast.Raise, ast.Return)):
                return {loop_continue_outcome}
            if isinstance(statement, ast.If):
                if isinstance(statement.test, ast.Constant):
                    branch = (
                        statement.body
                        if bool(statement.test.value)
                        else statement.orelse
                    )
                    return block_loop_outcomes(branch)
                return block_loop_outcomes(statement.body) | block_loop_outcomes(
                    statement.orelse
                )
            if isinstance(statement, ast.Match):
                outcomes: set[int] = set()
                guaranteed_match = False
                for case in statement.cases:
                    outcomes.update(block_loop_outcomes(case.body))
                    if case.guard is None and pattern_is_irrefutable(case.pattern):
                        guaranteed_match = True
                if not guaranteed_match:
                    outcomes.add(loop_fallthrough_outcome)
                return outcomes
            if isinstance(statement, (ast.With, ast.AsyncWith)):
                return block_loop_outcomes(statement.body)
            if isinstance(statement, (ast.Try, ast.TryStar)):
                outcomes = block_loop_outcomes([*statement.body, *statement.orelse])
                for handler in statement.handlers:
                    outcomes.update(block_loop_outcomes(handler.body))
                if not statement.finalbody:
                    return outcomes
                final_outcomes = block_loop_outcomes(statement.finalbody)
                result = final_outcomes - {loop_fallthrough_outcome}
                if loop_fallthrough_outcome in final_outcomes:
                    result.update(outcomes)
                return result
            return {loop_fallthrough_outcome}

        def run_after_path(
            path: dict[str, int],
            statements: list[ast.stmt],
        ) -> dict[str, int]:
            return run_path(statements, lambda: apply_path(path))

        def run_loop_body(
            statements: list[ast.stmt],
            setup: Any | None = None,
        ) -> tuple[dict[str, int], dict[int, list[dict[str, int]]]]:
            termination_paths = {
                loop_break_outcome: [],
                loop_continue_outcome: [],
            }
            loop_termination_path_collectors.append(termination_paths)
            try:
                result = run_path(
                    statements,
                    setup,
                    stop_on_loop_termination=True,
                )
            finally:
                loop_termination_path_collectors.pop()
            return result, termination_paths

        def process_loop(
            node: ast.For | ast.AsyncFor,
        ) -> None:
            process_expression(node.iter)

            def one_iteration() -> None:
                bind_target(node.target)

            body_result, termination_paths = run_loop_body(
                node.body,
                one_iteration,
            )
            outcomes = block_loop_outcomes(node.body)
            can_break = loop_break_outcome in outcomes
            can_exhaust = bool(
                outcomes & {loop_continue_outcome, loop_fallthrough_outcome}
            )
            cardinality = iterable_cardinality(node.iter)
            zero_iteration_result = run_path(node.orelse)
            if cardinality == 0:
                apply_path(zero_iteration_result)
                return
            results: list[dict[str, int]] = []
            if cardinality is None:
                results.append(zero_iteration_result)
            if can_break:
                results.extend([body_result, *termination_paths[loop_break_outcome]])
            if can_exhaust:
                exhaustion_paths = [
                    body_result,
                    *termination_paths[loop_continue_outcome],
                ]
                results.extend(
                    run_after_path(path, node.orelse) for path in exhaustion_paths
                )
            if not results:
                results.append(body_result)
            apply_join(results)

        def process_match(node: ast.Match) -> None:
            process_expression(node.subject)
            results: list[dict[str, int]] = []
            guaranteed_match = False
            for case in node.cases:
                process_expression(case.pattern)
                names = capture_names(case.pattern)

                def setup_case(names: set[str] = names) -> None:
                    for name in names:
                        set_state(name, class_name_bound)
                    if case.guard is not None:
                        process_expression(case.guard)

                results.append(run_path(case.body, setup_case))
                if case.guard is None and pattern_is_irrefutable(case.pattern):
                    guaranteed_match = True
            if not guaranteed_match:
                results.append({})
            apply_join(results)

        def process_try(node: ast.Try | ast.TryStar) -> None:
            results = [run_path([*node.body, *node.orelse])]
            for handler in node.handlers:

                def setup_handler(handler: ast.ExceptHandler = handler) -> None:
                    if handler.type is not None:
                        process_expression(handler.type)
                    if handler.name is not None:
                        set_state(handler.name, class_name_bound)

                handler_result = run_path(handler.body, setup_handler)
                if handler.name is not None:
                    handler_result[handler.name] = class_name_unbound
                results.append(handler_result)
            apply_join(results)
            process_statements(node.finalbody)

        def process_statement(node: ast.stmt) -> None:
            consume_class_dataflow_step()
            if isinstance(node, ast.Assign):
                process_expression(node.value)
                for target in node.targets:
                    bind_target(target)
                return
            if isinstance(node, ast.AnnAssign):
                if node.value is not None:
                    process_expression(node.value)
                    bind_target(node.target)
                else:
                    process_target_access(node.target)
                process_expression(node.annotation)
                return
            if isinstance(node, ast.AugAssign):
                process_target_access(node.target)
                if isinstance(node.target, ast.Name):
                    record_load(node.target)
                process_expression(node.value)
                bind_target(node.target)
                return
            if isinstance(node, ast.Delete):
                for target in node.targets:
                    delete_target(target)
                return
            if isinstance(node, ast.If):
                process_expression(node.test)
                if isinstance(node.test, ast.Constant):
                    branch = node.body if bool(node.test.value) else node.orelse
                    apply_path(run_path(branch))
                    return
                apply_join([run_path(node.body), run_path(node.orelse)])
                return
            if isinstance(node, (ast.For, ast.AsyncFor)):
                process_loop(node)
                return
            if isinstance(node, ast.While):
                process_expression(node.test)
                body_result, termination_paths = run_loop_body(node.body)
                outcomes = block_loop_outcomes(node.body)
                can_break = loop_break_outcome in outcomes
                can_exhaust = bool(
                    outcomes & {loop_continue_outcome, loop_fallthrough_outcome}
                )
                zero_iteration_result = run_path(node.orelse)
                break_results = [
                    body_result,
                    *termination_paths[loop_break_outcome],
                ]
                exhaustion_paths = [
                    body_result,
                    *termination_paths[loop_continue_outcome],
                ]
                exhaustion_results = [
                    run_after_path(path, node.orelse) for path in exhaustion_paths
                ]
                if isinstance(node.test, ast.Constant) and node.test.value is False:
                    apply_path(zero_iteration_result)
                elif isinstance(node.test, ast.Constant) and node.test.value is True:
                    results = break_results if can_break else [body_result]
                    apply_join(results)
                else:
                    results = [zero_iteration_result]
                    if can_break:
                        results.extend(break_results)
                    if can_exhaust:
                        results.extend(exhaustion_results)
                    apply_join(results)
                return
            if isinstance(node, ast.Match):
                process_match(node)
                return
            if isinstance(node, (ast.Try, ast.TryStar)):
                process_try(node)
                return
            if isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    process_expression(item.context_expr)
                    if item.optional_vars is not None:
                        bind_target(item.optional_vars)
                process_statements(node.body)
                return
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    process_expression(decorator)
                process_argument_definitions(node.args)
                if node.returns is not None:
                    process_expression(node.returns)
                for type_param in getattr(node, "type_params", ()):
                    process_expression(type_param)
                set_state(node.name, class_name_bound)
                return
            if isinstance(node, ast.ClassDef):
                for child in (
                    *node.decorator_list,
                    *node.bases,
                    *node.keywords,
                    *getattr(node, "type_params", ()),
                ):
                    process_expression(child)
                set_state(node.name, class_name_bound)
                return
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    set_state(
                        alias.asname or alias.name.split(".", 1)[0],
                        class_name_bound,
                    )
                return
            for child in ast.iter_child_nodes(node):
                if not isinstance(child, ast.stmt):
                    process_expression(child)

        def process_statements(
            statements: list[ast.stmt],
            *,
            stop_on_loop_termination: bool = False,
        ) -> None:
            for statement in statements:
                if isinstance(statement, (ast.Break, ast.Continue)):
                    if loop_termination_path_collectors:
                        outcome = (
                            loop_break_outcome
                            if isinstance(statement, ast.Break)
                            else loop_continue_outcome
                        )
                        loop_termination_path_collectors[-1][outcome].append(
                            current_transaction_result()
                        )
                    break
                process_statement(statement)
                if (
                    stop_on_loop_termination
                    and loop_fallthrough_outcome
                    not in statement_loop_outcomes(statement)
                ):
                    break

        process_statements(class_node.body)

    for node in nodes:
        if isinstance(node, ast.ClassDef):
            precompute_class_load_bindings(node)

    def normalized_literal_selector(node: ast.AST) -> int | str | None:
        if isinstance(node, ast.Constant):
            if type(node.value) is bool:
                return int(node.value)
            if type(node.value) in {int, str}:
                return node.value
        if isinstance(node, ast.UnaryOp):
            operand = normalized_literal_selector(node.operand)
            if operand is None:
                return None
            if isinstance(node.op, ast.Not):
                return int(not operand)
            if type(operand) is not int:
                return None
            if isinstance(node.op, ast.UAdd):
                return +operand
            if isinstance(node.op, ast.USub):
                return -operand
            if isinstance(node.op, ast.Invert):
                return ~operand
        return None

    modeled_string_method_names = frozenset(
        "capitalize casefold center count decode encode endswith expandtabs find "
        "format format_map fromhex hex index isalnum isalpha isascii isdecimal "
        "isdigit isidentifier islower isnumeric isprintable isspace istitle "
        "isupper join ljust lower lstrip maketrans partition removeprefix "
        "removesuffix replace rfind rindex rjust rpartition rsplit rstrip split "
        "splitlines startswith strip swapcase title translate upper zfill".split()
    )
    runtime_public_string_method_names = frozenset(
        name
        for owner in (str, bytes)
        for name in dir(owner)
        if not name.startswith("_") and callable(getattr(owner, name, None))
    )
    if runtime_public_string_method_names != modeled_string_method_names:
        raise ValueError(
            "Python runtime text method surface differs from the trusted policy"
        )
    non_text_string_method_names = frozenset(
        "count endswith find index isalnum isalpha isascii isdecimal isdigit "
        "isidentifier islower isnumeric isprintable isspace istitle isupper "
        "rfind rindex startswith".split()
    )
    text_emitting_string_method_names = (
        modeled_string_method_names - non_text_string_method_names
    )
    bound_string_method_names = frozenset(
        name
        for owner in (str, bytes)
        for name in dir(owner)
        if callable(getattr(owner, name, None))
    )
    deterministic_text_builtin_names = frozenset({"bytearray", "bytes", "chr", "str"})
    dynamic_code_builtin_names = frozenset({"compile", "eval", "exec"})
    static_import_builtin_names = frozenset({"__import__"})
    decoder_source_keyword_names = frozenset(
        "data hexstr input obj object s string".split()
    )
    text_codec_error_modes = frozenset(
        "backslashreplace ignore namereplace replace strict surrogateescape "
        "surrogatepass xmlcharrefreplace".split()
    )
    static_binary_decoder_methods_by_module = {
        "base64": frozenset(
            "a85decode b16decode b32decode b32hexdecode b64decode b85decode "
            "decode decodebytes standard_b64decode urlsafe_b64decode z85decode".split()
        ),
        "binascii": frozenset("a2b_base64 a2b_hex a2b_qp a2b_uu unhexlify".split()),
        "bz2": {"decompress"},
        "codecs": {"decode"},
        "gzip": {"decompress"},
        "lzma": {"decompress"},
        "quopri": {"decodestring"},
        "urllib.parse": {"unquote", "unquote_plus", "unquote_to_bytes"},
        "zlib": {"decompress"},
    }
    static_binary_decoder_modules = set(static_binary_decoder_methods_by_module)
    static_binary_decoder_qualified_names = frozenset(
        f"{module_name}.{method_name}"
        for module_name, method_names in static_binary_decoder_methods_by_module.items()
        for method_name in method_names
    )
    static_byte_constructor_qualified_names = frozenset({"struct.pack"})
    static_text_concatenation_qualified_names = frozenset(
        {
            "operator.add",
            "operator.concat",
            "operator.iadd",
            "operator.iconcat",
        }
    )
    static_text_repetition_qualified_names = frozenset(
        {
            "operator.imul",
            "operator.irepeat",
            "operator.mul",
            "operator.repeat",
        }
    )
    static_text_format_qualified_names = frozenset({"operator.imod", "operator.mod"})
    static_text_operator_qualified_names = (
        static_text_concatenation_qualified_names
        | static_text_repetition_qualified_names
        | static_text_format_qualified_names
    )
    import_resolver_qualified_names = frozenset({"importlib.import_module"})
    tracked_static_import_modules = static_binary_decoder_modules | {
        "importlib",
        "operator",
        "struct",
    }

    def normalized_literal_slice(node: ast.AST) -> slice | None:
        if not isinstance(node, ast.Slice):
            return None
        values: list[int | None] = []
        for component in (node.lower, node.upper, node.step):
            if component is None:
                values.append(None)
                continue
            value = normalized_literal_selector(component)
            if type(value) is not int:
                return None
            values.append(value)
        if values[2] == 0:
            raise ValueError("Python literal slice uses a zero step")
        return slice(*values)

    def is_supported_binding_expression(node: ast.AST) -> bool:
        if isinstance(node, ast.Constant):
            return node.value is None or type(node.value) in {
                bool,
                bytes,
                complex,
                float,
                int,
                str,
            }
        if isinstance(node, ast.Name):
            return isinstance(node.ctx, ast.Load)
        if isinstance(node, ast.Attribute):
            if node.attr == "to_bytes":
                return is_supported_binding_expression(node.value)
            return (
                node.attr in bound_string_method_names
                and (
                    node.attr in {"format", "format_map", "join"}
                    or not isinstance(node.value, ast.Name)
                    or node.value.id in {"bytes", "str"}
                    or name_has_prior_static_text_origin(node.value)
                )
                and is_supported_binding_expression(node.value)
            )
        if isinstance(node, (ast.Tuple, ast.List)):
            return all(is_supported_binding_expression(child) for child in node.elts)
        if isinstance(node, ast.Dict):
            return all(
                key is not None
                and is_supported_binding_expression(key)
                and is_supported_binding_expression(child)
                for key, child in zip(node.keys, node.values, strict=True)
            )
        if isinstance(node, ast.UnaryOp):
            return isinstance(node.op, (ast.UAdd, ast.USub)) and (
                is_supported_binding_expression(node.operand)
            )
        if isinstance(node, ast.Subscript):
            return (
                normalized_literal_selector(node.slice) is not None
                or (
                    normalized_literal_slice(node.slice) is not None
                    and not isinstance(node.value, ast.Name)
                )
            ) and (is_supported_binding_expression(node.value))
        if isinstance(node, ast.BinOp):
            return isinstance(node.op, (ast.Add, ast.Mult, ast.Mod)) and (
                is_supported_binding_expression(node.left)
                and is_supported_binding_expression(node.right)
            )
        if isinstance(node, ast.JoinedStr):
            return all(
                isinstance(child, ast.Constant)
                or (
                    isinstance(child, ast.FormattedValue)
                    and is_supported_binding_expression(child.value)
                    and (
                        child.format_spec is None
                        or is_supported_binding_expression(child.format_spec)
                    )
                )
                for child in node.values
            )
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and (
                node.func.id in deterministic_text_builtin_names
                or node.func.id in {"getattr", "range"}
                or name_has_prior_getattr_origin(node.func)
            ):
                return (
                    not any(isinstance(argument, ast.Starred) for argument in node.args)
                    and all(
                        is_supported_binding_expression(argument)
                        for argument in node.args
                    )
                    and all(
                        keyword.arg is not None
                        and is_supported_binding_expression(keyword.value)
                        for keyword in node.keywords
                    )
                )
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "to_bytes":
                    return (
                        is_supported_binding_expression(node.func.value)
                        and not any(
                            isinstance(argument, ast.Starred) for argument in node.args
                        )
                        and all(
                            is_supported_binding_expression(argument)
                            for argument in node.args
                        )
                        and all(
                            keyword.arg is not None
                            and is_supported_binding_expression(keyword.value)
                            for keyword in node.keywords
                        )
                    )
                return (
                    node.func.attr in bound_string_method_names
                    and (
                        node.func.attr in {"format", "format_map", "join"}
                        or not isinstance(node.func.value, ast.Name)
                        or node.func.value.id in {"bytes", "str"}
                        or name_has_prior_static_text_origin(node.func.value)
                    )
                    and is_supported_binding_expression(node.func.value)
                    and all(
                        is_supported_binding_expression(
                            argument.value
                            if isinstance(argument, ast.Starred)
                            else argument
                        )
                        for argument in node.args
                    )
                    and all(
                        is_supported_binding_expression(keyword.value)
                        for keyword in node.keywords
                    )
                )
        return False

    def assignment_targets(
        target: ast.AST,
        path: tuple[int, ...] = (),
    ) -> list[tuple[ast.Name, tuple[int, ...]]]:
        if isinstance(target, ast.Name):
            return [(target, path)]
        if isinstance(target, (ast.Tuple, ast.List)):
            targets: list[tuple[ast.Name, tuple[int, ...]]] = []
            starred_index = next(
                (
                    index
                    for index, child in enumerate(target.elts)
                    if isinstance(child, ast.Starred)
                ),
                None,
            )
            for index, child in enumerate(target.elts):
                if isinstance(child, ast.Starred):
                    continue
                selector = (
                    index - len(target.elts)
                    if starred_index is not None and index > starred_index
                    else index
                )
                targets.extend(assignment_targets(child, (*path, selector)))
            return targets
        return []

    binding_candidates: dict[
        tuple[int, str],
        list[
            tuple[
                ast.Assign | ast.AnnAssign,
                ast.AST,
                tuple[int, ...],
                ast.Name,
            ]
        ],
    ] = {}
    explicitly_ambiguous_binding_keys: set[tuple[int, str]] = set()
    ordinary_ambiguous_binding_values: dict[tuple[int, str], list[ast.AST]] = {}
    ordinary_ambiguous_binding_events: dict[
        tuple[int, str], list[tuple[int, ast.AST]]
    ] = {}
    StarredBindingCandidate = tuple[
        ast.Assign | ast.For | ast.AsyncFor,
        ast.AST,
        tuple[int, ...],
        int,
        int,
        ast.Name,
        bool,
    ]
    StarredCaptureAlternative = tuple[bool, tuple[ast.AST, ...]]
    starred_binding_candidates: dict[
        tuple[int, str], list[StarredBindingCandidate]
    ] = {}
    starred_target_ids: set[int] = set()
    non_guaranteed_binding_event_ids: set[int] = set()
    non_guaranteed_binding_body_ids: dict[int, frozenset[int]] = {}
    non_guaranteed_binding_orelse_ids: dict[int, frozenset[int]] = {}
    augassign_binding_keys_by_id: dict[int, set[tuple[int, str]]] = {}
    unresolved_augassign_receiver_ids: set[int] = set()
    bytearray_mutation_receivers: list[ast.Name] = []
    bytearray_mutation_origin_ids: frozenset[int] | None = None
    static_callable_import_bindings: dict[tuple[int, str], list[tuple[int, str]]] = {}
    static_module_import_bindings: dict[tuple[int, str], list[tuple[int, str]]] = {}
    static_builtin_import_bindings: dict[tuple[int, str], list[tuple[int, str]]] = {}
    parameter_default_sources: dict[tuple[int, str], list[tuple[int, ast.AST]]] = {}

    def record_starred_assignment_targets(
        statement: ast.Assign | ast.For | ast.AsyncFor,
        assigned_value: ast.AST,
        target: ast.AST,
        path: tuple[int, ...] = (),
        *,
        iterates_assigned_value: bool = False,
    ) -> None:
        if not isinstance(target, (ast.Tuple, ast.List)):
            return
        starred_index = next(
            (
                index
                for index, child in enumerate(target.elts)
                if isinstance(child, ast.Starred)
            ),
            None,
        )
        for index, child in enumerate(target.elts):
            if isinstance(child, ast.Starred):
                if not isinstance(child.value, ast.Name) or not isinstance(
                    child.value.ctx, ast.Store
                ):
                    continue
                target_scope = binding_scope_for_name(
                    scope_by_node_id[id(child.value)], child.value.id
                )
                key = (target_scope, child.value.id)
                starred_binding_candidates.setdefault(key, []).append(
                    (
                        statement,
                        assigned_value,
                        path,
                        index,
                        len(target.elts) - index - 1,
                        child.value,
                        iterates_assigned_value,
                    )
                )
                starred_target_ids.add(id(child.value))
                continue
            selector = (
                index - len(target.elts)
                if starred_index is not None and index > starred_index
                else index
            )
            record_starred_assignment_targets(
                statement,
                assigned_value,
                child,
                (*path, selector),
                iterates_assigned_value=iterates_assigned_value,
            )

    def name_has_prior_static_text_origin(
        node: ast.Name,
        observed_keys: frozenset[tuple[int, str]] = frozenset(),
    ) -> bool:
        key = name_load_binding_key(node)
        if key in observed_keys:
            return False
        next_observed = observed_keys | {key}
        for _, source, path, _ in binding_candidates.get(key, ()):
            selected = source
            for index in path:
                if not isinstance(selected, (ast.Tuple, ast.List)):
                    selected = None
                    break
                if index >= len(selected.elts):
                    selected = None
                    break
                selected = selected.elts[index]
            if isinstance(selected, ast.Constant) and type(selected.value) in {
                str,
                bytes,
            }:
                return True
            if isinstance(selected, ast.Name) and isinstance(selected.ctx, ast.Load):
                if name_has_prior_static_text_origin(selected, next_observed):
                    return True
                continue
            if isinstance(selected, ast.Call) and isinstance(
                selected.func, ast.Attribute
            ):
                receiver = selected.func.value
                if isinstance(receiver, ast.Name):
                    if receiver.id in {"bytes", "str"} or (
                        name_has_prior_static_text_origin(receiver, next_observed)
                    ):
                        return True
                elif is_supported_binding_expression(receiver):
                    return True
            if (
                isinstance(selected, ast.Call)
                and isinstance(selected.func, ast.Name)
                and selected.func.id in deterministic_text_builtin_names
            ):
                return True
            if isinstance(selected, (ast.Attribute, ast.Subscript)):
                receiver = selected.value
                if isinstance(receiver, ast.Name) and (
                    name_has_prior_static_text_origin(receiver, next_observed)
                ):
                    return True
                if not isinstance(receiver, ast.Name) and (
                    is_supported_binding_expression(receiver)
                ):
                    return True
            if isinstance(selected, (ast.BinOp, ast.JoinedStr)):
                return True
        return False

    def expression_static_text_builtin_origin_ids(
        node: ast.AST,
        builtin_names: frozenset[str],
        observed_keys: frozenset[tuple[int, str]] = frozenset(),
    ) -> frozenset[int]:
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in builtin_names
            and unshadowed_deterministic_text_builtin(node.func) is not None
        ):
            return frozenset({id(node)})
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            return expression_static_text_builtin_origin_ids(
                node.func.value,
                builtin_names,
                observed_keys,
            )
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            key = name_load_binding_key(node)
            if key in observed_keys:
                return frozenset()
            next_observed = observed_keys | {key}
            sources: list[ast.AST] = []
            for _, assigned_value, path, _ in binding_candidates.get(key, ()):
                selected = selected_assignment_expression(assigned_value, path)
                sources.append(selected or assigned_value)
            sources.extend(ordinary_ambiguous_binding_values.get(key, ()))
            origins: set[int] = set()
            for source in sources:
                origins.update(
                    expression_static_text_builtin_origin_ids(
                        source,
                        builtin_names,
                        next_observed,
                    )
                )
            return frozenset(origins)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return expression_static_text_builtin_origin_ids(
                node.value,
                builtin_names,
                observed_keys,
            )
        return frozenset()

    def expression_has_mutated_static_bytearray_origin(
        node: ast.AST,
    ) -> bool:
        nonlocal bytearray_mutation_origin_ids
        if bytearray_mutation_origin_ids is None:
            mutation_origins: set[int] = set()
            for receiver in bytearray_mutation_receivers:
                mutation_origins.update(
                    expression_static_text_builtin_origin_ids(
                        receiver,
                        frozenset({"bytearray"}),
                    )
                )
            bytearray_mutation_origin_ids = frozenset(mutation_origins)
        receiver_origins = expression_static_text_builtin_origin_ids(
            node,
            frozenset({"bytearray"}),
        )
        return bool(receiver_origins & bytearray_mutation_origin_ids)

    def mutation_receiver_name(target: ast.AST) -> ast.Name | None:
        while isinstance(target, (ast.Attribute, ast.Subscript)):
            target = target.value
        if isinstance(target, ast.Name) and isinstance(target.ctx, ast.Load):
            return target
        return None

    def mark_assignment_target_ambiguous(
        target: ast.AST,
        *,
        assigned_value: ast.AST | None = None,
        path: tuple[int, ...] = (),
    ) -> None:
        if isinstance(target, ast.Name) and isinstance(target.ctx, ast.Store):
            target_scope = binding_scope_for_name(
                scope_by_node_id[id(target)], target.id
            )
            key = (target_scope, target.id)
            if assigned_value is None:
                explicitly_ambiguous_binding_keys.add(key)
                return
            selected_value = assigned_value
            for index in path:
                if not isinstance(
                    selected_value, (ast.Tuple, ast.List)
                ) or index >= len(selected_value.elts):
                    selected_value = assigned_value
                    break
                selected_value = selected_value.elts[index]
            ordinary_ambiguous_binding_values.setdefault(key, []).append(selected_value)
            ordinary_ambiguous_binding_events.setdefault(key, []).append(
                (id(target), selected_value)
            )
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            starred_index = next(
                (
                    index
                    for index, child in enumerate(target.elts)
                    if isinstance(child, ast.Starred)
                ),
                None,
            )
            for index, child in enumerate(target.elts):
                if isinstance(child, ast.Starred):
                    if id(child.value) not in starred_target_ids:
                        mark_assignment_target_ambiguous(
                            child.value,
                            assigned_value=assigned_value,
                        )
                else:
                    selector = (
                        index - len(target.elts)
                        if starred_index is not None and index > starred_index
                        else index
                    )
                    mark_assignment_target_ambiguous(
                        child,
                        assigned_value=assigned_value,
                        path=(*path, selector),
                    )
            return
        for child in ast.walk(target):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                mark_assignment_target_ambiguous(child)

    def assignment_target_binds_class_scope(target: ast.AST) -> bool:
        return any(
            isinstance(child, ast.Name)
            and isinstance(child.ctx, ast.Store)
            and scope_kinds.get(
                binding_scope_for_name(scope_by_node_id[id(child)], child.id)
            )
            == "class"
            for child in ast.walk(target)
        )

    getattr_origin_cache: dict[int, bool] = {}
    getattr_origin_operations = 0
    getattr_origin_operation_limit = min(
        max(node_count * 16, 1),
        BOOTSTRAP_V2_MAX_PYTHON_METHOD_SELECTION_OPERATIONS,
    )

    def consume_getattr_origin_operation() -> None:
        nonlocal getattr_origin_operations
        if getattr_origin_operations >= getattr_origin_operation_limit:
            raise ValueError(
                "Python getattr origin analysis exceeds the trusted operation limit"
            )
        getattr_origin_operations += 1

    def name_has_prior_getattr_origin(
        node: ast.Name,
    ) -> bool:
        node_id = id(node)
        cached = getattr_origin_cache.get(node_id)
        if cached is not None:
            return cached
        expressions: dict[int, ast.Name] = {node_id: node}
        dependencies: dict[int, set[int]] = {}
        dependents: dict[int, set[int]] = {}
        origin_ids: set[int] = set()
        pending = [node]
        while pending:
            current = pending.pop()
            current_id = id(current)
            if current_id in dependencies:
                continue
            current_dependencies: set[int] = set()
            key = name_load_binding_key(current)
            for statement, source, path, _target in binding_candidates.get(key, ()):
                consume_getattr_origin_operation()
                if (current.lineno, current.col_offset) < (
                    statement.end_lineno,
                    statement.end_col_offset,
                ):
                    continue
                selected: ast.AST | None = source
                for index in path:
                    if not isinstance(selected, (ast.Tuple, ast.List)) or index >= len(
                        selected.elts
                    ):
                        selected = None
                        break
                    selected = selected.elts[index]
                if not isinstance(selected, ast.Name) or not isinstance(
                    selected.ctx,
                    ast.Load,
                ):
                    continue
                selected_key = name_load_binding_key(selected)
                if (
                    selected.id == "getattr"
                    and selected_key
                    == (
                        module_scope,
                        "getattr",
                    )
                    and not binding_candidates.get(selected_key)
                ):
                    origin_ids.add(current_id)
                    continue
                selected_cached = getattr_origin_cache.get(id(selected))
                if selected_cached is True:
                    origin_ids.add(current_id)
                    continue
                if selected_cached is False:
                    continue
                selected_id = id(selected)
                expressions[selected_id] = selected
                current_dependencies.add(selected_id)
                dependents.setdefault(selected_id, set()).add(current_id)
                pending.append(selected)
            dependencies[current_id] = current_dependencies

        reachable = set(origin_ids)
        pending_ids = list(origin_ids)
        while pending_ids:
            current_id = pending_ids.pop()
            for dependent_id in dependents.get(current_id, ()):
                consume_getattr_origin_operation()
                if dependent_id not in reachable:
                    reachable.add(dependent_id)
                    pending_ids.append(dependent_id)
        for expression_id in expressions:
            getattr_origin_cache[expression_id] = expression_id in reachable
        return node_id in reachable

    for node in nodes:
        if isinstance(node, ast.Assign):
            assigned_value = node.value
            for assignment_target in node.targets:
                record_starred_assignment_targets(
                    node,
                    assigned_value,
                    assignment_target,
                )
            if not is_supported_binding_expression(assigned_value):
                for assignment_target in node.targets:
                    mark_assignment_target_ambiguous(
                        assignment_target,
                        assigned_value=assigned_value,
                    )
                continue
            targets = [
                target
                for assignment_target in node.targets
                for target in assignment_targets(assignment_target)
            ]
            supported_target_ids = {id(target) for target, _ in targets}
            for assignment_target in node.targets:
                for child in ast.walk(assignment_target):
                    if (
                        isinstance(child, ast.Name)
                        and isinstance(child.ctx, ast.Store)
                        and id(child) not in supported_target_ids
                        and id(child) not in starred_target_ids
                    ):
                        mark_assignment_target_ambiguous(
                            child,
                            assigned_value=assigned_value,
                        )
        elif isinstance(node, ast.AnnAssign):
            targets = assignment_targets(node.target)
            if node.value is None or not isinstance(node.target, ast.Name):
                for target in ast.walk(node.target):
                    if isinstance(target, ast.Name):
                        target_scope = binding_scope_for_name(
                            scope_by_node_id[id(target)], target.id
                        )
                        explicitly_ambiguous_binding_keys.add((target_scope, target.id))
                continue
            if not is_supported_binding_expression(node.value):
                target = node.target
                target_scope = binding_scope_for_name(
                    scope_by_node_id[id(target)], target.id
                )
                explicitly_ambiguous_binding_keys.add((target_scope, target.id))
                continue
            assigned_value = node.value
        elif isinstance(node, ast.NamedExpr):
            mark_assignment_target_ambiguous(
                node.target,
                assigned_value=node.value,
            )
            continue
        elif isinstance(node, ast.AugAssign):
            mark_assignment_target_ambiguous(
                node.target,
                assigned_value=node.value,
            )
            if assignment_target_binds_class_scope(node.target):
                mark_assignment_target_ambiguous(node.target)
            for child in ast.walk(node.target):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                    target_scope = binding_scope_for_name(
                        scope_by_node_id[id(child)], child.id
                    )
                    augassign_binding_keys_by_id.setdefault(id(node), set()).add(
                        (target_scope, child.id)
                    )
            receiver = mutation_receiver_name(node.target)
            if receiver is not None:
                receiver_scope = binding_scope_for_name(
                    scope_by_node_id[id(receiver)], receiver.id
                )
                key = (receiver_scope, receiver.id)
                ordinary_ambiguous_binding_values.setdefault(key, []).append(node.value)
                ordinary_ambiguous_binding_events.setdefault(key, []).append(
                    (id(node), node.value)
                )
                augassign_binding_keys_by_id.setdefault(id(node), set()).add(key)
            elif not isinstance(node.target, ast.Name):
                unresolved_augassign_receiver_ids.add(id(node))
            continue
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            record_starred_assignment_targets(
                node,
                node.iter,
                node.target,
                iterates_assigned_value=True,
            )
            non_guaranteed_binding_event_ids.update(
                id(target)
                for target in ast.walk(node.target)
                if isinstance(target, ast.Name) and isinstance(target.ctx, ast.Store)
            )
            non_guaranteed_binding_body_ids[id(node)] = frozenset(
                id(statement) for statement in node.body
            )
            non_guaranteed_binding_orelse_ids[id(node)] = frozenset(
                id(statement) for statement in node.orelse
            )
            if (
                assignment_target_binds_class_scope(node.target)
                or isinstance(node.iter, (ast.List, ast.Tuple))
                or not is_supported_binding_expression(node.iter)
            ):
                mark_assignment_target_ambiguous(
                    node.target,
                    assigned_value=node.iter,
                )
            continue
        elif isinstance(node, ast.Match):
            subject_scope = scope_by_node_id[id(node.subject)]
            for case in node.cases:
                for pattern in ast.walk(case.pattern):
                    names: tuple[str | None, ...] = ()
                    if isinstance(pattern, (ast.MatchAs, ast.MatchStar)):
                        names = (pattern.name,)
                    elif isinstance(pattern, ast.MatchMapping):
                        names = (pattern.rest,)
                    for name in names:
                        if name is None:
                            continue
                        target_scope = binding_scope_for_name(subject_scope, name)
                        ordinary_ambiguous_binding_values.setdefault(
                            (target_scope, name), []
                        ).append(node.subject)
                        ordinary_ambiguous_binding_events.setdefault(
                            (target_scope, name), []
                        ).append((id(pattern), node.subject))
            continue
        else:
            continue
        for target, path in targets:
            target_scope = binding_scope_for_name(
                scope_by_node_id[id(target)], target.id
            )
            binding_candidates.setdefault((target_scope, target.id), []).append(
                (node, assigned_value, path, target)
            )

    for node in nodes:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        positional = (*node.args.posonlyargs, *node.args.args)
        positional_with_defaults = (
            positional[-len(node.args.defaults) :] if node.args.defaults else ()
        )
        for argument, default in zip(
            positional_with_defaults,
            node.args.defaults,
            strict=True,
        ):
            key = (scope_by_node_id[id(argument)], argument.arg)
            parameter_default_sources.setdefault(key, []).append(
                (id(argument), default)
            )
        for argument, default in zip(
            node.args.kwonlyargs,
            node.args.kw_defaults,
            strict=True,
        ):
            if default is None:
                continue
            key = (scope_by_node_id[id(argument)], argument.arg)
            parameter_default_sources.setdefault(key, []).append(
                (id(argument), default)
            )

    for node in nodes:
        if isinstance(node, ast.Import):
            scope = scope_by_node_id[id(node)]
            for alias in node.names:
                if alias.name not in tracked_static_import_modules:
                    continue
                local_name = alias.asname or alias.name.split(".", 1)[0]
                imported_name = (
                    alias.name if alias.asname else alias.name.split(".", 1)[0]
                )
                key = (binding_scope_for_name(scope, local_name), local_name)
                static_module_import_bindings.setdefault(key, []).append(
                    (id(alias), imported_name)
                )
            continue
        if not isinstance(node, ast.ImportFrom) or node.level or node.module is None:
            continue
        scope = scope_by_node_id[id(node)]
        for alias in node.names:
            if alias.name == "*" and node.module in static_binary_decoder_modules:
                raise ValueError(
                    "Python decoder module uses a wildcard import "
                    f"at line {getattr(node, 'lineno', 0)}"
                )
            local_name = alias.asname or alias.name
            key = (binding_scope_for_name(scope, local_name), local_name)
            qualified_name = f"{node.module}.{alias.name}"
            if qualified_name in tracked_static_import_modules:
                static_module_import_bindings.setdefault(key, []).append(
                    (id(alias), qualified_name)
                )
            if qualified_name in (
                static_binary_decoder_qualified_names
                | static_byte_constructor_qualified_names
                | static_text_operator_qualified_names
                | import_resolver_qualified_names
            ):
                static_callable_import_bindings.setdefault(key, []).append(
                    (id(alias), qualified_name)
                )
            if node.module == "builtins" and alias.name in {"getattr", "int"}:
                static_builtin_import_bindings.setdefault(key, []).append(
                    (id(alias), alias.name)
                )

    bytearray_mutating_method_names = frozenset(
        "__delitem__ __iadd__ __imul__ __setitem__ append clear extend insert "
        "pop remove reverse".split()
    )
    for node in nodes:
        receivers: list[ast.Name] = []
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in bytearray_mutating_method_names
        ):
            receiver = mutation_receiver_name(node.func.value)
            if receiver is not None:
                receivers.append(receiver)
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.Delete, ast.AugAssign)):
            if isinstance(node, (ast.Assign, ast.Delete)):
                mutation_targets = node.targets
            else:
                mutation_targets = (node.target,)
            for target in mutation_targets:
                if not isinstance(target, (ast.Attribute, ast.Subscript)):
                    continue
                receiver = mutation_receiver_name(target)
                if receiver is not None:
                    receivers.append(receiver)
        for receiver in receivers:
            bytearray_mutation_receivers.append(receiver)

    binding_event_ids: dict[tuple[int, str], set[int]] = {}

    def record_binding_event(
        scope: int,
        name: str | None,
        event_node: ast.AST,
    ) -> None:
        if name is None:
            return
        target_scope = binding_scope_for_name(scope, name)
        key = (target_scope, name)
        binding_event_ids.setdefault(key, set()).add(id(event_node))

    for node in nodes:
        scope = scope_by_node_id[id(node)]
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            record_binding_event(scope, node.id, node)
        elif isinstance(node, ast.arg):
            record_binding_event(scope, node.arg, node)
        elif isinstance(node, ast.MatchAs):
            record_binding_event(scope, node.name, node)
        elif isinstance(node, ast.MatchStar):
            record_binding_event(scope, node.name, node)
        elif isinstance(node, ast.MatchMapping):
            record_binding_event(scope, node.rest, node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            record_binding_event(scope, node.name, node)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                record_binding_event(
                    scope,
                    alias.asname or alias.name.split(".", 1)[0],
                    alias,
                )
        elif isinstance(node, ast.ExceptHandler):
            record_binding_event(scope, node.name, node)

    hard_ambiguous_binding_keys = (
        set(explicitly_ambiguous_binding_keys)
        | set(ordinary_ambiguous_binding_values)
        | set(starred_binding_candidates)
    )
    control_flow_ambiguous_binding_keys: set[tuple[int, str]] = set()
    for key, candidates in binding_candidates.items():
        if len(candidates) != 1:
            hard_ambiguous_binding_keys.add(key)
            continue
        statement, _, _, target = candidates[0]
        if binding_event_ids.get(key, set()) != {id(target)}:
            hard_ambiguous_binding_keys.add(key)
        elif id(statement) not in direct_statement_ids_by_scope.get(key[0], set()):
            control_flow_ambiguous_binding_keys.add(key)

    control_flow_ambiguous_binding_keys.difference_update(hard_ambiguous_binding_keys)
    ambiguous_binding_keys = (
        hard_ambiguous_binding_keys | control_flow_ambiguous_binding_keys
    )

    structural_parents_by_id: dict[int, dict[int, int]] = {}
    binding_roots_by_expression_id: dict[int, set[tuple[int, str]]] = {}
    ordinary_binding_roots_by_expression_id: dict[int, set[tuple[int, str]]] = {}
    binding_load_ids_by_key: dict[tuple[int, str], set[int]] = {}
    safe_control_flow_load_pairs: set[tuple[tuple[int, str], int]] = set()
    binding_dataflow_edges = 0
    binding_dataflow_edge_limit = max(node_count * 8, 1)
    binding_dataflow_unreachable_depth = BOOTSTRAP_V2_MAX_PYTHON_AST_DEPTH + 1

    def add_binding_dataflow_edge(targets: set[Any], target: Any) -> None:
        nonlocal binding_dataflow_edges
        if target in targets:
            return
        targets.add(target)
        binding_dataflow_edges += 1
        if binding_dataflow_edges > binding_dataflow_edge_limit:
            raise ValueError("Python binding dataflow exceeds the trusted edge limit")

    def add_structural_dataflow_edge(
        child_id: int,
        parent_id: int,
        opaque_call_cost: int,
    ) -> None:
        nonlocal binding_dataflow_edges
        parents = structural_parents_by_id.setdefault(child_id, {})
        previous_cost = parents.get(parent_id)
        if previous_cost is not None:
            parents[parent_id] = min(previous_cost, opaque_call_cost)
            return
        parents[parent_id] = opaque_call_cost
        binding_dataflow_edges += 1
        if binding_dataflow_edges > binding_dataflow_edge_limit:
            raise ValueError("Python binding dataflow exceeds the trusted edge limit")

    for parent in nodes:
        if isinstance(parent, (ast.Module, ast.stmt)):
            continue
        supported_string_call = (
            isinstance(parent, ast.Call)
            and isinstance(parent.func, ast.Attribute)
            and parent.func.attr in bound_string_method_names
        )
        opaque_call_cost = int(
            isinstance(parent, ast.Call) and not supported_string_call
        )
        for child in ast.iter_child_nodes(parent):
            add_structural_dataflow_edge(
                id(child),
                id(parent),
                opaque_call_cost,
            )

    for node in nodes:
        if not isinstance(node, ast.AugAssign):
            continue
        add_structural_dataflow_edge(id(node.value), id(node), 0)
        for key in augassign_binding_keys_by_id.get(id(node), ()):
            add_binding_dataflow_edge(
                binding_load_ids_by_key.setdefault(key, set()),
                id(node),
            )

    for key, candidates in binding_candidates.items():
        for _, assigned_value, _, _ in candidates:
            add_binding_dataflow_edge(
                binding_roots_by_expression_id.setdefault(id(assigned_value), set()),
                key,
            )
    for key, assigned_values in ordinary_ambiguous_binding_values.items():
        for assigned_value in assigned_values:
            add_binding_dataflow_edge(
                ordinary_binding_roots_by_expression_id.setdefault(
                    id(assigned_value), set()
                ),
                key,
            )
    for key, candidates in starred_binding_candidates.items():
        for _, assigned_value, _, _, _, _, _ in candidates:
            add_binding_dataflow_edge(
                ordinary_binding_roots_by_expression_id.setdefault(
                    id(assigned_value), set()
                ),
                key,
            )
    for node in nodes:
        if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load):
            continue
        key, skipped_class_keys = name_load_binding_resolution(node)
        for dependency_key in (key, *skipped_class_keys):
            add_binding_dataflow_edge(
                binding_load_ids_by_key.setdefault(dependency_key, set()),
                id(node),
            )
            candidates = binding_candidates.get(dependency_key)
            if (
                dependency_key in control_flow_ambiguous_binding_keys
                and candidates is not None
                and len(candidates) == 1
                and scope_by_node_id[id(node)] == dependency_key[0]
                and statement_dominates_load(candidates[0][0], node)
            ):
                safe_control_flow_load_pairs.add((dependency_key, id(node)))

    def propagate_binding_dataflow(
        *,
        initial_expression_ids: set[int] | None = None,
        initial_binding_keys: set[tuple[int, str]] | None = None,
        initial_binding_depths: dict[tuple[int, str], int] | None = None,
        include_ordinary_binding_roots: bool = True,
        skip_safe_control_flow_loads: bool = False,
    ) -> tuple[
        set[int],
        set[tuple[int, str]],
        dict[int, int],
        dict[tuple[int, str], int],
    ]:
        expression_depths = {
            expression_id: 0 for expression_id in (initial_expression_ids or ())
        }
        binding_depths = {key: 0 for key in (initial_binding_keys or ())}
        for key, depth in (initial_binding_depths or {}).items():
            binding_depths[key] = min(binding_depths.get(key, depth), depth)
        pending_expressions = list(expression_depths.items())
        pending_bindings = list(binding_depths.items())
        propagation_steps = 0
        propagation_limit = max(node_count * 24, 1)
        max_opaque_call_depth = BOOTSTRAP_V2_MAX_PYTHON_AST_DEPTH

        def consume_propagation_step() -> None:
            nonlocal propagation_steps
            propagation_steps += 1
            if propagation_steps > propagation_limit:
                raise ValueError(
                    "Python binding dataflow exceeds the trusted operation limit"
                )

        while pending_expressions or pending_bindings:
            while pending_expressions:
                expression_id, depth = pending_expressions.pop()
                if expression_depths.get(expression_id) != depth:
                    continue
                for parent_id, opaque_call_cost in structural_parents_by_id.get(
                    expression_id, {}
                ).items():
                    consume_propagation_step()
                    next_depth = depth + opaque_call_cost
                    if next_depth > max_opaque_call_depth:
                        continue
                    if next_depth < expression_depths.get(
                        parent_id, binding_dataflow_unreachable_depth
                    ):
                        expression_depths[parent_id] = next_depth
                        pending_expressions.append((parent_id, next_depth))
                for key in binding_roots_by_expression_id.get(expression_id, ()):
                    consume_propagation_step()
                    if depth < binding_depths.get(
                        key, binding_dataflow_unreachable_depth
                    ):
                        binding_depths[key] = depth
                        pending_bindings.append((key, depth))
                if include_ordinary_binding_roots:
                    for key in ordinary_binding_roots_by_expression_id.get(
                        expression_id, ()
                    ):
                        consume_propagation_step()
                        if depth < binding_depths.get(
                            key, binding_dataflow_unreachable_depth
                        ):
                            binding_depths[key] = depth
                            pending_bindings.append((key, depth))
            while pending_bindings:
                key, depth = pending_bindings.pop()
                if binding_depths.get(key) != depth:
                    continue
                for load_id in binding_load_ids_by_key.get(key, ()):
                    consume_propagation_step()
                    if (
                        skip_safe_control_flow_loads
                        and (
                            key,
                            load_id,
                        )
                        in safe_control_flow_load_pairs
                    ):
                        continue
                    if depth < expression_depths.get(
                        load_id, binding_dataflow_unreachable_depth
                    ):
                        expression_depths[load_id] = depth
                        pending_expressions.append((load_id, depth))
        return (
            set(expression_depths),
            set(binding_depths),
            expression_depths,
            binding_depths,
        )

    def text_seed_may_contribute_to_privacy_risk(node: ast.Constant) -> bool:
        text, _ = bootstrap_v2_python_constant_text(node.value)
        if bootstrap_v2_privacy_risk_lines(text):
            return True
        normalized = text.casefold()
        splittable_markers = (
            "ghp_",
            "github_pat_",
            "bearer ",
            "https://",
            "http://",
            "ssh://",
        )
        complete_markers = (
            "git@",
            "@example.com",
            "/users/",
            "/home/",
            "/root/",
            ".codex/",
            "private key",
            "secret key",
        )
        if any(marker in normalized for marker in complete_markers):
            return True
        if len(normalized) >= 3 and any(
            marker.startswith(normalized) or normalized.startswith(marker)
            for marker in splittable_markers
        ):
            return True
        if "@" in normalized or "://" in normalized:
            return True
        return len(normalized) >= 12 and normalized.isalnum()

    def is_unsupported_text_expression(node: ast.AST) -> bool:
        return isinstance(
            node,
            (
                ast.DictComp,
                ast.GeneratorExp,
                ast.ListComp,
                ast.SetComp,
            ),
        )

    unsupported_text_analysis_operations = 0
    unsupported_text_analysis_limit = max(node_count * 8, 1)

    def consume_unsupported_text_analysis_operation() -> None:
        nonlocal unsupported_text_analysis_operations
        unsupported_text_analysis_operations += 1
        if unsupported_text_analysis_operations > unsupported_text_analysis_limit:
            raise ValueError(
                "Python unsupported text analysis exceeds the trusted operation limit"
            )

    for expression in nodes:
        if not isinstance(expression, ast.expr) or not is_unsupported_text_expression(
            expression
        ):
            continue
        fragments: list[str] = []
        pending_fragment_nodes = [expression]
        while pending_fragment_nodes:
            consume_unsupported_text_analysis_operation()
            fragment_node = pending_fragment_nodes.pop()
            if isinstance(fragment_node, ast.Constant) and isinstance(
                fragment_node.value, (str, bytes)
            ):
                fragment, _ = bootstrap_v2_python_constant_text(fragment_node.value)
                fragments.append(fragment)
                continue
            pending_fragment_nodes.extend(
                reversed(list(ast.iter_child_nodes(fragment_node)))
            )
        if len(fragments) >= 2 and bootstrap_v2_privacy_risk_lines("".join(fragments)):
            raise ValueError(
                "Python text construction uses an unsupported expression "
                f"at line {getattr(expression, 'lineno', 0)}"
            )

    all_text_expression_ids = {
        id(node)
        for node in nodes
        if isinstance(node, ast.Constant) and type(node.value) in {str, bytes}
    }
    (
        _,
        supported_text_seeded_binding_keys,
        _,
        supported_text_seeded_binding_depths,
    ) = propagate_binding_dataflow(
        initial_expression_ids=all_text_expression_ids,
        include_ordinary_binding_roots=False,
    )
    (
        risk_text_seeded_expression_ids,
        ordinary_text_seeded_binding_keys,
        _,
        ordinary_text_seeded_binding_depths,
    ) = propagate_binding_dataflow(
        initial_expression_ids={
            id(node)
            for node in nodes
            if isinstance(node, ast.Constant)
            and type(node.value) in {str, bytes}
            and text_seed_may_contribute_to_privacy_risk(node)
        },
    )
    text_seeded_binding_keys = (
        supported_text_seeded_binding_keys | ordinary_text_seeded_binding_keys
    )
    text_seeded_binding_depths = {
        key: min(
            supported_text_seeded_binding_depths.get(
                key, binding_dataflow_unreachable_depth
            ),
            ordinary_text_seeded_binding_depths.get(
                key, binding_dataflow_unreachable_depth
            ),
        )
        for key in text_seeded_binding_keys
    }
    fail_closed_ambiguous_binding_keys = explicitly_ambiguous_binding_keys | (
        ambiguous_binding_keys & text_seeded_binding_keys
    )
    fail_closed_initial_depths = {
        key: (
            0
            if key in explicitly_ambiguous_binding_keys
            else text_seeded_binding_depths[key]
        )
        for key in fail_closed_ambiguous_binding_keys
    }
    (
        fail_closed_binding_expression_ids,
        fail_closed_binding_keys,
        _,
        _,
    ) = propagate_binding_dataflow(
        initial_binding_depths=fail_closed_initial_depths,
        skip_safe_control_flow_loads=True,
    )

    text_output_expression_ids: set[int] | None = None
    text_output_binding_keys: set[tuple[int, str]] | None = None

    def binding_expression_may_output_text(expression: ast.AST) -> bool:
        ensure_text_output_dataflow()
        assert text_output_expression_ids is not None
        return id(expression) in text_output_expression_ids

    def augassign_may_output_text(node: ast.AugAssign) -> bool:
        ensure_text_output_dataflow()
        assert text_output_expression_ids is not None
        assert text_output_binding_keys is not None
        return id(node.value) in text_output_expression_ids or any(
            key in text_output_binding_keys
            for key in augassign_binding_keys_by_id.get(id(node), ())
        )

    binding_value_cache: dict[tuple[int, str], Any] = {}
    binding_resolution_stack: set[tuple[int, str]] = set()
    binding_expression_cache: dict[int, Any] = {}
    retained_evaluated_value_sizes: dict[int, int] = {}
    retained_evaluated_bytes = 0

    def evaluated_text_payload_size(value: str | bytes) -> int:
        return bootstrap_v2_python_payload_size(value)

    def evaluated_text_risk_view(value: str | bytes) -> str:
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError:
                return value.decode("latin-1")
        bootstrap_v2_python_payload_size(value)
        return value

    def charge_retained_evaluated_value(
        node: ast.AST,
        result: str | bytes,
    ) -> None:
        nonlocal retained_evaluated_bytes
        payload_size = evaluated_text_payload_size(result)
        if payload_size > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES:
            raise ValueError("Python evaluated string exceeds the trusted byte limit")
        existing_size = retained_evaluated_value_sizes.get(id(node), 0)
        next_retained_bytes = retained_evaluated_bytes - existing_size + payload_size
        if next_retained_bytes > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_BYTES:
            raise ValueError(
                "Python AST evaluated strings exceed the trusted byte limit"
            )
        retained_evaluated_value_sizes[id(node)] = payload_size
        retained_evaluated_bytes = next_retained_bytes

    def binding_is_visible(
        load: ast.Name,
        statement: ast.Assign | ast.AnnAssign,
        binding_scope: int,
    ) -> bool:
        if scope_by_node_id[id(load)] != binding_scope:
            return True
        return (load.lineno, load.col_offset) >= (
            statement.end_lineno,
            statement.end_col_offset,
        )

    def binding_is_usable_for_load(
        load: ast.Name,
        key: tuple[int, str],
        statement: ast.Assign | ast.AnnAssign,
    ) -> bool:
        if key not in ambiguous_binding_keys:
            return binding_is_visible(load, statement, key[0])
        return (
            key in control_flow_ambiguous_binding_keys
            and scope_by_node_id[id(load)] == key[0]
            and statement_dominates_load(statement, load)
        )

    bound_string_method_marker = object()
    bound_int_to_bytes_method_marker = object()
    unresolved_int_method_marker = object()
    unresolved_int_method_kind = "<unresolved-int-method>"
    static_int_receiver_unset = object()
    static_getattr_type_objects = (
        bool,
        bytearray,
        bytes,
        complex,
        dict,
        float,
        frozenset,
        int,
        list,
        set,
        str,
        tuple,
    )
    static_getattr_receiver_types = frozenset(
        (type(None), *static_getattr_type_objects)
    )
    bound_string_method_kinds_by_expression_id: dict[int, frozenset[str]] = {}
    bound_string_method_dataflow_ready = False
    unknown_subscript_selector = object()
    selected_subscript_cache: dict[
        tuple[int, tuple[type[object], object]], tuple[ast.AST, ...]
    ] = {}
    ambiguous_selection_sources_cache: dict[
        tuple[tuple[int, str], int], tuple[ast.AST, ...]
    ] = {}
    selected_assignment_path_cache: dict[
        tuple[int, tuple[int, ...]], tuple[ast.AST, ...]
    ] = {}
    starred_capture_alternatives_cache: dict[
        tuple[int, tuple[int, ...], int, int, bool],
        tuple[StarredCaptureAlternative, ...],
    ] = {}
    starred_capture_alternatives_in_progress: set[
        tuple[int, tuple[int, ...], int, int, bool]
    ] = set()
    starred_capture_retained_sources = 0
    starred_capture_retained_alternatives = 0
    selection_binding_candidates_cache: dict[
        tuple[int, str],
        tuple[
            tuple[ast.Assign | ast.AnnAssign, ast.AST, tuple[int, ...], ast.Name],
            ...,
        ],
    ] = {}
    sequence_has_starred_cache: dict[int, bool] = {}
    static_sequence_length_cache: dict[int, int | None] = {}
    static_sequence_length_in_progress: set[int] = set()
    mapping_items_cache: dict[int, tuple[tuple[ast.AST | None, ast.AST], ...]] = {}
    selected_subscript_states = 0
    selected_subscript_state_limit = min(
        max(node_count * 8, 1),
        BOOTSTRAP_V2_MAX_PYTHON_METHOD_SELECTION_STATES,
    )
    selected_subscript_operations = 0
    selected_subscript_operation_limit = min(
        max(node_count * 32, 1),
        BOOTSTRAP_V2_MAX_PYTHON_METHOD_SELECTION_OPERATIONS,
    )

    def static_getattr_default_is_possible(
        receiver: Any,
        method_name: Any,
    ) -> bool:
        if type(method_name) is not str:
            return True
        if not (
            any(receiver is candidate for candidate in static_getattr_type_objects)
            or type(receiver) in static_getattr_receiver_types
        ):
            return True
        try:
            getattr(receiver, method_name)
        except AttributeError:
            return True
        except Exception:
            return True
        return False

    def consume_selected_subscript_operation() -> None:
        nonlocal selected_subscript_operations
        if selected_subscript_operations >= selected_subscript_operation_limit:
            raise ValueError(
                "Python bound string method selection exceeds the trusted "
                "operation limit"
            )
        selected_subscript_operations += 1

    def selection_binding_candidates(
        key: tuple[int, str],
    ) -> tuple[
        tuple[ast.Assign | ast.AnnAssign, ast.AST, tuple[int, ...], ast.Name],
        ...,
    ]:
        cached = selection_binding_candidates_cache.get(key)
        if cached is not None:
            return cached
        grouped: dict[
            tuple[int, int, tuple[int, ...]],
            tuple[ast.Assign | ast.AnnAssign, ast.AST, tuple[int, ...], ast.Name],
        ] = {}
        for candidate in binding_candidates.get(key, ()):
            statement, assigned_value, path, _target = candidate
            grouped.setdefault(
                (id(statement), id(assigned_value), path),
                candidate,
            )
        result = tuple(grouped.values())
        selection_binding_candidates_cache[key] = result
        return result

    def selected_assignment_expressions(
        expression: ast.AST,
        path: tuple[int, ...],
    ) -> tuple[ast.AST, ...]:
        if len(path) > BOOTSTRAP_V2_MAX_PYTHON_AST_DEPTH:
            raise ValueError(
                "Python bound string method selection exceeds the trusted path depth"
            )
        if not path:
            return (expression,)
        cache_key = (id(expression), path)
        cached = selected_assignment_path_cache.get(cache_key)
        if cached is not None:
            return cached
        selected: dict[int, ast.AST] = {}
        pending: list[tuple[ast.AST, tuple[int, ...]]] = []
        scheduled: set[tuple[int, tuple[int, ...]]] = set()

        def enqueue(current: ast.AST, remaining: tuple[int, ...]) -> None:
            nonlocal selected_subscript_states
            consume_selected_subscript_operation()
            if len(remaining) > BOOTSTRAP_V2_MAX_PYTHON_AST_DEPTH:
                raise ValueError(
                    "Python bound string method selection exceeds the trusted "
                    "path depth"
                )
            state = (id(current), remaining)
            if state in scheduled:
                return
            if selected_subscript_states >= selected_subscript_state_limit:
                raise ValueError(
                    "Python bound string method selection exceeds the trusted "
                    "candidate state limit"
                )
            selected_subscript_states += 1
            scheduled.add(state)
            pending.append((current, remaining))

        enqueue(expression, path)
        while pending:
            current, remaining = pending.pop()
            if not remaining:
                selected[id(current)] = current
                continue
            if isinstance(current, (ast.Tuple, ast.List)):
                index = remaining[0]
                if not -len(current.elts) <= index < len(current.elts):
                    continue
                child = current.elts[index]
                if isinstance(child, ast.Starred):
                    child = child.value
                enqueue(child, remaining[1:])
                continue
            if isinstance(current, ast.Subscript):
                for source in selected_subscript_expressions(current):
                    enqueue(source, remaining)
                continue
            if isinstance(current, ast.Name) and isinstance(current.ctx, ast.Load):
                key = name_load_binding_key(current)
                for (
                    statement,
                    assigned_value,
                    source_path,
                    target,
                ) in selection_binding_candidates(key):
                    consume_selected_subscript_operation()
                    if not event_may_reach_load(current, key, id(target)):
                        continue
                    enqueue(assigned_value, (*source_path, *remaining))
                for event_id, source in ordinary_ambiguous_binding_events.get(key, ()):
                    consume_selected_subscript_operation()
                    if event_may_reach_load(current, key, event_id):
                        enqueue(source, remaining)
                for candidate in starred_binding_candidates.get(key, ()):
                    consume_selected_subscript_operation()
                    if not event_may_reach_load(
                        current,
                        key,
                        id(candidate[5]),
                    ):
                        continue
                    selector = remaining[0]
                    for ordered, sources in starred_capture_alternatives(candidate):
                        consume_selected_subscript_operation()
                        selected_sources = sources
                        if ordered:
                            if not -len(sources) <= selector < len(sources):
                                continue
                            selected_sources = (sources[selector],)
                        for source in selected_sources:
                            enqueue(source, remaining[1:])
                for event_id, source in parameter_default_sources.get(key, ()):
                    consume_selected_subscript_operation()
                    if parameter_default_may_reach_load(current, key, event_id):
                        enqueue(source, remaining)
                continue
            if isinstance(current, ast.NamedExpr):
                enqueue(current.value, remaining)
                continue
            if isinstance(current, ast.IfExp):
                enqueue(current.body, remaining)
                enqueue(current.orelse, remaining)
                continue
            if isinstance(current, ast.BoolOp):
                for value in current.values:
                    enqueue(value, remaining)
        result = tuple(selected.values())
        selected_assignment_path_cache[cache_key] = result
        return result

    def selected_assignment_expression(
        expression: ast.AST,
        path: tuple[int, ...],
    ) -> ast.AST | None:
        selected = selected_assignment_expressions(expression, path)
        return selected[0] if len(selected) == 1 else None

    def resolved_starred_parent_sources(
        expression: ast.AST,
    ) -> tuple[ast.AST, ...]:
        nonlocal selected_subscript_states
        resolved: dict[int, ast.AST] = {}
        pending: list[ast.AST] = []
        scheduled: set[int] = set()

        def enqueue(source: ast.AST) -> None:
            nonlocal selected_subscript_states
            consume_selected_subscript_operation()
            source_id = id(source)
            if source_id in scheduled:
                return
            if selected_subscript_states >= selected_subscript_state_limit:
                raise ValueError(
                    "Python starred assignment selection exceeds the trusted "
                    "candidate state limit"
                )
            selected_subscript_states += 1
            scheduled.add(source_id)
            pending.append(source)

        enqueue(expression)
        while pending:
            current = pending.pop()
            if isinstance(current, ast.Name) and isinstance(current.ctx, ast.Load):
                key = name_load_binding_key(current)
                found_source = False
                for _, value, path, target in selection_binding_candidates(key):
                    consume_selected_subscript_operation()
                    if not event_may_reach_load(current, key, id(target)):
                        continue
                    found_source = True
                    for source in selected_assignment_expressions(value, path):
                        enqueue(source)
                for event_id, source in ordinary_ambiguous_binding_events.get(key, ()):
                    consume_selected_subscript_operation()
                    if event_may_reach_load(current, key, event_id):
                        found_source = True
                        enqueue(source)
                for event_id, source in parameter_default_sources.get(key, ()):
                    consume_selected_subscript_operation()
                    if parameter_default_may_reach_load(current, key, event_id):
                        found_source = True
                        enqueue(source)
                if not found_source or starred_binding_candidates.get(key):
                    resolved[id(current)] = current
                continue
            if isinstance(current, ast.Subscript):
                sources = selected_subscript_expressions(current)
                if sources:
                    for source in sources:
                        enqueue(source)
                else:
                    resolved[id(current)] = current
                continue
            if isinstance(current, ast.NamedExpr):
                enqueue(current.value)
                continue
            if isinstance(current, ast.IfExp):
                enqueue(current.body)
                enqueue(current.orelse)
                continue
            if isinstance(current, ast.BoolOp):
                for source in current.values:
                    enqueue(source)
                continue
            resolved[id(current)] = current
        return tuple(resolved.values())

    def starred_capture_alternatives(
        candidate: StarredBindingCandidate,
    ) -> tuple[StarredCaptureAlternative, ...]:
        nonlocal starred_capture_retained_alternatives
        nonlocal starred_capture_retained_sources
        (
            _,
            assigned_value,
            parent_path,
            prefix_count,
            suffix_count,
            _,
            iterates_assigned_value,
        ) = candidate
        capture_key = (
            id(assigned_value),
            parent_path,
            prefix_count,
            suffix_count,
            iterates_assigned_value,
        )
        cached = starred_capture_alternatives_cache.get(capture_key)
        if cached is not None:
            return cached
        if capture_key in starred_capture_alternatives_in_progress:
            raise ValueError("Python starred assignment selection is cyclic")
        starred_capture_alternatives_in_progress.add(capture_key)
        try:
            captured: dict[tuple[bool, tuple[int, ...]], StarredCaptureAlternative] = {}

            def alternatives_match(
                left: StarredCaptureAlternative,
                ordered: bool,
                sources: tuple[ast.AST, ...],
            ) -> bool:
                left_ordered, left_sources = left
                if left_ordered != ordered or len(left_sources) != len(sources):
                    return False
                for left_source, source in zip(left_sources, sources, strict=True):
                    consume_selected_subscript_operation()
                    if left_source is not source:
                        return False
                return True

            def alternative_key(
                ordered: bool,
                sources: tuple[ast.AST, ...],
            ) -> tuple[bool, tuple[int, ...]]:
                source_ids: list[int] = []
                for source in sources:
                    consume_selected_subscript_operation()
                    source_ids.append(id(source))
                return (ordered, tuple(source_ids))

            def duplicate_is_retained(
                alternatives: dict[
                    tuple[bool, tuple[int, ...]], StarredCaptureAlternative
                ],
                ordered: bool,
                sources: tuple[ast.AST, ...],
            ) -> bool:
                for alternative in alternatives.values():
                    consume_selected_subscript_operation()
                    if alternatives_match(alternative, ordered, sources):
                        return True
                return False

            def retain(
                ordered: bool,
                sources: tuple[ast.AST, ...],
            ) -> None:
                nonlocal starred_capture_retained_alternatives
                nonlocal starred_capture_retained_sources
                consume_selected_subscript_operation()
                if (
                    starred_capture_retained_alternatives
                    >= selected_subscript_state_limit
                    or len(sources)
                    > selected_subscript_state_limit - starred_capture_retained_sources
                ):
                    if duplicate_is_retained(captured, ordered, sources):
                        return
                    raise ValueError(
                        "Python starred assignment selection exceeds the trusted "
                        "retained source limit"
                    )
                retained_key = alternative_key(ordered, sources)
                if retained_key in captured:
                    return
                starred_capture_retained_alternatives += 1
                starred_capture_retained_sources += len(sources)
                captured[retained_key] = (ordered, sources)

            def collect_local_alternative(
                alternatives: dict[
                    tuple[bool, tuple[int, ...]], StarredCaptureAlternative
                ],
                source_count: list[int],
                ordered: bool,
                sources: tuple[ast.AST, ...],
            ) -> None:
                consume_selected_subscript_operation()
                if (
                    len(alternatives) >= selected_subscript_state_limit
                    or len(sources) > selected_subscript_state_limit - source_count[0]
                ):
                    if duplicate_is_retained(alternatives, ordered, sources):
                        return
                    raise ValueError(
                        "Python starred assignment selection exceeds the trusted "
                        "intermediate alternative limit"
                    )
                retained_key = alternative_key(ordered, sources)
                if retained_key in alternatives:
                    return
                alternatives[retained_key] = (ordered, sources)
                source_count[0] += len(sources)

            def sequence_alternatives(
                expression: ast.AST,
            ) -> tuple[StarredCaptureAlternative, ...]:
                consume_selected_subscript_operation()
                alternatives: dict[
                    tuple[bool, tuple[int, ...]], StarredCaptureAlternative
                ] = {}
                source_count = [0]
                if isinstance(expression, (ast.Tuple, ast.List)):
                    if not sequence_has_starred(expression):
                        if len(expression.elts) > selected_subscript_state_limit:
                            raise ValueError(
                                "Python starred assignment selection exceeds the "
                                "trusted intermediate source limit"
                            )
                        collect_local_alternative(
                            alternatives,
                            source_count,
                            True,
                            tuple(expression.elts),
                        )
                        return tuple(alternatives.values())
                    partials: dict[
                        tuple[bool, tuple[int, ...]], StarredCaptureAlternative
                    ] = {}
                    partial_source_count = [0]
                    collect_local_alternative(
                        partials,
                        partial_source_count,
                        True,
                        (),
                    )
                    for child in expression.elts:
                        consume_selected_subscript_operation()
                        if isinstance(child, ast.Starred):
                            child_alternatives = sequence_alternatives(child.value)
                        else:
                            child_alternatives = ((True, (child,)),)
                        next_partials: dict[
                            tuple[bool, tuple[int, ...]], StarredCaptureAlternative
                        ] = {}
                        next_source_count = [0]
                        for partial_ordered, partial_sources in partials.values():
                            for child_ordered, child_sources in child_alternatives:
                                consume_selected_subscript_operation()
                                if len(partial_sources) > (
                                    selected_subscript_state_limit - len(child_sources)
                                ):
                                    raise ValueError(
                                        "Python starred assignment selection exceeds "
                                        "the trusted intermediate source limit"
                                    )
                                collect_local_alternative(
                                    next_partials,
                                    next_source_count,
                                    partial_ordered and child_ordered,
                                    (*partial_sources, *child_sources),
                                )
                        partials = next_partials
                        if not partials:
                            break
                    for ordered, sources in partials.values():
                        collect_local_alternative(
                            alternatives,
                            source_count,
                            ordered,
                            sources,
                        )
                    return tuple(alternatives.values())
                if isinstance(expression, ast.BinOp) and isinstance(
                    expression.op, ast.Add
                ):
                    left_alternatives = sequence_alternatives(expression.left)
                    right_alternatives = sequence_alternatives(expression.right)
                    if left_alternatives and right_alternatives:
                        for left_ordered, left_sources in left_alternatives:
                            for right_ordered, right_sources in right_alternatives:
                                consume_selected_subscript_operation()
                                if len(left_sources) > (
                                    selected_subscript_state_limit - len(right_sources)
                                ):
                                    raise ValueError(
                                        "Python starred assignment selection exceeds "
                                        "the trusted intermediate source limit"
                                    )
                                collect_local_alternative(
                                    alternatives,
                                    source_count,
                                    left_ordered and right_ordered,
                                    (*left_sources, *right_sources),
                                )
                        return tuple(alternatives.values())
                if isinstance(expression, ast.BinOp) and isinstance(
                    expression.op, ast.Mult
                ):
                    right_multiplier = normalized_literal_selector(expression.right)
                    left_multiplier = normalized_literal_selector(expression.left)
                    if type(right_multiplier) is int:
                        sequence = expression.left
                        multiplier = right_multiplier
                    elif type(left_multiplier) is int:
                        sequence = expression.right
                        multiplier = left_multiplier
                    else:
                        sequence = None
                        multiplier = 0
                    if sequence is not None:
                        if multiplier <= 0:
                            collect_local_alternative(
                                alternatives,
                                source_count,
                                True,
                                (),
                            )
                            return tuple(alternatives.values())
                        for ordered, sources in sequence_alternatives(sequence):
                            consume_selected_subscript_operation()
                            if ordered and sources:
                                if multiplier > (
                                    selected_subscript_state_limit // len(sources)
                                ):
                                    raise ValueError(
                                        "Python starred assignment selection exceeds "
                                        "the trusted intermediate source limit"
                                    )
                                sources = sources * multiplier
                            collect_local_alternative(
                                alternatives,
                                source_count,
                                ordered,
                                sources,
                            )
                        if alternatives:
                            return tuple(alternatives.values())
                if isinstance(expression, ast.Name) and isinstance(
                    expression.ctx, ast.Load
                ):
                    key = name_load_binding_key(expression)
                    resolved_sources = resolved_starred_parent_sources(expression)
                    for resolved_source in resolved_sources:
                        consume_selected_subscript_operation()
                        if resolved_source is not expression:
                            for ordered, sources in sequence_alternatives(
                                resolved_source
                            ):
                                collect_local_alternative(
                                    alternatives,
                                    source_count,
                                    ordered,
                                    sources,
                                )
                            continue
                        for inner_candidate in starred_binding_candidates.get(key, ()):
                            consume_selected_subscript_operation()
                            if not event_may_reach_load(
                                expression,
                                key,
                                id(inner_candidate[5]),
                            ):
                                continue
                            for ordered, sources in starred_capture_alternatives(
                                inner_candidate
                            ):
                                collect_local_alternative(
                                    alternatives,
                                    source_count,
                                    ordered,
                                    sources,
                                )
                    if alternatives:
                        return tuple(alternatives.values())
                sources = selected_container_expressions(
                    expression,
                    unknown_subscript_selector,
                )
                if sources:
                    collect_local_alternative(
                        alternatives,
                        source_count,
                        False,
                        sources,
                    )
                return tuple(alternatives.values())

            def parent_alternatives(
                expression: ast.AST,
                path: tuple[int, ...],
            ) -> tuple[StarredCaptureAlternative, ...]:
                consume_selected_subscript_operation()
                if not path:
                    return sequence_alternatives(expression)
                alternatives: dict[
                    tuple[bool, tuple[int, ...]], StarredCaptureAlternative
                ] = {}
                source_count = [0]

                def collect_from_source(source: ast.AST) -> None:
                    consume_selected_subscript_operation()
                    for ordered, sources in parent_alternatives(source, remaining):
                        collect_local_alternative(
                            alternatives,
                            source_count,
                            ordered,
                            sources,
                        )

                index, remaining = path[0], path[1:]
                if isinstance(expression, (ast.Tuple, ast.List)) and not (
                    sequence_has_starred(expression)
                ):
                    if not -len(expression.elts) <= index < len(expression.elts):
                        return ()
                    return parent_alternatives(expression.elts[index], remaining)
                if isinstance(expression, ast.Name) and isinstance(
                    expression.ctx, ast.Load
                ):
                    key = name_load_binding_key(expression)
                    found_resolved_source = False
                    for resolved_source in resolved_starred_parent_sources(expression):
                        consume_selected_subscript_operation()
                        if resolved_source is not expression:
                            found_resolved_source = True
                            for ordered, sources in parent_alternatives(
                                resolved_source,
                                path,
                            ):
                                collect_local_alternative(
                                    alternatives,
                                    source_count,
                                    ordered,
                                    sources,
                                )
                            continue
                        for inner_candidate in starred_binding_candidates.get(key, ()):
                            consume_selected_subscript_operation()
                            if not event_may_reach_load(
                                expression,
                                key,
                                id(inner_candidate[5]),
                            ):
                                continue
                            found_resolved_source = True
                            for ordered, sources in starred_capture_alternatives(
                                inner_candidate
                            ):
                                consume_selected_subscript_operation()
                                if ordered:
                                    if -len(sources) <= index < len(sources):
                                        collect_from_source(sources[index])
                                else:
                                    for source in sources:
                                        collect_from_source(source)
                    if found_resolved_source:
                        return tuple(alternatives.values())
                for source in selected_assignment_expressions(expression, path):
                    consume_selected_subscript_operation()
                    for ordered, sources in sequence_alternatives(source):
                        collect_local_alternative(
                            alternatives,
                            source_count,
                            ordered,
                            sources,
                        )
                return tuple(alternatives.values())

            root_sources = resolved_starred_parent_sources(assigned_value)
            if iterates_assigned_value:
                iterated_sources: dict[int, ast.AST] = {}
                for root_source in root_sources:
                    for source in selected_container_expressions(
                        root_source,
                        unknown_subscript_selector,
                    ):
                        iterated_sources[id(source)] = source
                root_sources = tuple(iterated_sources.values())
            for root_source in root_sources:
                consume_selected_subscript_operation()
                for ordered, sources in parent_alternatives(
                    root_source,
                    parent_path,
                ):
                    consume_selected_subscript_operation()
                    if ordered:
                        stop = (
                            len(sources) - suffix_count
                            if suffix_count
                            else len(sources)
                        )
                        if stop < prefix_count:
                            continue
                        sources = sources[prefix_count:stop]
                    retain(ordered, sources)
            result = tuple(captured.values())
            starred_capture_alternatives_cache[capture_key] = result
            return result
        finally:
            starred_capture_alternatives_in_progress.remove(capture_key)

    def ambiguous_selection_sources(
        key: tuple[int, str],
        load: ast.Name | None = None,
    ) -> tuple[ast.AST, ...]:
        cache_key = (key, id(load) if load is not None else 0)
        cached = ambiguous_selection_sources_cache.get(cache_key)
        if cached is not None:
            return cached
        sources: dict[int, ast.AST] = {}
        for _, assigned_value, path, target in selection_binding_candidates(key):
            consume_selected_subscript_operation()
            if load is not None and not event_may_reach_load(load, key, id(target)):
                continue
            for source in selected_assignment_expressions(assigned_value, path):
                sources[id(source)] = source
        ordinary_events = ordinary_ambiguous_binding_events.get(key, ())
        for event_id, source in ordinary_events:
            consume_selected_subscript_operation()
            if load is not None and not event_may_reach_load(load, key, event_id):
                continue
            sources[id(source)] = source
        if not ordinary_events:
            for source in ordinary_ambiguous_binding_values.get(key, ()):
                consume_selected_subscript_operation()
                sources[id(source)] = source
        for event_id, source in parameter_default_sources.get(key, ()):
            consume_selected_subscript_operation()
            if load is None or parameter_default_may_reach_load(load, key, event_id):
                sources[id(source)] = source
        result = tuple(sources.values())
        ambiguous_selection_sources_cache[cache_key] = result
        return result

    def sequence_has_starred(sequence: ast.Tuple | ast.List) -> bool:
        sequence_id = id(sequence)
        if sequence_id in sequence_has_starred_cache:
            return sequence_has_starred_cache[sequence_id]
        result = False
        for value in sequence.elts:
            consume_selected_subscript_operation()
            if isinstance(value, ast.Starred):
                result = True
        sequence_has_starred_cache[sequence_id] = result
        return result

    def mapping_items(
        mapping: ast.Dict,
    ) -> tuple[tuple[ast.AST | None, ast.AST], ...]:
        mapping_id = id(mapping)
        cached = mapping_items_cache.get(mapping_id)
        if cached is not None:
            return cached
        items: list[tuple[ast.AST | None, ast.AST]] = []
        for key, value in zip(mapping.keys, mapping.values, strict=True):
            consume_selected_subscript_operation()
            items.append((key, value))
        result = tuple(items)
        mapping_items_cache[mapping_id] = result
        return result

    def static_sequence_length(expression: ast.AST) -> int | None:
        expression_id = id(expression)
        if expression_id in static_sequence_length_cache:
            return static_sequence_length_cache[expression_id]
        if expression_id in static_sequence_length_in_progress:
            return None
        consume_selected_subscript_operation()
        static_sequence_length_in_progress.add(expression_id)
        try:
            result: int | None = None
            if isinstance(expression, (ast.Tuple, ast.List)):
                if not sequence_has_starred(expression):
                    result = len(expression.elts)
            elif isinstance(expression, ast.Name) and isinstance(
                expression.ctx, ast.Load
            ):
                key = name_load_binding_key(expression)
                lengths: set[int] = set()
                found_source = False
                exact = key not in explicitly_ambiguous_binding_keys

                def observe_source(source: ast.AST) -> None:
                    nonlocal exact, found_source
                    consume_selected_subscript_operation()
                    found_source = True
                    source_length = static_sequence_length(source)
                    if source_length is None:
                        exact = False
                    else:
                        lengths.add(source_length)

                for _, assigned_value, path, target in selection_binding_candidates(
                    key
                ):
                    consume_selected_subscript_operation()
                    if event_may_reach_load(expression, key, id(target)):
                        for source in selected_assignment_expressions(
                            assigned_value,
                            path,
                        ):
                            observe_source(source)
                for event_id, source in ordinary_ambiguous_binding_events.get(key, ()):
                    consume_selected_subscript_operation()
                    if event_may_reach_load(expression, key, event_id):
                        if event_id in non_guaranteed_binding_event_ids:
                            found_source = True
                            exact = False
                            continue
                        observe_source(source)
                for event_id, source in parameter_default_sources.get(key, ()):
                    consume_selected_subscript_operation()
                    if parameter_default_may_reach_load(expression, key, event_id):
                        observe_source(source)
                for candidate in starred_binding_candidates.get(key, ()):
                    consume_selected_subscript_operation()
                    if event_may_reach_load(expression, key, id(candidate[5])):
                        found_source = True
                        exact = False
                if exact and found_source and len(lengths) == 1:
                    result = next(iter(lengths))
            elif isinstance(expression, ast.BinOp) and isinstance(
                expression.op, ast.Add
            ):
                left_length = static_sequence_length(expression.left)
                right_length = static_sequence_length(expression.right)
                if (
                    left_length is not None
                    and right_length is not None
                    and left_length <= selected_subscript_state_limit - right_length
                ):
                    result = left_length + right_length
            elif isinstance(expression, ast.BinOp) and isinstance(
                expression.op, ast.Mult
            ):
                right_multiplier = normalized_literal_selector(expression.right)
                left_multiplier = normalized_literal_selector(expression.left)
                if type(right_multiplier) is int:
                    sequence = expression.left
                    multiplier = max(right_multiplier, 0)
                elif type(left_multiplier) is int:
                    sequence = expression.right
                    multiplier = max(left_multiplier, 0)
                else:
                    sequence = None
                    multiplier = 0
                if sequence is not None:
                    sequence_length = static_sequence_length(sequence)
                    if sequence_length == 0 or multiplier == 0:
                        result = 0
                    elif (
                        sequence_length is not None
                        and multiplier
                        <= selected_subscript_state_limit // sequence_length
                    ):
                        result = sequence_length * multiplier
            static_sequence_length_cache[expression_id] = result
            return result
        finally:
            static_sequence_length_in_progress.remove(expression_id)

    def selected_container_expressions(
        container: ast.AST,
        selector: object,
    ) -> tuple[ast.AST, ...]:
        selector_key: tuple[type[object], object] = (type(selector), selector)
        cache_key = (id(container), selector_key)
        cached = selected_subscript_cache.get(cache_key)
        if cached is not None:
            return cached
        selected: dict[int, ast.AST] = {}

        # Intern selector paths so aliases share one bounded tuple.
        overflow_selector_path_id = 1
        selector_paths: list[tuple[object | None, int, int]] = [
            (None, 0, 0),
            (
                unknown_subscript_selector,
                overflow_selector_path_id,
                BOOTSTRAP_V2_MAX_PYTHON_AST_DEPTH + 1,
            ),
        ]
        selector_path_ids: dict[tuple[tuple[type[object], object], int], int] = {}

        def prepend_selector(value: object, tail_id: int) -> int:
            if tail_id == overflow_selector_path_id:
                return overflow_selector_path_id
            depth = selector_paths[tail_id][2] + 1
            if depth > BOOTSTRAP_V2_MAX_PYTHON_AST_DEPTH:
                return overflow_selector_path_id
            key = ((type(value), value), tail_id)
            existing = selector_path_ids.get(key)
            if existing is not None:
                return existing
            path_id = len(selector_paths)
            selector_paths.append((value, tail_id, depth))
            selector_path_ids[key] = path_id
            return path_id

        pending: list[tuple[ast.AST, int]] = []
        scheduled: set[tuple[int, int]] = set()

        def enqueue(current: ast.AST, selector_path_id: int) -> None:
            nonlocal selected_subscript_states
            consume_selected_subscript_operation()
            state = (id(current), selector_path_id)
            if state in scheduled:
                return
            if selected_subscript_states >= selected_subscript_state_limit:
                raise ValueError(
                    "Python bound string method selection exceeds the trusted "
                    "candidate state limit"
                )
            selected_subscript_states += 1
            scheduled.add(state)
            pending.append((current, selector_path_id))

        def record_selected(current: ast.AST) -> None:
            consume_selected_subscript_operation()
            selected[id(current)] = current

        enqueue(container, prepend_selector(selector, 0))
        while pending:
            current, selector_path_id = pending.pop()
            if isinstance(current, ast.Subscript):
                nested_selector = normalized_literal_selector(current.slice)
                enqueue(
                    current.value,
                    prepend_selector(
                        nested_selector
                        if nested_selector is not None
                        else unknown_subscript_selector,
                        selector_path_id,
                    ),
                )
                continue
            if isinstance(current, ast.Starred):
                enqueue(current.value, selector_path_id)
                continue
            if isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
                if selector_path_id == 0:
                    record_selected(current)
                    continue
                current_selector, remaining_path_id, _ = selector_paths[
                    selector_path_id
                ]
                left_length = static_sequence_length(current.left)
                right_length = static_sequence_length(current.right)
                if (
                    type(current_selector) is int
                    and left_length is not None
                    and right_length is not None
                ):
                    total_length = left_length + right_length
                    normalized_index = current_selector
                    if normalized_index < 0:
                        normalized_index += total_length
                    if not 0 <= normalized_index < total_length:
                        continue
                    if normalized_index < left_length:
                        source = current.left
                        source_index = normalized_index
                    else:
                        source = current.right
                        source_index = normalized_index - left_length
                    enqueue(
                        source,
                        prepend_selector(source_index, remaining_path_id),
                    )
                    continue
                for source in (current.left, current.right):
                    enqueue(
                        source,
                        prepend_selector(
                            unknown_subscript_selector,
                            remaining_path_id,
                        ),
                    )
                continue
            if isinstance(current, ast.BinOp) and isinstance(current.op, ast.Mult):
                if selector_path_id == 0:
                    record_selected(current)
                    continue
                right_multiplier = normalized_literal_selector(current.right)
                left_multiplier = normalized_literal_selector(current.left)
                if type(right_multiplier) is int:
                    sources = (current.left,)
                    multiplier = right_multiplier
                elif type(left_multiplier) is int:
                    sources = (current.right,)
                    multiplier = left_multiplier
                else:
                    sources = (current.left, current.right)
                    multiplier = None
                if type(multiplier) is int and multiplier <= 0:
                    continue
                current_selector, remaining_path_id, _ = selector_paths[
                    selector_path_id
                ]
                if type(multiplier) is int and len(sources) == 1:
                    sequence_length = static_sequence_length(sources[0])
                    total_length = static_sequence_length(current)
                    if sequence_length is not None and total_length is not None:
                        normalized_index = current_selector
                        if type(normalized_index) is int:
                            if normalized_index < 0:
                                normalized_index += total_length
                            if not 0 <= normalized_index < total_length:
                                continue
                            if sequence_length == 0:
                                continue
                            enqueue(
                                sources[0],
                                prepend_selector(
                                    normalized_index % sequence_length,
                                    remaining_path_id,
                                ),
                            )
                            continue
                for source in sources:
                    enqueue(
                        source,
                        prepend_selector(
                            unknown_subscript_selector,
                            remaining_path_id,
                        ),
                    )
                continue
            if isinstance(current, ast.Name) and isinstance(current.ctx, ast.Load):
                key = name_load_binding_key(current)
                if selector_path_id:
                    current_selector, remaining_path_id, _ = selector_paths[
                        selector_path_id
                    ]
                    for candidate in starred_binding_candidates.get(key, ()):
                        consume_selected_subscript_operation()
                        if not event_may_reach_load(
                            current,
                            key,
                            id(candidate[5]),
                        ):
                            continue
                        for ordered, sources in starred_capture_alternatives(candidate):
                            consume_selected_subscript_operation()
                            selected_sources = sources
                            if ordered and type(current_selector) is int:
                                if not -len(sources) <= current_selector < len(sources):
                                    continue
                                selected_sources = (sources[current_selector],)
                            for source in selected_sources:
                                if remaining_path_id:
                                    enqueue(source, remaining_path_id)
                                else:
                                    record_selected(source)
                if key in ambiguous_binding_keys:
                    for source in ambiguous_selection_sources(key, current):
                        enqueue(source, selector_path_id)
                else:
                    for statement, assigned_value, path, _ in binding_candidates.get(
                        key, ()
                    ):
                        consume_selected_subscript_operation()
                        if not binding_is_usable_for_load(current, key, statement):
                            continue
                        source = selected_assignment_expression(
                            assigned_value,
                            path,
                        )
                        if source is not None:
                            enqueue(source, selector_path_id)
                continue
            if isinstance(current, ast.NamedExpr):
                enqueue(current.value, selector_path_id)
                continue
            if isinstance(current, ast.IfExp):
                enqueue(current.body, selector_path_id)
                enqueue(current.orelse, selector_path_id)
                continue
            if isinstance(current, ast.BoolOp):
                for value in current.values:
                    enqueue(value, selector_path_id)
                continue
            if isinstance(current, ast.Call):
                for argument in current.args:
                    enqueue(
                        argument.value
                        if isinstance(argument, ast.Starred)
                        else argument,
                        selector_path_id,
                    )
                for keyword in current.keywords:
                    enqueue(keyword.value, selector_path_id)
                continue
            if selector_path_id == 0:
                record_selected(current)
                continue
            current_selector, remaining_path_id, _ = selector_paths[selector_path_id]
            assert current_selector is not None
            selected_values: list[ast.AST] = []
            if isinstance(current, (ast.Tuple, ast.List)):
                if current_selector is unknown_subscript_selector or (
                    sequence_has_starred(current)
                ):
                    for value in current.elts:
                        if isinstance(value, ast.Starred):
                            enqueue(
                                value.value,
                                prepend_selector(
                                    unknown_subscript_selector,
                                    remaining_path_id,
                                ),
                            )
                            if selector_path_id == overflow_selector_path_id:
                                enqueue(
                                    value.value,
                                    prepend_selector(unknown_subscript_selector, 0),
                                )
                        else:
                            selected_values.append(value)
                elif type(current_selector) is int and -len(
                    current.elts
                ) <= current_selector < len(current.elts):
                    selected_values.append(current.elts[current_selector])
            elif isinstance(current, ast.Dict):
                items = mapping_items(current)
                if current_selector is unknown_subscript_selector:
                    for key, value in items:
                        if key is None:
                            enqueue(
                                value,
                                prepend_selector(
                                    unknown_subscript_selector,
                                    remaining_path_id,
                                ),
                            )
                            if selector_path_id == overflow_selector_path_id:
                                enqueue(
                                    value,
                                    prepend_selector(unknown_subscript_selector, 0),
                                )
                        else:
                            selected_values.append(value)
                    items = ()
                for key, value in reversed(items):
                    consume_selected_subscript_operation()
                    if key is None:
                        enqueue(
                            value,
                            prepend_selector(current_selector, remaining_path_id),
                        )
                        continue
                    key_value = normalized_literal_selector(key)
                    if key_value is None:
                        selected_values.append(value)
                        continue
                    if key_value == current_selector:
                        selected_values.append(value)
                        break
            if not selected_values:
                continue
            for selected_value in selected_values:
                if remaining_path_id:
                    enqueue(selected_value, remaining_path_id)
                    if selector_path_id == overflow_selector_path_id:
                        enqueue(selected_value, 0)
                else:
                    record_selected(selected_value)
        result = tuple(selected.values())
        selected_subscript_cache[cache_key] = result
        return result

    def selected_subscript_expressions(
        expression: ast.Subscript,
    ) -> tuple[ast.AST, ...]:
        selector = normalized_literal_selector(expression.slice)
        if selector is None:
            selector = unknown_subscript_selector
        return selected_container_expressions(expression.value, selector)

    def ensure_bound_string_method_dataflow() -> None:
        nonlocal bound_string_method_dataflow_ready
        if bound_string_method_dataflow_ready:
            return
        expression_dependents: dict[int, set[int]] = {}
        binding_dependents: dict[int, set[tuple[int, str]]] = {}
        load_dependents: dict[tuple[int, str], set[int]] = {}
        pending_expressions: list[tuple[int, str]] = []
        pending_bindings: list[tuple[tuple[int, str], str]] = []
        expression_facts: set[tuple[int, str]] = set()
        binding_facts: set[tuple[tuple[int, str], str]] = set()
        operation_count = 0
        operation_limit = max(node_count * 24, 1)

        def consume_operation() -> None:
            nonlocal operation_count
            operation_count += 1
            if operation_count > operation_limit:
                raise ValueError(
                    "Python bound string method analysis exceeds the trusted operation limit"
                )

        def add_expression_edge(source: ast.AST, target: ast.AST) -> None:
            targets = expression_dependents.setdefault(id(source), set())
            if id(target) not in targets:
                consume_operation()
                targets.add(id(target))

        def add_binding_edge(source: ast.AST, target: tuple[int, str]) -> None:
            targets = binding_dependents.setdefault(id(source), set())
            if target not in targets:
                consume_operation()
                targets.add(target)

        def add_load_edge(source: tuple[int, str], target: ast.Name) -> None:
            targets = load_dependents.setdefault(source, set())
            if id(target) not in targets:
                consume_operation()
                targets.add(id(target))

        def seed_expression(expression: ast.AST, method_name: str) -> None:
            fact = (id(expression), method_name)
            if fact not in expression_facts:
                expression_facts.add(fact)
                pending_expressions.append(fact)

        for node in nodes:
            consume_operation()
            if isinstance(node, ast.Attribute) and (
                node.attr in bound_string_method_names or node.attr == "to_bytes"
            ):
                seed_expression(node, node.attr)
            elif (
                isinstance(node, ast.Call)
                and len(node.args) in {2, 3}
                and not node.keywords
                and has_static_builtin_origin(node.func, frozenset({"getattr"}))
            ):
                receiver = evaluate_binding_expression(node.args[0])
                method_name = evaluate_binding_expression(node.args[1])
                if len(node.args) == 3 and static_getattr_default_is_possible(
                    receiver,
                    method_name,
                ):
                    add_expression_edge(node.args[2], node)
                if method_name == "to_bytes":
                    seed_expression(node, "to_bytes")
                elif method_name is not_pure:
                    seed_expression(node, unresolved_int_method_kind)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                key = name_load_binding_key(node)
                for event_id, source in parameter_default_sources.get(key, ()):
                    if parameter_default_may_reach_load(node, key, event_id):
                        add_expression_edge(source, node)
                candidates = binding_candidates.get(key)
                if (
                    candidates is not None or key in ordinary_ambiguous_binding_values
                ) and (
                    key in ambiguous_binding_keys
                    or (
                        candidates is not None
                        and any(
                            binding_is_usable_for_load(node, key, candidate[0])
                            for candidate in candidates
                        )
                    )
                ):
                    add_load_edge(key, node)
            elif isinstance(node, ast.Subscript):
                for source in selected_subscript_expressions(node):
                    add_expression_edge(source, node)
            elif isinstance(node, ast.NamedExpr):
                add_expression_edge(node.value, node)
            elif isinstance(node, ast.IfExp):
                add_expression_edge(node.body, node)
                add_expression_edge(node.orelse, node)
            elif isinstance(node, ast.BoolOp):
                for value in node.values:
                    add_expression_edge(value, node)

        for key, candidates in binding_candidates.items():
            for _, assigned_value, path, _ in candidates:
                source = selected_assignment_expression(assigned_value, path)
                if source is not None:
                    add_binding_edge(source, key)
        for key, assigned_values in ordinary_ambiguous_binding_values.items():
            for assigned_value in assigned_values:
                add_binding_edge(assigned_value, key)

        while pending_expressions or pending_bindings:
            while pending_expressions:
                consume_operation()
                expression_id, method_name = pending_expressions.pop()
                for dependent_id in expression_dependents.get(expression_id, ()):
                    consume_operation()
                    fact = (dependent_id, method_name)
                    if fact not in expression_facts:
                        expression_facts.add(fact)
                        pending_expressions.append(fact)
                for key in binding_dependents.get(expression_id, ()):
                    consume_operation()
                    fact = (key, method_name)
                    if fact not in binding_facts:
                        binding_facts.add(fact)
                        pending_bindings.append(fact)
            while pending_bindings:
                consume_operation()
                key, method_name = pending_bindings.pop()
                for dependent_id in load_dependents.get(key, ()):
                    consume_operation()
                    fact = (dependent_id, method_name)
                    if fact not in expression_facts:
                        expression_facts.add(fact)
                        pending_expressions.append(fact)

        for expression_id, method_name in expression_facts:
            current = bound_string_method_kinds_by_expression_id.get(
                expression_id, frozenset()
            )
            bound_string_method_kinds_by_expression_id[expression_id] = current | {
                method_name
            }
        bound_string_method_dataflow_ready = True

    def bound_string_method_kinds(expression: ast.AST) -> frozenset[str]:
        ensure_bound_string_method_dataflow()
        return bound_string_method_kinds_by_expression_id.get(
            id(expression), frozenset()
        )

    function_parameter_binding_keys = frozenset(
        (scope_by_node_id[id(node)], node.arg)
        for node in nodes
        if isinstance(node, ast.arg)
    )
    opaque_join_iterable_call_names = frozenset(
        {
            "filter",
            "iter",
            "map",
            "reversed",
        }
    )
    opaque_join_iterable_cache: dict[int, bool] = {}
    opaque_join_callable_cache: dict[int, bool] = {}
    opaque_join_parameter_cache: dict[int, bool] = {}
    opaque_join_analysis_stack: set[tuple[str, int]] = set()
    opaque_join_analysis_operations = 0
    opaque_join_analysis_limit = max(node_count * 8, 1)

    def consume_opaque_join_analysis_operation() -> None:
        nonlocal opaque_join_analysis_operations
        opaque_join_analysis_operations += 1
        if opaque_join_analysis_operations > opaque_join_analysis_limit:
            raise ValueError(
                "Python join producer analysis exceeds the trusted operation limit"
            )

    def opaque_join_binding_sources(expression: ast.Name) -> tuple[ast.AST, ...]:
        key = name_load_binding_key(expression)
        sources: list[ast.AST] = []
        for statement, assigned_value, path, _ in binding_candidates.get(key, ()):
            consume_opaque_join_analysis_operation()
            if not binding_is_usable_for_load(expression, key, statement):
                continue
            selected = selected_assignment_expression(assigned_value, path)
            sources.append(selected or assigned_value)
        sources.extend(ordinary_ambiguous_binding_values.get(key, ()))
        return tuple(sources)

    def join_iterable_depends_on_parameter(expression: ast.AST) -> bool:
        expression_id = id(expression)
        cached = opaque_join_parameter_cache.get(expression_id)
        if cached is not None:
            return cached
        stack_key = ("parameter", expression_id)
        if stack_key in opaque_join_analysis_stack:
            return False
        consume_opaque_join_analysis_operation()
        opaque_join_analysis_stack.add(stack_key)
        try:
            if isinstance(expression, ast.Name):
                result = name_load_binding_key(
                    expression
                ) in function_parameter_binding_keys or any(
                    join_iterable_depends_on_parameter(source)
                    for source in opaque_join_binding_sources(expression)
                )
            elif isinstance(expression, ast.Starred):
                result = join_iterable_depends_on_parameter(expression.value)
            elif isinstance(expression, ast.NamedExpr):
                result = join_iterable_depends_on_parameter(expression.value)
            elif isinstance(expression, ast.IfExp):
                result = join_iterable_depends_on_parameter(
                    expression.body
                ) or join_iterable_depends_on_parameter(expression.orelse)
            elif isinstance(expression, ast.BoolOp):
                result = any(
                    join_iterable_depends_on_parameter(child)
                    for child in expression.values
                )
            elif isinstance(expression, ast.Subscript):
                sources = selected_subscript_expressions(expression)
                result = any(
                    join_iterable_depends_on_parameter(source)
                    for source in (sources or (expression.value,))
                )
            else:
                result = False
        finally:
            opaque_join_analysis_stack.remove(stack_key)
        opaque_join_parameter_cache[expression_id] = result
        return result

    def selects_opaque_join_callable(expression: ast.AST) -> bool:
        expression_id = id(expression)
        cached = opaque_join_callable_cache.get(expression_id)
        if cached is not None:
            return cached
        stack_key = ("callable", expression_id)
        if stack_key in opaque_join_analysis_stack:
            return False
        consume_opaque_join_analysis_operation()
        opaque_join_analysis_stack.add(stack_key)
        try:
            if isinstance(expression, ast.Name):
                result = expression.id in opaque_join_iterable_call_names or any(
                    selects_opaque_join_callable(source)
                    for source in opaque_join_binding_sources(expression)
                )
            elif isinstance(expression, ast.Attribute):
                result = expression.attr in opaque_join_iterable_call_names
            elif isinstance(expression, ast.Subscript):
                result = any(
                    selects_opaque_join_callable(source)
                    for source in selected_subscript_expressions(expression)
                )
            elif isinstance(expression, ast.NamedExpr):
                result = selects_opaque_join_callable(expression.value)
            elif isinstance(expression, ast.IfExp):
                result = selects_opaque_join_callable(
                    expression.body
                ) or selects_opaque_join_callable(expression.orelse)
            elif isinstance(expression, ast.BoolOp):
                result = any(
                    selects_opaque_join_callable(child) for child in expression.values
                )
            else:
                result = False
        finally:
            opaque_join_analysis_stack.remove(stack_key)
        opaque_join_callable_cache[expression_id] = result
        return result

    def opaque_join_iterable_may_emit_text(expression: ast.AST) -> bool:
        expression_id = id(expression)
        cached = opaque_join_iterable_cache.get(expression_id)
        if cached is not None:
            return cached
        stack_key = ("iterable", expression_id)
        if stack_key in opaque_join_analysis_stack:
            return False
        consume_opaque_join_analysis_operation()
        opaque_join_analysis_stack.add(stack_key)
        try:
            if isinstance(expression, ast.Call):
                result = (
                    selects_opaque_join_callable(expression.func)
                    or any(
                        opaque_join_iterable_may_emit_text(
                            argument.value
                            if isinstance(argument, ast.Starred)
                            else argument
                        )
                        for argument in expression.args
                    )
                    or any(
                        opaque_join_iterable_may_emit_text(keyword.value)
                        for keyword in expression.keywords
                    )
                )
            elif isinstance(expression, ast.Name):
                result = any(
                    opaque_join_iterable_may_emit_text(source)
                    for source in opaque_join_binding_sources(expression)
                )
            elif isinstance(expression, ast.NamedExpr):
                result = opaque_join_iterable_may_emit_text(expression.value)
            elif isinstance(expression, ast.IfExp):
                result = opaque_join_iterable_may_emit_text(
                    expression.body
                ) or opaque_join_iterable_may_emit_text(expression.orelse)
            elif isinstance(expression, ast.BoolOp):
                result = any(
                    opaque_join_iterable_may_emit_text(child)
                    for child in expression.values
                )
            elif isinstance(expression, ast.Subscript):
                result = any(
                    opaque_join_iterable_may_emit_text(source)
                    for source in selected_subscript_expressions(expression)
                )
            else:
                result = False
        finally:
            opaque_join_analysis_stack.remove(stack_key)
        opaque_join_iterable_cache[expression_id] = result
        return result

    def ensure_text_output_dataflow() -> None:
        nonlocal text_output_binding_keys, text_output_expression_ids
        if text_output_expression_ids is not None:
            return

        expression_dependents: dict[int, set[int]] = {}
        binding_dependents: dict[int, set[tuple[int, str]]] = {}
        load_dependents: dict[tuple[int, str], set[int]] = {}
        seeded_expression_ids: set[int] = set()
        operation_count = 0

        def consume_operation() -> None:
            nonlocal operation_count
            operation_count += 1
            if operation_count > BOOTSTRAP_V2_MAX_PYTHON_TEXT_OUTPUT_OPERATIONS:
                raise ValueError(
                    "Python text output analysis exceeds the trusted operation limit"
                )

        def add_expression_edge(source: ast.AST, target: ast.AST) -> None:
            targets = expression_dependents.setdefault(id(source), set())
            if id(target) not in targets:
                consume_operation()
                targets.add(id(target))

        def add_binding_edge(
            source: ast.AST,
            target: tuple[int, str],
        ) -> None:
            targets = binding_dependents.setdefault(id(source), set())
            if target not in targets:
                consume_operation()
                targets.add(target)

        def add_load_edge(
            source: tuple[int, str],
            target_id: int,
        ) -> None:
            targets = load_dependents.setdefault(source, set())
            if target_id not in targets:
                consume_operation()
                targets.add(target_id)

        for node in nodes:
            consume_operation()
            if isinstance(node, ast.Constant) and type(node.value) in {str, bytes}:
                seeded_expression_ids.add(id(node))
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                key, skipped_class_keys = name_load_binding_resolution(node)
                for dependency_key in (key, *skipped_class_keys):
                    add_load_edge(dependency_key, id(node))
            elif isinstance(node, ast.BinOp):
                if isinstance(node.op, (ast.Add, ast.Mult)):
                    add_expression_edge(node.left, node)
                    add_expression_edge(node.right, node)
                elif isinstance(node.op, ast.Mod):
                    add_expression_edge(node.left, node)
            elif isinstance(node, ast.JoinedStr):
                seeded_expression_ids.add(id(node))
            elif isinstance(node, ast.Call):
                if bound_string_method_kinds(node.func) & {
                    "format",
                    "format_map",
                    "join",
                }:
                    seeded_expression_ids.add(id(node))
            elif isinstance(node, (ast.Tuple, ast.List, ast.Set)):
                for child in node.elts:
                    add_expression_edge(child, node)
            elif isinstance(node, ast.Dict):
                for child in node.values:
                    add_expression_edge(child, node)
            elif isinstance(node, ast.Subscript):
                selected = selected_subscript_expressions(node)
                if selected:
                    for source in selected:
                        add_expression_edge(source, node)
                else:
                    add_expression_edge(node.value, node)
            elif isinstance(node, ast.IfExp):
                add_expression_edge(node.body, node)
                add_expression_edge(node.orelse, node)
            elif isinstance(node, ast.BoolOp):
                for child in node.values:
                    add_expression_edge(child, node)
            elif isinstance(node, ast.NamedExpr):
                add_expression_edge(node.value, node)

        for key, candidates in binding_candidates.items():
            for _, assigned_value, path, _ in candidates:
                consume_operation()
                source = selected_assignment_expression(assigned_value, path)
                add_binding_edge(source or assigned_value, key)
        for key, assigned_values in ordinary_ambiguous_binding_values.items():
            for assigned_value in assigned_values:
                consume_operation()
                add_binding_edge(assigned_value, key)

        output_expression_ids = set(seeded_expression_ids)
        output_binding_keys: set[tuple[int, str]] = set()
        pending_expressions = list(seeded_expression_ids)
        pending_bindings: list[tuple[int, str]] = []
        while pending_expressions or pending_bindings:
            while pending_expressions:
                consume_operation()
                expression_id = pending_expressions.pop()
                for dependent_id in expression_dependents.get(expression_id, ()):
                    consume_operation()
                    if dependent_id not in output_expression_ids:
                        output_expression_ids.add(dependent_id)
                        pending_expressions.append(dependent_id)
                for key in binding_dependents.get(expression_id, ()):
                    consume_operation()
                    if key not in output_binding_keys:
                        output_binding_keys.add(key)
                        pending_bindings.append(key)
            while pending_bindings:
                consume_operation()
                key = pending_bindings.pop()
                for dependent_id in load_dependents.get(key, ()):
                    consume_operation()
                    if dependent_id not in output_expression_ids:
                        output_expression_ids.add(dependent_id)
                        pending_expressions.append(dependent_id)

        text_output_expression_ids = output_expression_ids
        text_output_binding_keys = output_binding_keys

    def bound_string_method_value(
        method_name: str,
        receiver: Any,
    ) -> tuple[object, str, Any]:
        return (bound_string_method_marker, method_name, receiver)

    def unpack_bound_string_method(
        value: Any,
    ) -> tuple[str, Any] | None:
        if (
            type(value) is tuple
            and len(value) == 3
            and value[0] is bound_string_method_marker
            and value[1] in bound_string_method_names
            and (type(value[2]) in {str, bytes} or value[2] is str or value[2] is bytes)
        ):
            return value[1], value[2]
        return None

    def bound_int_to_bytes_method_value(receiver: Any) -> tuple[object, Any]:
        return (bound_int_to_bytes_method_marker, receiver)

    def unpack_bound_int_to_bytes_method(value: Any) -> Any:
        if (
            type(value) is tuple
            and len(value) == 2
            and value[0] is bound_int_to_bytes_method_marker
            and (type(value[1]) is int or value[1] is int)
        ):
            return value[1]
        return not_pure

    def unresolved_int_method_value(receiver: Any) -> tuple[object, Any]:
        return (unresolved_int_method_marker, receiver)

    def unpack_unresolved_int_method(value: Any) -> Any:
        if (
            type(value) is tuple
            and len(value) == 2
            and value[0] is unresolved_int_method_marker
            and (type(value[1]) is int or value[1] is int)
        ):
            return value[1]
        return not_pure

    def unshadowed_builtin_name(
        node: ast.AST,
        names: frozenset[str],
    ) -> str | None:
        if (
            not isinstance(node, ast.Name)
            or not isinstance(node.ctx, ast.Load)
            or node.id not in names
        ):
            return None
        key, skipped_class_keys = name_load_binding_resolution(node)
        if any(
            binding_event_ids.get(candidate) for candidate in (key, *skipped_class_keys)
        ):
            return None
        return node.id

    def unshadowed_deterministic_text_builtin(node: ast.AST) -> Any:
        name = unshadowed_builtin_name(node, deterministic_text_builtin_names)
        if name is None:
            return None
        return {
            "bytearray": bytearray,
            "bytes": bytes,
            "chr": chr,
            "str": str,
        }[name]

    def unshadowed_static_range_builtin(node: ast.AST) -> Any:
        return range if unshadowed_builtin_name(node, frozenset({"range"})) else None

    def unshadowed_static_int_builtin(node: ast.AST) -> Any:
        if unshadowed_builtin_name(node, frozenset({"int"})):
            return int
        if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load):
            return None
        key = name_load_binding_key(node)
        return (
            int
            if any(
                imported_name == "int" and event_may_reach_load(node, key, event_id)
                for event_id, imported_name in static_builtin_import_bindings.get(
                    key, ()
                )
            )
            else None
        )

    def unshadowed_builtin_text_type(node: ast.AST) -> type[str] | type[bytes] | None:
        value = unshadowed_deterministic_text_builtin(node)
        return value if value is bytes or value is str else None

    def normalized_text_codec(value: Any, *, default: str) -> str:
        if value is None:
            value = default
        if not isinstance(value, str):
            raise ValueError("Python deterministic text codec name is not a string")
        normalized = value.casefold().replace("-", "_").replace(" ", "_")
        aliases = {
            "latin1": "latin_1",
            "u8": "utf_8",
            "utf8": "utf_8",
            "utf16": "utf_16",
            "utf32": "utf_32",
        }
        normalized = aliases.get(normalized, normalized)
        allowed = {
            "ascii",
            "latin_1",
            "raw_unicode_escape",
            "unicode_escape",
            "utf_8",
            "utf_8_sig",
            "utf_16",
            "utf_16_be",
            "utf_16_le",
            "utf_32",
            "utf_32_be",
            "utf_32_le",
        }
        if normalized not in allowed:
            raise ValueError(
                "Python deterministic text codec is outside the trusted allowlist"
            )
        return normalized

    def validate_text_method_result(result: Any) -> Any:
        pending = [result]
        observed = 0
        aggregate_text_bytes = 0
        while pending:
            observed += 1
            if observed > BOOTSTRAP_V2_MAX_PYTHON_AST_NODES:
                raise ValueError(
                    "Python deterministic text method result exceeds the trusted item limit"
                )
            current = pending.pop()
            if current is None or type(current) in {bool, int}:
                continue
            if type(current) in {str, bytes}:
                payload_size = evaluated_text_payload_size(current)
                if payload_size > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES:
                    raise ValueError(
                        "Python evaluated string exceeds the trusted byte limit"
                    )
                aggregate_text_bytes += payload_size
                if aggregate_text_bytes > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_BYTES:
                    raise ValueError(
                        "Python deterministic text method result exceeds the trusted byte limit"
                    )
                continue
            if type(current) in {tuple, list}:
                pending.extend(reversed(current))
                continue
            if type(current) is dict:
                for key, child in current.items():
                    pending.extend((key, child))
                continue
            raise ValueError(
                "Python deterministic text method returned an unsupported value type"
            )
        return result

    static_constructor_analysis_operations = 0
    static_constructor_analysis_limit = max(node_count * 8, 1)
    static_constructor_builtin_names = set(
        "bin bytearray bytes chr enumerate filter frozenset hex int iter len list "
        "map max min oct ord range reversed set str sum tuple zip".split()
    )

    def consume_static_constructor_analysis_operation() -> None:
        nonlocal static_constructor_analysis_operations
        static_constructor_analysis_operations += 1
        if static_constructor_analysis_operations > static_constructor_analysis_limit:
            raise ValueError(
                "Python static constructor analysis exceeds the trusted operation limit"
            )

    def expression_is_closed_static_value(node: ast.AST) -> bool:
        local_names: set[str] = set()
        pending_local_names = [node]
        while pending_local_names:
            consume_static_constructor_analysis_operation()
            current = pending_local_names.pop()
            if isinstance(current, ast.Name) and isinstance(current.ctx, ast.Store):
                local_names.add(current.id)
            elif isinstance(current, ast.arg):
                local_names.add(current.arg)
            pending_local_names.extend(ast.iter_child_nodes(current))
        pending = [node]
        while pending:
            consume_static_constructor_analysis_operation()
            current = pending.pop()
            if isinstance(current, ast.Name) and isinstance(current.ctx, ast.Load):
                if (
                    current.id not in local_names
                    and current.id not in static_constructor_builtin_names
                ):
                    return False
            if isinstance(current, (ast.Await, ast.Yield, ast.YieldFrom)):
                return False
            pending.extend(ast.iter_child_nodes(current))
        return True

    def reject_unsupported_static_constructor_input(node: ast.AST) -> None:
        if expression_is_closed_static_value(node):
            raise ValueError(
                "Python deterministic text constructor uses an unsupported "
                f"static input at line {getattr(node, 'lineno', 0)}"
            )

    def evaluate_deterministic_text_builtin_call(
        node: ast.Call,
        constructor: Any,
        evaluate_node: Any,
    ) -> Any:
        if any(isinstance(argument, ast.Starred) for argument in node.args):
            return not_pure
        arguments: list[Any] = []
        for argument_node in node.args:
            argument = evaluate_node(argument_node)
            if argument is not_pure:
                reject_unsupported_static_constructor_input(argument_node)
                return not_pure
            arguments.append(argument)
        keywords: dict[str, Any] = {}
        for keyword in node.keywords:
            if keyword.arg is None or keyword.arg in keywords:
                return not_pure
            value = evaluate_node(keyword.value)
            if value is not_pure:
                reject_unsupported_static_constructor_input(keyword.value)
                return not_pure
            keywords[keyword.arg] = value

        if constructor is range:
            if (
                keywords
                or not 1 <= len(arguments) <= 3
                or any(type(argument) is not int for argument in arguments)
            ):
                return not_pure
            try:
                sequence = range(*arguments)
                length = len(sequence)
            except (OverflowError, ValueError) as exc:
                raise ValueError(
                    "Python deterministic range call is unsupported"
                ) from exc
            if length > min(
                BOOTSTRAP_V2_MAX_PYTHON_AST_NODES,
                BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES,
            ):
                raise ValueError(
                    "Python deterministic range exceeds the trusted item limit"
                )
            return validate_text_method_result(tuple(sequence))

        if constructor is chr:
            if len(arguments) != 1 or keywords or type(arguments[0]) is not int:
                return not_pure
            try:
                result = chr(arguments[0])
            except (OverflowError, ValueError) as exc:
                raise ValueError(
                    "Python deterministic chr call is unsupported"
                ) from exc
            return validate_text_method_result(result)

        if constructor not in {bytearray, bytes, str}:
            return not_pure
        if len(arguments) > 3 or not set(keywords) <= {"encoding", "errors"}:
            return not_pure

        mutable_arguments = list(arguments)
        mutable_keywords = dict(keywords)
        source = mutable_arguments[0] if mutable_arguments else None
        encoding_supplied = (
            len(mutable_arguments) >= 2 or "encoding" in mutable_keywords
        )
        errors_supplied = len(mutable_arguments) >= 3 or "errors" in mutable_keywords

        if constructor in {bytearray, bytes}:
            if source is None:
                if encoding_supplied or errors_supplied:
                    return not_pure
            elif type(source) is int:
                if encoding_supplied or errors_supplied:
                    return not_pure
                if source < 0 or source > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES:
                    raise ValueError(
                        "Python deterministic bytes allocation exceeds the trusted "
                        "byte limit"
                    )
            elif type(source) in {tuple, list}:
                if encoding_supplied or errors_supplied:
                    return not_pure
                if len(source) > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES:
                    raise ValueError(
                        "Python deterministic bytes iterable exceeds the trusted "
                        "byte limit"
                    )
                if any(
                    type(item) is not int or not 0 <= item <= 255 for item in source
                ):
                    raise ValueError(
                        "Python deterministic bytes iterable contains an invalid item"
                    )
            elif type(source) is str:
                if not encoding_supplied:
                    return not_pure
            elif type(source) is not bytes:
                return not_pure
        elif constructor is str and encoding_supplied and type(source) is not bytes:
            return not_pure

        if encoding_supplied:
            if len(mutable_arguments) >= 2:
                mutable_arguments[1] = normalized_text_codec(
                    mutable_arguments[1],
                    default="utf_8",
                )
            else:
                mutable_keywords["encoding"] = normalized_text_codec(
                    mutable_keywords["encoding"],
                    default="utf_8",
                )
        if errors_supplied:
            errors = (
                mutable_arguments[2]
                if len(mutable_arguments) >= 3
                else mutable_keywords["errors"]
            )
            if errors not in text_codec_error_modes:
                raise ValueError(
                    "Python deterministic text constructor error mode is outside "
                    "the trusted allowlist"
                )

        try:
            result = constructor(*mutable_arguments, **mutable_keywords)
        except Exception as exc:
            raise ValueError(
                "Python deterministic text constructor call is unsupported"
            ) from exc
        if isinstance(result, bytearray):
            result = bytes(result)
        return validate_text_method_result(result)

    def evaluate_static_int_to_bytes_method_reference(
        node: ast.AST,
        evaluate_node: Any,
    ) -> Any:
        if isinstance(node, ast.Attribute) and node.attr == "to_bytes":
            receiver = evaluate_node(node.value)
            if type(receiver) is int or receiver is int:
                return bound_int_to_bytes_method_value(receiver)
            return not_pure
        if (
            isinstance(node, ast.Call)
            and len(node.args) in {2, 3}
            and not node.keywords
            and has_static_builtin_origin(node.func, frozenset({"getattr"}))
        ):
            receiver = evaluate_node(node.args[0])
            method_name = evaluate_node(node.args[1])
            if type(receiver) is int or receiver is int:
                if method_name is not_pure:
                    return unresolved_int_method_value(receiver)
                if method_name == "to_bytes":
                    return bound_int_to_bytes_method_value(receiver)
            if len(node.args) == 3 and static_getattr_default_is_possible(
                receiver,
                method_name,
            ):
                default_method = evaluate_node(node.args[2])
                default_receiver = unpack_bound_int_to_bytes_method(default_method)
                if default_receiver is int or type(default_receiver) is int:
                    return default_method
                unresolved_receiver = unpack_unresolved_int_method(default_method)
                if unresolved_receiver is int or type(unresolved_receiver) is int:
                    return default_method
        return not_pure

    def evaluate_static_int_to_bytes_call(
        node: ast.Call,
        evaluate_node: Any,
        *,
        receiver_override: Any = static_int_receiver_unset,
    ) -> Any:
        if receiver_override is not static_int_receiver_unset:
            receiver = receiver_override
        else:
            method_value = evaluate_static_int_to_bytes_method_reference(
                node.func,
                evaluate_node,
            )
            if method_value is not_pure:
                method_value = evaluate_node(node.func)
            unresolved_receiver = unpack_unresolved_int_method(method_value)
            if unresolved_receiver is int or type(unresolved_receiver) is int:
                raise ValueError(
                    "Python deterministic int.to_bytes uses an unresolved int "
                    "method name "
                    f"at line {getattr(node, 'lineno', 0)}"
                )
            receiver = unpack_bound_int_to_bytes_method(method_value)
        if receiver is not int and type(receiver) is not int:
            return not_pure

        if any(isinstance(argument, ast.Starred) for argument in node.args):
            raise ValueError("Python deterministic int.to_bytes uses starred arguments")
        arguments: list[Any] = []
        for argument_node in node.args:
            argument = evaluate_node(argument_node)
            if argument is not_pure:
                raise ValueError(
                    "Python deterministic int.to_bytes uses an unresolved argument "
                    f"at line {getattr(node, 'lineno', 0)}"
                )
            arguments.append(argument)
        keywords: dict[str, Any] = {}
        for keyword in node.keywords:
            if keyword.arg is None or keyword.arg in keywords:
                raise ValueError(
                    "Python deterministic int.to_bytes uses unsupported keywords"
                )
            keyword_value = evaluate_node(keyword.value)
            if keyword_value is not_pure:
                raise ValueError(
                    "Python deterministic int.to_bytes uses an unresolved argument "
                    f"at line {getattr(node, 'lineno', 0)}"
                )
            keywords[keyword.arg] = keyword_value

        if receiver is int:
            if not arguments or type(arguments[0]) is not int:
                raise ValueError(
                    "Python deterministic int.to_bytes has no exact integer receiver"
                )
            receiver = arguments.pop(0)
        if (
            len(arguments) > 2
            or not set(keywords) <= {"length", "byteorder", "signed"}
            or (arguments and "length" in keywords)
            or (len(arguments) >= 2 and "byteorder" in keywords)
        ):
            raise ValueError("Python deterministic int.to_bytes call is outside policy")
        length = arguments[0] if arguments else keywords.get("length", 1)
        byteorder = (
            arguments[1] if len(arguments) >= 2 else keywords.get("byteorder", "big")
        )
        signed = keywords.get("signed", False)
        if (
            type(length) is not int
            or length < 0
            or length > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES
            or type(byteorder) is not str
            or byteorder not in {"big", "little"}
            or type(signed) is not bool
        ):
            raise ValueError(
                "Python deterministic int.to_bytes arguments are outside policy"
            )
        try:
            result = receiver.to_bytes(length, byteorder, signed=signed)
        except (OverflowError, ValueError) as exc:
            raise ValueError(
                "Python deterministic int.to_bytes call is unsupported"
            ) from exc
        return validate_text_method_result(result)

    def preflight_text_method_call(
        method_name: str,
        receiver: Any,
        arguments: tuple[Any, ...],
        keywords: dict[str, Any],
    ) -> None:
        limit = BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES

        if method_name not in modeled_string_method_names:
            raise ValueError(
                "Python deterministic text method is outside the trusted policy"
            )

        def argument(index: int, name: str, default: Any = None) -> Any:
            return (
                arguments[index]
                if len(arguments) > index
                else keywords.get(name, default)
            )

        if receiver is str or receiver is bytes:
            if method_name not in {"fromhex", "maketrans"}:
                raise ValueError(
                    "Python deterministic text type method is outside the trusted policy"
                )
            return
        if type(receiver) not in {str, bytes}:
            raise ValueError(
                "Python deterministic text method uses an unsupported receiver"
            )
        if method_name in {"center", "ljust", "rjust", "zfill"}:
            width = argument(0, "width")
            if type(width) is not int or width > limit:
                raise ValueError(
                    "Python deterministic text padding exceeds the trusted byte limit"
                )
        if method_name == "expandtabs":
            tab_size = argument(0, "tabsize", 8)
            if type(tab_size) is not int:
                raise ValueError(
                    "Python deterministic expandtabs size is not an integer"
                )
            source_size = bootstrap_v2_python_payload_size(receiver)
            if source_size * max(tab_size, 1) > limit:
                raise ValueError(
                    "Python deterministic expandtabs exceeds the trusted byte limit"
                )
        if method_name == "replace":
            old = argument(0, "old")
            new = argument(1, "new")
            if type(old) is not type(receiver) or type(new) is not type(receiver):
                raise ValueError(
                    "Python deterministic replace mixes text and bytes values"
                )
            count = argument(2, "count", -1)
            if type(count) is not int:
                raise ValueError("Python deterministic replace count is not an integer")
            occurrence_count = receiver.count(old)
            if count >= 0:
                occurrence_count = min(occurrence_count, count)
            source_size = bootstrap_v2_python_payload_size(receiver)
            old_size = bootstrap_v2_python_payload_size(old)
            new_size = bootstrap_v2_python_payload_size(new)
            growth = occurrence_count * max(new_size - old_size, 0)
            if source_size + growth > limit:
                raise ValueError(
                    "Python deterministic replace exceeds the trusted byte limit"
                )
        if method_name == "translate" and isinstance(receiver, str):
            table = argument(0, "table")
            if type(table) is not dict:
                raise ValueError(
                    "Python deterministic string translate table is unsupported"
                )
            translated_size = 0
            for character in receiver:
                replacement = table.get(ord(character), character)
                if replacement is None:
                    continue
                if type(replacement) is int:
                    try:
                        replacement = chr(replacement)
                    except (OverflowError, ValueError) as exc:
                        raise ValueError(
                            "Python deterministic string translate table is invalid"
                        ) from exc
                if not isinstance(replacement, str):
                    raise ValueError(
                        "Python deterministic string translate table is invalid"
                    )
                translated_size += bootstrap_v2_python_payload_size(replacement)
                if translated_size > limit:
                    raise ValueError(
                        "Python deterministic translate exceeds the trusted byte limit"
                    )
        if method_name in {"encode", "decode"}:
            default_encoding = "utf_8"
            encoding = argument(0, "encoding")
            normalized_text_codec(encoding, default=default_encoding)
            errors = argument(1, "errors", "strict")
            if errors not in text_codec_error_modes:
                raise ValueError(
                    "Python deterministic text codec error mode is outside the trusted allowlist"
                )

    def call_deterministic_text_method(
        method_name: str,
        receiver: Any,
        arguments: tuple[Any, ...],
        keywords: dict[str, Any],
    ) -> Any:
        preflight_text_method_call(method_name, receiver, arguments, keywords)
        if method_name in {"encode", "decode"}:
            mutable_arguments = list(arguments)
            mutable_keywords = dict(keywords)
            if mutable_arguments:
                mutable_arguments[0] = normalized_text_codec(
                    mutable_arguments[0], default="utf_8"
                )
            elif "encoding" in mutable_keywords:
                mutable_keywords["encoding"] = normalized_text_codec(
                    mutable_keywords["encoding"], default="utf_8"
                )
            arguments = tuple(mutable_arguments)
            keywords = mutable_keywords
        try:
            result = getattr(receiver, method_name)(*arguments, **keywords)
        except Exception as exc:
            raise ValueError(
                "Python deterministic text method call is unsupported"
            ) from exc
        return validate_text_method_result(result)

    def select_assignment_value(result: Any, path: tuple[int, ...]) -> Any:
        for index in path:
            if type(result) not in {tuple, list} or index >= len(result):
                return not_pure
            result = result[index]
        return result

    def resolve_binding(key: tuple[int, str]) -> Any:
        cached = binding_value_cache.get(key, not_pure)
        if key in binding_value_cache:
            return cached
        if key in hard_ambiguous_binding_keys or key in binding_resolution_stack:
            return not_pure
        candidates = binding_candidates.get(key)
        if candidates is None or len(candidates) != 1:
            return not_pure
        statement, assigned_value, path, _ = candidates[0]
        binding_resolution_stack.add(key)
        try:
            result = evaluate_binding_expression(assigned_value)
            result = select_assignment_value(result, path)
        finally:
            binding_resolution_stack.remove(key)
        binding_value_cache[key] = result
        return result

    def evaluate_bound_string_method_call(
        node: ast.Call,
        method_value: Any,
        evaluate_node: Any,
    ) -> Any:
        if isinstance(node.func, ast.Attribute):
            receiver_node = node.func.value
            if expression_has_mutated_static_bytearray_origin(receiver_node):
                if (
                    node.func.attr in text_emitting_string_method_names
                    or binding_expression_may_output_text(node)
                ):
                    raise ValueError(
                        "Python bytearray text method uses a mutable aliased receiver"
                    )
                return not_pure
        method = unpack_bound_string_method(method_value)
        if method is None:
            return not_pure
        method_name, receiver = method
        if method_name == "join":
            if len(node.args) != 1 or node.keywords:
                return not_pure
            elements = evaluate_node(node.args[0])
            if type(elements) not in {tuple, list}:
                if join_iterable_depends_on_parameter(
                    node.args[0]
                ) or opaque_join_iterable_may_emit_text(node.args[0]):
                    raise ValueError(
                        "Python join uses an unsupported text-producing iterable "
                        f"at line {getattr(node, 'lineno', 0)}"
                    )
                return not_pure
            return bootstrap_v2_python_literal_join(receiver, tuple(elements))
        arguments: list[Any] = []
        for argument_node in node.args:
            if isinstance(argument_node, ast.Starred):
                argument = evaluate_node(argument_node.value)
                if not isinstance(argument, (tuple, list)):
                    return not_pure
                arguments.extend(argument)
                continue
            argument = evaluate_node(argument_node)
            if argument is not_pure:
                return not_pure
            arguments.append(argument)
        keywords: dict[str, Any] = {}
        for keyword in node.keywords:
            keyword_value = evaluate_node(keyword.value)
            if keyword_value is not_pure:
                return not_pure
            if keyword.arg is None:
                if not isinstance(keyword_value, dict) or not all(
                    isinstance(key, str) for key in keyword_value
                ):
                    return not_pure
                keywords.update(keyword_value)
            else:
                keywords[keyword.arg] = keyword_value
        if method_name not in {"format", "format_map"}:
            return call_deterministic_text_method(
                method_name,
                receiver,
                tuple(arguments),
                keywords,
            )
        if not isinstance(receiver, str):
            raise ValueError("Python dot formatting uses an unsupported receiver type")
        return bootstrap_v2_python_dot_format(
            receiver,
            tuple(arguments),
            keywords,
            format_map=method_name == "format_map",
        )

    def evaluate_binding_expression(node: ast.AST) -> Any:
        if id(node) in binding_expression_cache:
            return binding_expression_cache[id(node)]
        result: Any = not_pure
        if isinstance(node, ast.Constant):
            if node.value is None or type(node.value) in {
                bool,
                bytes,
                complex,
                float,
                int,
                str,
            }:
                result = node.value
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            key = name_load_binding_key(node)
            candidates = binding_candidates.get(key)
            if candidates is not None and len(candidates) == 1:
                statement = candidates[0][0]
                if binding_is_usable_for_load(node, key, statement):
                    result = resolve_binding(key)
            if result is not_pure:
                builtin = unshadowed_deterministic_text_builtin(node)
                if builtin is not None:
                    result = builtin
                else:
                    result = (
                        unshadowed_static_range_builtin(node)
                        or unshadowed_static_int_builtin(node)
                        or not_pure
                    )
        elif isinstance(node, ast.Subscript):
            container = evaluate_binding_expression(node.value)
            selector = normalized_literal_selector(node.slice)
            if selector is None:
                selector = normalized_literal_slice(node.slice)
            if selector is not None:
                try:
                    if type(container) in {str, bytes, tuple, list, dict}:
                        result = container[selector]
                except (IndexError, KeyError, TypeError):
                    result = not_pure
        elif isinstance(node, ast.Attribute):
            receiver = evaluate_binding_expression(node.value)
            if node.attr in bound_string_method_names and (
                type(receiver) in {str, bytes} or receiver is str or receiver is bytes
            ):
                result = bound_string_method_value(node.attr, receiver)
            elif node.attr == "to_bytes" and (type(receiver) is int or receiver is int):
                result = bound_int_to_bytes_method_value(receiver)
        elif isinstance(node, (ast.Tuple, ast.List)):
            children = [evaluate_binding_expression(child) for child in node.elts]
            if all(child is not not_pure for child in children):
                result = tuple(children) if isinstance(node, ast.Tuple) else children
        elif isinstance(node, ast.Dict):
            pairs: list[tuple[Any, Any]] = []
            for key_node, value_node in zip(node.keys, node.values, strict=True):
                if key_node is None:
                    break
                key_value = evaluate_binding_expression(key_node)
                child = evaluate_binding_expression(value_node)
                if key_value is not_pure or child is not_pure:
                    break
                pairs.append((key_value, child))
            else:
                try:
                    result = dict(pairs)
                except TypeError as exc:
                    raise ValueError(
                        "Python deterministic mapping uses an unsupported key type"
                    ) from exc
        elif isinstance(node, ast.UnaryOp) and isinstance(
            node.op, (ast.UAdd, ast.USub)
        ):
            operand = evaluate_binding_expression(node.operand)
            if operand is not not_pure and type(operand) in {int, float, complex}:
                result = +operand if isinstance(node.op, ast.UAdd) else -operand
        elif isinstance(node, ast.BinOp):
            left = evaluate_binding_expression(node.left)
            right = evaluate_binding_expression(node.right)
            if left is not not_pure and right is not not_pure:
                if isinstance(node.op, ast.Add):
                    if not isinstance(left, (str, bytes)) and not isinstance(
                        right, (str, bytes)
                    ):
                        result = not_pure
                    elif not isinstance(left, (str, bytes)) or not isinstance(
                        right, (str, bytes)
                    ):
                        raise ValueError(
                            "Python constant addition uses an unsupported literal type"
                        )
                    elif type(left) is not type(right):
                        raise ValueError(
                            "Python constant addition mixes text and bytes literals"
                        )
                    else:
                        combined_size = sum(
                            bootstrap_v2_python_payload_size(part)
                            for part in (left, right)
                        )
                        if (
                            combined_size
                            > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES
                        ):
                            raise ValueError(
                                "Python constant addition exceeds the trusted byte limit"
                            )
                        result = left + right
                elif isinstance(node.op, ast.Mult):
                    if isinstance(left, (str, bytes)) and type(right) in {bool, int}:
                        text_value = left
                        multiplier = int(right)
                    elif type(left) in {bool, int} and isinstance(right, (str, bytes)):
                        text_value = right
                        multiplier = int(left)
                    elif isinstance(left, (str, bytes)) or isinstance(
                        right, (str, bytes)
                    ):
                        raise ValueError(
                            "Python constant repetition uses an unsupported literal type"
                        )
                    else:
                        text_value = None
                        multiplier = 0
                    if text_value is not None:
                        payload_size = bootstrap_v2_python_payload_size(text_value)
                        repeated_size = payload_size * max(multiplier, 0)
                        if (
                            repeated_size
                            > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES
                        ):
                            raise ValueError(
                                "Python constant repetition exceeds the trusted byte limit"
                            )
                        result = text_value * multiplier
                elif isinstance(node.op, ast.Mod) and isinstance(left, (str, bytes)):
                    result = bootstrap_v2_python_percent_format(left, right)
        elif isinstance(node, ast.JoinedStr):
            rendered_parts: list[str] = []
            rendered_size = 0
            for child in node.values:
                if isinstance(child, ast.Constant) and isinstance(child.value, str):
                    literal_size = bootstrap_v2_python_payload_size(child.value)
                    if (
                        literal_size
                        > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES - rendered_size
                    ):
                        raise ValueError(
                            "Python f-string exceeds the trusted byte limit"
                        )
                    rendered_parts.append(child.value)
                    rendered_size += literal_size
                    continue
                if not isinstance(child, ast.FormattedValue):
                    break
                child_value = evaluate_binding_expression(child.value)
                if child_value is not_pure:
                    break
                if child.format_spec is None:
                    format_spec = ""
                else:
                    format_spec = evaluate_binding_expression(child.format_spec)
                    if not isinstance(format_spec, str):
                        break
                rendered_parts.append(
                    bootstrap_v2_python_formatted_value(
                        child_value,
                        conversion=child.conversion,
                        format_spec=format_spec,
                        max_output_bytes=(
                            BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES
                            - rendered_size
                        ),
                    )
                )
                rendered_size += bootstrap_v2_python_constant_text(rendered_parts[-1])[
                    1
                ]
            else:
                result = "".join(rendered_parts)
        elif isinstance(node, ast.Call):
            result = evaluate_static_int_to_bytes_call(
                node,
                evaluate_binding_expression,
            )
            if result is not_pure:
                result = evaluate_static_int_to_bytes_method_reference(
                    node,
                    evaluate_binding_expression,
                )
            if result is not_pure:
                result = evaluate_static_text_operator_call(
                    node,
                    evaluate_binding_expression,
                )
            if result is not_pure:
                callable_value = evaluate_binding_expression(node.func)
                if any(
                    callable_value is constructor
                    for constructor in (bytearray, bytes, chr, range, str)
                ):
                    result = evaluate_deterministic_text_builtin_call(
                        node,
                        callable_value,
                        evaluate_binding_expression,
                    )
                else:
                    result = evaluate_bound_string_method_call(
                        node,
                        callable_value,
                        evaluate_binding_expression,
                    )
        if type(result) in {str, bytes} and not isinstance(
            node, (ast.Constant, ast.Name)
        ):
            charge_retained_evaluated_value(node, result)
        binding_expression_cache[id(node)] = result
        return result

    decoder_origin_ops = 0
    decoder_origin_limit = max(node_count * 16, 1)

    def charge_origin() -> None:
        nonlocal decoder_origin_ops
        decoder_origin_ops += 1
        if decoder_origin_ops > decoder_origin_limit:
            raise ValueError(
                "Python static decoder origin analysis exceeds the trusted "
                "operation limit"
            )

    def decoder_binding_sources(
        key: tuple[int, str],
        load: ast.Name | None = None,
        *,
        include_shadowed_assignments: bool = False,
    ) -> list[ast.AST]:
        sources: dict[int, ast.AST] = {}
        for _, value, path, target in selection_binding_candidates(key):
            charge()
            if (
                load is not None
                and not include_shadowed_assignments
                and not event_may_reach_load(load, key, id(target))
            ):
                continue
            selected = selected_assignment_expressions(value, path)
            if selected:
                for source in selected:
                    sources[id(source)] = source
            else:
                sources[id(value)] = value
        ordinary_events = ordinary_ambiguous_binding_events.get(key, ())
        for event_id, source in ordinary_events:
            charge()
            if (
                load is None
                or include_shadowed_assignments
                or event_may_reach_load(load, key, event_id)
            ):
                sources[id(source)] = source
        if not ordinary_events:
            for source in ordinary_ambiguous_binding_values.get(key, ()):
                charge()
                sources[id(source)] = source
        for event_id, source in parameter_default_sources.get(key, ()):
            charge()
            if load is None or parameter_default_may_reach_load(load, key, event_id):
                sources[id(source)] = source
        return list(sources.values())

    binding_event_statement_cache: dict[int, ast.stmt | None] = {}

    def binding_event_statement(event_id: int) -> ast.stmt | None:
        if event_id in binding_event_statement_cache:
            return binding_event_statement_cache[event_id]
        current = node_by_id.get(event_id)
        while current is not None and not isinstance(current, ast.stmt):
            consume_binding_reachability_step()
            current = parent_by_node_id.get(id(current))
        result = current if isinstance(current, ast.stmt) else None
        binding_event_statement_cache[event_id] = result
        return result

    direct_binding_event_statements_cache: dict[
        tuple[int, str],
        dict[tuple[int, str], tuple[tuple[int, int], ...]],
    ] = {}
    latest_binding_statement_cache: dict[tuple[int, tuple[int, str]], int | None] = {}
    loop_body_ancestor_ids_cache: dict[int, frozenset[int]] = {}
    loop_at_most_one_iteration_cache: dict[int, bool] = {}
    statement_loop_backedge_cache: dict[tuple[int, int], bool] = {}

    def loop_body_ancestor_ids(node: ast.AST) -> frozenset[int]:
        node_id = id(node)
        cached = loop_body_ancestor_ids_cache.get(node_id)
        if cached is not None:
            return cached
        ancestor_ids: set[int] = set()
        node_scope = scope_by_node_id[node_id]
        current: ast.AST | None = node
        while current is not None:
            consume_binding_reachability_step()
            parent = parent_by_node_id.get(id(current))
            if (
                isinstance(parent, ast.While)
                and current is parent.test
                and scope_by_node_id[id(parent)] == node_scope
            ) or (
                isinstance(parent, (ast.For, ast.AsyncFor))
                and current is parent.target
                and scope_by_node_id[id(parent)] == node_scope
            ):
                ancestor_ids.add(id(parent))
            if isinstance(current, ast.stmt):
                location = statement_membership.get(id(current))
                if location is not None and location[0][1] == "body":
                    block_parent = node_by_id.get(location[0][0])
                    if isinstance(
                        block_parent, (ast.For, ast.AsyncFor, ast.While)
                    ) and (scope_by_node_id[id(block_parent)] == node_scope):
                        ancestor_ids.add(id(block_parent))
            current = parent
        result = frozenset(ancestor_ids)
        loop_body_ancestor_ids_cache[node_id] = result
        return result

    def loop_has_at_most_one_iteration(
        loop: ast.For | ast.AsyncFor | ast.While,
    ) -> bool:
        loop_id = id(loop)
        cached = loop_at_most_one_iteration_cache.get(loop_id)
        if cached is not None:
            return cached
        result = False
        if isinstance(loop, ast.For):
            iterable = loop.iter
            if isinstance(iterable, (ast.List, ast.Tuple, ast.Set)):
                result = (
                    not any(
                        isinstance(element, ast.Starred) for element in iterable.elts
                    )
                    and len(iterable.elts) <= 1
                )
            elif isinstance(iterable, ast.Dict):
                result = (
                    all(key is not None for key in iterable.keys)
                    and len(iterable.keys) <= 1
                )
        loop_at_most_one_iteration_cache[loop_id] = result
        return result

    def nearest_loop_ancestor(node: ast.AST) -> ast.AST | None:
        current = parent_by_node_id.get(id(node))
        while current is not None:
            consume_binding_reachability_step()
            if isinstance(current, (ast.For, ast.AsyncFor, ast.While)):
                return current
            current = parent_by_node_id.get(id(current))
        return None

    def statement_can_reach_loop_backedge(
        statement: ast.stmt,
        loop: ast.For | ast.AsyncFor | ast.While,
    ) -> bool:
        cache_key = (id(statement), id(loop))
        cached = statement_loop_backedge_cache.get(cache_key)
        if cached is not None:
            return cached
        if loop_has_at_most_one_iteration(loop):
            statement_loop_backedge_cache[cache_key] = False
            return False
        current: ast.AST | None = statement
        while current is not None and current is not loop:
            consume_binding_reachability_step()
            if isinstance(current, ast.stmt):
                location = statement_membership.get(id(current))
                if location is not None:
                    block_parent = node_by_id.get(location[0][0])
                    if block_parent is loop and location[0][1] == "body":
                        if current is not statement:
                            if not isinstance(
                                current, (ast.For, ast.AsyncFor, ast.While)
                            ) or statement_can_reach_loop_backedge(statement, current):
                                statement_loop_backedge_cache[cache_key] = True
                                return True
                        elif isinstance(
                            current,
                            (
                                ast.If,
                                ast.Match,
                                ast.Try,
                                ast.TryStar,
                                ast.With,
                                ast.AsyncWith,
                                ast.For,
                                ast.AsyncFor,
                                ast.While,
                            ),
                        ):
                            statement_loop_backedge_cache[cache_key] = True
                            return True
                        block = getattr(block_parent, location[0][1], ())
                        if not isinstance(block, list):
                            statement_loop_backedge_cache[cache_key] = True
                            return True
                        for following_index in range(location[1] + 1, len(block)):
                            consume_binding_reachability_step()
                            following = block[following_index]
                            if isinstance(following, ast.Continue):
                                statement_loop_backedge_cache[cache_key] = True
                                return True
                            if isinstance(following, ast.Break):
                                if nearest_loop_ancestor(following) is loop:
                                    statement_loop_backedge_cache[cache_key] = False
                                    return False
                                statement_loop_backedge_cache[cache_key] = True
                                return True
                            if isinstance(following, (ast.Return, ast.Raise)):
                                statement_loop_backedge_cache[cache_key] = False
                                return False
                            if isinstance(
                                following,
                                (
                                    ast.If,
                                    ast.Match,
                                    ast.Try,
                                    ast.TryStar,
                                    ast.With,
                                    ast.AsyncWith,
                                    ast.For,
                                    ast.AsyncFor,
                                    ast.While,
                                ),
                            ):
                                statement_loop_backedge_cache[cache_key] = True
                                return True
                        statement_loop_backedge_cache[cache_key] = True
                        return True
            current = parent_by_node_id.get(id(current))
        statement_loop_backedge_cache[cache_key] = True
        return True

    def direct_binding_event_statements(
        key: tuple[int, str],
    ) -> dict[tuple[int, str], tuple[tuple[int, int], ...]]:
        cached = direct_binding_event_statements_cache.get(key)
        if cached is not None:
            return cached
        direct_ids = direct_statement_ids_by_scope.get(key[0], set())
        statements: dict[int, ast.stmt] = {}
        for event_id in binding_event_ids.get(key, ()):
            consume_binding_reachability_step()
            if event_id in non_guaranteed_binding_event_ids:
                continue
            statement = binding_event_statement(event_id)
            if statement is not None and id(statement) in direct_ids:
                statements[id(statement)] = statement
        grouped: dict[tuple[int, str], list[tuple[int, int]]] = {}
        for statement_id, statement in statements.items():
            location = statement_membership.get(statement_id)
            if location is not None:
                grouped.setdefault(location[0], []).append((location[1], statement_id))
        result = {block: tuple(sorted(entries)) for block, entries in grouped.items()}
        direct_binding_event_statements_cache[key] = result
        return result

    def latest_binding_statement_for_load(
        load: ast.Name,
        key: tuple[int, str],
    ) -> int | None:
        cache_key = (id(load), key)
        if cache_key in latest_binding_statement_cache:
            return latest_binding_statement_cache[cache_key]
        statements_by_block = direct_binding_event_statements(key)
        current: ast.AST | None = load
        result: int | None = None
        while current is not None:
            consume_binding_reachability_step()
            if isinstance(current, ast.stmt):
                location = statement_membership.get(id(current))
                if location is not None:
                    entries = statements_by_block.get(location[0], ())
                    position = (
                        bisect_right(
                            entries,
                            (location[1] - 1, sys.maxsize),
                        )
                        - 1
                    )
                    if position >= 0:
                        result = entries[position][1]
                        break
            current = parent_by_node_id.get(id(current))
        latest_binding_statement_cache[cache_key] = result
        return result

    def event_may_reach_load(
        load: ast.Name,
        key: tuple[int, str],
        event_id: int,
    ) -> bool:
        consume_binding_reachability_step()
        if event_id in non_guaranteed_binding_event_ids:
            statement = binding_event_statement(event_id)
            if not isinstance(statement, (ast.For, ast.AsyncFor)):
                raise ValueError("Python non-guaranteed binding event is invalid")
            if scope_by_node_id[id(load)] != key[0]:
                return True
            child: ast.AST = load
            while parent_by_node_id.get(id(child)) is not statement:
                consume_binding_reachability_step()
                parent = parent_by_node_id.get(id(child))
                if parent is None:
                    break
                child = parent
            if id(child) in non_guaranteed_binding_body_ids[id(statement)]:
                return True
            if id(child) in non_guaranteed_binding_orelse_ids[id(statement)]:
                return True
            return (load.lineno, load.col_offset) >= (
                statement.end_lineno,
                statement.end_col_offset,
            )
        statement = binding_event_statement(event_id)
        if statement is None:
            return True
        if scope_by_node_id[id(load)] == key[0] and (
            load.lineno,
            load.col_offset,
        ) < (
            statement.lineno,
            statement.col_offset,
        ):
            has_backedge = False
            for loop_id in loop_body_ancestor_ids(load) & loop_body_ancestor_ids(
                statement
            ):
                loop = node_by_id[loop_id]
                if isinstance(loop, (ast.For, ast.AsyncFor, ast.While)) and (
                    statement_can_reach_loop_backedge(statement, loop)
                ):
                    has_backedge = True
                    break
            if not has_backedge:
                return False
        if id(statement) == latest_binding_statement_for_load(load, key):
            return True
        direct_ids = direct_statement_ids_by_scope.get(key[0], set())
        if id(statement) not in direct_ids:
            return True
        return bool(
            scope_by_node_id[id(load)] != key[0]
            and not statement_dominates_load(statement, load)
        )

    def parameter_default_may_reach_load(
        load: ast.Name,
        key: tuple[int, str],
        event_id: int,
    ) -> bool:
        if event_id not in binding_event_ids.get(key, ()):
            raise ValueError("Python parameter default event is not bound")
        for binding_event_id in binding_event_ids.get(key, ()):
            consume_binding_reachability_step()
            if binding_event_id not in non_guaranteed_binding_event_ids:
                continue
            statement = binding_event_statement(binding_event_id)
            if not isinstance(statement, (ast.For, ast.AsyncFor)):
                raise ValueError("Python non-guaranteed binding event is invalid")
            child: ast.AST = load
            while parent_by_node_id.get(id(child)) is not statement:
                consume_binding_reachability_step()
                parent = parent_by_node_id.get(id(child))
                if parent is None:
                    break
                child = parent
            if id(child) in non_guaranteed_binding_body_ids[id(statement)]:
                return False
        return latest_binding_statement_for_load(load, key) is None

    input_ops = 0
    input_limit = min(
        max(node_count * 8, 1),
        BOOTSTRAP_V2_MAX_DECODER_INPUT_OPS,
    )

    def charge() -> None:
        nonlocal input_ops
        input_ops += 1
        if input_ops > input_limit:
            raise ValueError("Python decoder input exceeds the trusted operation limit")

    def static_input_origin(node, receiver):
        pending = [node]
        observed = set()
        direct = static_receiver_input if receiver else direct_static_input
        while pending:
            charge()
            current = pending.pop()
            if id(current) in observed:
                continue
            observed.add(id(current))
            if direct(current):
                return True
            if isinstance(current, ast.Name) and isinstance(current.ctx, ast.Load):
                key = name_load_binding_key(current)
                pending.extend(
                    decoder_binding_sources(
                        key,
                        current,
                        include_shadowed_assignments=True,
                    )
                )
        return False

    def static_receiver(node: ast.AST) -> bool:
        return static_input_origin(node, True)

    def has_static_module_origin(
        node: ast.AST,
        module_names: frozenset[str],
    ) -> bool:
        pending: list[tuple[ast.AST, str]] = [(node, "")]
        observed_expression_states: set[tuple[int, str]] = set()
        observed_binding_states: set[tuple[tuple[int, str], str]] = set()
        while pending:
            charge_origin()
            current, suffix = pending.pop()
            state = (id(current), suffix)
            if state in observed_expression_states:
                continue
            observed_expression_states.add(state)
            if isinstance(current, ast.Attribute):
                pending.append((current.value, f".{current.attr}{suffix}"))
                continue
            if not isinstance(current, ast.Name) or not isinstance(
                current.ctx, ast.Load
            ):
                continue
            key = name_load_binding_key(current)
            for event_id, imported_name in static_module_import_bindings.get(key, ()):
                if f"{imported_name}{suffix}" in module_names and event_may_reach_load(
                    current, key, event_id
                ):
                    return True
            binding_state = (key, suffix)
            if binding_state in observed_binding_states:
                continue
            observed_binding_states.add(binding_state)
            pending.extend(
                (source, suffix) for source in decoder_binding_sources(key, current)
            )
        return False

    def has_static_builtin_origin(
        node: ast.AST,
        builtin_names: frozenset[str],
    ) -> bool:
        pending = [node]
        observed_expression_ids: set[int] = set()
        observed_binding_keys: set[tuple[int, str]] = set()
        while pending:
            charge_origin()
            current = pending.pop()
            if id(current) in observed_expression_ids:
                continue
            observed_expression_ids.add(id(current))
            if unshadowed_builtin_name(current, builtin_names):
                return True
            if isinstance(current, ast.Subscript):
                pending.extend(selected_subscript_expressions(current))
                continue
            if isinstance(current, ast.NamedExpr):
                pending.append(current.value)
                continue
            if isinstance(current, ast.IfExp):
                pending.extend((current.body, current.orelse))
                continue
            if isinstance(current, ast.BoolOp):
                pending.extend(current.values)
                continue
            if not isinstance(current, ast.Name) or not isinstance(
                current.ctx, ast.Load
            ):
                continue
            key = name_load_binding_key(current)
            if key in observed_binding_keys:
                continue
            observed_binding_keys.add(key)
            if any(
                imported_name in builtin_names
                and event_may_reach_load(current, key, event_id)
                for event_id, imported_name in static_builtin_import_bindings.get(
                    key, ()
                )
            ):
                return True
            pending.extend(decoder_binding_sources(key, current))
        return False

    def reflective_callable_modules(
        selector: ast.AST,
        qualified_names: frozenset[str],
    ) -> frozenset[str]:
        all_modules = frozenset(
            qualified_name.rsplit(".", 1)[0] for qualified_name in qualified_names
        )
        selected_name = evaluate_binding_expression(selector)
        if selected_name is not_pure:
            return all_modules
        if type(selected_name) is not str:
            return frozenset()
        return frozenset(
            qualified_name.rsplit(".", 1)[0]
            for qualified_name in qualified_names
            if qualified_name.rsplit(".", 1)[1] == selected_name
        )

    def has_static_module_namespace_origin(
        node: ast.AST,
        module_names: frozenset[str],
    ) -> bool:
        namespaces = frozenset(
            f"{module_name}.__dict__" for module_name in module_names
        )
        if namespaces and has_static_module_origin(node, namespaces):
            return True
        if (
            isinstance(node, ast.Call)
            and len(node.args) in {2, 3}
            and not node.keywords
            and has_static_builtin_origin(node.func, frozenset({"getattr"}))
        ):
            selected_name = evaluate_binding_expression(node.args[1])
            if (
                selected_name is not_pure or selected_name == "__dict__"
            ) and has_static_module_origin(node.args[0], module_names):
                return True
        return bool(
            isinstance(node, ast.Call)
            and len(node.args) == 1
            and not node.keywords
            and has_static_builtin_origin(node.func, frozenset({"vars"}))
            and has_static_module_origin(node.args[0], module_names)
        )

    def has_static_module_namespace_accessor_origin(
        node: ast.AST,
        module_names: frozenset[str],
    ) -> bool:
        pending = [node]
        observed_expression_ids: set[int] = set()
        observed_binding_keys: set[tuple[int, str]] = set()
        while pending:
            charge_origin()
            current = pending.pop()
            if id(current) in observed_expression_ids:
                continue
            observed_expression_ids.add(id(current))
            if (
                isinstance(current, ast.Attribute)
                and current.attr in {"__getitem__", "get"}
                and has_static_module_namespace_origin(current.value, module_names)
            ):
                return True
            if (
                isinstance(current, ast.Call)
                and len(current.args) in {2, 3}
                and not current.keywords
                and has_static_builtin_origin(current.func, frozenset({"getattr"}))
            ):
                accessor_name = evaluate_binding_expression(current.args[1])
                if (
                    accessor_name is not_pure or accessor_name in {"__getitem__", "get"}
                ) and has_static_module_namespace_origin(current.args[0], module_names):
                    return True
            if not isinstance(current, ast.Name) or not isinstance(
                current.ctx, ast.Load
            ):
                continue
            key = name_load_binding_key(current)
            if key in observed_binding_keys:
                continue
            observed_binding_keys.add(key)
            pending.extend(decoder_binding_sources(key, current))
        return False

    def has_static_callable_origin(
        node: ast.AST,
        qualified_names: frozenset[str],
        builtin_names: frozenset[str] = frozenset(),
    ) -> bool:
        all_qualified_modules = frozenset(
            qualified_name.rsplit(".", 1)[0] for qualified_name in qualified_names
        )
        pending = [node]
        observed_expression_ids: set[int] = set()
        observed_binding_keys: set[tuple[int, str]] = set()
        while pending:
            charge_origin()
            current = pending.pop()
            if id(current) in observed_expression_ids:
                continue
            observed_expression_ids.add(id(current))
            if unshadowed_builtin_name(current, builtin_names):
                return True
            if isinstance(current, ast.Call):
                if (
                    current.args
                    and all_qualified_modules
                    and has_static_module_namespace_accessor_origin(
                        current.func, all_qualified_modules
                    )
                ):
                    module_names = reflective_callable_modules(
                        current.args[0], qualified_names
                    )
                    if module_names and has_static_module_namespace_accessor_origin(
                        current.func, module_names
                    ):
                        return True
                if (
                    len(current.args) in {2, 3}
                    and not current.keywords
                    and has_static_builtin_origin(current.func, frozenset({"getattr"}))
                ):
                    module_names = reflective_callable_modules(
                        current.args[1], qualified_names
                    )
                    if module_names and has_static_module_origin(
                        current.args[0], module_names
                    ):
                        return True
                if (
                    isinstance(current.func, ast.Attribute)
                    and current.func.attr == "get"
                    and current.args
                    and all_qualified_modules
                    and has_static_module_namespace_origin(
                        current.func.value, all_qualified_modules
                    )
                ):
                    module_names = reflective_callable_modules(
                        current.args[0], qualified_names
                    )
                    if module_names and has_static_module_namespace_origin(
                        current.func.value, module_names
                    ):
                        return True
                if (
                    len(current.args) >= 2
                    and all_qualified_modules
                    and has_static_module_namespace_origin(
                        current.args[0], all_qualified_modules
                    )
                ):
                    module_names = reflective_callable_modules(
                        current.args[1], qualified_names
                    )
                    if module_names and has_static_module_namespace_origin(
                        current.args[0], module_names
                    ):
                        return True
                pending.extend(current.args)
                pending.extend(keyword.value for keyword in current.keywords)
                continue
            if isinstance(current, ast.Subscript):
                if all_qualified_modules and has_static_module_namespace_origin(
                    current.value, all_qualified_modules
                ):
                    module_names = reflective_callable_modules(
                        current.slice, qualified_names
                    )
                    if module_names and has_static_module_namespace_origin(
                        current.value, module_names
                    ):
                        return True
                if isinstance(current.value, (ast.Tuple, ast.List)):
                    selector = normalized_literal_selector(current.slice)
                    if type(selector) is int:
                        try:
                            pending.append(current.value.elts[selector])
                        except IndexError:
                            pass
                        continue
                if isinstance(current.value, ast.Dict):
                    selector = evaluate_binding_expression(current.slice)
                    if selector is not not_pure:
                        matched = False
                        for key_node, value_node in zip(
                            current.value.keys, current.value.values, strict=True
                        ):
                            if (
                                key_node is not None
                                and evaluate_binding_expression(key_node) == selector
                            ):
                                pending.append(value_node)
                                matched = True
                        if matched:
                            continue
                pending.append(current.value)
                continue
            if isinstance(current, ast.Attribute):
                module_names = frozenset(
                    qualified_name.rsplit(".", 1)[0]
                    for qualified_name in qualified_names
                    if qualified_name.rsplit(".", 1)[1] == current.attr
                )
                if module_names and has_static_module_origin(
                    current.value,
                    module_names,
                ):
                    return True
                continue
            if isinstance(current, (ast.Tuple, ast.List, ast.Set)):
                pending.extend(current.elts)
                continue
            if isinstance(current, ast.Dict):
                pending.extend(current.values)
                continue
            if isinstance(current, ast.IfExp):
                pending.extend((current.body, current.orelse))
                continue
            if isinstance(current, ast.BoolOp):
                pending.extend(current.values)
                continue
            if isinstance(current, (ast.Lambda, ast.NamedExpr)):
                pending.append(
                    current.body if isinstance(current, ast.Lambda) else current.value
                )
                continue
            if not isinstance(current, ast.Name) or not isinstance(
                current.ctx, ast.Load
            ):
                continue
            key = name_load_binding_key(current)
            for event_id, qualified_name in static_callable_import_bindings.get(
                key, ()
            ):
                if qualified_name in qualified_names and event_may_reach_load(
                    current, key, event_id
                ):
                    return True
            if key in observed_binding_keys:
                continue
            observed_binding_keys.add(key)
            pending.extend(decoder_binding_sources(key, current))
        return False

    def has_static_binary_decoder_origin(node: ast.AST) -> bool:
        return has_static_callable_origin(
            node,
            static_binary_decoder_qualified_names,
        )

    def has_static_dynamic_import_origin(node: ast.AST) -> bool:
        return has_static_callable_origin(
            node,
            import_resolver_qualified_names,
            static_import_builtin_names,
        )

    def evaluate_static_text_operator_call(
        node: ast.Call,
        evaluate_node: Callable[[ast.AST], Any],
    ) -> Any:
        concatenates = has_static_callable_origin(
            node.func,
            static_text_concatenation_qualified_names,
        )
        if concatenates:
            operation = "concatenate"
        elif has_static_callable_origin(
            node.func,
            static_text_repetition_qualified_names,
        ):
            operation = "repeat"
        elif has_static_callable_origin(
            node.func,
            static_text_format_qualified_names,
        ):
            operation = "format"
        else:
            return not_pure
        if (
            len(node.args) != 2
            or any(isinstance(argument, ast.Starred) for argument in node.args)
            or node.keywords
        ):
            return not_pure
        left = evaluate_node(node.args[0])
        right = evaluate_node(node.args[1])
        if left is not_pure or right is not_pure:
            return not_pure
        if operation == "format":
            if not isinstance(left, (str, bytes)):
                return not_pure
            return bootstrap_v2_python_percent_format(left, right)
        if operation == "repeat":
            if isinstance(left, (str, bytes)) and type(right) in {bool, int}:
                text_value = left
                multiplier = int(right)
            elif type(left) in {bool, int} and isinstance(right, (str, bytes)):
                text_value = right
                multiplier = int(left)
            elif isinstance(left, (str, bytes)) or isinstance(right, (str, bytes)):
                raise ValueError(
                    "Python static text operator uses an unsupported repeat type"
                )
            else:
                return not_pure
            repeated_size = bootstrap_v2_python_payload_size(text_value) * max(
                multiplier,
                0,
            )
            if repeated_size > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES:
                raise ValueError(
                    "Python static text operator exceeds the trusted byte limit"
                )
            return text_value * multiplier
        if not isinstance(left, (str, bytes)) and not isinstance(right, (str, bytes)):
            return not_pure
        if not isinstance(left, (str, bytes)) or not isinstance(right, (str, bytes)):
            raise ValueError(
                "Python static text operator uses an unsupported literal type"
            )
        if type(left) is not type(right):
            raise ValueError("Python static text operator mixes text and bytes")
        combined_size = sum(
            bootstrap_v2_python_payload_size(part) for part in (left, right)
        )
        if combined_size > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES:
            raise ValueError(
                "Python static text operator exceeds the trusted byte limit"
            )
        return left + right

    value_input_cache: dict[int, bool | None] = {}

    def value_has_static_decoder_input(value: Any) -> bool:
        charge()
        if type(value) in {str, bytes}:
            return bool(value)
        if type(value) not in {tuple, list, dict}:
            return False
        value_id = id(value)
        if value_id in value_input_cache:
            cached = value_input_cache[value_id]
            if cached is None:
                raise ValueError("Python static decoder input contains a cycle")
            return cached
        value_input_cache[value_id] = None
        children = (
            value
            if type(value) in {tuple, list}
            else (child for pair in value.items() for child in pair)
        )
        result = any(value_has_static_decoder_input(child) for child in children)
        value_input_cache[value_id] = result
        return result

    def direct_static_input(node: ast.AST) -> bool:
        value = evaluated.get(id(node), not_pure)
        result = value is not not_pure and value_has_static_decoder_input(value)
        if not result:
            for child in ast.walk(node):
                charge()
                if (
                    isinstance(child, ast.Constant)
                    and type(child.value) in {str, bytes}
                    and child.value
                ):
                    result = True
                    break
        return result

    def static_receiver_input(node: ast.AST) -> bool:
        if expression_is_closed_static_value(node):
            return True
        if not isinstance(node, ast.Call) or not has_static_callable_origin(
            node.func,
            static_byte_constructor_qualified_names,
        ):
            return False
        sources = tuple(
            argument.value if isinstance(argument, ast.Starred) else argument
            for argument in node.args
        ) + tuple(keyword.value for keyword in node.keywords)
        return bool(sources) and all(
            evaluate_binding_expression(source) is not not_pure
            or expression_is_closed_static_value(source)
            for source in sources
        )

    def has_static_decoder_input(node: ast.AST) -> bool:
        return static_input_origin(node, False)

    def unresolved_static_binary_decoder_call(node: ast.AST) -> bool:
        if not isinstance(node, ast.Call) or not (
            has_static_binary_decoder_origin(node.func)
        ):
            return False
        return any(
            has_static_decoder_input(source)
            for source in call_source_nodes(node, decoder_source_keyword_names)
        )

    def call_source_nodes(
        node: ast.Call,
        keyword_names: frozenset[str],
    ) -> tuple[ast.AST, ...]:
        if node.args:
            first = node.args[0]
            return (first.value if isinstance(first, ast.Starred) else first,)
        return tuple(
            keyword.value for keyword in node.keywords if keyword.arg in keyword_names
        )

    def dynamic_code_call_uses_static_input(node: ast.Call) -> bool:
        if not has_static_callable_origin(
            node.func, frozenset(), dynamic_code_builtin_names
        ):
            return False
        return any(
            evaluate_binding_expression(source) is not not_pure
            or expression_is_closed_static_value(source)
            for source in call_source_nodes(node, frozenset({"source"}))
        )

    def dynamic_import_call_uses_decoder_module(node: ast.Call) -> bool:
        if not has_static_dynamic_import_origin(node.func):
            return False
        for source in call_source_nodes(node, frozenset({"name"})):
            imported_name = evaluate_binding_expression(source)
            if isinstance(imported_name, str) and any(
                imported_name == module_name
                or module_name.startswith(f"{imported_name}.")
                for module_name in static_binary_decoder_modules
            ):
                return True
        return False

    resolved_bindings: dict[
        tuple[int, str],
        tuple[ast.Assign | ast.AnnAssign, Any],
    ] = {}
    loaded_binding_keys = {
        name_load_binding_key(node)
        for node in nodes
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }
    for key, candidates in binding_candidates.items():
        if (
            key not in loaded_binding_keys
            or key in hard_ambiguous_binding_keys
            or len(candidates) != 1
        ):
            continue
        binding_value = resolve_binding(key)
        if binding_value is not_pure:
            continue
        resolved_bindings[key] = (candidates[0][0], binding_value)

    def record_constructed(node: ast.AST, result: str | bytes) -> None:
        nonlocal evaluated_bytes, evaluated_value_count
        payload_size = evaluated_text_payload_size(result)
        if payload_size > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES:
            raise ValueError("Python evaluated string exceeds the trusted byte limit")
        charge_retained_evaluated_value(node, result)
        evaluated_value_count += 1
        if evaluated_value_count > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUES:
            raise ValueError("Python AST exceeds the trusted evaluated value limit")
        evaluated_bytes += payload_size
        if evaluated_bytes > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_BYTES:
            raise ValueError(
                "Python AST evaluated strings exceed the trusted byte limit"
            )
        if isinstance(result, str):
            constructed[id(node)] = result
        else:
            try:
                result.decode("utf-8")
            except UnicodeDecodeError:
                opaque_text = result.decode("latin-1")
                if bootstrap_v2_privacy_risk_lines(opaque_text):
                    constructed[id(node)] = opaque_text
            else:
                constructed[id(node)] = result

    constructed_container_values: dict[tuple[int, int], str | bytes] = {}
    recorded_constructed_result_ids: set[int] = set()

    def record_constructed_result(node: ast.AST, result: Any) -> None:
        nonlocal evaluated_bytes, evaluated_value_count
        node_id = id(node)
        if node_id in recorded_constructed_result_ids:
            return
        recorded_constructed_result_ids.add(node_id)
        if type(result) in {str, bytes}:
            record_constructed(node, result)
            return
        pending = [result]
        observed = 0
        discovered: list[str | bytes] = []
        while pending:
            observed += 1
            if observed > BOOTSTRAP_V2_MAX_PYTHON_AST_NODES:
                raise ValueError(
                    "Python deterministic text method result exceeds the trusted item limit"
                )
            current = pending.pop()
            if type(current) in {str, bytes}:
                discovered.append(current)
            elif type(current) in {tuple, list}:
                pending.extend(reversed(current))
            elif type(current) is dict:
                for key, child in current.items():
                    pending.extend((key, child))
        for index, child in enumerate(discovered):
            payload_size = evaluated_text_payload_size(child)
            if payload_size > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES:
                raise ValueError(
                    "Python evaluated string exceeds the trusted byte limit"
                )
            evaluated_value_count += 1
            if evaluated_value_count > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUES:
                raise ValueError("Python AST exceeds the trusted evaluated value limit")
            evaluated_bytes += payload_size
            if evaluated_bytes > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_BYTES:
                raise ValueError(
                    "Python AST evaluated strings exceed the trusted byte limit"
                )
            if isinstance(child, str):
                constructed_container_values[(node_id, index)] = child
            else:
                try:
                    child.decode("utf-8")
                except UnicodeDecodeError:
                    opaque_text = child.decode("latin-1")
                    if bootstrap_v2_privacy_risk_lines(opaque_text):
                        constructed_container_values[(node_id, index)] = opaque_text
                else:
                    constructed_container_values[(node_id, index)] = child

    partial_values: dict[int, str | bytes] = {}

    def retain_partial(node: ast.AST, result: str | bytes) -> None:
        nonlocal evaluated_bytes, evaluated_value_count
        result_text = evaluated_text_risk_view(result)
        payload_size = evaluated_text_payload_size(result)
        if payload_size > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES:
            raise ValueError("Python evaluated string exceeds the trusted byte limit")
        existing = partial_values.get(id(node))
        existing_size = (
            evaluated_text_payload_size(existing) if existing is not None else 0
        )
        next_value_count = evaluated_value_count + (existing is None)
        next_evaluated_bytes = evaluated_bytes - existing_size + payload_size
        if next_value_count > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUES:
            raise ValueError("Python AST exceeds the trusted evaluated value limit")
        if next_evaluated_bytes > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_BYTES:
            raise ValueError(
                "Python AST evaluated strings exceed the trusted byte limit"
            )
        charge_retained_evaluated_value(node, result)
        evaluated_value_count = next_value_count
        evaluated_bytes = next_evaluated_bytes
        partial_values[id(node)] = result
        if bootstrap_v2_privacy_risk_lines(result_text):
            constructed[id(node)] = result

    def concatenate_fragment_values(
        fragments: tuple[str | bytes | None, ...],
    ) -> str | bytes | None:
        known = tuple(fragment for fragment in fragments if fragment is not None)
        if not known:
            return None
        expected_type = type(known[0])
        if any(type(fragment) is not expected_type for fragment in known):
            raise ValueError("Python partial construction mixes text and bytes")
        combined_size = sum(evaluated_text_payload_size(fragment) for fragment in known)
        if combined_size > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES:
            raise ValueError(
                "Python partial construction exceeds the trusted byte limit"
            )
        if expected_type is str:
            return "".join(known)
        return b"".join(known)

    recorded_literal_binding_statements: set[int] = set()
    for key, (assignment, binding) in resolved_bindings.items():
        assigned_value = binding_candidates[key][0][1]
        if (
            id(assignment) not in recorded_literal_binding_statements
            and isinstance(assigned_value, ast.Constant)
            and type(binding) in {str, bytes}
        ):
            record_constructed(assignment, binding)
            recorded_literal_binding_statements.add(id(assignment))

    ambiguous_receiver_cache: dict[int, tuple[bool, tuple[Any, ...]]] = {}
    ambiguous_receiver_operations = 0
    ambiguous_receiver_retained_states = 0
    ambiguous_receiver_cached_value_ids: set[int] = set()
    ambiguous_receiver_cached_bytes = 0
    ambiguous_receiver_operation_limit = min(
        max(node_count * 32, 1),
        BOOTSTRAP_V2_MAX_PYTHON_METHOD_SELECTION_OPERATIONS,
    )

    def consume_ambiguous_receiver_operation() -> None:
        nonlocal ambiguous_receiver_operations
        if ambiguous_receiver_operations >= ambiguous_receiver_operation_limit:
            raise ValueError(
                "Python ambiguous receiver analysis exceeds the trusted operation limit"
            )
        ambiguous_receiver_operations += 1

    def charge_ambiguous_receiver_state() -> None:
        nonlocal ambiguous_receiver_retained_states
        next_states = ambiguous_receiver_retained_states + 1
        if next_states > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUES:
            raise ValueError(
                "Python ambiguous receiver analysis exceeds the trusted state limit"
            )
        ambiguous_receiver_retained_states = next_states

    def charge_ambiguous_receiver_cache(values: tuple[Any, ...]) -> None:
        nonlocal ambiguous_receiver_cached_bytes
        for value in values:
            if type(value) not in {str, bytes}:
                continue
            value_id = id(value)
            if value_id in ambiguous_receiver_cached_value_ids:
                continue
            next_bytes = ambiguous_receiver_cached_bytes + evaluated_text_payload_size(
                value
            )
            if next_bytes > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_BYTES:
                raise ValueError(
                    "Python ambiguous receiver cache exceeds the trusted byte limit"
                )
            ambiguous_receiver_cached_value_ids.add(value_id)
            ambiguous_receiver_cached_bytes = next_bytes

    def ambiguous_static_receiver_values(
        expression: ast.AST,
    ) -> tuple[bool, tuple[Any, ...]]:
        cached = ambiguous_receiver_cache.get(id(expression))
        if cached is not None:
            return cached

        expressions: dict[int, ast.AST] = {}
        dependents: dict[int, set[int]] = {}
        call_method_names: dict[int, str] = {}
        forced_ambiguous_ids: set[int] = set()
        direct_values: dict[int, Any] = {}
        pending = [expression]
        while pending:
            consume_ambiguous_receiver_operation()
            current = pending.pop()
            current_id = id(current)
            if current_id in expressions:
                continue
            expressions[current_id] = current
            current_dependencies: tuple[ast.AST, ...] = ()
            if isinstance(current, ast.Name) and isinstance(current.ctx, ast.Load):
                key = name_load_binding_key(current)
                if key in ambiguous_binding_keys:
                    current_dependencies = ambiguous_selection_sources(key, current)
                    forced_ambiguous_ids.add(current_id)
                else:
                    current_dependencies = tuple(decoder_binding_sources(key, current))
                    if len(current_dependencies) > 1:
                        forced_ambiguous_ids.add(current_id)
                if key in function_parameter_binding_keys and any(
                    parameter_default_may_reach_load(current, key, event_id)
                    for event_id, _ in parameter_default_sources.get(key, ())
                ):
                    forced_ambiguous_ids.add(current_id)
            elif isinstance(current, ast.Call) and isinstance(
                current.func,
                ast.Attribute,
            ):
                current_dependencies = (current.func.value,)
                call_method_names[current_id] = current.func.attr
            elif isinstance(current, ast.Attribute):
                current_dependencies = (current.value,)
            elif isinstance(current, ast.Subscript):
                current_dependencies = selected_subscript_expressions(current)
                if len(current_dependencies) > 1:
                    forced_ambiguous_ids.add(current_id)
            elif isinstance(current, ast.NamedExpr):
                current_dependencies = (current.value,)
            elif isinstance(current, ast.IfExp):
                current_dependencies = (current.body, current.orelse)
                forced_ambiguous_ids.add(current_id)
            elif isinstance(current, ast.BoolOp):
                current_dependencies = tuple(current.values)
                if len(current_dependencies) > 1:
                    forced_ambiguous_ids.add(current_id)

            for child in current_dependencies:
                child_id = id(child)
                dependents.setdefault(child_id, set()).add(current_id)
                pending.append(child)
            direct = evaluate_binding_expression(current)
            if type(direct) in {str, bytes, int} or direct is int:
                direct_values[current_id] = direct

        state_ambiguity = {expression_id: False for expression_id in expressions}
        state_values: dict[int, dict[int, Any]] = {
            expression_id: {} for expression_id in expressions
        }
        events: list[tuple[int, bool, int | None]] = []
        retained_value_ids: set[int] = set()
        retained_value_bytes = 0

        def mark_ambiguous(expression_id: int) -> None:
            if state_ambiguity[expression_id]:
                return
            state_ambiguity[expression_id] = True
            events.append((expression_id, True, None))

        def add_value(expression_id: int, value: Any) -> None:
            nonlocal retained_value_bytes
            key = id(value)
            if key in state_values[expression_id]:
                return
            charge_ambiguous_receiver_state()
            if type(value) in {str, bytes} and id(value) not in retained_value_ids:
                next_bytes = retained_value_bytes + evaluated_text_payload_size(value)
                if next_bytes > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_BYTES:
                    raise ValueError(
                        "Python ambiguous receiver analysis exceeds the trusted "
                        "byte limit"
                    )
                retained_value_ids.add(id(value))
                retained_value_bytes = next_bytes
            state_values[expression_id][key] = value
            events.append((expression_id, False, key))

        for expression_id in forced_ambiguous_ids:
            mark_ambiguous(expression_id)
        for expression_id, value in direct_values.items():
            add_value(expression_id, value)

        event_index = 0
        while event_index < len(events):
            consume_ambiguous_receiver_operation()
            source_id, ambiguity_event, value_key = events[event_index]
            event_index += 1
            for dependent_id in dependents.get(source_id, ()):
                consume_ambiguous_receiver_operation()
                if ambiguity_event:
                    mark_ambiguous(dependent_id)
                    continue
                assert value_key is not None
                receiver = state_values[source_id][value_key]
                method_name = call_method_names.get(dependent_id)
                if method_name is None:
                    add_value(dependent_id, receiver)
                    continue
                current = expressions[dependent_id]
                assert isinstance(current, ast.Call)
                consume_ambiguous_receiver_operation()
                if method_name == "to_bytes" and (
                    type(receiver) is int or receiver is int
                ):
                    result = evaluate_static_int_to_bytes_call(
                        current,
                        evaluate_binding_expression,
                        receiver_override=receiver,
                    )
                else:
                    result = evaluate_bound_string_method_call(
                        current,
                        bound_string_method_value(method_name, receiver),
                        evaluate_binding_expression,
                    )
                if type(result) in {str, bytes, int} or result is int:
                    add_value(dependent_id, result)

        expression_id = id(expression)
        result = (
            state_ambiguity[expression_id],
            tuple(state_values[expression_id].values()),
        )
        charge_ambiguous_receiver_cache(result[1])
        ambiguous_receiver_cache[expression_id] = result
        return result

    int_to_bytes_origin_cache: dict[
        int,
        tuple[tuple[ast.AST, ...], tuple[ast.AST, ...], bool],
    ] = {}
    int_to_bytes_origin_operations = 0
    int_to_bytes_origin_operation_limit = min(
        max(node_count * 8, 1),
        BOOTSTRAP_V2_MAX_PYTHON_METHOD_SELECTION_OPERATIONS,
    )

    def consume_int_to_bytes_origin_operation() -> None:
        nonlocal int_to_bytes_origin_operations
        if int_to_bytes_origin_operations >= int_to_bytes_origin_operation_limit:
            raise ValueError(
                "Python int.to_bytes origin analysis exceeds the trusted "
                "operation limit"
            )
        int_to_bytes_origin_operations += 1

    def int_to_bytes_receiver_sources(
        expression: ast.AST,
    ) -> tuple[tuple[ast.AST, ...], tuple[ast.AST, ...], bool]:
        cached = int_to_bytes_origin_cache.get(id(expression))
        if cached is not None:
            return cached
        pending = [expression]
        observed_expression_ids: set[int] = set()
        receivers: dict[int, ast.AST] = {}
        unresolved: dict[int, ast.AST] = {}
        origin_is_ambiguous = False
        while pending:
            consume_int_to_bytes_origin_operation()
            current = pending.pop()
            if id(current) in observed_expression_ids:
                continue
            observed_expression_ids.add(id(current))
            if isinstance(current, ast.Attribute) and current.attr == "to_bytes":
                receivers[id(current.value)] = current.value
                pending.append(current.value)
                continue
            if (
                isinstance(current, ast.Call)
                and len(current.args) in {2, 3}
                and not current.keywords
                and has_static_builtin_origin(
                    current.func,
                    frozenset({"getattr"}),
                )
            ):
                method_name = evaluate_binding_expression(current.args[1])
                if method_name == "to_bytes":
                    receivers[id(current.args[0])] = current.args[0]
                elif method_name is not_pure:
                    unresolved[id(current.args[0])] = current.args[0]
                receiver = evaluate_binding_expression(current.args[0])
                if len(current.args) == 3 and static_getattr_default_is_possible(
                    receiver,
                    method_name,
                ):
                    origin_is_ambiguous = True
                    pending.append(current.args[2])
                pending.append(current.func)
                continue
            if isinstance(current, ast.Name) and isinstance(current.ctx, ast.Load):
                key = name_load_binding_key(current)
                origin_is_ambiguous = (
                    origin_is_ambiguous
                    or key in ambiguous_binding_keys
                    or key in function_parameter_binding_keys
                )
                pending.extend(decoder_binding_sources(key, current))
                continue
            if isinstance(current, ast.Subscript):
                selected = selected_subscript_expressions(current)
                origin_is_ambiguous = origin_is_ambiguous or len(selected) > 1
                pending.extend(selected)
                continue
            if isinstance(current, ast.NamedExpr):
                pending.append(current.value)
                continue
            if isinstance(current, ast.IfExp):
                origin_is_ambiguous = True
                pending.extend((current.body, current.orelse))
                continue
            if isinstance(current, ast.BoolOp):
                origin_is_ambiguous = origin_is_ambiguous or len(current.values) > 1
                pending.extend(current.values)
        result = (
            tuple(receivers.values()),
            tuple(unresolved.values()),
            origin_is_ambiguous,
        )
        int_to_bytes_origin_cache[id(expression)] = result
        return result

    ambiguous_result_items = 0
    ambiguous_result_bytes = 0

    def ambiguous_result_contains_privacy_risk(result: Any) -> bool:
        nonlocal ambiguous_result_bytes, ambiguous_result_items
        pending = [result]
        while pending:
            ambiguous_result_items += 1
            if ambiguous_result_items > BOOTSTRAP_V2_MAX_PYTHON_AST_NODES:
                raise ValueError(
                    "Python ambiguous text method result exceeds the trusted item limit"
                )
            current = pending.pop()
            if type(current) in {str, bytes}:
                payload_size = evaluated_text_payload_size(current)
                if payload_size > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES:
                    raise ValueError(
                        "Python ambiguous text method result exceeds the trusted "
                        "byte limit"
                    )
                ambiguous_result_bytes += payload_size
                if ambiguous_result_bytes > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_BYTES:
                    raise ValueError(
                        "Python ambiguous text method results exceed the trusted byte limit"
                    )
                if isinstance(current, bytes):
                    try:
                        text = current.decode("utf-8")
                    except UnicodeDecodeError:
                        text = current.decode("latin-1")
                else:
                    text = current
                if bootstrap_v2_privacy_risk_lines(text):
                    return True
            elif type(current) in {tuple, list}:
                pending.extend(current)
            elif type(current) is dict:
                for key, child in current.items():
                    pending.extend((key, child))
        return False

    def ambiguous_int_to_bytes_constructs_privacy_risk(node: ast.Call) -> bool:
        (
            receiver_sources,
            unresolved_sources,
            origin_is_ambiguous,
        ) = int_to_bytes_receiver_sources(node.func)
        for source in unresolved_sources:
            value = evaluate_binding_expression(source)
            is_ambiguous, receivers = ambiguous_static_receiver_values(source)
            if (
                value is int
                or type(value) is int
                or has_static_builtin_origin(source, frozenset({"int"}))
                or (
                    is_ambiguous
                    and any(
                        receiver is int or type(receiver) is int
                        for receiver in receivers
                    )
                )
            ):
                raise ValueError(
                    "Python deterministic int method uses an unresolved int method "
                    f"at line {getattr(node, 'lineno', 0)}"
                )
        candidates: dict[tuple[type[Any], Any], Any] = {}
        receiver_requires_scan = origin_is_ambiguous
        for source in receiver_sources:
            value = evaluate_binding_expression(source)
            if value is int or type(value) is int:
                candidates[(type(value), value)] = value
            if value is not int and has_static_builtin_origin(
                source, frozenset({"int"})
            ):
                candidates[(type, int)] = int
                receiver_requires_scan = True
            is_ambiguous, receivers = ambiguous_static_receiver_values(source)
            receiver_requires_scan = receiver_requires_scan or is_ambiguous
            for receiver in receivers:
                if receiver is int or type(receiver) is int:
                    candidates[(type(receiver), receiver)] = receiver
        if not receiver_requires_scan:
            return False
        for receiver in candidates.values():
            result = evaluate_static_int_to_bytes_call(
                node,
                evaluate_binding_expression,
                receiver_override=receiver,
            )
            if result is not not_pure and ambiguous_result_contains_privacy_risk(
                result
            ):
                return True
        return False

    def ambiguous_method_constructs_privacy_risk(node: ast.Call) -> bool:
        if not isinstance(node.func, ast.Attribute):
            return False
        is_ambiguous, receivers = ambiguous_static_receiver_values(node.func.value)
        if not is_ambiguous:
            return False
        for receiver in receivers:
            method_value = bound_string_method_value(node.func.attr, receiver)
            result = evaluate_bound_string_method_call(
                node,
                method_value,
                evaluate_binding_expression,
            )
            if result is not not_pure and ambiguous_result_contains_privacy_risk(
                result
            ):
                return True
        return False

    for node in reversed(nodes):
        if isinstance(node, ast.Call) and dynamic_code_call_uses_static_input(node):
            raise ValueError(
                "Python dynamic code primitive uses static input "
                f"at line {getattr(node, 'lineno', 0)}"
            )
        if isinstance(node, ast.Call) and dynamic_import_call_uses_decoder_module(node):
            raise ValueError(
                "Python decoder module uses a dynamic import "
                f"at line {getattr(node, 'lineno', 0)}"
            )
        depends_on_ambiguous_binding = id(node) in fail_closed_binding_expression_ids
        is_supported_string_constructor = (
            (
                isinstance(node, ast.BinOp)
                and isinstance(node.op, (ast.Add, ast.Mult, ast.Mod))
                and binding_expression_may_output_text(node)
            )
            or isinstance(node, ast.JoinedStr)
            or (
                isinstance(node, ast.Subscript)
                and binding_expression_may_output_text(node)
            )
        )
        if isinstance(node, ast.AugAssign):
            is_supported_string_constructor = isinstance(
                node.op, (ast.Add, ast.Mult, ast.Mod)
            ) and augassign_may_output_text(node)
        if isinstance(node, ast.Call):
            method_kinds = bound_string_method_kinds(node.func)
            is_supported_string_constructor = (
                is_supported_string_constructor
                or bool(method_kinds - {unresolved_int_method_kind})
                or has_static_callable_origin(
                    node.func,
                    static_text_operator_qualified_names,
                )
            )
            constructor = unshadowed_deterministic_text_builtin(node.func)
            if any(
                constructor is candidate for candidate in (bytearray, bytes, chr, str)
            ):
                constructor_result = evaluate_binding_expression(node)
                is_supported_string_constructor = (
                    is_supported_string_constructor
                    or type(constructor_result) in {str, bytes}
                )
            int_to_bytes_result = evaluate_static_int_to_bytes_call(
                node,
                evaluate_binding_expression,
            )
            is_supported_string_constructor = (
                is_supported_string_constructor or type(int_to_bytes_result) is bytes
            )
            reflected_method_call = (
                isinstance(node.func, ast.Call)
                and len(node.func.args) in {2, 3}
                and not node.func.keywords
                and has_static_builtin_origin(
                    node.func.func,
                    frozenset({"getattr"}),
                )
            )
            if (
                bool(method_kinds & {"to_bytes", unresolved_int_method_kind})
                or reflected_method_call
            ) and ambiguous_int_to_bytes_constructs_privacy_risk(node):
                raise ValueError(
                    "Python string construction depends on an ambiguous name binding "
                    f"at line {getattr(node, 'lineno', 0)}"
                )
        ambiguity_sensitive_constructor = is_supported_string_constructor
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr not in {"format", "format_map", "join"}
        ):
            ambiguity_sensitive_constructor = ambiguous_method_constructs_privacy_risk(
                node
            )
        if isinstance(node, ast.Subscript):
            ambiguity_sensitive_constructor = False
        if (
            isinstance(node, ast.AugAssign)
            and id(node) in unresolved_augassign_receiver_ids
            and isinstance(node.op, (ast.Add, ast.Mult, ast.Mod))
        ):
            raise ValueError(
                "Python string construction uses an unresolved augmented assignment "
                f"receiver at line {getattr(node, 'lineno', 0)}"
            )
        augassign_has_risk_seed = not isinstance(node, ast.AugAssign) or (
            id(node) in risk_text_seeded_expression_ids
            or any(
                key in explicitly_ambiguous_binding_keys
                for key in augassign_binding_keys_by_id.get(id(node), ())
            )
        )
        if (
            depends_on_ambiguous_binding
            and ambiguity_sensitive_constructor
            and augassign_has_risk_seed
        ):
            raise ValueError(
                "Python string construction depends on an ambiguous name binding "
                f"at line {getattr(node, 'lineno', 0)}"
            )

        cached_binding_value = binding_expression_cache.get(id(node), not_pure)
        if cached_binding_value is not not_pure:
            evaluated[id(node)] = cached_binding_value
            if is_supported_string_constructor:
                record_constructed_result(node, cached_binding_value)
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                    for child in (node.left, node.right):
                        if isinstance(child, ast.BinOp) and isinstance(
                            child.op, ast.Add
                        ):
                            nested_pure_adds.add(id(child))
            continue

        if isinstance(node, ast.Constant):
            if node.value is None or type(node.value) in {
                bool,
                bytes,
                complex,
                float,
                int,
                str,
            }:
                evaluated[id(node)] = node.value
            else:
                evaluated[id(node)] = not_pure
            continue

        if isinstance(node, ast.Name):
            binding_key = name_load_binding_key(node)
            binding = resolved_bindings.get(binding_key)
            if (
                binding is None
                or not isinstance(node.ctx, ast.Load)
                or not binding_is_usable_for_load(
                    node,
                    binding_key,
                    binding[0],
                )
            ):
                evaluated[id(node)] = (
                    unshadowed_deterministic_text_builtin(node)
                    or unshadowed_static_range_builtin(node)
                    or unshadowed_static_int_builtin(node)
                    or not_pure
                )
            else:
                evaluated[id(node)] = binding[1]
            continue

        if isinstance(node, ast.Subscript):
            container = evaluated.get(id(node.value), not_pure)
            selector: int | str | slice | None = normalized_literal_selector(node.slice)
            if selector is None:
                selector = normalized_literal_slice(node.slice)
            if selector is None or type(container) not in {
                str,
                bytes,
                tuple,
                list,
                dict,
            }:
                evaluated[id(node)] = not_pure
                continue
            try:
                evaluated[id(node)] = container[selector]
            except (IndexError, KeyError, TypeError):
                evaluated[id(node)] = not_pure
            selected_value = evaluated[id(node)]
            if selected_value is not not_pure and binding_expression_may_output_text(
                node
            ):
                record_constructed_result(node, selected_value)
            continue

        if isinstance(node, (ast.Tuple, ast.List)):
            children = [evaluated.get(id(child), not_pure) for child in node.elts]
            if any(child is not_pure for child in children):
                evaluated[id(node)] = not_pure
            elif isinstance(node, ast.Tuple):
                evaluated[id(node)] = tuple(children)
            else:
                evaluated[id(node)] = children
            continue

        if isinstance(node, ast.Dict):
            pairs: list[tuple[Any, Any]] = []
            pure_mapping = True
            for key_node, value_node in zip(node.keys, node.values, strict=True):
                if key_node is None:
                    pure_mapping = False
                    break
                key = evaluated.get(id(key_node), not_pure)
                child = evaluated.get(id(value_node), not_pure)
                if key is not_pure or child is not_pure:
                    pure_mapping = False
                    break
                pairs.append((key, child))
            if not pure_mapping:
                evaluated[id(node)] = not_pure
                continue
            try:
                evaluated[id(node)] = dict(pairs)
            except TypeError as exc:
                raise ValueError(
                    "Python deterministic mapping uses an unsupported key type"
                ) from exc
            continue

        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            operand = evaluated.get(id(node.operand), not_pure)
            if operand is not_pure or type(operand) not in {int, float, complex}:
                evaluated[id(node)] = not_pure
            elif isinstance(node.op, ast.UAdd):
                evaluated[id(node)] = +operand
            else:
                evaluated[id(node)] = -operand
            continue

        if isinstance(node, ast.BinOp):
            left = evaluated.get(id(node.left), not_pure)
            right = evaluated.get(id(node.right), not_pure)
            if left is not_pure or right is not_pure:
                evaluated[id(node)] = not_pure
                continue
            if isinstance(node.op, ast.Add):
                if not isinstance(left, (str, bytes)) and not isinstance(
                    right, (str, bytes)
                ):
                    evaluated[id(node)] = not_pure
                    continue
                if not isinstance(left, (str, bytes)) or not isinstance(
                    right, (str, bytes)
                ):
                    raise ValueError(
                        "Python constant addition uses an unsupported literal type"
                    )
                if type(left) is not type(right):
                    raise ValueError(
                        "Python constant addition mixes text and bytes literals"
                    )
                left_size = evaluated_text_payload_size(left)
                right_size = evaluated_text_payload_size(right)
                if (
                    left_size + right_size
                    > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES
                ):
                    raise ValueError(
                        "Python constant addition exceeds the trusted byte limit"
                    )
                combined = left + right
                evaluated[id(node)] = combined
                record_constructed(node, combined)
                for child in (node.left, node.right):
                    if isinstance(child, ast.BinOp) and isinstance(child.op, ast.Add):
                        nested_pure_adds.add(id(child))
                continue
            if isinstance(node.op, ast.Mult):
                if isinstance(left, (str, bytes)) and type(right) in {bool, int}:
                    text_value = left
                    multiplier = int(right)
                elif type(left) in {bool, int} and isinstance(right, (str, bytes)):
                    text_value = right
                    multiplier = int(left)
                elif isinstance(left, (str, bytes)) or isinstance(right, (str, bytes)):
                    raise ValueError(
                        "Python constant repetition uses an unsupported literal type"
                    )
                else:
                    evaluated[id(node)] = not_pure
                    continue
                payload_size = evaluated_text_payload_size(text_value)
                repeated_size = payload_size * max(multiplier, 0)
                if repeated_size > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES:
                    raise ValueError(
                        "Python constant repetition exceeds the trusted byte limit"
                    )
                repeated = text_value * multiplier
                evaluated[id(node)] = repeated
                record_constructed(node, repeated)
                continue
            if isinstance(node.op, ast.Mod) and isinstance(left, (str, bytes)):
                formatted = bootstrap_v2_python_percent_format(left, right)
                evaluated[id(node)] = formatted
                record_constructed(node, formatted)
                continue
            evaluated[id(node)] = not_pure
            continue

        if isinstance(node, ast.JoinedStr):
            is_pure = all(
                isinstance(child, ast.Constant)
                or (
                    isinstance(child, ast.FormattedValue)
                    and evaluated.get(id(child.value), not_pure) is not not_pure
                    and (
                        child.format_spec is None
                        or isinstance(
                            evaluated.get(id(child.format_spec), not_pure), str
                        )
                    )
                )
                for child in node.values
            )
            if not is_pure:
                evaluated[id(node)] = not_pure
                continue
            rendered_parts: list[str] = []
            rendered_size = 0
            for child in node.values:
                if isinstance(child, ast.Constant) and isinstance(child.value, str):
                    literal_size = evaluated_text_payload_size(child.value)
                    if (
                        literal_size
                        > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES - rendered_size
                    ):
                        raise ValueError(
                            "Python f-string exceeds the trusted byte limit"
                        )
                    rendered_parts.append(child.value)
                    rendered_size += literal_size
                    continue
                assert isinstance(child, ast.FormattedValue)
                child_value = evaluated.get(id(child.value), not_pure)
                assert child_value is not not_pure
                if child.format_spec is None:
                    format_spec = ""
                else:
                    format_spec = evaluated.get(id(child.format_spec), not_pure)
                    assert isinstance(format_spec, str)
                remaining_bytes = (
                    BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES - rendered_size
                )
                rendered_part = bootstrap_v2_python_formatted_value(
                    child_value,
                    conversion=child.conversion,
                    format_spec=format_spec,
                    max_output_bytes=remaining_bytes,
                )
                rendered_part_size = evaluated_text_payload_size(rendered_part)
                if rendered_part_size > remaining_bytes:
                    raise ValueError("Python f-string exceeds the trusted byte limit")
                rendered_parts.append(rendered_part)
                rendered_size += rendered_part_size
            rendered = "".join(rendered_parts)
            record_constructed(node, rendered)
            evaluated[id(node)] = rendered
            continue

        if isinstance(node, ast.Call) and any(
            (
                unshadowed_deterministic_text_builtin(node.func)
                or unshadowed_static_range_builtin(node.func)
            )
            is constructor
            for constructor in (bytearray, bytes, chr, range, str)
        ):
            constructor = unshadowed_deterministic_text_builtin(
                node.func
            ) or unshadowed_static_range_builtin(node.func)
            result = evaluate_deterministic_text_builtin_call(
                node,
                constructor,
                lambda child: evaluated.get(id(child), not_pure),
            )
            evaluated[id(node)] = result
            if result is not not_pure:
                record_constructed_result(node, result)
            continue

        if isinstance(node, ast.Call):
            result = evaluate_static_int_to_bytes_call(
                node,
                lambda child: evaluated.get(id(child), not_pure),
            )
            if result is not not_pure:
                evaluated[id(node)] = result
                record_constructed_result(node, result)
                continue

        if isinstance(node, ast.Call):
            result = evaluate_static_text_operator_call(
                node,
                lambda child: evaluated.get(id(child), not_pure),
            )
            if result is not not_pure:
                evaluated[id(node)] = result
                record_constructed_result(node, result)
                continue

        if isinstance(node, ast.Call) and unresolved_static_binary_decoder_call(node):
            raise ValueError(
                "Python unresolved binary decoder uses static text input "
                f"at line {getattr(node, 'lineno', 0)}"
            )

        if isinstance(node, ast.Call) and (
            bound_string_method_kinds(node.func) & bound_string_method_names
        ):
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in bound_string_method_names
            ):
                receiver = evaluated.get(id(node.func.value), not_pure)
                method_value = (
                    bound_string_method_value(node.func.attr, receiver)
                    if (
                        type(receiver) in {str, bytes}
                        or receiver is str
                        or receiver is bytes
                    )
                    else not_pure
                )
            else:
                method_value = evaluated.get(id(node.func), not_pure)
                if method_value is not_pure:
                    method_value = evaluate_binding_expression(node.func)
            direct_method_syntax = (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in bound_string_method_names
            )
            if method_value is not_pure and (
                not direct_method_syntax
                or (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in {"format", "format_map", "join"}
                    and id(node) in risk_text_seeded_expression_ids
                )
                or (
                    direct_method_syntax
                    and node.func.attr == "decode"
                    and static_receiver(node.func.value)
                )
            ):
                raise ValueError(
                    "Python string construction uses an unresolved bound string "
                    f"method at line {getattr(node, 'lineno', 0)}"
                )
            result = evaluate_bound_string_method_call(
                node,
                method_value,
                lambda child: evaluated.get(id(child), not_pure),
            )
            evaluated[id(node)] = result
            if result is not not_pure:
                record_constructed_result(node, result)
            continue

        evaluated[id(node)] = not_pure

    unknown_format_value = object()

    class PartialEvaluationLimitError(ValueError):
        pass

    partial_complete: set[int] = set()
    partial_resolution_stack: set[int] = set()
    partial_mapping_resolution_stack: set[int] = set()
    partial_recomputation_steps = 0
    partial_recomputation_limit = max(node_count * 4, 1)
    percent_field_re = re.compile(
        r"%(?:\((?P<key>[^)]*)\))?"
        r"(?P<flags>[#0\- +]*)"
        r"(?P<width>\*|[0-9]+)?"
        r"(?P<precision>\.(?:\*|[0-9]+))?"
        r"(?P<length>[hlL])?"
        r"(?P<conversion>[diouxXeEfFgGcrsab%])"
    )
    dot_formatter = string.Formatter()

    def consume_partial_step() -> None:
        nonlocal partial_recomputation_steps
        partial_recomputation_steps += 1
        if partial_recomputation_steps > partial_recomputation_limit:
            raise PartialEvaluationLimitError(
                "Python partial evaluation exceeds the trusted operation limit"
            )

    def partial_binding_source(node: ast.AST) -> ast.AST | None:
        if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load):
            return node
        key = name_load_binding_key(node)
        candidates = binding_candidates.get(key)
        if (
            candidates is None
            or len(candidates) != 1
            or not binding_is_usable_for_load(node, key, candidates[0][0])
        ):
            return None
        source = candidates[0][1]
        for index in candidates[0][2]:
            if not isinstance(source, (ast.Tuple, ast.List)):
                return None
            if index >= len(source.elts):
                return None
            source = source.elts[index]
        return source

    def partial_format_value(
        node: ast.AST,
        expected_type: type[str] | type[bytes],
    ) -> Any:
        evaluated_value = evaluated.get(id(node), not_pure)
        if evaluated_value is not_pure:
            source = partial_binding_source(node)
            if isinstance(source, ast.Dict):
                mapping = partial_mapping(node, expected_type)
                if mapping is not None:
                    return mapping
            if isinstance(source, (ast.Tuple, ast.List)):
                sequence = partial_sequence(node, expected_type)
                if sequence is not None:
                    return sequence
            fragment = partial_text(node)
            if fragment is not None and type(fragment) is expected_type:
                return fragment
            return unknown_format_value
        return evaluated_value

    def partial_sequence(
        node: ast.AST,
        expected_type: type[str] | type[bytes],
    ) -> tuple[Any, ...] | None:
        source = partial_binding_source(node)
        if source is None:
            return None
        evaluated_value = evaluated.get(id(source), not_pure)
        if evaluated_value is not_pure:
            evaluated_value = evaluate_binding_expression(source)
        if type(evaluated_value) in {tuple, list}:
            consume_partial_step()
            return tuple(evaluated_value)
        if not isinstance(source, (ast.Tuple, ast.List)):
            return None
        values: list[Any] = []
        for child in source.elts:
            consume_partial_step()
            values.append(partial_format_value(child, expected_type))
        return tuple(values)

    def partial_mapping(
        node: ast.AST,
        expected_type: type[str] | type[bytes],
    ) -> dict[Any, Any] | None:
        source = partial_binding_source(node)
        if source is None:
            return None
        source_id = id(source)
        if source_id in partial_mapping_resolution_stack:
            return None
        evaluated_value = evaluated.get(id(source), not_pure)
        if evaluated_value is not_pure:
            evaluated_value = evaluate_binding_expression(source)
        if isinstance(evaluated_value, dict):
            consume_partial_step()
            return evaluated_value
        if not isinstance(source, ast.Dict):
            return None
        known_items: dict[Any, Any] = {}
        partial_mapping_resolution_stack.add(source_id)
        try:
            for key_node, value_node in zip(source.keys, source.values, strict=True):
                consume_partial_step()
                if key_node is None:
                    expanded = partial_mapping(value_node, expected_type)
                    if expanded is not None:
                        known_items.update(expanded)
                    continue
                key = evaluated.get(id(key_node), not_pure)
                if key is not_pure:
                    key = evaluate_binding_expression(key_node)
                if key is not_pure:
                    continue
                try:
                    known_items[key] = partial_format_value(
                        value_node,
                        expected_type,
                    )
                except TypeError:
                    continue
        finally:
            partial_mapping_resolution_stack.remove(source_id)
        return known_items

    def percent_argument_fragment(
        spec: str | bytes,
        value: Any,
        star_values: tuple[Any, ...],
        *,
        expected_type: type[str] | type[bytes],
        mapping_key: str | bytes | None,
    ) -> str | bytes | None:
        if value is unknown_format_value:
            return None
        raw_fragment = value if type(value) is expected_type else None
        if any(star is unknown_format_value for star in star_values):
            return raw_fragment
        if mapping_key is not None:
            format_argument: Any = {mapping_key: value}
        elif star_values:
            format_argument = (*star_values, value)
        else:
            format_argument = value
        try:
            rendered = bootstrap_v2_python_percent_format(spec, format_argument)
        except ValueError:
            return raw_fragment
        return rendered

    def partial_percent_format(
        template: str | bytes,
        argument: Any,
    ) -> str | bytes | None:
        template_text = (
            template if isinstance(template, str) else template.decode("latin-1")
        )
        expected_type = type(template)
        fragments: list[str | bytes | None] = []
        literal_start = 0
        argument_index = 0
        sequence = argument if isinstance(argument, tuple) else (argument,)
        for match in percent_field_re.finditer(template_text):
            consume_partial_step()
            literal = template[literal_start : match.start()]
            fragments.append(literal)
            literal_start = match.end()
            if match.group("conversion") == "%":
                fragments.append("%" if expected_type is str else b"%")
                continue
            mapping_key_text = match.group("key")
            mapping_key: str | bytes | None
            star_count = int(match.group("width") == "*") + int(
                match.group("precision") == ".*"
            )
            if mapping_key_text is not None and isinstance(argument, dict):
                mapping_key = (
                    mapping_key_text
                    if expected_type is str
                    else mapping_key_text.encode("latin-1")
                )
                star_values = ()
                field_value = argument.get(mapping_key, unknown_format_value)
            else:
                mapping_key = None
                star_values = tuple(
                    sequence[index] if index < len(sequence) else unknown_format_value
                    for index in range(argument_index, argument_index + star_count)
                )
                argument_index += star_count
                field_value = (
                    sequence[argument_index]
                    if argument_index < len(sequence)
                    else unknown_format_value
                )
                argument_index += 1
            spec = template[match.start() : match.end()]
            fragments.append(
                percent_argument_fragment(
                    spec,
                    field_value,
                    star_values,
                    expected_type=expected_type,
                    mapping_key=mapping_key,
                )
            )
        fragments.append(template[literal_start:])
        return concatenate_fragment_values(tuple(fragments))

    def dot_argument_fragment(
        value: Any,
        *,
        conversion: str | None,
        format_spec: str,
    ) -> str | None:
        if value is unknown_format_value:
            return None
        raw_fragment = value if isinstance(value, str) else None
        conversion_code = -1 if conversion is None else ord(conversion)
        try:
            return bootstrap_v2_python_formatted_value(
                value,
                conversion=conversion_code,
                format_spec=format_spec,
                max_output_bytes=BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES,
            )
        except ValueError:
            return raw_fragment

    def partial_dot_format(
        template: str,
        arguments: tuple[Any, ...],
        keywords: dict[str, Any],
        *,
        format_map: bool,
    ) -> str | None:
        if format_map:
            field_arguments: tuple[Any, ...] = ()
            field_keywords = (
                arguments[0]
                if len(arguments) == 1 and isinstance(arguments[0], dict)
                else {}
            )
        else:
            field_arguments = arguments
            field_keywords = keywords
        fragments: list[str | None] = []
        auto_index = 0

        def consume_nested_auto_fields(format_spec: str, index: int) -> int:
            try:
                for _, nested_name, nested_spec, _ in dot_formatter.parse(format_spec):
                    consume_partial_step()
                    if nested_name == "":
                        index += 1
                    if nested_name is not None and nested_spec:
                        index = consume_nested_auto_fields(nested_spec, index)
            except PartialEvaluationLimitError:
                raise
            except ValueError:
                return index
            return index

        try:
            for literal, field_name, format_spec, conversion in dot_formatter.parse(
                template
            ):
                consume_partial_step()
                fragments.append(literal)
                if field_name is None:
                    continue
                if field_name == "":
                    field_name = str(auto_index)
                    auto_index += 1
                try:
                    field_value, _ = dot_formatter.get_field(
                        field_name,
                        field_arguments,
                        field_keywords,
                    )
                except (AttributeError, IndexError, KeyError, TypeError, ValueError):
                    field_value = unknown_format_value
                fragments.append(
                    dot_argument_fragment(
                        field_value,
                        conversion=conversion,
                        format_spec=format_spec,
                    )
                )
                if format_spec:
                    auto_index = consume_nested_auto_fields(format_spec, auto_index)
        except PartialEvaluationLimitError:
            raise
        except ValueError:
            fragments = [
                template,
                *(
                    value
                    for value in (*arguments, *keywords.values())
                    if isinstance(value, str)
                ),
            ]
        return concatenate_fragment_values(tuple(fragments))

    def partial_f_string(node: ast.JoinedStr) -> str | None:
        fragments: list[str | None] = []
        for child in node.values:
            consume_partial_step()
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                fragments.append(child.value)
                continue
            if not isinstance(child, ast.FormattedValue):
                continue
            evaluated_value = evaluated.get(id(child.value), not_pure)
            value_is_partial = evaluated_value is not_pure
            if value_is_partial:
                evaluated_value = partial_text(child.value)
            if evaluated_value is None or evaluated_value is not_pure:
                continue
            if child.format_spec is None:
                format_spec = ""
            else:
                format_spec_value = evaluated.get(id(child.format_spec), not_pure)
                if not isinstance(format_spec_value, str):
                    format_spec_value = partial_text(child.format_spec)
                format_spec = (
                    format_spec_value if isinstance(format_spec_value, str) else ""
                )
            raw_fragment = evaluated_value if isinstance(evaluated_value, str) else None
            if value_is_partial:
                fragments.append(raw_fragment)
                continue
            try:
                rendered = bootstrap_v2_python_formatted_value(
                    evaluated_value,
                    conversion=child.conversion,
                    format_spec=format_spec,
                    max_output_bytes=BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES,
                )
            except ValueError:
                rendered = raw_fragment
            fragments.append(rendered)
        return concatenate_fragment_values(tuple(fragments))

    def partial_text(node: ast.AST) -> str | bytes | None:
        evaluated_value = evaluated.get(id(node), not_pure)
        if type(evaluated_value) in {str, bytes}:
            return evaluated_value
        node_id = id(node)
        if node_id in partial_values:
            return partial_values[node_id]
        if node_id in partial_complete or node_id in partial_resolution_stack:
            return None
        consume_partial_step()
        partial_resolution_stack.add(node_id)
        result: str | bytes | None = None
        try:
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                source = partial_binding_source(node)
                if source is not None and source is not node:
                    result = partial_text(source)
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                result = concatenate_fragment_values(
                    (partial_text(node.left), partial_text(node.right))
                )
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
                left = evaluated.get(id(node.left), not_pure)
                right = evaluated.get(id(node.right), not_pure)
                left_fragment = partial_text(node.left)
                right_fragment = partial_text(node.right)
                if left_fragment is not None and type(right) in {bool, int}:
                    multiplier = max(int(right), 0)
                    payload_size = evaluated_text_payload_size(left_fragment)
                    if (
                        payload_size * multiplier
                        > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES
                    ):
                        raise ValueError(
                            "Python constant repetition exceeds the trusted byte limit"
                        )
                    result = left_fragment * multiplier
                elif right_fragment is not None and type(left) in {bool, int}:
                    multiplier = max(int(left), 0)
                    payload_size = evaluated_text_payload_size(right_fragment)
                    if (
                        payload_size * multiplier
                        > BOOTSTRAP_V2_MAX_PYTHON_EVALUATED_VALUE_BYTES
                    ):
                        raise ValueError(
                            "Python constant repetition exceeds the trusted byte limit"
                        )
                    result = right_fragment * multiplier
                else:
                    result = concatenate_fragment_values(
                        (left_fragment, right_fragment)
                    )
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                template = partial_text(node.left)
                if type(template) in {str, bytes}:
                    expected_type = type(template)
                    source = partial_binding_source(node.right)
                    if isinstance(source, (ast.Tuple, ast.List)):
                        argument: Any = partial_sequence(node.right, expected_type)
                    elif isinstance(source, ast.Dict):
                        argument = partial_mapping(node.right, expected_type)
                    else:
                        argument = partial_format_value(node.right, expected_type)
                    if argument is not None:
                        result = partial_percent_format(template, argument)
            elif isinstance(node, ast.JoinedStr):
                result = partial_f_string(node)
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "join"
                and len(node.args) == 1
                and not node.keywords
            ):
                separator = partial_text(node.func.value)
                expected_type = (
                    type(separator) if type(separator) in {str, bytes} else None
                )
                if expected_type is None:
                    source = partial_binding_source(node.args[0])
                    if isinstance(source, (ast.Tuple, ast.List)):
                        for element in source.elts:
                            fragment = partial_text(element)
                            if type(fragment) in {str, bytes}:
                                expected_type = type(fragment)
                                break
                    if expected_type is not None:
                        separator = "" if expected_type is str else b""
                if expected_type is not None:
                    elements = partial_sequence(node.args[0], expected_type)
                    if elements is not None:
                        empty = "" if expected_type is str else b""
                        normalized = tuple(
                            element if type(element) is expected_type else empty
                            for element in elements
                        )
                        result = bootstrap_v2_python_literal_join(
                            separator,
                            normalized,
                        )
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"format", "format_map"}
            ):
                template = partial_text(node.func.value)
                if isinstance(template, str):
                    arguments: list[Any] = []
                    keywords: dict[str, Any] = {}
                    for argument_node in node.args:
                        if isinstance(argument_node, ast.Starred):
                            sequence = partial_sequence(argument_node.value, str)
                            if sequence is None:
                                arguments.append(unknown_format_value)
                            else:
                                arguments.extend(sequence)
                        else:
                            arguments.append(partial_format_value(argument_node, str))
                    for keyword in node.keywords:
                        if keyword.arg is None:
                            mapping = partial_mapping(keyword.value, str)
                            if mapping is not None:
                                keywords.update(mapping)
                        else:
                            keywords[keyword.arg] = partial_format_value(
                                keyword.value, str
                            )
                    if node.func.attr == "format_map":
                        mapping = (
                            partial_mapping(node.args[0], str)
                            if len(node.args) == 1 and not node.keywords
                            else None
                        )
                        format_arguments = (mapping,) if mapping is not None else ({},)
                    else:
                        format_arguments = tuple(arguments)
                    result = partial_dot_format(
                        template,
                        format_arguments,
                        keywords,
                        format_map=node.func.attr == "format_map",
                    )
        finally:
            partial_resolution_stack.remove(node_id)
        partial_complete.add(node_id)
        if result is not None:
            retain_partial(node, result)
        return result

    for node in nodes:
        if evaluated.get(id(node), not_pure) is not not_pure:
            continue
        is_partial_constructor = (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, (ast.Add, ast.Mult, ast.Mod))
        ) or isinstance(node, ast.JoinedStr)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            is_partial_constructor = is_partial_constructor or node.func.attr in {
                "format",
                "format_map",
                "join",
            }
        if is_partial_constructor:
            partial_text(node)

    for node in nodes:
        constructed_value = constructed.get(id(node))
        if constructed_value is not None and id(node) not in nested_pure_adds:
            constants.append(evaluated_text_risk_view(constructed_value))
    for child in constructed_container_values.values():
        constants.append(evaluated_text_risk_view(child))
    return constants


def bootstrap_v2_python_privacy_risk_values(value: str) -> list[str]:
    return [
        constant
        for constant in bootstrap_v2_python_string_constants(value)
        if bootstrap_v2_privacy_risk_lines(constant)
    ]


def contains_bootstrap_v2_python_privacy_risk(value: str, *, relative: Path) -> bool:
    risky_values = bootstrap_v2_python_privacy_risk_values(value)
    if not risky_values:
        return False
    expected_fingerprint = BOOTSTRAP_V2_TRUSTED_PYTHON_RISK_VALUES_SHA256.get(relative)
    return (
        expected_fingerprint is None
        or bootstrap_v2_privacy_risk_lines_fingerprint(risky_values)
        != expected_fingerprint
    )


def contains_decoded_infrastructure_risk(value: Any) -> bool:
    if isinstance(value, str):
        return contains_infrastructure_risk_text(value)
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and contains_infrastructure_risk_text(key):
                return True
            if contains_decoded_infrastructure_risk(child):
                return True
    if isinstance(value, list):
        return any(contains_decoded_infrastructure_risk(child) for child in value)
    return False


def contains_risky_token(value: Any) -> bool:
    return isinstance(value, str) and SENSITIVE_TOKEN_RE.search(value) is not None


def contains_risky_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and (
                contains_risky_text(key) or contains_risky_token(key)
            ):
                return True
            if contains_risky_key(child):
                return True
    if isinstance(value, list):
        return any(contains_risky_key(child) for child in value)
    return False


def contains_raw_path_fields(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"root", "path"}:
                return True
            if contains_raw_path_fields(child):
                return True
    if isinstance(value, list):
        return any(contains_raw_path_fields(child) for child in value)
    return False


def unexpected_keys(row: dict[str, Any], allowed: frozenset[str]) -> list[str]:
    return ["unexpected field is not allowed"] if set(row) - allowed else []


def missing_keys(row: dict[str, Any], required: frozenset[str]) -> list[str]:
    return [f"missing required field: {key}" for key in sorted(required - set(row))]


def valid_timestamp_or_null(value: Any) -> bool:
    return value is None or valid_timestamp(value)


def valid_timestamp(value: Any) -> bool:
    return isinstance(value, str) and TIMESTAMP_RE.fullmatch(value) is not None


def timestamp_order_key(value: str) -> tuple[int, int, int, int, int, int, int]:
    main = value.removesuffix("Z")
    if "." in main:
        main, fraction = main.split(".", 1)
    else:
        fraction = ""
    date_part, time_part = main.split("T", 1)
    year, month, day = (int(part) for part in date_part.split("-", 2))
    hour, minute, second = (int(part) for part in time_part.split(":", 2))
    nanosecond = int(fraction.ljust(9, "0") or "0")
    return (year, month, day, hour, minute, second, nanosecond)


def timestamp_epoch_nanoseconds(value: str) -> int:
    year, month, day, hour, minute, second, nanosecond = timestamp_order_key(value)
    ordinal = dt.date(year, month, day).toordinal()
    seconds = ((ordinal * 24 + hour) * 60 + minute) * 60 + second
    return seconds * 1_000_000_000 + nanosecond


def valid_non_negative_int(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_COUNT
    )


def valid_schema_version_one(value: Any) -> bool:
    return type(value) is int and value == 1


def valid_safe_token(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= MAX_SAFE_TOKEN_LENGTH
        and SAFE_TOKEN_RE.fullmatch(value) is not None
        and not contains_risky_token(value)
        and not contains_risky_text(value)
    )


def valid_retained_host(value: Any) -> bool:
    return isinstance(value, str) and value in RETAINED_EVIDENCE_HOSTS


def valid_retained_coverage_host(value: Any) -> bool:
    return isinstance(value, str) and value in RETAINED_HOSTS


def valid_retained_mode(value: Any) -> bool:
    return isinstance(value, str) and (
        value in RETAINED_FIXED_MODES or BASELINE_MODE_RE.fullmatch(value) is not None
    )


def retained_mode_days(mode: str) -> int | None:
    if mode == "daily":
        return 1
    if mode == "weekly":
        return 7
    if mode == "baseline-90d":
        return 90
    return None


def expected_mode_from_retained_export_path(relative: Path) -> str | None:
    parts = relative.parts
    if len(parts) == 3 and parts[:2] in RETAINED_EXPORT_DIRS:
        return parts[1]
    return None


def validate_expected_mode(
    value: Any, expected_mode: str | None, label: str
) -> list[str]:
    if expected_mode is None:
        return []
    if expected_mode == "baseline":
        if value != "baseline-90d":
            return [f"{label} must match retained/baseline export directory"]
        return []
    if value != expected_mode:
        return [f"{label} must match retained/{expected_mode} export directory"]
    return []


def valid_retained_model_id(value: Any) -> bool:
    return isinstance(value, str) and value in RETAINED_MODEL_IDS


def valid_retained_model_era(value: Any) -> bool:
    return isinstance(value, str) and value in RETAINED_MODEL_ERAS


def allowed_infrastructure_artifact(
    relative: Path, *, history_v2: bool = False
) -> bool:
    path_text = relative.as_posix()
    if path_text in ROOT_DOC_FILES:
        return True
    if history_v2 and relative in BOOTSTRAP_V2_ALLOWED_FILES:
        return True
    if relative == BOOTSTRAP_V2_PERMANENT_CI_TEMPLATE_PATH:
        return True
    parts = relative.parts
    if not parts:
        return False
    if parts[0] == ".github":
        return (
            len(parts) >= 3
            and parts[1] == "workflows"
            and relative.suffix.lower() in WORKFLOW_SUFFIXES
        )
    if parts[0] == "scripts":
        return len(parts) == 2 and relative.suffix.lower() == ".py"
    if parts[0] == "schemas":
        return len(parts) == 2 and relative.name in SCHEMA_FILES
    if parts[0] == "tests":
        return len(parts) == 2 and relative.suffix.lower() == ".py"
    return False


def content_scanned_infrastructure_artifact(
    relative: Path, *, history_v2: bool = False
) -> bool:
    if history_v2 and relative in BOOTSTRAP_V2_ALLOWED_FILES:
        return False
    return allowed_infrastructure_artifact(relative, history_v2=history_v2)


def valid_date_components(year_text: str, month_text: str, day_text: str) -> bool:
    if (
        re.fullmatch(r"\d{4}", year_text) is None
        or re.fullmatch(r"\d{2}", month_text) is None
        or re.fullmatch(r"\d{2}", day_text) is None
    ):
        return False
    try:
        dt.date(int(year_text), int(month_text), int(day_text))
    except ValueError:
        return False
    return True


def valid_baseline_report_filename(name: str) -> bool:
    match = re.fullmatch(
        r"(\d{4})-(\d{2})-(\d{2})_to_(\d{4})-(\d{2})-(\d{2})\.md", name
    )
    if match is None:
        return False
    start_year, start_month, start_day, end_year, end_month, end_day = match.groups()
    if not valid_date_components(start_year, start_month, start_day):
        return False
    if not valid_date_components(end_year, end_month, end_day):
        return False
    start = dt.date(int(start_year), int(start_month), int(start_day))
    end = dt.date(int(end_year), int(end_month), int(end_day))
    return (end - start).days == 90


def allowed_retained_text_artifact(relative: Path) -> bool:
    path_text = relative.as_posix()
    if path_text in {"data/README.md", "reports/README.md"}:
        return True
    parts = relative.parts
    if len(parts) == 5 and parts[0] == "reports" and parts[1] in {"daily", "weekly"}:
        year, month, day_file = parts[2], parts[3], parts[4]
        return bool(
            relative.suffix.lower() == ".md"
            and valid_date_components(year, month, Path(day_file).stem)
        )
    if len(parts) == 4 and parts[:3] == ("reports", "baseline", "90-day-windows"):
        return valid_baseline_report_filename(parts[3])
    return False


def valid_year_month(parts: tuple[str, ...], start: int) -> bool:
    if (
        len(parts) <= start + 1
        or re.fullmatch(r"\d{4}", parts[start]) is None
        or re.fullmatch(r"\d{2}", parts[start + 1]) is None
    ):
        return False
    year = int(parts[start])
    month = int(parts[start + 1])
    if not 1 <= month <= 12:
        return False
    try:
        dt.date(year, month, 1)
        if month == 12:
            dt.date(year + 1, 1, 1)
        else:
            dt.date(year, month + 1, 1)
    except ValueError:
        return False
    return True


def data_month_window(
    data_month: tuple[str, str, str],
) -> tuple[
    tuple[int, int, int, int, int, int, int],
    tuple[int, int, int, int, int, int, int],
]:
    _, year_text, month_text = data_month
    year = int(year_text)
    month = int(month_text)
    start = dt.date(year, month, 1)
    if month == 12:
        end = dt.date(year + 1, 1, 1)
    else:
        end = dt.date(year, month + 1, 1)
    start_key = (start.year, start.month, start.day, 0, 0, 0, 0)
    end_key = (end.year, end.month, end.day, 0, 0, 0, 0)
    return (start_key, end_key)


def allowed_retained_json_artifact(relative: Path) -> str | None:
    parts = relative.parts
    if (
        len(parts) == 3
        and parts[:2] in RETAINED_EXPORT_DIRS
        and relative.name == "trend_report.json"
    ):
        return "trend"
    if (
        len(parts) == 3
        and parts[:2] in RETAINED_EXPORT_DIRS
        and relative.name == "retained_manifest.json"
    ):
        return "manifest"
    if (
        len(parts) == 5
        and parts[:2] == ("data", "trends")
        and valid_year_month(parts, 2)
        and relative.name == "trend_report.json"
    ):
        return "trend"
    if (
        len(parts) == 5
        and parts[:2] == ("data", "manifests")
        and valid_year_month(parts, 2)
        and relative.name == "retained_manifest.json"
    ):
        return "manifest"
    return None


def allowed_retained_jsonl_artifact(relative: Path) -> str | None:
    parts = relative.parts
    if (
        len(parts) == 3
        and parts[:2] in RETAINED_EXPORT_DIRS
        and relative.name == "episodes.jsonl"
    ):
        return "episode"
    if (
        len(parts) == 3
        and parts[:2] in RETAINED_EXPORT_DIRS
        and relative.name == "turn_flags.jsonl"
    ):
        return "turn_flag"
    if (
        len(parts) == 5
        and parts[:2] == ("data", "episodes")
        and valid_year_month(parts, 2)
        and relative.name == "episodes.jsonl"
    ):
        return "episode"
    if (
        len(parts) == 5
        and parts[:2] == ("data", "turn_flags")
        and valid_year_month(parts, 2)
        and relative.name == "turn_flags.jsonl"
    ):
        return "turn_flag"
    return None


def validate_safe_token_array(
    value: Any, label: str, *, min_items: int = 0
) -> list[str]:
    if not isinstance(value, list):
        return [f"{label} must be safe-token array"]
    issues: list[str] = []
    if len(value) < min_items:
        issues.append(f"{label} must contain at least {min_items} item")
    if len(value) > MAX_TOKEN_ARRAY_ITEMS:
        issues.append(f"{label} must contain at most {MAX_TOKEN_ARRAY_ITEMS} items")
    if not all(valid_safe_token(item) for item in value):
        issues.append(f"{label} must be safe-token array")
    return issues


def validate_issue_flag_array(
    value: Any, label: str, *, min_items: int = 0
) -> list[str]:
    issues = validate_safe_token_array(value, label, min_items=min_items)
    if isinstance(value, list):
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str) or item not in ISSUE_FLAGS:
                issues.append(f"{label} must use allowed issue flags")
                break
            if item in seen:
                issues.append(f"{label} must not contain duplicate issue flags")
                break
            seen.add(item)
    return issues


def validate_count_map(value: Any, label: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{label} must be an object"]
    issues: list[str] = []
    if len(value) > MAX_COUNT_MAP_PROPERTIES:
        issues.append(f"{label} must contain at most {MAX_COUNT_MAP_PROPERTIES} keys")
    for key, count in value.items():
        if not valid_safe_token(key):
            issues.append(f"{label} key must be a safe token")
        if label == "hosts" and not valid_retained_host(key):
            issues.append("hosts key must be an allowed retained host")
        if label == "model_eras" and not valid_retained_model_era(key):
            issues.append("model_eras key must be an allowed retained model era")
        if not valid_non_negative_int(count):
            issues.append(f"{label} value must be a bounded non-negative integer")
    return issues


def validate_issue_flag_count_map(value: Any, label: str) -> list[str]:
    issues = validate_count_map(value, label)
    if isinstance(value, dict):
        for key in value:
            if key not in ISSUE_FLAGS:
                issues.append(f"{label} keys must use allowed issue flags")
                break
    return issues


def validate_window(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["window must be an object"]
    issues = unexpected_keys(value, WINDOW_KEYS) + missing_keys(value, WINDOW_KEYS)
    if not valid_retained_mode(value.get("mode")):
        issues.append("window.mode must be an allowed retained mode")
    start_value = value.get("start")
    end_value = value.get("end")
    start_valid = valid_timestamp(start_value)
    end_valid = valid_timestamp(end_value)
    if not start_valid:
        issues.append("window.start must be timestamp")
    if not end_valid:
        issues.append("window.end must be timestamp")
    if start_valid and end_valid:
        if timestamp_order_key(start_value) >= timestamp_order_key(end_value):
            issues.append("window.start must be before window.end")
        elif isinstance(value.get("mode"), str):
            mode_days = retained_mode_days(value["mode"])
            if mode_days is not None:
                expected_ns = mode_days * 24 * 60 * 60 * 1_000_000_000
                if (
                    timestamp_epoch_nanoseconds(end_value)
                    - timestamp_epoch_nanoseconds(start_value)
                    != expected_ns
                ):
                    issues.append("window duration must match window.mode")
    return issues


def retained_window_identity(
    value: Any,
) -> (
    tuple[
        str,
        tuple[int, int, int, int, int, int, int],
        tuple[int, int, int, int, int, int, int],
    ]
    | None
):
    if not isinstance(value, dict):
        return None
    mode = value.get("mode")
    start = value.get("start")
    end = value.get("end")
    if (
        not valid_retained_mode(mode)
        or not valid_timestamp(start)
        or not valid_timestamp(end)
    ):
        return None
    return (mode, timestamp_order_key(start), timestamp_order_key(end))


def valid_timestamp_key(value: Any) -> tuple[int, int, int, int, int, int, int] | None:
    if not valid_timestamp(value):
        return None
    return timestamp_order_key(value)


def validate_coverage_gap(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["coverage gap must be an object"]
    issues = unexpected_keys(value, COVERAGE_GAP_KEYS)
    if "host" not in value or not valid_retained_coverage_host(value.get("host")):
        issues.append("coverage gap host must be an allowed retained host")
    if "reason" not in value or value.get("reason") not in COVERAGE_REASONS:
        issues.append("coverage gap reason is invalid")
    if "root_ref" in value and not PATH_REF_RE.fullmatch(
        str(value.get("root_ref", ""))
    ):
        issues.append("coverage gap root_ref must be path_ref_v1")
    if "bytes" in value and not valid_non_negative_int(value.get("bytes")):
        issues.append("coverage gap bytes must be a non-negative integer")
    return issues


def validate_coverage_gaps(value: Any) -> list[str]:
    if not isinstance(value, list):
        return ["coverage_gaps must be an array"]
    issues: list[str] = []
    if len(value) > MAX_COVERAGE_GAPS:
        issues.append(f"coverage_gaps must contain at most {MAX_COVERAGE_GAPS} items")
    for index, gap in enumerate(value, 1):
        issues.extend(
            f"coverage_gaps[{index}]: {issue}" for issue in validate_coverage_gap(gap)
        )
    return issues


def validate_source_summary(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["source summary must be an object"]
    issues = unexpected_keys(value, SOURCE_SUMMARY_KEYS) + missing_keys(
        value, SOURCE_SUMMARY_KEYS
    )
    if not valid_retained_host(value.get("host")):
        issues.append("source host must be an allowed retained host")
    if not PATH_REF_RE.fullmatch(str(value.get("root_ref", ""))):
        issues.append("source root_ref must be path_ref_v1")
    if value.get("status") not in SOURCE_STATUSES:
        issues.append("source status is invalid")
    count_values: dict[str, int] = {}
    for key in ("rollout_count", "summary_count"):
        count = value.get(key)
        if valid_non_negative_int(count):
            count_values[key] = count
        else:
            count_values[key] = 0
            issues.append(f"source {key} must be a bounded non-negative integer")
    if value.get("status") == "ready" and not (
        count_values["rollout_count"] >= 1 or count_values["summary_count"] >= 1
    ):
        issues.append("ready source must have rollout_count or summary_count")
    if value.get("status") in {"empty", "missing", "stale"} and (
        value.get("rollout_count") != 0 or value.get("summary_count") != 0
    ):
        issues.append("non-ready source counts must be zero")
    return issues


def validate_retained_text(
    value: Any, label: str, *, nullable: bool = False
) -> list[str]:
    if value is None and nullable:
        return []
    if not isinstance(value, str):
        return [f"{label} must be retained text"]
    if len(value) > 1200 or contains_risky_text(value):
        return [f"{label} contains retained-text risk"]
    return []


def validate_episode(row: Any) -> list[str]:
    issues: list[str] = []
    if not isinstance(row, dict):
        return ["episode row must be an object"]
    issues.extend(unexpected_keys(row, EPISODE_KEYS))
    issues.extend(missing_keys(row, EPISODE_KEYS))
    if contains_raw_path_fields(row):
        issues.append("episode contains raw root/path field")
    if contains_risky_key(row):
        issues.append("episode JSON key contains raw/sensitive evidence")
    if not EPISODE_REF_RE.fullmatch(str(row.get("episode_id", ""))):
        issues.append("episode_id must be episode_ref_v1")
    if not valid_retained_host(row.get("host")):
        issues.append("host must be an allowed retained host")
    if not SESSION_REF_RE.fullmatch(str(row.get("session_id", ""))):
        issues.append("session_id must be session_ref_v1")
    start_value = row.get("start")
    end_value = row.get("end")
    start_valid = valid_timestamp_or_null(start_value)
    end_valid = valid_timestamp_or_null(end_value)
    if not start_valid:
        issues.append("start must be timestamp or null")
    if not end_valid:
        issues.append("end must be timestamp or null")
    if (
        start_valid
        and end_valid
        and isinstance(start_value, str)
        and isinstance(end_value, str)
    ):
        if timestamp_order_key(start_value) > timestamp_order_key(end_value):
            issues.append("episode start must be before or equal to end")
    if row.get("cwd") is not None and not PATH_REF_RE.fullmatch(str(row.get("cwd"))):
        issues.append("cwd must be path_ref_v1 or null")
    if not valid_retained_model_era(row.get("model_era")):
        issues.append("model_era must be an allowed retained model era")
    issues.extend(validate_retained_text(row.get("topic"), "topic"))
    if not valid_non_negative_int(row.get("turn_count")):
        issues.append("turn_count must be a bounded non-negative integer")
    issues.extend(
        validate_issue_flag_array(row.get("friction_flags"), "friction_flags")
    )
    if row.get("outcome") not in OUTCOMES:
        issues.append("outcome is invalid")
    issues.extend(
        validate_retained_text(
            row.get("work_report_hint"), "work_report_hint", nullable=True
        )
    )
    return issues


def validate_turn_flag(row: Any) -> list[str]:
    issues: list[str] = []
    if not isinstance(row, dict):
        return ["turn flag row must be an object"]
    issues.extend(unexpected_keys(row, TURN_FLAG_KEYS))
    issues.extend(missing_keys(row, TURN_FLAG_KEYS))
    if contains_raw_path_fields(row):
        issues.append("turn flag contains raw root/path field")
    if contains_risky_key(row):
        issues.append("turn flag JSON key contains raw/sensitive evidence")
    if not TURN_REF_RE.fullmatch(str(row.get("turn_id", ""))):
        issues.append("turn_id must be turn_ref_v1")
    if not EPISODE_REF_RE.fullmatch(str(row.get("episode_id", ""))):
        issues.append("episode_id must be episode_ref_v1")
    if not valid_retained_host(row.get("host")):
        issues.append("host must be an allowed retained host")
    if not SESSION_REF_RE.fullmatch(str(row.get("session_id", ""))):
        issues.append("session_id must be session_ref_v1")
    if not PATH_REF_RE.fullmatch(str(row.get("source_path", ""))):
        issues.append("source_path must be path_ref_v1")
    if not SOURCE_HASH_RE.fullmatch(str(row.get("source_hash", ""))):
        issues.append("source_hash must be source_hash_v1")
    if not valid_timestamp_or_null(row.get("timestamp")):
        issues.append("timestamp must be timestamp or null")
    if row.get("cwd") is not None and not PATH_REF_RE.fullmatch(str(row.get("cwd"))):
        issues.append("cwd must be path_ref_v1 or null")
    if row.get("model") is not None and not valid_retained_model_id(row.get("model")):
        issues.append("model must be an allowed retained model id or null")
    if not valid_retained_model_era(row.get("model_era")):
        issues.append("model_era must be an allowed retained model era")
    for key in (
        "redacted_user_prompt_summary",
        "assistant_action_summary",
        "prompt_improvement",
    ):
        issues.extend(
            validate_retained_text(
                row.get(key), key, nullable=(key == "prompt_improvement")
            )
        )
    issues.extend(
        validate_issue_flag_array(row.get("issue_flags"), "issue_flags", min_items=1)
    )
    return issues


def validate_trend(data: Any, *, expected_mode: str | None = None) -> list[str]:
    if not isinstance(data, dict):
        return ["trend must be an object"]
    issues = unexpected_keys(data, TREND_KEYS) + missing_keys(data, TREND_KEYS)
    if contains_risky_key(data):
        issues.append("trend JSON key contains raw/sensitive evidence")
    if not valid_schema_version_one(data.get("schema_version")):
        issues.append("trend schema_version must be 1")
    issues.extend(validate_window(data.get("window")))
    window = data.get("window") if isinstance(data.get("window"), dict) else {}
    issues.extend(
        validate_expected_mode(window.get("mode"), expected_mode, "trend window.mode")
    )
    for key in ("turn_count", "flagged_turn_count", "episode_count"):
        if not valid_non_negative_int(data.get(key)):
            issues.append(f"{key} must be a non-negative integer")
    if valid_non_negative_int(data.get("turn_count")) and valid_non_negative_int(
        data.get("flagged_turn_count")
    ):
        if data["flagged_turn_count"] > data["turn_count"]:
            issues.append("flagged_turn_count must be less than or equal to turn_count")
    issues.extend(validate_issue_flag_count_map(data.get("flags"), "flags"))
    for key in ("hosts", "model_eras"):
        issues.extend(validate_count_map(data.get(key), key))
    issues.extend(validate_coverage_gaps(data.get("coverage_gaps")))
    return issues


def validate_manifest(data: Any, *, expected_mode: str | None = None) -> list[str]:
    issues: list[str] = []
    if not isinstance(data, dict):
        return ["manifest must be an object"]
    issues.extend(unexpected_keys(data, MANIFEST_KEYS))
    issues.extend(missing_keys(data, MANIFEST_KEYS))
    if contains_raw_path_fields(data):
        issues.append("manifest contains raw root/path field")
    if contains_risky_key(data):
        issues.append("manifest JSON key contains raw/sensitive evidence")
    if contains_risky_text(data):
        issues.append("manifest retained text contains raw/sensitive evidence")
    if not valid_schema_version_one(data.get("schema_version")):
        issues.append("manifest schema_version must be 1")
    if not valid_retained_mode(data.get("mode")):
        issues.append("manifest mode must be an allowed retained mode")
    issues.extend(validate_window(data.get("window")))
    window = data.get("window") if isinstance(data.get("window"), dict) else {}
    if isinstance(window, dict) and window.get("mode") != data.get("mode"):
        issues.append("manifest mode must match window.mode")
    issues.extend(
        validate_expected_mode(data.get("mode"), expected_mode, "manifest mode")
    )
    if not isinstance(data.get("sources"), list) or not data.get("sources"):
        issues.append("manifest sources must be a non-empty array")
    else:
        if len(data["sources"]) > MAX_MANIFEST_SOURCES:
            issues.append(
                f"manifest sources must contain at most {MAX_MANIFEST_SOURCES} items"
            )
        for index, source in enumerate(data.get("sources", []), 1):
            issues.extend(
                f"sources[{index}]: {issue}"
                for issue in validate_source_summary(source)
            )
    issues.extend(validate_coverage_gaps(data.get("coverage_gaps")))
    if not valid_schema_version_one(data.get("redaction_policy_version")):
        issues.append("manifest redaction_policy_version must be 1")
    if (
        data.get("retention_note")
        != "Derived retained manifest; raw location fields removed and opaque refs preserved."
    ):
        issues.append("manifest retention_note is invalid")
    if data.get("retention_safe") is not True:
        issues.append("manifest retention_safe must be true")
    return issues


def retained_export_key(relative: Path) -> tuple[str, str] | None:
    if len(relative.parts) == 3 and relative.parts[:2] in RETAINED_EXPORT_DIRS:
        return tuple(relative.parts[:2])
    return None


def retained_data_month_key(relative: Path) -> tuple[str, str, str] | None:
    parts = relative.parts
    if (
        len(parts) == 5
        and parts[0] == "data"
        and parts[1] in {"episodes", "turn_flags", "trends", "manifests"}
        and valid_year_month(parts, 2)
    ):
        return ("data", parts[2], parts[3])
    return None


def valid_trend_count_map(value: Any) -> bool:
    return isinstance(value, dict) and all(
        isinstance(key, str) and valid_non_negative_int(count)
        for key, count in value.items()
    )


def sorted_counter(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted((key, count) for key, count in counter.items() if count))


def validate_retained_export_consistency(
    export_dir: tuple[str, ...],
    rows: dict[str, list[Any]],
    trend: Any,
    manifest: Any = None,
    artifact_paths: dict[str, Path] | None = None,
    data_month: tuple[str, str, str] | None = None,
) -> list[str]:
    export_path = Path(*export_dir)
    artifact_paths = artifact_paths or {}
    episodes_path = artifact_paths.get("episode", export_path / "episodes.jsonl")
    turn_flags_path = artifact_paths.get("turn_flag", export_path / "turn_flags.jsonl")
    trend_path = artifact_paths.get("trend", export_path / "trend_report.json")
    manifest_path = artifact_paths.get(
        "manifest", export_path / "retained_manifest.json"
    )
    issues: list[str] = []

    episodes = [row for row in rows.get("episode", []) if isinstance(row, dict)]
    turn_flags = [row for row in rows.get("turn_flag", []) if isinstance(row, dict)]
    episodes_by_id: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(episodes, 1):
        episode_id = row.get("episode_id")
        if (
            not isinstance(episode_id, str)
            or EPISODE_REF_RE.fullmatch(episode_id) is None
        ):
            continue
        if episode_id in episodes_by_id:
            issues.append(f"{episodes_path}:{index}: duplicate episode_id")
            continue
        episodes_by_id[episode_id] = row
    turn_ids: set[str] = set()
    for index, row in enumerate(turn_flags, 1):
        turn_id = row.get("turn_id")
        if not isinstance(turn_id, str) or TURN_REF_RE.fullmatch(turn_id) is None:
            continue
        if turn_id in turn_ids:
            issues.append(f"{turn_flags_path}:{index}: duplicate turn_id")
            continue
        turn_ids.add(turn_id)

    for index, row in enumerate(turn_flags, 1):
        episode_id = row.get("episode_id")
        if not isinstance(episode_id, str) or not EPISODE_REF_RE.fullmatch(episode_id):
            continue
        episode = episodes_by_id.get(episode_id)
        if episode is None:
            issues.append(
                f"{turn_flags_path}:{index}: episode_id is missing from episodes export"
            )
            continue
        if row.get("host") != episode.get("host"):
            issues.append(
                f"{turn_flags_path}:{index}: host must match referenced episode"
            )
        if row.get("session_id") != episode.get("session_id"):
            issues.append(
                f"{turn_flags_path}:{index}: session_id must match referenced episode"
            )
        timestamp_key = valid_timestamp_key(row.get("timestamp"))
        episode_start_key = valid_timestamp_key(episode.get("start"))
        episode_end_key = valid_timestamp_key(episode.get("end"))
        if timestamp_key is not None and (
            (episode_start_key is not None and timestamp_key < episode_start_key)
            or (episode_end_key is not None and timestamp_key > episode_end_key)
        ):
            issues.append(
                f"{turn_flags_path}:{index}: timestamp must be within referenced episode"
            )

    flagged_turn_counts_by_episode = Counter[str]()
    for row in turn_flags:
        episode_id = row.get("episode_id")
        if isinstance(episode_id, str) and EPISODE_REF_RE.fullmatch(episode_id):
            flagged_turn_counts_by_episode[episode_id] += 1
    for episode_id, flagged_count in flagged_turn_counts_by_episode.items():
        episode = episodes_by_id.get(episode_id)
        if episode is None:
            continue
        turn_count = episode.get("turn_count")
        if valid_non_negative_int(turn_count) and flagged_count > turn_count:
            issues.append(
                f"{turn_flags_path}: flagged turns must not exceed referenced episode turn_count"
            )

    row_window_identity = None
    row_window_label = None
    if isinstance(trend, dict):
        row_window_identity = retained_window_identity(trend.get("window"))
        row_window_label = "trend window"
    if row_window_identity is None and isinstance(manifest, dict):
        row_window_identity = retained_window_identity(manifest.get("window"))
        row_window_label = "manifest window"

    if data_month is not None:
        month_start, month_end = data_month_window(data_month)
        row_scope_crosses_into_data_month = (
            row_window_identity is not None
            and row_window_identity[0] in {"weekly", "baseline-90d"}
            and row_window_identity[1] < month_start
            and row_window_identity[2] <= month_end
        )
        for artifact, path in ((trend, trend_path), (manifest, manifest_path)):
            if isinstance(artifact, dict):
                window_identity = retained_window_identity(artifact.get("window"))
                if window_identity is not None:
                    _, window_start, window_end = window_identity
                    if window_start >= month_end or window_end <= month_start:
                        issues.append(f"{path}: window must overlap data month")
                    elif window_end > month_end:
                        issues.append(f"{path}: window end must be within data month")
        if not row_scope_crosses_into_data_month:
            for index, row in enumerate(episodes, 1):
                start_key = valid_timestamp_key(row.get("start"))
                end_key = valid_timestamp_key(row.get("end"))
                if (
                    start_key is not None
                    and (start_key < month_start or start_key >= month_end)
                ) or (
                    end_key is not None
                    and (end_key < month_start or end_key > month_end)
                ):
                    issues.append(
                        f"{episodes_path}:{index}: episode start/end must be within data month"
                    )
            for index, row in enumerate(turn_flags, 1):
                timestamp_key = valid_timestamp_key(row.get("timestamp"))
                if timestamp_key is not None and (
                    timestamp_key < month_start or timestamp_key >= month_end
                ):
                    issues.append(
                        f"{turn_flags_path}:{index}: timestamp must be within data month"
                    )

    if row_window_identity is not None:
        _, window_start, window_end = row_window_identity
        assert row_window_label is not None
        label = row_window_label
        for index, row in enumerate(episodes, 1):
            start_key = valid_timestamp_key(row.get("start"))
            end_key = valid_timestamp_key(row.get("end"))
            if (
                start_key is not None
                and (start_key < window_start or start_key >= window_end)
            ) or (
                end_key is not None and (end_key < window_start or end_key > window_end)
            ):
                issues.append(
                    f"{episodes_path}:{index}: episode start/end must be within {label}"
                )
        for index, row in enumerate(turn_flags, 1):
            timestamp_key = valid_timestamp_key(row.get("timestamp"))
            if timestamp_key is not None and (
                timestamp_key < window_start or timestamp_key >= window_end
            ):
                issues.append(
                    f"{turn_flags_path}:{index}: timestamp must be within {label}"
                )

    if (
        not episodes
        and not turn_flags
        and "episode" not in rows
        and "turn_flag" not in rows
        and not isinstance(trend, dict)
    ):
        return issues

    if not isinstance(trend, dict):
        return issues

    if valid_non_negative_int(trend.get("episode_count")) and trend[
        "episode_count"
    ] != len(episodes):
        issues.append(f"{trend_path}: episode_count must match episodes.jsonl")
    if valid_non_negative_int(trend.get("flagged_turn_count")) and trend[
        "flagged_turn_count"
    ] != len(turn_flags):
        issues.append(f"{trend_path}: flagged_turn_count must match turn_flags.jsonl")

    episode_turn_counts = [
        row.get("turn_count")
        for row in episodes
        if valid_non_negative_int(row.get("turn_count"))
    ]
    if len(episode_turn_counts) == len(episodes):
        expected_turn_count = sum(episode_turn_counts)
        if (
            valid_non_negative_int(trend.get("turn_count"))
            and trend["turn_count"] != expected_turn_count
        ):
            issues.append(
                f"{trend_path}: turn_count must match episodes.jsonl turn_count total"
            )

        expected_hosts = Counter[str]()
        expected_model_eras = Counter[str]()
        for row in episodes:
            turn_count = row["turn_count"]
            host = row.get("host")
            model_era = row.get("model_era")
            if valid_retained_host(host):
                expected_hosts[host] += turn_count
            if valid_retained_model_era(model_era):
                expected_model_eras[model_era] += turn_count
        if valid_trend_count_map(trend.get("hosts")) and trend[
            "hosts"
        ] != sorted_counter(expected_hosts):
            issues.append(
                f"{trend_path}: hosts must match episodes.jsonl turn_count totals"
            )
        if valid_trend_count_map(trend.get("model_eras")) and trend[
            "model_eras"
        ] != sorted_counter(expected_model_eras):
            issues.append(
                f"{trend_path}: model_eras must match episodes.jsonl turn_count totals"
            )

    expected_flags = Counter[str]()
    for row in turn_flags:
        flags = row.get("issue_flags")
        if isinstance(flags, list):
            expected_flags.update(
                {
                    flag
                    for flag in flags
                    if isinstance(flag, str) and flag in ISSUE_FLAGS
                }
            )
    if valid_trend_count_map(trend.get("flags")) and trend["flags"] != sorted_counter(
        expected_flags
    ):
        issues.append(f"{trend_path}: flags must match turn_flags.jsonl issue_flags")

    return issues


def contains_bootstrap_v2_nonpublic_key_marker(value: str) -> bool:
    upper_value = value.upper()
    return (
        any(marker in upper_value for marker in BOOTSTRAP_V2_FORBIDDEN_ARMOR_MARKERS)
        or "PRIVATE KEY" in upper_value
        or "SECRET KEY" in upper_value
        or "SECRET-KEY" in upper_value
    )


def decode_bootstrap_v2_public_key_armor(value: bytes) -> bytes:
    if any((byte < 0x20 and byte != 0x0A) or byte == 0x7F for byte in value):
        raise ValueError("public key armor contains prohibited control bytes")
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("public key armor must be ASCII") from exc
    if contains_bootstrap_v2_nonpublic_key_marker(text):
        raise ValueError("public key artifact contains a non-public key marker")

    if not text.endswith("\n"):
        raise ValueError("public key armor must end with one LF")
    lines = text[:-1].split("\n")
    begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    end = "-----END PGP PUBLIC KEY BLOCK-----"
    if len(lines) < 4 or lines[0] != begin or lines[1] != "" or lines[-1] != end:
        raise ValueError(
            "public key artifact must contain exactly one public-key armor block"
        )
    if lines.count(begin) != 1 or lines.count(end) != 1:
        raise ValueError(
            "public key artifact must contain exactly one public-key armor block"
        )
    interior = lines[2:-1]
    if not interior or any(not line for line in interior):
        raise ValueError("public key armor contains an empty payload line")
    checksum_line: str | None = None
    if interior[-1].startswith("="):
        checksum_line = interior[-1]
        encoded_lines = interior[:-1]
    else:
        encoded_lines = interior
    if (
        not encoded_lines
        or any(
            re.fullmatch(r"[A-Za-z0-9+/]{64}", line) is None
            for line in encoded_lines[:-1]
        )
        or re.fullmatch(
            r"[A-Za-z0-9+/]{1,64}={0,2}",
            encoded_lines[-1],
        )
        is None
    ):
        raise ValueError("public key armor payload is not canonical base64")

    expected_checksum: bytes | None = None
    if checksum_line is not None:
        if re.fullmatch(r"=[A-Za-z0-9+/]{4}", checksum_line) is None:
            raise ValueError("public key armor contains a malformed checksum")
        try:
            expected_checksum = base64.b64decode(
                checksum_line[1:],
                validate=True,
            )
        except (binascii.Error, ValueError) as exc:
            raise ValueError("public key armor contains a malformed checksum") from exc
        if (
            len(expected_checksum) != 3
            or base64.b64encode(expected_checksum).decode("ascii") != checksum_line[1:]
        ):
            raise ValueError("public key armor contains a malformed checksum")

    encoded = "".join(encoded_lines)
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("public key armor payload is not valid base64") from exc
    if not decoded:
        raise ValueError("public key armor payload must not be empty")
    if base64.b64encode(decoded).decode("ascii") != encoded:
        raise ValueError("public key armor payload is not canonical base64")
    if expected_checksum is not None and expected_checksum != bootstrap_v2_crc24(
        decoded
    ):
        raise ValueError("public key armor checksum does not match its payload")
    return decoded


def bootstrap_v2_crc24(value: bytes) -> bytes:
    checksum = 0xB704CE
    for octet in value:
        checksum ^= octet << 16
        for _bit in range(8):
            checksum <<= 1
            if checksum & 0x1000000:
                checksum ^= 0x1864CFB
    return (checksum & 0xFFFFFF).to_bytes(3, "big")


def bootstrap_v2_public_key_visible_text(value: str) -> str:
    visible_lines: list[str] = []
    for line in value.split("\n"):
        if (
            not line
            or line
            in {
                "-----BEGIN PGP PUBLIC KEY BLOCK-----",
                "-----END PGP PUBLIC KEY BLOCK-----",
            }
            or re.fullmatch(r"=?[A-Za-z0-9+/]+={0,2}", line)
        ):
            continue
        visible_lines.append(line)
    return "\n".join(visible_lines)


def read_bootstrap_v2_new_packet_body(value: bytes, offset: int) -> tuple[bytes, int]:
    chunks: list[bytes] = []
    while True:
        if offset >= len(value):
            raise ValueError("public key packet length is truncated")
        first = value[offset]
        offset += 1
        if first < 192:
            length = first
        elif first < 224:
            if offset >= len(value):
                raise ValueError("public key packet length is truncated")
            length = ((first - 192) << 8) + value[offset] + 192
            offset += 1
        elif first == 255:
            if offset + 4 > len(value):
                raise ValueError("public key packet length is truncated")
            length = int.from_bytes(value[offset : offset + 4], "big")
            offset += 4
        else:
            length = 1 << (first & 0x1F)
            end = offset + length
            if end > len(value):
                raise ValueError("public key partial packet body is truncated")
            chunks.append(value[offset:end])
            offset = end
            continue
        end = offset + length
        if end > len(value):
            raise ValueError("public key packet body is truncated")
        chunks.append(value[offset:end])
        return b"".join(chunks), end


def parse_bootstrap_v2_public_key_packets(value: bytes) -> list[tuple[int, bytes]]:
    packets: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(value):
        header = value[offset]
        offset += 1
        if header & 0x80 == 0:
            raise ValueError("public key packet header is malformed")
        if header & 0x40:
            tag = header & 0x3F
            body, offset = read_bootstrap_v2_new_packet_body(value, offset)
        else:
            tag = (header >> 2) & 0x0F
            length_type = header & 0x03
            length_octets = (1, 2, 4)[length_type] if length_type < 3 else 0
            if length_type == 3:
                raise ValueError(
                    "public key artifact uses an indeterminate packet length"
                )
            else:
                if offset + length_octets > len(value):
                    raise ValueError("public key packet length is truncated")
                length = int.from_bytes(value[offset : offset + length_octets], "big")
                offset += length_octets
                end = offset + length
                if end > len(value):
                    raise ValueError("public key packet body is truncated")
                body = value[offset:end]
                offset = end
        if tag == 0:
            raise ValueError("public key artifact contains a reserved packet tag")
        packets.append((tag, body))

    if not packets:
        raise ValueError("public key artifact contains no packets")
    if any(tag in BOOTSTRAP_V2_REJECTED_PACKET_TAGS for tag, _body in packets):
        raise ValueError("public key artifact contains a secret-key packet")
    rejected_tags = sorted(
        {tag for tag, _body in packets} - BOOTSTRAP_V2_ALLOWED_PACKET_TAGS
    )
    if rejected_tags:
        raise ValueError(
            "public key artifact contains a packet type outside the trusted public-key grammar"
        )
    return packets


def read_bootstrap_v2_mpi(value: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 2 > len(value):
        raise ValueError("public key MPI length is truncated")
    bit_length = int.from_bytes(value[offset : offset + 2], "big")
    offset += 2
    byte_length = (bit_length + 7) // 8
    end = offset + byte_length
    if bit_length == 0 or end > len(value):
        raise ValueError("public key MPI body is malformed")
    mpi = value[offset:end]
    actual_bit_length = (len(mpi) - 1) * 8 + mpi[0].bit_length()
    if mpi[0] == 0 or actual_bit_length != bit_length:
        raise ValueError("public key MPI is not canonically encoded")
    return mpi, end


def read_bootstrap_v2_subpacket_length(
    value: bytes, offset: int, *, label: str
) -> tuple[int, int]:
    if offset >= len(value):
        raise ValueError(f"{label} subpacket length is truncated")
    first = value[offset]
    offset += 1
    if first < 192:
        length = first
    elif first < 224:
        if offset >= len(value):
            raise ValueError(f"{label} subpacket length is truncated")
        length = ((first - 192) << 8) + value[offset] + 192
        offset += 1
    elif first == 255:
        if offset + 4 > len(value):
            raise ValueError(f"{label} subpacket length is truncated")
        length = int.from_bytes(value[offset : offset + 4], "big")
        offset += 4
        if length < 8_384:
            raise ValueError(f"{label} subpacket length is not canonical")
    else:
        raise ValueError(f"{label} subpacket length is not canonical")
    if length == 0:
        raise ValueError(f"{label} subpacket is missing its type")
    if offset + length > len(value):
        raise ValueError(f"{label} subpacket body is truncated")
    return length, offset


def parse_bootstrap_v2_subpackets(
    value: bytes,
    *,
    label: str,
    critical_type_bit: bool,
) -> list[tuple[int, bool, bytes]]:
    subpackets: list[tuple[int, bool, bytes]] = []
    offset = 0
    while offset < len(value):
        length, body_offset = read_bootstrap_v2_subpacket_length(
            value, offset, label=label
        )
        end = body_offset + length
        encoded_type = value[body_offset]
        critical = critical_type_bit and bool(encoded_type & 0x80)
        subpacket_type = encoded_type & 0x7F if critical_type_bit else encoded_type
        if subpacket_type == 0:
            raise ValueError(f"{label} subpacket type is reserved")
        subpackets.append((subpacket_type, critical, value[body_offset + 1 : end]))
        offset = end
    return subpackets


def bootstrap_v2_printable_packet_text(value: bytes) -> list[str]:
    return [match.decode("ascii") for match in re.findall(rb"[\x20-\x7e]+", value)]


def bootstrap_v2_signature_subpacket_text(
    subpacket_type: int,
    value: bytes,
    *,
    nesting_depth: int,
) -> list[str]:
    if subpacket_type == 28:
        try:
            signer_user_id = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(
                "signature signer user ID subpacket must be UTF-8"
            ) from exc
        if not signer_user_id or NUL_TEXT in signer_user_id:
            raise ValueError("signature signer user ID subpacket is malformed")
        return [signer_user_id]
    if subpacket_type == 20:
        if len(value) < 8:
            raise ValueError("signature notation data subpacket is truncated")
        name_length = int.from_bytes(value[4:6], "big")
        notation_length = int.from_bytes(value[6:8], "big")
        name_end = 8 + name_length
        notation_end = name_end + notation_length
        if name_end > len(value) or notation_end != len(value):
            raise ValueError("signature notation data subpacket lengths are malformed")
    if subpacket_type == 32:
        if nesting_depth >= 4:
            raise ValueError(
                "embedded signature subpacket nesting exceeds the trusted limit"
            )
        return validate_bootstrap_v2_signature_packet_body(
            value, nesting_depth=nesting_depth + 1
        )
    return bootstrap_v2_printable_packet_text(value)


def validate_bootstrap_v2_user_attribute_packet_body(value: bytes) -> list[str]:
    subpackets = parse_bootstrap_v2_subpackets(
        value,
        label="user attribute",
        critical_type_bit=False,
    )
    if not subpackets:
        raise ValueError("public key user attribute packet must contain a subpacket")
    human_values: list[str] = []
    for subpacket_type, _critical, body in subpackets:
        if subpacket_type != 1:
            raise ValueError(
                "public key user attribute subpacket type is outside the trusted grammar"
            )
        if len(body) < 16:
            raise ValueError("public key image attribute header is truncated")
        header_length = int.from_bytes(body[:2], "little")
        if header_length != 16:
            raise ValueError("public key image attribute header length is malformed")
        if body[2] != 1 or body[3] != 1 or any(body[4:header_length]):
            raise ValueError(
                "public key image attribute header is outside the trusted grammar"
            )
        image = body[header_length:]
        if not image:
            raise ValueError("public key image attribute payload must not be empty")
        human_values.extend(bootstrap_v2_printable_packet_text(image))
    return human_values


def validate_bootstrap_v2_key_packet_body(value: bytes, *, label: str) -> None:
    if len(value) < 7 or value[0] != 4:
        raise ValueError(f"{label} packet must contain a version 4 public key body")
    algorithm = value[5]
    offset = 6
    if algorithm == 1:
        modulus, offset = read_bootstrap_v2_mpi(value, offset)
        exponent, offset = read_bootstrap_v2_mpi(value, offset)
        if int.from_bytes(modulus, "big").bit_length() < 2048:
            raise ValueError(f"{label} RSA modulus is below the trusted minimum")
        if modulus[-1] & 1 == 0:
            raise ValueError(f"{label} RSA modulus is invalid")
        exponent_value = int.from_bytes(exponent, "big")
        if exponent_value < 3 or exponent_value % 2 == 0:
            raise ValueError(f"{label} RSA exponent is invalid")
    elif algorithm in {18, 22}:
        if offset >= len(value):
            raise ValueError(f"{label} curve identifier is truncated")
        oid_length = value[offset]
        offset += 1
        oid_end = offset + oid_length
        if oid_length == 0 or oid_end > len(value):
            raise ValueError(f"{label} curve identifier is malformed")
        oid = value[offset:oid_end]
        offset = oid_end
        point, offset = read_bootstrap_v2_mpi(value, offset)
        expected_oid = (
            BOOTSTRAP_V2_CURVE25519_OID if algorithm == 18 else BOOTSTRAP_V2_ED25519_OID
        )
        if (
            oid != expected_oid
            or len(point) != 33
            or point[0] != 0x40
            or not any(point[1:])
        ):
            raise ValueError(f"{label} curve key material is malformed")
        if algorithm == 18:
            if offset >= len(value):
                raise ValueError(f"{label} ECDH parameters are truncated")
            parameter_length = value[offset]
            offset += 1
            parameter_end = offset + parameter_length
            if parameter_length != 3 or parameter_end > len(value):
                raise ValueError(f"{label} ECDH parameters are malformed")
            reserved, hash_algorithm, cipher_algorithm = value[offset:parameter_end]
            if (
                reserved != 1
                or hash_algorithm not in {8, 9, 10}
                or cipher_algorithm not in {7, 8, 9}
            ):
                raise ValueError(
                    f"{label} ECDH parameters are outside the trusted policy"
                )
            offset = parameter_end
    else:
        raise ValueError(f"{label} algorithm is outside the trusted public-key policy")
    if offset != len(value):
        raise ValueError(f"{label} packet contains trailing key material")


def validate_bootstrap_v2_signature_packet_body(
    value: bytes, *, nesting_depth: int = 0
) -> list[str]:
    if len(value) < 10 or value[0] != 4:
        raise ValueError("signature packet must contain a version 4 signature body")
    public_key_algorithm = value[2]
    hashed_length = int.from_bytes(value[4:6], "big")
    hashed_start = 6
    hashed_end = hashed_start + hashed_length
    if hashed_end + 2 > len(value):
        raise ValueError("signature packet hashed area is truncated")
    hashed_subpackets = parse_bootstrap_v2_subpackets(
        value[hashed_start:hashed_end],
        label="signature hashed area",
        critical_type_bit=True,
    )
    unhashed_length = int.from_bytes(value[hashed_end : hashed_end + 2], "big")
    unhashed_start = hashed_end + 2
    unhashed_end = unhashed_start + unhashed_length
    if unhashed_end + 2 > len(value):
        raise ValueError("signature packet unhashed area is truncated")
    unhashed_subpackets = parse_bootstrap_v2_subpackets(
        value[unhashed_start:unhashed_end],
        label="signature unhashed area",
        critical_type_bit=True,
    )
    offset = unhashed_end + 2
    mpi_count = (
        1
        if public_key_algorithm in {1, 2, 3}
        else 2
        if public_key_algorithm in {17, 19, 22}
        else 0
    )
    if mpi_count == 0:
        raise ValueError(
            "signature packet algorithm is outside the trusted public-key grammar"
        )
    for _index in range(mpi_count):
        _mpi, offset = read_bootstrap_v2_mpi(value, offset)
    if offset != len(value):
        raise ValueError("signature packet contains trailing material")
    human_values: list[str] = []
    for subpacket_type, _critical, body in (
        *hashed_subpackets,
        *unhashed_subpackets,
    ):
        if subpacket_type in BOOTSTRAP_V2_RESERVED_SIGNATURE_SUBPACKET_TYPES:
            raise ValueError("signature subpacket type is reserved")
        human_values.extend(
            bootstrap_v2_signature_subpacket_text(
                subpacket_type,
                body,
                nesting_depth=nesting_depth,
            )
        )
    return human_values


def validate_bootstrap_v2_public_key_grammar(packets: list[tuple[int, bytes]]) -> None:
    index = 0
    key_count = 0
    while index < len(packets):
        tag, body = packets[index]
        if tag != 6:
            raise ValueError(
                "public key export must begin each transferable key with a public-key packet"
            )
        validate_bootstrap_v2_key_packet_body(body, label="public-key")
        key_count += 1
        index += 1
        identity_count = 0
        while index < len(packets) and packets[index][0] != 6:
            tag, body = packets[index]
            if tag == 2:
                validate_bootstrap_v2_signature_packet_body(body)
                index += 1
                continue
            if tag in {13, 17}:
                if not body:
                    raise ValueError("public key identity packet must not be empty")
                if tag == 17:
                    validate_bootstrap_v2_user_attribute_packet_body(body)
                identity_count += 1
            elif tag == 14:
                validate_bootstrap_v2_key_packet_body(body, label="public-subkey")
            else:
                raise ValueError(
                    "public key packet ordering is outside the trusted grammar"
                )
            index += 1
            signature_count = 0
            while index < len(packets) and packets[index][0] == 2:
                validate_bootstrap_v2_signature_packet_body(packets[index][1])
                signature_count += 1
                index += 1
            if signature_count == 0:
                raise ValueError(
                    "public key identity and subkey packets require a signature"
                )
        if identity_count == 0:
            raise ValueError(
                "transferable public key must contain a signed identity packet"
            )
    if key_count == 0:
        raise ValueError("public key artifact contains no transferable public keys")


def bootstrap_v2_human_readable_packet_text(
    packets: list[tuple[int, bytes]],
) -> list[str]:
    values: list[str] = []
    for tag, body in packets:
        if tag == 13:
            try:
                user_id = body.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("public key user ID must be UTF-8") from exc
            if not user_id or NUL_TEXT in user_id:
                raise ValueError("public key user ID is malformed")
            values.append(user_id)
            continue
        if tag == 17:
            values.extend(validate_bootstrap_v2_user_attribute_packet_body(body))
            continue
        if tag == 2:
            values.extend(validate_bootstrap_v2_signature_packet_body(body))
            continue
        values.extend(
            match.decode("ascii") for match in re.findall(rb"[\x20-\x7e]{8,}", body)
        )
    return values


def validate_bootstrap_v2_public_key(value: bytes, *, relative: Path) -> list[str]:
    issues: list[str] = []
    try:
        decoded = decode_bootstrap_v2_public_key_armor(value)
        packets = parse_bootstrap_v2_public_key_packets(decoded)
        validate_bootstrap_v2_public_key_grammar(packets)
        human_values = bootstrap_v2_human_readable_packet_text(packets)
        for human_text in human_values:
            if contains_bootstrap_v2_nonpublic_key_marker(human_text):
                issues.append(
                    "public key human-readable content contains a non-public key marker"
                )
        risky_human_values = [
            human_text
            for human_text in human_values
            if bootstrap_v2_privacy_risk_lines(human_text)
        ]
        if risky_human_values:
            expected_fingerprint = BOOTSTRAP_V2_TRUSTED_OPENPGP_RISK_VALUES_SHA256.get(
                relative
            )
            observed_fingerprint = bootstrap_v2_privacy_risk_lines_fingerprint(
                risky_human_values
            )
            if (
                expected_fingerprint is None
                or observed_fingerprint != expected_fingerprint
            ):
                issues.append(
                    "public key human-readable content contains raw/sensitive evidence"
                )
    except ValueError as exc:
        issues.append(safe_exception_message(exc))
    return issues


def validate_bootstrap_v2_ci_transition(
    base_entries: dict[Path, GitIndexEntry],
    candidate_entries: dict[Path, GitIndexEntry],
) -> list[str]:
    issues: list[str] = []
    base_ci = base_entries.get(BOOTSTRAP_V2_CI_PATH)
    candidate_ci = candidate_entries.get(BOOTSTRAP_V2_CI_PATH)
    template = base_entries.get(BOOTSTRAP_V2_PERMANENT_CI_TEMPLATE_PATH)
    if (
        template is None
        or template.mode != "100644"
        or template.object_id != BOOTSTRAP_V2_PERMANENT_CI_BLOB_OID
    ):
        issues.append(
            "trusted base permanent CI template does not match the authorized blob"
        )
    if base_ci is None or base_ci.mode != "100644":
        issues.append("trusted base CI is not an exact regular file")
    elif base_ci.object_id not in {
        BOOTSTRAP_V2_LEGACY_CI_BLOB_OID,
        BOOTSTRAP_V2_PERMANENT_CI_BLOB_OID,
    }:
        issues.append("trusted base CI blob is outside the authorized migration")
    if (
        candidate_ci is None
        or candidate_ci.mode != "100644"
        or candidate_ci.object_id != BOOTSTRAP_V2_PERMANENT_CI_BLOB_OID
    ):
        issues.append(
            ".github/workflows/ci.yml: candidate CI must equal the authorized permanent CI blob"
        )
    return issues


def validate_history_v2_ci_tree(
    candidate_entries: dict[Path, GitIndexEntry],
) -> list[str]:
    candidate_ci = candidate_entries.get(BOOTSTRAP_V2_CI_PATH)
    if (
        candidate_ci is None
        or candidate_ci.mode != "100644"
        or candidate_ci.object_id != BOOTSTRAP_V2_PERMANENT_CI_BLOB_OID
    ):
        return [
            ".github/workflows/ci.yml: post-migration CI must equal the authorized permanent CI blob"
        ]
    return []


def validate_bootstrap_v2_candidate(
    base_root: Path,
    candidate_root: Path,
    *,
    post_migration: bool = False,
    candidate_snapshots: tuple[HistoryV2FileSnapshot, ...] | None = None,
) -> list[str]:
    base_root = base_root.resolve()
    candidate_root = candidate_root.resolve()
    if not base_root.is_dir():
        return ["base root must be an existing directory"]
    if not candidate_root.is_dir():
        return ["candidate root must be an existing directory"]
    if base_root == candidate_root and not post_migration:
        return ["base and candidate roots must be distinct directories"]
    if post_migration and base_root != candidate_root:
        return ["post-migration validation requires one exact candidate root"]
    if BOOTSTRAP_V2_ALLOWED_FILES != BOOTSTRAP_V2_REQUIRED_FILES:
        return ["trusted bootstrap-v2 allowed/required inventories differ"]

    issues = BoundedDiagnosticList()
    base_entries, base_index_issue = git_index_entries(
        base_root,
        label="trusted base",
        max_entries=BOOTSTRAP_V2_MAX_CANDIDATE_ENTRIES,
    )
    if base_index_issue is not None or base_entries is None:
        return [base_index_issue or "trusted base Git index could not be inspected"]

    protected_base_paths = set(base_entries) - BOOTSTRAP_V2_TEMPORARY_PATHS
    allowed_candidate_paths = BOOTSTRAP_V2_ALLOWED_FILES | protected_base_paths
    candidate_entries, candidate_index_issue = git_index_entries(
        candidate_root,
        label="candidate",
        max_entries=BOOTSTRAP_V2_MAX_CANDIDATE_ENTRIES,
    )
    if candidate_index_issue is not None or candidate_entries is None:
        return [candidate_index_issue or "candidate Git index could not be inspected"]
    if post_migration:
        issues.extend(validate_history_v2_ci_tree(candidate_entries))
    else:
        issues.extend(
            validate_bootstrap_v2_ci_transition(base_entries, candidate_entries)
        )
    indexed_paths = set(candidate_entries)
    immutable_issue_messages: set[str] = set()

    def append_immutable_issue(relative: Path, detail: str) -> None:
        message = f"{display_relative_path(relative)}: {detail}"
        if message not in immutable_issue_messages:
            immutable_issue_messages.add(message)
            issues.append(message)

    for relative in sorted(protected_base_paths):
        if relative == BOOTSTRAP_V2_CI_PATH:
            continue
        base_entry = base_entries[relative]
        candidate_entry = candidate_entries.get(relative)
        if candidate_entry is None:
            append_immutable_issue(
                relative, "existing tracked artifact must not be deleted"
            )
            continue
        if candidate_entry.mode != base_entry.mode:
            append_immutable_issue(
                relative, "existing tracked artifact mode must not change"
            )
        if candidate_entry.object_id != base_entry.object_id:
            append_immutable_issue(
                relative, "existing tracked artifact content must not be rewritten"
            )

    for relative, entry in sorted(
        candidate_entries.items(), key=lambda item: item[0].as_posix()
    ):
        display_relative = display_relative_path(relative)
        mode = entry.mode
        if mode == "120000":
            issues.append(f"{display_relative}: symlink artifact is not allowed")
        elif mode == "160000":
            issues.append(f"{display_relative}: gitlink artifact is not allowed")
        elif relative in BOOTSTRAP_V2_ALLOWED_FILES and mode != "100644":
            issues.append(f"{display_relative}: candidate file mode must be 100644")
    for relative in sorted(BOOTSTRAP_V2_TEMPORARY_PATHS & indexed_paths):
        issues.append(
            f"{relative.as_posix()}: temporary bootstrap artifact must be absent from the candidate index"
        )
    for relative in sorted(BOOTSTRAP_V2_REQUIRED_FILES - indexed_paths):
        issues.append(
            f"{relative.as_posix()}: required bootstrap-v2 candidate index entry is missing"
        )
    unexpected_index = (
        indexed_paths - allowed_candidate_paths - BOOTSTRAP_V2_TEMPORARY_PATHS
    )
    for relative in sorted(unexpected_index):
        issues.append(
            f"{display_relative_path(relative)}: unexpected bootstrap-v2 candidate index entry"
        )

    if candidate_snapshots is None:
        candidate_snapshots, path_issue = snapshot_bootstrap_v2_files(
            candidate_root,
            max_entries=BOOTSTRAP_V2_MAX_CANDIDATE_ENTRIES,
        )
    else:
        path_issue = None
    if path_issue is not None or candidate_snapshots is None:
        issues.append(path_issue or "candidate artifact enumeration failed")
        return issues
    observed = {snapshot.relative for snapshot in candidate_snapshots}
    for relative in sorted(BOOTSTRAP_V2_TEMPORARY_PATHS & observed):
        issues.append(
            f"{relative.as_posix()}: temporary bootstrap artifact must be absent from the final candidate tree"
        )
    for relative in sorted(BOOTSTRAP_V2_REQUIRED_FILES - observed):
        issues.append(
            f"{relative.as_posix()}: required bootstrap-v2 candidate artifact is missing"
        )
    unexpected = observed - allowed_candidate_paths - BOOTSTRAP_V2_TEMPORARY_PATHS
    for relative in sorted(unexpected):
        issues.append(
            f"{display_relative_path(relative)}: unexpected bootstrap-v2 candidate artifact"
        )
    for relative in sorted(observed - indexed_paths):
        issues.append(
            f"{display_relative_path(relative)}: untracked candidate artifact is not allowed"
        )
    for relative in sorted(indexed_paths - observed):
        if candidate_entries[relative].mode not in {"120000", "160000"}:
            issues.append(
                f"{display_relative_path(relative)}: indexed candidate artifact is missing"
            )

    total_size = 0
    snapshot_by_relative = {
        snapshot.relative: snapshot for snapshot in candidate_snapshots
    }
    for relative in sorted(protected_base_paths):
        if relative == BOOTSTRAP_V2_CI_PATH:
            continue
        snapshot = snapshot_by_relative.get(relative)
        if snapshot is None:
            append_immutable_issue(
                relative, "existing tracked artifact must not be deleted"
            )
            continue
        base_entry = base_entries[relative]
        if snapshot.is_symlink:
            worktree_mode = "120000"
            if worktree_mode != base_entry.mode:
                append_immutable_issue(
                    relative, "existing tracked artifact mode must not change"
                )
            continue
        if snapshot.value is None or not snapshot.is_regular:
            issues.append(
                f"{display_relative_path(relative)}: base immutability check failed"
            )
            continue
        worktree_mode = "100755" if snapshot.mode & 0o111 else "100644"
        if worktree_mode != base_entry.mode:
            append_immutable_issue(
                relative, "existing tracked artifact mode must not change"
            )
        observed_object_id = git_blob_bytes_object_id(
            snapshot.value,
            expected_length=len(base_entry.object_id),
        )
        if observed_object_id != base_entry.object_id:
            append_immutable_issue(
                relative, "existing tracked artifact content must not be rewritten"
            )
    for relative in sorted(observed & BOOTSTRAP_V2_ALLOWED_FILES):
        snapshot = snapshot_by_relative[relative]
        display_relative = display_relative_path(relative)
        if snapshot.is_symlink:
            if candidate_entries.get(relative, GitIndexEntry("", "")).mode != "120000":
                issues.append(f"{display_relative}: symlink artifact is not allowed")
            continue
        try:
            value = snapshot.value
            size = snapshot.size
            if value is None or not snapshot.is_regular or len(value) != size:
                issues.append(
                    f"{display_relative}: candidate artifact changed while being read"
                )
                continue
            if size > BOOTSTRAP_V2_MAX_FILE_BYTES:
                issues.append(
                    f"{display_relative}: candidate artifact exceeds the trusted size limit"
                )
                continue
            if (
                relative.suffix.lower() == ".py"
                and size > BOOTSTRAP_V2_MAX_PYTHON_SOURCE_BYTES
            ):
                issues.append(
                    f"{display_relative}: Python source exceeds the trusted AST size limit"
                )
                continue
            total_size += size
            candidate_entry = candidate_entries.get(relative)
            if candidate_entry is not None:
                worktree_mode = "100755" if snapshot.mode & 0o111 else "100644"
                if worktree_mode != candidate_entry.mode:
                    issues.append(
                        f"{display_relative}: candidate worktree mode does not match candidate index"
                    )
                worktree_object_id = git_blob_bytes_object_id(
                    value,
                    expected_length=len(candidate_entry.object_id),
                )
                if worktree_object_id != candidate_entry.object_id:
                    issues.append(
                        f"{display_relative}: candidate worktree content does not match candidate index"
                    )
            if relative in BOOTSTRAP_V2_PUBLIC_KEY_FILES:
                if size > BOOTSTRAP_V2_MAX_PUBLIC_KEY_BYTES:
                    issues.append(
                        f"{display_relative}: public key artifact exceeds the trusted size limit"
                    )
                    continue
                try:
                    text = value.decode("ascii")
                except UnicodeDecodeError:
                    text = ""
                expected_digest = BOOTSTRAP_V2_PUBLIC_KEY_SHA256[relative]
                if hashlib.sha256(value).hexdigest() != expected_digest:
                    issues.append(
                        f"{display_relative}: public key artifact digest does not match trusted policy"
                    )
                if text and contains_bootstrap_v2_privacy_risk_text(
                    bootstrap_v2_public_key_visible_text(text),
                    relative=relative,
                ):
                    issues.append(
                        f"{display_relative}: infrastructure text contains raw/sensitive evidence"
                    )
                issues.extend(
                    f"{display_relative}: {issue}"
                    for issue in validate_bootstrap_v2_public_key(
                        value, relative=relative
                    )
                )
                continue

            text = value.decode("utf-8")
            if NUL_TEXT in text:
                issues.append(
                    f"{display_relative}: infrastructure text contains a NUL byte"
                )
            if contains_bootstrap_v2_privacy_risk_text(text, relative=relative):
                issues.append(
                    f"{display_relative}: infrastructure text contains raw/sensitive evidence"
                )
            if (
                relative.suffix.lower() == ".py"
                and contains_bootstrap_v2_python_privacy_risk(
                    text,
                    relative=relative,
                )
            ):
                issues.append(
                    f"{display_relative}: infrastructure text contains raw/sensitive evidence"
                )
            if relative.suffix.lower() == ".json":
                data = parse_strict_json(text)
                if contains_bootstrap_v2_decoded_privacy_risk(data, relative=relative):
                    issues.append(
                        f"{display_relative}: infrastructure text contains raw/sensitive evidence"
                    )
                if relative in BOOTSTRAP_V2_SCHEMA_FILES:
                    if not isinstance(data, dict):
                        issues.append(
                            f"{display_relative}: v2 JSON schema root must be an object"
                        )
                    elif data.get("$schema") != BOOTSTRAP_V2_JSON_SCHEMA_DIALECT:
                        issues.append(
                            f"{display_relative}: v2 JSON schema dialect is not trusted"
                        )
        except RecursionError:
            detail = (
                JSON_NESTING_ERROR
                if relative.suffix.lower() == ".json"
                else "candidate artifact validation exceeds the trusted depth limit"
            )
            issues.append(f"{display_relative}: {detail}")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            issues.append(f"{display_relative}: {safe_exception_message(exc)}")
    if post_migration:
        total_size = sum(snapshot.size for snapshot in candidate_snapshots)
    if total_size > BOOTSTRAP_V2_MAX_TREE_BYTES:
        issues.append(
            "history-v2 tree exceeds the trusted size limit"
            if post_migration
            else "bootstrap-v2 candidate tree exceeds the trusted size limit"
        )
    return issues


def history_v2_mutable_artifact(relative: Path) -> bool:
    return bool(
        history_v2_run_artifact(relative)
        or allowed_retained_text_artifact(relative)
        or allowed_retained_json_artifact(relative) is not None
        or allowed_retained_jsonl_artifact(relative) is not None
    )


def history_v2_tree_artifact_allowed(relative: Path) -> bool:
    return bool(
        relative in BOOTSTRAP_V2_ALLOWED_FILES
        or relative == Path("scripts/trusted_history_ci.py")
        or history_v2_mutable_artifact(relative)
    )


def classify_history_v2_transaction(
    changed: list[tuple[str, Path]],
) -> str:
    if not changed:
        raise ValueError("history-v2 transaction is empty")
    publication = tuple(
        history_v2_mutable_artifact(relative) for _status, relative in changed
    )
    if all(publication):
        return "publication"
    if any(publication):
        raise ValueError("history-v2 transaction mixes publication and admin paths")
    return "admin"


@dataclass
class HistoryV2WorkBudget:
    path_references: int = 0
    blob_read_operations: int = 0
    blob_read_bytes: int = 0
    parent_edges: int = 0
    diff_calls: int = 0
    diff_bytes: int = 0
    materializations: int = 0
    temp_disk_bytes: int = 0
    blob_payloads: dict[str, bytes] = field(default_factory=dict)
    path_payloads: dict[tuple[str, Path], bytes] = field(default_factory=dict)
    tree_entries: dict[str, tuple[HistoryV2TreeEntry, ...]] = field(
        default_factory=dict
    )
    validated_tree_oids: set[str] = field(default_factory=set)
    domain_contracts: dict[tuple[Path, str], HistoryV2DomainContract | None] = field(
        default_factory=dict
    )
    authorized_domain_revisions: set[tuple[Path, str]] = field(default_factory=set)

    def add_path_references(self, count: int) -> None:
        if count < 0 or self.path_references + count > HISTORY_V2_MAX_PATH_REFERENCES:
            raise ValueError("history-v2 path-reference budget exceeded")
        self.path_references += count

    def add_parent_edges(self, count: int) -> None:
        if count < 0 or self.parent_edges + count > HISTORY_V2_MAX_PARENT_EDGES:
            raise ValueError("history-v2 parent-edge budget exceeded")
        self.parent_edges += count

    def reserve_diff_call(self) -> None:
        if self.diff_calls >= HISTORY_V2_MAX_DIFF_CALLS:
            raise ValueError("history-v2 diff-call budget exceeded")
        self.diff_calls += 1

    def add_diff_bytes(self, count: int) -> None:
        if count < 0 or self.diff_bytes + count > HISTORY_V2_MAX_DIFF_BYTES:
            raise ValueError("history-v2 diff-output budget exceeded")
        self.diff_bytes += count

    def reserve_blob_read(self, expected_bytes: int) -> None:
        if (
            expected_bytes < 0
            or self.blob_read_operations >= HISTORY_V2_MAX_BLOB_READ_OPERATIONS
            or self.blob_read_bytes + expected_bytes > HISTORY_V2_MAX_BLOB_READ_BYTES
        ):
            raise ValueError("history-v2 blob-read budget exceeded")
        self.blob_read_operations += 1
        self.blob_read_bytes += expected_bytes

    def add_blob_read_bytes(self, count: int) -> None:
        if count < 0 or self.blob_read_bytes + count > HISTORY_V2_MAX_BLOB_READ_BYTES:
            raise ValueError("history-v2 blob-read budget exceeded")
        self.blob_read_bytes += count

    def reserve_materialization(self, logical_bytes: int) -> None:
        if (
            logical_bytes < 0
            or self.materializations >= HISTORY_V2_MAX_MATERIALIZATIONS
            or self.temp_disk_bytes + logical_bytes > HISTORY_V2_MAX_TEMP_DISK_BYTES
        ):
            raise ValueError("history-v2 materialization budget exceeded")
        self.materializations += 1
        self.temp_disk_bytes += logical_bytes


def _history_v2_domain_issue_payload(
    value: Any,
) -> tuple[bool, bool]:
    if type(value) is not list or len(value) > HISTORY_V2_MAX_DOMAIN_ISSUES:
        return False, False
    encoded_bytes = 0
    for issue in value:
        if (
            type(issue) is not str
            or not issue
            or len(issue) > HISTORY_V2_MAX_DOMAIN_ISSUE_CHARACTERS
            or any(
                ord(character) < 0x20 or ord(character) > 0x7E for character in issue
            )
        ):
            return False, False
        encoded_bytes += len(issue.encode("ascii"))
        if encoded_bytes > HISTORY_V2_MAX_DOMAIN_ISSUE_BYTES:
            return False, False
    return True, bool(value)


def _history_v2_domain_source_snapshots(
    trusted_root: Path,
) -> tuple[HistoryV2FileSnapshot, ...] | None:
    try:
        root_descriptor = _history_v2_open_directory(
            trusted_root,
            label="trusted history-v2 domain root",
        )
    except ValueError as exc:
        raise ValueError(
            "trusted history-v2 domain validator source is unavailable"
        ) from exc
    snapshots: list[HistoryV2FileSnapshot] = []
    missing = 0
    try:
        for relative in HISTORY_V2_DOMAIN_MODULE_PATHS:
            try:
                snapshots.append(
                    _history_v2_snapshot_relative_file(
                        root_descriptor,
                        relative,
                        max_file_bytes=BOOTSTRAP_V2_MAX_PYTHON_SOURCE_BYTES,
                        label="trusted history-v2 domain source",
                    )
                )
            except ValueError as exc:
                if str(exc) == "trusted history-v2 domain source is missing":
                    missing += 1
                    continue
                raise ValueError(
                    "trusted history-v2 domain validator source is unreadable"
                ) from exc
    finally:
        os.close(root_descriptor)
    if missing == len(HISTORY_V2_DOMAIN_MODULE_PATHS):
        return None
    if missing:
        raise ValueError("trusted history-v2 domain validator source is incomplete")
    if any(not snapshot.is_regular or snapshot.value is None for snapshot in snapshots):
        raise ValueError("trusted history-v2 domain validator source is invalid")
    return tuple(snapshots)


class _HistoryV2FrozenDynamicLoader:
    def __init__(self, module: Any) -> None:
        self.module = module

    def exec_module(self, module: Any) -> None:
        if module is not self.module:
            raise ImportError(
                "trusted history-v2 dynamic helper module is inconsistent"
            )


class _HistoryV2FrozenDynamicSpec:
    def __init__(self, name: str, module: Any) -> None:
        self.name = name
        self.loader = _HistoryV2FrozenDynamicLoader(module)


class _HistoryV2FrozenImportlibUtil:
    def __init__(self, expected_path: Path, module: Any) -> None:
        self.expected_path = expected_path
        self.module = module

    def spec_from_file_location(
        self,
        name: str,
        location: object,
    ) -> _HistoryV2FrozenDynamicSpec | None:
        try:
            observed = Path(location)
        except TypeError:
            return None
        if (
            name != "_retrospective_history_privacy_v2_for_history"
            or observed != self.expected_path
        ):
            return None
        return _HistoryV2FrozenDynamicSpec(name, self.module)

    def module_from_spec(self, spec: object) -> Any:
        if (
            not isinstance(spec, _HistoryV2FrozenDynamicSpec)
            or spec.loader.module is not self.module
        ):
            raise ImportError("trusted history-v2 dynamic helper spec is inconsistent")
        return self.module


def _history_v2_load_frozen_domain_modules(
    trusted_root: Path,
    source_snapshots: tuple[HistoryV2FileSnapshot, ...],
) -> tuple[Any, Any]:
    if tuple(
        snapshot.relative for snapshot in source_snapshots
    ) != HISTORY_V2_DOMAIN_MODULE_PATHS or any(
        not snapshot.is_regular or snapshot.value is None
        for snapshot in source_snapshots
    ):
        raise ValueError(
            "trusted history-v2 domain validator source inventory is invalid"
        )

    source_digest = hashlib.sha256()
    compiled: dict[Path, Any] = {}
    for snapshot in source_snapshots:
        source = snapshot.value or b""
        source_digest.update(snapshot.relative.as_posix().encode("utf-8"))
        source_digest.update(NUL_BYTE)
        source_digest.update(source)
        try:
            compiled[snapshot.relative] = compile(
                source,
                f"<frozen-history-v2:{snapshot.relative.as_posix()}>",
                "exec",
                dont_inherit=True,
            )
        except (SyntaxError, ValueError) as exc:
            raise ValueError(
                "trusted history-v2 domain validator source is invalid"
            ) from exc

    generation = source_digest.hexdigest()[:24]
    modules_by_relative: dict[Path, Any] = {}
    aliases: dict[str, Any] = {}
    registered: list[tuple[str, Any]] = []
    for snapshot in source_snapshots:
        stem = snapshot.relative.stem
        module = type(sys)(f"_history_v2_frozen_pending_{stem}")
        private_name = f"_history_v2_frozen_{generation}_{id(module):x}_{stem}"
        if private_name in sys.modules:
            raise ValueError(
                "trusted history-v2 domain validator module state is ambiguous"
            )
        module.__name__ = private_name
        module.__file__ = str(trusted_root / snapshot.relative)
        module.__package__ = ""
        module.__loader__ = None
        module.__spec__ = None
        modules_by_relative[snapshot.relative] = module
        aliases[stem] = module
        aliases[f"scripts.{stem}"] = module
        sys.modules[private_name] = module
        registered.append((private_name, module))

    package = type(sys)(f"_history_v2_frozen_{generation}_scripts")
    package.__path__ = ()
    for relative, module in modules_by_relative.items():
        setattr(package, relative.stem, module)

    builtin_source = __builtins__
    builtin_values = (
        dict(builtin_source)
        if isinstance(builtin_source, dict)
        else dict(vars(builtin_source))
    )
    original_import = builtin_values["__import__"]

    def frozen_import(
        name: str,
        globals_value: dict[str, Any] | None = None,
        locals_value: dict[str, Any] | None = None,
        fromlist: Sequence[str] = (),
        level: int = 0,
    ) -> Any:
        requested = tuple(fromlist or ())
        if level == 0 and name == "scripts":
            if any(item not in aliases for item in requested):
                raise ModuleNotFoundError(
                    "trusted history-v2 helper dependency is outside policy"
                )
            return package
        if level == 0 and name in aliases:
            if name.startswith("scripts.") and not requested:
                return package
            return aliases[name]
        normalized = name.removeprefix("scripts.") if level == 0 else name
        if normalized.startswith("retrospective_history_"):
            raise ModuleNotFoundError(
                "trusted history-v2 helper dependency is outside policy"
            )
        return original_import(
            name,
            globals_value,
            locals_value,
            requested,
            level,
        )

    frozen_builtins = {**builtin_values, "__import__": frozen_import}
    try:
        for relative in HISTORY_V2_DOMAIN_MODULE_PATHS:
            module = modules_by_relative[relative]
            module.__dict__["__builtins__"] = frozen_builtins
            exec(compiled[relative], module.__dict__)
        privacy_module = modules_by_relative[
            Path("scripts/retrospective_history_privacy_v2.py")
        ]
        runtime_module = modules_by_relative[
            Path("scripts/retrospective_history_v2.py")
        ]
        importlib_facade = type(sys)(f"_history_v2_frozen_{generation}_importlib")
        importlib_facade.util = _HistoryV2FrozenImportlibUtil(
            trusted_root / "scripts" / "retrospective_history_privacy_v2.py",
            privacy_module,
        )
        runtime_module.importlib = importlib_facade
        return (
            modules_by_relative[Path("scripts/retrospective_history_git_v2.py")],
            runtime_module,
        )
    except BaseException:
        for name, module in registered:
            if sys.modules.get(name) is module:
                sys.modules.pop(name, None)
        raise


def _history_v2_domain_contract_from_modules(
    *,
    trusted_root: Path,
    trusted_revision: str,
    trusted_generation: str,
    git_module: Any,
    runtime_module: Any,
) -> HistoryV2DomainContract:
    max_artifact_bytes = getattr(git_module, "MAX_ARTIFACT_BYTES", None)
    max_manifest_bytes = (
        max_artifact_bytes.get("manifest.json")
        if isinstance(max_artifact_bytes, dict)
        else None
    )
    functions = (
        getattr(runtime_module, "validate_v2_runs_with_inventory", None),
        getattr(git_module, "_verify_publisher_attestation", None),
        getattr(git_module, "build_pull_request_merge_plan", None),
        getattr(git_module, "validate_default_branch_update", None),
    )
    if (
        any(not callable(function) for function in functions)
        or type(max_manifest_bytes) is not int
        or not 0 < max_manifest_bytes <= HISTORY_V2_MAX_BLOB_READ_BYTES
    ):
        raise ValueError("trusted history-v2 domain validator contract is invalid")
    return HistoryV2DomainContract(
        validate_v2_runs_with_inventory=functions[0],
        verify_publisher_attestation=functions[1],
        build_pull_request_merge_plan=functions[2],
        validate_default_branch_update=functions[3],
        max_manifest_bytes=max_manifest_bytes,
        trusted_root=trusted_root,
        trusted_revision=trusted_revision,
        trusted_generation=trusted_generation,
    )


def trusted_history_v2_domain_contract(
    *,
    expected_revision: str | None = None,
    candidate_root: Path | None = None,
) -> HistoryV2DomainContract | None:
    global _TRUSTED_HISTORY_V2_DOMAIN
    cached = _TRUSTED_HISTORY_V2_DOMAIN
    if cached is not _HISTORY_V2_DOMAIN_UNSET:
        if not isinstance(cached, HistoryV2DomainContract):
            return None
        if (
            expected_revision is not None
            and cached.trusted_revision != expected_revision
        ):
            expected_revision = canonical_history_v2_oid(
                expected_revision,
                "trusted history-v2 domain base revision",
            )
            if candidate_root is None or cached.trusted_generation is None:
                raise ValueError(
                    "trusted history-v2 domain validator revision is inconsistent"
                )
            observed_generation = history_v2_trust_generation_digest(
                candidate_root,
                expected_revision,
                work_budget=HistoryV2WorkBudget(),
            )
            if observed_generation != cached.trusted_generation:
                raise ValueError(
                    "trusted history-v2 domain validator generation changed"
                )
        if (
            candidate_root is not None
            and cached.trusted_root is not None
            and cached.trusted_root == candidate_root.resolve()
        ):
            raise ValueError(
                "trusted history-v2 domain validator cannot come from the candidate"
            )
        return cached

    trusted_root = Path(__file__).resolve().parent.parent
    if candidate_root is not None and trusted_root == candidate_root.resolve():
        raise ValueError(
            "trusted history-v2 domain validator cannot come from the candidate"
        )
    source_snapshots = _history_v2_domain_source_snapshots(trusted_root)
    if source_snapshots is None:
        _TRUSTED_HISTORY_V2_DOMAIN = None
        return None
    if expected_revision is not None:
        expected_revision = canonical_history_v2_oid(
            expected_revision,
            "trusted history-v2 domain base revision",
        )
    observed_top = Path(
        history_v2_git_text(
            trusted_root,
            "rev-parse",
            "--show-toplevel",
        ).strip()
    ).resolve()
    observed_revision = canonical_history_v2_oid(
        history_v2_git_text(
            trusted_root,
            "rev-parse",
            "--verify",
            "HEAD",
            max_bytes=128,
        ).strip(),
        "trusted history-v2 domain source revision",
    )
    if observed_top != trusted_root:
        raise ValueError("trusted history-v2 domain validator root is inconsistent")
    if history_v2_git_output(
        trusted_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignore-submodules=none",
    ):
        raise ValueError(
            "trusted history-v2 domain validator base snapshot is not pristine"
        )
    trusted_generation = history_v2_trust_generation_digest(
        trusted_root,
        observed_revision,
        work_budget=HistoryV2WorkBudget(),
    )
    if expected_revision is not None and observed_revision != expected_revision:
        if candidate_root is None:
            raise ValueError(
                "trusted history-v2 domain validator is not the exact base snapshot"
            )
        expected_generation = history_v2_trust_generation_digest(
            candidate_root,
            expected_revision,
            work_budget=HistoryV2WorkBudget(),
        )
        if expected_generation != trusted_generation:
            raise ValueError("trusted history-v2 domain validator generation changed")
    source_fingerprints = {
        snapshot.relative: hashlib.sha256(snapshot.value or b"").digest()
        for snapshot in source_snapshots
    }
    try:
        git_module, runtime_module = _history_v2_load_frozen_domain_modules(
            trusted_root,
            source_snapshots,
        )
    except Exception as exc:
        raise ValueError(
            "trusted history-v2 domain validator could not be loaded"
        ) from exc
    final_source_snapshots = _history_v2_domain_source_snapshots(trusted_root)
    if (
        final_source_snapshots is None
        or {
            snapshot.relative: hashlib.sha256(snapshot.value or b"").digest()
            for snapshot in final_source_snapshots
        }
        != source_fingerprints
    ):
        raise ValueError(
            "trusted history-v2 domain validator source changed while loading"
        )

    contract = _history_v2_domain_contract_from_modules(
        trusted_root=trusted_root,
        trusted_revision=observed_revision,
        trusted_generation=trusted_generation,
        git_module=git_module,
        runtime_module=runtime_module,
    )
    _TRUSTED_HISTORY_V2_DOMAIN = contract
    return contract


def history_v2_run_artifact(relative: Path) -> bool:
    return bool(
        not relative.is_absolute() and relative.parts and relative.parts[0] == "runs"
    )


def validate_history_v2_domain_tree(
    root: Path,
    *,
    visible_files: Sequence[Path] | None = None,
    file_snapshots: tuple[HistoryV2FileSnapshot, ...] | None = None,
    trusted_base_rev: str | None = None,
    trusted_revision_domain: bool = False,
    work_budget: HistoryV2WorkBudget | None = None,
) -> list[str]:
    root = root.resolve()
    if visible_files is not None and file_snapshots is not None:
        return ["trusted history-v2 domain inventory source is ambiguous"]
    if file_snapshots is None and visible_files is None:
        file_snapshots, visibility_issue = git_visible_file_snapshots(
            root,
            max_entries=BOOTSTRAP_V2_MAX_CANDIDATE_ENTRIES,
        )
        if visibility_issue is not None or file_snapshots is None:
            return [visibility_issue or "trusted Git file enumeration failed closed"]
    elif file_snapshots is None:
        try:
            relatives = tuple(
                path.relative_to(root) for path in tuple(visible_files or ())
            )
        except ValueError:
            return ["trusted history-v2 domain inventory escaped its root"]
        file_snapshots, visibility_issue = snapshot_explicit_history_v2_files(
            root,
            relatives,
            max_entries=BOOTSTRAP_V2_MAX_CANDIDATE_ENTRIES,
            label="trusted history-v2 domain entry",
        )
        if visibility_issue is not None or file_snapshots is None:
            return [
                visibility_issue
                or "trusted history-v2 domain inventory could not be frozen"
            ]
    frozen_snapshots = tuple(file_snapshots)
    run_files = tuple(
        snapshot
        for snapshot in frozen_snapshots
        if history_v2_run_artifact(snapshot.relative)
    )
    try:
        if trusted_base_rev is None:
            contract = trusted_history_v2_domain_contract()
        elif trusted_revision_domain:
            contract = trusted_history_v2_domain_revision_contract(
                root,
                trusted_base_rev,
                work_budget=work_budget or HistoryV2WorkBudget(),
            )
        else:
            contract = trusted_history_v2_domain_contract(
                expected_revision=trusted_base_rev,
                candidate_root=root,
            )
    except (OSError, UnicodeError, ValueError) as exc:
        return [safe_exception_message(exc)]
    if contract is None:
        return (
            ["trusted history-v2 domain validator is unavailable"] if run_files else []
        )

    inventory: Any = ()
    try:
        if any(
            snapshot.is_symlink or not snapshot.is_regular or snapshot.value is None
            for snapshot in frozen_snapshots
        ):
            raise ValueError(
                "trusted history-v2 domain inventory is not a regular-file snapshot"
            )
        visible_relatives = frozenset(
            snapshot.relative for snapshot in frozen_snapshots
        )
        snapshot_by_relative = {
            snapshot.relative: snapshot for snapshot in frozen_snapshots
        }
        expected_inventory = tuple(
            sorted(
                relative
                for relative in visible_relatives
                if history_v2_run_artifact(relative)
                and relative.name == "manifest.json"
            )
        )
        if len(expected_inventory) > HISTORY_V2_MAX_DOMAIN_MANIFESTS:
            raise ValueError("trusted history-v2 manifest inventory exceeds its limit")
        attestation_issues = BoundedDiagnosticList()
        for relative in expected_inventory:
            manifest = snapshot_by_relative[relative].value
            if (
                manifest is None
                or len(manifest) <= 0
                or len(manifest) > contract.max_manifest_bytes
            ):
                raise ValueError(
                    "trusted history-v2 publisher attestation input is invalid"
                )
            try:
                verified = contract.verify_publisher_attestation(
                    {"manifest.json": manifest}
                )
            except Exception as exc:
                raise ValueError(
                    "trusted history-v2 publisher attestation verifier failed closed"
                ) from exc
            if verified is not True:
                attestation_issues.append(
                    "trusted history-v2 publisher attestation is invalid"
                )
        if attestation_issues:
            return list(dict.fromkeys(attestation_issues))

        with tempfile.TemporaryDirectory(
            prefix="history-v2-domain-snapshot-"
        ) as raw_snapshot:
            helper_root = Path(raw_snapshot) / "tree"
            helper_root.mkdir(mode=0o700)
            helper_paths: list[Path] = []
            for snapshot in frozen_snapshots:
                destination = helper_root / snapshot.relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with destination.open("xb") as stream:
                        stream.write(snapshot.value or b"")
                    destination.chmod(0o400)
                except OSError as exc:
                    raise ValueError(
                        "trusted history-v2 domain snapshot could not be materialized"
                    ) from exc
                helper_paths.append(destination)
            helper_baseline, baseline_issue = snapshot_bootstrap_v2_files(
                helper_root,
                max_entries=BOOTSTRAP_V2_MAX_CANDIDATE_ENTRIES,
            )
            if baseline_issue is not None or helper_baseline is None:
                raise ValueError(
                    "trusted history-v2 domain snapshot could not be frozen"
                )
            try:
                result = contract.validate_v2_runs_with_inventory(
                    helper_root,
                    tuple(helper_paths),
                )
            except Exception as exc:
                raise ValueError(
                    "trusted history-v2 domain validator failed closed"
                ) from exc
            if type(result) is not tuple or len(result) != 2:
                raise ValueError(
                    "trusted history-v2 domain validator result is invalid"
                )
            raw_inventory = result[1]
            frozen_inventory: list[Any] = []
            try:
                for count, item in enumerate(raw_inventory, 1):
                    if count > HISTORY_V2_MAX_DOMAIN_MANIFESTS:
                        raise ValueError(
                            "trusted history-v2 manifest inventory exceeds its limit"
                        )
                    frozen_inventory.append(item)
            except TypeError as exc:
                raise ValueError(
                    "trusted history-v2 manifest inventory is invalid"
                ) from exc
            finally:
                close_raw_inventory = getattr(raw_inventory, "close", None)
                if callable(close_raw_inventory):
                    close_raw_inventory()
            result = (result[0], tuple(frozen_inventory))
            helper_final, final_issue = snapshot_bootstrap_v2_files(
                helper_root,
                max_entries=BOOTSTRAP_V2_MAX_CANDIDATE_ENTRIES,
            )
            if (
                final_issue is not None
                or helper_final is None
                or len(helper_final) != len(helper_baseline)
                or any(
                    not _history_v2_snapshot_protected_equal(before, after)
                    for before, after in zip(
                        helper_baseline,
                        helper_final,
                        strict=True,
                    )
                )
            ):
                raise ValueError(
                    "trusted history-v2 domain snapshot changed during validation"
                )
        valid_issue_payload, has_domain_issues = _history_v2_domain_issue_payload(
            result[0]
        )
        if not valid_issue_payload:
            raise ValueError("trusted history-v2 domain validator result is invalid")
        if has_domain_issues:
            return ["trusted history-v2 domain validator rejected the frozen snapshot"]
        inventory = result[1]

        supplied_inventory: list[Path] = []
        count = 0
        for supplied_relative in inventory:
            count += 1
            if count > HISTORY_V2_MAX_DOMAIN_MANIFESTS:
                raise ValueError(
                    "trusted history-v2 manifest inventory exceeds its limit"
                )
            if not isinstance(supplied_relative, Path):
                raise ValueError("trusted history-v2 manifest inventory is invalid")
            relative = supplied_relative
            if (
                relative.is_absolute()
                or relative.as_posix() != str(relative)
                or not history_v2_run_artifact(relative)
                or relative.name != "manifest.json"
                or relative not in visible_relatives
            ):
                raise ValueError("trusted history-v2 manifest inventory is invalid")
            supplied_inventory.append(relative)
        if (
            len(set(supplied_inventory)) != len(supplied_inventory)
            or tuple(supplied_inventory) != expected_inventory
            or frozenset(supplied_inventory) != frozenset(expected_inventory)
        ):
            raise ValueError(
                "trusted history-v2 manifest inventory is not exact and ordered"
            )
        return []
    except (OSError, UnicodeError, ValueError) as exc:
        return [safe_exception_message(exc)]
    except Exception:
        return ["trusted history-v2 domain validation failed closed"]
    finally:
        close_inventory = getattr(inventory, "close", None)
        if callable(close_inventory):
            close_inventory()


def validate_history_v2_tree(
    root: Path,
    *,
    verify_head_tree: bool = True,
    work_budget: HistoryV2WorkBudget | None = None,
    trusted_base_rev: str | None = None,
    trusted_revision_domain: bool = False,
) -> list[str]:
    root = root.resolve()
    file_snapshots, snapshot_issue = snapshot_bootstrap_v2_files(
        root,
        max_entries=BOOTSTRAP_V2_MAX_CANDIDATE_ENTRIES,
    )
    if snapshot_issue is not None or file_snapshots is None:
        return [snapshot_issue or "history-v2 candidate snapshot could not be frozen"]
    issues = validate_bootstrap_v2_candidate(
        root,
        root,
        post_migration=True,
        candidate_snapshots=file_snapshots,
    )
    if issues:
        return issues
    entries, entry_issue = git_index_entries(
        root,
        label="history-v2",
        max_entries=BOOTSTRAP_V2_MAX_CANDIDATE_ENTRIES,
    )
    if entry_issue is not None or entries is None:
        issues.append(entry_issue or "history-v2 Git index could not be inspected")
        return list(dict.fromkeys(issues))
    for relative in sorted(entries):
        if not history_v2_tree_artifact_allowed(relative):
            issues.append(
                f"{display_relative_path(relative)}: unexpected history-v2 tree artifact"
            )
    if issues:
        return list(dict.fromkeys(issues))

    visible_relatives, visibility_issue = _git_visible_relatives(
        root,
        max_entries=BOOTSTRAP_V2_MAX_CANDIDATE_ENTRIES,
    )
    if visibility_issue is not None or visible_relatives is None:
        return [visibility_issue or "trusted Git file enumeration failed closed"]
    snapshot_by_relative = {snapshot.relative: snapshot for snapshot in file_snapshots}
    if frozenset(visible_relatives) != frozenset(snapshot_by_relative):
        return ["trusted Git inventory differs from the frozen candidate snapshot"]
    visible_snapshots = tuple(
        snapshot_by_relative[relative] for relative in visible_relatives
    )
    domain_issues = validate_history_v2_domain_tree(
        root,
        file_snapshots=visible_snapshots,
        trusted_base_rev=trusted_base_rev,
        trusted_revision_domain=trusted_revision_domain,
        work_budget=work_budget,
    )
    if domain_issues:
        return list(dict.fromkeys(domain_issues))
    issues.extend(
        validate_root(
            root,
            history_v2=True,
            file_snapshots=visible_snapshots,
        )
    )
    if verify_head_tree and not issues:
        budget = work_budget or HistoryV2WorkBudget()
        try:
            head = canonical_history_v2_oid(
                history_v2_git_text(
                    root,
                    "rev-parse",
                    "--verify",
                    "HEAD",
                    max_bytes=128,
                ).strip(),
                "history-v2 default-branch head",
            )
            tree_oid = canonical_history_v2_oid(
                history_v2_git_text(
                    root,
                    "rev-parse",
                    "--verify",
                    f"{head}^{{tree}}",
                    max_bytes=128,
                ).strip(),
                "history-v2 default-branch tree",
            )
            tree_entries = history_v2_tree_entries(
                root,
                head,
                tree_oid=tree_oid,
                work_budget=budget,
            )
            validate_history_v2_commit_tree(
                root,
                head,
                tree_oid,
                tree_entries,
                work_budget=budget,
                validate_contents=False,
            )
        except (OSError, UnicodeError, ValueError) as exc:
            issues.append(safe_exception_message(exc))
    return list(dict.fromkeys(issues))


def history_v2_git_output(
    root: Path,
    *arguments: str,
    max_bytes: int = BOOTSTRAP_V2_MAX_GIT_METADATA_BYTES,
) -> bytes:
    validate_history_v2_closed_object_store(root)
    try:
        return bounded_process_output(
            closed_git_command(
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                str(root),
                *arguments,
            ),
            max_output_bytes=max_bytes,
            timeout_seconds=HISTORY_V2_GIT_TIMEOUT_SECONDS,
            environment=closed_git_environment(),
        )
    except BoundedProcessError as exc:
        raise ValueError("history-v2 Git inspection failed within its bounds") from exc


def history_v2_git_text(
    root: Path,
    *arguments: str,
    max_bytes: int = 64 * 1024,
) -> str:
    try:
        return history_v2_git_output(
            root,
            *arguments,
            max_bytes=max_bytes,
        ).decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("history-v2 Git metadata is not ASCII") from exc


def canonical_history_v2_oid(value: str, label: str) -> str:
    if HISTORY_V2_OID_RE.fullmatch(value) is None:
        raise ValueError(f"{label} is not a canonical lowercase object ID")
    return value


def parse_history_v2_changed_paths(value: bytes) -> list[tuple[str, Path]]:
    fields = value.split(NUL_BYTE)
    if fields[-1:] != [b""]:
        raise ValueError("history-v2 changed-path metadata is malformed")
    changed: list[tuple[str, Path]] = []
    seen: set[Path] = set()
    for index in range(0, len(fields) - 1, 2):
        if index + 1 >= len(fields) - 1:
            raise ValueError("history-v2 changed-path metadata is incomplete")
        try:
            status = fields[index].decode("ascii")
            path_text = fields[index + 1].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("history-v2 changed-path metadata is invalid") from exc
        relative = Path(path_text)
        if (
            status not in {"A", "M"}
            or not path_text
            or relative.is_absolute()
            or relative.as_posix() != path_text
            or any(part in {"", ".", ".."} for part in relative.parts)
            or len(path_text.encode("utf-8")) > 1024
            or relative in seen
        ):
            raise ValueError("history-v2 changed-path metadata is outside policy")
        seen.add(relative)
        changed.append((status, relative))
        if len(changed) > BOOTSTRAP_V2_MAX_CANDIDATE_ENTRIES:
            raise ValueError("history-v2 changed-path count exceeds the trusted limit")
    if not changed:
        raise ValueError("history-v2 range contains no retained-history change")
    return changed


class HistoryV2TreeEntry(NamedTuple):
    mode: str
    object_type: str
    object_id: str
    size: int | None
    relative: Path


class HistoryV2CommitSignature(NamedTuple):
    armor: bytes
    signed_payload: bytes
    signer_fingerprint: str
    created_at: int
    public_key_algorithm: int
    hash_algorithm: int


class HistoryV2CommitObject(NamedTuple):
    tree_oid: str
    parents: tuple[str, ...]
    signature: HistoryV2CommitSignature


class HistoryV2GitHubSquashCommit(NamedTuple):
    tree_oid: str
    parents: tuple[str, ...]
    signature_armor: bytes
    signed_payload: bytes
    author_identity_sha256: str
    committer_identity_sha256: str
    author_timestamp: int
    committer_timestamp: int
    pull_request_number: int | None


class HistoryV2PhysicalCommit(NamedTuple):
    tree_oid: str
    parents: tuple[str, ...]
    subject: str


def validate_history_v2_commit_identity(value: bytes, label: str) -> int:
    if len(value) > 512:
        raise ValueError(f"history-v2 {label} identity exceeds policy")
    try:
        identity_text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"history-v2 {label} identity is not UTF-8") from exc
    match = HISTORY_V2_IDENTITY_RE.fullmatch(identity_text)
    if match is None or match.group("identity") != HISTORY_V2_CANONICAL_IDENTITY:
        raise ValueError(
            f"history-v2 {label} identity is outside retained privacy policy"
        )
    timestamp = int(match.group("timestamp"))
    if timestamp > 4_294_967_295:
        raise ValueError(f"history-v2 {label} identity timestamp is outside policy")
    return timestamp


def decode_history_v2_commit_signature_armor(value: bytes) -> bytes:
    if not 0 < len(value) <= HISTORY_V2_MAX_COMMIT_SIGNATURE_BYTES:
        raise ValueError("history-v2 commit signature exceeds policy")
    if any((byte < 0x20 and byte != 0x0A) or byte == 0x7F for byte in value):
        raise ValueError(
            "history-v2 commit signature armor contains prohibited control bytes"
        )
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("history-v2 commit signature armor is not ASCII") from exc
    if not text.endswith("\n"):
        raise ValueError("history-v2 commit signature armor is not canonical")
    lines = text[:-1].split("\n")
    begin = "-----BEGIN PGP SIGNATURE-----"
    end = "-----END PGP SIGNATURE-----"
    if (
        len(lines) < 5
        or lines[0] != begin
        or lines[1] != ""
        or lines[-1] != end
        or lines.count(begin) != 1
        or lines.count(end) != 1
    ):
        raise ValueError("history-v2 commit signature armor is not canonical")
    encoded_lines = lines[2:-2]
    checksum_line = lines[-2]
    if (
        not encoded_lines
        or len(checksum_line) != 5
        or not checksum_line.startswith("=")
        or any(
            not re.fullmatch(r"[A-Za-z0-9+/]{64}", line) for line in encoded_lines[:-1]
        )
        or re.fullmatch(r"[A-Za-z0-9+/]{1,64}={0,2}", encoded_lines[-1]) is None
    ):
        raise ValueError("history-v2 commit signature armor is not canonical")
    encoded = "".join(encoded_lines)
    try:
        decoded = base64.b64decode(encoded, validate=True)
        checksum = base64.b64decode(checksum_line[1:], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("history-v2 commit signature armor is malformed") from exc
    if (
        not decoded
        or base64.b64encode(decoded).decode("ascii") != encoded
        or len(checksum) != 3
        or checksum != bootstrap_v2_crc24(decoded)
    ):
        raise ValueError("history-v2 commit signature armor is malformed")
    return decoded


def encode_history_v2_signature_packet(body: bytes) -> bytes:
    if len(body) < 256:
        return bytes((0x88, len(body))) + body
    if len(body) < 65_536:
        return bytes((0x89,)) + len(body).to_bytes(2, "big") + body
    return bytes((0x8A,)) + len(body).to_bytes(4, "big") + body


def validate_history_v2_commit_signature(
    armor: bytes,
    *,
    signed_payload: bytes,
    committer_timestamp: int,
) -> HistoryV2CommitSignature:
    packet = decode_history_v2_commit_signature_armor(armor)
    if len(packet) < 2:
        raise ValueError("history-v2 commit signature packet is malformed")
    header = packet[0]
    if header == 0x88:
        body_offset = 2
        body_length = packet[1]
    elif header == 0x89 and len(packet) >= 3:
        body_offset = 3
        body_length = int.from_bytes(packet[1:3], "big")
    elif header == 0x8A and len(packet) >= 5:
        body_offset = 5
        body_length = int.from_bytes(packet[1:5], "big")
    else:
        raise ValueError("history-v2 commit signature packet is not canonical")
    body = packet[body_offset:]
    if (
        len(body) != body_length
        or packet != encode_history_v2_signature_packet(body)
        or len(body) < 10
        or body[0] != 4
        or body[1] != 0
        or body[2] not in HISTORY_V2_SIGNATURE_PUBLIC_KEY_ALGORITHMS
        or body[3] != HISTORY_V2_SIGNATURE_HASH_ALGORITHM
    ):
        raise ValueError("history-v2 commit signature packet is outside policy")

    hashed_length = int.from_bytes(body[4:6], "big")
    hashed_start = 6
    hashed_end = hashed_start + hashed_length
    if hashed_end + 2 > len(body):
        raise ValueError("history-v2 commit signature hashed area is truncated")
    hashed = parse_bootstrap_v2_subpackets(
        body[hashed_start:hashed_end],
        label="history-v2 commit signature hashed area",
        critical_type_bit=True,
    )
    if (
        len(hashed) != 2
        or hashed[0][0:2] != (2, False)
        or len(hashed[0][2]) != 4
        or hashed[1][0:2] != (33, False)
        or len(hashed[1][2]) != 21
        or hashed[1][2][0] != 4
    ):
        raise ValueError(
            "history-v2 commit signature hashed subpackets are outside policy"
        )
    created_at = int.from_bytes(hashed[0][2], "big")
    if created_at != committer_timestamp:
        raise ValueError(
            "history-v2 commit signature time differs from canonical commit time"
        )
    signer_fingerprint = binascii.hexlify(hashed[1][2][1:]).decode("ascii").upper()

    unhashed_length = int.from_bytes(body[hashed_end : hashed_end + 2], "big")
    unhashed_start = hashed_end + 2
    unhashed_end = unhashed_start + unhashed_length
    if unhashed_end + 2 > len(body):
        raise ValueError("history-v2 commit signature unhashed area is truncated")
    unhashed = parse_bootstrap_v2_subpackets(
        body[unhashed_start:unhashed_end],
        label="history-v2 commit signature unhashed area",
        critical_type_bit=True,
    )
    if (
        len(unhashed) != 1
        or unhashed[0][0:2] != (16, False)
        or len(unhashed[0][2]) != 8
        or unhashed[0][2] != bytes.fromhex(signer_fingerprint[-16:])
    ):
        raise ValueError(
            "history-v2 commit signature unhashed subpackets are outside policy"
        )

    offset = unhashed_end + 2
    mpi_count = 1 if body[2] == 1 else 2
    for _index in range(mpi_count):
        _mpi, offset = read_bootstrap_v2_mpi(body, offset)
    if offset != len(body):
        raise ValueError("history-v2 commit signature contains trailing material")
    return HistoryV2CommitSignature(
        armor=armor,
        signed_payload=signed_payload,
        signer_fingerprint=signer_fingerprint,
        created_at=created_at,
        public_key_algorithm=body[2],
        hash_algorithm=body[3],
    )


def history_v2_commit_object_id(raw: bytes, *, expected_length: int) -> str:
    if expected_length == 40:
        digest = hashlib.sha1(usedforsecurity=False)
    elif expected_length == 64:
        digest = hashlib.sha256()
    else:
        raise ValueError("history-v2 commit uses an unsupported hash format")
    digest.update(b"commit " + str(len(raw)).encode("ascii") + NUL_BYTE)
    digest.update(raw)
    return digest.hexdigest()


def validate_history_v2_commit_message(
    message: bytes,
    *,
    squash: bool,
    github_provider: bool = False,
) -> str:
    if type(github_provider) is not bool or (github_provider and not squash):
        raise ValueError("history-v2 squash commit message mode is invalid")
    canonical_message = (
        bool(message)
        and not message.endswith(b"\n")
        and len(message) <= HISTORY_V2_MAX_COMMIT_MESSAGE_BYTES
        if github_provider
        else (
            message.endswith(b"\n")
            and not message.endswith(b"\n\n")
            and message != b"\n"
            and len(message)
            <= (
                HISTORY_V2_MAX_SQUASH_COMMIT_MESSAGE_BYTES
                if squash
                else HISTORY_V2_MAX_COMMIT_MESSAGE_BYTES
            )
        )
    )
    if not canonical_message:
        raise ValueError(
            "history-v2 squash commit message is not canonical"
            if squash
            else "history-v2 commit message is not canonical"
        )
    try:
        message_text = (
            message.decode("utf-8") if github_provider else message[:-1].decode("utf-8")
        )
    except UnicodeDecodeError as exc:
        raise ValueError(
            "history-v2 squash commit message is not UTF-8"
            if squash
            else "history-v2 commit message is not UTF-8"
        ) from exc
    message_lines = message_text.split("\n")
    valid_shape = (
        bool(message_lines)
        and bool(message_lines[0])
        and bool(message_lines[-1])
        and len(message_lines[0].encode("utf-8"))
        < HISTORY_V2_MAX_SQUASH_COMMIT_MESSAGE_BYTES
        if github_provider
        else len(message_lines) == 1
        if squash
        else (
            len(message_lines) == 1
            or (
                len(message_lines) == 3
                and message_lines[1] == ""
                and message_lines[2] in HISTORY_V2_CODEX_TRAILERS
            )
        )
    )
    subject = message_lines[0] if message_lines else ""
    subject_policy_text = subject
    if github_provider:
        provider_suffix = HISTORY_V2_GITHUB_SQUASH_SUFFIX_RE.fullmatch(subject)
        if provider_suffix is not None:
            subject_policy_text = provider_suffix.group("title")
    if (
        not valid_shape
        or HISTORY_V2_COMMIT_SUBJECT_RE.fullmatch(subject_policy_text) is None
        or unicodedata.normalize("NFC", message_text) != message_text
        or any(
            not character.isprintable() and character != "\n"
            for character in message_text
        )
        or any(line != line.strip(" \t") for line in message_lines)
    ):
        if not squash and any(
            line.startswith("Co-authored-by: Codex ") for line in message_lines[1:]
        ):
            raise ValueError(
                "history-v2 commit message contains raw/sensitive evidence"
            )
        raise ValueError(
            "history-v2 squash commit message is not canonical"
            if squash
            else "history-v2 commit message is not canonical"
        )
    privacy_values = message_lines if github_provider else (subject,)
    contains_prohibited_evidence = (
        HISTORY_V2_RAW_CONVERSATION_EVIDENCE_RE.search(
            message_text if github_provider else subject
        )
        is not None
    )
    for privacy_value in privacy_values:
        if github_provider and privacy_value in HISTORY_V2_CODEX_TRAILERS:
            continue
        if contains_bootstrap_v2_privacy_risk_text(
            privacy_value,
            relative=Path(
                "git-history/squash-message.txt"
                if squash
                else "git-history/commit-message.txt"
            ),
        ):
            contains_prohibited_evidence = True
            break
    if contains_prohibited_evidence:
        raise ValueError(
            "history-v2 squash commit metadata contains prohibited retained evidence"
            if squash
            else "history-v2 commit message contains raw/sensitive evidence"
        )
    return subject


def parse_history_v2_unsigned_squash_commit(
    raw: bytes,
    *,
    expected_oid: str,
) -> tuple[str, tuple[str, ...]]:
    expected_oid = canonical_history_v2_oid(
        expected_oid,
        "history-v2 unsigned squash commit",
    )
    if (
        not raw
        or len(raw) > HISTORY_V2_MAX_COMMIT_BYTES
        or b"\r" in raw
        or NUL_BYTE in raw
    ):
        raise ValueError("history-v2 squash commit metadata is outside policy")
    if (
        history_v2_commit_object_id(
            raw,
            expected_length=len(expected_oid),
        )
        != expected_oid
    ):
        raise ValueError(
            "history-v2 squash commit object ID does not match its contents"
        )
    header, separator, message = raw.partition(b"\n\n")
    header_lines = header.split(b"\n")
    if (
        not separator
        or len(header_lines) != 4
        or any(not line or line.startswith((b" ", b"\t")) for line in header_lines)
    ):
        raise ValueError("history-v2 squash commit header set is outside policy")
    parsed_headers = tuple(line.partition(b" ") for line in header_lines)
    if any(
        not field_separator or not value
        for _name, field_separator, value in parsed_headers
    ) or tuple(name for name, _separator, _value in parsed_headers) != (
        b"tree",
        b"parent",
        b"author",
        b"committer",
    ):
        raise ValueError("history-v2 squash commit header set is outside policy")
    try:
        tree_text = parsed_headers[0][2].decode("ascii")
        parent_text = parsed_headers[1][2].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("history-v2 squash commit object IDs are not ASCII") from exc
    tree_oid = canonical_history_v2_oid(
        tree_text,
        "history-v2 squash commit tree",
    )
    parent_oid = canonical_history_v2_oid(
        parent_text,
        "history-v2 squash commit parent",
    )
    if len(tree_oid) != len(expected_oid) or len(parent_oid) != len(expected_oid):
        raise ValueError(
            "history-v2 squash commit object IDs use inconsistent hash formats"
        )

    for label, value in (
        ("author", parsed_headers[2][2]),
        ("committer", parsed_headers[3][2]),
    ):
        match = HISTORY_V2_UNSIGNED_SQUASH_IDENTITY_RE.fullmatch(value)
        if match is None:
            raise ValueError(
                f"history-v2 squash {label} identity is outside privacy policy"
            )
        timestamp = int(match.group("timestamp"))
        if timestamp > 4_294_967_295:
            raise ValueError(f"history-v2 squash {label} timestamp is outside policy")
        name = match.group("name").decode("ascii")
        if HISTORY_V2_RAW_CONVERSATION_EVIDENCE_RE.search(
            name
        ) or contains_bootstrap_v2_privacy_risk_text(
            name,
            relative=Path("git-history/squash-identity.txt"),
        ):
            raise ValueError(
                "history-v2 squash identity contains prohibited retained evidence"
            )

    validate_history_v2_commit_message(message, squash=True)
    return tree_oid, (parent_oid,)


def validate_history_v2_github_squash_identity(
    value: bytes,
    *,
    label: str,
) -> tuple[int, bytes]:
    if len(value) > 640:
        raise ValueError(f"history-v2 GitHub squash {label} identity exceeds policy")
    match = HISTORY_V2_GITHUB_SQUASH_IDENTITY_RE.fullmatch(value)
    if match is None:
        raise ValueError(f"history-v2 GitHub squash {label} identity is outside policy")
    try:
        name = match.group("name").decode("utf-8")
        match.group("email").decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"history-v2 GitHub squash {label} identity is not canonical"
        ) from exc
    if label == "author":
        expected_name = b"Retrospective History"
        expected_email = b"retrospective-history-v2@users.noreply.github.com"
    elif label == "committer":
        expected_name = b"GitHub"
        expected_email = b"noreply@github.com"
    else:
        raise ValueError("history-v2 GitHub squash identity role is outside policy")
    if (
        match.group("name") != expected_name
        or match.group("email") != expected_email
        or name != name.strip(" \t")
        or unicodedata.normalize("NFC", name) != name
        or any(not character.isprintable() for character in name)
        or HISTORY_V2_RAW_CONVERSATION_EVIDENCE_RE.search(name)
        or contains_bootstrap_v2_privacy_risk_text(
            name,
            relative=Path("git-history/github-squash-identity.txt"),
        )
    ):
        raise ValueError(
            f"history-v2 GitHub squash {label} identity is outside privacy policy"
        )
    timestamp = int(match.group("timestamp"))
    if timestamp > 4_294_967_295:
        raise ValueError(
            f"history-v2 GitHub squash {label} timestamp is outside policy"
        )
    return timestamp, match.group("timezone")


def parse_history_v2_github_squash_commit(
    raw: bytes,
    *,
    expected_oid: str,
) -> HistoryV2GitHubSquashCommit:
    expected_oid = canonical_history_v2_oid(
        expected_oid,
        "history-v2 GitHub squash commit",
    )
    if (
        not raw
        or len(raw) > HISTORY_V2_MAX_COMMIT_BYTES
        or b"\r" in raw
        or NUL_BYTE in raw
    ):
        raise ValueError("history-v2 GitHub squash metadata is outside policy")
    if (
        history_v2_commit_object_id(
            raw,
            expected_length=len(expected_oid),
        )
        != expected_oid
    ):
        raise ValueError(
            "history-v2 GitHub squash commit object ID does not match its contents"
        )
    header, separator, message = raw.partition(b"\n\n")
    header_lines = header.split(b"\n")
    if not separator or not header_lines or any(not line for line in header_lines):
        raise ValueError("history-v2 GitHub squash commit header set is outside policy")

    parsed_headers: list[tuple[bytes, bytes]] = []
    unsigned_header_lines: list[bytes] = []
    signature_armor: bytes | None = None
    index = 0
    while index < len(header_lines):
        line = header_lines[index]
        if line.startswith((b" ", b"\t")):
            raise ValueError(
                "history-v2 GitHub squash commit header continuation is prohibited"
            )
        name, field_separator, value = line.partition(b" ")
        if not field_separator or not value:
            raise ValueError(
                "history-v2 GitHub squash commit header set is outside policy"
            )
        if name == b"gpgsig":
            if signature_armor is not None:
                raise ValueError(
                    "history-v2 GitHub squash commit contains duplicate signatures"
                )
            signature_lines = [value]
            index += 1
            while index < len(header_lines) and header_lines[index].startswith(b" "):
                signature_lines.append(header_lines[index][1:])
                index += 1
            if signature_lines[-1:] == [b""]:
                signature_lines.pop()
            if not signature_lines or signature_lines[-1:] == [b""]:
                raise ValueError(
                    "history-v2 GitHub squash commit signature is not canonical"
                )
            signature_armor = b"\n".join(signature_lines) + b"\n"
            parsed_headers.append((name, b""))
            continue
        if name not in {b"tree", b"parent", b"author", b"committer"}:
            raise ValueError(
                "history-v2 GitHub squash commit header set is outside policy"
            )
        parsed_headers.append((name, value))
        unsigned_header_lines.append(line)
        index += 1

    if [name for name, _value in parsed_headers] != [
        b"tree",
        b"parent",
        b"author",
        b"committer",
        b"gpgsig",
    ] or signature_armor is None:
        raise ValueError("history-v2 GitHub squash commit header order is invalid")
    try:
        tree_text = parsed_headers[0][1].decode("ascii")
        parent_text = parsed_headers[1][1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(
            "history-v2 GitHub squash commit object IDs are not ASCII"
        ) from exc
    tree_oid = canonical_history_v2_oid(
        tree_text,
        "history-v2 GitHub squash commit tree",
    )
    parent_oid = canonical_history_v2_oid(
        parent_text,
        "history-v2 GitHub squash commit parent",
    )
    if len(tree_oid) != len(expected_oid) or len(parent_oid) != len(expected_oid):
        raise ValueError(
            "history-v2 GitHub squash commit object IDs use inconsistent hash formats"
        )

    author_value = parsed_headers[2][1]
    committer_value = parsed_headers[3][1]
    author_timestamp, author_timezone = validate_history_v2_github_squash_identity(
        author_value,
        label="author",
    )
    committer_timestamp, committer_timezone = (
        validate_history_v2_github_squash_identity(
            committer_value,
            label="committer",
        )
    )
    if not committer_value.startswith(HISTORY_V2_GITHUB_COMMITTER_IDENTITY + b" "):
        raise ValueError(
            "history-v2 GitHub squash committer identity is outside provider policy"
        )
    if author_timestamp != committer_timestamp or author_timezone != committer_timezone:
        raise ValueError("history-v2 GitHub squash identity times differ")

    validate_history_v2_commit_message(
        message,
        squash=True,
        github_provider=True,
    )
    message_subject = message.decode("utf-8").split("\n", 1)[0]
    provider_suffix = HISTORY_V2_GITHUB_SQUASH_SUFFIX_RE.fullmatch(message_subject)
    pull_request_number = (
        int(provider_suffix.group("pull_request_number"))
        if provider_suffix is not None
        else None
    )
    if provider_suffix is not None and provider_suffix.group("title").endswith(" "):
        raise ValueError("history-v2 GitHub squash commit subject is not canonical")
    decode_history_v2_commit_signature_armor(signature_armor)
    signed_payload = b"\n".join(unsigned_header_lines) + b"\n\n" + message
    return HistoryV2GitHubSquashCommit(
        tree_oid=tree_oid,
        parents=(parent_oid,),
        signature_armor=signature_armor,
        signed_payload=signed_payload,
        author_identity_sha256=hashlib.sha256(author_value).hexdigest(),
        committer_identity_sha256=hashlib.sha256(committer_value).hexdigest(),
        author_timestamp=author_timestamp,
        committer_timestamp=committer_timestamp,
        pull_request_number=pull_request_number,
    )


def parse_history_v2_commit_object(
    raw: bytes, *, expected_oid: str
) -> HistoryV2CommitObject:
    expected_oid = canonical_history_v2_oid(
        expected_oid,
        "history-v2 commit",
    )
    if len(raw) > HISTORY_V2_MAX_COMMIT_BYTES:
        raise ValueError("history-v2 commit object exceeds policy")
    if b"\r" in raw:
        raise ValueError("history-v2 commit object contains prohibited CR bytes")
    if (
        history_v2_commit_object_id(
            raw,
            expected_length=len(expected_oid),
        )
        != expected_oid
    ):
        raise ValueError("history-v2 commit object ID does not match its contents")

    header, separator, message = raw.partition(b"\n\n")
    if not separator or len(message) > HISTORY_V2_MAX_COMMIT_MESSAGE_BYTES:
        raise ValueError("history-v2 commit message exceeds policy")
    header_lines = header.split(b"\n")
    if not header_lines or any(not line for line in header_lines):
        raise ValueError("history-v2 commit header is malformed")

    parsed_headers: list[tuple[bytes, bytes]] = []
    unsigned_header_lines: list[bytes] = []
    signature_armor: bytes | None = None
    index = 0
    while index < len(header_lines):
        line = header_lines[index]
        if line.startswith((b" ", b"\t")):
            raise ValueError("history-v2 commit header continuation is prohibited")
        name, field_separator, value = line.partition(b" ")
        if not field_separator or not value:
            raise ValueError("history-v2 commit header is malformed")
        if name == b"gpgsig":
            if signature_armor is not None:
                raise ValueError("history-v2 commit contains duplicate signatures")
            signature_lines = [value]
            index += 1
            while index < len(header_lines) and header_lines[index].startswith(b" "):
                signature_lines.append(header_lines[index][1:])
                index += 1
            signature_armor = b"\n".join(signature_lines) + b"\n"
            parsed_headers.append((name, b""))
            continue
        if name == b"gpgsig-sha256":
            raise ValueError("history-v2 alternate signature headers are prohibited")
        if name not in {b"tree", b"parent", b"author", b"committer"}:
            raise ValueError("history-v2 commit header is outside policy")
        parsed_headers.append((name, value))
        unsigned_header_lines.append(line)
        index += 1

    if len(parsed_headers) < 5 or parsed_headers[0][0] != b"tree":
        raise ValueError("history-v2 commit header order is invalid")
    parent_end = 1
    while (
        parent_end < len(parsed_headers) and parsed_headers[parent_end][0] == b"parent"
    ):
        parent_end += 1
    if (
        parent_end == 1
        or [name for name, _value in parsed_headers[parent_end:]]
        != [b"author", b"committer", b"gpgsig"]
        or signature_armor is None
    ):
        raise ValueError("history-v2 commit header order is invalid")

    try:
        tree_text = parsed_headers[0][1].decode("ascii")
        parent_texts = [
            value.decode("ascii")
            for name, value in parsed_headers[1:parent_end]
            if name == b"parent"
        ]
    except UnicodeDecodeError as exc:
        raise ValueError("history-v2 commit object IDs are not ASCII") from exc
    tree = canonical_history_v2_oid(tree_text, "history-v2 commit tree")
    parents = tuple(
        canonical_history_v2_oid(value, "history-v2 commit parent")
        for value in parent_texts
    )
    if any(len(object_id) != len(expected_oid) for object_id in (tree, *parents)):
        raise ValueError("history-v2 commit object IDs use inconsistent hash formats")
    if len(set(parents)) != len(parents):
        raise ValueError("history-v2 commit contains duplicate parent headers")
    author_timestamp = validate_history_v2_commit_identity(
        parsed_headers[parent_end][1],
        "author",
    )
    committer_timestamp = validate_history_v2_commit_identity(
        parsed_headers[parent_end + 1][1],
        "committer",
    )
    if author_timestamp != committer_timestamp:
        raise ValueError("history-v2 author and committer timestamps must match")

    validate_history_v2_commit_message(message, squash=False)
    signed_payload = b"\n".join(unsigned_header_lines) + b"\n\n" + message
    signature = validate_history_v2_commit_signature(
        signature_armor,
        signed_payload=signed_payload,
        committer_timestamp=committer_timestamp,
    )
    return HistoryV2CommitObject(tree, parents, signature)


def parse_history_v2_key_fingerprints(value: bytes) -> frozenset[str]:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("history-v2 signing key metadata is not ASCII") from exc
    fingerprints: set[str] = set()
    for line in text.splitlines():
        fields = line.split(":")
        if fields[0] != "fpr":
            continue
        if len(fields) < 10 or re.fullmatch(r"[0-9A-F]{40}", fields[9]) is None:
            raise ValueError("history-v2 signing key fingerprint is malformed")
        fingerprints.add(fields[9])
    if not fingerprints:
        raise ValueError("history-v2 signing key has no accepted fingerprint")
    return frozenset(fingerprints)


def validate_history_v2_gpg_status(
    value: bytes,
    *,
    signature: HistoryV2CommitSignature,
    allowed_fingerprints: frozenset[str],
) -> None:
    try:
        lines = value.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("history-v2 signature verifier status is not ASCII") from exc
    rejected_statuses = {
        "BADSIG",
        "ERRSIG",
        "EXPSIG",
        "EXPKEYSIG",
        "NO_PUBKEY",
        "REVKEYSIG",
    }
    valid_signatures: list[list[str]] = []
    for line in lines:
        if not line.startswith("[GNUPG:] "):
            raise ValueError("history-v2 signature verifier status is malformed")
        fields = line[len("[GNUPG:] ") :].split()
        if not fields:
            raise ValueError("history-v2 signature verifier status is malformed")
        if fields[0] in rejected_statuses:
            raise ValueError("history-v2 commit signature verification failed")
        if fields[0] == "VALIDSIG":
            valid_signatures.append(fields[1:])
    if len(valid_signatures) != 1:
        raise ValueError("history-v2 commit signature verification is ambiguous")
    fields = valid_signatures[0]
    if (
        len(fields) != 10
        or fields[0] != signature.signer_fingerprint
        or fields[0] not in allowed_fingerprints
        or not fields[2].isdecimal()
        or int(fields[2]) != signature.created_at
        or fields[4:6] != ["4", "0"]
        or fields[6] != str(signature.public_key_algorithm)
        or fields[7] != str(signature.hash_algorithm)
        or fields[8] != "00"
        or fields[9] not in allowed_fingerprints
    ):
        raise ValueError(
            "history-v2 commit signature differs from the trusted signer profile"
        )


class HistoryV2SignatureVerifier:
    def __init__(self, public_key: bytes, *, relative: Path) -> None:
        self.public_key = public_key
        self.relative = relative
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self.home: Path | None = None
        self.environment: dict[str, str] | None = None
        self.allowed_fingerprints = frozenset[str]()

    def __enter__(self) -> HistoryV2SignatureVerifier:
        if self.relative not in HISTORY_V2_SIGNATURE_KEY_PATHS.values():
            raise ValueError("history-v2 signing key role is outside policy")
        if (
            not 0 < len(self.public_key) <= BOOTSTRAP_V2_MAX_PUBLIC_KEY_BYTES
            or hashlib.sha256(self.public_key).hexdigest()
            != BOOTSTRAP_V2_PUBLIC_KEY_SHA256[self.relative]
        ):
            raise ValueError("history-v2 signing key differs from trusted policy")
        key_issues = validate_bootstrap_v2_public_key(
            self.public_key,
            relative=self.relative,
        )
        if key_issues:
            raise ValueError(key_issues[0])

        self._temporary = tempfile.TemporaryDirectory(prefix="history-v2-signature-")
        self.home = Path(self._temporary.name)
        self.home.chmod(0o700)
        self.environment = {
            **os.environ,
            "GNUPGHOME": str(self.home),
            "HOME": str(self.home),
            "LC_ALL": "C",
        }
        common = [
            "gpg",
            "--quiet",
            "--no-options",
            "--no-autostart",
            "--batch",
            "--homedir",
            str(self.home),
        ]
        try:
            bounded_process_output(
                [*common, "--import"],
                input_data=self.public_key,
                max_output_bytes=64 * 1024,
                timeout_seconds=HISTORY_V2_GIT_TIMEOUT_SECONDS,
                environment=self.environment,
            )
            fingerprints = bounded_process_output(
                [
                    *common,
                    "--with-colons",
                    "--fingerprint",
                    "--fingerprint",
                    "--list-keys",
                ],
                max_output_bytes=64 * 1024,
                timeout_seconds=HISTORY_V2_GIT_TIMEOUT_SECONDS,
                environment=self.environment,
            )
            self.allowed_fingerprints = parse_history_v2_key_fingerprints(fingerprints)
        except (BoundedProcessError, OSError, ValueError) as exc:
            self.__exit__(None, None, None)
            raise ValueError(
                "history-v2 trusted signing key could not be prepared"
            ) from exc
        return self

    def __exit__(self, *_args: object) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()
        self._temporary = None
        self.home = None
        self.environment = None
        self.allowed_fingerprints = frozenset()

    def verify(self, signature: HistoryV2CommitSignature) -> None:
        if self.home is None or self.environment is None:
            raise ValueError("history-v2 signature verifier is not active")
        signature_path = self.home / "commit-signature.asc"
        descriptor = -1
        try:
            descriptor = os.open(
                signature_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(signature.armor)
                stream.flush()
                os.fsync(stream.fileno())
            status = bounded_process_output(
                [
                    "gpg",
                    "--quiet",
                    "--no-options",
                    "--no-autostart",
                    "--batch",
                    "--homedir",
                    str(self.home),
                    "--status-fd=1",
                    "--verify",
                    str(signature_path),
                    "-",
                ],
                input_data=signature.signed_payload,
                max_output_bytes=64 * 1024,
                timeout_seconds=HISTORY_V2_GIT_TIMEOUT_SECONDS,
                environment=self.environment,
            )
        except (BoundedProcessError, OSError) as exc:
            if descriptor >= 0:
                os.close(descriptor)
            raise ValueError("history-v2 commit signature verification failed") from exc
        finally:
            try:
                signature_path.unlink(missing_ok=True)
            except OSError:
                pass
        validate_history_v2_gpg_status(
            status,
            signature=signature,
            allowed_fingerprints=self.allowed_fingerprints,
        )


def _read_history_v2_policy_file_descriptor(
    descriptor: int,
    *,
    max_bytes: int,
) -> bytes:
    value = bytearray()
    while len(value) <= max_bytes:
        chunk = os.read(
            descriptor,
            min(64 * 1024, max_bytes + 1 - len(value)),
        )
        if not chunk:
            return bytes(value)
        value.extend(chunk)
    return bytes(value)


def _history_v2_policy_access_state(
    metadata: os.stat_result,
) -> tuple[int, int, int]:
    return (
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH),
    )


def _history_v2_policy_path_metadata(
    path: Path,
    *,
    label: str,
) -> os.stat_result:
    try:
        return os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise _history_v2_filesystem_error(
            label=label,
            operation="revalidated",
            error=exc,
        ) from exc


def _validate_history_v2_policy_metadata(
    metadata: os.stat_result,
    *,
    opened: os.stat_result,
    label: str,
) -> None:
    if _history_v2_entry_identity(metadata) != _history_v2_entry_identity(opened):
        raise ValueError(f"{label} object identity changed while being read")
    if _history_v2_policy_access_state(metadata) != _history_v2_policy_access_state(
        opened
    ):
        raise ValueError(f"{label} access policy changed while being read")
    if metadata.st_size != opened.st_size:
        raise ValueError(f"{label} content changed while being read")


def read_history_v2_stable_policy_file(
    path: Path,
    *,
    label: str,
    max_bytes: int,
) -> bytes:
    # The protected properties are path object identity, returned content,
    # owner/group identity, and absence of group/other write access. Mtime only
    # triggers bounded byte revalidation; access tightening remains benign.
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("no-follow filesystem inspection is unavailable")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _history_v2_filesystem_error(
            label=label,
            operation="opened",
            error=exc,
        ) from exc

    try:
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_size <= 0:
                raise ValueError(f"{label} is not a nonempty regular file")
            if opened.st_size > max_bytes:
                raise ValueError(f"{label} exceeds the trusted size limit")
            if opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise ValueError(f"{label} access policy is unsafe")

            first = _read_history_v2_policy_file_descriptor(
                descriptor,
                max_bytes=max_bytes,
            )
            os.lseek(descriptor, 0, os.SEEK_SET)
            second = _read_history_v2_policy_file_descriptor(
                descriptor,
                max_bytes=max_bytes,
            )
            final = os.fstat(descriptor)
        except ValueError:
            raise
        except OSError as exc:
            raise _history_v2_filesystem_error(
                label=label,
                operation="read safely",
                error=exc,
            ) from exc

        _validate_history_v2_policy_metadata(
            final,
            opened=opened,
            label=label,
        )
        if (
            len(first) != opened.st_size
            or len(second) != final.st_size
            or first != second
        ):
            raise ValueError(f"{label} content changed while being read")

        current = _history_v2_policy_path_metadata(path, label=label)
        _validate_history_v2_policy_metadata(
            current,
            opened=opened,
            label=label,
        )
        if (
            opened.st_mtime_ns == final.st_mtime_ns
            and final.st_mtime_ns == current.st_mtime_ns
        ):
            return first

        for attempt in range(3):
            before_mtime_ns = current.st_mtime_ns
            try:
                os.lseek(descriptor, 0, os.SEEK_SET)
                verified = _read_history_v2_policy_file_descriptor(
                    descriptor,
                    max_bytes=max_bytes,
                )
                revalidated = os.fstat(descriptor)
            except OSError as exc:
                raise _history_v2_filesystem_error(
                    label=label,
                    operation="revalidated",
                    error=exc,
                ) from exc
            _validate_history_v2_policy_metadata(
                revalidated,
                opened=opened,
                label=label,
            )
            if len(verified) != opened.st_size or verified != first:
                raise ValueError(f"{label} content changed during revalidation")
            current = _history_v2_policy_path_metadata(path, label=label)
            _validate_history_v2_policy_metadata(
                current,
                opened=opened,
                label=label,
            )
            if (
                revalidated.st_mtime_ns == before_mtime_ns
                and current.st_mtime_ns == before_mtime_ns
            ):
                return first
            if attempt == 2:
                raise ValueError(f"{label} could not be revalidated")
        raise AssertionError("unreachable policy revalidation state")
    finally:
        os.close(descriptor)


def load_history_v2_github_squash_receipt(path: Path) -> dict[str, Any]:
    raw = read_history_v2_stable_policy_file(
        path,
        label="history-v2 GitHub squash verification receipt",
        max_bytes=HISTORY_V2_MAX_GITHUB_COMMIT_RECEIPT_BYTES,
    )
    try:
        payload = parse_strict_json(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(
            "history-v2 GitHub squash verification receipt is not valid JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError(
            "history-v2 GitHub squash verification receipt is not an object"
        )
    canonical = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if raw != canonical:
        raise ValueError(
            "history-v2 GitHub squash verification receipt is not canonical"
        )
    return payload


def validate_history_v2_github_squash_receipt(
    payload: dict[str, Any],
    *,
    commit: HistoryV2GitHubSquashCommit,
    repository: str,
    repository_id: int,
    before_rev: str,
    head_rev: str,
) -> None:
    expected_keys = {
        "schema_version",
        "kind",
        "repository",
        "base_sha",
        "head_sha",
        "tree_sha",
        "signed_payload_sha256",
        "signature_sha256",
        "author_identity_sha256",
        "committer_identity_sha256",
        "github_committer_login",
        "verification_reason",
        "verified_at",
        "pull_request_number",
        "pull_request_node_identity_sha256",
        "repository_identity_sha256",
        "pull_request_provenance_sha256",
        "pull_request_merged_at",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != expected_keys
        or type(payload.get("schema_version")) is not int
    ):
        raise ValueError(
            "history-v2 GitHub squash verification receipt shape is invalid"
        )
    if (
        not isinstance(repository, str)
        or HISTORY_V2_GITHUB_REPOSITORY_RE.fullmatch(repository) is None
        or payload.get("schema_version") != 2
        or payload.get("kind") != HISTORY_V2_GITHUB_SQUASH_RECEIPT_KIND
        or payload.get("repository") != repository
        or payload.get("base_sha") != before_rev
        or payload.get("head_sha") != head_rev
        or payload.get("tree_sha") != commit.tree_oid
        or payload.get("signed_payload_sha256")
        != hashlib.sha256(commit.signed_payload).hexdigest()
        or payload.get("signature_sha256")
        != hashlib.sha256(commit.signature_armor).hexdigest()
        or payload.get("author_identity_sha256") != commit.author_identity_sha256
        or payload.get("committer_identity_sha256") != commit.committer_identity_sha256
        or payload.get("github_committer_login") != "web-flow"
        or payload.get("verification_reason") != "valid"
    ):
        raise ValueError(
            "history-v2 GitHub squash verification receipt differs from the exact commit"
        )
    verified_at = payload.get("verified_at")
    pull_request_number = payload.get("pull_request_number")
    pull_request_node_identity_sha256 = payload.get("pull_request_node_identity_sha256")
    repository_identity_sha256 = payload.get("repository_identity_sha256")
    pull_request_provenance_sha256 = payload.get("pull_request_provenance_sha256")
    pull_request_merged_at = payload.get("pull_request_merged_at")
    if (
        not isinstance(verified_at, str)
        or TIMESTAMP_RE.fullmatch(verified_at) is None
        or type(pull_request_number) is not int
        or pull_request_number <= 0
        or type(repository_id) is not int
        or repository_id <= 0
        or not isinstance(pull_request_node_identity_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", pull_request_node_identity_sha256) is None
        or not isinstance(repository_identity_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", repository_identity_sha256) is None
        or not isinstance(pull_request_provenance_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", pull_request_provenance_sha256) is None
        or not isinstance(pull_request_merged_at, str)
        or TIMESTAMP_RE.fullmatch(pull_request_merged_at) is None
    ):
        raise ValueError(
            "history-v2 GitHub squash verification receipt provenance is invalid"
        )
    if (
        commit.pull_request_number is not None
        and commit.pull_request_number != pull_request_number
    ):
        raise ValueError(
            "history-v2 GitHub squash verification receipt differs from the exact commit"
        )
    expected_repository_identity = hashlib.sha256(
        f"{repository_id}:{repository}".encode("utf-8")
    ).hexdigest()
    expected_provenance = {
        "base_ref": HISTORY_V2_DEFAULT_BRANCH,
        "base_repository": repository,
        "base_repository_id": repository_id,
        "base_sha": before_rev,
        "head_repository": repository,
        "head_repository_id": repository_id,
        "merge_commit_sha": head_rev,
        "merged_at": pull_request_merged_at,
        "node_identity_sha256": pull_request_node_identity_sha256,
        "number": pull_request_number,
    }
    expected_provenance_sha256 = hashlib.sha256(
        json.dumps(
            expected_provenance,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if (
        repository_identity_sha256 != expected_repository_identity
        or pull_request_provenance_sha256 != expected_provenance_sha256
    ):
        raise ValueError(
            "history-v2 GitHub squash verification receipt provenance differs"
        )


def history_v2_signature_verifier_for_root(
    root: Path,
    *,
    policy: str,
    revision: str | None = None,
) -> HistoryV2SignatureVerifier:
    relative = HISTORY_V2_SIGNATURE_KEY_PATHS.get(policy)
    if relative is None:
        raise ValueError("history-v2 signature role is outside policy")
    if revision is None:
        path = root / relative
        public_key = read_history_v2_stable_policy_file(
            path,
            label="history-v2 trusted signing key",
            max_bytes=BOOTSTRAP_V2_MAX_PUBLIC_KEY_BYTES,
        )
    else:
        revision = canonical_history_v2_oid(
            revision,
            "history-v2 signing-key revision",
        )
        public_key = history_v2_git_output(
            root,
            "show",
            f"{revision}:{relative.as_posix()}",
            max_bytes=BOOTSTRAP_V2_MAX_PUBLIC_KEY_BYTES,
        )
        if not public_key:
            raise ValueError("history-v2 trusted signing key is empty")
    return HistoryV2SignatureVerifier(public_key, relative=relative)


def validate_history_v2_commit_object(
    root: Path,
    revision: str,
    *,
    signature_verifier: HistoryV2SignatureVerifier,
) -> HistoryV2CommitObject:
    revision = canonical_history_v2_oid(revision, "history-v2 commit")
    raw = history_v2_git_output(
        root,
        "cat-file",
        "commit",
        revision,
        max_bytes=HISTORY_V2_MAX_COMMIT_BYTES,
    )
    parsed = parse_history_v2_commit_object(raw, expected_oid=revision)
    signature_verifier.verify(parsed.signature)
    return parsed


def validate_history_v2_physical_commit_object(
    root: Path,
    revision: str,
    *,
    signature_verifier: HistoryV2SignatureVerifier | None,
) -> HistoryV2PhysicalCommit:
    revision = canonical_history_v2_oid(
        revision,
        "history-v2 physical commit",
    )
    raw = history_v2_git_output(
        root,
        "cat-file",
        "commit",
        revision,
        max_bytes=HISTORY_V2_MAX_COMMIT_BYTES,
    )
    header, separator, message = raw.partition(b"\n\n")
    if not separator:
        raise ValueError("history-v2 physical commit metadata is malformed")
    if b"\ngpgsig " in b"\n" + header:
        parsed = parse_history_v2_commit_object(
            raw,
            expected_oid=revision,
        )
        if signature_verifier is not None:
            signature_verifier.verify(parsed.signature)
        tree_oid = parsed.tree_oid
        parents = parsed.parents
        subject = validate_history_v2_commit_message(
            message,
            squash=False,
        )
    else:
        if signature_verifier is not None:
            raise ValueError(
                "history-v2 authorized candidate commit signature is missing"
            )
        tree_oid, parents = parse_history_v2_unsigned_squash_commit(
            raw,
            expected_oid=revision,
        )
        subject = validate_history_v2_commit_message(
            message,
            squash=True,
        )
    return HistoryV2PhysicalCommit(tree_oid, parents, subject)


def reject_history_v2_sensitive_path(relative: Path) -> None:
    if relative in BOOTSTRAP_V2_ALLOWED_FILES:
        return
    if any(forbidden_history_v2_path_component(part) for part in relative.parts):
        raise ValueError("history-v2 commit tree contains a sensitive path")


def history_v2_tree_entries(
    root: Path,
    revision: str,
    *,
    tree_oid: str,
    work_budget: HistoryV2WorkBudget,
) -> tuple[HistoryV2TreeEntry, ...]:
    cached = work_budget.tree_entries.get(tree_oid)
    if cached is not None:
        return cached
    raw = history_v2_git_output(
        root,
        "ls-tree",
        "-r",
        "-t",
        "-z",
        "-l",
        "--full-tree",
        revision,
    )
    records = raw.split(NUL_BYTE)
    if records[-1:] != [b""]:
        raise ValueError("history-v2 commit tree metadata is malformed")
    entries: list[HistoryV2TreeEntry] = []
    seen_paths: set[Path] = set()
    seen_casefolded_paths: set[str] = set()
    observed_tree_paths: set[Path] = set()
    expected_tree_paths: set[Path] = set()
    total_size = 0
    for record in records[:-1]:
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 4:
            raise ValueError("history-v2 commit tree metadata is malformed")
        raw_mode, object_type, raw_object_id, raw_size = fields
        try:
            mode = raw_mode.decode("ascii")
            decoded_type = object_type.decode("ascii")
            object_id = canonical_history_v2_oid(
                raw_object_id.decode("ascii"),
                "history-v2 commit tree object",
            )
            path_text = raw_path.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("history-v2 commit tree metadata is invalid") from exc
        relative = Path(path_text)
        casefolded = path_text.casefold()
        if (
            not path_text
            or "\\" in path_text
            or relative.is_absolute()
            or relative.as_posix() != path_text
            or any(part in {"", ".", "..", ".git"} for part in relative.parts)
            or len(relative.parts) > HISTORY_V2_MAX_PATH_DEPTH
            or len(raw_path) > 1024
            or any(len(part.encode("utf-8")) > 255 for part in relative.parts)
            or relative in seen_paths
            or casefolded in seen_casefolded_paths
            or len(object_id) != len(tree_oid)
        ):
            raise ValueError("history-v2 commit tree entry is outside policy")
        reject_history_v2_sensitive_path(relative)
        if decoded_type == "tree":
            if mode != "040000" or raw_size != b"-":
                raise ValueError("history-v2 commit tree object is malformed")
            size: int | None = None
            observed_tree_paths.add(relative)
        elif decoded_type == "blob":
            if mode not in {"100644", "100755"} or not raw_size.isdigit():
                raise ValueError("history-v2 commit tree blob is malformed")
            size = int(raw_size)
            if size > BOOTSTRAP_V2_MAX_FILE_BYTES:
                raise ValueError(
                    "history-v2 commit tree blob exceeds the trusted size limit"
                )
            total_size += size
            for depth in range(1, len(relative.parts)):
                expected_tree_paths.add(Path(*relative.parts[:depth]))
        else:
            raise ValueError("history-v2 commit tree object type is prohibited")
        seen_paths.add(relative)
        seen_casefolded_paths.add(casefolded)
        entries.append(
            HistoryV2TreeEntry(mode, decoded_type, object_id, size, relative)
        )
        if len(entries) > BOOTSTRAP_V2_MAX_CANDIDATE_ENTRIES:
            raise ValueError(
                "history-v2 commit tree entry count exceeds the trusted limit"
            )
    if total_size > BOOTSTRAP_V2_MAX_TREE_BYTES:
        raise ValueError("history-v2 commit tree exceeds the trusted size limit")
    if observed_tree_paths != expected_tree_paths:
        raise ValueError(
            "history-v2 commit tree contains an empty or unrepresented subtree"
        )
    work_budget.add_path_references(len(entries))
    result = tuple(entries)
    work_budget.tree_entries[tree_oid] = result
    return result


def history_v2_read_blob(
    root: Path,
    entry: HistoryV2TreeEntry,
    *,
    work_budget: HistoryV2WorkBudget,
) -> bytes:
    reject_history_v2_sensitive_path(entry.relative)
    if entry.object_type != "blob" or entry.size is None:
        raise ValueError("history-v2 blob request is malformed")
    cached = work_budget.blob_payloads.get(entry.object_id)
    if cached is not None:
        if len(cached) != entry.size:
            raise ValueError("history-v2 reachable blob metadata changed")
        return cached
    work_budget.reserve_blob_read(entry.size)
    value = history_v2_git_output(
        root,
        "cat-file",
        "blob",
        entry.object_id,
        max_bytes=entry.size,
    )
    if (
        len(value) != entry.size
        or git_blob_bytes_object_id(value, expected_length=len(entry.object_id))
        != entry.object_id
    ):
        raise ValueError("history-v2 commit tree blob changed while being read")
    work_budget.blob_payloads[entry.object_id] = value
    return value


def trusted_history_v2_domain_revision_contract(
    root: Path,
    revision: str,
    *,
    work_budget: HistoryV2WorkBudget,
) -> HistoryV2DomainContract | None:
    root = root.resolve()
    validate_history_v2_closed_object_store(root)
    revision = canonical_history_v2_oid(
        revision,
        "trusted history-v2 domain base revision",
    )
    if (root, revision) not in work_budget.authorized_domain_revisions:
        raise ValueError(
            "trusted history-v2 domain revision was not authorized by the default-event barrier"
        )
    cache_key = (root, revision)
    if cache_key in work_budget.domain_contracts:
        return work_budget.domain_contracts[cache_key]

    tree_oid = canonical_history_v2_oid(
        history_v2_git_text(
            root,
            "rev-parse",
            "--verify",
            f"{revision}^{{tree}}",
            max_bytes=128,
        ).strip(),
        "trusted history-v2 domain base tree",
    )
    entries = history_v2_tree_entries(
        root,
        revision,
        tree_oid=tree_oid,
        work_budget=work_budget,
    )
    by_path = {
        entry.relative: entry for entry in entries if entry.object_type == "blob"
    }
    selected: list[HistoryV2FileSnapshot] = []
    missing = 0
    for index, relative in enumerate(HISTORY_V2_DOMAIN_MODULE_PATHS, 1):
        entry = by_path.get(relative)
        if entry is None:
            missing += 1
            continue
        if (
            entry.mode != "100644"
            or entry.object_type != "blob"
            or entry.size is None
            or entry.size > BOOTSTRAP_V2_MAX_PYTHON_SOURCE_BYTES
        ):
            raise ValueError("trusted history-v2 domain revision source is invalid")
        value = history_v2_read_blob(root, entry, work_budget=work_budget)
        selected.append(
            HistoryV2FileSnapshot(
                relative=relative,
                value=value,
                mode=stat.S_IFREG | 0o444,
                device=0,
                inode=index,
                uid=0,
                gid=0,
                size=len(value),
                mtime_ns=0,
            )
        )
    if missing == len(HISTORY_V2_DOMAIN_MODULE_PATHS):
        work_budget.domain_contracts[cache_key] = None
        return None
    if missing or tuple(snapshot.relative for snapshot in selected) != (
        HISTORY_V2_DOMAIN_MODULE_PATHS
    ):
        raise ValueError("trusted history-v2 domain revision source is incomplete")

    trusted_generation = history_v2_trust_generation_digest(
        root,
        revision,
        work_budget=work_budget,
    )
    try:
        git_module, runtime_module = _history_v2_load_frozen_domain_modules(
            root,
            tuple(selected),
        )
    except Exception as exc:
        raise ValueError(
            "trusted history-v2 domain revision could not be loaded"
        ) from exc
    contract = _history_v2_domain_contract_from_modules(
        trusted_root=root,
        trusted_revision=revision,
        trusted_generation=trusted_generation,
        git_module=git_module,
        runtime_module=runtime_module,
    )
    work_budget.domain_contracts[cache_key] = contract
    return contract


def validate_history_v2_commit_tree(
    root: Path,
    revision: str,
    tree_oid: str,
    entries: tuple[HistoryV2TreeEntry, ...],
    *,
    work_budget: HistoryV2WorkBudget,
    validate_contents: bool = True,
) -> None:
    if tree_oid in work_budget.validated_tree_oids:
        return
    blob_entries = tuple(entry for entry in entries if entry.object_type == "blob")
    index_records = tuple(
        entry.mode.encode("ascii")
        + b" "
        + entry.object_id.encode("ascii")
        + b"\t"
        + entry.relative.as_posix().encode("utf-8")
        + NUL_BYTE
        for entry in blob_entries
    )
    logical_bytes = 4096 + sum(len(record) for record in index_records)
    if validate_contents:
        logical_bytes += sum(entry.size or 0 for entry in blob_entries)
    work_budget.reserve_materialization(logical_bytes)
    payloads: dict[str, bytes] = {}
    if validate_contents:
        for entry in blob_entries:
            payloads[entry.object_id] = history_v2_read_blob(
                root,
                entry,
                work_budget=work_budget,
            )

    with tempfile.TemporaryDirectory(prefix="history-v2-commit-") as raw:
        workspace = Path(raw)
        tree_root = workspace / "tree"
        git_dir = workspace / "git"
        home = workspace / "home"
        home.mkdir(mode=0o700)
        object_format = "sha256" if len(revision) == 64 else "sha1"
        environment = closed_git_environment(home=home)
        try:
            bounded_process_output(
                closed_git_command(
                    "init",
                    "--quiet",
                    f"--object-format={object_format}",
                    "--separate-git-dir",
                    str(git_dir),
                    str(tree_root),
                ),
                max_output_bytes=0,
                timeout_seconds=HISTORY_V2_GIT_TIMEOUT_SECONDS,
                environment=environment,
            )
        except BoundedProcessError as exc:
            raise ValueError("history-v2 commit tree materialization failed") from exc

        if validate_contents:
            for entry in blob_entries:
                destination = tree_root / entry.relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with destination.open("xb") as stream:
                        stream.write(payloads[entry.object_id])
                    destination.chmod(0o755 if entry.mode == "100755" else 0o644)
                except OSError as exc:
                    raise ValueError(
                        "history-v2 commit tree materialization failed"
                    ) from exc
        try:
            bounded_process_output(
                closed_git_command(
                    "-C",
                    str(tree_root),
                    "update-index",
                    "--add",
                    "--info-only",
                    "-z",
                    "--index-info",
                ),
                input_data=b"".join(index_records),
                max_output_bytes=0,
                timeout_seconds=HISTORY_V2_GIT_TIMEOUT_SECONDS,
                environment=environment,
            )
        except BoundedProcessError as exc:
            raise ValueError(
                "history-v2 commit tree index could not be created"
            ) from exc
        try:
            reconstructed_tree = canonical_history_v2_oid(
                bounded_process_output(
                    closed_git_command(
                        "-C",
                        str(tree_root),
                        "write-tree",
                        "--missing-ok",
                    ),
                    max_output_bytes=128,
                    timeout_seconds=HISTORY_V2_GIT_TIMEOUT_SECONDS,
                    environment=environment,
                )
                .decode("ascii")
                .strip(),
                "history-v2 reconstructed tree",
            )
        except (BoundedProcessError, UnicodeDecodeError) as exc:
            raise ValueError(
                "history-v2 commit tree identity could not be reconstructed"
            ) from exc
        if reconstructed_tree != tree_oid:
            raise ValueError(
                "history-v2 reconstructed tree does not equal the original tree"
            )
        if validate_contents:
            issues = validate_history_v2_tree(
                tree_root,
                verify_head_tree=False,
            )
            if issues:
                raise ValueError(
                    "history-v2 newly reachable commit tree failed validation: "
                    + issues[0]
                )
    work_budget.validated_tree_oids.add(tree_oid)


def history_v2_diff_output(
    root: Path,
    parent_rev: str,
    commit_rev: str,
    *,
    work_budget: HistoryV2WorkBudget,
) -> bytes:
    work_budget.reserve_diff_call()
    remaining = HISTORY_V2_MAX_DIFF_BYTES - work_budget.diff_bytes
    raw = history_v2_git_output(
        root,
        "diff-tree",
        "--no-commit-id",
        "--name-status",
        "-z",
        "-r",
        "--no-renames",
        parent_rev,
        commit_rev,
        max_bytes=remaining,
    )
    work_budget.add_diff_bytes(len(raw))
    return raw


def history_v2_read_path_value(
    root: Path,
    revision: str,
    relative: Path,
    *,
    work_budget: HistoryV2WorkBudget,
) -> bytes:
    key = (revision, relative)
    cached = work_budget.path_payloads.get(key)
    if cached is not None:
        return cached
    work_budget.reserve_blob_read(0)
    remaining = HISTORY_V2_MAX_BLOB_READ_BYTES - work_budget.blob_read_bytes
    value = history_v2_git_output(
        root,
        "show",
        f"{revision}:{relative.as_posix()}",
        max_bytes=min(BOOTSTRAP_V2_MAX_FILE_BYTES, remaining),
    )
    work_budget.add_blob_read_bytes(len(value))
    work_budget.path_payloads[key] = value
    return value


def validate_history_v2_commit_edge(
    root: Path,
    *,
    parent_rev: str,
    commit_rev: str,
    role: str = "publication",
    work_budget: HistoryV2WorkBudget,
) -> None:
    changed = parse_history_v2_changed_paths(
        history_v2_diff_output(
            root,
            parent_rev,
            commit_rev,
            work_budget=work_budget,
        )
    )
    observed_role = classify_history_v2_transaction(changed)
    if role not in {"publication", "admin"} or observed_role != role:
        raise ValueError(
            "history-v2 intermediate commit changes a different authority role"
        )
    for status, relative in changed:
        if (
            role == "publication"
            and status == "M"
            and allowed_retained_jsonl_artifact(relative) is not None
        ):
            parent_value = history_v2_read_path_value(
                root,
                parent_rev,
                relative,
                work_budget=work_budget,
            )
            commit_value = history_v2_read_path_value(
                root,
                commit_rev,
                relative,
                work_budget=work_budget,
            )
            if len(commit_value) <= len(parent_value) or not commit_value.startswith(
                parent_value
            ):
                raise ValueError(
                    "history-v2 intermediate JSONL changes must be strict append-only updates"
                )
        elif role == "publication" and status == "M":
            raise ValueError(
                "history-v2 intermediate publication rewrites a retained artifact"
            )


def validate_history_v2_new_commits(
    root: Path,
    *,
    base_rev: str,
    head_rev: str,
    expected_count: int,
    role: str = "publication",
    work_budget: HistoryV2WorkBudget,
    verify_candidate_signature: bool = True,
) -> dict[str, HistoryV2PhysicalCommit]:
    if type(verify_candidate_signature) is not bool:
        raise ValueError("history-v2 candidate signature mode is invalid")
    commits = tuple(
        line
        for line in history_v2_git_text(
            root,
            "rev-list",
            "--reverse",
            "--topo-order",
            f"{base_rev}..{head_rev}",
            max_bytes=(HISTORY_V2_MAX_COMMITS + 1) * 129,
        ).splitlines()
        if line
    )
    if (
        len(commits) != expected_count
        or len(set(commits)) != len(commits)
        or head_rev not in commits
    ):
        raise ValueError("history-v2 newly reachable commit enumeration changed")
    commit_objects: dict[str, HistoryV2PhysicalCommit] = {}
    preceding_commits = {base_rev}
    signature_policy = "history-v2" if role == "publication" else "bootstrap-v2"
    verifier_context: Any
    if verify_candidate_signature:
        verifier_context = history_v2_signature_verifier_for_root(
            root,
            policy=signature_policy,
            revision=base_rev,
        )
    else:
        verifier_context = contextlib.nullcontext(None)
    with verifier_context as signature_verifier:
        for commit_rev in commits:
            commit_rev = canonical_history_v2_oid(
                commit_rev,
                "history-v2 newly reachable commit",
            )
            commit_object = validate_history_v2_physical_commit_object(
                root,
                commit_rev,
                signature_verifier=signature_verifier,
            )
            work_budget.add_parent_edges(len(commit_object.parents))
            if any(parent not in preceding_commits for parent in commit_object.parents):
                raise ValueError(
                    "history-v2 commit graph is not bounded to the authorized range"
                )
            commit_objects[commit_rev] = commit_object
            preceding_commits.add(commit_rev)

    expected_parent = base_rev
    for commit_rev in commits:
        if commit_objects[commit_rev].parents != (expected_parent,):
            raise ValueError(
                "history-v2 parent edges must form a linear exact-base chain"
            )
        expected_parent = commit_rev
    if expected_parent != head_rev:
        raise ValueError("history-v2 parent-edge chain does not end at head")

    reachable_blobs: dict[str, int] = {}
    commit_entries: dict[str, tuple[HistoryV2TreeEntry, ...]] = {}
    for commit_rev in commits:
        commit_object = commit_objects[commit_rev]
        entries = history_v2_tree_entries(
            root,
            commit_rev,
            tree_oid=commit_object.tree_oid,
            work_budget=work_budget,
        )
        commit_entries[commit_rev] = entries
        for entry in entries:
            if entry.object_type != "blob" or entry.size is None:
                continue
            previous_size = reachable_blobs.setdefault(entry.object_id, entry.size)
            if previous_size != entry.size:
                raise ValueError("history-v2 reachable blob metadata changed")
        if (
            len(reachable_blobs) > HISTORY_V2_MAX_REACHABLE_BLOBS
            or sum(reachable_blobs.values()) > HISTORY_V2_MAX_REACHABLE_BLOB_BYTES
        ):
            raise ValueError("history-v2 reachable blob set exceeds the trusted limit")

    for commit_rev in commits:
        commit_object = commit_objects[commit_rev]
        validate_history_v2_commit_tree(
            root,
            commit_rev,
            commit_object.tree_oid,
            commit_entries[commit_rev],
            work_budget=work_budget,
        )

    for commit_rev in commits:
        commit_object = commit_objects[commit_rev]
        for parent_rev in commit_object.parents:
            validate_history_v2_commit_edge(
                root,
                parent_rev=parent_rev,
                commit_rev=commit_rev,
                role=role,
                work_budget=work_budget,
            )
    return commit_objects


def validated_history_v2_range_checkout(
    root: Path,
    *,
    base_rev: str,
    head_rev: str,
) -> tuple[Path, str, str]:
    root = root.resolve()
    base_rev = canonical_history_v2_oid(base_rev, "history-v2 base")
    head_rev = canonical_history_v2_oid(head_rev, "history-v2 head")
    if base_rev == head_rev or len(base_rev) != len(head_rev):
        raise ValueError("history-v2 base and head coordinates are invalid")
    top = Path(
        history_v2_git_text(root, "rev-parse", "--show-toplevel").strip()
    ).resolve()
    if top != root:
        raise ValueError("history-v2 root must be the exact Git worktree root")
    observed_head = canonical_history_v2_oid(
        history_v2_git_text(root, "rev-parse", "--verify", "HEAD").strip(),
        "history-v2 worktree head",
    )
    if observed_head != head_rev:
        raise ValueError("history-v2 worktree head differs from the authorized head")
    if history_v2_git_output(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignore-submodules=none",
    ):
        raise ValueError("history-v2 worktree must exactly match the authorized head")
    for label, revision in (("base", base_rev), ("head", head_rev)):
        observed_type = history_v2_git_text(
            root,
            "cat-file",
            "-t",
            revision,
            max_bytes=64,
        ).strip()
        if observed_type != "commit":
            raise ValueError(f"history-v2 {label} is not a commit")
    try:
        merge_bases = tuple(
            line
            for line in history_v2_git_text(
                root,
                "merge-base",
                "--all",
                base_rev,
                head_rev,
                max_bytes=1024,
            ).splitlines()
            if line
        )
    except ValueError as exc:
        raise ValueError(
            "history-v2 head is not based on the exact authorized base"
        ) from exc
    if merge_bases != (base_rev,):
        raise ValueError("history-v2 head is not based on the exact authorized base")
    return root, base_rev, head_rev


def validate_history_v2_merge_range(
    root: Path,
    *,
    base_rev: str,
    head_rev: str,
    role: str = "publication",
    work_budget: HistoryV2WorkBudget | None = None,
    verify_candidate_signature: bool = True,
) -> dict[str, Any]:
    if role not in {"publication", "admin"}:
        raise ValueError("history-v2 candidate authority role is invalid")
    root, base_rev, head_rev = validated_history_v2_range_checkout(
        root,
        base_rev=base_rev,
        head_rev=head_rev,
    )
    budget = work_budget or HistoryV2WorkBudget()
    commit_count_text = history_v2_git_text(
        root,
        "rev-list",
        "--count",
        f"--max-count={HISTORY_V2_MAX_COMMITS + 1}",
        f"{base_rev}..{head_rev}",
        max_bytes=128,
    ).strip()
    if not commit_count_text.isdecimal():
        raise ValueError("history-v2 commit count is invalid")
    commit_count = int(commit_count_text)
    if not 1 <= commit_count <= HISTORY_V2_MAX_COMMITS:
        raise ValueError("history-v2 commit count exceeds the trusted limit")
    commit_objects = validate_history_v2_new_commits(
        root,
        base_rev=base_rev,
        head_rev=head_rev,
        expected_count=commit_count,
        role=role,
        work_budget=budget,
        verify_candidate_signature=verify_candidate_signature,
    )
    changed = parse_history_v2_changed_paths(
        history_v2_diff_output(
            root,
            base_rev,
            head_rev,
            work_budget=budget,
        )
    )
    if classify_history_v2_transaction(changed) != role:
        raise ValueError(
            "history-v2 candidate range changes a different authority role"
        )
    for status, relative in changed:
        if (
            role == "publication"
            and status == "M"
            and allowed_retained_jsonl_artifact(relative) is not None
        ):
            base_value = history_v2_read_path_value(
                root,
                base_rev,
                relative,
                work_budget=budget,
            )
            head_value = history_v2_read_path_value(
                root,
                head_rev,
                relative,
                work_budget=budget,
            )
            if len(head_value) <= len(base_value) or not head_value.startswith(
                base_value
            ):
                raise ValueError(
                    "history-v2 JSONL modifications must be strict append-only updates"
                )
        elif role == "publication" and status == "M":
            raise ValueError(
                "history-v2 publication range rewrites a retained artifact"
            )
    head_tree = canonical_history_v2_oid(
        history_v2_git_text(
            root,
            "rev-parse",
            "--verify",
            f"{head_rev}^{{tree}}",
            max_bytes=128,
        ).strip(),
        "history-v2 head tree",
    )
    return {
        "schema_version": 1,
        "kind": HISTORY_V2_MERGE_PLAN_KIND,
        "validation_mode": "history-v2-candidate-range",
        "base_sha": base_rev,
        "head_sha": head_rev,
        "head_tree_sha": head_tree,
        "head_subject": commit_objects[head_rev].subject,
        "commit_count": commit_count,
        "changed_path_count": len(changed),
        "transaction_role": role,
    }


@dataclass(frozen=True)
class HistoryV2MergePlan:
    base_oid: str
    head_oid: str
    head_tree_oid: str
    squash_subject: str
    trust_generation: str
    role: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "base_oid": self.base_oid,
            "head_oid": self.head_oid,
            "head_tree_oid": self.head_tree_oid,
            "squash_subject": self.squash_subject,
            "trust_generation": self.trust_generation,
            "role": self.role,
        }


def history_v2_commit_subject(root: Path, revision: str) -> str:
    return validate_history_v2_physical_commit_object(
        root,
        revision,
        signature_verifier=None,
    ).subject


def history_v2_trust_generation_digest(
    root: Path,
    revision: str,
    *,
    work_budget: HistoryV2WorkBudget,
) -> str:
    revision = canonical_history_v2_oid(
        revision,
        "history-v2 trust-generation revision",
    )
    tree_oid = canonical_history_v2_oid(
        history_v2_git_text(
            root,
            "rev-parse",
            "--verify",
            f"{revision}^{{tree}}",
            max_bytes=128,
        ).strip(),
        "history-v2 trust-generation tree",
    )
    entries = history_v2_tree_entries(
        root,
        revision,
        tree_oid=tree_oid,
        work_budget=work_budget,
    )
    by_path = {
        entry.relative: entry for entry in entries if entry.object_type == "blob"
    }
    selected = []
    for relative in HISTORY_V2_TRUST_GENERATION_PATHS:
        entry = by_path.get(relative)
        if (
            entry is None
            or entry.mode != "100644"
            or entry.object_type != "blob"
            or len(entry.object_id) != len(revision)
        ):
            raise ValueError("history-v2 trust-generation inventory is incomplete")
        selected.append(
            (
                relative.as_posix(),
                entry.mode,
                entry.object_type,
                entry.object_id,
            )
        )
    encoded = (
        json.dumps(selected, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def history_v2_domain_candidate_plan(
    root: Path,
    *,
    base_rev: str,
    head_rev: str,
    changed: list[tuple[str, Path]],
) -> tuple[dict[str, Any] | None, list[str]]:
    if not any(history_v2_run_artifact(relative) for _status, relative in changed):
        return None, []
    try:
        contract = trusted_history_v2_domain_contract(
            expected_revision=base_rev,
            candidate_root=root,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        return None, [safe_exception_message(exc)]
    if contract is None:
        return None, ["trusted history-v2 domain validator is unavailable"]
    try:
        plan, issues = contract.build_pull_request_merge_plan(
            root,
            base_rev,
            head_rev,
        )
    except Exception:
        return None, ["trusted history-v2 candidate range validation failed"]
    valid_issue_payload, has_issues = _history_v2_domain_issue_payload(issues)
    if not valid_issue_payload:
        return None, ["trusted history-v2 candidate range result is invalid"]
    if has_issues:
        return None, [
            "trusted history-v2 candidate range validator rejected the transaction"
        ]
    try:
        payload = plan.as_dict()
    except Exception:
        return None, ["trusted history-v2 candidate range plan is unavailable"]
    expected_keys = {
        "schema_version",
        "base_oid",
        "head_oid",
        "head_tree_oid",
        "squash_subject",
        "trust_generation",
    }
    if (
        type(payload) is not dict
        or set(payload) != expected_keys
        or type(payload.get("schema_version")) is not int
        or payload["schema_version"] != 1
        or payload.get("base_oid") != base_rev
        or payload.get("head_oid") != head_rev
        or type(payload.get("base_oid")) is not str
        or type(payload.get("head_oid")) is not str
        or type(payload.get("head_tree_oid")) is not str
        or HISTORY_V2_OID_RE.fullmatch(payload["head_tree_oid"]) is None
        or len(payload["head_tree_oid"]) != len(head_rev)
        or type(payload.get("squash_subject")) is not str
        or HISTORY_V2_COMMIT_SUBJECT_RE.fullmatch(payload["squash_subject"]) is None
        or HISTORY_V2_RAW_CONVERSATION_EVIDENCE_RE.search(payload["squash_subject"])
        is not None
        or type(payload.get("trust_generation")) is not str
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}",
            payload["trust_generation"],
        )
        is None
    ):
        return None, ["trusted history-v2 candidate range plan is inconsistent"]
    return payload, []


def validate_history_v2_domain_candidate_range(
    root: Path,
    *,
    base_rev: str,
    head_rev: str,
    changed: list[tuple[str, Path]],
    expected_tree: str,
    expected_subject: str,
    expected_trust_generation: str,
) -> list[str]:
    payload, issues = history_v2_domain_candidate_plan(
        root,
        base_rev=base_rev,
        head_rev=head_rev,
        changed=changed,
    )
    if issues or payload is None:
        return issues
    if (
        payload["head_tree_oid"] != expected_tree
        or payload["squash_subject"] != expected_subject
        or payload["trust_generation"] != expected_trust_generation
    ):
        return ["trusted history-v2 candidate range plan is inconsistent"]
    return []


def validate_history_v2_domain_default_range(
    root: Path,
    *,
    base_rev: str,
    head_rev: str,
    changed: list[tuple[str, Path]],
    work_budget: HistoryV2WorkBudget,
) -> list[str]:
    if not any(history_v2_run_artifact(relative) for _status, relative in changed):
        return []
    try:
        contract = trusted_history_v2_domain_revision_contract(
            root,
            base_rev,
            work_budget=work_budget,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        return [safe_exception_message(exc)]
    if contract is None:
        return ["trusted history-v2 domain validator is unavailable"]
    try:
        issues = contract.validate_default_branch_update(
            root,
            base_rev,
            head_rev,
        )
    except Exception:
        return ["trusted history-v2 default transaction validation failed"]
    valid_issue_payload, has_issues = _history_v2_domain_issue_payload(issues)
    if not valid_issue_payload:
        return ["trusted history-v2 default transaction result is invalid"]
    if has_issues:
        return [
            "trusted history-v2 default transaction validator rejected the transaction"
        ]
    return []


def build_pull_request_candidate_plan(
    root: Path,
    base_rev: str,
    head_rev: str,
) -> tuple[HistoryV2MergePlan | None, list[str]]:
    root = root.resolve()
    budget = HistoryV2WorkBudget()
    try:
        root, base_rev, head_rev = validated_history_v2_range_checkout(
            root,
            base_rev=base_rev,
            head_rev=head_rev,
        )
        changed = parse_history_v2_changed_paths(
            history_v2_diff_output(
                root,
                base_rev,
                head_rev,
                work_budget=budget,
            )
        )
        role = classify_history_v2_transaction(changed)
        has_domain_artifacts = any(
            history_v2_run_artifact(relative) for _status, relative in changed
        )
        if has_domain_artifacts and role != "publication":
            raise ValueError(
                "trusted history-v2 bundle transaction is not a publication"
            )
        validation = validate_history_v2_merge_range(
            root,
            base_rev=base_rev,
            head_rev=head_rev,
            role=role,
            work_budget=budget,
            verify_candidate_signature=True,
        )
        head_tree_oid = validation["head_tree_sha"]
        squash_subject = validation["head_subject"]
        trust_generation = history_v2_trust_generation_digest(
            root,
            base_rev,
            work_budget=budget,
        )
        issues = validate_history_v2_tree(
            root,
            work_budget=budget,
            trusted_base_rev=base_rev,
        )
        if issues:
            return None, list(dict.fromkeys(issues))
        if has_domain_artifacts:
            domain_issues = validate_history_v2_domain_candidate_range(
                root,
                base_rev=base_rev,
                head_rev=head_rev,
                changed=changed,
                expected_tree=head_tree_oid,
                expected_subject=squash_subject,
                expected_trust_generation="sha256:" + trust_generation,
            )
            if domain_issues:
                return None, list(dict.fromkeys(domain_issues))
        plan = HistoryV2MergePlan(
            base_oid=base_rev,
            head_oid=head_rev,
            head_tree_oid=head_tree_oid,
            squash_subject=squash_subject,
            trust_generation=trust_generation,
            role=role,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        return None, [safe_exception_message(exc)]
    return plan, []


def validate_fixed_head_snapshot(
    root: Path,
    expected_head: str,
) -> list[str]:
    root = root.resolve()
    try:
        expected_head = canonical_history_v2_oid(
            expected_head,
            "history-v2 fixed snapshot head",
        )
        top = Path(
            history_v2_git_text(
                root,
                "rev-parse",
                "--show-toplevel",
            ).strip()
        ).resolve()
        observed_head = canonical_history_v2_oid(
            history_v2_git_text(
                root,
                "rev-parse",
                "--verify",
                "HEAD",
                max_bytes=128,
            ).strip(),
            "history-v2 fixed snapshot observed head",
        )
        if top != root or observed_head != expected_head:
            raise ValueError(
                "history-v2 fixed snapshot is not the exact requested head"
            )
        if history_v2_git_output(
            root,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ):
            raise ValueError("history-v2 fixed snapshot is not pristine")
    except (OSError, UnicodeError, ValueError) as exc:
        return [safe_exception_message(exc)]
    return validate_history_v2_tree(root)


def validate_history_v2_generic_append_only_changes(
    root: Path,
    *,
    base_rev: str,
    head_rev: str,
    changed: list[tuple[str, Path]],
    work_budget: HistoryV2WorkBudget,
    rewrite_error: str,
    append_error: str,
) -> None:
    for status, relative in changed:
        jsonl_kind = allowed_retained_jsonl_artifact(relative)
        if status == "D" or (status == "M" and jsonl_kind is None):
            raise ValueError(rewrite_error)
        if status != "M":
            continue
        base_value = history_v2_read_path_value(
            root,
            base_rev,
            relative,
            work_budget=work_budget,
        )
        head_value = history_v2_read_path_value(
            root,
            head_rev,
            relative,
            work_budget=work_budget,
        )
        if len(head_value) <= len(base_value) or not head_value.startswith(base_value):
            raise ValueError(append_error)


def validate_append_only_event_range(
    root: Path,
    before_rev: str,
    head_rev: str,
    *,
    forced: bool,
) -> list[str]:
    root = root.resolve()
    try:
        if type(forced) is not bool or forced:
            raise ValueError("history-v2 prospective squash is forced")
        before_rev = canonical_history_v2_oid(
            before_rev,
            "history-v2 prospective squash base",
        )
        head_rev = canonical_history_v2_oid(
            head_rev,
            "history-v2 prospective squash head",
        )
        budget = HistoryV2WorkBudget()
        head_tree_oid, _parents = history_v2_single_parent_squash_coordinates(
            root,
            before_rev=before_rev,
            head_rev=head_rev,
        )
        budget.authorized_domain_revisions.add((root, before_rev))
        observed_tree_oid = canonical_history_v2_oid(
            history_v2_git_text(
                root,
                "rev-parse",
                "--verify",
                "HEAD^{tree}",
                max_bytes=128,
            ).strip(),
            "history-v2 fixed-Q tree",
        )
        if observed_tree_oid != head_tree_oid:
            raise ValueError("history-v2 prospective squash tree differs from fixed Q")
        changed = parse_history_v2_changed_paths(
            history_v2_diff_output(
                root,
                before_rev,
                head_rev,
                work_budget=budget,
            )
        )
        if classify_history_v2_transaction(changed) != "publication":
            raise ValueError("history-v2 prospective squash is not a publication")
        validate_history_v2_generic_append_only_changes(
            root,
            base_rev=before_rev,
            head_rev=head_rev,
            changed=changed,
            work_budget=budget,
            rewrite_error=(
                "history-v2 prospective squash rewrites a retained artifact"
            ),
            append_error=(
                "history-v2 prospective JSONL update is not strict append-only"
            ),
        )
        if any(history_v2_run_artifact(relative) for _status, relative in changed):
            return validate_history_v2_domain_default_range(
                root,
                base_rev=before_rev,
                head_rev=head_rev,
                changed=changed,
                work_budget=budget,
            )
    except (OSError, UnicodeError, ValueError) as exc:
        return [safe_exception_message(exc)]
    return []


def history_v2_bootstrap_markers(root: Path, base_rev: str) -> frozenset[Path]:
    raw = history_v2_git_output(
        root,
        "ls-tree",
        "-z",
        "--name-only",
        base_rev,
        "--",
        *(path.as_posix() for path in sorted(BOOTSTRAP_V2_TEMPORARY_PATHS)),
        max_bytes=16 * 1024,
    )
    fields = raw.split(NUL_BYTE)
    if fields[-1:] != [b""]:
        raise ValueError("history-v2 bootstrap marker inventory is malformed")
    markers: set[Path] = set()
    for raw_path in fields[:-1]:
        try:
            path_text = raw_path.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(
                "history-v2 bootstrap marker inventory is invalid"
            ) from exc
        relative = Path(path_text)
        if (
            relative not in BOOTSTRAP_V2_TEMPORARY_PATHS
            or relative in markers
            or relative.as_posix() != path_text
        ):
            raise ValueError("history-v2 bootstrap marker inventory is invalid")
        markers.add(relative)
    return frozenset(markers)


def history_v2_blob_entry_map(
    entries: tuple[HistoryV2TreeEntry, ...],
) -> dict[Path, HistoryV2TreeEntry]:
    return {entry.relative: entry for entry in entries if entry.object_type == "blob"}


def validate_history_v2_bootstrap_transaction(
    root: Path,
    *,
    base_rev: str,
    head_rev: str,
    verify_candidate_signature: bool = True,
    work_budget: HistoryV2WorkBudget | None = None,
    github_commit_receipt: dict[str, Any] | None = None,
    repository: str | None = None,
    repository_id: int | None = None,
) -> dict[str, Any]:
    root, base_rev, head_rev = validated_history_v2_range_checkout(
        root,
        base_rev=base_rev,
        head_rev=head_rev,
    )
    budget = work_budget or HistoryV2WorkBudget()
    count_text = history_v2_git_text(
        root,
        "rev-list",
        "--count",
        "--max-count=2",
        f"{base_rev}..{head_rev}",
        max_bytes=16,
    ).strip()
    if count_text != "1":
        raise ValueError("history-v2 bootstrap must contain exactly one commit")
    if type(verify_candidate_signature) is not bool:
        raise ValueError("history-v2 bootstrap signature mode is invalid")
    if verify_candidate_signature:
        with history_v2_signature_verifier_for_root(
            root,
            policy="bootstrap-v2",
        ) as signature_verifier:
            commit = validate_history_v2_commit_object(
                root,
                head_rev,
                signature_verifier=signature_verifier,
            )
        head_tree_oid = commit.tree_oid
        parents = commit.parents
    else:
        head_tree_oid, parents = history_v2_single_parent_squash_coordinates(
            root,
            before_rev=base_rev,
            head_rev=head_rev,
            github_commit_receipt=github_commit_receipt,
            repository=repository,
            repository_id=repository_id,
        )
    budget.add_parent_edges(len(parents))
    if parents != (base_rev,):
        raise ValueError(
            "history-v2 bootstrap head must have the event before SHA as its only parent"
        )

    base_tree_oid = canonical_history_v2_oid(
        history_v2_git_text(
            root,
            "rev-parse",
            "--verify",
            f"{base_rev}^{{tree}}",
            max_bytes=128,
        ).strip(),
        "history-v2 bootstrap base tree",
    )
    base_entries = history_v2_blob_entry_map(
        history_v2_tree_entries(
            root,
            base_rev,
            tree_oid=base_tree_oid,
            work_budget=budget,
        )
    )
    head_entries = history_v2_blob_entry_map(
        history_v2_tree_entries(
            root,
            head_rev,
            tree_oid=head_tree_oid,
            work_budget=budget,
        )
    )
    if BOOTSTRAP_V2_ALLOWED_FILES != BOOTSTRAP_V2_REQUIRED_FILES:
        raise ValueError("trusted bootstrap-v2 inventories differ")
    markers = frozenset(base_entries) & BOOTSTRAP_V2_TEMPORARY_PATHS
    if markers != BOOTSTRAP_V2_TEMPORARY_PATHS:
        raise ValueError("history-v2 bootstrap base marker set is incomplete")
    if frozenset(head_entries) & BOOTSTRAP_V2_TEMPORARY_PATHS:
        raise ValueError("history-v2 bootstrap artifacts remain at head")

    base_ci = base_entries.get(BOOTSTRAP_V2_CI_PATH)
    template = base_entries.get(BOOTSTRAP_V2_PERMANENT_CI_TEMPLATE_PATH)
    head_ci = head_entries.get(BOOTSTRAP_V2_CI_PATH)
    if (
        base_ci is None
        or base_ci.mode != "100644"
        or base_ci.object_id
        not in {
            BOOTSTRAP_V2_LEGACY_CI_BLOB_OID,
            BOOTSTRAP_V2_PERMANENT_CI_BLOB_OID,
        }
        or template is None
        or template.mode != "100644"
        or template.object_id != BOOTSTRAP_V2_PERMANENT_CI_BLOB_OID
        or head_ci is None
        or head_ci.mode != "100644"
        or head_ci.object_id != BOOTSTRAP_V2_PERMANENT_CI_BLOB_OID
    ):
        raise ValueError("history-v2 bootstrap CI transition is not authorized")

    protected = set(base_entries) - BOOTSTRAP_V2_TEMPORARY_PATHS
    for relative in protected - {BOOTSTRAP_V2_CI_PATH}:
        if head_entries.get(relative) != base_entries[relative]:
            raise ValueError(
                "history-v2 bootstrap rewrites or deletes a protected base artifact"
            )
    head_paths = set(head_entries)
    allowed_head_paths = protected | BOOTSTRAP_V2_ALLOWED_FILES
    if not BOOTSTRAP_V2_REQUIRED_FILES <= head_paths:
        raise ValueError("history-v2 bootstrap head is missing a required artifact")
    if not head_paths <= allowed_head_paths:
        raise ValueError("history-v2 bootstrap head adds an unexpected artifact")
    if any(
        head_entries[relative].mode != "100644"
        for relative in BOOTSTRAP_V2_ALLOWED_FILES
    ):
        raise ValueError("history-v2 bootstrap artifact mode is not authorized")
    return {
        "schema_version": 1,
        "kind": "retrospective-history-v2-default-transaction",
        "transaction_kind": "bootstrap-v2",
        "validation_mode": "bootstrap-v2-actual-default-squash",
        "base_sha": base_rev,
        "head_sha": head_rev,
        "head_tree_sha": head_tree_oid,
        "commit_count": 1,
        "candidate_signature_retained": verify_candidate_signature,
    }


def history_v2_single_parent_squash_coordinates(
    root: Path,
    *,
    before_rev: str,
    head_rev: str,
    github_commit_receipt: dict[str, Any] | None = None,
    repository: str | None = None,
    repository_id: int | None = None,
) -> tuple[str, tuple[str, ...]]:
    before_rev = canonical_history_v2_oid(
        before_rev,
        "history-v2 squash base",
    )
    head_rev = canonical_history_v2_oid(head_rev, "history-v2 squash head")
    raw_line = history_v2_git_text(
        root,
        "rev-list",
        "--parents",
        "--max-count=1",
        head_rev,
        max_bytes=512,
    ).strip()
    fields = raw_line.split()
    if fields[:1] != [head_rev] or len(fields) != 2:
        raise ValueError(
            "history-v2 default update must be one linear single-parent squash"
        )
    raw_commit = history_v2_git_output(
        root,
        "cat-file",
        "commit",
        head_rev,
        max_bytes=HISTORY_V2_MAX_COMMIT_BYTES,
    )
    if b"\ngpgsig " in b"\n" + raw_commit.partition(b"\n\n")[0]:
        if github_commit_receipt is None or repository is None or repository_id is None:
            raise ValueError(
                "history-v2 GitHub squash commit lacks exact provider verification"
            )
        parsed = parse_history_v2_github_squash_commit(
            raw_commit,
            expected_oid=head_rev,
        )
        validate_history_v2_github_squash_receipt(
            github_commit_receipt,
            commit=parsed,
            repository=repository,
            repository_id=repository_id,
            before_rev=before_rev,
            head_rev=head_rev,
        )
        head_tree_oid, parents = parsed.tree_oid, parsed.parents
    else:
        if any(
            value is not None
            for value in (github_commit_receipt, repository, repository_id)
        ):
            raise ValueError("history-v2 default squash is not GitHub provider-signed")
        head_tree_oid, parents = parse_history_v2_unsigned_squash_commit(
            raw_commit,
            expected_oid=head_rev,
        )
    if len(parents) != 1:
        raise ValueError(
            "history-v2 default update must be one linear single-parent squash"
        )
    parent = parents[0]
    if parent != before_rev:
        raise ValueError(
            "history-v2 default update parent does not equal event before SHA"
        )
    return head_tree_oid, (parent,)


def validated_history_v2_default_event_checkout(
    root: Path,
    *,
    before_rev: str,
    head_rev: str,
    event_created: bool,
    event_deleted: bool,
    event_forced: bool,
    work_budget: HistoryV2WorkBudget | None = None,
    github_commit_receipt: dict[str, Any] | None = None,
    repository: str | None = None,
    repository_id: int | None = None,
) -> tuple[Path, str, str]:
    if any(
        type(value) is not bool
        for value in (event_created, event_deleted, event_forced)
    ):
        raise ValueError("history-v2 push event flags are invalid")
    before_rev = canonical_history_v2_oid(
        before_rev,
        "history-v2 event before",
    )
    head_rev = canonical_history_v2_oid(head_rev, "history-v2 event head")
    if set(before_rev) == {"0"} or event_created:
        raise ValueError(
            "history-v2 zero-before branch creation/bootstrap is unsupported"
        )
    if set(head_rev) == {"0"} or event_deleted:
        raise ValueError("history-v2 default-branch deletion is prohibited")
    if event_forced:
        raise ValueError("history-v2 force-push is prohibited")
    if len(before_rev) != len(head_rev):
        raise ValueError("history-v2 event object ID lengths differ")

    root, before_rev, head_rev = validated_history_v2_range_checkout(
        root,
        base_rev=before_rev,
        head_rev=head_rev,
    )
    history_v2_single_parent_squash_coordinates(
        root,
        before_rev=before_rev,
        head_rev=head_rev,
        github_commit_receipt=github_commit_receipt,
        repository=repository,
        repository_id=repository_id,
    )
    if work_budget is not None:
        work_budget.authorized_domain_revisions.add((root, before_rev))
    return root, before_rev, head_rev


def validate_history_v2_actual_squash_transaction(
    root: Path,
    *,
    before_rev: str,
    head_rev: str,
    work_budget: HistoryV2WorkBudget | None = None,
    github_commit_receipt: dict[str, Any] | None = None,
    repository: str | None = None,
    repository_id: int | None = None,
) -> dict[str, Any]:
    root, before_rev, head_rev = validated_history_v2_range_checkout(
        root,
        base_rev=before_rev,
        head_rev=head_rev,
    )
    budget = work_budget or HistoryV2WorkBudget()
    head_tree_oid, _parents = history_v2_single_parent_squash_coordinates(
        root,
        before_rev=before_rev,
        head_rev=head_rev,
        github_commit_receipt=github_commit_receipt,
        repository=repository,
        repository_id=repository_id,
    )
    budget.authorized_domain_revisions.add((root, before_rev))
    changed = parse_history_v2_changed_paths(
        history_v2_diff_output(
            root,
            before_rev,
            head_rev,
            work_budget=budget,
        )
    )
    if not changed:
        raise ValueError("history-v2 default squash transaction is empty")
    role = classify_history_v2_transaction(changed)
    has_v2_runs = any(
        history_v2_run_artifact(relative) for _status, relative in changed
    )
    if role == "publication":
        validate_history_v2_generic_append_only_changes(
            root,
            base_rev=before_rev,
            head_rev=head_rev,
            changed=changed,
            work_budget=budget,
            rewrite_error=(
                "history-v2 default squash deletes or rewrites retained history"
            ),
            append_error=("history-v2 default JSONL update is not strict append-only"),
        )
    if has_v2_runs:
        domain_issues = validate_history_v2_domain_default_range(
            root,
            base_rev=before_rev,
            head_rev=head_rev,
            changed=changed,
            work_budget=budget,
        )
        if domain_issues:
            raise ValueError(domain_issues[0])
    return {
        "schema_version": 1,
        "kind": "retrospective-history-v2-default-transaction",
        "transaction_kind": "history-v2",
        "validation_mode": "history-v2-actual-default-squash",
        "base_sha": before_rev,
        "head_sha": head_rev,
        "head_tree_sha": head_tree_oid,
        "commit_count": 1,
        "changed_path_count": len(changed),
        "candidate_signature_retained": False,
        "transaction_role": role,
    }


def validate_history_v2_default_transaction(
    root: Path,
    *,
    before_rev: str,
    head_rev: str,
    event_created: bool,
    event_deleted: bool,
    event_forced: bool,
    work_budget: HistoryV2WorkBudget | None = None,
    github_commit_receipt: dict[str, Any] | None = None,
    repository: str | None = None,
    repository_id: int | None = None,
) -> dict[str, Any]:
    root, before_rev, head_rev = validated_history_v2_default_event_checkout(
        root,
        before_rev=before_rev,
        head_rev=head_rev,
        event_created=event_created,
        event_deleted=event_deleted,
        event_forced=event_forced,
        work_budget=work_budget,
        github_commit_receipt=github_commit_receipt,
        repository=repository,
        repository_id=repository_id,
    )

    markers = history_v2_bootstrap_markers(root, before_rev)
    if markers:
        if markers != BOOTSTRAP_V2_TEMPORARY_PATHS:
            raise ValueError("history-v2 bootstrap base marker set is incomplete")
        return validate_history_v2_bootstrap_transaction(
            root,
            base_rev=before_rev,
            head_rev=head_rev,
            verify_candidate_signature=False,
            work_budget=work_budget,
            github_commit_receipt=github_commit_receipt,
            repository=repository,
            repository_id=repository_id,
        )
    return validate_history_v2_actual_squash_transaction(
        root,
        before_rev=before_rev,
        head_rev=head_rev,
        work_budget=work_budget,
        github_commit_receipt=github_commit_receipt,
        repository=repository,
        repository_id=repository_id,
    )


def write_history_v2_merge_plan(
    path: Path,
    payload: dict[str, Any],
    *,
    root: Path,
) -> None:
    root = root.resolve()
    parent = path.parent.resolve()
    destination = parent / path.name
    try:
        destination.relative_to(root)
    except ValueError:
        pass
    else:
        raise ValueError(
            "history-v2 merge plan must be written outside the candidate root"
        )
    if not parent.is_dir() or destination.exists() or destination.is_symlink():
        raise ValueError("history-v2 merge plan destination is not a new regular file")
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if len(encoded) > HISTORY_V2_MAX_MERGE_PLAN_BYTES:
        raise ValueError("history-v2 merge plan exceeds the trusted size limit")
    descriptor = -1
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise ValueError("history-v2 merge plan could not be written safely") from exc


def validate_root(
    root: Path,
    *,
    history_v2: bool = False,
    visible_files: Sequence[Path] | None = None,
    file_snapshots: tuple[HistoryV2FileSnapshot, ...] | None = None,
) -> list[str]:
    root = root.resolve()
    issues = BoundedDiagnosticList()
    if visible_files is not None and file_snapshots is not None:
        return ["retained history inventory source is ambiguous"]
    if file_snapshots is None and visible_files is not None:
        try:
            relatives = tuple(path.relative_to(root) for path in tuple(visible_files))
        except ValueError:
            return ["retained history inventory escaped its root"]
        file_snapshots, snapshot_issue = snapshot_explicit_history_v2_files(
            root,
            relatives,
            max_entries=BOOTSTRAP_V2_MAX_CANDIDATE_ENTRIES,
            label="retained artifact",
        )
        if snapshot_issue is not None or file_snapshots is None:
            return [snapshot_issue or "retained history inventory could not be frozen"]
    elif file_snapshots is None:
        git_snapshots, git_issue = git_visible_file_snapshots(
            root,
            max_entries=BOOTSTRAP_V2_MAX_CANDIDATE_ENTRIES,
        )
        if git_snapshots is not None:
            file_snapshots = git_snapshots
        elif git_control_path_present(root):
            return [git_issue or "trusted Git file enumeration failed closed"]
        else:
            file_snapshots, snapshot_issue = snapshot_bootstrap_v2_files(
                root,
                max_entries=BOOTSTRAP_V2_MAX_CANDIDATE_ENTRIES,
            )
            if snapshot_issue is not None or file_snapshots is None:
                if "candidate root is missing" in (snapshot_issue or ""):
                    return ["root must be an existing directory"]
                return [
                    snapshot_issue or "retained history inventory could not be frozen"
                ]
    frozen_snapshots = tuple(file_snapshots)
    retained_export_files: dict[tuple[str, str], set[str]] = {}
    retained_export_modes: dict[tuple[str, str], dict[str, str]] = {}
    retained_export_windows: dict[
        tuple[str, str],
        dict[
            str,
            tuple[
                str,
                tuple[int, int, int, int, int, int, int],
                tuple[int, int, int, int, int, int, int],
            ],
        ],
    ] = {}
    retained_export_rows: dict[tuple[str, str], dict[str, list[Any]]] = {}
    retained_export_trends: dict[tuple[str, str], Any] = {}
    data_month_rows: dict[tuple[str, str, str], dict[str, list[Any]]] = {}
    data_month_trends: dict[tuple[str, str, str], Any] = {}
    data_month_manifests: dict[tuple[str, str, str], Any] = {}
    data_month_paths: dict[tuple[str, str, str], dict[str, Path]] = {}
    total_jsonl_rows = 0
    for snapshot in frozen_snapshots:
        relative = snapshot.relative
        display_relative = display_relative_path(relative)
        if history_v2 and history_v2_run_artifact(relative):
            continue
        export_key = retained_export_key(relative)
        data_month_key = retained_data_month_key(relative)
        if export_key is not None:
            retained_export_files.setdefault(export_key, set()).add(relative.name)
        if snapshot.is_symlink:
            issues.append(f"{display_relative}: symlink artifact is not allowed")
            continue
        if snapshot.value is None or not snapshot.is_regular:
            issues.append(f"{display_relative}: artifact is not a regular file")
            continue
        value = snapshot.value
        if forbidden_path(relative) and not (
            history_v2 and relative in BOOTSTRAP_V2_ALLOWED_FILES
        ):
            issues.append(f"{display_relative}: forbidden raw/transient artifact")
            continue
        suffix = relative.suffix.lower()
        try:
            if content_scanned_infrastructure_artifact(
                relative,
                history_v2=history_v2,
            ):
                infrastructure_text = value.decode("utf-8")
                if contains_infrastructure_risk_text(
                    infrastructure_text, relative=relative
                ):
                    issues.append(
                        f"{display_relative}: infrastructure text contains raw/sensitive evidence"
                    )
                if relative == BOOTSTRAP_WORKFLOW_PATH:
                    issues.extend(
                        f"{display_relative}: {issue}"
                        for issue in validate_bootstrap_workflow(infrastructure_text)
                    )
            if suffix == ".json":
                data = parse_json_bytes(value)
                if allowed_infrastructure_artifact(
                    relative,
                    history_v2=history_v2,
                ) and contains_decoded_infrastructure_risk(data):
                    issues.append(
                        f"{display_relative}: infrastructure text contains raw/sensitive evidence"
                    )
                json_kind = allowed_retained_json_artifact(relative)
                if json_kind == "manifest":
                    expected_mode = expected_mode_from_retained_export_path(relative)
                    issues.extend(
                        f"{display_relative}: {issue}"
                        for issue in validate_manifest(
                            data, expected_mode=expected_mode
                        )
                    )
                    if (
                        expected_mode is not None
                        and isinstance(data, dict)
                        and isinstance(data.get("mode"), str)
                    ):
                        retained_export_modes.setdefault(tuple(relative.parts[:2]), {})[
                            "manifest"
                        ] = data["mode"]
                    if export_key is not None and isinstance(data, dict):
                        window_identity = retained_window_identity(data.get("window"))
                        if window_identity is not None:
                            retained_export_windows.setdefault(export_key, {})[
                                "manifest"
                            ] = window_identity
                    if data_month_key is not None and isinstance(data, dict):
                        data_month_manifests[data_month_key] = data
                        data_month_paths.setdefault(data_month_key, {})["manifest"] = (
                            relative
                        )
                elif json_kind == "trend":
                    expected_mode = expected_mode_from_retained_export_path(relative)
                    issues.extend(
                        f"{display_relative}: {issue}"
                        for issue in validate_trend(data, expected_mode=expected_mode)
                    )
                    if expected_mode is not None and isinstance(data, dict):
                        window = data.get("window")
                        if isinstance(window, dict) and isinstance(
                            window.get("mode"), str
                        ):
                            retained_export_modes.setdefault(
                                tuple(relative.parts[:2]), {}
                            )["trend"] = window["mode"]
                        if export_key is not None:
                            retained_export_trends[export_key] = data
                            window_identity = retained_window_identity(window)
                            if window_identity is not None:
                                retained_export_windows.setdefault(export_key, {})[
                                    "trend"
                                ] = window_identity
                    if data_month_key is not None and isinstance(data, dict):
                        data_month_trends[data_month_key] = data
                        data_month_paths.setdefault(data_month_key, {})["trend"] = (
                            relative
                        )
                elif relative.parts[0] in {
                    "data",
                    "reports",
                } or not allowed_infrastructure_artifact(
                    relative,
                    history_v2=history_v2,
                ):
                    issues.append(f"{display_relative}: unexpected JSON artifact")
                    if contains_risky_key(data):
                        issues.append(
                            f"{display_relative}: JSON key contains raw/sensitive evidence"
                        )
                    if contains_risky_text(data):
                        issues.append(
                            f"{display_relative}: retained text contains raw/sensitive evidence"
                        )
            elif suffix == ".jsonl":
                rows = parse_jsonl_bytes(value)
                total_jsonl_rows += len(rows)
                if total_jsonl_rows > HISTORY_V2_MAX_TOTAL_JSONL_ROWS:
                    raise ValueError("JSONL total row count exceeds the trusted limit")
                jsonl_kind = allowed_retained_jsonl_artifact(relative)
                if jsonl_kind is None:
                    issues.append(f"{display_relative}: unexpected JSONL artifact")
                else:
                    validator = (
                        validate_episode
                        if jsonl_kind == "episode"
                        else validate_turn_flag
                    )
                    for index, row in enumerate(rows, 1):
                        if issues.saturated:
                            break
                        issues.extend(
                            f"{display_relative}:{index}: {issue}"
                            for issue in validator(row)
                        )
                    if export_key is not None:
                        retained_export_rows.setdefault(export_key, {}).setdefault(
                            jsonl_kind, []
                        ).extend(rows)
                    if data_month_key is not None:
                        data_month_rows.setdefault(data_month_key, {}).setdefault(
                            jsonl_kind, []
                        ).extend(rows)
                        data_month_paths.setdefault(data_month_key, {})[jsonl_kind] = (
                            relative
                        )
            elif relative.parts[0] in {"data", "reports"} and suffix in {".md", ".txt"}:
                if not allowed_retained_text_artifact(relative):
                    issues.append(
                        f"{display_relative}: unexpected retained text artifact location"
                    )
                include_safety_markers = relative.as_posix() not in {
                    "data/README.md",
                    "reports/README.md",
                }
                if contains_risky_text(
                    value.decode("utf-8"),
                    include_safety_markers=include_safety_markers,
                ):
                    issues.append(
                        f"{display_relative}: retained text contains raw/sensitive evidence"
                    )
            elif (
                relative.parts[0] in {"data", "reports"}
                and suffix not in VALID_RETAINED_SUFFIXES
            ):
                issues.append(
                    f"{display_relative}: unexpected retained artifact suffix"
                )
                try:
                    if contains_risky_text(value.decode("utf-8")):
                        issues.append(
                            f"{display_relative}: retained text contains raw/sensitive evidence"
                        )
                except UnicodeDecodeError:
                    pass
            elif not allowed_infrastructure_artifact(
                relative,
                history_v2=history_v2,
            ):
                issues.append(
                    f"{display_relative}: unexpected retained artifact location"
                )
                if suffix in TEXT_ARTIFACT_SUFFIXES:
                    try:
                        if contains_risky_text(value.decode("utf-8")):
                            issues.append(
                                f"{display_relative}: retained text contains raw/sensitive evidence"
                            )
                    except UnicodeDecodeError:
                        pass
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            issues.append(f"{display_relative}: {safe_exception_message(exc)}")
    for export_dir, names in sorted(retained_export_files.items()):
        if names != RETAINED_EXPORT_FILES:
            issues.append(
                f"{Path(*export_dir)}: retained export directory is incomplete or has extra files"
            )
        modes = retained_export_modes.get(export_dir, {})
        if (
            modes.get("trend")
            and modes.get("manifest")
            and modes["trend"] != modes["manifest"]
        ):
            issues.append(
                f"{Path(*export_dir)}: retained export mode differs between trend and manifest"
            )
        windows = retained_export_windows.get(export_dir, {})
        if (
            windows.get("trend")
            and windows.get("manifest")
            and windows["trend"] != windows["manifest"]
        ):
            issues.append(
                f"{Path(*export_dir)}: retained export window differs between trend and manifest"
            )
        issues.extend(
            validate_retained_export_consistency(
                export_dir,
                retained_export_rows.get(export_dir, {}),
                retained_export_trends.get(export_dir),
            )
        )
    for data_month in sorted(
        set(data_month_rows) | set(data_month_trends) | set(data_month_manifests)
    ):
        trend = data_month_trends.get(data_month)
        manifest = data_month_manifests.get(data_month)
        if isinstance(trend, dict) and isinstance(manifest, dict):
            trend_window = retained_window_identity(trend.get("window"))
            manifest_window = retained_window_identity(manifest.get("window"))
            if (
                trend_window is not None
                and manifest_window is not None
                and trend_window != manifest_window
            ):
                issues.append(
                    f"{Path(*data_month)}: retained export window differs between trend and manifest"
                )
        issues.extend(
            validate_retained_export_consistency(
                data_month,
                data_month_rows.get(data_month, {}),
                data_month_trends.get(data_month),
                manifest=data_month_manifests.get(data_month),
                artifact_paths=data_month_paths.get(data_month),
                data_month=data_month,
            )
        )
    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate retained session retrospective history artifacts."
    )
    parser.add_argument("--root")
    parser.add_argument("--base-root")
    parser.add_argument("--candidate-root")
    parser.add_argument("--base-rev")
    parser.add_argument("--head-rev")
    parser.add_argument("--repository")
    parser.add_argument("--repository-id", type=int)
    parser.add_argument("--github-commit-receipt", type=Path)
    parser.add_argument("--write-merge-plan", type=Path)
    parser.add_argument("--event-created", choices=("true", "false"))
    parser.add_argument("--event-deleted", choices=("true", "false"))
    parser.add_argument("--event-forced", choices=("true", "false"))
    parser.add_argument(
        "--mode",
        choices=(
            "ordinary",
            "bootstrap-v2-candidate",
            "history-v2-candidate-range",
            "history-v2-actual-default-squash",
        ),
        default="ordinary",
    )
    args = parser.parse_args(argv)
    if args.mode == "bootstrap-v2-candidate":
        if (
            args.root is not None
            or args.base_root is None
            or args.candidate_root is None
            or args.base_rev is not None
            or args.head_rev is not None
            or args.write_merge_plan is not None
            or args.event_created is not None
            or args.event_deleted is not None
            or args.event_forced is not None
            or args.repository is not None
            or args.repository_id is not None
            or args.github_commit_receipt is not None
        ):
            parser.error(
                "bootstrap-v2-candidate mode requires --base-root and --candidate-root only"
            )
        issues = validate_bootstrap_v2_candidate(
            Path(args.base_root),
            Path(args.candidate_root),
        )
    elif args.mode == "history-v2-candidate-range":
        if (
            args.base_root is not None
            or args.candidate_root is not None
            or args.event_created is not None
            or args.event_deleted is not None
            or args.event_forced is not None
            or args.root is None
            or args.base_rev is None
            or args.head_rev is None
            or args.write_merge_plan is None
            or args.repository is not None
            or args.repository_id is not None
            or args.github_commit_receipt is not None
        ):
            parser.error(
                "history-v2-candidate-range requires --root, --base-rev, --head-rev, and --write-merge-plan"
            )
        root = Path(args.root)
        merge_plan, issues = build_pull_request_candidate_plan(
            root,
            args.base_rev,
            args.head_rev,
        )
        if not issues and merge_plan is not None:
            try:
                write_history_v2_merge_plan(
                    args.write_merge_plan,
                    merge_plan.as_dict(),
                    root=root,
                )
            except (OSError, UnicodeError, ValueError) as exc:
                issues.append(safe_exception_message(exc))
    elif args.mode == "history-v2-actual-default-squash":
        if (
            args.base_root is not None
            or args.candidate_root is not None
            or args.base_rev is None
            or args.head_rev is None
            or args.write_merge_plan is not None
            or args.event_created is None
            or args.event_deleted is None
            or args.event_forced is None
            or args.repository is None
            or args.repository_id is None
            or args.github_commit_receipt is None
        ):
            parser.error(
                "history-v2-actual-default-squash mode requires --root, --base-rev, --head-rev, --repository, --repository-id, --github-commit-receipt, and every event flag"
            )
        root = Path(args.root or ".")
        work_budget = HistoryV2WorkBudget()
        try:
            github_commit_receipt = load_history_v2_github_squash_receipt(
                args.github_commit_receipt
            )
            root, before_rev, head_rev = validated_history_v2_default_event_checkout(
                root,
                before_rev=args.base_rev,
                head_rev=args.head_rev,
                event_created=args.event_created == "true",
                event_deleted=args.event_deleted == "true",
                event_forced=args.event_forced == "true",
                work_budget=work_budget,
                github_commit_receipt=github_commit_receipt,
                repository=args.repository,
                repository_id=args.repository_id,
            )
        except (OSError, UnicodeError, ValueError) as exc:
            issues = [safe_exception_message(exc)]
        else:
            issues = validate_history_v2_tree(
                root,
                work_budget=work_budget,
                trusted_base_rev=before_rev,
                trusted_revision_domain=True,
            )
        if not issues:
            try:
                validate_history_v2_default_transaction(
                    root,
                    before_rev=before_rev,
                    head_rev=head_rev,
                    event_created=args.event_created == "true",
                    event_deleted=args.event_deleted == "true",
                    event_forced=args.event_forced == "true",
                    work_budget=work_budget,
                    github_commit_receipt=github_commit_receipt,
                    repository=args.repository,
                    repository_id=args.repository_id,
                )
            except (OSError, UnicodeError, ValueError) as exc:
                issues.append(safe_exception_message(exc))
    else:
        if (
            args.base_root is not None
            or args.candidate_root is not None
            or args.base_rev is not None
            or args.head_rev is not None
            or args.write_merge_plan is not None
            or args.event_created is not None
            or args.event_deleted is not None
            or args.event_forced is not None
            or args.repository is not None
            or args.repository_id is not None
            or args.github_commit_receipt is not None
        ):
            parser.error("ordinary mode accepts --root only")
        issues = validate_root(Path(args.root or "."))
    bounded_issues = BoundedDiagnosticList(issues)
    if bounded_issues:
        for issue in bounded_issues:
            print(issue)
        return 1
    if args.mode == "bootstrap-v2-candidate":
        print("bootstrap v2 candidate is valid")
    elif args.mode in {
        "history-v2-candidate-range",
        "history-v2-actual-default-squash",
    }:
        print("history v2 tree is valid")
    else:
        print("retained history is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
