#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import unicodedata
from typing import Any


SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "schemas"
    / "session-retrospective-v2.schema.json"
)

V2_COMMIT_IDENTITY = (
    "Codex Session Retrospective Publisher "
    "<codex-session-retrospective@users.noreply.github.com>"
)
V2_COMMIT_MESSAGE_RE = re.compile(
    r"\APublish session retrospective v2 "
    r"(?P<mode>daily|weekly|baseline|session) "
    r"(?P<window>\d{4}-\d{2}-\d{2}(?:_to_\d{4}-\d{2}-\d{2})?) "
    r"(?P<run_ref>run_ref_v2:[0-9a-f]{64})\n\Z"
)

ISSUE_PATH = "path: retained v2 artifact path is not allowed"
ISSUE_SCHEMA = "content: retained v2 schema vocabulary is unavailable"
ISSUE_UTF8 = "content: payload is not valid UTF-8 text"
ISSUE_FORMAT = "content: payload is not valid retained JSON or JSONL"
ISSUE_REPORT = "content: report.md does not use the fixed retained structure"
ISSUE_KEY = "content: JSON key is outside the retained schema vocabulary"
ISSUE_SCALAR = "content: string scalar is outside the retained closed vocabulary"
ISSUE_SENSITIVE_MATERIAL = "content: sensitive authentication material is not allowed"
ISSUE_URL = "content: URL, address, or network locator is not allowed"
ISSUE_RAW_PATH = "content: raw filesystem path is not allowed"
ISSUE_RAW_ID = "content: raw or misplaced identifier is not allowed"
ISSUE_HOST = "content: host alias is not allowed"
ISSUE_PROMPT = "content: original prompt or transcript material is not allowed"
ISSUE_TOOL_OUTPUT = "content: tool or command output is not allowed"
ISSUE_CODE = "content: code or proprietary excerpt is not allowed"
ISSUE_HASH = "content: bare or misplaced digest is not allowed"
ISSUE_PROSE = "content: prose is outside the retained template vocabulary"
ISSUE_COMMIT_AUTHOR = "commit metadata: author identity is not allowed"
ISSUE_COMMIT_COMMITTER = "commit metadata: committer identity is not allowed"
ISSUE_COMMIT_MESSAGE = "commit metadata: message does not use the fixed v2 grammar"

ARTIFACT_BASENAMES = frozenset(
    {
        "coverage.json",
        "episodes.jsonl",
        "manifest.json",
        "report.md",
        "summary.json",
        "topics.jsonl",
        "trend_report.json",
        "turn_findings.jsonl",
    }
)
RUN_MODES = frozenset({"daily", "weekly", "baseline", "session"})
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100_000
RUN_ID_RE = re.compile(r"^[0-9a-f]{64}$")
RUN_REF_RE = re.compile(r"^run_ref_v2:[0-9a-f]{64}$")
PRODUCTION_CONFIGURATION_ROOT_RE = re.compile(
    r"^production_configuration_root_v2:sha256:[0-9a-f]{64}$"
)
CAMPAIGN_SEGMENT_ROOT_RE = re.compile(r"^campaign_segment_root_v2:sha256:[0-9a-f]{64}$")
COARSE_TIMESTAMP_RE = re.compile(
    r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
    r"T(?:[01]\d|2[0-3]):[0-5]\d:00Z$"
)
BUNDLE_DIGEST_RE = re.compile(r"^retained_bundle_digest_v2:sha256:[0-9a-f]{64}$")
GIT_OBJECT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")

TYPED_REF_DEFS = frozenset(
    {
        "aggregate_input_ref",
        "authorization_usage_ref",
        "campaign_leaf_root_ref",
        "campaign_page_root_ref",
        "campaign_ref",
        "confidence_basis_ref",
        "coverage_revision_ref",
        "episode_ref",
        "episode_revision_ref",
        "evidence_commitment_ref",
        "evidence_ref",
        "gap_ref",
        "gap_revision_ref",
        "head_ref",
        "host_ref",
        "job_ref",
        "key_id",
        "model_era_ref",
        "parameter_set_ref",
        "policy_era_ref",
        "provenance_ref",
        "provider_policy_ref",
        "publication_attempt_ref",
        "quarantine_generation_ref",
        "receipt_ref",
        "run_input_ref",
        "run_ref",
        "run_revision_ref",
        "session_ref",
        "source_cell_ref",
        "source_ref",
        "source_snapshot_ref",
        "source_unit_ref",
        "summary_revision_ref",
        "topic_ref",
        "topic_revision_ref",
        "transaction_ref",
        "trend_revision_ref",
        "turn_finding_revision_ref",
        "turn_ref",
        "workstream_ref",
    }
)
TYPED_REF_RE = re.compile(
    r"^(?P<kind>[a-z][a-z0-9_]*_ref)_v2:(?P<digest>[0-9a-f]{32})$"
)
KEY_ID_RE = re.compile(r"^key_id_v2:[0-9a-f]{16}$")
ANY_RETAINED_REF_RE = re.compile(r"\b[a-z][a-z0-9_]*_ref_v[12]:[A-Za-z0-9._:-]+", re.I)
WINDOW_ROUTE_COMPONENT_COUNT = 32
RUN_ROUTE_COMPONENT_COUNT = 32
RUN_ARTIFACT_PATH_COMPONENT_COUNT = 68
WINDOW_ROUTE_DOMAIN = b"session-retrospective-retained-window-route-v2"
ROUTE_COMPONENT_RE = re.compile(r"^[0-9a-f]{2}$")

REPORT_HEADINGS = (
    "# Session Retrospective",
    "## What Happened",
    "## What Worked Well",
    "## Friction And Confusion",
    "## Errors And Verification",
    "## Collaboration Patterns",
    "## Safety And Privacy",
    "## Prompt Improvements",
    "## Durable AGENTS.md Guidance",
    "## Reusable Skill Candidates",
    "## Follow-up Actions",
    "## Confidence",
    "## Change From Prior Compatible Period",
)

UNSAFE_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----", re.I),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b", re.I),
    re.compile(r"\bBasic\s+[A-Za-z0-9+/=]{8,}\b", re.I),
    re.compile(r"\b(?:sk|rk)[-_](?:proj[-_])?[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", re.I),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(
        r"(?<![A-Za-z0-9_])[\"']?"
        r"[A-Za-z0-9._-]*(?:password|passwd|pwd|credentials?|secret(?:[\s._-]+key)?|"
        r"access[\s._-]*token|refresh[\s._-]*token|api[\s._-]*key|authorization|"
        r"client[\s._-]*secret|private[\s._-]*key)"
        r"[A-Za-z0-9._-]*[\"']?\s*(?::|=)\s*\S+",
        re.I,
    ),
    re.compile(
        r"\b(?:password|passwd|api[\s._-]*key|secret[\s._-]*key|access[\s._-]*token|"
        r"refresh[\s._-]*token|client[\s._-]*secret|private[\s._-]*key)"
        r"\s+[\"']?[A-Za-z0-9._~+/=-]{4,}",
        re.I,
    ),
)
URL_PATTERNS = (
    re.compile(r"\b(?:https?|ssh|git|file|smb)://", re.I),
    re.compile(r"\bgit@[A-Za-z0-9_.-]+:"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(
        r"\b(?:localhost|[A-Za-z0-9-]+\.(?:internal|corp|local|lan|example|invalid|test))"
        r"(?::\d{1,5})?\b",
        re.I,
    ),
    re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
    re.compile(
        r"(?<![0-9A-Fa-f:])(?:::1|f[cd][0-9A-Fa-f:]+|fe[89abAB][0-9A-Fa-f:]+)(?![0-9A-Fa-f:])"
    ),
)
IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Za-z:])\[?"
    r"(?P<address>(?=[0-9A-Fa-f:]*:)[0-9A-Fa-f:]{2,})"
    r"\]?(?::\d{1,5})?(?![0-9A-Za-z:])"
)
LONG_DIGIT_IDENTIFIER_RE = re.compile(r"(?<![A-Za-z0-9])\d{7,}(?![A-Za-z0-9])")
PHONE_LIKE_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:\+\d{1,3}[ .-]*)?"
    r"(?:\(?\d{2,4}\)?[ .-]+){1,3}\d{3,4}(?![A-Za-z0-9])"
)
PATH_PATTERNS = (
    re.compile(
        r"(?<![A-Za-z0-9_:])"
        r"(?:~|/(?:Users|home|root|private|tmp|var|etc|opt|Volumes|workspace|workspaces))[/\\]",
        re.I,
    ),
    re.compile(r"(?<![A-Za-z0-9_:])/(?:[A-Za-z_.][A-Za-z0-9._-]*/)+[A-Za-z0-9._-]+"),
    re.compile(r"(?<![A-Za-z0-9_])(?:\.{1,2}|~)[/\\][^\s\"'<>]+"),
    re.compile(r"(?<![A-Za-z0-9_])\.codex(?:-local|-tmp)?[/\\]", re.I),
    re.compile(r"(?<![A-Za-z0-9_])(?:sessions|archived_sessions)[/\\]", re.I),
    re.compile(
        r"\b[A-Za-z]:\\(?:Users|home|root|private|tmp|var|etc|opt|workspace|workspaces)\\",
        re.I,
    ),
    re.compile(r"(?<![A-Za-z0-9_])[A-Za-z]:\\(?:[^\\\s\"'<>]+\\)+[^\\\s\"'<>]+"),
    re.compile(r"(?<![A-Za-z0-9_])\\\\[A-Za-z0-9_.-]+\\[A-Za-z0-9$_.-]+"),
    re.compile(
        r"(?<![A-Za-z0-9_])(?:[A-Za-z0-9_.-]+/)+"
        r"(?:[A-Za-z0-9_.-]+\.(?:py|js|ts|tsx|jsx|go|rs|swift|c|cc|cpp|h|java|rb|sh|zsh|jsonl?|log|sqlite))\b",
        re.I,
    ),
)
RAW_ID_PATTERNS = (
    re.compile(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I
    ),
    re.compile(
        r"(?<![A-Za-z0-9_])[\"']?(?:source|source[._ -]?unit|session|thread|turn|episode|"
        r"conversation|message|tool[._ -]?call)(?:[._ -]?id)[\"']?"
        r"(?:\s*[:=]\s*|\s+)[\"']?[A-Za-z0-9_.:-]{6,}",
        re.I,
    ),
    re.compile(
        r"\b(?:sess|session|thread|turn|conversation|msg|message|call|toolu|chatcmpl|resp|asst)"
        r"[_-][A-Za-z0-9_.-]{8,}\b",
        re.I,
    ),
    re.compile(r"\brollout(?:-summary)?-[A-Za-z0-9_.-]+\.jsonl\b", re.I),
    re.compile(r"\brun_v2_[0-9a-f]{24}\b"),
)
HOST_PATTERNS = (
    re.compile(r"\b(?:miku-bot-dev|hoteng-srv-01|localhost)\b", re.I),
    re.compile(
        r"\b(?:host|hostname|ssh[ _-]?target|server)[\s._-]*(?::|=)\s*[A-Za-z0-9_.-]+",
        re.I,
    ),
)
PROMPT_PATTERNS = (
    re.compile(
        r"(?im)^\s*(?:original|raw|full)?\s*(?:user|developer|system|assistant)\s*(?:prompt|message)?\s*:"
    ),
    re.compile(
        r"(?im)^\s*(?:original|raw|full)[ _-]?(?:prompt|transcript|conversation)\s*(?::|=)"
    ),
    re.compile(r"(?i)<\|?(?:user|developer|system|assistant)(?:_start|_end|\|)"),
    re.compile(
        r"(?i)[\"']role[\"']\s*:\s*[\"'](?:user|developer|system|assistant)[\"']"
    ),
)
TOOL_OUTPUT_PATTERNS = (
    re.compile(
        r"(?im)^\s*(?:tool(?:[ _-]?output)?|stdout|stderr|command[ _-]?output|exit[ _-]?code)\s*:"
    ),
    re.compile(r"(?i)<\|?(?:tool|tool_output)(?:_start|_end|\|)"),
    re.compile(r"(?im)^\s*(?:process exited with code|script completed|wall time:)"),
)
CODE_PATTERNS = (
    re.compile(r"```|`[^`\n]+`"),
    re.compile(
        r"(?m)^\s*(?:#!|def\s+\w+\s*\(|class\s+\w+|function\s+\w+\s*\(|"
        r"(?:from\s+\S+\s+)?import\s+\S+|#include\s*[<\"]|(?:const|let|var)\s+\w+\s*=|"
        r"func\s+\w+\s*\()"
    ),
    re.compile(
        r"(?m)^\s*(?:Traceback \(most recent call last\):|diff --git |@@\s|--- a/|\+\+\+ b/)"
    ),
    re.compile(r"(?m)^\s*\$\s+\S+"),
)
SOURCE_ENTITY_RE = re.compile(
    r"\b(?:customer|client|repository|repo|project|incident|tenant|organization|org)"
    r"\s*(?::|=)\s*[A-Za-z0-9_.-]+",
    re.I,
)
BARE_HASH_RE = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])"
)
LONG_OPAQUE_RE = re.compile(
    r"\b(?=[A-Za-z0-9_-]{24,}\b)(?=[A-Za-z0-9_-]*[A-Za-z])(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]+\b"
)
UNKNOWN_SNAKE_OR_CAMEL_RE = re.compile(
    r"\b(?:[a-z][a-z0-9]*_[a-z0-9_]+|[a-z]+[A-Z][A-Za-z0-9]*)\b"
)

BIDI_AND_INVISIBLE = frozenset(
    {
        "\u061c",
        "\u200b",
        "\u200c",
        "\u200d",
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2060",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
        "\ufeff",
    }
)


class _DuplicateKeyError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _reject_non_json_constant(_: str) -> None:
    raise ValueError


def _load_schema_policy() -> tuple[
    bool,
    frozenset[str],
    dict[str, frozenset[str]],
    dict[str, frozenset[str]],
    frozenset[str],
]:
    try:
        schema = json.loads(
            SCHEMA_PATH.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ):
        return (False, frozenset(), {}, {}, frozenset())

    definitions = schema.get("$defs", {})
    if not isinstance(definitions, dict):
        return (False, frozenset(), {}, {}, frozenset())

    allowed_keys: set[str] = set()
    field_literals: dict[str, set[str]] = {}
    field_ref_defs: dict[str, set[str]] = {}
    all_literals: set[str] = set()

    def policy_for(
        node: Any, seen_refs: frozenset[str] = frozenset()
    ) -> tuple[set[str], set[str]]:
        literals: set[str] = set()
        refs: set[str] = set()
        if isinstance(node, list):
            for child in node:
                child_literals, child_refs = policy_for(child, seen_refs)
                literals.update(child_literals)
                refs.update(child_refs)
            return literals, refs
        if not isinstance(node, dict):
            return literals, refs

        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/$defs/"):
            name = ref.removeprefix("#/$defs/")
            if name in TYPED_REF_DEFS:
                refs.add(name)
            if name not in seen_refs and name in definitions:
                child_literals, child_refs = policy_for(
                    definitions[name], seen_refs | {name}
                )
                literals.update(child_literals)
                refs.update(child_refs)

        constant = node.get("const")
        if isinstance(constant, str):
            literals.add(constant)
        enum = node.get("enum")
        if isinstance(enum, list):
            literals.update(value for value in enum if isinstance(value, str))

        for keyword in ("allOf", "anyOf", "oneOf", "prefixItems"):
            child_literals, child_refs = policy_for(node.get(keyword), seen_refs)
            literals.update(child_literals)
            refs.update(child_refs)
        child_literals, child_refs = policy_for(node.get("items"), seen_refs)
        literals.update(child_literals)
        refs.update(child_refs)
        return literals, refs

    def walk(node: Any) -> None:
        if isinstance(node, list):
            for child in node:
                walk(child)
            return
        if not isinstance(node, dict):
            return
        constant = node.get("const")
        if isinstance(constant, str):
            all_literals.add(constant)
        enum = node.get("enum")
        if isinstance(enum, list):
            all_literals.update(value for value in enum if isinstance(value, str))
        properties = node.get("properties")
        if isinstance(properties, dict):
            for key, child in properties.items():
                if not isinstance(key, str):
                    continue
                allowed_keys.add(key)
                literals, refs = policy_for(child)
                field_literals.setdefault(key, set()).update(literals)
                field_ref_defs.setdefault(key, set()).update(refs)
        for child in node.values():
            walk(child)

    try:
        walk(schema)
    except RecursionError:
        return (False, frozenset(), {}, {}, frozenset())
    return (
        True,
        frozenset(allowed_keys),
        {key: frozenset(values) for key, values in field_literals.items()},
        {key: frozenset(values) for key, values in field_ref_defs.items()},
        frozenset(all_literals),
    )


(
    _SCHEMA_POLICY_AVAILABLE,
    _ALLOWED_JSON_KEYS,
    _FIELD_LITERALS,
    _FIELD_REF_DEFS,
    _ALL_CLOSED_LITERALS,
) = _load_schema_policy()


def _build_prose_vocabulary() -> frozenset[str]:
    words = {
        "a",
        "about",
        "across",
        "after",
        "all",
        "also",
        "an",
        "and",
        "any",
        "are",
        "as",
        "at",
        "be",
        "because",
        "before",
        "between",
        "blocked",
        "blocking",
        "by",
        "can",
        "cannot",
        "claim",
        "claimed",
        "claims",
        "completed",
        "could",
        "did",
        "do",
        "does",
        "during",
        "each",
        "encountered",
        "evidence",
        "exact",
        "for",
        "from",
        "had",
        "has",
        "have",
        "identified",
        "if",
        "in",
        "inference",
        "into",
        "is",
        "it",
        "its",
        "may",
        "more",
        "must",
        "no",
        "not",
        "of",
        "on",
        "one",
        "only",
        "or",
        "per",
        "prior",
        "recorded",
        "remains",
        "required",
        "requires",
        "result",
        "results",
        "section",
        "should",
        "succeeded",
        "than",
        "that",
        "the",
        "their",
        "them",
        "there",
        "this",
        "to",
        "under",
        "unknown",
        "unavailable",
        "used",
        "using",
        "v",
        "was",
        "were",
        "when",
        "where",
        "while",
        "will",
        "with",
        "within",
        "without",
        "would",
    }
    for value in (*_ALL_CLOSED_LITERALS, *REPORT_HEADINGS):
        words.update(word.casefold() for word in re.findall(r"[A-Za-z]+", value))
    return frozenset(words)


_PROSE_VOCABULARY = _build_prose_vocabulary()


def _valid_date(value: str) -> bool:
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is None:
        return False
    try:
        dt.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _valid_window(value: str) -> bool:
    if "_to_" not in value:
        return _valid_date(value)
    parts = value.split("_to_")
    if len(parts) != 2 or not all(_valid_date(part) for part in parts):
        return False
    return dt.date.fromisoformat(parts[0]) < dt.date.fromisoformat(parts[1])


def _update_typed_frame(hasher: Any, frame_type: bytes, value: bytes) -> None:
    hasher.update(frame_type)
    hasher.update(len(value).to_bytes(8, byteorder="big", signed=False))
    hasher.update(value)


def _window_route_components(mode: str, window: str) -> tuple[str, ...]:
    hasher = hashlib.sha256()
    hasher.update(WINDOW_ROUTE_DOMAIN)
    _update_typed_frame(hasher, b"M", mode.encode("ascii"))
    _update_typed_frame(hasher, b"W", window.encode("ascii"))
    digest = hasher.hexdigest()
    return tuple(digest[offset : offset + 2] for offset in range(0, 64, 2))


def _valid_retained_path(relative: Path) -> bool:
    if (
        relative.is_absolute()
        or len(relative.parts) != RUN_ARTIFACT_PATH_COMPONENT_COUNT
    ):
        return False
    if any(
        part in {"", ".", ".."} or "\\" in part or UNSAFE_CONTROL_RE.search(part)
        for part in relative.parts
    ):
        return False
    parts = relative.parts
    root, mode = parts[:2]
    window_route_end = 2 + WINDOW_ROUTE_COMPONENT_COUNT
    window_route = tuple(parts[2:window_route_end])
    window = parts[window_route_end]
    run_route_start = window_route_end + 1
    run_route = tuple(
        parts[run_route_start : run_route_start + RUN_ROUTE_COMPONENT_COUNT]
    )
    basename = parts[-1]
    run_id = "".join(run_route)
    return (
        root == "runs"
        and mode in RUN_MODES
        and _valid_window(window)
        and all(
            ROUTE_COMPONENT_RE.fullmatch(component) is not None
            for component in (*window_route, *run_route)
        )
        and window_route == _window_route_components(mode, window)
        and RUN_ID_RE.fullmatch(run_id) is not None
        and basename in ARTIFACT_BASENAMES
    )


def _typed_ref_kind(value: str) -> str | None:
    if KEY_ID_RE.fullmatch(value):
        return "key_id"
    if RUN_REF_RE.fullmatch(value):
        return "run_ref"
    match = TYPED_REF_RE.fullmatch(value)
    if match is None:
        return None
    kind = match.group("kind")
    if kind == "run_ref":
        return None
    return kind if kind in TYPED_REF_DEFS else None


def _valid_template_parent(parent: Any, rendered_text: str) -> bool:
    if not isinstance(parent, dict):
        return False
    template_id = parent.get("template_id")
    if not isinstance(template_id, str) or not template_id.startswith(
        "retrospective.v2."
    ):
        return False
    if template_id not in _FIELD_LITERALS.get("template_id", frozenset()):
        return False
    if parent.get("rendering_policy") != "retained-template-renderer-v2":
        return False
    if not isinstance(parent.get("slots"), list):
        return False
    disposition = parent.get("detail_disposition")
    if template_id == "retrospective.v2.detail_not_retained":
        return (
            disposition == "detail_not_retained"
            and rendered_text
            == "Detail was not retained under the v2 retained-language policy."
            and parent.get("slots") == []
        )
    return disposition == "rendered"


def _allowed_json_string(
    field: str | None, value: str, parent: Any
) -> tuple[bool, bool, bool]:
    """Return allowed, opaque-structured, and prose flags."""
    if field is None or field not in _ALLOWED_JSON_KEYS:
        return (False, False, False)
    if field == "rendered_text":
        allowed = _valid_template_parent(parent, value)
        return (allowed, False, allowed)
    if field == "retained_bundle_digest_v2":
        allowed = BUNDLE_DIGEST_RE.fullmatch(value) is not None
        return (allowed, allowed, False)
    if field == "production_configuration_root_v2":
        allowed = PRODUCTION_CONFIGURATION_ROOT_RE.fullmatch(value) is not None
        return (allowed, allowed, False)
    if field == "campaign_segment_root_v2":
        allowed = CAMPAIGN_SEGMENT_ROOT_RE.fullmatch(value) is not None
        return (allowed, allowed, False)
    if field in {"engine_commit", "locked_first_parent_object_id"}:
        allowed = GIT_OBJECT_RE.fullmatch(value) is not None
        return (allowed, allowed, False)
    if field == "run_id":
        allowed = RUN_ID_RE.fullmatch(value) is not None
        return (allowed, allowed, False)
    if field == "path_component":
        allowed = _valid_window(value)
        return (allowed, allowed, False)
    if COARSE_TIMESTAMP_RE.fullmatch(value) is not None:
        return (_valid_date(value[:10]), True, False)

    ref_kind = _typed_ref_kind(value)
    if ref_kind is not None:
        allowed = ref_kind in _FIELD_REF_DEFS.get(field, frozenset())
        return (allowed, allowed, False)
    if value in _FIELD_LITERALS.get(field, frozenset()):
        return (True, True, False)
    return (False, False, False)


def _has_any(patterns: tuple[re.Pattern[str], ...], value: str) -> bool:
    return any(pattern.search(value) is not None for pattern in patterns)


def _contains_ipv6_locator(value: str) -> bool:
    for match in IPV6_CANDIDATE_RE.finditer(value):
        try:
            address = ipaddress.ip_address(match.group("address"))
        except ValueError:
            continue
        if isinstance(address, ipaddress.IPv6Address):
            return True
    return False


def _scan_prose_vocabulary(value: str, issues: set[str]) -> None:
    if any(ord(character) > 127 for character in value):
        issues.add(ISSUE_PROSE)
    words = (word.casefold() for word in re.findall(r"[A-Za-z]+", value))
    if any(word not in _PROSE_VOCABULARY for word in words):
        issues.add(ISSUE_PROSE)
    if UNKNOWN_SNAKE_OR_CAMEL_RE.search(value):
        issues.add(ISSUE_PROSE)


def _scan_text_risks(
    value: str,
    issues: set[str],
    *,
    allow_opaque: bool = False,
    prose: bool = False,
) -> None:
    normalized = unicodedata.normalize("NFKC", value)
    if (
        normalized != value
        or UNSAFE_CONTROL_RE.search(value)
        or any(character in BIDI_AND_INVISIBLE for character in value)
    ):
        issues.add(ISSUE_PROSE)
    if _has_any(SENSITIVE_VALUE_PATTERNS, normalized):
        issues.add(ISSUE_SENSITIVE_MATERIAL)
    if _has_any(URL_PATTERNS, normalized) or _contains_ipv6_locator(normalized):
        issues.add(ISSUE_URL)
    if _has_any(PATH_PATTERNS, normalized):
        issues.add(ISSUE_RAW_PATH)
    if _has_any(HOST_PATTERNS, normalized):
        issues.add(ISSUE_HOST)
    if _has_any(PROMPT_PATTERNS, normalized):
        issues.add(ISSUE_PROMPT)
    if _has_any(TOOL_OUTPUT_PATTERNS, normalized):
        issues.add(ISSUE_TOOL_OUTPUT)
    if _has_any(CODE_PATTERNS, normalized):
        issues.add(ISSUE_CODE)
    if SOURCE_ENTITY_RE.search(normalized):
        issues.add(ISSUE_PROSE)
    if not allow_opaque:
        if ANY_RETAINED_REF_RE.search(normalized) or _has_any(
            RAW_ID_PATTERNS, normalized
        ):
            issues.add(ISSUE_RAW_ID)
        if LONG_DIGIT_IDENTIFIER_RE.search(normalized) or PHONE_LIKE_RE.search(
            normalized
        ):
            issues.add(ISSUE_RAW_ID)
        if BARE_HASH_RE.search(normalized):
            issues.add(ISSUE_HASH)
        if LONG_OPAQUE_RE.search(normalized):
            issues.add(ISSUE_RAW_ID)
    if prose:
        _scan_prose_vocabulary(normalized, issues)


def _scan_unknown_key(key: str, issues: set[str]) -> None:
    issues.add(ISSUE_KEY)
    normalized = re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")
    if normalized in {
        "original_prompt",
        "raw_prompt",
        "full_prompt",
        "user_prompt",
        "prompt_text",
        "transcript",
        "conversation_log",
        "messages",
    }:
        issues.add(ISSUE_PROMPT)
    if normalized in {
        "tool_output",
        "command_output",
        "stdout",
        "stderr",
        "console_output",
    }:
        issues.add(ISSUE_TOOL_OUTPUT)
    if normalized in {"code", "code_excerpt", "source_code", "patch", "diff"}:
        issues.add(ISSUE_CODE)
    if normalized in {"path", "root", "cwd", "source_path", "filesystem_path"}:
        issues.add(ISSUE_RAW_PATH)
    if normalized in {"host", "hostname", "host_alias", "ssh_target"}:
        issues.add(ISSUE_HOST)
    if any(
        token in normalized
        for token in ("password", "credential", "secret", "api_key", "token")
    ):
        issues.add(ISSUE_SENSITIVE_MATERIAL)
    _scan_text_risks(key, issues)


def _scan_json_value(
    value: Any,
    issues: set[str],
    *,
    field: str | None = None,
    parent: Any = None,
) -> None:
    stack: list[tuple[Any, str | None, Any, int]] = [(value, field, parent, 0)]
    visited = 0
    while stack:
        current, current_field, current_parent, depth = stack.pop()
        visited += 1
        if visited > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            issues.add(ISSUE_FORMAT)
            return
        if isinstance(current, dict):
            for key in sorted(current, reverse=True):
                if key not in _ALLOWED_JSON_KEYS:
                    _scan_unknown_key(key, issues)
                stack.append((current[key], key, current, depth + 1))
            continue
        if isinstance(current, list):
            for child in reversed(current):
                stack.append((child, current_field, current, depth + 1))
            continue
        if not isinstance(current, str):
            continue

        allowed, opaque, prose = _allowed_json_string(
            current_field, current, current_parent
        )
        if not allowed:
            issues.add(ISSUE_SCALAR)
        _scan_text_risks(current, issues, allow_opaque=opaque, prose=prose)


def _parse_json(text: str) -> Any:
    return json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_json_constant,
    )


def _parse_jsonl(text: str) -> list[Any]:
    rows: list[Any] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        rows.append(_parse_json(line))
    return rows


def _scan_report(text: str, issues: set[str]) -> None:
    headings = tuple(line for line in text.splitlines() if line.startswith("#"))
    if not text.endswith("\n") or headings != REPORT_HEADINGS:
        issues.add(ISSUE_REPORT)
    if re.search(r"(?m)^\s*(?:>| {4}|\t)", text):
        issues.add(ISSUE_PROMPT)
    if re.search(r"!?\[[^\]\n]*\]\([^\)\n]*\)|<[^>\n]+>", text):
        issues.add(ISSUE_CODE)
    _scan_text_risks(text, issues, prose=False)
    body = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
    _scan_prose_vocabulary(body, issues)


def validate_v2_privacy(relative: Path, payload: bytes) -> list[str]:
    """Validate one retained v2 artifact without returning source-derived evidence."""
    issues: set[str] = set()
    relative = Path(relative)
    if not _valid_retained_path(relative):
        issues.add(ISSUE_PATH)
    if not _SCHEMA_POLICY_AVAILABLE:
        issues.add(ISSUE_SCHEMA)

    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        issues.add(ISSUE_UTF8)
        return sorted(issues)

    basename = relative.name
    if basename == "report.md":
        _scan_report(text, issues)
        return sorted(issues)

    try:
        if basename.endswith(".jsonl"):
            values = _parse_jsonl(text)
        elif basename.endswith(".json"):
            values = [_parse_json(text)]
        else:
            issues.add(ISSUE_FORMAT)
            _scan_text_risks(text, issues, prose=True)
            return sorted(issues)
    except (json.JSONDecodeError, RecursionError, ValueError):
        issues.add(ISSUE_FORMAT)
        _scan_text_risks(text, issues)
        return sorted(issues)

    try:
        for value in values:
            _scan_json_value(value, issues)
    except RecursionError:
        issues.add(ISSUE_FORMAT)
    return sorted(issues)


def validate_v2_commit_metadata(author: str, committer: str, message: str) -> list[str]:
    """Validate the fixed privacy-safe v2 commit identity and subject grammar."""
    issues: set[str] = set()
    if author != V2_COMMIT_IDENTITY:
        issues.add(ISSUE_COMMIT_AUTHOR)
    if committer != V2_COMMIT_IDENTITY:
        issues.add(ISSUE_COMMIT_COMMITTER)

    match = V2_COMMIT_MESSAGE_RE.fullmatch(message)
    if match is None or not _valid_window(match.group("window")):
        issues.add(ISSUE_COMMIT_MESSAGE)
    return sorted(issues)


__all__ = [
    "V2_COMMIT_IDENTITY",
    "V2_COMMIT_MESSAGE_RE",
    "validate_v2_commit_metadata",
    "validate_v2_privacy",
]
