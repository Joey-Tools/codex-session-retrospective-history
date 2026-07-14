from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "retrospective_history_v2.py"
SPEC = importlib.util.spec_from_file_location("retrospective_history_v2", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


ARTIFACTS = (
    "coverage.json",
    "episodes.jsonl",
    "manifest.json",
    "report.md",
    "summary.json",
    "topics.jsonl",
    "trend_report.json",
    "turn_findings.jsonl",
)
DOMAIN_TAG = b"session-retrospective-retained-bundle-v2"
PRODUCTION_CONFIGURATION_DOMAIN_TAG = (
    b"session-retrospective-production-configuration-v2"
)
CAMPAIGN_SEGMENT_DOMAIN_TAG = b"session-retrospective-campaign-segments-v2"
WINDOW_ROUTE_DOMAIN = b"session-retrospective-retained-window-route-v2"
WINDOW = {
    "mode": "daily",
    "path_component": "2026-07-13",
    "start": "2026-07-13T00:00:00Z",
    "end": "2026-07-14T00:00:00Z",
}
INVENTORY = [
    {
        "basename": "coverage.json",
        "media_type": "application/json",
        "encoding": "utf-8",
        "canonicalization": "canonical-json-v2",
        "schema_target": "coverage",
    },
    {
        "basename": "episodes.jsonl",
        "media_type": "application/x-ndjson",
        "encoding": "utf-8",
        "canonicalization": "canonical-jsonl-v2",
        "schema_target": "episode_record",
    },
    {
        "basename": "manifest.json",
        "media_type": "application/json",
        "encoding": "utf-8",
        "canonicalization": "canonical-json-projection-v2",
        "schema_target": "manifest",
    },
    {
        "basename": "report.md",
        "media_type": "text/markdown",
        "encoding": "utf-8",
        "canonicalization": "renderer-exact-markdown-v2",
        "schema_target": "report_markdown",
    },
    {
        "basename": "summary.json",
        "media_type": "application/json",
        "encoding": "utf-8",
        "canonicalization": "canonical-json-v2",
        "schema_target": "summary",
    },
    {
        "basename": "topics.jsonl",
        "media_type": "application/x-ndjson",
        "encoding": "utf-8",
        "canonicalization": "canonical-jsonl-v2",
        "schema_target": "topic_record",
    },
    {
        "basename": "trend_report.json",
        "media_type": "application/json",
        "encoding": "utf-8",
        "canonicalization": "canonical-json-v2",
        "schema_target": "trend_report",
    },
    {
        "basename": "turn_findings.jsonl",
        "media_type": "application/x-ndjson",
        "encoding": "utf-8",
        "canonicalization": "canonical-jsonl-v2",
        "schema_target": "turn_finding_record",
    },
]

REPORT_SECTION_HEADINGS = (
    "What Happened",
    "What Worked Well",
    "Friction And Confusion",
    "Errors And Verification",
    "Collaboration Patterns",
    "Safety And Privacy",
    "Prompt Improvements",
    "Durable AGENTS.md Guidance",
    "Reusable Skill Candidates",
    "Follow-up Actions",
    "Confidence",
    "Change From Prior Compatible Period",
)
POLICY_VERSION_FIELDS = (
    "source_registry",
    "source_accounting",
    "identity",
    "identity_reconciliation",
    "redaction",
    "detector",
    "evidence_verifier",
    "meaningfulness",
    "segmentation",
    "workstream",
    "continuation",
    "high_impact_screening",
    "review_adjudication",
    "topic_synthesis",
    "semantic_repair",
    "run_creation",
    "retained_generalization",
    "provider_egress",
    "transient_storage",
    "publisher_signature",
    "prompt_set",
)
OPERATIONAL_COUNT_FIELDS = (
    "jobs_issued",
    "jobs_completed",
    "jobs_rejected",
    "jobs_retried",
    "jobs_failed",
    "jobs_adjudicated",
    "source_leases_issued",
    "source_leases_accepted",
    "source_leases_revoked",
    "source_leases_expired",
    "source_leases_failed",
    "cache_hits",
    "cache_misses",
    "retained_bytes",
    "unresolved_required_receipts",
    "unresolved_privacy_breaches",
)


def hex_ref(prefix: str, value: int, width: int = 32) -> str:
    return f"{prefix}{value:0{width}x}"


def detail_template() -> dict[str, object]:
    return {
        "template_id": "retrospective.v2.detail_not_retained",
        "slots": [],
        "rendered_text": "Detail was not retained under the v2 retained-language policy.",
        "rendering_policy": "retained-template-renderer-v2",
        "detail_disposition": "detail_not_retained",
    }


def rendered_template(text: str) -> dict[str, object]:
    return {
        "template_id": "retrospective.v2.what_happened",
        "slots": [],
        "rendered_text": text,
        "rendering_policy": "retained-template-renderer-v2",
        "detail_disposition": "rendered",
    }


def confidence_dimensions(number: int = 1) -> dict[str, object]:
    dimension = {
        "level": "high",
        "basis": "complete_ledger",
        "basis_refs": [hex_ref("confidence_basis_ref_v2:", number)],
    }
    return {
        name: dict(dimension)
        for name in ("coverage", "extraction", "review", "comparability")
    }


def taxonomy_vector() -> dict[str, object]:
    return {
        "events": {
            name: "not_observed"
            for name in (
                "failed_command",
                "approval_request",
                "auth_denial",
                "retry",
                "user_correction",
                "incomplete_verification",
            )
        },
        "findings": {
            name: "not_observed"
            for name in (
                "over_exploration",
                "under_asking",
                "context_loss",
                "assumption_risk",
                "verification_gap",
                "safety_privacy_risk",
            )
        },
        "strengths": {
            name: "not_observed"
            for name in (
                "clear_scope",
                "efficient_execution",
                "appropriate_validation",
                "safe_handling",
                "effective_recovery",
                "concise_communication",
            )
        },
    }


def head_pair(number: int) -> dict[str, str]:
    return {
        "expected_head_ref": "absent_v2",
        "proposed_head_ref": hex_ref("head_ref_v2:", number),
    }


def source_accounting(number: int) -> dict[str, object]:
    return {"global": head_pair(number), "unit_corrections": []}


def report_payload(summary: dict[str, object]) -> bytes:
    summary_fields = (
        "what_happened",
        "worked_well",
        "friction_and_confusion",
        "errors_and_verification",
        "collaboration_patterns",
        "safety_and_privacy",
        "prompt_improvements",
        "agents_guidance",
        "skill_candidates",
        "follow_ups",
    )
    lines = ["# Session Retrospective"]
    for field_name, heading in zip(
        summary_fields, REPORT_SECTION_HEADINGS[:10], strict=True
    ):
        templates = summary[field_name]
        assert isinstance(templates, list)
        lines.extend(("", f"## {heading}"))
        lines.extend(
            [f"- {template['rendered_text']}" for template in templates]
            or ["- No observation was retained."]
        )
    confidence = summary["confidence"]
    assert isinstance(confidence, dict)
    lines.extend(("", "## Confidence"))
    for field_name, label in (
        ("coverage", "Coverage"),
        ("extraction", "Extraction"),
        ("review", "Review"),
        ("comparability", "Compatible"),
    ):
        dimension = confidence[field_name]
        assert isinstance(dimension, dict)
        level = str(dimension["level"]).replace("_", " ")
        basis = str(dimension["basis"]).replace("_", " ")
        lines.append(f"- {label}: {level} ({basis}).")
    change = summary["change_from_prior"]
    assert isinstance(change, dict)
    status = str(change["status"])
    detail = str(change["direction"] if status == "available" else change["reason"])
    lines.extend(
        (
            "",
            "## Change From Prior Compatible Period",
            f"- {status.title().replace('_', ' ')} ({detail.replace('_', ' ')}).",
        )
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def update_frame(hasher: object, frame_type: bytes, value: bytes) -> None:
    hasher.update(frame_type)
    hasher.update(len(value).to_bytes(8, "big"))
    hasher.update(value)


def window_route_components(mode: str, window: str) -> tuple[str, ...]:
    hasher = hashlib.sha256()
    hasher.update(WINDOW_ROUTE_DOMAIN)
    update_frame(hasher, b"M", mode.encode("ascii"))
    update_frame(hasher, b"W", window.encode("ascii"))
    digest = hasher.hexdigest()
    return tuple(digest[offset : offset + 2] for offset in range(0, 64, 2))


def physical_bundle_directory(root: Path, mode: str, window: str, run_id: str) -> Path:
    return root.joinpath(
        "runs",
        mode,
        *window_route_components(mode, window),
        window,
        *(run_id[offset : offset + 2] for offset in range(0, 64, 2)),
    )


def bundle_digest(payloads: dict[str, bytes], manifest: dict) -> str:
    projection = dict(manifest)
    projection.pop("retained_bundle_digest_v2")
    hasher = hashlib.sha256()
    hasher.update(DOMAIN_TAG)
    for basename in ARTIFACTS:
        content = (
            canonical_json(projection)
            if basename == "manifest.json"
            else payloads[basename]
        )
        update_frame(hasher, b"N", basename.encode("ascii"))
        update_frame(hasher, b"B", content)
    return f"retained_bundle_digest_v2:sha256:{hasher.hexdigest()}"


def production_configuration_root(provenance: dict[str, object]) -> str:
    hasher = hashlib.sha256()
    hasher.update(PRODUCTION_CONFIGURATION_DOMAIN_TAG)
    for field_name in (
        "active_calibration_receipt_ref",
        "active_calibration_model_era_ref",
        "active_shadow_receipt_ref",
        "active_shadow_model_era_ref",
    ):
        update_frame(hasher, b"N", field_name.encode("ascii"))
        update_frame(hasher, b"V", str(provenance[field_name]).encode("ascii"))
    return f"production_configuration_root_v2:sha256:{hasher.hexdigest()}"


def campaign_segment_root(
    campaign_ref: str,
    segment_count: int,
    segments: list[tuple[int, str, str]],
) -> str:
    hasher = hashlib.sha256()
    hasher.update(CAMPAIGN_SEGMENT_DOMAIN_TAG)
    update_frame(hasher, b"C", campaign_ref.encode("ascii"))
    update_frame(hasher, b"N", segment_count.to_bytes(8, "big"))
    for ordinal, run_ref, digest in sorted(segments):
        update_frame(hasher, b"O", ordinal.to_bytes(8, "big"))
        update_frame(hasher, b"R", run_ref.encode("ascii"))
        update_frame(hasher, b"D", digest.encode("ascii"))
    return f"campaign_segment_root_v2:sha256:{hasher.hexdigest()}"


@dataclass(frozen=True)
class BundleRefs:
    directory: Path
    run_id: str
    run_revision_ref: str
    coverage_revision_ref: str
    summary_revision_ref: str
    trend_revision_ref: str
    status: str


def write_json(path: Path, value: object) -> bytes:
    raw = canonical_json(value)
    path.write_bytes(raw)
    return raw


def rewrite_digest(directory: Path, *, pretty_manifest: bool = False) -> None:
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    payloads = {basename: (directory / basename).read_bytes() for basename in ARTIFACTS}
    manifest["retained_bundle_digest_v2"] = bundle_digest(payloads, manifest)
    if pretty_manifest:
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    else:
        manifest_path.write_bytes(canonical_json(manifest))


def write_bundle(
    root: Path,
    number: int,
    *,
    status: str = "complete",
    reason: str = "initial",
    predecessor: BundleRefs | None = None,
    execution_kind: str = "retrospective",
    window: dict[str, object] | None = None,
) -> BundleRefs:
    run_window = dict(WINDOW if window is None else window)
    mode = str(run_window["mode"])
    window_component = str(run_window["path_component"])
    run_id = f"{number:064x}"
    directory = physical_bundle_directory(root, mode, window_component, run_id)
    directory.mkdir(parents=True)

    run_ref = f"run_ref_v2:{run_id}"
    run_revision_ref = hex_ref("run_revision_ref_v2:", number)
    coverage_revision_ref = hex_ref("coverage_revision_ref_v2:", number)
    summary_revision_ref = hex_ref("summary_revision_ref_v2:", number)
    trend_revision_ref = hex_ref("trend_revision_ref_v2:", number)
    key_id = hex_ref("key_id_v2:", number, 16)
    policy_era_ref = hex_ref("policy_era_ref_v2:", 1)
    model_era_ref = hex_ref("model_era_ref_v2:", 1)
    revision_kind = (
        reason
        if reason
        in {
            "initial",
            "backfill",
            "correction",
            "identity_reconciliation",
            "screening_correction",
            "policy_transition",
            "model_transition",
            "compliance_retraction",
        }
        else "correction"
    )

    predecessor_run_refs = (
        [predecessor.run_revision_ref] if predecessor is not None else []
    )
    coverage_predecessor = (
        predecessor.coverage_revision_ref if predecessor is not None else None
    )
    summary_predecessor = (
        predecessor.summary_revision_ref if predecessor is not None else None
    )
    trend_predecessor = (
        predecessor.trend_revision_ref if predecessor is not None else None
    )

    gaps = []
    if status == "partial":
        gaps = [
            {
                "gap_ref": hex_ref("gap_ref_v2:", number),
                "gap_revision_ref": hex_ref("gap_revision_ref_v2:", number),
                "predecessor_gap_revision_ref": None,
                "scope": "source_unit",
                "stage": "transport",
                "reason": "source_transport_gap",
                "repairability": "repairable",
                "host_ref": None,
                "source_ref": None,
                "source_unit_ref": None,
                "turn_ref": None,
                "episode_ref": None,
                "topic_ref": None,
                "affected_unit_count": 1,
                "affected_byte_count": 0,
                "evidence_commitment_refs": [
                    hex_ref("evidence_commitment_ref_v2:", number)
                ],
                "authorization_usage_ref": None,
            }
        ]
    elif execution_kind == "compliance_retraction":
        gaps = [
            {
                "gap_ref": hex_ref("gap_ref_v2:", number),
                "gap_revision_ref": hex_ref("gap_revision_ref_v2:", number),
                "predecessor_gap_revision_ref": None,
                "scope": "publication",
                "stage": "finalize",
                "reason": "raw_retention_breach",
                "repairability": "terminal_policy",
                "host_ref": None,
                "source_ref": None,
                "source_unit_ref": None,
                "turn_ref": None,
                "episode_ref": None,
                "topic_ref": None,
                "affected_unit_count": 1,
                "affected_byte_count": 0,
                "evidence_commitment_refs": [
                    hex_ref("evidence_commitment_ref_v2:", number)
                ],
                "authorization_usage_ref": None,
            }
        ]
    gap_summary = {
        "source_repairable_gap_count": 1 if status == "partial" else 0,
        "semantic_repairable_gap_count": 0,
        "terminal_gap_count": 1 if execution_kind == "compliance_retraction" else 0,
        "terminal_authorization_usage_refs": [],
        "unaccounted_source_unit_count": 0,
        "privacy_breach_count": 1 if execution_kind == "compliance_retraction" else 0,
    }

    source_cells = [
        {
            "cell_ref": hex_ref("source_cell_ref_v2:", number * 10 + index),
            "host_ref": hex_ref("host_ref_v2:", number),
            "source_ref": hex_ref("source_ref_v2:", number * 10 + index),
            "source_kind": source_kind,
            "disposition": "no_activity",
            "enumeration_proof_ref": hex_ref(
                "evidence_commitment_ref_v2:", number * 10 + index
            ),
            "record_count": 0,
            "unit_count": 0,
            "byte_count": 0,
            "gap_refs": [],
        }
        for index, source_kind in enumerate(
            ("session_index", "history", "active_rollout", "archived_rollout"),
            1,
        )
    ]
    if status == "partial":
        source_cells[0].update(
            {
                "disposition": "gap",
                "record_count": 1,
                "unit_count": 1,
                "gap_refs": [gaps[0]["gap_ref"]],
            }
        )
        gaps[0].update(
            {
                "host_ref": source_cells[0]["host_ref"],
                "source_ref": source_cells[0]["source_ref"],
                "source_unit_ref": hex_ref("source_unit_ref_v2:", number),
            }
        )
    dispositions = {
        "source_unit": {
            "consumed": 0,
            "structurally_excluded": 0,
            "gap": 1 if status == "partial" else 0,
        },
        "parent_record": {
            "fully_consumed": 0,
            "fully_excluded": 0,
            "mixed_consumed_excluded": 0,
            "has_gap": 1 if status == "partial" else 0,
        },
        "structural_exclusion": {
            "deterministic_wrapper": 0,
            "heartbeat": 0,
            "empty_unit": 0,
            "duplicate_of": 0,
            "retrospective_coordinator": 0,
            "worker_attempt": 0,
            "out_of_window": 0,
            "source_policy_exclusion": 0,
        },
        "semantic_turn": {"meaningful": 0, "context_only": 0, "meaningfulness_gap": 0},
        "episode_review": {"reviewed": 0, "review_not_required": 0, "review_gap": 0},
        "turn_review": {"high_impact": 0, "not_high_impact": 0, "turn_review_gap": 0},
        "topic": {"reviewed": 0, "topic_decision_gap": 0},
        "synthesis": {"complete": 1, "synthesis_gap": 0},
    }

    coverage = {
        "artifact_type": "coverage",
        "schema_version": 2,
        "run_ref": run_ref,
        "coverage_revision_ref": coverage_revision_ref,
        "predecessor_coverage_revision_ref": coverage_predecessor,
        "supersedes_coverage_revision_refs": [],
        "revision_kind": revision_kind,
        "key_id": key_id,
        "publication_status": status,
        "source_accounting": source_accounting(number * 100 + 1),
        "source_cells": source_cells,
        "dispositions": dispositions,
        "gaps": gaps,
        "confidence": confidence_dimensions(number),
        "policy_era_refs": [policy_era_ref],
        "model_era_refs": [model_era_ref],
    }
    summary = {
        "artifact_type": "summary",
        "schema_version": 2,
        "run_ref": run_ref,
        "summary_revision_ref": summary_revision_ref,
        "predecessor_summary_revision_ref": summary_predecessor,
        "supersedes_summary_revision_refs": [],
        "revision_kind": revision_kind,
        "publication_status": status,
        "what_happened": [detail_template()],
        "worked_well": [],
        "friction_and_confusion": [],
        "errors_and_verification": [],
        "collaboration_patterns": [],
        "safety_and_privacy": [],
        "prompt_improvements": [],
        "agents_guidance": [],
        "skill_candidates": [],
        "follow_ups": [],
        "confidence": confidence_dimensions(number),
        "change_from_prior": {"status": "unavailable", "reason": "no_prior_period"},
        "policy_era_refs": [policy_era_ref],
        "model_era_refs": [model_era_ref],
        "report_render_contract": {
            "template_set": "session-retrospective-report-v2",
            "section_order": [
                "what_happened",
                "worked_well",
                "friction_and_confusion",
                "errors_and_verification",
                "collaboration_patterns",
                "safety_and_privacy",
                "prompt_improvements",
                "agents_guidance",
                "skill_candidates",
                "follow_ups",
                "confidence",
                "change_from_prior",
            ],
            "renderer_byte_equality_required": True,
        },
    }
    trend = {
        "artifact_type": "trend_report",
        "schema_version": 2,
        "run_ref": run_ref,
        "trend_revision_ref": trend_revision_ref,
        "predecessor_trend_revision_ref": trend_predecessor,
        "supersedes_trend_revision_refs": [],
        "revision_kind": revision_kind,
        "publication_status": status,
        "window": run_window,
        "strata": [
            {
                "policy_era_ref": policy_era_ref,
                "model_era_ref": model_era_ref,
                "meaningful_turn_count": 0,
                "meaningful_episode_count": 0,
                "metrics": [
                    {
                        "metric": "failed_command",
                        "status": "unavailable",
                        "reason": "insufficient_cohort",
                    }
                ],
                "confidence": confidence_dimensions(number),
            }
        ],
        "confidence": confidence_dimensions(number),
    }

    payloads = {
        "coverage.json": write_json(directory / "coverage.json", coverage),
        "episodes.jsonl": b"",
        "manifest.json": b"",
        "report.md": report_payload(summary),
        "summary.json": write_json(directory / "summary.json", summary),
        "topics.jsonl": b"",
        "trend_report.json": write_json(directory / "trend_report.json", trend),
        "turn_findings.jsonl": b"",
    }
    for basename in (
        "episodes.jsonl",
        "report.md",
        "topics.jsonl",
        "turn_findings.jsonl",
    ):
        (directory / basename).write_bytes(payloads[basename])

    manifest = {
        "artifact_type": "manifest",
        "schema_version": 2,
        "execution_kind": execution_kind,
        "publication_role": "standalone",
        "mode": mode,
        "window": run_window,
        "run_id": run_id,
        "run_input_ref": hex_ref("run_input_ref_v2:", number),
        "run_ref": run_ref,
        "run_revision_ref": run_revision_ref,
        "key_ids": [key_id],
        "prepared_at": "2026-07-14T00:00:00Z",
        "status": status,
        "gap_summary": gap_summary,
        "supersession": {
            "reason": reason,
            "supersedes_run_revision_refs": predecessor_run_refs,
            "supersedes_episode_revision_refs": [],
            "supersedes_topic_revision_refs": [],
            "supersedes_turn_finding_revision_refs": [],
        },
        "artifact_inventory": INVENTORY,
        "retained_bundle_digest_v2": "retained_bundle_digest_v2:sha256:" + "0" * 64,
        "bundle_digest_contract": {
            "algorithm": "sha-256",
            "domain_tag": DOMAIN_TAG.decode("ascii"),
            "ordering": "bytewise-basename",
            "framing": "typed-name-length-v2",
            "manifest_projection": "omit-retained_bundle_digest_v2-only",
        },
        "head_bindings": {
            "bound_quarantine_generation_ref": hex_ref(
                "quarantine_generation_ref_v2:", number
            ),
            "cursor_heads": [],
            "source_accounting": source_accounting(number * 100 + 1),
            "semantic_repair": head_pair(number * 100 + 3),
            "session_identity": head_pair(number * 100 + 4),
            "turn_screening": head_pair(number * 100 + 5),
            "episode": head_pair(number * 100 + 6),
            "workstream": head_pair(number * 100 + 7),
            "continuation": head_pair(number * 100 + 8),
            "topic": head_pair(number * 100 + 9),
            "run_validity": head_pair(number * 100 + 10),
        },
        "eras": {
            "policy_eras": [
                {
                    "policy_era_ref": policy_era_ref,
                    "predecessor_policy_era_ref": None,
                    "compatibility": "baseline",
                    "versions": {field: 1 for field in POLICY_VERSION_FIELDS},
                }
            ],
            "model_eras": [
                {
                    "model_era_ref": model_era_ref,
                    "predecessor_model_era_ref": None,
                    "compatibility": "baseline",
                    "job_profiles": [
                        {
                            "job_kind": "synthesis",
                            "model_id": "gpt-5.6-sol",
                            "service_tier": "default",
                            "reasoning_effort": "xhigh",
                            "parameter_set_ref": hex_ref(
                                "parameter_set_ref_v2:", number
                            ),
                        }
                    ],
                }
            ],
            "comparison_rule": "stratify-compatible-policy-and-model-eras",
        },
        "provenance": {
            "active_calibration_receipt_ref": hex_ref(
                "receipt_ref_v2:", number * 10 + 6
            ),
            "active_calibration_model_era_ref": model_era_ref,
            "active_shadow_receipt_ref": hex_ref("receipt_ref_v2:", number * 10 + 8),
            "active_shadow_model_era_ref": model_era_ref,
            "engine_repository": "codex-workflow-hygiene",
            "engine_commit": f"{number:040x}",
            "retained_schema_version": 2,
            "execution_schema_version": 2,
            "source_snapshot_refs": [hex_ref("source_snapshot_ref_v2:", number)],
            "identity_backup_receipt_ref": hex_ref("receipt_ref_v2:", number * 10 + 1),
            "job_refs": [hex_ref("job_ref_v2:", number)],
            "provider_policy_refs": [hex_ref("provider_policy_ref_v2:", number)],
            "request_egress_receipt_refs": [
                hex_ref("receipt_ref_v2:", number * 10 + 2)
            ],
            "clock_receipt_ref": hex_ref("receipt_ref_v2:", number * 10 + 3),
            "containment_receipt_refs": [hex_ref("receipt_ref_v2:", number * 10 + 4)],
            "storage_control_receipt_refs": [
                hex_ref("receipt_ref_v2:", number * 10 + 5)
            ],
            "calibration_receipt_refs": [hex_ref("receipt_ref_v2:", number * 10 + 6)],
            "capacity_generation": number,
            "reserved_max_pack_count": 8,
            "reserved_max_pack_bytes": 256 * 1024 * 1024,
            "locked_first_parent_object_id": f"{number + 1:040x}",
            "publication_attempt_ref": hex_ref("publication_attempt_ref_v2:", number),
            "publisher_metadata_policy_version": 1,
            "publisher_signature_policy_version": 1,
            "operational_counts": {field: 0 for field in OPERATIONAL_COUNT_FIELDS},
        },
        "production_configuration_root_v2": "",
        "retention_contract": {
            "retention_safe": True,
            "opaque_references_only": True,
            "raw_identifiers_retained": False,
            "source_specific_prose_retained": False,
            "text_policy": "template-and-typed-slots-v2",
            "renderer_byte_equality_required": True,
        },
    }
    manifest["production_configuration_root_v2"] = production_configuration_root(
        manifest["provenance"]
    )
    manifest["retained_bundle_digest_v2"] = bundle_digest(payloads, manifest)
    (directory / "manifest.json").write_bytes(canonical_json(manifest))
    return BundleRefs(
        directory=directory,
        run_id=run_id,
        run_revision_ref=run_revision_ref,
        coverage_revision_ref=coverage_revision_ref,
        summary_revision_ref=summary_revision_ref,
        trend_revision_ref=trend_revision_ref,
        status=status,
    )


def campaign_window(mode: str) -> dict[str, object]:
    if mode == "daily":
        return dict(WINDOW)
    if mode == "weekly":
        return {
            "mode": "weekly",
            "path_component": "2026-07-07_to_2026-07-13",
            "start": "2026-07-07T00:00:00Z",
            "end": "2026-07-14T00:00:00Z",
        }
    if mode == "session":
        return {
            "mode": "session",
            "path_component": "2026-07-13",
            "start": "2026-07-13T00:00:00Z",
            "end": "2026-07-14T00:00:00Z",
            "target_session_refs": [hex_ref("session_ref_v2:", 1)],
        }
    if mode == "baseline":
        return {
            "mode": "baseline",
            "path_component": "2026-07-01_to_2026-07-13",
            "start": "2026-07-01T00:00:00Z",
            "end": "2026-07-14T00:00:00Z",
        }
    raise ValueError("unsupported campaign mode")


def write_campaign_bundle(
    root: Path,
    number: int,
    *,
    publication_role: str,
    mode: str,
    campaign_number: int = 1,
    segment_count: int = 2,
    segment_ordinal: int | None = None,
    campaign_reason: str | None = None,
) -> BundleRefs:
    refs = write_bundle(root, number, window=campaign_window(mode))
    manifest_path = refs.directory / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    reason = campaign_reason or (
        "baseline_window" if mode == "baseline" else "size_partition"
    )
    manifest.update(
        {
            "publication_role": publication_role,
            "publication_campaign_reason": reason,
            "campaign_ref": hex_ref("campaign_ref_v2:", campaign_number),
            "campaign_segment_count": segment_count,
        }
    )
    quarantine_ref = hex_ref("quarantine_generation_ref_v2:", campaign_number)
    manifest["head_bindings"]["bound_quarantine_generation_ref"] = quarantine_ref
    if publication_role == "campaign_segment":
        if segment_ordinal is None:
            raise ValueError("campaign segment requires an ordinal")
        manifest["campaign_segment_metadata"] = {
            "segment_ordinal": segment_ordinal,
            "leaf_root_refs": [hex_ref("campaign_leaf_root_ref_v2:", number)],
            "page_root_refs": [hex_ref("campaign_page_root_ref_v2:", number)],
        }
        manifest["head_bindings"] = {
            "bound_quarantine_generation_ref": quarantine_ref,
            "cursor_heads": [],
            "source_accounting": None,
            "semantic_repair": None,
            "session_identity": None,
            "turn_screening": None,
            "episode": None,
            "workstream": None,
            "continuation": None,
            "topic": None,
            "run_validity": None,
        }
    elif publication_role == "campaign_root":
        segment_commitments: list[tuple[int, str, str]] = []
        for candidate_path in root.rglob("manifest.json"):
            candidate = json.loads(candidate_path.read_bytes())
            if (
                candidate.get("publication_role") != "campaign_segment"
                or candidate.get("campaign_ref") != manifest["campaign_ref"]
            ):
                continue
            metadata = candidate.get("campaign_segment_metadata")
            if not isinstance(metadata, dict):
                continue
            segment_commitments.append(
                (
                    int(metadata["segment_ordinal"]),
                    str(candidate["run_ref"]),
                    str(candidate["retained_bundle_digest_v2"]),
                )
            )
        manifest["campaign_segment_root_v2"] = campaign_segment_root(
            str(manifest["campaign_ref"]),
            segment_count,
            segment_commitments,
        )
    else:
        raise ValueError("unsupported campaign role")
    manifest_path.write_bytes(canonical_json(manifest))
    rewrite_digest(refs.directory)
    return refs


def episode_row(number: int, run_ref: str, key_id: str) -> dict:
    return {
        "artifact_type": "episode_record",
        "schema_version": 2,
        "run_ref": run_ref,
        "episode_ref": hex_ref("episode_ref_v2:", number),
        "episode_revision_ref": hex_ref("episode_revision_ref_v2:", number),
        "predecessor_episode_revision_ref": None,
        "supersedes_episode_revision_refs": [],
        "revision_kind": "initial",
        "key_id": key_id,
        "host_ref": hex_ref("host_ref_v2:", number),
        "session_ref": hex_ref("session_ref_v2:", number),
        "workstream_ref": hex_ref("workstream_ref_v2:", number),
        "primary_topic_ref": None,
        "continuation_of_episode_ref": None,
        "start_time": None,
        "end_time": None,
        "turn_refs": [hex_ref("turn_ref_v2:", number)],
        "meaningful_turn_count": 0,
        "context_turn_count": 1,
        "review_disposition": "review_not_required",
        "taxonomy": taxonomy_vector(),
        "summary": detail_template(),
        "strengths": [],
        "findings": [],
        "recommendations": [],
        "evidence_refs": [],
        "gap_refs": [],
        "confidence": confidence_dimensions(number),
        "policy_era_ref": hex_ref("policy_era_ref_v2:", 1),
        "model_era_ref": hex_ref("model_era_ref_v2:", 1),
    }


class RetrospectiveHistoryV2Tests(unittest.TestCase):
    def test_valid_complete_bundle_and_reordered_visible_files_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            visible = list(reversed(sorted(refs.directory.iterdir())))
            relative_visible = [path.relative_to(root) for path in visible]

            self.assertEqual(MODULE.validate_v2_runs(root, visible), [])
            self.assertEqual(MODULE.validate_v2_runs(root, relative_visible), [])
            self.assertEqual(MODULE.validate_v2_runs(root), [])

    def test_physical_path_binds_window_route_and_logical_run_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            parts = refs.directory.relative_to(root).parts
            route_end = 2 + MODULE.WINDOW_ROUTE_COMPONENT_COUNT
            run_start = route_end + 1
            manifest = json.loads((refs.directory / "manifest.json").read_bytes())

            self.assertEqual(len(parts), MODULE.RUN_ARTIFACT_PATH_COMPONENT_COUNT - 1)
            self.assertEqual(
                parts[2:route_end],
                window_route_components("daily", str(WINDOW["path_component"])),
            )
            self.assertEqual(parts[route_end], WINDOW["path_component"])
            self.assertEqual("".join(parts[run_start:]), refs.run_id)
            self.assertEqual(manifest["run_id"], refs.run_id)
            self.assertEqual(manifest["run_ref"], f"run_ref_v2:{refs.run_id}")

    def test_old_direct_run_layout_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            old_directory = (
                root / "runs" / "daily" / str(WINDOW["path_component"]) / refs.run_id
            )
            old_directory.parent.mkdir(parents=True, exist_ok=True)
            refs.directory.rename(old_directory)

            issues = MODULE.validate_v2_runs(root)
            self.assertIn("runs/[invalid]: invalid v2 retained-run path", issues)
            self.assertFalse(any("schema target" in issue for issue in issues), issues)

    def test_wrong_window_route_and_malformed_physical_components_are_rejected(
        self,
    ) -> None:
        with self.subTest(case="wrong-window-route"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                refs = write_bundle(root, 1)
                route = list(
                    window_route_components("daily", str(WINDOW["path_component"]))
                )
                route[0] = "00" if route[0] != "00" else "01"
                target = root.joinpath(
                    "runs",
                    "daily",
                    *route,
                    str(WINDOW["path_component"]),
                    *(refs.run_id[offset : offset + 2] for offset in range(0, 64, 2)),
                )
                target.parent.mkdir(parents=True, exist_ok=True)
                refs.directory.rename(target)

                self.assertIn(
                    "runs/[invalid]: invalid v2 retained-run path",
                    MODULE.validate_v2_runs(root),
                )

        with self.subTest(case="non-hex-run-component"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                refs = write_bundle(root, 1)
                run_route = [
                    refs.run_id[offset : offset + 2] for offset in range(0, 64, 2)
                ]
                run_route[0] = "gg"
                target = root.joinpath(
                    "runs",
                    "daily",
                    *window_route_components("daily", str(WINDOW["path_component"])),
                    str(WINDOW["path_component"]),
                    *run_route,
                )
                target.parent.mkdir(parents=True, exist_ok=True)
                refs.directory.rename(target)

                self.assertIn(
                    "runs/[invalid]: invalid v2 retained-run path",
                    MODULE.validate_v2_runs(root),
                )

        with self.subTest(case="extra-depth"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                refs = write_bundle(root, 1)
                target = refs.directory / "00"
                target.mkdir()
                for basename in ARTIFACTS:
                    (refs.directory / basename).rename(target / basename)

                self.assertIn(
                    "runs/[invalid]: invalid v2 retained-run path",
                    MODULE.validate_v2_runs(root),
                )

    def test_manifest_run_identity_binds_path_and_run_ref_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            manifest_path = refs.directory / "manifest.json"
            manifest = json.loads(manifest_path.read_bytes())
            manifest["run_id"] = "f" * 64
            manifest_path.write_bytes(canonical_json(manifest))
            rewrite_digest(refs.directory)

            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any("run_id must match the run path" in issue for issue in issues),
                issues,
            )
            self.assertTrue(
                any("run_ref payload must match run_id" in issue for issue in issues),
                issues,
            )

    def test_window_route_and_logical_run_collisions_fail_closed(self) -> None:
        second_window = {
            "mode": "daily",
            "path_component": "2026-07-12",
            "start": "2026-07-12T00:00:00Z",
            "end": "2026-07-13T00:00:00Z",
        }
        with self.subTest(case="window-route"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                first = write_bundle(root, 1)
                second = write_bundle(root / "staging", 2, window=second_window)
                colliding_route = window_route_components(
                    "daily", str(WINDOW["path_component"])
                )
                target = root.joinpath(
                    "runs",
                    "daily",
                    *colliding_route,
                    str(second_window["path_component"]),
                    *(second.run_id[offset : offset + 2] for offset in range(0, 64, 2)),
                )
                target.parent.mkdir(parents=True, exist_ok=True)
                second.directory.rename(target)

                with (
                    mock.patch.object(
                        MODULE,
                        "_window_route_components",
                        return_value=colliding_route,
                    ),
                    mock.patch.object(
                        MODULE, "_read_fd_bounded", wraps=MODULE._read_fd_bounded
                    ) as read,
                ):
                    issues = MODULE.validate_v2_runs(root)

                self.assertEqual(issues, [MODULE.PATH_COLLISION_ISSUE])
                read.assert_not_called()
                self.assertTrue(first.directory.is_dir())

        with self.subTest(case="logical-run-id"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                write_bundle(root, 1)
                write_bundle(root, 1, window=second_window)

                with mock.patch.object(
                    MODULE, "_read_fd_bounded", wraps=MODULE._read_fd_bounded
                ) as read:
                    issues = MODULE.validate_v2_runs(root)

                self.assertEqual(issues, [MODULE.PATH_COLLISION_ISSUE])
                read.assert_not_called()

    def test_digest_uses_sibling_bytes_and_canonical_manifest_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            coverage_path = refs.directory / "coverage.json"
            original = coverage_path.read_bytes()
            coverage_path.write_bytes(original + b"\n")

            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any(
                    "retained_bundle_digest_v2 does not match" in issue
                    for issue in issues
                )
            )

            coverage_path.write_bytes(original)
            rewrite_digest(refs.directory, pretty_manifest=True)
            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any(
                    "manifest.json: JSON must use exact canonical bytes" in issue
                    for issue in issues
                )
            )

    def test_report_must_exactly_match_deterministic_summary_rendering(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            report_path = refs.directory / "report.md"
            report_path.write_bytes(
                report_path.read_bytes().replace(
                    b"- No observation was retained.\n",
                    b"- No observation was retained.\n- No observation was retained.\n",
                    1,
                )
            )
            rewrite_digest(refs.directory)

            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any(
                    "bytes must exactly match the summary.json rendering" in issue
                    for issue in issues
                ),
                issues,
            )

    def test_json_and_jsonl_require_exact_canonical_bytes(self) -> None:
        with self.subTest(artifact="JSON"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                refs = write_bundle(root, 1)
                coverage_path = refs.directory / "coverage.json"
                coverage_path.write_bytes(coverage_path.read_bytes() + b"\n")
                rewrite_digest(refs.directory)

                issues = MODULE.validate_v2_runs(root)
                self.assertTrue(
                    any(
                        "coverage.json: JSON must use exact canonical bytes" in issue
                        for issue in issues
                    ),
                    issues,
                )

        with self.subTest(artifact="JSONL"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                refs = write_bundle(root, 1)
                manifest = json.loads((refs.directory / "manifest.json").read_bytes())
                row = episode_row(1, manifest["run_ref"], manifest["key_ids"][0])
                pretty = json.dumps(
                    row, ensure_ascii=False, sort_keys=True, separators=(", ", ": ")
                )
                (refs.directory / "episodes.jsonl").write_text(
                    pretty + "\n", encoding="utf-8"
                )
                rewrite_digest(refs.directory)

                issues = MODULE.validate_v2_runs(root)
                self.assertTrue(
                    any(
                        "JSONL row must use exact canonical bytes" in issue
                        for issue in issues
                    ),
                    issues,
                )

    def test_format_checker_rejects_impossible_date_time(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            manifest_path = refs.directory / "manifest.json"
            manifest = json.loads(manifest_path.read_bytes())
            manifest["prepared_at"] = "2026-02-30T00:00:00Z"
            manifest_path.write_bytes(canonical_json(manifest))
            rewrite_digest(refs.directory)

            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any(
                    "schema target manifest failed keyword format" in issue
                    for issue in issues
                ),
                issues,
            )

    def test_window_order_and_path_dates_are_consistent(self) -> None:
        with self.subTest(case="non-increasing"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                refs = write_bundle(root, 1)
                manifest_path = refs.directory / "manifest.json"
                trend_path = refs.directory / "trend_report.json"
                manifest = json.loads(manifest_path.read_bytes())
                trend = json.loads(trend_path.read_bytes())
                manifest["window"]["end"] = manifest["window"]["start"]
                trend["window"] = manifest["window"]
                manifest_path.write_bytes(canonical_json(manifest))
                trend_path.write_bytes(canonical_json(trend))
                rewrite_digest(refs.directory)

                issues = MODULE.validate_v2_runs(root)
                self.assertTrue(
                    any("window.start must be earlier" in issue for issue in issues),
                    issues,
                )

        with self.subTest(case="path-date"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                refs = write_bundle(root, 1)
                manifest_path = refs.directory / "manifest.json"
                trend_path = refs.directory / "trend_report.json"
                manifest = json.loads(manifest_path.read_bytes())
                trend = json.loads(trend_path.read_bytes())
                manifest["window"]["start"] = "2026-07-12T00:00:00Z"
                trend["window"] = manifest["window"]
                manifest_path.write_bytes(canonical_json(manifest))
                trend_path.write_bytes(canonical_json(trend))
                rewrite_digest(refs.directory)

                issues = MODULE.validate_v2_runs(root)
                self.assertTrue(
                    any(
                        "window dates must match the run path" in issue
                        for issue in issues
                    ),
                    issues,
                )

    def test_cross_artifact_coverage_and_trend_cardinalities_are_enforced(self) -> None:
        with self.subTest(case="coverage"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                refs = write_bundle(root, 1)
                coverage_path = refs.directory / "coverage.json"
                coverage = json.loads(coverage_path.read_bytes())
                coverage["source_cells"][0]["disposition"] = "complete"
                coverage["source_cells"][0]["unit_count"] = 1
                coverage_path.write_bytes(canonical_json(coverage))
                rewrite_digest(refs.directory)

                issues = MODULE.validate_v2_runs(root)
                self.assertTrue(
                    any(
                        "source_unit dispositions must total source cell units" in issue
                        for issue in issues
                    ),
                    issues,
                )

        with self.subTest(case="trend"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                refs = write_bundle(root, 1)
                trend_path = refs.directory / "trend_report.json"
                trend = json.loads(trend_path.read_bytes())
                trend["strata"][0]["meaningful_turn_count"] = 1
                trend["strata"][0]["meaningful_episode_count"] = 1
                trend["strata"][0]["metrics"] = [
                    {
                        "metric": "failed_command",
                        "status": "available",
                        "numerator": 1,
                        "denominator": 1,
                        "rate_per_100": 100,
                        "normalized_change": {
                            "status": "unavailable",
                            "reason": "no_prior_period",
                        },
                    }
                ]
                trend_path.write_bytes(canonical_json(trend))
                rewrite_digest(refs.directory)

                issues = MODULE.validate_v2_runs(root)
                self.assertTrue(
                    any(
                        "stratum counts must match episodes.jsonl" in issue
                        for issue in issues
                    )
                )
                self.assertTrue(
                    any(
                        "available metric must match retained turn findings" in issue
                        for issue in issues
                    )
                )

    def test_compliance_retraction_and_extended_head_bindings_are_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            predecessor = write_bundle(root, 1)
            write_bundle(
                root,
                2,
                status="complete_with_terminal_gaps",
                reason="compliance_retraction",
                predecessor=predecessor,
                execution_kind="compliance_retraction",
            )

            self.assertEqual(MODULE.validate_v2_runs(root), [])

    def test_campaign_segments_and_roots_are_complete_bundles_for_every_mode(
        self,
    ) -> None:
        for campaign_number, mode in enumerate(
            ("daily", "weekly", "session", "baseline"),
            start=1,
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                bundles = (
                    write_campaign_bundle(
                        root,
                        1,
                        publication_role="campaign_segment",
                        mode=mode,
                        campaign_number=campaign_number,
                        segment_ordinal=1,
                    ),
                    write_campaign_bundle(
                        root,
                        2,
                        publication_role="campaign_segment",
                        mode=mode,
                        campaign_number=campaign_number,
                        segment_ordinal=2,
                    ),
                    write_campaign_bundle(
                        root,
                        3,
                        publication_role="campaign_root",
                        mode=mode,
                        campaign_number=campaign_number,
                    ),
                )

                for refs in bundles:
                    self.assertEqual(
                        {path.name for path in refs.directory.iterdir()},
                        set(ARTIFACTS),
                    )
                self.assertEqual(MODULE.validate_v2_runs(root), [])

    def test_complete_campaign_segment_can_precede_its_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_campaign_bundle(
                root,
                1,
                publication_role="campaign_segment",
                mode="daily",
                segment_ordinal=1,
            )

            self.assertEqual(MODULE.validate_v2_runs(root), [])

    def test_campaign_root_requires_segments_and_is_unique(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_campaign_bundle(
                root,
                1,
                publication_role="campaign_root",
                mode="daily",
            )

            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any(
                    "root must not exist without campaign segments" in issue
                    for issue in issues
                ),
                issues,
            )

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for ordinal in (1, 2):
                write_campaign_bundle(
                    root,
                    ordinal,
                    publication_role="campaign_segment",
                    mode="daily",
                    segment_ordinal=ordinal,
                )
            write_campaign_bundle(
                root, 3, publication_role="campaign_root", mode="daily"
            )
            write_campaign_bundle(
                root, 4, publication_role="campaign_root", mode="daily"
            )

            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any("at most one campaign root" in issue for issue in issues), issues
            )

    def test_campaign_root_binds_ordered_segment_bundle_digests(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = write_campaign_bundle(
                root,
                1,
                publication_role="campaign_segment",
                mode="daily",
                segment_ordinal=1,
            )
            write_campaign_bundle(
                root,
                2,
                publication_role="campaign_segment",
                mode="daily",
                segment_ordinal=2,
            )
            write_campaign_bundle(
                root, 3, publication_role="campaign_root", mode="daily"
            )
            manifest_path = first.directory / "manifest.json"
            manifest = json.loads(manifest_path.read_bytes())
            manifest["prepared_at"] = "2026-07-14T00:01:00Z"
            manifest_path.write_bytes(canonical_json(manifest))
            rewrite_digest(first.directory)

            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any(
                    "does not bind the ordered segment run refs and bundle digests"
                    in issue
                    for issue in issues
                ),
                issues,
            )

    def test_campaign_reason_matches_mode_and_campaign_coordinates(self) -> None:
        for mode in ("daily", "baseline"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                write_campaign_bundle(
                    root,
                    1,
                    publication_role="campaign_segment",
                    mode=mode,
                    segment_ordinal=1,
                )
                write_campaign_bundle(
                    root,
                    2,
                    publication_role="campaign_segment",
                    mode=mode,
                    segment_ordinal=2,
                )
                root_bundle = write_campaign_bundle(
                    root,
                    3,
                    publication_role="campaign_root",
                    mode=mode,
                )
                manifest_path = root_bundle.directory / "manifest.json"
                manifest = json.loads(manifest_path.read_bytes())
                manifest["publication_campaign_reason"] = (
                    "size_partition" if mode == "baseline" else "baseline_window"
                )
                manifest_path.write_bytes(canonical_json(manifest))
                rewrite_digest(root_bundle.directory)

                issues = MODULE.validate_v2_runs(root)
                self.assertTrue(
                    any(
                        "publication campaign reason does not match mode" in issue
                        for issue in issues
                    ),
                    issues,
                )
                self.assertTrue(
                    any(
                        "must share mode, window, and campaign reason" in issue
                        for issue in issues
                    ),
                    issues,
                )

    def test_standalone_rejects_every_campaign_only_field(self) -> None:
        campaign_fields = {
            "publication_campaign_reason": "size_partition",
            "campaign_ref": hex_ref("campaign_ref_v2:", 1),
            "campaign_segment_count": 1,
            "campaign_segment_metadata": {
                "segment_ordinal": 1,
                "leaf_root_refs": [hex_ref("campaign_leaf_root_ref_v2:", 1)],
                "page_root_refs": [hex_ref("campaign_page_root_ref_v2:", 1)],
            },
            "campaign_segment_root_v2": "campaign_segment_root_v2:sha256:" + "a" * 64,
        }
        for field, value in campaign_fields.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                refs = write_bundle(root, 1)
                manifest_path = refs.directory / "manifest.json"
                manifest = json.loads(manifest_path.read_bytes())
                manifest[field] = value
                manifest_path.write_bytes(canonical_json(manifest))
                rewrite_digest(refs.directory)

                issues = MODULE.validate_v2_runs(root)
                self.assertTrue(
                    any(
                        "standalone publication must not contain campaign fields"
                        in issue
                        for issue in issues
                    ),
                    issues,
                )

    def test_campaign_bundle_missing_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            segment = write_campaign_bundle(
                root,
                1,
                publication_role="campaign_segment",
                mode="daily",
                segment_ordinal=1,
            )
            write_campaign_bundle(
                root,
                2,
                publication_role="campaign_segment",
                mode="daily",
                segment_ordinal=2,
            )
            write_campaign_bundle(
                root,
                3,
                publication_role="campaign_root",
                mode="daily",
            )
            (segment.directory / "topics.jsonl").unlink()

            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any(
                    "must contain exactly the eight required artifacts" in issue
                    for issue in issues
                ),
                issues,
            )

    def test_campaign_bundle_artifact_input_uses_existing_byte_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            segment = write_campaign_bundle(
                root,
                1,
                publication_role="campaign_segment",
                mode="daily",
                segment_ordinal=1,
            )
            summary_path = segment.directory / "summary.json"
            with summary_path.open("wb") as stream:
                stream.truncate(MODULE.MAX_ARTIFACT_BYTES["summary.json"] + 1)

            with mock.patch.object(
                MODULE,
                "_read_fd_bounded",
                wraps=MODULE._read_fd_bounded,
            ) as read:
                issues = MODULE.validate_v2_runs(
                    root,
                    sorted(segment.directory.iterdir()),
                )

            read.assert_not_called()
            self.assertTrue(
                any(
                    "summary.json: artifact exceeds its byte limit" in issue
                    for issue in issues
                ),
                issues,
            )

    def test_campaign_segment_ordinal_is_bounded_by_campaign_count(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            baseline_window = {
                "mode": "baseline",
                "path_component": "2026-07-01_to_2026-07-13",
                "start": "2026-07-01T00:00:00Z",
                "end": "2026-07-14T00:00:00Z",
            }
            refs = write_bundle(root, 1, window=baseline_window)
            directory = refs.directory
            manifest_path = directory / "manifest.json"
            manifest = json.loads(manifest_path.read_bytes())
            quarantine_ref = manifest["head_bindings"][
                "bound_quarantine_generation_ref"
            ]
            manifest.update(
                {
                    "publication_role": "campaign_segment",
                    "publication_campaign_reason": "baseline_window",
                    "campaign_ref": hex_ref("campaign_ref_v2:", 1),
                    "campaign_segment_count": 1,
                    "campaign_segment_metadata": {
                        "segment_ordinal": 2,
                        "leaf_root_refs": [hex_ref("campaign_leaf_root_ref_v2:", 1)],
                        "page_root_refs": [hex_ref("campaign_page_root_ref_v2:", 1)],
                    },
                    "head_bindings": {
                        "bound_quarantine_generation_ref": quarantine_ref,
                        "cursor_heads": [],
                        "source_accounting": None,
                        "semantic_repair": None,
                        "session_identity": None,
                        "turn_screening": None,
                        "episode": None,
                        "workstream": None,
                        "continuation": None,
                        "topic": None,
                        "run_validity": None,
                    },
                }
            )
            manifest_path.write_bytes(canonical_json(manifest))
            rewrite_digest(directory)

            issues = MODULE.validate_v2_runs(root)
            self.assertFalse(
                any("schema target manifest" in issue for issue in issues), issues
            )
            self.assertTrue(
                any("campaign segment ordinal exceeds" in issue for issue in issues),
                issues,
            )

    def test_duplicate_keys_are_rejected_without_echoing_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            manifest_path = refs.directory / "manifest.json"
            text = manifest_path.read_text(encoding="utf-8")
            text = text.replace(
                '"mode":"daily"', '"mode":"daily","mode":"private-customer-value"', 1
            )
            manifest_path.write_text(text, encoding="utf-8")

            issues = MODULE.validate_v2_runs(root)
            rendered = "\n".join(issues)
            self.assertIn("duplicate JSON key is not allowed", rendered)
            self.assertNotIn("private-customer-value", rendered)
            self.assertNotIn(str(root), rendered)

    def test_duplicate_jsonl_keys_are_rejected_with_only_line_number(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            manifest = json.loads(
                (refs.directory / "manifest.json").read_text(encoding="utf-8")
            )
            run_ref = manifest["run_ref"]
            key_id = manifest["key_ids"][0]
            row = episode_row(1, run_ref, key_id)
            raw = canonical_json(row).decode("utf-8")
            raw = raw.replace(
                '"artifact_type":"episode_record"',
                '"artifact_type":"episode_record","artifact_type":"private-value"',
            )
            (refs.directory / "episodes.jsonl").write_text(raw + "\n", encoding="utf-8")
            rewrite_digest(refs.directory)

            issues = MODULE.validate_v2_runs(root)
            rendered = "\n".join(issues)
            self.assertIn(
                "episodes.jsonl:1: duplicate JSON key is not allowed", rendered
            )
            self.assertNotIn("private-value", rendered)

    def test_parser_resource_failures_use_fixed_safe_diagnostics(self) -> None:
        cases = {
            "integer-limit": b'{"number":' + b"9" * 5000 + b"}",
            "depth-limit": b"[" * (MODULE.MAX_JSON_DEPTH + 1)
            + b"0"
            + b"]" * (MODULE.MAX_JSON_DEPTH + 1),
        }
        for name, raw in cases.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    refs = write_bundle(root, 1)
                    (refs.directory / "summary.json").write_bytes(raw)
                    rewrite_digest(refs.directory)

                    issues = MODULE.validate_v2_runs(root)
                    self.assertTrue(
                        any(MODULE.JSON_RESOURCE_ISSUE in issue for issue in issues),
                        issues,
                    )
                    self.assertNotIn("9" * 64, "\n".join(issues))

        with self.subTest(name="recursion"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                refs = write_bundle(root, 1)
                summary_raw = (refs.directory / "summary.json").read_bytes()
                original_parse = MODULE._parse_json_bytes

                def recursive_parse(raw: bytes) -> object:
                    if raw == summary_raw:
                        raise RecursionError
                    return original_parse(raw)

                with mock.patch.object(
                    MODULE, "_parse_json_bytes", side_effect=recursive_parse
                ):
                    issues = MODULE.validate_v2_runs(root)

                self.assertTrue(
                    any(MODULE.JSON_RESOURCE_ISSUE in issue for issue in issues), issues
                )

    def test_namespace_and_exact_inventory_errors_are_privacy_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            (refs.directory / "private-customer-artifact.txt").write_text(
                "private", encoding="utf-8"
            )
            invalid = (
                root
                / "runs"
                / "private-customer-mode"
                / "private-window"
                / "private-run"
                / "manifest.json"
            )
            invalid.parent.mkdir(parents=True)
            invalid.write_text("{}", encoding="utf-8")

            issues = MODULE.validate_v2_runs(root)
            rendered = "\n".join(issues)
            self.assertIn("exactly the eight required artifacts", rendered)
            self.assertIn("runs/[invalid]", rendered)
            self.assertNotIn("private-customer", rendered)

    def test_manifest_and_bundle_identity_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            coverage_path = refs.directory / "coverage.json"
            coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
            coverage["run_ref"] = hex_ref("run_ref_v2:", 999)
            coverage_path.write_bytes(canonical_json(coverage))
            rewrite_digest(refs.directory)

            forward = MODULE.validate_v2_runs(root, sorted(refs.directory.iterdir()))
            reverse = MODULE.validate_v2_runs(
                root, list(reversed(sorted(refs.directory.iterdir())))
            )
            self.assertEqual(forward, reverse)
            self.assertEqual(forward, sorted(set(forward)))
            self.assertTrue(
                any("run_ref must match manifest.json" in issue for issue in forward),
                forward,
            )

    def test_partial_to_full_backfill_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            partial = write_bundle(root, 1, status="partial")
            write_bundle(
                root, 2, status="complete", reason="backfill", predecessor=partial
            )

            self.assertEqual(MODULE.validate_v2_runs(root), [])

    def test_closed_predecessor_cannot_be_superseded_by_two_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            partial = write_bundle(root, 1, status="partial")
            write_bundle(
                root, 2, status="complete", reason="backfill", predecessor=partial
            )
            write_bundle(
                root, 3, status="complete", reason="correction", predecessor=partial
            )

            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any("already closed by another run" in issue for issue in issues)
            )

    def test_backfill_requires_partial_predecessor(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            complete = write_bundle(root, 1)
            write_bundle(
                root, 2, status="complete", reason="backfill", predecessor=complete
            )

            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any("backfill predecessor must be partial" in issue for issue in issues)
            )

    def test_jsonl_records_require_stable_unique_order(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            manifest = json.loads(
                (refs.directory / "manifest.json").read_text(encoding="utf-8")
            )
            rows = [
                episode_row(2, manifest["run_ref"], manifest["key_ids"][0]),
                episode_row(1, manifest["run_ref"], manifest["key_ids"][0]),
            ]
            raw = b"".join(canonical_json(row) + b"\n" for row in rows)
            (refs.directory / "episodes.jsonl").write_bytes(raw)
            rewrite_digest(refs.directory)

            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any(
                    "stable bytewise entity/revision order" in issue for issue in issues
                )
            )

    def test_manifest_era_catalog_requires_stable_unique_order(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            manifest_path = refs.directory / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            first = manifest["eras"]["policy_eras"][0]
            second = {"policy_era_ref": hex_ref("policy_era_ref_v2:", 2)}
            manifest["eras"]["policy_eras"] = [second, first]
            manifest_path.write_bytes(canonical_json(manifest))
            rewrite_digest(refs.directory)

            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any(
                    "policy_eras must use bytewise-sorted unique references" in issue
                    for issue in issues
                )
            )

    def test_source_cells_require_unique_identity_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            coverage_path = refs.directory / "coverage.json"
            coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
            cell_ref = hex_ref("source_cell_ref_v2:", 1)
            coverage["source_cells"] = [
                {"cell_ref": cell_ref, "record_count": 1},
                {"cell_ref": cell_ref, "record_count": 2},
            ]
            coverage_path.write_bytes(canonical_json(coverage))
            rewrite_digest(refs.directory)

            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any(
                    "source_cells must contain unique reference keys" in issue
                    for issue in issues
                )
            )

    def test_missing_predecessor_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            summary_path = refs.directory / "summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary["revision_kind"] = "correction"
            summary["predecessor_summary_revision_ref"] = hex_ref(
                "summary_revision_ref_v2:", 999
            )
            summary_path.write_bytes(canonical_json(summary))
            rewrite_digest(refs.directory)

            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any("predecessor revision is not present" in issue for issue in issues)
            )

    def test_schema_rejects_missing_required_field(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            summary_path = refs.directory / "summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary.pop("confidence")
            summary_path.write_bytes(canonical_json(summary))
            rewrite_digest(refs.directory)

            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any(
                    "schema target summary failed keyword required" in issue
                    for issue in issues
                ),
                issues,
            )

    def test_schema_rejects_extra_properties_without_echoing_them(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            summary_path = refs.directory / "summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            unknown_field = "private_customer_field"
            unknown_value = "private-customer-value"
            summary[unknown_field] = unknown_value
            summary_path.write_bytes(canonical_json(summary))
            rewrite_digest(refs.directory)

            issues = MODULE.validate_v2_runs(root)
            rendered = "\n".join(issues)
            self.assertIn(
                "schema target summary failed keyword additionalProperties", rendered
            )
            self.assertNotIn(unknown_field, rendered)
            self.assertNotIn(unknown_value, rendered)
            self.assertNotIn(str(root), rendered)

    def test_schema_rejects_wrong_scalar_type(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            manifest_path = refs.directory / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["prepared_at"] = 7
            manifest_path.write_bytes(canonical_json(manifest))
            rewrite_digest(refs.directory)

            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any(
                    "schema target manifest failed keyword type" in issue
                    for issue in issues
                ),
                issues,
            )

    def test_schema_dependency_failure_is_fail_closed(self) -> None:
        for dependency in ("_Draft202012Validator", "_FormatChecker"):
            with self.subTest(dependency=dependency):
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    write_bundle(root, 1)
                    MODULE._load_schema_validators.cache_clear()
                    try:
                        with mock.patch.object(MODULE, dependency, None):
                            self.assertEqual(
                                MODULE.validate_v2_runs(root),
                                [MODULE.SCHEMA_UNAVAILABLE_ISSUE],
                            )
                    finally:
                        MODULE._load_schema_validators.cache_clear()

    def test_missing_schema_file_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_bundle(root, 1)
            MODULE._load_schema_validators.cache_clear()
            try:
                with mock.patch.object(
                    MODULE, "SESSION_SCHEMA_PATH", root / "missing-schema.json"
                ):
                    self.assertEqual(
                        MODULE.validate_v2_runs(root),
                        [MODULE.SCHEMA_UNAVAILABLE_ISSUE],
                    )
            finally:
                MODULE._load_schema_validators.cache_clear()

    def test_oversized_artifact_fails_before_any_artifact_read(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            summary_path = refs.directory / "summary.json"
            with summary_path.open("wb") as stream:
                stream.truncate(MODULE.MAX_ARTIFACT_BYTES["summary.json"] + 1)

            self.assertIsNotNone(MODULE._load_schema_validators())
            self.assertIsNotNone(MODULE._load_privacy_validator())
            with mock.patch.object(
                MODULE,
                "_read_fd_bounded",
                wraps=MODULE._read_fd_bounded,
            ) as bounded_read:
                issues = MODULE.validate_v2_runs(root)

            bounded_read.assert_not_called()
            self.assertTrue(
                any(
                    "summary.json: artifact exceeds its byte limit" in issue
                    for issue in issues
                ),
                issues,
            )

    def test_total_byte_limit_fails_before_any_artifact_read(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            total_bytes = sum(path.stat().st_size for path in refs.directory.iterdir())

            self.assertIsNotNone(MODULE._load_schema_validators())
            self.assertIsNotNone(MODULE._load_privacy_validator())
            with (
                mock.patch.object(MODULE, "MAX_BUNDLE_ARTIFACT_BYTES", total_bytes - 1),
                mock.patch.object(
                    MODULE,
                    "_read_fd_bounded",
                    wraps=MODULE._read_fd_bounded,
                ) as bounded_read,
            ):
                issues = MODULE.validate_v2_runs(root)

            bounded_read.assert_not_called()
            self.assertTrue(
                any(
                    "retained bundle exceeds the total byte limit" in issue
                    for issue in issues
                )
            )

    def test_total_byte_budget_is_reset_for_each_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = write_bundle(root, 1)
            second = write_bundle(root, 2)
            per_bundle_limit = max(
                sum(path.stat().st_size for path in refs.directory.iterdir())
                for refs in (first, second)
            )

            with mock.patch.object(
                MODULE, "MAX_BUNDLE_ARTIFACT_BYTES", per_bundle_limit
            ):
                self.assertEqual(MODULE.validate_v2_runs(root), [])

    def test_discovery_file_and_bundle_work_is_bounded(self) -> None:
        with self.subTest(limit="entries"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                write_bundle(root, 1)
                with mock.patch.object(MODULE, "MAX_DISCOVERY_ENTRIES", 3):
                    issues = MODULE.validate_v2_runs(root)
                self.assertIn(MODULE.DISCOVERY_LIMIT_ISSUE, issues)

        with self.subTest(limit="files"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                write_bundle(root, 1)
                with (
                    mock.patch.object(MODULE, "MAX_DISCOVERY_FILES", 7),
                    mock.patch.object(
                        MODULE,
                        "_read_fd_bounded",
                        wraps=MODULE._read_fd_bounded,
                    ) as read,
                ):
                    issues = MODULE.validate_v2_runs(root)
                self.assertIn(MODULE.DISCOVERY_LIMIT_ISSUE, issues)
                read.assert_not_called()

        with self.subTest(limit="bundles"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                write_bundle(root, 1)
                write_bundle(root, 2)
                with mock.patch.object(MODULE, "MAX_BUNDLES", 1):
                    issues = MODULE.validate_v2_runs(root)
                self.assertIn(MODULE.DISCOVERY_LIMIT_ISSUE, issues)

    def test_diagnostic_count_is_strictly_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            (refs.directory / "episodes.jsonl").write_bytes(b"{}\n" * 100)
            rewrite_digest(refs.directory)

            with mock.patch.object(
                MODULE,
                "_parse_json_bytes",
                wraps=MODULE._parse_json_bytes,
            ) as parse_json:
                issues = MODULE.validate_v2_runs(root)
            self.assertEqual(len(issues), MODULE.MAX_DIAGNOSTICS)
            self.assertEqual(issues.count(MODULE.DIAGNOSTIC_LIMIT_ISSUE), 1)
            self.assertEqual(issues, sorted(set(issues)))
            self.assertLess(parse_json.call_count, 100)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "O_NOFOLLOW is unavailable")
    def test_symlink_artifact_is_rejected_without_following_it(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            summary_path = refs.directory / "summary.json"
            target = root / "outside-summary.json"
            target.write_bytes(summary_path.read_bytes())
            summary_path.unlink()
            summary_path.symlink_to(target)

            issues = MODULE.validate_v2_runs(root)
            rendered = "\n".join(issues)
            self.assertIn("summary.json: symlink artifact is not allowed", rendered)
            self.assertNotIn(str(root), rendered)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "O_NOFOLLOW is unavailable")
    def test_intermediate_directory_symlink_is_never_followed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "root"
            outside = base / "outside"
            root.mkdir()
            refs = write_bundle(outside, 1)
            (root / "runs").mkdir()
            (root / "runs" / "daily").symlink_to(
                outside / "runs" / "daily",
                target_is_directory=True,
            )
            relative_directory = refs.directory.relative_to(outside)
            visible = [root / relative_directory / basename for basename in ARTIFACTS]

            issues = MODULE.validate_v2_runs(root, visible)
            rendered = "\n".join(issues)
            self.assertIn("run directory could not be opened safely", rendered)
            self.assertNotIn(str(outside), rendered)

            discovered_issues = MODULE.validate_v2_runs(root)
            discovered = "\n".join(discovered_issues)
            self.assertIn("runs/[invalid]: invalid v2 retained-run path", discovered)
            self.assertNotIn(str(outside), discovered)

    def test_artifact_changed_during_read_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            summary_path = refs.directory / "summary.json"
            summary_inode = summary_path.stat().st_ino
            original_read = MODULE._read_fd_bounded
            changed = False

            def racing_read(descriptor: int, byte_limit: int) -> bytes:
                nonlocal changed
                if not changed and os.fstat(descriptor).st_ino == summary_inode:
                    with summary_path.open("ab") as stream:
                        stream.write(b" ")
                    changed = True
                return original_read(descriptor, byte_limit)

            self.assertIsNotNone(MODULE._load_schema_validators())
            self.assertIsNotNone(MODULE._load_privacy_validator())
            with mock.patch.object(MODULE, "_read_fd_bounded", side_effect=racing_read):
                issues = MODULE.validate_v2_runs(root)

            self.assertTrue(changed)
            self.assertTrue(
                any(
                    "summary.json: artifact changed while being read" in issue
                    for issue in issues
                ),
                issues,
            )

    def test_schema_valid_adversarial_prose_is_privacy_scanned_from_raw_bytes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            summary_path = refs.directory / "summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            private_text = "The project was Phoenix."
            summary["what_happened"] = [rendered_template(private_text)]
            summary_path.write_bytes(canonical_json(summary))
            rewrite_digest(refs.directory)

            issues = MODULE.validate_v2_runs(root)
            rendered = "\n".join(issues)
            safe_prefix = f"{refs.directory.relative_to(root).as_posix()}/summary.json:"
            self.assertIn(
                f"{safe_prefix} content: prose is outside the retained template vocabulary",
                rendered,
            )
            self.assertNotIn("schema target summary", rendered)
            self.assertNotIn(private_text, rendered)
            self.assertNotIn(str(root), rendered)

    def test_report_templates_are_recomputed_from_id_and_slots(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            summary_path = refs.directory / "summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary["what_happened"] = [rendered_template("The task was retained.")]
            summary_path.write_bytes(canonical_json(summary))
            (refs.directory / "report.md").write_bytes(report_payload(summary))
            rewrite_digest(refs.directory)

            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any("report renderer input is invalid" in issue for issue in issues),
                issues,
            )

    def test_production_configuration_root_binds_active_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            manifest_path = refs.directory / "manifest.json"
            manifest = json.loads(manifest_path.read_bytes())
            manifest["provenance"]["active_shadow_receipt_ref"] = hex_ref(
                "receipt_ref_v2:", 999
            )
            manifest_path.write_bytes(canonical_json(manifest))
            rewrite_digest(refs.directory)

            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any(
                    "does not bind the active provenance references" in issue
                    for issue in issues
                ),
                issues,
            )


if __name__ == "__main__":
    unittest.main()
