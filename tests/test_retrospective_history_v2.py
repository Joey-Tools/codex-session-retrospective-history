from __future__ import annotations

import base64
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
HISTORY_KEY_ID = "key_id_v2:" + "0" * 15 + "1"
FAKE_PUBLISHER_SIGNATURE = (
    "-----BEGIN PGP SIGNATURE-----\n\n"
    "wjQEAAEIAB0FAgAAAAEWIQRA+l0FrHo9XBgLA3/23Pegb/ycUgAKCRD23Pegb/yc\n"
    "UgAAAAEB\n"
    "=pLXK\n"
    "-----END PGP SIGNATURE-----"
)
WINDOW = {
    "mode": "daily",
    "path_component": "2026-07-13",
    "start": "2026-07-13T00:00:00Z",
    "end": "2026-07-14T00:00:00Z",
}
PRIOR_DAILY_WINDOW = {
    "mode": "daily",
    "path_component": "2026-07-12",
    "start": "2026-07-12T00:00:00Z",
    "end": "2026-07-13T00:00:00Z",
}
FUTURE_DAILY_WINDOW = {
    "mode": "daily",
    "path_component": "2026-07-14",
    "start": "2026-07-14T00:00:00Z",
    "end": "2026-07-15T00:00:00Z",
}
PRIOR_WEEKLY_WINDOW = {
    "mode": "weekly",
    "path_component": "2026-07-06_to_2026-07-12",
    "start": "2026-07-06T00:00:00Z",
    "end": "2026-07-13T00:00:00Z",
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


def canonical_run_id(value: int) -> str:
    encoded = base64.b32encode(value.to_bytes(16, "big"))
    return encoded.decode("ascii").lower().rstrip("=")


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


def physical_bundle_directory(root: Path, mode: str, window: str, run_id: str) -> Path:
    return root.joinpath("runs", mode, window, run_id)


def legacy_radix_bundle_directory(
    root: Path, mode: str, window: str, run_id: str
) -> Path:
    hasher = hashlib.sha256()
    hasher.update(b"session-retrospective-retained-window-route-v2")
    update_frame(hasher, b"M", mode.encode("ascii"))
    update_frame(hasher, b"W", window.encode("ascii"))
    route = hasher.hexdigest()
    return root.joinpath(
        "runs",
        mode,
        *(route[offset : offset + 2] for offset in range(0, 64, 2)),
        window,
        *(run_id[offset : offset + 2] for offset in range(0, len(run_id), 2)),
    )


def bundle_digest(payloads: dict[str, bytes], manifest: dict) -> str:
    projection = dict(manifest)
    projection.pop("retained_bundle_digest_v2")
    projection.pop("publisher_attestation")
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


def remove_model_execution_provenance(refs: BundleRefs) -> None:
    manifest_path = refs.directory / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["eras"]["model_eras"] = []
    for field_name in (
        "job_refs",
        "provider_policy_refs",
        "request_egress_receipt_refs",
        "calibration_receipt_refs",
    ):
        manifest["provenance"][field_name] = []
    manifest["production_configuration_root_v2"] = production_configuration_root(
        manifest["provenance"]
    )
    manifest_path.write_bytes(canonical_json(manifest))
    rewrite_digest(refs.directory)


def set_trend_metric(
    refs: BundleRefs,
    *,
    rate: int | float,
    metric_ref: str,
    normalized_change: dict[str, object],
) -> None:
    trend_path = refs.directory / "trend_report.json"
    trend = json.loads(trend_path.read_bytes())
    trend["strata"][0]["metrics"] = [
        {
            "metric": "failed_command",
            "metric_ref": metric_ref,
            "status": "available",
            "numerator": 0,
            "denominator": 1,
            "rate_per_100": rate,
            "normalized_change": normalized_change,
        }
    ]
    trend_path.write_bytes(canonical_json(trend))
    rewrite_digest(refs.directory)


def set_summary_change(refs: BundleRefs, change: dict[str, object]) -> None:
    summary_path = refs.directory / "summary.json"
    summary = json.loads(summary_path.read_bytes())
    summary["change_from_prior"] = change
    summary_path.write_bytes(canonical_json(summary))
    (refs.directory / "report.md").write_bytes(report_payload(summary))
    rewrite_digest(refs.directory)


def set_prepared_at(refs: BundleRefs, prepared_at: str) -> None:
    manifest_path = refs.directory / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["prepared_at"] = prepared_at
    manifest_path.write_bytes(canonical_json(manifest))
    rewrite_digest(refs.directory)


def write_bundle(
    root: Path,
    number: int,
    *,
    status: str = "complete",
    reason: str = "initial",
    predecessor: BundleRefs | None = None,
    execution_kind: str = "retrospective",
    window: dict[str, object] | None = None,
    key_id: str = HISTORY_KEY_ID,
) -> BundleRefs:
    run_window = dict(WINDOW if window is None else window)
    mode = str(run_window["mode"])
    window_component = str(run_window["path_component"])
    run_id = canonical_run_id(number)
    directory = physical_bundle_directory(root, mode, window_component, run_id)
    directory.mkdir(parents=True)

    run_ref = f"run_ref_v2:{run_id}"
    run_revision_ref = hex_ref("run_revision_ref_v2:", number)
    coverage_revision_ref = hex_ref("coverage_revision_ref_v2:", number)
    summary_revision_ref = hex_ref("summary_revision_ref_v2:", number)
    trend_revision_ref = hex_ref("trend_revision_ref_v2:", number)
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
        "key_id": key_id,
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
        "publisher_attestation": {
            "scheme": "openpgp-detached-v1",
            "signer_fingerprint": "40FA5D05AC7A3D5C180B037FF6DCF7A06FFC9C52",
            "signature": FAKE_PUBLISHER_SIGNATURE,
        },
        "bundle_digest_contract": {
            "algorithm": "sha-256",
            "domain_tag": DOMAIN_TAG.decode("ascii"),
            "ordering": "bytewise-basename",
            "framing": "typed-name-length-v2",
            "manifest_projection": "omit-digest-and-publisher-attestation-v2",
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
    turn_refs = [hex_ref("turn_ref_v2:", number)]
    row = {
        "artifact_type": "episode_record",
        "schema_version": 2,
        "run_ref": run_ref,
        "episode_ref": hex_ref("episode_ref_v2:", number),
        "episode_revision_ref": hex_ref("episode_revision_ref_v2:", number),
        "episode_revision_operation": "create",
        "episode_lineage_id": hex_ref("episode_lineage_id_v2:", number),
        "episode_anchor": hex_ref("episode_anchor_v2:", number),
        "segmentation_major": 1,
        "episode_policy_major": 1,
        "member_turn_root": MODULE._episode_member_turn_root(turn_refs),
        "member_turn_count": len(turn_refs),
        "presentation_ranges": [{"turn_refs": turn_refs}],
        "transition_group_id": None,
        "transition_group_ordinal": None,
        "generalized_content_digest": "",
        "predecessor_lineage_metadata": [],
        "backfill_membership_evidence": [],
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
        "turn_refs": turn_refs,
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
    row["generalized_content_digest"] = (
        MODULE._episode_generalized_content_digest(row)
    )
    return row


def episode_predecessor_metadata(row: dict[str, object]) -> dict[str, object]:
    return {
        "episode_revision_ref": row["episode_revision_ref"],
        "episode_lineage_id": row["episode_lineage_id"],
        "episode_anchor": row["episode_anchor"],
        "segmentation_major": row["segmentation_major"],
        "episode_policy_major": row["episode_policy_major"],
        "member_turn_root": row["member_turn_root"],
        "member_turn_count": row["member_turn_count"],
    }


def set_episode_members(
    row: dict[str, object], presentation_turn_refs: list[str]
) -> None:
    row["turn_refs"] = sorted(presentation_turn_refs)
    row["member_turn_count"] = len(presentation_turn_refs)
    row["member_turn_root"] = MODULE._episode_member_turn_root(
        presentation_turn_refs
    )
    row["presentation_ranges"] = [{"turn_refs": presentation_turn_refs}]
    row["generalized_content_digest"] = (
        MODULE._episode_generalized_content_digest(row)
    )


def transition_episode_row(
    number: int,
    operation: str,
    predecessors: list[dict[str, object]],
    presentation_turn_refs: list[str],
    *,
    transition_group_id: str | None = None,
    transition_group_ordinal: int | None = None,
    episode_anchor: str | None = None,
    episode_lineage_id: str | None = None,
    backfill_membership_evidence: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    if not predecessors:
        raise ValueError("transition predecessor is required")
    row = json.loads(json.dumps(predecessors[0]))
    row["run_ref"] = f"run_ref_v2:{canonical_run_id(number)}"
    row["episode_revision_ref"] = hex_ref("episode_revision_ref_v2:", number)
    row["episode_revision_operation"] = operation
    row["revision_kind"] = MODULE.EPISODE_OPERATION_REVISION_KINDS[operation]
    set_episode_members(row, presentation_turn_refs)
    row["transition_group_id"] = transition_group_id
    row["transition_group_ordinal"] = transition_group_ordinal
    row["predecessor_lineage_metadata"] = [
        episode_predecessor_metadata(predecessor) for predecessor in predecessors
    ]
    row["backfill_membership_evidence"] = (
        []
        if backfill_membership_evidence is None
        else backfill_membership_evidence
    )
    if operation == "merge":
        row["predecessor_episode_revision_ref"] = None
        row["supersedes_episode_revision_refs"] = sorted(
            str(predecessor["episode_revision_ref"])
            for predecessor in predecessors
        )
        row["episode_ref"] = hex_ref("episode_ref_v2:", number)
    else:
        row["predecessor_episode_revision_ref"] = predecessors[0][
            "episode_revision_ref"
        ]
        row["supersedes_episode_revision_refs"] = []
        if operation == "split":
            row["episode_ref"] = hex_ref("episode_ref_v2:", number)
    if episode_anchor is not None:
        row["episode_anchor"] = episode_anchor
    if episode_lineage_id is not None:
        row["episode_lineage_id"] = episode_lineage_id
    row["generalized_content_digest"] = MODULE._episode_generalized_content_digest(row)
    return row


def record_episode_bundle(
    index: object,
    bundle_id: int,
    rows: dict[str, object] | list[dict[str, object]],
) -> None:
    run_id = canonical_run_id(bundle_id)
    index.connection.execute(
        """
        INSERT INTO discovered_bundles(id, mode, window_component, run_id)
        VALUES (?, ?, ?, ?)
        """,
        (bundle_id, "daily", "2026-07-13", run_id),
    )
    bundle = MODULE.Bundle(
        label=f"runs/daily/2026-07-13/{run_id}",
        mode="daily",
        window_component="2026-07-13",
        run_id=run_id,
        files={},
        manifest={
            "run_ref": f"run_ref_v2:{run_id}",
            "run_revision_ref": hex_ref("run_revision_ref_v2:", bundle_id),
            "key_id": HISTORY_KEY_ID,
        },
    )
    for line_number, row in enumerate(
        [rows] if isinstance(rows, dict) else rows, start=1
    ):
        parse_issues: list[str] = []
        node = MODULE._validate_revision_record(
            row,
            MODULE.REVISION_SPECS["episodes.jsonl"],
            bundle,
            f"{bundle.label}/episodes.jsonl:{line_number}",
            parse_issues,
        )
        if parse_issues or node is None:
            raise AssertionError(parse_issues)
        bundle.revisions.append(node)
    index.record_bundle(bundle_id, bundle)


class RetrospectiveHistoryV2Tests(unittest.TestCase):
    def test_episode_record_schema_requires_canonical_transition_identity(self) -> None:
        row = episode_row(
            1, f"run_ref_v2:{canonical_run_id(1)}", HISTORY_KEY_ID
        )
        validators = MODULE._load_schema_validators()
        self.assertIsNotNone(validators)
        assert validators is not None
        self.assertEqual(list(validators["episode_record"].iter_errors(row)), [])

        missing_operation = dict(row)
        missing_operation.pop("episode_revision_operation")
        self.assertTrue(
            list(validators["episode_record"].iter_errors(missing_operation))
        )

    def test_episode_extend_backfill_split_and_merge_transitions_are_valid(self) -> None:
        turns = [hex_ref("turn_ref_v2:", number) for number in range(1, 7)]
        with tempfile.TemporaryDirectory() as temp:
            index = MODULE._ValidationIndex(Path(temp) / "history.sqlite3")
            try:
                create = episode_row(
                    10, f"run_ref_v2:{canonical_run_id(1)}", HISTORY_KEY_ID
                )
                set_episode_members(create, turns[1:3])
                record_episode_bundle(index, 1, create)

                extend = transition_episode_row(
                    11, "extend", [create], turns[1:4]
                )
                record_episode_bundle(index, 2, extend)

                backfill = transition_episode_row(
                    12, "backfill", [extend], turns[0:4]
                )
                record_episode_bundle(index, 3, backfill)

                split_group = hex_ref("episode_transition_group_id_v2:", 1)
                left = transition_episode_row(
                    13,
                    "split",
                    [backfill],
                    [turns[0], turns[2]],
                    transition_group_id=split_group,
                    transition_group_ordinal=1,
                )
                right = transition_episode_row(
                    14,
                    "split",
                    [backfill],
                    [turns[1], turns[3]],
                    transition_group_id=split_group,
                    transition_group_ordinal=2,
                )
                partition_roots = [
                    str(left["member_turn_root"]),
                    str(right["member_turn_root"]),
                ]
                ordered_successors = sorted(
                    (left, right), key=lambda row: str(row["member_turn_root"])
                )
                for ordinal, successor in enumerate(ordered_successors, start=1):
                    successor["transition_group_ordinal"] = ordinal
                    anchor, lineage_id = MODULE._derive_split_episode_identity(
                        str(backfill["episode_anchor"]), partition_roots, ordinal
                    )
                    successor["episode_anchor"] = anchor
                    successor["episode_lineage_id"] = lineage_id
                record_episode_bundle(index, 4, [left, right])

                merge_group = hex_ref("episode_transition_group_id_v2:", 2)
                merge = transition_episode_row(
                    15,
                    "merge",
                    [left, right],
                    [turns[0], turns[2], turns[1], turns[3]],
                    transition_group_id=merge_group,
                )
                merge_anchor, merge_lineage = MODULE._derive_merge_episode_identity(
                    (
                        (str(predecessor["episode_anchor"]), str(predecessor["episode_revision_ref"]))
                        for predecessor in (left, right)
                    )
                )
                merge["episode_anchor"] = merge_anchor
                merge["episode_lineage_id"] = merge_lineage
                record_episode_bundle(index, 5, merge)

                issues: list[str] = []
                MODULE._validate_indexed_revision_graph(index, issues)
                self.assertEqual(issues, [])
            finally:
                index.close()

    def test_episode_transitions_reject_summary_only_extend_and_bad_split(self) -> None:
        turns = [hex_ref("turn_ref_v2:", number) for number in range(1, 4)]
        with self.subTest(operation="summary-only-extend"):
            with tempfile.TemporaryDirectory() as temp:
                index = MODULE._ValidationIndex(Path(temp) / "history.sqlite3")
                try:
                    create = episode_row(
                        20, f"run_ref_v2:{canonical_run_id(1)}", HISTORY_KEY_ID
                    )
                    set_episode_members(create, turns[:2])
                    record_episode_bundle(index, 1, create)
                    extend = transition_episode_row(
                        21, "extend", [create], turns[:2]
                    )
                    record_episode_bundle(index, 2, extend)
                    issues: list[str] = []
                    MODULE._validate_indexed_revision_graph(index, issues)
                    self.assertTrue(
                        any("add at least one" in issue for issue in issues), issues
                    )
                finally:
                    index.close()

        with self.subTest(operation="overlapping-split"):
            with tempfile.TemporaryDirectory() as temp:
                index = MODULE._ValidationIndex(Path(temp) / "history.sqlite3")
                try:
                    create = episode_row(
                        30, f"run_ref_v2:{canonical_run_id(1)}", HISTORY_KEY_ID
                    )
                    set_episode_members(create, turns)
                    record_episode_bundle(index, 1, create)
                    group_id = hex_ref("episode_transition_group_id_v2:", 3)
                    left = transition_episode_row(
                        31,
                        "split",
                        [create],
                        turns[:2],
                        transition_group_id=group_id,
                        transition_group_ordinal=1,
                    )
                    right = transition_episode_row(
                        32,
                        "split",
                        [create],
                        turns[1:],
                        transition_group_id=group_id,
                        transition_group_ordinal=2,
                    )
                    roots = [
                        str(left["member_turn_root"]),
                        str(right["member_turn_root"]),
                    ]
                    ordered_successors = sorted(
                        (left, right), key=lambda row: str(row["member_turn_root"])
                    )
                    for ordinal, successor in enumerate(
                        ordered_successors, start=1
                    ):
                        successor["transition_group_ordinal"] = ordinal
                        anchor, lineage_id = MODULE._derive_split_episode_identity(
                            str(create["episode_anchor"]), roots, ordinal
                        )
                        successor["episode_anchor"] = anchor
                        successor["episode_lineage_id"] = lineage_id
                    record_episode_bundle(index, 2, [left, right])
                    issues = []
                    MODULE._validate_indexed_revision_graph(index, issues)
                    self.assertTrue(
                        any("disjoint partitions" in issue for issue in issues), issues
                    )
                finally:
                    index.close()

    def test_episode_current_heads_reject_cross_lineage_member_ownership(self) -> None:
        turns = [hex_ref("turn_ref_v2:", number) for number in range(1, 3)]
        with tempfile.TemporaryDirectory() as temp:
            index = MODULE._ValidationIndex(Path(temp) / "history.sqlite3")
            try:
                create_a = episode_row(
                    90, f"run_ref_v2:{canonical_run_id(1)}", HISTORY_KEY_ID
                )
                set_episode_members(create_a, [turns[0]])
                record_episode_bundle(index, 1, create_a)

                extend_a = transition_episode_row(
                    91, "extend", [create_a], turns
                )
                record_episode_bundle(index, 2, extend_a)

                create_b = episode_row(
                    92, f"run_ref_v2:{canonical_run_id(3)}", HISTORY_KEY_ID
                )
                set_episode_members(create_b, [turns[1]])
                record_episode_bundle(index, 3, create_b)

                indexed_issues: list[str] = []
                MODULE._validate_indexed_revision_graph(index, indexed_issues)
                self.assertTrue(
                    any(
                        "compatible current episode heads" in issue
                        for issue in indexed_issues
                    ),
                    indexed_issues,
                )

                nodes = {}
                for row in MODULE._indexed_episode_rows(index.connection):
                    node = MODULE._indexed_episode_node_from_row(
                        index.connection, row
                    )
                    nodes[node.current] = node
                in_memory_issues: list[str] = []
                MODULE._validate_episode_transition_graph(nodes, in_memory_issues)
                self.assertTrue(
                    any(
                        "compatible current episode heads" in issue
                        for issue in in_memory_issues
                    ),
                    in_memory_issues,
                )
            finally:
                index.close()

    def test_episode_split_rejects_swapped_partition_ordinals(self) -> None:
        turns = [hex_ref("turn_ref_v2:", number) for number in range(1, 5)]
        with tempfile.TemporaryDirectory() as temp:
            index = MODULE._ValidationIndex(Path(temp) / "history.sqlite3")
            try:
                create = episode_row(
                    93, f"run_ref_v2:{canonical_run_id(1)}", HISTORY_KEY_ID
                )
                set_episode_members(create, turns)
                record_episode_bundle(index, 1, create)

                group_id = hex_ref("episode_transition_group_id_v2:", 7)
                successors = [
                    transition_episode_row(
                        94,
                        "split",
                        [create],
                        turns[:2],
                        transition_group_id=group_id,
                        transition_group_ordinal=1,
                    ),
                    transition_episode_row(
                        95,
                        "split",
                        [create],
                        turns[2:],
                        transition_group_id=group_id,
                        transition_group_ordinal=2,
                    ),
                ]
                canonical = sorted(
                    successors, key=lambda row: str(row["member_turn_root"])
                )
                for ordinal, successor in zip((2, 1), canonical, strict=True):
                    successor["transition_group_ordinal"] = ordinal
                ordinal_roots = [
                    str(successor["member_turn_root"])
                    for successor in sorted(
                        successors,
                        key=lambda row: int(row["transition_group_ordinal"]),
                    )
                ]
                for successor in successors:
                    ordinal = int(successor["transition_group_ordinal"])
                    anchor, lineage_id = MODULE._derive_split_episode_identity(
                        str(create["episode_anchor"]), ordinal_roots, ordinal
                    )
                    successor["episode_anchor"] = anchor
                    successor["episode_lineage_id"] = lineage_id
                record_episode_bundle(index, 2, successors)

                indexed_issues: list[str] = []
                MODULE._validate_indexed_revision_graph(index, indexed_issues)
                self.assertTrue(
                    any(
                        "canonical partition-root order" in issue
                        for issue in indexed_issues
                    ),
                    indexed_issues,
                )
                self.assertFalse(
                    any(
                        "identity is not deterministic" in issue
                        for issue in indexed_issues
                    ),
                    indexed_issues,
                )

                nodes = {}
                for row in MODULE._indexed_episode_rows(index.connection):
                    node = MODULE._indexed_episode_node_from_row(
                        index.connection, row
                    )
                    nodes[node.current] = node
                in_memory_issues: list[str] = []
                MODULE._validate_episode_transition_graph(nodes, in_memory_issues)
                self.assertTrue(
                    any(
                        "canonical partition-root order" in issue
                        for issue in in_memory_issues
                    ),
                    in_memory_issues,
                )
                self.assertFalse(
                    any(
                        "identity is not deterministic" in issue
                        for issue in in_memory_issues
                    ),
                    in_memory_issues,
                )
            finally:
                index.close()

    def test_episode_split_predecessor_has_one_atomic_transition_group(self) -> None:
        turns = [hex_ref("turn_ref_v2:", number) for number in range(1, 5)]
        with tempfile.TemporaryDirectory() as temp:
            index = MODULE._ValidationIndex(Path(temp) / "history.sqlite3")
            try:
                create = episode_row(
                    40, f"run_ref_v2:{canonical_run_id(1)}", HISTORY_KEY_ID
                )
                set_episode_members(create, turns)
                record_episode_bundle(index, 1, create)

                successors: list[dict[str, object]] = []
                for group_number, first_revision in ((4, 41), (5, 43)):
                    group_id = hex_ref(
                        "episode_transition_group_id_v2:", group_number
                    )
                    group = [
                        transition_episode_row(
                            first_revision,
                            "split",
                            [create],
                            turns[:2],
                            transition_group_id=group_id,
                            transition_group_ordinal=1,
                        ),
                        transition_episode_row(
                            first_revision + 1,
                            "split",
                            [create],
                            turns[2:],
                            transition_group_id=group_id,
                            transition_group_ordinal=2,
                        ),
                    ]
                    roots = [str(row["member_turn_root"]) for row in group]
                    ordered_group = sorted(
                        group, key=lambda row: str(row["member_turn_root"])
                    )
                    for ordinal, row in enumerate(ordered_group, start=1):
                        row["transition_group_ordinal"] = ordinal
                        anchor, lineage_id = MODULE._derive_split_episode_identity(
                            str(create["episode_anchor"]), roots, ordinal
                        )
                        row["episode_anchor"] = anchor
                        row["episode_lineage_id"] = lineage_id
                    successors.extend(group)
                record_episode_bundle(index, 2, successors)

                indexed_issues: list[str] = []
                MODULE._validate_indexed_revision_graph(index, indexed_issues)
                self.assertTrue(
                    any("only one split group" in issue for issue in indexed_issues),
                    indexed_issues,
                )

                nodes = {}
                for row in MODULE._indexed_episode_rows(index.connection):
                    node = MODULE._indexed_episode_node_from_row(
                        index.connection, row
                    )
                    nodes[node.current] = node
                in_memory_issues: list[str] = []
                MODULE._validate_episode_transition_graph(nodes, in_memory_issues)
                self.assertTrue(
                    any("only one split group" in issue for issue in in_memory_issues),
                    in_memory_issues,
                )
            finally:
                index.close()

    def test_episode_merge_group_and_root_anchor_are_unique(self) -> None:
        turns = [hex_ref("turn_ref_v2:", number) for number in range(1, 5)]
        with self.subTest(case="merge-group"):
            with tempfile.TemporaryDirectory() as temp:
                index = MODULE._ValidationIndex(Path(temp) / "history.sqlite3")
                try:
                    creates = []
                    for ordinal, turn_ref in enumerate(turns, start=1):
                        create = episode_row(
                            50 + ordinal,
                            f"run_ref_v2:{canonical_run_id(ordinal)}",
                            HISTORY_KEY_ID,
                        )
                        set_episode_members(create, [turn_ref])
                        record_episode_bundle(index, ordinal, create)
                        creates.append(create)
                    group_id = hex_ref("episode_transition_group_id_v2:", 6)
                    merges = []
                    for revision, predecessors in (
                        (60, creates[:2]),
                        (61, creates[2:]),
                    ):
                        merged = transition_episode_row(
                            revision,
                            "merge",
                            predecessors,
                            [
                                str(predecessor["turn_refs"][0])
                                for predecessor in predecessors
                            ],
                            transition_group_id=group_id,
                        )
                        anchor, lineage_id = MODULE._derive_merge_episode_identity(
                            (
                                (
                                    str(predecessor["episode_anchor"]),
                                    str(predecessor["episode_revision_ref"]),
                                )
                                for predecessor in predecessors
                            )
                        )
                        merged["episode_anchor"] = anchor
                        merged["episode_lineage_id"] = lineage_id
                        merges.append(merged)
                    record_episode_bundle(index, 5, merges)

                    issues: list[str] = []
                    MODULE._validate_indexed_revision_graph(index, issues)
                    self.assertTrue(
                        any("one atomic split or merge" in issue for issue in issues),
                        issues,
                    )
                finally:
                    index.close()

        with self.subTest(case="root-anchor"):
            with tempfile.TemporaryDirectory() as temp:
                index = MODULE._ValidationIndex(Path(temp) / "history.sqlite3")
                try:
                    left = episode_row(
                        70, f"run_ref_v2:{canonical_run_id(1)}", HISTORY_KEY_ID
                    )
                    right = episode_row(
                        71, f"run_ref_v2:{canonical_run_id(2)}", HISTORY_KEY_ID
                    )
                    right["episode_anchor"] = left["episode_anchor"]
                    record_episode_bundle(index, 1, left)
                    record_episode_bundle(index, 2, right)

                    issues = []
                    MODULE._validate_indexed_revision_graph(index, issues)
                    self.assertTrue(
                        any("anchor may have only one root" in issue for issue in issues),
                        issues,
                    )
                finally:
                    index.close()

    def test_episode_backfill_gap_evidence_is_exact_and_declared(self) -> None:
        turns = [hex_ref("turn_ref_v2:", number) for number in range(1, 4)]
        gap_ref = hex_ref("gap_ref_v2:", 1)
        with tempfile.TemporaryDirectory() as temp:
            index = MODULE._ValidationIndex(Path(temp) / "history.sqlite3")
            try:
                create = episode_row(
                    80, f"run_ref_v2:{canonical_run_id(1)}", HISTORY_KEY_ID
                )
                set_episode_members(create, [turns[0], turns[2]])
                record_episode_bundle(index, 1, create)
                backfill = transition_episode_row(
                    81,
                    "backfill",
                    [create],
                    turns,
                    backfill_membership_evidence=[
                        {"turn_ref": turns[1], "gap_ref": gap_ref}
                    ],
                )
                backfill["gap_refs"] = [gap_ref]
                backfill["generalized_content_digest"] = (
                    MODULE._episode_generalized_content_digest(backfill)
                )
                record_episode_bundle(index, 2, backfill)

                issues: list[str] = []
                MODULE._validate_indexed_revision_graph(index, issues)
                self.assertEqual(issues, [])
            finally:
                index.close()

        undeclared = transition_episode_row(
            82,
            "backfill",
            [create],
            turns,
            backfill_membership_evidence=[
                {"turn_ref": turns[1], "gap_ref": gap_ref}
            ],
        )
        with tempfile.TemporaryDirectory() as temp:
            index = MODULE._ValidationIndex(Path(temp) / "history.sqlite3")
            try:
                with self.assertRaisesRegex(AssertionError, "declared gap_refs"):
                    record_episode_bundle(index, 1, undeclared)
            finally:
                index.close()

    def test_canonical_run_id_decoder_rejects_final_character_aliases(self) -> None:
        run_id = canonical_run_id(1)
        alias = run_id[:-1] + "f"
        canonical_path = Path("runs", "daily", "2026-07-13", run_id, "manifest.json")
        alias_path = Path("runs", "daily", "2026-07-13", alias, "manifest.json")
        legacy_path = Path(
            "runs",
            "daily",
            *("00" for _ in range(32)),
            "2026-07-13",
            *("00" for _ in range(32)),
            "manifest.json",
        )

        self.assertTrue(MODULE._valid_run_id(run_id))
        self.assertFalse(MODULE._valid_run_id(alias))
        self.assertIsNotNone(MODULE._parse_physical_artifact_path(canonical_path))
        self.assertIsNone(MODULE._parse_physical_artifact_path(alias_path))
        self.assertIsNone(MODULE._parse_physical_artifact_path(legacy_path))

    def test_valid_complete_bundle_and_reordered_visible_files_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            visible = list(reversed(sorted(refs.directory.iterdir())))
            relative_visible = [path.relative_to(root) for path in visible]

            self.assertEqual(MODULE.validate_v2_runs(root, visible), [])
            self.assertEqual(MODULE.validate_v2_runs(root, relative_visible), [])
            self.assertEqual(MODULE.validate_v2_runs(root), [])

    def test_physical_path_binds_window_and_canonical_run_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            parts = refs.directory.relative_to(root).parts
            manifest = json.loads((refs.directory / "manifest.json").read_bytes())

            self.assertEqual(len(parts), MODULE.RUN_ARTIFACT_PATH_COMPONENT_COUNT - 1)
            self.assertEqual(
                parts,
                ("runs", "daily", str(WINDOW["path_component"]), refs.run_id),
            )
            self.assertEqual(manifest["run_id"], refs.run_id)
            self.assertEqual(manifest["run_ref"], f"run_ref_v2:{refs.run_id}")

    def test_old_radix_run_layout_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            old_directory = legacy_radix_bundle_directory(
                root,
                "daily",
                str(WINDOW["path_component"]),
                "0" * 63 + "1",
            )
            old_directory.parent.mkdir(parents=True, exist_ok=True)
            refs.directory.rename(old_directory)

            issues = MODULE.validate_v2_runs(root)
            self.assertIn("runs/[invalid]: invalid v2 retained-run path", issues)
            self.assertFalse(any("schema target" in issue for issue in issues), issues)

    def test_noncanonical_run_id_and_extra_path_depth_are_rejected(
        self,
    ) -> None:
        with self.subTest(case="noncanonical-final-alias"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                refs = write_bundle(root, 1)
                self.assertEqual(refs.run_id[-1], "e")
                target = refs.directory.with_name(refs.run_id[:-1] + "f")
                target.parent.mkdir(parents=True, exist_ok=True)
                refs.directory.rename(target)

                self.assertIn(
                    "runs/[invalid]: invalid v2 retained-run path",
                    MODULE.validate_v2_runs(root),
                )

        with self.subTest(case="invalid-base32-character"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                refs = write_bundle(root, 1)
                target = refs.directory.with_name("0" + refs.run_id[1:])
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
            manifest["run_id"] = canonical_run_id(99)
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

    def test_logical_run_id_collision_fails_closed(self) -> None:
        second_window = {
            "mode": "daily",
            "path_component": "2026-07-12",
            "start": "2026-07-12T00:00:00Z",
            "end": "2026-07-13T00:00:00Z",
        }
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

    def test_manifest_rejects_multiple_identity_key_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            manifest_path = refs.directory / "manifest.json"
            manifest = json.loads(manifest_path.read_bytes())
            manifest.pop("key_id")
            manifest["key_ids"] = [
                HISTORY_KEY_ID,
                "key_id_v2:" + "0" * 15 + "2",
            ]
            manifest_path.write_bytes(canonical_json(manifest))
            rewrite_digest(refs.directory)

            issues = MODULE.validate_v2_runs(root)

            self.assertTrue(
                any("manifest fields do not match" in issue for issue in issues),
                issues,
            )
            self.assertTrue(
                any("schema target manifest" in issue for issue in issues), issues
            )

    def test_bundle_and_history_identity_key_mismatches_fail_closed(self) -> None:
        class AcceptAllSchemaValidator:
            @staticmethod
            def iter_errors(_value: object) -> tuple[object, ...]:
                return ()

        validators = {
            target: AcceptAllSchemaValidator()
            for target in MODULE.SCHEMA_TARGETS.values()
        }
        second_key_id = "key_id_v2:" + "0" * 15 + "2"
        with self.subTest(scope="bundle"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                refs = write_bundle(root, 1)
                coverage_path = refs.directory / "coverage.json"
                coverage = json.loads(coverage_path.read_bytes())
                coverage["key_id"] = second_key_id
                coverage_path.write_bytes(canonical_json(coverage))
                rewrite_digest(refs.directory)

                with mock.patch.object(
                    MODULE, "_load_schema_validators", return_value=validators
                ):
                    issues = MODULE.validate_v2_runs(root)

                self.assertTrue(
                    any("key_id must match manifest.json" in issue for issue in issues),
                    issues,
                )

        with self.subTest(scope="history-generation"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                write_bundle(root, 1)
                write_bundle(root, 2, key_id=second_key_id)

                with mock.patch.object(
                    MODULE, "_load_schema_validators", return_value=validators
                ):
                    issues = MODULE.validate_v2_runs(root)

                self.assertIn(MODULE.HISTORY_IDENTITY_ISSUE, issues)

    def test_indexed_history_identity_requires_one_key_generation(self) -> None:
        def record_bundle(
            index: object, bundle_id: int, number: int, key_id: str
        ) -> None:
            run_id = canonical_run_id(number)
            index.connection.execute(
                """
                INSERT INTO discovered_bundles(
                    id, mode, window_component, run_id
                ) VALUES (?, ?, ?, ?)
                """,
                (bundle_id, "daily", "2026-07-13", run_id),
            )
            index.record_bundle(
                bundle_id,
                MODULE.Bundle(
                    label=f"runs/daily/2026-07-13/{run_id}",
                    mode="daily",
                    window_component="2026-07-13",
                    run_id=run_id,
                    files={},
                    manifest={"key_id": key_id},
                ),
            )

        with tempfile.TemporaryDirectory() as temp:
            index = MODULE._ValidationIndex(Path(temp) / "history.sqlite3")
            try:
                record_bundle(index, 1, 1, HISTORY_KEY_ID)
                record_bundle(index, 2, 2, HISTORY_KEY_ID)
                issues: list[str] = []
                MODULE._validate_indexed_history_identity(index, issues)
                self.assertEqual(issues, [])

                record_bundle(
                    index,
                    3,
                    3,
                    "key_id_v2:" + "0" * 15 + "2",
                )
                MODULE._validate_indexed_history_identity(index, issues)
                self.assertEqual(issues, [MODULE.HISTORY_IDENTITY_ISSUE])
            finally:
                index.close()

    def test_digest_uses_sibling_bytes_and_canonical_manifest_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            payloads = {
                artifact: (refs.directory / artifact).read_bytes()
                for artifact in ARTIFACTS
            }
            manifest = json.loads(payloads["manifest.json"])
            original_digest = bundle_digest(payloads, manifest)
            changed_attestation = json.loads(json.dumps(manifest))
            changed_attestation["publisher_attestation"]["signer_fingerprint"] = (
                "B" * 40
            )
            self.assertEqual(
                bundle_digest(payloads, changed_attestation),
                original_digest,
            )

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
                row = episode_row(1, manifest["run_ref"], manifest["key_id"])
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
                        "metric_ref": hex_ref("trend_metric_ref_v2:", 1),
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

    def test_normalized_change_binds_prior_compatible_metric_rate(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prior = write_bundle(root, 1, window=PRIOR_DAILY_WINDOW)
            current = write_bundle(root, 2)
            set_trend_metric(
                prior,
                rate=20,
                metric_ref=hex_ref("trend_metric_ref_v2:", 1),
                normalized_change={
                    "status": "unavailable",
                    "reason": "no_prior_period",
                },
            )
            set_trend_metric(
                current,
                rate=80,
                metric_ref=hex_ref("trend_metric_ref_v2:", 2),
                normalized_change={
                    "status": "available",
                    "prior_run_revision_ref": prior.run_revision_ref,
                    "direction": "regressed",
                    "delta_per_100": 10,
                },
            )

            issues = MODULE.validate_v2_runs(root)

            self.assertTrue(
                any(
                    "normalized change delta must exactly match the compatible prior metric"
                    in issue
                    for issue in issues
                ),
                issues,
            )

            trend_path = current.directory / "trend_report.json"
            trend = json.loads(trend_path.read_bytes())
            trend["strata"][0]["metrics"][0]["normalized_change"][
                "prior_run_revision_ref"
            ] = hex_ref("run_revision_ref_v2:", 999)
            trend_path.write_bytes(canonical_json(trend))
            rewrite_digest(current.directory)

            issues = MODULE.validate_v2_runs(root)

            self.assertTrue(
                any(
                    "prior run revision is not present as an eligible trend observation"
                    for issue in issues
                ),
                issues,
            )

    def test_prior_trend_requires_eligible_mode_and_window(self) -> None:
        cases = (
            ("future", FUTURE_DAILY_WINDOW),
            ("different-mode", PRIOR_WEEKLY_WINDOW),
            ("overlap", WINDOW),
        )
        for label, prior_window in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                prior = write_bundle(root, 1, window=prior_window)
                current = write_bundle(root, 2)
                set_trend_metric(
                    prior,
                    rate=20,
                    metric_ref=hex_ref("trend_metric_ref_v2:", 1),
                    normalized_change={
                        "status": "unavailable",
                        "reason": "no_prior_period",
                    },
                )
                set_trend_metric(
                    current,
                    rate=80,
                    metric_ref=hex_ref("trend_metric_ref_v2:", 2),
                    normalized_change={
                        "status": "available",
                        "prior_run_revision_ref": prior.run_revision_ref,
                        "direction": "regressed",
                        "delta_per_100": 60,
                    },
                )

                issues = MODULE.validate_v2_runs(root)

                self.assertTrue(
                    any(
                        "prior run must share mode and use a strictly earlier non-overlapping window"
                        in issue
                        for issue in issues
                    ),
                    issues,
                )

    def test_campaign_segment_is_not_a_prior_trend_observation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            segment = write_campaign_bundle(
                root,
                1,
                publication_role="campaign_segment",
                mode="daily",
                segment_count=1,
                segment_ordinal=1,
            )
            current = write_bundle(root, 2)
            set_trend_metric(
                segment,
                rate=20,
                metric_ref=hex_ref("trend_metric_ref_v2:", 1),
                normalized_change={
                    "status": "unavailable",
                    "reason": "no_prior_period",
                },
            )
            set_trend_metric(
                current,
                rate=80,
                metric_ref=hex_ref("trend_metric_ref_v2:", 2),
                normalized_change={
                    "status": "available",
                    "prior_run_revision_ref": segment.run_revision_ref,
                    "direction": "regressed",
                    "delta_per_100": 60,
                },
            )

            issues = MODULE.validate_v2_runs(root)

            self.assertTrue(
                any(
                    "prior run revision is not present as an eligible trend observation"
                    in issue
                    for issue in issues
                ),
                issues,
            )

    def test_campaign_segment_semantic_revision_family_inventory_is_complete(
        self,
    ) -> None:
        self.assertEqual(
            MODULE.CAMPAIGN_SEGMENT_REVISION_FAMILIES - {"run"},
            {
                "coverage",
                "summary",
                "trend",
                "gap",
                "episode",
                "topic",
                "turn_finding",
            },
        )

    def test_campaign_segment_gap_revision_must_be_initial(self) -> None:
        segment = MODULE.Bundle(
            label="runs/campaign-segment",
            mode="daily",
            window_component="2026-07-13",
            run_id=canonical_run_id(1),
            files={},
            manifest={"publication_role": "campaign_segment"},
        )
        segment.revisions = [
            MODULE.RevisionNode(
                family="gap",
                current="gap-current",
                predecessors=("gap-prior",),
                kind="correction",
                entity_ref="gap-entity",
                transaction_ref="segment-run",
                label="runs/campaign-segment/gap",
            )
        ]
        issues: list[str] = []

        MODULE._validate_campaign_revision_ownership([segment], issues)

        self.assertIn(
            "runs/campaign-segment: campaign segment gap revision must be initial and predecessor-free",
            issues,
        )

    def test_canonical_bundles_cannot_inherit_segment_owned_gap(self) -> None:
        segment = MODULE.Bundle(
            label="runs/campaign-segment",
            mode="daily",
            window_component="2026-07-13",
            run_id=canonical_run_id(1),
            files={},
            manifest={"publication_role": "campaign_segment"},
        )
        segment.revisions = [
            MODULE.RevisionNode(
                family="gap",
                current="gap-segment",
                predecessors=(),
                kind="initial",
                entity_ref="gap-entity",
                transaction_ref="segment-run",
                label="runs/campaign-segment/gap",
            )
        ]

        for role in ("campaign_root", "standalone"):
            with self.subTest(role=role):
                successor = MODULE.Bundle(
                    label=f"runs/{role}",
                    mode="daily",
                    window_component="2026-07-13",
                    run_id=canonical_run_id(2),
                    files={},
                    manifest={"publication_role": role},
                )
                successor.revisions = [
                    MODULE.RevisionNode(
                        family="gap",
                        current=f"gap-{role}",
                        predecessors=("gap-segment",),
                        kind="correction",
                        entity_ref="gap-entity",
                        transaction_ref=f"{role}-run",
                        label=f"runs/{role}/gap",
                    )
                ]
                issues: list[str] = []

                MODULE._validate_campaign_revision_ownership(
                    [segment, successor], issues
                )

                self.assertIn(
                    f"runs/{role}: {role} gap revision must not target a campaign-segment-owned predecessor",
                    issues,
                )

    def test_campaign_segment_semantic_revisions_must_all_be_initial(self) -> None:
        segment = MODULE.Bundle(
            label="runs/campaign-segment",
            mode="daily",
            window_component="2026-07-13",
            run_id=canonical_run_id(1),
            files={},
            manifest={"publication_role": "campaign_segment"},
        )
        segment.revisions = [
            MODULE.RevisionNode(
                family=family,
                current=f"{family}-current",
                predecessors=(f"{family}-prior",),
                kind="correction",
                entity_ref=None,
                transaction_ref="segment-run",
                label=f"runs/campaign-segment/{family}",
            )
            for family in sorted(MODULE.CAMPAIGN_SEGMENT_REVISION_FAMILIES)
        ]
        issues: list[str] = []

        MODULE._validate_campaign_revision_ownership([segment], issues)

        for family in MODULE.CAMPAIGN_SEGMENT_REVISION_FAMILIES:
            self.assertTrue(
                any(
                    f"campaign segment {family} revision must be initial" in issue
                    for issue in issues
                ),
                (family, issues),
            )

    def test_root_and_standalone_cannot_succeed_segment_semantic_heads(self) -> None:
        owned_families = tuple(sorted(MODULE.CAMPAIGN_SEGMENT_REVISION_FAMILIES))
        segment = MODULE.Bundle(
            label="runs/campaign-segment",
            mode="daily",
            window_component="2026-07-13",
            run_id=canonical_run_id(1),
            files={},
            manifest={"publication_role": "campaign_segment"},
        )
        segment.revisions = [
            MODULE.RevisionNode(
                family=family,
                current=f"{family}-segment",
                predecessors=(),
                kind="initial",
                entity_ref=None,
                transaction_ref="segment-run",
                label=f"runs/campaign-segment/{family}",
            )
            for family in owned_families
        ]

        for role in ("campaign_root", "standalone"):
            with self.subTest(role=role):
                successor = MODULE.Bundle(
                    label=f"runs/{role}",
                    mode="daily",
                    window_component="2026-07-13",
                    run_id=canonical_run_id(2),
                    files={},
                    manifest={"publication_role": role},
                )
                successor.revisions = [
                    MODULE.RevisionNode(
                        family=family,
                        current=f"{family}-{role}",
                        predecessors=(f"{family}-segment",),
                        kind="correction",
                        entity_ref=None,
                        transaction_ref=f"{role}-run",
                        label=f"runs/{role}/{family}",
                    )
                    for family in owned_families
                ]
                issues: list[str] = []

                MODULE._validate_campaign_revision_ownership(
                    [segment, successor], issues
                )

                for family in MODULE.CAMPAIGN_SEGMENT_REVISION_FAMILIES:
                    self.assertTrue(
                        any(
                            f"{family} revision must not target a campaign-segment-owned predecessor"
                            in issue
                            for issue in issues
                        ),
                        (family, issues),
                    )

    def test_campaign_ownership_checks_manifest_and_head_targets(self) -> None:
        families = tuple(sorted(MODULE.CAMPAIGN_SEGMENT_REVISION_FAMILIES))
        segment = MODULE.Bundle(
            label="runs/campaign-segment",
            mode="daily",
            window_component="2026-07-13",
            run_id=canonical_run_id(1),
            files={},
            manifest={
                "publication_role": "campaign_segment",
                "supersession": {"supersedes_topic_revision_refs": ["topic-prior"]},
                "head_bindings": {
                    "bound_quarantine_generation_ref": "quarantine",
                    "episode": {"proposed_head_ref": "head"},
                },
            },
        )
        segment.revisions = [
            MODULE.RevisionNode(
                family=family,
                current=f"{family}-segment",
                predecessors=(),
                kind="initial",
                entity_ref=None,
                transaction_ref="segment-run",
                label=f"runs/campaign-segment/{family}",
            )
            for family in families
        ]
        successor = MODULE.Bundle(
            label="runs/standalone",
            mode="daily",
            window_component="2026-07-13",
            run_id=canonical_run_id(2),
            files={},
            manifest={
                "publication_role": "standalone",
                "supersession": {
                    field: [f"{family}-segment"]
                    for family, field in MODULE.CAMPAIGN_SEGMENT_MANIFEST_SUPERSESSION_FIELDS.items()
                },
                "head_bindings": {
                    "retained_targets": [
                        f"{family}-segment"
                        for family in MODULE.CAMPAIGN_SEGMENT_AGGREGATE_FAMILIES
                    ]
                    + ["gap-segment"]
                },
            },
        )
        issues: list[str] = []

        MODULE._validate_campaign_revision_ownership([segment, successor], issues)

        self.assertTrue(
            any(
                "campaign segment topic revision must be initial and predecessor-free"
                in issue
                for issue in issues
            ),
            issues,
        )
        self.assertTrue(
            any(
                "campaign segment must not propose retained state or head successors"
                in issue
                for issue in issues
            ),
            issues,
        )
        for family in families:
            self.assertTrue(
                any(
                    f"standalone {family} revision must not target a campaign-segment-owned predecessor"
                    in issue
                    for issue in issues
                ),
                (family, issues),
            )

    def test_summary_change_resolves_trend_comparison_and_exact_direction(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prior = write_bundle(root, 1, window=PRIOR_DAILY_WINDOW)
            current = write_bundle(root, 2)
            current_metric_ref = hex_ref("trend_metric_ref_v2:", 2)
            set_trend_metric(
                prior,
                rate=20,
                metric_ref=hex_ref("trend_metric_ref_v2:", 1),
                normalized_change={
                    "status": "unavailable",
                    "reason": "no_prior_period",
                },
            )
            set_trend_metric(
                current,
                rate=10,
                metric_ref=current_metric_ref,
                normalized_change={
                    "status": "available",
                    "prior_run_revision_ref": prior.run_revision_ref,
                    "direction": "improved",
                    "delta_per_100": -10,
                },
            )
            set_summary_change(
                current,
                {
                    "status": "available",
                    "direction": "regressed",
                    "prior_run_revision_ref": prior.run_revision_ref,
                    "metric_refs": [current_metric_ref],
                },
            )

            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any(
                    "change_from_prior direction must match exact normalized trend deltas"
                    in issue
                    for issue in issues
                ),
                issues,
            )

            missing_prior = hex_ref("run_revision_ref_v2:", 999)
            set_summary_change(
                current,
                {
                    "status": "available",
                    "direction": "improved",
                    "prior_run_revision_ref": missing_prior,
                    "metric_refs": [current_metric_ref],
                },
            )
            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any(
                    "/summary.json: prior run revision is not present" in issue
                    for issue in issues
                ),
                issues,
            )

            set_summary_change(
                current,
                {
                    "status": "available",
                    "direction": "improved",
                    "prior_run_revision_ref": prior.run_revision_ref,
                    "metric_refs": [hex_ref("trend_metric_ref_v2:", 999)],
                },
            )
            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any(
                    "metric_refs must resolve uniquely to available normalized trend comparisons"
                    in issue
                    for issue in issues
                ),
                issues,
            )

    def test_prior_trend_must_be_active_at_current_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prior = write_bundle(root, 1, window=PRIOR_DAILY_WINDOW)
            replacement = write_bundle(
                root,
                2,
                reason="correction",
                predecessor=prior,
                window=PRIOR_DAILY_WINDOW,
            )
            current = write_bundle(root, 3)
            current_metric_ref = hex_ref("trend_metric_ref_v2:", 3)
            set_prepared_at(prior, "2026-07-14T00:00:00Z")
            set_prepared_at(current, "2026-07-14T00:02:00Z")
            set_prepared_at(replacement, "2026-07-14T00:03:00Z")
            set_trend_metric(
                prior,
                rate=20,
                metric_ref=hex_ref("trend_metric_ref_v2:", 1),
                normalized_change={
                    "status": "unavailable",
                    "reason": "no_prior_period",
                },
            )
            set_trend_metric(
                replacement,
                rate=5,
                metric_ref=hex_ref("trend_metric_ref_v2:", 2),
                normalized_change={
                    "status": "unavailable",
                    "reason": "no_prior_period",
                },
            )
            set_trend_metric(
                current,
                rate=10,
                metric_ref=current_metric_ref,
                normalized_change={
                    "status": "available",
                    "prior_run_revision_ref": prior.run_revision_ref,
                    "direction": "improved",
                    "delta_per_100": -10,
                },
            )
            set_summary_change(
                current,
                {
                    "status": "available",
                    "direction": "improved",
                    "prior_run_revision_ref": prior.run_revision_ref,
                    "metric_refs": [current_metric_ref],
                },
            )

            issues = MODULE.validate_v2_runs(root)
            self.assertFalse(
                any("prior run revision was not active" in issue for issue in issues),
                issues,
            )

            set_prepared_at(replacement, "2026-07-14T00:01:00Z")
            issues = MODULE.validate_v2_runs(root)
            self.assertTrue(
                any(
                    "/trend_report.json: prior run revision was not active" in issue
                    for issue in issues
                ),
                issues,
            )
            self.assertTrue(
                any(
                    "/summary.json: prior run revision was not active" in issue
                    for issue in issues
                ),
                issues,
            )

            set_trend_metric(
                current,
                rate=10,
                metric_ref=current_metric_ref,
                normalized_change={
                    "status": "available",
                    "prior_run_revision_ref": replacement.run_revision_ref,
                    "direction": "regressed",
                    "delta_per_100": 5,
                },
            )
            set_summary_change(
                current,
                {
                    "status": "available",
                    "direction": "improved",
                    "prior_run_revision_ref": replacement.run_revision_ref,
                    "metric_refs": [current_metric_ref],
                },
            )
            issues = MODULE.validate_v2_runs(root)
            self.assertFalse(
                any("prior run revision was not active" in issue for issue in issues),
                issues,
            )
            self.assertTrue(
                any(
                    "change_from_prior direction must match exact normalized trend deltas"
                    in issue
                    for issue in issues
                ),
                issues,
            )

            set_summary_change(
                current,
                {
                    "status": "available",
                    "direction": "regressed",
                    "prior_run_revision_ref": replacement.run_revision_ref,
                    "metric_refs": [current_metric_ref],
                },
            )
            issues = MODULE.validate_v2_runs(root)
            trend_contract_issues = (
                "prior run revision was not active",
                "normalized change delta must exactly match",
                "change_from_prior direction must match",
            )
            self.assertFalse(
                any(
                    contract in issue
                    for issue in issues
                    for contract in trend_contract_issues
                ),
                issues,
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

    def test_model_era_catalog_requirement_matches_execution_kind(self) -> None:
        allowed_cases = (
            ("bootstrap_v2", "complete"),
            ("compliance_retraction", "complete_with_terminal_gaps"),
        )
        for execution_kind, status in allowed_cases:
            with (
                self.subTest(execution_kind=execution_kind),
                tempfile.TemporaryDirectory() as temp,
            ):
                root = Path(temp)
                predecessor = None
                reason = "initial"
                number = 1
                if execution_kind == "compliance_retraction":
                    predecessor = write_bundle(root, 1)
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

                self.assertEqual(MODULE.validate_v2_runs(root), [])

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            remove_model_execution_provenance(refs)

            issues = MODULE.validate_v2_runs(root)

        self.assertTrue(
            any("model_eras must be a non-empty array" in issue for issue in issues),
            issues,
        )

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

    def test_campaign_segments_without_root_must_form_a_contiguous_prefix(self) -> None:
        for ordinals in ((2,), (1, 3)):
            with self.subTest(ordinals=ordinals), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                for number, ordinal in enumerate(ordinals, start=1):
                    write_campaign_bundle(
                        root,
                        number,
                        publication_role="campaign_segment",
                        mode="daily",
                        segment_ordinal=ordinal,
                    )

                issues = MODULE.validate_v2_runs(root)

                self.assertTrue(
                    any(
                        "segments must cover every unique bounded ordinal" in issue
                        for issue in issues
                    ),
                    issues,
                )

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

    def test_campaign_root_cannot_supersede_segment_owned_revisions(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            segment = write_campaign_bundle(
                root,
                1,
                publication_role="campaign_segment",
                mode="daily",
                segment_count=1,
                segment_ordinal=1,
            )
            campaign_root = write_campaign_bundle(
                root,
                2,
                publication_role="campaign_root",
                mode="daily",
                segment_count=1,
            )
            manifest_path = campaign_root.directory / "manifest.json"
            manifest = json.loads(manifest_path.read_bytes())
            manifest["supersession"]["reason"] = "correction"
            manifest["supersession"]["supersedes_run_revision_refs"] = [
                segment.run_revision_ref
            ]
            manifest_path.write_bytes(canonical_json(manifest))

            aggregate_predecessors = {
                "coverage.json": (
                    "predecessor_coverage_revision_ref",
                    segment.coverage_revision_ref,
                ),
                "summary.json": (
                    "predecessor_summary_revision_ref",
                    segment.summary_revision_ref,
                ),
                "trend_report.json": (
                    "predecessor_trend_revision_ref",
                    segment.trend_revision_ref,
                ),
            }
            for basename, (field, predecessor) in aggregate_predecessors.items():
                path = campaign_root.directory / basename
                document = json.loads(path.read_bytes())
                document[field] = predecessor
                document["revision_kind"] = "correction"
                path.write_bytes(canonical_json(document))
            rewrite_digest(campaign_root.directory)

            issues = MODULE.validate_v2_runs(root)

        self.assertTrue(
            any(
                "campaign_root run revision must not target a campaign-segment-owned predecessor"
                in issue
                for issue in issues
            ),
            issues,
        )
        for family in MODULE.CAMPAIGN_SEGMENT_AGGREGATE_FAMILIES:
            self.assertTrue(
                any(
                    f"campaign_root {family} revision must not target a campaign-segment-owned predecessor"
                    in issue
                    for issue in issues
                ),
                (family, issues),
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
            key_id = manifest["key_id"]
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

    def test_wide_json_is_rejected_before_object_graph_materialization(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            wide = (
                b"["
                + b",".join(b"0" for _ in range(MODULE.MAX_JSON_CONTAINER_ITEMS + 1))
                + b"]"
            )
            (refs.directory / "episodes.jsonl").write_bytes(wide + b"\n")
            rewrite_digest(refs.directory)
            original_parse = MODULE._parse_json_bytes

            def guarded_parse(raw: bytes) -> object:
                if raw == wide:
                    self.fail("wide JSON reached json.loads")
                return original_parse(raw)

            with mock.patch.object(
                MODULE, "_parse_json_bytes", side_effect=guarded_parse
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
            coverage["run_ref"] = f"run_ref_v2:{canonical_run_id(999)}"
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
                episode_row(2, manifest["run_ref"], manifest["key_id"]),
                episode_row(1, manifest["run_ref"], manifest["key_id"]),
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

    def test_unrelated_visible_files_do_not_consume_v2_discovery_cap(self) -> None:
        unrelated_count = MODULE.MAX_DISCOVERY_PAGE_FILES * 2 + 1
        visible_files = (
            Path("reports", f"infrastructure-{index:06x}.json")
            for index in range(unrelated_count)
        )

        with (
            tempfile.TemporaryDirectory() as temp,
            mock.patch.object(MODULE, "_load_schema_validators", return_value={}),
            mock.patch.object(
                MODULE, "_load_privacy_validator", return_value=lambda *_: []
            ),
        ):
            issues = MODULE.validate_v2_runs(Path(temp), visible_files)

        self.assertEqual(issues, [])

    def test_visible_invalid_runs_paths_are_rejected_without_disclosure(self) -> None:
        visible_files = (
            Path("runs", "v1", "raw-session.jsonl"),
            Path("runs", "daily", "short.json"),
            Path("runs", "latest"),
        )

        with (
            tempfile.TemporaryDirectory() as temp,
            mock.patch.object(MODULE, "_load_schema_validators", return_value={}),
            mock.patch.object(
                MODULE, "_load_privacy_validator", return_value=lambda *_: []
            ),
        ):
            issues = MODULE.validate_v2_runs(Path(temp), visible_files)

        self.assertIn("runs/[invalid]: invalid v2 retained-run path", issues)
        rendered = "\n".join(issues)
        self.assertNotIn("raw-session", rendered)
        self.assertNotIn("short.json", rendered)
        self.assertNotIn("latest", rendered)

    def test_duplicate_visible_candidates_do_not_expand_the_index(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            candidates = tuple(sorted(refs.directory.iterdir()))
            visible_files = (
                candidate
                for _ in range(MODULE.MAX_DISCOVERY_PAGE_FILES + 1)
                for candidate in candidates
            )

            self.assertEqual(MODULE.validate_v2_runs(root, visible_files), [])

    def test_discovery_and_validation_pages_are_bounded_not_lifetime_caps(
        self,
    ) -> None:
        with self.subTest(limit="directory"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                write_bundle(root, 1)
                with mock.patch.object(MODULE, "MAX_DIRECTORY_ENTRIES", 3):
                    issues = MODULE.validate_v2_runs(root)
                self.assertIn(MODULE.DISCOVERY_LIMIT_ISSUE, issues)

        with self.subTest(page="files"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                write_bundle(root, 1)
                write_bundle(root, 2)
                with (
                    mock.patch.object(MODULE, "MAX_DISCOVERY_PAGE_FILES", 3),
                    mock.patch.object(
                        MODULE,
                        "_read_fd_bounded",
                        wraps=MODULE._read_fd_bounded,
                    ) as read,
                ):
                    self.assertEqual(MODULE.validate_v2_runs(root), [])
                self.assertGreater(read.call_count, 0)

        with self.subTest(page="bundles"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                write_bundle(root, 1)
                write_bundle(root, 2)
                with mock.patch.object(MODULE, "MAX_BUNDLE_PAGE_SIZE", 1):
                    self.assertEqual(MODULE.validate_v2_runs(root), [])

    def test_more_than_512_valid_bundles_are_admitted_in_bounded_pages(self) -> None:
        bundle_count = 513
        page_size = 37
        observed_page_sizes: list[int] = []
        original_iter_pages = MODULE._ValidationIndex.iter_bundle_pages

        def record_pages(index: object) -> object:
            for page in original_iter_pages(index):
                observed_page_sizes.append(len(page))
                yield page

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for number in range(1, bundle_count + 1):
                write_bundle(root, number)
            with (
                mock.patch.object(MODULE, "MAX_BUNDLE_PAGE_SIZE", page_size),
                mock.patch.object(
                    MODULE._ValidationIndex,
                    "iter_bundle_pages",
                    record_pages,
                ),
            ):
                issues, manifests = MODULE.validate_v2_runs_with_inventory(root)

        try:
            self.assertEqual(issues, [])
            self.assertEqual(len(manifests), bundle_count)
            self.assertGreater(len(observed_page_sizes), 1)
            self.assertLessEqual(max(observed_page_sizes), page_size)
        finally:
            close_inventory = getattr(manifests, "close", None)
            if callable(close_inventory):
                close_inventory()

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

    def test_bundle_directory_replacement_during_read_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            summary_inode = (refs.directory / "summary.json").stat().st_ino
            detached = refs.directory.parent / "detached-bundle"
            original_read = MODULE._read_fd_bounded
            replaced = False

            def racing_read(descriptor: int, byte_limit: int) -> bytes:
                nonlocal replaced
                if not replaced and os.fstat(descriptor).st_ino == summary_inode:
                    refs.directory.rename(detached)
                    refs.directory.mkdir()
                    replaced = True
                return original_read(descriptor, byte_limit)

            with mock.patch.object(MODULE, "_read_fd_bounded", side_effect=racing_read):
                issues = MODULE.validate_v2_runs(root)

            self.assertTrue(replaced)
            self.assertTrue(
                any(
                    "run directory identity changed while artifacts were read" in issue
                    for issue in issues
                ),
                issues,
            )
            self.assertNotIn(str(root), "\n".join(issues))

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

    def test_bundle_privacy_detects_sensitive_material_split_across_files(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            coverage_path = refs.directory / "coverage.json"
            coverage = json.loads(coverage_path.read_bytes())
            coverage["rendered_text"] = "Authoriza"
            coverage_path.write_bytes(canonical_json(coverage))
            (refs.directory / "episodes.jsonl").write_bytes(
                canonical_json(
                    {"rendered_text": "tion: Bearer abcdefghijklmnop"}
                )
                + b"\n"
            )
            rewrite_digest(refs.directory)

            issues = MODULE.validate_v2_runs(root)
            rendered = "\n".join(issues)
            self.assertIn(
                f"{refs.directory.relative_to(root).as_posix()}: "
                "content: sensitive authentication material is not allowed",
                rendered,
            )
            self.assertNotIn("abcdefghijklmnop", rendered)
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

    def test_report_templates_are_bound_to_their_summary_section(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            refs = write_bundle(root, 1)
            summary_path = refs.directory / "summary.json"
            summary = json.loads(summary_path.read_bytes())
            summary["friction_and_confusion"] = [
                {
                    "template_id": "retrospective.v2.strength",
                    "slots": [],
                    "rendered_text": "No observation was retained.",
                    "rendering_policy": "retained-template-renderer-v2",
                    "detail_disposition": "rendered",
                }
            ]
            summary_path.write_bytes(canonical_json(summary))
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
