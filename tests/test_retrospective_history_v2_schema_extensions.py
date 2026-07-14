from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SESSION_SCHEMA_PATH = ROOT / "schemas" / "session-retrospective-v2.schema.json"
MANIFEST_SCHEMA_PATH = ROOT / "schemas" / "retained-manifest-v2.schema.json"
RUNTIME_PATH = ROOT / "scripts" / "retrospective_history_v2.py"
SESSION_SCHEMA = json.loads(SESSION_SCHEMA_PATH.read_text(encoding="utf-8"))
MANIFEST_SCHEMA = json.loads(MANIFEST_SCHEMA_PATH.read_text(encoding="utf-8"))
SCHEMA_URI = "https://json-schema.org/draft/2020-12/schema"
LOGICAL_RUN_ID = "ab" * 32
CAMPAIGN_MODES = ("daily", "weekly", "session", "baseline")
PRODUCTION_CONFIGURATION_ROOT = "production_configuration_root_v2:sha256:" + "a" * 64
BOOTSTRAP_GAP_REASONS = (
    "bootstrap_deferred_to_baseline",
    "legacy_horizon_unknown",
    "legacy_out_of_horizon",
)
MODEL_PROVENANCE_FIELDS = (
    "calibration_receipt_refs",
    "job_refs",
    "provider_policy_refs",
    "request_egress_receipt_refs",
)
PATH_LEAK_FIXTURES = (
    ("windows_drive", "C:" + r"\Us" + r"ers\alice\private\source.jsonl"),
    ("windows_forward_slash", "D:" + "/work" + "space/private/source.jsonl"),
    ("windows_unc", "\\\\" + r"file" + r"server\share\source.jsonl"),
    ("mnt", "/" + "mnt/private/source.jsonl"),
    ("quoted_unix", '"' + "/" + "Us" + "ers/alice/private/source.jsonl" + '"'),
    ("single_quoted_unix", "'" + "/" + "private/tmp/source.jsonl" + "'"),
    ("backticked_unix", "`" + "/" + "ho" + "me/alice/private/source.jsonl" + "`"),
)
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
RUNTIME_CONSTRAINTS = (
    {
        "applies_to_publication_role": "campaign_segment",
        "constraint_id": "campaign_segment_ordinal_lte_campaign_segment_count",
        "left_instance_pointer": "/campaign_segment_metadata/segment_ordinal",
        "operator": "less_than_or_equal",
        "right_instance_pointer": "/campaign_segment_count",
        "validator": "scripts/retrospective_history_v2.py:_validate_manifest",
    },
    {
        "constraint_id": "logical_run_id_matches_run_ref_and_history_path",
        "left_instance_pointer": "/run_id",
        "operator": "equals_run_ref_payload_and_bound_history_path",
        "physical_path_validation": "history_validator_only",
        "right_instance_pointer": "/run_ref",
        "validator": "scripts/retrospective_history_v2.py:_validate_manifest",
    },
    {
        "constraint_id": "production_configuration_root_binds_active_provenance",
        "left_instance_pointer": "/production_configuration_root_v2",
        "operator": "commits_exact_active_provenance_refs",
        "right_instance_pointers": [
            "/provenance/active_calibration_receipt_ref",
            "/provenance/active_calibration_model_era_ref",
            "/provenance/active_shadow_receipt_ref",
            "/provenance/active_shadow_model_era_ref",
        ],
        "validator": "scripts/retrospective_history_v2.py:_validate_manifest",
    },
)
V1_SCHEMA_HASHES = {
    ROOT / "schemas" / "session-retrospective-v1.schema.json": (
        "1694f5b91840aede71529455284a387a0" + "7c8c8efc2fe9df616815abf0ab0f297"
    ),
    ROOT / "schemas" / "retained-manifest-v1.schema.json": (
        "65276ca38557e9a94138bf99f617833f" + "4ff5535f55b69195131d7af6f0d65699"
    ),
}

RUNTIME_SPEC = importlib.util.spec_from_file_location(
    "retrospective_history_v2_schema_extension_runtime",
    RUNTIME_PATH,
)
assert RUNTIME_SPEC is not None
assert RUNTIME_SPEC.loader is not None
RUNTIME = importlib.util.module_from_spec(RUNTIME_SPEC)
sys.modules[RUNTIME_SPEC.name] = RUNTIME
RUNTIME_SPEC.loader.exec_module(RUNTIME)


def typed_ref(prefix: str, value: str = "a", width: int = 32) -> str:
    return prefix + value * width


def production_configuration_root(provenance: dict[str, object]) -> str:
    hasher = hashlib.sha256()
    hasher.update(b"session-retrospective-production-configuration-v2")
    for field_name in (
        "active_calibration_receipt_ref",
        "active_calibration_model_era_ref",
        "active_shadow_receipt_ref",
        "active_shadow_model_era_ref",
    ):
        for frame_type, value in (
            (b"N", field_name.encode("ascii")),
            (b"V", str(provenance[field_name]).encode("ascii")),
        ):
            hasher.update(frame_type)
            hasher.update(len(value).to_bytes(8, "big"))
            hasher.update(value)
    return f"production_configuration_root_v2:sha256:{hasher.hexdigest()}"


def normalize_session_refs(value: object) -> object:
    if isinstance(value, list):
        return [normalize_session_refs(item) for item in value]
    if not isinstance(value, dict):
        return value

    normalized: dict[str, object] = {}
    for key, item in value.items():
        if key == "$ref" and isinstance(item, str):
            prefix = "session-retrospective-v2.schema.json#"
            normalized[key] = (
                "#" + item[len(prefix) :] if item.startswith(prefix) else item
            )
        else:
            normalized[key] = normalize_session_refs(item)
    return normalized


def definition_validator(name: str) -> Draft202012Validator:
    schema = {
        "$schema": SCHEMA_URI,
        "$defs": SESSION_SCHEMA["$defs"],
        "$ref": f"#/$defs/{name}",
    }
    return Draft202012Validator(schema)


def full_manifest_validator(manifest_schema: dict[str, object]) -> Draft202012Validator:
    normalized = normalize_session_refs(copy.deepcopy(manifest_schema))
    assert isinstance(normalized, dict)
    normalized["$schema"] = SCHEMA_URI
    normalized["$defs"] = SESSION_SCHEMA["$defs"]
    Draft202012Validator.check_schema(normalized)
    return Draft202012Validator(normalized)


MANIFEST_VALIDATORS = (
    full_manifest_validator(SESSION_SCHEMA["$defs"]["manifest"]),
    full_manifest_validator(MANIFEST_SCHEMA),
)


def head_pair(value: str) -> dict[str, str]:
    return {
        "expected_head_ref": "absent_v2",
        "proposed_head_ref": typed_ref("head_ref_v2:", value),
    }


def canonical_head_bindings() -> dict[str, object]:
    return {
        "bound_quarantine_generation_ref": typed_ref("quarantine_generation_ref_v2:"),
        "cursor_heads": [],
        "source_accounting": {
            "global": head_pair("1"),
            "unit_corrections": [],
        },
        "semantic_repair": head_pair("2"),
        "session_identity": head_pair("3"),
        "turn_screening": head_pair("4"),
        "episode": head_pair("5"),
        "workstream": head_pair("6"),
        "continuation": head_pair("7"),
        "topic": head_pair("8"),
        "run_validity": head_pair("9"),
    }


def segment_head_bindings() -> dict[str, object]:
    return {
        "bound_quarantine_generation_ref": typed_ref("quarantine_generation_ref_v2:"),
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


def gap_summary() -> dict[str, object]:
    return {
        "source_repairable_gap_count": 0,
        "semantic_repairable_gap_count": 0,
        "terminal_gap_count": 0,
        "terminal_authorization_usage_refs": [],
        "unaccounted_source_unit_count": 0,
        "privacy_breach_count": 0,
    }


def supersession(reason: str = "initial") -> dict[str, object]:
    return {
        "reason": reason,
        "supersedes_run_revision_refs": [],
        "supersedes_episode_revision_refs": [],
        "supersedes_topic_revision_refs": [],
        "supersedes_turn_finding_revision_refs": [],
    }


def segment_metadata(ordinal: int = 1) -> dict[str, object]:
    return {
        "segment_ordinal": ordinal,
        "leaf_root_refs": [typed_ref("campaign_leaf_root_ref_v2:")],
        "page_root_refs": [typed_ref("campaign_page_root_ref_v2:")],
    }


def artifact_inventory() -> list[dict[str, object]]:
    definitions = SESSION_SCHEMA["$defs"]["artifact_inventory"]["prefixItems"]
    inventory = []
    for definition in definitions:
        properties = definition["properties"]
        inventory.append(
            {field: properties[field]["const"] for field in definition["required"]}
        )
    return inventory


def manifest_window(mode: str) -> dict[str, object]:
    if mode in {"weekly", "baseline"}:
        path_component = "2026-07-07_to_2026-07-14"
        start = "2026-07-07T00:00:00Z"
    else:
        path_component = "2026-07-13"
        start = "2026-07-13T00:00:00Z"
    window: dict[str, object] = {
        "mode": mode,
        "path_component": path_component,
        "start": start,
        "end": "2026-07-14T00:00:00Z",
    }
    if mode == "session":
        window["target_session_refs"] = [typed_ref("session_ref_v2:")]
    return window


def era_catalog(with_model_provenance: bool) -> dict[str, object]:
    policy_versions = {
        field: 1 for field in SESSION_SCHEMA["$defs"]["policy_versions"]["required"]
    }
    model_eras: list[dict[str, object]] = []
    if with_model_provenance:
        model_eras.append(
            {
                "model_era_ref": typed_ref("model_era_ref_v2:"),
                "predecessor_model_era_ref": None,
                "compatibility": "baseline",
                "job_profiles": [
                    {
                        "job_kind": "synthesis",
                        "model_id": "gpt-5.6-sol",
                        "service_tier": "default",
                        "reasoning_effort": "xhigh",
                        "parameter_set_ref": typed_ref("parameter_set_ref_v2:"),
                    }
                ],
            }
        )
    return {
        "policy_eras": [
            {
                "policy_era_ref": typed_ref("policy_era_ref_v2:"),
                "predecessor_policy_era_ref": None,
                "compatibility": "baseline",
                "versions": policy_versions,
            }
        ],
        "model_eras": model_eras,
        "comparison_rule": "stratify-compatible-policy-and-model-eras",
    }


def run_provenance(with_model_provenance: bool) -> dict[str, object]:
    operational_counts = {
        field: 0 for field in SESSION_SCHEMA["$defs"]["operational_counts"]["required"]
    }
    return {
        "active_calibration_receipt_ref": typed_ref("receipt_ref_v2:", "6"),
        "active_calibration_model_era_ref": typed_ref("model_era_ref_v2:"),
        "active_shadow_receipt_ref": typed_ref("receipt_ref_v2:", "8"),
        "active_shadow_model_era_ref": typed_ref("model_era_ref_v2:"),
        "engine_repository": "codex-workflow-hygiene",
        "engine_commit": "a" * 40,
        "retained_schema_version": 2,
        "execution_schema_version": 2,
        "source_snapshot_refs": [typed_ref("source_snapshot_ref_v2:")],
        "identity_backup_receipt_ref": typed_ref("receipt_ref_v2:", "1"),
        "job_refs": [typed_ref("job_ref_v2:")] if with_model_provenance else [],
        "provider_policy_refs": (
            [typed_ref("provider_policy_ref_v2:")] if with_model_provenance else []
        ),
        "request_egress_receipt_refs": (
            [typed_ref("receipt_ref_v2:", "2")] if with_model_provenance else []
        ),
        "clock_receipt_ref": typed_ref("receipt_ref_v2:", "3"),
        "containment_receipt_refs": [typed_ref("receipt_ref_v2:", "4")],
        "storage_control_receipt_refs": [typed_ref("receipt_ref_v2:", "5")],
        "calibration_receipt_refs": (
            [typed_ref("receipt_ref_v2:", "6")] if with_model_provenance else []
        ),
        "capacity_generation": 1,
        "reserved_max_pack_count": 64,
        "reserved_max_pack_bytes": 1048576,
        "locked_first_parent_object_id": "b" * 40,
        "publication_attempt_ref": typed_ref("publication_attempt_ref_v2:"),
        "publisher_metadata_policy_version": 1,
        "publisher_signature_policy_version": 1,
        "operational_counts": operational_counts,
    }


def full_manifest(
    *,
    execution_kind: str = "retrospective",
    publication_role: str = "standalone",
    mode: str = "daily",
    with_model_provenance: bool | None = None,
) -> dict[str, object]:
    if with_model_provenance is None:
        with_model_provenance = execution_kind == "retrospective"

    status = "complete"
    summary = gap_summary()
    supersession_value = supersession()
    if execution_kind == "compliance_retraction":
        status = "complete_with_terminal_gaps"
        summary.update(
            {
                "terminal_gap_count": 1,
                "privacy_breach_count": 1,
            }
        )
        supersession_value = supersession("compliance_retraction")
        supersession_value["supersedes_run_revision_refs"] = [
            typed_ref("run_revision_ref_v2:", "b")
        ]

    manifest: dict[str, object] = {
        "artifact_type": "manifest",
        "schema_version": 2,
        "execution_kind": execution_kind,
        "publication_role": publication_role,
        "mode": mode,
        "window": manifest_window(mode),
        "run_id": LOGICAL_RUN_ID,
        "run_input_ref": typed_ref("run_input_ref_v2:"),
        "run_ref": "run_ref_v2:" + LOGICAL_RUN_ID,
        "run_revision_ref": typed_ref("run_revision_ref_v2:"),
        "key_ids": [typed_ref("key_id_v2:", width=16)],
        "prepared_at": "2026-07-14T00:00:00Z",
        "status": status,
        "gap_summary": summary,
        "supersession": supersession_value,
        "artifact_inventory": artifact_inventory(),
        "retained_bundle_digest_v2": "retained_bundle_digest_v2:sha256:" + "a" * 64,
        "bundle_digest_contract": {
            "algorithm": "sha-256",
            "domain_tag": "session-retrospective-retained-bundle-v2",
            "ordering": "bytewise-basename",
            "framing": "typed-name-length-v2",
            "manifest_projection": "omit-retained_bundle_digest_v2-only",
        },
        "head_bindings": canonical_head_bindings(),
        "eras": era_catalog(with_model_provenance),
        "provenance": run_provenance(with_model_provenance),
        "production_configuration_root_v2": PRODUCTION_CONFIGURATION_ROOT,
        "retention_contract": {
            "retention_safe": True,
            "opaque_references_only": True,
            "raw_identifiers_retained": False,
            "source_specific_prose_retained": False,
            "text_policy": "template-and-typed-slots-v2",
            "renderer_byte_equality_required": True,
        },
    }
    provenance = manifest["provenance"]
    assert isinstance(provenance, dict)
    manifest["production_configuration_root_v2"] = production_configuration_root(
        provenance
    )
    if publication_role in {"campaign_segment", "campaign_root"}:
        manifest["publication_campaign_reason"] = (
            "baseline_window" if mode == "baseline" else "size_partition"
        )
    if publication_role == "campaign_segment":
        manifest.update(
            {
                "campaign_ref": typed_ref("campaign_ref_v2:"),
                "campaign_segment_count": 2,
                "campaign_segment_metadata": segment_metadata(),
                "head_bindings": segment_head_bindings(),
            }
        )
    elif publication_role == "campaign_root":
        manifest.update(
            {
                "campaign_ref": typed_ref("campaign_ref_v2:"),
                "campaign_segment_count": 2,
                "campaign_segment_root_v2": (
                    "campaign_segment_root_v2:sha256:" + "a" * 64
                ),
            }
        )
    return manifest


def assert_valid_for_both(test: unittest.TestCase, value: object) -> None:
    for validator in MANIFEST_VALIDATORS:
        errors = list(validator.iter_errors(value))
        test.assertEqual(errors, [], [error.message for error in errors])


def assert_invalid_for_both(test: unittest.TestCase, value: object) -> None:
    for validator in MANIFEST_VALIDATORS:
        test.assertTrue(list(validator.iter_errors(value)))


def coverage_gap(reason: str, authorization_usage_ref: str | None) -> dict[str, object]:
    return {
        "gap_ref": typed_ref("gap_ref_v2:"),
        "gap_revision_ref": typed_ref("gap_revision_ref_v2:"),
        "predecessor_gap_revision_ref": None,
        "scope": "publication",
        "stage": "finalize",
        "reason": reason,
        "repairability": "terminal_policy",
        "host_ref": None,
        "source_ref": None,
        "source_unit_ref": None,
        "turn_ref": None,
        "episode_ref": None,
        "topic_ref": None,
        "affected_unit_count": 1,
        "affected_byte_count": 0,
        "evidence_commitment_refs": [typed_ref("evidence_commitment_ref_v2:")],
        "authorization_usage_ref": authorization_usage_ref,
    }


def rendered_report(extra_text: str = "") -> str:
    body = (
        "Generalized retained observation with bounded evidence and no source-specific "
        "identifiers."
    )
    parts = ["# Session Retrospective"]
    for index, heading in enumerate(REPORT_SECTION_HEADINGS):
        section_body = f"{extra_text} {body}" if index == 0 and extra_text else body
        parts.extend((f"## {heading}", section_body))
    return "\n\n".join(parts) + "\n"


def runtime_manifest_issues(manifest: dict[str, object]) -> list[str]:
    window = manifest["window"]
    assert isinstance(window, dict)
    bundle = RUNTIME.Bundle(
        label="manifest-runtime-test",
        mode=str(manifest["mode"]),
        window_component=str(window["path_component"]),
        run_id=str(manifest["run_id"]),
        files={},
        documents={"manifest.json": manifest},
    )
    issues: list[str] = []
    RUNTIME._validate_manifest(bundle, issues)
    return issues


class RetrospectiveHistoryV2SchemaExtensionTests(unittest.TestCase):
    def test_schemas_meta_validate_and_manifest_contracts_match(self) -> None:
        for path, schema in (
            (SESSION_SCHEMA_PATH, SESSION_SCHEMA),
            (MANIFEST_SCHEMA_PATH, MANIFEST_SCHEMA),
        ):
            with self.subTest(path=path.name):
                self.assertEqual(schema["$schema"], SCHEMA_URI)
                Draft202012Validator.check_schema(schema)

        retained_contract = {
            key: value
            for key, value in MANIFEST_SCHEMA.items()
            if key not in {"$schema", "$comment", "description", "title"}
        }
        self.assertEqual(
            normalize_session_refs(retained_contract),
            SESSION_SCHEMA["$defs"]["manifest"],
        )
        self.assertIn(
            "publication_role", SESSION_SCHEMA["$defs"]["manifest"]["required"]
        )
        self.assertIn("publication_role", MANIFEST_SCHEMA["required"])
        self.assertIn(
            "production_configuration_root_v2",
            SESSION_SCHEMA["$defs"]["manifest"]["required"],
        )
        self.assertIn("production_configuration_root_v2", MANIFEST_SCHEMA["required"])
        active_provenance_fields = {
            "active_calibration_receipt_ref",
            "active_calibration_model_era_ref",
            "active_shadow_receipt_ref",
            "active_shadow_model_era_ref",
        }
        self.assertTrue(
            active_provenance_fields.issubset(
                SESSION_SCHEMA["$defs"]["run_provenance"]["required"]
            )
        )
        self.assertFalse(SESSION_SCHEMA["$defs"]["manifest"]["additionalProperties"])
        self.assertFalse(MANIFEST_SCHEMA["additionalProperties"])

    def test_v1_schema_hashes_remain_unchanged(self) -> None:
        for path, expected in V1_SCHEMA_HASHES.items():
            with self.subTest(path=path.name):
                self.assertEqual(
                    hashlib.sha256(path.read_bytes()).hexdigest(), expected
                )

    def test_bootstrap_execution_and_gap_taxonomy_are_closed(self) -> None:
        execution_validator = definition_validator("execution_kind")
        for execution_kind in (
            "retrospective",
            "bootstrap_v2",
            "compliance_retraction",
        ):
            self.assertEqual(list(execution_validator.iter_errors(execution_kind)), [])
        self.assertTrue(list(execution_validator.iter_errors("bootstrap")))

        bootstrap_validator = definition_validator("bootstrap_gap_reason")
        gap_validator = definition_validator("gap_reason")
        for reason in BOOTSTRAP_GAP_REASONS:
            with self.subTest(reason=reason):
                self.assertEqual(list(bootstrap_validator.iter_errors(reason)), [])
                self.assertEqual(list(gap_validator.iter_errors(reason)), [])
        self.assertTrue(list(bootstrap_validator.iter_errors("legacy_gap")))

    def test_logical_run_identity_uses_256_bit_lowercase_hex(self) -> None:
        run_id_validator = definition_validator("run_id")
        run_ref_validator = definition_validator("run_ref")
        self.assertEqual(list(run_id_validator.iter_errors(LOGICAL_RUN_ID)), [])
        self.assertEqual(
            list(run_ref_validator.iter_errors("run_ref_v2:" + LOGICAL_RUN_ID)),
            [],
        )

        physical_split_path = "/".join(
            LOGICAL_RUN_ID[index : index + 2] for index in range(0, 64, 2)
        )
        for value in (
            "run_v2_" + "a" * 24,
            "a" * 63,
            "a" * 65,
            "A" * 64,
            "g" * 64,
            physical_split_path,
        ):
            with self.subTest(run_id=value):
                self.assertTrue(list(run_id_validator.iter_errors(value)))

        for value in (
            "run_ref_v2:" + "a" * 32,
            "run_ref_v2:" + "A" * 64,
            "run_ref_v2:" + physical_split_path,
            "run_v2_ref:" + LOGICAL_RUN_ID,
        ):
            with self.subTest(run_ref=value):
                self.assertTrue(list(run_ref_validator.iter_errors(value)))

        manifest = full_manifest()
        self.assertEqual(manifest["run_id"], LOGICAL_RUN_ID)
        self.assertEqual(manifest["run_ref"], "run_ref_v2:" + LOGICAL_RUN_ID)
        assert_valid_for_both(self, manifest)

        mismatched_payload = copy.deepcopy(manifest)
        mismatched_payload["run_ref"] = "run_ref_v2:" + "cd" * 32
        # JSON Schema validates each opaque value; the history validator binds them.
        assert_valid_for_both(self, mismatched_payload)
        self.assertIn(
            "run_ref payload must match run_id",
            "\n".join(runtime_manifest_issues(mismatched_payload)),
        )

    def test_full_manifests_allow_truthful_no_model_lifecycle_provenance(self) -> None:
        retrospective = full_manifest()
        assert_valid_for_both(self, retrospective)

        no_model_retrospective = full_manifest(with_model_provenance=False)
        assert_invalid_for_both(self, no_model_retrospective)

        for execution_kind in ("bootstrap_v2", "compliance_retraction"):
            with self.subTest(execution_kind=execution_kind):
                lifecycle = full_manifest(execution_kind=execution_kind)
                eras = lifecycle["eras"]
                provenance = lifecycle["provenance"]
                assert isinstance(eras, dict)
                assert isinstance(provenance, dict)
                self.assertEqual(eras["model_eras"], [])
                for field in MODEL_PROVENANCE_FIELDS:
                    self.assertEqual(provenance[field], [])
                assert_valid_for_both(self, lifecycle)

        bootstrap_terminal = full_manifest(execution_kind="bootstrap_v2")
        bootstrap_terminal["status"] = "complete_with_terminal_gaps"
        bootstrap_terminal["gap_summary"]["terminal_gap_count"] = 1
        assert_valid_for_both(self, bootstrap_terminal)

        empty_bootstrap_terminal = copy.deepcopy(bootstrap_terminal)
        empty_bootstrap_terminal["gap_summary"]["terminal_gap_count"] = 0
        assert_invalid_for_both(self, empty_bootstrap_terminal)

    def test_production_configuration_commitment_and_active_refs_are_required(
        self,
    ) -> None:
        root_validator = definition_validator("production_configuration_root_v2")
        self.assertEqual(
            list(root_validator.iter_errors(PRODUCTION_CONFIGURATION_ROOT)), []
        )

        malformed_roots = (
            "a" * 64,
            "production_configuration_root_v2:sha256:" + "a" * 63,
            "production_configuration_root_v2:sha256:" + "a" * 65,
            "production_configuration_root_v2:sha256:" + "A" * 64,
            "production_configuration_root_v2:sha256:" + "g" * 64,
            "production_configuration_root_v1:sha256:" + "a" * 64,
        )
        for value in malformed_roots:
            with self.subTest(target="definition", value=value):
                self.assertTrue(list(root_validator.iter_errors(value)))

        malformed_active_refs = {
            "active_calibration_receipt_ref": "receipt_ref_v2:" + "A" * 32,
            "active_calibration_model_era_ref": "model_era_ref_v2:" + "a" * 31,
            "active_shadow_receipt_ref": "receipt_ref_v1:" + "a" * 32,
            "active_shadow_model_era_ref": "model_era_ref_v2:" + "g" * 32,
        }
        for execution_kind in (
            "retrospective",
            "bootstrap_v2",
            "compliance_retraction",
        ):
            manifest = full_manifest(execution_kind=execution_kind)
            assert_valid_for_both(self, manifest)

            with self.subTest(execution_kind=execution_kind, target="missing_root"):
                missing_root = copy.deepcopy(manifest)
                missing_root.pop("production_configuration_root_v2")
                assert_invalid_for_both(self, missing_root)

            for value in malformed_roots:
                with self.subTest(
                    execution_kind=execution_kind,
                    target="malformed_root",
                    value=value,
                ):
                    malformed_root = copy.deepcopy(manifest)
                    malformed_root["production_configuration_root_v2"] = value
                    assert_invalid_for_both(self, malformed_root)

            for field, malformed_value in malformed_active_refs.items():
                with self.subTest(
                    execution_kind=execution_kind,
                    target="missing_active_ref",
                    field=field,
                ):
                    missing_ref = copy.deepcopy(manifest)
                    missing_ref["provenance"].pop(field)
                    assert_invalid_for_both(self, missing_ref)

                with self.subTest(
                    execution_kind=execution_kind,
                    target="malformed_active_ref",
                    field=field,
                ):
                    malformed_ref = copy.deepcopy(manifest)
                    malformed_ref["provenance"][field] = malformed_value
                    assert_invalid_for_both(self, malformed_ref)

    def test_retained_provenance_allows_only_pre_tree_remote_upload_fields(
        self,
    ) -> None:
        provenance_schema = SESSION_SCHEMA["$defs"]["run_provenance"]
        properties = set(provenance_schema["properties"])
        required = set(provenance_schema["required"])
        pre_tree_fields = {
            "capacity_generation",
            "reserved_max_pack_count",
            "reserved_max_pack_bytes",
            "locked_first_parent_object_id",
            "publication_attempt_ref",
        }
        post_tree_fields = {
            "actual_pack_count",
            "actual_pack_bytes",
            "pack_count",
            "pack_bytes",
            "prefix_pack_root",
            "prefix_pack_root_v2",
            "seal_state",
            "transaction_id",
            "transaction_ref",
            "prepared_transaction_ref",
            "locked_parent_object_id",
            "expected_quarantine_generation_head",
            "future_commit_id",
            "future_commit_object_id",
            "working_cleanup_state",
            "expected_working_cleanup_ref",
            "cleanup_receipt_ref",
            "ownership_transfer_receipt_ref",
        }
        self.assertTrue(pre_tree_fields.issubset(properties))
        self.assertTrue(pre_tree_fields.issubset(required))
        self.assertFalse(post_tree_fields & properties)
        self.assertFalse(post_tree_fields & required)
        self.assertEqual(
            provenance_schema["properties"]["locked_first_parent_object_id"]["$ref"],
            "#/$defs/engine_commit",
        )

        attempt_validator = definition_validator("publication_attempt_ref")
        valid_attempt_ref = typed_ref("publication_attempt_ref_v2:")
        self.assertEqual(list(attempt_validator.iter_errors(valid_attempt_ref)), [])
        for value in (
            typed_ref("publication_attempt_ref_v1:"),
            "publication_attempt_ref_v2:" + "a" * 31,
            "publication_attempt_ref_v2:" + "A" * 32,
        ):
            with self.subTest(target="publication_attempt_ref", value=value):
                self.assertTrue(list(attempt_validator.iter_errors(value)))

        for execution_kind in (
            "retrospective",
            "bootstrap_v2",
            "compliance_retraction",
        ):
            manifest = full_manifest(execution_kind=execution_kind)
            assert_valid_for_both(self, manifest)
            for field in pre_tree_fields:
                with self.subTest(
                    execution_kind=execution_kind,
                    target="missing_pre_tree_field",
                    field=field,
                ):
                    missing = copy.deepcopy(manifest)
                    missing["provenance"].pop(field)
                    assert_invalid_for_both(self, missing)

        malformed_pre_tree_values = {
            "capacity_generation": -1,
            "reserved_max_pack_count": -1,
            "reserved_max_pack_bytes": -1,
            "locked_first_parent_object_id": "B" * 40,
            "publication_attempt_ref": "publication_attempt_ref_v2:" + "g" * 32,
        }
        manifest = full_manifest()
        for field, value in malformed_pre_tree_values.items():
            with self.subTest(target="malformed_pre_tree_field", field=field):
                malformed = copy.deepcopy(manifest)
                malformed["provenance"][field] = value
                assert_invalid_for_both(self, malformed)

        post_tree_values = {
            "actual_pack_count": 1,
            "actual_pack_bytes": 1024,
            "pack_count": 1,
            "pack_bytes": 1024,
            "prefix_pack_root": "prefix_pack_root_v2:sha256:" + "a" * 64,
            "prefix_pack_root_v2": "prefix_pack_root_v2:sha256:" + "a" * 64,
            "seal_state": "sealed",
            "transaction_id": "synthetic-post-tree-transaction",
            "transaction_ref": typed_ref("transaction_ref_v2:"),
            "prepared_transaction_ref": typed_ref("transaction_ref_v2:"),
            "locked_parent_object_id": "b" * 40,
            "expected_quarantine_generation_head": "b" * 40,
            "future_commit_id": "c" * 40,
            "future_commit_object_id": "c" * 40,
            "working_cleanup_state": "cleanup_pending",
            "expected_working_cleanup_ref": typed_ref("receipt_ref_v2:"),
            "cleanup_receipt_ref": typed_ref("receipt_ref_v2:"),
            "ownership_transfer_receipt_ref": typed_ref("receipt_ref_v2:"),
        }
        for field, value in post_tree_values.items():
            with self.subTest(target="post_tree_field", field=field):
                post_tree = copy.deepcopy(manifest)
                post_tree["provenance"][field] = value
                assert_invalid_for_both(self, post_tree)

    def test_publication_roles_bind_campaign_reason_mode_and_execution_kind(
        self,
    ) -> None:
        role_validator = definition_validator("publication_role")
        for role in ("standalone", "campaign_segment", "campaign_root"):
            self.assertEqual(list(role_validator.iter_errors(role)), [])
        self.assertTrue(list(role_validator.iter_errors("segment")))

        reason_validator = definition_validator("publication_campaign_reason")
        for reason in ("size_partition", "baseline_window"):
            self.assertEqual(list(reason_validator.iter_errors(reason)), [])
        self.assertTrue(list(reason_validator.iter_errors("manual_partition")))

        for mode in CAMPAIGN_MODES:
            with self.subTest(role="standalone", mode=mode):
                assert_valid_for_both(self, full_manifest(mode=mode))

            expected_reason = (
                "baseline_window" if mode == "baseline" else "size_partition"
            )
            wrong_reason = "size_partition" if mode == "baseline" else "baseline_window"
            for role in ("campaign_segment", "campaign_root"):
                with self.subTest(role=role, mode=mode, case="valid"):
                    campaign = full_manifest(publication_role=role, mode=mode)
                    self.assertEqual(
                        campaign["publication_campaign_reason"], expected_reason
                    )
                    assert_valid_for_both(self, campaign)

                with self.subTest(role=role, mode=mode, case="missing_reason"):
                    missing_reason = copy.deepcopy(campaign)
                    missing_reason.pop("publication_campaign_reason")
                    assert_invalid_for_both(self, missing_reason)

                with self.subTest(role=role, mode=mode, case="wrong_reason"):
                    inconsistent_reason = copy.deepcopy(campaign)
                    inconsistent_reason["publication_campaign_reason"] = wrong_reason
                    assert_invalid_for_both(self, inconsistent_reason)

        standalone = full_manifest()
        campaign_only_fields = {
            "publication_campaign_reason": "size_partition",
            "campaign_ref": typed_ref("campaign_ref_v2:"),
            "campaign_segment_count": 2,
            "campaign_segment_metadata": segment_metadata(),
            "campaign_segment_root_v2": ("campaign_segment_root_v2:sha256:" + "a" * 64),
        }
        for field, value in campaign_only_fields.items():
            with self.subTest(role="standalone", unexpected_field=field):
                unexpected_campaign = copy.deepcopy(standalone)
                unexpected_campaign[field] = value
                assert_invalid_for_both(self, unexpected_campaign)

        bootstrap_segment = full_manifest(
            execution_kind="bootstrap_v2",
            publication_role="campaign_segment",
            mode="baseline",
        )
        assert_invalid_for_both(self, bootstrap_segment)

        compliance_segment = full_manifest(
            execution_kind="compliance_retraction",
            publication_role="campaign_segment",
            mode="daily",
        )
        assert_invalid_for_both(self, compliance_segment)

        segment = full_manifest(publication_role="campaign_segment", mode="daily")
        canonical_segment = copy.deepcopy(segment)
        canonical_segment["head_bindings"] = canonical_head_bindings()
        assert_invalid_for_both(self, canonical_segment)

        segment_with_root = copy.deepcopy(segment)
        segment_with_root["campaign_segment_root_v2"] = (
            "campaign_segment_root_v2:sha256:" + "a" * 64
        )
        assert_invalid_for_both(self, segment_with_root)

        root_with_segment_rows = full_manifest(
            publication_role="campaign_root",
            mode="weekly",
        )
        root_with_segment_rows["campaign_segment_metadata"] = segment_metadata()
        assert_invalid_for_both(self, root_with_segment_rows)

        for mode in CAMPAIGN_MODES:
            with self.subTest(role="campaign_root", mode=mode, lifecycle=True):
                lifecycle_root = full_manifest(
                    execution_kind="compliance_retraction",
                    publication_role="campaign_root",
                    mode=mode,
                )
                assert_valid_for_both(self, lifecycle_root)

                invalid_lifecycle_reason = copy.deepcopy(lifecycle_root)
                invalid_lifecycle_reason["publication_campaign_reason"] = (
                    "size_partition" if mode == "baseline" else "baseline_window"
                )
                assert_invalid_for_both(self, invalid_lifecycle_reason)

        bootstrap_root = full_manifest(
            execution_kind="bootstrap_v2",
            publication_role="campaign_root",
            mode="baseline",
        )
        assert_invalid_for_both(self, bootstrap_root)

    def test_manifest_mode_matches_window_and_targets_only_session_runs(self) -> None:
        daily = full_manifest()
        assert_valid_for_both(self, daily)

        mismatched_mode = copy.deepcopy(daily)
        mismatched_mode["window"]["mode"] = "weekly"
        assert_invalid_for_both(self, mismatched_mode)

        daily_target = copy.deepcopy(daily)
        daily_target["window"]["target_session_refs"] = [typed_ref("session_ref_v2:")]
        assert_invalid_for_both(self, daily_target)

        session = full_manifest(mode="session")
        assert_valid_for_both(self, session)

        session_without_target = copy.deepcopy(session)
        session_without_target["window"]["target_session_refs"] = []
        assert_invalid_for_both(self, session_without_target)

        session_without_field = copy.deepcopy(session)
        session_without_field["window"].pop("target_session_refs")
        assert_invalid_for_both(self, session_without_field)

    def test_campaign_ordinal_runtime_constraint_rejects_three_of_two(self) -> None:
        for schema in (SESSION_SCHEMA["$defs"]["manifest"], MANIFEST_SCHEMA):
            self.assertEqual(
                schema["x-runtime-constraints"],
                list(RUNTIME_CONSTRAINTS),
            )

        segment = full_manifest(publication_role="campaign_segment", mode="baseline")
        segment["campaign_segment_metadata"]["segment_ordinal"] = 2
        assert_valid_for_both(self, segment)
        self.assertNotIn(
            "campaign segment ordinal exceeds campaign segment count",
            "\n".join(runtime_manifest_issues(segment)),
        )

        out_of_range = copy.deepcopy(segment)
        out_of_range["campaign_segment_metadata"]["segment_ordinal"] = 3
        # Draft 2020-12 cannot compare sibling instance values; the declared runtime gate does.
        assert_valid_for_both(self, out_of_range)
        self.assertIn(
            "campaign segment ordinal exceeds campaign segment count",
            "\n".join(runtime_manifest_issues(out_of_range)),
        )

    def test_canonical_heads_bind_run_validity_and_quarantine_generation(self) -> None:
        validator = definition_validator("publication_head_bindings")
        bindings = canonical_head_bindings()
        self.assertEqual(list(validator.iter_errors(bindings)), [])

        for field in ("run_validity", "bound_quarantine_generation_ref"):
            with self.subTest(field=field):
                invalid = copy.deepcopy(bindings)
                invalid.pop(field)
                self.assertTrue(list(validator.iter_errors(invalid)))

        segment_validator = definition_validator("campaign_segment_head_bindings")
        segment_bindings = segment_head_bindings()
        self.assertEqual(list(segment_validator.iter_errors(segment_bindings)), [])
        segment_bindings["run_validity"] = head_pair("c")
        self.assertTrue(list(segment_validator.iter_errors(segment_bindings)))

    def test_compliance_retraction_has_closed_lifecycle_contract(self) -> None:
        self.assertEqual(
            list(
                definition_validator("revision_kind").iter_errors(
                    "compliance_retraction"
                )
            ),
            [],
        )

        retraction = full_manifest(execution_kind="compliance_retraction")
        assert_valid_for_both(self, retraction)

        authorized_retraction = copy.deepcopy(retraction)
        authorized_retraction["gap_summary"]["terminal_authorization_usage_refs"] = [
            typed_ref("authorization_usage_ref_v2:")
        ]
        assert_invalid_for_both(self, authorized_retraction)

        no_breach = copy.deepcopy(retraction)
        no_breach["gap_summary"]["privacy_breach_count"] = 0
        assert_invalid_for_both(self, no_breach)

        wrong_revision = copy.deepcopy(retraction)
        wrong_revision["supersession"]["reason"] = "correction"
        assert_invalid_for_both(self, wrong_revision)

        ordinary_terminal = full_manifest()
        ordinary_terminal["status"] = "complete_with_terminal_gaps"
        ordinary_terminal["gap_summary"] = {
            **gap_summary(),
            "terminal_gap_count": 1,
            "terminal_authorization_usage_refs": [
                typed_ref("authorization_usage_ref_v2:")
            ],
        }
        assert_valid_for_both(self, ordinary_terminal)
        ordinary_terminal["gap_summary"]["terminal_authorization_usage_refs"] = []
        assert_invalid_for_both(self, ordinary_terminal)

    def test_terminal_policy_authorization_uses_explicit_allowlist(self) -> None:
        validator = definition_validator("coverage_gap")
        authorizable = set(
            SESSION_SCHEMA["$defs"]["terminal_authorizable_gap_reason"]["enum"]
        )
        non_authorizable = set(
            SESSION_SCHEMA["$defs"]["non_authorizable_terminal_gap_reason"]["enum"]
        )
        self.assertFalse(authorizable & non_authorizable)
        self.assertIn("oversized_record_unprocessed", authorizable)
        self.assertNotIn("provider_retention_unverified", authorizable)

        ordinary_terminal = coverage_gap("oversized_record_unprocessed", None)
        self.assertTrue(list(validator.iter_errors(ordinary_terminal)))
        ordinary_terminal["authorization_usage_ref"] = typed_ref(
            "authorization_usage_ref_v2:"
        )
        self.assertEqual(list(validator.iter_errors(ordinary_terminal)), [])

        for reason in (
            "provider_retention_unverified",
            "provider_retention_window_exceeded",
            "source_disappeared",
            "legacy_horizon_unknown",
            "legacy_out_of_horizon",
            "provider_retention_breach",
        ):
            with self.subTest(reason=reason):
                terminal = coverage_gap(reason, None)
                self.assertEqual(list(validator.iter_errors(terminal)), [])

                authorized = copy.deepcopy(terminal)
                authorized["authorization_usage_ref"] = typed_ref(
                    "authorization_usage_ref_v2:"
                )
                self.assertTrue(list(validator.iter_errors(authorized)))

                repairable = copy.deepcopy(terminal)
                repairable["repairability"] = "repairable"
                self.assertTrue(list(validator.iter_errors(repairable)))

        deferred = coverage_gap(
            "bootstrap_deferred_to_baseline",
            typed_ref("authorization_usage_ref_v2:"),
        )
        self.assertEqual(list(validator.iter_errors(deferred)), [])

    def test_rendered_prose_and_reports_reject_sensitive_path_shapes(self) -> None:
        rendered_validator = definition_validator("rendered_text")
        report_validator = definition_validator("report_markdown")
        self.assertEqual(
            list(rendered_validator.iter_errors("Generalized retained observation.")),
            [],
        )
        self.assertEqual(list(report_validator.iter_errors(rendered_report())), [])

        for name, path_value in PATH_LEAK_FIXTURES:
            with self.subTest(name=name, target="rendered_text"):
                rendered = (
                    f"Generalized observation referenced {path_value} during review."
                )
                self.assertTrue(list(rendered_validator.iter_errors(rendered)))
            with self.subTest(name=name, target="report_markdown"):
                self.assertTrue(
                    list(report_validator.iter_errors(rendered_report(path_value)))
                )


if __name__ == "__main__":
    unittest.main()
