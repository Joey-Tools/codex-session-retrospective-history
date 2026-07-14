#!/usr/bin/env python3
from __future__ import annotations

import json
import math
import re
from typing import Any


DETAIL_TEMPLATE_ID = "retrospective.v2.detail_not_retained"
DETAIL_RENDERED_TEXT = "Detail was not retained under the v2 retained-language policy."

TEMPLATE_HEADINGS = {
    "retrospective.v2.what_happened": "What Happened",
    "retrospective.v2.strength": "What Worked Well",
    "retrospective.v2.friction": "Friction And Confusion",
    "retrospective.v2.error_or_retry": "Errors And Verification",
    "retrospective.v2.collaboration_pattern": "Collaboration Patterns",
    "retrospective.v2.safety_privacy": "Safety And Privacy",
    "retrospective.v2.problem_statement": "Prompt Improvements",
    "retrospective.v2.cause": "Prompt Improvements",
    "retrospective.v2.prompt_rewrite": "Prompt Improvements",
    "retrospective.v2.expected_effect": "Prompt Improvements",
    "retrospective.v2.recommendation": "Follow-up Actions",
    "retrospective.v2.agents_guidance": "Durable AGENTS.md Guidance",
    "retrospective.v2.skill_candidate": "Reusable Skill Candidates",
    "retrospective.v2.follow_up": "Follow-up Actions",
    "retrospective.v2.change_summary": "Change From Prior Compatible Period",
    "retrospective.v2.no_observation": "No Observation",
    "retrospective.v2.gap_disposition": "Errors And Verification",
}

SLOT_NAMES = frozenset(
    {
        "actor",
        "object",
        "action",
        "outcome",
        "cause",
        "effect",
        "risk",
        "guidance",
        "metric",
        "comparison",
        "scope",
        "disposition",
        "timeframe",
        "verification",
        "category",
    }
)
TAXONOMY_VALUES = frozenset(
    {
        "failed_command",
        "approval_request",
        "auth_denial",
        "retry",
        "user_correction",
        "incomplete_verification",
        "over_exploration",
        "under_asking",
        "context_loss",
        "assumption_risk",
        "verification_gap",
        "safety_privacy_risk",
        "clear_scope",
        "efficient_execution",
        "appropriate_validation",
        "safe_handling",
        "effective_recovery",
        "concise_communication",
        "detail_not_retained",
        "not_observed",
        "not_applicable",
    }
)
PLACEHOLDER_VALUES = frozenset(
    {
        "the_user",
        "the_assistant",
        "the_task",
        "the_workflow",
        "the_environment",
        "the_command",
        "the_verification",
        "the_source_scope",
        "the_review",
        "the_follow_up",
    }
)
CLAUSE_VALUES = frozenset(
    {
        "state_the_goal",
        "state_the_scope",
        "state_constraints_first",
        "name_the_primary_evidence",
        "ask_one_blocking_question",
        "use_a_bounded_search",
        "verify_before_claiming",
        "report_the_exact_blocker",
        "stop_at_the_decision_point",
        "preserve_unrelated_changes",
        "separate_observation_from_inference",
        "record_a_follow_up",
    }
)
METRIC_FORMULAS = frozenset(
    {
        "ledger_count_v2",
        "ledger_byte_sum_v2",
        "bounded_fraction_v2",
        "rate_per_100_meaningful_turns_v2",
        "rate_per_100_meaningful_episodes_v2",
        "normalized_change_v2",
    }
)
METRIC_UNITS = frozenset({"count", "bytes", "fraction", "percent", "rate_per_100"})
METRIC_ROUNDING = frozenset({"integer", "nearest_tenth", "three_decimal_places"})
METRIC_COHORTS = frozenset(
    {
        "all_terminal_members",
        "minimum_three_lineages",
        "minimum_cohort_policy_v2",
        "not_applicable",
    }
)
METRIC_GAP_REASONS = frozenset(
    {
        "coverage_gap",
        "review_gap",
        "meaningfulness_gap",
        "incompatible_policy_era",
        "incompatible_model_era",
        "insufficient_cohort",
    }
)
AGGREGATE_INPUT_REF_RE = re.compile(r"^aggregate_input_ref_v2:[0-9a-f]{32}$")


def _words(value: str) -> str:
    return value.replace("_", " ")


def _valid_metric(metric: Any) -> bool:
    if not isinstance(metric, dict):
        return False
    status = metric.get("status")
    formula_id = metric.get("formula_id")
    if not isinstance(formula_id, str) or formula_id not in METRIC_FORMULAS:
        return False
    if status == "available":
        if set(metric) != {
            "status",
            "formula_id",
            "value",
            "unit",
            "rounding",
            "cohort_policy",
            "input_refs",
        }:
            return False
        value = metric.get("value")
        input_refs = metric.get("input_refs")
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and -1_000_000_000 <= value <= 1_000_000_000
            and math.isfinite(value)
            and isinstance(metric.get("unit"), str)
            and metric.get("unit") in METRIC_UNITS
            and isinstance(metric.get("rounding"), str)
            and metric.get("rounding") in METRIC_ROUNDING
            and isinstance(metric.get("cohort_policy"), str)
            and metric.get("cohort_policy") in METRIC_COHORTS
            and isinstance(input_refs, list)
            and 1 <= len(input_refs) <= 64
            and all(
                isinstance(ref, str) and AGGREGATE_INPUT_REF_RE.fullmatch(ref)
                for ref in input_refs
            )
            and len(input_refs) == len(set(input_refs))
        )
    if status == "unavailable":
        reason = metric.get("reason")
        return (
            set(metric) == {"status", "formula_id", "reason"}
            and isinstance(reason, str)
            and reason in METRIC_GAP_REASONS
        )
    return False


def _render_slot(slot: Any) -> str | None:
    if not isinstance(slot, dict):
        return None
    name = slot.get("name")
    slot_type = slot.get("slot_type")
    if not isinstance(name, str) or name not in SLOT_NAMES:
        return None
    if slot_type == "taxonomy_term":
        value = slot.get("value")
        if (
            set(slot) != {"name", "slot_type", "value"}
            or not isinstance(value, str)
            or value not in TAXONOMY_VALUES
        ):
            return None
        return f"{_words(name)} {_words(value)}"
    if slot_type == "generic_placeholder":
        value = slot.get("value")
        if (
            set(slot) != {"name", "slot_type", "value"}
            or not isinstance(value, str)
            or value not in PLACEHOLDER_VALUES
        ):
            return None
        return f"{_words(name)} {_words(value)}"
    if slot_type == "reviewed_clause":
        value = slot.get("value")
        if (
            set(slot) != {"name", "slot_type", "value"}
            or not isinstance(value, str)
            or value not in CLAUSE_VALUES
        ):
            return None
        return f"{_words(name)} {_words(value)}"
    if slot_type == "aggregate_metric":
        metric = slot.get("metric")
        if set(slot) != {"name", "slot_type", "metric"} or not _valid_metric(metric):
            return None
        assert isinstance(metric, dict)
        status = metric["status"]
        detail = metric["unit"] if status == "available" else metric["reason"]
        return (
            f"{_words(name)} {_words(status)} "
            f"{_words(metric['formula_id'])} {_words(detail)}"
        )
    return None


def render_template(template_id: Any, slots: Any) -> str | None:
    """Render one retained template without consulting caller-provided prose."""
    if template_id == DETAIL_TEMPLATE_ID:
        return DETAIL_RENDERED_TEXT if slots == [] else None
    if not isinstance(template_id, str):
        return None
    heading = TEMPLATE_HEADINGS.get(template_id)
    if heading is None or not isinstance(slots, list) or len(slots) > 12:
        return None
    try:
        canonical_slots = [
            json.dumps(
                slot,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            for slot in slots
        ]
    except (RecursionError, TypeError, ValueError):
        return None
    if len(canonical_slots) != len(set(canonical_slots)):
        return None
    rendered_slots = [_render_slot(slot) for slot in slots]
    if any(rendered is None for rendered in rendered_slots):
        return None
    if not rendered_slots:
        return "No observation was retained."
    return f"{heading}: {'; '.join(rendered_slots)}."


def validate_and_render_template(value: Any) -> str | None:
    """Validate fixed template metadata and return the canonical rendering."""
    if not isinstance(value, dict):
        return None
    if set(value) != {
        "template_id",
        "slots",
        "rendered_text",
        "rendering_policy",
        "detail_disposition",
    }:
        return None
    template_id = value.get("template_id")
    expected = render_template(template_id, value.get("slots"))
    if expected is None or value.get("rendered_text") != expected:
        return None
    if value.get("rendering_policy") != "retained-template-renderer-v2":
        return None
    expected_disposition = (
        "detail_not_retained" if template_id == DETAIL_TEMPLATE_ID else "rendered"
    )
    if value.get("detail_disposition") != expected_disposition:
        return None
    return expected


__all__ = [
    "DETAIL_RENDERED_TEXT",
    "DETAIL_TEMPLATE_ID",
    "TEMPLATE_HEADINGS",
    "render_template",
    "validate_and_render_template",
]
