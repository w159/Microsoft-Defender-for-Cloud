"""§4.4/§4.5 — tests for briefing input and the ADO work-item field mapping."""

from __future__ import annotations

from models.briefing import BriefingInput, WorkItemFields, WorkItemResult
from models.enrichment import EnrichmentBundle
from models.mdc_payload import MdcRecommendationPayload

# Exact ADO field reference-name set per §4.4.
EXPECTED_ADO_FIELDS = {
    "System.WorkItemType",
    "System.Title",
    "System.Description",
    "Custom.MDCAssessmentId",
    "Custom.MDCResourceId",
    "Custom.Severity",
    "Microsoft.VSTS.Common.Priority",
    "Microsoft.VSTS.Scheduling.DueDate",
    "Custom.SubscriptionId",
    "Custom.ResourceType",
    "Custom.ComplianceStandards",
    "Custom.SuggestedOwner",
    "Custom.Criticality",
    "Custom.OnAttackPath",
    "Custom.AttackPathCount",
    "Custom.OtherOpenRecsCount",
    "Custom.CVECount",
    "Custom.MaxCVSS",
    "Custom.FirstDetected",
    "Custom.LastSeen",
    "Custom.MaterialHash",
    "System.Tags",
    "System.AreaPath",
    "System.IterationPath",
    "System.State",
    "System.AssignedTo",
}


def test_work_item_fields_uses_exact_ado_names() -> None:
    # Full field set (including None values) maps to exactly the §4.4 reference names.
    assert set(WorkItemFields().to_ado_fields(exclude_none=False).keys()) == EXPECTED_ADO_FIELDS


def test_work_item_fields_excludes_none_by_default() -> None:
    fields = WorkItemFields(
        work_item_type="Security Recommendation",
        title="Endpoint protection missing — contoso-web-01",
        mdc_assessment_id="guid",
        mdc_resource_id="/subscriptions/sub/.../contoso-web-01",
        severity="High",
        priority=1,
        on_attack_path=True,
        attack_path_count=2,
        cve_count=8,
        max_cvss=9.8,
        material_hash="abc123",
    )
    produced = set(fields.to_ado_fields().keys())
    assert produced <= EXPECTED_ADO_FIELDS
    assert "Custom.MDCAssessmentId" in produced
    assert "Custom.MaterialHash" in produced
    # None-valued fields are dropped.
    assert "Custom.LastSeen" not in produced
    assert "System.AssignedTo" not in produced


def test_briefing_input_composition() -> None:
    payload = MdcRecommendationPayload(name="guid")
    bundle = EnrichmentBundle()
    briefing_input = BriefingInput(payload=payload, enrichment=bundle)
    assert briefing_input.payload.name == "guid"
    assert briefing_input.owner is None


def test_work_item_result_actions() -> None:
    created = WorkItemResult(id=1, url="u", action="created")
    updated = WorkItemResult(id=2, url="u", action="updated")
    skipped = WorkItemResult(id=3, url="u", action="skipped")
    assert (created.action, updated.action, skipped.action) == ("created", "updated", "skipped")
