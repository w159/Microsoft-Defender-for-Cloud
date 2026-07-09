"""§4.4/§4.5 — briefing input + ADO work-item field/result models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from models.enrichment import EnrichmentBundle, OwnerInfo
from models.mdc_payload import MdcRecommendationPayload, Severity


class BriefingInput(BaseModel):
    """§4.5 — inputs to the triage-briefing renderer (payload + enrichment + owner)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    payload: MdcRecommendationPayload
    enrichment: EnrichmentBundle
    owner: OwnerInfo | None = None


class WorkItemFields(BaseModel):
    """§4.4 — ADO field-name -> value mapping.

    Each attribute carries the literal ADO field reference name as its serialization
    alias, so ``to_ado_fields()`` yields a dict keyed exactly as ADO expects.
    """

    model_config = ConfigDict(frozen=True, extra="ignore", populate_by_name=True)

    work_item_type: str | None = Field(default=None, serialization_alias="System.WorkItemType")
    title: str | None = Field(default=None, serialization_alias="System.Title")
    description: str | None = Field(default=None, serialization_alias="System.Description")
    mdc_assessment_id: str | None = Field(
        default=None, serialization_alias="Custom.MDCAssessmentId"
    )
    mdc_resource_id: str | None = Field(default=None, serialization_alias="Custom.MDCResourceId")
    severity: Severity | None = Field(default=None, serialization_alias="Custom.Severity")
    priority: int | None = Field(default=None, serialization_alias="Microsoft.VSTS.Common.Priority")
    due_date: datetime | None = Field(
        default=None, serialization_alias="Microsoft.VSTS.Scheduling.DueDate"
    )
    subscription_id: str | None = Field(default=None, serialization_alias="Custom.SubscriptionId")
    resource_type: str | None = Field(default=None, serialization_alias="Custom.ResourceType")
    compliance_standards: str | None = Field(
        default=None, serialization_alias="Custom.ComplianceStandards"
    )
    suggested_owner: str | None = Field(default=None, serialization_alias="Custom.SuggestedOwner")
    criticality: str | None = Field(default=None, serialization_alias="Custom.Criticality")
    on_attack_path: bool | None = Field(default=None, serialization_alias="Custom.OnAttackPath")
    attack_path_count: int | None = Field(
        default=None, serialization_alias="Custom.AttackPathCount"
    )
    other_open_recs_count: int | None = Field(
        default=None, serialization_alias="Custom.OtherOpenRecsCount"
    )
    cve_count: int | None = Field(default=None, serialization_alias="Custom.CVECount")
    max_cvss: float | None = Field(default=None, serialization_alias="Custom.MaxCVSS")
    first_detected: datetime | None = Field(
        default=None, serialization_alias="Custom.FirstDetected"
    )
    last_seen: datetime | None = Field(default=None, serialization_alias="Custom.LastSeen")
    material_hash: str | None = Field(default=None, serialization_alias="Custom.MaterialHash")
    tags: str | None = Field(default=None, serialization_alias="System.Tags")
    area_path: str | None = Field(default=None, serialization_alias="System.AreaPath")
    iteration_path: str | None = Field(default=None, serialization_alias="System.IterationPath")
    state: str | None = Field(default=None, serialization_alias="System.State")
    assigned_to: str | None = Field(default=None, serialization_alias="System.AssignedTo")

    def to_ado_fields(self, *, exclude_none: bool = True) -> dict[str, Any]:
        """§4.4 — serialize to a dict keyed by the literal ADO field reference names."""
        return self.model_dump(by_alias=True, exclude_none=exclude_none)


class WorkItemResult(BaseModel):
    """§4.4/§5.2.5 — outcome of a create/update work-item operation.

    ``skipped`` = a no-op update suppressed by the §5.2.5 churn control.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    id: int
    url: str
    action: Literal["created", "updated", "skipped"]
