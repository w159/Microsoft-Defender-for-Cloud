"""§4.3/§4.4 — pydantic models for the MDC Workflow Automation trigger payload.

All fields are optional unless the spec or sample payloads prove them mandatory —
MDC payloads vary across recommendation types (copilot-instructions.md §3). Fields that
live under the wire ``properties`` envelope are lifted to the top level via alias paths,
so both nested (real MDC) and flat inputs parse.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from urllib.parse import quote

from pydantic import AliasChoices, AliasPath, BaseModel, ConfigDict, Field

Severity = Literal["High", "Medium", "Low"]


class ResourceDetails(BaseModel):
    """§4.3 — resource portion of the MDC payload (the ARM resource id + source)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    id: str | None = None
    source: str | None = None


class AssessmentStatus(BaseModel):
    """§4.3 — assessment status block (code/cause/description)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    code: str | None = None
    cause: str | None = None
    description: str | None = None


class AssessmentLinks(BaseModel):
    """§4.3 — portal deep-links carried on the recommendation payload.

    The MDC Workflow Automation trigger exposes ``azurePortalUri``; Azure Resource
    Graph exposes the same link as ``azurePortal``. Either may be present.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    azure_portal_uri: str | None = Field(default=None, validation_alias="azurePortalUri")
    azure_portal: str | None = Field(default=None, validation_alias="azurePortal")


class AssessmentMetadata(BaseModel):
    """§4.3 — assessment metadata (severity, type, description, remediation)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    severity: str | None = None
    assessment_type: str | None = Field(default=None, validation_alias="assessmentType")
    description: str | None = None
    remediation_description: str | None = Field(
        default=None, validation_alias="remediationDescription"
    )
    categories: list[str] | None = None
    compliance_standards: list[str] | None = Field(
        default=None, validation_alias="complianceStandards"
    )


class MdcRecommendationPayload(BaseModel):
    """§4.3 — top-level MDC recommendation payload (one security assessment)."""

    model_config = ConfigDict(frozen=True, extra="ignore", populate_by_name=True)

    name: str | None = None
    id: str | None = None
    type: str | None = None
    display_name: str | None = Field(
        default=None,
        validation_alias=AliasChoices("display_name", AliasPath("properties", "displayName")),
    )
    resource_details: ResourceDetails | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "resource_details", AliasPath("properties", "resourceDetails")
        ),
    )
    metadata: AssessmentMetadata | None = Field(
        default=None,
        validation_alias=AliasChoices("metadata", AliasPath("properties", "metadata")),
    )
    status: AssessmentStatus | None = Field(
        default=None,
        validation_alias=AliasChoices("status", AliasPath("properties", "status")),
    )
    links: AssessmentLinks | None = Field(
        default=None,
        validation_alias=AliasChoices("links", AliasPath("properties", "links")),
    )
    status_change_date: datetime | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "status_change_date", AliasPath("properties", "statusChangeDate")
        ),
    )

    # --- helpers (§4.3 #8, §4.4) ---------------------------------------------------

    @property
    def resource_id(self) -> str | None:
        """Full ARM id of the affected resource (the ``Custom.MDCResourceId`` key)."""
        return self.resource_details.id if self.resource_details else None

    @property
    def recommendation_url(self) -> str | None:
        """§4.3 — portal deep-link to the MDC recommendation.

        Prefers the link supplied in the payload (``azurePortalUri`` / ``azurePortal``);
        otherwise reconstructs the Recommendations-blade URL from the assessment key
        and resource id. Returns ``None`` when neither is available.
        """
        if self.links:
            url = self.links.azure_portal_uri or self.links.azure_portal
            if url:
                return url if url.startswith("http") else f"https://{url}"
        key = self.name
        rid = self.resource_id
        if key and rid:
            return (
                "https://portal.azure.com/#blade/Microsoft_Azure_Security/"
                f"RecommendationsBlade/assessmentKey/{key}/resourceId/{quote(rid, safe='')}"
            )
        return None

    @property
    def resource_portal_url(self) -> str | None:
        """§4.3 — portal deep-link to the affected resource's overview blade."""
        rid = self.resource_id
        return f"https://portal.azure.com/#@/resource{rid}/overview" if rid else None

    @property
    def assessment_resource_id(self) -> str | None:
        """§4.6 — ARM id of the assessment, for governance-assignment write-back.

        Builds the canonical *resource-scoped* assessment id
        (``<resourceId>/providers/Microsoft.Security/assessments/<key>``) from the
        reliable resource id + assessment key; only falls back to the payload ``id``
        when those are unavailable. Constructing is preferred because a payload ``id``
        can be scoped differently (e.g. subscription/RG-scoped) and would not resolve
        for the governance API.
        """
        marker = "/providers/Microsoft.Security/assessments/"
        rid = self.resource_id
        if rid and self.name:
            return f"{rid}{marker}{self.name}"
        if self.id and marker in self.id:
            return self.id
        return None

    def _id_segment(self, key: str) -> str | None:
        """Return the path segment immediately following ``key`` in the resource id."""
        rid = self.resource_id
        if not rid:
            return None
        parts = [p for p in rid.split("/") if p]
        lowered = [p.lower() for p in parts]
        target = key.lower()
        for index, part in enumerate(lowered):
            if part == target and index + 1 < len(parts):
                return parts[index + 1]
        return None

    @property
    def subscription_id(self) -> str | None:
        """§4.3 #8 — subscription GUID parsed from the resource id."""
        return self._id_segment("subscriptions")

    @property
    def resource_group(self) -> str | None:
        """§4.3 #8 — resource group name parsed from the resource id."""
        return self._id_segment("resourceGroups")

    @property
    def resource_name(self) -> str | None:
        """§4.3 #8 — leaf resource name parsed from the resource id."""
        rid = self.resource_id
        if not rid:
            return None
        parts = [p for p in rid.split("/") if p]
        return parts[-1] if parts else None

    @property
    def resource_type(self) -> str | None:
        """§4.3 #8 — provider/type (e.g. ``Microsoft.Compute/virtualMachines``)."""
        rid = self.resource_id
        if not rid:
            return None
        parts = [p for p in rid.split("/") if p]
        lowered = [p.lower() for p in parts]
        if "providers" not in lowered:
            return None
        rest = parts[lowered.index("providers") + 1 :]
        if len(rest) < 2:
            return None
        namespace = rest[0]
        type_tokens = rest[1::2]
        return "/".join([namespace, *type_tokens])

    @property
    def severity(self) -> Severity:
        """§4.4 — severity normalized to High/Medium/Low (default Low if missing)."""
        raw = (self.metadata.severity if self.metadata else None) or ""
        match raw.strip().lower():
            case "high":
                return "High"
            case "medium":
                return "Medium"
            case _:
                return "Low"
