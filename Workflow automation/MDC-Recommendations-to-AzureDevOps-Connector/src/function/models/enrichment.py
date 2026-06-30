"""§4.3 — enrichment signal models aggregated into EnrichmentBundle.

Every field is optional so the bundle degrades gracefully when a signal fails (§5.2.3).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

CriticalityLevel = Literal["Critical", "High", "Medium", "Low", "Unknown"]


class AadUser(BaseModel):
    """§4.3 #5 — a Microsoft Graph user (subset) returned by owner resolution."""

    model_config = ConfigDict(frozen=True, extra="ignore", populate_by_name=True)

    id: str
    mail: str | None = None
    user_principal_name: str | None = Field(default=None, alias="userPrincipalName")


class OwnerInfo(BaseModel):
    """§4.3 #5 — resolved resource owner (best-effort: tag, then Graph)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    email: str | None = None
    source: Literal["tag", "graph", "unknown"] = "unknown"
    aad_object_id: str | None = None


class OtherRecsSummary(BaseModel):
    """§4.3 #1, #2 — other open recommendations on the resource and their assignment."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    total: int = 0
    assigned: int = 0
    unassigned: int = 0
    by_severity: dict[str, int] = {}


class AttackPath(BaseModel):
    """§4.3 #3 — a single attack path the resource participates in."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    id: str | None = None
    display_name: str | None = None
    entry_point: str | None = None
    target: str | None = None


class AttackPathInfo(BaseModel):
    """§4.3 #3 — attack paths the resource is on."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    paths: list[AttackPath] = []


class CveRecord(BaseModel):
    """§4.3 #4 — a single CVE finding."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    id: str | None = None
    cvss: float | None = None
    description: str | None = None


class VulnerabilityFindings(BaseModel):
    """§4.3 #4 — vulnerability/CVE rollup for the resource."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    cve_count: int = 0
    max_cvss: float | None = None
    top_cves: list[CveRecord] = []


class ResourceCriticality(BaseModel):
    """§4.3 #6 — criticality (tag-based, enriched from attack-path insights)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    level: CriticalityLevel = "Unknown"
    source: str | None = None


class ExposureInfo(BaseModel):
    """§4.3 #7 — internet exposure derived from attack-path risk factors."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    internet_facing: bool = False
    reasoning: str | None = None


class EnrichmentBundle(BaseModel):
    """§4.3 — aggregate of all enrichment signals; every field optional (§5.2.3)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    other_recs: OtherRecsSummary | None = None
    attack_paths: AttackPathInfo | None = None
    vulnerabilities: VulnerabilityFindings | None = None
    owner: OwnerInfo | None = None
    criticality: ResourceCriticality | None = None
    exposure: ExposureInfo | None = None
