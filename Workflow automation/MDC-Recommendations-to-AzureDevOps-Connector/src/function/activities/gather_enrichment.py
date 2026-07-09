"""§4.3/§5.2.1 — Durable activity: gather enrichment via ARG (signals 1-4, 7, 8).

Signal 6 (criticality) is tag-based (``tags.Criticality`` + attack-path insights),
not an ARG type. Signal 5 (owner tag) is read here; Graph resolution happens in
``activity_resolve_owner``. Degrades gracefully per §5.2.3 — never raises; every
per-signal parse failure leaves that bundle field ``None`` (§4.3).
"""

from __future__ import annotations

import logging
import time
from collections import Counter
from collections.abc import Callable
from typing import Any

import azure.durable_functions as df
from opentelemetry import trace

from activities.assign_recommendation import is_backref_owner
from clients import arg_queries
from clients.arg_client import ArgClient
from models.enrichment import (
    AttackPath,
    AttackPathInfo,
    CriticalityLevel,
    CveRecord,
    EnrichmentBundle,
    ExposureInfo,
    OtherRecsSummary,
    OwnerInfo,
    ResourceCriticality,
    VulnerabilityFindings,
)
from models.mdc_payload import MdcRecommendationPayload

logger = logging.getLogger(__name__)
_tracer = trace.get_tracer(__name__)
bp = df.Blueprint()

_CRITICALITY_LEVELS: tuple[CriticalityLevel, ...] = (
    "Critical",
    "High",
    "Medium",
    "Low",
    "Unknown",
)


def _build_arg_client() -> ArgClient:
    """Construct the ARG client (seam so tests can inject a fake credential, §7)."""
    return ArgClient()


def _batch_query(resource_id: str) -> str:
    """§4.3 — one ARG batch covering signals 1, 2, 3, 4, 7, 8 (discriminated rows)."""
    return arg_queries.union_queries(
        arg_queries.other_open_recommendations(resource_id),
        arg_queries.governance_assignments(resource_id),
        arg_queries.attack_paths_for_resource(resource_id),
        arg_queries.vulnerability_subassessments(resource_id),
        arg_queries.resource_details(resource_id),
    )


def _rows_by_kind(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group unioned ARG rows by their ``signalKind`` discriminator (§4.3)."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        kind = row.get("signalKind")
        if isinstance(kind, str):
            grouped.setdefault(kind, []).append(row)
    return grouped


def _parse_other_recs(
    rec_rows: list[dict[str, Any]],
    gov_rows: list[dict[str, Any]],
    current_assessment_id: str | None = None,
) -> OtherRecsSummary | None:
    """§4.3 #1, #2 — *other* open recs on the resource + assigned/unassigned split.

    Excludes the recommendation this Work Item is about (``current_assessment_id``) so
    the count reflects genuinely *other* open recommendations, not the current one.
    """
    others = [
        row
        for row in rec_rows
        if not (current_assessment_id and str(row.get("assessmentId")) == current_assessment_id)
    ]
    if not others:
        return None
    by_severity = Counter(str(row.get("severity") or "Unknown") for row in others)
    assigned_ids = {str(row.get("assessmentId")) for row in gov_rows if row.get("owner")}
    assigned = sum(1 for row in others if str(row.get("assessmentId")) in assigned_ids)
    total = len(others)
    return OtherRecsSummary(
        total=total,
        assigned=assigned,
        unassigned=total - assigned,
        by_severity=dict(by_severity),
    )


def _parse_attack_paths(path_rows: list[dict[str, Any]]) -> AttackPathInfo | None:
    """§4.3 #3 — attack paths the resource participates in."""
    if not path_rows:
        return None
    paths = [
        AttackPath(id=row.get("attackPathId"), display_name=row.get("displayName"))
        for row in path_rows
    ]
    return AttackPathInfo(paths=paths)


def _parse_exposure(path_rows: list[dict[str, Any]]) -> ExposureInfo | None:
    """§4.3 #7 — internet exposure derived from attack-path risk factors."""
    if not path_rows:
        return None
    for row in path_rows:
        risk_factors = row.get("riskFactors") or []
        factors = risk_factors if isinstance(risk_factors, list) else [risk_factors]
        for factor in factors:
            if "internet exposure" in str(factor).lower():
                return ExposureInfo(internet_facing=True, reasoning=str(factor))
    return ExposureInfo(internet_facing=False)


def _parse_vulnerabilities(vuln_rows: list[dict[str, Any]]) -> VulnerabilityFindings | None:
    """§4.3 #4 — CVE rollup (count + max CVSS + top findings)."""
    if not vuln_rows:
        return None
    cves: list[CveRecord] = []
    max_cvss: float | None = None
    for row in vuln_rows:
        raw_cvss = row.get("cvss")
        cvss = float(raw_cvss) if isinstance(raw_cvss, int | float) else None
        if cvss is not None and (max_cvss is None or cvss > max_cvss):
            max_cvss = cvss
        cves.append(CveRecord(id=row.get("cve"), cvss=cvss, description=row.get("description")))
    top = sorted(cves, key=lambda c: c.cvss or 0.0, reverse=True)[:5]
    return VulnerabilityFindings(cve_count=len(cves), max_cvss=max_cvss, top_cves=top)


def _parse_owner(
    resource_rows: list[dict[str, Any]], gov_rows: list[dict[str, Any]]
) -> OwnerInfo | None:
    """§4.3 #5 — owner from the resource tag, else a governance-assignment owner.

    Prefers ``tags.Owner``/``tags.SecurityContact`` on the resource; when those are
    absent (common in practice), falls back to the owner recorded on a governance
    assignment for the resource. Either way the value is later refined via Graph.
    """
    if resource_rows:
        tag = resource_rows[0].get("owner") or resource_rows[0].get("securityContact")
        if tag:
            return OwnerInfo(email=str(tag), source="tag")
    for gov in gov_rows:
        owner = gov.get("owner")
        if owner:
            return OwnerInfo(email=str(owner), source="tag")
    return None


def _parse_criticality(resource_rows: list[dict[str, Any]]) -> ResourceCriticality | None:
    """§4.3 #6 — criticality from ``tags.Criticality`` (tag-based, not ARG)."""
    if not resource_rows:
        return None
    raw = resource_rows[0].get("criticality")
    if not raw:
        return None
    normalized = str(raw).strip().lower()
    for level in _CRITICALITY_LEVELS:
        if level.lower() == normalized:
            return ResourceCriticality(level=level, source="tag")
    return ResourceCriticality(level="Unknown", source="tag")


def _safe[T](signal: str, parser: Callable[..., T | None], *args: Any) -> T | None:
    """Run a per-signal parser, degrading to ``None`` on failure (§5.2.3)."""
    try:
        return parser(*args)
    except Exception:
        logger.exception("gather_enrichment: failed to parse signal %s", signal)
        return None


@bp.activity_trigger(input_name="payload")
async def activity_gather_enrichment(payload: MdcRecommendationPayload) -> dict[str, Any]:
    """§4.3 — issue one ARG batch and decompose into an EnrichmentBundle.

    Best-effort (§5.2.3): a batch failure or any per-signal parse failure leaves the
    affected field ``None`` and the activity still returns a (possibly empty) bundle.
    """
    model = MdcRecommendationPayload.model_validate(payload)
    resource_id = model.resource_id
    subscription_id = model.subscription_id

    start = time.perf_counter()
    with _tracer.start_as_current_span("activity.gather_enrichment") as span:
        span.set_attribute("assessment_id", model.name or "")
        span.set_attribute("resource_id", resource_id or "")

        if not resource_id or not subscription_id:
            logger.warning(
                "gather_enrichment: missing resource/subscription id; "
                "returning empty bundle (assessment_id=%s)",
                model.name,
            )
            span.set_attribute("duration_ms", (time.perf_counter() - start) * 1000.0)
            return EnrichmentBundle().model_dump(mode="json")

        grouped: dict[str, list[dict[str, Any]]] = {}
        try:
            async with _build_arg_client() as client:
                rows = await client.query(_batch_query(resource_id), [subscription_id])
            grouped = _rows_by_kind(rows)
        except Exception:
            logger.exception(
                "gather_enrichment: ARG batch failed; degrading to empty bundle "
                "(assessment_id=%s, resource_id=%s)",
                model.name,
                resource_id,
            )

        rec_rows = grouped.get("otherRecs", [])
        gov_rows = grouped.get("governance", [])
        path_rows = grouped.get("attackPath", [])
        vuln_rows = grouped.get("vulnerability", [])
        resource_rows = grouped.get("resource", [])

        # Feedback-loop guard (§4.7): drop our own Work Item back-reference owners so
        # a prior write-back assignment is never surfaced as a human owner or counted
        # as a human-assigned recommendation.
        gov_rows = [r for r in gov_rows if not is_backref_owner(str(r.get("owner") or ""))]

        bundle = EnrichmentBundle(
            other_recs=_safe("other_recs", _parse_other_recs, rec_rows, gov_rows, model.name),
            attack_paths=_safe("attack_paths", _parse_attack_paths, path_rows),
            exposure=_safe("exposure", _parse_exposure, path_rows),
            vulnerabilities=_safe("vulnerabilities", _parse_vulnerabilities, vuln_rows),
            owner=_safe("owner", _parse_owner, resource_rows, gov_rows),
            criticality=_safe("criticality", _parse_criticality, resource_rows),
        )
        span.set_attribute("duration_ms", (time.perf_counter() - start) * 1000.0)
        return bundle.model_dump(mode="json")
