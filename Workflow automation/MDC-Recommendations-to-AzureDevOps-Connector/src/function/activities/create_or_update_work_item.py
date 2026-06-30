"""§4.4/§5.2/§5.2.5 — Durable activity: create or churn-controlled update of the WI.

Terminal activity: raises on failure so Durable retry applies (unlike enrichment
activities, which degrade gracefully per §5.2.3).
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import azure.durable_functions as df
from opentelemetry import trace
from pydantic import BaseModel, ConfigDict

from clients.ado_client import AdoClient
from models.briefing import WorkItemFields, WorkItemResult
from models.enrichment import EnrichmentBundle, OwnerInfo
from models.mdc_payload import MdcRecommendationPayload, Severity

logger = logging.getLogger(__name__)
_tracer = trace.get_tracer(__name__)
bp = df.Blueprint()

_WORK_ITEM_TYPE = "Security Recommendation"
_PRIORITY_BY_SEVERITY: dict[Severity, int] = {"High": 1, "Medium": 2, "Low": 3}
_SLA_DAYS_BY_SEVERITY: dict[Severity, int] = {"High": 7, "Medium": 30, "Low": 90}
_MATERIAL_HASH_FIELD = "Custom.MaterialHash"


class WorkItemActivityInput(BaseModel):
    """§5.2.2 — composite input for the create/update activity."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    payload: MdcRecommendationPayload
    enrichment: EnrichmentBundle = EnrichmentBundle()
    owner: OwnerInfo | None = None
    briefing: str = ""
    existing_wi_id: int | None = None


def _build_ado_client() -> AdoClient:
    """Construct the ADO client (seam so tests can inject a fake credential, §7)."""
    return AdoClient()


def _now() -> datetime:
    """Current UTC time (wrapped so ``freezegun`` can pin it in tests)."""
    return datetime.now(UTC)


def _material_hash(
    *,
    severity: str,
    briefing: str,
    attack_path_count: int,
    cve_count: int,
    max_cvss: float | None,
    criticality: str,
    owner: str | None,
) -> str:
    """§5.2.5 — sha256 over the *material* fields only (change-detection key)."""
    material = {
        "severity": severity,
        "briefing": briefing,
        "attack_path_count": attack_path_count,
        "cve_count": cve_count,
        "max_cvss": max_cvss,
        "criticality": criticality,
        "owner": owner,
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _derive(model: WorkItemActivityInput) -> dict[str, Any]:
    """Derive the material/scalar values shared by create and update (§4.4/§5.2.5)."""
    enrichment = model.enrichment
    attack_paths = enrichment.attack_paths.paths if enrichment.attack_paths else []
    attack_path_count = len(attack_paths)
    vulns = enrichment.vulnerabilities
    cve_count = vulns.cve_count if vulns else 0
    max_cvss = vulns.max_cvss if vulns else None
    criticality = enrichment.criticality.level if enrichment.criticality else "Unknown"
    owner_email = model.owner.email if model.owner else None
    severity = model.payload.severity
    return {
        "severity": severity,
        "attack_path_count": attack_path_count,
        "on_attack_path": attack_path_count > 0,
        "cve_count": cve_count,
        "max_cvss": max_cvss,
        "criticality": criticality,
        "owner_email": owner_email,
        "other_open_recs_count": enrichment.other_recs.total if enrichment.other_recs else 0,
        "material_hash": _material_hash(
            severity=severity,
            briefing=model.briefing,
            attack_path_count=attack_path_count,
            cve_count=cve_count,
            max_cvss=max_cvss,
            criticality=criticality,
            owner=owner_email,
        ),
    }


def _tags(payload: MdcRecommendationPayload, *, on_attack_path: bool, criticality: str) -> str:
    """§4.4 — conditional ``System.Tags`` (semicolon-delimited)."""
    parts = ["MDC", payload.severity]
    if payload.resource_type:
        parts.append(payload.resource_type)
    if on_attack_path:
        parts.append("AttackPath")
    if criticality == "Critical":
        parts.append("Critical")
    return "; ".join(parts)


def _create_fields(
    model: WorkItemActivityInput, derived: dict[str, Any], now: datetime
) -> dict[str, Any]:
    """§4.4 — full field set for a brand-new Work Item."""
    payload = model.payload
    title = f"{payload.display_name or 'Security recommendation'} — {payload.resource_name or ''}"
    compliance = payload.metadata.compliance_standards if payload.metadata else None
    fields = WorkItemFields(
        work_item_type=_WORK_ITEM_TYPE,
        title=title[:255],
        description=model.briefing,
        mdc_assessment_id=payload.name,
        mdc_resource_id=payload.resource_id,
        severity=derived["severity"],
        priority=_PRIORITY_BY_SEVERITY[derived["severity"]],
        due_date=now + timedelta(days=_SLA_DAYS_BY_SEVERITY[derived["severity"]]),
        subscription_id=payload.subscription_id,
        resource_type=payload.resource_type,
        compliance_standards=", ".join(compliance) if compliance else None,
        suggested_owner=derived["owner_email"],
        criticality=derived["criticality"],
        on_attack_path=derived["on_attack_path"],
        attack_path_count=derived["attack_path_count"],
        other_open_recs_count=derived["other_open_recs_count"],
        cve_count=derived["cve_count"],
        max_cvss=derived["max_cvss"],
        first_detected=payload.status_change_date or now,
        last_seen=now,
        material_hash=derived["material_hash"],
        tags=_tags(
            payload,
            on_attack_path=derived["on_attack_path"],
            criticality=derived["criticality"],
        ),
        state="To do",
    )
    return fields.to_ado_fields()


def _update_fields(
    model: WorkItemActivityInput, derived: dict[str, Any], now: datetime
) -> dict[str, Any]:
    """§5.2.5 — material fields to PATCH (never ``FirstDetected``); refresh ``LastSeen``."""
    fields = WorkItemFields(
        description=model.briefing,
        severity=derived["severity"],
        priority=_PRIORITY_BY_SEVERITY[derived["severity"]],
        suggested_owner=derived["owner_email"],
        criticality=derived["criticality"],
        on_attack_path=derived["on_attack_path"],
        attack_path_count=derived["attack_path_count"],
        other_open_recs_count=derived["other_open_recs_count"],
        cve_count=derived["cve_count"],
        max_cvss=derived["max_cvss"],
        last_seen=now,
        material_hash=derived["material_hash"],
    )
    return fields.to_ado_fields()


@bp.activity_trigger(input_name="work_item_input")
async def activity_create_or_update_work_item(work_item_input: object) -> dict[str, Any]:
    """§4.4/§5.2.5 — create a new WI, or update only on material change.

    If no existing WI: create with the full field set, set ``FirstDetected`` once and
    compute ``Custom.MaterialHash``. Otherwise apply update-churn control (§5.2.5):
    recompute the material hash and PATCH only if it differs from the stored value;
    never refresh ``LastSeen`` alone. A comment is added only when a material update is
    applied. Returns ``WorkItemResult`` with action ``created`` / ``updated`` /
    ``skipped``. Raises on failure (after logging) so Durable retry fires (§5.2).
    """
    model = WorkItemActivityInput.model_validate(work_item_input)
    derived = _derive(model)
    now = _now()

    start = time.perf_counter()
    with _tracer.start_as_current_span("activity.create_or_update_work_item") as span:
        span.set_attribute("assessment_id", model.payload.name or "")
        span.set_attribute("resource_id", model.payload.resource_id or "")
        try:
            async with _build_ado_client() as client:
                if model.existing_wi_id is None:
                    result = await client.create_work_item(_create_fields(model, derived, now))
                else:
                    result = await _update_with_churn_control(client, model, derived, now)
        except Exception:
            logger.exception(
                "create_or_update_work_item failed (assessment_id=%s, resource_id=%s)",
                model.payload.name,
                model.payload.resource_id,
            )
            raise
        span.set_attribute("duration_ms", (time.perf_counter() - start) * 1000.0)
        span.set_attribute("work_item_action", result.action)
        return result.model_dump(mode="json")


async def _update_with_churn_control(
    client: AdoClient,
    model: WorkItemActivityInput,
    derived: dict[str, Any],
    now: datetime,
) -> WorkItemResult:
    """§5.2.5 — PATCH only when the material hash differs; else skip."""
    existing_id = int(model.existing_wi_id or 0)
    existing = await client.get_work_item(existing_id)
    existing_fields = existing.get("fields", {})
    stored_hash = existing_fields.get(_MATERIAL_HASH_FIELD)
    new_hash = derived["material_hash"]

    if stored_hash == new_hash:
        links = existing.get("_links", {})
        html = links.get("html", {}) if isinstance(links, dict) else {}
        url = html.get("href") or existing.get("url", "")
        logger.info(
            "create_or_update_work_item: material hash unchanged for WI %d; skipping PATCH",
            existing_id,
        )
        return WorkItemResult(id=existing_id, url=str(url), action="skipped")

    result = await client.update_work_item(existing_id, _update_fields(model, derived, now))
    await client.add_comment(
        existing_id,
        "MDC re-evaluated this recommendation; material fields changed — "
        f"Work Item refreshed (hash {new_hash[:12]}).",
    )
    return result
