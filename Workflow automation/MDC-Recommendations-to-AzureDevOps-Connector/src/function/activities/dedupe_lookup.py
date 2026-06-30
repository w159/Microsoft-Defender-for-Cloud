"""§5.1/§5.2 — Durable activity: dedupe lookup via ADO WIQL.

Authoritative dedupe: returns the existing open Work Item id for the
``Custom.MDCAssessmentId`` + ``Custom.MDCResourceId`` composite key, or None.
"""

from __future__ import annotations

import logging
import time

import azure.durable_functions as df
from opentelemetry import trace

from clients.ado_client import AdoClient
from models.mdc_payload import MdcRecommendationPayload

logger = logging.getLogger(__name__)
_tracer = trace.get_tracer(__name__)
bp = df.Blueprint()


def _build_ado_client() -> AdoClient:
    """Construct the ADO client (seam so tests can inject a fake credential, §7)."""
    return AdoClient()


def _escape_wiql_literal(value: str) -> str:
    """Escape a value for a single-quoted WIQL string literal (doubles quotes)."""
    return value.replace("'", "''")


def _build_wiql(assessment_id: str, resource_id: str) -> str:
    """§5.1/§5.2 — WIQL for the open Work Item matching the composite dedupe key."""
    aid = _escape_wiql_literal(assessment_id)
    rid = _escape_wiql_literal(resource_id)
    return (
        "SELECT [System.Id] FROM WorkItems "
        f"WHERE [Custom.MDCAssessmentId] = '{aid}' "
        f"AND [Custom.MDCResourceId] = '{rid}' "
        "AND [System.State] <> 'Done'"
    )


@bp.activity_trigger(input_name="payload")
async def activity_dedupe_lookup(payload: MdcRecommendationPayload) -> int | None:
    """§5.2 — WIQL lookup for an existing not-Done Work Item.

    Returns the matching Work Item id, or ``None`` when there is no open match.
    Best-effort (§5.2.3): a lookup failure degrades to ``None`` (treated as "no
    existing item") rather than raising, so the orchestration still proceeds.
    """
    model = MdcRecommendationPayload.model_validate(payload)
    assessment_id = model.name
    resource_id = model.resource_id

    start = time.perf_counter()
    with _tracer.start_as_current_span("activity.dedupe_lookup") as span:
        span.set_attribute("assessment_id", assessment_id or "")
        span.set_attribute("resource_id", resource_id or "")

        if not assessment_id or not resource_id:
            logger.warning(
                "dedupe_lookup: missing dedupe key (assessment_id=%s); treating as new",
                assessment_id,
            )
            span.set_attribute("duration_ms", (time.perf_counter() - start) * 1000.0)
            return None

        try:
            async with _build_ado_client() as client:
                ids = await client.query_wiql(_build_wiql(assessment_id, resource_id))
        except Exception:
            logger.exception(
                "dedupe_lookup: WIQL query failed; treating as new "
                "(assessment_id=%s, resource_id=%s)",
                assessment_id,
                resource_id,
            )
            span.set_attribute("duration_ms", (time.perf_counter() - start) * 1000.0)
            return None

        span.set_attribute("duration_ms", (time.perf_counter() - start) * 1000.0)
        return ids[0] if ids else None
