"""§5.2.2 — Durable orchestrator: dedupe -> enrich -> briefing -> create/update WI."""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

import azure.durable_functions as df

bp = df.Blueprint()


def _orchestrate(
    context: df.DurableOrchestrationContext,
) -> Generator[Any, Any, dict[str, Any]]:
    """§5.2.2 — orchestrate the enrichment chain.

    Sequence (per §5.2.2 pseudocode, reconciled with the activity contracts):
      1. Fan out ``activity_dedupe_lookup`` and ``activity_gather_enrichment`` in
         parallel (``task_all``).
      2. ``activity_resolve_owner`` on the owner tag surfaced by enrichment — this
         depends on enrichment output, so it runs after the fan-out rather than fully
         parallel as the illustrative pseudocode shows.
      3. ``activity_build_triage_briefing``.
      4. ``activity_create_or_update_work_item`` (terminal; retried on failure).

    Returns the serialized :class:`WorkItemResult` dict.
    """
    payload = context.get_input()

    # 1. Fan out the two payload-only activities in parallel (§5.2.2).
    dedupe_task = context.call_activity("activity_dedupe_lookup", payload)
    enrichment_task = context.call_activity("activity_gather_enrichment", payload)
    existing_wi_id, enrichment = yield context.task_all([dedupe_task, enrichment_task])

    # 2. Owner resolution depends on the tag found during enrichment.
    owner_tag = None
    if isinstance(enrichment, dict):
        owner = enrichment.get("owner")
        if isinstance(owner, dict):
            owner_tag = owner.get("email")
    resolved_owner = yield context.call_activity("activity_resolve_owner", owner_tag)

    # 3. Compose the HTML triage briefing.
    briefing = yield context.call_activity(
        "activity_build_triage_briefing",
        {"payload": payload, "enrichment": enrichment, "owner": resolved_owner},
    )

    # 4. Create or churn-controlled update of the Work Item (§5.2.5).
    result: dict[str, Any] = yield context.call_activity(
        "activity_create_or_update_work_item",
        {
            "payload": payload,
            "enrichment": enrichment,
            "owner": resolved_owner,
            "briefing": briefing,
            "existing_wi_id": existing_wi_id,
        },
    )

    # 5. Write-back: assign the recommendation to the Work Item (§4.7, Feature B).
    #    Only on a material create/update — a churn-suppressed skip needs no re-assign.
    if isinstance(result, dict) and result.get("action") in ("created", "updated"):
        yield context.call_activity(
            "activity_assign_recommendation",
            {
                "payload": payload,
                "work_item_id": result.get("id"),
                "action": result.get("action"),
            },
        )
    return result


@bp.orchestration_trigger(context_name="context")
def enrich_and_create_orchestrator(
    context: df.DurableOrchestrationContext,
) -> Generator[Any, Any, dict[str, Any]]:
    """§5.2.2 — Durable orchestration trigger.

    Thin delegating wrapper around :func:`_orchestrate` (the testable generator);
    the Durable runtime drives the returned generator during replay.
    """
    return _orchestrate(context)
