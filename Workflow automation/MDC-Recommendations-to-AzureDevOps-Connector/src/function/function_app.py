"""§5.1/§5.2.4/§10.1 — Azure Functions v2 app: HTTP starter + blueprint registration.

The single writer to ADO. Dispatched to by the Logic App; fans out enrichment via
Durable Functions and composes a Triage Briefing before creating/updating the Work Item.
"""

from __future__ import annotations

import hashlib
import logging

import azure.durable_functions as df
import azure.functions as func

from activities.assign_recommendation import bp as assign_recommendation_bp
from activities.build_triage_briefing import bp as build_briefing_bp
from activities.create_or_update_work_item import bp as create_or_update_bp
from activities.dedupe_lookup import bp as dedupe_bp
from activities.gather_enrichment import bp as gather_bp
from activities.resolve_owner import bp as resolve_owner_bp
from orchestrators.enrich_and_create import bp as orchestrator_bp

logger = logging.getLogger(__name__)

app = df.DFApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# Register the orchestrator + activity blueprints (§5.2.1).
app.register_blueprint(orchestrator_bp)
app.register_blueprint(gather_bp)
app.register_blueprint(resolve_owner_bp)
app.register_blueprint(build_briefing_bp)
app.register_blueprint(dedupe_bp)
app.register_blueprint(create_or_update_bp)
app.register_blueprint(assign_recommendation_bp)

_ORCHESTRATOR_NAME = "enrich_and_create_orchestrator"
# Only an in-flight (active) instance for the same key is a duplicate. A non-existent
# key surfaces as a status object whose runtime_status is None (NOT a terminal state),
# so a denylist of terminal states would wrongly dedupe the first event. Use an
# allowlist of active states instead; None / terminal both fall through to start (§5.2.4).
_ACTIVE_STATES = {
    df.OrchestrationRuntimeStatus.Running,
    df.OrchestrationRuntimeStatus.Pending,
    df.OrchestrationRuntimeStatus.ContinuedAsNew,
}


def _instance_id(payload: dict[str, object]) -> str:
    """§5.2.4 — deterministic instance id ``sha256(assessment_id|resource_id)``."""
    properties = payload.get("properties")
    props = properties if isinstance(properties, dict) else {}
    assessment_id = str(payload.get("name") or "")
    resource_details = props.get("resourceDetails")
    rd = resource_details if isinstance(resource_details, dict) else {}
    resource_id = str(rd.get("id") or "")
    digest = hashlib.sha256(f"{assessment_id}|{resource_id}".encode())
    return digest.hexdigest()


@app.route(route="EnrichAndCreate", methods=["POST"])
@app.durable_client_input(client_name="client")
async def http_start(
    req: func.HttpRequest, client: df.DurableOrchestrationClient
) -> func.HttpResponse:
    """§5.2.4 — HTTP starter (entry point from the Logic App).

    Thin Durable-binding wrapper; the testable logic lives in
    :func:`_handle_http_start`.
    """
    return await _handle_http_start(req, client)


async def _handle_http_start(
    req: func.HttpRequest, client: df.DurableOrchestrationClient
) -> func.HttpResponse:
    """§5.2.4 — compute the deterministic instance id and start/dedupe.

    Computes ``sha256(assessment_id|resource_id)`` and, before starting, checks
    ``get_status``: a still-running instance for the same key is treated as a
    duplicate (no second orchestration); a terminal instance is re-fired with the
    same id (the legitimate update path). The authoritative dedupe remains the ADO
    WIQL lookup (§5.2.4).
    """
    try:
        payload = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON payload", status_code=400)
    if not isinstance(payload, dict):
        return func.HttpResponse("Expected a JSON object payload", status_code=400)

    instance_id = _instance_id(payload)

    existing = await client.get_status(instance_id)
    if existing is not None and existing.runtime_status in _ACTIVE_STATES:
        logger.info(
            "EnrichAndCreate: instance %s already %s; treating event as duplicate",
            instance_id,
            existing.runtime_status,
        )
        duplicate: func.HttpResponse = client.create_check_status_response(req, instance_id)
        return duplicate

    await client.start_new(_ORCHESTRATOR_NAME, instance_id, payload)
    logger.info("EnrichAndCreate: started orchestration %s", instance_id)
    started: func.HttpResponse = client.create_check_status_response(req, instance_id)
    return started
