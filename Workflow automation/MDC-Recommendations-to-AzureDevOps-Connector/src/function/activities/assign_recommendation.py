"""§4.7 — Durable activity: write-back a governance assignment to MDC (Feature B, v2.1).

After a Work Item is created/updated, "assign" the MDC recommendation by PUT-ing a
governance assignment whose ``owner`` is a back-reference to the ADO Work Item
(``ado-wi-<id>@<domain>``). This flips the recommendation to **Assigned** in MDC and
persists the Work Item id (working around §2.4's "no back-reference storage").

Best-effort (§5.2.3): the Work Item already exists, so this never raises — any failure
(e.g. the Managed Identity lacking Security Admin) is logged and the activity returns
``assigned=False``. Gated behind ``MDC_WRITE_BACK_ENABLED`` and run only on a material
create/update (not on a churn-suppressed skip).
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import azure.durable_functions as df
from opentelemetry import trace
from pydantic import BaseModel, ConfigDict

from clients.mdc_client import MdcAssignmentConflictError, MdcClient
from models.mdc_payload import MdcRecommendationPayload, Severity

logger = logging.getLogger(__name__)
_tracer = trace.get_tracer(__name__)
bp = df.Blueprint()

_OWNER_PREFIX = "ado-wi-"
_DEFAULT_OWNER_DOMAIN = "ado.local"
_SLA_DAYS_BY_SEVERITY: dict[Severity, int] = {"High": 7, "Medium": 30, "Low": 90}
# Stable namespace so the assignment key is deterministic (idempotent upsert, §4.7).
_ASSIGNMENT_NAMESPACE = uuid.UUID("6f6d6463-6164-6f00-0000-676f7665726e")


class AssignmentActivityInput(BaseModel):
    """§4.7 — input for the recommendation-assignment activity."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    payload: MdcRecommendationPayload
    work_item_id: int
    action: str = ""


def _build_mdc_client() -> MdcClient:
    """Construct the MDC client (seam so tests can inject a fake credential, §7)."""
    return MdcClient()


def _now() -> datetime:
    """Current UTC time (wrapped so ``freezegun`` can pin it in tests)."""
    return datetime.now(UTC)


def _write_back_enabled() -> bool:
    """Whether MDC write-back is enabled (opt-in via ``MDC_WRITE_BACK_ENABLED``)."""
    return os.environ.get("MDC_WRITE_BACK_ENABLED", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _owner_domain() -> str:
    """The email domain for the Work Item back-reference owner (§4.7)."""
    return os.environ.get("MDC_ASSIGNMENT_OWNER_DOMAIN", _DEFAULT_OWNER_DOMAIN).strip() or (
        _DEFAULT_OWNER_DOMAIN
    )


def assignment_owner(work_item_id: int) -> str:
    """§4.7 — the governance-assignment owner that back-references a Work Item."""
    return f"{_OWNER_PREFIX}{work_item_id}@{_owner_domain()}"


def is_backref_owner(owner: str) -> bool:
    """§4.7 — whether ``owner`` is one of our Work Item back-references.

    Detected by the ``ado-wi-`` local-part prefix so it stays correct regardless of
    the configured domain. Used by enrichment to avoid treating our own assignment as
    a human owner (feedback-loop guard, §4.3 #5).
    """
    local = owner.split("@", 1)[0].strip().lower()
    return local.startswith(_OWNER_PREFIX)


def _assignment_key(assessment_name: str, resource_id: str) -> str:
    """Deterministic governance-assignment GUID (idempotent upsert, §4.7)."""
    return str(uuid.uuid5(_ASSIGNMENT_NAMESPACE, f"{assessment_name}|{resource_id}"))


@bp.activity_trigger(input_name="assignment_input")
async def activity_assign_recommendation(assignment_input: object) -> dict[str, Any]:
    """§4.7 — assign the MDC recommendation to the Work Item back-reference (best-effort)."""
    model = AssignmentActivityInput.model_validate(assignment_input)
    start = time.perf_counter()
    with _tracer.start_as_current_span("activity.assign_recommendation") as span:
        span.set_attribute("assessment_id", model.payload.name or "")
        span.set_attribute("resource_id", model.payload.resource_id or "")
        result = await _assign(model)
        span.set_attribute("assigned", bool(result.get("assigned")))
        span.set_attribute("duration_ms", (time.perf_counter() - start) * 1000.0)
        return result


async def _assign(model: AssignmentActivityInput) -> dict[str, Any]:
    """§4.7 — assignment logic (degrades to ``assigned=False``; never raises)."""
    if not _write_back_enabled():
        return {"assigned": False, "reason": "disabled"}
    if model.action not in {"created", "updated"}:
        return {"assigned": False, "reason": f"action={model.action}"}

    payload = model.payload
    assessment_id = payload.assessment_resource_id
    resource_id = payload.resource_id
    if not assessment_id or not resource_id or not payload.name:
        return {"assigned": False, "reason": "missing assessment/resource id"}

    owner = assignment_owner(model.work_item_id)
    key = _assignment_key(payload.name, resource_id)
    due = _now() + timedelta(days=_SLA_DAYS_BY_SEVERITY[payload.severity])
    try:
        async with _build_mdc_client() as client:
            await client.assign_governance(
                assessment_id, key, owner=owner, remediation_due_date=due
            )
    except MdcAssignmentConflictError:
        # The recommendation already has a governance assignment (e.g. a human owner).
        # Leave it intact rather than overwriting it (§4.7).
        logger.info(
            "assign_recommendation: recommendation already has a governance assignment; "
            "leaving it unchanged (wi=%s)",
            model.work_item_id,
        )
        return {"assigned": False, "reason": "already-assigned"}
    except Exception:
        logger.exception(
            "assign_recommendation: governance assignment failed (wi=%s)", model.work_item_id
        )
        return {"assigned": False, "reason": "error"}

    logger.info(
        "assign_recommendation: recommendation assigned to %s (wi=%s)", owner, model.work_item_id
    )
    return {"assigned": True, "owner": owner, "assignmentKey": key}
