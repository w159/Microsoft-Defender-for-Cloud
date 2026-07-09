"""§4.3 #5 — Durable activity: resolve resource owner (tag, then optional Graph)."""

from __future__ import annotations

import logging
import re
import time
from typing import Any

import azure.durable_functions as df
from opentelemetry import trace

from clients.graph_client import GraphClient
from models.enrichment import OwnerInfo

logger = logging.getLogger(__name__)
_tracer = trace.get_tracer(__name__)
bp = df.Blueprint()

# Pragmatic email shape check — full RFC 5322 validation is unnecessary here (§4.3 #5).
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _build_graph_client() -> GraphClient:
    """Construct the Graph client (seam so tests can inject a fake credential, §7)."""
    return GraphClient()


def _looks_like_email(value: str) -> bool:
    """Return whether ``value`` is plausibly an email address (§4.3 #5)."""
    return bool(_EMAIL_RE.match(value.strip()))


@bp.activity_trigger(input_name="owner_tag")
async def activity_resolve_owner(owner_tag: object) -> dict[str, Any]:
    """§4.3 #5 — resolve the owner from the resource tag, enriched via Graph.

    ``owner_tag`` is the ``tags.Owner`` / ``tags.SecurityContact`` value found by
    ``activity_gather_enrichment`` (a ``str`` or ``None`` at runtime; typed ``object``
    because the Functions worker rejects union annotations on activity bindings). If it
    looks like an email, Microsoft Graph is queried for the matching Entra user.
    Best-effort (§5.2.3): any failure degrades to the tag value (or ``unknown``) and the
    activity never raises. Returns a JSON-serializable dict (Durable activity contract).
    """
    start = time.perf_counter()
    with _tracer.start_as_current_span("activity.resolve_owner") as span:
        span.set_attribute("resource_id", "")
        info = await _resolve_owner_info(owner_tag)
        span.set_attribute("duration_ms", (time.perf_counter() - start) * 1000.0)
        return info.model_dump(mode="json")


async def _resolve_owner_info(owner_tag: object) -> OwnerInfo:
    """§4.3 #5 — owner-resolution logic (returns the model; the trigger serializes it)."""
    tag = (owner_tag if isinstance(owner_tag, str) else "").strip()
    if not tag:
        return OwnerInfo(source="unknown")

    if not _looks_like_email(tag):
        # A non-email tag (e.g. a team name) is still a useful owner hint.
        return OwnerInfo(email=tag, source="tag")

    try:
        async with _build_graph_client() as client:
            user = await client.resolve_user(tag)
    except Exception:
        logger.exception("resolve_owner: Graph lookup failed; degrading to tag (owner=<redacted>)")
        return OwnerInfo(email=tag, source="tag")

    if user is None:
        # Tag is an email but not a resolvable Entra identity — keep the tag.
        return OwnerInfo(email=tag, source="tag")

    resolved_email = user.mail or user.user_principal_name or tag
    return OwnerInfo(email=resolved_email, source="graph", aad_object_id=user.id)
