"""Unit tests for ``orchestrators.enrich_and_create`` (§5.2.2).

The orchestrator is a deterministic Durable generator: it must not perform I/O,
only ``yield`` task objects produced by the replay context. These tests drive the
generator by hand with a recording fake context (mirroring the Durable replay loop)
and assert the call sequence, the activity inputs, and the owner-tag plumbing.
"""

from __future__ import annotations

from typing import Any

from orchestrators.enrich_and_create import _orchestrate

_RESOURCE_ID = (
    "/subscriptions/sub-1/resourceGroups/rg-web/providers/"
    "Microsoft.Compute/virtualMachines/contoso-web-01"
)


class _RecordingContext:
    """Minimal ``DurableOrchestrationContext`` double recording activity calls."""

    def __init__(self, input_value: Any) -> None:
        self._input = input_value
        self.activity_calls: list[dict[str, Any]] = []
        self.task_all_args: Any = None

    def get_input(self) -> Any:
        return self._input

    def call_activity(self, name: str, input_: Any = None) -> dict[str, Any]:
        token = {"activity": name, "input": input_}
        self.activity_calls.append(token)
        return token

    def task_all(self, tasks: Any) -> dict[str, Any]:
        self.task_all_args = list(tasks)
        return {"task_all": list(tasks)}


def _payload() -> dict[str, Any]:
    return {
        "name": "assessment-guid-1",
        "properties": {"resourceDetails": {"id": _RESOURCE_ID}},
    }


def test_orchestrator_happy_path_sequences_activities() -> None:
    """Full chain: fan-out dedupe+enrich, then owner, briefing, create — in order."""
    payload = _payload()
    enrichment = {"owner": {"email": "alice@contoso.com"}}
    owner = {"email": "alice@contoso.com", "source": "graph"}
    briefing = "<div>briefing</div>"
    final = {"id": 1001, "url": "https://ado/1001", "action": "created"}

    ctx = _RecordingContext(payload)
    gen = _orchestrate(ctx)

    # 1. First yield is the fan-out task_all of dedupe + gather (both payload-only).
    first = next(gen)
    assert first == {"task_all": ctx.task_all_args}
    assert ctx.activity_calls[0] == {"activity": "activity_dedupe_lookup", "input": payload}
    assert ctx.activity_calls[1] == {
        "activity": "activity_gather_enrichment",
        "input": payload,
    }

    # 2. Fan-out resolves to (existing_wi_id, enrichment) -> resolve_owner on the tag.
    resolve_yield = gen.send([55, enrichment])
    assert resolve_yield == {
        "activity": "activity_resolve_owner",
        "input": "alice@contoso.com",
    }

    # 3. Owner resolved -> build_triage_briefing with payload+enrichment+owner.
    briefing_yield = gen.send(owner)
    assert briefing_yield == {
        "activity": "activity_build_triage_briefing",
        "input": {"payload": payload, "enrichment": enrichment, "owner": owner},
    }

    # 4. Briefing rendered -> create_or_update_work_item carries the existing id.
    create_yield = gen.send(briefing)
    assert create_yield == {
        "activity": "activity_create_or_update_work_item",
        "input": {
            "payload": payload,
            "enrichment": enrichment,
            "owner": owner,
            "briefing": briefing,
            "existing_wi_id": 55,
        },
    }

    # 5. Material create -> write-back assignment, then the orchestrator returns.
    assign_yield = gen.send(final)
    assert assign_yield == {
        "activity": "activity_assign_recommendation",
        "input": {"payload": payload, "work_item_id": 1001, "action": "created"},
    }
    try:
        gen.send({"assigned": True})
    except StopIteration as stop:
        assert stop.value == final
    else:  # pragma: no cover - generator must terminate after the assignment
        raise AssertionError("orchestrator did not return after the assignment")


def test_orchestrator_skips_assignment_when_no_material_change() -> None:
    """A churn-suppressed skip returns immediately, with no write-back assignment."""
    payload = _payload()
    ctx = _RecordingContext(payload)
    gen = _orchestrate(ctx)
    next(gen)
    gen.send([55, {"owner": {"email": "a@b.com"}}])  # -> resolve_owner
    gen.send({"email": "a@b.com", "source": "tag"})  # -> build_triage_briefing
    gen.send("<div/>")  # -> create_or_update_work_item
    final = {"id": 55, "url": "u", "action": "skipped"}
    try:
        gen.send(final)
    except StopIteration as stop:
        assert stop.value == final
    else:  # pragma: no cover - generator must terminate after a skipped update
        raise AssertionError("orchestrator did not return after a skipped update")
    assert all(c["activity"] != "activity_assign_recommendation" for c in ctx.activity_calls)


def _owner_tag_for(enrichment: Any) -> Any:
    """Drive the generator up to the resolve_owner yield and return its input."""
    ctx = _RecordingContext(_payload())
    gen = _orchestrate(ctx)
    next(gen)
    resolve_yield = gen.send([None, enrichment])
    return resolve_yield["input"]


def test_owner_tag_extracted_when_present() -> None:
    """An ``owner.email`` in the enrichment bundle is passed to resolve_owner."""
    assert _owner_tag_for({"owner": {"email": "bob@contoso.com"}}) == "bob@contoso.com"


def test_owner_tag_none_when_enrichment_not_dict() -> None:
    """A non-dict enrichment (degraded fan-out) yields a ``None`` owner tag."""
    assert _owner_tag_for(None) is None


def test_owner_tag_none_when_owner_missing_or_malformed() -> None:
    """Missing or non-dict ``owner`` yields a ``None`` owner tag (no email key)."""
    assert _owner_tag_for({}) is None
    assert _owner_tag_for({"owner": "not-a-dict"}) is None
    assert _owner_tag_for({"owner": {}}) is None
