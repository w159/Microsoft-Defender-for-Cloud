"""Unit tests for ``activities.assign_recommendation`` (§4.7).

The activity is best-effort write-back: gated behind ``MDC_WRITE_BACK_ENABLED``, run
only on a material create/update, and never raising. HTTP is mocked with ``respx`` and
the MDC client is built with a fake credential via the module seam.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx

import activities.assign_recommendation as assign
from clients.mdc_client import MdcClient

# Captured at import time so the seam test can exercise the *real* builder even while
# the autouse fixture below monkeypatches the module attribute.
_REAL_BUILD_MDC = assign._build_mdc_client

_ARM_HOST = "management.azure.com"
_RESOURCE_ID = (
    "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
)


class _FakeCredential:
    def __init__(self, *, error: Exception | None = None) -> None:
        self._error = error

    async def get_token(self, *scopes: str, **kwargs: Any) -> SimpleNamespace:
        if self._error is not None:
            raise self._error
        return SimpleNamespace(token="fake-token", expires_on=int(time.time() + 3600))

    async def close(self) -> None:  # pragma: no cover - parity with real credential
        return None


@pytest.fixture(autouse=True)
def _inject_fake_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        assign, "_build_mdc_client", lambda: MdcClient(credential=_FakeCredential())
    )


def _input(action: str = "created", *, wi: int = 42) -> dict[str, Any]:
    return {
        "payload": {
            "name": "assess-key-1",
            "properties": {
                "resourceDetails": {"id": _RESOURCE_ID},
                "metadata": {"severity": "High"},
            },
        },
        "work_item_id": wi,
        "action": action,
    }


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def test_assignment_owner_format(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MDC_ASSIGNMENT_OWNER_DOMAIN", "contoso.dev")
    assert assign.assignment_owner(7) == "ado-wi-7@contoso.dev"


def test_assignment_owner_default_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MDC_ASSIGNMENT_OWNER_DOMAIN", raising=False)
    assert assign.assignment_owner(7) == "ado-wi-7@ado.local"


def test_is_backref_owner_detects_our_refs_regardless_of_domain() -> None:
    assert assign.is_backref_owner("ado-wi-42@ado.local") is True
    assert assign.is_backref_owner("ADO-WI-42@whatever.com") is True
    assert assign.is_backref_owner("alice@contoso.com") is False
    assert assign.is_backref_owner("") is False


def test_assignment_key_is_deterministic() -> None:
    k1 = assign._assignment_key("assess-key-1", _RESOURCE_ID)
    k2 = assign._assignment_key("assess-key-1", _RESOURCE_ID)
    k3 = assign._assignment_key("assess-key-2", _RESOURCE_ID)
    assert k1 == k2
    assert k1 != k3


# --------------------------------------------------------------------------- #
# activity
# --------------------------------------------------------------------------- #


async def test_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MDC_WRITE_BACK_ENABLED", raising=False)
    result = await assign.activity_assign_recommendation(_input())
    assert result == {"assigned": False, "reason": "disabled"}


async def test_skips_non_material_action(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MDC_WRITE_BACK_ENABLED", "true")
    result = await assign.activity_assign_recommendation(_input(action="skipped"))
    assert result["assigned"] is False
    assert result["reason"] == "action=skipped"


async def test_skips_when_assessment_id_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MDC_WRITE_BACK_ENABLED", "true")
    payload_input: dict[str, Any] = {
        "payload": {"name": "k"},
        "work_item_id": 1,
        "action": "created",
    }
    result = await assign.activity_assign_recommendation(payload_input)
    assert result["assigned"] is False
    assert "missing" in result["reason"]


async def test_happy_path_puts_governance_assignment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MDC_WRITE_BACK_ENABLED", "true")
    monkeypatch.setenv("MDC_ASSIGNMENT_OWNER_DOMAIN", "ado.local")
    with respx.mock:
        route = respx.mock.route(method="PUT", host=_ARM_HOST).mock(
            return_value=httpx.Response(200, json={})
        )
        result = await assign.activity_assign_recommendation(_input(wi=42))

    assert result["assigned"] is True
    assert result["owner"] == "ado-wi-42@ado.local"
    req = route.calls.last.request
    assert "/providers/Microsoft.Security/assessments/assess-key-1/governanceAssignments/" in str(
        req.url
    )
    assert req.url.params["api-version"] == "2025-05-04"


async def test_degrades_when_write_back_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A governance write failure (e.g. missing Security Admin) never raises (§5.2.3)."""
    monkeypatch.setenv("MDC_WRITE_BACK_ENABLED", "true")
    with respx.mock:
        respx.mock.route(method="PUT", host=_ARM_HOST).mock(
            return_value=httpx.Response(403, text="forbidden")
        )
        result = await assign.activity_assign_recommendation(_input())
    assert result == {"assigned": False, "reason": "error"}


async def test_skips_when_already_assigned_409(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 409 (rec already has a governance assignment) is a clean skip, not an error (§4.7)."""
    monkeypatch.setenv("MDC_WRITE_BACK_ENABLED", "true")
    with respx.mock:
        respx.mock.route(method="PUT", host=_ARM_HOST).mock(
            return_value=httpx.Response(409, text="already exists with a different key")
        )
        result = await assign.activity_assign_recommendation(_input())
    assert result == {"assigned": False, "reason": "already-assigned"}


def test_default_mdc_client_seam_builds_client() -> None:
    """The real builder seam constructs an MdcClient (covers the default path, §7)."""
    assert isinstance(_REAL_BUILD_MDC(), MdcClient)
