"""Unit tests for ``activities.dedupe_lookup`` (§5.1, §5.2, §5.2.3)."""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx

import activities.dedupe_lookup as dedupe
from clients.ado_client import AdoClient
from models.mdc_payload import MdcRecommendationPayload

# Captured at import time so the seam test can exercise the *real* builder even
# while the autouse fixture below monkeypatches the module attribute.
_REAL_BUILD_ADO = dedupe._build_ado_client

_ADO_HOST = "dev.azure.com"
_RESOURCE_ID = (
    "/subscriptions/sub-1/resourceGroups/rg-web/providers/"
    "Microsoft.Compute/virtualMachines/contoso-web-01"
)


class _FakeCredential:
    """Async credential test double mirroring ``AsyncTokenCredential`` (§7)."""

    async def get_token(self, *scopes: str, **kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(token="fake-token", expires_on=int(time.time() + 3600))

    async def close(self) -> None:  # pragma: no cover - parity with real credential
        return None


@pytest.fixture(autouse=True)
def _ado_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADO_ORG_URL", "https://dev.azure.com/contoso")
    monkeypatch.setenv("ADO_PROJECT", "Security")
    monkeypatch.setattr(
        dedupe, "_build_ado_client", lambda: AdoClient(credential=_FakeCredential())
    )


def _payload() -> MdcRecommendationPayload:
    return MdcRecommendationPayload.model_validate(
        {
            "name": "assessment-guid-1",
            "properties": {"resourceDetails": {"id": _RESOURCE_ID}},
        }
    )


def _wiql_route() -> respx.Route:
    return respx.mock.route(method="POST", host=_ADO_HOST, path__regex=r".*/wiql")


async def test_dedupe_lookup_returns_existing_id() -> None:
    """A WIQL match returns the first matching Work Item id."""
    with respx.mock:
        route = _wiql_route().mock(
            return_value=httpx.Response(200, json={"workItems": [{"id": 4242}, {"id": 99}]})
        )
        result = await dedupe.activity_dedupe_lookup(_payload())

    assert result == 4242
    body = route.calls.last.request.content.decode()
    assert "Custom.MDCAssessmentId" in body
    assert "Custom.MDCResourceId" in body
    assert "System.State" in body


async def test_dedupe_lookup_no_match_returns_none() -> None:
    """An empty WIQL result returns ``None`` (no existing Work Item)."""
    with respx.mock:
        _wiql_route().mock(return_value=httpx.Response(200, json={"workItems": []}))
        result = await dedupe.activity_dedupe_lookup(_payload())

    assert result is None


async def test_dedupe_lookup_degrades_on_error() -> None:
    """A persistent ADO 5xx degrades to ``None``, never raising (§5.2.3)."""
    with respx.mock:
        _wiql_route().mock(return_value=httpx.Response(500, json={"error": "boom"}))
        result = await dedupe.activity_dedupe_lookup(_payload())

    assert result is None


async def test_dedupe_lookup_missing_key_returns_none() -> None:
    """Without a dedupe key the lookup short-circuits to ``None``."""
    payload = MdcRecommendationPayload.model_validate({"name": "a"})
    assert await dedupe.activity_dedupe_lookup(payload) is None


def test_build_ado_client_seam_returns_real_client() -> None:
    """The real ``_build_ado_client`` seam constructs an ``AdoClient`` (§7)."""
    client = _REAL_BUILD_ADO()
    assert isinstance(client, AdoClient)
