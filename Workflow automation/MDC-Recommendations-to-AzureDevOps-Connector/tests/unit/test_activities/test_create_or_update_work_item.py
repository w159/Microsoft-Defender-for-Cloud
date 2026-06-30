"""Unit tests for ``activities.create_or_update_work_item`` (§4.4, §5.2, §5.2.5)."""

from __future__ import annotations

import json
import time
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx
from freezegun import freeze_time

import activities.create_or_update_work_item as cou
from clients.ado_client import AdoClient, AdoClientError
from models.briefing import WorkItemResult

# Captured at import time so the seam test can exercise the *real* builder even
# while the autouse fixture below monkeypatches the module attribute.
_REAL_BUILD_ADO = cou._build_ado_client

_ADO_HOST = "dev.azure.com"
_RESOURCE_ID = (
    "/subscriptions/sub-1/resourceGroups/rg-web/providers/"
    "Microsoft.Compute/virtualMachines/contoso-web-01"
)


class _FakeCredential:
    async def get_token(self, *scopes: str, **kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(token="fake-token", expires_on=int(time.time() + 3600))

    async def close(self) -> None:  # pragma: no cover - parity with real credential
        return None


@pytest.fixture(autouse=True)
def _ado_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADO_ORG_URL", "https://dev.azure.com/contoso")
    monkeypatch.setenv("ADO_PROJECT", "Security")
    monkeypatch.setattr(cou, "_build_ado_client", lambda: AdoClient(credential=_FakeCredential()))


def _input(existing_wi_id: int | None = None) -> dict[str, Any]:
    return {
        "payload": {
            "name": "assessment-guid-1",
            "properties": {
                "displayName": "Endpoint protection missing",
                "resourceDetails": {"id": _RESOURCE_ID},
                "metadata": {
                    "severity": "High",
                    "complianceStandards": ["PCI-DSS 4.0"],
                },
            },
        },
        "enrichment": {
            "attack_paths": {"paths": [{"id": "ap1", "display_name": "x"}]},
            "vulnerabilities": {"cve_count": 3, "max_cvss": 9.1, "top_cves": []},
            "criticality": {"level": "Critical", "source": "tag"},
            "other_recs": {"total": 5, "assigned": 1, "unassigned": 4},
        },
        "owner": {"email": "alice@contoso.com", "source": "graph"},
        "briefing": "<div>briefing</div>",
        "existing_wi_id": existing_wi_id,
    }


def _expected_hash(briefing: str = "<div>briefing</div>") -> str:
    return cou._material_hash(
        severity="High",
        briefing=briefing,
        attack_path_count=1,
        cve_count=3,
        max_cvss=9.1,
        criticality="Critical",
        owner="alice@contoso.com",
    )


@freeze_time("2026-06-23T12:00:00Z")
async def test_create_new_work_item() -> None:
    """No existing id -> POST create with the full field set incl. FirstDetected + hash."""
    with respx.mock:
        route = respx.mock.route(
            method="POST", host=_ADO_HOST, path__regex=r".*/workitems/\$.*"
        ).mock(
            return_value=httpx.Response(
                200,
                json={"id": 1001, "_links": {"html": {"href": "https://ado/1001"}}},
            )
        )
        result = WorkItemResult.model_validate(
            await cou.activity_create_or_update_work_item(_input())
        )

    assert result.action == "created"
    assert result.id == 1001
    patch = json.loads(route.calls.last.request.content)
    ops = {op["path"]: op["value"] for op in patch}
    assert ops["/fields/Custom.MaterialHash"] == _expected_hash()
    assert ops["/fields/Custom.FirstDetected"].startswith("2026-06-23")
    assert ops["/fields/Microsoft.VSTS.Common.Priority"] == 1
    assert ops["/fields/Custom.OnAttackPath"] is True
    assert "Critical" in ops["/fields/System.Tags"]


@freeze_time("2026-06-23T12:00:00Z")
async def test_update_skipped_when_hash_unchanged() -> None:
    """Existing WI with a matching material hash -> skipped (no PATCH) (§5.2.5)."""
    with respx.mock:
        get_route = respx.mock.route(
            method="GET", host=_ADO_HOST, path__regex=r".*/workitems/77$"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": 77,
                    "url": "https://ado/77",
                    "fields": {"Custom.MaterialHash": _expected_hash()},
                },
            )
        )
        patch_route = respx.mock.route(
            method="PATCH", host=_ADO_HOST, path__regex=r".*/workitems/77$"
        )
        result = WorkItemResult.model_validate(
            await cou.activity_create_or_update_work_item(_input(existing_wi_id=77))
        )

    assert result.action == "skipped"
    assert result.id == 77
    assert get_route.call_count == 1
    assert patch_route.call_count == 0


@freeze_time("2026-06-23T12:00:00Z")
async def test_update_patches_on_material_change() -> None:
    """Existing WI with a different stored hash -> PATCH + comment (§5.2.5)."""
    with respx.mock:
        respx.mock.route(method="GET", host=_ADO_HOST, path__regex=r".*/workitems/77$").mock(
            return_value=httpx.Response(
                200,
                json={"id": 77, "fields": {"Custom.MaterialHash": "stale-hash"}},
            )
        )
        patch_route = respx.mock.route(
            method="PATCH", host=_ADO_HOST, path__regex=r".*/workitems/77$"
        ).mock(
            return_value=httpx.Response(
                200, json={"id": 77, "_links": {"html": {"href": "https://ado/77"}}}
            )
        )
        comment_route = respx.mock.route(
            method="POST", host=_ADO_HOST, path__regex=r".*/comments$"
        ).mock(return_value=httpx.Response(200, json={"id": 9}))
        result = WorkItemResult.model_validate(
            await cou.activity_create_or_update_work_item(_input(existing_wi_id=77))
        )

    assert result.action == "updated"
    assert patch_route.call_count == 1
    assert comment_route.call_count == 1
    patch = json.loads(patch_route.calls.last.request.content)
    ops = {op["path"]: op["value"] for op in patch}
    assert ops["/fields/Custom.MaterialHash"] == _expected_hash()
    # Churn control: never rewrite FirstDetected on update.
    assert "/fields/Custom.FirstDetected" not in ops
    assert "/fields/Custom.LastSeen" in ops


async def test_create_or_update_raises_on_ado_error() -> None:
    """A persistent ADO 5xx is re-raised so Durable retry fires (§5.2)."""
    with respx.mock:
        respx.mock.route(method="POST", host=_ADO_HOST, path__regex=r".*/workitems/\$.*").mock(
            return_value=httpx.Response(500, json={"error": "boom"})
        )
        with pytest.raises(AdoClientError):
            await cou.activity_create_or_update_work_item(_input())


def test_build_ado_client_seam_returns_real_client() -> None:
    """The real ``_build_ado_client`` seam constructs an ``AdoClient`` (§7)."""
    client = _REAL_BUILD_ADO()
    assert isinstance(client, AdoClient)
