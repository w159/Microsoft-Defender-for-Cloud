"""Unit tests for ``activities.build_triage_briefing`` (§4.5, §5.2.3)."""

from __future__ import annotations

from pathlib import Path

import activities.build_triage_briefing as briefing
from models.briefing import BriefingInput

_GOLDEN = Path(__file__).parent.parent.parent / "fixtures" / "golden"

_FULL_INPUT: dict[str, object] = {
    "payload": {
        "name": "assessment-guid-1",
        "properties": {
            "displayName": "Endpoint protection missing",
            "resourceDetails": {
                "id": (
                    "/subscriptions/1111-2222/resourceGroups/rg-web-prod/providers/"
                    "Microsoft.Compute/virtualMachines/contoso-web-01"
                )
            },
            "metadata": {
                "severity": "High",
                "description": "Install an endpoint protection solution on the virtual machine.",
                "remediationDescription": "Deploy Microsoft Defender for Endpoint via the portal.",
                "complianceStandards": ["PCI-DSS 4.0", "ISO 27001:2022"],
            },
        },
    },
    "enrichment": {
        "other_recs": {
            "total": 17,
            "assigned": 3,
            "unassigned": 14,
            "by_severity": {"High": 5, "Medium": 12},
        },
        "attack_paths": {
            "paths": [
                {"id": "ap1", "display_name": "Internet-exposed -> lateral move to SQL Server"},
                {
                    "id": "ap2",
                    "display_name": "Compromise -> privilege escalation to Subscription Owner",
                },
            ]
        },
        "vulnerabilities": {
            "cve_count": 8,
            "max_cvss": 9.8,
            "top_cves": [
                {"id": "CVE-2024-0001", "cvss": 9.8},
                {"id": "CVE-2024-0002", "cvss": 7.5},
            ],
        },
        "owner": {"email": "alice@contoso.com", "source": "tag"},
        "criticality": {"level": "High", "source": "tag"},
        "exposure": {"internet_facing": True, "reasoning": "Internet exposure"},
    },
    "owner": {"email": "alice@contoso.com", "source": "graph", "aad_object_id": "obj-1"},
}


async def test_build_triage_briefing_matches_golden() -> None:
    """The fully-enriched briefing renders identically to the golden snapshot (§4.5)."""
    html = await briefing.activity_build_triage_briefing(BriefingInput.model_validate(_FULL_INPUT))
    expected = (_GOLDEN / "triage_briefing_full.html").read_text()
    assert html == expected


async def test_build_triage_briefing_degraded_omits_sections() -> None:
    """With no enrichment, guarded sections are omitted but the briefing still renders."""
    degraded: dict[str, object] = {
        "payload": {
            "name": "assessment-guid-2",
            "properties": {
                "displayName": "Secure transfer required",
                "resourceDetails": {
                    "id": (
                        "/subscriptions/1111-2222/resourceGroups/rg-data/providers/"
                        "Microsoft.Storage/storageAccounts/contosostore"
                    )
                },
                "metadata": {"severity": "Medium"},
            },
        },
        "enrichment": {},
        "owner": None,
    }
    html = await briefing.activity_build_triage_briefing(BriefingInput.model_validate(degraded))

    assert "🚨 [MEDIUM] contosostore — Secure transfer required" in html
    assert "Blast Radius" not in html
    assert "Recommendation Detail" not in html
    assert "Compliance" not in html
    assert "Owner:" not in html


async def test_build_triage_briefing_strips_injected_html() -> None:
    """User-controlled MDC text is stripped of markup to prevent HTML injection (security)."""
    payload: dict[str, object] = {
        "payload": {
            "name": "a",
            "properties": {
                "displayName": "x",
                "resourceDetails": {"id": "/subscriptions/s/resourceGroups/rg/providers/p/t/n"},
                "metadata": {
                    "severity": "Low",
                    "description": "<script>alert('xss')</script>",
                },
            },
        },
        "enrichment": {},
        "owner": None,
    }
    html = await briefing.activity_build_triage_briefing(BriefingInput.model_validate(payload))
    assert "<script>" not in html
    assert "alert" not in html
    assert "&lt;script&gt;" not in html


async def test_build_triage_briefing_cleans_mdc_html_to_plain_text() -> None:
    """MDC HTML fragments render as clean plain text with logical line breaks (§4.5)."""
    payload: dict[str, object] = {
        "payload": {
            "name": "a",
            "properties": {
                "displayName": "x",
                "resourceDetails": {"id": "/subscriptions/s/resourceGroups/rg/providers/p/t/n"},
                "metadata": {
                    "severity": "Low",
                    "description": (
                        "Overprovisioned identities in Azure are risky.<br> Regularly adjust "
                        "permissions.<br>"
                    ),
                    "remediationDescription": (
                        "Remediate identities.</br> 1.Login to "
                        '<a href="https://ms.portal.azure.com/#home">Azure portal</a></br>'
                        "2.Navigate to 'Microsoft Entra ID'</br>"
                    ),
                },
            },
        },
        "enrichment": {},
        "owner": None,
    }
    html = await briefing.activity_build_triage_briefing(BriefingInput.model_validate(payload))
    # No source markup survives.
    assert "</br>" not in html
    assert "ms.portal.azure.com" not in html  # the MDC-supplied <a href> URL is stripped
    assert "Azure portal" in html
    # Logical breaks become a single <br>; readable text remains.
    assert "Overprovisioned identities in Azure are risky.<br>" in html
    assert "1.Login to Azure portal<br>" in html
    assert "2.Navigate to &#39;Microsoft Entra ID&#39;" in html
