"""§4.3 — tests for enrichment models: defaults, degraded construction, round-trip."""

from __future__ import annotations

from models.enrichment import (
    AttackPath,
    AttackPathInfo,
    CveRecord,
    EnrichmentBundle,
    ExposureInfo,
    OtherRecsSummary,
    OwnerInfo,
    ResourceCriticality,
    VulnerabilityFindings,
)


def test_degraded_bundle_all_none() -> None:
    bundle = EnrichmentBundle()
    assert bundle.other_recs is None
    assert bundle.attack_paths is None
    assert bundle.vulnerabilities is None
    assert bundle.owner is None
    assert bundle.criticality is None
    assert bundle.exposure is None


def test_signal_defaults() -> None:
    assert OwnerInfo().source == "unknown"
    assert ResourceCriticality().level == "Unknown"
    assert ExposureInfo().internet_facing is False
    assert OtherRecsSummary().by_severity == {}
    assert VulnerabilityFindings().top_cves == []


def test_round_trip_serialization() -> None:
    bundle = EnrichmentBundle(
        other_recs=OtherRecsSummary(
            total=17, assigned=3, unassigned=14, by_severity={"High": 5, "Medium": 12}
        ),
        attack_paths=AttackPathInfo(
            paths=[AttackPath(id="ap1", display_name="Internet exposed VM", target="SQL")]
        ),
        vulnerabilities=VulnerabilityFindings(
            cve_count=8,
            max_cvss=9.8,
            top_cves=[CveRecord(id="CVE-2024-0001", cvss=9.8, description="rce")],
        ),
        owner=OwnerInfo(email="alice@contoso.com", source="tag"),
        criticality=ResourceCriticality(level="High", source="tag"),
        exposure=ExposureInfo(internet_facing=True, reasoning="Internet exposure"),
    )
    restored = EnrichmentBundle.model_validate(bundle.model_dump())
    assert restored == bundle
    assert restored.vulnerabilities is not None
    assert restored.vulnerabilities.max_cvss == 9.8
