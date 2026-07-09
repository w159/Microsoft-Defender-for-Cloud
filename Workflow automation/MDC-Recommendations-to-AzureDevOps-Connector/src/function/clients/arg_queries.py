"""§4.3 — composable Azure Resource Graph (KQL) fragments for enrichment signals.

Each builder returns a standalone KQL query string that targets the ARG
``securityresources`` / ``resources`` tables. Per the §4.3 implementation note,
signals 1, 2, 3, 4, 7 and 8 are ARG-served and should be combined into one or two
batches; :func:`union_queries` joins fragments into a single ARG request so the
15-queries / 5-sec throttle is respected.

Signal coverage (see §4.3):

* #1 other open recommendations  -> :func:`other_open_recommendations`
* #2 governance assignments       -> :func:`governance_assignments`
* #3 attack paths (and #7 exposure, derived) -> :func:`attack_paths_for_resource`
* #4 vulnerability sub-assessments -> :func:`vulnerability_subassessments`
* #5 owner tags / #8 resource facts -> :func:`resource_details`
"""

from __future__ import annotations


def escape_kql_string(value: str) -> str:
    """Escape a value for safe embedding inside a single-quoted KQL literal.

    KQL single-quoted strings escape a backslash and a single quote with a
    leading backslash. Escaping defends against query breakage (and injection)
    when a resource id or tag value contains those characters (§4.3).
    """
    return value.replace("\\", "\\\\").replace("'", "\\'")


def other_open_recommendations(resource_id: str) -> str:
    """§4.3 #1 — open (Unhealthy) MDC assessments on the affected resource.

    The ``assessments`` table stores the target id PascalCase as
    ``resourceDetails.Id``/``ResourceId`` (NOT lowercase ``id``); KQL dynamic field
    access is case-sensitive, so coalesce the known casings or the filter silently
    matches nothing.
    """
    rid = escape_kql_string(resource_id)
    return (
        "securityresources\n"
        "| where type =~ 'microsoft.security/assessments'\n"
        "| extend _rid = tostring(coalesce(\n"
        "    properties.resourceDetails.Id,\n"
        "    properties.resourceDetails.ResourceId,\n"
        "    properties.resourceDetails.id))\n"
        f"| where _rid =~ '{rid}'\n"
        "| where properties.status.code =~ 'Unhealthy'\n"
        "| project signalKind = 'otherRecs',\n"
        "          assessmentId = name,\n"
        "          displayName = tostring(properties.displayName),\n"
        "          severity = tostring(properties.metadata.severity),\n"
        "          status = tostring(properties.status.code)"
    )


def governance_assignments(resource_id: str) -> str:
    """§4.3 #2 — governance assignments (owner + due date) on the resource's assessments.

    Governance assignments carry no ``resourceDetails``; they reference the assessment via
    ``properties.assignedResourceId`` (``<resourceId>/providers/Microsoft.Security/
    assessments/<assessmentId>``). Match on that prefix and recover the assessment id so
    recs can be split into assigned vs unassigned (§4.3 #1).
    """
    rid = escape_kql_string(resource_id)
    return (
        "securityresources\n"
        "| where type =~ 'microsoft.security/assessments/governanceassignments'\n"
        "| extend _arid = tostring(properties.assignedResourceId)\n"
        f"| where _arid startswith '{rid}'\n"
        "| project signalKind = 'governance',\n"
        "          assessmentId = tostring(split(_arid, '/assessments/')[1]),\n"
        "          owner = tostring(properties.owner),\n"
        "          dueDate = tostring(properties.remediationDueDate)"
    )


def attack_paths_for_resource(resource_id: str) -> str:
    """§4.3 #3 / #7 — attack paths the resource participates in.

    Attack paths reference their members by an internal security-graph entity id, not
    the ARM id, so ``targetEntityInternalId``/``entryPointEntityInternalId`` cannot be
    matched against a resource id directly. The affected ARM resource is found in
    ``properties.graphComponent.entities[].entityIdentifiers.azureResourceId``; expand
    the entities and match that. Internet exposure (signal #7) is derived from
    ``properties.riskFactors`` on the returned rows.
    """
    rid = escape_kql_string(resource_id)
    return (
        "securityresources\n"
        "| where type =~ 'microsoft.security/attackpaths'\n"
        "| mv-expand entity = properties.graphComponent.entities\n"
        "| extend _erid = tostring(entity.entityIdentifiers.azureResourceId)\n"
        f"| where _erid =~ '{rid}'\n"
        "| project signalKind = 'attackPath',\n"
        "          attackPathId = name,\n"
        "          displayName = tostring(properties.displayName),\n"
        "          description = tostring(properties.description),\n"
        "          riskFactors = properties.riskFactors"
    )


def vulnerability_subassessments(resource_id: str) -> str:
    """§4.3 #4 — CVE vulnerability sub-assessments for the resource.

    The ``subassessments`` table stores ``resourceDetails`` with a lowercase ``id`` (unlike
    the ``assessments`` table); coalesce the known casings defensively. Only true CVE
    findings are selected — baseline/configuration ``GeneralVulnerability`` sub-assessments
    are excluded as they overlap with the open-recs signal (§4.3 #1).
    """
    rid = escape_kql_string(resource_id)
    return (
        "securityresources\n"
        "| where type =~ 'microsoft.security/assessments/subassessments'\n"
        "| extend _rid = tostring(coalesce(\n"
        "    properties.resourceDetails.id,\n"
        "    properties.resourceDetails.Id,\n"
        "    properties.resourceDetails.ResourceId))\n"
        f"| where _rid =~ '{rid}'\n"
        "| extend _art = tostring(properties.additionalData.assessedResourceType)\n"
        "| extend _cve = coalesce(\n"
        "    tostring(properties.additionalData.cve),\n"
        "    tostring(properties.id))\n"
        "| where _art in~ ('ContainerRegistryVulnerability', 'ContainerImageVulnerability',\n"
        "                  'ServerVulnerabilityAssessment', 'MachineVulnerabilityAssessment')\n"
        "   or _cve startswith 'CVE-'\n"
        "| project signalKind = 'vulnerability',\n"
        "          cve = _cve,\n"
        "          cvss = todouble(coalesce(\n"
        "              properties.additionalData.cvss['3.1'].base,\n"
        "              properties.additionalData.cvss['3.0'].base,\n"
        "              properties.additionalData.cvss['2.0'].base)),\n"
        "          description = tostring(properties.description),\n"
        "          severity = tostring(properties.status.severity)"
    )


def resource_details(resource_id: str) -> str:
    """§4.3 #5 / #8 — owner tags plus resource type/location/sub/RG facts."""
    rid = escape_kql_string(resource_id)
    return (
        "resources\n"
        f"| where id =~ '{rid}'\n"
        "| project signalKind = 'resource',\n"
        "          id,\n"
        "          name,\n"
        "          type,\n"
        "          location,\n"
        "          subscriptionId,\n"
        "          resourceGroup,\n"
        "          owner = tostring(tags.Owner),\n"
        "          securityContact = tostring(tags.SecurityContact),\n"
        "          criticality = tostring(tags.Criticality)"
    )


def union_queries(*queries: str) -> str:
    """Combine fragments into one ARG request to respect the throttle (§4.3).

    ARG does not accept the leading ``union (a), (b)`` form (it fails to resolve the
    first table); the batch must be expressed as ``<head> | union (b), (c), ...`` where
    the first fragment stays unwrapped and the rest are parenthesized subqueries. Each
    fragment projects a ``signalKind`` discriminator so a single POST returns rows for
    every signal. Raises ``ValueError`` if called with no fragments.
    """
    if not queries:
        raise ValueError("union_queries requires at least one query fragment")
    head, *rest = queries
    if not rest:
        return head
    wrapped = ",\n".join(f"(\n{q}\n)" for q in rest)
    return f"{head}\n| union\n{wrapped}"
