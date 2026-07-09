#!/usr/bin/env python3
"""Provision the Azure DevOps process schema the MDC -> ADO Connector requires (§4.4).

Creates (idempotently):
  1. An inherited process ("MDC Security") from the system "Basic" process.
  2. A "Security Recommendation" work-item type in that process.
  3. The 16 ``Custom.*`` fields the connector PATCHes, with the correct data types.
  4. Attaches the two built-in fields the connector also writes
     (``Microsoft.VSTS.Common.Priority``, ``Microsoft.VSTS.Scheduling.DueDate``).

This is a one-off operations script. It is intentionally dependency-free (stdlib
``urllib`` only) so it never touches the Function's runtime dependency set, and it is
**dry-run by default** — it prints the planned actions and mutates ADO only when run
with ``--apply``.

Auth: a bearer token for the Azure DevOps resource. Either set ``ADO_TOKEN`` or rely on
the Azure CLI fallback (``az account get-access-token --resource <ADO app id>``).

NOTE: Moving an existing project onto the new process is **not** performed here — the
public REST surface for that is not stable. After this script succeeds, switch your
project (e.g. ``MDC-WorkItems``) to the "MDC Security" process in the portal:
  Organization settings -> Boards -> Process -> "MDC Security" -> (...) -> Move projects.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

# Azure DevOps Entra application id (token audience). Matches the connector (§6.1).
_ADO_RESOURCE = "499b84ac-1321-427f-aa17-267ca6975798"

_PROCESS_API = "7.1-preview.2"
_WIT_API = "7.1"

_WIT_NAME = "Security Recommendation"
_WIT_DESCRIPTION = "Microsoft Defender for Cloud security recommendation (auto-created)."


@dataclass(frozen=True)
class FieldSpec:
    """A custom field to create at the collection level and attach to the WIT."""

    reference_name: str
    name: str
    type: str
    description: str


# The 16 Custom.* fields, typed per the WorkItemFields model (src/function/models/briefing.py).
_CUSTOM_FIELDS: tuple[FieldSpec, ...] = (
    FieldSpec("Custom.MDCAssessmentId", "MDC Assessment Id", "string", "MDC assessment GUID."),
    FieldSpec("Custom.MDCResourceId", "MDC Resource Id", "string", "Target Azure resource id."),
    FieldSpec("Custom.Severity", "MDC Severity", "string", "MDC severity (High/Medium/Low)."),
    FieldSpec("Custom.SubscriptionId", "Subscription Id", "string", "Azure subscription GUID."),
    FieldSpec("Custom.ResourceType", "Resource Type", "string", "Azure resource type."),
    FieldSpec(
        "Custom.ComplianceStandards",
        "Compliance Standards",
        "string",
        "Comma-separated compliance standards impacted.",
    ),
    FieldSpec("Custom.SuggestedOwner", "Suggested Owner", "string", "Resolved owner contact."),
    FieldSpec("Custom.Criticality", "Criticality", "string", "Resource criticality tier."),
    FieldSpec(
        "Custom.OnAttackPath", "On Attack Path", "boolean", "Resource sits on an attack path."
    ),
    FieldSpec("Custom.AttackPathCount", "Attack Path Count", "integer", "Number of attack paths."),
    FieldSpec(
        "Custom.OtherOpenRecsCount",
        "Other Open Recs Count",
        "integer",
        "Other open recommendations on the resource.",
    ),
    FieldSpec("Custom.CVECount", "CVE Count", "integer", "Distinct CVEs found."),
    FieldSpec("Custom.MaxCVSS", "Max CVSS", "double", "Highest CVSS score among findings."),
    FieldSpec("Custom.FirstDetected", "First Detected", "dateTime", "First detection timestamp."),
    FieldSpec("Custom.LastSeen", "Last Seen", "dateTime", "Most recent detection timestamp."),
    FieldSpec("Custom.MaterialHash", "Material Hash", "string", "Churn-control material hash."),
)

# Built-in fields the connector also writes; they exist at the collection level already
# and only need attaching to the new work-item type.
_BUILTIN_FIELDS: tuple[str, ...] = (
    "Microsoft.VSTS.Common.Priority",
    "Microsoft.VSTS.Scheduling.DueDate",
)


class AdoError(RuntimeError):
    """Raised when an Azure DevOps REST call fails unexpectedly."""


def _get_token() -> str:
    """Return a bearer token from ADO_TOKEN or the Azure CLI fallback."""
    import os

    token = os.environ.get("ADO_TOKEN", "").strip()
    if token:
        return token
    try:
        out = subprocess.run(
            ["az", "account", "get-access-token", "--resource", _ADO_RESOURCE,
             "--query", "accessToken", "-o", "tsv"],
            capture_output=True, text=True, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise AdoError("could not obtain an ADO token (set ADO_TOKEN or login via az)") from exc
    token = out.stdout.strip()
    if not token:
        raise AdoError("az returned an empty ADO token")
    return token


def _request(
    method: str, url: str, token: str, body: dict[str, Any] | None = None
) -> tuple[int, Any]:
    """Issue an ADO REST call and return ``(status, parsed_json_or_text)``."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:  # noqa: S310 - fixed https ADO host
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, raw


def _org_base(org: str) -> str:
    return f"https://dev.azure.com/{org}"


def _find_process(org: str, token: str, name: str) -> dict[str, Any] | None:
    url = f"{_org_base(org)}/_apis/work/processes?api-version={_PROCESS_API}"
    status, payload = _request("GET", url, token)
    if status != 200:
        raise AdoError(f"list processes failed: HTTP {status}: {payload}")
    for proc in payload.get("value", []):
        if proc.get("name", "").lower() == name.lower():
            return proc
    return None


def _ensure_process(org: str, token: str, name: str, parent: str, apply: bool) -> str:
    """Create the inherited process if absent; return its typeId."""
    existing = _find_process(org, token, name)
    if existing is not None:
        print(f"  [skip] process '{name}' already exists (typeId={existing['typeId']})")
        return str(existing["typeId"])
    parent_proc = _find_process(org, token, parent)
    if parent_proc is None:
        raise AdoError(f"parent process '{parent}' not found")
    print(f"  [plan] create process '{name}' inheriting from '{parent}'")
    if not apply:
        return "<dry-run-process-id>"
    status, payload = _request(
        "POST", f"{_org_base(org)}/_apis/work/processes?api-version={_PROCESS_API}", token,
        {"name": name, "parentProcessTypeId": parent_proc["typeId"],
         "description": "Inherited process for the MDC -> ADO Connector."},
    )
    if status not in (200, 201):
        raise AdoError(f"create process failed: HTTP {status}: {payload}")
    print(f"  [done] created process '{name}' (typeId={payload['typeId']})")
    return str(payload["typeId"])


def _find_wit(org: str, token: str, process_id: str, name: str) -> dict[str, Any] | None:
    url = (
        f"{_org_base(org)}/_apis/work/processes/{process_id}"
        f"/workitemtypes?api-version={_PROCESS_API}"
    )
    status, payload = _request("GET", url, token)
    if status != 200:
        raise AdoError(f"list work-item types failed: HTTP {status}: {payload}")
    for wit in payload.get("value", []):
        if wit.get("name", "").lower() == name.lower():
            return wit
    return None


def _ensure_wit(org: str, token: str, process_id: str, apply: bool) -> str:
    """Create the Security Recommendation WIT if absent; return its referenceName."""
    if process_id.startswith("<dry-run"):
        print(f"  [plan] create work-item type '{_WIT_NAME}' (deferred; process not yet created)")
        return "<dry-run-wit-ref>"
    existing = _find_wit(org, token, process_id, _WIT_NAME)
    if existing is not None:
        print(
            f"  [skip] work-item type '{_WIT_NAME}' already exists "
            f"(ref={existing['referenceName']})"
        )
        return str(existing["referenceName"])
    print(f"  [plan] create work-item type '{_WIT_NAME}'")
    if not apply:
        return "<dry-run-wit-ref>"
    url = (
        f"{_org_base(org)}/_apis/work/processes/{process_id}"
        f"/workitemtypes?api-version={_PROCESS_API}"
    )
    status, payload = _request(
        "POST", url, token,
        {"name": _WIT_NAME, "description": _WIT_DESCRIPTION, "color": "f6546a",
         "icon": "icon_clipboard", "isDisabled": False},
    )
    if status not in (200, 201):
        raise AdoError(f"create work-item type failed: HTTP {status}: {payload}")
    print(f"  [done] created work-item type (ref={payload['referenceName']})")
    return str(payload["referenceName"])


def _field_exists(org: str, token: str, reference_name: str) -> bool:
    url = f"{_org_base(org)}/_apis/wit/fields/{reference_name}?api-version={_WIT_API}"
    status, _ = _request("GET", url, token)
    return status == 200


def _ensure_collection_field(org: str, token: str, spec: FieldSpec, apply: bool) -> None:
    if _field_exists(org, token, spec.reference_name):
        print(f"  [skip] field {spec.reference_name} already exists")
        return
    print(f"  [plan] create field {spec.reference_name} ({spec.type})")
    if not apply:
        return
    url = f"{_org_base(org)}/_apis/wit/fields?api-version={_WIT_API}"
    status, payload = _request(
        "POST", url, token,
        {"name": spec.name, "referenceName": spec.reference_name, "type": spec.type,
         "description": spec.description, "usage": "workItem", "readOnly": False,
         "canSortBy": True, "isQueryable": True},
    )
    if status not in (200, 201):
        raise AdoError(f"create field {spec.reference_name} failed: HTTP {status}: {payload}")
    print(f"  [done] created field {spec.reference_name}")


def _wit_field_attached(
    org: str, token: str, process_id: str, wit_ref: str, field_ref: str
) -> bool:
    url = (f"{_org_base(org)}/_apis/work/processes/{process_id}/workItemTypes/"
           f"{wit_ref}/fields/{field_ref}?api-version={_PROCESS_API}")
    status, _ = _request("GET", url, token)
    return status == 200


def _attach_field(
    org: str,
    token: str,
    process_id: str,
    wit_ref: str,
    field_ref: str,
    apply: bool,
    is_boolean: bool = False,
) -> None:
    if wit_ref.startswith("<dry-run") or process_id.startswith("<dry-run"):
        print(f"  [plan] attach {field_ref} to {_WIT_NAME} (deferred; WIT not yet created)")
        return
    if _wit_field_attached(org, token, process_id, wit_ref, field_ref):
        print(f"  [skip] {field_ref} already on {_WIT_NAME}")
        return
    print(f"  [plan] attach {field_ref} to {_WIT_NAME}")
    if not apply:
        return
    url = (f"{_org_base(org)}/_apis/work/processes/{process_id}/workItemTypes/"
           f"{wit_ref}/fields?api-version={_PROCESS_API}")
    body: dict[str, Any] = {
        "referenceName": field_ref,
        "required": False,
        "readOnly": False,
        "allowGroups": False,
    }
    # Boolean fields must be required and carry a string "false" default to be added.
    if is_boolean:
        body["required"] = True
        body["defaultValue"] = "false"
    status, payload = _request("POST", url, token, body)
    if status not in (200, 201):
        raise AdoError(f"attach field {field_ref} failed: HTTP {status}: {payload}")
    print(f"  [done] attached {field_ref}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Provision ADO process schema for the MDC connector."
    )
    parser.add_argument(
        "--org", required=True, help="Azure DevOps organization (e.g. your-org)."
    )
    parser.add_argument(
        "--project", required=True, help="Target project (for the manual move note)."
    )
    parser.add_argument(
        "--process-name", default="MDC Security", help="Inherited process name to create/use."
    )
    parser.add_argument("--parent", default="Basic", help="System process to inherit from.")
    parser.add_argument(
        "--apply", action="store_true", help="Actually mutate ADO (default: dry-run)."
    )
    args = parser.parse_args(argv)

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"== MDC ADO schema provisioning ({mode}) :: org={args.org} project={args.project} ==")
    token = _get_token()

    print("\n[1/4] Inherited process")
    process_id = _ensure_process(args.org, token, args.process_name, args.parent, args.apply)

    print("\n[2/4] Work-item type")
    wit_ref = _ensure_wit(args.org, token, process_id, args.apply)

    print("\n[3/4] Custom fields (collection level)")
    for spec in _CUSTOM_FIELDS:
        _ensure_collection_field(args.org, token, spec, args.apply)

    print("\n[4/4] Attach fields to the work-item type")
    for spec in _CUSTOM_FIELDS:
        _attach_field(
            args.org, token, process_id, wit_ref, spec.reference_name, args.apply,
            is_boolean=spec.type == "boolean",
        )
    for field_ref in _BUILTIN_FIELDS:
        _attach_field(args.org, token, process_id, wit_ref, field_ref, args.apply)

    print("\n== complete ==")
    if not args.apply:
        print("Dry-run only — re-run with --apply to make changes.")
    else:
        print(
            f"Next: move project '{args.project}' onto the "
            f"'{args.process_name}' process in the portal:"
        )
        print("  Org settings -> Boards -> Process -> 'MDC Security' -> (...) -> Move projects.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
