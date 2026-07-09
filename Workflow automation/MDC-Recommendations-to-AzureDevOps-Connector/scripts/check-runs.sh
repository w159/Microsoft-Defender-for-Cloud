#!/usr/bin/env bash
#
# check-runs.sh — triage Logic App dispatches vs. ADO Work Items.
#
# For each recent Logic App run it prints the recommendation it forwarded
# (assessment + resource) and whether a matching ADO Work Item already exists —
# so you can tell a correct dedupe/skip ("WI already exists, unchanged") from a
# genuinely missing Work Item ("NO WI — would create").
#
# Why this is needed: a Logic App run showing "Succeeded" only means the 202
# dispatch was forwarded, NOT that a Work Item was created. A churn-suppressed
# skip (same recommendation re-fired with no material change) is deliberately
# invisible (§5.2.5), and Flex Consumption telemetry is unreliable. The
# authoritative check is the ADO WIQL on Custom.MDCAssessmentId + MDCResourceId,
# which is exactly what this script does.
#
# Usage:   scripts/check-runs.sh [N]      # N = number of recent runs (default 8)
# Requires: az logged in (az login). Override defaults via env vars below.
#
set -euo pipefail
set +H  # disable history expansion (resource ids contain no '!', but be safe)

SUB="${SUB:?set SUB to your subscription id}"
RG="${RG:-rg-mdc-ado-dev}"
LA="${LA:-la-mdc-ado-dispatcher}"
ADO_ORG="${ADO_ORG:?set ADO_ORG, e.g. https://dev.azure.com/your-org}"
ADO_PROJECT="${ADO_PROJECT:?set ADO_PROJECT to your project name}"
ADO_RESOURCE="499b84ac-1321-427f-aa17-267ca6975798"  # Azure DevOps Entra app id
N="${1:-8}"

echo "Acquiring tokens (az)…" >&2
ARM_TOKEN=$(az account get-access-token --resource https://management.azure.com --query accessToken -o tsv)
ADO_TOKEN=$(az account get-access-token --resource "$ADO_RESOURCE" --query accessToken -o tsv)

RUNS=$(az rest --method get \
  --uri "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Logic/workflows/$LA/runs?api-version=2016-06-01")

RUNS_FILE=$(mktemp)
trap 'rm -f "$RUNS_FILE"' EXIT
printf '%s' "$RUNS" > "$RUNS_FILE"

RUNS_FILE="$RUNS_FILE" ARM_TOKEN="$ARM_TOKEN" ADO_TOKEN="$ADO_TOKEN" \
  ADO_ORG="$ADO_ORG" ADO_PROJECT="$ADO_PROJECT" N="$N" python3 - <<'PY'
import json, os, urllib.request

ado = os.environ["ADO_TOKEN"]; org = os.environ["ADO_ORG"]; proj = os.environ["ADO_PROJECT"]
n = int(os.environ["N"])
with open(os.environ["RUNS_FILE"], encoding="utf-8") as fh:
    runs = json.load(fh).get("value", [])[:n]


def _get(url, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return json.load(urllib.request.urlopen(urllib.request.Request(url, headers=headers)))


def _post(url, token, body):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    return json.load(urllib.request.urlopen(req))


def find_wi(assessment, resource):
    q = (
        "SELECT [System.Id] FROM WorkItems WHERE "
        f"[Custom.MDCAssessmentId] = '{assessment}' AND [Custom.MDCResourceId] = '{resource}'"
    )
    d = _post(f"{org}/{proj}/_apis/wit/wiql?api-version=7.1", ado, {"query": q})
    return [w["id"] for w in d.get("workItems", [])]


def wi_detail(wid):
    f = _get(f"{org}/{proj}/_apis/wit/workitems/{wid}?api-version=7.1", ado)["fields"]
    return f.get("System.State"), str(f.get("System.ChangedDate", ""))[:19]


print(f"\nLast {len(runs)} Logic App run(s) — la-mdc-ado-dispatcher\n" + "=" * 78)
for r in runs:
    p = r.get("properties", {})
    start = str(p.get("startTime", ""))[:19]
    status = p.get("status", "?")
    body = {}
    try:
        uri = p.get("trigger", {}).get("outputsLink", {}).get("uri")
        if uri:
            body = _get(uri).get("body", {})
    except Exception as exc:  # noqa: BLE001
        body = {"_error": str(exc)}
    props = body.get("properties", {})
    name = body.get("name", "?")
    rd = props.get("resourceDetails", {}) or {}
    rid = rd.get("id") or rd.get("ResourceId") or rd.get("Id") or ""
    disp = props.get("displayName", "") or "(no displayName)"
    sev = (props.get("metadata") or {}).get("severity", "?")

    verdict = "?"
    try:
        wis = find_wi(name, rid) if (name != "?" and rid) else []
        if wis:
            st, ch = wi_detail(wis[0])
            # A WI changed before this run started was definitively NOT touched by it
            # (a churn-suppressed skip). Changed at/after the run = touched at/after it
            # (by this run or a later one — the Function updates asynchronously).
            touched = bool(ch and start and ch >= start)
            note = "changed at/after run (updated)" if touched else "unchanged before run (skip)"
            verdict = f"WI #{wis[0]} exists -> dedupe OK  (state={st}; {note}; changed {ch})"
        elif name != "?" and rid:
            verdict = "NO WI — would create  (INVESTIGATE)"
        else:
            verdict = "could not read payload"
    except Exception as exc:  # noqa: BLE001
        verdict = f"lookup error: {exc}"

    print(f"{start}Z  [{status}]  sev={sev}")
    print(f"  rec : {name}  —  {disp[:70]}")
    print(f"  res : ...{rid[-66:]}")
    print(f"  --> {verdict}")
    print("-" * 78)
PY
