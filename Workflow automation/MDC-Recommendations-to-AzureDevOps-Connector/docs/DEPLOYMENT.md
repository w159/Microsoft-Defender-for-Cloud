# Deployment Guide — MDC → ADO Connector

This guide takes you from an empty subscription to a working connector. It covers both deployment
paths (portal "Deploy to Azure" button and CLI), the one-time manual steps no template can do, the
configuration reference, and how to test and tear down.

> **Naming.** Resources are named `*-mdc-ado-<env>` (e.g. `fa-mdc-ado-dev`). The examples below use
> `env = dev` and resource group `rg-mdc-ado-dev`. Adjust for `test` / `prod`.

---

## 1. Prerequisites

| Requirement | Notes |
|---|---|
| Azure subscription | With **Microsoft Defender for Cloud — Defender CSPM** enabled (required for enrichment: governance, attack paths). |
| Permissions | Ability to create resources, **role assignments** at subscription scope, and an **Entra app registration**. (Owner or User Access Administrator + Application Administrator.) |
| Azure DevOps | An organization and a project where Work Items will be created. You must be a Project/Collection Administrator. |
| Tooling (CLI path) | [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) (with the Bicep extension), [Azure Functions Core Tools v4](https://learn.microsoft.com/azure/azure-functions/functions-run-local), Python 3.12. |

```bash
az login
az account set --subscription <your-subscription-id>
```

---

## 2. Create the Entra app registration (Easy Auth audience)

The Function is fronted by **Easy Auth**; the Logic App's managed identity calls it with an Entra
token whose **audience** is this app registration. Create it once per environment.

```bash
# Create the app registration and capture its client (app) id.
APP_ID=$(az ad app create --display-name "mdc-ado-enricher-api-dev" --query appId -o tsv)
echo "functionApiClientId = $APP_ID"

# Set an Application ID URI so it can be used as a token audience.
az ad app update --id "$APP_ID" --identifier-uris "api://$APP_ID"

# Create a service principal for the app registration.
az ad sp create --id "$APP_ID"
```

Use `$APP_ID` as the `functionApiClientId` parameter (CLI path) or in the portal form (button path).

---

## 3. Provision the Azure DevOps work-item schema

The connector writes a custom work-item type **`Security Recommendation`** (16 `Custom.*` fields)
in an inherited process **"MDC Security"**. Provision it with the included stdlib-only script —
**dry-run first**, then `--apply`.

```bash
# Dry-run: prints the planned actions, mutates nothing.
python infra/ado/provision_ado_process.py --org <your-org> --project <your-project>

# Apply: creates the process, work-item type, and fields (idempotent).
python infra/ado/provision_ado_process.py --org <your-org> --project <your-project> --apply
```

Auth: the script uses `az account get-access-token` for the Azure DevOps resource, or set
`ADO_TOKEN`.

**Then, in the ADO portal (one-time, manual):** move your project onto the new process —
*Organization settings → Boards → Process → "MDC Security" → ⋮ → Move projects → select your
project*. Verify the project now exposes the **Security Recommendation** work-item type.

---

## 4. Deploy the infrastructure

The Bicep deploys six modules into a resource group: a shared **user-assigned managed identity**,
**storage** (identity-based, for Durable state), **Application Insights**, the **Function App**
(Flex Consumption + Easy Auth), the **Logic App** dispatcher, and an optional **Key Vault** (off by
default). Storage data-plane RBAC for the MI is created by the template at storage scope.

### Option A — Portal ("Deploy to Azure")

1. Push this repo to GitHub and update the button URL in the [README](../README.md) to your
   `<owner>/<repo>`.
2. Click **Deploy to Azure**. The portal reads `infra/main.json` and prompts for parameters
   (resource group, `env`, `adoOrgUrl`, `adoProject`, `functionApiClientId`, write-back options).
3. Review and create. This provisions **infrastructure only** — continue with sections 5–7.

### Option B — CLI

```bash
cp infra/parameters/dev.bicepparam.example infra/parameters/dev.bicepparam
# Edit dev.bicepparam: adoOrgUrl, adoProject, functionApiClientId (= $APP_ID from step 2).

az group create -n rg-mdc-ado-dev -l eastus

# Optional preview:
az deployment group what-if -g rg-mdc-ado-dev \
  --template-file infra/main.bicep --parameters infra/parameters/dev.bicepparam

az deployment group create -g rg-mdc-ado-dev \
  --template-file infra/main.bicep --parameters infra/parameters/dev.bicepparam
```

> Three storage role assignments may show as "Unsupported" in `what-if` because their names depend
> on the MI principal id resolved at deploy time — this is expected; the deployment still applies
> them.

---

## 5. Assign managed-identity roles

The shared MI is `id-mdc-ado-<env>`. Grant it the access it needs (storage data-plane roles are
already assigned by the template).

```bash
SUB=<your-subscription-id>
MI_PRINCIPAL_ID=$(az identity show -g rg-mdc-ado-dev -n id-mdc-ado-dev --query principalId -o tsv)

# Read access for ARG enrichment.
az role assignment create --assignee-object-id "$MI_PRINCIPAL_ID" --assignee-principal-type ServicePrincipal \
  --role "Reader" --scope "/subscriptions/$SUB"
az role assignment create --assignee-object-id "$MI_PRINCIPAL_ID" --assignee-principal-type ServicePrincipal \
  --role "Security Reader" --scope "/subscriptions/$SUB"

# Only if MDC write-back is enabled (Feature B): lets the connector set the recommendation Assigned.
az role assignment create --assignee-object-id "$MI_PRINCIPAL_ID" --assignee-principal-type ServicePrincipal \
  --role "Security Admin" --scope "/subscriptions/$SUB"
```

**Azure DevOps access (portal, manual):** add the managed identity `id-mdc-ado-<env>` as a member
of your ADO **organization**, then grant it **Contributor** (or "Edit work items") on the project.
The connector authenticates to ADO with this MI's Entra token (no PAT).

**Optional — owner resolution via Microsoft Graph:** to resolve owner emails to directory users,
grant the MI the Graph application permission **`User.Read.All`** (admin consent required). Without
it, owner resolution degrades to the raw tag/governance value (the Work Item is still created).

---

## 6. Publish the Function code

The template provisions the Function App but not its code. Publish from `src/function`:

```bash
cd src/function
func azure functionapp publish fa-mdc-ado-dev --python
```

Verify the host indexes all functions (orchestrator + activities + the HTTP starter).

---

## 7. Wire MDC Workflow Automation → Logic App

In the Azure portal: **Microsoft Defender for Cloud → Environment settings → (subscription) →
Workflow automation → Add workflow automation**:

- **Trigger:** Security recommendations (optionally filter by severity/standard).
- **Action:** the Logic App `la-mdc-ado-dispatcher` created by the deployment.

From now on, every matching recommendation flows end-to-end to a Work Item.

---

## 8. Configuration reference (Function app settings)

These are set by the Bicep template; you normally don't edit them by hand.

| Setting | Purpose |
|---|---|
| `AZURE_CLIENT_ID` | Selects the user-assigned MI for `DefaultAzureCredential`. |
| `ADO_ORG_URL` | Azure DevOps org URL (e.g. `https://dev.azure.com/your-org`). |
| `ADO_PROJECT` | Target ADO project. |
| `MDC_WRITE_BACK_ENABLED` | `true`/`false` — enable the governance back-reference (Feature B). |
| `MDC_ASSIGNMENT_OWNER_DOMAIN` | Email domain for the `ado-wi-<id>@<domain>` back-reference. |
| `AzureWebJobsStorage__accountName` / `__credential` / `__clientId` | Identity-based Durable storage (no connection strings). |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | Telemetry. |

Deployment parameters live in `infra/parameters/*.bicepparam` (copy from the `.example` templates).

---

## 9. Test

### Smoke test (manual dispatch)

You can POST a sample payload straight to the Logic App callback URL, bypassing MDC:

```bash
# Get the Logic App callback (trigger) URL.
CALLBACK=$(az rest --method post \
  --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-mdc-ado-dev/providers/Microsoft.Logic/workflows/la-mdc-ado-dispatcher/triggers/<trigger-name>/listCallbackUrl?api-version=2019-05-01" \
  --query value -o tsv)

# Send a sample recommendation.
curl -sS -X POST "$CALLBACK" \
  -H 'Content-Type: application/json' \
  --data @tests/fixtures/sample_payloads/vm_endpoint_protection_high.json -i
```

Expect HTTP `202`. A new **Security Recommendation** Work Item should appear in your ADO project.
Re-sending the **same** payload must **not** create a duplicate (dedupe + churn control).

### Ops triage

`scripts/check-runs.sh` maps recent Logic App dispatches → the recommendation each forwarded → the
matching ADO Work Item (or flags a genuinely missing one). Requires `az login`:

```bash
export SUB=<your-subscription-id>
export ADO_ORG=https://dev.azure.com/<your-org>
export ADO_PROJECT=<your-project>
scripts/check-runs.sh 8
```

### Unit tests

```bash
pytest tests/ -q     # all external I/O mocked; no Azure access required
```

---

## 10. Tear down

```bash
az group delete -n rg-mdc-ado-dev --yes --no-wait
```

Also remove (manual): the MDC Workflow Automation, the subscription-scope role assignments for the
MI, the MI's membership in the ADO org, and the Entra app registration from step 2. The custom ADO
process/work-item type can be left in place or removed via the portal once no project uses it.
