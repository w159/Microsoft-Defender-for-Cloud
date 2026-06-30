// main.bicep — MDC -> ADO Connector infrastructure (TSD §3.2, §6, §10.1).
// Deployment scope: resource group. Orchestrates all module deployments.
targetScope = 'resourceGroup'

@description('Environment short name (dev | test | prod).')
@allowed([
  'dev'
  'test'
  'prod'
])
param env string = 'dev'

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Deploy the optional Key Vault — only if a secret is introduced (§6.2).')
param deployKeyVault bool = false

@description('Existing Log Analytics workspace id for App Insights. Empty => create a Function-scoped one (§2.3).')
param workspaceResourceId string = ''

@description('Always-ready Function instances to keep cold starts off the critical path (§5.2, §8).')
@minValue(0)
@maxValue(20)
param alwaysReadyInstances int = 1

@description('Maximum Flex Consumption scale-out instance count (§8).')
@minValue(40)
@maxValue(1000)
param maximumInstanceCount int = 100

@description('Per-instance memory (MB) for the Flex Consumption plan (§5.2, §8).')
@allowed([
  2048
  4096
])
param instanceMemoryMB int = 2048

@description('Extra tags merged onto the common tag set applied to every resource.')
param tags object = {}

@description('Azure DevOps organization URL the connector writes work items to (§6.1).')
param adoOrgUrl string

@description('Azure DevOps project that holds the Security Recommendation work items (§4.4).')
param adoProject string

@description('Client (app) id of the Entra app registration used as the Function Easy Auth audience (§6.3).')
param functionApiClientId string

@description('Enable MDC write-back: assign the recommendation to the Work Item back-reference (§4.7, Feature B). Requires the MI to have Security Admin at subscription scope.')
param mdcWriteBackEnabled bool = false

@description('Email domain used for the Work Item back-reference owner written to MDC (§4.7).')
param mdcAssignmentOwnerDomain string = 'ado.local'

// Common tags applied to every resource across all modules (§10.1 conventions).
var commonTags = union(
  {
    application: 'mdc-ado-connector'
    environment: env
    managedBy: 'bicep'
  },
  tags
)

// Storage redundancy: ZRS in prod, LRS elsewhere (§ storage module, prompt 05).
var storageSkuName = env == 'prod' ? 'Standard_ZRS' : 'Standard_LRS'

// Key Vault hardening: purge protection on in prod (§6.2).
var keyVaultPurgeProtection = env == 'prod'

// 1. Shared user-assigned managed identity (id-mdc-ado-<env>) — Function + Logic App (§6.1).
module managedIdentity 'modules/managed-identity.bicep' = {
  name: 'managed-identity'
  params: {
    env: env
    location: location
    tags: commonTags
  }
}

// 2. Storage account (stmdcado<env>) for Durable state — identity-based RBAC (§6.3).
module storage 'modules/storage.bicep' = {
  name: 'storage'
  params: {
    env: env
    location: location
    tags: commonTags
    skuName: storageSkuName
    identityPrincipalId: managedIdentity.outputs.principalId
  }
}

// 3. Application Insights (appi-mdc-ado-enricher) — workspace-based, Function-scoped (§7.1).
module appInsights 'modules/app-insights.bicep' = {
  name: 'app-insights'
  params: {
    env: env
    location: location
    tags: commonTags
    workspaceResourceId: workspaceResourceId
  }
}

// 4. Function App (fa-mdc-ado-enricher) — Flex Consumption, identity-based, Easy Auth (§5.2, §6.3).
module functionApp 'modules/function-app.bicep' = {
  name: 'function-app'
  params: {
    env: env
    location: location
    tags: commonTags
    identityResourceId: managedIdentity.outputs.id
    identityClientId: managedIdentity.outputs.clientId
    easyAuthAllowedPrincipalId: managedIdentity.outputs.principalId
    functionApiClientId: functionApiClientId
    appInsightsConnectionString: appInsights.outputs.connectionString
    storageAccountName: storage.outputs.name
    storageBlobEndpoint: storage.outputs.primaryBlobEndpoint
    deploymentContainerName: storage.outputs.deploymentContainerName
    instanceMemoryMB: instanceMemoryMB
    maximumInstanceCount: maximumInstanceCount
    alwaysReadyInstances: alwaysReadyInstances
    adoOrgUrl: adoOrgUrl
    adoProject: adoProject
    mdcWriteBackEnabled: mdcWriteBackEnabled
    mdcAssignmentOwnerDomain: mdcAssignmentOwnerDomain
  }
}

// 5. Logic App (la-mdc-ado-dispatcher) — dispatch-only, Easy Auth via the shared MI (§5.1).
module logicApp 'modules/logic-app.bicep' = {
  name: 'logic-app'
  params: {
    location: location
    tags: commonTags
    identityResourceId: managedIdentity.outputs.id
    functionAppHostname: functionApp.outputs.defaultHostname
    functionAudienceClientId: functionApiClientId
  }
}

// 6. Key Vault (kv-mdc-ado-<env>) — OPTIONAL, gated behind deployKeyVault (§6.2).
module keyVault 'modules/key-vault.bicep' = if (deployKeyVault) {
  name: 'key-vault'
  params: {
    env: env
    location: location
    tags: commonTags
    identityPrincipalId: managedIdentity.outputs.principalId
    enablePurgeProtection: keyVaultPurgeProtection
  }
}

@description('Resource id of the shared user-assigned managed identity.')
output managedIdentityId string = managedIdentity.outputs.id

@description('Name of the Function App.')
output functionAppName string = functionApp.outputs.name

@description('Default hostname of the Function App.')
output functionAppHostname string = functionApp.outputs.defaultHostname

@description('Name of the Logic App dispatcher.')
output logicAppName string = logicApp.outputs.name

@description('Name of the storage account backing Durable Functions.')
output storageAccountName string = storage.outputs.name

@description('Application Insights connection string output (for diagnostics wiring).')
output appInsightsName string = appInsights.outputs.name

@description('Resource id of the Key Vault when deployed (empty when deployKeyVault is false).')
output keyVaultId string = deployKeyVault ? keyVault!.outputs.id : ''
