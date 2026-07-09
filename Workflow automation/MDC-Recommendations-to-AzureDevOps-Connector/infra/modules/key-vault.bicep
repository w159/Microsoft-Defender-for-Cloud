// key-vault.bicep — kv-mdc-ado-<env> (TSD §6.2). OPTIONAL.
// Not part of the v2 baseline: auth is Managed Identity end-to-end (no PAT, no secrets).
// main.bicep deploys this module only when `deployKeyVault` is true. If deployed, the
// Function MI is granted Key Vault Secrets User (RBAC authorization, no access policies).

@description('Environment short name (dev | test | prod). Drives resource naming.')
param env string

@description('Azure region for the Key Vault.')
param location string = resourceGroup().location

@description('Tags applied to every resource in this module.')
param tags object = {}

@description('Object (principal) id of the MI granted Key Vault Secrets User (§6.1, §6.2).')
param identityPrincipalId string

@description('Enable purge protection (recommended/required in prod, param-driven §6.2).')
param enablePurgeProtection bool = false

@description('Soft-delete retention window in days.')
@minValue(7)
@maxValue(90)
param softDeleteRetentionInDays int = 90

@description('Enable a Private Endpoint via Flex Consumption VNet integration (§6.3). Off by default.')
param enablePrivateEndpoint bool = false

// Key Vault Secrets User built-in role (§6.1).
var keyVaultSecretsUserRoleId = '4633458b-17de-406a-b960-e35d36a04f3e'

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-mdc-ado-${env}'
  location: location
  tags: tags
  properties: {
    tenantId: tenant().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: softDeleteRetentionInDays
    enablePurgeProtection: enablePurgeProtection ? true : null
    publicNetworkAccess: enablePrivateEndpoint ? 'Disabled' : 'Enabled'
    networkAcls: {
      defaultAction: enablePrivateEndpoint ? 'Deny' : 'Allow'
      bypass: 'AzureServices'
    }
  }
}

resource secretsUserAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, identityPrincipalId, keyVaultSecretsUserRoleId)
  scope: keyVault
  properties: {
    principalId: identityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUserRoleId)
  }
}

@description('Resource id of the Key Vault.')
output id string = keyVault.id

@description('Name of the Key Vault.')
output name string = keyVault.name

@description('Vault URI (for secret references, if used).')
output vaultUri string = keyVault.properties.vaultUri
