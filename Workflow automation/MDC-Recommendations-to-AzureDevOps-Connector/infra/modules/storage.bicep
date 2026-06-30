// storage.bicep — Durable Functions state store stmdcado<env> (TSD §3.2 #6, §6.3).
// Identity-based access only (no account keys / connection strings). The Function runtime
// reaches Durable blob/queue/table state and the Flex Consumption deployment container via
// the user-assigned MI granted data-plane RBAC below (AzureWebJobsStorage__accountName).

@description('Environment short name (dev | test | prod). Drives resource naming.')
param env string

@description('Azure region for the storage account.')
param location string = resourceGroup().location

@description('Tags applied to every resource in this module.')
param tags object = {}

@description('Storage SKU: Standard_LRS for non-prod, Standard_ZRS for prod (param-driven).')
@allowed([
  'Standard_LRS'
  'Standard_ZRS'
])
param skuName string = 'Standard_LRS'

@description('Object (principal) id of the user-assigned MI granted identity-based storage RBAC.')
param identityPrincipalId string

@description('Name of the blob container used by Flex Consumption for the deployment package.')
param deploymentContainerName string = 'app-package'

// Built-in role definition ids (§6.3 — identity-based, no keys).
var storageBlobDataOwnerRoleId = 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
var storageQueueDataContributorRoleId = '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
var storageTableDataContributorRoleId = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  // Storage account names: lowercase, no hyphens, 3-24 chars (§3 naming).
  name: 'stmdcado${env}'
  location: location
  tags: tags
  sku: {
    name: skuName
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

resource blobServices 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource deploymentContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobServices
  name: deploymentContainerName
  properties: {
    publicAccess: 'None'
  }
}

// Identity-based RBAC for the Function MI (§6.3): blob (Durable + deployment package),
// queue (Durable control/work-item queues), table (Durable instances/history).
resource blobDataOwnerAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identityPrincipalId, storageBlobDataOwnerRoleId)
  scope: storage
  properties: {
    principalId: identityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataOwnerRoleId)
  }
}

resource queueDataContributorAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identityPrincipalId, storageQueueDataContributorRoleId)
  scope: storage
  properties: {
    principalId: identityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageQueueDataContributorRoleId)
  }
}

resource tableDataContributorAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identityPrincipalId, storageTableDataContributorRoleId)
  scope: storage
  properties: {
    principalId: identityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageTableDataContributorRoleId)
  }
}

@description('Resource id of the storage account.')
output id string = storage.id

@description('Name of the storage account (used as AzureWebJobsStorage__accountName).')
output name string = storage.name

@description('Primary blob endpoint (used by the Flex Consumption deployment storage config).')
output primaryBlobEndpoint string = storage.properties.primaryEndpoints.blob

@description('Name of the deployment package container.')
output deploymentContainerName string = deploymentContainer.name
