// managed-identity.bicep — user-assigned identity id-mdc-ado-<env> (TSD §3.2 #5, §6.1).
// Single user-assigned identity shared by the Function and the Logic App. Used by the
// Function for ARG, Microsoft Graph, ADO (Entra token), and identity-based storage; used
// by the Logic App as the Easy Auth caller of the Function (§5.1 step 4, §6.3).

@description('Environment short name (dev | test | prod). Drives resource naming.')
param env string

@description('Azure region for the identity.')
param location string = resourceGroup().location

@description('Tags applied to every resource in this module.')
param tags object = {}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-mdc-ado-${env}'
  location: location
  tags: tags
}

@description('Resource id of the user-assigned managed identity.')
output id string = identity.id

@description('Name of the user-assigned managed identity.')
output name string = identity.name

@description('Entra object (principal) id — used for RBAC and Easy Auth allowed callers.')
output principalId string = identity.properties.principalId

@description('Entra application (client) id — identity-based storage and Easy Auth audience.')
output clientId string = identity.properties.clientId
