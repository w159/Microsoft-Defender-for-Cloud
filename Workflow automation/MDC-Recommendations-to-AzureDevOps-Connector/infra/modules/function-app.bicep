// function-app.bicep — fa-mdc-ado-enricher (TSD §3.2 #3, §5.2, §6.1, §6.3).
// Flex Consumption plan (FC1), Python 3.12, Durable Functions, user-assigned MI.
// Identity-based storage (AzureWebJobsStorage__accountName, no keys, no PAT, no Key Vault
// app settings — §6.1/§6.2). Easy Auth restricted to the shared MI as the allowed caller
// (the Logic App authenticates with that same identity, §5.1 step 4, §6.3); the function
// key is a documented fallback only.

@description('Environment short name (dev | test | prod). Drives resource naming.')
param env string

@description('Optional suffix appended to the globally-unique Function app name so the template can be deployed more than once.')
param nameSuffix string = ''

@description('Azure region for the plan and app.')
param location string = resourceGroup().location

@description('Tags applied to every resource in this module.')
param tags object = {}

@description('Resource id of the user-assigned managed identity (Function + storage + ADO auth).')
param identityResourceId string

@description('Client (application) id of the user-assigned MI — used for identity-based storage.')
param identityClientId string

@description('Object (principal) id of the shared MI allowed to call the Function via Easy Auth (§6.3).')
param easyAuthAllowedPrincipalId string

@description('Client (app) id of the Entra app registration that represents the Function API audience (§6.3). The MI requests a token for api://<this>.')
param functionApiClientId string

@description('Application Insights connection string (from app-insights.bicep).')
param appInsightsConnectionString string

@description('Storage account name for identity-based Durable state (AzureWebJobsStorage__accountName).')
param storageAccountName string

@description('Primary blob endpoint of the storage account (deployment package storage).')
param storageBlobEndpoint string

@description('Name of the deployment package container in the storage account.')
param deploymentContainerName string = 'app-package'

@description('Per-instance memory (MB) for the Flex Consumption plan (§5.2, §8).')
@allowed([
  2048
  4096
])
param instanceMemoryMB int = 2048

@description('Maximum scale-out instance count for the Flex Consumption plan (§8).')
@minValue(40)
@maxValue(1000)
param maximumInstanceCount int = 100

@description('Always-ready instance count to keep cold starts off the critical path (§5.2, §8).')
@minValue(0)
@maxValue(20)
param alwaysReadyInstances int = 1

@description('Enable Easy Auth (Entra) restricting ingress to the allowed MI (§6.3). Function key is fallback.')
param enableEasyAuth bool = true

@description('Azure DevOps organization URL the connector writes work items to (§6.1). E.g. https://dev.azure.com/<org>.')
param adoOrgUrl string

@description('Azure DevOps project that holds the Security Recommendation work items (§4.4).')
param adoProject string

@description('Enable MDC write-back: assign the recommendation to the Work Item back-reference (§4.7, Feature B). Requires the MI to have Security Admin.')
param mdcWriteBackEnabled bool = false

@description('Email domain used for the Work Item back-reference owner written to MDC (§4.7). E.g. ado.local.')
param mdcAssignmentOwnerDomain string = 'ado.local'

var pythonVersion = '3.12'

resource plan 'Microsoft.Web/serverfarms@2024-11-01' = {
  name: 'asp-mdc-ado-${env}'
  location: location
  tags: tags
  sku: {
    tier: 'FlexConsumption'
    name: 'FC1'
  }
  kind: 'functionapp'
  properties: {
    reserved: true
  }
}

resource functionApp 'Microsoft.Web/sites@2024-11-01' = {
  name: 'fa-mdc-ado-enricher${nameSuffix}'
  location: location
  tags: tags
  kind: 'functionapp,linux'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identityResourceId}': {}
    }
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storageBlobEndpoint}${deploymentContainerName}'
          authentication: {
            type: 'UserAssignedIdentity'
            userAssignedIdentityResourceId: identityResourceId
          }
        }
      }
      scaleAndConcurrency: {
        instanceMemoryMB: instanceMemoryMB
        maximumInstanceCount: maximumInstanceCount
        alwaysReady: [
          {
            name: 'http'
            instanceCount: alwaysReadyInstances
          }
        ]
      }
      runtime: {
        name: 'python'
        version: pythonVersion
      }
    }
    siteConfig: {
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      // Identity-based storage (§6.1/§6.2): no AzureWebJobsStorage connection string, no
      // ADO PAT, no Key Vault references in the baseline.
      appSettings: [
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsightsConnectionString
        }
        {
          name: 'AzureWebJobsStorage__accountName'
          value: storageAccountName
        }
        {
          name: 'AzureWebJobsStorage__credential'
          value: 'managedidentity'
        }
        {
          name: 'AzureWebJobsStorage__clientId'
          value: identityClientId
        }
        {
          // DefaultAzureCredential uses this to select the user-assigned MI (§6.1).
          // Without it the MSI token endpoint returns 400 (no system-assigned identity).
          name: 'AZURE_CLIENT_ID'
          value: identityClientId
        }
        {
          name: 'ADO_ORG_URL'
          value: adoOrgUrl
        }
        {
          name: 'ADO_PROJECT'
          value: adoProject
        }
        {
          // Feature B write-back (§4.7): assign the recommendation to the WI back-reference.
          name: 'MDC_WRITE_BACK_ENABLED'
          value: string(mdcWriteBackEnabled)
        }
        {
          name: 'MDC_ASSIGNMENT_OWNER_DOMAIN'
          value: mdcAssignmentOwnerDomain
        }
      ]
    }
  }
}

// Easy Auth (Entra) — restrict ingress to the shared MI as the only allowed caller (§6.3).
// The audience is the Function's app-id URI; the Logic App requests a token for it and is
// validated by object id in allowedPrincipals.identities. App registration / federation is
// configured out-of-band (§10.3). Function key remains a documented fallback.
resource authSettings 'Microsoft.Web/sites/config@2024-11-01' = if (enableEasyAuth) {
  parent: functionApp
  name: 'authsettingsV2'
  properties: {
    platform: {
      enabled: true
    }
    globalValidation: {
      requireAuthentication: true
      unauthenticatedClientAction: 'Return401'
    }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          openIdIssuer: '${environment().authentication.loginEndpoint}${tenant().tenantId}/v2.0'
          clientId: functionApiClientId
        }
        validation: {
          allowedAudiences: [
            'api://${functionApiClientId}'
          ]
          defaultAuthorizationPolicy: {
            allowedPrincipals: {
              identities: [
                easyAuthAllowedPrincipalId
              ]
            }
          }
        }
      }
    }
  }
}

@description('Resource id of the Function App.')
output id string = functionApp.id

@description('Name of the Function App.')
output name string = functionApp.name

@description('Default hostname of the Function App (used by the Logic App to forward events).')
output defaultHostname string = functionApp.properties.defaultHostName
