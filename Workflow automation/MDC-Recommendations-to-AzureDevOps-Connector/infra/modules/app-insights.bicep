// app-insights.bicep — appi-mdc-ado-enricher (TSD §3.2 #7, §7.1).
// Workspace-based Application Insights (connection-string based — instrumentation keys are
// deprecated). When no workspaceResourceId is supplied, a Function-scoped Log Analytics
// workspace is created here. Per §2.3 / §3.2 note this is NOT the centralized SIEM-style
// LAW (that is deferred to v3); it is the workspace App Insights requires to operate.

@description('Environment short name (dev | test | prod). Drives resource naming.')
param env string

@description('Azure region for the telemetry resources.')
param location string = resourceGroup().location

@description('Tags applied to every resource in this module.')
param tags object = {}

@description('Existing Log Analytics workspace resource id. Empty string => create a Function-scoped one (§2.3, §3.2).')
param workspaceResourceId string = ''

@description('Retention (days) for the Function-scoped workspace when one is created here.')
@minValue(30)
@maxValue(730)
param retentionInDays int = 30

var createWorkspace = empty(workspaceResourceId)

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = if (createWorkspace) {
  name: 'log-mdc-ado-${env}'
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

var effectiveWorkspaceId = createWorkspace ? workspace.id : workspaceResourceId

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: 'appi-mdc-ado-enricher'
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: effectiveWorkspaceId
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

@description('Resource id of the Application Insights component.')
output id string = appInsights.id

@description('Name of the Application Insights component.')
output name string = appInsights.name

@description('Connection string for the Function (APPLICATIONINSIGHTS_CONNECTION_STRING).')
output connectionString string = appInsights.properties.ConnectionString

@description('Resource id of the workspace backing App Insights (created or supplied).')
output workspaceId string = effectiveWorkspaceId
