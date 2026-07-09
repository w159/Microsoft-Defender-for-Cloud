// logic-app.bicep — la-mdc-ado-dispatcher (TSD §4.1, §5.1, §6.3).
// Dispatch-only Consumption Logic App. Attaches the shared user-assigned MI and forwards
// the MDC payload to the Function, authenticating via Easy Auth with that identity. No
// function key, no Key Vault reference, no secrets in the definition (§5.1 step 4, §6.2).

@description('Azure region for the Logic App.')
param location string = resourceGroup().location

@description('Tags applied to every resource in this module.')
param tags object = {}

@description('Resource id of the shared user-assigned MI used as the Easy Auth caller (§6.3).')
param identityResourceId string

@description('Default hostname of the Function App to forward events to (§5.1 step 3).')
param functionAppHostname string

@description('Client (application) id of the Function App audience the MI requests a token for (§6.3).')
param functionAudienceClientId string

// Workflow definition is authored in src/logic-app/workflow.json and is dispatch-only:
// no business logic lives here (§4.1). The target Function URL and the Easy Auth audience
// are injected as workflow parameters so no values are hard-coded in the definition.
var workflow = loadJsonContent('../../src/logic-app/workflow.json')

resource logicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'la-mdc-ado-dispatcher'
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identityResourceId}': {}
    }
  }
  properties: {
    state: 'Enabled'
    definition: workflow.definition
    parameters: {
      functionUrl: {
        value: 'https://${functionAppHostname}/api/EnrichAndCreate'
      }
      functionAudience: {
        value: 'api://${functionAudienceClientId}'
      }
      functionMiResourceId: {
        value: identityResourceId
      }
    }
  }
}

@description('Resource id of the Logic App.')
output id string = logicApp.id

@description('Name of the Logic App.')
output name string = logicApp.name
