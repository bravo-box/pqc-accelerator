// =============================================================================
// arc-cse-linux.bicep
// Deploys the PQC Validator Custom Script Extension to a single Linux
// Arc-connected machine. Reference this as a module from a parent template
// or deploy directly for targeted rollout.
// =============================================================================

@description('Name of the Arc machine (Microsoft.HybridCompute/machines resource)')
param machineName string

@description('Azure region of the Arc machine resource')
param location string = resourceGroup().location

@description('Data Collection Endpoint URL (DCE) for Log Analytics ingestion')
param dceEndpoint string

@description('Immutable ID of the Data Collection Rule (DCR)')
param dcrImmutableId string

@description('Log Analytics custom stream name — must match DCR stream declaration')
param streamName string = 'Custom-PQCCompliance_CL'

@description('Public URL to the install.sh bootstrap script in blob storage')
param installScriptUrl string

@description('''
SAS URL to pqc-validator.zip in Azure Blob Storage.
Stored in protectedSettings so the token is encrypted at rest and in transit.
''')
@secure()
param packageUrl string

@description('Daily run time HH:MM in UTC. The systemd timer fires at this time with up to 5 min random jitter across the fleet.')
param scheduleTime string = '03:00'

@description('Increment this string to force the CSE to re-run on all machines (e.g. "v1", "v2"). Changing this value causes the policy existenceCondition to evaluate as non-compliant, triggering a redeploy across the fleet.')
param forceUpdateTag string = 'v1'

// ---------------------------------------------------------------------------
// Reference the existing Arc machine — we do NOT create it here
// ---------------------------------------------------------------------------
resource arcMachine 'Microsoft.HybridCompute/machines@2024-05-20-preview' existing = {
  name: machineName
}

// ---------------------------------------------------------------------------
// Custom Script Extension — Linux
// Publisher : Microsoft.Azure.Extensions
// Type      : CustomScript
// Runs      : bash install.sh (once at extension deployment time)
// The script then installs a systemd timer for subsequent daily runs.
// ---------------------------------------------------------------------------
resource pqcCseLinux 'Microsoft.HybridCompute/machines/extensions@2024-05-20-preview' = {
  parent: arcMachine
  name: 'PQCValidatorCSE'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Extensions'
    type: 'CustomScript'
    typeHandlerVersion: '2.1'
    autoUpgradeMinorVersion: true
    // settings block is intentionally empty — all values are in protectedSettings
    // so the DCE endpoint, DCR ID, and package SAS URL are encrypted.
    settings: {
      forceUpdateTag: forceUpdateTag
    }
    protectedSettings: {
      // fileUris are downloaded by the CSE agent before commandToExecute runs
      fileUris: [installScriptUrl]
      commandToExecute: 'PQC_DCE_ENDPOINT="${dceEndpoint}" PQC_DCR_IMMUTABLE_ID="${dcrImmutableId}" PQC_STREAM_NAME="${streamName}" PQC_PACKAGE_URL="${packageUrl}" PQC_SCHEDULE_TIME="${scheduleTime}" /bin/bash install.sh'
    }
  }
}

output extensionId string = pqcCseLinux.id
output extensionProvisioningState string = pqcCseLinux.properties.provisioningState
