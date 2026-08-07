// =============================================================================
// arc-cse-windows.bicep
// Deploys the PQC Validator Custom Script Extension to a single Windows
// Arc-connected machine.
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

@description('Public URL to the install.ps1 bootstrap script in blob storage')
param installScriptUrl string

@description('''
SAS URL to pqc-validator.zip in Azure Blob Storage.
Stored in protectedSettings so the token is encrypted at rest and in transit.
''')
@secure()
param packageUrl string

@description('Expected SHA-256 for pqc-validator.zip')
param packageSha256 string

@description('SAS URL to detached signature for pqc-validator.zip')
@secure()
param packageSigUrl string

@description('SAS URL to DER certificate containing signing public key')
@secure()
param packageCertUrl string

@description('Daily run time HH:MM in UTC. The Windows Scheduled Task fires at this time.')
param scheduleTime string = '03:00'

@description('Increment this string to force the CSE to re-run on all machines (e.g. "v1", "v2").')
param forceUpdateTag string = 'v1'

// ---------------------------------------------------------------------------
// Reference the existing Arc machine
// ---------------------------------------------------------------------------
resource arcMachine 'Microsoft.HybridCompute/machines@2024-05-20-preview' existing = {
  name: machineName
}

// ---------------------------------------------------------------------------
// Custom Script Extension — Windows
// Publisher : Microsoft.Compute
// Type      : CustomScriptExtension
// Runs      : install.ps1 (once at extension deployment time)
// The script then creates a Windows Scheduled Task for subsequent daily runs.
// ---------------------------------------------------------------------------
resource pqcCseWindows 'Microsoft.HybridCompute/machines/extensions@2024-05-20-preview' = {
  parent: arcMachine
  name: 'PQCValidatorCSE'
  location: location
  properties: {
    publisher: 'Microsoft.Compute'
    type: 'CustomScriptExtension'
    typeHandlerVersion: '1.10'
    autoUpgradeMinorVersion: true
    settings: {
      forceUpdateTag: forceUpdateTag
    }
    protectedSettings: {
      fileUris: [installScriptUrl]
      // PowerShell parameters are passed inline; the -File argument runs install.ps1
      // after fileUris are downloaded to the CSE working directory.
      // -File with a bare filename fails because the CSE binary runs from the plugin dir, not the download dir.
      // Instead use -Command, set env vars, then locate install.ps1 dynamically under the plugin tree.
      commandToExecute: 'powershell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass -Command "& { $env:PQC_DCE_ENDPOINT=\'${dceEndpoint}\'; $env:PQC_DCR_IMMUTABLE_ID=\'${dcrImmutableId}\'; $env:PQC_STREAM_NAME=\'${streamName}\'; $env:PQC_PACKAGE_URL=\'${packageUrl}\'; $env:PQC_PACKAGE_SHA256=\'${packageSha256}\'; $env:PQC_PACKAGE_SIG_URL=\'${packageSigUrl}\'; $env:PQC_PACKAGE_CERT_URL=\'${packageCertUrl}\'; $env:PQC_SCHEDULE_TIME=\'${scheduleTime}\'; $f=(Get-ChildItem $env:SystemDrive\\Packages\\Plugins\\Microsoft.Compute.CustomScriptExtension -Recurse -Filter install.ps1 | Select-Object -First 1).FullName; if (!$f){throw \'install.ps1 not found\'}; & $f }"'
    }
  }
}

output extensionId string = pqcCseWindows.id
output extensionProvisioningState string = pqcCseWindows.properties.provisioningState
