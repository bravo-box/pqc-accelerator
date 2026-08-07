// =============================================================================
// main.bicep  —  Deploy PQC Validator CSE to multiple Arc machines
//
// Usage:
//   az deployment group create \
//     --resource-group <rg> \
//     --template-file main.bicep \
//     --parameters main.bicepparam
// =============================================================================

@description('Data Collection Endpoint URL')
param dceEndpoint string

@description('DCR Immutable ID')
param dcrImmutableId string

@description('Log Analytics stream name')
param streamName string = 'Custom-PQCCompliance_CL'

@description('Public URL to install.sh in blob storage')
param linuxInstallScriptUrl string

@description('Public URL to install.ps1 in blob storage')
param windowsInstallScriptUrl string

@description('SAS URL to pqc-validator.zip in blob storage')
@secure()
param packageUrl string

@description('Expected SHA-256 digest of pqc-validator.zip')
param packageSha256 string

@description('SAS URL to detached signature for pqc-validator.zip')
@secure()
param packageSigUrl string

@description('URL to PEM public key used to verify pqc-validator.zip')
param packagePubkeyUrl string

@description('SAS URL to DER certificate used for Windows signature verification')
@secure()
param packageCertUrl string

@description('Daily run time HH:MM UTC')
param scheduleTime string = '03:00'

@description('List of Linux Arc machine names in this resource group')
param linuxMachines array = []

@description('List of Windows Arc machine names in this resource group')
param windowsMachines array = []

// ---------------------------------------------------------------------------
// Deploy to Linux machines
// ---------------------------------------------------------------------------
module linuxCse 'arc-cse-linux.bicep' = [for machine in linuxMachines: {
  name: 'pqc-cse-linux-${machine}'
  params: {
    machineName:       machine
    dceEndpoint:       dceEndpoint
    dcrImmutableId:    dcrImmutableId
    streamName:        streamName
    installScriptUrl:  linuxInstallScriptUrl
    packageUrl:        packageUrl
    packageSha256:     packageSha256
    packageSigUrl:     packageSigUrl
    packagePubkeyUrl:  packagePubkeyUrl
    scheduleTime:      scheduleTime
  }
}]

// ---------------------------------------------------------------------------
// Deploy to Windows machines
// ---------------------------------------------------------------------------
module windowsCse 'arc-cse-windows.bicep' = [for machine in windowsMachines: {
  name: 'pqc-cse-windows-${machine}'
  params: {
    machineName:       machine
    dceEndpoint:       dceEndpoint
    dcrImmutableId:    dcrImmutableId
    streamName:        streamName
    installScriptUrl:  windowsInstallScriptUrl
    packageUrl:        packageUrl
    packageSha256:     packageSha256
    packageSigUrl:     packageSigUrl
    packageCertUrl:    packageCertUrl
    scheduleTime:      scheduleTime
  }
}]

output linuxExtensionIds array = [for (machine, i) in linuxMachines: linuxCse[i].outputs.extensionId]
output windowsExtensionIds array = [for (machine, i) in windowsMachines: windowsCse[i].outputs.extensionId]
