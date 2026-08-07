// main.bicepparam — parameters for main.bicep
// Fill in values output by deploy/setup_azure.py and package-and-upload.sh

using './main.bicep'

// ── From setup_azure.py output (.env.pqc) ────────────────────────────────────
param dceEndpoint    = 'https://<dce-name>.<region>.ingest.monitor.azure.com'
param dcrImmutableId = 'dcr-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
param streamName     = 'Custom-PQCCompliance_CL'

// ── From package-and-upload.sh output ─────────────────────────────────────────
// install.sh and install.ps1 can be public (no secrets inside)
param linuxInstallScriptUrl   = 'https://<storage>.blob.core.windows.net/pqc-cse/linux/install.sh'
param windowsInstallScriptUrl = 'https://<storage>.blob.core.windows.net/pqc-cse/windows/install.ps1'

// pqc-validator.zip SAS URL — keep this secret, do not commit to git
// Generate with: package-and-upload.sh --generate-sas
param packageUrl = 'https://<storage>.blob.core.windows.net/pqc-cse/pqc-validator.zip?<sas-token>'

// Required package integrity and authenticity inputs
param packageSha256    = '<sha256-hex-from-.env.cse>'
param packageSigUrl    = 'https://<storage>.blob.core.windows.net/pqc-cse/pqc-validator.zip.sig?<sas-token>'
param packagePubkeyUrl = 'https://<storage>.blob.core.windows.net/pqc-cse/pqc-signing-key.pem?<sas-token>'
param packageCertUrl   = 'https://<storage>.blob.core.windows.net/pqc-cse/pqc-signing-cert.cer?<sas-token>'

// ── Schedule ──────────────────────────────────────────────────────────────────
param scheduleTime = '03:00'

// ── Target machines ───────────────────────────────────────────────────────────
// Arc machine names (resource names, not hostnames) in the deployment resource group
param linuxMachines = [
  // 'ubuntu-vm-01'
  // 'rhel-server-02'
]

param windowsMachines = [
  // 'winserver-01'
  // 'winserver-02'
]
