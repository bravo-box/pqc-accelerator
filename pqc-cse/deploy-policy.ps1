#Requires -Version 7.0
<#
.SYNOPSIS
    Register PQC policy definitions, create an initiative, and assign it at
    subscription (or management group) scope.

.DESCRIPTION
    PowerShell equivalent of deploy-policy.sh. Uses the az CLI for all Azure
    operations and native ConvertTo-Json/ConvertFrom-Json instead of jq.

.PARAMETER Subscription
    Subscription ID to deploy into. Required.

.PARAMETER ManagementGroup
    Optional: register/assign at management group scope instead of subscription.

.PARAMETER ScopeRg
    Optional: limit the assignment to a single resource group.

.EXAMPLE
    ./deploy-policy.ps1 -Subscription <sub-id>

.EXAMPLE
    ./deploy-policy.ps1 -Subscription <sub-id> -ManagementGroup <mg-id>

.NOTES
    Prerequisites:
      - az cli logged in with Owner or Policy Contributor + User Access Administrator
      - package-and-upload.sh already run (.env.cse exists)
      - setup_azure.py already run (.env.pqc exists)
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Subscription,

    [string]$ManagementGroup = '',

    [string]$ScopeRg = ''
)

$ErrorActionPreference = 'Stop'

$ScriptDir = $PSScriptRoot
$PolicyDir = Join-Path $ScriptDir 'policy'

function Write-Log {
    param([string]$Message)
    $ts = (Get-Date).ToUniversalTime().ToString('HH:mm:ss')
    Write-Host "[$ts] $Message"
}

function Assert-LastExitCode {
    param([string]$Context)
    if ($LASTEXITCODE -ne 0) {
        throw "$Context failed with exit code $LASTEXITCODE"
    }
}

# ── Load environment files ────────────────────────────────────────────────────
# Resolve the most recent .env.pqc from common setup locations to avoid using stale endpoints.
function Import-EnvFile {
    param([string]$Path)
    foreach ($line in Get-Content -Path $Path) {
        if ($line -match '^\s*#' -or $line -match '^\s*$') { continue }
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
            $name = $Matches[1]
            $value = $Matches[2].Trim()
            if ($value.Length -ge 2 -and $value.StartsWith('"') -and $value.EndsWith('"')) {
                $value = $value.Substring(1, $value.Length - 2)
            }
            Set-Variable -Name $name -Value $value -Scope Script
        }
    }
}

$EnvCse = Join-Path $ScriptDir '.env.cse'
$EnvPqc = ''
$PqcCandidates = @(
    (Join-Path $ScriptDir '../.env.pqc'),
    (Join-Path $ScriptDir '../pqc-validator/.env.pqc'),
    (Join-Path $ScriptDir '../pqc-validator/deploy/.env.pqc')
)

foreach ($candidate in $PqcCandidates) {
    if (Test-Path $candidate) {
        if (-not $EnvPqc -or (Get-Item $candidate).LastWriteTime -gt (Get-Item $EnvPqc).LastWriteTime) {
            $EnvPqc = $candidate
        }
    }
}

foreach ($f in @($EnvPqc, $EnvCse)) {
    if (-not $f -or -not (Test-Path $f)) {
        Write-Error "ERROR: Required env file not found: $f`n  Run setup_azure.py and package-and-upload.sh first."
        exit 1
    }
}

Write-Log "Using PQC env file: $EnvPqc"
Write-Log "Using CSE env file: $EnvCse"

Import-EnvFile -Path $EnvPqc
Import-EnvFile -Path $EnvCse

foreach ($var in @('PQC_PACKAGE_URL', 'PQC_PACKAGE_SHA256', 'PQC_PACKAGE_SIG_URL', 'PQC_PACKAGE_PUBKEY_URL', 'PQC_PACKAGE_CERT_URL', 'PQC_LINUX_INSTALL_SCRIPT_URL', 'PQC_WINDOWS_INSTALL_SCRIPT_URL')) {
    if (-not (Get-Variable -Name $var -Scope Script -ErrorAction SilentlyContinue).Value) {
        Write-Error "ERROR: Missing required variable '$var' in $EnvCse`n  Re-run package-and-upload.sh to regenerate secure artifact URLs."
        exit 1
    }
}

az account set --subscription $Subscription
Assert-LastExitCode 'az account set'
$SubScope = "/subscriptions/$Subscription"

# ── Detect cloud and pick a valid MI location for the policy assignment ───────
# Azure Government: policy assignment identity only works in gov regions.
$CurrentCloud = az cloud show --query name -o tsv 2>$null
if (-not $CurrentCloud) { $CurrentCloud = 'AzureCloud' }
if ($CurrentCloud -match 'Government|Dod|USGov') {
    $MiLocation = 'usgovvirginia'
} else {
    $MiLocation = 'eastus'
}
Write-Log "Cloud: $CurrentCloud | MI location: $MiLocation"

# Helper: register a single policy definition from a full policy JSON file.
# az policy definition create --rules expects ONLY the policyRule object (if/then),
# and --params expects ONLY the parameters object — not the full properties wrapper.
function Register-PqcPolicy {
    param(
        [string]$Name,
        [string]$DisplayName,
        [string]$Description,
        [string]$JsonFile
    )

    $policyDoc = Get-Content -Raw -Path $JsonFile | ConvertFrom-Json
    $tmpRules = [System.IO.Path]::GetTempFileName()
    $tmpParams = [System.IO.Path]::GetTempFileName()

    ($policyDoc.properties.policyRule | ConvertTo-Json -Depth 100) | Set-Content -Path $tmpRules -Encoding utf8
    (($policyDoc.properties.parameters ?? [pscustomobject]@{}) | ConvertTo-Json -Depth 100) | Set-Content -Path $tmpParams -Encoding utf8

    $scopeArgs = @()
    if ($ManagementGroup) { $scopeArgs = @('--management-group', $ManagementGroup) }
    else { $scopeArgs = @('--subscription', $Subscription) }

    $policyId = az policy definition create `
        --name $Name `
        --display-name $DisplayName `
        --description $Description `
        --rules $tmpRules `
        --params $tmpParams `
        --mode Indexed `
        @scopeArgs `
        --query id --output tsv
    Assert-LastExitCode "Register policy '$Name'"

    Remove-Item -Force $tmpRules, $tmpParams -ErrorAction SilentlyContinue
    return $policyId
}

# ── Register policy definitions ───────────────────────────────────────────────
Write-Log '--- Registering Linux policy definition...'
$LinuxPolicyId = Register-PqcPolicy `
    -Name 'pqc-validator-linux-arc-cse' `
    -DisplayName '[PQC] Deploy PQC Validator CSE to Linux Arc machines' `
    -Description 'Deploys PQC Compliance Validator via Custom Script Extension to Linux Arc machines' `
    -JsonFile (Join-Path $PolicyDir 'pqc-linux-policy.json')
Write-Log "Linux policy: $LinuxPolicyId"

Write-Log '--- Registering Windows policy definition...'
$WinPolicyId = Register-PqcPolicy `
    -Name 'pqc-validator-windows-arc-cse' `
    -DisplayName '[PQC] Deploy PQC Validator CSE to Windows Arc machines' `
    -Description 'Deploys PQC Compliance Validator via Custom Script Extension to Windows Arc machines' `
    -JsonFile (Join-Path $PolicyDir 'pqc-windows-policy.json')
Write-Log "Windows policy: $WinPolicyId"

# ── Patch initiative with real policy IDs and extract sub-objects ────────────
$InitiativeFile = Join-Path $PolicyDir 'pqc-initiative.json'
$InitiativeDoc = Get-Content -Raw -Path $InitiativeFile | ConvertFrom-Json

foreach ($def in $InitiativeDoc.properties.policyDefinitions) {
    if ($def.policyDefinitionId -eq '<LINUX-POLICY-DEFINITION-ID>') { $def.policyDefinitionId = $LinuxPolicyId }
    elseif ($def.policyDefinitionId -eq '<WINDOWS-POLICY-DEFINITION-ID>') { $def.policyDefinitionId = $WinPolicyId }
}

$TmpDefs = [System.IO.Path]::GetTempFileName()
$TmpParams = [System.IO.Path]::GetTempFileName()
($InitiativeDoc.properties.policyDefinitions | ConvertTo-Json -Depth 100) | Set-Content -Path $TmpDefs -Encoding utf8
($InitiativeDoc.properties.parameters | ConvertTo-Json -Depth 100) | Set-Content -Path $TmpParams -Encoding utf8

Write-Log '--- Creating policy initiative...'
$ScopeArgs = @()
if ($ManagementGroup) { $ScopeArgs = @('--management-group', $ManagementGroup) }
else { $ScopeArgs = @('--subscription', $Subscription) }

$InitiativeId = az policy set-definition create `
    --name 'pqc-validator-arc-initiative' `
    --display-name '[PQC] Deploy PQC Compliance Validator to Arc machines' `
    --definitions $TmpDefs `
    --params $TmpParams `
    @ScopeArgs `
    --query id --output tsv
Assert-LastExitCode 'Create policy initiative'

Remove-Item -Force $TmpDefs, $TmpParams -ErrorAction SilentlyContinue
Write-Log "Initiative: $InitiativeId"

# ── Determine assignment scope ────────────────────────────────────────────────
if ($ManagementGroup) {
    $AssignScope = "/providers/Microsoft.Management/managementGroups/$ManagementGroup"
    $RemediationDiscoveryMode = 'ExistingNonCompliant'
} elseif ($ScopeRg) {
    $AssignScope = "$SubScope/resourceGroups/$ScopeRg"
    $RemediationDiscoveryMode = 'ReEvaluateCompliance'
} else {
    $AssignScope = $SubScope
    $RemediationDiscoveryMode = 'ReEvaluateCompliance'
}
Write-Log "Assignment scope: $AssignScope"

# ── Assign initiative ──────────────────────────────────────────────────────────
Write-Log '--- Assigning initiative...'
$AssignmentParams = @{
    dceEndpoint             = @{ value = $PQC_DCE_ENDPOINT }
    dcrImmutableId          = @{ value = $PQC_DCR_IMMUTABLE_ID }
    streamName              = @{ value = $(if ($PQC_STREAM_NAME) { $PQC_STREAM_NAME } else { 'Custom-PQCCompliance_CL' }) }
    linuxInstallScriptUrl   = @{ value = $PQC_LINUX_INSTALL_SCRIPT_URL }
    windowsInstallScriptUrl = @{ value = $PQC_WINDOWS_INSTALL_SCRIPT_URL }
    packageUrl              = @{ value = $PQC_PACKAGE_URL }
    packageSha256           = @{ value = $PQC_PACKAGE_SHA256 }
    packageSigUrl           = @{ value = $PQC_PACKAGE_SIG_URL }
    packagePubkeyUrl        = @{ value = $PQC_PACKAGE_PUBKEY_URL }
    packageCertUrl          = @{ value = $PQC_PACKAGE_CERT_URL }
    scheduleTime            = @{ value = '03:00' }
    forceUpdateTag          = @{ value = 'v6' }
    linuxEffect             = @{ value = 'DeployIfNotExists' }
    windowsEffect           = @{ value = 'DeployIfNotExists' }
}
$TmpAssignParams = [System.IO.Path]::GetTempFileName()
($AssignmentParams | ConvertTo-Json -Depth 100) | Set-Content -Path $TmpAssignParams -Encoding utf8

$AssignmentJson = az policy assignment create `
    --name 'pqc-validator-arc' `
    --display-name '[PQC] PQC Validator — Arc fleet' `
    --policy-set-definition $InitiativeId `
    --scope $AssignScope `
    --location $MiLocation `
    --mi-system-assigned `
    --params $TmpAssignParams `
    --output json
Assert-LastExitCode 'Assign initiative'
Remove-Item -Force $TmpAssignParams -ErrorAction SilentlyContinue

$Assignment = $AssignmentJson | ConvertFrom-Json
$AssignmentId = $Assignment.id
$AssignmentMi = $Assignment.identity.principalId
Write-Log "Assignment: $AssignmentId"
Write-Log "Assignment MI principal: $AssignmentMi"

# ── Grant remediation identity the Arc Connected Machine Resource Administrator role ──
# Role: Azure Connected Machine Resource Administrator
# GUID:  cd570a14-e51a-42ad-bac8-bafd67325302
Write-Log '--- Granting policy MI the Arc resource administrator role...'
$ExistingRoleAssignmentId = az role assignment list `
    --assignee-object-id $AssignmentMi `
    --scope $AssignScope `
    --query "[?roleDefinitionId && contains(roleDefinitionId, 'cd570a14-e51a-42ad-bac8-bafd67325302')].id | [0]" `
    --output tsv 2>$null

if ($ExistingRoleAssignmentId) {
    Write-Log "Role assignment already exists for policy MI: $ExistingRoleAssignmentId"
} else {
    az role assignment create `
        --role 'cd570a14-e51a-42ad-bac8-bafd67325302' `
        --assignee-object-id $AssignmentMi `
        --assignee-principal-type ServicePrincipal `
        --scope $AssignScope `
        --output none
    Assert-LastExitCode 'Grant Arc resource administrator role'
    Write-Log "Role granted to assignment MI: $AssignmentMi"
}

# ── Create remediation tasks for existing machines ────────────────────────────
# For initiative (policy set) assignments, a separate remediation task is required
# for each member policy definition, identified by --definition-reference-id.
# --policy-assignment accepts either the assignment name or the full resource ID.
# Scope arguments must match the assignment scope.
    param(
        [string]$Name,
        [string]$DefinitionReferenceId,
        [string]$Label
    )

    Write-Log "--- Creating remediation task for $Label..."
    $scopeArgs = @()
    if ($ManagementGroup) {
        $scopeArgs = @('--management-group', $ManagementGroup)
    } elseif ($ScopeRg) {
        $scopeArgs = @('--resource-group', $ScopeRg)
    } else {
        $scopeArgs = @('--subscription', $Subscription)
    }

    $state = az policy remediation show `
        --name $Name `
        @scopeArgs `
        --query 'properties.provisioningState' `
        --output tsv 2>$null

    if ($state -and $state -ne 'Failed') {
        Write-Log "$Label remediation already exists (state: $state); skipping create"
        return
    }

    $output = az policy remediation create `
        --name $Name `
        --policy-assignment $AssignmentId `
        --definition-reference-id $DefinitionReferenceId `
        @scopeArgs `
        --resource-discovery-mode $RemediationDiscoveryMode `
        --output none 2>&1
    if ($LASTEXITCODE -ne 0) {
        if ($output -match 'InvalidUpdateRemediationRequest') {
            Write-Log "$Label remediation already active; skipping create"
        } else {
            Write-Host $output
            exit $LASTEXITCODE
        }
    }
}

New-PqcRemediation -Name 'pqc-remediation-linux' -DefinitionReferenceId 'pqc-linux-arc-cse' -Label 'Linux Arc machines'
New-PqcRemediation -Name 'pqc-remediation-windows' -DefinitionReferenceId 'pqc-windows-arc-cse' -Label 'Windows Arc machines'

Write-Log ''
Write-Log '============================================================'
Write-Log 'Policy deployment complete'
Write-Log ''
Write-Log "  Linux policy  : $LinuxPolicyId"
Write-Log "  Windows policy: $WinPolicyId"
Write-Log "  Initiative    : $InitiativeId"
Write-Log "  Assignment    : $AssignmentId"
Write-Log "  Scope         : $AssignScope"
Write-Log ''
Write-Log 'New Arc machines will automatically receive the CSE extension'
Write-Log 'within the policy evaluation cycle (every 24h).'
Write-Log ''
Write-Log 'Monitor compliance:'
Write-Log '  az policy state list --policy-assignment pqc-validator-arc \'
Write-Log "      --subscription $Subscription --output table"
Write-Log '============================================================'
