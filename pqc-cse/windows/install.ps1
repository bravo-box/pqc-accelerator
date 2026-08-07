#Requires -RunAsAdministrator
<#
.SYNOPSIS
    PQC Validator — Arc Custom Script Extension Bootstrap (Windows)

.DESCRIPTION
    Runs ONCE via the Arc CustomScriptExtension.
    Installs the PQC Compliance Validator (PowerShell module — no Python required)
    and creates a daily Windows Scheduled Task to run the validator and stream
    results to Log Analytics via the DCE Logs Ingestion API using the Arc
    machine's System-Assigned Managed Identity.

.PARAMETER DceEndpoint
    Data Collection Endpoint URL.

.PARAMETER DcrImmutableId
    DCR Immutable ID (dcr-xxxx).

.PARAMETER StreamName
    Log Analytics stream name. Default: Custom-PQCCompliance_CL

.PARAMETER PackageUrl
    SAS URL to pqc-validator.zip in Azure Blob Storage.

.PARAMETER PackageSha256
    Expected SHA-256 of pqc-validator.zip.

.PARAMETER PackageSigUrl
    SAS URL to detached signature for pqc-validator.zip.

.PARAMETER PackageCertUrl
    SAS URL to DER certificate containing signing public key.

.PARAMETER ScheduleTime
    Daily run time HH:MM in UTC. Default: 03:00

.PARAMETER InstallDir
    Installation directory. Default: C:\pqc-validator
#>
param(
    [string]$DceEndpoint    = 'https://pqc-dce-odbi.usgovvirginia-1.ingest.monitor.azure.us',
    [string]$DcrImmutableId = 'dcr-d1e102cdb8d54975b5218038d0be7b50',
    [string]$StreamName     = 'Custom-PQCCompliance_CL',
    [string]$PackageUrl     = '',
    [string]$PackageSha256  = '',
    [string]$PackageSigUrl  = '',
    [string]$PackageCertUrl = '',
    [string]$ScheduleTime   = '03:00',
    [string]$InstallDir     = 'C:\pqc-validator'
)

# Accept overrides via environment variables
if ($env:PQC_DCE_ENDPOINT     -and -not $PSBoundParameters.ContainsKey('DceEndpoint'))    { $DceEndpoint    = $env:PQC_DCE_ENDPOINT }
if ($env:PQC_DCR_IMMUTABLE_ID -and -not $PSBoundParameters.ContainsKey('DcrImmutableId')) { $DcrImmutableId = $env:PQC_DCR_IMMUTABLE_ID }
if ($env:PQC_STREAM_NAME      -and -not $PSBoundParameters.ContainsKey('StreamName'))      { $StreamName     = $env:PQC_STREAM_NAME }
if ($env:PQC_PACKAGE_URL      -and -not $PSBoundParameters.ContainsKey('PackageUrl'))      { $PackageUrl     = $env:PQC_PACKAGE_URL }
if ($env:PQC_PACKAGE_SHA256   -and -not $PSBoundParameters.ContainsKey('PackageSha256'))   { $PackageSha256  = $env:PQC_PACKAGE_SHA256 }
if ($env:PQC_PACKAGE_SIG_URL  -and -not $PSBoundParameters.ContainsKey('PackageSigUrl'))   { $PackageSigUrl  = $env:PQC_PACKAGE_SIG_URL }
if ($env:PQC_PACKAGE_CERT_URL -and -not $PSBoundParameters.ContainsKey('PackageCertUrl'))  { $PackageCertUrl = $env:PQC_PACKAGE_CERT_URL }
if ($env:PQC_SCHEDULE_TIME    -and -not $PSBoundParameters.ContainsKey('ScheduleTime'))    { $ScheduleTime   = $env:PQC_SCHEDULE_TIME }
if ($env:PQC_INSTALL_DIR      -and -not $PSBoundParameters.ContainsKey('InstallDir'))      { $InstallDir     = $env:PQC_INSTALL_DIR }

$ErrorActionPreference = 'Stop'

$ModuleFile  = "$InstallDir\PQCValidator.psm1"
$DailyScript = "$InstallDir\run-daily.ps1"
$LogDir      = "$InstallDir\logs"
$ReportDir   = "$InstallDir\reports"
$InstallLog  = "C:\Windows\Temp\pqc-cse-install.log"
$TaskName    = 'PQC-DailyValidator'
$TaskPath    = '\Microsoft\PQC\'

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Message)
    $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $line = "[$ts] $Message"
    Write-Host $line
    Add-Content -Path $InstallLog -Value $line -Encoding UTF8
}

function Test-DetachedRsaSignature {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][string]$SignaturePath,
        [Parameter(Mandatory=$true)][string]$CertificatePath
    )

    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath)
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
    if (-not $rsa) {
        throw 'Certificate does not contain an RSA public key'
    }

    $data = [System.IO.File]::ReadAllBytes($FilePath)
    $sig = [System.IO.File]::ReadAllBytes($SignaturePath)

    try {
        $ok = $rsa.VerifyData(
            $data,
            $sig,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
    } finally {
        $rsa.Dispose()
    }

    return $ok
}

New-Item -ItemType Directory -Force (Split-Path $InstallLog) | Out-Null
New-Item -ItemType File -Force $InstallLog | Out-Null

# ── Validate parameters ───────────────────────────────────────────────────────
Write-Log '=========================================================='
Write-Log 'PQC Validator CSE Install starting'
Write-Log 'Version      : 3.1.0'
Write-Log '=========================================================='

foreach ($kv in @{
    PackageUrl=$PackageUrl
    PackageSha256=$PackageSha256
    PackageSigUrl=$PackageSigUrl
    PackageCertUrl=$PackageCertUrl
}.GetEnumerator()) {
    if ([string]::IsNullOrWhiteSpace($kv.Value)) {
        Write-Log "ERROR: Required parameter '$($kv.Key)' is not set"
        exit 1
    }
}

Write-Log "DCE Endpoint : $DceEndpoint"
Write-Log "DCR ID       : $DcrImmutableId"
Write-Log "Stream Name  : $StreamName"
Write-Log "Schedule     : $ScheduleTime UTC"
Write-Log "Install Dir  : $InstallDir"
Write-Log "Package SHA  : $PackageSha256"

# ── TLS 1.2 / security protocol ───────────────────────────────────────────────
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ── Download & extract validator package ──────────────────────────────────────
Write-Log '--- Downloading signed PQC Validator package...'
$zipPath = "$env:TEMP\pqc-validator.zip"
$sigPath = "$env:TEMP\pqc-validator.zip.sig"
$certPath = "$env:TEMP\pqc-signing-cert.cer"

try {
    Invoke-WebRequest -Uri $PackageUrl -OutFile $zipPath -UseBasicParsing
    Invoke-WebRequest -Uri $PackageSigUrl -OutFile $sigPath -UseBasicParsing
    Invoke-WebRequest -Uri $PackageCertUrl -OutFile $certPath -UseBasicParsing
} catch {
    Write-Log "ERROR: Failed to download package artifact: $_"
    exit 1
}

Write-Log '--- Verifying package SHA-256...'
$actualHash = (Get-FileHash -Algorithm SHA256 -Path $zipPath).Hash.ToLowerInvariant()
$expectedHash = $PackageSha256.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    Write-Log 'ERROR: Package hash mismatch'
    Write-Log "  expected: $expectedHash"
    Write-Log "  actual  : $actualHash"
    exit 1
}

Write-Log '--- Verifying detached package signature...'
try {
    if (-not (Test-DetachedRsaSignature -FilePath $zipPath -SignaturePath $sigPath -CertificatePath $certPath)) {
        Write-Log 'ERROR: Signature verification failed'
        exit 1
    }
} catch {
    Write-Log "ERROR: Signature verification error: $_"
    exit 1
}
Write-Log 'Package verification passed'

Write-Log "--- Extracting to $InstallDir..."
if (Test-Path $InstallDir) {
    Remove-Item -Recurse -Force $InstallDir
}
Expand-Archive -Path $zipPath -DestinationPath $InstallDir -Force
Remove-Item $zipPath, $sigPath, $certPath -Force

# Verify the module was included in the package
if (-not (Test-Path $ModuleFile)) {
    Write-Log "ERROR: PQCValidator.psm1 not found in package at $ModuleFile"
    Write-Log 'Re-run package-and-upload.sh to rebuild the package with the PowerShell module.'
    exit 1
}
Write-Log "PowerShell module: $ModuleFile"

# ── Create runtime directories ─────────────────────────────────────────────────
New-Item -ItemType Directory -Force $LogDir   | Out-Null
New-Item -ItemType Directory -Force $ReportDir | Out-Null

# ── Write daily runner script ─────────────────────────────────────────────────
Write-Log "--- Writing daily runner: $DailyScript"

$dailyScriptContent = @"
# PQC Validator daily runner — executed by Windows Task Scheduler
# Uses PQCValidator.psm1 (native PowerShell). Streams via DCE Logs Ingestion API + Arc MI.
`$ErrorActionPreference = 'Stop'

Import-Module '$ModuleFile' -Force

Invoke-PQCDailyRun ``
    -DceEndpoint    '$DceEndpoint' ``
    -DcrImmutableId '$DcrImmutableId' ``
    -StreamName     '$StreamName' ``
    -LogDir         '$LogDir' ``
    -ReportDir      '$ReportDir'
"@

$dailyScriptContent | Out-File -FilePath $DailyScript -Encoding UTF8 -Force

# ── Create Scheduled Task ─────────────────────────────────────────────────────
Write-Log "--- Creating Scheduled Task '$TaskName' at $ScheduleTime UTC..."

# Build task start time on today's date at the requested UTC time
$startTime = [datetime]::SpecifyKind(
    [datetime]::ParseExact("2000-01-01 $ScheduleTime`:00", 'yyyy-MM-dd HH:mm:ss', $null),
    [System.DateTimeKind]::Utc
)

$taskAction = New-ScheduledTaskAction `
    -Execute 'powershell.exe' `
    -Argument "-NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"$DailyScript`""

$taskTrigger = New-ScheduledTaskTrigger -Daily -At $startTime

$taskSettings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit  (New-TimeSpan -Hours 2) `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -MultipleInstances IgnoreNew `
    -Hidden

$taskPrincipal = New-ScheduledTaskPrincipal `
    -UserId    'NT AUTHORITY\SYSTEM' `
    -LogonType ServiceAccount `
    -RunLevel  Highest

# Ensure task folder exists
$schedSvc = New-Object -ComObject Schedule.Service
$schedSvc.Connect()
try { $schedSvc.GetFolder($TaskPath) | Out-Null }
catch {
    try {
        $schedSvc.GetFolder('\Microsoft').CreateFolder('PQC') | Out-Null
    } catch [System.Runtime.InteropServices.COMException] {
        # 0x800700B7 = folder already exists — safe to ignore on re-deploy
        if ($_.Exception.HResult -ne [int]0x800700B7) { throw }
    }
}
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($schedSvc) | Out-Null

# Remove any existing task registration
$existingTask = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Unregister-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Confirm:$false
    Write-Log "Removed existing task registration"
}

Register-ScheduledTask `
    -TaskName   $TaskName `
    -TaskPath   $TaskPath `
    -Action     $taskAction `
    -Trigger    $taskTrigger `
    -Settings   $taskSettings `
    -Principal  $taskPrincipal `
    -Description 'Daily PQC Compliance Validation — reports to Azure Log Analytics' `
    -Force | Out-Null

Write-Log "Scheduled Task registered: $TaskPath$TaskName (daily at $ScheduleTime UTC)"

# ── Run immediately on first install ──────────────────────────────────────────
Write-Log '--- Running initial validation (this may take a few minutes)...'
try {
    & powershell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass -File $DailyScript
    Write-Log "Initial validation completed (exit=$LASTEXITCODE)"
} catch {
    Write-Log "WARNING: Initial validation encountered an error: $_"
}

Write-Log '=========================================================='
Write-Log 'PQC Validator install complete'
Write-Log "  Validator  : $InstallDir"
Write-Log "  Daily log  : $LogDir\run-YYYYMMDD.log"
Write-Log "  Schedule   : $ScheduleTime UTC (Task: $TaskPath$TaskName)"
Write-Log "  Install log: $InstallLog"
Write-Log '=========================================================='
