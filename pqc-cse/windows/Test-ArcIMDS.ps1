#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Diagnoses the Arc Managed Identity IMDS challenge-response flow.
    Run this on the Windows Arc machine as Administrator to capture the exact
    error and file contents that PQCValidator.psm1 sees.
#>

$Resource   = 'https://monitor.azure.us'
$OutputFile = 'C:\Windows\Temp\arc-imds-diag.txt'

function Log([string]$msg) {
    $line = "[$(Get-Date -Format 'o')] $msg"
    Write-Host $line
    Add-Content -Path $OutputFile -Value $line -Encoding UTF8
}

New-Item -ItemType File -Force $OutputFile | Out-Null
Log '===== Arc IMDS Diagnostic ====='

# ── Environment ────────────────────────────────────────────────────────────────
Log "IDENTITY_ENDPOINT : $($env:IDENTITY_ENDPOINT)"
Log "IMDS_ENDPOINT      : $($env:IMDS_ENDPOINT)"

if (-not $env:IDENTITY_ENDPOINT) {
    Log 'ERROR: IDENTITY_ENDPOINT is not set. Arc agent may not be running or this session does not have the env var.'
    Log 'Try running: Get-Service himds | Select-Object Status'
    Get-Service himds -ErrorAction SilentlyContinue | ForEach-Object { Log "himds service: $($_.Status)" }
    exit 1
}

# ── Step 1: challenge request ──────────────────────────────────────────────────
$encoded = [Uri]::EscapeDataString($Resource)
$url     = "$($env:IDENTITY_ENDPOINT)?api-version=2020-06-01&resource=$encoded"
Log "Request URL: $url"

$wwwAuth = $null
try {
    $req1 = [System.Net.HttpWebRequest]::Create($url)
    $req1.Method = 'GET'
    $req1.Headers.Add('Metadata', 'true')
    $req1.AllowAutoRedirect = $false
    $r = $req1.GetResponse()
    Log "Step 1: Unexpected 200 - response body follows"
    $body = (New-Object System.IO.StreamReader($r.GetResponseStream())).ReadToEnd()
    $r.Close()
    Log "Body: $body"
} catch [System.Net.WebException] {
    $errResp = $_.Exception.Response
    if ($null -eq $errResp) {
        Log "Step 1: Exception with no response - $_"
        exit 1
    }
    $status = [int]$errResp.StatusCode
    Log "Step 1: HTTP $status (expected 401)"
    $wwwAuth = $errResp.Headers['WWW-Authenticate']
    Log "WWW-Authenticate: $wwwAuth"
    $errResp.Close()
}

if (-not $wwwAuth) {
    Log 'ERROR: No WWW-Authenticate header returned from IMDS'
    exit 1
}

# ── Extract challenge file path ────────────────────────────────────────────────
$rawRealm      = ($wwwAuth -split 'realm=', 2)[1].Trim()
$challengeFile = ($rawRealm -split ',')[0].Trim().Trim('"').Trim("'")
Log "Challenge file path: $challengeFile"
Log "File exists: $(Test-Path $challengeFile)"

if (-not (Test-Path $challengeFile)) {
    Log 'ERROR: Challenge file does not exist'
    exit 1
}

$bytes = [System.IO.File]::ReadAllBytes($challengeFile)
Log "File size (bytes): $($bytes.Length)"
Log "First 32 bytes hex: $(($bytes | Select-Object -First 32 | ForEach-Object { $_.ToString('X2') }) -join ' ')"

# ── Step 2: try both credential encodings ─────────────────────────────────────
$candidates = [ordered]@{
    # The file IS already base64 - use verbatim (correct approach)
    'VerbatimFileContent' = (Get-Content -Path $challengeFile -Raw -Encoding ASCII).Trim()
    # Legacy: base64 of trimmed UTF-8 (double-encodes - likely wrong)
    'TrimmedUTF8' = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(
        (Get-Content -Path $challengeFile -Raw -Encoding UTF8).TrimEnd()))
    # Legacy: raw bytes
    'RawBytes'    = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($challengeFile))
}

foreach ($name in $candidates.Keys) {
    $b64 = $candidates[$name]
    Log "--- Trying encoding: $name ---"
    Log "Base64 (first 40): $($b64.Substring(0, [Math]::Min(40, $b64.Length)))..."
    try {
        $req2 = [System.Net.HttpWebRequest]::Create($url)
        $req2.Method = 'GET'
        $req2.Headers.Add('Metadata',      'true')
        $req2.Headers.Add('Authorization', "Basic $b64")
        $req2.AllowAutoRedirect = $false

        $resp = $req2.GetResponse()
        $body = (New-Object System.IO.StreamReader($resp.GetResponseStream())).ReadToEnd()
        $resp.Close()
        Log "SUCCESS with encoding '$name'"
        $parsed = $body | ConvertFrom-Json
        Log "Token type    : $($parsed.token_type)"
        Log "Expires in    : $($parsed.expires_in)s"
        Log "Token (first 40): $($parsed.access_token.Substring(0,40))..."
        break
    } catch [System.Net.WebException] {
        $errResp = $_.Exception.Response
        $status  = [int]$errResp.StatusCode
        $errBody = ''
        try { $errBody = (New-Object System.IO.StreamReader($errResp.GetResponseStream())).ReadToEnd() } catch {}
        $errResp.Close()
        Log "FAILED ($status): $errBody"
    }
}

Log '===== Diagnostic complete ====='
Log "Output saved to: $OutputFile"
Write-Host "`nFull output also at: $OutputFile"
