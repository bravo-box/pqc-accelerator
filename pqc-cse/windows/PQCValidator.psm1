#Requires -Version 5.1
<#
.SYNOPSIS
    PQC Compliance Validator — native PowerShell module for Windows Arc machines.

.DESCRIPTION
    Runs all PQC / cryptographic compliance checks and streams results to
    Azure Monitor Log Analytics via the Arc machine's System-Assigned
    Managed Identity. No Python, no external dependencies.

    Exported functions:
        Invoke-PQCValidation   — run all checks, return result objects
        Send-PQCResults        — POST a result batch to the DCE/DCR endpoint
        Invoke-PQCDailyRun     — convenience wrapper used by run-daily.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Schema helpers ─────────────────────────────────────────────────────────────

function New-CheckRecord {
    param(
        [string]$CheckName,
        [string]$Category,
        [ValidateSet('COMPLIANT','REQUIRES_UPDATE','DEPRECATED','NOT_FOUND','UNKNOWN','ERROR')]
        [string]$Status,
        [string]$Details,
        [string]$Algorithm   = '',
        [string]$Version     = '',
        [string]$Hostname    = '',
        [string]$OsVersion   = ''
    )
    [PSCustomObject]@{
        TimeGenerated      = (Get-Date).ToUniversalTime().ToString('o')
        record_type        = 'scan_result'
        hostname           = $Hostname
        platform           = 'Windows'
        os_version         = $OsVersion
        check_name         = $CheckName
        category           = $Category
        status             = $Status
        details            = $Details
        algorithm          = $Algorithm
        version            = $Version
        gap_type           = ''
        severity           = ''
        affected_component = ''
        recommendation     = ''
        priority_score     = 0.0
        error_type         = ''
    }
}

function New-GapRecord {
    param(
        [string]$GapType,
        [ValidateSet('CRITICAL','HIGH','MEDIUM','LOW')]
        [string]$Severity,
        [string]$Description,
        [string]$AffectedComponent,
        [string]$Recommendation,
        [float] $PriorityScore = 0.0,
        [string]$Hostname  = '',
        [string]$OsVersion = ''
    )
    [PSCustomObject]@{
        TimeGenerated      = (Get-Date).ToUniversalTime().ToString('o')
        record_type        = 'compliance_gap'
        hostname           = $Hostname
        platform           = 'Windows'
        os_version         = $OsVersion
        check_name         = ''
        category           = ''
        status             = ''
        details            = $Description
        algorithm          = ''
        version            = ''
        gap_type           = $GapType
        severity           = $Severity
        affected_component = $AffectedComponent
        recommendation     = $Recommendation
        priority_score     = $PriorityScore
        error_type         = ''
    }
}

function New-ErrorRecord {
    param(
        [string]$ErrorType,
        [string]$Message,
        [string]$Hostname  = '',
        [string]$OsVersion = ''
    )
    [PSCustomObject]@{
        TimeGenerated      = (Get-Date).ToUniversalTime().ToString('o')
        record_type        = 'error'
        hostname           = $Hostname
        platform           = 'Windows'
        os_version         = $OsVersion
        check_name         = ''
        category           = ''
        status             = 'ERROR'
        details            = $Message
        algorithm          = ''
        version            = ''
        gap_type           = ''
        severity           = ''
        affected_component = ''
        recommendation     = ''
        priority_score     = 0.0
        error_type         = $ErrorType
    }
}

# ── System info ────────────────────────────────────────────────────────────────

function Get-SystemInfo {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $osVer = if ($os) { $os.Caption + ' ' + $os.Version } else { 'Unknown' }
    [PSCustomObject]@{
        Hostname  = $env:COMPUTERNAME
        OsVersion = $osVer
    }
}

# ── Individual checks ──────────────────────────────────────────────────────────

function Test-CNGSupport {
    param([string]$Hostname, [string]$OsVersion)
    try {
        $providers = Get-Item -Path 'HKLM:\Software\Microsoft\Cryptography\Providers' -ErrorAction Stop |
            Get-ChildItem -ErrorAction SilentlyContinue
        if ($providers -and ($providers.Name -match 'Microsoft')) {
            New-CheckRecord 'Windows CNG Support' 'crypto_library' 'COMPLIANT' `
                'CNG (Cryptography Next Generation) is available' -Hostname $Hostname -OsVersion $OsVersion
        } else {
            New-CheckRecord 'Windows CNG Support' 'crypto_library' 'REQUIRES_UPDATE' `
                'CNG not properly configured' -Hostname $Hostname -OsVersion $OsVersion
        }
    } catch {
        New-CheckRecord 'Windows CNG Support' 'crypto_library' 'UNKNOWN' `
            "Could not verify CNG: $_" -Hostname $Hostname -OsVersion $OsVersion
    }
}

function Test-BCryptDll {
    param([string]$Hostname, [string]$OsVersion)
    try {
        $path = 'C:\Windows\System32\bcrypt.dll'
        if (Test-Path $path) {
            $ver = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path).FileVersion
            New-CheckRecord 'BCrypt Library Check' 'crypto_library' 'COMPLIANT' `
                "BCrypt.dll available (version: $ver)" -Version $ver -Hostname $Hostname -OsVersion $OsVersion
        } else {
            New-CheckRecord 'BCrypt Library Check' 'crypto_library' 'NOT_FOUND' `
                'BCrypt.dll not found' -Hostname $Hostname -OsVersion $OsVersion
        }
    } catch {
        New-ErrorRecord 'bcrypt_check' "BCrypt check failed: $_" -Hostname $Hostname -OsVersion $OsVersion
    }
}

function Test-SchannelProtocols {
    param([string]$Hostname, [string]$OsVersion)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $regBase = 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
        $protocols = Get-ChildItem -Path $regBase -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty PSChildName

        $deprecated = @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')
        $foundDeprecated = $protocols | Where-Object { $deprecated -contains $_ }

        if ($foundDeprecated) {
            $list = $foundDeprecated -join ', '
            $results.Add((New-CheckRecord 'SChannel Protocol Configuration' 'tls_configuration' 'REQUIRES_UPDATE' `
                "Deprecated protocols detected: $list" -Hostname $Hostname -OsVersion $OsVersion))
            $results.Add((New-GapRecord 'deprecated_protocols' 'HIGH' `
                "Windows SChannel has deprecated protocols enabled: $list" `
                'SChannel/TLS' `
                'Disable deprecated protocols via Registry: HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\<protocol>\Server, set Enabled=0' `
                0.9 -Hostname $Hostname -OsVersion $OsVersion))
        } else {
            $results.Add((New-CheckRecord 'SChannel Protocol Configuration' 'tls_configuration' 'COMPLIANT' `
                'No deprecated protocols detected' -Hostname $Hostname -OsVersion $OsVersion))
        }
    } catch {
        $results.Add((New-ErrorRecord 'schannel_check' "SChannel check failed: $_" -Hostname $Hostname -OsVersion $OsVersion))
    }
    $results
}

function Test-CertificateStoreHealth {
    param([string]$Hostname, [string]$OsVersion)
    try {
        $count = (Get-ChildItem -Path Cert:\LocalMachine\Root -ErrorAction Stop | Measure-Object).Count
        if ($count -gt 0) {
            New-CheckRecord 'Certificate Store Health' 'certificates' 'COMPLIANT' `
                "Windows certificate store accessible ($count root certificates)" -Hostname $Hostname -OsVersion $OsVersion
        } else {
            New-CheckRecord 'Certificate Store Health' 'certificates' 'UNKNOWN' `
                'Certificate store appears empty' -Hostname $Hostname -OsVersion $OsVersion
        }
    } catch {
        New-ErrorRecord 'cert_store_check' "Certificate store check failed: $_" -Hostname $Hostname -OsVersion $OsVersion
    }
}

function Test-WeakRootCertificates {
    param([string]$Hostname, [string]$OsVersion)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $certs      = Get-ChildItem -Path Cert:\LocalMachine\Root -ErrorAction Stop
        $weakCerts  = $certs | Where-Object { $_.SignatureAlgorithm.FriendlyName -match 'sha1|md5|dsa' }
        $weakCount  = ($weakCerts | Measure-Object).Count

        if ($weakCount -gt 0) {
            $results.Add((New-CheckRecord 'Root Certificate Algorithm Check' 'certificates' 'REQUIRES_UPDATE' `
                "Found $weakCount root certificates using weak algorithms" -Hostname $Hostname -OsVersion $OsVersion))
            $results.Add((New-GapRecord 'weak_root_certificates' 'MEDIUM' `
                "$weakCount root certificates using weak algorithms (SHA1/MD5/DSA)" `
                'Windows Certificate Store' `
                'Update or remove certificates using SHA1, MD5, or DSA algorithms' `
                0.7 -Hostname $Hostname -OsVersion $OsVersion))
        } else {
            $results.Add((New-CheckRecord 'Root Certificate Algorithm Check' 'certificates' 'COMPLIANT' `
                'No weak root certificates detected' -Hostname $Hostname -OsVersion $OsVersion))
        }
    } catch {
        $results.Add((New-ErrorRecord 'weak_root_cert_check' "Weak cert check failed: $_" -Hostname $Hostname -OsVersion $OsVersion))
    }
    $results
}

function Test-WindowsOpenSSL {
    param([string]$Hostname, [string]$OsVersion)
    try {
        $raw = & openssl version 2>&1
        if ($LASTEXITCODE -ne 0) { throw "openssl exited $LASTEXITCODE" }
        if ($raw -match 'OpenSSL (\d+\.\d+\.\d+)') {
            $ver   = $Matches[1]
            $major = [int]($ver.Split('.')[0])
            if ($major -ge 3) {
                New-CheckRecord 'Windows OpenSSL Check' 'crypto_library' 'COMPLIANT' `
                    "OpenSSL $ver (Windows) - Has PQC support" -Version $ver -Hostname $Hostname -OsVersion $OsVersion
            } else {
                New-CheckRecord 'Windows OpenSSL Check' 'crypto_library' 'REQUIRES_UPDATE' `
                    "OpenSSL $ver (Windows) - Upgrade to 3.x for PQC support" -Version $ver -Hostname $Hostname -OsVersion $OsVersion
            }
        } else {
            New-CheckRecord 'Windows OpenSSL Check' 'crypto_library' 'UNKNOWN' `
                'OpenSSL version could not be determined' -Hostname $Hostname -OsVersion $OsVersion
        }
    } catch {
        New-CheckRecord 'Windows OpenSSL Check' 'crypto_library' 'NOT_FOUND' `
            'OpenSSL not installed on Windows' -Hostname $Hostname -OsVersion $OsVersion
    }
}

function Test-WindowsSecurityPatches {
    param([string]$Hostname, [string]$OsVersion)
    try {
        $count = (Get-HotFix -ErrorAction Stop | Measure-Object).Count
        if ($count -gt 0) {
            New-CheckRecord 'Windows Security Patches' 'system_security' 'COMPLIANT' `
                "Windows has $count security patches installed" -Hostname $Hostname -OsVersion $OsVersion
        } else {
            New-CheckRecord 'Windows Security Patches' 'system_security' 'REQUIRES_UPDATE' `
                'No security patches detected - system may be out of date' -Hostname $Hostname -OsVersion $OsVersion
        }
    } catch {
        New-ErrorRecord 'windows_update_check' "Windows patch check failed: $_" -Hostname $Hostname -OsVersion $OsVersion
    }
}

function Test-BitLockerEncryption {
    param([string]$Hostname, [string]$OsVersion)
    try {
        $vol = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop
        if ($vol.EncryptionPercentage -eq 100) {
            New-CheckRecord 'BitLocker Encryption' 'encryption' 'COMPLIANT' `
                'BitLocker encryption enabled and complete' -Hostname $Hostname -OsVersion $OsVersion
        } else {
            $pct = $vol.EncryptionPercentage
            New-CheckRecord 'BitLocker Encryption' 'encryption' 'REQUIRES_UPDATE' `
                "BitLocker encryption at $pct% - not fully enabled" `
                -Hostname $Hostname -OsVersion $OsVersion
        }
    } catch {
        New-CheckRecord 'BitLocker Encryption' 'encryption' 'UNKNOWN' `
            'Could not determine BitLocker status' -Hostname $Hostname -OsVersion $OsVersion
    }
}

function Test-FIPSPolicy {
    param([string]$Hostname, [string]$OsVersion)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $fipsKey  = 'HKLM:\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy'
        $fipsVal  = (Get-ItemProperty -Path $fipsKey -Name Enabled -ErrorAction Stop).Enabled
        if ($fipsVal -eq 1) {
            $results.Add((New-CheckRecord 'FIPS Algorithm Policy' 'system_security' 'COMPLIANT' `
                'FIPS 140 algorithm policy is enabled' -Hostname $Hostname -OsVersion $OsVersion))
        } else {
            $results.Add((New-CheckRecord 'FIPS Algorithm Policy' 'system_security' 'REQUIRES_UPDATE' `
                'FIPS 140 algorithm policy is disabled' -Hostname $Hostname -OsVersion $OsVersion))
            $results.Add((New-GapRecord 'fips_policy_disabled' 'MEDIUM' `
                'FIPS 140 algorithm policy is not enabled on this system' `
                'Windows Security Policy' `
                'Enable FIPS via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options' `
                0.6 -Hostname $Hostname -OsVersion $OsVersion))
        }
    } catch {
        $results.Add((New-CheckRecord 'FIPS Algorithm Policy' 'system_security' 'UNKNOWN' `
            "Could not read FIPS policy registry key: $_" -Hostname $Hostname -OsVersion $OsVersion))
    }
    $results
}

function Test-TLSCipherSuites {
    param([string]$Hostname, [string]$OsVersion)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $suites = Get-TlsCipherSuite -ErrorAction Stop | Select-Object -ExpandProperty Name

        $weakPatterns = @('RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'anon', 'MD5')
        $weakFound    = $suites | Where-Object { $name = $_; $weakPatterns | Where-Object { $name -match $_ } }
        $weakCount    = ($weakFound | Measure-Object).Count

        if ($weakCount -gt 0) {
            $weakList = $weakFound -join ', '
            $results.Add((New-CheckRecord 'TLS Cipher Suite Configuration' 'tls_configuration' 'REQUIRES_UPDATE' `
                "Found $weakCount weak cipher suites enabled: $weakList" `
                -Hostname $Hostname -OsVersion $OsVersion))
            $results.Add((New-GapRecord 'weak_cipher_suites' 'HIGH' `
                "$weakCount weak cipher suites are enabled" `
                'Windows TLS' `
                'Disable weak cipher suites via Group Policy or registry under HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL' `
                0.85 -Hostname $Hostname -OsVersion $OsVersion))
        } else {
            $suiteCount = $suites.Count
            $msg = "No weak cipher suites detected ($suiteCount suites configured)"
            $results.Add((New-CheckRecord 'TLS Cipher Suite Configuration' 'tls_configuration' 'COMPLIANT' $msg -Hostname $Hostname -OsVersion $OsVersion))
        }
    } catch {
        $results.Add((New-ErrorRecord 'cipher_suite_check' "Cipher suite check failed: $_" -Hostname $Hostname -OsVersion $OsVersion))
    }
    $results
}

# ── Arc Managed Identity token ─────────────────────────────────────────────────

function Get-ArcManagedIdentityToken {
    param([string]$Resource)

    $endpoint = $env:IDENTITY_ENDPOINT
    if (-not $endpoint) {
        throw 'IDENTITY_ENDPOINT not set — ensure the Arc Connected Machine Agent is running'
    }

    # URL-encode the resource so that '://' in the audience doesn't confuse the IMDS parser
    $encodedResource = [Uri]::EscapeDataString($Resource)
    $url = "${endpoint}?api-version=2020-06-01&resource=$encodedResource"

    # Step 1: challenge request — Arc IMDS always returns 401 first
    $req1 = [System.Net.HttpWebRequest]::Create($url)
    $req1.Method = 'GET'
    $req1.Headers.Add('Metadata', 'true')
    $req1.AllowAutoRedirect = $false

    $challengeFile = $null
    try {
        $r = $req1.GetResponse(); $r.Close()
        throw 'Arc IMDS returned 200 without challenge — unexpected'
    } catch [System.Net.WebException] {
        $wr = $_.Exception.Response
        if ($null -eq $wr) { throw }
        if ([int]$wr.StatusCode -ne 401) { throw }
        $wwwAuth = $wr.Headers['WWW-Authenticate']
        $wr.Close()
        if (-not $wwwAuth) { throw 'Arc IMDS 401 missing WWW-Authenticate header' }
        # Extract realm path — strip quotes; stop at comma for multi-attribute headers
        $rawRealm = ($wwwAuth -split 'realm=', 2)[1].Trim()
        $challengeFile = ($rawRealm -split ',')[0].Trim().Trim('"').Trim("'")
    }

    if (-not (Test-Path $challengeFile)) {
        throw "Arc IMDS challenge file not found: $challengeFile"
    }

    # The key file content IS already the base64 Basic auth token — use it verbatim
    $challengeKey = (Get-Content -Path $challengeFile -Raw -Encoding ASCII).Trim()

    $req2 = [System.Net.HttpWebRequest]::Create($url)
    $req2.Method = 'GET'
    $req2.Headers.Add('Metadata',      'true')
    $req2.Headers.Add('Authorization', "Basic $challengeKey")
    $req2.AllowAutoRedirect = $false

    $resp2   = $req2.GetResponse()
    $stream  = $resp2.GetResponseStream()
    $reader  = New-Object System.IO.StreamReader($stream)
    $body    = $reader.ReadToEnd()
    $reader.Close(); $resp2.Close()

    ($body | ConvertFrom-Json).access_token
}

# ── DCE / Logs Ingestion API ───────────────────────────────────────────────────

function Send-PQCResults {
    <#
    .SYNOPSIS
        POST a batch of PQC result objects to Azure Monitor via the DCE Logs Ingestion API.
    .PARAMETER DceEndpoint
        Data Collection Endpoint URL (e.g. https://<name>.ingest.monitor.azure.us).
    .PARAMETER DcrImmutableId
        DCR Immutable ID (dcr-xxxx).
    .PARAMETER StreamName
        Custom stream name matching the DCR.
    .PARAMETER Records
        Array of PSCustomObject records to send.
    #>
    param(
        [string]           $DceEndpoint,
        [string]           $DcrImmutableId,
        [string]           $StreamName,
        [PSCustomObject[]] $Records
    )

    if (-not $Records -or $Records.Count -eq 0) { return }

    $isGov    = $DceEndpoint -match '\.azure\.us'
    $resource = if ($isGov) { 'https://monitor.azure.us' } else { 'https://monitor.azure.com' }

    $token = Get-ArcManagedIdentityToken -Resource $resource

    $dceBase = $DceEndpoint.TrimEnd('/')
    $url     = "$dceBase/dataCollectionRules/$DcrImmutableId/streams/$StreamName`?api-version=2023-01-01"
    $body    = $Records | ConvertTo-Json -Compress -Depth 5
    if ($body[0] -ne '[') { $body = "[$body]" }

    $headers = @{
        Authorization  = "Bearer $token"
        'Content-Type' = 'application/json'
    }

    $response = Invoke-WebRequest -Uri $url -Method Post -Headers $headers `
        -Body $body -UseBasicParsing -ErrorAction Stop

    if ($response.StatusCode -notin 200, 204) {
        $sc = $response.StatusCode
        $sb = $response.Content
        throw "DCE ingestion returned HTTP $sc`: $sb"
    }
}

# ── Public API ─────────────────────────────────────────────────────────────────

function Invoke-PQCValidation {
    <#
    .SYNOPSIS
        Run all PQC compliance checks and return an array of result records.
    .OUTPUTS
        PSCustomObject[]  — records matching the Log Analytics schema
    #>
    [OutputType([PSCustomObject[]])]
    param()

    $sys      = Get-SystemInfo
    $hostname = $sys.Hostname
    $osVer    = $sys.OsVersion

    $all = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Crypto libraries
    $all.Add((Test-CNGSupport  -Hostname $hostname -OsVersion $osVer))
    $all.Add((Test-BCryptDll   -Hostname $hostname -OsVersion $osVer))
    Test-SchannelProtocols     -Hostname $hostname -OsVersion $osVer | ForEach-Object { $all.Add($_) }
    Test-TLSCipherSuites       -Hostname $hostname -OsVersion $osVer | ForEach-Object { $all.Add($_) }
    $all.Add((Test-WindowsOpenSSL -Hostname $hostname -OsVersion $osVer))

    # Certificate store
    $all.Add((Test-CertificateStoreHealth  -Hostname $hostname -OsVersion $osVer))
    Test-WeakRootCertificates              -Hostname $hostname -OsVersion $osVer | ForEach-Object { $all.Add($_) }

    # System security
    $all.Add((Test-WindowsSecurityPatches -Hostname $hostname -OsVersion $osVer))
    $all.Add((Test-BitLockerEncryption    -Hostname $hostname -OsVersion $osVer))
    Test-FIPSPolicy                        -Hostname $hostname -OsVersion $osVer | ForEach-Object { $all.Add($_) }

    # Stamp hostname/osVersion on any records that may have missed it
    foreach ($rec in $all) {
        if (-not $rec.hostname)  { $rec.hostname  = $hostname }
        if (-not $rec.os_version){ $rec.os_version = $osVer }
    }

    $all.ToArray()
}

function Invoke-PQCDailyRun {
    <#
    .SYNOPSIS
        Convenience wrapper: validate, log locally, and stream to Log Analytics via DCE.
    .PARAMETER DceEndpoint
        Data Collection Endpoint URL.
    .PARAMETER DcrImmutableId
        DCR Immutable ID.
    .PARAMETER StreamName
        Log Analytics stream name.
    .PARAMETER LogDir
        Directory for local log files.
    .PARAMETER ReportDir
        Directory for local report files (JSON summary).
    #>
    param(
        [Parameter(Mandatory)][string]$DceEndpoint,
        [Parameter(Mandatory)][string]$DcrImmutableId,
        [string]$StreamName = 'Custom-Json-PQCCompliance',
        [string]$LogDir     = 'C:\pqc-validator\logs',
        [string]$ReportDir  = 'C:\pqc-validator\reports'
    )

    $null = New-Item -ItemType Directory -Force $LogDir, $ReportDir

    $runDate = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    $logFile = Join-Path $LogDir "run-$runDate.log"

    function Write-RunLog([string]$msg) {
        $ts   = (Get-Date).ToUniversalTime().ToString('o')
        $line = "[$ts] $msg"
        Write-Host $line
        Add-Content -Path $logFile -Value $line -Encoding UTF8
    }

    Write-RunLog 'PQC validation started'

    try {
        $records = Invoke-PQCValidation

        # Write local JSON report
        $reportFile = Join-Path $ReportDir "pqc-report-$runDate.json"
        $records | ConvertTo-Json -Depth 5 | Out-File -FilePath $reportFile -Encoding UTF8 -Force
        $recCount = $records.Count
        Write-RunLog "Local report: $reportFile ($recCount records)"

        # Stream to Log Analytics via DCE
        Write-RunLog "Sending $recCount records to Log Analytics..."
        Send-PQCResults -DceEndpoint $DceEndpoint -DcrImmutableId $DcrImmutableId `
            -StreamName $StreamName -Records $records
        Write-RunLog "Log Analytics ingestion complete"

        # Rotate logs older than 30 days
        Get-ChildItem -Path $LogDir -Filter 'run-*.log' -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
            Remove-Item -Force -ErrorAction SilentlyContinue

    } catch {
        Write-RunLog "ERROR: $_"
        throw
    }

    Write-RunLog 'PQC validation finished'
}

Export-ModuleMember -Function Invoke-PQCValidation, Send-PQCResults, Invoke-PQCDailyRun
