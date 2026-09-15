# Shared runner library.
#
# Dot-sourced by every *_test_runner.ps1 so that a fix to artifact handling,
# report text normalization or expectation parsing has a single home.
#
# Contract for the caller: before invoking any artifact helper the runner must
# define $script:RunId, $script:ArtifactsRoot and $script:ArtifactsRunDir.
# Runner-specific behaviour is expressed by redefining a function after the
# dot-source (the later definition wins) or by setting the documented
# $script:* configuration variables below.

# Extra result_snapshot fields appended by platform-specific runners.
# Ordered map of field name -> default value used when the payload omits it.
$script:ArtifactSnapshotExtraFields = [ordered]@{}

# ---------------------------------------------------------------------------
# Artifact store
# ---------------------------------------------------------------------------

function Ensure-Directory {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Get-SafePathToken {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return "unknown" }
    return (($Value -replace '[^A-Za-z0-9._-]', '_').Trim('_'))
}

function Initialize-ArtifactStore {
    Ensure-Directory -Path $script:ArtifactsRoot
    $script:ArtifactsRunDir = Join-Path $script:ArtifactsRoot $script:RunId
    Ensure-Directory -Path $script:ArtifactsRunDir
}

function Write-TestArtifact {
    param(
        [string]$TestId,
        [string]$ArtifactName,
        [object]$Data
    )

    if ([string]::IsNullOrWhiteSpace($script:ArtifactsRunDir)) {
        Initialize-ArtifactStore
    }

    $safeTestId = Get-SafePathToken -Value $TestId
    $safeName = Get-SafePathToken -Value $ArtifactName
    $testDir = Join-Path $script:ArtifactsRunDir $safeTestId
    Ensure-Directory -Path $testDir

    $filePath = Join-Path $testDir ("{0}.json" -f $safeName)
    ($Data | ConvertTo-Json -Depth 12) | Out-File -FilePath $filePath -Encoding UTF8

    return "artifacts/$($script:RunId)/$safeTestId/$safeName.json"
}

function Add-ArtifactMetadata {
    param([hashtable]$Payload)

    $testId = [string](Get-ResultField -Result $Payload -FieldName 'test_id' -DefaultValue 'UNKNOWN')
    $snapshot = [ordered]@{
        run_id = $script:RunId
        collected_at = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        test_id = $testId
        test_name = (Get-ResultField -Result $Payload -FieldName 'test_name' -DefaultValue '')
        status = (Get-ResultField -Result $Payload -FieldName 'status' -DefaultValue '')
        severity = (Get-ResultField -Result $Payload -FieldName 'severity' -DefaultValue '')
        expected_value = (Get-ResultField -Result $Payload -FieldName 'expected_value' -DefaultValue '')
        expected_kind = (Get-ResultField -Result $Payload -FieldName 'expected_kind' -DefaultValue '')
        expected_machine_value = (Get-ResultField -Result $Payload -FieldName 'expected_machine_value' -DefaultValue '')
        observed_value = (Get-ResultField -Result $Payload -FieldName 'observed_value' -DefaultValue '')
        evidence_output = (Get-ResultField -Result $Payload -FieldName 'evidence_output' -DefaultValue '')
        evidence_type = (Get-ResultField -Result $Payload -FieldName 'evidence_type' -DefaultValue '')
        details = (Get-ResultField -Result $Payload -FieldName 'details' -DefaultValue '')
        message = (Get-ResultField -Result $Payload -FieldName 'message' -DefaultValue '')
        status_reason = (Get-ResultField -Result $Payload -FieldName 'status_reason' -DefaultValue '')
    }

    foreach ($extraField in @($script:ArtifactSnapshotExtraFields.Keys)) {
        $snapshot[$extraField] = Get-ResultField -Result $Payload -FieldName $extraField -DefaultValue $script:ArtifactSnapshotExtraFields[$extraField]
    }

    $artifactPath = Write-TestArtifact -TestId $testId -ArtifactName 'result_snapshot' -Data $snapshot
    $Payload.run_id = $script:RunId
    $Payload.evidence_path = $artifactPath
    $Payload.evidence_items = @(
        @{
            type = if ([string]::IsNullOrWhiteSpace([string]$Payload.evidence_type)) { 'result_snapshot' } else { [string]$Payload.evidence_type }
            path = $artifactPath
            collected_at = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }
    )

    return $Payload
}

# ---------------------------------------------------------------------------
# Result field access
# ---------------------------------------------------------------------------

function Get-ResultField {
    param(
        [object]$Result,
        [string]$FieldName,
        [object]$DefaultValue = ""
    )

    if ($null -eq $Result) { return $DefaultValue }

    if ($Result -is [hashtable]) {
        if ($Result.ContainsKey($FieldName)) { return $Result[$FieldName] }
        return $DefaultValue
    }

    $prop = $Result.PSObject.Properties[$FieldName]
    if ($null -ne $prop) { return $prop.Value }
    return $DefaultValue
}

function Get-ResultFieldOrFallback {
    param(
        [object]$Result,
        [string]$FieldName,
        [object]$FallbackValue = ""
    )

    $value = Get-ResultField -Result $Result -FieldName $FieldName -DefaultValue $null
    if ($null -eq $value) { return $FallbackValue }
    if ($value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($value)) { return $FallbackValue }
        return $value
    }
    return $value
}

function Get-DefaultStatusReason {
    param([string]$Status)

    switch ([string]$Status) {
        'PASSED' { return 'expected_condition_met' }
        'FAILED' { return 'expected_condition_not_met' }
        'UNKNOWN' { return 'verification_inconclusive' }
        'NOT_ASSESSED' { return 'evidence_not_collectable' }
        default { return 'not_classified' }
    }
}

function Get-MachineComparableExpectation {
    param(
        [object]$ExpectedValue,
        [object]$ObservedValue
    )

    $text = [string]$ExpectedValue
    if ([string]::IsNullOrWhiteSpace($text)) {
        return @{ kind = ''; value = '' }
    }

    $t = $text.ToLowerInvariant()

    if ($t -match '>=\s*(-?\d+)') {
        return @{ kind = 'numeric_gte'; value = [string]$Matches[1] }
    }
    if ($t -match 'en az\s*(-?\d+)') {
        return @{ kind = 'numeric_gte'; value = [string]$Matches[1] }
    }
    if ($t -match '(?i)expected:\s*(-?\d+)') {
        return @{ kind = 'numeric_eq'; value = [string]$Matches[1] }
    }
    if ($t -match '(?i)\b(true|false)\b') {
        return @{ kind = 'bool'; value = $Matches[1].ToLowerInvariant() }
    }
    if ($t -match '(?i)\b(0|1)\b\s*olmali') {
        $boolVal = if ($Matches[1] -eq '1') { 'true' } else { 'false' }
        return @{ kind = 'bool'; value = $boolVal }
    }
    if ($t -match '(?i)tanimli\s+olmamali|bulunmamali|bos\s+olmali') {
        return @{ kind = 'bool'; value = 'false' }
    }
    if ($t -match '(?i)tanimli\s+olmali') {
        return @{ kind = 'bool'; value = 'true' }
    }
    if ($t -match '(?i)\b(tls1\.[0-3])\b') {
        return @{ kind = 'enum'; value = $Matches[1].ToLowerInvariant() }
    }

    # Fallback: explicit mode values commonly used in policy expectations.
    if ($t -match '(?i)\b(secure|off|system|fixed_servers|pac_script)\b') {
        return @{ kind = 'enum'; value = $Matches[1].ToLowerInvariant() }
    }

    return @{ kind = ''; value = '' }
}

# ---------------------------------------------------------------------------
# Report text normalization
# ---------------------------------------------------------------------------

function Sanitize-ReportText {
    param(
        [object]$Value,
        [string]$TestName = ""
    )

    if ($null -eq $Value) { return "" }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return "" }

    $cleaned = $text
    $cleaned = [regex]::Replace($cleaned, '(?i)Mapped\s+policy(?:\s+key)?(?:\s+not\s+found\s+locally|\s+not\s+found)?\s*:\s*[^\r\n]+', 'The mapped policy key could not be detected on the local system.')
    $cleaned = [regex]::Replace($cleaned, '(?i)Mapped\s+pref(?:erence)?(?:\s+key)?(?:\s+not\s+found\s+locally|\s+not\s+found)?\s*:\s*[^\r\n]+', 'The mapped preference key could not be detected on the local system.')
    $cleaned = [regex]::Replace($cleaned, 'policies\.json not found', 'The enterprise policy file was not found on this endpoint', 'IgnoreCase')
    $cleaned = [regex]::Replace($cleaned, '\bpref(?:erence)?\s+not\s+found\b', 'preference key not found', 'IgnoreCase')
    $cleaned = [regex]::Replace($cleaned, '\s+', ' ').Trim()

    if ($cleaned -match '^[A-Za-z0-9 _-]+:\s*RISK$') {
        $label = ($cleaned -split ':')[0].Trim()
        $cleaned = "$label a risky configuration was detected in this control."
    }

    if (-not [string]::IsNullOrWhiteSpace($TestName) -and [string]::Equals($cleaned, $TestName, [System.StringComparison]::OrdinalIgnoreCase)) {
        $cleaned = "$TestName a state that is not aligned with enterprise security expectations was detected in this control."
    }

    return $cleaned
}

function Convert-ImpactTextToEnglish {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }

    $converted = [string]$Text
    $rules = @(
        @('(?i)Olasi etki:', 'Potential impact:'),
        @('(?i)Beklenen durum:', 'Expected state:'),
        @('(?i)Gozlenen durum:', 'Observed state:'),
        @('(?i)kurumsal politika ile sinirlandirilmis gorunuyor', 'appears restricted by enterprise policy'),
        @('(?i)devre disi', 'disabled'),
        @('(?i)aciksa', 'if enabled'),
        @('(?i)yoksa', 'if missing'),
        @('(?i)tarayici', 'browser'),
        @('(?i)saldiri yuzeyi', 'attack surface'),
        @('(?i)denetim izi', 'audit trail'),
        @('(?i)uyumluluk acigi', 'compliance gap'),
        @('(?i)gizlilik/kvkk uyumsuzlugu', 'privacy and data protection compliance risk')
    )

    foreach ($rule in $rules) {
        $converted = [regex]::Replace($converted, $rule[0], $rule[1])
    }

    $converted = [regex]::Replace($converted, '\s+', ' ').Trim()
    return $converted
}

function Is-NaLikeText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $true }
    return [bool]([regex]::IsMatch($Text.Trim(), '^(yok|n/?a|na|null|none|-)$', 'IgnoreCase'))
}

function Get-FirstMeaningfulText {
    param(
        [object[]]$Candidates,
        [string]$TestName = ""
    )
    foreach ($candidate in $Candidates) {
        $cleaned = Sanitize-ReportText -Value $candidate -TestName $TestName
        if (-not (Is-NaLikeText $cleaned)) {
            return $cleaned
        }
    }
    return ""
}

function Is-CrossLayerWarningText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }

    $pattern = '(?i)(baska\s+.*katman|proxy|sse|casb|cloud\s*policy|yonetim\s+katman|enforcement\s+olabilir|davranissal\s+manuel\s+test)'
    return [bool]([regex]::IsMatch($Text, $pattern))
}

function ConvertTo-BoolSafe {
    param([object]$Value)

    if ($Value -is [bool]) { return $Value }
    if ($null -eq $Value) { return $false }

    if ($Value -is [string]) {
        $t = $Value.Trim().ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($t)) { return $false }
        return ($t -in @('true', '1', 'yes', 'y', 'evet'))
    }

    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) {
        return ([double]$Value -ne 0)
    }

    return $true
}

function Should-KeepWarningNote {
    param(
        [hashtable]$Payload,
        [string]$WarningText
    )

    if ([string]::IsNullOrWhiteSpace($WarningText)) { return $false }
    if (-not (Is-CrossLayerWarningText -Text $WarningText)) { return $true }

    $status = [string](Get-ResultField -Result $Payload -FieldName 'status' -DefaultValue '')
    $manualRequiredRaw = Get-ResultField -Result $Payload -FieldName 'manual_required' -DefaultValue $false
    $manualRequired = ConvertTo-BoolSafe -Value $manualRequiredRaw

    if ($status -eq 'UNKNOWN') { return $true }
    if ($manualRequired) { return $true }

    return $false
}

function Get-ImpactNarrative {
    param(
        [string]$TestName,
        [string]$CurrentImpact,
        [string]$Status,
        [string]$ExpectedValue,
        [string]$ObservedValue
    )

    $name = ([string]$TestName).ToLowerInvariant()
    $impact = [string]$CurrentImpact
    $isGeneric = [string]::IsNullOrWhiteSpace($impact) -or [regex]::IsMatch($impact, '(?i)^bu bulgu guvenlik durusunu olumsuz etkileyebilir\.?$|policies\s+file\s+bulunamazsa')

    $risk = 'When the setting is not enforced, the attack surface grows, the audit trail weakens, and a compliance gap can appear.'
    if ($name -match 'incognito|inprivate|private browsing') {
        $risk = 'If private browsing remains unrestricted, the audit trail shrinks and data exfiltration, shadow IT, and forensic investigation difficulties increase.'
    } elseif ($name -match 'password') {
        $risk = 'If browser password storage stays enabled, credentials can be harvested quickly after endpoint compromise, increasing the risk of account takeover.'
    } elseif ($name -match 'extension|eklenti') {
        $risk = 'Unauthorized extensions can be used to steal tokens and cookies, manipulate page content, and exfiltrate data.'
    } elseif ($name -match 'developer|devtools') {
        $risk = 'Without DevTools restrictions, client-side controls can be bypassed, script injection becomes easier, and tampering with secure workflows increases.'
    } elseif ($name -match 'safe browsing|security bypass') {
        $risk = 'If malicious site and download warnings are weakened, phishing, malware, and drive-by download incidents can increase.'
    } elseif ($name -match 'sync|account|firefox accounts') {
        $risk = 'If synchronization remains enabled, bookmarks, history, and sometimes credentials can be moved to clouds outside the organization, causing data classification violations.'
    } elseif ($name -match 'dns|doh') {
        $risk = 'If DNS queries are unprotected, traffic visibility can be lost and manipulated DNS responses can redirect users to fraudulent destinations.'
    } elseif ($name -match 'download') {
        $risk = 'If download restrictions are weak, users can execute unsigned or risky files, increasing the likelihood of ransomware and trojan infections.'
    } elseif ($name -match 'proxy') {
        $risk = 'Without enforced proxy controls, traffic can bypass security layers, and DLP, URL filtering, and centralized logging may be weakened.'
    } elseif ($name -match 'telemetry|form history|autofill|cookie') {
        $risk = 'If browser data collection and retention controls are weak, sensitive data residue increases and privacy and data protection compliance risk arises.'
    }

    $statePrefix = if ([string]$Status -eq 'PASSED') { 'The control is currently in the expected state. ' } else { 'The control is not in the expected state. ' }
    $expectedClean = ([string]$ExpectedValue).Trim().TrimEnd('.')
    $observedClean = ([string]$ObservedValue).Trim().TrimEnd('.')
    $expectedNote = if (-not [string]::IsNullOrWhiteSpace($expectedClean)) { " Expected state: $expectedClean." } else { '' }
    $observedNote = if (-not [string]::IsNullOrWhiteSpace($observedClean)) { " Observed state: $observedClean." } else { '' }

    if ($isGeneric) {
        return "$statePrefix$risk$expectedNote$observedNote".Trim()
    }

    if ($impact -notmatch '(?i)olasi|risk|etki|saldiri|uyumluluk|veri') {
        return "$($impact.Trim()) Potential impact: $risk$expectedNote$observedNote".Trim()
    }

    return "$($impact.Trim())$expectedNote$observedNote".Trim()
}

function Get-IncidentScenarioNarrative {
    param(
        [string]$TestName,
        [string]$Status,
        [string]$ExpectedValue,
        [string]$ObservedValue
    )

    $name = ([string]$TestName).ToLowerInvariant()
    $title = if ([string]::IsNullOrWhiteSpace([string]$TestName)) { 'This control' } else { [string]$TestName }
    $isPassed = [string]$Status -eq 'PASSED'
    $expected = ([string]$ExpectedValue).Trim().TrimEnd('.')
    $observed = ([string]$ObservedValue).Trim().TrimEnd('.')

    $vector = 'Browser security configuration weakness'
    $techImpact = 'parts of client-side security barriers can be indirectly bypassed'
    $businessImpact = 'account security, data privacy, and audit compliance can be put at risk'

    if ($name -match 'incognito|inprivate|private browsing') {
        $vector = 'untracked private session usage'
        $techImpact = 'the audit trail and URL/session visibility shrink, weakening incident investigation evidence'
        $businessImpact = 'root cause analysis is delayed in inappropriate data access or policy violation incidents'
    } elseif ($name -match 'password|autocomplete') {
        $vector = 'abuse of credentials stored in the browser'
        $techImpact = 'saved password and autofill data can be collected after an endpoint compromise'
        $businessImpact = 'the risk of account takeover, privileged access, and unauthorized actions on critical systems increases'
    } elseif ($name -match 'extension|add-on|store') {
        $vector = 'unauthorized extension installation chain'
        $techImpact = 'extension permissions can read cookie, DOM, and form data and send it to external destinations'
        $businessImpact = 'data leakage and supply-chain-driven security incidents may occur'
    } elseif ($name -match 'developer|devtools|debug|about:config|developer edition') {
        $vector = 'abuse of debug and privileged developer features'
        $techImpact = 'client-side controls can be manipulated to neutralize protective mechanisms'
        $businessImpact = 'the likelihood of a breach increases in insider threat and red-team style attack scenarios'
    } elseif ($name -match 'safe browsing|smartscreen|phishing|security warning') {
        $vector = 'redirection to malicious destinations and phishing'
        $techImpact = 'threat reputation warnings weaken, so malware and phishing detection can be delayed'
        $businessImpact = 'user credentials and corporate accounts can be targeted'
    } elseif ($name -match 'sync|accounts?|browser sign-in|implicit sign-in|profile separation') {
        $vector = 'cloud synchronization outside the organization'
        $techImpact = 'history, bookmark, session, and profile data can be moved to unmanaged environments'
        $businessImpact = 'data sovereignty, privacy regulation compliance, and audit finding risk increase'
    } elseif ($name -match 'dns|doh|webrtc|local ip') {
        $vector = 'name and egress traffic manipulation and network metadata leakage'
        $techImpact = 'users can be redirected to fraudulent destinations or local network information can be exposed'
        $businessImpact = 'phishing success rates may increase while network-level visibility decreases'
    } elseif ($name -match 'download|file type|prompt') {
        $vector = 'uncontrolled file download and execution'
        $techImpact = 'malware delivery through unsigned or risky files becomes easier'
        $businessImpact = 'business continuity interruption and ransomware-driven financial loss may occur'
    } elseif ($name -match 'proxy|ssl|https-only|tls|certificate|ocsp|crl|pinning|hsts|mixed content|quic') {
        $vector = 'weak traffic security and certificate validation'
        $techImpact = 'MITM-style attacks become more likely to succeed and secure channel guarantees weaken'
        $businessImpact = 'confidentiality and integrity risk rises during sensitive data transfer'
    } elseif ($name -match 'cookie|third-party storage|site isolation|renderer|sandbox|referrer|protocol handler') {
        $vector = 'weakening of session and browser isolation controls'
        $techImpact = 'session tracking, cookie abuse, or cross-site impact scope can grow'
        $businessImpact = 'account abuse and user privacy violations can increase'
    } elseif ($name -match 'telemetry|metrics|feedback|crash|domain reliability|usage') {
        $vector = 'unmanaged diagnostic and data sharing channels'
        $techImpact = 'client behaviour and metric data can be transferred to external services'
        $businessImpact = 'non-compliance with data minimization and regulatory expectations may arise'
    }

    $statePrefix = if ($isPassed) { 'Status: The control is currently active and compliant with the expected policy.' } else { 'Status: The control is not at the expected hardening level.' }
    $expectedNote = if (-not [string]::IsNullOrWhiteSpace($expected)) { " Expected: $expected." } else { '' }
    $observedNote = if (-not [string]::IsNullOrWhiteSpace($observed)) { " Observed: $observed." } else { '' }

    return "$statePrefix Incident Scenario ($title): A threat actor can progress through $vector. Technical Impact: $techImpact. Business Impact: $businessImpact.$expectedNote$observedNote".Trim()
}

function Get-ControlDisplayName {
    param(
        [string]$PolicyKey,
        [hashtable]$Definition
    )

    if (-not [string]::IsNullOrWhiteSpace($PolicyKey)) {
        $name = $PolicyKey -replace '[._-]+', ' '
        $name = $name -creplace '([A-Z]+)([A-Z][a-z])', '$1 $2'
        $name = $name -creplace '([a-z0-9])([A-Z])', '$1 $2'
        return $name.Trim()
    }

    $name = ([string]$Definition.raw_line) -replace '^\S+\s+', ''
    $name = $name -replace '^\(L\d+\)\s+', ''
    $name = $name -replace '(?i)^Ensure\s+', ''
    $name = $name -replace "(?i)\s+is set to\s+'[^']+'\s*$", ''
    return $name.Trim()
}

# ---------------------------------------------------------------------------
# Windows browser discovery
# ---------------------------------------------------------------------------

function Get-ExecutableVersion {
    param(
        [string]$BrowserExecutableName,
        [string[]]$Candidates,
        [string[]]$LocalAppDataFallback = @()
    )

    $candidatePool = @($Candidates + $LocalAppDataFallback)
    try {
        $cmd = Get-Command $BrowserExecutableName -ErrorAction SilentlyContinue
        if ($null -ne $cmd -and -not [string]::IsNullOrWhiteSpace([string]$cmd.Source)) {
            $candidatePool += [string]$cmd.Source
        }
    } catch {
        Write-Verbose "PATH lookup failed for '$BrowserExecutableName': $($_.Exception.Message)"
    }

    $appPathKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$BrowserExecutableName",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\$BrowserExecutableName",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$BrowserExecutableName"
    )
    foreach ($k in $appPathKeys) {
        try {
            if (Test-Path $k) {
                $v = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).'(default)'
                if (-not [string]::IsNullOrWhiteSpace([string]$v)) {
                    $candidatePool += [string]$v
                }
            }
        } catch {
            Write-Verbose "App Paths lookup failed for '$k': $($_.Exception.Message)"
        }
    }

    $candidatePool = @($candidatePool | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
    foreach ($candidate in $candidatePool) {
        if (-not (Test-Path $candidate)) {
            continue
        }
        try {
            $vi = (Get-Item $candidate).VersionInfo
            $version = [string]$vi.ProductVersion
            if ([string]::IsNullOrWhiteSpace($version)) {
                $version = [string]$vi.FileVersion
            }
            if (-not [string]::IsNullOrWhiteSpace($version)) {
                return $version
            }
        } catch {
            Write-Verbose "Version read failed for '$candidate': $($_.Exception.Message)"
        }
    }

    return "NOT_FOUND"
}

function Get-BrowserExecutablePath {
    param(
        [string]$BrowserExecutableName,
        [string[]]$Candidates,
        [string[]]$LocalAppDataFallback = @()
    )

    $allCandidates = @($Candidates + $LocalAppDataFallback)

    try {
        $cmd = Get-Command $BrowserExecutableName -ErrorAction SilentlyContinue
        if ($null -ne $cmd -and -not [string]::IsNullOrWhiteSpace([string]$cmd.Source)) {
            $allCandidates += [string]$cmd.Source
        }
    } catch {
        Write-Verbose "PATH lookup failed for '$BrowserExecutableName': $($_.Exception.Message)"
    }

    $appPathKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$BrowserExecutableName",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\$BrowserExecutableName",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$BrowserExecutableName"
    )
    foreach ($k in $appPathKeys) {
        try {
            if (Test-Path $k) {
                $v = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).'(default)'
                if (-not [string]::IsNullOrWhiteSpace([string]$v)) {
                    $allCandidates += [string]$v
                }
            }
        } catch {
            Write-Verbose "App Paths lookup failed for '$k': $($_.Exception.Message)"
        }
    }

    $allCandidates = @($allCandidates | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
    foreach ($candidate in $allCandidates) {
        if (Test-Path $candidate) { return $candidate }
    }
    return ""
}

function Get-EnvironmentInfo {
    return @{
        hostname = $env:COMPUTERNAME
        browser_versions = @{
            edge = Get-ExecutableVersion -BrowserExecutableName "msedge.exe" -Candidates @("$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe", "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe") -LocalAppDataFallback @("$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe")
            chrome = Get-ExecutableVersion -BrowserExecutableName "chrome.exe" -Candidates @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe") -LocalAppDataFallback @("$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe")
            firefox = Get-ExecutableVersion -BrowserExecutableName "firefox.exe" -Candidates @("$env:ProgramFiles\Mozilla Firefox\firefox.exe", "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") -LocalAppDataFallback @("$env:LOCALAPPDATA\Mozilla Firefox\firefox.exe")
        }
    }
}

# ---------------------------------------------------------------------------
# macOS evidence helpers
# ---------------------------------------------------------------------------

function ConvertTo-MacDisplayValue {
    param([object]$Value)

    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [array]) {
        return (@($Value | ForEach-Object { ConvertTo-MacDisplayValue -Value $_ }) -join ',')
    }
    if ($Value -is [pscustomobject] -or $Value -is [hashtable]) {
        try { return ($Value | ConvertTo-Json -Depth 8 -Compress) } catch { return [string]$Value }
    }
    return [string]$Value
}
