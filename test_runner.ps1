# Browser Security Test Runner - Modular Design
# Each test is defined as a separate function; a single test can be executed via parameter

param(
    [string]$TestId = "ALL",
    [switch]$OutputJSON = $false,
    [string]$OutputFile = ""
)

$script:TestResults = @()
$script:RunId = Get-Date -Format "yyyyMMdd_HHmmss"
$script:ArtifactsRoot = Join-Path $PSScriptRoot "artifacts"
$script:ArtifactsRunDir = ""

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

    $relativePath = "artifacts/$($script:RunId)/$safeTestId/$safeName.json"
    return $relativePath
}

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
    } catch {}

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
        } catch {}
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
        } catch {}
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
    } catch {}

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
        } catch {}
    }

    $allCandidates = @($allCandidates | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
    foreach ($candidate in $allCandidates) {
        if (Test-Path $candidate) { return $candidate }
    }
    return ""
}

function Get-EdgePolicyValue {
    param([string]$KeyName)

    $paths = @(
        "HKCU:\Software\Policies\Microsoft\Edge",
        "HKLM:\Software\Policies\Microsoft\Edge",
        "HKLM:\Software\WOW6432Node\Policies\Microsoft\Edge"
    )

    foreach ($path in $paths) {
        try {
            if (Test-Path $path) {
                $val = (Get-ItemProperty -Path $path -Name $KeyName -ErrorAction SilentlyContinue).$KeyName
                if ($null -ne $val) {
                    return @{ found = $true; value = $val; source = $path }
                }
            }
        } catch {}
    }

    return @{ found = $false; value = $null; source = "" }
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

    if (-not [string]::IsNullOrWhiteSpace($TestName) -and $cleaned.ToLower() -eq $TestName.ToLower()) {
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
        $t = $Value.Trim().ToLower()
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

    $risk = 'When the setting is not enforced, the attack surface grows, the audit trail weakens, and a compliance gap can emerge.'
    if ($name -match 'incognito|inprivate|private browsing') {
        $risk = 'If private browsing stays unrestricted, the audit trail is reduced and data exfiltration, shadow IT, and forensic investigation difficulties increase.'
    } elseif ($name -match 'password') {
        $risk = 'If password saving in the browser stays enabled, credentials can be harvested quickly after an endpoint compromise and the account takeover risk increases.'
    } elseif ($name -match 'extension|eklenti') {
        $risk = 'Unauthorized extensions can be used to steal tokens and cookies, manipulate page content, and exfiltrate data.'
    } elseif ($name -match 'developer|devtools') {
        $risk = 'Without DevTools restrictions, client-side controls can be bypassed, script injection becomes easier, and interference with secure business workflows increases.'
    } elseif ($name -match 'safe browsing|security bypass') {
        $risk = 'If malicious site and download warnings are weakened, phishing, malware, and drive-by download incidents can increase.'
    } elseif ($name -match 'sync|account|firefox accounts') {
        $risk = 'If synchronization stays enabled, bookmarks, history, and sometimes credentials can be moved to clouds outside the organization, which can create a data classification violation.'
    } elseif ($name -match 'dns|doh') {
        $risk = 'If DNS queries are not protected, traffic visibility can be lost and manipulated DNS responses can redirect users to fraudulent destinations.'
    } elseif ($name -match 'download') {
        $risk = 'If download restrictions are weak, users can execute unsigned or risky files and the likelihood of ransomware and trojan infection increases.'
    } elseif ($name -match 'proxy') {
        $risk = 'Without enforced proxy controls, traffic can bypass security layers, and DLP, URL filtering, and centralized logging may be weakened.'
    } elseif ($name -match 'telemetry|form history|autofill|cookie') {
        $risk = 'If browser data collection and retention controls are weak, sensitive data residue increases and privacy and data protection compliance risk emerges.'
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

function Normalize-ReportPayload {
    param([hashtable]$Payload)

    $testName = [string]$Payload.test_name
    $currentFinding = Get-FirstMeaningfulText -Candidates @($Payload.details) -TestName $testName
    if ([string]::IsNullOrWhiteSpace($currentFinding)) { $currentFinding = 'The detected state could not be reported clearly.' }

    $findingDetails = Get-FirstMeaningfulText -Candidates @(
        $Payload.finding_details,
        $Payload.manual_check_expected,
        $Payload.details,
        $Payload.test_name
    ) -TestName $testName
    if ([string]::IsNullOrWhiteSpace($findingDetails)) { $findingDetails = $currentFinding }
    if ($findingDetails.ToLower() -eq $currentFinding.ToLower()) {
        $findingDetails = Get-FirstMeaningfulText -Candidates @($Payload.manual_check_expected, $Payload.test_name) -TestName $testName
        if ([string]::IsNullOrWhiteSpace($findingDetails)) { $findingDetails = $currentFinding }
    }

    $remediationText = "Apply the required enterprise policy for '$testName', confirm that the intended secure value is enforced, and rerun the assessment."

    $Payload.details = Sanitize-ReportText -Value $Payload.details -TestName $testName
    $sanitizedObserved = Sanitize-ReportText -Value $Payload.observed_value -TestName $testName
    $sanitizedEvidence = Get-FirstMeaningfulText -Candidates @(
        $Payload.evidence_output,
        $Payload.details
    ) -TestName $testName

    $Payload.evidence_output = $sanitizedEvidence
    if (-not (Is-NaLikeText $sanitizedObserved) -and -not (Is-NaLikeText $sanitizedEvidence) -and $sanitizedObserved.Trim().ToLowerInvariant() -eq $sanitizedEvidence.Trim().ToLowerInvariant()) {
        $Payload.observed_value = ''
    } else {
        $Payload.observed_value = $sanitizedObserved
    }

    $Payload.finding_details = $findingDetails
    # test_method and rationale are metadata fields, not report text; skip Sanitize to preserve enriched values
    # $Payload.test_method = Sanitize-ReportText -Value $Payload.test_method -TestName $testName
    # $Payload.rationale = Sanitize-ReportText -Value $Payload.rationale -TestName $testName
    if ($Payload.ContainsKey('impact')) {
        $Payload.Remove('impact')
    }
    if ($Payload.ContainsKey('message')) {
        $Payload.Remove('message')
    }
    $Payload.incident_scenario = Get-IncidentScenarioNarrative -TestName $testName -Status ([string]$Payload.status) -ExpectedValue ([string]$Payload.expected_value) -ObservedValue ([string]$Payload.observed_value)
    $Payload.remediation = $remediationText
    $sanitizedWarning = Sanitize-ReportText -Value $Payload.warning_note -TestName $testName
    if (Should-KeepWarningNote -Payload $Payload -WarningText $sanitizedWarning) {
        $Payload.warning_note = $sanitizedWarning
    } else {
        $Payload.warning_note = ''
    }
    return $Payload
}

function Get-ResultField {
    param(
        [object]$Result,
        [string]$FieldName,
        [object]$DefaultValue = ""
    )

    if ($null -eq $Result) { return $DefaultValue }

    if ($Result -is [hashtable]) {
        if ($Result.ContainsKey($FieldName)) {
            return $Result[$FieldName]
        }
        return $DefaultValue
    }

    $prop = $Result.PSObject.Properties[$FieldName]
    if ($null -ne $prop) {
        return $prop.Value
    }

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
        evidence_type = (Get-ResultField -Result $Payload -FieldName 'evidence_type' -DefaultValue '')
        details = (Get-ResultField -Result $Payload -FieldName 'details' -DefaultValue '')
        status_reason = (Get-ResultField -Result $Payload -FieldName 'status_reason' -DefaultValue '')
        evidence_output = (Get-ResultField -Result $Payload -FieldName 'evidence_output' -DefaultValue '')
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

function Get-EdgeManualCheckGuidance {
    param(
        [string]$TestId,
        [hashtable]$TestConfig,
        [hashtable]$Result
    )

    $name = [string]$TestConfig.Name
    $status = [string]$Result.status

    $check = "Edge policy ve davranis kontrolunu birlikte dogrulayin."
    $steps = @(
        "edge://policy sayfasini acin ve ilgili policy anahtarinin degerini kontrol edin.",
        "Testin hedefledigi davranisi tarayici arayuzunden manuel deneyin.",
        "Davranis policy degeri ile tutarliysa sonucu PASS; degilse FAIL olarak kaydedin."
    )
    $command = "Start-Process msedge.exe 'edge://policy'"
    $expected = "Policy degeri ve tarayici davranisi birbiriyle tutarli olmali."

    if ($name -match 'InPrivate|Private') {
        $check = "InPrivate kisitini hem policy ekranindan hem davranissal olarak dogrulayin."
        $steps = @(
            "edge://policy ekraninda InPrivateModeAvailability degerini kontrol edin.",
            "Tarayicida Ctrl+Shift+N ile InPrivate pencere acmayi deneyin.",
            "Acilmiyorsa veya kurumsal yonetim engeli goruluyorsa kontrolu PASS olarak not edin."
        )
        $expected = "InPrivate acilamiyor veya policy gereksinimine uygun kisitli modda calisiyor olmali."
    } elseif ($name -match 'Extension') {
        $check = "Eklenti kurulum kontrolunu policy + magaza davranisi ile dogrulayin."
        $steps = @(
            "edge://policy sayfasinda Extension* policy anahtarlarini kontrol edin.",
            "Edge Add-ons veya Chrome Web Store uzerinden test eklentisi kurmayi deneyin.",
            "Kurulum engelleniyorsa ve kurum yonetimi bildirimi goruluyorsa kontrolu PASS olarak isaretleyin."
        )
        $expected = "Yetkisiz eklenti kurulumu engellenmeli; izinli eklentiler kurum politikasina uygun olmali."
    } elseif ($name -match 'Password') {
        $check = "Parola yoneticisi kisitini policy ve ayarlar ekraninda dogrulayin."
        $steps = @(
            "edge://policy uzerinden PasswordManagerEnabled degerini kontrol edin.",
            "Edge Ayarlar > Profiller > Parolalar ekranina gidin.",
            "Parola kaydetme secenegi devre disi ise PASS olarak not edin."
        )
        $expected = "Parola kaydetme ozelligi kurum politikasina gore devre disi veya kisitli olmali."
    } elseif ($name -match 'Developer|DevTools') {
        $check = "Developer Tools kisitini policy ve klavye kisayolu ile dogrulayin."
        $steps = @(
            "edge://policy ekraninda DeveloperToolsAvailability degerini kontrol edin.",
            "F12 veya Ctrl+Shift+I ile DevTools acmayi deneyin.",
            "Acilmiyorsa veya policy nedeniyle engelleniyorsa PASS olarak not edin."
        )
        $expected = "DevTools kurum politikasina uygun olarak engelli veya kisitli olmali."
    } elseif ($name -match 'Download') {
        $check = "Indirme kontrolunu policy ve gercek dosya indirme denemesi ile dogrulayin."
        $steps = @(
            "edge://policy ekraninda PromptForDownloadLocation veya DownloadRestrictions degerlerini kontrol edin.",
            "Guvenli bir test dosyasi indirerek tarayici davranisini gozlemleyin.",
            "Beklenen kisit/prompt davranisi varsa PASS, yoksa FAIL olarak not edin."
        )
        $expected = "Indirme akisinda kurum politikasi ile uyumlu kisit veya onay davranisi gorulmeli."
    } elseif ($name -match 'Sync') {
        $check = "Senkronizasyon kisitini policy ve hesap/sync ekranindan dogrulayin."
        $steps = @(
            "edge://policy ekraninda SyncDisabled veya ilgili signin policy degerlerini kontrol edin.",
            "Edge profile/sync ekraninda senkronizasyon ac/kapat durumunu inceleyin.",
            "Kurumsal beklentiye aykiri sync acikligi yoksa PASS olarak not edin."
        )
        $expected = "Senkronizasyon kurumsal guvenlik gereksinimine uygun olmalÄ±."
    }

    $note = if ($status -eq 'UNKNOWN') {
        "! Otomatik test kesin karar veremedi. Bu kontrol manuel dogrulama ile kapanmali. Gerekirse GPO/Intune ve ag katmani loglarini birlikte inceleyin."
    } else {
        "Otomatik bulgu mevcut; manuel kontrol bu bulguyu ikinci kanit olarak dogrular."
    }

    return @{
        manual_check = $check
        manual_check_steps = $steps
        manual_check_command = $command
        manual_check_expected = $expected
        manual_check_note = $note
    }
}

# ==================== TEST FUNCTIONS ====================

function Test-InPrivateMode {
    $regKey = "InPrivateModeAvailability"
    $paths = @(
        "HKCU:\Software\Policies\Microsoft\Edge",
        "HKLM:\Software\Policies\Microsoft\Edge",
        "HKLM:\Software\WOW6432Node\Policies\Microsoft\Edge"
    )
    
    try {
        foreach ($path in $paths) {
            if (Test-Path $path) {
                $value = (Get-ItemProperty -Path $path -Name $regKey -ErrorAction SilentlyContinue).$regKey
                if ($null -ne $value) {
                    $asInt = [int]$value
                    $passed = ($asInt -eq 1 -or $asInt -eq 2)
                    $modeText = switch ($asInt) {
                        0 { "ENABLED" }
                        1 { "DISABLED" }
                        2 { "FORCED" }
                        default { "UNKNOWN($asInt)" }
                    }
                    return @{
                        status = if ($passed) { "PASSED" } else { "FAILED" }
                        message = "InPrivate: $modeText"
                        details = "Policy source: $path\\$regKey = $asInt"
                        expected_value = "InPrivateModeAvailability degeri 1 (Disabled) veya 2 (Forced) olmali"
                        observed_value = "$regKey=$asInt ($modeText) @ $path"
                        evidence_type = "registry_policy"
                        confidence = "HIGH"
                        status_reason = if ($passed) { "expected_policy_value_found" } else { "policy_value_not_hardened" }
                        manual_required = $false
                        finding_details = "InPrivate denetimi birden fazla policy dalinda arandi. Deger 1 (disabled) veya 2 (forced) oldugunda kontrol uyumlu kabul edilir."
                        test_method = "Multi-path registry check (HKCU/HKLM/WOW6432Node) + policy value evaluation (0/1/2)."
                        rationale = "Kurumsal ortamlarda InPrivate kisiti farkli policy kapsamlarindan dagitilabilir."
                        impact = if ($passed) { "InPrivate oturumu kurumsal politika ile sinirlandirilmis gorunuyor." } else { "InPrivate aciksa denetim izi ve veri cikisi kontrolleri zayiflayabilir." }
                        remediation = "InPrivateModeAvailability degerini 1 (disabled) veya politika gereksinimine gore 2 (forced) olarak tanimlayin."
                        reference = "https://learn.microsoft.com/deployedge/microsoft-edge-policies#inprivatemodeavailability"
                    }
                }
            }
        }

        return @{
            status = "UNKNOWN"
            message = "InPrivate: Local policy key not found"
            details = "InPrivateModeAvailability key not found in HKCU/HKLM/WOW6432Node"
            expected_value = "InPrivateModeAvailability degeri 1 (Disabled) veya 2 (Forced) olmali"
            observed_value = "HKCU/HKLM/WOW6432Node taramasinda InPrivateModeAvailability anahtari bulunamadi"
            evidence_type = "registry_policy_scan"
            confidence = "MEDIUM"
            status_reason = "local_policy_not_found"
            manual_required = $true
            finding_details = "! Bu endpointte local registry policy anahtari gorunmuyor. Kontrol Intune bulut politikasi, guvenlik ajanlari veya baska zorlayici katmanlarla uygulanmis olabilir."
            test_method = "Multi-path registry check + external enforcement ambiguity handling."
            rationale = "Sadece tek registry kaynagina bakmak false positive sonuc uretebilir."
            impact = "Davranissal olarak kisit aktif olsa bile local policy gorunmediginde kesin PASS/FAIL karari verilemez."
            remediation = "Kurumsal policy dagitim kaynagini (GPO/Intune) dogrulayin ve mumkunse endpointte policy izini gorunur hale getirin."
            reference = "https://learn.microsoft.com/deployedge/microsoft-edge-policies#inprivatemodeavailability"
        }
    } catch {
        return @{
            status = "UNKNOWN"
            message = "InPrivate: Error checking policy"
            details = "Error: $($_.Exception.Message)"
            expected_value = "InPrivateModeAvailability degeri 1 (Disabled) veya 2 (Forced) olmali"
            observed_value = "Policy kontrolu teknik hata nedeniyle tamamlanamadi"
            evidence_type = "tool_runtime_error"
            confidence = "LOW"
            status_reason = "tooling_error"
            manual_required = $true
        }
    }
}

function Test-ExtensionPolicy {
    $keys = @("ExtensionAllowList", "ExtensionBlockList", "ExtensionInstallAllowlist", "ExtensionInstallBlocklist", "ExtensionSettings")
    $found = @()

    try {
        foreach ($k in $keys) {
            $r = Get-EdgePolicyValue -KeyName $k
            if ($r.found) {
                $found += "$k@$($r.source)"
            }
        }

        if ($found.Count -gt 0) {
            return @{ status = "PASSED"; message = "Extension governance configured"; details = "Found keys: $($found -join ', ')" }
        }

        return @{
            status = "FAILED"
            message = "Extension policy key not found locally"
            details = "No extension governance policy in HKCU/HKLM/WOW6432Node"
            finding_details = "! Extension kisiti ag/proxy/SSE katmaninda uygulanmis olabilir; endpoint policy izi gorunmeyebilir."
            test_method = "Multi-path registry key discovery with external-enforcement awareness."
            rationale = "Tek bir registry dalina bagli testler false positive uretebilir."
            impact = "Davranissal blok aktif olsa bile local policy kaniti eksik kalabilir."
            remediation = "Policy dagitim kaynagini ve ag katmani kisitlarini birlikte dogrulayin."
            reference = "https://learn.microsoft.com/deployedge/microsoft-edge-policies#extensioninstallblocklist"
            warning_note = "Bu kontrol baska bir guvenlik katmaninda (proxy/SSE/CASB) uygulanmis olabilir."
        }
    } catch {
        return @{ status = "UNKNOWN"; message = "Extension: Error checking policy"; details = "Error: $($_.Exception.Message)"; warning_note = "Teknik hata nedeniyle kesin karar verilemedi." }
    }
}

function Test-PasswordManager {
    $r = Get-EdgePolicyValue -KeyName "PasswordManagerEnabled"
    try {
        if (-not $r.found) {
            $prefPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Preferences"
            if (Test-Path $prefPath) {
                try {
                    $prefs = Get-Content $prefPath -Raw | ConvertFrom-Json -ErrorAction Stop
                    $pm = $prefs.profile.password_manager_enabled
                    $credSvc = $prefs.credentials_enable_service
                    if ($pm -eq $false -and $credSvc -eq $false) {
                        return @{
                            status = "PASSED"
                            message = "Password Manager: DISABLED (prefs)"
                            details = "$prefPath => password_manager_enabled=false, credentials_enable_service=false"
                            expected_value = "PasswordManagerEnabled=0 veya prefs alanlarinda password_manager_enabled=false ve credentials_enable_service=false"
                            observed_value = "prefs: password_manager_enabled=false, credentials_enable_service=false"
                            evidence_type = "preferences_file"
                            confidence = "MEDIUM"
                            status_reason = "prefs_values_hardened"
                            manual_required = $false
                            warning_note = "Policy key gorunmese de davranissal/prefs kaniti mevcut."
                        }
                    }
                    return @{
                        status = "FAILED"
                        message = "Password Manager: ENABLED (prefs/default)"
                        details = "$prefPath => password_manager_enabled=$pm, credentials_enable_service=$credSvc"
                        expected_value = "PasswordManagerEnabled=0 veya prefs alanlarinda password_manager_enabled=false ve credentials_enable_service=false"
                        observed_value = "prefs: password_manager_enabled=$pm, credentials_enable_service=$credSvc"
                        evidence_type = "preferences_file"
                        confidence = "MEDIUM"
                        status_reason = "prefs_values_not_hardened"
                        manual_required = $true
                        warning_note = "Politika baska katmanda uygulanmis olabilir ancak yerel davranis su an guvenli degil."
                    }
                } catch {
                    return @{
                        status = "FAILED"
                        message = "Password Manager: Policy NOT SET"
                        details = "PasswordManagerEnabled key missing and Preferences parse failed"
                        expected_value = "PasswordManagerEnabled=0 veya prefs alanlarinda koruyucu degerler gorunmeli"
                        observed_value = "Policy key yok, prefs dosyasi okunamadi"
                        evidence_type = "registry_plus_prefs_fallback"
                        confidence = "LOW"
                        status_reason = "policy_missing_and_prefs_unreadable"
                        manual_required = $true
                        warning_note = "Baska katman enforcement olabilir; manuel davranissal dogrulama gerekir."
                    }
                }
            }
            return @{
                status = "FAILED"
                message = "Password Manager: Policy NOT SET"
                details = "PasswordManagerEnabled not found in HKCU/HKLM/WOW6432Node and Preferences missing"
                expected_value = "PasswordManagerEnabled=0 veya prefs alanlarinda koruyucu degerler gorunmeli"
                observed_value = "Policy key yok, Preferences dosyasi bulunamadi"
                evidence_type = "registry_policy_scan"
                confidence = "LOW"
                status_reason = "policy_missing_and_prefs_missing"
                manual_required = $true
                warning_note = "Baska katman enforcement olabilir; manuel davranissal dogrulama gerekir."
            }
        }
        $value = $r.value
        $passed = ($value -eq 0)  # 0 = disabled
        return @{
            status = if ($passed) { "PASSED" } else { "FAILED" }
            message = "Password Manager: $(if ($passed) { 'DISABLED' } else { 'ENABLED' })"
            details = "Registry: $($r.source)\PasswordManagerEnabled = $value"
            expected_value = "PasswordManagerEnabled registry degeri 0 olmali"
            observed_value = "PasswordManagerEnabled=$value @ $($r.source)"
            evidence_type = "registry_policy"
            confidence = "HIGH"
            status_reason = if ($passed) { "expected_policy_value_found" } else { "policy_value_not_hardened" }
            manual_required = $false
        }
    } catch {
        return @{
            status = "UNKNOWN"
            message = "Password Manager: Error checking policy"
            details = "Error: $($_.Exception.Message)"
            expected_value = "PasswordManagerEnabled=0 veya prefs alanlarinda koruyucu degerler gorunmeli"
            observed_value = "Kontrol teknik hata nedeniyle tamamlanamadi"
            evidence_type = "tool_runtime_error"
            confidence = "LOW"
            status_reason = "tooling_error"
            manual_required = $true
            warning_note = "Teknik hata nedeniyle kesin karar verilemedi."
        }
    }
}

function Test-DeveloperTools {
    $r = Get-EdgePolicyValue -KeyName "DeveloperToolsAvailability"
    try {
        if (-not $r.found) {
            $cmds = @()
            try { $cmds = @((Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -ErrorAction SilentlyContinue | ForEach-Object { $_.CommandLine })) } catch {}
            $riskyFlags = @('--auto-open-devtools-for-tabs', '--remote-debugging-port')
            $hits = @()
            foreach ($cmd in $cmds) {
                foreach ($flag in $riskyFlags) {
                    if ($cmd -match [regex]::Escape($flag)) { $hits += $flag }
                }
            }
            $hits = $hits | Select-Object -Unique
            if ($hits.Count -gt 0) {
                return @{
                    status = "FAILED"
                    message = "DevTools: Runtime evidence indicates ENABLED"
                    details = "Risky flags detected: $($hits -join ', ')"
                    expected_value = "DeveloperToolsAvailability=2 veya runtime'da riskli debug flagleri olmamali"
                    observed_value = "Riskli flagler: $($hits -join ', ')"
                    evidence_type = "runtime_process_flags"
                    confidence = "HIGH"
                    status_reason = "risky_runtime_flags_detected"
                    manual_required = $true
                    warning_note = "Policy key yok; runtime kanitina gore DevTools erisimi acik gorunuyor."
                }
            }
            return @{
                status = "FAILED"
                message = "DevTools: Policy NOT SET"
                details = "DeveloperToolsAvailability not found in HKCU/HKLM/WOW6432Node"
                expected_value = "DeveloperToolsAvailability=2 olmali"
                observed_value = "HKCU/HKLM/WOW6432Node taramasinda policy anahtari bulunamadi"
                evidence_type = "registry_policy_scan"
                confidence = "MEDIUM"
                status_reason = "policy_not_found"
                manual_required = $true
                warning_note = "Baska katman enforcement olabilir; manuel F12/Ctrl+Shift+I davranis testi ile dogrulayin."
            }
        }
        $value = $r.value
        $passed = ($value -eq 2)  # 2 = disabled
        return @{
            status = if ($passed) { "PASSED" } else { "FAILED" }
            message = "DevTools: $(if ($passed) { 'DISABLED' } else { 'ENABLED' })"
            details = "Registry: $($r.source)\DeveloperToolsAvailability = $value"
            expected_value = "DeveloperToolsAvailability registry degeri 2 olmali"
            observed_value = "DeveloperToolsAvailability=$value @ $($r.source)"
            evidence_type = "registry_policy"
            confidence = "HIGH"
            status_reason = if ($passed) { "expected_policy_value_found" } else { "policy_value_not_hardened" }
            manual_required = $false
        }
    } catch {
        return @{
            status = "UNKNOWN"
            message = "DevTools: Error checking policy"
            details = "Error: $($_.Exception.Message)"
            expected_value = "DeveloperToolsAvailability=2 veya runtime'da riskli debug flagleri olmamali"
            observed_value = "Kontrol teknik hata nedeniyle tamamlanamadi"
            evidence_type = "tool_runtime_error"
            confidence = "LOW"
            status_reason = "tooling_error"
            manual_required = $true
            warning_note = "Teknik hata nedeniyle kesin karar verilemedi."
        }
    }
}

function Test-DownloadPolicy {
    $r = Get-EdgePolicyValue -KeyName "PromptForDownloadLocation"
    try {
        if (-not $r.found) {
            $r2 = Get-EdgePolicyValue -KeyName "DownloadRestrictions"
            if ($r2.found) {
                $v2 = [int]$r2.value
                $ok2 = ($v2 -ge 1)
                return @{ status = if ($ok2) { "PASSED" } else { "FAILED" }; message = if ($ok2) { "Download: Restrictions ACTIVE" } else { "Download: Restrictions WEAK" }; details = "Registry: $($r2.source)\DownloadRestrictions = $v2"; warning_note = "Prompt policy yok; karar DownloadRestrictions uzerinden verildi." }
            }
            return @{ status = "FAILED"; message = "Download: Policy NOT SET"; details = "PromptForDownloadLocation and DownloadRestrictions not found in HKCU/HKLM/WOW6432Node"; warning_note = "Baska katman enforcement olabilir; manuel guvenli dosya indirme testi yapin." }
        }
        $value = $r.value
        $passed = ($value -eq 1)  # 1 = prompt, 0 = silent
        return @{ status = if ($passed) { "PASSED" } else { "FAILED" }; message = "Download: No Control"; details = "Registry: $($r.source)\PromptForDownloadLocation = $value" }
    } catch {
        return @{ status = "UNKNOWN"; message = "Download: Error checking policy"; details = "Error: $($_.Exception.Message)"; warning_note = "Teknik hata nedeniyle kesin karar verilemedi." }
    }
}

function Test-MailExfiltration {
    $outlookPath = "$env:APPDATA\Microsoft\Outlook"
    $exists = Test-Path $outlookPath
    $details = if ($exists) { "Outlook profile: EXISTS" } else { "Outlook profile: MISSING" }
    return @{ status = "FAILED"; message = "Mail Exfiltration: RISK"; details = $details + " - Data exfiltration possible" }
}

function Test-AITools {
    $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
    $preferencesFile = "$edgePath\Preferences"
    if (Test-Path $preferencesFile) {
        $content = Get-Content $preferencesFile -Raw
        $details = if ($content -match "copilot") { "Copilot: ACTIVE" } else { "Copilot: ACTIVE (default)" }
    } else {
        $details = "Edge profile not found"
    }
    return @{ status = "FAILED"; message = "AI Tools: RISK"; details = $details + " - Prompt injection possible" }
}

function Test-CopyPaste {
    return @{ status = "FAILED"; message = "Copy-Paste: No Control"; details = "Browser: Clipboard access unrestricted" }
}

function Test-BrowserSync {
    $r = Get-EdgePolicyValue -KeyName "SyncDisabled"
    try {
        if ($r.found) {
            $value = $r.value
            $details = "$($r.source)\\SyncDisabled = $value"
            if ($value -eq 1 -or $value -eq $true) {
                return @{ status = "PASSED"; message = "Browser Sync: DISABLED"; details = $details }
            }
            return @{ status = "FAILED"; message = "Browser Sync: ENABLED"; details = $details }
        }
        $rSignin = Get-EdgePolicyValue -KeyName "BrowserSignin"
        if ($rSignin.found) {
            [int64]$signinVal = -1
            if ([int64]::TryParse([string]$rSignin.value, [ref]$signinVal) -and $signinVal -eq 0) {
                return @{ status = "PASSED"; message = "Browser Sync: Restricted via BrowserSignin"; details = "$($rSignin.source)\\BrowserSignin = $signinVal"; warning_note = "SyncDisabled anahtari yok; ikincil sinyal BrowserSignin kullanildi." }
            }
        }
        $details = "SyncDisabled not found in HKCU/HKLM/WOW6432Node"
    } catch {
        $details = "Error checking sync policy: $($_.Exception.Message)"
    }
    return @{ status = "FAILED"; message = "Browser Sync: Policy NOT SET"; details = $details; warning_note = "Baska katman enforcement olabilir; profil/sync ekraninda davranissal dogrulama yapin." }
}

function Test-DownloadBypass {
    $dlPath = "$env:USERPROFILE\Downloads"
    $dlCount = (Get-ChildItem $dlPath -ErrorAction SilentlyContinue | Measure-Object).Count
    return @{ status = "FAILED"; message = "Download Bypass: RISK"; details = "Downloaded files count: $dlCount - No control mechanism" }
}

function Test-M365Auth {
    $cacheFile = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
    $exists = Test-Path $cacheFile
    $details = if ($exists) { "Edge cache: EXISTS" } else { "Edge cache: MISSING" }
    return @{ status = "FAILED"; message = "M365 Auth: RISK"; details = $details + " - Token hijacking possible" }
}

function Test-ConditionalAccess {
    return @{ status = "UNKNOWN"; message = "Conditional Access: CANNOT TEST"; details = "Azure AD backend check required - cannot test locally" }
}

function Test-SessionHijacking {
    # Observation: Session token protection requires runtime browser instrumentation (requires running browser + CDP)
    return @{ status = "UNKNOWN"; message = "Session Hijacking"; details = "Runtime check requires active browser session and Chrome DevTools Protocol; marked NOT_ASSESSED" }
}

function Test-TokenTheft {
    # Observation: Token theft protection is enforced by OS credential isolation (DPAPI) and browser security model, not policy-configurable
    return @{ status = "UNKNOWN"; message = "Token Theft"; details = "Runtime check requires instrumented credential monitoring; marked NOT_ASSESSED" }
}

function Test-ProfileSeparation {
    # Observation: Profile count is not a policy metric; separation is a user choice and not managed by policy
    return @{ status = "UNKNOWN"; message = "Profile Separation"; details = "Profile architecture is user-driven, not policy-controlled; marked NOT_ASSESSED" }
}

function Test-StoreExtensions {
    $extensionPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
    if (Test-Path $extensionPath) {
        $extCount = (Get-ChildItem $extensionPath -Directory | Measure-Object).Count
        $details = "Installed: $extCount extensions"
    } else {
        $details = "Extension folder: MISSING"
        $extCount = 0
    }
    return @{ status = if ($extCount -gt 0) { "FAILED" } else { "PASSED" }; message = "Store Extensions: $(if ($extCount -gt 0) { 'RISK - ' + $extCount + ' items' } else { 'CLEAN' })"; details = $details }
}

function Test-UnpackedExtensions {
    $extPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
    $unpackedCount = 0
    if (Test-Path $extPath) {
        Get-ChildItem $extPath -Directory | ForEach-Object {
            if (Test-Path "$($_.FullName)\manifest.json") {
                $unpackedCount++
            }
        }
    }
    return @{ status = if ($unpackedCount -gt 0) { "FAILED" } else { "PASSED" }; message = "Unpacked: $(if ($unpackedCount -gt 0) { 'RISK' } else { 'CLEAN' })"; details = "Unpacked extensions: $unpackedCount" }
}

function Test-ExtensionPermissions {
    # Observation: Extension permissions require runtime browser inspection (requires active browser + CDP protocol)
    return @{ status = "UNKNOWN"; message = "Extension Permissions"; details = "Permission audit requires Chrome DevTools Protocol (live browser); marked NOT_ASSESSED" }
}

function Test-DOMAccess {
    # Observation: DOM access restrictions require runtime content script analysis (requires active browser + CDP)
    return @{ status = "UNKNOWN"; message = "DOM Access"; details = "DOM audit requires Chrome DevTools Protocol (live browser); marked NOT_ASSESSED" }
}

function Test-CookieHarvesting {
    # Observation: SameSite behavior requires runtime cookie inspection (requires active browser + network monitoring)
    return @{ status = "UNKNOWN"; message = "Cookie Harvesting"; details = "Cookie attribute audit requires Chrome DevTools Protocol (live browser); marked NOT_ASSESSED" }
}

function Test-ProxyBypass {
    $regPath = "HKCU:\Software\Policies\Microsoft\Edge"
    try {
        $proxyMode = (Get-ItemProperty -Path $regPath -Name "ProxyMode" -ErrorAction Stop).ProxyMode
        $details = "ProxyMode: $proxyMode (1=off, 2=direct, 3=pac, 4=fixed, 5=auto)"
    } catch {
        $details = "Proxy policy: NOT SET"
    }
    return @{ status = "FAILED"; message = "Proxy Bypass: RISK"; details = $details }
}

function Test-DNS {
    # Observation: DNS behavior requires network traffic inspection (requires proxy/CASB integration, external to this host)
    return @{ status = "UNKNOWN"; message = "DNS/DoH"; details = "DNS query audit requires network-level monitoring or policy backend; marked NOT_ASSESSED" }
}

function Test-SSLInspection {
    return @{ status = "UNKNOWN"; message = "SSL Inspection: CANNOT TEST"; details = "Proxy/MITM test required - cannot test locally" }
}

function Test-CASB {
    # Observation: CASB enforcement is external (cloud policy backend); cannot audit from host
    return @{ status = "UNKNOWN"; message = "CASB/SSE"; details = "CASB enforcement is cloud-based; marked NOT_ASSESSED" }
}

function Test-TLSVersionMin {
    $r = Get-EdgePolicyValue -KeyName "SSLVersionMin"
    try {
        if (-not $r.found) {
            return @{
                status = "FAILED"
                message = "TLS Minimum Version: Policy NOT SET"
                details = "SSLVersionMin not found in HKCU/HKLM/WOW6432Node"
                expected_value = "SSLVersionMin en az tls1.2 olmali"
                observed_value = "Policy anahtari bulunamadi"
                remediation = "SSLVersionMin policy degerini tls1.2 veya tls1.3 olarak ayarlayin."
                reference = "https://learn.microsoft.com/deployedge/microsoft-edge-policies/#sslversionmin"
            }
        }

        $actual = ([string]$r.value).ToLowerInvariant()
        $passed = @('tls1.2', 'tls1.3') -contains $actual
        return @{
            status = if ($passed) { "PASSED" } else { "FAILED" }
            message = if ($passed) { "TLS Minimum Version: HARDENED" } else { "TLS Minimum Version: WEAK" }
            details = "Registry: $($r.source)\\SSLVersionMin = $($r.value)"
            expected_value = "SSLVersionMin en az tls1.2 olmali"
            observed_value = "SSLVersionMin=$($r.value)"
            remediation = "SSLVersionMin policy degerini tls1.2 veya tls1.3 olarak ayarlayin."
            reference = "https://learn.microsoft.com/deployedge/microsoft-edge-policies/#sslversionmin"
        }
    } catch {
        return @{ status = "UNKNOWN"; message = "TLS Minimum Version: Error"; details = "Error: $($_.Exception.Message)"; reference = "https://learn.microsoft.com/deployedge/microsoft-edge-policies/#sslversionmin" }
    }
}

function Test-QuicAllowed {
    $r = Get-EdgePolicyValue -KeyName "QuicAllowed"
    try {
        if (-not $r.found) {
            return @{
                status = "FAILED"
                message = "QUIC Control: Policy NOT SET"
                details = "QuicAllowed not found in HKCU/HKLM/WOW6432Node"
                expected_value = "QuicAllowed=false (0) olmali"
                observed_value = "Policy anahtari bulunamadi"
                remediation = "QuicAllowed policy degerini 0 (false) olarak ayarlayin."
                reference = "https://learn.microsoft.com/deployedge/microsoft-edge-policies/#quicallowed"
            }
        }

        $v = [string]$r.value
        $passed = ($v -eq '0' -or $v.ToLowerInvariant() -eq 'false')
        return @{
            status = if ($passed) { "PASSED" } else { "FAILED" }
            message = if ($passed) { "QUIC Control: HARDENED" } else { "QUIC Control: WEAK" }
            details = "Registry: $($r.source)\\QuicAllowed = $($r.value)"
            expected_value = "QuicAllowed=false (0) olmali"
            observed_value = "QuicAllowed=$($r.value)"
            remediation = "QuicAllowed policy degerini 0 (false) olarak ayarlayin."
            reference = "https://learn.microsoft.com/deployedge/microsoft-edge-policies/#quicallowed"
        }
    } catch {
        return @{ status = "UNKNOWN"; message = "QUIC Control: Error"; details = "Error: $($_.Exception.Message)"; reference = "https://learn.microsoft.com/deployedge/microsoft-edge-policies/#quicallowed" }
    }
}

function Test-InsecureContentExceptions {
    $r = Get-EdgePolicyValue -KeyName "InsecureContentAllowedForUrls"
    try {
        if (-not $r.found) {
            return @{
                status = "PASSED"
                message = "Insecure Content Exceptions: CLEAN"
                details = "InsecureContentAllowedForUrls policy anahtari bulunmadi"
                expected_value = "InsecureContentAllowedForUrls tanimli olmamali"
                observed_value = "Policy anahtari yok"
                remediation = "InsecureContentAllowedForUrls istisnasi eklemeyin."
                reference = "https://learn.microsoft.com/deployedge/microsoft-edge-policies/#insecurecontentallowedforurls"
            }
        }

        $raw = [string]$r.value
        $hasValue = -not [string]::IsNullOrWhiteSpace($raw)
        return @{
            status = if ($hasValue) { "FAILED" } else { "PASSED" }
            message = if ($hasValue) { "Insecure Content Exceptions: PRESENT" } else { "Insecure Content Exceptions: EMPTY" }
            details = "Registry: $($r.source)\\InsecureContentAllowedForUrls = $($r.value)"
            expected_value = "InsecureContentAllowedForUrls tanimli olmamali"
            observed_value = "InsecureContentAllowedForUrls=$($r.value)"
            remediation = "InsecureContentAllowedForUrls istisnalarini kaldirin."
            reference = "https://learn.microsoft.com/deployedge/microsoft-edge-policies/#insecurecontentallowedforurls"
        }
    } catch {
        return @{ status = "UNKNOWN"; message = "Insecure Content Exceptions: Error"; details = "Error: $($_.Exception.Message)"; reference = "https://learn.microsoft.com/deployedge/microsoft-edge-policies/#insecurecontentallowedforurls" }
    }
}

function Test-CertificateTransparencyExceptions {
    $keys = @(
        'CertificateTransparencyEnforcementDisabledForCas',
        'CertificateTransparencyEnforcementDisabledForLegacyCas',
        'CertificateTransparencyEnforcementDisabledForUrls'
    )

    try {
        $hits = @()
        foreach ($k in $keys) {
            $r = Get-EdgePolicyValue -KeyName $k
            if ($r.found -and -not [string]::IsNullOrWhiteSpace([string]$r.value)) {
                $hits += "$k=$($r.value)"
            }
        }

        if ($hits.Count -gt 0) {
            return @{
                status = "FAILED"
                message = "Certificate Transparency Exceptions: PRESENT"
                details = "Configured exceptions: $($hits -join '; ')"
                expected_value = "Certificate Transparency bypass listeleri bos olmali"
                observed_value = $hits -join '; '
                remediation = "Certificate Transparency exception policy degerlerini temizleyin."
                reference = "https://learn.microsoft.com/deployedge/microsoft-edge-policies/#certificatetransparencyenforcementdisabledforcas"
            }
        }

        return @{
            status = "PASSED"
            message = "Certificate Transparency Exceptions: CLEAN"
            details = "No Certificate Transparency bypass exception policy found"
            expected_value = "Certificate Transparency bypass listeleri bos olmali"
            observed_value = "Exception policy bulunamadi"
            remediation = "Mevcut durumu koruyun; bypass listesi tanimlamayin."
            reference = "https://learn.microsoft.com/deployedge/microsoft-edge-policies/#certificatetransparencyenforcementdisabledforcas"
        }
    } catch {
        return @{ status = "UNKNOWN"; message = "Certificate Transparency Exceptions: Error"; details = "Error: $($_.Exception.Message)"; reference = "https://learn.microsoft.com/deployedge/microsoft-edge-policies/#certificatetransparencyenforcementdisabledforcas" }
    }
}

function Test-EdgeInstalledExtensions {
    $extensionPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
    $preferencesPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Preferences"
    
    try {
        $forceInstalled = @()
        
        # Check Preferences for force_installed extensions
        if (Test-Path $preferencesPath) {
            $prefs = Get-Content $preferencesPath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($prefs.extensions.settings) {
                $prefs.extensions.settings | Get-Member -MemberType NoteProperty | ForEach-Object {
                    $extId = $_.Name
                    $ext = $prefs.extensions.settings.$extId
                    if ($ext.update_url -match "googleusercontent" -or $ext.location -eq 4) {
                        $forceInstalled += $extId
                    }
                }
            }
        }
        
        if ($forceInstalled.Count -gt 0) {
            return @{ 
                status = "FAILED"
                message = "Force Installed: RISK ($($forceInstalled.Count) detected)"
                details = "Extensions: $($forceInstalled -join ', ') - CIS 1.5: MDM-managed extensions should be reviewed"
            }
        } else {
            return @{ 
                status = "PASSED"
                message = "Force Installed: CLEAN"
                details = "No force-installed extensions detected - CIS 1.5: OK"
            }
        }
    } catch {
        return @{ 
            status = "UNKNOWN"
            message = "Force Installed: CANNOT DETERMINE"
            details = "Error reading preferences: $($_.Exception.Message)"
        }
    }
}

function Test-EdgePreferences {
    $preferencesPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Preferences"
    $riskSettings = @()
    
    try {
        $prefs = Get-Content $preferencesPath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
        
        # User-preference observations only; the managed-policy equivalents are checked by the EDGE-CIS tests.
        if ($prefs.autofill.enabled -eq $true) {
            $riskSettings += "AutoFill: ENABLED"
        }
        
        if ($prefs.password_manager_enabled -ne $false) {
            $riskSettings += "PasswordManager: ENABLED"
        }
        
        if ($prefs.credentials_enable_service -ne $false) {
            $riskSettings += "CredentialService: ENABLED"
        }
        
        if ($prefs.profile.default_content_settings.plugins -ne 1) {
            $riskSettings += "Plugins: ENABLED"
        }
        
        if ($prefs.printing.enabled -ne $false) {
            $riskSettings += "Printing: ENABLED"
        }
        
        if ($prefs.sync.enabled -eq $true) {
            $riskSettings += "Sync: ENABLED"
        }
        
        if ($riskSettings.Count -gt 0) {
            return @{ 
                status = "FAILED"
                message = "Risky Settings: FOUND ($($riskSettings.Count))"
                details = "Issues: $($riskSettings -join ' | ')"
            }
        } else {
            return @{ 
                status = "PASSED"
                message = "Preferences: HARDENED"
                details = "No risky user preference observed in the Edge profile"
            }
        }
    } catch {
        return @{ 
            status = "UNKNOWN"
            message = "Preferences: CANNOT CHECK"
            details = "Error reading preferences: $($_.Exception.Message)"
        }
    }
}

function Test-EdgeProcessArguments {
    try {
        $edgeProcess = Get-Process msedge -ErrorAction SilentlyContinue
        
        if ($null -eq $edgeProcess) {
            return @{ 
                status = "UNKNOWN"
                message = "Process Args: EDGE NOT RUNNING"
                details = "Cannot check runtime arguments while process is inactive"
            }
        }
        
        $cmdLine = $edgeProcess.CommandLine
        $riskFlags = @()
        
        # Check for risky flags
        if ($cmdLine -match "--disable-extensions") {
            $riskFlags += "ExtensionsDisabled"
        }
        if ($cmdLine -match "--disable-component-extensions-with-background-pages") {
            $riskFlags += "ComponentExtensionsDisabled"
        }
        if ($cmdLine -match "--allow-running-insecure-content") {
            $riskFlags += "InsecureContentAllowed"
        }
        if ($cmdLine -match "--no-sandbox") {
            $riskFlags += "SandboxDisabled"
        }
        
        if ($riskFlags.Count -gt 0) {
            return @{ 
                status = "FAILED"
                message = "Process Flags: RISK ($($riskFlags.Count))"
                details = "Risky flags detected: $($riskFlags -join ', ')"
            }
        } else {
            return @{ 
                status = "PASSED"
                message = "Process Args: SECURE"
                details = "No risky runtime flags detected"
            }
        }
    } catch {
        return @{ 
            status = "UNKNOWN"
            message = "Process Args: CANNOT CHECK"
            details = "Error checking process: $($_.Exception.Message)"
        }
    }
}

function Get-EdgePolicyStore {
    $paths = @(
        "HKCU:\Software\Policies\Microsoft\Edge",
        "HKLM:\Software\Policies\Microsoft\Edge",
        "HKLM:\Software\WOW6432Node\Policies\Microsoft\Edge"
    )

    $store = @{}
    foreach ($path in $paths) {
        if (-not (Test-Path $path)) { continue }
        try {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -like "PS*") { continue }
                if (-not $store.ContainsKey($p.Name)) {
                    $store[$p.Name] = @{ value = $p.Value; source = $path }
                }
            }
        } catch {}
    }

    return $store
}

function Get-EdgeCisDefinitionFromLine {
    param([string]$Line)

    if ([string]::IsNullOrWhiteSpace($Line)) { return $null }

    $controlId = ($Line -split '\s+')[0].Trim()
    if ([string]::IsNullOrWhiteSpace($controlId)) { return $null }

    $title = ""
    $mTitle = [regex]::Match($Line, "'([^']+)'")
    if ($mTitle.Success) {
        $title = $mTitle.Groups[1].Value.Trim()
    } else {
        $title = $Line.Trim()
    }

    $expected = ""
    $mSetTo = [regex]::Match($Line, "set to '([^']+)'", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($mSetTo.Success) {
        $expected = $mSetTo.Groups[1].Value.Trim()
    } elseif ($Line -match '(?i)Is\s+Configured') {
        $expected = 'Configured'
    } elseif ($Line -match '(?i)Is\s+Disabled') {
        $expected = 'Disabled'
    } elseif ($Line -match '(?i)Is\s+Enabled') {
        $expected = 'Enabled'
    }

    return @{
        control_id = $controlId
        title = $title
        expected = $expected
        raw_line = $Line.Trim()
    }
}

function Get-EdgeCisMapIndex {
    $mapPath = Join-Path $PSScriptRoot 'edge_cis_policy_map.json'
    $index = @{}
    if (-not (Test-Path $mapPath)) { return $index }

    try {
        $mapItems = Get-Content -Path $mapPath -Raw | ConvertFrom-Json -ErrorAction Stop
        foreach ($item in $mapItems) {
            $id = [string]$item.control_id
            if ([string]::IsNullOrWhiteSpace($id)) { continue }
            $equivalents = @()
            if ($null -ne $item.equivalent_policy_keys) {
                $equivalents = @($item.equivalent_policy_keys | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            }
            $index[$id] = @{
                policy_key = [string]$item.policy_key
                mode = if ([string]::IsNullOrWhiteSpace([string]$item.mode)) { 'MANUAL' } else { ([string]$item.mode).ToUpperInvariant() }
                equivalent_policy_keys = $equivalents
            }
        }
    } catch {}

    return $index
}

function Get-EdgeCisSeverity {
    param([hashtable]$Definition)

    $t = ($Definition.title + " " + $Definition.expected).ToLowerInvariant()
    if ($t -match 'password|sync|download|proxy|tls|https|smartscreen|cookie|extension|developer') {
        return 'HIGH'
    }
    if ($t -match 'autofill|metrics|background|import|collections') {
        return 'MEDIUM'
    }
    return 'LOW'
}

function Test-EdgePolicyExpectation {
    param(
        [object]$Value,
        [string]$Expected
    )

    $vStr = [string]$Value
    $vLower = $vStr.ToLowerInvariant()
    $isDisabledValue = @('0','false','disabled','no') -contains $vLower
    $isEnabledValue = -not [string]::IsNullOrWhiteSpace($vStr) -and -not $isDisabledValue

    if ([string]::IsNullOrWhiteSpace($Expected)) {
        return @{ status = 'UNKNOWN'; message = "Policy value found ($vStr), expected pattern could not be parsed" }
    }

    $mNum = [regex]::Match($Expected, '\b\d+\b')
    if ($mNum.Success) {
        $expectedNum = [int64]$mNum.Value
        [int64]$actualNum = 0
        if ([int64]::TryParse($vStr, [ref]$actualNum)) {
            $ok = ($actualNum -eq $expectedNum)
            return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = "Expected $expectedNum, actual $actualNum" }
        }
    }

    if ($Expected -match '(?i)disabled') {
        $ok = $isDisabledValue
        return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = "Expected Disabled, actual: $vStr" }
    }

    if ($Expected -match '(?i)enabled') {
        $ok = $isEnabledValue
        return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = "Expected Enabled, actual: $vStr" }
    }

    if ($Expected -match '(?i)configured') {
        return @{ status = 'PASSED'; message = "Policy configured, actual: $vStr" }
    }

    return @{ status = 'UNKNOWN'; message = "Policy value found ($vStr), expectation '$Expected' requires manual review" }
}

function Get-PolicyExpectedMachineMeta {
    param(
        [string]$PolicyKey,
        [string]$ExpectedText
    )

    if ([string]::IsNullOrWhiteSpace($PolicyKey) -or [string]::IsNullOrWhiteSpace($ExpectedText)) {
        return @{ kind = ''; value = '' }
    }

    $expected = $ExpectedText.ToLowerInvariant()
    $state = ''
    if ($expected -match '(?i)disabled|block|false') { $state = 'DISABLED' }
    elseif ($expected -match '(?i)enabled|allow|true') { $state = 'ENABLED' }

    $mNum = [regex]::Match($ExpectedText, '\b\d+\b')
    if ($mNum.Success) {
        return @{ kind = 'numeric_eq'; value = [string]$mNum.Value }
    }

    switch ($PolicyKey) {
        'PasswordManagerEnabled' { if ($state) { return @{ kind = 'bool'; value = if ($state -eq 'DISABLED') { 'false' } else { 'true' } } } }
        'AutofillAddressEnabled' { if ($state) { return @{ kind = 'bool'; value = if ($state -eq 'DISABLED') { 'false' } else { 'true' } } } }
        'AutofillCreditCardEnabled' { if ($state) { return @{ kind = 'bool'; value = if ($state -eq 'DISABLED') { 'false' } else { 'true' } } } }
        'SearchSuggestEnabled' { if ($state) { return @{ kind = 'bool'; value = if ($state -eq 'DISABLED') { 'false' } else { 'true' } } } }
        'TranslateEnabled' { if ($state) { return @{ kind = 'bool'; value = if ($state -eq 'DISABLED') { 'false' } else { 'true' } } } }
        'PrintingEnabled' { if ($state) { return @{ kind = 'bool'; value = if ($state -eq 'DISABLED') { 'false' } else { 'true' } } } }
        'AlternateErrorPagesEnabled' { if ($state) { return @{ kind = 'bool'; value = if ($state -eq 'DISABLED') { 'false' } else { 'true' } } } }
        'PaymentMethodQueryEnabled' { if ($state) { return @{ kind = 'bool'; value = if ($state -eq 'DISABLED') { 'false' } else { 'true' } } } }
        'BlockThirdPartyCookies' { if ($state) { return @{ kind = 'bool'; value = if ($state -eq 'DISABLED') { 'false' } else { 'true' } } } }
        'SafeBrowsingProtectionLevel' {
            if ($state -eq 'ENABLED') { return @{ kind = 'numeric_gte'; value = '1' } }
            if ($state -eq 'DISABLED') { return @{ kind = 'numeric_eq'; value = '0' } }
        }
        'DefaultGeolocationSetting' { if ($state) { return @{ kind = 'numeric_eq'; value = if ($state -eq 'DISABLED') { '2' } else { '1' } } } }
        'DefaultNotificationsSetting' { if ($state) { return @{ kind = 'numeric_eq'; value = if ($state -eq 'DISABLED') { '2' } else { '1' } } } }
        'DefaultPopupsSetting' { if ($state) { return @{ kind = 'numeric_eq'; value = if ($state -eq 'DISABLED') { '2' } else { '1' } } } }
        'DefaultJavaScriptSetting' { if ($state) { return @{ kind = 'numeric_eq'; value = if ($state -eq 'DISABLED') { '2' } else { '1' } } } }
    }

    return @{ kind = ''; value = '' }
}

function Get-EdgePolicyChildValues {
    param([string]$ChildKeyName)

    $paths = @(
        "HKCU:\Software\Policies\Microsoft\Edge",
        "HKLM:\Software\Policies\Microsoft\Edge",
        "HKLM:\Software\WOW6432Node\Policies\Microsoft\Edge"
    )

    $values = @()
    foreach ($basePath in $paths) {
        $childPath = Join-Path $basePath $ChildKeyName
        if (-not (Test-Path $childPath)) { continue }

        try {
            $props = Get-ItemProperty -Path $childPath -ErrorAction SilentlyContinue
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -like "PS*") { continue }
                if ($null -eq $p.Value) { continue }
                $text = [string]$p.Value
                if ([string]::IsNullOrWhiteSpace($text)) { continue }
                $values += @{
                    name = [string]$p.Name
                    value = $text
                    source = $childPath
                }
            }
        } catch {}
    }

    return $values
}

function Test-EdgeExtensionControlIntent {
    param([hashtable]$PolicyStore)

    $blocklistValues = @()
    if ($PolicyStore.ContainsKey('ExtensionInstallBlocklist')) {
        $raw = $PolicyStore['ExtensionInstallBlocklist'].value
        if ($raw -is [array]) {
            $blocklistValues += @($raw | ForEach-Object { [string]$_ })
        } elseif ($null -ne $raw) {
            $blocklistValues += [string]$raw
        }
    }

    $childEntries = Get-EdgePolicyChildValues -ChildKeyName 'ExtensionInstallBlocklist'
    foreach ($entry in $childEntries) {
        $blocklistValues += [string]$entry.value
    }

    $normalizedBlocklist = @($blocklistValues | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ([string]$_).Trim() })
    if ($normalizedBlocklist.Count -gt 0) {
        if ($normalizedBlocklist -contains '*') {
            return @{
                status = 'PASSED'
                message = 'Extension install governance enforced by ExtensionInstallBlocklist (*)'
                observed_value = "ExtensionInstallBlocklist=$($normalizedBlocklist -join ',')"
                source = 'ExtensionInstallBlocklist'
            }
        }

        return @{
            status = 'PASSED'
            message = 'Extension install governance configured by ExtensionInstallBlocklist'
            observed_value = "ExtensionInstallBlocklist=$($normalizedBlocklist -join ',')"
            source = 'ExtensionInstallBlocklist'
        }
    }

    if ($PolicyStore.ContainsKey('ExtensionSettings')) {
        $rawSettings = [string]$PolicyStore['ExtensionSettings'].value
        if (-not [string]::IsNullOrWhiteSpace($rawSettings)) {
            try {
                $settingsObj = $rawSettings | ConvertFrom-Json -ErrorAction Stop
                $globalRule = $settingsObj.PSObject.Properties | Where-Object { $_.Name -eq '*' } | Select-Object -First 1
                if ($null -ne $globalRule) {
                    $globalValue = $globalRule.Value

                    $mode = [string]$globalValue.installation_mode
                    if ($mode -eq 'blocked') {
                        return @{
                            status = 'PASSED'
                            message = 'Extension install governance enforced by ExtensionSettings (*.installation_mode=blocked)'
                            observed_value = 'ExtensionSettings[*].installation_mode=blocked'
                            source = 'ExtensionSettings'
                        }
                    }

                    $sources = @($globalValue.install_sources)
                    $normalizedSources = @($sources | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                    if ($normalizedSources.Count -gt 0) {
                        $hasBroadSource = $false
                        foreach ($src in $normalizedSources) {
                            if ($src -eq '*' -or $src -match '^https?://\*/?\*?$') {
                                $hasBroadSource = $true
                                break
                            }
                        }

                        if (-not $hasBroadSource) {
                            return @{
                                status = 'PASSED'
                                message = 'Extension install governance enforced by restricted ExtensionSettings install_sources'
                                observed_value = "ExtensionSettings[*].install_sources=$($normalizedSources -join ',')"
                                source = 'ExtensionSettings'
                            }
                        }
                    }
                }
            } catch {
                return @{
                    status = 'FAILED'
                    message = 'ExtensionSettings present but invalid JSON; extension governance intent cannot be validated'
                    observed_value = '(invalid ExtensionSettings JSON)'
                    source = 'ExtensionSettings'
                }
            }
        }
    }

    return @{
        status = 'FAILED'
        message = 'No policy evidence found for extension install governance intent'
        observed_value = '(not set)'
        source = 'None'
    }
}

function Invoke-EdgeCisPolicyTest {
    param(
        [hashtable]$Definition,
        [hashtable]$PolicyStore,
        [hashtable]$Mapping
    )

    $meta = Get-PolicyExpectedMachineMeta -PolicyKey ([string]$Mapping.policy_key) -ExpectedText ([string]$Definition.expected)

    if ($null -eq $Mapping -or $Mapping.mode -ne 'POLICY' -or [string]::IsNullOrWhiteSpace($Mapping.policy_key)) {
        return @{
            status = 'UNKNOWN'
            message = 'Strict Edge CIS mapping requires manual verification for this control'
            details = "Control: $($Definition.control_id) | Expected: $($Definition.expected)"
            expected_value = "Expected: $($Definition.expected)"
            observed_value = "(not assessed)"
            expected_kind = $meta.kind
            expected_machine_value = $meta.value
            finding_details = 'Bu Edge CIS kontrolu strict map dosyasinda eksik veya manuel isaretli oldugu icin otomatik policy anahtar testi uygulanmadi.'
            test_method = 'Control ID -> edge_cis_policy_map.json strict map lookup (MANUAL mode).'
            rationale = 'Belirsiz policy anahtarlari ile otomatik test yapmak yanlis pozitif/negatif sonuclar uretebilir.'
            impact = 'Kontrol durumu manuel dogrulama gerektirdiginden kesin uyum karari verilemez.'
            remediation = 'edge_cis_policy_map.json dosyasinda bu kontrol icin kesin policy_key ve POLICY mode tanimlayin.'
            reference = 'https://learn.microsoft.com/deployedge/microsoft-edge-policies/'
        }
    }

    $matchedKey = [string]$Mapping.policy_key
    $equivalentKeys = @()
    if ($null -ne $Mapping.equivalent_policy_keys) {
        $equivalentKeys = @($Mapping.equivalent_policy_keys | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    if ([string]$Definition.control_id -eq '1.6' -and [string]$matchedKey -eq 'ExtensionInstallBlocklist') {
        $intentEval = Test-EdgeExtensionControlIntent -PolicyStore $PolicyStore
        return @{
            status = $intentEval.status
            message = $intentEval.message
            details = "Control: $($Definition.control_id) | Intent source: $($intentEval.source)"
            expected_value = "Expected: $($Definition.expected)"
            observed_value = [string]$intentEval.observed_value
            expected_kind = $meta.kind
            expected_machine_value = $meta.value
            finding_details = "CIS $($Definition.control_id) icin extension install yonetimi intent-bazli degerlendirildi."
            test_method = 'Strict map baseline + intent-aware extension policy evaluation (ExtensionInstallBlocklist and ExtensionSettings content).'
            rationale = 'MDM/GPO dagitiminda extension kisiti tek bir key yerine policy kompozisyonu ile uygulanabilir; karar mekanizmasi bunu dogrulamalidir.'
            impact = 'Intent dogrulandiginda extension tehditlerinin rapor statuleri sahadaki gercek enforcement ile uyumlu olur.'
            remediation = 'ExtensionInstallBlocklist veya ExtensionSettings icinde extension kurulumunu kisitlayan acik bir kural tanimlayin.'
            reference = 'https://learn.microsoft.com/deployedge/microsoft-edge-policies#extensionsettings'
        }
    }

    if (-not $PolicyStore.ContainsKey($matchedKey)) {
        foreach ($candidate in $equivalentKeys) {
            if ($PolicyStore.ContainsKey($candidate)) {
                $entry = $PolicyStore[$candidate]
                $eval = Test-EdgePolicyExpectation -Value $entry.value -Expected $Definition.expected
                return @{
                    status = $eval.status
                    message = "$($eval.message) (evaluated via equivalent key: $candidate)"
                    details = "$($entry.source)\\$candidate = $($entry.value)"
                    expected_value = "Expected: $($Definition.expected)"
                    observed_value = [string]$entry.value
                    expected_kind = $meta.kind
                    expected_machine_value = $meta.value
                    finding_details = "CIS $($Definition.control_id) strict key '$matchedKey' bulunamadi, equivalent key '$candidate' ile degerlendirildi."
                    test_method = "Control ID -> strict map -> equivalent key fallback ($candidate)."
                    rationale = 'MDM/GPO dagitiminda ayni guvenlik niyeti farkli policy key uzerinden uygulanabilir; fallback yalnizca explicit map ile etkinlesir.'
                    impact = 'Equivalent key ile dogrulanan kontroller, sadece key adi farkindan kaynaklanan yanlis FAIL sonucunu azaltir.'
                    remediation = "Strict key '$matchedKey' veya mapped equivalent key '$candidate' kurum standardina uygun sekilde dagitilsin."
                    reference = 'https://learn.microsoft.com/deployedge/microsoft-edge-policies/'
                }
            }
        }

        return @{
            status = 'FAILED'
            message = "Mapped policy key not found locally: $matchedKey"
            details = "Control: $($Definition.control_id) | Expected: $($Definition.expected)"
            expected_value = "Expected: $($Definition.expected)"
            observed_value = "(not set)"
            expected_kind = $meta.kind
            expected_machine_value = $meta.value
            finding_details = "! Strict map bu kontrolu '$matchedKey' anahtarina bagladi ancak local registry policy store'da key bulunamadi. Kurumsal enforcement cloud policy veya baska bir guvenlik katmaninda olabilir."
            test_method = "Control ID -> strict map -> registry key lookup ($matchedKey)."
            rationale = 'Policy anahtarinin yerelde gorunmemesi her zaman kontrol yok anlamina gelmez; farkli yonetim katmanlari olabilir.'
            impact = 'Kesin PASS/FAIL karari yerine manuel/ikinci katman dogrulamasi gerekir; aksi durumda false positive riski olusur.'
            remediation = "'$matchedKey' anahtari icin GPO/Intune dagitimini ve davranissal sonucu birlikte dogrulayin."
            reference = 'https://learn.microsoft.com/deployedge/microsoft-edge-policies/'
            warning_note = 'Yerel policy anahtari bulunamadi; bu kontrolu kurumsal dagitim kaynagi ve manuel davranis testi ile dogrulayin.'
            manual_required = $true
        }
    }

    $entry = $PolicyStore[$matchedKey]
    $eval = Test-EdgePolicyExpectation -Value $entry.value -Expected $Definition.expected
    if ($matchedKey -eq 'InPrivateModeAvailability') {
        [int64]$inPrivateNum = -1
        if ([int64]::TryParse([string]$entry.value, [ref]$inPrivateNum)) {
            if ($Definition.expected -match '(?i)disabled') {
                if ($inPrivateNum -eq 1 -or $inPrivateNum -eq 2) {
                    $eval = @{ status = 'PASSED'; message = "Expected Disabled, actual policy mode: $inPrivateNum" }
                } else {
                    $eval = @{ status = 'FAILED'; message = "Expected Disabled, actual policy mode: $inPrivateNum" }
                }
            }
        }
    }
    return @{
        status = $eval.status
        message = $eval.message
        details = "$($entry.source)\\$matchedKey = $($entry.value)"
        expected_value = "Expected: $($Definition.expected)"
        observed_value = [string]$entry.value
        expected_kind = $meta.kind
        expected_machine_value = $meta.value
        finding_details = "Reference control $($Definition.control_id) denetiminde '$matchedKey' policy anahtari kullanildi."
        test_method = "Control ID strict map ile '$matchedKey' key'ine baglandi ve expected ifadesiyle deger karsilastirildi."
        rationale = 'Bu referans kontrolu, tarayici policy yonetiminin merkezi ve denetlenebilir olmasini hedefler.'
        impact = 'Beklenen deger saglanmazsa ilgili koruma mekanizmasi devre disi veya zayif kalabilir.'
        remediation = "'$matchedKey' policy degerini referans beklentisine ($($Definition.expected)) uygun sekilde ayarlayin."
        reference = 'https://learn.microsoft.com/deployedge/microsoft-edge-policies/'
    }
}

function Get-EdgeCisTestsFromCatalog {
    $catalogPath = Join-Path $PSScriptRoot 'edge_cis_controls.txt'
    if (-not (Test-Path $catalogPath)) {
        Write-Warning "Edge reference catalog not found: $catalogPath. All EDGE-REF-* controls are skipped; the run is incomplete."
        return @{}
    }

    $tests = @{}
    $usedIds = @{}
    $lines = Get-Content -Path $catalogPath | ForEach-Object { $_.Trim() } | Where-Object { $_ }

    foreach ($line in $lines) {
        $def = Get-EdgeCisDefinitionFromLine -Line $line
        if ($null -eq $def) { continue }

        $rawId = "EDGE-REF-" + ($def.control_id -replace '[^0-9A-Za-z]+', '-')
        $id = $rawId
        $idx = 2
        while ($usedIds.ContainsKey($id)) {
            $id = "$rawId-$idx"
            $idx++
        }
        $usedIds[$id] = $true

        $tests[$id] = @{
            Name = "Reference control $($def.control_id) - $($def.title)"
            Severity = Get-EdgeCisSeverity -Definition $def
            Package = 'ED-REF'
            VerifiedVia = 'Registry Policy Strict Map (HKCU/HKLM)'
            CISControls = @($def.control_id)
            Type = 'ED-REF'
            Definition = $def
            Mapping = if ($script:EdgeCisMapIndex.ContainsKey($def.control_id)) { $script:EdgeCisMapIndex[$def.control_id] } else { @{ policy_key = ''; mode = 'MANUAL' } }
        }
    }

    return $tests
}

# ==================== TEST RUNNER ====================

$BaseTestMap = @{
    "P1-001" = @{ Name = "InPrivate Mode"; Func = "Test-InPrivateMode"; Severity = "HIGH"; Package = "PKG-1"; VerifiedVia = "Registry (HKCU/HKLM)"; CISControls = @() }
    "P1-002" = @{ Name = "Extension Policy"; Func = "Test-ExtensionPolicy"; Severity = "HIGH"; Package = "PKG-1"; VerifiedVia = "Registry (HKCU)"; CISControls = @(); PolicyKey = "ExtensionInstallBlocklist" }
    "P1-003" = @{ Name = "Password Manager"; Func = "Test-PasswordManager"; Severity = "MEDIUM"; Package = "PKG-1"; VerifiedVia = "Registry (HKCU), Preferences File"; CISControls = @("1.2") }
    "P1-004" = @{ Name = "Developer Tools"; Func = "Test-DeveloperTools"; Severity = "MEDIUM"; Package = "PKG-1"; VerifiedVia = "Registry (HKCU)"; CISControls = @(); PolicyKey = "DeveloperToolsAvailability" }
    "P1-005" = @{ Name = "Download Policy"; Func = "Test-DownloadPolicy"; Severity = "HIGH"; Package = "PKG-1"; VerifiedVia = "Registry (HKCU)"; CISControls = @(); PolicyKey = "PromptForDownloadLocation" }
    "P2-001" = @{ Name = "Mail Exfiltration"; Func = "Test-MailExfiltration"; Severity = "CRITICAL"; Package = "PKG-2"; VerifiedVia = "Filesystem (AppData)"; CISControls = @(); IntuneReferenceUrl = "https://learn.microsoft.com/en-us/intune/app-management/protection/overview"; ManageEngineReferenceUrl = "https://www.manageengine.com/mobile-device-management/help/security_management/mdm_security_management.html" }
    "P2-002" = @{ Name = "AI Tools"; Func = "Test-AITools"; Severity = "CRITICAL"; Package = "PKG-2"; VerifiedVia = "Preferences File"; CISControls = @(); IntuneReferenceUrl = "https://learn.microsoft.com/en-us/purview/dlp-create-policy-prevent-cloud-sharing-from-edge-biz"; ManageEngineReferenceUrl = "https://www.manageengine.com/mobile-device-management/help/app_management/blocklisting-apps.html" }
    "P2-003" = @{ Name = "Copy-Paste"; Func = "Test-CopyPaste"; Severity = "HIGH"; Package = "PKG-2"; VerifiedVia = "Browser API (requires DevTools)"; CISControls = @() }
    "P2-004" = @{ Name = "Browser Sync"; Func = "Test-BrowserSync"; Severity = "CRITICAL"; Package = "PKG-2"; VerifiedVia = "Registry (HKCU), Preferences File"; CISControls = @("1.5"); IntuneReferenceUrl = "https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies"; ManageEngineReferenceUrl = "https://www.manageengine.com/mobile-device-management/help/profile_management/mdm_profile_management.html" }
    "P2-005" = @{ Name = "Download Bypass"; Func = "Test-DownloadBypass"; Severity = "HIGH"; Package = "PKG-2"; VerifiedVia = "Filesystem (Downloads folder)"; CISControls = @() }
    "P3-001" = @{ Name = "M365"; Func = "Test-M365Auth"; Severity = "HIGH"; Package = "PKG-3"; VerifiedVia = "Filesystem (Cache)"; CISControls = @() }
    "P3-002" = @{ Name = "Conditional Access"; Func = "Test-ConditionalAccess"; Severity = "HIGH"; Package = "PKG-3"; VerifiedVia = "Azure AD backend (external)"; CISControls = @() }
    "P3-003" = @{ Name = "Session"; Func = "Test-SessionHijacking"; Severity = "MEDIUM"; Package = "PKG-3"; VerifiedVia = "Filesystem (Cache)"; CISControls = @(); PolicyMapping = "OBSERVATIONAL" }
    "P3-004" = @{ Name = "Token"; Func = "Test-TokenTheft"; Severity = "HIGH"; Package = "PKG-3"; VerifiedVia = "Filesystem (Registry)"; CISControls = @() }
    "P3-005" = @{ Name = "Profile"; Func = "Test-ProfileSeparation"; Severity = "HIGH"; Package = "PKG-3"; VerifiedVia = "Filesystem (User Data folder)"; CISControls = @(); PolicyMapping = "OBSERVATIONAL" }
    "P4-001" = @{ Name = "Store Extensions"; Func = "Test-StoreExtensions"; Severity = "HIGH"; Package = "PKG-4"; VerifiedVia = "Filesystem (Extensions folder), DevTools (CDP)"; CISControls = @() }
    "P4-002" = @{ Name = "Unpacked"; Func = "Test-UnpackedExtensions"; Severity = "HIGH"; Package = "PKG-4"; VerifiedVia = "Filesystem (Extensions folder)"; CISControls = @(); PolicyMapping = "OBSERVATIONAL" }
    "P4-003" = @{ Name = "Permissions"; Func = "Test-ExtensionPermissions"; Severity = "HIGH"; Package = "PKG-4"; VerifiedVia = "Registry Policy, DevTools (CDP)"; CISControls = @(); PolicyMapping = "OBSERVATIONAL" }
    "P4-004" = @{ Name = "DOM"; Func = "Test-DOMAccess"; Severity = "CRITICAL"; Package = "PKG-4"; VerifiedVia = "DevTools (CDP - requires live browser)"; CISControls = @(); PolicyMapping = "OBSERVATIONAL"; IntuneReferenceUrl = "https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies"; ManageEngineReferenceUrl = "https://www.manageengine.com/mobile-device-management/help/profile_management/mdm_profile_management.html" }
    "P4-005" = @{ Name = "Cookie"; Func = "Test-CookieHarvesting"; Severity = "CRITICAL"; Package = "PKG-4"; VerifiedVia = "DevTools (CDP - requires live browser)"; CISControls = @(); PolicyMapping = "OBSERVATIONAL"; IntuneReferenceUrl = "https://learn.microsoft.com/en-us/intune/app-management/protection/overview"; ManageEngineReferenceUrl = "https://www.manageengine.com/mobile-device-management/help/security_management/mdm_security_management.html" }
    "P5-001" = @{ Name = "Proxy"; Func = "Test-ProxyBypass"; Severity = "HIGH"; Package = "PKG-5"; VerifiedVia = "Registry (HKCU)"; CISControls = @() }
    "P5-002" = @{ Name = "DNS"; Func = "Test-DNS"; Severity = "MEDIUM"; Package = "PKG-5"; VerifiedVia = "Network config (external)"; CISControls = @() }
    "P5-003" = @{ Name = "SSL"; Func = "Test-SSLInspection"; Severity = "HIGH"; Package = "PKG-5"; VerifiedVia = "Proxy inspection (external)"; CISControls = @() }
    "P5-004" = @{ Name = "CASB"; Func = "Test-CASB"; Severity = "HIGH"; Package = "PKG-5"; VerifiedVia = "Cloud policy (external)"; CISControls = @() }
    "P5-005" = @{ Name = "TLS Minimum Version"; Func = "Test-TLSVersionMin"; Severity = "HIGH"; Package = "PKG-5"; VerifiedVia = "Registry (HKCU/HKLM)"; CISControls = @() }
    "P5-006" = @{ Name = "QUIC Disable"; Func = "Test-QuicAllowed"; Severity = "MEDIUM"; Package = "PKG-5"; VerifiedVia = "Registry (HKCU/HKLM)"; CISControls = @() }
    "P5-007" = @{ Name = "Insecure Content Exceptions"; Func = "Test-InsecureContentExceptions"; Severity = "HIGH"; Package = "PKG-5"; VerifiedVia = "Registry (HKCU/HKLM)"; CISControls = @() }
    "P5-008" = @{ Name = "Certificate Transparency Exceptions"; Func = "Test-CertificateTransparencyExceptions"; Severity = "HIGH"; Package = "PKG-5"; VerifiedVia = "Registry (HKCU/HKLM)"; CISControls = @() }
    "P6-001" = @{ Name = "Force Extensions"; Func = "Test-EdgeInstalledExtensions"; Severity = "CRITICAL"; Package = "PKG-6"; VerifiedVia = "Preferences File, DevTools (CDP)"; CISControls = @(); IntuneReferenceUrl = "https://learn.microsoft.com/en-us/purview/dlp-browser-dlp-learn"; ManageEngineReferenceUrl = "https://www.manageengine.com/mobile-device-management/help/app_management/mdm_app_management.html" }
    # User-preference aggregate; the matching CIS policy controls are covered by the EDGE-CIS catalog tests.
    "P6-002" = @{ Name = "Preferences"; Func = "Test-EdgePreferences"; Severity = "MEDIUM"; Package = "PKG-6"; VerifiedVia = "Preferences File, DevTools (CDP)"; CISControls = @(); PolicyMapping = "OBSERVATIONAL" }
    "P6-003" = @{ Name = "Process Args"; Func = "Test-EdgeProcessArguments"; Severity = "MEDIUM"; Package = "PKG-6"; VerifiedVia = "Process Command Line (Live)"; CISControls = @() }
}

$script:EdgeCisMapIndex = Get-EdgeCisMapIndex
$EdgeCisTestMap = Get-EdgeCisTestsFromCatalog
$TestMap = @{}
$BaseTestMap.Keys | ForEach-Object { $TestMap[$_] = $BaseTestMap[$_] }
$EdgeCisTestMap.Keys | Sort-Object | ForEach-Object { $TestMap[$_] = $EdgeCisTestMap[$_] }
$script:EdgePolicyStore = Get-EdgePolicyStore

# Testeri Ã§alÄ±ÅŸtÄ±r
if ($TestId -eq "ALL") {
    $TestMap.Keys | Sort-Object | ForEach-Object {
        $testKey = $_
        $testConfig = $TestMap[$testKey]
        if ($testConfig.Type -eq 'ED-REF') {
            $result = Invoke-EdgeCisPolicyTest -Definition $testConfig.Definition -PolicyStore $script:EdgePolicyStore -Mapping $testConfig.Mapping
        } else {
            $result = & $testConfig.Func
        }
        $manual = Get-EdgeManualCheckGuidance -TestId $testKey -TestConfig $testConfig -Result $result
        $evidenceOutput = Get-ResultFieldOrFallback -Result $result -FieldName "evidence_output" -FallbackValue (Get-ResultFieldOrFallback -Result $result -FieldName "details" -FallbackValue (Get-ResultField -Result $result -FieldName "message" -DefaultValue ""))
        $expectedValue = Get-ResultField -Result $result -FieldName "expected_value" -DefaultValue ""
        $observedValue = Get-ResultField -Result $result -FieldName "observed_value" -DefaultValue ""
        $expectedMeta = Get-MachineComparableExpectation -ExpectedValue $expectedValue -ObservedValue $observedValue
        
        $resultPayload = @{
            test_id = $testKey
            test_name = $testConfig.Name
            package_id = $testConfig.Package
            severity = $testConfig.Severity
            cis_controls = $testConfig.CISControls
            verified_via = $testConfig.VerifiedVia
            policy_key = if ($testConfig.PolicyKey) { [string]$testConfig.PolicyKey } else { "" }
            policy_mapping = if ($testConfig.PolicyMapping) { [string]$testConfig.PolicyMapping } else { "" }
            status = $result.status
            message = $result.message
            details = $result.details
            finding_details = $result.finding_details
            test_method = $result.test_method
            rationale = $result.rationale
            remediation = $result.remediation
            reference = $result.reference
            intune_reference_url = if ($testConfig.IntuneReferenceUrl) { $testConfig.IntuneReferenceUrl } else { "" }
            manageengine_reference_url = if ($testConfig.ManageEngineReferenceUrl) { $testConfig.ManageEngineReferenceUrl } else { "" }
            warning_note = $result.warning_note
            expected_value = $expectedValue
            expected_kind = Get-ResultFieldOrFallback -Result $result -FieldName "expected_kind" -FallbackValue $expectedMeta.kind
            expected_machine_value = Get-ResultFieldOrFallback -Result $result -FieldName "expected_machine_value" -FallbackValue $expectedMeta.value
            observed_value = $observedValue
            evidence_output = $evidenceOutput
            evidence_type = Get-ResultField -Result $result -FieldName "evidence_type" -DefaultValue ""
            confidence = Get-ResultField -Result $result -FieldName "confidence" -DefaultValue "MEDIUM"
            status_reason = Get-ResultField -Result $result -FieldName "status_reason" -DefaultValue ""
            manual_required = Get-ResultField -Result $result -FieldName "manual_required" -DefaultValue $false
            manual_check = $manual.manual_check
            manual_check_steps = $manual.manual_check_steps
            manual_check_command = $manual.manual_check_command
            manual_check_expected = $manual.manual_check_expected
            manual_check_note = $manual.manual_check_note
            retest_command = ".\\test_runner.ps1 -TestId $testKey"
            timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }
        $normalizedPayload = Normalize-ReportPayload -Payload $resultPayload
        $enrichedPayload = Add-ArtifactMetadata -Payload $normalizedPayload
        $script:TestResults += $enrichedPayload
    }
} else {
    # Spesifik test
    if ($TestMap.ContainsKey($TestId)) {
        $testConfig = $TestMap[$TestId]
        if ($testConfig.Type -eq 'ED-REF') {
            $result = Invoke-EdgeCisPolicyTest -Definition $testConfig.Definition -PolicyStore $script:EdgePolicyStore -Mapping $testConfig.Mapping
        } else {
            $result = & $testConfig.Func
        }
        $manual = Get-EdgeManualCheckGuidance -TestId $TestId -TestConfig $testConfig -Result $result
        $evidenceOutput = Get-ResultFieldOrFallback -Result $result -FieldName "evidence_output" -FallbackValue (Get-ResultFieldOrFallback -Result $result -FieldName "details" -FallbackValue (Get-ResultField -Result $result -FieldName "message" -DefaultValue ""))
        $expectedValue = Get-ResultField -Result $result -FieldName "expected_value" -DefaultValue ""
        $observedValue = Get-ResultField -Result $result -FieldName "observed_value" -DefaultValue ""
        $expectedMeta = Get-MachineComparableExpectation -ExpectedValue $expectedValue -ObservedValue $observedValue
        
        $resultPayload = @{
            test_id = $TestId
            test_name = $testConfig.Name
            package_id = $testConfig.Package
            severity = $testConfig.Severity
            cis_controls = $testConfig.CISControls
            verified_via = $testConfig.VerifiedVia
            policy_key = if ($testConfig.PolicyKey) { [string]$testConfig.PolicyKey } else { "" }
            policy_mapping = if ($testConfig.PolicyMapping) { [string]$testConfig.PolicyMapping } else { "" }
            status = $result.status
            message = $result.message
            details = $result.details
            finding_details = $result.finding_details
            test_method = $result.test_method
            rationale = $result.rationale
            remediation = $result.remediation
            reference = $result.reference
            intune_reference_url = if ($testConfig.IntuneReferenceUrl) { $testConfig.IntuneReferenceUrl } else { "" }
            manageengine_reference_url = if ($testConfig.ManageEngineReferenceUrl) { $testConfig.ManageEngineReferenceUrl } else { "" }
            warning_note = $result.warning_note
            expected_value = $expectedValue
            expected_kind = Get-ResultFieldOrFallback -Result $result -FieldName "expected_kind" -FallbackValue $expectedMeta.kind
            expected_machine_value = Get-ResultFieldOrFallback -Result $result -FieldName "expected_machine_value" -FallbackValue $expectedMeta.value
            observed_value = $observedValue
            evidence_output = $evidenceOutput
            evidence_type = Get-ResultField -Result $result -FieldName "evidence_type" -DefaultValue ""
            confidence = Get-ResultField -Result $result -FieldName "confidence" -DefaultValue "MEDIUM"
            status_reason = Get-ResultField -Result $result -FieldName "status_reason" -DefaultValue ""
            manual_required = Get-ResultField -Result $result -FieldName "manual_required" -DefaultValue $false
            manual_check = $manual.manual_check
            manual_check_steps = $manual.manual_check_steps
            manual_check_command = $manual.manual_check_command
            manual_check_expected = $manual.manual_check_expected
            manual_check_note = $manual.manual_check_note
            retest_command = ".\\test_runner.ps1 -TestId $TestId"
            timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }
        $normalizedPayload = Normalize-ReportPayload -Payload $resultPayload
        $enrichedPayload = Add-ArtifactMetadata -Payload $normalizedPayload
        $script:TestResults += $enrichedPayload
    } else {
        Write-Host "HATA: Bilinmeyen test ID: $TestId" -ForegroundColor Red
        exit 1
    }
}

# Output
if ($OutputJSON) {
    # Calculate summary
    $passed = @($script:TestResults | Where-Object { $_.status -eq "PASSED" }).Count
    $failed = @($script:TestResults | Where-Object { $_.status -eq "FAILED" }).Count
    $unknown = @($script:TestResults | Where-Object { $_.status -eq "UNKNOWN" }).Count
    $total = @($script:TestResults).Count
    
    # Risk score calculation (normalized weighted model)
    $severityWeights = @{ CRITICAL = 4.0; HIGH = 3.0; MEDIUM = 2.0; LOW = 1.0 }
    $totalWeight = 0.0
    $failedWeight = 0.0
    $unknownWeight = 0.0

    foreach ($t in $script:TestResults) {
        $sev = [string]$t.severity
        $w = if ($severityWeights.ContainsKey($sev)) { [double]$severityWeights[$sev] } else { 2.0 }
        $totalWeight += $w

        if ($t.status -eq "FAILED") {
            $failedWeight += $w
        } elseif ($t.status -eq "UNKNOWN") {
            # Unknown contributes partially because risk exists but confidence is lower than FAILED.
            $unknownWeight += ($w * 0.35)
        }
    }

    $score = if ($totalWeight -gt 0) {
        [Math]::Round((($failedWeight + $unknownWeight) / $totalWeight) * 100, 0)
    } else {
        0
    }
    $riskLevel = if ($score -ge 75) { "CRITICAL" } elseif ($score -ge 55) { "HIGH" } elseif ($score -ge 30) { "MEDIUM" } else { "LOW" }
    
    # Create full report object
    $report = @{
        organization = "Corporate Security"
        browser = "Microsoft Edge"
        test_date = (Get-Date -Format "yyyy-MM-dd")
        test_time = (Get-Date -Format "HH:mm:ss")
        environment = Get-EnvironmentInfo
        summary = @{
            total_tests = $total
            passed = $passed
            failed = $failed
            unknown = $unknown
            risk_score = $score
            risk_level = $riskLevel
        }
        results = $script:TestResults
    }
    
    $jsonOutput = $report | ConvertTo-Json -Depth 10
    
    if ($OutputFile) {
        # Write to file
        $jsonOutput | Out-File -FilePath $OutputFile -Encoding UTF8
        Write-Host "Results saved to: $OutputFile" -ForegroundColor Green
    } else {
        # Write to console
        Write-Output $jsonOutput
    }
} else {
    $script:TestResults | Format-Table -AutoSize @(
        @{ Label = "TEST ID"; Expression = { $_.test_id }; Width = 10 },
        @{ Label = "TEST NAME"; Expression = { $_.test_name }; Width = 20 },
        @{ Label = "STATUS"; Expression = { $_.status }; Width = 10 },
        @{ Label = "MESSAGE"; Expression = { $_.message }; Width = 40 }
    )
}

