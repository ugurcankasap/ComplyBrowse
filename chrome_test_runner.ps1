# Chrome Security Test Runner
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
    $businessImpact = 'hesap guvenligi, veri gizliligi ve denetim uyumu riske girebilir'

    if ($name -match 'incognito|inprivate|private browsing') {
        $vector = 'izsiz ozel oturum kullanimi'
        $techImpact = 'denetim izi ve URL/oturum gorunurlugu azalir, olay inceleme delilleri zayiflar'
        $businessImpact = 'uygunsuz veri erisimi veya politika ihlali olaylarinda kok neden analizi gecikir'
    } elseif ($name -match 'password|autocomplete') {
        $vector = 'tarayicida kayitli kimlik bilgisi suistimali'
        $techImpact = 'endpoint ele gecirme sonrasi sakli parola/otomatik doldurma verisi toplanabilir'
        $businessImpact = 'hesap devralma, ayricalikli erisim ve kritik sistemlerde yetkisiz islem riski artar'
    } elseif ($name -match 'extension|add-on|store') {
        $vector = 'yetkisiz eklenti yukleme zinciri'
        $techImpact = 'eklenti izinleri ile cerez, DOM ve form verisi okunup dis ortama aktarilabilir'
        $businessImpact = 'data leakage and supply-chain-driven security incidents may occur'
    } elseif ($name -match 'developer|devtools|debug|about:config|developer edition') {
        $vector = 'debug/yetkili gelistirici ozelliklerinin kotuye kullanimi'
        $techImpact = 'istemci tarafi kontroller manipule edilerek koruyucu mekanizmalar etkisizlestirilebilir'
        $businessImpact = 'ic tehdit ve red-team benzeri saldiri senaryolarinda ihlal olasiligi artar'
    } elseif ($name -match 'safe browsing|smartscreen|phishing|security warning') {
        $vector = 'zararli hedeflere yonlendirme ve kimlik avi'
        $techImpact = 'tehdit itibari uyarilari zayiflayarak malware/phishing tespiti gecikebilir'
        $businessImpact = 'kullanici kimlik bilgileri ve kurumsal hesaplar hedef alinabilir'
    } elseif ($name -match 'sync|accounts?|browser sign-in|implicit sign-in|profile separation') {
        $vector = 'kurum disi bulut senkronizasyonu'
        $techImpact = 'gecmis, yer imi, oturum ve profil verileri yonetim disi ortamlara tasinabilir'
        $businessImpact = 'veri egemenligi, KVKK/GDPR uyumu ve denetim kapsaminda bulgu riski artar'
    } elseif ($name -match 'dns|doh|webrtc|local ip') {
        $vector = 'ad/cikti trafik manipuÌˆlasyonu ve ag metadata sizintisi'
        $techImpact = 'kullanicilar sahte hedeflere yonlendirilebilir veya yerel ag bilgisi ifsa olabilir'
        $businessImpact = 'phishing success rates may increase while network-level visibility decreases'
    } elseif ($name -match 'download|file type|prompt') {
        $vector = 'kontrolsuz dosya indirme ve calistirma'
        $techImpact = 'imzasiz/riskli dosyalar uzerinden malware yuklenmesi kolaylasir'
        $businessImpact = 'is surekliligi kesintisi ve fidye yazilimi kaynakli finansal kayip olusabilir'
    } elseif ($name -match 'proxy|ssl|https-only|tls|certificate|ocsp|crl|pinning|hsts|mixed content|quic') {
        $vector = 'trafik guvenligi ve sertifika dogrulama zayifligi'
        $techImpact = 'MITM benzeri saldirilarin basari sansi artabilir, guvenli kanal garantisi zayiflar'
        $businessImpact = 'hassas veri aktariminda gizlilik ve butunluk riski yukselir'
    } elseif ($name -match 'cookie|third-party storage|site isolation|renderer|sandbox|referrer|protocol handler') {
        $vector = 'oturum ve tarayici izolasyon kontrollerinin zayiflamasi'
        $techImpact = 'oturum takibi, cerez suistimali veya siteler arasi etki alani buyuyebilir'
        $businessImpact = 'hesap suistimali ve kullanici mahremiyeti ihlalleri artabilir'
    } elseif ($name -match 'telemetry|metrics|feedback|crash|domain reliability|usage') {
        $vector = 'yonetim disi tanilama/veri paylasim kanallari'
        $techImpact = 'istemci davranis/metrik verisi dis servislere transfer edilebilir'
        $businessImpact = 'veri minimizasyonu ve reguÌˆlatif beklentilerle uyumsuzluk olusabilir'
    }

    $statePrefix = if ($isPassed) { 'Durum: Kontrol su an aktif ve beklenen politikaya uyumlu.' } else { 'Durum: Kontrol beklenen sertlestirme seviyesinde degil.' }
    $expectedNote = if (-not [string]::IsNullOrWhiteSpace($expected)) { " Beklenen: $expected." } else { '' }
    $observedNote = if (-not [string]::IsNullOrWhiteSpace($observed)) { " Gozlenen: $observed." } else { '' }

    return "$statePrefix Olay Senaryosu ($title): Tehdit aktoru $vector uzerinden ilerleyebilir. Teknik Etki: $techImpact. Is Etkisi: $businessImpact.$expectedNote$observedNote".Trim()
}

function Normalize-ReportPayload {
    param([hashtable]$Payload)

    $testName = [string]$Payload.test_name
    $currentFinding = Get-FirstMeaningfulText -Candidates @($Payload.message, $Payload.details) -TestName $testName
    if ([string]::IsNullOrWhiteSpace($currentFinding)) { $currentFinding = 'The detected state could not be reported clearly.' }

    $findingDetails = Get-FirstMeaningfulText -Candidates @(
        $Payload.finding_details,
        $Payload.manual_check_expected,
        $Payload.impact,
        $Payload.details,
        $Payload.test_name
    ) -TestName $testName
    if ([string]::IsNullOrWhiteSpace($findingDetails)) { $findingDetails = $currentFinding }
    if ($findingDetails.ToLower() -eq $currentFinding.ToLower()) {
        $findingDetails = Get-FirstMeaningfulText -Candidates @($Payload.manual_check_expected, $Payload.impact, $Payload.test_name) -TestName $testName
        if ([string]::IsNullOrWhiteSpace($findingDetails)) { $findingDetails = $currentFinding }
    }

    $impactText = Get-FirstMeaningfulText -Candidates @($Payload.impact, $Payload.message, $Payload.details) -TestName $testName
    $impactText = Get-ImpactNarrative -TestName $testName -CurrentImpact $impactText -Status ([string]$Payload.status) -ExpectedValue ([string]$Payload.expected_value) -ObservedValue ([string]$Payload.observed_value)

    $remediationText = Get-FirstMeaningfulText -Candidates @($Payload.remediation) -TestName $testName
    if ([string]::IsNullOrWhiteSpace($remediationText)) {
        $remediationText = "$testName icin kurum politikasina uygun guvenli deger uygulanmali ve test yeniden calistirilmalidir."
    }

    $Payload.message = $currentFinding
    $Payload.details = Sanitize-ReportText -Value $Payload.details -TestName $testName
    $sanitizedObserved = Sanitize-ReportText -Value $Payload.observed_value -TestName $testName
    $sanitizedEvidence = Get-FirstMeaningfulText -Candidates @(
        $Payload.evidence_output,
        $Payload.details,
        $Payload.message
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
    $Payload.impact = $impactText
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
    if ($t -match '(?i)\b(secure|off|system|fixed_servers|pac_script)\b') {
        return @{ kind = 'enum'; value = $Matches[1].ToLowerInvariant() }
    }

    return @{ kind = ''; value = '' }
}

function Get-DefaultEvidenceType {
    param([string]$VerifiedVia)

    $vv = [string]$VerifiedVia
    if ($vv -match 'Registry') { return 'registry_policy_scan' }
    if ($vv -match 'Preferences') { return 'preferences_file' }
    if ($vv -match 'Process Command Line') { return 'runtime_process_flags' }
    return 'result_snapshot'
}

function Get-DefaultStatusReason {
    param([string]$Status)

    switch ([string]$Status) {
        'PASSED' { return 'expected_condition_met' }
        'FAILED' { return 'expected_condition_not_met' }
        'UNKNOWN' { return 'verification_inconclusive' }
        default { return 'not_classified' }
    }
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

function Get-ChromeManualCheckGuidance {
    param(
        [string]$TestId,
        [hashtable]$TestConfig,
        [hashtable]$Result
    )

    $name = [string]$TestConfig.Name
    $status = [string]$Result.status

    $check = "Chrome policy ve davranis kontrolunu birlikte dogrulayin."
    $steps = @(
        "chrome://policy ekraninda ilgili policy anahtarini kontrol edin.",
        "Kontrolle ilgili davranisi Chrome arayuzunden manuel deneyin.",
        "Policy ve davranis tutarliysa PASS, degilse FAIL olarak kaydedin."
    )
    $command = "Start-Process chrome.exe 'chrome://policy'"
    $expected = "Policy degeri ile gercek davranis birbiriyle uyumlu olmali."

    if ($name -match 'Incognito|Private') {
        $check = "Incognito kisitini policy + davranissal test ile dogrulayin."
        $steps = @(
            "chrome://policy uzerinden IncognitoModeAvailability degerini kontrol edin.",
            "Ctrl+Shift+N ile Incognito pencere acmayi deneyin.",
            "Acilmiyorsa veya kurum yonetimi uyarisi varsa PASS olarak not edin."
        )
        $expected = "Incognito kurum politikasina uygun bicimde kisitli olmali."
    } elseif ($name -match 'Extension') {
        $check = "Extension governance kontrolunu policy + magazada kurulum denemesi ile dogrulayin."
        $steps = @(
            "chrome://policy ekraninda Extension* ve ExtensionSettings anahtarlarini kontrol edin.",
            "Chrome Web Store uzerinden test eklentisi kurmayi deneyin.",
            "Kurulum engelleniyor veya sadece izinli eklentiler yuklenebiliyorsa PASS olarak not edin."
        )
        $expected = "Yetkisiz eklenti kurulumu engellenmeli, izinli eklentiler policy ile yonetilmeli."
    } elseif ($name -match 'Password') {
        $check = "Parola yoneticisi kisitini policy ve ayarlar ekrani ile dogrulayin."
        $steps = @(
            "chrome://policy ekraninda PasswordManagerEnabled degerini kontrol edin.",
            "Ayarlar > Otomatik Doldurma > Parolalar ekranina gidin.",
            "Parola kaydetme secenegi devre disi ise PASS olarak not edin."
        )
        $expected = "Parola kaydetme davranisi kurum politikasiyla uyumlu olmali."
    } elseif ($name -match 'Developer') {
        $check = "Developer Tools kisitini policy ve kisayol ile dogrulayin."
        $steps = @(
            "chrome://policy ekraninda DeveloperToolsAvailability degerini kontrol edin.",
            "F12 veya Ctrl+Shift+I ile DevTools acmayi deneyin.",
            "Engelleniyorsa veya policy geregi kisitliysa PASS olarak not edin."
        )
        $expected = "DevTools kurum politikasina gore engelli veya kisitli olmali."
    } elseif ($name -match 'Download') {
        $check = "Indirme kisitini policy ve dosya indirme denemesi ile dogrulayin."
        $steps = @(
            "chrome://policy ekraninda DownloadRestrictions degerini kontrol edin.",
            "Guvenli bir test dosyasi indirerek davranisi gozlemleyin.",
            "Beklenen blok/prompt davranisi varsa PASS olarak not edin."
        )
        $expected = "Indirme davranisi kurumsal kisitlarla uyumlu olmali."
    } elseif ($name -match 'Sync') {
        $check = "Sync kisitini policy ve hesap ekranindan dogrulayin."
        $steps = @(
            "chrome://policy ekraninda SyncDisabled degerini kontrol edin.",
            "Chrome profil/sync ekraninda senkronizasyon seceneklerini inceleyin.",
            "Kurum beklentisine aykiri sync acikligi yoksa PASS olarak not edin."
        )
        $expected = "Sync davranisi kurumsal guvenlik gereksinimine uygun olmalÄ±."
    }

    $note = if ($status -eq 'UNKNOWN') {
        "! The automated test could not produce a definitive decision. Close this item with manual validation and, if needed, review GPO/MDM and proxy/SSE logs together."
    } else {
        "Otomatik bulgu mevcut; manuel kontrol ikinci kanit amaciyla uygulanir."
    }

    return @{
        manual_check = $check
        manual_check_steps = $steps
        manual_check_command = $command
        manual_check_expected = $expected
        manual_check_note = $note
    }
}

function Get-ChromePolicyValue {
    param([string]$KeyName)

    $paths = @(
        "HKCU:\Software\Policies\Google\Chrome",
        "HKLM:\Software\Policies\Google\Chrome",
        "HKLM:\Software\WOW6432Node\Policies\Google\Chrome"
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

function Get-ChromePreferences {
    $prefPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences"
    try {
        if (Test-Path $prefPath) {
            $prefs = Get-Content $prefPath -Raw | ConvertFrom-Json -ErrorAction Stop
            return @{ found = $true; prefs = $prefs; source = $prefPath }
        }
    } catch {}

    return @{ found = $false; prefs = $null; source = $prefPath }
}

function Get-ChromeCommandLines {
    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" -ErrorAction SilentlyContinue
        if ($null -eq $procs) { return @() }
        return @($procs | ForEach-Object { $_.CommandLine })
    } catch {
        return @()
    }
}

function Test-C001 {
    $r = Get-ChromePolicyValue -KeyName "IncognitoModeAvailability"
    if (-not $r.found) {
        return @{ 
            status = "FAILED"
            message = "Incognito policy not set"
            details = "IncognitoModeAvailability policy missing"
            test_method = "Multi-path registry key lookup (HKCU/HKLM/WOW6432Node) + policy value evaluation (0/1/2)."
            rationale = "Kurumsal ortamlarda Incognito oturumu sadece yonetim kontrolu altinda kullanilmali."
            impact = "Incognito aciksa, oturum ve veri sizdirmasi kontrolleri zayiflayabilir."
            finding_details = "IncognitoModeAvailability policy anahtari bulunamadi; kontrol policy dagitim kaynaginda tanimlanmamis."
            layer_1_status = "FAILED"
            layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
            layer_1_details = "HKLM:\Software\Policies\Google\Chrome\IncognitoModeAvailability not found"
            remediation = "IncognitoModeAvailability policy degerini GPO/MDM tarafinda konfigurasyonu yapini ve Disabled (1) veya Forced Off (2) olarak ayarlayin."
            reference = "https://chromeenterprise.google/policies/#IncognitoModeAvailability"
        }
    }

    $v = [int]$r.value
    $passed = ($v -eq 1 -or $v -eq 2)
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Incognito restricted" } else { "Incognito available" }
        details = "$($r.source)\\IncognitoModeAvailability = $v"
        test_method = "Multi-path registry key lookup (HKCU/HKLM/WOW6432Node) + policy value evaluation (0/1/2)."
        rationale = "Kurumsal ortamlarda Incognito oturumu sadece yonetim kontrolu altinda kullanilmali."
        impact = if ($passed) { "Incognito oturumu kurumsal politika ile sinirlandirilmis gorunuyor." } else { "Incognito aciksa, oturum ve veri sizdirmasi kontrolleri zayiflayabilir." }
        finding_details = "IncognitoModeAvailability = $v (1=Disabled, 2=Forced Off, 0=Allowed)"
        layer_1_status = "PASSED"
        layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
        layer_1_details = "$($r.source)\\IncognitoModeAvailability = $v"
        remediation = "IncognitoModeAvailability policy degerini Disabled (1) veya Forced Off (2) olarak ayarlayin."
        reference = "https://chromeenterprise.google/policies/#IncognitoModeAvailability"
    }
}

function Test-C002 {
    $r = Get-ChromePolicyValue -KeyName "PasswordManagerEnabled"
    if (-not $r.found) {
        return @{
            status = "FAILED"
            message = "Password manager policy missing"
            details = "PasswordManagerEnabled not configured"
            test_method = "Registry policy lookup (HKCU/HKLM) + boolean value evaluation."
            rationale = "Sifreler tarayici tarafinda saklandiginda, endpointin ele gecmesi durumunda kullanici hesaplari riske girer."
            impact = "Parola yoneticisi aciksa, kurumsal sifreler local depolama ile riske girer."
            finding_details = "PasswordManagerEnabled policy anahtari bulunamadi; kontrol policy dagitim kaynaginda tanimlanmamis."
            layer_1_status = "FAILED"
            layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
            layer_1_details = "HKLM:\Software\Policies\Google\Chrome\PasswordManagerEnabled not found"
            remediation = "PasswordManagerEnabled policy degerini Disabled (0) olarak ayarlayin."
            reference = "https://chromeenterprise.google/policies/#PasswordManagerEnabled"
        }
    }

    $passed = ($r.value -eq 0 -or $r.value -eq $false)
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Password manager disabled" } else { "Password manager enabled" }
        details = "$($r.source)\\PasswordManagerEnabled = $($r.value)"
        test_method = "Registry policy lookup (HKCU/HKLM) + boolean value evaluation."
        rationale = "Sifreler tarayici tarafinda saklandiginda, endpointin ele gecmesi durumunda kullanici hesaplari riske girer."
        impact = if ($passed) { "Parola yoneticisi devre disi; kurumsal sifre yonetimi risk altinda degil." } else { "Parola yoneticisi aciksa, kurumsal sifreler local depolama ile riske girer." }
        finding_details = "PasswordManagerEnabled = $($r.value) (0=Disabled, 1=Enabled)"
        layer_1_status = "PASSED"
        layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
        layer_1_details = "$($r.source)\\PasswordManagerEnabled = $($r.value)"
        remediation = "PasswordManagerEnabled policy degerini Disabled (0) olarak ayarlayin."
        reference = "https://chromeenterprise.google/policies/#PasswordManagerEnabled"
    }
}

function Test-C003 {
    $r = Get-ChromePolicyValue -KeyName "DeveloperToolsAvailability"
    if (-not $r.found) {
        return @{
            status = "FAILED"
            message = "Developer tools policy missing"
            details = "DeveloperToolsAvailability not configured"
            test_method = "Registry policy lookup (HKCU/HKLM) + integer value evaluation (0/1/2)."
            rationale = "DevTools'un acik birakilmasi, ic oto kontrol baypasi ve kod degistirme imkani tanir."
            impact = "DevTools aciksa, endpoint guvenlik kontrolleri baypas edilebilir."
            finding_details = "DeveloperToolsAvailability policy anahtari bulunamadi."
            layer_1_status = "FAILED"
            layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
            layer_1_details = "HKLM:\Software\Policies\Google\Chrome\DeveloperToolsAvailability not found"
            remediation = "DeveloperToolsAvailability policy degerini Disallowed (2) olarak ayarlayin."
            reference = "https://chromeenterprise.google/policies/#DeveloperToolsAvailability"
        }
    }

    $passed = ([int]$r.value -eq 2)
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Developer tools restricted" } else { "Developer tools allowed" }
        details = "$($r.source)\\DeveloperToolsAvailability = $($r.value)"
        test_method = "Registry policy lookup (HKCU/HKLM) + integer value evaluation (0/1/2)."
        rationale = "DevTools'un acik birakilmasi, ic oto kontrol baypasi ve kod degistirme imkani tanir."
        impact = if ($passed) { "DevTools engellenmis; guvenlik kontrolleri baypas riski asgariye indirgenmiÅŸtir." } else { "DevTools aciksa, endpoint guvenlik kontrolleri baypas edilebilir." }
        finding_details = "DeveloperToolsAvailability = $($r.value) (0=Allowed, 1=Disallowed except for sites, 2=Disallowed)"
        layer_1_status = "PASSED"
        layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
        layer_1_details = "$($r.source)\\DeveloperToolsAvailability = $($r.value)"
        remediation = "DeveloperToolsAvailability policy degerini Disallowed (2) olarak ayarlayin."
        reference = "https://chromeenterprise.google/policies/#DeveloperToolsAvailability"
    }
}

function Test-C004 {
    $r = Get-ChromePolicyValue -KeyName "SyncDisabled"
    if (-not $r.found) {
        return @{
            status = "FAILED"
            message = "Sync policy missing"
            details = "SyncDisabled not configured"
            test_method = "Registry policy lookup (HKCU/HKLM) + boolean value evaluation."
            rationale = "Chrome Sync, tarayici verisi (sifreler, yer imler, geÃ§is) bulut ile senkronize etmektedir; kurumsal ortamlarda kontrol altinda olmali."
            impact = "Sync aciksa, kurumsal veriler sadece kullanici kontrolu altinda buluta akis saÄŸlayabilir."
            finding_details = "SyncDisabled policy anahtari bulunamadi."
            layer_1_status = "FAILED"
            layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
            layer_1_details = "HKLM:\Software\Policies\Google\Chrome\SyncDisabled not found"
            remediation = "SyncDisabled policy degerini Enabled (true/1) olarak ayarlayin."
            reference = "https://chromeenterprise.google/policies/#SyncDisabled"
        }
    }

    $passed = ([int]$r.value -eq 1 -or $r.value -eq $true)
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Sync disabled" } else { "Sync enabled" }
        details = "$($r.source)\\SyncDisabled = $($r.value)"
        test_method = "Registry policy lookup (HKCU/HKLM) + boolean value evaluation."
        rationale = "Chrome Sync, tarayici verisi (sifreler, yer imler, geÃ§is) bulut ile senkronize etmektedir; kurumsal ortamlarda kontrol altinda olmali."
        impact = if ($passed) { "Sync devre disi; tarayici verisi bulut senkronizasyonundan korunmaktadÄ±r." } else { "Sync aciksa, kurumsal veriler sadece kullanici kontrolu altinda buluta akis saÄŸlayabilir." }
        finding_details = "SyncDisabled = $($r.value) (true/1=Disabled, false/0=Enabled)"
        layer_1_status = "PASSED"
        layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
        layer_1_details = "$($r.source)\\SyncDisabled = $($r.value)"
        remediation = "SyncDisabled policy degerini Enabled (true/1) olarak ayarlayin."
        reference = "https://chromeenterprise.google/policies/#SyncDisabled"
    }
}

function Test-C005 {
    $r = Get-ChromePolicyValue -KeyName "SafeBrowsingProtectionLevel"
    if (-not $r.found) {
        return @{
            status = "FAILED"
            message = "Safe browsing policy missing"
            details = "SafeBrowsingProtectionLevel not configured"
            test_method = "Registry policy lookup (HKCU/HKLM) + integer value evaluation (0/1/2)."
            rationale = "Safe Browsing, zararlÄ± web sitelerini, indirmeleri ve uzantilari tespit edip uyarir."
            impact = "Safe Browsing devre disi yapilirsa, kullanicilar kÃ¶tÃ¼ amaÃ§li web siteleri ve zararlÄ± dosyalara direkt olarak karsilasabilir."
            finding_details = "SafeBrowsingProtectionLevel policy anahtari bulunamadi."
            layer_1_status = "FAILED"
            layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
            layer_1_details = "HKLM:\Software\Policies\Google\Chrome\SafeBrowsingProtectionLevel not found"
            remediation = "SafeBrowsingProtectionLevel policy degerini Standard (1) veya Enhanced (2) olarak ayarlayin."
            reference = "https://chromeenterprise.google/policies/#SafeBrowsingProtectionLevel"
        }
    }

    $passed = ([int]$r.value -ge 1)
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Safe browsing enforced" } else { "Safe browsing weak" }
        details = "$($r.source)\\SafeBrowsingProtectionLevel = $($r.value)"
        test_method = "Registry policy lookup (HKCU/HKLM) + integer value evaluation (0/1/2)."
        rationale = "Safe Browsing, zararlÄ± web sitelerini, indirmeleri ve uzantilari tespit edip uyarir."
        impact = if ($passed) { "Safe Browsing aktif; kÃ¶tÃ¼ amaÃ§li web sitesi ve zararlÄ± dosya korumasÄ± saglanmaktadÄ±r." } else { "Safe Browsing devre disi; kÃ¶tÃ¼ amaÃ§li web siteleri riskinin yÃ¼ksek olduÄŸu durum." }
        finding_details = "SafeBrowsingProtectionLevel = $($r.value) (0=Disabled, 1=Standard, 2=Enhanced)"
        layer_1_status = "PASSED"
        layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
        layer_1_details = "$($r.source)\\SafeBrowsingProtectionLevel = $($r.value)"
        remediation = "SafeBrowsingProtectionLevel policy degerini Standard (1) veya Enhanced (2) olarak ayarlayin."
        reference = "https://chromeenterprise.google/policies/#SafeBrowsingProtectionLevel"
    }
}

function Test-C006 {
    $paths = @(
        "HKCU:\Software\Policies\Google\Chrome",
        "HKLM:\Software\Policies\Google\Chrome",
        "HKLM:\Software\WOW6432Node\Policies\Google\Chrome"
    )

    $governanceKeys = @(
        "ExtensionInstallBlocklist",
        "ExtensionInstallAllowlist",
        "ExtensionInstallForcelist",
        "ExtensionSettings",
        "BlockExternalExtensions",
        "ExtensionInstallSources"
    )

    foreach ($path in $paths) {
        if (Test-Path $path) {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($null -eq $props) { continue }
            $present = @($props.PSObject.Properties.Name | Where-Object { $governanceKeys -contains $_ })
            if ($present.Count -gt 0) {
                return @{
                    status = "PASSED"
                    message = "Extension governance configured"
                    details = "Policy keys found under ${path}: $($present -join ', ')"
                    finding_details = "Extension kurulumu birden fazla policy anahtariyla yonetiliyor."
                    test_method = "Multi-path registry scan + extension governance key discovery."
                    rationale = "Kurumsal ortamlarda extension kontrolu allow/block/force veya ExtensionSettings ile uygulanabilir."
                    impact = "Yonetimsiz extension kurulumu veri sizdirma ve oturum ele gecirme riskini artirir."
                    remediation = "Onayli extension modeli icin allowlist/forcelist/ExtensionSettings politikalari merkezden yonetin."
                    reference = "https://chromeenterprise.google/policies/#ExtensionInstallBlocklist"
                }
            }
        }
    }

    return @{
        status = "FAILED"
        message = "Extension governance key not found locally"
        details = "No extension allow/block/force/settings policy found in HKCU/HKLM/WOW6432Node"
        finding_details = "! Browser-side policy key gorunmuyor. Kurulum kisiti proxy/SSE/CASB veya baska bir ag katmaninda uygulanmis olabilir."
        test_method = "Multi-path registry scan with external-enforcement awareness."
        rationale = "Tek kaynakli registry kontrolu, network katmaninda uygulanan kisitlarda false positive uretebilir."
        impact = "Davranissal olarak extension market erisimi engelli olsa bile local policy izi olmayabilir."
        remediation = "Chrome policy dagitim kaynagini (GPO/MDM) ve ag katmani kisitlarini birlikte dokumante ederek ikili dogrulama uygulayin."
        reference = "https://chromeenterprise.google/policies/#ExtensionInstallBlocklist"
        warning_note = "Bu kontrol baska bir guvenlik katmaninda (proxy/SSE/CASB) uygulanmis olabilir."
    }
}

function Test-C007 {
    $r = Get-ChromePolicyValue -KeyName "DownloadRestrictions"
    if (-not $r.found) {
        return @{
            status = "FAILED"
            message = "Download restrictions missing"
            details = "DownloadRestrictions not configured"
            test_method = "Registry policy lookup (HKCU/HKLM) + integer value evaluation (0/1/2/3)."
            rationale = "Indirme kisitlari, zararlÄ± veya yetkisiz yazilim kurulumundan koruma saglar."
            impact = "Indirme kisitlari yoksa, kullanicilar zararlÄ± dosya indirebilir ve cihazlari enfekte edebilir."
            finding_details = "DownloadRestrictions policy anahtari bulunamadi."
            layer_1_status = "FAILED"
            layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
            layer_1_details = "HKLM:\Software\Policies\Google\Chrome\DownloadRestrictions not found"
            remediation = "DownloadRestrictions policy degerini uygun seviyede (1 Block Dangerous, 2 Block Potentially Unwanted, 3 Block All) ayarlayin."
            reference = "https://chromeenterprise.google/policies/#DownloadRestrictions"
        }
    }

    $passed = ([int]$r.value -ge 1)
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Download restrictions active" } else { "Download restrictions weak" }
        details = "$($r.source)\\DownloadRestrictions = $($r.value)"
        test_method = "Registry policy lookup (HKCU/HKLM) + integer value evaluation (0/1/2/3)."
        rationale = "Indirme kisitlari, zararlÄ± veya yetkisiz yazilim kurulumundan koruma saglar."
        impact = if ($passed) { "Indirme kisitlari aktif; zararlÄ± dosya indirilmesi riskine karÅŸi koruma saglanmaktadÄ±r." } else { "Indirme kisitlari yoksa, kullanicilar zararlÄ± dosya indirebilir." }
        finding_details = "DownloadRestrictions = $($r.value) (0=None, 1=Block Dangerous, 2=Block Potentially Unwanted, 3=Block All)"
        layer_1_status = "PASSED"
        layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
        layer_1_details = "$($r.source)\\DownloadRestrictions = $($r.value)"
        remediation = "DownloadRestrictions policy degerini uygun seviyede (1 Block Dangerous, 2 Block Potentially Unwanted, 3 Block All) ayarlayin."
        reference = "https://chromeenterprise.google/policies/#DownloadRestrictions"
    }
}

function Test-C008 {
    $r = Get-ChromePolicyValue -KeyName "SitePerProcess"
    if (-not $r.found) {
        return @{
            status = "FAILED"
            message = "Site isolation policy missing"
            details = "SitePerProcess not configured"
            test_method = "Registry policy lookup (HKCU/HKLM) + boolean value evaluation."
            rationale = "Site Isolation, her siteyi ayri bir process'te calistirarak XSS ve Spectre-tipi saldirilar acarsindan korur."
            impact = "Site Isolation devre disi yapilirsa, bir siteyi kÃ¶tÃ¼ amaÃ§li kod kÃ¶tÃ¼ye kullanarak diger sitelerdeki veriye erisebilir."
            finding_details = "SitePerProcess policy anahtari bulunamadi."
            layer_1_status = "FAILED"
            layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
            layer_1_details = "HKLM:\Software\Policies\Google\Chrome\SitePerProcess not found"
            remediation = "SitePerProcess policy degerini Enabled (true/1) olarak ayarlayin."
            reference = "https://chromeenterprise.google/policies/#SitePerProcess"
        }
    }

    $passed = ($r.value -eq 1 -or $r.value -eq $true)
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Site isolation enabled" } else { "Site isolation disabled" }
        details = "$($r.source)\\SitePerProcess = $($r.value)"
        test_method = "Registry policy lookup (HKCU/HKLM) + boolean value evaluation."
        rationale = "Site Isolation, her siteyi ayri bir process'te calistirarak XSS ve Spectre-tipi saldirilar acarsindan korur."
        impact = if ($passed) { "Site Isolation aktif; site izolasyonu saglanmaktadÄ±r ve XSS saldiri riski asgariye indirgenmiÅŸtir." } else { "Site Isolation devre disi; XSS ve Spectre saldiri riski yÃ¼ksektir." }
        finding_details = "SitePerProcess = $($r.value) (true/1=Enabled, false/0=Disabled)"
        layer_1_status = "PASSED"
        layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
        layer_1_details = "$($r.source)\\SitePerProcess = $($r.value)"
        remediation = "SitePerProcess policy degerini Enabled (true/1) olarak ayarlayin."
        reference = "https://chromeenterprise.google/policies/#SitePerProcess"
    }
}

function Test-C009 {
    $r = Get-ChromePolicyValue -KeyName "DnsOverHttpsMode"
    if (-not $r.found) {
        return @{
            status = "FAILED"
            message = "DoH policy missing"
            details = "DnsOverHttpsMode not configured"
            test_method = "Registry policy lookup (HKCU/HKLM) + string value evaluation."
            rationale = "DNS-over-HTTPS (DoH), DNS sorgularini encrypted iletisim uzerinden gÃ¶ndererek privacy ve guvenlik saglar."
            impact = "DoH konfigurasyonu yoksa, DNS sorgulari plain text olarak aktarÄ±labilir ve komÅŸu aglar tarafÄ±ndan gÃ¶zlemlenebilir."
            finding_details = "DnsOverHttpsMode policy anahtari bulunamadi."
            layer_1_status = "FAILED"
            layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
            layer_1_details = "HKLM:\Software\Policies\Google\Chrome\DnsOverHttpsMode not found"
            remediation = "DnsOverHttpsMode policy degerini 'secure' veya kurumsal DoH sunucusunu ayarlayin."
            reference = "https://chromeenterprise.google/policies/#DnsOverHttpsMode"
        }
    }

    $passed = [string]::IsNullOrWhiteSpace([string]$r.value) -eq $false
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "DoH policy configured" } else { "DoH policy empty" }
        details = "$($r.source)\\DnsOverHttpsMode = $($r.value)"
        test_method = "Registry policy lookup (HKCU/HKLM) + string value evaluation."
        rationale = "DNS-over-HTTPS (DoH), DNS sorgularini encrypted iletisim uzerinden gÃ¶ndererek privacy ve guvenlik saglar."
        impact = if ($passed) { "DoH konfigurasyonu saglanmis; DNS sorgulari encrypted aktarÄ±lmaktadÄ±r." } else { "DoH konfigurasyonu yoksa, DNS sorgulari plain text olarak aktarÄ±labilir." }
        finding_details = "DnsOverHttpsMode = '$($r.value)' (empty=Default, 'secure'=Secure mode, 'off'=Off)"
        layer_1_status = "PASSED"
        layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
        layer_1_details = "$($r.source)\\DnsOverHttpsMode = $($r.value)"
        remediation = "DnsOverHttpsMode policy degerini 'secure' veya kurumsal DoH sunucusunu ayarlayin."
        reference = "https://chromeenterprise.google/policies/#DnsOverHttpsMode"
    }
}

function Test-C010 {
    $addr = Get-ChromePolicyValue -KeyName "AutofillAddressEnabled"
    $card = Get-ChromePolicyValue -KeyName "AutofillCreditCardEnabled"

    if (-not $addr.found -and -not $card.found) {
        return @{
            status = "FAILED"
            message = "Autofill policies missing"
            details = "AutofillAddressEnabled and AutofillCreditCardEnabled not configured"
            test_method = "Registry policy lookup (HKCU/HKLM) for Autofill-related policies."
            rationale = "Otomatik doldurma (Autofill), adres ve kart bilgisini siyasetlerin deminlemesine baÄŸlÄ±dÄ±r."
            impact = "Autofill aciksa, kimlik hÄ±rsÄ±zlÄ±ÄŸÄ± ve mali bilgi sizdirmasi riskini artirir."
            finding_details = "AutofillAddressEnabled ve AutofillCreditCardEnabled policy anahtarlari bulunamadi."
            layer_1_status = "FAILED"
            layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
            layer_1_details = "Neither AutofillAddressEnabled nor AutofillCreditCardEnabled found"
            remediation = "Her iki autofill policy'sini Disabled (0) olarak ayarlayin."
            reference = "https://chromeenterprise.google/policies/#AutofillAddressEnabled"
        }
    }

    $addrDisabled = (-not $addr.found) -or ($addr.value -eq 0 -or $addr.value -eq $false)
    $cardDisabled = (-not $card.found) -or ($card.value -eq 0 -or $card.value -eq $false)
    $passed = $addrDisabled -and $cardDisabled

    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Autofill sensitive fields restricted" } else { "Autofill sensitive fields enabled" }
        details = "Address: $($addr.value); CreditCard: $($card.value)"
        test_method = "Registry policy lookup (HKCU/HKLM) for Autofill-related policies."
        rationale = "Otomatik doldurma (Autofill), adres ve kart bilgisini siyasetlerin deminlemesine baÄŸlÄ±dÄ±r."
        impact = if ($passed) { "Autofill hassas alanlar icin devre disi; kimlik bilgisi riski asgariye indirilmiÅŸtir." } else { "Autofill aciksa, kimlik hÄ±rsÄ±zlÄ±ÄŸÄ± ve mali bilgi sizdirmasi riskini artirir." }
        finding_details = "AutofillAddressEnabled = $($addr.value); AutofillCreditCardEnabled = $($card.value)"
        layer_1_status = "PASSED"
        layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
        layer_1_details = "Address enabled: $(if($addr.found) { $addr.value } else { 'not configured' }); Card enabled: $(if($card.found) { $card.value } else { 'not configured' })"
        remediation = "Her iki autofill policy'sini Disabled (0) olarak ayarlayin."
        reference = "https://chromeenterprise.google/policies/#AutofillAddressEnabled"
    }
}

function Test-C011 {
    $r = Get-ChromePolicyValue -KeyName "BlockThirdPartyCookies"
    if (-not $r.found) {
        return @{
            status = "FAILED"
            message = "Third-party cookie policy missing"
            details = "BlockThirdPartyCookies not configured"
            test_method = "Registry policy lookup (HKCU/HKLM) + boolean value evaluation."
            rationale = "Ucuncu taraf cookies, web sitelerinde cihazÄ±n her yerinde takip etmek iÃ§in kullanÄ±labilir."
            impact = "Ucuncu taraf cookies aciksa, kullanicilar web tarama aktiviteleri tarafÄ±ndan yaygÄ±n takip edilebilir."
            finding_details = "BlockThirdPartyCookies policy anahtari bulunamadi."
            layer_1_status = "FAILED"
            layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
            layer_1_details = "HKLM:\Software\Policies\Google\Chrome\BlockThirdPartyCookies not found"
            remediation = "BlockThirdPartyCookies policy degerini Enabled (true/1) olarak ayarlayin."
            reference = "https://chromeenterprise.google/policies/#BlockThirdPartyCookies"
        }
    }

    $passed = ($r.value -eq 1 -or $r.value -eq $true)
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Third-party cookies blocked" } else { "Third-party cookies allowed" }
        details = "$($r.source)\\BlockThirdPartyCookies = $($r.value)"
        test_method = "Registry policy lookup (HKCU/HKLM) + boolean value evaluation."
        rationale = "Ucuncu taraf cookies, web sitelerinde cihazÄ±n her yerinde takip etmek iÃ§in kullanÄ±labilir."
        impact = if ($passed) { "Ucuncu taraf cookies engelli; cihazda tarama faaliyetlerinin izlenmesi riski asgariye indirilmiÅŸtir." } else { "Ucuncu taraf cookies aciksa, kullanicilar web tarama aktiviteleri tarafÄ±ndan yaygÄ±n takip edilebilir." }
        finding_details = "BlockThirdPartyCookies = $($r.value) (true/1=Blocked, false/0=Allowed)"
        layer_1_status = "PASSED"
        layer_1_method = "Registry Policy Lookup (HKCU/HKLM)"
        layer_1_details = "$($r.source)\\BlockThirdPartyCookies = $($r.value)"
        remediation = "BlockThirdPartyCookies policy degerini Enabled (true/1) olarak ayarlayin."
        reference = "https://chromeenterprise.google/policies/#BlockThirdPartyCookies"
    }
}

function Test-C012 {
    $cmds = Get-ChromeCommandLines
    if ($cmds.Count -eq 0) {
        return @{ status = "UNKNOWN"; message = "Chrome not running"; details = "Runtime flags cannot be evaluated" }
    }

    $riskyFlags = @("--no-sandbox", "--disable-web-security", "--allow-running-insecure-content")
    $hits = @()

    foreach ($cmd in $cmds) {
        foreach ($flag in $riskyFlags) {
            if ($cmd -match [regex]::Escape($flag)) {
                $hits += $flag
            }
        }
    }

    $hits = $hits | Select-Object -Unique

    if ($hits.Count -gt 0) {
        return @{
            status = "FAILED"
            message = "Risky runtime flags found"
            details = "Flags: $($hits -join ', ')"
            test_method = "Live process command-line enumeration (Win32_Process CIM) + risky flag pattern detection."
            rationale = "Tehlikeli runtime bayraklarÄ± (--no-sandbox, --disable-web-security) temel guvenlik kontrollerini devre disi birakirlar."
            impact = "Bu bayraklarla Chrome baslatilirsa, tarayici sandbox korumasÄ± ve web guvenlik Ã¶zellikleri devre disi olur."
            finding_details = "Risky flags detected in live Chrome process(es): $($hits -join ', ')"
            layer_1_status = "FAILED"
            layer_1_method = "Process Runtime Environment (Live)"
            layer_1_details = "Chrome running with risky flags: $($hits -join ', ')"
            remediation = "Chrome'u tehlikeli bayraklarla baslatmayin. Kurumsal ortamda bu bayraklari engellemek icin Group Policy veya startup script'lerini inceleyin."
            reference = "https://chromium.googlesource.com/chromium/src/+/main/docs/linux_sandboxing.md"
        }
    }

    return @{
        status = "PASSED"
        message = "Runtime flags secure"
        details = "No risky Chrome runtime flags detected"
        test_method = "Live process command-line enumeration (Win32_Process CIM) + risky flag pattern detection."
        rationale = "Tehlikeli runtime bayraklarÄ±nÄ±n yokluÄŸu, tarayicinin guvenlik kontrollerinin aktif olduÄŸunu gÃ¶sterir."
        impact = "Chrome guvenli bayraklarla baslatiliyor; sandbox ve web guvenlik Ã¶zellikleri aktif kalÄ±yor."
        finding_details = "No risky runtime flags found in live Chrome processes"
        layer_1_status = "PASSED"
        layer_1_method = "Process Runtime Environment (Live)"
        layer_1_details = "Chrome process(es) running without --no-sandbox, --disable-web-security, or similar risky flags"
        remediation = "Mevcut durumu koru. Chrome baslatma talimatlarÄ±nda tehlikeli bayraklarin ve ortam deÄŸiÅŸkenlerinin kontrolÃ¼ devam et."
        reference = "https://chromium.googlesource.com/chromium/src/+/main/docs/linux_sandboxing.md"
    }
}

function Test-C013 {
    $r = Get-ChromePolicyValue -KeyName "ProxyMode"
    if (-not $r.found) {
        return @{
            status = "FAILED"
            message = "Proxy mode policy missing"
            details = "ProxyMode not configured"
            test_method = "Registry policy lookup (HKCU/HKLM) + string value evaluation."
            rationale = "Proxy zorunlulugu trafik denetimi, DLP ve merkezi loglama icin kritik bir kontroldur."
            impact = "Proxy mode tanimli degilse tarayici trafigi kurumsal denetim katmanlarini atlayabilir."
            finding_details = "ProxyMode policy anahtari bulunamadi."
            remediation = "ProxyMode policy degerini fixed_servers, pac_script veya system olarak ayarlayin."
            reference = "https://chromeenterprise.google/policies/#ProxyMode"
        }
    }

    $mode = ([string]$r.value).ToLowerInvariant()
    $passed = @('fixed_servers', 'pac_script', 'system') -contains $mode
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Proxy mode hardened" } else { "Proxy mode weak" }
        details = "$($r.source)\\ProxyMode = $($r.value)"
        test_method = "Registry policy lookup (HKCU/HKLM) + string value evaluation."
        rationale = "Proxy zorunlulugu trafik denetimi, DLP ve merkezi loglama icin kritik bir kontroldur."
        impact = if ($passed) { "Proxy mode merkezi ag denetimine uygun sekilde tanimli." } else { "Proxy mode direct/off ise trafik denetim katmanlari bypass edilebilir." }
        finding_details = "ProxyMode = '$($r.value)'"
        remediation = "ProxyMode policy degerini fixed_servers, pac_script veya system olarak ayarlayin."
        reference = "https://chromeenterprise.google/policies/#ProxyMode"
    }
}

function Test-C014 {
    $r = Get-ChromePolicyValue -KeyName "QuicAllowed"
    if (-not $r.found) {
        return @{
            status = "FAILED"
            message = "QUIC control policy missing"
            details = "QuicAllowed not configured"
            test_method = "Registry policy lookup (HKCU/HKLM) + boolean value evaluation."
            rationale = "QUIC kontrolu, inspection ve TLS gorunurlugu beklentileri icin kurum politikasina gore sinirlanabilir."
            impact = "QuicAllowed anahtari yoksa endpointler arasi transport davranisi standartlastirilamayabilir."
            finding_details = "QuicAllowed policy anahtari bulunamadi."
            remediation = "QuicAllowed policy degerini kurum standartina gore false (0) olarak ayarlayin."
            reference = "https://chromeenterprise.google/policies/#QuicAllowed"
        }
    }

    $v = [string]$r.value
    $passed = ($v -eq '0' -or $v.ToLowerInvariant() -eq 'false')
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "QUIC disabled" } else { "QUIC enabled" }
        details = "$($r.source)\\QuicAllowed = $($r.value)"
        test_method = "Registry policy lookup (HKCU/HKLM) + boolean value evaluation."
        rationale = "QUIC kontrolu, inspection ve TLS gorunurlugu beklentileri icin kurum politikasina gore sinirlanabilir."
        impact = if ($passed) { "QUIC devre disi; denetimli transport standardi korunuyor." } else { "QUIC acik; inspection/visibility beklentileriyle uyumsuzluk riski olabilir." }
        finding_details = "QuicAllowed = $($r.value)"
        remediation = "QuicAllowed policy degerini kurum standartina gore false (0) olarak ayarlayin."
        reference = "https://chromeenterprise.google/policies/#QuicAllowed"
    }
}

function Test-C015 {
    $r = Get-ChromePolicyValue -KeyName "InsecureContentAllowedForUrls"
    if (-not $r.found) {
        return @{
            status = "PASSED"
            message = "No insecure-content allowlist"
            details = "InsecureContentAllowedForUrls not configured"
            test_method = "Registry policy lookup (HKCU/HKLM) + exception list presence check."
            rationale = "Mixed/insecure content istisnalari MITM ve downgrade riskini artirabilir."
            impact = "Istisna listesi yok; insecure content bypass riski azaltilmis durumda."
            finding_details = "InsecureContentAllowedForUrls policy anahtari bulunamadi."
            remediation = "InsecureContentAllowedForUrls istisna listesi tanimlamayin."
            reference = "https://chromeenterprise.google/policies/#InsecureContentAllowedForUrls"
        }
    }

    $raw = [string]$r.value
    $hasValue = -not [string]::IsNullOrWhiteSpace($raw)
    return @{
        status = if ($hasValue) { "FAILED" } else { "PASSED" }
        message = if ($hasValue) { "Insecure-content allowlist present" } else { "Insecure-content allowlist empty" }
        details = "$($r.source)\\InsecureContentAllowedForUrls = $($r.value)"
        test_method = "Registry policy lookup (HKCU/HKLM) + exception list presence check."
        rationale = "Mixed/insecure content istisnalari MITM ve downgrade riskini artirabilir."
        impact = if ($hasValue) { "Istisna listesi tanimli; guvenli kanal zorlamasi zayiflayabilir." } else { "Istisna degeri bos; guvenli kanal zorlamasi korunuyor." }
        finding_details = "InsecureContentAllowedForUrls = '$($r.value)'"
        remediation = "InsecureContentAllowedForUrls istisnalarini kaldirin."
        reference = "https://chromeenterprise.google/policies/#InsecureContentAllowedForUrls"
    }
}

function Test-C016 {
    $keys = @(
        'CertificateTransparencyEnforcementDisabledForCas',
        'CertificateTransparencyEnforcementDisabledForLegacyCas',
        'CertificateTransparencyEnforcementDisabledForUrls'
    )

    $hits = @()
    foreach ($k in $keys) {
        $r = Get-ChromePolicyValue -KeyName $k
        if ($r.found -and -not [string]::IsNullOrWhiteSpace([string]$r.value)) {
            $hits += "$k=$($r.value)"
        }
    }

    if ($hits.Count -gt 0) {
        return @{
            status = "FAILED"
            message = "Certificate transparency bypass list present"
            details = "Configured exception(s): $($hits -join '; ')"
            test_method = "Registry policy scan for certificate-transparency bypass exception keys."
            rationale = "Certificate Transparency bypass listeleri sahte sertifika riskini arttirabilir."
            impact = "Bypass listesi varsa sertifika guven zinciri kontrolu zayiflayabilir."
            finding_details = "Configured CT bypass: $($hits -join '; ')"
            remediation = "CertificateTransparencyEnforcementDisabledFor* policy degerlerini temizleyin."
            reference = "https://chromeenterprise.google/policies/#CertificateTransparencyEnforcementDisabledForCas"
        }
    }

    return @{
        status = "PASSED"
        message = "Certificate transparency bypass list clean"
        details = "No CertificateTransparencyEnforcementDisabledFor* policy with value found"
        test_method = "Registry policy scan for certificate-transparency bypass exception keys."
        rationale = "Certificate Transparency bypass listeleri sahte sertifika riskini arttirabilir."
        impact = "Bypass listesi yok; sertifika guven zinciri kontrolu korunuyor."
        finding_details = "No CT bypass exception configured"
        remediation = "Mevcut durumu koruyun; bypass listesi tanimlamayin."
        reference = "https://chromeenterprise.google/policies/#CertificateTransparencyEnforcementDisabledForCas"
    }
}

function Get-ChromePolicyStore {
    $paths = @(
        "HKCU:\Software\Policies\Google\Chrome",
        "HKLM:\Software\Policies\Google\Chrome",
        "HKLM:\Software\WOW6432Node\Policies\Google\Chrome"
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

function Get-CisDefinitionFromLine {
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
    } elseif ($Line -match '(?i)Explicitly\s+Configured') {
        $expected = 'Configured'
    } elseif ($Line -match '(?i)Is\s+Properly\s+Configured') {
        $expected = 'Properly Configured'
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

function Get-CisPolicyMapIndex {
    $mapPath = Join-Path $PSScriptRoot 'chrome_cis_policy_map.json'
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

function Get-CisSeverity {
    param([hashtable]$Definition)

    $t = ($Definition.title + " " + $Definition.expected).ToLowerInvariant()
    if ($t -match 'safe browsing|password|remote debugging|site isolation|download|third.?party cookies|synchronization|tls|proxy') {
        return 'HIGH'
    }
    if ($t -match 'remote access|insecure|autofill|clipboard|certificate|ocsp|hsts') {
        return 'MEDIUM'
    }
    return 'LOW'
}

function Test-PolicyExpectation {
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

    if ($Expected -match "(?i)except\s*'?(0)'?") {
        $ok = $vLower -ne '0'
        return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = "Expected non-zero, actual: $vStr" }
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

    if ($Expected -match '\*') {
        $ok = $vStr -match '\*'
        return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = "Expected wildcard pattern, actual: $vStr" }
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

function Get-ChromePolicyChildValues {
    param([string]$ChildKeyName)

    $paths = @(
        "HKCU:\Software\Policies\Google\Chrome",
        "HKLM:\Software\Policies\Google\Chrome",
        "HKLM:\Software\WOW6432Node\Policies\Google\Chrome"
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

function Get-ChromeExtensionIntentEvidence {
    param([hashtable]$PolicyStore)

    $evidence = @{
        has_extension_settings = $false
        settings_valid_json = $false
        settings_error = ''
        has_global_rule = $false
        has_global_block_mode = $false
        install_sources = @()
        has_restricted_sources = $false
        has_broad_sources = $false
    }

    if (-not $PolicyStore.ContainsKey('ExtensionSettings')) {
        return $evidence
    }

    $rawSettings = [string]$PolicyStore['ExtensionSettings'].value
    if ([string]::IsNullOrWhiteSpace($rawSettings)) {
        return $evidence
    }

    $evidence.has_extension_settings = $true
    try {
        $settingsObj = $rawSettings | ConvertFrom-Json -ErrorAction Stop
        $evidence.settings_valid_json = $true

        $globalRule = $settingsObj.PSObject.Properties | Where-Object { $_.Name -eq '*' } | Select-Object -First 1
        if ($null -eq $globalRule) {
            return $evidence
        }

        $evidence.has_global_rule = $true
        $globalValue = $globalRule.Value
        $mode = [string]$globalValue.installation_mode
        if ($mode -eq 'blocked') {
            $evidence.has_global_block_mode = $true
        }

        $sources = @($globalValue.install_sources)
        $normalizedSources = @($sources | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $evidence.install_sources = $normalizedSources

        if ($normalizedSources.Count -gt 0) {
            $hasBroad = $false
            foreach ($src in $normalizedSources) {
                if ($src -eq '*' -or $src -match '^https?://\*/?\*?$') {
                    $hasBroad = $true
                    break
                }
            }

            $evidence.has_broad_sources = $hasBroad
            $evidence.has_restricted_sources = -not $hasBroad
        }
    } catch {
        $evidence.settings_error = [string]$_.Exception.Message
    }

    return $evidence
}

function Test-ChromeExtensionControlIntent {
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

    $childEntries = Get-ChromePolicyChildValues -ChildKeyName 'ExtensionInstallBlocklist'
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

    $intent = Get-ChromeExtensionIntentEvidence -PolicyStore $PolicyStore
    if ($intent.has_extension_settings -and -not $intent.settings_valid_json) {
        return @{
            status = 'FAILED'
            message = 'ExtensionSettings present but invalid JSON; extension governance intent cannot be validated'
            observed_value = '(invalid ExtensionSettings JSON)'
            source = 'ExtensionSettings'
        }
    }

    if ($intent.has_global_block_mode) {
        return @{
            status = 'PASSED'
            message = 'Extension install governance enforced by ExtensionSettings (*.installation_mode=blocked)'
            observed_value = 'ExtensionSettings[*].installation_mode=blocked'
            source = 'ExtensionSettings'
        }
    }

    if ($intent.has_restricted_sources -and $intent.install_sources.Count -gt 0) {
        return @{
            status = 'PASSED'
            message = 'Extension install governance enforced by restricted ExtensionSettings install_sources'
            observed_value = "ExtensionSettings[*].install_sources=$($intent.install_sources -join ',')"
            source = 'ExtensionSettings'
        }
    }

    return @{
        status = 'FAILED'
        message = 'No policy evidence found for extension install governance intent'
        observed_value = '(not set)'
        source = 'None'
    }
}

function Test-ChromeExtensionAllowedTypesControl {
    param([hashtable]$PolicyStore)

    $types = @()

    if ($PolicyStore.ContainsKey('ExtensionAllowedTypes')) {
        $raw = $PolicyStore['ExtensionAllowedTypes'].value
        if ($raw -is [array]) {
            $types += @($raw | ForEach-Object { [string]$_ })
        } elseif ($null -ne $raw) {
            $types += [string]$raw
        }
    }

    $childEntries = Get-ChromePolicyChildValues -ChildKeyName 'ExtensionAllowedTypes'
    foreach ($entry in $childEntries) {
        $types += [string]$entry.value
    }

    $normalized = @($types | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    if ($normalized.Count -eq 0) {
        return @{
            status = 'FAILED'
            message = 'ExtensionAllowedTypes configured neither as direct value nor list-style child values'
            observed_value = '(not set)'
            source = 'ExtensionAllowedTypes'
        }
    }

    $required = @('extension', 'hosted_app', 'platform_app', 'theme')
    $missing = @($required | Where-Object { $normalized -notcontains $_ })
    if ($missing.Count -eq 0) {
        return @{
            status = 'PASSED'
            message = 'ExtensionAllowedTypes includes all required types'
            observed_value = "ExtensionAllowedTypes=$($normalized -join ',')"
            source = 'ExtensionAllowedTypes'
        }
    }

    return @{
        status = 'FAILED'
        message = "ExtensionAllowedTypes missing required type(s): $($missing -join ',')"
        observed_value = "ExtensionAllowedTypes=$($normalized -join ',')"
        source = 'ExtensionAllowedTypes'
    }
}

function Invoke-CisPolicyTest {
    param(
        [hashtable]$Definition,
        [hashtable]$PolicyStore,
        [hashtable]$Mapping
    )

    $meta = Get-PolicyExpectedMachineMeta -PolicyKey ([string]$Mapping.policy_key) -ExpectedText ([string]$Definition.expected)

    if ($null -eq $Mapping -or $Mapping.mode -ne 'POLICY' -or [string]::IsNullOrWhiteSpace($Mapping.policy_key)) {
        return @{
            status = 'UNKNOWN'
            message = 'Strict CIS mapping requires manual verification for this control'
            details = "Control: $($Definition.control_id) | Expected: $($Definition.expected)"
            expected_value = "Expected: $($Definition.expected)"
            observed_value = "(not assessed)"
            expected_kind = $meta.kind
            expected_machine_value = $meta.value
            finding_details = 'Bu kontrol strict policy map dosyasinda MANUAL olarak isaretlendigi icin otomatik policy anahtar testi uygulanmadi.'
            test_method = 'Control ID -> chrome_cis_policy_map.json strict map lookup (MANUAL mode).'
            rationale = 'Belirsiz policy anahtarlari ile otomatik test yapmak yanlis pozitif/negatif uretebilir.'
            impact = 'Kontrol durumu manuel dogrulama gerektirdiginden kesin uyum karari verilemez.'
            remediation = 'chrome_cis_policy_map.json dosyasinda bu kontrol icin kesin policy_key ve POLICY mode tanimlayin.'
            reference = 'https://chromeenterprise.google/policies/'
        }
    }

    $matchedKey = [string]$Mapping.policy_key
    $equivalentKeys = @()
    if ($null -ne $Mapping.equivalent_policy_keys) {
        $equivalentKeys = @($Mapping.equivalent_policy_keys | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    if ([string]$Definition.control_id -eq '2.3.3' -and [string]$matchedKey -eq 'ExtensionInstallBlocklist') {
        $intentEval = Test-ChromeExtensionControlIntent -PolicyStore $PolicyStore
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
            reference = 'https://chromeenterprise.google/policies/#ExtensionSettings'
        }
    }

    if ([string]$Definition.control_id -eq '2.3.2' -and [string]$matchedKey -eq 'ExtensionAllowedTypes') {
        $typesEval = Test-ChromeExtensionAllowedTypesControl -PolicyStore $PolicyStore
        return @{
            status = $typesEval.status
            message = $typesEval.message
            details = "Control: $($Definition.control_id) | Intent source: $($typesEval.source)"
            expected_value = "Expected: $($Definition.expected)"
            observed_value = [string]$typesEval.observed_value
            expected_kind = $meta.kind
            expected_machine_value = $meta.value
            finding_details = "CIS $($Definition.control_id) icin ExtensionAllowedTypes listesi intent-bazli degerlendirildi."
            test_method = 'Strict map baseline + list-style child key aware evaluation for ExtensionAllowedTypes.'
            rationale = 'Bu kontrol cogu kurulumda list-style subkey olarak tutulur; sadece root value aramak yanlis negatif uretebilir.'
            impact = 'Subkey-aware kontrol, MDM/GPO ile duzeltilmis type-list ayarlarinin dogru sekilde PASS edilmesini saglar.'
            remediation = 'ExtensionAllowedTypes icinde extension, hosted_app, platform_app, theme tiplerini merkezden dagitin.'
            reference = 'https://chromeenterprise.google/policies/#ExtensionAllowedTypes'
        }
    }

    if (-not $PolicyStore.ContainsKey($matchedKey)) {
        if ([string]$Definition.control_id -eq '2.3.1' -and [string]$matchedKey -eq 'BlockExternalExtensions') {
            $intent = Get-ChromeExtensionIntentEvidence -PolicyStore $PolicyStore
            if ($intent.has_restricted_sources -and $intent.install_sources.Count -gt 0) {
                return @{
                    status = 'PASSED'
                    message = 'External extension installs effectively blocked by restricted ExtensionSettings install_sources'
                    details = "Control: $($Definition.control_id) | Intent source: ExtensionSettings"
                    expected_value = "Expected: $($Definition.expected)"
                    observed_value = "ExtensionSettings[*].install_sources=$($intent.install_sources -join ',')"
                    expected_kind = $meta.kind
                    expected_machine_value = $meta.value
                    finding_details = "CIS $($Definition.control_id) strict key bulunamadi; extension install source kisiti ile intent dogrulandi."
                    test_method = 'Strict map key lookup + ExtensionSettings install_sources intent fallback.'
                    rationale = 'BlockExternalExtensions key yoksa da yalniz kurum onayli kaynaklara izin veren ExtensionSettings ayni koruma niyetini saglayabilir.'
                    impact = 'Yalnizca key adi farkindan kaynaklanan yanlis FAIL azaltilir; gercek enforcement rapora yansir.'
                    remediation = 'BlockExternalExtensions=1 veya ExtensionSettings install_sources kisiti ile kurulum kaynaklarini sinirlayin.'
                    reference = 'https://chromeenterprise.google/policies/#BlockExternalExtensions'
                }
            }
        }

        if ([string]$Definition.control_id -eq '2.3.7' -and [string]$matchedKey -eq 'ExtensionUnpublishedAvailability') {
            $intent = Get-ChromeExtensionIntentEvidence -PolicyStore $PolicyStore
            if ($intent.has_restricted_sources -and $intent.install_sources.Count -gt 0) {
                return @{
                    status = 'PASSED'
                    message = 'Unpublished extension availability effectively restricted by ExtensionSettings install_sources'
                    details = "Control: $($Definition.control_id) | Intent source: ExtensionSettings"
                    expected_value = "Expected: $($Definition.expected)"
                    observed_value = "ExtensionSettings[*].install_sources=$($intent.install_sources -join ',')"
                    expected_kind = $meta.kind
                    expected_machine_value = $meta.value
                    finding_details = "CIS $($Definition.control_id) strict key bulunamadi; extension source kisiti ile unpublished extension riski azaltildi."
                    test_method = 'Strict map key lookup + ExtensionSettings source restriction intent fallback.'
                    rationale = 'Sadece kurum onayli update/install kaynaklarina izin verilmesi, unpublished extension erisilebilirligini pratikte kisitlar.'
                    impact = 'MDM ile uygulanan source-kisitli modelin uyum sonucu FAIL yerine sahadaki etkisini yansitacak sekilde PASS olur.'
                    remediation = 'ExtensionUnpublishedAvailability degerini Disabled olarak dagitin veya ExtensionSettings install_sources kisiti uygulayin.'
                    reference = 'https://chromeenterprise.google/policies/#ExtensionUnpublishedAvailability'
                }
            }
        }

        foreach ($candidate in $equivalentKeys) {
            if ($PolicyStore.ContainsKey($candidate)) {
                $entry = $PolicyStore[$candidate]
                $eval = Test-PolicyExpectation -Value $entry.value -Expected $Definition.expected
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
                    reference = 'https://chromeenterprise.google/policies/'
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
            finding_details = "! Strict map bu kontrolu '$matchedKey' anahtarina bagladi ancak local registry policy store'da key bulunamadi. Kontrol farkli yonetim/ag katmaninda uygulanmis olabilir."
            test_method = "Control ID -> strict map -> registry key lookup ($matchedKey)."
            rationale = 'Policy anahtarinin sadece lokal registryde gorunmemesi her zaman kontrol yoklugu anlamina gelmez.'
            impact = 'Kesin PASS/FAIL yerine ikinci katman dogrulamasi gerekir; aksi halde false positive riski artar.'
            remediation = "'$matchedKey' policy dagitimini GPO/MDM tarafinda dogrulayin ve endpointte gorunen policy izi olusturun."
            reference = 'https://chromeenterprise.google/policies/'
            warning_note = 'Yerel policy anahtari bulunamadi; bu kontrolu kurumsal dagitim kaynagi ve manuel davranis testi ile dogrulayin.'
            manual_required = $true
        }
    }

    $entry = $PolicyStore[$matchedKey]
    $eval = Test-PolicyExpectation -Value $entry.value -Expected $Definition.expected
    if ($matchedKey -eq 'IncognitoModeAvailability') {
        [int64]$incognitoNum = -1
        if ([int64]::TryParse([string]$entry.value, [ref]$incognitoNum)) {
            if ($Definition.expected -match '(?i)disabled') {
                if ($incognitoNum -eq 1 -or $incognitoNum -eq 2) {
                    $eval = @{ status = 'PASSED'; message = "Expected Disabled, actual policy mode: $incognitoNum" }
                } else {
                    $eval = @{ status = 'FAILED'; message = "Expected Disabled, actual policy mode: $incognitoNum" }
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
        finding_details = "CIS $($Definition.control_id) denetiminde '$matchedKey' policy anahtari kullanildi."
        test_method = "Control ID strict map ile '$matchedKey' key'ine baglandi ve expected ifadesiyle deger karsilastirildi."
        rationale = 'CIS gereksinimi, browser policy yonetiminin merkezi ve denetlenebilir olmasini hedefler.'
        impact = 'Beklenen deger saglanmazsa ilgili koruma mekanizmasi devre disi veya zayif kalabilir.'
        remediation = "'$matchedKey' policy degerini CIS beklentisine ($($Definition.expected)) uygun sekilde ayarlayin."
        reference = 'https://chromeenterprise.google/policies/'
    }
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

function Get-CisTestsFromCatalog {
    $catalogPath = Join-Path $PSScriptRoot 'chrome_cis_controls.txt'
    if (-not (Test-Path $catalogPath)) {
        throw "Chrome CIS control catalog not found: $catalogPath. The run cannot continue with incomplete control coverage."
    }

    $tests = @{}
    $usedIds = @{}
    $lines = Get-Content -Path $catalogPath | ForEach-Object { $_.Trim() } | Where-Object { $_ }

    foreach ($line in $lines) {
        $def = Get-CisDefinitionFromLine -Line $line
        if ($null -eq $def) { continue }

        $rawId = "CIS-" + ($def.control_id -replace '[^0-9A-Za-z]+', '-')
        $id = $rawId
        $idx = 2
        while ($usedIds.ContainsKey($id)) {
            $id = "$rawId-$idx"
            $idx++
        }
        $usedIds[$id] = $true
        $mapping = if ($script:CisPolicyMapIndex.ContainsKey($def.control_id)) { $script:CisPolicyMapIndex[$def.control_id] } else { @{ policy_key = ''; mode = 'MANUAL' } }

        $tests[$id] = @{
            Name = Get-ControlDisplayName -PolicyKey ([string]$mapping.policy_key) -Definition $def
            Severity = Get-CisSeverity -Definition $def
            Package = 'CH-CIS'
            VerifiedVia = 'Registry Policy Strict Map (HKCU/HKLM)'
            CISControls = @($def.control_id)
            Type = 'CIS'
            Definition = $def
            Mapping = $mapping
        }
    }

    if ($tests.Count -eq 0) {
        throw "Chrome CIS control catalog contains no parseable controls: $catalogPath"
    }

    return $tests
}

$BaseTestMap = @{
    "C-001" = @{ Name = "Incognito Mode Policy"; Func = "Test-C001"; Severity = "HIGH"; Package = "CH-PKG-1"; VerifiedVia = "Registry (HKCU/HKLM)"; CISControls = @("2.1") }
    "C-002" = @{ Name = "Password Manager"; Func = "Test-C002"; Severity = "HIGH"; Package = "CH-PKG-1"; VerifiedVia = "Registry (HKCU/HKLM), Preferences File"; CISControls = @("2.6") }
    "C-003" = @{ Name = "Developer Tools Restriction"; Func = "Test-C003"; Severity = "MEDIUM"; Package = "CH-PKG-1"; VerifiedVia = "Registry (HKCU/HKLM)"; CISControls = @() }
    "C-004" = @{ Name = "Browser Sync"; Func = "Test-C004"; Severity = "CRITICAL"; Package = "CH-PKG-2"; VerifiedVia = "Registry (HKCU/HKLM), Preferences File"; CISControls = @("2.15"); IntuneReferenceUrl = "https://learn.microsoft.com/en-us/intune/app-management/protection/overview"; ManageEngineReferenceUrl = "https://www.manageengine.com/mobile-device-management/help/profile_management/mdm_profile_management.html" }
    "C-005" = @{ Name = "Safe Browsing Enforcement"; Func = "Test-C005"; Severity = "CRITICAL"; Package = "CH-PKG-2"; VerifiedVia = "Registry (HKCU/HKLM)"; CISControls = @("2.12"); IntuneReferenceUrl = "https://learn.microsoft.com/en-us/purview/dlp-browser-dlp-learn"; ManageEngineReferenceUrl = "https://www.manageengine.com/mobile-device-management/help/security_management/mdm_security_management.html" }
    "C-006" = @{ Name = "Extension Installation Control"; Func = "Test-C006"; Severity = "HIGH"; Package = "CH-PKG-3"; VerifiedVia = "Registry (HKCU/HKLM)"; CISControls = @("2.3", "2.4") }
    "C-007" = @{ Name = "Download Restriction Level"; Func = "Test-C007"; Severity = "HIGH"; Package = "CH-PKG-2"; VerifiedVia = "Registry (HKCU/HKLM)"; CISControls = @() }
    "C-008" = @{ Name = "Site Isolation"; Func = "Test-C008"; Severity = "HIGH"; Package = "CH-PKG-4"; VerifiedVia = "Registry (HKCU/HKLM)"; CISControls = @() }
    "C-009" = @{ Name = "DNS over HTTPS"; Func = "Test-C009"; Severity = "MEDIUM"; Package = "CH-PKG-5"; VerifiedVia = "Registry (HKCU/HKLM)"; CISControls = @() }
    "C-010" = @{ Name = "Autofill Address/Payment"; Func = "Test-C010"; Severity = "MEDIUM"; Package = "CH-PKG-2"; VerifiedVia = "Registry (HKCU/HKLM), Preferences File"; CISControls = @() }
    "C-011" = @{ Name = "Third-Party Cookies"; Func = "Test-C011"; Severity = "HIGH"; Package = "CH-PKG-4"; VerifiedVia = "Registry (HKCU/HKLM)"; CISControls = @() }
    "C-012" = @{ Name = "Command-Line Hardening"; Func = "Test-C012"; Severity = "MEDIUM"; Package = "CH-PKG-6"; VerifiedVia = "Process Command Line (Live)"; CISControls = @() }
    "C-013" = @{ Name = "Proxy Mode Enforcement"; Func = "Test-C013"; Severity = "HIGH"; Package = "CH-PKG-5"; VerifiedVia = "Registry (HKCU/HKLM)"; CISControls = @() }
    "C-014" = @{ Name = "QUIC Disable"; Func = "Test-C014"; Severity = "MEDIUM"; Package = "CH-PKG-5"; VerifiedVia = "Registry (HKCU/HKLM)"; CISControls = @() }
    "C-015" = @{ Name = "Insecure Content Allowlist"; Func = "Test-C015"; Severity = "HIGH"; Package = "CH-PKG-5"; VerifiedVia = "Registry (HKCU/HKLM)"; CISControls = @() }
    "C-016" = @{ Name = "Certificate Transparency Exceptions"; Func = "Test-C016"; Severity = "HIGH"; Package = "CH-PKG-5"; VerifiedVia = "Registry (HKCU/HKLM)"; CISControls = @() }
}

$script:CisPolicyMapIndex = Get-CisPolicyMapIndex
$CisTestMap = Get-CisTestsFromCatalog
$TestMap = @{}
$BaseTestMap.Keys | ForEach-Object { $TestMap[$_] = $BaseTestMap[$_] }
$CisTestMap.Keys | Sort-Object | ForEach-Object { $TestMap[$_] = $CisTestMap[$_] }

$script:CisPolicyStore = Get-ChromePolicyStore

if ($TestId -eq "ALL") {
    $TestMap.Keys | Sort-Object | ForEach-Object {
        $k = $_
        $cfg = $TestMap[$k]
        if ($cfg.Type -eq 'CIS') {
            $r = Invoke-CisPolicyTest -Definition $cfg.Definition -PolicyStore $script:CisPolicyStore -Mapping $cfg.Mapping
        } else {
            $r = & $cfg.Func
        }
        $manual = Get-ChromeManualCheckGuidance -TestId $k -TestConfig $cfg -Result $r
        $defaultConfidence = if ($r.status -eq 'UNKNOWN') { 'LOW' } else { 'MEDIUM' }
        $evidenceOutput = Get-ResultFieldOrFallback -Result $r -FieldName "evidence_output" -FallbackValue (Get-ResultFieldOrFallback -Result $r -FieldName "details" -FallbackValue (Get-ResultField -Result $r -FieldName "message" -DefaultValue ""))
        $expectedValue = Get-ResultFieldOrFallback -Result $r -FieldName "expected_value" -FallbackValue $manual.manual_check_expected
        $observedValue = Get-ResultFieldOrFallback -Result $r -FieldName "observed_value" -FallbackValue ""
        $expectedMeta = Get-MachineComparableExpectation -ExpectedValue $expectedValue -ObservedValue $observedValue
        
        # Enrich test_method, rationale, impact for CIS tests (if missing from Invoke-ChromeCisTest)
        $testMethodVal = if (-not [string]::IsNullOrWhiteSpace($r.test_method)) { $r.test_method } else { "Chrome CIS $($cfg.CISControls[0]) - Strict policy mapping via $($cfg.VerifiedVia)" }
        $rationaleVal = if (-not [string]::IsNullOrWhiteSpace($r.rationale)) { $r.rationale } else { "Chrome CIS Control $($cfg.CISControls[0]): $($cfg.Name) kurumsal guvenlik politikasina uygun olmali." }
        $impactVal = if (-not [string]::IsNullOrWhiteSpace($r.impact)) { $r.impact } else { "Kontrolu saglamayan sistemlerde Chrome guvenlik ve uyum hedefleri tamamlanmaz." }
        
        $resultPayload = @{
            test_id = $k
            test_name = $cfg.Name
            package_id = $cfg.Package
            severity = $cfg.Severity
            cis_controls = $cfg.CISControls
            verified_via = $cfg.VerifiedVia
            status = $r.status
            message = $r.message
            details = $r.details
            finding_details = $r.finding_details
            test_method = $testMethodVal
            rationale = $rationaleVal
            impact = $impactVal
            layer_1_status = Get-ResultField -Result $r -FieldName "layer_1_status" -DefaultValue ""
            layer_1_method = Get-ResultField -Result $r -FieldName "layer_1_method" -DefaultValue ""
            layer_1_details = Get-ResultField -Result $r -FieldName "layer_1_details" -DefaultValue ""
            layer_2_status = Get-ResultField -Result $r -FieldName "layer_2_status" -DefaultValue ""
            layer_2_method = Get-ResultField -Result $r -FieldName "layer_2_method" -DefaultValue ""
            layer_2_details = Get-ResultField -Result $r -FieldName "layer_2_details" -DefaultValue ""
            layer_3_status = Get-ResultField -Result $r -FieldName "layer_3_status" -DefaultValue ""
            layer_3_method = Get-ResultField -Result $r -FieldName "layer_3_method" -DefaultValue ""
            layer_3_details = Get-ResultField -Result $r -FieldName "layer_3_details" -DefaultValue ""
            remediation = $r.remediation
            reference = $r.reference
            intune_reference_url = if ($cfg.IntuneReferenceUrl) { $cfg.IntuneReferenceUrl } else { "" }
            manageengine_reference_url = if ($cfg.ManageEngineReferenceUrl) { $cfg.ManageEngineReferenceUrl } else { "" }
            warning_note = $r.warning_note
            expected_value = $expectedValue
            expected_kind = Get-ResultFieldOrFallback -Result $r -FieldName "expected_kind" -FallbackValue $expectedMeta.kind
            expected_machine_value = Get-ResultFieldOrFallback -Result $r -FieldName "expected_machine_value" -FallbackValue $expectedMeta.value
            observed_value = $observedValue
            evidence_output = $evidenceOutput
            evidence_type = Get-ResultFieldOrFallback -Result $r -FieldName "evidence_type" -FallbackValue (Get-DefaultEvidenceType -VerifiedVia $cfg.VerifiedVia)
            confidence = Get-ResultFieldOrFallback -Result $r -FieldName "confidence" -FallbackValue $defaultConfidence
            status_reason = Get-ResultFieldOrFallback -Result $r -FieldName "status_reason" -FallbackValue (Get-DefaultStatusReason -Status $r.status)
            manual_required = Get-ResultField -Result $r -FieldName "manual_required" -DefaultValue ($r.status -eq 'UNKNOWN')
            manual_check = $manual.manual_check
            manual_check_steps = $manual.manual_check_steps
            manual_check_command = $manual.manual_check_command
            manual_check_expected = $manual.manual_check_expected
            manual_check_note = $manual.manual_check_note
            retest_command = ".\chrome_test_runner.ps1 -TestId $k"
            timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }
        $normalizedPayload = Normalize-ReportPayload -Payload $resultPayload
        $enrichedPayload = Add-ArtifactMetadata -Payload $normalizedPayload
        $script:TestResults += $enrichedPayload
    }
} else {
    if (-not $TestMap.ContainsKey($TestId)) {
        Write-Host "ERROR: Unknown test ID: $TestId" -ForegroundColor Red
        exit 1
    }

    $cfg = $TestMap[$TestId]
    if ($cfg.Type -eq 'CIS') {
        $r = Invoke-CisPolicyTest -Definition $cfg.Definition -PolicyStore $script:CisPolicyStore -Mapping $cfg.Mapping
    } else {
        $r = & $cfg.Func
    }
    $manual = Get-ChromeManualCheckGuidance -TestId $TestId -TestConfig $cfg -Result $r
    $defaultConfidence = if ($r.status -eq 'UNKNOWN') { 'LOW' } else { 'MEDIUM' }
    $evidenceOutput = Get-ResultFieldOrFallback -Result $r -FieldName "evidence_output" -FallbackValue (Get-ResultFieldOrFallback -Result $r -FieldName "details" -FallbackValue (Get-ResultField -Result $r -FieldName "message" -DefaultValue ""))
    $expectedValue = Get-ResultFieldOrFallback -Result $r -FieldName "expected_value" -FallbackValue $manual.manual_check_expected
    $observedValue = Get-ResultFieldOrFallback -Result $r -FieldName "observed_value" -FallbackValue ""
    $expectedMeta = Get-MachineComparableExpectation -ExpectedValue $expectedValue -ObservedValue $observedValue
    
    # Enrich test_method, rationale, impact for CIS tests (if missing from Invoke-CisPolicyTest)
    $testMethodVal = if (-not [string]::IsNullOrWhiteSpace($r.test_method)) { $r.test_method } else { "Chrome CIS $($cfg.CISControls[0]) - Strict policy mapping via $($cfg.VerifiedVia)" }
    $rationaleVal = if (-not [string]::IsNullOrWhiteSpace($r.rationale)) { $r.rationale } else { "Chrome CIS Control $($cfg.CISControls[0]): $($cfg.Name) kurumsal guvenlik politikasina uygun olmali." }
    $impactVal = if (-not [string]::IsNullOrWhiteSpace($r.impact)) { $r.impact } else { "Kontrolu saglamayan sistemlerde Chrome guvenlik ve uyum hedefleri tamamlanmaz." }
    
    $resultPayload = @{
        test_id = $TestId
        test_name = $cfg.Name
        package_id = $cfg.Package
        severity = $cfg.Severity
        cis_controls = $cfg.CISControls
        verified_via = $cfg.VerifiedVia
        status = $r.status
        message = $r.message
        details = $r.details
        finding_details = $r.finding_details
        test_method = $testMethodVal
        rationale = $rationaleVal
        impact = $impactVal
        layer_1_status = Get-ResultField -Result $r -FieldName "layer_1_status" -DefaultValue ""
        layer_1_method = Get-ResultField -Result $r -FieldName "layer_1_method" -DefaultValue ""
        layer_1_details = Get-ResultField -Result $r -FieldName "layer_1_details" -DefaultValue ""
        layer_2_status = Get-ResultField -Result $r -FieldName "layer_2_status" -DefaultValue ""
        layer_2_method = Get-ResultField -Result $r -FieldName "layer_2_method" -DefaultValue ""
        layer_2_details = Get-ResultField -Result $r -FieldName "layer_2_details" -DefaultValue ""
        layer_3_status = Get-ResultField -Result $r -FieldName "layer_3_status" -DefaultValue ""
        layer_3_method = Get-ResultField -Result $r -FieldName "layer_3_method" -DefaultValue ""
        layer_3_details = Get-ResultField -Result $r -FieldName "layer_3_details" -DefaultValue ""
        remediation = $r.remediation
        reference = $r.reference
        intune_reference_url = if ($cfg.IntuneReferenceUrl) { $cfg.IntuneReferenceUrl } else { "" }
        manageengine_reference_url = if ($cfg.ManageEngineReferenceUrl) { $cfg.ManageEngineReferenceUrl } else { "" }
        warning_note = $r.warning_note
        expected_value = $expectedValue
        expected_kind = Get-ResultFieldOrFallback -Result $r -FieldName "expected_kind" -FallbackValue $expectedMeta.kind
        expected_machine_value = Get-ResultFieldOrFallback -Result $r -FieldName "expected_machine_value" -FallbackValue $expectedMeta.value
        observed_value = $observedValue
        evidence_output = $evidenceOutput
        evidence_type = Get-ResultFieldOrFallback -Result $r -FieldName "evidence_type" -FallbackValue (Get-DefaultEvidenceType -VerifiedVia $cfg.VerifiedVia)
        confidence = Get-ResultFieldOrFallback -Result $r -FieldName "confidence" -FallbackValue $defaultConfidence
        status_reason = Get-ResultFieldOrFallback -Result $r -FieldName "status_reason" -FallbackValue (Get-DefaultStatusReason -Status $r.status)
        manual_required = Get-ResultField -Result $r -FieldName "manual_required" -DefaultValue ($r.status -eq 'UNKNOWN')
        manual_check = $manual.manual_check
        manual_check_steps = $manual.manual_check_steps
        manual_check_command = $manual.manual_check_command
        manual_check_expected = $manual.manual_check_expected
        manual_check_note = $manual.manual_check_note
        retest_command = ".\chrome_test_runner.ps1 -TestId $TestId"
        timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
    $normalizedPayload = Normalize-ReportPayload -Payload $resultPayload
    $enrichedPayload = Add-ArtifactMetadata -Payload $normalizedPayload
    $script:TestResults += $enrichedPayload
}

if ($OutputJSON) {
    $countPassed = @($script:TestResults | Where-Object { $_.status -eq "PASSED" }).Count
    $countFailed = @($script:TestResults | Where-Object { $_.status -eq "FAILED" }).Count
    $countUnknown = @($script:TestResults | Where-Object { $_.status -eq "UNKNOWN" }).Count
    $countTotal = $script:TestResults.Count

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
            $unknownWeight += ($w * 0.35)
        }
    }

    $score = if ($totalWeight -gt 0) {
        [Math]::Round((($failedWeight + $unknownWeight) / $totalWeight) * 100, 0)
    } else {
        0
    }
    $riskLevel = if ($score -ge 75) { "CRITICAL" } elseif ($score -ge 55) { "HIGH" } elseif ($score -ge 30) { "MEDIUM" } else { "LOW" }

    $report = @{
        organization = "Corporate Security"
        browser = "Google Chrome"
        test_date = (Get-Date -Format "yyyy-MM-dd")
        test_time = (Get-Date -Format "HH:mm:ss")
        environment = Get-EnvironmentInfo
        summary = @{
            total_tests = $countTotal
            passed = $countPassed
            failed = $countFailed
            unknown = $countUnknown
            risk_score = $score
            risk_level = $riskLevel
        }
        results = $script:TestResults
    }

    $json = $report | ConvertTo-Json -Depth 10
    if ($OutputFile) {
        $json | Out-File -FilePath $OutputFile -Encoding UTF8
        Write-Host "Results saved to: $OutputFile" -ForegroundColor Green
    } else {
        Write-Output $json
    }
} else {
    $script:TestResults | Format-Table -AutoSize @(
        @{ Label = "TEST ID"; Expression = { $_.test_id }; Width = 10 },
        @{ Label = "TEST NAME"; Expression = { $_.test_name }; Width = 28 },
        @{ Label = "STATUS"; Expression = { $_.status }; Width = 10 },
        @{ Label = "MESSAGE"; Expression = { $_.message }; Width = 42 }
    )
}

