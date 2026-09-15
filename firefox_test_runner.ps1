# Firefox Security Test Runner
param(
    [string]$TestId = "ALL",
    [switch]$OutputJSON = $false,
    [string]$OutputFile = ""
)

$script:TestResults = @()
$script:RunId = Get-Date -Format "yyyyMMdd_HHmmss"
$script:ArtifactsRoot = Join-Path $PSScriptRoot "artifacts"
$script:ArtifactsRunDir = ""

$script:CommonLibraryPath = Join-Path $PSScriptRoot 'lib/common.ps1'
if (-not (Test-Path -LiteralPath $script:CommonLibraryPath)) {
    throw "Shared runner library not found: $script:CommonLibraryPath"
}
. $script:CommonLibraryPath

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
    if ([string]::Equals($findingDetails, $currentFinding, [System.StringComparison]::OrdinalIgnoreCase)) {
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

function Get-DefaultEvidenceType {
    param([string]$VerifiedVia)

    $vv = [string]$VerifiedVia
    if ($vv -match 'policies\.json') { return 'policies_json' }
    if ($vv -match 'prefs\.js') { return 'preferences_file' }
    if ($vv -match 'Process Command Line') { return 'runtime_process_flags' }
    return 'result_snapshot'
}

function Get-FirefoxManualCheckGuidance {
    param(
        [string]$TestId,
        [hashtable]$TestConfig,
        [hashtable]$Result
    )

    $name = [string]$TestConfig.Name
    $status = [string]$Result.status

    $check = "Validate Firefox policy and runtime behavior together."
    $steps = @(
        "Check the related policy key on the about:policies page.",
        "Manually test the related behavior in the Firefox UI.",
        "If policy and behavior are consistent, record PASS; otherwise record FAIL."
    )
    $command = "Start-Process firefox.exe 'about:policies'"
    $expected = "The policy value and observed behavior should be consistent."

    if ($name -match 'Private') {
        $check = "Validate the Private Browsing restriction with policy and behavioral checks."
        $steps = @(
            "Check the DisablePrivateBrowsing value on about:policies.",
            "Try opening a private window with Ctrl+Shift+P.",
            "If it does not open or a policy block appears, record PASS."
        )
        $expected = "Private browsing should be restricted according to enterprise policy."
    } elseif ($name -match 'Extension') {
        $check = "Validate extension installation controls through policy and add-on install attempts."
        $steps = @(
            "Check the ExtensionSettings value on about:policies.",
            "Try installing a test add-on through about:addons.",
            "If unauthorized installation is blocked, record PASS."
        )
        $expected = "Unauthorized extension installation should be blocked and approved extensions should be policy-managed."
    } elseif ($name -match 'Password') {
        $check = "Validate password manager restriction via policy and settings."
        $steps = @(
            "Check the PasswordManagerEnabled value on about:policies.",
            "Review Settings > Privacy & Security > Logins and Passwords.",
            "If password saving is disabled, record PASS."
        )
        $expected = "The password manager should be disabled according to enterprise policy."
    } elseif ($name -match 'Developer|Debug') {
        $check = "Validate developer/debug restrictions via policy and shortcut behavior."
        $steps = @(
            "Check DisableDeveloperTools or the related key on about:policies.",
            "Try opening DevTools with F12.",
            "If it does not open or is restricted, record PASS."
        )
        $expected = "Developer/debug features should be restricted according to enterprise policy."
    } elseif ($name -match 'Proxy|DNS|HTTPS|TLS') {
        $check = "Validate network security settings through policy and settings."
        $steps = @(
            "Check the related network setting via about:policies and about:config.",
            "Review proxy/DNS behavior in Settings > Network Settings.",
            "If behavior matches enterprise expectations, record PASS."
        )
        $expected = "Proxy/DNS/TLS behavior should comply with enterprise security policy."
    }

    $note = if ($status -eq 'UNKNOWN') {
        "! The automated test could not produce a definitive decision. Close this item with manual validation and, if needed, review endpoint and network logs together."
    } else {
        "An automated finding exists; perform manual validation as secondary evidence."
    }

    return @{
        manual_check = $check
        manual_check_steps = $steps
        manual_check_command = $command
        manual_check_expected = $expected
        manual_check_note = $note
    }
}

function Get-FirefoxPolicies {
    $paths = New-Object System.Collections.Generic.List[string]
    foreach ($p in @(
        "$env:ProgramFiles\Mozilla Firefox\distribution\policies.json",
        "$env:ProgramFiles(x86)\Mozilla Firefox\distribution\policies.json",
        "$env:LOCALAPPDATA\Mozilla Firefox\distribution\policies.json",
        "$env:LOCALAPPDATA\Programs\Mozilla Firefox\distribution\policies.json"
    )) {
        if (-not [string]::IsNullOrWhiteSpace($p)) { $paths.Add($p) }
    }

    $exe = Get-FirefoxExecutablePath
    if (-not [string]::IsNullOrWhiteSpace($exe)) {
        $installDir = Split-Path -Path $exe -Parent
        if (-not [string]::IsNullOrWhiteSpace($installDir)) {
            $paths.Add((Join-Path $installDir 'distribution\policies.json'))
        }
    }

    $unique = @{}
    $orderedPaths = New-Object System.Collections.Generic.List[string]
    foreach ($p in $paths) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        if (-not $unique.ContainsKey($p)) {
            $unique[$p] = $true
            $orderedPaths.Add($p)
        }
    }

    foreach ($path in $orderedPaths) {
        try {
            if (Test-Path $path) {
                $json = Get-Content $path -Raw | ConvertFrom-Json -ErrorAction Stop
                return @{ found = $true; policies = $json.policies; source = $path }
            }
        } catch {
            Write-Verbose "policies.json parse failed for '$path': $($_.Exception.Message)"
        }
    }

    $regCandidates = @(
        'HKLM:\SOFTWARE\Policies\Mozilla\Firefox',
        'HKLM:\SOFTWARE\WOW6432Node\Policies\Mozilla\Firefox',
        'HKCU:\SOFTWARE\Policies\Mozilla\Firefox'
    )

    $merged = @{}
    $resolvedSources = New-Object System.Collections.Generic.List[string]
    foreach ($regPath in $regCandidates) {
        if (-not (Test-Path $regPath)) { continue }
        try {
            $item = Get-ItemProperty -Path $regPath -ErrorAction Stop
            $resolvedSources.Add($regPath)
            foreach ($prop in $item.PSObject.Properties) {
                $name = [string]$prop.Name
                if ($name -match '^PS(.*)$') { continue }
                if ($merged.ContainsKey($name)) { continue }

                $value = $prop.Value
                if ($value -is [string]) {
                    $trim = $value.Trim()
                    if ($trim.StartsWith('{') -or $trim.StartsWith('[')) {
                        try {
                            $value = $trim | ConvertFrom-Json -ErrorAction Stop
                        } catch {
                            $value = $trim
                        }
                    }
                }

                $merged[$name] = $value
            }
        } catch {
            Write-Verbose "Policy registry read failed for '$regPath': $($_.Exception.Message)"
        }
    }

    if ($merged.Count -gt 0) {
        return @{
            found = $true
            policies = [pscustomobject]$merged
            source = "Registry: $($resolvedSources -join ', ')"
        }
    }

    return @{ found = $false; policies = $null; source = "" }
}

function Get-FirefoxProfileCandidates {
    $ordered = New-Object System.Collections.Generic.List[string]
    $seen = @{}

    $roots = @(
        "$env:APPDATA\Mozilla\Firefox",
        "$env:LOCALAPPDATA\Mozilla\Firefox"
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    foreach ($root in $roots) {
        $profilesIni = Join-Path $root 'profiles.ini'
        if (Test-Path $profilesIni) {
            $sections = @()
            $current = @{}
            foreach ($line in (Get-Content $profilesIni -ErrorAction SilentlyContinue)) {
                $trim = [string]$line
                if ($trim -match '^\s*\[(.+)\]\s*$') {
                    if ($current.Count -gt 0) { $sections += ,$current }
                    $current = @{ name = $Matches[1] }
                    continue
                }
                if ($trim -match '^\s*([^=]+?)\s*=\s*(.*?)\s*$') {
                    $k = $Matches[1].Trim()
                    $v = $Matches[2].Trim()
                    $current[$k] = $v
                }
            }
            if ($current.Count -gt 0) { $sections += ,$current }

            $defaultPaths = New-Object System.Collections.Generic.List[string]
            $otherPaths = New-Object System.Collections.Generic.List[string]
            foreach ($section in $sections) {
                if (-not $section.ContainsKey('Path')) { continue }
                $p = [string]$section['Path']
                if ([string]::IsNullOrWhiteSpace($p)) { continue }
                $isRelative = ($section.ContainsKey('IsRelative') -and [string]$section['IsRelative'] -eq '1')
                $full = if ($isRelative) { Join-Path $root $p } else { $p }
                if (-not (Test-Path $full)) { continue }
                $isDefault = ($section.ContainsKey('Default') -and [string]$section['Default'] -eq '1')
                if ($isDefault) { $defaultPaths.Add($full) } else { $otherPaths.Add($full) }
            }
            foreach ($p in @($defaultPaths + $otherPaths)) {
                if (-not $seen.ContainsKey($p)) {
                    $seen[$p] = $true
                    $ordered.Add($p)
                }
            }
        }

        $profilesRoot = Join-Path $root 'Profiles'
        if (Test-Path $profilesRoot) {
            $dirs = Get-ChildItem $profilesRoot -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
            foreach ($d in $dirs) {
                if (-not $seen.ContainsKey($d.FullName)) {
                    $seen[$d.FullName] = $true
                    $ordered.Add($d.FullName)
                }
            }
        }
    }

    return @($ordered)
}

function Get-FirefoxPrefsText {
    try {
        $candidates = Get-FirefoxProfileCandidates
        if ($candidates.Count -eq 0) {
            return @{ found = $false; text = ""; source = "" }
        }

        foreach ($profilePath in $candidates) {
            $chunks = New-Object System.Collections.Generic.List[string]

            $userJsPath = Join-Path $profilePath 'user.js'
            if (Test-Path $userJsPath) {
                $chunks.Add((Get-Content $userJsPath -Raw))
            }

            $prefsPath = Join-Path $profilePath 'prefs.js'
            if (Test-Path $prefsPath) {
                $chunks.Add((Get-Content $prefsPath -Raw))
            }

            if ($chunks.Count -gt 0) {
                $txt = ($chunks -join "`n")
                return @{ found = $true; text = $txt; source = $profilePath }
            }
        }

        return @{ found = $false; text = ""; source = "" }
    } catch {
        Write-Verbose "Profile preference read failed: $($_.Exception.Message)"
    }

    return @{ found = $false; text = ""; source = "" }
}

function Get-FirefoxCommandLines {
    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name='firefox.exe'" -ErrorAction SilentlyContinue
        if ($null -eq $procs) { return @() }
        return @($procs | ForEach-Object { $_.CommandLine })
    } catch {
        return @()
    }
}

function Get-FirefoxExecutablePath {
    return Get-BrowserExecutablePath -BrowserExecutableName "firefox.exe" -Candidates @(
        "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
        "$env:ProgramFiles(x86)\Mozilla Firefox\firefox.exe"
    ) -LocalAppDataFallback @("$env:LOCALAPPDATA\Mozilla Firefox\firefox.exe")
}

function Get-FirefoxRuntimeEvidence {
    $cmds = Get-FirefoxCommandLines
    if ($cmds.Count -gt 0) {
        return @{ available = $true; cmds = $cmds; started_by_script = $false; started_pid = $null }
    }

    $exe = Get-FirefoxExecutablePath
    if ([string]::IsNullOrWhiteSpace($exe)) {
        return @{ available = $false; cmds = @(); started_by_script = $false; started_pid = $null; reason = 'Firefox executable not found' }
    }

    try {
        $p = Start-Process -FilePath $exe -ArgumentList 'about:blank' -PassThru -WindowStyle Minimized -ErrorAction Stop
        $retry = 0
        do {
            $cmds = Get-FirefoxCommandLines
            $retry++
        } while ($cmds.Count -eq 0 -and $retry -lt 20)

        $available = ($cmds.Count -gt 0)
        return @{ available = $available; cmds = $cmds; started_by_script = $true; started_pid = $p.Id; reason = if ($available) { '' } else { 'Firefox process command line could not be collected after auto-start' } }
    } catch {
        return @{ available = $false; cmds = @(); started_by_script = $false; started_pid = $null; reason = "Firefox start failed: $($_.Exception.Message)" }
    }
}

function Test-F001 {
    $p = Get-FirefoxPolicies
    if (-not $p.found) {
        return @{
            status = "FAILED"
            message = "Policies file missing"
            details = "policies.json not found"
            test_method = "Firefox policies.json lookup (AppData/Roaming/Mozilla/Firefox/) + DisablePrivateBrowsing key evaluation."
            rationale = "Kurumsal ortamlarda Private Browsing oturumu sadece yonetim kontrolu altinda kullanilmali."
            impact = "Policies file bulunamazsa, policy kontrolleri endpointte uygulanamamis demek."
            finding_details = "Firefox policies.json dosyasi bulunamadi."
            layer_1_status = "FAILED"
            layer_1_method = "Firefox Policies File (policies.json)"
            layer_1_details = "Mozilla Firefox policies.json not found in expected locations"
            remediation = "Firefox policies.json dosyasini kurumsal dagitim aracilariyla (GPO/MDM) kurumsal profiline add edin."
            reference = "https://mozilla.github.io/policy-templates/"
        }
    }

    $v = $p.policies.DisablePrivateBrowsing
    $passed = ($v -eq $true)
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Private browsing disabled" } else { "Private browsing allowed" }
        details = "$($p.source): DisablePrivateBrowsing = $v"
        test_method = "Firefox policies.json lookup (AppData/Roaming/Mozilla/Firefox/) + DisablePrivateBrowsing key evaluation."
        rationale = "Kurumsal ortamlarda Private Browsing oturumu sadece yonetim kontrolu altinda kullanilmali."
        impact = if ($passed) { "Private Browsing devre disi; oturum privacy kontrolleri saglanmaktadir." } else { "Private Browsing aciksa, oturum ve veri sizdirmasi kontrolleri zayif kalabilir." }
        finding_details = "DisablePrivateBrowsing = $v (true=Disabled, false/null=Enabled)"
        layer_1_status = "PASSED"
        layer_1_method = "Firefox Policies File (policies.json)"
        layer_1_details = "$($p.source): DisablePrivateBrowsing = $v"
        remediation = "DisablePrivateBrowsing policy degerini true olarak set edin."
        reference = "https://mozilla.github.io/policy-templates/#disableprivatebrowsing"
    }
}

function Test-F002 {
    $p = Get-FirefoxPolicies
    if (-not $p.found) {
        return @{
            status = "FAILED"
            message = "Policies file missing"
            details = "policies.json not found"
            test_method = "Firefox policies.json lookup + PasswordManagerEnabled key evaluation."
            rationale = "Sifreler Firefox tarafidan saklandiginda, endpointin ele gecmesi durumunda kullanici hesaplari riske girer."
            impact = "Policies file bulunamazsa, policy kontrolleri uygulanamamis demek."
            finding_details = "Firefox policies.json dosyasi bulunamadi."
            layer_1_status = "FAILED"
            layer_1_method = "Firefox Policies File (policies.json)"
            layer_1_details = "Mozilla Firefox policies.json not found"
            remediation = "Firefox policies.json dosyasini kurumsal dagitim ile configure edin."
            reference = "https://mozilla.github.io/policy-templates/"
        }
    }

    $v = $p.policies.PasswordManagerEnabled
    $passed = ($v -eq $false)
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Password manager disabled" } else { "Password manager enabled" }
        details = "$($p.source): PasswordManagerEnabled = $v"
        test_method = "Firefox policies.json lookup + PasswordManagerEnabled key evaluation."
        rationale = "Sifreler Firefox tarafidan saklandiginda, endpointin ele gecmesi durumunda kullanici hesaplari riske girer."
        impact = if ($passed) { "Parola yoneticisi devre disi; kurumsal sifre yonetimi risk altinda degil." } else { "Parola yoneticisi aciksa, kurumsal sifreler local depolama ile riske girer." }
        finding_details = "PasswordManagerEnabled = $v (false=Disabled, true/null=Enabled)"
        layer_1_status = "PASSED"
        layer_1_method = "Firefox Policies File (policies.json)"
        layer_1_details = "$($p.source): PasswordManagerEnabled = $v"
        remediation = "PasswordManagerEnabled policy degerini false olarak set edin."
        reference = "https://mozilla.github.io/policy-templates/#passwordmanagerenabled"
    }
}

function Test-F003 {
    $p = Get-FirefoxPolicies
    if (-not $p.found) {
        return @{
            status = "FAILED"
            message = "Policies file missing"
            details = "policies.json not found"
            expected_kind = "enum"
            expected_machine_value = "extension_restricted"
            policy_key = "ExtensionSettings"
            test_method = "Firefox policies.json lookup + ExtensionSettings key evaluation."
            rationale = "Yetkisiz eklenti kurulumu veri sizdirmasi ve oturum ele gecirme riskini artirir."
            impact = "Policies file bulunamazsa, extension kontrolleri uygulanamamis demek."
            finding_details = "Firefox policies.json dosyasi bulunamadi."
            layer_1_status = "FAILED"
            layer_1_method = "Firefox Policies File (policies.json)"
            layer_1_details = "Mozilla Firefox policies.json not found"
            remediation = "Firefox policies.json dosyasini kurumsal dagitim ile configure edin."
            reference = "https://mozilla.github.io/policy-templates/"
        }
    }

    $v = $p.policies.ExtensionSettings
    $shape = if ($null -ne $v) { ($v | ConvertTo-Json -Depth 8 -Compress).ToLowerInvariant() } else { '' }
    $hasInstallMode = $shape -match 'installation_mode'
    $hasControlRules = $shape -match 'blocked|force_installed|allowed|blocked_install_message'
    $passed = ($null -ne $v) -and $hasInstallMode -and $hasControlRules
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Extension policy configured" } else { "Extension policy missing" }
        details = "$($p.source): ExtensionSettings present = $($null -ne $v); installation_mode = $hasInstallMode; control_rules = $hasControlRules"
        test_method = "Firefox policies.json lookup + ExtensionSettings key evaluation."
        rationale = "Yetkisiz eklenti kurulumu veri sizdirmasi ve oturum ele gecirme riskini artirir."
        impact = if ($passed) { "Extension settings policy uygulanmis; eklenti kurulumu kontrol altinda." } else { "Extension policy yoksa, yetkisiz eklenti kurulumu riski yuksek." }
        finding_details = "ExtensionSettings policy $(if($passed) { 'configured' } else { 'missing' })"
        expected_kind = "enum"
        expected_machine_value = "extension_restricted"
        policy_key = "ExtensionSettings"
        observed_value = "installation_mode=$hasInstallMode; control_rules=$hasControlRules"
        layer_1_status = "PASSED"
        layer_1_method = "Firefox Policies File (policies.json)"
        layer_1_details = "$($p.source): ExtensionSettings = $(if($passed) { 'Configured' } else { 'Missing' })"
        remediation = "ExtensionSettings policy ile izinli eklentileri tanimlayin."
        reference = "https://mozilla.github.io/policy-templates/#extensionsettings"
    }
}

function Test-F004 {
    $p = Get-FirefoxPolicies
    if (-not $p.found) {
        return @{
            status = "FAILED"
            message = "Policies file missing"
            details = "policies.json not found"
            test_method = "Firefox policies.json lookup + EnableTrackingProtection/DisableSecurityBypass key evaluation."
            rationale = "Tracking Protection ve Security bypass disablement, web tarama gizliligi ve guvenligini saglar."
            impact = "Policies file bulunamazsa, tracking ve security kontrolleri uygulanamamis demek."
            finding_details = "Firefox policies.json dosyasi bulunamadi."
            layer_1_status = "FAILED"
            layer_1_method = "Firefox Policies File (policies.json)"
            layer_1_details = "Mozilla Firefox policies.json not found"
            remediation = "Firefox policies.json dosyasini kurumsal dagitim ile configure edin."
            reference = "https://mozilla.github.io/policy-templates/"
        }
    }

    $tracking = $p.policies.EnableTrackingProtection
    $disableBypass = $p.policies.DisableSecurityBypass
    $passed = ($null -ne $tracking -or $disableBypass -eq $true)

    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Safe browsing controls configured" } else { "Safe browsing controls weak" }
        details = "EnableTrackingProtection present = $($null -ne $tracking); DisableSecurityBypass = $disableBypass"
        test_method = "Firefox policies.json lookup + EnableTrackingProtection/DisableSecurityBypass key evaluation."
        rationale = "Tracking Protection ve Security bypass disablement, web tarama gizliligi ve guvenligini saglar."
        impact = if ($passed) { "Tracking Protection ve security bypass kontrolleri uygulanmis; web tarama gizliligi saglanmaktadir." } else { "Tracking Protection ve security bypass kontrolleri yoksa, web tarama gizliligi zayif." }
        finding_details = "EnableTrackingProtection: $(if($null -ne $tracking) { 'Configured' } else { 'Missing' }); DisableSecurityBypass: $disableBypass"
        layer_1_status = "PASSED"
        layer_1_method = "Firefox Policies File (policies.json)"
        layer_1_details = "$($p.source): EnableTrackingProtection = $(if($null -ne $tracking) { 'Configured' } else { 'Missing' }); DisableSecurityBypass = $disableBypass"
        remediation = "EnableTrackingProtection ve DisableSecurityBypass politikalari aktif edin."
        reference = "https://mozilla.github.io/policy-templates/#enabletrackingprotection"
    }
}

function Test-F005 {
    $p = Get-FirefoxPolicies
    if (-not $p.found) {
        return @{
            status = "FAILED"
            message = "Policies file missing"
            details = "policies.json not found"
            test_method = "Firefox policies.json lookup + DisableTelemetry key evaluation."
            rationale = "Firefox telemetry'si, kullanici ve sistem bilgilerini Mozilla'ya gonderebilir; kurumsal ortamlarda devre disi olmali."
            impact = "Policies file bulunamazsa, telemetry kontrolleri uygulanamamis demek."
            finding_details = "Firefox policies.json dosyasi bulunamadi."
            layer_1_status = "FAILED"
            layer_1_method = "Firefox Policies File (policies.json)"
            layer_1_details = "Mozilla Firefox policies.json not found"
            remediation = "Firefox policies.json dosyasini kurumsal dagitim ile configure edin."
            reference = "https://mozilla.github.io/policy-templates/"
        }
    }

    $v = $p.policies.DisableTelemetry
    $passed = ($v -eq $true)
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Telemetry disabled" } else { "Telemetry enabled" }
        details = "$($p.source): DisableTelemetry = $v"
        test_method = "Firefox policies.json lookup + DisableTelemetry key evaluation."
        rationale = "Firefox telemetry'si, kullanici ve sistem bilgilerini Mozilla'ya gonderebilir; kurumsal ortamlarda devre disi olmali."
        impact = if ($passed) { "Telemetry devre disi; kurumsal veriler Mozilla'ya aktarilmiyor." } else { "Telemetry aciksa, kurumsal veri Mozilla'ya iletilebilir." }
        finding_details = "DisableTelemetry = $v (true=Disabled, false/null=Enabled)"
        layer_1_status = "PASSED"
        layer_1_method = "Firefox Policies File (policies.json)"
        layer_1_details = "$($p.source): DisableTelemetry = $v"
        remediation = "DisableTelemetry policy degerini true olarak set edin."
        reference = "https://mozilla.github.io/policy-templates/#disabletelemetry"
    }
}

function Test-F006 {
    $p = Get-FirefoxPolicies
    if (-not $p.found) {
        return @{
            status = "FAILED"
            message = "Policies file missing"
            details = "policies.json not found"
            test_method = "Firefox policies.json lookup + DisableFirefoxAccounts key evaluation."
            rationale = "Firefox Accounts, bulut senkronizasyonu ve veri sizdirmasi riski olusturabilir; kurumsal ortamlarda devre disi olmali."
            impact = "Policies file bulunamazsa, Firefox Accounts kontrolleri uygulanamamis demek."
            finding_details = "Firefox policies.json dosyasi bulunamadi."
            layer_1_status = "FAILED"
            layer_1_method = "Firefox Policies File (policies.json)"
            layer_1_details = "Mozilla Firefox policies.json not found"
            remediation = "Firefox policies.json dosyasini kurumsal dagitim ile configure edin."
            reference = "https://mozilla.github.io/policy-templates/"
        }
    }

    $v = $p.policies.DisableFirefoxAccounts
    $passed = ($v -eq $true)
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Firefox accounts disabled" } else { "Firefox accounts enabled" }
        details = "$($p.source): DisableFirefoxAccounts = $v"
        test_method = "Firefox policies.json lookup + DisableFirefoxAccounts key evaluation."
        rationale = "Firefox Accounts, bulut senkronizasyonu ve veri sizdirmasi riski olusturabilir; kurumsal ortamlarda devre disi olmali."
        impact = if ($passed) { "Firefox Accounts devre disi; bulut senkronizasyonu riski elimine edilmis." } else { "Firefox Accounts aciksa, kullanici verisi Mozilla'ya senkronize edilebilir." }
        finding_details = "DisableFirefoxAccounts = $v (true=Disabled, false/null=Enabled)"
        layer_1_status = "PASSED"
        layer_1_method = "Firefox Policies File (policies.json)"
        layer_1_details = "$($p.source): DisableFirefoxAccounts = $v"
        remediation = "DisableFirefoxAccounts policy degerini true olarak set edin."
        reference = "https://mozilla.github.io/policy-templates/#disablefirefoxaccounts"
    }
}

function Test-F007 {
    $p = Get-FirefoxPolicies
    if (-not $p.found) {
        return @{
            status = "FAILED"
            message = "Policies file missing"
            details = "policies.json not found"
            expected_kind = "enum"
            expected_machine_value = "doh_managed"
            policy_key = "DNSOverHTTPS"
            test_method = "Firefox policies.json lookup + DNSOverHTTPS key evaluation."
            rationale = "DNS-over-HTTPS (DoH), DNS sorgularini encrypted iletisim uzerinden gÃ¶ndererek privacy ve guvenlik saglar."
            impact = "Policies file bulunamazsa, DoH kontrolleri uygulanamamis demek."
            finding_details = "Firefox policies.json dosyasi bulunamadi."
            layer_1_status = "FAILED"
            layer_1_method = "Firefox Policies File (policies.json)"
            layer_1_details = "Mozilla Firefox policies.json not found"
            remediation = "Firefox policies.json dosyasini kurumsal dagitim ile configure edin."
            reference = "https://mozilla.github.io/policy-templates/"
        }
    }

    $v = $p.policies.DNSOverHTTPS
    $shape = if ($null -ne $v) { ($v | ConvertTo-Json -Depth 8 -Compress).ToLowerInvariant() } else { '' }
    $hasMode = $shape -match '"mode"|\bmode\b'
    $hasProviderOrState = $shape -match 'provider|enabled|locked|excludeddomains|excluded_domains'
    $passed = ($null -ne $v) -and $hasMode -and $hasProviderOrState
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "DoH policy configured" } else { "DoH policy missing" }
        details = "$($p.source): DNSOverHTTPS present = $($null -ne $v); mode = $hasMode; provider_or_state = $hasProviderOrState"
        test_method = "Firefox policies.json lookup + DNSOverHTTPS key evaluation."
        rationale = "DNS-over-HTTPS (DoH), DNS sorgularini encrypted iletisim uzerinden gÃ¶ndererek privacy ve guvenlik saglar."
        impact = if ($passed) { "DoH policy uygulanmis; DNS sorgulari encrypted aktarÄ±lmaktadÄ±r." } else { "DoH policy yoksa, DNS sorgulari plain text olarak aktarÄ±labilir." }
        finding_details = "DNSOverHTTPS policy $(if($passed) { 'configured' } else { 'missing' })"
        expected_kind = "enum"
        expected_machine_value = "doh_managed"
        policy_key = "DNSOverHTTPS"
        observed_value = "mode=$hasMode; provider_or_state=$hasProviderOrState"
        layer_1_status = "PASSED"
        layer_1_method = "Firefox Policies File (policies.json)"
        layer_1_details = "$($p.source): DNSOverHTTPS = $(if($passed) { 'Configured' } else { 'Missing' })"
        remediation = "DNSOverHTTPS policy ile DoH sunucusunu tanimlayin."
        reference = "https://mozilla.github.io/policy-templates/#dnsoverhttps"
    }
}

function Test-F008 {
    $p = Get-FirefoxPolicies
    if (-not $p.found) {
        return @{
            status = "FAILED"
            message = "Policies file missing"
            details = "policies.json not found"
            expected_kind = "enum"
            expected_machine_value = "cookie_restricted"
            policy_key = "Cookies"
            test_method = "Firefox policies.json lookup + Cookies key evaluation."
            rationale = "Cookie kontrolleri, ucuncu taraf tracking'i ve veri sizdirmasi riskini azaltir."
            impact = "Policies file bulunamazsa, cookie kontrolleri uygulanamamis demek."
            finding_details = "Firefox policies.json dosyasi bulunamadi."
            layer_1_status = "FAILED"
            layer_1_method = "Firefox Policies File (policies.json)"
            layer_1_details = "Mozilla Firefox policies.json not found"
            remediation = "Firefox policies.json dosyasini kurumsal dagitim ile configure edin."
            reference = "https://mozilla.github.io/policy-templates/"
        }
    }

    $v = $p.policies.Cookies
    $shape = if ($null -ne $v) { ($v | ConvertTo-Json -Depth 8 -Compress).ToLowerInvariant() } else { '' }
    $hasBehavior = $shape -match 'behavior|cookiebehavior|cookie_behavior'
    $hasRestrictionSignal = $shape -match 'lifetime|third|block|reject|acceptthirdparty|accept_third_party'
    $passed = ($null -ne $v) -and $hasBehavior -and $hasRestrictionSignal
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Cookie policy configured" } else { "Cookie policy missing" }
        details = "$($p.source): Cookies policy present = $($null -ne $v); behavior = $hasBehavior; restriction_signal = $hasRestrictionSignal"
        test_method = "Firefox policies.json lookup + Cookies key evaluation."
        rationale = "Cookie kontrolleri, ucuncu taraf tracking'i ve veri sizdirmasi riskini azaltir."
        impact = if ($passed) { "Cookie policy uygulanmis; ucuncu taraf tracking riski asgariye indirgenmiÅŸtir." } else { "Cookie policy yoksa, ucuncu taraf tracking riski yuksek." }
        finding_details = "Cookies policy $(if($passed) { 'configured' } else { 'missing' })"
        expected_kind = "enum"
        expected_machine_value = "cookie_restricted"
        policy_key = "Cookies"
        observed_value = "behavior=$hasBehavior; restriction_signal=$hasRestrictionSignal"
        layer_1_status = "PASSED"
        layer_1_method = "Firefox Policies File (policies.json)"
        layer_1_details = "$($p.source): Cookies = $(if($passed) { 'Configured' } else { 'Missing' })"
        remediation = "Cookies policy ile ucuncu taraf cookies'leri engelle."
        reference = "https://mozilla.github.io/policy-templates/#cookies"
    }
}

function Test-F009 {
    $p = Get-FirefoxPolicies
    if (-not $p.found) {
        return @{
            status = "FAILED"
            message = "Policies file missing"
            details = "policies.json not found"
            test_method = "Firefox policies.json lookup + DisableDeveloperTools key evaluation."
            rationale = "DevTools'un acik birakilmasi, ic oto kontrol baypasi ve kod degistirme imkani tanir."
            impact = "Policies file bulunamazsa, DevTools kontrolleri uygulanamamis demek."
            finding_details = "Firefox policies.json dosyasi bulunamadi."
            layer_1_status = "FAILED"
            layer_1_method = "Firefox Policies File (policies.json)"
            layer_1_details = "Mozilla Firefox policies.json not found"
            remediation = "Firefox policies.json dosyasini kurumsal dagitim ile configure edin."
            reference = "https://mozilla.github.io/policy-templates/"
        }
    }

    $v = $p.policies.DisableDeveloperTools
    $passed = ($v -eq $true)
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Developer tools disabled" } else { "Developer tools allowed" }
        details = "$($p.source): DisableDeveloperTools = $v"
        test_method = "Firefox policies.json lookup + DisableDeveloperTools key evaluation."
        rationale = "DevTools'un acik birakilmasi, ic oto kontrol baypasi ve kod degistirme imkani tanir."
        impact = if ($passed) { "DevTools engellenmis; guvenlik kontrolleri baypas riski asgariye indirgenmiÅŸtir." } else { "DevTools aciksa, endpoint guvenlik kontrolleri baypas edilebilir." }
        finding_details = "DisableDeveloperTools = $v (true=Disabled, false/null=Enabled)"
        layer_1_status = "PASSED"
        layer_1_method = "Firefox Policies File (policies.json)"
        layer_1_details = "$($p.source): DisableDeveloperTools = $v"
        remediation = "DisableDeveloperTools policy degerini true olarak set edin."
        reference = "https://mozilla.github.io/policy-templates/#disabledevelopertools"
    }
}

function Test-F010 {
    $p = Get-FirefoxPolicies
    if (-not $p.found) {
        return @{
            status = "FAILED"
            message = "Policies file missing"
            details = "policies.json not found"
            expected_kind = "enum"
            expected_machine_value = "proxy_managed"
            policy_key = "Proxy"
            test_method = "Firefox policies.json lookup + Proxy key evaluation."
            rationale = "Proxy settings, kurumsal network guvenliginin vazgecilmez komponentleridir."
            impact = "Policies file bulunamazsa, proxy kontrolleri uygulanamamis demek."
            finding_details = "Firefox policies.json dosyasi bulunamadi."
            layer_1_status = "FAILED"
            layer_1_method = "Firefox Policies File (policies.json)"
            layer_1_details = "Mozilla Firefox policies.json not found"
            remediation = "Firefox policies.json dosyasini kurumsal dagitim ile configure edin."
            reference = "https://mozilla.github.io/policy-templates/"
        }
    }

    $v = $p.policies.Proxy
    $shape = if ($null -ne $v) { ($v | ConvertTo-Json -Depth 8 -Compress).ToLowerInvariant() } else { '' }
    $hasMode = $shape -match '"mode"|\bmode\b'
    $hasRoutingHint = $shape -match 'autoconfigurl|httpproxy|sslproxy|socksproxy|proxyserver|pac|server'
    $passed = ($null -ne $v) -and ($hasMode -or $hasRoutingHint)
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Proxy policy configured" } else { "Proxy policy missing" }
        details = "$($p.source): Proxy policy present = $($null -ne $v); mode = $hasMode; routing_hint = $hasRoutingHint"
        test_method = "Firefox policies.json lookup + Proxy key evaluation."
        rationale = "Proxy settings, kurumsal network guvenliginin vazgecilmez komponentleridir."
        impact = if ($passed) { "Proxy policy uygulanmis; network trafiklemesi kontrol altinda." } else { "Proxy policy yoksa, network trafiklemesi kurumsal kontrol disinda kalmis olabilir." }
        finding_details = "Proxy policy $(if($passed) { 'configured' } else { 'missing' })"
        expected_kind = "enum"
        expected_machine_value = "proxy_managed"
        policy_key = "Proxy"
        observed_value = "mode=$hasMode; routing_hint=$hasRoutingHint"
        layer_1_status = "PASSED"
        layer_1_method = "Firefox Policies File (policies.json)"
        layer_1_details = "$($p.source): Proxy = $(if($passed) { 'Configured' } else { 'Missing' })"
        remediation = "Proxy policy ile kurumsal proxy server adresini tanimlayin."
        reference = "https://mozilla.github.io/policy-templates/#proxy"
    }
}

function Test-F011 {
    $p = Get-FirefoxPolicies
    if (-not $p.found) {
        return @{
            status = "FAILED"
            message = "Policies file missing"
            details = "policies.json not found"
            test_method = "Firefox policies.json lookup + DisableFormHistory key evaluation."
            rationale = "Form gecmisi depolama, girmis veriler tarayici tarafinda saklandiginda veri sizdirmasi riski olusturabilir."
            impact = "Policies file bulunamazsa, form history kontrolleri uygulanamamis demek."
            finding_details = "Firefox policies.json dosyasi bulunamadi."
            layer_1_status = "FAILED"
            layer_1_method = "Firefox Policies File (policies.json)"
            layer_1_details = "Mozilla Firefox policies.json not found"
            remediation = "Firefox policies.json dosyasini kurumsal dagitim ile configure edin."
            reference = "https://mozilla.github.io/policy-templates/"
        }
    }

    $v = $p.policies.DisableFormHistory
    $passed = ($v -eq $true)
    return @{
        status = if ($passed) { "PASSED" } else { "FAILED" }
        message = if ($passed) { "Form history disabled" } else { "Form history enabled" }
        details = "$($p.source): DisableFormHistory = $v"
        test_method = "Firefox policies.json lookup + DisableFormHistory key evaluation."
        rationale = "Form gecmisi depolama, girmis veriler tarayici tarafinda saklandiginda veri sizdirmasi riski olusturabilir."
        impact = if ($passed) { "Form history devre disi; girmis veriler tarayici tarafinda saklanmiyor." } else { "Form history aciksa, girmis veriler tarayici tarafinda kaydedilebilir." }
        finding_details = "DisableFormHistory = $v (true=Disabled, false/null=Enabled)"
        layer_1_status = "PASSED"
        layer_1_method = "Firefox Policies File (policies.json)"
        layer_1_details = "$($p.source): DisableFormHistory = $v"
        remediation = "DisableFormHistory policy degerini true olarak set edin."
        reference = "https://mozilla.github.io/policy-templates/#disableformhistory"
    }
}

function Test-F012 {
    $runtime = Get-FirefoxRuntimeEvidence
    if (-not $runtime.available) {
        return @{
            status = "UNKNOWN"
            message = "Firefox runtime unavailable"
            details = $runtime.reason
            warning_note = "Firefox runtime kaniti alinamadigi icin bu kontrol teknik olarak degerlendirilemedi."
            test_method = "Live process command-line enumeration (Win32_Process CIM) + risky flag pattern detection."
            rationale = "Tehlikeli runtime bayraklari (--safe-mode, --allow-downgrade) temel guvenlik kontrollerini devre disi birakirlar."
            impact = "Firefox runtime evidence alinamazsa, runtime bayrak kontrolleri yapilamamis demek."
            finding_details = "Firefox process'leri bulunamadi veya runtime evidence toplanamamadi."
            layer_1_status = "UNKNOWN"
            layer_1_method = "Process Runtime Environment (Live)"
            layer_1_details = $runtime.reason
            remediation = "Firefox'un calisip calismadigi kontrol edin. Manual olarak process command-line'ni inceleyin."
            reference = "https://developer.mozilla.org/en-US/docs/Mozilla/Command_Line_Options"
        }
    }

    $cmds = $runtime.cmds

    $risky = @("--safe-mode", "--allow-downgrade")
    $hits = @()

    foreach ($cmd in $cmds) {
        foreach ($flag in $risky) {
            if ($cmd -match [regex]::Escape($flag)) { $hits += $flag }
        }
    }

    $hits = $hits | Select-Object -Unique
    if ($hits.Count -gt 0) {
        if ($runtime.started_by_script -and $runtime.started_pid) { try { Stop-Process -Id $runtime.started_pid -ErrorAction SilentlyContinue } catch { Write-Verbose "Probe process cleanup failed: $($_.Exception.Message)" } }
        return @{
            status = "FAILED"
            message = "Risky runtime flags found"
            policy_key = 'RuntimeProcessFlags'
            expected_value = 'Expected: CLEAN'
            details = "Flags: $($hits -join ', ')"
            test_method = "Live process command-line enumeration (Win32_Process CIM) + risky flag pattern detection."
            rationale = "Tehlikeli runtime bayraklari (--safe-mode, --allow-downgrade) temel guvenlik kontrollerini devre disi birakirlar."
            impact = "Bu bayraklarla Firefox baslatilirsa, sandbox korumas\u0131 ve guvenlik \u00f6zellikleri devre disi olabilir."
            finding_details = "Risky flags detected in live Firefox process(es): $($hits -join ', ')"
            layer_1_status = "FAILED"
            layer_1_method = "Process Runtime Environment (Live)"
            layer_1_details = "Firefox running with risky flags: $($hits -join ', ')"
            remediation = "Firefox'u tehlikeli bayraklarla baslatmayin. Kurumsal ortamda bu bayraklari engellemek icin startup script'lerini inceleyin."
            reference = "https://developer.mozilla.org/en-US/docs/Mozilla/Command_Line_Options"
        }
    }

    if ($runtime.started_by_script -and $runtime.started_pid) { try { Stop-Process -Id $runtime.started_pid -ErrorAction SilentlyContinue } catch { Write-Verbose "Probe process cleanup failed: $($_.Exception.Message)" } }
    return @{
        status = "PASSED"
        message = "Runtime flags secure"
        details = "No risky Firefox runtime flags detected"
        test_method = "Live process command-line enumeration (Win32_Process CIM) + risky flag pattern detection."
        rationale = "Tehlikeli runtime bayraklari'nin yoklugu, tarayicinin guvenlik kontrollerinin aktif oldu\u011funu g\u00f6sterir."
        impact = "Firefox guvenli bayraklarla baslatiliyor; sandbox ve guvenlik \u00f6zellikleri aktif kaliyor."
        finding_details = "No risky runtime flags found in live Firefox processes"
        layer_1_status = "PASSED"
        layer_1_method = "Process Runtime Environment (Live)"
        layer_1_details = "Firefox process(es) running without --safe-mode, --allow-downgrade, or similar risky flags"
        remediation = "Mevcut durumu koru. Firefox baslatma talimatlarinda tehlikeli bayraklarin kontrol\u00fc devam et."
        reference = "https://developer.mozilla.org/en-US/docs/Mozilla/Command_Line_Options"
    }
}

function Get-ObjectValueByPath {
    param(
        [object]$Root,
        [string]$Path
    )

    if ($null -eq $Root -or [string]::IsNullOrWhiteSpace($Path)) {
        return @{ found = $false; value = $null }
    }

    $current = $Root
    foreach ($part in ($Path -split '\.')) {
        if ($null -eq $current) {
            return @{ found = $false; value = $null }
        }

        if ($current -is [System.Collections.IDictionary]) {
            if (-not $current.Contains($part)) {
                return @{ found = $false; value = $null }
            }
            $current = $current[$part]
            continue
        }

        $prop = $current.PSObject.Properties[$part]
        if ($null -eq $prop) {
            return @{ found = $false; value = $null }
        }
        $current = $prop.Value
    }

    return @{ found = $true; value = $current }
}

function Get-FirefoxPrefValue {
    param(
        [string]$PrefsText,
        [string]$PrefKey
    )

    if ([string]::IsNullOrWhiteSpace($PrefsText) -or [string]::IsNullOrWhiteSpace($PrefKey)) {
        return @{ found = $false; value = $null }
    }

    $pattern = 'user_pref\("' + [regex]::Escape($PrefKey) + '",\s*(.+?)\s*\);'
    $m = [regex]::Match($PrefsText, $pattern)
    if (-not $m.Success) {
        return @{ found = $false; value = $null }
    }

    $raw = $m.Groups[1].Value.Trim()
    if ($raw -match '^"(.*)"$') {
        return @{ found = $true; value = $Matches[1] }
    }
    if ($raw -match '^(?i:true|false)$') {
        return @{ found = $true; value = ($raw.ToLowerInvariant() -eq 'true') }
    }

    [int64]$n = 0
    if ([int64]::TryParse($raw, [ref]$n)) {
        return @{ found = $true; value = $n }
    }

    return @{ found = $true; value = $raw }
}

function Test-ExplicitExpectation {
    param(
        [object]$Value,
        [string]$Expectation
    )

    $vStr = [string]$Value
    $vLower = $vStr.ToLowerInvariant()
    $isFalseLike = @('0', 'false', 'no', 'off', '') -contains $vLower
    $isTrueLike = -not $isFalseLike

    if ([string]::IsNullOrWhiteSpace($Expectation)) {
        return @{ status = 'UNKNOWN'; message = "Expectation missing, actual: $vStr" }
    }

    if ($Expectation -eq 'TRUE') {
        return @{ status = if ($isTrueLike) { 'PASSED' } else { 'FAILED' }; message = "Expected TRUE, actual: $vStr" }
    }
    if ($Expectation -eq 'FALSE') {
        return @{ status = if ($isFalseLike) { 'PASSED' } else { 'FAILED' }; message = "Expected FALSE, actual: $vStr" }
    }
    if ($Expectation -eq 'PRESENT') {
        $ok = -not [string]::IsNullOrWhiteSpace($vStr)
        return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = "Expected configured value, actual: $vStr" }
    }
    if ($Expectation -like 'NUM_EQ:*') {
        $target = [int64]($Expectation.Split(':')[1])
        [int64]$actual = 0
        if ([int64]::TryParse($vStr, [ref]$actual)) {
            return @{ status = if ($actual -eq $target) { 'PASSED' } else { 'FAILED' }; message = "Expected $target, actual: $actual" }
        }
        return @{ status = 'FAILED'; message = "Expected numeric value ($target), actual: $vStr" }
    }
    if ($Expectation -like 'NUM_GTE:*') {
        $target = [int64]($Expectation.Split(':')[1])
        [int64]$actual = 0
        if ([int64]::TryParse($vStr, [ref]$actual)) {
            return @{ status = if ($actual -ge $target) { 'PASSED' } else { 'FAILED' }; message = "Expected >= $target, actual: $actual" }
        }
        return @{ status = 'FAILED'; message = "Expected numeric value (>= $target), actual: $vStr" }
    }

    if ($Expectation -eq 'EXTENSION_RESTRICTED') {
        $json = ($Value | ConvertTo-Json -Depth 8 -Compress).ToLowerInvariant()
        $ok = ($json -match 'installation_mode') -and ($json -match 'blocked|force_installed|allowed')
        return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = "Expected extension restrictions, actual: $vStr" }
    }
    if ($Expectation -eq 'DOH_MANAGED') {
        $json = ($Value | ConvertTo-Json -Depth 8 -Compress).ToLowerInvariant()
        $ok = $json -match 'mode|provider|enabled|locked'
        return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = "Expected DoH managed object, actual: $vStr" }
    }
    if ($Expectation -eq 'COOKIE_RESTRICTED') {
        $json = ($Value | ConvertTo-Json -Depth 8 -Compress).ToLowerInvariant()
        $ok = $json -match 'third|cookie|lifetime|behavior|block'
        return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = "Expected cookie restriction object, actual: $vStr" }
    }
    if ($Expectation -eq 'PROXY_MANAGED') {
        $json = ($Value | ConvertTo-Json -Depth 8 -Compress).ToLowerInvariant()
        $ok = $json -match 'mode|pac|server|proxy'
        return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = "Expected proxy managed object, actual: $vStr" }
    }
    if ($Expectation -eq 'LOCKED') {
        $ok = -not [string]::IsNullOrWhiteSpace($vStr)
        return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = "Expected locked/configured value, actual: $vStr" }
    }
    if ($Expectation -eq 'DOWNLOAD_RESTRICTED') {
        [int64]$actual = 0
        if ([int64]::TryParse($vStr, [ref]$actual)) {
            return @{ status = if ($actual -ge 1) { 'PASSED' } else { 'FAILED' }; message = "Expected download restrictions >= 1, actual: $actual" }
        }
        $json = ($Value | ConvertTo-Json -Depth 8 -Compress).ToLowerInvariant()
        $ok = $json -match 'block|restrict|download'
        return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = "Expected download restriction object, actual: $vStr" }
    }

    return @{ status = 'UNKNOWN'; message = "Unknown expectation '$Expectation', actual: $vStr" }
}

function Convert-ExplicitExpectationToMachineMeta {
    param([string]$Expectation)

    if ([string]::IsNullOrWhiteSpace($Expectation)) {
        return @{ kind = ''; value = '' }
    }

    $e = $Expectation.ToUpperInvariant()
    if ($e -eq 'TRUE') { return @{ kind = 'bool'; value = 'true' } }
    if ($e -eq 'FALSE') { return @{ kind = 'bool'; value = 'false' } }
    if ($e -eq 'PRESENT') { return @{ kind = 'present'; value = 'true' } }
    if ($e -eq 'CLEAN') { return @{ kind = 'enum'; value = 'clean' } }
    if ($e -eq 'EXTENSION_RESTRICTED') { return @{ kind = 'enum'; value = 'extension_restricted' } }
    if ($e -eq 'DOH_MANAGED') { return @{ kind = 'enum'; value = 'doh_managed' } }
    if ($e -eq 'COOKIE_RESTRICTED') { return @{ kind = 'enum'; value = 'cookie_restricted' } }
    if ($e -eq 'PROXY_MANAGED') { return @{ kind = 'enum'; value = 'proxy_managed' } }
    if ($e -eq 'LOCKED') { return @{ kind = 'present'; value = 'true' } }
    if ($e -eq 'DOWNLOAD_RESTRICTED') { return @{ kind = 'numeric_gte'; value = '1' } }
    if ($e -like 'NUM_EQ:*') { return @{ kind = 'numeric_eq'; value = ($Expectation.Split(':', 2)[1]) } }
    if ($e -like 'NUM_GTE:*') { return @{ kind = 'numeric_gte'; value = ($Expectation.Split(':', 2)[1]) } }
    return @{ kind = ''; value = '' }
}

function Resolve-FirefoxCisExpectation {
    param(
        [hashtable]$Definition,
        [hashtable]$Mapping
    )

    $existing = [string]$Mapping.expectation
    if (-not [string]::IsNullOrWhiteSpace($existing)) {
        return $existing.ToUpperInvariant()
    }

    $mode = ([string]$Mapping.mode).ToUpperInvariant()
    $key = [string]$Mapping.key
    if ($mode -eq 'MANUAL') { return '' }
    if ($mode -eq 'RUNTIME') { return 'CLEAN' }

    switch -Exact ($key) {
        'DisablePrivateBrowsing' { return 'TRUE' }
        'PasswordManagerEnabled' { return 'FALSE' }
        'ExtensionSettings' { return 'EXTENSION_RESTRICTED' }
        'DisableSecurityBypass' { return 'TRUE' }
        'DisableTelemetry' { return 'TRUE' }
        'DisableFirefoxAccounts' { return 'TRUE' }
        'DNSOverHTTPS' { return 'DOH_MANAGED' }
        'Cookies' { return 'COOKIE_RESTRICTED' }
        'DisableDeveloperTools' { return 'TRUE' }
        'Proxy' { return 'PROXY_MANAGED' }
        'DisableFormHistory' { return 'TRUE' }
        'DisablePocket' { return 'TRUE' }
        'DisableFirefoxStudies' { return 'TRUE' }
        'DisableFeedbackCommands' { return 'TRUE' }
        'DisableProfileImport' { return 'TRUE' }
        'EnableTrackingProtection' { return 'TRUE' }
        'Homepage' { return 'LOCKED' }
        'SearchEngines' { return 'LOCKED' }
        'BlockAboutConfig' { return 'TRUE' }
        'DownloadRestrictions' { return 'DOWNLOAD_RESTRICTED' }
        'DontCheckDefaultBrowser' { return 'TRUE' }
        'network.captive-portal-service.enabled' { return 'FALSE' }
        'signon.management.page.breach-alerts.enabled' { return 'FALSE' }
        'extensions.formautofill.addresses.enabled' { return 'FALSE' }
        'extensions.formautofill.creditCards.enabled' { return 'FALSE' }
        'network.cookie.cookieBehavior' { return 'NUM_GTE:1' }
        'network.cookie.lifetimePolicy' { return 'NUM_GTE:1' }
        'permissions.default.clipboard' { return 'NUM_EQ:2' }
        'permissions.default.camera' { return 'NUM_EQ:2' }
        'permissions.default.microphone' { return 'NUM_EQ:2' }
        'permissions.default.geo' { return 'NUM_EQ:2' }
        'permissions.default.desktop-notification' { return 'NUM_EQ:2' }
        'media.autoplay.default' { return 'NUM_GTE:1' }
        'media.peerconnection.ice.default_address_only' { return 'TRUE' }
        'dom.security.https_only_mode' { return 'TRUE' }
        'security.tls.version.min' { return 'NUM_GTE:3' }
        'security.OCSP.enabled' { return 'NUM_GTE:1' }
        'browser.xul.error_pages.expert_bad_cert' { return 'FALSE' }
        'browser.sessionstore.resume_from_crash' { return 'FALSE' }
        'devtools.debugger.remote-enabled' { return 'FALSE' }
        'security.enterprise_roots.enabled' { return 'TRUE' }
        'datareporting.healthreport.uploadEnabled' { return 'FALSE' }
        'browser.urlbar.suggest.searches' { return 'FALSE' }
        'browser.download.useDownloadDir' { return 'FALSE' }
        'extensions.legacy.enabled' { return 'FALSE' }
        'extensions.update.url' { return 'PRESENT' }
        'signon.autofillForms' { return 'FALSE' }
        'security.mixed_content.block_active_content' { return 'TRUE' }
        'network.http.referer.XOriginPolicy' { return 'NUM_GTE:2' }
        'network.protocol-handler.external-default' { return 'FALSE' }
        'media.getusermedia.screensharing.enabled' { return 'FALSE' }
        'privacy.file_unique_origin' { return 'TRUE' }
        'network.http.http3.enable' { return 'FALSE' }
        'security.cert_pinning.enforcement_level' { return 'NUM_GTE:1' }
        'signon.privateBrowsingCapture.enabled' { return 'FALSE' }
        'app.normandy.enabled' { return 'FALSE' }
    }
    return ''
}

function Get-FirefoxCisDefinitionFromLine {
    param([string]$Line)

    if ([string]::IsNullOrWhiteSpace($Line)) { return $null }

    $m = [regex]::Match($Line, '^(\d+(?:\.\d+)*)\s+\(L\d+\)\s+(.+)$')
    if (-not $m.Success) { return $null }

    return @{
        control_id = $m.Groups[1].Value.Trim()
        title = $m.Groups[2].Value.Trim()
        raw_line = $Line.Trim()
    }
}

function Get-FirefoxCisSeverity {
    param([hashtable]$Definition)

    $t = $Definition.title.ToLowerInvariant()
    if ($t -match 'safe browsing|phishing|sync|accounts|https|tls|certificate|remote debugging|extension|download') {
        return 'HIGH'
    }
    if ($t -match 'cookies|telemetry|proxy|clipboard|camera|microphone|location|notification|webrtc|autoplay') {
        return 'MEDIUM'
    }
    return 'LOW'
}

function Get-FirefoxCisMapIndex {
    $mapPath = Join-Path $PSScriptRoot 'firefox_cis_policy_map.json'
    $index = @{}
    
    if (Test-Path $mapPath) {
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
                    key = [string]$item.policy_key
                    mode = if ([string]::IsNullOrWhiteSpace([string]$item.mode)) { 'MANUAL' } else { ([string]$item.mode).ToUpperInvariant() }
                    expectation = ''
                    equivalent_policy_keys = $equivalents
                }
            }
        } catch {
            Write-Host "Warning: Could not load firefox_cis_policy_map.json: $_" -ForegroundColor Yellow
        }
    }
    
    # Fallback hardcoded index if JSON load fails
    if ($index.Count -eq 0) {
        $index = @{
            '1.1' = @{ mode = 'POLICY'; key = 'DisablePrivateBrowsing'; expectation = 'TRUE'; equivalent_policy_keys = @() }
            '1.2' = @{ mode = 'POLICY'; key = 'PasswordManagerEnabled'; expectation = 'FALSE'; equivalent_policy_keys = @() }
            '1.3' = @{ mode = 'POLICY'; key = 'ExtensionSettings'; expectation = 'PRESENT'; equivalent_policy_keys = @('Extensions') }
            '1.4' = @{ mode = 'POLICY'; key = 'DisableSecurityBypass'; expectation = 'TRUE'; equivalent_policy_keys = @() }
            '1.5' = @{ mode = 'POLICY'; key = 'DisableTelemetry'; expectation = 'TRUE'; equivalent_policy_keys = @() }
            '1.6' = @{ mode = 'POLICY'; key = 'DisableFirefoxAccounts'; expectation = 'TRUE'; equivalent_policy_keys = @() }
            '1.7' = @{ mode = 'POLICY'; key = 'DNSOverHTTPS'; expectation = 'PRESENT'; equivalent_policy_keys = @() }
            '1.8' = @{ mode = 'POLICY'; key = 'Cookies'; expectation = 'PRESENT'; equivalent_policy_keys = @() }
            '1.9' = @{ mode = 'POLICY'; key = 'DisableDeveloperTools'; expectation = 'TRUE'; equivalent_policy_keys = @() }
            '1.10' = @{ mode = 'POLICY'; key = 'Proxy'; expectation = 'PRESENT'; equivalent_policy_keys = @() }
            '1.11' = @{ mode = 'POLICY'; key = 'DisableFormHistory'; expectation = 'TRUE'; equivalent_policy_keys = @() }
            '1.12' = @{ mode = 'MANUAL'; key = 'RuntimeProcessFlags'; expectation = 'CLEAN'; equivalent_policy_keys = @() }
        }
    }

    return $index
}

function Invoke-FirefoxCisTest {
    param(
        [hashtable]$Definition,
        [hashtable]$Mapping,
        [hashtable]$PoliciesBundle,
        [hashtable]$PrefsBundle
    )

    $effectiveExpectation = Resolve-FirefoxCisExpectation -Definition $Definition -Mapping $Mapping
    $machineMeta = Convert-ExplicitExpectationToMachineMeta -Expectation $effectiveExpectation

    if ($null -eq $Mapping -or [string]::IsNullOrWhiteSpace([string]$Mapping.mode) -or $Mapping.mode -eq 'MANUAL') {
        return @{
            status = 'FAILED'
            message = 'Mapping not defined for this CIS control'
            details = "Control: $($Definition.control_id) | Title: $($Definition.title)"
            warning_note = 'Bu CIS maddesi strict mapte MANUAL olarak isaretli; otomatik policy eslestirmesi olmadigi icin manuel dogrulama zorunlu.'
            policy_key = [string]$Mapping.key
            expected_kind = [string]$machineMeta.kind
            expected_machine_value = [string]$machineMeta.value
        }
    }

    if ($Mapping.mode -eq 'RUNTIME') {
        $runtime = Get-FirefoxRuntimeEvidence
        if (-not $runtime.available) {
            return @{ 
                status = 'UNKNOWN'
                message = 'Firefox runtime unavailable'
                details = $runtime.reason
                warning_note = 'Runtime kaniti alinamadigi icin bu kontrol teknik olarak degerlendirilemedi.'
                expected_value = "Runtime should be: $effectiveExpectation"
                policy_key = [string]$Mapping.key
                expected_kind = [string]$machineMeta.kind
                expected_machine_value = [string]$machineMeta.value
            }
        }

        $cmds = $runtime.cmds

        $risky = @('--safe-mode', '--allow-downgrade')
        $hits = @()
        foreach ($cmd in $cmds) {
            foreach ($flag in $risky) {
                if ($cmd -match [regex]::Escape($flag)) { $hits += $flag }
            }
        }
        $hits = $hits | Select-Object -Unique
        if ($hits.Count -gt 0) {
            if ($runtime.started_by_script -and $runtime.started_pid) { try { Stop-Process -Id $runtime.started_pid -ErrorAction SilentlyContinue } catch { Write-Verbose "Probe process cleanup failed: $($_.Exception.Message)" } }
            return @{ 
                status = 'FAILED'
                message = "Risky runtime flags found: $($hits -join ', ')"
                details = 'Runtime command line analysis'
                expected_value = "Expected: $effectiveExpectation (Found: $($hits -join ', '))"
                policy_key = [string]$Mapping.key
                expected_kind = [string]$machineMeta.kind
                expected_machine_value = [string]$machineMeta.value
            }
        }
        if ($runtime.started_by_script -and $runtime.started_pid) { try { Stop-Process -Id $runtime.started_pid -ErrorAction SilentlyContinue } catch { Write-Verbose "Probe process cleanup failed: $($_.Exception.Message)" } }
        return @{ 
            status = 'PASSED'
            message = 'No risky runtime flags found'
            details = 'Runtime command line analysis'
            expected_value = "Expected: $effectiveExpectation"
            policy_key = [string]$Mapping.key
            expected_kind = [string]$machineMeta.kind
            expected_machine_value = [string]$machineMeta.value
        }
    }

    if ($Mapping.mode -eq 'POLICY') {
        if (-not $PoliciesBundle.found -or $null -eq $PoliciesBundle.policies) {
            return @{ 
                status = 'FAILED'
                message = 'policies.json not found'
                details = "Mapped policy: $($Mapping.key)"
                expected_value = "Policy should be: $effectiveExpectation"
                policy_key = [string]$Mapping.key
                expected_kind = [string]$machineMeta.kind
                expected_machine_value = [string]$machineMeta.value
            }
        }

        $policyValue = Get-ObjectValueByPath -Root $PoliciesBundle.policies -Path $Mapping.key
        $resolvedKey = [string]$Mapping.key
        if (-not $policyValue.found) {
            $equivalentKeys = @()
            if ($null -ne $Mapping.equivalent_policy_keys) {
                $equivalentKeys = @($Mapping.equivalent_policy_keys | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            }

            foreach ($candidate in $equivalentKeys) {
                $candidateValue = Get-ObjectValueByPath -Root $PoliciesBundle.policies -Path $candidate
                if ($candidateValue.found) {
                    $policyValue = $candidateValue
                    $resolvedKey = $candidate
                    break
                }
            }
        }

        if (-not $policyValue.found) {
            return @{ 
                status = 'FAILED'
                message = "Mapped policy not found: $($Mapping.key)"
                details = "Control: $($Definition.control_id)"
                expected_value = "Expected: $effectiveExpectation"
                policy_key = [string]$Mapping.key
                expected_kind = [string]$machineMeta.kind
                expected_machine_value = [string]$machineMeta.value
            }
        }

        $eval = Test-ExplicitExpectation -Value $policyValue.value -Expectation $effectiveExpectation
        return @{ 
            status = $eval.status
            message = if ($resolvedKey -eq [string]$Mapping.key) { $eval.message } else { "$($eval.message) (evaluated via equivalent key: $resolvedKey)" }
            details = "$($PoliciesBundle.source): $resolvedKey = $($policyValue.value)"
            expected_value = "Expected: $effectiveExpectation (Actual: $($policyValue.value))"
            policy_key = $resolvedKey
            expected_kind = [string]$machineMeta.kind
            expected_machine_value = [string]$machineMeta.value
        }
    }

    if ($Mapping.mode -eq 'PREF') {
        if (-not $PrefsBundle.found -or [string]::IsNullOrWhiteSpace($PrefsBundle.text)) {
            return @{ 
                status = 'FAILED'
                message = 'prefs.js not found'
                details = "Mapped pref: $($Mapping.key)"
                expected_value = "Preference should be: $effectiveExpectation"
                policy_key = [string]$Mapping.key
                expected_kind = [string]$machineMeta.kind
                expected_machine_value = [string]$machineMeta.value
            }
        }

        $prefValue = Get-FirefoxPrefValue -PrefsText $PrefsBundle.text -PrefKey $Mapping.key
        if (-not $prefValue.found) {
            return @{ 
                status = 'FAILED'
                message = "Mapped pref not found: $($Mapping.key)"
                details = "Control: $($Definition.control_id)"
                expected_value = "Expected: $effectiveExpectation"
                policy_key = [string]$Mapping.key
                expected_kind = [string]$machineMeta.kind
                expected_machine_value = [string]$machineMeta.value
            }
        }

        $eval = Test-ExplicitExpectation -Value $prefValue.value -Expectation $effectiveExpectation
        return @{ 
            status = $eval.status
            message = $eval.message
            details = "$($PrefsBundle.source): $($Mapping.key) = $($prefValue.value)"
            expected_value = "Expected: $effectiveExpectation (Actual: $($prefValue.value))"
            policy_key = [string]$Mapping.key
            expected_kind = [string]$machineMeta.kind
            expected_machine_value = [string]$machineMeta.value
        }
    }

    return @{ status = 'FAILED'; message = "Unsupported mapping mode: $($Mapping.mode)"; details = "Control: $($Definition.control_id)"; warning_note = 'Map mode tanimsiz oldugu icin kontrol otomatik dogrulanamadi; map duzeltmesi gerekir.' }
}

function Get-FirefoxCisTestsFromCatalog {
    param([hashtable]$CisMap)

    $catalogPath = Join-Path $PSScriptRoot 'firefox_security_controls.txt'
    if (-not (Test-Path $catalogPath)) {
        throw "Firefox control catalog not found: $catalogPath. The run cannot continue with incomplete control coverage."
    }

    $tests = @{}
    $lines = Get-Content -Path $catalogPath | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    foreach ($line in $lines) {
        $def = Get-FirefoxCisDefinitionFromLine -Line $line
        if ($null -eq $def) { continue }

        $testId = 'FF-REF-' + ($def.control_id -replace '[^0-9A-Za-z]+', '-')
        $mapping = if ($CisMap.ContainsKey($def.control_id)) { $CisMap[$def.control_id] } else { @{ mode = 'MANUAL'; key = ''; expectation = '' } }

        $tests[$testId] = @{
            Name = Get-ControlDisplayName -PolicyKey ([string]$mapping.key) -Definition $def
            Severity = Get-FirefoxCisSeverity -Definition $def
            Package = 'FF-REF'
            VerifiedVia = 'Firefox policy/prefs strict map'
            CISControls = @($def.control_id)
            Type = 'FF-REF'
            Definition = $def
            Mapping = $mapping
        }
    }

    if ($tests.Count -eq 0) {
        throw "Firefox control catalog contains no parseable controls: $catalogPath"
    }

    return $tests
}

function Test-F013 {
    $prefs = Get-FirefoxPrefsText
    if (-not $prefs.found) { return @{ status = 'FAILED'; message = 'prefs.js missing'; details = 'dom.security.https_only_mode cannot be verified'; expected_value = 'Expected: true (HTTPS-Only mode enabled)' } }

    $v = Get-FirefoxPrefValue -PrefsText $prefs.text -PrefKey 'dom.security.https_only_mode'
    if (-not $v.found) { return @{ status = 'FAILED'; message = 'HTTPS-Only preference missing'; details = 'dom.security.https_only_mode not found'; expected_value = 'Expected: true (HTTPS-Only mode enabled)' } }

    $ok = ($v.value -eq $true)
    return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = if ($ok) { 'HTTPS-Only mode enabled' } else { 'HTTPS-Only mode disabled' }; details = "$($prefs.source): dom.security.https_only_mode = $($v.value)"; expected_value = "Expected: true (Actual: $($v.value))" }
}

function Test-F014 {
    $prefs = Get-FirefoxPrefsText
    if (-not $prefs.found) { return @{ status = 'FAILED'; message = 'prefs.js missing'; details = 'security.tls.version.min cannot be verified'; expected_value = 'Expected: >= 3 (TLS 1.2 or higher)' } }

    $v = Get-FirefoxPrefValue -PrefsText $prefs.text -PrefKey 'security.tls.version.min'
    if (-not $v.found) { return @{ status = 'FAILED'; message = 'TLS minimum version preference missing'; details = 'security.tls.version.min not found'; expected_value = 'Expected: >= 3 (TLS 1.2 or higher)' } }

    [int64]$n = 0
    $ok = [int64]::TryParse([string]$v.value, [ref]$n) -and $n -ge 3
    return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = if ($ok) { 'TLS minimum version hardened' } else { 'TLS minimum version weak' }; details = "$($prefs.source): security.tls.version.min = $($v.value)"; expected_value = "Expected: >= 3 (Actual: $($v.value))" }
}

function Test-F015 {
    $prefs = Get-FirefoxPrefsText
    if (-not $prefs.found) { return @{ status = 'FAILED'; message = 'prefs.js missing'; details = 'devtools.debugger.remote-enabled cannot be verified'; expected_value = 'Expected: false (Remote debugging disabled)' } }

    $v = Get-FirefoxPrefValue -PrefsText $prefs.text -PrefKey 'devtools.debugger.remote-enabled'
    if (-not $v.found) { return @{ status = 'FAILED'; message = 'Remote debugging preference missing'; details = 'devtools.debugger.remote-enabled not found'; expected_value = 'Expected: false (Remote debugging disabled)' } }

    $ok = ($v.value -eq $false)
    return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = if ($ok) { 'Remote debugging disabled' } else { 'Remote debugging enabled' }; details = "$($prefs.source): devtools.debugger.remote-enabled = $($v.value)"; expected_value = "Expected: false (Actual: $($v.value))" }
}

function Test-F016 {
    $prefs = Get-FirefoxPrefsText
    if (-not $prefs.found) { return @{ status = 'FAILED'; message = 'prefs.js missing'; details = 'app.normandy.enabled cannot be verified'; expected_value = 'Expected: false (Firefox experiments disabled)'; policy_key = 'app.normandy.enabled' } }

    $v = Get-FirefoxPrefValue -PrefsText $prefs.text -PrefKey 'app.normandy.enabled'
    if (-not $v.found) { return @{ status = 'FAILED'; message = 'Experiment preference missing'; details = 'app.normandy.enabled not found'; expected_value = 'Expected: false (Firefox experiments disabled)'; policy_key = 'app.normandy.enabled' } }

    $ok = ($v.value -eq $false)
    return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = if ($ok) { 'Firefox experiments disabled' } else { 'Firefox experiments enabled' }; details = "$($prefs.source): app.normandy.enabled = $($v.value)"; expected_value = "Expected: false (Actual: $($v.value))"; policy_key = 'app.normandy.enabled' }
}

function Test-F017 {
    $prefs = Get-FirefoxPrefsText
    if (-not $prefs.found) {
        return @{ status = 'FAILED'; message = 'prefs.js missing'; details = 'security.OCSP.enabled cannot be verified'; expected_value = 'Expected: >= 1 (OCSP validation enabled)'; reference = 'https://support.mozilla.org/en-US/kb/ocsp-stapling-firefox'; policy_key = 'security.OCSP.enabled' }
    }

    $v = Get-FirefoxPrefValue -PrefsText $prefs.text -PrefKey 'security.OCSP.enabled'
    if (-not $v.found) {
        return @{ status = 'FAILED'; message = 'OCSP preference missing'; details = 'security.OCSP.enabled not found'; expected_value = 'Expected: >= 1 (OCSP validation enabled)'; reference = 'https://support.mozilla.org/en-US/kb/ocsp-stapling-firefox'; policy_key = 'security.OCSP.enabled' }
    }

    [int64]$n = 0
    $ok = [int64]::TryParse([string]$v.value, [ref]$n) -and $n -ge 1
    return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = if ($ok) { 'OCSP validation enabled' } else { 'OCSP validation disabled' }; details = "$($prefs.source): security.OCSP.enabled = $($v.value)"; expected_value = "Expected: >= 1 (Actual: $($v.value))"; reference = 'https://support.mozilla.org/en-US/kb/ocsp-stapling-firefox'; policy_key = 'security.OCSP.enabled' }
}

function Test-F018 {
    $prefs = Get-FirefoxPrefsText
    if (-not $prefs.found) {
        return @{ status = 'FAILED'; message = 'prefs.js missing'; details = 'network.http.http3.enable cannot be verified'; expected_value = 'Expected: false (HTTP/3 disabled for controlled inspection)'; reference = 'https://searchfox.org/mozilla-central/search?q=network.http.http3.enable'; policy_key = 'network.http.http3.enable' }
    }

    $v = Get-FirefoxPrefValue -PrefsText $prefs.text -PrefKey 'network.http.http3.enable'
    if (-not $v.found) {
        return @{ status = 'FAILED'; message = 'HTTP/3 preference missing'; details = 'network.http.http3.enable not found'; expected_value = 'Expected: false (HTTP/3 disabled for controlled inspection)'; reference = 'https://searchfox.org/mozilla-central/search?q=network.http.http3.enable'; policy_key = 'network.http.http3.enable' }
    }

    $ok = ($v.value -eq $false)
    return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = if ($ok) { 'HTTP/3 disabled' } else { 'HTTP/3 enabled' }; details = "$($prefs.source): network.http.http3.enable = $($v.value)"; expected_value = "Expected: false (Actual: $($v.value))"; reference = 'https://searchfox.org/mozilla-central/search?q=network.http.http3.enable'; policy_key = 'network.http.http3.enable' }
}

function Test-F019 {
    $prefs = Get-FirefoxPrefsText
    if (-not $prefs.found) {
        return @{ status = 'FAILED'; message = 'prefs.js missing'; details = 'security.mixed_content.block_active_content cannot be verified'; expected_value = 'Expected: true (active mixed content blocked)'; reference = 'https://searchfox.org/mozilla-central/search?q=security.mixed_content.block_active_content'; policy_key = 'security.mixed_content.block_active_content' }
    }

    $v = Get-FirefoxPrefValue -PrefsText $prefs.text -PrefKey 'security.mixed_content.block_active_content'
    if (-not $v.found) {
        return @{ status = 'FAILED'; message = 'Mixed-content preference missing'; details = 'security.mixed_content.block_active_content not found'; expected_value = 'Expected: true (active mixed content blocked)'; reference = 'https://searchfox.org/mozilla-central/search?q=security.mixed_content.block_active_content'; policy_key = 'security.mixed_content.block_active_content' }
    }

    $ok = ($v.value -eq $true)
    return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = if ($ok) { 'Active mixed content blocked' } else { 'Active mixed content allowed' }; details = "$($prefs.source): security.mixed_content.block_active_content = $($v.value)"; expected_value = "Expected: true (Actual: $($v.value))"; reference = 'https://searchfox.org/mozilla-central/search?q=security.mixed_content.block_active_content'; policy_key = 'security.mixed_content.block_active_content' }
}

function Test-F020 {
    $prefs = Get-FirefoxPrefsText
    if (-not $prefs.found) {
        return @{ status = 'FAILED'; message = 'prefs.js missing'; details = 'security.cert_pinning.enforcement_level cannot be verified'; expected_value = 'Expected: >= 1 (certificate pinning enforcement enabled)'; reference = 'https://searchfox.org/mozilla-central/search?q=security.cert_pinning.enforcement_level'; policy_key = 'security.cert_pinning.enforcement_level' }
    }

    $v = Get-FirefoxPrefValue -PrefsText $prefs.text -PrefKey 'security.cert_pinning.enforcement_level'
    if (-not $v.found) {
        return @{ status = 'FAILED'; message = 'Certificate pinning preference missing'; details = 'security.cert_pinning.enforcement_level not found'; expected_value = 'Expected: >= 1 (certificate pinning enforcement enabled)'; reference = 'https://searchfox.org/mozilla-central/search?q=security.cert_pinning.enforcement_level'; policy_key = 'security.cert_pinning.enforcement_level' }
    }

    [int64]$n = 0
    $ok = [int64]::TryParse([string]$v.value, [ref]$n) -and $n -ge 1
    return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = if ($ok) { 'Certificate pinning enforcement enabled' } else { 'Certificate pinning enforcement weak' }; details = "$($prefs.source): security.cert_pinning.enforcement_level = $($v.value)"; expected_value = "Expected: >= 1 (Actual: $($v.value))"; reference = 'https://searchfox.org/mozilla-central/search?q=security.cert_pinning.enforcement_level'; policy_key = 'security.cert_pinning.enforcement_level' }
}

$BaseTestMap = @{
    "F-001" = @{ Name = "Private Browsing"; Func = "Test-F001"; Severity = "HIGH"; Package = "FF-PKG-1"; VerifiedVia = "policies.json"; CISControls = @("1.1") }
    "F-002" = @{ Name = "Password Manager"; Func = "Test-F002"; Severity = "HIGH"; Package = "FF-PKG-1"; VerifiedVia = "policies.json"; CISControls = @("1.2") }
    "F-003" = @{ Name = "Extension Installation"; Func = "Test-F003"; Severity = "HIGH"; Package = "FF-PKG-3"; VerifiedVia = "policies.json"; CISControls = @("1.3") }
    "F-004" = @{ Name = "Safe Browsing"; Func = "Test-F004"; Severity = "CRITICAL"; Package = "FF-PKG-2"; VerifiedVia = "policies.json"; CISControls = @("1.4"); IntuneReferenceUrl = "https://learn.microsoft.com/en-us/purview/dlp-browser-dlp-learn"; ManageEngineReferenceUrl = "https://www.manageengine.com/mobile-device-management/help/security_management/mdm_security_management.html" }
    "F-005" = @{ Name = "Telemetry Control"; Func = "Test-F005"; Severity = "MEDIUM"; Package = "FF-PKG-2"; VerifiedVia = "policies.json"; CISControls = @("1.5") }
    "F-006" = @{ Name = "Firefox Sync / Accounts"; Func = "Test-F006"; Severity = "CRITICAL"; Package = "FF-PKG-2"; VerifiedVia = "policies.json"; CISControls = @("1.6"); IntuneReferenceUrl = "https://learn.microsoft.com/en-us/intune/app-management/protection/overview"; ManageEngineReferenceUrl = "https://www.manageengine.com/mobile-device-management/help/profile_management/mdm_profile_management.html" }
    "F-007" = @{ Name = "DNS over HTTPS"; Func = "Test-F007"; Severity = "MEDIUM"; Package = "FF-PKG-5"; VerifiedVia = "policies.json"; CISControls = @("1.7") }
    "F-008" = @{ Name = "Cookie Behavior"; Func = "Test-F008"; Severity = "HIGH"; Package = "FF-PKG-4"; VerifiedVia = "policies.json"; CISControls = @("1.8") }
    "F-009" = @{ Name = "Disable Developer Tools"; Func = "Test-F009"; Severity = "MEDIUM"; Package = "FF-PKG-1"; VerifiedVia = "policies.json"; CISControls = @("1.9") }
    "F-010" = @{ Name = "Proxy Policy"; Func = "Test-F010"; Severity = "HIGH"; Package = "FF-PKG-5"; VerifiedVia = "policies.json"; CISControls = @("1.10") }
    "F-011" = @{ Name = "Disable Form History"; Func = "Test-F011"; Severity = "MEDIUM"; Package = "FF-PKG-2"; VerifiedVia = "policies.json"; CISControls = @("1.11") }
    "F-012" = @{ Name = "Command-Line & Runtime Flags"; Func = "Test-F012"; Severity = "MEDIUM"; Package = "FF-PKG-6"; VerifiedVia = "Process Command Line (Live)"; CISControls = @("1.12") }
    "F-013" = @{ Name = "HTTPS-Only Mode"; Func = "Test-F013"; Severity = "HIGH"; Package = "FF-PKG-7"; VerifiedVia = "prefs.js"; CISControls = @("1.31") }
    "F-014" = @{ Name = "TLS Minimum Version"; Func = "Test-F014"; Severity = "HIGH"; Package = "FF-PKG-7"; VerifiedVia = "prefs.js"; CISControls = @("1.32") }
    "F-015" = @{ Name = "Remote Debugging"; Func = "Test-F015"; Severity = "HIGH"; Package = "FF-PKG-7"; VerifiedVia = "prefs.js"; CISControls = @("1.39") }
    "F-016" = @{ Name = "Disable Experiments"; Func = "Test-F016"; Severity = "MEDIUM"; Package = "FF-PKG-7"; VerifiedVia = "prefs.js"; CISControls = @("1.14", "1.59") }
    "F-017" = @{ Name = "OCSP Validation"; Func = "Test-F017"; Severity = "HIGH"; Package = "FF-PKG-5"; VerifiedVia = "prefs.js"; CISControls = @() }
    "F-018" = @{ Name = "HTTP/3 Disable"; Func = "Test-F018"; Severity = "MEDIUM"; Package = "FF-PKG-5"; VerifiedVia = "prefs.js"; CISControls = @() }
    "F-019" = @{ Name = "Mixed Content Block"; Func = "Test-F019"; Severity = "HIGH"; Package = "FF-PKG-5"; VerifiedVia = "prefs.js"; CISControls = @() }
    "F-020" = @{ Name = "Certificate Pinning"; Func = "Test-F020"; Severity = "HIGH"; Package = "FF-PKG-5"; VerifiedVia = "prefs.js"; CISControls = @() }
}

$script:FirefoxCisMap = Get-FirefoxCisMapIndex
$script:FirefoxPolicyBundle = Get-FirefoxPolicies
$script:FirefoxPrefsBundle = Get-FirefoxPrefsText
$CisTestMap = Get-FirefoxCisTestsFromCatalog -CisMap $script:FirefoxCisMap

$TestMap = @{}
$BaseTestMap.Keys | ForEach-Object { $TestMap[$_] = $BaseTestMap[$_] }
$CisTestMap.Keys | Sort-Object | ForEach-Object { $TestMap[$_] = $CisTestMap[$_] }

if ($TestId -eq "ALL") {
    $TestMap.Keys | Sort-Object | ForEach-Object {
        $k = $_
        $cfg = $TestMap[$k]
        if ($cfg.Type -eq 'FF-REF') {
            $r = Invoke-FirefoxCisTest -Definition $cfg.Definition -Mapping $cfg.Mapping -PoliciesBundle $script:FirefoxPolicyBundle -PrefsBundle $script:FirefoxPrefsBundle
        } else {
            $r = & $cfg.Func
        }
        $manual = Get-FirefoxManualCheckGuidance -TestId $k -TestConfig $cfg -Result $r
        $defaultConfidence = if ($r.status -eq 'UNKNOWN') { 'LOW' } else { 'MEDIUM' }
        $evidenceOutput = Get-ResultFieldOrFallback -Result $r -FieldName "evidence_output" -FallbackValue (Get-ResultFieldOrFallback -Result $r -FieldName "details" -FallbackValue (Get-ResultField -Result $r -FieldName "message" -DefaultValue ""))
        $expectedValue = Get-ResultFieldOrFallback -Result $r -FieldName "expected_value" -FallbackValue $manual.manual_check_expected
        $observedValue = Get-ResultFieldOrFallback -Result $r -FieldName "observed_value" -FallbackValue ""
        $expectedMeta = Get-MachineComparableExpectation -ExpectedValue $expectedValue -ObservedValue $observedValue
        
        # Enrich test_method and rationale for CIS tests (if missing from Invoke-FirefoxCisTest)
        $testMethodVal = if (-not [string]::IsNullOrWhiteSpace($r.test_method)) { $r.test_method } else { "Firefox CIS $($cfg.CISControls[0]) - Strict policy/pref mapping via $($cfg.VerifiedVia)" }
        $rationaleVal = if (-not [string]::IsNullOrWhiteSpace($r.rationale)) { $r.rationale } else { "Firefox CIS Control $($cfg.CISControls[0]): $($cfg.Name) kurumsal guvenlik politikasina uygun olmali." }
        
        $policyKeyFallback = ''
        if ($cfg.Type -eq 'FF-REF' -and $null -ne $cfg.Mapping) {
            $policyKeyFallback = [string]$cfg.Mapping.key
        }

        $resultPayload = @{
            test_id = $k
            test_name = $cfg.Name
            package_id = $cfg.Package
            severity = $cfg.Severity
            cis_controls = $cfg.CISControls
            policy_key = Get-ResultFieldOrFallback -Result $r -FieldName "policy_key" -FallbackValue $policyKeyFallback
            verified_via = $cfg.VerifiedVia
            status = $r.status
            message = $r.message
            details = $r.details
            finding_details = $r.finding_details
            test_method = $testMethodVal
            rationale = $rationaleVal
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
            reference = if ($r.reference) { $r.reference } else { 'https://mozilla.github.io/policy-templates/' }
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
            retest_command = ".\\firefox_test_runner.ps1 -TestId $k"
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
    if ($cfg.Type -eq 'FF-REF') {
        $r = Invoke-FirefoxCisTest -Definition $cfg.Definition -Mapping $cfg.Mapping -PoliciesBundle $script:FirefoxPolicyBundle -PrefsBundle $script:FirefoxPrefsBundle
    } else {
        $r = & $cfg.Func
    }
    $manual = Get-FirefoxManualCheckGuidance -TestId $TestId -TestConfig $cfg -Result $r
    $defaultConfidence = if ($r.status -eq 'UNKNOWN') { 'LOW' } else { 'MEDIUM' }
    $evidenceOutput = Get-ResultFieldOrFallback -Result $r -FieldName "evidence_output" -FallbackValue (Get-ResultFieldOrFallback -Result $r -FieldName "details" -FallbackValue (Get-ResultField -Result $r -FieldName "message" -DefaultValue ""))
    $expectedValue = Get-ResultFieldOrFallback -Result $r -FieldName "expected_value" -FallbackValue $manual.manual_check_expected
    $observedValue = Get-ResultFieldOrFallback -Result $r -FieldName "observed_value" -FallbackValue ""
    $expectedMeta = Get-MachineComparableExpectation -ExpectedValue $expectedValue -ObservedValue $observedValue
    
    # Enrich test_method and rationale for CIS tests (if missing from Invoke-FirefoxCisTest)
    $testMethodVal = if (-not [string]::IsNullOrWhiteSpace($r.test_method)) { $r.test_method } else { "Firefox CIS $($cfg.CISControls[0]) - Strict policy/pref mapping via $($cfg.VerifiedVia)" }
    $rationaleVal = if (-not [string]::IsNullOrWhiteSpace($r.rationale)) { $r.rationale } else { "Firefox CIS Control $($cfg.CISControls[0]): $($cfg.Name) kurumsal guvenlik politikasina uygun olmali." }
    
    $policyKeyFallback = ''
    if ($cfg.Type -eq 'FF-REF' -and $null -ne $cfg.Mapping) {
        $policyKeyFallback = [string]$cfg.Mapping.key
    }

    $resultPayload = @{
        test_id = $TestId
        test_name = $cfg.Name
        package_id = $cfg.Package
        severity = $cfg.Severity
        cis_controls = $cfg.CISControls
        policy_key = Get-ResultFieldOrFallback -Result $r -FieldName "policy_key" -FallbackValue $policyKeyFallback
        verified_via = $cfg.VerifiedVia
        status = $r.status
        message = $r.message
        details = $r.details
        finding_details = $r.finding_details
        test_method = $testMethodVal
        rationale = $rationaleVal
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
        retest_command = ".\\firefox_test_runner.ps1 -TestId $TestId"
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
        browser = "Mozilla Firefox"
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
        @{ Label = "TEST NAME"; Expression = { $_.test_name }; Width = 30 },
        @{ Label = "STATUS"; Expression = { $_.status }; Width = 10 },
        @{ Label = "MESSAGE"; Expression = { $_.message }; Width = 40 }
    )
}

