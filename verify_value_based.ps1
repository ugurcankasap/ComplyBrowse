<#
Value-Based Compliance Verification Engine

Design principles:
  - Layers are an EVIDENCE PRECEDENCE CHAIN, not votes. Layer counting is removed.
  - Every layer performs expected_value vs actual_value comparison.
    If a deterministic comparison is impossible, the layer returns NOT_ASSESSED.
    Key presence alone is NEVER treated as compliance.
  - Layer 3 is an ARBITER, invoked only when the managed layer and the user layer conflict.

Layer evidence vocabulary (per layer):
    COMPLIANT             actual value matches expected value
    NON_COMPLIANT_VALUE   setting present but value does not match expected
    ABSENT                setting not configured at this layer
    NOT_APPLICABLE        this layer has no equivalent for the setting (policy-only control)
    NOT_ASSESSED          evidence unreadable or expectation not machine-comparable

Final verdict vocabulary (4 states):
    PASS                compliant AND enforced (managed layer)
    PASS_NOT_ENFORCED   compliant but only via user-level config (user can revert it)
    FAIL                non-compliant or not configured anywhere
    NOT_ASSESSED        insufficient evidence - excluded from the compliance score
#>

# ---------------------------------------------------------------------------
# Expectation parsing
# ---------------------------------------------------------------------------

function Get-ExpectedState {
    <#
      Normalizes the CIS expectation of a test record into ENABLED / DISABLED / $null.
      $null means the expectation is not machine-comparable, which forces NOT_ASSESSED
      instead of an optimistic guess.
    #>
    param([psobject]$Test)

    $candidates = @(
        $Test.expected_value,
        $Test.details,
        $Test.message
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    foreach ($text in $candidates) {
        $m = [regex]::Match($text, '(?i)expected[:\s]+([^|,\.]+)')
        $token = if ($m.Success) { $m.Groups[1].Value } else { $text }

        if ($token -match '(?i)\bdisabled?\b|\bblock(ed)?\b|\bfalse\b') { return 'DISABLED' }
        if ($token -match '(?i)\benabled?\b|\ballow(ed)?\b|\btrue\b')   { return 'ENABLED' }
    }

    return $null
}

# ---------------------------------------------------------------------------
# Layer 1 - Managed policy (Registry GPO / MDM / enterprise policies.json)
# ---------------------------------------------------------------------------

function Get-Layer1Evidence {
    <#
      Normalizes the test-runner outcome. The runners already compare policy values
      against the CIS expectation, so Layer 1 is re-expressed here rather than re-run.
    #>
    param([psobject]$Test)

    $result = @{
        layer    = 'L1'
        source   = 'Managed policy (Registry GPO / MDM / enterprise policies.json)'
        enforced = $true
        state    = 'NOT_ASSESSED'
        expected = ''
        actual   = ''
        details  = ''
    }

    $message = "$($Test.message) $($Test.details)"

    # A collector that reports it has no mapping or no way to check the control
    # has produced a coverage gap, not a policy observation. Reading that as
    # "policy present but wrong" would invent evidence that was never collected.
    if ($message -match '(?i)mapping (not|is not) (defined|available)|no mapping|not implemented|could not be (verified|checked)|cannot be (verified|checked)|eslesme tanimli degil') {
        $result.state    = 'NOT_ASSESSED'
        $result.details  = "The collector reported no verification mapping for this control. $($Test.message)"
        $result.expected = [string](Get-ExpectedState -Test $Test)
        $result.actual   = '(no check performed)'
        return $result
    }

    switch ($Test.status) {
        'PASSED' {
            $result.state   = 'COMPLIANT'
            $result.details = "Managed policy value matches CIS expectation. $($Test.message)"
        }
        'FAILED' {
            if ($message -match '(?i)missing|not configured|not found|tespit edilemedi|bulunamad') {
                $result.state   = 'ABSENT'
                $result.details = "No managed policy configured for this control. $($Test.message)"
            }
            else {
                $result.state   = 'NON_COMPLIANT_VALUE'
                $result.details = "Managed policy present but value does not match expectation. $($Test.message)"
            }
        }
        default {
            $result.state   = 'NOT_ASSESSED'
            $result.details = "Managed policy evidence inconclusive. $($Test.message)"
        }
    }

    $result.expected = [string](Get-ExpectedState -Test $Test)
    $result.actual   = [string]$Test.details

    return $result
}

# ---------------------------------------------------------------------------
# Layer 2 - User-level configuration
# ---------------------------------------------------------------------------

# Explicit policy -> user-preference mapping.
# Only controls with a genuine user-level equivalent are listed. Anything absent
# from this table is policy-only and correctly reported as NOT_APPLICABLE at L2.
# whenDisabled / whenEnabled describe the user-pref value that satisfies the
# corresponding CIS expectation.
$script:ChromiumPrefMap = @{
    'PasswordManagerEnabled'      = @{ pref = 'credentials_enable_service';                           whenDisabled = $false; whenEnabled = $true }
    'AutofillAddressEnabled'      = @{ pref = 'autofill.profile_enabled';                             whenDisabled = $false; whenEnabled = $true }
    'AutofillCreditCardEnabled'   = @{ pref = 'autofill.credit_card_enabled';                         whenDisabled = $false; whenEnabled = $true }
    'SearchSuggestEnabled'        = @{ pref = 'search.suggest_enabled';                               whenDisabled = $false; whenEnabled = $true }
    'TranslateEnabled'            = @{ pref = 'translate.enabled';                                    whenDisabled = $false; whenEnabled = $true }
    'PrintingEnabled'             = @{ pref = 'printing.enabled';                                     whenDisabled = $false; whenEnabled = $true }
    'AlternateErrorPagesEnabled'  = @{ pref = 'alternate_error_pages.enabled';                        whenDisabled = $false; whenEnabled = $true }
    'PaymentMethodQueryEnabled'   = @{ pref = 'payments.can_make_payment_enabled';                    whenDisabled = $false; whenEnabled = $true }
    'BlockThirdPartyCookies'      = @{ pref = 'profile.block_third_party_cookies';                    whenDisabled = $false; whenEnabled = $true }
    'SafeBrowsingProtectionLevel' = @{ pref = 'safebrowsing.enabled';                                 whenDisabled = $false; whenEnabled = $true }
    'DefaultGeolocationSetting'   = @{ pref = 'profile.default_content_setting_values.geolocation';   whenDisabled = 2;      whenEnabled = 1 }
    'DefaultNotificationsSetting' = @{ pref = 'profile.default_content_setting_values.notifications'; whenDisabled = 2;      whenEnabled = 1 }
    'DefaultPopupsSetting'        = @{ pref = 'profile.default_content_setting_values.popups';        whenDisabled = 2;      whenEnabled = 1 }
    'DefaultJavaScriptSetting'    = @{ pref = 'profile.default_content_setting_values.javascript';    whenDisabled = 2;      whenEnabled = 1 }
}

$script:FirefoxPrefMap = @{
    'OfferToSaveLogins'      = @{ pref = 'signon.rememberSignons';                   whenDisabled = $false; whenEnabled = $true }
    'PasswordManagerEnabled' = @{ pref = 'signon.rememberSignons';                   whenDisabled = $false; whenEnabled = $true }
    'DisableFormHistory'     = @{ pref = 'browser.formfill.enable';                  whenDisabled = $true;  whenEnabled = $false }
    'DisableTelemetry'       = @{ pref = 'datareporting.healthreport.uploadEnabled'; whenDisabled = $true;  whenEnabled = $false }
    'DisablePocket'          = @{ pref = 'extensions.pocket.enabled';                whenDisabled = $true;  whenEnabled = $false }
    'DisableFirefoxAccounts' = @{ pref = 'identity.fxaccounts.enabled';              whenDisabled = $true;  whenEnabled = $false }
    'DisableFirefoxStudies'  = @{ pref = 'app.shield.optoutstudies.enabled';         whenDisabled = $true;  whenEnabled = $false }
    'DisableDeveloperTools'  = @{ pref = 'devtools.policy.disabled';                 whenDisabled = $true;  whenEnabled = $false }
    'SearchSuggestEnabled'   = @{ pref = 'browser.search.suggest.enabled';           whenDisabled = $false; whenEnabled = $true }
    'PopupBlocking'          = @{ pref = 'dom.disable_open_during_load';             whenDisabled = $false; whenEnabled = $true }
    'SanitizeOnShutdown'     = @{ pref = 'privacy.sanitize.sanitizeOnShutdown';      whenDisabled = $false; whenEnabled = $true }
}

function Get-JsonValueByPath {
    <# Walks a dot-separated path in a parsed JSON object. Returns a hashtable with found/value. #>
    param([psobject]$Root, [string]$Path)

    $node = $Root
    foreach ($segment in $Path.Split('.')) {
        if ($null -eq $node) { return @{ found = $false; value = $null } }
        $property = $node.PSObject.Properties[$segment]
        if ($null -eq $property) { return @{ found = $false; value = $null } }
        $node = $property.Value
    }
    return @{ found = $true; value = $node }
}

function Get-FirefoxPrefValue {
    <# Reads a single pref from prefs.js / user.js. Returns a hashtable with found/value. #>
    param([string]$ProfilePath, [string]$PrefName)

    foreach ($fileName in @('user.js', 'prefs.js')) {
        $file = Join-Path $ProfilePath $fileName
        if (-not (Test-Path $file)) { continue }

        $pattern = 'user_pref\(\s*"' + [regex]::Escape($PrefName) + '"\s*,\s*([^)]+?)\s*\)'
        $match = [regex]::Match((Get-Content $file -Raw), $pattern)
        if (-not $match.Success) { continue }

        $raw = $match.Groups[1].Value.Trim().Trim('"')
        $value = switch -Regex ($raw) {
            '^(?i)true$'  { $true;  break }
            '^(?i)false$' { $false; break }
            '^-?\d+$'     {
                # Firefox stores timestamps that overflow Int32, so parse wide
                # and keep the raw string when it does not fit.
                $parsed = 0L
                if ([int64]::TryParse($raw, [ref]$parsed)) { $parsed } else { $raw }
                break
            }
            default       { $raw }
        }
        return @{ found = $true; value = $value; source = $fileName }
    }

    return @{ found = $false; value = $null; source = '' }
}

function Get-ChromiumProfileCandidates {
    <#
      Enterprise endpoints routinely carry more than one browser profile.
      Reading only "Default" reports a setting as unset whenever the user works
      in "Profile 1", so every profile directory that owns a Preferences file is
      scanned, with Default first.
    #>
    param([string]$Browser)

    $ordered = New-Object System.Collections.Generic.List[string]

    $userDataRoots = switch ($Browser) {
        'Edge'   { @("$env:LOCALAPPDATA\Microsoft\Edge\User Data", "$env:LOCALAPPDATA\Microsoft\Edge Beta\User Data") }
        'Chrome' { @("$env:LOCALAPPDATA\Google\Chrome\User Data", "$env:LOCALAPPDATA\Google\Chrome Beta\User Data") }
        default  { @() }
    }

    foreach ($root in $userDataRoots) {
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path $root)) { continue }

        $default = Join-Path $root 'Default\Preferences'
        if (Test-Path $default) { $ordered.Add($default) | Out-Null }

        $others = Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -ne 'Default' } |
                  Sort-Object Name
        foreach ($dir in $others) {
            $candidate = Join-Path $dir.FullName 'Preferences'
            if ((Test-Path $candidate) -and -not $ordered.Contains($candidate)) {
                $ordered.Add($candidate) | Out-Null
            }
        }
    }

    return $ordered.ToArray()
}

function Get-FirefoxProfileCandidates {
    <# Resolves likely Firefox profile directories with default profiles prioritized. #>
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
            $dirs = Get-ChildItem -Path $profilesRoot -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
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

function Get-Layer2Evidence {
    <#
      User-level configuration check with real value comparison.
      Returns NOT_APPLICABLE for policy-only controls instead of guessing.
    #>
    param(
        [string]$Browser,
        [string]$PolicyKey,
        [string]$ExpectedState,
        [string]$ExpectedRaw = '',
        [string]$ExpectedKind = '',
        [string]$ExpectedMachineValue = ''
    )

    $result = @{
        layer    = 'L2'
        source   = 'User-level configuration (Preferences / prefs.js)'
        enforced = $false
        state    = 'NOT_ASSESSED'
        expected = $ExpectedState
        actual   = ''
        details  = ''
    }

    if ([string]::IsNullOrWhiteSpace($PolicyKey)) {
        $result.details = 'Policy key could not be resolved for this control.'
        return $result
    }

    $map = if ($Browser -eq 'Firefox') { $script:FirefoxPrefMap } else { $script:ChromiumPrefMap }

    $isDirectFirefoxPref = $false
    if (-not $map.ContainsKey($PolicyKey)) {
        if ($Browser -eq 'Firefox' -and $PolicyKey -match '\.') {
            # Many Firefox CIS controls map directly to prefs.js keys.
            $isDirectFirefoxPref = $true
            $mapping = @{ pref = $PolicyKey; whenDisabled = $false; whenEnabled = $true }
        }
        else {
            $result.state   = 'NOT_APPLICABLE'
            $result.details = "'$PolicyKey' has no user-level equivalent; it is a policy-only control."
            return $result
        }
    }
    else {
        $mapping = $map[$PolicyKey]
    }

    $target  = if ($ExpectedState -eq 'DISABLED') { $mapping.whenDisabled } else { $mapping.whenEnabled }
    $result.expected = "$($mapping.pref) = $target"

    $comparisonMode = 'STATE'
    $numericTarget = $null
    $numericOp = ''
    $boolTarget = $null
    $enumTarget = ''

    if (-not [string]::IsNullOrWhiteSpace($ExpectedKind) -and -not [string]::IsNullOrWhiteSpace($ExpectedMachineValue)) {
        switch ($ExpectedKind) {
            'bool' {
                $comparisonMode = 'BOOL'
                $boolTarget = ([string]$ExpectedMachineValue).ToLowerInvariant() -eq 'true'
                $result.expected = "$($mapping.pref) = $boolTarget"
            }
            'present' {
                $comparisonMode = 'PRESENT'
                $result.expected = "$($mapping.pref) is present"
            }
            'enum' {
                $comparisonMode = 'ENUM'
                $enumTarget = ([string]$ExpectedMachineValue).ToLowerInvariant()
                $result.expected = "$($mapping.pref) = $enumTarget"
            }
            'numeric_gte' {
                $parsed = 0L
                if ([int64]::TryParse([string]$ExpectedMachineValue, [ref]$parsed)) {
                    $comparisonMode = 'NUM_GTE'
                    $numericTarget = $parsed
                    $numericOp = '>='
                    $result.expected = "$($mapping.pref) >= $numericTarget"
                }
            }
            'numeric_eq' {
                $parsed = 0L
                if ([int64]::TryParse([string]$ExpectedMachineValue, [ref]$parsed)) {
                    $comparisonMode = 'NUM_EQ'
                    $numericTarget = $parsed
                    $numericOp = '=='
                    $result.expected = "$($mapping.pref) == $numericTarget"
                }
            }
        }
    }

    if ($comparisonMode -eq 'STATE' -and -not $ExpectedState) {
        if ($isDirectFirefoxPref -and -not [string]::IsNullOrWhiteSpace($ExpectedRaw)) {
            $raw = $ExpectedRaw.ToLowerInvariant()
            if ($raw -match '(?i)expected:\s*(true|false)') {
                $comparisonMode = 'BOOL'
                $boolTarget = ($Matches[1].ToLowerInvariant() -eq 'true')
                $result.expected = "$($mapping.pref) = $boolTarget"
            }
            elseif ($raw -match '(?i)>=\s*(-?\d+)') {
                $comparisonMode = 'NUM_GTE'
                $numericTarget = [int64]$Matches[1]
                $numericOp = '>='
                $result.expected = "$($mapping.pref) >= $numericTarget"
            }
            elseif ($raw -match '(?i)en az\s*(-?\d+)') {
                $comparisonMode = 'NUM_GTE'
                $numericTarget = [int64]$Matches[1]
                $numericOp = '>='
                $result.expected = "$($mapping.pref) >= $numericTarget"
            }
            elseif ($raw -match '(?i)expected:\s*(-?\d+)') {
                $comparisonMode = 'NUM_EQ'
                $numericTarget = [int64]$Matches[1]
                $numericOp = '=='
                $result.expected = "$($mapping.pref) == $numericTarget"
            }
            else {
                $result.details = "Expectation for '$PolicyKey' is not machine-comparable; no value check performed."
                return $result
            }
        }
        else {
            $result.details = "Expectation for '$PolicyKey' is not machine-comparable; no value check performed."
            return $result
        }
    }

    if ($Browser -eq 'Firefox') {
        $profileCandidates = Get-FirefoxProfileCandidates
        if ($profileCandidates.Count -eq 0) {
            $result.details = 'No Firefox profile available to read.'
            return $result
        }

        $lookup = @{ found = $false; value = $null; source = '' }
        $scanned = 0
        foreach ($profilePath in $profileCandidates) {
            $scanned++
            $candidate = Get-FirefoxPrefValue -ProfilePath $profilePath -PrefName $mapping.pref
            if ($candidate.found) {
                $lookup = $candidate
                $lookup.source = Join-Path $profilePath $candidate.source
                break
            }
        }

        if (-not $lookup.found) {
            $result.state   = 'ABSENT'
            $result.actual  = '(not set)'
            $result.details = "User preference '$($mapping.pref)' is not set in scanned Firefox profiles ($scanned profile(s)); browser default applies."
            return $result
        }
    }
    else {
        $profileCandidates = @(Get-ChromiumProfileCandidates -Browser $Browser)
        if ($profileCandidates.Count -eq 0) {
            $result.details = "$Browser Preferences file not found in any profile."
            return $result
        }

        $lookup = @{ found = $false; value = $null; source = '' }
        $parsed = 0
        foreach ($prefsPath in $profileCandidates) {
            try {
                $prefs = Get-Content $prefsPath -Raw -Encoding UTF8 | ConvertFrom-Json
            }
            catch {
                continue
            }
            $parsed++

            $candidate = Get-JsonValueByPath -Root $prefs -Path $mapping.pref
            if ($candidate.found) {
                $lookup = $candidate
                $lookup.source = $prefsPath
                break
            }
        }

        if ($parsed -eq 0) {
            $result.details = "$Browser Preferences files could not be parsed ($($profileCandidates.Count) candidate(s))."
            return $result
        }

        if (-not $lookup.found) {
            $result.state   = 'ABSENT'
            $result.actual  = '(not set)'
            $result.details = "User preference '$($mapping.pref)' is not set in any scanned $Browser profile ($parsed profile(s)); browser default applies."
            return $result
        }
    }

    if (-not $lookup.found) {
        $result.state   = 'ABSENT'
        $result.actual  = '(not set)'
        $result.details = "User preference '$($mapping.pref)' is not set; browser default applies."
        return $result
    }

    $sourceSuffix = if (-not [string]::IsNullOrWhiteSpace([string]$lookup.source)) { " (source: $($lookup.source))" } else { '' }
    $result.actual = "$($mapping.pref) = $($lookup.value)$sourceSuffix"

    $isCompliant = $false
    if ($comparisonMode -eq 'STATE') {
        $isCompliant = ([string]$lookup.value -eq [string]$target)
    }
    elseif ($comparisonMode -eq 'PRESENT') {
        $isCompliant = $lookup.found -and -not [string]::IsNullOrWhiteSpace([string]$lookup.value)
    }
    elseif ($comparisonMode -eq 'BOOL') {
        $valBool = $null
        $s = [string]$lookup.value
        if ($s -match '^(?i:true|false)$') {
            $valBool = ($s.ToLowerInvariant() -eq 'true')
        }
        $isCompliant = ($null -ne $valBool -and $valBool -eq $boolTarget)
    }
    elseif ($comparisonMode -in @('NUM_GTE', 'NUM_EQ')) {
        [int64]$actualNum = 0
        if ([int64]::TryParse([string]$lookup.value, [ref]$actualNum)) {
            if ($comparisonMode -eq 'NUM_GTE') { $isCompliant = ($actualNum -ge $numericTarget) }
            if ($comparisonMode -eq 'NUM_EQ')  { $isCompliant = ($actualNum -eq $numericTarget) }
        }
    }
    elseif ($comparisonMode -eq 'ENUM') {
        $isCompliant = ([string]$lookup.value).ToLowerInvariant() -eq $enumTarget
    }

    if ($isCompliant) {
        $result.state = 'COMPLIANT'
        if ($isDirectFirefoxPref) {
            $result.details = "Direct Firefox pref matches expectation ($($mapping.pref) = $($lookup.value))."
        } else {
            $result.details = "User preference matches expectation ($($mapping.pref) = $($lookup.value))."
        }
    } else {
        $result.state = 'NON_COMPLIANT_VALUE'
        if ($isDirectFirefoxPref) {
            if ($comparisonMode -in @('NUM_GTE', 'NUM_EQ')) {
                $result.details = "Direct Firefox pref value mismatch: expected $numericOp $numericTarget, found $($lookup.value)."
            } elseif ($comparisonMode -eq 'BOOL') {
                $result.details = "Direct Firefox pref value mismatch: expected $boolTarget, found $($lookup.value)."
            } elseif ($comparisonMode -eq 'ENUM') {
                $result.details = "Direct Firefox pref value mismatch: expected '$enumTarget', found '$($lookup.value)'."
            } else {
                $result.details = "Direct Firefox pref value mismatch: expected $target, found $($lookup.value)."
            }
        } else {
            if ($comparisonMode -in @('NUM_GTE', 'NUM_EQ')) {
                $result.details = "User preference value mismatch: expected $numericOp $numericTarget, found $($lookup.value)."
            } elseif ($comparisonMode -eq 'BOOL') {
                $result.details = "User preference value mismatch: expected $boolTarget, found $($lookup.value)."
            } elseif ($comparisonMode -eq 'ENUM') {
                $result.details = "User preference value mismatch: expected '$enumTarget', found '$($lookup.value)'."
            } else {
                $result.details = "User preference value mismatch: expected $target, found $($lookup.value)."
            }
        }
    }

    return $result
}

# ---------------------------------------------------------------------------
# Layer 3 - Runtime arbiter (invoked only on L1/L2 conflict)
# ---------------------------------------------------------------------------

function Get-Layer3Arbiter {
    <#
      Runtime truth check. Only called when the managed layer and the user layer
      disagree. Looks for command-line switches that can neutralise a deployed policy.
      Returns NOT_ASSESSED when no conclusive runtime evidence is available -
      it never invents a verdict.
    #>
    param(
        [string]$Browser,
        [psobject]$Test
    )

    $result = @{
        layer    = 'L3'
        source   = 'Runtime arbiter (process command line)'
        enforced = $false
        state    = 'NOT_ASSESSED'
        expected = 'No policy-neutralising runtime override'
        actual   = ''
        details  = 'Arbiter not invoked.'
    }

    $processName = switch ($Browser) {
        'Edge'    { 'msedge' }
        'Chrome'  { 'chrome' }
        'Firefox' { 'firefox' }
        default   { $null }
    }
    if (-not $processName) { return $result }

    # The arbiter inspects generic policy-neutralising switches. That signal says
    # nothing about a control whose evidence lives outside this endpoint (identity
    # backend, proxy/MITM appliance, cloud console). Treating "no override switch"
    # as proof of compliance for such controls manufactures a PASS out of nothing.
    $externalEvidence = "$($Test.verified_via) $($Test.details)"
    if ($externalEvidence -match '(?i)\bexternal\b|backend|cannot test|test edilemez|manual (check|verification|review)') {
        $result.state   = 'NOT_ASSESSED'
        $result.actual  = '(evidence not obtainable on this endpoint)'
        $result.details = 'This control is verified outside the endpoint (identity backend, network inspection or manual review). Local runtime evidence cannot decide it.'
        return $result
    }

    try {
        $commandLines = @(Get-CimInstance Win32_Process -Filter "Name='$processName.exe'" -ErrorAction Stop |
                          Select-Object -ExpandProperty CommandLine)
    }
    catch {
        $commandLines = @()
    }

    if (-not $commandLines -or $commandLines.Count -eq 0) {
        $via = [string]$Test.verified_via
        if ($via -match '(?i)runtime|process command line|win32_process') {
            if ([string]$Test.status -eq 'PASSED') {
                $result.state = 'COMPLIANT'
                $result.actual = 'Runtime status from test runner: PASSED'
                $result.details = 'Runtime process output was not readable now, but test runner runtime evidence indicates compliant behavior.'
                return $result
            }
            if ([string]$Test.status -eq 'FAILED') {
                $result.state = 'NON_COMPLIANT_VALUE'
                $result.actual = 'Runtime status from test runner: FAILED'
                $result.details = 'Runtime process output was not readable now, but test runner runtime evidence indicates non-compliant behavior.'
                return $result
            }
        }

        $result.details = "$Browser is not running; runtime evidence unavailable."
        return $result
    }

    $overridePatterns = @(
        '--disable-features=',
        '--disable-policy',
        '--allow-running-insecure-content',
        '--disable-web-security',
        '--remote-debugging-port'
    )

    $hits = @()
    foreach ($line in $commandLines) {
        foreach ($pattern in $overridePatterns) {
            if ($line -like "*$pattern*") { $hits += $pattern }
        }
    }
    $hits = @($hits | Select-Object -Unique)

    if ($hits.Count -gt 0) {
        $result.state   = 'NON_COMPLIANT_VALUE'
        $result.actual  = ($hits -join ', ')
        $result.details = "Runtime override switches detected that can neutralise policy: $($hits -join ', ')"
    }
    else {
        # Absence of a bypass switch is only meaningful for controls whose evidence
        # really is the process command line. For anything else it proves nothing
        # about the control, and promoting it to COMPLIANT would manufacture a PASS.
        $runtimeScoped = "$($Test.verified_via) $($Test.test_method)"
        if ($runtimeScoped -match '(?i)runtime|process command line|process argument|win32_process|command[- ]line') {
            $result.state   = 'COMPLIANT'
            $result.actual  = 'No override switches present'
            $result.details = 'No policy-neutralising command-line switch found in the running browser.'
        }
        else {
            $result.state   = 'NOT_ASSESSED'
            $result.actual  = 'No override switches present'
            $result.details = 'No policy-neutralising command-line switch was found, but this control is not verified through the command line. Absence of a bypass switch is not evidence of compliance for it.'
        }
    }

    return $result
}

# ---------------------------------------------------------------------------
# Verdict resolution - evidence precedence, not voting
# ---------------------------------------------------------------------------

function Resolve-ComplianceVerdict {
    <#
      Managed policy outranks user configuration, because a managed policy cannot be
      changed by the user and overrides any user preference. User configuration only
      matters when no managed policy is present.
    #>
    param(
        [string]$Browser,
        [hashtable]$Layer1,
        [hashtable]$Layer2,
        [hashtable]$Layer3
    )

    $l1 = $Layer1.state
    $l2 = $Layer2.state
    $l3 = if ($Layer3) { $Layer3.state } else { 'NOT_ASSESSED' }

    # Runtime-only controls: when L1/L2 are not applicable, allow L3 to provide
    # the final compliance decision.
    if ($l1 -eq 'NOT_APPLICABLE' -and $l2 -eq 'NOT_APPLICABLE') {
        if ($l3 -eq 'COMPLIANT') {
            return @{
                verdict         = 'PASS'
                deciding_layer  = 'L3'
                counts_in_score = $true
                reasoning       = 'This control is runtime-oriented, so L1/L2 are not applicable; L3 evidence is compliant, therefore the verdict is PASS.'
            }
        }
        if ($l3 -eq 'NON_COMPLIANT_VALUE') {
            return @{
                verdict         = 'FAIL'
                deciding_layer  = 'L3'
                counts_in_score = $true
                reasoning       = 'This control is runtime-oriented, so L1/L2 are not applicable; L3 evidence is non-compliant, therefore the verdict is FAIL.'
            }
        }
    }

    # Conflict or drift indicator: policy looks compliant, but lower layers diverge.
    if ($l1 -eq 'COMPLIANT' -and ($l2 -in @('NON_COMPLIANT_VALUE', 'ABSENT', 'NOT_ASSESSED'))) {
        if ($l3 -eq 'NON_COMPLIANT_VALUE') {
            return @{
                verdict         = 'FAIL'
                deciding_layer  = 'L3'
                counts_in_score = $true
                reasoning       = 'L1 policy appears compliant, but the L2/L3 layers show a drift/bypass signal; L3 runtime evidence indicates the policy effect is bypassed, therefore the verdict is FAIL.'
            }
        }
        if ($l3 -eq 'COMPLIANT') {
            return @{
                verdict         = 'PASS'
                deciding_layer  = 'L3'
                counts_in_score = $true
                reasoning       = 'Although a drift/mismatch signal exists between L1 and L2, L3 runtime evidence confirmed effective enforcement; the verdict is PASS.'
            }
        }
    }

    if ($l1 -eq 'COMPLIANT') {
        if ($l2 -eq 'NOT_APPLICABLE' -and $l3 -eq 'NON_COMPLIANT_VALUE') {
            return @{
                verdict         = 'FAIL'
                deciding_layer  = 'L3'
                counts_in_score = $true
                reasoning       = 'L1 appears compliant, but runtime evidence indicates the policy effect is bypassed in the live environment; the verdict is FAIL, decided at L3.'
            }
        }
        if ($l2 -eq 'NOT_APPLICABLE' -and $l3 -eq 'COMPLIANT') {
            return @{
                verdict         = 'PASS'
                deciding_layer  = 'L3'
                counts_in_score = $true
                reasoning       = 'This control carries a runtime signal and L2 is not applicable; L3 evidence is compliant, so the verdict is PASS, decided at L3.'
            }
        }

        return @{
            verdict         = 'PASS'
            deciding_layer  = 'L1'
            counts_in_score = $true
            reasoning       = 'The L1 managed policy value matches the CIS expectation and is enforced; the final verdict is PASS.'
        }
    }

    if ($l1 -eq 'NON_COMPLIANT_VALUE') {
        return @{
            verdict         = 'FAIL'
            deciding_layer  = 'L1'
            counts_in_score = $true
            reasoning       = 'An L1 managed policy exists but its value does not match the CIS expectation; because managed policy overrides user settings, the final verdict is FAIL.'
        }
    }

    # A compliant user-level value is the only thing that can compensate for a
    # missing managed policy, and it is never treated as enforced.
    if ($l2 -eq 'COMPLIANT') {
        return @{
            verdict         = 'PASS_NOT_ENFORCED'
            deciding_layer  = 'L2'
            counts_in_score = $false
            reasoning       = 'The setting is compliant only at the L2 user level. Because the user can revert it, the verdict is marked PASS_NOT_ENFORCED.'
        }
    }

    if ($l1 -eq 'ABSENT') {
        if ($l2 -eq 'COMPLIANT') {
            if ($l3 -eq 'NON_COMPLIANT_VALUE') {
                return @{
                    verdict         = 'FAIL'
                    deciding_layer  = 'L3'
                    counts_in_score = $true
                    reasoning       = 'The L2 user setting appears compliant, but L3 runtime evidence shows the setting is not effective; the verdict is FAIL.'
                }
            }

            return @{
                verdict         = 'PASS_NOT_ENFORCED'
                deciding_layer  = if ($l3 -eq 'COMPLIANT') { 'L3' } else { 'L2' }
                counts_in_score = $false
                reasoning       = 'No L1 managed policy is deployed; the L2 user setting is compliant, so compliance is temporary and not enforced, therefore the verdict is PASS_NOT_ENFORCED.'
            }
        }

        if ($l2 -eq 'NON_COMPLIANT_VALUE') {
            return @{
                verdict         = 'FAIL'
                deciding_layer  = 'L2'
                counts_in_score = $true
                reasoning       = 'No L1 managed policy is deployed and the L2 user configuration value is explicitly non-compliant; based on concrete L2 evidence, the verdict is FAIL.'
            }
        }

        if ($Browser -eq 'Firefox' -and $l2 -in @('ABSENT', 'NOT_ASSESSED')) {
            return @{
                verdict         = 'NOT_ASSESSED'
                deciding_layer  = 'NONE'
                counts_in_score = $false
                reasoning       = 'For Firefox, when no managed policy exists and the user preference is missing or unreadable, default behaviour is treated as indeterminate; NOT_ASSESSED was returned instead of FAIL.'
            }
        }

        if ($l2 -eq 'ABSENT') {
            if ($Browser -eq 'Firefox') {
                return @{
                    verdict         = 'NOT_ASSESSED'
                    deciding_layer  = 'NONE'
                    counts_in_score = $false
                    reasoning       = 'For Firefox, when no managed policy exists and no user preference is defined, default behaviour is treated as indeterminate; NOT_ASSESSED was returned instead of FAIL.'
                }
            }

            return @{
                verdict         = 'FAIL'
                deciding_layer  = 'L2'
                counts_in_score = $true
                reasoning       = 'No L1 managed policy is deployed. A user-level preference equivalent exists for this control at L2, but no value is defined; therefore the verdict is FAIL.'
            }
        }

        # The managed layer was read successfully and the policy is definitively
        # not deployed. Absence of evidence for a required control is a finding,
        # so this is a FAIL rather than NOT_ASSESSED.
        $why = switch ($l2) {
            'NON_COMPLIANT_VALUE' { 'the L2 user configuration value is also non-compliant' }
            'ABSENT'              { 'the setting is not defined at the L2 user layer either' }
            'NOT_APPLICABLE'      { 'this control is policy-oriented and has no equivalent at the user layer' }
            default               { 'no compensating compliance evidence could be obtained at L2' }
        }
        return @{
            verdict         = 'FAIL'
            deciding_layer  = 'L1'
            counts_in_score = $true
            reasoning       = "No L1 managed policy is deployed for this control and $why; therefore the verdict is FAIL."
        }
    }

    if ($l2 -eq 'NON_COMPLIANT_VALUE') {
        return @{
            verdict         = 'FAIL'
            deciding_layer  = 'L2'
            counts_in_score = $true
            reasoning       = 'L1 layer evidence is inconclusive and the L2 user value is non-compliant; with the available evidence the final verdict is FAIL.'
        }
    }

    # Reserved for the case where the managed layer itself could not be read.
    return @{
        verdict         = 'NOT_ASSESSED'
        deciding_layer  = 'NONE'
        counts_in_score = $false
        reasoning       = 'L1 managed-layer evidence could not be read and no comparable value was found at L2; this control was excluded from scoring and marked NOT_ASSESSED.'
    }
}
