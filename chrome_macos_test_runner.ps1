# Chrome Security Test Runner - macOS evidence collector.
# PowerShell 7 only. The emitted result contract is identical to
# chrome_test_runner.ps1 so apply_verification.ps1 and the reporting layer
# consume Windows and macOS runs without any change.
param(
    [string]$TestId = "ALL",
    [switch]$OutputJSON = $false,
    [string]$OutputFile = ""
)

$script:TestResults = @()
$script:RunId = Get-Date -Format "yyyyMMdd_HHmmss"
$script:ArtifactsRoot = Join-Path $PSScriptRoot "artifacts"
$script:ArtifactsRunDir = ""

# ---------------------------------------------------------------------------
# Shared evidence helpers (fail-fast: a missing collector is a coverage gap,
# not something to silently work around)
# ---------------------------------------------------------------------------

$script:EvidenceHelperPath = Join-Path $PSScriptRoot 'macos_evidence.ps1'
if (-not (Test-Path -LiteralPath $script:EvidenceHelperPath)) {
    throw "macOS evidence helper not found: $script:EvidenceHelperPath. The run cannot continue with incomplete evidence coverage."
}
. $script:EvidenceHelperPath

$script:IsMacHost = ($PSVersionTable.PSVersion.Major -ge 6) -and [bool]$IsMacOS
$script:ChromeDomain = 'com.google.Chrome'
$script:ManagedPreferencesRoot = '/Library/Managed Preferences'
$script:SystemPreferencesRoot = '/Library/Preferences'

$script:UserHome = [Environment]::GetFolderPath('UserProfile')
if ([string]::IsNullOrWhiteSpace($script:UserHome)) { $script:UserHome = "$HOME" }
$script:UserPreferencesRoot = Join-Path $script:UserHome 'Library/Preferences'
$script:ChromeProfileRoot = Join-Path $script:UserHome 'Library/Application Support/Google/Chrome'

$script:ChromeBundlePaths = @(
    '/Applications/Google Chrome.app',
    (Join-Path $script:UserHome 'Applications/Google Chrome.app'),
    '/Applications/Google Chrome Beta.app',
    '/Applications/Google Chrome Dev.app',
    '/Applications/Google Chrome Canary.app'
)

# Bypass flags that neutralise a deployed policy at runtime.
$script:ChromeBypassFlags = @(
    '--no-sandbox',
    '--disable-web-security',
    '--allow-running-insecure-content',
    '--disable-site-isolation-trials',
    '--ignore-certificate-errors',
    '--remote-debugging-port',
    '--remote-debugging-pipe'
)

# Policy keys with a genuine per-profile user preference equivalent.
$script:ChromeProfilePrefMap = @{
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
    'SavingBrowserHistoryDisabled'= @{ pref = 'savingbrowserhistorydisabled';                         whenDisabled = $false; whenEnabled = $true }
    'DefaultGeolocationSetting'   = @{ pref = 'profile.default_content_setting_values.geolocation';   whenDisabled = 2;      whenEnabled = 1 }
    'DefaultNotificationsSetting' = @{ pref = 'profile.default_content_setting_values.notifications'; whenDisabled = 2;      whenEnabled = 1 }
    'DefaultPopupsSetting'        = @{ pref = 'profile.default_content_setting_values.popups';        whenDisabled = 2;      whenEnabled = 1 }
    'DefaultJavaScriptSetting'    = @{ pref = 'profile.default_content_setting_values.javascript';    whenDisabled = 2;      whenEnabled = 1 }
}

# ---------------------------------------------------------------------------
# Shared runner library (artifact store, result fields, report text helpers)
# ---------------------------------------------------------------------------

$script:CommonLibraryPath = Join-Path $PSScriptRoot 'lib/common.ps1'
if (-not (Test-Path -LiteralPath $script:CommonLibraryPath)) {
    throw "Shared runner library not found: $script:CommonLibraryPath. The run cannot continue with incomplete evidence coverage."
}
. $script:CommonLibraryPath

# macOS runs also record the runner verdict and the evidence provenance.
$script:ArtifactSnapshotExtraFields = [ordered]@{
    runner_verdict = ''
    evidence_source_label = ''
    evidence_paths = @()
}

# ---------------------------------------------------------------------------
# macOS preference stores
# ---------------------------------------------------------------------------

function Get-MacDomainPlistCandidate {
    param([ValidateSet('Managed', 'System', 'User')][string]$Scope)

    $domainFile = "$($script:ChromeDomain).plist"
    switch ($Scope) {
        'Managed' {
            $paths = @((Join-Path $script:ManagedPreferencesRoot $domainFile))
            foreach ($dir in (Get-ChildItem -LiteralPath $script:ManagedPreferencesRoot -Directory -Force -ErrorAction SilentlyContinue)) {
                $paths += (Join-Path $dir.FullName $domainFile)
            }
            return @($paths | Select-Object -Unique)
        }
        'System' { return @((Join-Path $script:SystemPreferencesRoot $domainFile)) }
        'User'   { return @((Join-Path $script:UserPreferencesRoot $domainFile)) }
    }
    return @()
}

function Initialize-MacPreferenceStore {
    param([ValidateSet('Managed', 'System', 'User')][string]$Scope)

    $store = @{
        scope = $Scope
        documents = @()
        access_denied = $false
        denied_paths = @()
    }
    if (-not $script:IsMacHost) { return $store }

    if ($Scope -eq 'Managed') {
        $rootAccess = Test-MacReadAccess -Path $script:ManagedPreferencesRoot
        if ($rootAccess.access_denied) {
            $store.access_denied = $true
            $store.denied_paths += $script:ManagedPreferencesRoot
        }
    }

    foreach ($path in (Get-MacDomainPlistCandidate -Scope $Scope)) {
        $access = Test-MacReadAccess -Path $path
        if (-not $access.exists) { continue }
        if (-not $access.readable) {
            $store.access_denied = $true
            $store.denied_paths += $path
            continue
        }

        $document = ConvertFrom-MacPlistJson -Path $path
        if ($document.state -eq 'read') {
            $store.documents += @{ path = $path; value = $document.value }
        }
        else {
            # An existing plist that cannot be parsed is unreadable evidence, not
            # proof that the setting is absent.
            $store.access_denied = $true
            $store.denied_paths += $path
        }
    }

    return $store
}

function Get-MacStoreValue {
    param(
        [hashtable]$Store,
        [string]$Key
    )

    $result = @{
        found = $false
        value = $null
        display = ''
        source_path = ''
        access_denied = [bool]$Store.access_denied
    }
    if ([string]::IsNullOrWhiteSpace($Key)) { return $result }

    foreach ($document in @($Store.documents)) {
        if ($null -eq $document.value) { continue }
        $property = $document.value.PSObject.Properties |
            Where-Object { $_.Name -ieq $Key } |
            Select-Object -First 1
        if ($null -ne $property) {
            $result.found = $true
            $result.value = $property.Value
            $result.display = ConvertTo-MacDisplayValue -Value $property.Value
            $result.source_path = [string]$document.path
            return $result
        }
    }

    return $result
}

function Initialize-MacChromeProfileStore {
    <#
      Enterprise endpoints routinely carry more than one Chrome profile. Reading
      only "Default" reports a setting as unset whenever the user works in
      "Profile 1", so every profile directory owning a Preferences file is read.
    #>
    $store = @{
        root = $script:ChromeProfileRoot
        profiles = @()
        access_denied = $false
        denied_paths = @()
        unreadable_paths = @()
    }
    if (-not $script:IsMacHost) { return $store }

    $rootAccess = Test-MacReadAccess -Path $script:ChromeProfileRoot
    if ($rootAccess.access_denied) {
        $store.access_denied = $true
        $store.denied_paths += $script:ChromeProfileRoot
        return $store
    }
    if (-not $rootAccess.exists) { return $store }

    $profileDirs = @()
    $defaultDir = Join-Path $script:ChromeProfileRoot 'Default'
    if (Test-Path -LiteralPath $defaultDir) { $profileDirs += $defaultDir }
    foreach ($dir in (Get-ChildItem -LiteralPath $script:ChromeProfileRoot -Directory -Force -ErrorAction SilentlyContinue | Sort-Object Name)) {
        if ($dir.Name -eq 'Default') { continue }
        $profileDirs += $dir.FullName
    }

    foreach ($dir in $profileDirs) {
        $prefPath = Join-Path $dir 'Preferences'
        $access = Test-MacReadAccess -Path $prefPath
        if (-not $access.exists) { continue }
        if (-not $access.readable) {
            $store.access_denied = $true
            $store.denied_paths += $prefPath
            continue
        }

        try {
            $parsed = Get-Content -LiteralPath $prefPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $store.profiles += @{ name = (Split-Path $dir -Leaf); path = $prefPath; value = $parsed }
        }
        catch {
            $store.unreadable_paths += $prefPath
        }
    }

    return $store
}

function Get-JsonValueByPath {
    param(
        [object]$Root,
        [string]$Path
    )

    $result = @{ found = $false; value = $null }
    if ($null -eq $Root -or [string]::IsNullOrWhiteSpace($Path)) { return $result }

    $node = $Root
    foreach ($segment in ($Path -split '\.')) {
        if ($null -eq $node) { return $result }
        $property = $node.PSObject.Properties[$segment]
        if ($null -eq $property) { return $result }
        $node = $property.Value
    }

    $result.found = $true
    $result.value = $node
    return $result
}

function Get-MacChromeProfilePrefValue {
    param([string]$PolicyKey)

    $result = @{ found = $false; value = $null; display = ''; source_path = ''; pref = ''; expectation = $null }
    if (-not $script:ChromeProfilePrefMap.ContainsKey($PolicyKey)) { return $result }

    $mapping = $script:ChromeProfilePrefMap[$PolicyKey]
    $result.pref = [string]$mapping.pref
    $result.expectation = $mapping

    foreach ($prof in @($script:ChromeProfileStore.profiles)) {
        $lookup = Get-JsonValueByPath -Root $prof.value -Path $mapping.pref
        if ($lookup.found) {
            $result.found = $true
            $result.value = $lookup.value
            $result.display = "$($mapping.pref)=$(ConvertTo-MacDisplayValue -Value $lookup.value) [profile: $($prof.name)]"
            $result.source_path = [string]$prof.path
            return $result
        }
    }

    return $result
}

function Get-MacChromeProcessArgument {
    if (-not $script:IsMacHost) { return @() }
    try {
        $rows = Get-MacProcessArguments -ProcessNamePattern '(?i)chrome|google'
    }
    catch { return @() }
    return @($rows)
}

function Test-MacChromeInstalled {
    if (-not $script:IsMacHost) { return $false }
    foreach ($bundle in $script:ChromeBundlePaths) {
        $access = Test-MacReadAccess -Path $bundle
        if ($access.exists) { return $true }
    }
    return $false
}

function Get-MacAppVersionText {
    param([string[]]$BundlePath)

    if (-not $script:IsMacHost) { return "NOT_ASSESSED" }
    try {
        $version = Get-MacAppVersion -BundlePath $BundlePath
    }
    catch { return "NOT_FOUND" }

    if ($version.access_denied) { return "ACCESS_DENIED" }
    if ($version.found) { return [string]$version.value }
    return "NOT_FOUND"
}

function Get-EnvironmentInfo {
    return @{
        hostname = [Environment]::MachineName
        platform = if ($script:IsMacHost) { 'macOS' } else { [string][System.Runtime.InteropServices.RuntimeInformation]::OSDescription }
        os_version = [string][System.Environment]::OSVersion.Version
        browser_versions = @{
            chrome = Get-MacAppVersionText -BundlePath $script:ChromeBundlePaths
            edge = Get-MacAppVersionText -BundlePath @('/Applications/Microsoft Edge.app', (Join-Path $script:UserHome 'Applications/Microsoft Edge.app'))
            firefox = Get-MacAppVersionText -BundlePath @('/Applications/Firefox.app', (Join-Path $script:UserHome 'Applications/Firefox.app'))
        }
        evidence_sources = @{
            managed_preferences = $script:ManagedPreferencesRoot
            system_preferences = $script:SystemPreferencesRoot
            user_preferences = $script:UserPreferencesRoot
            chrome_profiles = $script:ChromeProfileRoot
        }
    }
}

# ---------------------------------------------------------------------------
# Expectation parsing (identical semantics to chrome_test_runner.ps1)
# ---------------------------------------------------------------------------

function Get-MacExpectedState {
    param([string]$ExpectedText)

    if ([string]::IsNullOrWhiteSpace($ExpectedText)) { return '' }
    if ($ExpectedText -match '(?i)\bdisabled?\b|\bblock(ed)?\b|\bfalse\b') { return 'DISABLED' }
    if ($ExpectedText -match '(?i)\benabled?\b|\ballow(ed)?\b|\btrue\b') { return 'ENABLED' }
    return ''
}

function Test-MacPolicyExpectation {
    param(
        [object]$Value,
        [string]$Expected,
        [string]$PolicyKey = ''
    )

    $vStr = [string]$Value
    $vLower = $vStr.ToLowerInvariant()
    $isDisabledValue = @('0', 'false', 'disabled', 'no') -contains $vLower
    $isEnabledValue = -not [string]::IsNullOrWhiteSpace($vStr) -and -not $isDisabledValue

    if ([string]::IsNullOrWhiteSpace($Expected)) {
        return @{ status = 'UNKNOWN'; message = "Policy value found ($vStr), expected pattern could not be parsed" }
    }

    # IncognitoModeAvailability is an enum, not a boolean: 1 = Disabled,
    # 2 = Forced Off. Comparing it as a plain number reports an enforced
    # restriction as non-compliant.
    if ($PolicyKey -eq 'IncognitoModeAvailability' -and $Expected -match '(?i)disabled') {
        [int64]$mode = -1
        if ([int64]::TryParse($vStr, [ref]$mode)) {
            $ok = ($mode -eq 1 -or $mode -eq 2)
            return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = "Expected Disabled, actual policy mode: $mode" }
        }
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

    $state = Get-MacExpectedState -ExpectedText $ExpectedText

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

# ---------------------------------------------------------------------------
# Catalog and macOS policy map (fail-fast, no silent scope reduction)
# ---------------------------------------------------------------------------

function Get-MacPolicyMapIndex {
    $mapPath = Join-Path $PSScriptRoot 'chrome_macos_policy_map.json'
    if (-not (Test-Path -LiteralPath $mapPath)) {
        throw "Chrome macOS policy map not found: $mapPath. The run cannot continue with incomplete control coverage."
    }

    try {
        $mapItems = @(Get-Content -LiteralPath $mapPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        throw "Chrome macOS policy map is not valid JSON: $mapPath. $($_.Exception.Message)"
    }

    if ($mapItems.Count -eq 0) {
        throw "Chrome macOS policy map contains no entries: $mapPath"
    }

    $index = @{}
    $byPolicyKey = @{}
    foreach ($item in $mapItems) {
        $controlId = [string]$item.control_id
        if ([string]::IsNullOrWhiteSpace($controlId)) {
            throw "Chrome macOS policy map contains an entry without control_id: $mapPath"
        }
        if ($null -eq $item.PSObject.Properties['macos_supported']) {
            throw "Chrome macOS policy map entry '$controlId' has no macos_supported flag: $mapPath"
        }

        $supported = [bool]$item.macos_supported
        $policyKey = [string]$item.policy_key
        if ($supported -and [string]::IsNullOrWhiteSpace($policyKey)) {
            throw "Chrome macOS policy map entry '$controlId' is marked supported but has no policy_key: $mapPath"
        }
        if (-not $supported -and [string]::IsNullOrWhiteSpace([string]$item.unsupported_reason)) {
            throw "Chrome macOS policy map entry '$controlId' is marked unsupported but has no unsupported_reason: $mapPath"
        }

        $equivalents = @()
        if ($null -ne $item.equivalent_policy_keys) {
            $equivalents = @($item.equivalent_policy_keys | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }

        $entry = @{
            control_id = $controlId
            policy_key = $policyKey
            preference_domain = if ([string]::IsNullOrWhiteSpace([string]$item.preference_domain)) { $script:ChromeDomain } else { [string]$item.preference_domain }
            mode = if ([string]::IsNullOrWhiteSpace([string]$item.mode)) { 'MANUAL' } else { ([string]$item.mode).ToUpperInvariant() }
            value_type = [string]$item.value_type
            macos_supported = $supported
            unsupported_result = if ([string]::IsNullOrWhiteSpace([string]$item.unsupported_result)) { 'NOT_ASSESSED' } else { [string]$item.unsupported_result }
            unsupported_reason = [string]$item.unsupported_reason
            equivalent_policy_keys = $equivalents
        }

        $index[$controlId] = $entry
        if (-not [string]::IsNullOrWhiteSpace($policyKey) -and -not $byPolicyKey.ContainsKey($policyKey)) {
            $byPolicyKey[$policyKey] = $entry
        }
    }

    return @{ by_control = $index; by_policy_key = $byPolicyKey }
}

function Get-CisDefinitionFromLine {
    param([string]$Line)

    if ([string]::IsNullOrWhiteSpace($Line)) { return $null }

    $controlId = ($Line -split '\s+')[0].Trim()
    if ([string]::IsNullOrWhiteSpace($controlId)) { return $null }

    $title = ""
    $mTitle = [regex]::Match($Line, "'([^']+)'")
    if ($mTitle.Success) { $title = $mTitle.Groups[1].Value.Trim() } else { $title = $Line.Trim() }

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

function Get-CisSeverity {
    param([hashtable]$Definition)

    $t = ($Definition.title + " " + $Definition.expected).ToLowerInvariant()
    if ($t -match 'safe browsing|password|remote debugging|site isolation|download|third.?party cookies|synchronization|tls|proxy') { return 'HIGH' }
    if ($t -match 'remote access|insecure|autofill|clipboard|certificate|ocsp|hsts') { return 'MEDIUM' }
    return 'LOW'
}

function Get-CisTestsFromCatalog {
    $catalogPath = Join-Path $PSScriptRoot 'chrome_cis_controls.txt'
    if (-not (Test-Path -LiteralPath $catalogPath)) {
        throw "Chrome CIS control catalog not found: $catalogPath. The run cannot continue with incomplete control coverage."
    }

    $tests = @{}
    $usedIds = @{}
    $lines = Get-Content -LiteralPath $catalogPath | ForEach-Object { $_.Trim() } | Where-Object { $_ }

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

        $mapping = $null
        if ($script:MacPolicyMap.by_control.ContainsKey($def.control_id)) {
            $mapping = $script:MacPolicyMap.by_control[$def.control_id]
        }

        $tests[$id] = @{
            Name = Get-ControlDisplayName -PolicyKey ([string]$mapping.policy_key) -Definition $def
            Severity = Get-CisSeverity -Definition $def
            Package = 'CH-MAC-CIS'
            CISControls = @($def.control_id)
            Type = 'CIS'
            PolicyKey = [string]$mapping.policy_key
            EquivalentKeys = @($mapping.equivalent_policy_keys)
            Expected = [string]$def.expected
            Mapping = $mapping
            Special = ''
        }
    }

    if ($tests.Count -eq 0) {
        throw "Chrome CIS control catalog contains no parseable controls: $catalogPath"
    }

    return $tests
}

# ---------------------------------------------------------------------------
# Layer evidence
# ---------------------------------------------------------------------------

function Get-MacTierEvidence {
    <#
      Collects the same policy key from every macOS evidence tier.
      Only /Library/Managed Preferences is MDM-enforced. /Library/Preferences
      looks similar but is writable outside the management channel, so it is
      reported under its own source label and never counted as enforced.
    #>
    param(
        [string]$PolicyKey,
        [string[]]$EquivalentKeys = @()
    )

    $keys = @(@($PolicyKey) + @($EquivalentKeys) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

    $evidence = @{
        matched_key = ''
        managed = @{ found = $false; display = ''; source_path = ''; access_denied = [bool]$script:ManagedStore.access_denied; value = $null }
        system = @{ found = $false; display = ''; source_path = ''; access_denied = [bool]$script:SystemStore.access_denied; value = $null }
        user = @{ found = $false; display = ''; source_path = ''; access_denied = [bool]$script:UserStore.access_denied; value = $null }
        profile = @{ found = $false; display = ''; source_path = ''; access_denied = [bool]$script:ChromeProfileStore.access_denied; value = $null }
    }

    foreach ($key in $keys) {
        $managed = Get-MacStoreValue -Store $script:ManagedStore -Key $key
        if ($managed.found) {
            $evidence.managed = $managed
            $evidence.matched_key = $key
            break
        }
    }
    foreach ($key in $keys) {
        $system = Get-MacStoreValue -Store $script:SystemStore -Key $key
        if ($system.found) {
            $evidence.system = $system
            if ([string]::IsNullOrWhiteSpace($evidence.matched_key)) { $evidence.matched_key = $key }
            break
        }
    }
    foreach ($key in $keys) {
        $user = Get-MacStoreValue -Store $script:UserStore -Key $key
        if ($user.found) {
            $evidence.user = $user
            if ([string]::IsNullOrWhiteSpace($evidence.matched_key)) { $evidence.matched_key = $key }
            break
        }
    }
    foreach ($key in $keys) {
        $prefLookup = Get-MacChromeProfilePrefValue -PolicyKey $key
        if ($prefLookup.found) {
            $evidence.profile = @{
                found = $true
                value = $prefLookup.value
                display = $prefLookup.display
                source_path = $prefLookup.source_path
                access_denied = [bool]$script:ChromeProfileStore.access_denied
                pref = $prefLookup.pref
                expectation = $prefLookup.expectation
            }
            if ([string]::IsNullOrWhiteSpace($evidence.matched_key)) { $evidence.matched_key = $key }
            break
        }
    }

    if ([string]::IsNullOrWhiteSpace($evidence.matched_key)) { $evidence.matched_key = [string]$PolicyKey }

    # ProxySettings is a dictionary on macOS; the decisive member is ProxyMode.
    if ($evidence.matched_key -eq 'ProxySettings') {
        foreach ($tierName in @('managed', 'system', 'user')) {
            $tier = $evidence.$tierName
            if (-not $tier.found -or $null -eq $tier.value) { continue }
            $mode = $tier.value.PSObject.Properties | Where-Object { $_.Name -ieq 'ProxyMode' } | Select-Object -First 1
            if ($null -ne $mode) { $tier.display = "ProxyMode=$(ConvertTo-MacDisplayValue -Value $mode.Value)" }
        }
    }

    return $evidence
}

function Test-MacProfilePrefExpectation {
    param(
        [hashtable]$ProfileEvidence,
        [string]$ExpectedText
    )

    $state = Get-MacExpectedState -ExpectedText $ExpectedText
    if ([string]::IsNullOrWhiteSpace($state) -or $null -eq $ProfileEvidence.expectation) {
        return @{ status = 'UNKNOWN'; message = "Profile preference value found ($($ProfileEvidence.display)), expectation could not be compared" }
    }

    $target = if ($state -eq 'DISABLED') { $ProfileEvidence.expectation.whenDisabled } else { $ProfileEvidence.expectation.whenEnabled }
    $ok = ((ConvertTo-MacDisplayValue -Value $ProfileEvidence.value) -eq (ConvertTo-MacDisplayValue -Value $target))
    return @{
        status = if ($ok) { 'PASSED' } else { 'FAILED' }
        message = "Expected $state (profile preference $(ConvertTo-MacDisplayValue -Value $target)), actual: $(ConvertTo-MacDisplayValue -Value $ProfileEvidence.value)"
    }
}

function Test-MacChromeExtensionIntent {
    <#
      Extension governance is routinely deployed as a policy composition rather
      than as one key, so the intent is validated across the managed keys before
      the control is reported as absent.
    #>
    $intent = @{ found = $false; satisfied = $false; observed = ''; source_path = ''; source_key = '' }

    foreach ($key in @('ExtensionInstallBlocklist', 'ExtensionSettings', 'BlockExternalExtensions')) {
        $managed = Get-MacStoreValue -Store $script:ManagedStore -Key $key
        if (-not $managed.found) { continue }

        $intent.found = $true
        $intent.source_key = $key
        $intent.source_path = $managed.source_path
        $intent.observed = "$key=$($managed.display)"

        if ($key -eq 'ExtensionInstallBlocklist') {
            $values = @($managed.value | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
            if ($values.Count -gt 0) { $intent.satisfied = $true; return $intent }
        }
        elseif ($key -eq 'BlockExternalExtensions') {
            if ((ConvertTo-MacDisplayValue -Value $managed.value) -in @('true', '1')) { $intent.satisfied = $true; return $intent }
        }
        else {
            $globalRule = $managed.value.PSObject.Properties | Where-Object { $_.Name -eq '*' } | Select-Object -First 1
            if ($null -ne $globalRule) {
                $mode = [string]$globalRule.Value.installation_mode
                $sources = @($globalRule.Value.install_sources | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ })
                $hasBroadSource = @($sources | Where-Object { $_ -eq '*' -or $_ -match '^https?://\*/?\*?$' }).Count -gt 0
                if ($mode -eq 'blocked' -or ($sources.Count -gt 0 -and -not $hasBroadSource)) {
                    $intent.satisfied = $true
                    $intent.observed = "ExtensionSettings[*].installation_mode=$mode; install_sources=$($sources -join ',')"
                    return $intent
                }
            }
        }
    }

    return $intent
}

function Get-MacChromeRuntimeEvidence {
    <#
      Runtime evidence is only meaningful for runtime-scoped controls and bypass
      flags. Absence of a bypass switch is not evidence of compliance for any
      other control, so this is never used as a general arbiter here.
    #>
    $arguments = Get-MacChromeProcessArgument
    $result = @{
        running = ($arguments.Count -gt 0)
        process_count = $arguments.Count
        hits = @()
    }

    foreach ($line in $arguments) {
        foreach ($flag in $script:ChromeBypassFlags) {
            if ($line -match [regex]::Escape($flag)) { $result.hits += $flag }
        }
    }
    $result.hits = @($result.hits | Select-Object -Unique)

    return $result
}

# ---------------------------------------------------------------------------
# Control evaluation
# ---------------------------------------------------------------------------

function New-MacNotAssessedResult {
    param(
        [hashtable]$Cfg,
        [string]$Reason,
        [bool]$AccessDenied = $false,
        [string[]]$EvidencePaths = @()
    )

    $expected = [string]$Cfg.Expected
    $meta = Get-PolicyExpectedMachineMeta -PolicyKey ([string]$Cfg.PolicyKey) -ExpectedText $expected

    return @{
        status = 'NOT_ASSESSED'
        verdict = 'NOT_ASSESSED'
        enforced = $false
        message = $Reason
        details = "Control: $($Cfg.CISControls -join ', ') | Policy key: $(if ([string]::IsNullOrWhiteSpace([string]$Cfg.PolicyKey)) { '(none)' } else { $Cfg.PolicyKey })"
        finding_details = $Reason
        not_assessed_reason = $Reason
        access_denied = $AccessDenied
        access_denied_reason = if ($AccessDenied) { $Reason } else { '' }
        expected_value = if ([string]::IsNullOrWhiteSpace($expected)) { '' } else { "Expected: $expected" }
        expected_kind = $meta.kind
        expected_machine_value = $meta.value
        observed_value = '(not assessed)'
        evidence_output = $Reason
        evidence_type = if ($AccessDenied) { 'evidence_access_denied' } else { 'not_assessed' }
        evidence_source_label = 'NONE'
        evidence_paths = @($EvidencePaths)
        layer_1_status = 'NOT_ASSESSED'
        layer_1_method = 'Managed Preferences Policy (/Library/Managed Preferences, MDM enforced)'
        layer_1_details = $Reason
        layer_2_status = 'NOT_ASSESSED'
        layer_2_method = 'User-revertible preferences (/Library/Preferences, ~/Library/Preferences, Chrome profile preferences)'
        layer_2_details = $Reason
        layer_3_status = 'NOT_ASSESSED'
        layer_3_method = 'Live Chrome process arguments'
        layer_3_details = 'Runtime evidence is collected only for runtime-scoped controls and bypass flags.'
        test_method = 'macOS managed preference / preference domain / Chrome profile preference evidence collection.'
        rationale = 'A control that cannot produce local evidence must not carry a compliance statement.'
        impact = 'The control is excluded from scoring because no evidence tier could observe its value on this endpoint.'
        remediation = 'Verify the control through the management console or an evidence source that is readable on this endpoint.'
        reference = 'https://chromeenterprise.google/policies/'
        confidence = 'LOW'
        manual_required = $true
        status_reason = if ($AccessDenied) { 'evidence_access_denied' } else { 'evidence_not_collectable' }
        warning_note = $Reason
    }
}

function Invoke-MacChromeControl {
    param([hashtable]$Cfg)

    # Platform and installation gates: no local evidence means no verdict.
    if (-not $script:IsMacHost) {
        return New-MacNotAssessedResult -Cfg $Cfg -Reason 'This runner collects evidence only on macOS, so the control could not be verified on this host.'
    }
    if (-not $script:ChromeInstalled) {
        return New-MacNotAssessedResult -Cfg $Cfg -Reason 'Google Chrome is not installed on this endpoint, so the control could not be verified locally.'
    }

    if ($Cfg.Type -eq 'CIS' -and $null -eq $Cfg.Mapping) {
        return New-MacNotAssessedResult -Cfg $Cfg -Reason "No mapping is defined for this control in chrome_macos_policy_map.json, so it could not be verified on macOS."
    }
    if ($null -ne $Cfg.Mapping -and -not $Cfg.Mapping.macos_supported) {
        return New-MacNotAssessedResult -Cfg $Cfg -Reason "This control could not be verified on macOS: $($Cfg.Mapping.unsupported_reason)"
    }
    if ($null -ne $Cfg.Mapping -and $Cfg.Mapping.mode -ne 'POLICY') {
        return New-MacNotAssessedResult -Cfg $Cfg -Reason "The macOS map marks this control as $($Cfg.Mapping.mode), so no automated policy check could be performed."
    }

    if ($Cfg.Special -eq 'Runtime') {
        return Invoke-MacChromeRuntimeControl -Cfg $Cfg
    }

    if ($script:ManagedStore.access_denied) {
        return New-MacNotAssessedResult -Cfg $Cfg `
            -Reason "Read access to macOS managed preferences was denied (TCC / Full Disk Access): $($script:ManagedStore.denied_paths -join ', '). Unreadable evidence cannot establish that a configuration is absent." `
            -AccessDenied $true -EvidencePaths @($script:ManagedStore.denied_paths)
    }

    return Invoke-MacChromePolicyControl -Cfg $Cfg
}

function Invoke-MacChromeRuntimeControl {
    param([hashtable]$Cfg)

    $runtime = Get-MacChromeRuntimeEvidence
    $expected = 'No policy-neutralising runtime override'
    $base = @{
        expected_value = "Expected: $expected"
        expected_kind = 'enum'
        expected_machine_value = 'no_bypass_flag'
        evidence_type = 'runtime_process_flags'
        evidence_source_label = 'RUNTIME_PROCESS_ARGUMENTS'
        evidence_paths = @('/bin/ps -axo pid=,command=')
        layer_1_status = 'NOT_ASSESSED'
        layer_1_method = 'Managed Preferences Policy (/Library/Managed Preferences, MDM enforced)'
        layer_1_details = 'This control is runtime-scoped; it has no managed preference equivalent.'
        layer_2_status = 'NOT_ASSESSED'
        layer_2_method = 'User-revertible preferences (/Library/Preferences, ~/Library/Preferences, Chrome profile preferences)'
        layer_2_details = 'This control is runtime-scoped; it has no user preference equivalent.'
        layer_3_method = 'Live Chrome process arguments'
        test_method = 'Live process argument enumeration (/bin/ps) + bypass flag pattern detection.'
        rationale = 'Bypass flags such as --no-sandbox or --disable-web-security neutralise the browser security model regardless of deployed policy.'
        remediation = 'Do not launch Chrome with bypass flags. Review launch agents, login items and management scripts that start Chrome.'
        reference = 'https://chromium.googlesource.com/chromium/src/+/main/docs/linux_sandboxing.md'
    }

    if (-not $runtime.running) {
        $reason = 'Chrome is not running, so runtime arguments could not be verified.'
        $result = New-MacNotAssessedResult -Cfg $Cfg -Reason $reason
        $result.layer_3_details = $reason
        $result.evidence_type = 'runtime_process_flags'
        return $result
    }

    if ($runtime.hits.Count -gt 0) {
        $observed = ($runtime.hits -join ', ')
        return ($base + @{
            status = 'FAILED'
            verdict = 'FAIL'
            enforced = $false
            message = "Bypass flags detected in live Chrome processes: $observed"
            details = "Live Chrome process arguments contain bypass flags: $observed"
            finding_details = "Bypass flags detected in $($runtime.process_count) live Chrome process argument set(s): $observed"
            observed_value = $observed
            evidence_output = "Bypass flags: $observed"
            layer_3_status = 'FAILED'
            layer_3_details = "Runtime override switches detected that can neutralise policy: $observed"
            impact = 'Chrome is running with switches that disable sandboxing or transport security, so deployed policies can be bypassed in the live session.'
            confidence = 'HIGH'
            status_reason = 'expected_condition_not_met'
            manual_required = $false
            warning_note = ''
            access_denied = $false
            access_denied_reason = ''
        })
    }

    return ($base + @{
        status = 'PASSED'
        verdict = 'PASS'
        enforced = $false
        message = 'No bypass flags detected in live Chrome processes'
        details = "No bypass flag found in $($runtime.process_count) live Chrome process argument set(s)."
        finding_details = 'Live Chrome processes are running without --no-sandbox, --disable-web-security, --remote-debugging-port or similar bypass flags.'
        observed_value = 'No bypass flags present'
        evidence_output = 'No bypass flags present in live Chrome process arguments.'
        layer_3_status = 'PASSED'
        layer_3_details = 'No policy-neutralising command-line switch was found in the running browser.'
        impact = 'Chrome is running with the sandbox and web security model intact.'
        confidence = 'MEDIUM'
        status_reason = 'expected_condition_met'
        manual_required = $false
        warning_note = ''
        access_denied = $false
        access_denied_reason = ''
    })
}

function Invoke-MacChromePolicyControl {
    param([hashtable]$Cfg)

    $policyKey = [string]$Cfg.PolicyKey
    $expectedText = [string]$Cfg.Expected
    $meta = Get-PolicyExpectedMachineMeta -PolicyKey $policyKey -ExpectedText $expectedText
    $evidence = Get-MacTierEvidence -PolicyKey $policyKey -EquivalentKeys @($Cfg.EquivalentKeys)
    $matchedKey = [string]$evidence.matched_key

    $base = @{
        policy_key = $policyKey
        expected_value = if ([string]::IsNullOrWhiteSpace($expectedText)) { '' } else { "Expected: $expectedText" }
        expected_kind = $meta.kind
        expected_machine_value = $meta.value
        layer_1_method = 'Managed Preferences Policy (/Library/Managed Preferences, MDM enforced)'
        layer_2_method = 'User-revertible preferences (/Library/Preferences, ~/Library/Preferences, Chrome profile preferences)'
        layer_3_method = 'Live Chrome process arguments'
        layer_3_status = 'NOT_ASSESSED'
        layer_3_details = 'Runtime evidence is collected only for runtime-scoped controls and bypass flags.'
        test_method = "Control -> chrome_macos_policy_map.json -> '$matchedKey' lookup across managed, system and user preference domains plus every Chrome profile."
        rationale = 'On macOS only a value delivered through a configuration profile into /Library/Managed Preferences cannot be changed by the user.'
        remediation = "Deploy '$matchedKey' through an MDM configuration profile for the $($script:ChromeDomain) domain so the value becomes enforced."
        reference = "https://chromeenterprise.google/policies/#$matchedKey"
        confidence = 'MEDIUM'
        access_denied = $false
        access_denied_reason = ''
    }

    # Exception-list controls: a configured exception is the finding, absence is compliant.
    if ($Cfg.Special -eq 'ExceptionListAbsent') {
        return (Invoke-MacChromeExceptionListControl -Cfg $Cfg -Base $base)
    }

    # Tier 1 - MDM enforced.
    if ($evidence.managed.found) {
        $eval = Test-MacPolicyExpectation -Value $evidence.managed.display -Expected $expectedText -PolicyKey $matchedKey
        $passed = ($eval.status -eq 'PASSED')
        return ($base + @{
            status = if ($eval.status -eq 'UNKNOWN') { 'UNKNOWN' } else { $eval.status }
            verdict = if ($passed) { 'PASS' } elseif ($eval.status -eq 'UNKNOWN') { 'NOT_ASSESSED' } else { 'FAIL' }
            enforced = $true
            message = if ($passed) { "Managed preference value matches the expected value. $($eval.message)" } elseif ($eval.status -eq 'UNKNOWN') { $eval.message } else { "Managed preference value does not match the expected value. $($eval.message)" }
            details = "$($evidence.managed.source_path) : $matchedKey = $($evidence.managed.display)"
            finding_details = "'$matchedKey' is delivered by a configuration profile and evaluated as enforced evidence."
            observed_value = $evidence.managed.display
            evidence_output = "$matchedKey = $($evidence.managed.display) (source: $($evidence.managed.source_path))"
            evidence_type = 'managed_preferences_plist'
            evidence_source_label = 'MANAGED_PREFERENCES_MDM_ENFORCED'
            evidence_paths = @($evidence.managed.source_path)
            layer_1_status = $eval.status
            layer_1_details = "$($evidence.managed.source_path) : $matchedKey = $($evidence.managed.display)"
            layer_2_status = 'NOT_ASSESSED'
            layer_2_details = 'A managed preference is present and overrides any user-level value, so the user tier does not decide this control.'
            impact = if ($passed) { 'The control is enforced through the management channel and the user cannot revert it.' } else { 'A managed value exists but does not match the expectation, so the intended protection is not in effect.' }
            status_reason = Get-DefaultStatusReason -Status $eval.status
            manual_required = ($eval.status -eq 'UNKNOWN')
            warning_note = ''
        })
    }

    # Tier 2 - present but not enforced. /Library/Preferences looks like a system
    # scope but is not delivered by MDM, so it gets its own source label.
    $unenforcedTiers = @(
        @{ evidence = $evidence.system;  label = 'SYSTEM_DOMAIN_NOT_MDM_ENFORCED'; type = 'preferences_plist';          note = "$($script:SystemPreferencesRoot) is writable outside the management channel, so this value is not MDM-enforced." },
        @{ evidence = $evidence.user;    label = 'USER_DOMAIN_NOT_ENFORCED';       type = 'preferences_plist';          note = 'The value lives in the user preference domain and the user can revert it at any time.' },
        @{ evidence = $evidence.profile; label = 'CHROME_PROFILE_PREFERENCE';      type = 'profile_preferences_file';   note = 'The value comes from a Chrome profile preference file and the user can change it from the browser UI.' }
    )

    foreach ($tier in $unenforcedTiers) {
        if (-not $tier.evidence.found) { continue }

        $eval = if ($tier.label -eq 'CHROME_PROFILE_PREFERENCE') {
            Test-MacProfilePrefExpectation -ProfileEvidence $tier.evidence -ExpectedText $expectedText
        } else {
            Test-MacPolicyExpectation -Value $tier.evidence.display -Expected $expectedText -PolicyKey $matchedKey
        }

        $satisfied = ($eval.status -eq 'PASSED')
        return ($base + @{
            # The runner status reports the L1 fact: no managed policy is deployed.
            # The non-enforced compliance is carried by verdict/layer_2_status so
            # the verification engine can arbitrate instead of inheriting a claim
            # of enforcement that was never observed.
            status = if ($satisfied) { 'FAILED' } elseif ($eval.status -eq 'UNKNOWN') { 'UNKNOWN' } else { 'FAILED' }
            verdict = if ($satisfied) { 'PASS_NOT_ENFORCED' } elseif ($eval.status -eq 'UNKNOWN') { 'NOT_ASSESSED' } else { 'FAIL' }
            enforced = $false
            message = if ($satisfied) {
                "The managed preference is not configured for this control; the expected value is present only in a user-revertible source ($($tier.label))."
            } else {
                "The managed preference is not configured for this control and the user-revertible value does not match the expectation. $($eval.message)"
            }
            details = "$($tier.evidence.source_path) : $matchedKey = $($tier.evidence.display)"
            finding_details = "$($tier.note) $($eval.message)"
            observed_value = $tier.evidence.display
            evidence_output = "$matchedKey = $($tier.evidence.display) (source: $($tier.evidence.source_path))"
            evidence_type = $tier.type
            evidence_source_label = $tier.label
            evidence_paths = @($tier.evidence.source_path)
            layer_1_status = 'FAILED'
            layer_1_details = "$matchedKey is not configured under $($script:ManagedPreferencesRoot); no MDM-enforced value exists for this control."
            layer_2_status = if ($satisfied) { 'PASS_NOT_ENFORCED' } else { 'FAILED' }
            layer_2_details = "$($tier.evidence.source_path) : $matchedKey = $($tier.evidence.display). $($tier.note)"
            impact = if ($satisfied) {
                'The setting currently has the expected value, but because it is not enforced the user or any local process can revert it without detection.'
            } else {
                'Neither an enforced value nor a compliant local value exists, so the protection this control describes is not in effect.'
            }
            status_reason = if ($satisfied) { 'expected_condition_met_without_enforcement' } else { 'expected_condition_not_met' }
            manual_required = $true
            warning_note = 'The value was found outside the MDM-enforced managed preference domain; it is reported as an enforcement gap rather than as a compliant control.'
        })
    }

    # Extension governance is deployed as a policy composition rather than a
    # single key, so the intent is checked before reporting the control absent.
    if ($matchedKey -in @('ExtensionInstallBlocklist', 'BlockExternalExtensions', 'ExtensionUnpublishedAvailability', 'ExtensionAllowedTypes')) {
        $intent = Test-MacChromeExtensionIntent
        if ($intent.found -and $intent.satisfied) {
            return ($base + @{
                status = 'PASSED'
                verdict = 'PASS'
                enforced = $true
                message = "Extension install governance is enforced through the equivalent managed key '$($intent.source_key)'."
                details = "$($intent.source_path) : $($intent.observed)"
                finding_details = "'$matchedKey' is not deployed, but the same governance intent is enforced by '$($intent.source_key)'."
                observed_value = $intent.observed
                evidence_output = "$($intent.observed) (source: $($intent.source_path))"
                evidence_type = 'managed_preferences_plist'
                evidence_source_label = 'MANAGED_PREFERENCES_MDM_ENFORCED'
                evidence_paths = @($intent.source_path)
                layer_1_status = 'PASSED'
                layer_1_details = "$($intent.source_path) : $($intent.observed)"
                layer_2_status = 'NOT_ASSESSED'
                layer_2_details = 'A managed preference is present and overrides any user-level value.'
                impact = 'Extension installation is governed centrally, so unauthorized extensions cannot be installed by the user.'
                status_reason = 'expected_condition_met'
                manual_required = $false
                warning_note = ''
            })
        }
    }

    # No evidence in any tier. The managed store was readable, so this is a real
    # absence rather than unreadable evidence.
    return ($base + @{
        status = 'FAILED'
        verdict = 'FAIL'
        enforced = $false
        message = "The managed preference '$matchedKey' is not configured in any macOS evidence tier."
        details = "Control: $($Cfg.CISControls -join ', ') | Expected: $expectedText | $matchedKey not found under managed, system, user or profile preferences."
        finding_details = "'$matchedKey' was not found under $($script:ManagedPreferencesRoot), $($script:SystemPreferencesRoot), $($script:UserPreferencesRoot) or any Chrome profile preference file."
        observed_value = '(not set)'
        evidence_output = "$matchedKey not found in any macOS preference tier."
        evidence_type = 'managed_preferences_plist'
        evidence_source_label = 'NONE'
        evidence_paths = @($script:ManagedPreferencesRoot)
        layer_1_status = 'FAILED'
        layer_1_details = "$matchedKey is not configured under $($script:ManagedPreferencesRoot)."
        layer_2_status = 'FAILED'
        layer_2_details = "$matchedKey is not configured under $($script:SystemPreferencesRoot), $($script:UserPreferencesRoot) or any Chrome profile preference file."
        impact = 'The control is not deployed on this endpoint, so the protection it describes is absent.'
        status_reason = 'expected_condition_not_met'
        manual_required = $false
        warning_note = ''
    })
}

function Invoke-MacChromeExceptionListControl {
    param(
        [hashtable]$Cfg,
        [hashtable]$Base
    )

    $hits = @()
    $paths = @()
    foreach ($key in @($Cfg.ExceptionKeys)) {
        foreach ($tier in @(
            @{ store = $script:ManagedStore; label = 'MANAGED_PREFERENCES_MDM_ENFORCED' },
            @{ store = $script:SystemStore;  label = 'SYSTEM_DOMAIN_NOT_MDM_ENFORCED' },
            @{ store = $script:UserStore;    label = 'USER_DOMAIN_NOT_ENFORCED' }
        )) {
            $lookup = Get-MacStoreValue -Store $tier.store -Key $key
            if ($lookup.found -and -not [string]::IsNullOrWhiteSpace($lookup.display)) {
                $hits += "$key=$($lookup.display) [$($tier.label)]"
                $paths += $lookup.source_path
            }
        }
    }

    if ($hits.Count -gt 0) {
        return ($Base + @{
            status = 'FAILED'
            verdict = 'FAIL'
            enforced = $false
            message = 'A security bypass exception list is configured for this control.'
            details = "Configured exception(s): $($hits -join '; ')"
            finding_details = "Exception entries weaken the control: $($hits -join '; ')"
            observed_value = ($hits -join '; ')
            evidence_output = ($hits -join '; ')
            evidence_type = 'managed_preferences_plist'
            evidence_source_label = 'EXCEPTION_LIST_PRESENT'
            evidence_paths = @($paths | Select-Object -Unique)
            layer_1_status = 'FAILED'
            layer_1_details = "Configured exception(s): $($hits -join '; ')"
            layer_2_status = 'NOT_ASSESSED'
            layer_2_details = 'The exception list was evaluated across every preference tier in a single check.'
            impact = 'Exception entries create a documented bypass path around the protection this control provides.'
            status_reason = 'expected_condition_not_met'
            manual_required = $false
            warning_note = ''
        })
    }

    return ($Base + @{
        status = 'PASSED'
        verdict = 'PASS'
        enforced = $true
        message = 'No security bypass exception list is configured for this control.'
        details = "No value found for: $(@($Cfg.ExceptionKeys) -join ', ')"
        finding_details = 'No exception entry was found in the managed, system or user preference domains.'
        observed_value = '(no exception configured)'
        evidence_output = 'No bypass exception entry found in any macOS preference tier.'
        evidence_type = 'managed_preferences_plist'
        evidence_source_label = 'EXCEPTION_LIST_ABSENT'
        evidence_paths = @($script:ManagedPreferencesRoot)
        layer_1_status = 'PASSED'
        layer_1_details = "No exception entry found under $($script:ManagedPreferencesRoot)."
        layer_2_status = 'PASSED'
        layer_2_details = "No exception entry found under $($script:SystemPreferencesRoot) or $($script:UserPreferencesRoot)."
        impact = 'No bypass path is configured, so the control keeps its intended protection.'
        status_reason = 'expected_condition_met'
        manual_required = $false
        warning_note = ''
    })
}

# ---------------------------------------------------------------------------
# Manual verification guidance
# ---------------------------------------------------------------------------

function Get-MacChromeManualGuidance {
    param(
        [hashtable]$Cfg,
        [hashtable]$Result
    )

    $name = [string]$Cfg.Name
    $policyKey = [string]$Cfg.PolicyKey
    $status = [string]$Result.status

    $check = 'Verify the Chrome policy value and the resulting behaviour together on macOS.'
    $steps = @(
        'Open chrome://policy and confirm the policy source is reported as "Platform policy" (machine level).',
        "Run: defaults read $($script:ChromeDomain) $policyKey",
        'Run: sudo profiles show -type configuration to confirm the value arrives from a configuration profile.',
        'If the value only exists in the user domain, treat the control as an enforcement gap, not as compliant.'
    )
    $command = "/usr/bin/defaults read $($script:ChromeDomain) $policyKey"
    $expected = 'The value must be delivered by an MDM configuration profile and be visible under /Library/Managed Preferences.'

    if ($Cfg.Special -eq 'Runtime') {
        $check = 'Verify how Chrome is launched and whether bypass flags are present.'
        $steps = @(
            'Run: ps -axo pid=,command= | grep "Google Chrome"',
            'Check launch agents and login items that start Chrome for bypass flags.',
            'Confirm no --no-sandbox, --disable-web-security or --remote-debugging-port switch is used.'
        )
        $command = 'ps -axo pid=,command= | grep "Google Chrome"'
        $expected = 'Chrome must run without any policy-neutralising command-line switch.'
    }
    elseif ($name -match 'Incognito') {
        $check = 'Verify the Incognito restriction through policy and behaviour.'
        $steps = @(
            "Run: defaults read $($script:ChromeDomain) IncognitoModeAvailability",
            'Press Shift+Cmd+N and try to open an Incognito window.',
            'Record PASS only if the window is blocked or a management notice is shown.'
        )
        $expected = 'Incognito browsing must be restricted in line with the corporate policy.'
    }
    elseif ($name -match 'Extension') {
        $check = 'Verify extension governance through policy and an install attempt.'
        $steps = @(
            "Run: defaults read $($script:ChromeDomain) ExtensionSettings",
            'Try to install a test extension from the Chrome Web Store.',
            'Record PASS only if the install is blocked or restricted to approved sources.'
        )
        $expected = 'Unauthorized extension installation must be blocked by managed policy.'
    }
    elseif ($name -match 'Password') {
        $check = 'Verify the password manager restriction through policy and the settings UI.'
        $steps = @(
            "Run: defaults read $($script:ChromeDomain) PasswordManagerEnabled",
            'Open Settings > Autofill and passwords > Google Password Manager.',
            'Record PASS only if password saving is disabled and managed.'
        )
        $expected = 'Browser password storage must follow the corporate policy.'
    }

    $note = if ($status -in @('UNKNOWN', 'NOT_ASSESSED')) {
        'The automated check could not produce a definitive result. Close this item with manual validation and review the MDM console alongside the endpoint evidence.'
    } else {
        'An automated finding exists; the manual check is applied as a second evidence source.'
    }

    return @{
        manual_check = $check
        manual_check_steps = $steps
        manual_check_command = $command
        manual_check_expected = $expected
        manual_check_note = $note
    }
}

function Get-MacIncidentScenario {
    param(
        [string]$TestName,
        [string]$Verdict,
        [string]$ExpectedValue,
        [string]$ObservedValue
    )

    $statePrefix = switch ($Verdict) {
        'PASS' { 'The control is enforced and in the expected state.' }
        'PASS_NOT_ENFORCED' { 'The control currently has the expected value but is not enforced, so it can be reverted at any time.' }
        'FAIL' { 'The control is not in the expected state.' }
        default { 'The control state could not be established from local evidence.' }
    }

    $expectedNote = if (-not [string]::IsNullOrWhiteSpace($ExpectedValue)) { " Expected: $($ExpectedValue.Trim().TrimEnd('.'))." } else { '' }
    $observedNote = if (-not [string]::IsNullOrWhiteSpace($ObservedValue)) { " Observed: $($ObservedValue.Trim().TrimEnd('.'))." } else { '' }

    return "$statePrefix Incident scenario ($TestName): a threat actor can target the weakness this control covers; on macOS an unenforced value can also be changed by any local process running as the user.$expectedNote$observedNote"
}

# ---------------------------------------------------------------------------
# Test catalog
# ---------------------------------------------------------------------------

function Get-MacBaseTestMap {
    $definitions = @(
        @{ Id = 'C-001'; Name = 'Incognito Mode Policy';               PolicyKey = 'IncognitoModeAvailability';     Expected = 'Disabled';   Severity = 'HIGH';     Package = 'CH-MAC-PKG-1'; CISControls = @('2.1') },
        @{ Id = 'C-002'; Name = 'Password Manager';                    PolicyKey = 'PasswordManagerEnabled';        Expected = 'Disabled';   Severity = 'HIGH';     Package = 'CH-MAC-PKG-1'; CISControls = @('2.6') },
        @{ Id = 'C-003'; Name = 'Developer Tools Restriction';         PolicyKey = 'DeveloperToolsAvailability';    Expected = 'Disabled';   Severity = 'MEDIUM';   Package = 'CH-MAC-PKG-1'; CISControls = @() },
        @{ Id = 'C-004'; Name = 'Browser Sync';                        PolicyKey = 'SyncDisabled';                  Expected = 'Enabled';    Severity = 'CRITICAL'; Package = 'CH-MAC-PKG-2'; CISControls = @('2.15') },
        @{ Id = 'C-005'; Name = 'Safe Browsing Enforcement';           PolicyKey = 'SafeBrowsingProtectionLevel';   Expected = 'Enabled';    Severity = 'CRITICAL'; Package = 'CH-MAC-PKG-2'; CISControls = @('2.12') },
        @{ Id = 'C-006'; Name = 'Extension Installation Control';      PolicyKey = 'ExtensionInstallBlocklist';     Expected = 'Configured'; Severity = 'HIGH';     Package = 'CH-MAC-PKG-3'; CISControls = @('2.3'); EquivalentKeys = @('ExtensionSettings') },
        @{ Id = 'C-007'; Name = 'Download Restriction Level';          PolicyKey = 'DownloadRestrictions';          Expected = 'Configured'; Severity = 'HIGH';     Package = 'CH-MAC-PKG-2'; CISControls = @() },
        @{ Id = 'C-008'; Name = 'Site Isolation';                      PolicyKey = 'SitePerProcess';                Expected = 'Enabled';    Severity = 'HIGH';     Package = 'CH-MAC-PKG-4'; CISControls = @() },
        @{ Id = 'C-009'; Name = 'DNS over HTTPS';                      PolicyKey = 'DnsOverHttpsMode';              Expected = 'Configured'; Severity = 'MEDIUM';   Package = 'CH-MAC-PKG-5'; CISControls = @() },
        @{ Id = 'C-010'; Name = 'Autofill Payment';                    PolicyKey = 'AutofillCreditCardEnabled';     Expected = 'Disabled';   Severity = 'MEDIUM';   Package = 'CH-MAC-PKG-2'; CISControls = @() },
        @{ Id = 'C-011'; Name = 'Third-Party Cookies';                 PolicyKey = 'BlockThirdPartyCookies';        Expected = 'Enabled';    Severity = 'HIGH';     Package = 'CH-MAC-PKG-4'; CISControls = @() },
        @{ Id = 'C-013'; Name = 'Proxy Settings Enforcement';          PolicyKey = 'ProxySettings';                 Expected = 'Configured'; Severity = 'HIGH';     Package = 'CH-MAC-PKG-5'; CISControls = @() },
        @{ Id = 'C-014'; Name = 'QUIC Disable';                        PolicyKey = 'QuicAllowed';                   Expected = 'Disabled';   Severity = 'MEDIUM';   Package = 'CH-MAC-PKG-5'; CISControls = @() }
    )

    $map = @{}
    foreach ($def in $definitions) {
        $mapping = $null
        if ($script:MacPolicyMap.by_policy_key.ContainsKey($def.PolicyKey)) {
            $mapping = $script:MacPolicyMap.by_policy_key[$def.PolicyKey]
        }

        $map[$def.Id] = @{
            Name = $def.Name
            Severity = $def.Severity
            Package = $def.Package
            CISControls = @($def.CISControls)
            Type = 'BASE'
            PolicyKey = $def.PolicyKey
            EquivalentKeys = @($def.EquivalentKeys)
            Expected = $def.Expected
            Mapping = $mapping
            Special = ''
        }
    }

    $map['C-012'] = @{
        Name = 'Command-Line Hardening'
        Severity = 'MEDIUM'
        Package = 'CH-MAC-PKG-6'
        CISControls = @()
        Type = 'BASE'
        PolicyKey = 'RuntimeProcessFlags'
        EquivalentKeys = @()
        Expected = 'No policy-neutralising runtime override'
        Mapping = $null
        Special = 'Runtime'
    }

    $map['C-015'] = @{
        Name = 'Insecure Content Allowlist'
        Severity = 'HIGH'
        Package = 'CH-MAC-PKG-5'
        CISControls = @()
        Type = 'BASE'
        PolicyKey = 'InsecureContentAllowedForUrls'
        EquivalentKeys = @()
        Expected = 'No exception entry'
        Mapping = $script:MacPolicyMap.by_policy_key['InsecureContentAllowedForUrls']
        Special = 'ExceptionListAbsent'
        ExceptionKeys = @('InsecureContentAllowedForUrls')
    }

    $map['C-016'] = @{
        Name = 'Certificate Transparency Exceptions'
        Severity = 'HIGH'
        Package = 'CH-MAC-PKG-5'
        CISControls = @()
        Type = 'BASE'
        PolicyKey = 'CertificateTransparencyEnforcementDisabledForCas'
        EquivalentKeys = @()
        Expected = 'No exception entry'
        Mapping = $script:MacPolicyMap.by_policy_key['CertificateTransparencyEnforcementDisabledForCas']
        Special = 'ExceptionListAbsent'
        ExceptionKeys = @(
            'CertificateTransparencyEnforcementDisabledForCas',
            'CertificateTransparencyEnforcementDisabledForLegacyCas',
            'CertificateTransparencyEnforcementDisabledForUrls'
        )
    }

    return $map
}

# ---------------------------------------------------------------------------
# Result payload
# ---------------------------------------------------------------------------

function New-MacResultPayload {
    param(
        [string]$Id,
        [hashtable]$Cfg,
        [hashtable]$Result
    )

    $manual = Get-MacChromeManualGuidance -Cfg $Cfg -Result $Result
    $expectedValue = Get-ResultFieldOrFallback -Result $Result -FieldName 'expected_value' -FallbackValue $manual.manual_check_expected
    $observedValue = Get-ResultFieldOrFallback -Result $Result -FieldName 'observed_value' -FallbackValue ''
    $expectedMeta = Get-MachineComparableExpectation -ExpectedValue $expectedValue
    $evidenceOutput = Get-ResultFieldOrFallback -Result $Result -FieldName 'evidence_output' `
        -FallbackValue (Get-ResultFieldOrFallback -Result $Result -FieldName 'details' -FallbackValue (Get-ResultField -Result $Result -FieldName 'message' -DefaultValue ''))

    $verifiedVia = if ($Cfg.Special -eq 'Runtime') {
        'Process Command Line (Live), macOS runtime'
    } else {
        'Managed Preferences Policy (MDM), macOS Preferences Domain, Chrome Profile Preferences'
    }

    $payload = @{
        test_id = $Id
        test_name = $Cfg.Name
        package_id = $Cfg.Package
        severity = $Cfg.Severity
        cis_controls = @($Cfg.CISControls)
        verified_via = $verifiedVia
        platform = 'macOS'
        policy_key = Get-ResultField -Result $Result -FieldName 'policy_key' -DefaultValue ([string]$Cfg.PolicyKey)
        policy_mapping = if ($Cfg.Special -eq 'Runtime') { 'OBSERVATIONAL' } else { 'POLICY' }
        preference_domain = $script:ChromeDomain
        macos_supported = if ($null -eq $Cfg.Mapping) { $true } else { [bool]$Cfg.Mapping.macos_supported }
        status = $Result.status
        # Named runner_verdict, not verdict: apply_verification.ps1 writes its own
        # 'verdict' property and would otherwise overwrite the collector's finding.
        runner_verdict = Get-ResultField -Result $Result -FieldName 'verdict' -DefaultValue $Result.status
        enforced = [bool](Get-ResultField -Result $Result -FieldName 'enforced' -DefaultValue $false)
        message = $Result.message
        details = $Result.details
        finding_details = Get-ResultFieldOrFallback -Result $Result -FieldName 'finding_details' -FallbackValue $Result.message
        test_method = $Result.test_method
        rationale = $Result.rationale
        impact = $Result.impact
        layer_1_status = Get-ResultField -Result $Result -FieldName 'layer_1_status' -DefaultValue ''
        layer_1_method = Get-ResultField -Result $Result -FieldName 'layer_1_method' -DefaultValue ''
        layer_1_details = Get-ResultField -Result $Result -FieldName 'layer_1_details' -DefaultValue ''
        layer_2_status = Get-ResultField -Result $Result -FieldName 'layer_2_status' -DefaultValue ''
        layer_2_method = Get-ResultField -Result $Result -FieldName 'layer_2_method' -DefaultValue ''
        layer_2_details = Get-ResultField -Result $Result -FieldName 'layer_2_details' -DefaultValue ''
        layer_3_status = Get-ResultField -Result $Result -FieldName 'layer_3_status' -DefaultValue ''
        layer_3_method = Get-ResultField -Result $Result -FieldName 'layer_3_method' -DefaultValue ''
        layer_3_details = Get-ResultField -Result $Result -FieldName 'layer_3_details' -DefaultValue ''
        remediation = $Result.remediation
        reference = $Result.reference
        intune_reference_url = 'https://learn.microsoft.com/en-us/intune/intune-service/configuration/preference-file-settings-macos'
        manageengine_reference_url = 'https://www.manageengine.com/mobile-device-management/help/mac_management/mdm_mac_custom_configuration.html'
        warning_note = Get-ResultField -Result $Result -FieldName 'warning_note' -DefaultValue ''
        expected_value = $expectedValue
        expected_kind = Get-ResultFieldOrFallback -Result $Result -FieldName 'expected_kind' -FallbackValue $expectedMeta.kind
        expected_machine_value = Get-ResultFieldOrFallback -Result $Result -FieldName 'expected_machine_value' -FallbackValue $expectedMeta.value
        observed_value = $observedValue
        evidence_output = $evidenceOutput
        evidence_type = Get-ResultFieldOrFallback -Result $Result -FieldName 'evidence_type' -FallbackValue 'result_snapshot'
        evidence_source_label = Get-ResultFieldOrFallback -Result $Result -FieldName 'evidence_source_label' -FallbackValue 'NONE'
        evidence_paths = @(Get-ResultField -Result $Result -FieldName 'evidence_paths' -DefaultValue @())
        access_denied = [bool](Get-ResultField -Result $Result -FieldName 'access_denied' -DefaultValue $false)
        access_denied_reason = [string](Get-ResultField -Result $Result -FieldName 'access_denied_reason' -DefaultValue '')
        not_assessed_reason = [string](Get-ResultField -Result $Result -FieldName 'not_assessed_reason' -DefaultValue '')
        confidence = Get-ResultFieldOrFallback -Result $Result -FieldName 'confidence' -FallbackValue 'MEDIUM'
        status_reason = Get-ResultFieldOrFallback -Result $Result -FieldName 'status_reason' -FallbackValue (Get-DefaultStatusReason -Status $Result.status)
        manual_required = [bool](Get-ResultField -Result $Result -FieldName 'manual_required' -DefaultValue ($Result.status -in @('UNKNOWN', 'NOT_ASSESSED')))
        manual_check = $manual.manual_check
        manual_check_steps = $manual.manual_check_steps
        manual_check_command = $manual.manual_check_command
        manual_check_expected = $manual.manual_check_expected
        manual_check_note = $manual.manual_check_note
        retest_command = "./chrome_macos_test_runner.ps1 -TestId $Id"
        timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }

    $payload.incident_scenario = Get-MacIncidentScenario -TestName ([string]$Cfg.Name) -Verdict ([string]$payload.runner_verdict) -ExpectedValue ([string]$payload.expected_value) -ObservedValue ([string]$payload.observed_value)

    return (Add-ArtifactMetadata -Payload $payload)
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

$script:MacPolicyMap = Get-MacPolicyMapIndex
$script:ManagedStore = Initialize-MacPreferenceStore -Scope 'Managed'
$script:SystemStore = Initialize-MacPreferenceStore -Scope 'System'
$script:UserStore = Initialize-MacPreferenceStore -Scope 'User'
$script:ChromeProfileStore = Initialize-MacChromeProfileStore
$script:ChromeInstalled = Test-MacChromeInstalled

$TestMap = @{}
$baseTests = Get-MacBaseTestMap
$cisTests = Get-CisTestsFromCatalog
$baseTests.Keys | Sort-Object | ForEach-Object { $TestMap[$_] = $baseTests[$_] }
$cisTests.Keys | Sort-Object | ForEach-Object { $TestMap[$_] = $cisTests[$_] }

if ($TestId -eq "ALL") {
    $TestMap.Keys | Sort-Object | ForEach-Object {
        $cfg = $TestMap[$_]
        $script:TestResults += (New-MacResultPayload -Id $_ -Cfg $cfg -Result (Invoke-MacChromeControl -Cfg $cfg))
    }
} else {
    if (-not $TestMap.ContainsKey($TestId)) {
        Write-Host "ERROR: Unknown test ID: $TestId" -ForegroundColor Red
        exit 1
    }
    $cfg = $TestMap[$TestId]
    $script:TestResults += (New-MacResultPayload -Id $TestId -Cfg $cfg -Result (Invoke-MacChromeControl -Cfg $cfg))
}

if ($OutputJSON) {
    $countPassed = @($script:TestResults | Where-Object { $_.status -eq "PASSED" }).Count
    $countFailed = @($script:TestResults | Where-Object { $_.status -eq "FAILED" }).Count
    $countUnknown = @($script:TestResults | Where-Object { $_.status -eq "UNKNOWN" }).Count
    $countNotAssessed = @($script:TestResults | Where-Object { $_.status -eq "NOT_ASSESSED" }).Count
    $countNotEnforced = @($script:TestResults | Where-Object { $_.runner_verdict -eq "PASS_NOT_ENFORCED" }).Count
    $countTotal = $script:TestResults.Count

    # NOT_ASSESSED carries no compliance statement, so it is excluded from the
    # weighted risk score instead of being counted as a finding.
    $severityWeights = @{ CRITICAL = 4.0; HIGH = 3.0; MEDIUM = 2.0; LOW = 1.0 }
    $totalWeight = 0.0
    $failedWeight = 0.0
    $unknownWeight = 0.0

    foreach ($t in $script:TestResults) {
        if ($t.status -eq "NOT_ASSESSED") { continue }
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
        platform = "macOS"
        test_date = (Get-Date -Format "yyyy-MM-dd")
        test_time = (Get-Date -Format "HH:mm:ss")
        environment = Get-EnvironmentInfo
        evidence_scope = @{
            chrome_installed = $script:ChromeInstalled
            managed_preferences_readable = (-not $script:ManagedStore.access_denied)
            managed_preferences_denied_paths = @($script:ManagedStore.denied_paths)
            chrome_profiles_scanned = @($script:ChromeProfileStore.profiles | ForEach-Object { $_.name })
            chrome_profiles_unreadable = @($script:ChromeProfileStore.denied_paths + $script:ChromeProfileStore.unreadable_paths)
        }
        summary = @{
            total_tests = $countTotal
            passed = $countPassed
            failed = $countFailed
            unknown = $countUnknown
            not_assessed = $countNotAssessed
            pass_not_enforced = $countNotEnforced
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
        @{ Label = "TEST ID"; Expression = { $_.test_id }; Width = 12 },
        @{ Label = "TEST NAME"; Expression = { $_.test_name }; Width = 28 },
        @{ Label = "STATUS"; Expression = { $_.status }; Width = 14 },
        @{ Label = "VERDICT"; Expression = { $_.runner_verdict }; Width = 18 },
        @{ Label = "MESSAGE"; Expression = { $_.message }; Width = 42 }
    )
}
