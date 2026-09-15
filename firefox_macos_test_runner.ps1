# Firefox Security Test Runner - macOS evidence collector.
# PowerShell 7 only. The emitted result contract is identical to
# firefox_test_runner.ps1 so apply_verification.ps1 and the reporting layer
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
# Shared helpers (fail-fast: a missing collector is a coverage gap, not
# something to silently work around)
# ---------------------------------------------------------------------------

$script:EvidenceHelperPath = Join-Path $PSScriptRoot 'macos_evidence.ps1'
if (-not (Test-Path -LiteralPath $script:EvidenceHelperPath)) {
    throw "macOS evidence helper not found: $script:EvidenceHelperPath. The run cannot continue with incomplete evidence coverage."
}
. $script:EvidenceHelperPath

# The prefs.js / user.js parser already exists in the verification engine and is
# platform-agnostic, so it is reused here instead of being reimplemented.
# verify_value_based.ps1 is a definition-only library; dot-sourcing it runs no
# verification work. Get-FirefoxPrefValue must therefore never be redefined below.
$script:VerificationEnginePath = Join-Path $PSScriptRoot 'verify_value_based.ps1'
if (-not (Test-Path -LiteralPath $script:VerificationEnginePath)) {
    throw "Verification engine not found: $script:VerificationEnginePath. The shared prefs.js parser cannot be loaded."
}
. $script:VerificationEnginePath
if (-not (Get-Command -Name 'Get-FirefoxPrefValue' -CommandType Function -ErrorAction SilentlyContinue)) {
    throw "The shared prefs.js parser (Get-FirefoxPrefValue) was not exported by $script:VerificationEnginePath."
}

$script:IsMacHost = ($PSVersionTable.PSVersion.Major -ge 6) -and [bool]$IsMacOS
$script:ManagedPreferencesRoot = '/Library/Managed Preferences'
$script:SystemPreferencesRoot = '/Library/Preferences'

$script:UserHome = [Environment]::GetFolderPath('UserProfile')
if ([string]::IsNullOrWhiteSpace($script:UserHome)) { $script:UserHome = "$HOME" }
$script:UserPreferencesRoot = Join-Path $script:UserHome 'Library/Preferences'

# Launch switches that neutralise a deployed policy or open a remote control
# surface at runtime.
$script:FirefoxBypassFlags = @(
    '--safe-mode',
    '-safe-mode',
    '--allow-downgrade',
    '--marionette',
    '--start-debugger-server',
    '--remote-debugging-port',
    '--jsdebugger',
    '--disable-e10s',
    '--purgecaches'
)

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
    evidence_provenance = @{}
}

# ---------------------------------------------------------------------------
# macOS policy map (single source of truth for domains, paths and modes)
# ---------------------------------------------------------------------------

function Expand-MacPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    if ($Path.StartsWith('~/')) { return (Join-Path $script:UserHome $Path.Substring(2)) }
    if ($Path -eq '~') { return $script:UserHome }
    return $Path
}

function Get-MacFirefoxPolicyMap {
    $mapPath = Join-Path $PSScriptRoot 'firefox_macos_policy_map.json'
    if (-not (Test-Path -LiteralPath $mapPath)) {
        throw "Firefox macOS policy map not found: $mapPath. The run cannot continue with incomplete control coverage."
    }

    try {
        $map = Get-Content -LiteralPath $mapPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Firefox macOS policy map is not valid JSON: $mapPath. $($_.Exception.Message)"
    }

    $controls = @($map.controls)
    if ($controls.Count -eq 0) {
        throw "Firefox macOS policy map contains no controls: $mapPath"
    }

    $byControl = @{}
    $byPolicyKey = @{}
    foreach ($item in $controls) {
        $controlId = [string]$item.control_id
        if ([string]::IsNullOrWhiteSpace($controlId)) {
            throw "Firefox macOS policy map contains an entry without control_id: $mapPath"
        }

        $mode = if ([string]::IsNullOrWhiteSpace([string]$item.mode)) { 'MANUAL' } else { ([string]$item.mode).ToUpperInvariant() }
        $supported = $true
        if ($null -ne $item.PSObject.Properties['macos_supported']) { $supported = [bool]$item.macos_supported }
        if (-not $supported -and [string]::IsNullOrWhiteSpace([string]$item.unsupported_reason)) {
            throw "Firefox macOS policy map entry '$controlId' is marked unsupported but has no unsupported_reason: $mapPath"
        }
        if ($supported -and $mode -in @('POLICY', 'PREF') -and [string]::IsNullOrWhiteSpace([string]$item.policy_key)) {
            throw "Firefox macOS policy map entry '$controlId' is $mode-mapped but has no policy_key: $mapPath"
        }

        $entry = @{
            control_id = $controlId
            policy_key = [string]$item.policy_key
            preference_domain = if ([string]::IsNullOrWhiteSpace([string]$item.preference_domain)) { [string]$map.preference_domain } else { [string]$item.preference_domain }
            mode = $mode
            value_type = [string]$item.value_type
            pref_name = [string]$item.pref_name
            equivalent_policy_keys = @($item.equivalent_policy_keys | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            equivalent_pref_names = @($item.equivalent_pref_names | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            macos_supported = $supported
            unsupported_result = if ([string]::IsNullOrWhiteSpace([string]$item.unsupported_result)) { 'NOT_ASSESSED' } else { [string]$item.unsupported_result }
            unsupported_reason = [string]$item.unsupported_reason
            notes = [string]$item.notes
        }

        $byControl[$controlId] = $entry
        $key = $entry.policy_key
        if (-not [string]::IsNullOrWhiteSpace($key) -and -not $byPolicyKey.ContainsKey($key)) {
            $byPolicyKey[$key] = $entry
        }
    }

    $bundleCandidates = @($map.discovery.application_bundle.candidate_paths | ForEach-Object { Expand-MacPath -Path ([string]$_) } | Where-Object { $_ })
    $profilesIniCandidates = @($map.discovery.profiles_ini.candidate_paths | ForEach-Object { Expand-MacPath -Path ([string]$_) } | Where-Object { $_ })
    if ($bundleCandidates.Count -eq 0 -or $profilesIniCandidates.Count -eq 0) {
        throw "Firefox macOS policy map has no discovery candidates: $mapPath"
    }

    return @{
        path = $mapPath
        document = $map
        by_control = $byControl
        by_policy_key = $byPolicyKey
        preference_domain = [string]$map.preference_domain
        gate_key = [string]$map.channels.plist.gate.key
        policies_json_relative = [string]$map.channels.policies_json.bundle_relative_path
        policies_json_root_key = [string]$map.channels.policies_json.root_key
        bundle_candidates = $bundleCandidates
        bundle_process_pattern = [string]$map.discovery.application_bundle.process_pattern
        profiles_ini_candidates = $profilesIniCandidates
        profile_fallback_root = Expand-MacPath -Path ([string]$map.discovery.profiles.fallback_root)
        profile_evidence_files = @($map.discovery.profiles.evidence_files | ForEach-Object { [string]$_ } | Where-Object { $_ })
        plist_scope_order = @($map.channel_precedence.within_plist_channel.order | ForEach-Object { [string]$_ })
        unreadable_root_cause = [string]$map.channel_precedence.unreadable_channel.root_cause
    }
}

# ---------------------------------------------------------------------------
# Value helpers
# ---------------------------------------------------------------------------

function Get-MacObjectMember {
    <#
      Single-segment, case-insensitive member lookup. Firefox preference names
      contain dots, so a dot-splitting path walker would shred keys such as
      'network.trr.mode' into non-existent members.
    #>
    param(
        [object]$Root,
        [string]$Name
    )

    $result = @{ found = $false; value = $null }
    if ($null -eq $Root -or [string]::IsNullOrWhiteSpace($Name)) { return $result }

    if ($Root -is [System.Collections.IDictionary]) {
        foreach ($key in $Root.Keys) {
            if ([string]$key -ieq $Name) {
                $result.found = $true
                $result.value = $Root[$key]
                return $result
            }
        }
        return $result
    }

    $property = $Root.PSObject.Properties | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
    if ($null -ne $property) {
        $result.found = $true
        $result.value = $property.Value
    }
    return $result
}

function Resolve-FirefoxPrefPolicyShape {
    <#
      A Preferences member is either the scalar value itself (legacy shape) or a
      { Value, Status, Type } object (Firefox 81+). Treating the object as the
      value would compare a dictionary against a boolean and report a correctly
      deployed preference as non-compliant.
    #>
    param([object]$Value)

    $result = @{ value = $Value; locked = $false; shape = 'scalar' }
    if ($null -eq $Value) { return $result }
    if ($Value -is [bool] -or $Value -is [string] -or $Value -is [int] -or $Value -is [int64] -or $Value -is [double]) { return $result }

    $inner = Get-MacObjectMember -Root $Value -Name 'Value'
    if (-not $inner.found) { return $result }

    $status = Get-MacObjectMember -Root $Value -Name 'Status'
    $result.value = $inner.value
    $result.shape = 'value_status'
    $result.locked = ($status.found -and ([string]$status.value) -ieq 'locked')
    return $result
}

# ---------------------------------------------------------------------------
# Preference-domain stores (plist channel)
# ---------------------------------------------------------------------------

function Get-MacDomainPlistCandidate {
    param([ValidateSet('MANAGED', 'SYSTEM', 'USER')][string]$Scope)

    $domainFile = "$($script:FirefoxDomain).plist"
    switch ($Scope) {
        'MANAGED' {
            $paths = @((Join-Path $script:ManagedPreferencesRoot $domainFile))
            foreach ($dir in (Get-ChildItem -LiteralPath $script:ManagedPreferencesRoot -Directory -Force -ErrorAction SilentlyContinue)) {
                $paths += (Join-Path $dir.FullName $domainFile)
            }
            return @($paths | Select-Object -Unique)
        }
        'SYSTEM' { return @((Join-Path $script:SystemPreferencesRoot $domainFile)) }
        'USER'   { return @((Join-Path $script:UserPreferencesRoot $domainFile)) }
    }
    return @()
}

function Initialize-MacPreferenceStore {
    param([ValidateSet('MANAGED', 'SYSTEM', 'USER')][string]$Scope)

    $store = @{
        scope = $Scope
        enforced = ($Scope -eq 'MANAGED')
        documents = @()
        access_denied = $false
        denied_paths = @()
    }
    if (-not $script:IsMacHost) { return $store }

    if ($Scope -eq 'MANAGED') {
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
        key_path = $Key
        scope = [string]$Store.scope
        locked = $false
        access_denied = [bool]$Store.access_denied
    }
    if ([string]::IsNullOrWhiteSpace($Key)) { return $result }

    foreach ($document in @($Store.documents)) {
        $lookup = Get-MacObjectMember -Root $document.value -Name $Key
        if (-not $lookup.found) { continue }
        $result.found = $true
        $result.value = $lookup.value
        $result.display = ConvertTo-MacDisplayValue -Value $lookup.value
        $result.source_path = [string]$document.path
        return $result
    }

    return $result
}

function Get-MacStorePrefValue {
    <# Reads policies.Preferences.<pref> from a preference-domain document. #>
    param(
        [hashtable]$Store,
        [string]$PrefName
    )

    $result = @{
        found = $false
        value = $null
        display = ''
        source_path = ''
        key_path = "Preferences.$PrefName"
        scope = [string]$Store.scope
        locked = $false
        access_denied = [bool]$Store.access_denied
    }
    if ([string]::IsNullOrWhiteSpace($PrefName)) { return $result }

    foreach ($document in @($Store.documents)) {
        $prefsRoot = Get-MacObjectMember -Root $document.value -Name 'Preferences'
        if (-not $prefsRoot.found) { continue }
        $lookup = Get-MacObjectMember -Root $prefsRoot.value -Name $PrefName
        if (-not $lookup.found) { continue }

        $shape = Resolve-FirefoxPrefPolicyShape -Value $lookup.value
        $result.found = $true
        $result.value = $shape.value
        $result.locked = [bool]$shape.locked
        $result.display = ConvertTo-MacDisplayValue -Value $shape.value
        $result.source_path = [string]$document.path
        return $result
    }

    return $result
}

# ---------------------------------------------------------------------------
# Application bundles and the policies.json channel
# ---------------------------------------------------------------------------

function Get-MacFirefoxProcessArgument {
    if (-not $script:IsMacHost) { return @() }
    try {
        $pattern = if ([string]::IsNullOrWhiteSpace($script:PolicyMap.bundle_process_pattern)) { '(?i)firefox' } else { $script:PolicyMap.bundle_process_pattern }
        return @(Get-MacProcessArguments -ProcessNamePattern $pattern)
    }
    catch { return @() }
}

function Get-MacFirefoxBundleFromProcess {
    <#
      A bundle installed outside /Applications is still discoverable through the
      running executable path, so a non-standard deployment is not reported as
      "Firefox not installed".
    #>
    $bundles = @()
    foreach ($line in (Get-MacFirefoxProcessArgument)) {
        $match = [regex]::Match([string]$line, '^\s*(?<bundle>/.*?\.app)/Contents/MacOS/[^\s]+')
        if ($match.Success) { $bundles += $match.Groups['bundle'].Value }
    }
    return @($bundles | Select-Object -Unique)
}

function Read-MacFirefoxPoliciesJson {
    param([string]$Path)

    $result = @{ state = 'missing'; value = $null; path = $Path }

    $access = Test-MacReadAccess -Path $Path
    if (-not $access.exists) { return $result }
    if (-not $access.readable) {
        $result.state = 'access_denied'
        return $result
    }

    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    }
    catch [System.UnauthorizedAccessException] {
        $result.state = 'access_denied'
        return $result
    }
    catch {
        $result.state = 'access_denied'
        return $result
    }

    try {
        $result.value = $raw | ConvertFrom-Json -ErrorAction Stop
        $result.state = 'read'
    }
    catch {
        # A malformed policy file is unreadable evidence, not proof of absence.
        $result.state = 'unparsable'
    }

    return $result
}

function Initialize-MacFirefoxBundleStore {
    $store = @{
        bundles = @()
        access_denied = $false
        denied_paths = @()
        installed = $false
    }
    if (-not $script:IsMacHost) { return $store }

    $candidates = @(@(Get-MacFirefoxBundleFromProcess) + @($script:PolicyMap.bundle_candidates) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

    foreach ($bundlePath in $candidates) {
        $access = Test-MacReadAccess -Path $bundlePath
        if ($access.access_denied) {
            $store.access_denied = $true
            $store.denied_paths += $bundlePath
            $store.installed = $true
            continue
        }
        if (-not $access.exists) { continue }

        $store.installed = $true
        $policiesPath = Join-Path $bundlePath $script:PolicyMap.policies_json_relative
        $policies = Read-MacFirefoxPoliciesJson -Path $policiesPath

        if ($policies.state -in @('access_denied', 'unparsable')) {
            $store.access_denied = $true
            $store.denied_paths += $policiesPath
        }

        $version = Get-MacAppVersion -BundlePath @($bundlePath)
        $store.bundles += @{
            path = $bundlePath
            version = if ($version.found) { [string]$version.value } elseif ($version.access_denied) { 'ACCESS_DENIED' } else { 'NOT_FOUND' }
            policies_json_path = $policiesPath
            policies_json_state = $policies.state
            policies = if ($policies.state -eq 'read') { (Get-MacObjectMember -Root $policies.value -Name $script:PolicyMap.policies_json_root_key).value } else { $null }
        }
    }

    return $store
}

function Get-MacBundlePolicyValue {
    param(
        [string]$PolicyKey,
        [string[]]$EquivalentKeys = @()
    )

    $result = @{
        found = $false; value = $null; display = ''; source_path = ''; bundle_path = ''
        bundle_version = ''; key_path = ''; matched_key = [string]$PolicyKey
        scope = 'BUNDLE'; access_denied = [bool]$script:BundleStore.access_denied
    }

    $keys = @(@($PolicyKey) + @($EquivalentKeys) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    foreach ($bundle in @($script:BundleStore.bundles)) {
        if ($null -eq $bundle.policies) { continue }
        foreach ($key in $keys) {
            $lookup = Get-MacObjectMember -Root $bundle.policies -Name $key
            if (-not $lookup.found) { continue }
            $result.found = $true
            $result.value = $lookup.value
            $result.display = ConvertTo-MacDisplayValue -Value $lookup.value
            $result.source_path = [string]$bundle.policies_json_path
            $result.bundle_path = [string]$bundle.path
            $result.bundle_version = [string]$bundle.version
            $result.matched_key = $key
            $result.key_path = "$($script:PolicyMap.policies_json_root_key).$key"
            return $result
        }
    }

    return $result
}

function Get-MacBundlePrefValue {
    param([string]$PrefName)

    $result = @{
        found = $false; value = $null; display = ''; source_path = ''; bundle_path = ''
        bundle_version = ''; key_path = ''; matched_key = [string]$PrefName
        scope = 'BUNDLE'; locked = $false; access_denied = [bool]$script:BundleStore.access_denied
    }
    if ([string]::IsNullOrWhiteSpace($PrefName)) { return $result }

    foreach ($bundle in @($script:BundleStore.bundles)) {
        if ($null -eq $bundle.policies) { continue }
        $prefsRoot = Get-MacObjectMember -Root $bundle.policies -Name 'Preferences'
        if (-not $prefsRoot.found) { continue }
        $lookup = Get-MacObjectMember -Root $prefsRoot.value -Name $PrefName
        if (-not $lookup.found) { continue }

        $shape = Resolve-FirefoxPrefPolicyShape -Value $lookup.value
        $result.found = $true
        $result.value = $shape.value
        $result.locked = [bool]$shape.locked
        $result.display = ConvertTo-MacDisplayValue -Value $shape.value
        $result.source_path = [string]$bundle.policies_json_path
        $result.bundle_path = [string]$bundle.path
        $result.bundle_version = [string]$bundle.version
        $result.key_path = "$($script:PolicyMap.policies_json_root_key).Preferences.$PrefName"
        return $result
    }

    return $result
}

# ---------------------------------------------------------------------------
# Provider selection (PROVIDER_EXCLUSIVE, decided once per endpoint)
# ---------------------------------------------------------------------------

function Resolve-MacFirefoxProvider {
    <#
      Firefox picks ONE policy provider for the whole policy set. When
      EnterprisePoliciesEnabled is true in the preference domain, policies.json
      is not read at all, so a value that exists only there is a deployment
      defect rather than compliance.
    #>
    $result = @{
        resolved = $false
        winner = ''
        gate_key = [string]$script:PolicyMap.gate_key
        gate_found = $false
        gate_value = ''
        gate_scope = ''
        gate_source_path = ''
        reason = ''
        root_cause = ''
        denied_paths = @()
    }

    if ($script:ManagedStore.access_denied) {
        $result.reason = "The preference-domain gate '$($result.gate_key)' could not be read because access to $($script:ManagedStore.denied_paths -join ', ') was denied (TCC / Full Disk Access). The winning policy provider is therefore unknown."
        $result.root_cause = [string]$script:PolicyMap.unreadable_root_cause
        $result.denied_paths = @($script:ManagedStore.denied_paths)
        return $result
    }

    foreach ($scope in @($script:PolicyMap.plist_scope_order)) {
        $store = $script:PlistStores[$scope]
        if ($null -eq $store) { continue }
        $gate = Get-MacStoreValue -Store $store -Key $result.gate_key
        if (-not $gate.found) { continue }

        $result.gate_found = $true
        $result.gate_value = $gate.display
        $result.gate_scope = $scope
        $result.gate_source_path = $gate.source_path
        break
    }

    $result.resolved = $true
    if ($result.gate_found -and ($result.gate_value -in @('true', '1'))) {
        $result.winner = 'PLIST'
        $result.reason = "$($result.gate_key)=$($result.gate_value) in the $($result.gate_scope) scope, so every policy value is read from the $($script:FirefoxDomain) preference domain and policies.json is ignored by Firefox."
    }
    else {
        $result.winner = 'POLICIES_JSON'
        $result.reason = if ($result.gate_found) {
            "$($result.gate_key)=$($result.gate_value), so the preference-domain provider is inactive and Firefox reads the policies.json shipped in the application bundle."
        } else {
            "$($result.gate_key) is not defined in any preference-domain scope, so Firefox reads the policies.json shipped in the application bundle."
        }
    }

    return $result
}

# ---------------------------------------------------------------------------
# Profile discovery (every profile is scanned, default profiles first)
# ---------------------------------------------------------------------------

function Read-MacProfilesIniSection {
    param([string]$Path)

    $sections = @()
    $current = @{}
    foreach ($line in (Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        $text = [string]$line
        if ($text -match '^\s*\[(.+)\]\s*$') {
            if ($current.Count -gt 0) { $sections += , $current }
            $current = @{ section = $Matches[1] }
            continue
        }
        if ($text -match '^\s*([^=]+?)\s*=\s*(.*?)\s*$') {
            $current[$Matches[1].Trim()] = $Matches[2].Trim()
        }
    }
    if ($current.Count -gt 0) { $sections += , $current }
    return @($sections)
}

function Initialize-MacFirefoxProfileStore {
    <#
      Enterprise endpoints routinely carry more than one Firefox profile, so
      every profile listed in profiles.ini is scanned and the profile that
      produced a value is recorded with the evidence. Default profiles are read
      first only to report the most representative value first.
    #>
    $store = @{
        profiles = @()
        profiles_ini_paths = @()
        discovered = $false
        evidence_available = $false
        access_denied = $false
        denied_paths = @()
    }
    if (-not $script:IsMacHost) { return $store }

    $seen = @{}
    $defaults = New-Object System.Collections.Generic.List[hashtable]
    $others = New-Object System.Collections.Generic.List[hashtable]

    foreach ($iniPath in @($script:PolicyMap.profiles_ini_candidates)) {
        $iniAccess = Test-MacReadAccess -Path $iniPath
        if ($iniAccess.access_denied) {
            $store.access_denied = $true
            $store.denied_paths += $iniPath
            continue
        }
        if (-not $iniAccess.exists) { continue }

        $store.profiles_ini_paths += $iniPath
        $root = Split-Path -Path $iniPath -Parent

        foreach ($section in (Read-MacProfilesIniSection -Path $iniPath)) {
            if (-not $section.ContainsKey('Path')) { continue }
            $relative = [string]$section['Path']
            if ([string]::IsNullOrWhiteSpace($relative)) { continue }

            $isRelative = ($section.ContainsKey('IsRelative') -and [string]$section['IsRelative'] -eq '1')
            $full = if ($isRelative) { Join-Path $root $relative } else { Expand-MacPath -Path $relative }
            if ($seen.ContainsKey($full)) { continue }

            $access = Test-MacReadAccess -Path $full
            if ($access.access_denied) {
                $store.access_denied = $true
                $store.denied_paths += $full
                continue
            }
            if (-not $access.exists) { continue }

            $seen[$full] = $true
            $isDefault = ($section.ContainsKey('Default') -and [string]$section['Default'] -eq '1')
            $entry = @{
                name = if ($section.ContainsKey('Name')) { [string]$section['Name'] } else { (Split-Path $full -Leaf) }
                path = $full
                is_default = $isDefault
                source = 'profiles.ini'
                root = $root
            }
            if ($isDefault) { $defaults.Add($entry) } else { $others.Add($entry) }
        }
    }

    $scanRoots = @(@($script:PolicyMap.profiles_ini_candidates | ForEach-Object { Join-Path (Split-Path -Path $_ -Parent) 'Profiles' }) +
        @($script:PolicyMap.profile_fallback_root) | Where-Object { $_ } | Select-Object -Unique)

    foreach ($scanRoot in $scanRoots) {
        $rootAccess = Test-MacReadAccess -Path $scanRoot
        if ($rootAccess.access_denied) {
            $store.access_denied = $true
            $store.denied_paths += $scanRoot
            continue
        }
        if (-not $rootAccess.exists) { continue }

        foreach ($dir in (Get-ChildItem -LiteralPath $scanRoot -Directory -Force -ErrorAction SilentlyContinue | Sort-Object Name)) {
            if ($seen.ContainsKey($dir.FullName)) { continue }
            $seen[$dir.FullName] = $true
            $others.Add(@{
                name = $dir.Name
                path = $dir.FullName
                is_default = $false
                source = 'profiles_directory_scan'
                root = $scanRoot
            })
        }
    }

    foreach ($entry in @($defaults.ToArray() + $others.ToArray())) {
        $evidenceFiles = @()
        foreach ($fileName in @($script:PolicyMap.profile_evidence_files)) {
            $filePath = Join-Path $entry.path $fileName
            $access = Test-MacReadAccess -Path $filePath
            if (-not $access.exists) { continue }
            if (-not $access.readable) {
                $store.access_denied = $true
                $store.denied_paths += $filePath
                continue
            }
            $evidenceFiles += $fileName
        }

        $entry.evidence_files = @($evidenceFiles)
        $store.profiles += $entry
        if ($evidenceFiles.Count -gt 0) { $store.evidence_available = $true }
    }

    $store.discovered = ($store.profiles.Count -gt 0)
    return $store
}

function Get-MacFirefoxProfilePref {
    <#
      Reuses the shared, platform-agnostic prefs.js / user.js parser from
      verify_value_based.ps1 and adds the macOS profile provenance around it.
    #>
    param(
        [string]$PrefName,
        [string[]]$EquivalentPrefs = @()
    )

    $result = @{
        found = $false; value = $null; display = ''; source_path = ''; matched_key = [string]$PrefName
        profile_name = ''; profile_path = ''; profile_is_default = $false; profile_source = ''
        evidence_file = ''; scope = 'PROFILE_PREFS'; access_denied = [bool]$script:ProfileStore.access_denied
    }

    $prefs = @(@($PrefName) + @($EquivalentPrefs) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    if ($prefs.Count -eq 0) { return $result }

    foreach ($firefoxProfile in @($script:ProfileStore.profiles)) {
        if (@($firefoxProfile.evidence_files).Count -eq 0) { continue }
        foreach ($pref in $prefs) {
            $lookup = Get-FirefoxPrefValue -ProfilePath $firefoxProfile.path -PrefName $pref
            if ([bool]$lookup.access_denied) {
                $result.access_denied = $true
                continue
            }
            if (-not [bool]$lookup.found) { continue }

            $result.found = $true
            $result.value = $lookup.value
            $result.display = ConvertTo-MacDisplayValue -Value $lookup.value
            $result.matched_key = $pref
            $result.evidence_file = [string]$lookup.source
            $result.source_path = Join-Path $firefoxProfile.path ([string]$lookup.source)
            $result.profile_name = [string]$firefoxProfile.name
            $result.profile_path = [string]$firefoxProfile.path
            $result.profile_is_default = [bool]$firefoxProfile.is_default
            $result.profile_source = [string]$firefoxProfile.source
            return $result
        }
    }

    return $result
}

# ---------------------------------------------------------------------------
# Expectation resolution and comparison (same vocabulary as the Windows runner)
# ---------------------------------------------------------------------------

function Resolve-MacFirefoxExpectation {
    param([hashtable]$Mapping)

    if ($null -eq $Mapping) { return '' }
    $mode = [string]$Mapping.mode
    if ($mode -eq 'MANUAL') { return '' }
    if ($mode -eq 'RUNTIME') { return 'CLEAN' }

    switch -Exact ([string]$Mapping.policy_key) {
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

function Convert-MacExpectationToMachineMeta {
    param([string]$Expectation)

    if ([string]::IsNullOrWhiteSpace($Expectation)) { return @{ kind = ''; value = '' } }

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

function Test-MacFirefoxExpectation {
    param(
        [object]$Value,
        [string]$Expectation
    )

    $vStr = ConvertTo-MacDisplayValue -Value $Value
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
    if ($Expectation -eq 'PRESENT' -or $Expectation -eq 'LOCKED') {
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
        $json = $vLower
        $ok = ($json -match 'installation_mode') -and ($json -match 'blocked|force_installed|allowed')
        return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = "Expected extension restrictions, actual: $vStr" }
    }
    if ($Expectation -eq 'DOH_MANAGED') {
        $ok = $vLower -match 'mode|provider|enabled|locked'
        return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = "Expected DoH managed object, actual: $vStr" }
    }
    if ($Expectation -eq 'COOKIE_RESTRICTED') {
        $ok = $vLower -match 'third|cookie|lifetime|behavior|block'
        return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = "Expected cookie restriction object, actual: $vStr" }
    }
    if ($Expectation -eq 'PROXY_MANAGED') {
        $ok = $vLower -match 'mode|pac|server|proxy'
        return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = "Expected proxy managed object, actual: $vStr" }
    }
    if ($Expectation -eq 'DOWNLOAD_RESTRICTED') {
        [int64]$actual = 0
        if ([int64]::TryParse($vStr, [ref]$actual)) {
            return @{ status = if ($actual -ge 1) { 'PASSED' } else { 'FAILED' }; message = "Expected download restrictions >= 1, actual: $actual" }
        }
        $ok = $vLower -match 'block|restrict|download'
        return @{ status = if ($ok) { 'PASSED' } else { 'FAILED' }; message = "Expected download restriction object, actual: $vStr" }
    }

    return @{ status = 'UNKNOWN'; message = "Unknown expectation '$Expectation', actual: $vStr" }
}

# ---------------------------------------------------------------------------
# Control catalog
# ---------------------------------------------------------------------------

function Get-MacFirefoxCisDefinitionFromLine {
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

function Get-MacFirefoxCisSeverity {
    param([hashtable]$Definition)

    $t = ([string]$Definition.title).ToLowerInvariant()
    if ($t -match 'safe browsing|phishing|sync|accounts|https|tls|certificate|remote debugging|extension|download') { return 'HIGH' }
    if ($t -match 'cookies|telemetry|proxy|clipboard|camera|microphone|location|notification|webrtc|autoplay') { return 'MEDIUM' }
    return 'LOW'
}

function Get-MacFirefoxCisTestsFromCatalog {
    $catalogPath = Join-Path $PSScriptRoot 'firefox_security_controls.txt'
    if (-not (Test-Path -LiteralPath $catalogPath)) {
        throw "Firefox control catalog not found: $catalogPath. The run cannot continue with incomplete control coverage."
    }

    $tests = @{}
    $lines = Get-Content -LiteralPath $catalogPath | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    foreach ($line in $lines) {
        $def = Get-MacFirefoxCisDefinitionFromLine -Line $line
        if ($null -eq $def) { continue }

        $mapping = if ($script:PolicyMap.by_control.ContainsKey($def.control_id)) { $script:PolicyMap.by_control[$def.control_id] } else { $null }
        $testId = 'FF-REF-' + ($def.control_id -replace '[^0-9A-Za-z]+', '-')

        $tests[$testId] = @{
            Name = Get-ControlDisplayName -PolicyKey ([string]$mapping.policy_key) -Definition $def
            Severity = Get-MacFirefoxCisSeverity -Definition $def
            Package = 'FF-REF'
            CISControls = @($def.control_id)
            Type = 'FF-REF'
            Definition = $def
            Mapping = $mapping
            PolicyKey = [string]$mapping.policy_key
        }
    }

    if ($tests.Count -eq 0) {
        throw "Firefox control catalog contains no parseable controls: $catalogPath"
    }

    return $tests
}

function Get-MacFirefoxBaseTestMap {
    $definitions = @(
        @{ Id = 'F-001'; Name = 'Private Browsing';               PolicyKey = 'DisablePrivateBrowsing';                    Severity = 'HIGH';     Package = 'FF-PKG-1'; CISControls = @('1.1') },
        @{ Id = 'F-002'; Name = 'Password Manager';               PolicyKey = 'PasswordManagerEnabled';                    Severity = 'HIGH';     Package = 'FF-PKG-1'; CISControls = @('1.2') },
        @{ Id = 'F-003'; Name = 'Extension Installation';         PolicyKey = 'ExtensionSettings';                         Severity = 'HIGH';     Package = 'FF-PKG-3'; CISControls = @('1.3') },
        @{ Id = 'F-004'; Name = 'Safe Browsing';                  PolicyKey = 'DisableSecurityBypass';                     Severity = 'CRITICAL'; Package = 'FF-PKG-2'; CISControls = @('1.4'); IntuneReferenceUrl = 'https://learn.microsoft.com/en-us/purview/dlp-browser-dlp-learn'; ManageEngineReferenceUrl = 'https://www.manageengine.com/mobile-device-management/help/security_management/mdm_security_management.html' },
        @{ Id = 'F-005'; Name = 'Telemetry Control';              PolicyKey = 'DisableTelemetry';                          Severity = 'MEDIUM';   Package = 'FF-PKG-2'; CISControls = @('1.5') },
        @{ Id = 'F-006'; Name = 'Firefox Sync / Accounts';        PolicyKey = 'DisableFirefoxAccounts';                    Severity = 'CRITICAL'; Package = 'FF-PKG-2'; CISControls = @('1.6'); IntuneReferenceUrl = 'https://learn.microsoft.com/en-us/intune/app-management/protection/overview'; ManageEngineReferenceUrl = 'https://www.manageengine.com/mobile-device-management/help/profile_management/mdm_profile_management.html' },
        @{ Id = 'F-007'; Name = 'DNS over HTTPS';                 PolicyKey = 'DNSOverHTTPS';                              Severity = 'MEDIUM';   Package = 'FF-PKG-5'; CISControls = @('1.7') },
        @{ Id = 'F-008'; Name = 'Cookie Behavior';                PolicyKey = 'Cookies';                                   Severity = 'HIGH';     Package = 'FF-PKG-4'; CISControls = @('1.8') },
        @{ Id = 'F-009'; Name = 'Disable Developer Tools';        PolicyKey = 'DisableDeveloperTools';                     Severity = 'MEDIUM';   Package = 'FF-PKG-1'; CISControls = @('1.9') },
        @{ Id = 'F-010'; Name = 'Proxy Policy';                   PolicyKey = 'Proxy';                                     Severity = 'HIGH';     Package = 'FF-PKG-5'; CISControls = @('1.10') },
        @{ Id = 'F-011'; Name = 'Disable Form History';           PolicyKey = 'DisableFormHistory';                        Severity = 'MEDIUM';   Package = 'FF-PKG-2'; CISControls = @('1.11') },
        @{ Id = 'F-012'; Name = 'Command-Line & Runtime Flags';   PolicyKey = 'RuntimeProcessFlags';                       Severity = 'MEDIUM';   Package = 'FF-PKG-6'; CISControls = @('1.12') },
        @{ Id = 'F-013'; Name = 'HTTPS-Only Mode';                PolicyKey = 'dom.security.https_only_mode';              Severity = 'HIGH';     Package = 'FF-PKG-7'; CISControls = @('1.31') },
        @{ Id = 'F-014'; Name = 'TLS Minimum Version';            PolicyKey = 'security.tls.version.min';                  Severity = 'HIGH';     Package = 'FF-PKG-7'; CISControls = @('1.32') },
        @{ Id = 'F-015'; Name = 'Remote Debugging';               PolicyKey = 'devtools.debugger.remote-enabled';          Severity = 'HIGH';     Package = 'FF-PKG-7'; CISControls = @('1.39') },
        @{ Id = 'F-016'; Name = 'Disable Experiments';            PolicyKey = 'app.normandy.enabled';                      Severity = 'MEDIUM';   Package = 'FF-PKG-7'; CISControls = @('1.14', '1.59') },
        @{ Id = 'F-017'; Name = 'OCSP Validation';                PolicyKey = 'security.OCSP.enabled';                     Severity = 'HIGH';     Package = 'FF-PKG-5'; CISControls = @() },
        @{ Id = 'F-018'; Name = 'HTTP/3 Disable';                 PolicyKey = 'network.http.http3.enable';                 Severity = 'MEDIUM';   Package = 'FF-PKG-5'; CISControls = @() },
        @{ Id = 'F-019'; Name = 'Mixed Content Block';            PolicyKey = 'security.mixed_content.block_active_content'; Severity = 'HIGH';   Package = 'FF-PKG-5'; CISControls = @() },
        @{ Id = 'F-020'; Name = 'Certificate Pinning';            PolicyKey = 'security.cert_pinning.enforcement_level';   Severity = 'HIGH';     Package = 'FF-PKG-5'; CISControls = @() }
    )

    $map = @{}
    foreach ($def in $definitions) {
        $mapping = if ($script:PolicyMap.by_policy_key.ContainsKey($def.PolicyKey)) { $script:PolicyMap.by_policy_key[$def.PolicyKey] } else { $null }
        if ($null -eq $mapping) {
            throw "Base test $($def.Id) references '$($def.PolicyKey)', which is absent from $($script:PolicyMap.path). The run cannot continue with incomplete control coverage."
        }

        $map[$def.Id] = @{
            Name = $def.Name
            Severity = $def.Severity
            Package = $def.Package
            CISControls = @($def.CISControls)
            Type = 'BASE'
            Definition = @{ control_id = $mapping.control_id; title = $def.Name; raw_line = $def.Name }
            Mapping = $mapping
            PolicyKey = $def.PolicyKey
            IntuneReferenceUrl = [string]$def.IntuneReferenceUrl
            ManageEngineReferenceUrl = [string]$def.ManageEngineReferenceUrl
        }
    }

    return $map
}

# ---------------------------------------------------------------------------
# Layer evidence
# ---------------------------------------------------------------------------

function Get-MacFirefoxLayer1Evidence {
    <#
      L1 is the enforced tier: the policies.json inside the application bundle or
      the org.mozilla.firefox value under /Library/Managed Preferences. Only the
      provider Firefox actually reads can decide the verdict; the losing channel
      is recorded as context.
    #>
    param([hashtable]$Mapping)

    $evidence = @{
        found = $false; value = $null; display = ''; channel = ''; scope = ''
        source_path = ''; key_path = ''; matched_key = ''; bundle_path = ''; bundle_version = ''
        locked = $false; conflict = $false; conflict_note = ''; access_denied = $false
    }

    $isPref = ([string]$Mapping.mode -eq 'PREF')
    $winner = [string]$script:Provider.winner

    $plistHit = $null
    if ($isPref) {
        $plistHit = Get-MacStorePrefValue -Store $script:PlistStores['MANAGED'] -PrefName ([string]$Mapping.pref_name)
    }
    else {
        foreach ($key in @(@([string]$Mapping.policy_key) + @($Mapping.equivalent_policy_keys) | Where-Object { $_ } | Select-Object -Unique)) {
            $candidate = Get-MacStoreValue -Store $script:PlistStores['MANAGED'] -Key $key
            if ($candidate.found) { $plistHit = $candidate; break }
            if ($null -eq $plistHit) { $plistHit = $candidate }
        }
    }

    $bundleHit = if ($isPref) {
        Get-MacBundlePrefValue -PrefName ([string]$Mapping.pref_name)
    } else {
        Get-MacBundlePolicyValue -PolicyKey ([string]$Mapping.policy_key) -EquivalentKeys @($Mapping.equivalent_policy_keys)
    }

    if ($winner -eq 'PLIST') {
        $winnerHit = $plistHit
        $loserHit = $bundleHit
        $winnerChannel = 'PLIST'
        $loserChannel = 'POLICIES_JSON'
    }
    else {
        $winnerHit = $bundleHit
        $loserHit = $plistHit
        $winnerChannel = 'POLICIES_JSON'
        $loserChannel = 'PLIST'
    }

    if ($null -ne $winnerHit -and [bool]$winnerHit.found) {
        $evidence.found = $true
        $evidence.value = $winnerHit.value
        $evidence.display = [string]$winnerHit.display
        $evidence.channel = $winnerChannel
        $evidence.scope = if ($winnerChannel -eq 'PLIST') { 'MANAGED' } else { 'BUNDLE' }
        $evidence.source_path = [string]$winnerHit.source_path
        $evidence.key_path = [string]$winnerHit.key_path
        $evidence.matched_key = [string]$winnerHit.matched_key
        $evidence.locked = [bool]$winnerHit.locked
        if ($winnerChannel -eq 'POLICIES_JSON') {
            $evidence.bundle_path = [string]$winnerHit.bundle_path
            $evidence.bundle_version = [string]$winnerHit.bundle_version
        }
        if ([string]::IsNullOrWhiteSpace($evidence.matched_key)) { $evidence.matched_key = [string]$Mapping.policy_key }
        return $evidence
    }

    if ($null -ne $loserHit -and [bool]$loserHit.found) {
        # Configured but not in force: reported as a deployment defect, never as compliance.
        $evidence.conflict = $true
        $evidence.conflict_note = "The value is configured in the $loserChannel channel ($($loserHit.source_path)) but Firefox reads policies from $winnerChannel on this endpoint, so the configured value is not in force."
    }

    $evidence.matched_key = if ($isPref) { [string]$Mapping.pref_name } else { [string]$Mapping.policy_key }
    return $evidence
}

function Get-MacFirefoxLayer2Evidence {
    <#
      L2 is the user-revertible tier: the profile prefs.js / user.js files plus
      the preference-domain scopes that are writable outside the management
      channel (/Library/Preferences and ~/Library/Preferences).
    #>
    param([hashtable]$Mapping)

    $evidence = @{
        found = $false; value = $null; display = ''; source_label = ''; source_path = ''
        matched_key = ''; profile_name = ''; profile_path = ''; profile_is_default = $false
        profile_source = ''; evidence_file = ''; scope = ''; access_denied = $false
    }

    $prefName = [string]$Mapping.pref_name
    if (-not [string]::IsNullOrWhiteSpace($prefName)) {
        $hit = Get-MacFirefoxProfilePref -PrefName $prefName -EquivalentPrefs @($Mapping.equivalent_pref_names)
        $evidence.access_denied = [bool]$hit.access_denied
        if ($hit.found) {
            $evidence.found = $true
            $evidence.value = $hit.value
            $evidence.display = "$($hit.matched_key)=$($hit.display) [profile: $($hit.profile_name)]"
            $evidence.source_label = 'FIREFOX_PROFILE_PREFERENCE'
            $evidence.source_path = [string]$hit.source_path
            $evidence.matched_key = [string]$hit.matched_key
            $evidence.profile_name = [string]$hit.profile_name
            $evidence.profile_path = [string]$hit.profile_path
            $evidence.profile_is_default = [bool]$hit.profile_is_default
            $evidence.profile_source = [string]$hit.profile_source
            $evidence.evidence_file = [string]$hit.evidence_file
            $evidence.scope = 'PROFILE'
            return $evidence
        }
    }

    $isPref = ([string]$Mapping.mode -eq 'PREF')
    foreach ($scope in @('SYSTEM', 'USER')) {
        $store = $script:PlistStores[$scope]
        if ($null -eq $store) { continue }
        if ([bool]$store.access_denied) { $evidence.access_denied = $true }

        $hit = if ($isPref) {
            Get-MacStorePrefValue -Store $store -PrefName $prefName
        } else {
            Get-MacStoreValue -Store $store -Key ([string]$Mapping.policy_key)
        }
        if (-not $hit.found) { continue }

        $evidence.found = $true
        $evidence.value = $hit.value
        $evidence.display = [string]$hit.display
        $evidence.source_label = if ($scope -eq 'SYSTEM') { 'SYSTEM_DOMAIN_NOT_MDM_ENFORCED' } else { 'USER_DOMAIN_NOT_ENFORCED' }
        $evidence.source_path = [string]$hit.source_path
        $evidence.matched_key = [string]$hit.key_path
        $evidence.scope = $scope
        return $evidence
    }

    $evidence.matched_key = if ([string]::IsNullOrWhiteSpace($prefName)) { [string]$Mapping.policy_key } else { $prefName }
    return $evidence
}

function Get-MacFirefoxRuntimeEvidence {
    <#
      Runtime evidence is only meaningful for runtime-scoped controls and bypass
      flags. Absence of a bypass switch is never used as compliance evidence for
      any other control.
    #>
    $arguments = @(Get-MacFirefoxProcessArgument)
    $result = @{
        running = ($arguments.Count -gt 0)
        process_count = $arguments.Count
        hits = @()
    }

    foreach ($line in $arguments) {
        foreach ($flag in $script:FirefoxBypassFlags) {
            if ($line -match ([regex]::Escape($flag) + '(\s|=|$)')) { $result.hits += $flag }
        }
    }
    $result.hits = @($result.hits | Select-Object -Unique)

    return $result
}

# ---------------------------------------------------------------------------
# Control evaluation
# ---------------------------------------------------------------------------

function Get-MacLayerMethodText {
    param([string]$Layer)

    switch ($Layer) {
        'L1' { return "Enforced policy channel (Firefox bundle policies.json / $($script:ManagedPreferencesRoot)/$($script:FirefoxDomain).plist)" }
        'L2' { return "User-revertible configuration (Firefox profile prefs.js and user.js, $($script:SystemPreferencesRoot) and $($script:UserPreferencesRoot) preference domains)" }
        'L3' { return 'Live Firefox process arguments' }
    }
    return ''
}

function New-MacNotAssessedResult {
    param(
        [hashtable]$Cfg,
        [string]$Reason,
        [bool]$AccessDenied = $false,
        [string[]]$EvidencePaths = @(),
        [string]$RootCause = ''
    )

    $mapping = $Cfg.Mapping
    $expectation = Resolve-MacFirefoxExpectation -Mapping $mapping
    $meta = Convert-MacExpectationToMachineMeta -Expectation $expectation
    $policyKey = [string]$Cfg.PolicyKey

    return @{
        status = 'NOT_ASSESSED'
        verdict = 'NOT_ASSESSED'
        enforced = $false
        message = $Reason
        details = "Control: $(@($Cfg.CISControls) -join ', ') | Policy key: $(if ([string]::IsNullOrWhiteSpace($policyKey)) { '(none)' } else { $policyKey })"
        finding_details = $Reason
        not_assessed_reason = $Reason
        root_cause = $RootCause
        access_denied = $AccessDenied
        access_denied_reason = if ($AccessDenied) { $Reason } else { '' }
        expected_value = if ([string]::IsNullOrWhiteSpace($expectation)) { '' } else { "Expected: $expectation" }
        expected_kind = $meta.kind
        expected_machine_value = $meta.value
        observed_value = '(not assessed)'
        evidence_output = $Reason
        evidence_type = if ($AccessDenied) { 'evidence_access_denied' } else { 'not_assessed' }
        evidence_source_label = 'NONE'
        evidence_paths = @($EvidencePaths)
        evidence_provenance = @{ channel = 'NONE'; scope = ''; source_path = ''; key_path = $policyKey }
        policy_key = $policyKey
        effective_channel = [string]$script:Provider.winner
        channel_conflict = $false
        layer_1_status = 'NOT_ASSESSED'
        layer_1_method = Get-MacLayerMethodText -Layer 'L1'
        layer_1_details = $Reason
        layer_2_status = 'NOT_ASSESSED'
        layer_2_method = Get-MacLayerMethodText -Layer 'L2'
        layer_2_details = $Reason
        layer_3_status = 'NOT_ASSESSED'
        layer_3_method = Get-MacLayerMethodText -Layer 'L3'
        layer_3_details = 'Runtime evidence is collected only for runtime-scoped controls and bypass flags.'
        test_method = 'macOS Firefox evidence collection: bundle policies.json, org.mozilla.firefox preference domain, profile prefs.js/user.js and live process arguments.'
        rationale = 'A control that cannot produce local evidence must not carry a compliance statement.'
        remediation = 'Verify the control through the management console or an evidence source that is readable on this endpoint, then rerun the assessment.'
        reference = 'https://mozilla.github.io/policy-templates/'
        confidence = 'LOW'
        manual_required = $true
        status_reason = if ($AccessDenied) { 'evidence_access_denied' } else { 'evidence_not_collectable' }
        warning_note = $Reason
    }
}

function Get-MacFirefoxReferenceUrl {
    param([hashtable]$Mapping)

    if ($null -eq $Mapping) { return 'https://mozilla.github.io/policy-templates/' }
    if ([string]$Mapping.mode -eq 'PREF') {
        return "https://searchfox.org/mozilla-central/search?q=$([uri]::EscapeDataString([string]$Mapping.policy_key))"
    }
    return "https://mozilla.github.io/policy-templates/#$(([string]$Mapping.policy_key).ToLowerInvariant())"
}

function Invoke-MacFirefoxRuntimeControl {
    param([hashtable]$Cfg)

    $runtime = Get-MacFirefoxRuntimeEvidence
    $base = @{
        policy_key = [string]$Cfg.PolicyKey
        expected_value = 'Expected: CLEAN (no policy-neutralising runtime override)'
        expected_kind = 'enum'
        expected_machine_value = 'clean'
        evidence_type = 'runtime_process_flags'
        evidence_source_label = 'RUNTIME_PROCESS_ARGUMENTS'
        evidence_paths = @('/bin/ps -axo pid=,command=')
        evidence_provenance = @{ channel = 'RUNTIME'; scope = 'PROCESS'; source_path = '/bin/ps'; key_path = 'command line' }
        effective_channel = [string]$script:Provider.winner
        channel_conflict = $false
        layer_1_status = 'NOT_ASSESSED'
        layer_1_method = Get-MacLayerMethodText -Layer 'L1'
        layer_1_details = 'This control is runtime-scoped; neither policy channel carries evidence for it.'
        layer_2_status = 'NOT_ASSESSED'
        layer_2_method = Get-MacLayerMethodText -Layer 'L2'
        layer_2_details = 'This control is runtime-scoped; it has no preference equivalent.'
        layer_3_method = Get-MacLayerMethodText -Layer 'L3'
        test_method = 'Live process argument enumeration (/bin/ps) plus bypass flag pattern detection.'
        rationale = 'Switches such as --safe-mode, --marionette or --start-debugger-server disable policy enforcement or expose a remote control channel regardless of the deployed policy set.'
        remediation = 'Do not launch Firefox with bypass flags. Review login items, launch agents and management scripts that start Firefox, then rerun the assessment.'
        reference = 'https://firefox-source-docs.mozilla.org/testing/marionette/Intro.html'
        access_denied = $false
        access_denied_reason = ''
        not_assessed_reason = ''
        root_cause = ''
    }

    if (-not $runtime.running) {
        $reason = 'Firefox is not running, so runtime arguments could not be collected on this endpoint.'
        $result = New-MacNotAssessedResult -Cfg $Cfg -Reason $reason
        $result.evidence_type = 'runtime_process_flags'
        $result.layer_3_details = $reason
        return $result
    }

    if ($runtime.hits.Count -gt 0) {
        $observed = ($runtime.hits -join ', ')
        return ($base + @{
            status = 'FAILED'
            verdict = 'FAIL'
            enforced = $false
            message = "Bypass flags detected in live Firefox processes: $observed"
            details = "Live Firefox process arguments contain bypass flags: $observed"
            finding_details = "Bypass flags detected in $($runtime.process_count) live Firefox process argument set(s): $observed"
            observed_value = $observed
            evidence_output = "Bypass flags: $observed"
            layer_3_status = 'FAILED'
            layer_3_details = "Runtime override switches detected that can neutralise policy: $observed"
            confidence = 'HIGH'
            status_reason = 'expected_condition_not_met'
            manual_required = $false
            warning_note = ''
        })
    }

    return ($base + @{
        status = 'PASSED'
        verdict = 'PASS'
        enforced = $false
        message = 'No bypass flags detected in live Firefox processes'
        details = "No bypass flag found in $($runtime.process_count) live Firefox process argument set(s)."
        finding_details = 'Live Firefox processes are running without --safe-mode, --marionette, --start-debugger-server or similar policy-neutralising switches.'
        observed_value = 'No bypass flags present'
        evidence_output = 'No bypass flags present in live Firefox process arguments.'
        layer_3_status = 'PASSED'
        layer_3_details = 'No policy-neutralising command-line switch was found in the running browser.'
        confidence = 'MEDIUM'
        status_reason = 'expected_condition_met'
        manual_required = $false
        warning_note = ''
    })
}

function Invoke-MacFirefoxPolicyControl {
    param([hashtable]$Cfg)

    $mapping = $Cfg.Mapping
    $expectation = Resolve-MacFirefoxExpectation -Mapping $mapping
    $meta = Convert-MacExpectationToMachineMeta -Expectation $expectation

    if ([string]::IsNullOrWhiteSpace($expectation)) {
        return (New-MacNotAssessedResult -Cfg $Cfg -Reason "No machine-comparable expectation is defined for '$($Cfg.PolicyKey)', so the observed value could not be judged automatically.")
    }

    $layer1 = Get-MacFirefoxLayer1Evidence -Mapping $mapping
    $layer2 = Get-MacFirefoxLayer2Evidence -Mapping $mapping
    $matchedKey = if ([string]::IsNullOrWhiteSpace($layer1.matched_key)) { [string]$Cfg.PolicyKey } else { [string]$layer1.matched_key }
    $hasPrefEquivalent = -not [string]::IsNullOrWhiteSpace([string]$mapping.pref_name)

    $base = @{
        policy_key = [string]$Cfg.PolicyKey
        expected_value = "Expected: $expectation"
        expected_kind = $meta.kind
        expected_machine_value = $meta.value
        effective_channel = [string]$script:Provider.winner
        channel_conflict = [bool]$layer1.conflict
        layer_1_method = Get-MacLayerMethodText -Layer 'L1'
        layer_2_method = Get-MacLayerMethodText -Layer 'L2'
        layer_3_method = Get-MacLayerMethodText -Layer 'L3'
        layer_3_status = 'NOT_ASSESSED'
        layer_3_details = 'Runtime evidence is collected only for runtime-scoped controls and bypass flags.'
        test_method = "Control -> firefox_macos_policy_map.json -> '$matchedKey' resolved through the $($script:Provider.winner) provider, then compared against the profile prefs.js/user.js tier."
        rationale = "Firefox selects one policy provider per endpoint. $($script:Provider.reason)"
        remediation = if ($script:Provider.winner -eq 'PLIST') {
            "Deliver '$matchedKey' through an MDM configuration profile for the $($script:FirefoxDomain) domain so the value becomes enforced, then rerun the assessment."
        } else {
            "Deploy '$matchedKey' in the policies.json shipped with the Firefox application bundle, or enable the preference-domain provider and deliver it by MDM, then rerun the assessment."
        }
        reference = Get-MacFirefoxReferenceUrl -Mapping $mapping
        access_denied = $false
        access_denied_reason = ''
        not_assessed_reason = ''
        root_cause = ''
        confidence = 'MEDIUM'
    }

    # Tier 1 - the provider Firefox actually reads.
    if ($layer1.found) {
        $eval = Test-MacFirefoxExpectation -Value $layer1.value -Expectation $expectation
        $passed = ($eval.status -eq 'PASSED')
        $channelLabel = if ($layer1.channel -eq 'PLIST') { 'MANAGED_PREFERENCES_MDM_ENFORCED' } else { 'BUNDLE_POLICIES_JSON' }

        return ($base + @{
            status = if ($eval.status -eq 'UNKNOWN') { 'UNKNOWN' } else { $eval.status }
            verdict = if ($passed) { 'PASS' } elseif ($eval.status -eq 'UNKNOWN') { 'NOT_ASSESSED' } else { 'FAIL' }
            enforced = $true
            message = if ($passed) { "The enforced policy value matches the expected value. $($eval.message)" } elseif ($eval.status -eq 'UNKNOWN') { $eval.message } else { "The enforced policy value does not match the expected value. $($eval.message)" }
            details = "$($layer1.source_path) : $($layer1.key_path) = $($layer1.display)"
            finding_details = "'$matchedKey' is delivered through the $($layer1.channel) channel and evaluated as enforced evidence."
            observed_value = $layer1.display
            evidence_output = "$($layer1.key_path) = $($layer1.display) (source: $($layer1.source_path))"
            evidence_type = if ($layer1.channel -eq 'PLIST') { 'managed_preferences_plist' } else { 'policies_json' }
            evidence_source_label = $channelLabel
            evidence_paths = @($layer1.source_path)
            evidence_provenance = @{
                channel = [string]$layer1.channel
                scope = [string]$layer1.scope
                source_path = [string]$layer1.source_path
                key_path = [string]$layer1.key_path
                bundle_path = [string]$layer1.bundle_path
                bundle_version = [string]$layer1.bundle_version
                locked = [bool]$layer1.locked
            }
            layer_1_status = $eval.status
            layer_1_details = "$($layer1.source_path) : $($layer1.key_path) = $($layer1.display)"
            layer_2_status = 'NOT_ASSESSED'
            layer_2_details = 'An enforced policy value is present and overrides any profile-level value, so the user tier does not decide this control.'
            status_reason = Get-DefaultStatusReason -Status $eval.status
            manual_required = ($eval.status -eq 'UNKNOWN')
            warning_note = ''
        })
    }

    # Tier 2 - present but user-revertible.
    if ($layer2.found) {
        $eval = Test-MacFirefoxExpectation -Value $layer2.value -Expectation $expectation
        $satisfied = ($eval.status -eq 'PASSED')
        $profileNote = if ([string]::IsNullOrWhiteSpace($layer2.profile_name)) { '' } else { " Evidence profile: '$($layer2.profile_name)' ($($layer2.profile_path), default=$($layer2.profile_is_default), discovered via $($layer2.profile_source), file $($layer2.evidence_file))." }

        return ($base + @{
            # The runner status reports the L1 fact: no enforced policy is deployed.
            # The unenforced compliance is carried by verdict/layer_2_status so the
            # verification engine can arbitrate instead of inheriting a claim of
            # enforcement that was never observed.
            status = if ($eval.status -eq 'UNKNOWN') { 'UNKNOWN' } else { 'FAILED' }
            verdict = if ($satisfied) { 'PASS_NOT_ENFORCED' } elseif ($eval.status -eq 'UNKNOWN') { 'NOT_ASSESSED' } else { 'FAIL' }
            enforced = $false
            # The wording carries the L1 fact explicitly: Get-Layer1Evidence classifies
            # a missing enforced policy as ABSENT only when the collector says so.
            message = if ($satisfied) {
                "The enforced policy '$matchedKey' is not configured on this endpoint; the expected value is present only in a user-revertible source ($($layer2.source_label))."
            } else {
                "The enforced policy '$matchedKey' is not configured on this endpoint and the user-revertible value does not match the expectation. $($eval.message)"
            }
            details = "$($layer2.source_path) : $($layer2.matched_key) = $($layer2.display)"
            finding_details = "The value comes from a user-revertible source ($($layer2.source_label)) and can be changed without the management channel.$profileNote $($eval.message)"
            observed_value = $layer2.display
            evidence_output = "$($layer2.matched_key) = $($layer2.display) (source: $($layer2.source_path))"
            evidence_type = if ($layer2.scope -eq 'PROFILE') { 'preferences_file' } else { 'preferences_plist' }
            evidence_source_label = [string]$layer2.source_label
            evidence_paths = @($layer2.source_path)
            evidence_provenance = @{
                channel = if ($layer2.scope -eq 'PROFILE') { 'PROFILE_PREFS' } else { 'PLIST' }
                scope = [string]$layer2.scope
                source_path = [string]$layer2.source_path
                key_path = [string]$layer2.matched_key
                profile_name = [string]$layer2.profile_name
                profile_path = [string]$layer2.profile_path
                profile_is_default = [bool]$layer2.profile_is_default
                profile_source = [string]$layer2.profile_source
                evidence_file = [string]$layer2.evidence_file
            }
            layer_1_status = 'FAILED'
            layer_1_details = "'$matchedKey' is not configured in the $($script:Provider.winner) provider, so no enforced value exists for this control."
            layer_2_status = if ($satisfied) { 'PASS_NOT_ENFORCED' } else { 'FAILED' }
            layer_2_details = "$($layer2.source_path) : $($layer2.matched_key) = $($layer2.display).$profileNote"
            status_reason = if ($satisfied) { 'expected_condition_met_without_enforcement' } else { 'expected_condition_not_met' }
            manual_required = $true
            warning_note = 'The value was found outside the enforced policy channel; it is reported as an enforcement gap rather than as a compliant control.'
        })
    }

    # No value in any tier. An empty or unreadable profile tier is not evidence of
    # absence, so a control with a preference equivalent is not failed for it.
    if ($hasPrefEquivalent -and -not $script:ProfileStore.evidence_available) {
        $reason = 'No enforced policy value exists for this control and no Firefox profile on this endpoint contains a readable prefs.js or user.js, so the user-level state could not be observed.'
        $result = New-MacNotAssessedResult -Cfg $Cfg -Reason $reason -AccessDenied ([bool]$script:ProfileStore.access_denied) -EvidencePaths @($script:ProfileStore.denied_paths)
        $result.layer_1_status = 'FAILED'
        $result.layer_1_details = "'$matchedKey' is not configured in the $($script:Provider.winner) provider."
        $result.layer_2_details = $reason
        return $result
    }

    $conflictNote = [string]$layer1.conflict_note
    return ($base + @{
        status = 'FAILED'
        verdict = 'FAIL'
        enforced = $false
        message = "'$matchedKey' is not configured in any Firefox evidence tier on this endpoint."
        details = "Control: $(@($Cfg.CISControls) -join ', ') | Expected: $expectation | $matchedKey not found in the $($script:Provider.winner) provider, the user-revertible preference domains or any Firefox profile."
        finding_details = if ([string]::IsNullOrWhiteSpace($conflictNote)) {
            "'$matchedKey' was not found in the enforced policy channel or in any scanned Firefox profile."
        } else { $conflictNote }
        observed_value = '(not set)'
        evidence_output = "$matchedKey not found in any Firefox evidence tier."
        evidence_type = if ($script:Provider.winner -eq 'PLIST') { 'managed_preferences_plist' } else { 'policies_json' }
        evidence_source_label = 'NONE'
        evidence_paths = @($script:ProfileStore.profiles | ForEach-Object { $_.path })
        evidence_provenance = @{
            channel = [string]$script:Provider.winner
            scope = ''
            source_path = ''
            key_path = $matchedKey
            profiles_scanned = @($script:ProfileStore.profiles | ForEach-Object { $_.name })
        }
        layer_1_status = 'FAILED'
        layer_1_details = "'$matchedKey' is not configured in the $($script:Provider.winner) provider."
        layer_2_status = 'FAILED'
        layer_2_details = "'$matchedKey' is not configured in the user-revertible preference domains or in any of the $(@($script:ProfileStore.profiles).Count) scanned Firefox profile(s)."
        status_reason = 'expected_condition_not_met'
        manual_required = $false
        warning_note = $conflictNote
    })
}

function Invoke-MacFirefoxControl {
    param([hashtable]$Cfg)

    if (-not $script:IsMacHost) {
        return (New-MacNotAssessedResult -Cfg $Cfg -Reason 'This runner collects evidence only on macOS, so the control could not be verified on this host.')
    }
    if (-not $script:BundleStore.installed) {
        return (New-MacNotAssessedResult -Cfg $Cfg -Reason 'Mozilla Firefox is not installed on this endpoint, so the control could not be verified locally.')
    }

    $mapping = $Cfg.Mapping
    if ($null -eq $mapping) {
        return (New-MacNotAssessedResult -Cfg $Cfg -Reason "No mapping is defined for this control in firefox_macos_policy_map.json, so it could not be verified on macOS.")
    }
    if (-not $mapping.macos_supported) {
        return (New-MacNotAssessedResult -Cfg $Cfg -Reason "This control could not be verified on macOS: $($mapping.unsupported_reason)")
    }
    if ($mapping.mode -eq 'RUNTIME') {
        return (Invoke-MacFirefoxRuntimeControl -Cfg $Cfg)
    }
    if ($mapping.mode -notin @('POLICY', 'PREF')) {
        return (New-MacNotAssessedResult -Cfg $Cfg -Reason "The macOS map marks this control as $($mapping.mode), so no automated policy check could be performed.")
    }

    if (-not $script:Provider.resolved) {
        return (New-MacNotAssessedResult -Cfg $Cfg -Reason $script:Provider.reason -AccessDenied $true `
            -EvidencePaths @($script:Provider.denied_paths) -RootCause ([string]$script:Provider.root_cause))
    }

    if ($script:Provider.winner -eq 'POLICIES_JSON' -and $script:BundleStore.access_denied) {
        return (New-MacNotAssessedResult -Cfg $Cfg `
            -Reason "The policies.json inside the Firefox application bundle could not be read ($($script:BundleStore.denied_paths -join ', ')). Unreadable evidence cannot establish that a policy is absent." `
            -AccessDenied $true -EvidencePaths @($script:BundleStore.denied_paths) -RootCause 'RC_TCC_PERMISSION_MISSING')
    }

    return (Invoke-MacFirefoxPolicyControl -Cfg $Cfg)
}

# ---------------------------------------------------------------------------
# Manual verification guidance
# ---------------------------------------------------------------------------

function Get-MacFirefoxManualGuidance {
    param(
        [hashtable]$Cfg,
        [hashtable]$Result
    )

    $name = [string]$Cfg.Name
    $policyKey = [string]$Cfg.PolicyKey
    $status = [string]$Result.status
    $isRuntime = ($null -ne $Cfg.Mapping -and [string]$Cfg.Mapping.mode -eq 'RUNTIME')

    $check = 'Validate the Firefox policy value and the resulting behaviour together on macOS.'
    $steps = @(
        'Open about:policies and confirm the control appears under Active policies.',
        "Run: defaults read $($script:FirefoxDomain) $policyKey",
        'Run: sudo profiles show -type configuration to confirm the value arrives from a configuration profile.',
        'If the value only exists in a profile prefs.js or user.js, treat the control as an enforcement gap, not as compliant.'
    )
    $command = "/usr/bin/defaults read $($script:FirefoxDomain) $policyKey"
    $expected = 'The value must be delivered by the enforced policy channel and be observable in about:policies.'

    if ($isRuntime) {
        $check = 'Validate how Firefox is launched and whether bypass flags are present.'
        $steps = @(
            'Run: ps -axo pid=,command= | grep -i firefox',
            'Review login items, launch agents and management scripts that start Firefox.',
            'Confirm no --safe-mode, --marionette, --start-debugger-server or --remote-debugging-port switch is used.'
        )
        $command = 'ps -axo pid=,command= | grep -i firefox'
        $expected = 'Firefox must run without any policy-neutralising command-line switch.'
    }
    elseif ($name -match 'Private') {
        $check = 'Validate the private browsing restriction with policy and behavioural checks.'
        $steps = @(
            'Check DisablePrivateBrowsing on about:policies.',
            'Try opening a private window with Shift+Cmd+P.',
            'Record PASS only if the window is blocked or a policy notice is shown.'
        )
        $expected = 'Private browsing must be restricted according to enterprise policy.'
    }
    elseif ($name -match 'Extension') {
        $check = 'Validate extension governance through policy and an install attempt.'
        $steps = @(
            'Check ExtensionSettings on about:policies.',
            'Try installing a test add-on through about:addons.',
            'Record PASS only if unauthorized installation is blocked.'
        )
        $expected = 'Unauthorized extension installation must be blocked by managed policy.'
    }
    elseif ($name -match 'Password') {
        $check = 'Validate the password manager restriction via policy and settings.'
        $steps = @(
            'Check PasswordManagerEnabled on about:policies.',
            'Review Settings > Privacy & Security > Logins and Passwords.',
            'Record PASS only if password saving is disabled and managed.'
        )
        $expected = 'The password manager must follow the corporate policy.'
    }
    elseif ($name -match 'Developer|Debug') {
        $check = 'Validate developer and debug restrictions via policy and shortcut behaviour.'
        $steps = @(
            'Check DisableDeveloperTools or the related preference on about:policies and about:config.',
            'Try opening DevTools with Option+Cmd+I.',
            'Record PASS only if the tooling is blocked or restricted.'
        )
        $expected = 'Developer and debug features must be restricted according to enterprise policy.'
    }
    elseif ($name -match 'Proxy|DNS|HTTPS|TLS|Certificate|OCSP') {
        $check = 'Validate the network and transport security settings through policy and settings.'
        $steps = @(
            'Review the related value on about:policies and about:config.',
            'Review proxy and DNS behaviour in Settings > Network Settings.',
            'Record PASS only if the observed behaviour matches the enterprise expectation.'
        )
        $expected = 'Proxy, DNS and TLS behaviour must comply with the enterprise security policy.'
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

function Get-MacFirefoxIncidentScenario {
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

    return "$statePrefix Incident scenario ($TestName): a threat actor can target the weakness this control covers; on macOS a value that lives only in a Firefox profile can also be changed by any local process running as the user.$expectedNote$observedNote"
}

# ---------------------------------------------------------------------------
# Result payload
# ---------------------------------------------------------------------------

function New-MacFirefoxResultPayload {
    param(
        [string]$Id,
        [hashtable]$Cfg,
        [hashtable]$Result
    )

    $mapping = $Cfg.Mapping
    $mode = if ($null -eq $mapping) { 'MANUAL' } else { [string]$mapping.mode }
    $manual = Get-MacFirefoxManualGuidance -Cfg $Cfg -Result $Result

    $verifiedVia = if ($mode -eq 'RUNTIME') {
        'Process Command Line (Live), macOS runtime'
    } else {
        'policies.json, Managed Preferences Policy (MDM), Firefox profile prefs.js/user.js'
    }

    $expectedValue = Get-ResultFieldOrFallback -Result $Result -FieldName 'expected_value' -FallbackValue $manual.manual_check_expected
    $observedValue = Get-ResultFieldOrFallback -Result $Result -FieldName 'observed_value' -FallbackValue ''
    $evidenceOutput = Get-ResultFieldOrFallback -Result $Result -FieldName 'evidence_output' `
        -FallbackValue (Get-ResultFieldOrFallback -Result $Result -FieldName 'details' -FallbackValue (Get-ResultField -Result $Result -FieldName 'message' -DefaultValue ''))

    $firstControl = if (@($Cfg.CISControls).Count -gt 0) { @($Cfg.CISControls)[0] } else { '' }
    $testMethod = Get-ResultFieldOrFallback -Result $Result -FieldName 'test_method' `
        -FallbackValue "Firefox macOS control $firstControl - policy map driven evidence collection via $verifiedVia"
    $rationale = Get-ResultFieldOrFallback -Result $Result -FieldName 'rationale' `
        -FallbackValue "Firefox control $($firstControl): '$($Cfg.Name)' must comply with the enterprise security policy."

    $payload = @{
        test_id = $Id
        test_name = $Cfg.Name
        package_id = $Cfg.Package
        severity = $Cfg.Severity
        cis_controls = @($Cfg.CISControls)
        policy_key = Get-ResultFieldOrFallback -Result $Result -FieldName 'policy_key' -FallbackValue ([string]$Cfg.PolicyKey)
        policy_mapping = if ($mode -eq 'RUNTIME') { 'OBSERVATIONAL' } else { $mode }
        preference_domain = $script:FirefoxDomain
        macos_supported = if ($null -eq $mapping) { $false } else { [bool]$mapping.macos_supported }
        platform = 'macOS'
        verified_via = $verifiedVia
        status = $Result.status
        message = Get-ResultField -Result $Result -FieldName 'message' -DefaultValue ''
        # Named runner_verdict, not verdict: apply_verification.ps1 writes its own
        # 'verdict' property and would otherwise overwrite the collector's finding.
        runner_verdict = Get-ResultField -Result $Result -FieldName 'verdict' -DefaultValue $Result.status
        enforced = [bool](Get-ResultField -Result $Result -FieldName 'enforced' -DefaultValue $false)
        details = Get-ResultField -Result $Result -FieldName 'details' -DefaultValue ''
        finding_details = Get-ResultFieldOrFallback -Result $Result -FieldName 'finding_details' -FallbackValue (Get-ResultField -Result $Result -FieldName 'message' -DefaultValue '')
        test_method = $testMethod
        rationale = $rationale
        effective_channel = Get-ResultField -Result $Result -FieldName 'effective_channel' -DefaultValue ([string]$script:Provider.winner)
        channel_conflict = [bool](Get-ResultField -Result $Result -FieldName 'channel_conflict' -DefaultValue $false)
        layer_1_status = Get-ResultField -Result $Result -FieldName 'layer_1_status' -DefaultValue ''
        layer_1_method = Get-ResultField -Result $Result -FieldName 'layer_1_method' -DefaultValue ''
        layer_1_details = Get-ResultField -Result $Result -FieldName 'layer_1_details' -DefaultValue ''
        layer_2_status = Get-ResultField -Result $Result -FieldName 'layer_2_status' -DefaultValue ''
        layer_2_method = Get-ResultField -Result $Result -FieldName 'layer_2_method' -DefaultValue ''
        layer_2_details = Get-ResultField -Result $Result -FieldName 'layer_2_details' -DefaultValue ''
        layer_3_status = Get-ResultField -Result $Result -FieldName 'layer_3_status' -DefaultValue ''
        layer_3_method = Get-ResultField -Result $Result -FieldName 'layer_3_method' -DefaultValue ''
        layer_3_details = Get-ResultField -Result $Result -FieldName 'layer_3_details' -DefaultValue ''
        remediation = Get-ResultField -Result $Result -FieldName 'remediation' -DefaultValue ''
        reference = Get-ResultFieldOrFallback -Result $Result -FieldName 'reference' -FallbackValue 'https://mozilla.github.io/policy-templates/'
        intune_reference_url = if (-not [string]::IsNullOrWhiteSpace([string]$Cfg.IntuneReferenceUrl)) { [string]$Cfg.IntuneReferenceUrl } else { 'https://learn.microsoft.com/en-us/intune/intune-service/configuration/preference-file-settings-macos' }
        manageengine_reference_url = if (-not [string]::IsNullOrWhiteSpace([string]$Cfg.ManageEngineReferenceUrl)) { [string]$Cfg.ManageEngineReferenceUrl } else { 'https://www.manageengine.com/mobile-device-management/help/mac_management/mdm_mac_custom_configuration.html' }
        warning_note = Get-ResultField -Result $Result -FieldName 'warning_note' -DefaultValue ''
        expected_value = $expectedValue
        expected_kind = Get-ResultField -Result $Result -FieldName 'expected_kind' -DefaultValue ''
        expected_machine_value = Get-ResultField -Result $Result -FieldName 'expected_machine_value' -DefaultValue ''
        observed_value = $observedValue
        evidence_output = $evidenceOutput
        evidence_type = Get-ResultFieldOrFallback -Result $Result -FieldName 'evidence_type' -FallbackValue 'result_snapshot'
        evidence_source_label = Get-ResultFieldOrFallback -Result $Result -FieldName 'evidence_source_label' -FallbackValue 'NONE'
        evidence_paths = @(Get-ResultField -Result $Result -FieldName 'evidence_paths' -DefaultValue @())
        evidence_provenance = Get-ResultField -Result $Result -FieldName 'evidence_provenance' -DefaultValue @{}
        access_denied = [bool](Get-ResultField -Result $Result -FieldName 'access_denied' -DefaultValue $false)
        access_denied_reason = [string](Get-ResultField -Result $Result -FieldName 'access_denied_reason' -DefaultValue '')
        not_assessed_reason = [string](Get-ResultField -Result $Result -FieldName 'not_assessed_reason' -DefaultValue '')
        root_cause = [string](Get-ResultField -Result $Result -FieldName 'root_cause' -DefaultValue '')
        confidence = Get-ResultFieldOrFallback -Result $Result -FieldName 'confidence' -FallbackValue 'MEDIUM'
        status_reason = Get-ResultFieldOrFallback -Result $Result -FieldName 'status_reason' -FallbackValue (Get-DefaultStatusReason -Status $Result.status)
        manual_required = [bool](Get-ResultField -Result $Result -FieldName 'manual_required' -DefaultValue ($Result.status -in @('UNKNOWN', 'NOT_ASSESSED')))
        manual_check = $manual.manual_check
        manual_check_steps = $manual.manual_check_steps
        manual_check_command = $manual.manual_check_command
        manual_check_expected = $manual.manual_check_expected
        manual_check_note = $manual.manual_check_note
        retest_command = "./firefox_macos_test_runner.ps1 -TestId $Id"
        timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }

    $payload.incident_scenario = Get-MacFirefoxIncidentScenario -TestName ([string]$Cfg.Name) `
        -Verdict ([string]$payload.runner_verdict) -ExpectedValue ([string]$payload.expected_value) -ObservedValue ([string]$payload.observed_value)

    return (Add-ArtifactMetadata -Payload $payload)
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

$script:PolicyMap = Get-MacFirefoxPolicyMap
$script:FirefoxDomain = if ([string]::IsNullOrWhiteSpace($script:PolicyMap.preference_domain)) { 'org.mozilla.firefox' } else { $script:PolicyMap.preference_domain }

$script:PlistStores = @{
    MANAGED = Initialize-MacPreferenceStore -Scope 'MANAGED'
    SYSTEM  = Initialize-MacPreferenceStore -Scope 'SYSTEM'
    USER    = Initialize-MacPreferenceStore -Scope 'USER'
}
$script:ManagedStore = $script:PlistStores['MANAGED']
$script:BundleStore = Initialize-MacFirefoxBundleStore
$script:ProfileStore = Initialize-MacFirefoxProfileStore
$script:Provider = Resolve-MacFirefoxProvider

$TestMap = @{}
$baseTests = Get-MacFirefoxBaseTestMap
$cisTests = Get-MacFirefoxCisTestsFromCatalog
$baseTests.Keys | Sort-Object | ForEach-Object { $TestMap[$_] = $baseTests[$_] }
$cisTests.Keys | Sort-Object | ForEach-Object { $TestMap[$_] = $cisTests[$_] }

if ($TestId -eq "ALL") {
    $TestMap.Keys | Sort-Object | ForEach-Object {
        $cfg = $TestMap[$_]
        $script:TestResults += (New-MacFirefoxResultPayload -Id $_ -Cfg $cfg -Result (Invoke-MacFirefoxControl -Cfg $cfg))
    }
} else {
    if (-not $TestMap.ContainsKey($TestId)) {
        Write-Host "ERROR: Unknown test ID: $TestId" -ForegroundColor Red
        exit 1
    }
    $cfg = $TestMap[$TestId]
    $script:TestResults += (New-MacFirefoxResultPayload -Id $TestId -Cfg $cfg -Result (Invoke-MacFirefoxControl -Cfg $cfg))
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

    $profilesReport = @($script:ProfileStore.profiles | ForEach-Object {
        @{
            name = $_.name
            path = $_.path
            is_default = $_.is_default
            source = $_.source
            evidence_files = @($_.evidence_files)
        }
    })
    $evidenceProfiles = @($script:TestResults |
        ForEach-Object { [string]$_.evidence_provenance.profile_name } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique)

    $report = @{
        organization = "Corporate Security"
        browser = "Mozilla Firefox"
        platform = "macOS"
        test_date = (Get-Date -Format "yyyy-MM-dd")
        test_time = (Get-Date -Format "HH:mm:ss")
        environment = @{
            hostname = [Environment]::MachineName
            platform = if ($script:IsMacHost) { 'macOS' } else { [string][System.Runtime.InteropServices.RuntimeInformation]::OSDescription }
            os_version = [string][System.Environment]::OSVersion.Version
            browser_versions = @{
                firefox = if (@($script:BundleStore.bundles).Count -gt 0) { [string]@($script:BundleStore.bundles)[0].version } elseif ($script:BundleStore.access_denied) { 'ACCESS_DENIED' } else { 'NOT_FOUND' }
            }
            evidence_sources = @{
                managed_preferences = $script:ManagedPreferencesRoot
                system_preferences = $script:SystemPreferencesRoot
                user_preferences = $script:UserPreferencesRoot
                preference_domain = $script:FirefoxDomain
                policy_map = $script:PolicyMap.path
            }
        }
        evidence_scope = @{
            firefox_installed = $script:BundleStore.installed
            bundles_scanned = @($script:BundleStore.bundles | ForEach-Object {
                @{ path = $_.path; version = $_.version; policies_json_path = $_.policies_json_path; policies_json_state = $_.policies_json_state }
            })
            bundles_unreadable = @($script:BundleStore.denied_paths)
            effective_channel = $script:Provider.winner
            channel_gate = @{
                key = $script:Provider.gate_key
                found = $script:Provider.gate_found
                value = $script:Provider.gate_value
                scope = $script:Provider.gate_scope
                source_path = $script:Provider.gate_source_path
                reason = $script:Provider.reason
            }
            managed_preferences_readable = (-not $script:ManagedStore.access_denied)
            managed_preferences_denied_paths = @($script:ManagedStore.denied_paths)
            profiles_ini_paths = @($script:ProfileStore.profiles_ini_paths)
            profiles_scanned = $profilesReport
            profiles_unreadable = @($script:ProfileStore.denied_paths)
            profile_evidence_available = $script:ProfileStore.evidence_available
            profiles_that_produced_evidence = $evidenceProfiles
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
        @{ Label = "PROFILE"; Expression = { [string]$_.evidence_provenance.profile_name }; Width = 18 },
        @{ Label = "MESSAGE"; Expression = { $_.finding_details }; Width = 40 }
    )
}
