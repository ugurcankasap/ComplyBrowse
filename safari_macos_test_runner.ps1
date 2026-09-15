# Safari macOS evidence collector.
# Safari has no vendor enterprise policy file or independent Safari CIS benchmark.
param(
    [string]$TestId = 'ALL',
    [switch]$OutputJSON = $false,
    [string]$OutputFile = ''
)

$ErrorActionPreference = 'Stop'
$script:TestResults = @()
$script:RunId = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:MapPath = Join-Path $PSScriptRoot 'safari_macos_policy_map.json'
$script:CatalogPath = Join-Path $PSScriptRoot 'safari_controls.txt'
$script:IsMacHost = ($PSVersionTable.PSVersion.Major -ge 6) -and [bool]$IsMacOS
$script:ManagedRoot = '/Library/Managed Preferences'
$script:UserHome = [Environment]::GetFolderPath('UserProfile')
if ([string]::IsNullOrWhiteSpace($script:UserHome)) { $script:UserHome = "$HOME" }
$script:UserPreferenceRoot = Join-Path $script:UserHome 'Library/Containers/com.apple.Safari/Data/Library/Preferences'
$script:SafariRoot = Join-Path $script:UserHome 'Library/Safari'

$helper = Join-Path $PSScriptRoot 'macos_evidence.ps1'
if (-not (Test-Path -LiteralPath $helper)) { throw "macOS evidence helper not found: $helper" }
. $helper

function Get-SafariMap {
    if (-not (Test-Path -LiteralPath $script:MapPath)) { throw "Safari macOS policy map not found: $script:MapPath" }
    try { return (Get-Content -LiteralPath $script:MapPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop) }
    catch { throw "Safari macOS policy map is not valid JSON: $script:MapPath. $($_.Exception.Message)" }
}

function Get-SafariCatalog {
    if (-not (Test-Path -LiteralPath $script:CatalogPath)) { throw "Safari control catalog not found: $script:CatalogPath" }
    $entries = @()
    foreach ($line in (Get-Content -LiteralPath $script:CatalogPath -Encoding UTF8)) {
        $text = ([string]$line).Trim()
        if ([string]::IsNullOrWhiteSpace($text) -or $text.StartsWith('#')) { continue }
        $parts = $text -split '\|', 6
        if ($parts.Count -ne 6) { throw "Safari control catalog contains an invalid line: $text" }
        $entries += [ordered]@{
            control_id = $parts[0]; name = $parts[1]; policy_key = $parts[2]
            expected_text = $parts[3]; macos_supported = ($parts[4] -eq 'true'); notes = $parts[5]
        }
    }
    if ($entries.Count -eq 0) { throw "Safari control catalog contains no controls: $script:CatalogPath" }
    return @($entries)
}

function Get-SafariAccessState {
    $state = @{ access_denied = $false; readable = $false; managed_readable = $false; user_readable = $false; managed_access_denied = $false; user_access_denied = $false; denied_paths = @(); checked_paths = @() }
    foreach ($path in @($script:UserPreferenceRoot, $script:SafariRoot)) {
        $state.checked_paths += $path
        $access = Test-MacReadAccess -Path $path
        if ($access.access_denied) { $state.user_access_denied = $true; $state.denied_paths += $path }
        if ($access.readable) { $state.user_readable = $true; $state.readable = $true }
    }
    $managed = Test-MacReadAccess -Path $script:ManagedRoot
    if ($managed.access_denied) { $state.managed_access_denied = $true; $state.denied_paths += $script:ManagedRoot }
    if ($managed.readable) { $state.managed_readable = $true; $state.readable = $true }
    $state.access_denied = $state.managed_access_denied -or $state.user_access_denied
    return $state
}

function Get-SafariDocuments {
    param([ValidateSet('Managed','User')][string]$Scope)
    $paths = if ($Scope -eq 'Managed') {
        @((Join-Path $script:ManagedRoot 'com.apple.Safari.plist')) + @(
            Get-ChildItem -LiteralPath $script:ManagedRoot -Filter '*.plist' -File -Recurse -Force -ErrorAction SilentlyContinue |
                ForEach-Object { $_.FullName }
        )
    } else {
        @((Join-Path $script:UserPreferenceRoot 'com.apple.Safari.plist')) + @(
            Get-ChildItem -LiteralPath $script:SafariRoot -Filter '*.plist' -File -Recurse -Force -ErrorAction SilentlyContinue |
                ForEach-Object { $_.FullName }
        )
    }

    $documents = @()
    foreach ($path in ($paths | Select-Object -Unique)) {
        $access = Test-MacReadAccess -Path $path
        if (-not $access.exists -or -not $access.readable) { continue }
        $document = ConvertFrom-MacPlistJson -Path $path
        if ($document.state -eq 'read') { $documents += @{ path = $path; value = $document.value } }
    }
    return @($documents)
}

function Get-SafariValue {
    param([object[]]$Documents, [string]$Key)
    foreach ($document in @($Documents)) {
        if ($Key -eq 'com.apple.Safari' -and [System.IO.Path]::GetFileName([string]$document.path) -ieq 'com.apple.Safari.plist') {
            return @{ found = $true; value = $document.value; path = $document.path }
        }
        $property = $document.value.PSObject.Properties | Where-Object { $_.Name -ieq $Key } | Select-Object -First 1
        if ($null -ne $property) { return @{ found = $true; value = $property.Value; path = $document.path } }
    }
    return @{ found = $false; value = $null; path = '' }
}

function ConvertTo-SafariDisplayValue {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { return if ($Value) { 'true' } else { 'false' } }
    if ($Value -is [array] -or $Value -is [pscustomobject] -or $Value -is [hashtable]) { return 'configured' }
    return [string]$Value
}

function Test-SafariExpected {
    param([object]$Value, [string]$ExpectedText, [string]$ValueType)
    if ($ValueType -eq 'presence') { return $true }
    if ($ExpectedText -eq '') { return $true }
    $expected = [bool]::Parse($ExpectedText)
    return ([bool]$Value -eq $expected)
}

function New-SafariNotAssessed {
    param([object]$Control, [string]$Reason, [string]$RootCause = '', [bool]$AccessDenied = $false)
    return [ordered]@{
        test_id = [string]$Control.control_id; test_name = [string]$Control.name; browser = 'Safari'; platform = 'macOS'
        control_id = [string]$Control.control_id; status = 'NOT_ASSESSED'; verdict = 'NOT_ASSESSED'; enforced = $false
        expected_value = [string]$Control.expected_text; observed_value = '(not assessed)'; evidence_type = 'not_assessed'
        evidence_source_label = 'NONE'; evidence_paths = @(); access_denied = $AccessDenied
        root_cause = $RootCause; not_assessed_reason = $Reason; counts_in_score = $false
        layer_1_status = 'NOT_ASSESSED'; layer_2_status = 'NOT_ASSESSED'; layer_3_status = 'NOT_ASSESSED'
        l3_arbiter = $false; message = $Reason; reference_basis = 'CIS Apple macOS Benchmark'
    }
}

function Invoke-SafariControl {
    param([object]$Control, [object[]]$ManagedDocuments, [object[]]$UserDocuments, [hashtable]$Access)
    if (-not $script:IsMacHost) { return New-SafariNotAssessed $Control 'Safari macOS collection is only available on macOS.' }
    if (-not $Control.macos_supported) {
        return New-SafariNotAssessed $Control ([string]$Control.unsupported_reason) 'UNSUPPORTED_PLATFORM_CONTROL'
    }
    if ($Access.managed_access_denied -and -not $Access.user_readable) {
        return New-SafariNotAssessed $Control 'Safari preference paths are unreadable under macOS TCC. Full Disk Access is required.' 'RC_TCC_PERMISSION_MISSING' $true
    }

    $managed = Get-SafariValue -Documents $ManagedDocuments -Key ([string]$Control.policy_key)
    $user = Get-SafariValue -Documents $UserDocuments -Key ([string]$Control.policy_key)
    if ($Control.control_id -eq 'SAF-009') { $managed = Get-SafariValue -Documents $ManagedDocuments -Key 'com.apple.Safari' }

    if ($managed.found) {
        $passed = Test-SafariExpected $managed.value ([string]$Control.expected_text) ([string]$Control.value_type)
        return [ordered]@{
            test_id = [string]$Control.control_id; test_name = [string]$Control.name; browser = 'Safari'; platform = 'macOS'; control_id = [string]$Control.control_id
            status = if ($passed) { 'PASSED' } else { 'FAILED' }; verdict = if ($passed) { 'PASS' } else { 'FAIL' }; enforced = $true
            expected_value = [string]$Control.expected_text; observed_value = ConvertTo-SafariDisplayValue $managed.value; evidence_type = 'managed_preferences_plist'
            evidence_source_label = 'MANAGED_PREFERENCES_MDM_ENFORCED'; evidence_paths = @($managed.path); access_denied = $false; root_cause = ''
            counts_in_score = $true; layer_1_status = if ($passed) { 'PASSED' } else { 'FAILED' }; layer_2_status = 'NOT_ASSESSED'; layer_3_status = 'NOT_ASSESSED'; l3_arbiter = $false
            message = 'Managed Safari preference was compared.'; reference_basis = 'CIS Apple macOS Benchmark'
        }
    }
    if ($Access.user_access_denied) {
        return New-SafariNotAssessed $Control 'Safari managed evidence was absent, but user preference paths are unreadable under macOS TCC. Full Disk Access is required to assess the user layer.' 'RC_TCC_PERMISSION_MISSING' $true
    }
    if ($user.found) {
        $passed = Test-SafariExpected $user.value ([string]$Control.expected_text) ([string]$Control.value_type)
        return [ordered]@{
            test_id = [string]$Control.control_id; test_name = [string]$Control.name; browser = 'Safari'; platform = 'macOS'; control_id = [string]$Control.control_id
            status = 'FAILED'; verdict = if ($passed) { 'PASS_NOT_ENFORCED' } else { 'FAIL' }; enforced = $false
            expected_value = [string]$Control.expected_text; observed_value = ConvertTo-SafariDisplayValue $user.value; evidence_type = 'user_safari_preference'
            evidence_source_label = 'USER_SAFARI_SANDBOX_PREFERENCE'; evidence_paths = @($user.path); access_denied = $false; root_cause = ''
            counts_in_score = $true; layer_1_status = 'FAILED'; layer_2_status = if ($passed) { 'PASS_NOT_ENFORCED' } else { 'FAILED' }; layer_3_status = 'NOT_ASSESSED'; l3_arbiter = $false
            message = 'Safari user preference was compared; it is not enforced.'; reference_basis = 'CIS Apple macOS Benchmark'
        }
    }
    return New-SafariNotAssessed $Control 'No comparable Safari preference value was found in readable managed or user evidence.' 'EVIDENCE_NOT_FOUND'
}

$map = Get-SafariMap
$catalog = Get-SafariCatalog
$mapById = @{}
foreach ($control in @($map.controls)) { $mapById[[string]$control.control_id] = $control }
$access = Get-SafariAccessState
$managedDocuments = if ($script:IsMacHost) { Get-SafariDocuments -Scope Managed } else { @() }
$userDocuments = if ($script:IsMacHost) { Get-SafariDocuments -Scope User } else { @() }

foreach ($catalogItem in $catalog) {
    if ($TestId -ne 'ALL' -and $TestId -ne $catalogItem.control_id) { continue }
    $mapping = $mapById[[string]$catalogItem.control_id]
    if ($null -eq $mapping) { throw "Safari catalog control is absent from policy map: $($catalogItem.control_id)" }
    $mapping | Add-Member -NotePropertyName 'expected_text' -NotePropertyValue ([string]$catalogItem.expected_text) -Force
    $mapping | Add-Member -NotePropertyName 'name' -NotePropertyValue ([string]$catalogItem.name) -Force
    $script:TestResults += Invoke-SafariControl -Control $mapping -ManagedDocuments $managedDocuments -UserDocuments $userDocuments -Access $access
}

$results = @($script:TestResults)
$summary = [ordered]@{
    total_tests = $results.Count
    pass = @($results | Where-Object { $_.verdict -eq 'PASS' }).Count
    pass_not_enforced = @($results | Where-Object { $_.verdict -eq 'PASS_NOT_ENFORCED' }).Count
    fail = @($results | Where-Object { $_.verdict -eq 'FAIL' }).Count
    not_assessed = @($results | Where-Object { $_.verdict -eq 'NOT_ASSESSED' }).Count
}
$summary.compliance_score_percent = if (($summary.pass + $summary.pass_not_enforced + $summary.fail) -gt 0) { [math]::Round(($summary.pass / ($summary.pass + $summary.pass_not_enforced + $summary.fail)) * 100, 1) } else { 0 }
$json = [ordered]@{
    schema_version = '1.0'; browser = 'Safari'; platform = 'macOS'; reference_basis = 'CIS Apple macOS Benchmark'
    l3_arbiter = $false; results = $results; summary = $summary; verification_summary = $summary
}
if ($OutputJSON) {
    if ([string]::IsNullOrWhiteSpace($OutputFile)) { $json | ConvertTo-Json -Depth 12 }
    else { $json | ConvertTo-Json -Depth 12 | Out-File -FilePath $OutputFile -Encoding UTF8 }
}
else {
    $results | Format-Table test_id, verdict, evidence_type, root_cause
}
