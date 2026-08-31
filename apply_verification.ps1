<#
Applies the value-based verification engine to a browser test-result file.

Output verdicts: PASS | PASS_NOT_ENFORCED | FAIL | NOT_ASSESSED
Compliance score counts PASS only. PASS_NOT_ENFORCED is reported as a separate
enforcement-gap metric. NOT_ASSESSED is excluded from the score entirely.
#>

param(
    [Parameter(Mandatory = $true)][string]$InputFile,
    [Parameter(Mandatory = $true)][ValidateSet('Edge', 'Chrome', 'Firefox')][string]$Browser,
    [string]$OutputFile
)

. "$PSScriptRoot\verify_value_based.ps1"
. "$PSScriptRoot\management_channel.ps1"

function Import-PolicyMap {
    param([string]$Browser)

    $mapFile = switch ($Browser) {
        'Edge'    { 'edge_cis_policy_map.json' }
        'Chrome'  { 'chrome_cis_policy_map.json' }
        'Firefox' { 'firefox_cis_policy_map.json' }
        default   { $null }
    }

    $lookup = @{}
    if (-not $mapFile) { return $lookup }

    $path = Join-Path $PSScriptRoot $mapFile
    if (-not (Test-Path $path)) { return $lookup }

    foreach ($entry in (Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json)) {
        if ($entry.control_id -and $entry.policy_key) {
            $lookup[[string]$entry.control_id] = [string]$entry.policy_key
        }
    }
    return $lookup
}

function Import-PolicyAliasMap {
    <#
      Some controls are satisfiable through more than one policy key (for example
      an extension blocklist or an equivalent ExtensionSettings declaration).
      Provenance lookup has to try the aliases too, otherwise a control that is
      genuinely enforced is reported as having no managed evidence.
    #>
    param([string]$Browser)

    $mapFile = switch ($Browser) {
        'Edge'    { 'edge_cis_policy_map.json' }
        'Chrome'  { 'chrome_cis_policy_map.json' }
        'Firefox' { 'firefox_cis_policy_map.json' }
        default   { $null }
    }

    $lookup = @{}
    if (-not $mapFile) { return $lookup }

    $path = Join-Path $PSScriptRoot $mapFile
    if (-not (Test-Path $path)) { return $lookup }

    foreach ($entry in (Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json)) {
        $aliases = @($entry.equivalent_policy_keys | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        if ($entry.policy_key -and $aliases.Count -gt 0) {
            $lookup[[string]$entry.policy_key] = @($aliases | ForEach-Object { [string]$_ })
        }
    }
    return $lookup
}

function Resolve-PolicyKey {
    <#
      Resolves the real policy key for a test and records HOW it was resolved.
      Splitting the test_id was previously used for this and produced meaningless
      keys such as "1" or "10".

      The trailing text-scan branches are heuristics: they pick an identifier out
      of prose and can attach the wrong key to a control. They are kept because
      they still help remediation guidance, but they are tagged INFERRED_FROM_TEXT
      so that no downstream consumer presents them as a verified mapping.
    #>
    param([psobject]$Test, [hashtable]$PolicyMap)

    $existingPolicyKey = [string]$Test.policy_key
    if (-not [string]::IsNullOrWhiteSpace($existingPolicyKey)) {
        return @{ key = $existingPolicyKey; source = 'RUNNER_DECLARED'; trusted = $true }
    }

    # A runner can declare that a control is intentionally not policy-mapped, which
    # stops the prose heuristics below from attaching an invented key to it.
    if ([string]$Test.policy_mapping -eq 'OBSERVATIONAL') {
        return @{ key = ''; source = 'RUNNER_DECLARED_OBSERVATIONAL'; trusted = $false }
    }

    if ([string]::IsNullOrWhiteSpace($existingPolicyKey) -and
        [string]$Test.verified_via -match '(?i)DevTools\s*\(CDP.*requires live browser') {
        return @{ key = ''; source = 'OBSERVATIONAL_RUNTIME_ONLY'; trusted = $false }
    }

    foreach ($controlId in @($Test.cis_controls)) {
        if ($controlId -and $PolicyMap.ContainsKey([string]$controlId)) {
            $mapped = $PolicyMap[[string]$controlId]

            # A test that measures a user preference must not inherit a managed
            # policy key from its CIS tag. The two often have opposite polarity
            # (pref "experiments enabled = false" vs policy "DisableStudies = true"),
            # and silently binding them attaches a contradictory expectation to
            # the key. The key is still reported, but not trusted as evidence.
            $via = [string]$Test.verified_via
            $userScoped = ($via -match '(?i)prefs\.js|user\.js|preferences file' -and $via -notmatch '(?i)registry|policies\.json|policy')
            $prefStyleKey = ($mapped -match '^[a-z][a-z0-9_]*(\.[A-Za-z0-9_\-]+)+$')

            if ($userScoped -and -not $prefStyleKey) {
                return @{ key = $mapped; source = 'CONTROL_MAP_POLARITY_UNVERIFIED'; trusted = $false }
            }

            return @{ key = $mapped; source = 'CONTROL_MAP'; trusted = $true }
        }
    }

    $referenceUrl = [string]$Test.reference
    if (-not [string]::IsNullOrWhiteSpace($referenceUrl)) {
        $anchor = [regex]::Match($referenceUrl, '#([A-Za-z][A-Za-z0-9_]{3,})')
        if ($anchor.Success) {
            return @{ key = $anchor.Groups[1].Value; source = 'REFERENCE_ANCHOR'; trusted = $true }
        }
    }

    foreach ($text in @($Test.test_method, $Test.remediation, $Test.details, $Test.message)) {
        if ([string]::IsNullOrWhiteSpace($text)) { continue }

        $quoted = [regex]::Match($text, "'([A-Za-z][A-Za-z0-9_]{5,})'")
        if ($quoted.Success) { return @{ key = $quoted.Groups[1].Value; source = 'INFERRED_FROM_TEXT'; trusted = $false } }

        $camel = [regex]::Match($text, '\b([A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+){1,})\b')
        if ($camel.Success) { return @{ key = $camel.Groups[1].Value; source = 'INFERRED_FROM_TEXT'; trusted = $false } }
    }

    if ([string]$Test.test_id -match '^F-(?:0?0?[1-9]|0?1[0-2]|0?1[7-9]|020)$') {
        $firefoxKey = switch ([string]$Test.test_id) {
            'F-001' { 'DisablePrivateBrowsing' }
            'F-002' { 'PasswordManagerEnabled' }
            'F-003' { 'ExtensionSettings' }
            'F-004' { 'DisableSecurityBypass' }
            'F-005' { 'DisableTelemetry' }
            'F-006' { 'DisableFirefoxAccounts' }
            'F-007' { 'DNSOverHTTPS' }
            'F-008' { 'Cookies' }
            'F-009' { 'DisableDeveloperTools' }
            'F-010' { 'Proxy' }
            'F-011' { 'DisableFormHistory' }
            'F-012' { 'RuntimeProcessFlags' }
            'F-017' { 'security.OCSP.enabled' }
            'F-018' { 'network.http.http3.enable' }
            'F-019' { 'security.mixed_content.block_active_content' }
            'F-020' { 'security.cert_pinning.enforcement_level' }
            default { '' }
        }
        if (-not [string]::IsNullOrWhiteSpace($firefoxKey)) {
            return @{ key = $firefoxKey; source = 'STATIC_TABLE'; trusted = $true }
        }
    }

    return @{ key = ''; source = 'UNRESOLVED'; trusted = $false }
}

function Import-ControlSemantics {
    <#
      Loads the declared control semantics. Kept in data rather than in code so
      that anyone deploying this project can extend it for their own baseline
      without editing the engine.
    #>
    $semantics = @{ keys = @(); key_patterns = @(); name_patterns = @() }

    $path = Join-Path $PSScriptRoot 'control_semantics.json'
    if (-not (Test-Path $path)) { return $semantics }

    try {
        $doc = Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        Write-Warning "control_semantics.json could not be parsed; default semantics apply."
        return $semantics
    }

    $block = $doc.absence_is_compliant
    if ($block) {
        $semantics.keys          = @($block.policy_keys          | ForEach-Object { ([string]$_).ToLowerInvariant() })
        $semantics.key_patterns  = @($block.policy_key_patterns  | ForEach-Object { [string]$_ })
        $semantics.name_patterns = @($block.test_name_patterns   | ForEach-Object { [string]$_ })
    }

    return $semantics
}

function Test-AbsenceIsCompliant {
    param([hashtable]$Semantics, [string]$PolicyKey, [string]$TestName)

    if (-not [string]::IsNullOrWhiteSpace($PolicyKey)) {
        if ($Semantics.keys -contains $PolicyKey.ToLowerInvariant()) { return $true }
        foreach ($pattern in $Semantics.key_patterns) {
            if ($PolicyKey -match $pattern) { return $true }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($TestName)) {
        foreach ($pattern in $Semantics.name_patterns) {
            if ($TestName -match $pattern) { return $true }
        }
    }

    return $false
}

function Test-ContainsAny {
    param([string]$Text, [string[]]$Patterns)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    foreach ($pattern in $Patterns) {
        if ($Text -match $pattern) { return $true }
    }
    return $false
}

function Get-ReferenceUrlForPolicyKey {
    param(
        [string]$Browser,
        [string]$PolicyKey,
        [string]$CurrentReference,
        [psobject]$Test
    )

    $existing = [string]$CurrentReference
    $normalized = $existing.Trim().ToLowerInvariant()

    $isGeneric = $false
    if (-not [string]::IsNullOrWhiteSpace($normalized)) {
        if ($normalized -match 'microsoft-edge-policies/?$|chromeenterprise\.google/policies/?$|mozilla\.github\.io/policy-templates/?$') {
            $isGeneric = $true
        }
    }

    $generated = ''
    if (-not [string]::IsNullOrWhiteSpace($PolicyKey)) {
        $encoded = [uri]::EscapeDataString($PolicyKey)
        $generated = switch ($Browser) {
            'Edge'    { "https://learn.microsoft.com/deployedge/microsoft-edge-policies/#$encoded" }
            'Firefox' {
                if ($PolicyKey -match '\.') {
                    "https://searchfox.org/mozilla-central/search?q=$encoded"
                } else {
                    "https://mozilla.github.io/policy-templates/#$encoded"
                }
            }
            default { '' }
        }
    }

    if ([string]::IsNullOrWhiteSpace($existing)) {
        if (-not [string]::IsNullOrWhiteSpace($generated)) {
            return $generated
        }

        $seed = [string]$Test.test_id
        if ([string]::IsNullOrWhiteSpace($seed)) { $seed = [string]$Test.test_name }
        $query = [uri]::EscapeDataString($seed)
        $fallbackRef = ''
        switch ($Browser) {
            'Edge'    { $fallbackRef = "https://learn.microsoft.com/en-us/search/?terms=$query&scope=Microsoft%20Edge" }
            'Chrome'  { $fallbackRef = "https://chromeenterprise.google/policies/?q=$query" }
            'Firefox' { $fallbackRef = "https://searchfox.org/mozilla-central/search?q=$query" }
            default   { $fallbackRef = '' }
        }
        return $fallbackRef
    }
    if ($isGeneric -and -not [string]::IsNullOrWhiteSpace($generated)) {
        return $generated
    }
    return $existing
}

function Get-RiskGroup {
    param([psobject]$Test, [string]$PolicyKey)

    $packageId = ([string]$Test.package_id).ToUpperInvariant()
    switch -Regex ($packageId) {
        '^PKG-1$' { return 'Policy Hardening' }
        '^PKG-2$' { return 'Data Exfiltration' }
        '^PKG-3$' { return 'Identity & Session Security' }
        '^PKG-4$' { return 'Extension Threats' }
        '^PKG-5$|^CH-PKG-5$|^FF-PKG-5$' { return 'Network & Visibility' }
        '^CH-PKG-1$|^FF-PKG-1$' { return 'Policy Hardening' }
        '^CH-PKG-2$|^CH-PKG-4$|^FF-PKG-2$|^FF-PKG-4$' { return 'Identity & Session Security' }
        '^CH-PKG-3$|^FF-PKG-3$' { return 'Extension Threats' }
        '^CH-PKG-6$|^FF-PKG-6$' { return 'Policy Hardening' }
        '^FF-PKG-7$' { return 'Certificate/Proxy Inspection' }
    }

    $text = @(
        [string]$Test.test_name,
        [string]$Test.test_id,
        [string]$PolicyKey,
        [string]$Test.remediation,
        [string]$Test.test_method,
        [string]$Test.reference
    ) -join ' '
    $t = $text.ToLowerInvariant()

    if ($t -match 'extension|add-on|plugin|forcelist|blocklist|extensionsettings') { return 'Extension Threats' }
    if ($t -match 'password|credential|signin|session|cookie|third[- ]party|autofill|privatebrowsingcapture') { return 'Identity & Session Security' }
    if ($t -match 'dns|doh|webrtc|captive|network|resolver|urlbar|visibility|proxymode|dnsoverhttpsmode') { return 'Network & Visibility' }
    if ($t -match 'tls|https|certificate|ocsp|crl|hsts|quic|proxy|pinning|enterprise_roots|smartscreen') { return 'Certificate/Proxy Inspection' }
    if ($t -match 'download|upload|clipboard|telemetry|sync|history|feedback|healthreport|file_unique_origin|screensharing') { return 'Data Exfiltration' }
    if ($t -match 'ai|saas|copilot|chatgpt|gemini|shadow') { return 'Shadow AI & SaaS' }
    if ($t -match 'update|componentupdates|version|unsupported os|patch|normandy') { return 'Patch & Version Hygiene' }
    if ($t -match 'compliance|sovereignty|regulation|forensic|audit') { return 'Compliance & Data Sovereignty' }
    return 'Policy Hardening'
}

function Get-FallbackIncidentScenario {
    param([psobject]$Test, [string]$RiskGroup)

    $title = [string]$Test.test_name
    if ([string]::IsNullOrWhiteSpace($title)) { $title = [string]$Test.test_id }
    $expected = [string]$Test.expected_value
    $observed = [string]$Test.observed_value

    $scenario = switch ($RiskGroup) {
        'Network & Visibility' { 'network visibility can weaken and the risk of DNS/routing manipulation can increase' }
        'Certificate/Proxy Inspection' { 'secure channel integrity can be damaged and MITM-like risks can increase' }
        'Extension Threats' { 'data access and leakage can occur through an unauthorized extension chain' }
        'Identity & Session Security' { 'account takeover and session abuse risk can increase' }
        'Data Exfiltration' { 'corporate data egress and loss of traceability risk can increase' }
        default { 'security controls can weaken due to policy override' }
    }

    $status = [string]$Test.status
    $statusText = if ($status -eq 'PASSED') { 'The control is in the expected state, but drift risk should be monitored.' } else { 'The control is not at the expected hardening level.' }
    $expectedNote = if (-not [string]::IsNullOrWhiteSpace($expected)) { " Expected: $expected." } else { '' }
    $observedNote = if (-not [string]::IsNullOrWhiteSpace($observed)) { " Observed: $observed." } else { '' }

    return "State ($title): $statusText Incident scenario: if this persists, $scenario.$expectedNote$observedNote".Trim()
}

function Get-NormalizedComparableText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $t = $Text.ToLowerInvariant()
    $t = [regex]::Replace($t, '\s+', ' ').Trim()
    $t = [regex]::Replace($t, '[^a-z0-9 ]', '')
    return $t
}

function Test-IsNarrativeDuplicate {
    param(
        [string]$A,
        [string]$B
    )

    $na = Get-NormalizedComparableText -Text $A
    $nb = Get-NormalizedComparableText -Text $B
    if ([string]::IsNullOrWhiteSpace($na) -or [string]::IsNullOrWhiteSpace($nb)) { return $false }
    return $na -eq $nb
}

function Normalize-ResultNarrativeFields {
    param(
        [psobject]$TestObj,
        [hashtable]$Decision,
        [hashtable]$Layer1,
        [hashtable]$Layer2,
        [hashtable]$Layer3,
        [string]$MappingClass,
        [string]$PolicyKey
    )

    $testId = [string]$TestObj.test_id
    $testName = [string]$TestObj.test_name
    if ([string]::IsNullOrWhiteSpace($testName)) { $testName = $testId }

    $message = [string]$TestObj.message
    $details = [string]$TestObj.details
    $finding = [string]$TestObj.finding_details
    $evidence = [string]$TestObj.evidence_output

    $expected = [string]$TestObj.expected_value
    if ([string]::IsNullOrWhiteSpace($expected)) {
        $expected = [string]$TestObj.expected_machine_value
    }

    $observed = [string]$TestObj.observed_value
    if ([string]::IsNullOrWhiteSpace($observed)) {
        switch ([string]$Decision.deciding_layer) {
            'L1' { $observed = [string]$Layer1.actual }
            'L2' { $observed = [string]$Layer2.actual }
            'L3' { $observed = [string]$Layer3.actual }
            default { $observed = '' }
        }
    }

    $scope = if ([string]::IsNullOrWhiteSpace($PolicyKey)) { 'policy_key=unresolved' } else { "policy_key=$PolicyKey" }
    $layerLine = "L1=$($Layer1.state), L2=$($Layer2.state), L3=$($Layer3.state), deciding=$($Decision.deciding_layer)"

    if ([string]::IsNullOrWhiteSpace($message)) {
        $message = "$testName ($testId) decision for control: $($Decision.verdict)."
    }
    $message = "[$testId] $testName - $message"

    if ([string]::IsNullOrWhiteSpace($details) -or (Test-IsNarrativeDuplicate -A $details -B $message)) {
        $details = "$testName technical assessment: $layerLine; mapping=$MappingClass; $scope."
    }
    if (-not ($details -match [regex]::Escape($testId))) {
        $details = "$details test_id=$testId."
    }

    if ([string]::IsNullOrWhiteSpace($finding) -or (Test-IsNarrativeDuplicate -A $finding -B $message) -or (Test-IsNarrativeDuplicate -A $finding -B $details)) {
        $finding = "$testName finding: expected='$expected'; observed='$observed'; verdict=$($Decision.verdict); reason=$($Decision.reasoning)."
    }
    if (-not ($finding -match [regex]::Escape($testId))) {
        $finding = "$finding test_id=$testId; $scope."
    }

    $primaryLayer = switch ([string]$Decision.deciding_layer) {
        'L1' { $Layer1 }
        'L2' { $Layer2 }
        'L3' { $Layer3 }
        default { $Layer1 }
    }
    $primarySource = [string]$primaryLayer.source
    $primaryActual = [string]$primaryLayer.actual
    $verifiedVia = [string]$TestObj.verified_via

    $evidence = "Evidence trail: verified_via='$verifiedVia'; primary_source='$primarySource'; primary_actual='$primaryActual'; deciding_layer=$($Decision.deciding_layer); mapping=$MappingClass; $scope."
    if (-not ($evidence -match [regex]::Escape($testId))) {
        $evidence = "$evidence test_id=$testId."
    }

    if (Test-IsNarrativeDuplicate -A $details -B $finding) {
        $finding = "$finding Finding class: $MappingClass."
    }
    if (Test-IsNarrativeDuplicate -A $evidence -B $details) {
        $evidence = "$evidence Evidence class: $MappingClass."
    }

    $TestObj | Add-Member -NotePropertyName 'message' -NotePropertyValue $message -Force
    $TestObj | Add-Member -NotePropertyName 'details' -NotePropertyValue $details -Force
    $TestObj | Add-Member -NotePropertyName 'finding_details' -NotePropertyValue $finding -Force
    $TestObj | Add-Member -NotePropertyName 'evidence_output' -NotePropertyValue $evidence -Force
    return $TestObj
}

function Get-RootCauseClassification {
    param(
        [hashtable]$Decision,
        [hashtable]$Layer1,
        [hashtable]$Layer2,
        [hashtable]$Layer3
    )

    if ([string]$Decision.verdict -ne 'FAIL') {
        return @{
            code = 'RC_NONE'
            category = 'NON_FAIL'
            summary = 'This record is not a FAIL; root-cause classification was not applied.'
            evidence_layer = [string]$Decision.deciding_layer
        }
    }

    if ($Layer3.state -eq 'NON_COMPLIANT_VALUE') {
        return @{
            code = 'RC_RUNTIME_CONTRADICTION'
            category = 'RUNTIME_CONFLICT'
            summary = 'The runtime layer reported a value or bypass signal that contradicts the managed/user expectation.'
            evidence_layer = 'L3'
        }
    }

    if ($Layer1.state -eq 'NON_COMPLIANT_VALUE') {
        return @{
            code = 'RC_POLICY_VALUE_MISMATCH'
            category = 'MANAGED_POLICY_MISCONFIG'
            summary = 'A managed policy exists but its value does not match the expected machine value.'
            evidence_layer = 'L1'
        }
    }

    if ($Layer1.state -eq 'ABSENT' -and $Layer2.state -eq 'NON_COMPLIANT_VALUE') {
        return @{
            code = 'RC_POLICY_ABSENT_USER_MISMATCH'
            category = 'MULTI_LAYER_MISCONFIG'
            summary = 'Managed policy is not deployed, and the user-level setting is explicitly non-compliant.'
            evidence_layer = 'L2'
        }
    }

    if ($Layer1.state -eq 'ABSENT' -and $Layer2.state -eq 'ABSENT') {
        return @{
            code = 'RC_CONTROL_UNCONFIGURED'
            category = 'UNCONFIGURED'
            summary = 'The control is defined at neither the managed nor the user layer; the required setting has not been deployed.'
            evidence_layer = [string]$Decision.deciding_layer
        }
    }

    if ($Layer1.state -eq 'ABSENT' -and $Layer2.state -eq 'NOT_APPLICABLE') {
        return @{
            code = 'RC_POLICY_NOT_DEPLOYED'
            category = 'MANAGED_POLICY_MISSING'
            summary = 'This control is policy-oriented; it failed because no managed policy is deployed.'
            evidence_layer = 'L1'
        }
    }

    if ($Layer2.state -eq 'NON_COMPLIANT_VALUE') {
        return @{
            code = 'RC_USER_VALUE_MISMATCH'
            category = 'USER_CONFIG_MISCONFIG'
            summary = 'The user-level configuration value does not match the expected value.'
            evidence_layer = 'L2'
        }
    }

    if ($Layer2.state -eq 'ABSENT') {
        return @{
            code = 'RC_USER_SETTING_MISSING'
            category = 'USER_CONFIG_MISSING'
            summary = 'A user-level preference equivalent exists, but no value is defined.'
            evidence_layer = 'L2'
        }
    }

    if ($Layer1.state -eq 'ABSENT') {
        return @{
            code = 'RC_POLICY_NOT_DEPLOYED'
            category = 'MANAGED_POLICY_MISSING'
            summary = 'Because no managed policy is deployed, the control could not reach the required enforcement level.'
            evidence_layer = 'L1'
        }
    }

    return @{
        code = 'RC_UNCLASSIFIED_FAIL'
        category = 'UNCLASSIFIED'
        summary = 'A FAIL decision was produced, but the current layer combination did not match standard root-cause classes.'
        evidence_layer = [string]$Decision.deciding_layer
    }
}

function Get-ExpectedMachineMeta {
    param([psobject]$Test)

    $kind = [string]$Test.expected_kind
    $value = [string]$Test.expected_machine_value
    if (-not [string]::IsNullOrWhiteSpace($kind) -and -not [string]::IsNullOrWhiteSpace($value)) {
        return @{ kind = $kind; value = $value }
    }

    $text = [string]$Test.expected_value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return @{ kind = ''; value = '' }
    }

    $t = $text.ToLowerInvariant()
    if ($t -match '>=\s*(-?\d+)') { return @{ kind = 'numeric_gte'; value = [string]$Matches[1] } }
    if ($t -match 'en az\s*(-?\d+)') { return @{ kind = 'numeric_gte'; value = [string]$Matches[1] } }
    if ($t -match '(?i)expected:\s*(-?\d+)') { return @{ kind = 'numeric_eq'; value = [string]$Matches[1] } }
    if ($t -match '(?i)\b(true|false)\b') { return @{ kind = 'bool'; value = $Matches[1].ToLowerInvariant() } }
    if ($t -match '(?i)\bpresent\b') { return @{ kind = 'present'; value = 'true' } }
    if ($t -match '(?i)\bclean\b') { return @{ kind = 'enum'; value = 'clean' } }
    if ($t -match '(?i)\b(tls1\.[0-3])\b') { return @{ kind = 'enum'; value = $Matches[1].ToLowerInvariant() } }

    return @{ kind = ''; value = '' }
}

function Get-BehavioralValidationMeta {
    param(
        [psobject]$Test,
        [string]$PolicyKey,
        [hashtable]$ExpectedMeta,
        [string]$MappingClass,
        [bool]$HasRuntimeSignal,
        [hashtable]$Layer1,
        [hashtable]$Layer2,
        [hashtable]$Layer3
    )

    $expectedKind = ([string]$ExpectedMeta.kind).ToLowerInvariant()
    $expectedMachine = ([string]$ExpectedMeta.value).ToLowerInvariant()
    $pk = [string]$PolicyKey

    $policyObjectFamilies = @(
        'ExtensionSettings',
        'ExtensionInstallBlocklist',
        'ExtensionInstallAllowlist',
        'ExtensionInstallForcelist',
        'ProxyMode',
        'ProxySettings',
        'Proxy',
        'DnsOverHttpsMode',
        'DNSOverHTTPS',
        'Cookies',
        'ChromeVariations',
        'DefaultClipboardSetting',
        'StoragePartitioningBlockedForOrigins',
        'ClipboardAllowedForUrls',
        'ClipboardBlockedForUrls',
        'HttpAllowlist',
        'SyncTypesListDisabled'
    )

    $matchesObjectFamily = $false
    foreach ($family in $policyObjectFamilies) {
        if ($pk -eq $family) {
            $matchesObjectFamily = $true
            break
        }
    }

    $requiresBehaviorValidation = ($expectedKind -eq 'present' -or $expectedMachine -eq 'configured' -or $matchesObjectFamily)
    if (-not $requiresBehaviorValidation) {
        return @{
            required = $false
            level = 'NOT_REQUIRED'
            gap = $false
            summary = 'This control is not in the policy-object/presence class; behavioral evidence is not required.'
        }
    }

    $evidenceText = @(
        [string]$Test.verified_via,
        [string]$Test.test_method,
        [string]$Test.message,
        [string]$Test.details,
        [string]$Test.finding_details,
        [string]$Test.observed_value,
        [string]$Layer1.actual,
        [string]$Layer2.actual,
        [string]$Layer3.actual
    ) -join ' '
    $t = $evidenceText.ToLowerInvariant()

    $hasRuntimeBehaviorEvidence = $HasRuntimeSignal -or ($t -match 'runtime|process command line|win32_process|live process|risky flag|no risky')
    $hasRestrictionSemantics = ($t -match 'installation_mode\s*=\s*true|control_rules\s*=\s*true|restriction_signal\s*=\s*true|routing_hint\s*=\s*true|provider_or_state\s*=\s*true|mode\s*=\s*true|blocked|blocklist|forcelist|deny|reject|disabled|enforced|locked|clean')
    $presenceOnly = ($t -match 'present\s*=\s*true|configured') -and (-not $hasRestrictionSemantics)

    if ($hasRuntimeBehaviorEvidence) {
        return @{
            required = $true
            level = 'STRONG'
            gap = $false
            summary = 'The policy-object control was cross-validated with runtime/behavioral evidence.'
        }
    }

    if ($hasRestrictionSemantics) {
        return @{
            required = $true
            level = 'MODERATE'
            gap = $false
            summary = 'The policy-object control was validated using fields that include constraint semantics, not presence alone.'
        }
    }

    if ($presenceOnly) {
        return @{
            required = $true
            level = 'LIMITED'
            gap = $true
            summary = 'The control relies on present/configured evidence only; behavioral effect was validated to a limited degree.'
        }
    }

    return @{
        required = $true
        level = 'NONE'
        gap = $true
        summary = 'Insufficient behavioral or constraint-semantics evidence was found for this policy-object control.'
    }
}

function Get-FirefoxDeterministicMetaByPolicyKey {
    param([string]$PolicyKey)

    switch ([string]$PolicyKey) {
        'DisablePrivateBrowsing'      { return @{ kind = 'bool'; value = 'true' } }
        'PasswordManagerEnabled'      { return @{ kind = 'bool'; value = 'false' } }
        'DisableSecurityBypass'       { return @{ kind = 'bool'; value = 'true' } }
        'DisableTelemetry'            { return @{ kind = 'bool'; value = 'true' } }
        'DisableFirefoxAccounts'      { return @{ kind = 'bool'; value = 'true' } }
        'DisableDeveloperTools'       { return @{ kind = 'bool'; value = 'true' } }
        'DisableFormHistory'          { return @{ kind = 'bool'; value = 'true' } }
        'DisablePocket'               { return @{ kind = 'bool'; value = 'true' } }
        'DisableFirefoxStudies'       { return @{ kind = 'bool'; value = 'true' } }
        'DisableFeedbackCommands'     { return @{ kind = 'bool'; value = 'true' } }
        'DisableProfileImport'        { return @{ kind = 'bool'; value = 'true' } }
        'EnableTrackingProtection'    { return @{ kind = 'bool'; value = 'true' } }
        'BlockAboutConfig'            { return @{ kind = 'bool'; value = 'true' } }
        'DontCheckDefaultBrowser'     { return @{ kind = 'bool'; value = 'true' } }
        'RuntimeProcessFlags'         { return @{ kind = 'enum'; value = 'clean' } }
        default                       { return @{ kind = ''; value = '' } }
    }
}

function Get-ChromiumDeterministicMetaByPolicyKey {
    param(
        [string]$PolicyKey,
        [string]$ExpectedState,
        [string]$ExpectedRaw
    )

    if ([string]::IsNullOrWhiteSpace($PolicyKey)) { return @{ kind = ''; value = '' } }

    $state = ([string]$ExpectedState).ToUpperInvariant()
    $raw = [string]$ExpectedRaw
    $rawLower = $raw.ToLowerInvariant()

    # Numeric/enum families where presence-only semantics are weak.
    switch ([string]$PolicyKey) {
        'PromptForDownloadLocation' { return @{ kind = 'bool'; value = 'true' } }
        'SyncDisabled' { return @{ kind = 'bool'; value = 'true' } }
        'SitePerProcess' { return @{ kind = 'bool'; value = 'true' } }
        'ImplicitSignInEnabled' { return @{ kind = 'bool'; value = 'false' } }
        'ExtensionInstallBlocklist' { return @{ kind = 'enum'; value = 'configured' } }
        'BlockThirdPartyCookies' { return @{ kind = 'bool'; value = 'true' } }
        'InsecureContentAllowedForUrls' { return @{ kind = 'bool'; value = 'false' } }
        'CertificateTransparencyEnforcementDisabledForCas' { return @{ kind = 'bool'; value = 'false' } }
        'IncognitoModeAvailability' { return @{ kind = 'enum'; value = if ($state -eq 'DISABLED') { 'disabled' } else { 'enabled' } } }
        'SafeBrowsingProtectionLevel' { return @{ kind = 'numeric_gte'; value = '1' } }
        'QuicAllowed' { return @{ kind = 'bool'; value = 'false' } }
        'CertificateTransparencyEnforcementDisabledFor' { return @{ kind = 'bool'; value = 'false' } }
        'ChromeVariations' { return @{ kind = 'enum'; value = 'configured' } }
        'AutoUpdateCheckPeriodMinutes' { return @{ kind = 'numeric_gte'; value = '1' } }
        'DefaultClipboardSetting' { return @{ kind = 'enum'; value = 'configured' } }
        'DownloadRestrictions' { return @{ kind = 'numeric_gte'; value = '1' } }
        'DiskCacheSize' {
            $m = [regex]::Match($raw, '(-?\d+)')
            if ($m.Success) { return @{ kind = 'numeric_eq'; value = [string]$m.Groups[1].Value } }
            return @{ kind = 'numeric_gte'; value = '1' }
        }
        'DeveloperToolsAvailability' {
            if ($raw -match '(?i)DeveloperToolsAvailability\s*=\s*2\b|\bvalue\s+2\b') {
                return @{ kind = 'enum'; value = 'disabled' }
            }
            return @{ kind = 'enum'; value = if ($state -eq 'DISABLED') { 'disabled' } else { 'enabled' } }
        }
        'InPrivateModeAvailability' { return @{ kind = 'enum'; value = if ($state -eq 'DISABLED') { 'disabled' } else { 'enabled' } } }
        'BrowserSignin' { return @{ kind = 'enum'; value = if ($state -eq 'DISABLED') { 'disabled' } else { 'enabled' } } }
        'ProxyMode' { return @{ kind = 'enum'; value = 'configured' } }
        'ProxySettings' { return @{ kind = 'enum'; value = 'configured' } }
        'DnsOverHttpsMode' { return @{ kind = 'enum'; value = 'configured' } }
        'SameSite' { return @{ kind = 'enum'; value = 'configured' } }
        'ExtensionSettings' { return @{ kind = 'enum'; value = 'configured' } }
        'StoragePartitioningBlockedForOrigins' { return @{ kind = 'enum'; value = 'configured' } }
        'ClipboardAllowedForUrls' { return @{ kind = 'enum'; value = 'configured' } }
        'ClipboardBlockedForUrls' { return @{ kind = 'enum'; value = 'configured' } }
        'HttpAllowlist' { return @{ kind = 'enum'; value = 'configured' } }
        'SyncTypesListDisabled' { return @{ kind = 'enum'; value = 'configured' } }
    }

    # Explicit boolean text in expectation has highest confidence.
    if ($rawLower -match '\btrue\b') { return @{ kind = 'bool'; value = 'true' } }
    if ($rawLower -match '\bfalse\b') { return @{ kind = 'bool'; value = 'false' } }
    if ($rawLower -match 'tanimli\s+olmamali|bulunmamali|bos\s+olmali') { return @{ kind = 'bool'; value = 'false' } }

    # Policy-name families with known polarity.
    if ($PolicyKey -match 'Disabled$') {
        if ($state -eq 'DISABLED') { return @{ kind = 'bool'; value = 'true' } }
        if ($state -eq 'ENABLED') { return @{ kind = 'bool'; value = 'false' } }
    }
    if ($PolicyKey -match 'Enabled$') {
        if ($state -eq 'DISABLED') { return @{ kind = 'bool'; value = 'false' } }
        if ($state -eq 'ENABLED') { return @{ kind = 'bool'; value = 'true' } }
    }
    if ($PolicyKey -match 'Allowed$') {
        if ($state -eq 'DISABLED') { return @{ kind = 'bool'; value = 'false' } }
        if ($state -eq 'ENABLED') { return @{ kind = 'bool'; value = 'true' } }
    }

    # Fallback by expectation wording.
    if ($rawLower -match 'expected:\s*disabled|\bdisabled\b') { return @{ kind = 'enum'; value = 'disabled' } }
    if ($rawLower -match 'expected:\s*enabled|\benabled\b') { return @{ kind = 'enum'; value = 'enabled' } }
    if ($rawLower -match 'configured|properly\s+configured') { return @{ kind = 'enum'; value = 'configured' } }

    return @{ kind = ''; value = '' }
}

if (-not (Test-Path $InputFile)) {
    Write-Error "Input file not found: $InputFile"
    exit 1
}
if (-not $OutputFile) {
    $OutputFile = $InputFile -replace '\.json$', '_verified.json'
}

$report     = Get-Content $InputFile -Raw -Encoding UTF8 | ConvertFrom-Json
$allResults = @($report.results)
$policyMap  = Import-PolicyMap -Browser $Browser
$policyAliasMap = Import-PolicyAliasMap -Browser $Browser
$controlSemantics = Import-ControlSemantics
$mgmtProfile = Get-DeviceManagementProfile -Browser $Browser
$evidenceIncomplete = Test-ManagedEvidenceIsIncomplete -ManagementProfile $mgmtProfile

$activeChannels = @()
if ($mgmtProfile.domain_joined) { $activeChannels += 'GPO (domain-joined)' }
if ($mgmtProfile.mdm.enrolled) { $activeChannels += "MDM ($($mgmtProfile.mdm.provider))" }
if ($mgmtProfile.admx_ingestion.present) { $activeChannels += 'MDM ADMX ingestion' }
foreach ($agent in @($mgmtProfile.agents)) { $activeChannels += "Agent: $($agent.name)" }
if ($mgmtProfile.cloud_management.enrolled) { $activeChannels += "Cloud: $($mgmtProfile.cloud_management.service)" }
if ($activeChannels.Count -eq 0) { $activeChannels += 'None detected (unmanaged or local-only configuration)' }
$activeChannels = @($activeChannels | Select-Object -Unique)

Write-Host "Input   : $InputFile"     -ForegroundColor Cyan
Write-Host "Browser : $Browser"       -ForegroundColor Cyan
Write-Host "Tests   : $($allResults.Count)" -ForegroundColor Cyan
Write-Host "Model   : value-based, evidence precedence (no layer voting)" -ForegroundColor Green
Write-Host "Mgmt    : $($activeChannels -join ' | ')" -ForegroundColor Green
if ($evidenceIncomplete) {
    Write-Host "WARNING : an active management channel cannot be read on-box; missing-policy findings are reported NOT_ASSESSED instead of FAIL." -ForegroundColor Yellow
}
Write-Host ""

$verdictCounts = @{ PASS = 0; PASS_NOT_ENFORCED = 0; FAIL = 0; NOT_ASSESSED = 0 }
$layerStates   = @{
    L1 = @{ COMPLIANT = 0; NON_COMPLIANT_VALUE = 0; ABSENT = 0; NOT_APPLICABLE = 0; NOT_ASSESSED = 0 }
    L2 = @{ COMPLIANT = 0; NON_COMPLIANT_VALUE = 0; ABSENT = 0; NOT_APPLICABLE = 0; NOT_ASSESSED = 0 }
    L3 = @{ COMPLIANT = 0; NON_COMPLIANT_VALUE = 0; ABSENT = 0; NOT_APPLICABLE = 0; NOT_ASSESSED = 0 }
    L4 = @{ COMPLIANT = 0; NON_COMPLIANT_VALUE = 0; ABSENT = 0; NOT_APPLICABLE = 0; NOT_ASSESSED = 0 }
}
$decidingLayer = @{ L1 = 0; L2 = 0; L3 = 0; NONE = 0 }
$mappingStandardization = @{ DIRECT = 0; POLICY_ONLY = 0; RUNTIME = 0; MANUAL = 0; UNKNOWN = 0 }
$failRootCauseDistribution = @{}
$behaviorValidationLevels = @{ STRONG = 0; MODERATE = 0; LIMITED = 0; NONE = 0; NOT_REQUIRED = 0 }
$behavioralGapCount = 0

$enriched          = @()
$counter           = 0
$arbitrated        = 0
$noExpectation     = 0
$noPolicyKey       = 0
$channelDistribution = @{}
$suppressedFails     = 0
$mdmSourcedControls  = 0
$policyKeySourceDistribution = @{}
$untrustedKeyCount   = 0
$evidenceBasisDistribution = @{}

foreach ($test in $allResults) {
    $counter++
    if ($counter % 25 -eq 0) {
        Write-Host "  [$counter/$($allResults.Count)]" -ForegroundColor DarkGray
    }

    $policyKeyInfo = Resolve-PolicyKey -Test $test -PolicyMap $policyMap
    $policyKey     = [string]$policyKeyInfo.key
    $policyKeySource  = [string]$policyKeyInfo.source
    $policyKeyTrusted = [bool]$policyKeyInfo.trusted
    $expectedState = Get-ExpectedState -Test $test
    $expectedMeta  = Get-ExpectedMachineMeta -Test $test
    if ($Browser -eq 'Firefox' -and [string]::IsNullOrWhiteSpace([string]$expectedMeta.kind)) {
        $firefoxFallbackMeta = Get-FirefoxDeterministicMetaByPolicyKey -PolicyKey $policyKey
        if (-not [string]::IsNullOrWhiteSpace([string]$firefoxFallbackMeta.kind)) {
            $expectedMeta = $firefoxFallbackMeta
        }
    }
    if (($Browser -eq 'Edge' -or $Browser -eq 'Chrome') -and -not [string]::IsNullOrWhiteSpace($policyKey)) {
        $chromiumMeta = Get-ChromiumDeterministicMetaByPolicyKey -PolicyKey $policyKey -ExpectedState $expectedState -ExpectedRaw ([string]$test.expected_value)
        $currentKind = [string]$expectedMeta.kind
        if (-not [string]::IsNullOrWhiteSpace([string]$chromiumMeta.kind)) {
            if ([string]::IsNullOrWhiteSpace($currentKind) -or $currentKind -eq 'present') {
                $expectedMeta = $chromiumMeta
            }
        }
        if ([string]::IsNullOrWhiteSpace([string]$expectedMeta.kind)) {
            # Last-resort deterministic baseline when no family rule exists.
            $expectedMeta = @{ kind = 'present'; value = 'true' }
        }
    }

    # Determine which layers to evaluate based on verified_via
    $verifiedVia = [string]$test.verified_via
    $managedMarkers = @('policies\.json', 'managed.*policy', 'registry', 'gpo', 'mdm')
    $userMarkers = @('prefs\.js', 'preferences', 'user.*config')
    $runtimeMarkers = @(
        'process command line',
        'runtime',
        'win32_process',
        'command-line',
        'devtools',
        'browser api',
        'filesystem',
        'network config',
        'proxy inspection',
        'cloud policy',
        'azure ad backend',
        '\(external\)'
    )

    $hasManagedSignal = Test-ContainsAny -Text $verifiedVia -Patterns $managedMarkers
    $hasUserSignal = Test-ContainsAny -Text $verifiedVia -Patterns $userMarkers
    $hasRuntimeSignal = Test-ContainsAny -Text $verifiedVia -Patterns $runtimeMarkers

    $mappingClass = 'MANUAL'
    if (-not [string]::IsNullOrWhiteSpace($policyKey) -and -not [string]::IsNullOrWhiteSpace([string]$expectedMeta.kind)) {
        $mappingClass = 'DIRECT'
    }
    elseif (-not [string]::IsNullOrWhiteSpace($policyKey)) {
        $mappingClass = 'POLICY_ONLY'
    }
    elseif ($hasRuntimeSignal) {
        $mappingClass = 'RUNTIME'
    }
    if ([string]$policyKey -eq 'RuntimeProcessFlags') {
        $mappingClass = 'RUNTIME'
    }
    # A key guessed from prose is not a verified mapping, so it must not raise the
    # evidence-strength weighting that DIRECT carries in the confidence index.
    if (-not $policyKeyTrusted -and $mappingClass -eq 'DIRECT') {
        $mappingClass = 'POLICY_ONLY'
    }

    $keySourceKey = $policyKeySource
    if (-not $policyKeySourceDistribution.ContainsKey($keySourceKey)) { $policyKeySourceDistribution[$keySourceKey] = 0 }
    $policyKeySourceDistribution[$keySourceKey]++
    if (-not $policyKeyTrusted -and -not [string]::IsNullOrWhiteSpace($policyKey)) { $untrustedKeyCount++ }

    if (-not $expectedState) { $noExpectation++ }

    # Count no-policy only for controls that are expected to be policy-mappable.
    if ([string]::IsNullOrWhiteSpace($policyKey) -and ($mappingClass -in @('DIRECT', 'POLICY_ONLY'))) {
        $noPolicyKey++
    }

    $mappingStandardization[$mappingClass]++

    # Default: evaluate both layers when possible to detect drift/override.
    $evalL1 = $true
    $evalL2 = $true

    # Pure user-config checks: L1 is not applicable.
    if ($hasUserSignal -and -not $hasManagedSignal -and -not $hasRuntimeSignal) {
        $evalL1 = $false
    }

    # Pure runtime checks: L1/L2 are not applicable, L3 becomes primary evidence.
    $runtimeOnly = ($hasRuntimeSignal -and -not $hasManagedSignal -and -not $hasUserSignal)
    if ($runtimeOnly) {
        $evalL1 = $false
        $evalL2 = $false
    }
    
    # Evaluate layers
    $layer1 = if ($evalL1) { 
        Get-Layer1Evidence -Test $test 
    } else { 
        @{ layer = 'L1'; source = 'Managed policy'; enforced = $true; state = 'NOT_APPLICABLE'; expected = ''; actual = ''; details = 'Not verified via managed policy.' }
    }
    
    $layer2 = if ($evalL2) { 
        Get-Layer2Evidence -Browser $Browser -PolicyKey $policyKey -ExpectedState $expectedState -ExpectedRaw ([string]$test.expected_value) -ExpectedKind ([string]$expectedMeta.kind) -ExpectedMachineValue ([string]$expectedMeta.value)
    } else { 
        @{ layer = 'L2'; source = 'User preferences'; enforced = $false; state = 'NOT_APPLICABLE'; expected = ''; actual = ''; details = 'Not verified via user preferences.' }
    }

    # Standard-agnostic rule: if user-layer evidence is expected and missing,
    # classify deterministically by expectation clarity, independent of CIS/PCI/HIPAA.
    if ($evalL2 -and $layer2.state -eq 'ABSENT') {
        if (-not [string]::IsNullOrWhiteSpace([string]$expectedMeta.kind)) {
            $layer2.state = 'NON_COMPLIANT_VALUE'
            $layer2.details = 'The user-level value is not set. Because this control has an explicit machine-comparable expectation, ABSENT was evaluated as a value mismatch (NON_COMPLIANT_VALUE).'
        } else {
            $layer2.state = 'NOT_ASSESSED'
            $layer2.details = 'The user-level value is not set; due to default-behaviour ambiguity and the lack of an explicit expectation, it was classified as NOT_ASSESSED.'
        }
    }

    # Behavior-driven tests may provide deterministic PASS/FAIL even when no policy key exists.
    # Use runner outcome as observational evidence instead of leaving them unassessed.
    if ([string]::IsNullOrWhiteSpace($policyKey) -and [string]::IsNullOrWhiteSpace([string]$expectedMeta.kind) -and ($layer1.state -in @('NOT_APPLICABLE', 'NOT_ASSESSED'))) {
        $statusText = ([string]$test.status).ToUpperInvariant()
        if ($statusText -eq 'PASSED') {
            $layer1.state = 'COMPLIANT'
            $layer1.source = 'Observed behavior evidence (runner outcome)'
            $layer1.details = "Behavioral verification reported PASS. $([string]$test.message)"
            $layer1.actual = [string]$test.details
        }
        elseif ($statusText -eq 'FAILED') {
            $layer1.state = 'NON_COMPLIANT_VALUE'
            $layer1.source = 'Observed behavior evidence (runner outcome)'
            $layer1.details = "Behavioral verification reported FAIL. $([string]$test.message)"
            $layer1.actual = [string]$test.details
        }
    }

    # Layer 3 runs as an arbiter for explicit runtime controls, direct conflicts,
    # and drift indicators between managed and user layers.
    $layer3 = @{
        layer = 'L3'; source = 'Runtime arbiter (process command line)'; enforced = $false
        state = 'NOT_ASSESSED'; expected = ''; actual = ''
        details = 'Not invoked - no conflict between managed and user layers.'
    }
    $hasDriftSignal = ($layer1.state -eq 'COMPLIANT' -and ($layer2.state -in @('NON_COMPLIANT_VALUE', 'ABSENT', 'NOT_ASSESSED')))
    $hasHardConflict = ($layer1.state -eq 'COMPLIANT' -and $layer2.state -eq 'NON_COMPLIANT_VALUE')
    $l1MissingUserEquivalent = ($layer1.state -eq 'ABSENT' -and $layer2.state -eq 'COMPLIANT')

    if ($hasHardConflict) {
        $layer3 = Get-Layer3Arbiter -Browser $Browser -Test $test
        $arbitrated++
    } elseif ($hasDriftSignal) {
        $layer3 = Get-Layer3Arbiter -Browser $Browser -Test $test
        $arbitrated++
    } elseif ($l1MissingUserEquivalent) {
        $layer3 = Get-Layer3Arbiter -Browser $Browser -Test $test
        $arbitrated++
    } elseif ($hasRuntimeSignal) {
        $layer3 = Get-Layer3Arbiter -Browser $Browser -Test $test
        $arbitrated++
    } elseif ($runtimeOnly) {
        $layer3 = Get-Layer3Arbiter -Browser $Browser -Test $test
        $arbitrated++
    }

    # Resolve WHICH management channel actually delivered this policy. Enforcement
    # and delivery channel are separate facts: a value under a Policies path is
    # provably enforced, but may come from GPO, MDM ADMX ingestion, or an agent.
    # An inferred key is never used for provenance - attributing evidence to a key
    # guessed from prose would fabricate a management fact.
    $provenance = @{ found = $false; value = $null; channel = 'NONE'; evidence_path = ''; enforced = $false; scope = ''; attribution = 'NOT_FOUND'; candidate_channels = @(); notes = '' }
    if ($policyKeyTrusted -and -not [string]::IsNullOrWhiteSpace($policyKey)) {
        $provenance = Resolve-ManagedPolicyEvidence -Browser $Browser -PolicyKey $policyKey -ManagementProfile $mgmtProfile
        if (-not $provenance.found -and $policyAliasMap.ContainsKey($policyKey)) {
            foreach ($alias in $policyAliasMap[$policyKey]) {
                $aliasEvidence = Resolve-ManagedPolicyEvidence -Browser $Browser -PolicyKey $alias -ManagementProfile $mgmtProfile
                if ($aliasEvidence.found) {
                    $aliasEvidence.notes = "Satisfied through the equivalent policy key '$alias'. $([string]$aliasEvidence.notes)"
                    $provenance = $aliasEvidence
                    break
                }
            }
        }
    }
    elseif (-not [string]::IsNullOrWhiteSpace($policyKey)) {
        $provenance.notes = "Policy key '$policyKey' was inferred from free text and is not reliable enough for evidence attribution."
    }

    $channelKey = [string]$provenance.channel
    if (-not $channelDistribution.ContainsKey($channelKey)) { $channelDistribution[$channelKey] = 0 }
    $channelDistribution[$channelKey]++
    if ($channelKey -in @('MDM_CSP', 'MDM_ADMX_INGESTED')) { $mdmSourcedControls++ }

    $layer4 = @{
        layer    = 'L4'
        source   = 'MDM policy CSP store (PolicyManager)'
        enforced = $true
        state    = 'NOT_APPLICABLE'
        expected = ''
        actual   = ''
        details  = 'No MDM CSP entry found for this policy key; managed evidence, if any, comes from the registry policy path.'
    }
    if ($channelKey -eq 'MDM_CSP') {
        $layer4.state   = $layer1.state
        $layer4.actual  = "$policyKey = $($provenance.value)"
        $layer4.details = "Policy value is present in the MDM CSP store: $($provenance.evidence_path)"
    }

    $absenceIsCompliant = Test-AbsenceIsCompliant -Semantics $controlSemantics -PolicyKey $policyKey -TestName ([string]$test.test_name)
    $complianceSemantics = 'CONFIGURATION_REQUIRED'
    if ($absenceIsCompliant) { $complianceSemantics = 'ABSENCE_IS_COMPLIANT' }

    $decision = Resolve-ComplianceVerdict -Browser $Browser -Layer1 $layer1 -Layer2 $layer2 -Layer3 $layer3

    # Hard gate: a runner that could not determine the state of a control must not
    # be converted into a compliance statement. Only a layer that performed a real
    # expected-vs-actual comparison may override an inconclusive runner outcome.
    $runnerStatus = ([string]$test.status).ToUpperInvariant()
    $hasComparedEvidence = ($layer1.state -in @('COMPLIANT', 'NON_COMPLIANT_VALUE')) -or ($layer2.state -in @('COMPLIANT', 'NON_COMPLIANT_VALUE'))
    if ($runnerStatus -in @('UNKNOWN', 'ERROR', 'SKIPPED', 'INCONCLUSIVE') -and -not $hasComparedEvidence) {
        $decision.verdict = 'NOT_ASSESSED'
        $decision.deciding_layer = 'NONE'
        $decision.counts_in_score = $false
        $decision.reasoning = "The test runner could not produce a conclusive result for this control (status=$runnerStatus) and no layer performed a real expected-vs-observed value comparison; the control was excluded from scoring and marked NOT_ASSESSED."
    }

    # A collector that states it has no mapping or no way to check a control has
    # reported a coverage gap, not a security finding. Scoring it as FAIL would
    # blame the endpoint for a limitation of the tool.
    $selfDeclaredGap = "$([string]$test.message) $([string]$test.details)"
    if ($selfDeclaredGap -match '(?i)mapping (not|is not) (defined|available)|no mapping|not implemented|could not be (verified|checked)|cannot be (verified|checked)|dogrulanamiyor|eslesme tanimli degil') {
        $decision.verdict = 'NOT_ASSESSED'
        $decision.deciding_layer = 'NONE'
        $decision.counts_in_score = $false
        $decision.reasoning = "The collector reported that it has no mapping or verification method for this control. This is a coverage gap rather than an endpoint non-compliance; it was excluded from scoring and marked NOT_ASSESSED."
    }

    # Evidence basis explains WHAT the verdict rests on, so a reader can tell a
    # policy-value comparison from a filesystem or runtime observation.
    $evidenceBasis = 'OBSERVATION'
    if (-not [string]::IsNullOrWhiteSpace([string]$expectedMeta.kind) -or -not [string]::IsNullOrWhiteSpace([string]$expectedState)) {
        $evidenceBasis = 'VALUE_COMPARISON'
    }
    elseif ($mappingClass -eq 'RUNTIME') {
        $evidenceBasis = 'RUNTIME_OBSERVATION'
    }
    if ($decision.verdict -eq 'NOT_ASSESSED') { $evidenceBasis = 'NONE' }
    if (-not $evidenceBasisDistribution.ContainsKey($evidenceBasis)) { $evidenceBasisDistribution[$evidenceBasis] = 0 }
    $evidenceBasisDistribution[$evidenceBasis]++
    $behaviorValidation = Get-BehavioralValidationMeta -Test $test -PolicyKey $policyKey -ExpectedMeta $expectedMeta -MappingClass $mappingClass -HasRuntimeSignal $hasRuntimeSignal -Layer1 $layer1 -Layer2 $layer2 -Layer3 $layer3

    $levelKey = [string]$behaviorValidation.level
    if (-not $behaviorValidationLevels.ContainsKey($levelKey)) { $levelKey = 'NONE' }
    $behaviorValidationLevels[$levelKey]++

    if ($behaviorValidation.required -and $behaviorValidation.gap) {
        $behavioralGapCount++
    }

    if ($decision.verdict -eq 'PASS' -and $behaviorValidation.required -and $behaviorValidation.gap) {
        $decision.verdict = 'PASS_NOT_ENFORCED'
        $decision.reasoning = "$([string]$decision.reasoning) Behavioral validation gap: $([string]$behaviorValidation.summary)"
    }

    # Absence of evidence is only evidence of absence when every active management
    # channel was readable. If the endpoint is managed through a channel this
    # scanner cannot read (browser-native cloud management), a missing policy is
    # unknown - not non-compliant.
    $channelSuppressed = $false
    if ($decision.verdict -eq 'FAIL' -and $evidenceIncomplete -and $layer1.state -eq 'ABSENT' -and -not $provenance.found) {
        $unreadable = @($mgmtProfile.unreadable_channels | ForEach-Object { [string]$_.channel })
        $reasons = @($mgmtProfile.unreadable_channels | ForEach-Object { [string]$_.reason })
        $decision.verdict = 'NOT_ASSESSED'
        $decision.deciding_layer = 'NONE'
        $decision.counts_in_score = $false
        $decision.reasoning = "This endpoint has a management channel that could not be read ($($unreadable -join ', ')): $($reasons -join ' '). Because the policy value could not be read locally, a 'not found' result is not evidence of non-compliance; NOT_ASSESSED was returned instead of FAIL."
        $channelSuppressed = $true
        $suppressedFails++
    }

    # An unsupported platform cannot produce any local evidence at all, so no
    # control on it may carry a compliance statement.
    if (-not $mgmtProfile.platform_supported) {
        $decision.verdict = 'NOT_ASSESSED'
        $decision.deciding_layer = 'NONE'
        $decision.counts_in_score = $false
        $decision.reasoning = "Local evidence cannot be collected for this control: $([string]$mgmtProfile.platform_note)"
        $channelSuppressed = $true
    }

    $rootCause = Get-RootCauseClassification -Decision $decision -Layer1 $layer1 -Layer2 $layer2 -Layer3 $layer3
    if ($channelSuppressed) {
        $rootCause = @{
            code           = 'RC_MANAGEMENT_CHANNEL_UNREADABLE'
            category       = 'EVIDENCE_COVERAGE'
            summary        = 'The control could not be evaluated because an active management channel could not be read on-box.'
            evidence_layer = 'NONE'
        }
    }

    $verdictCounts[$decision.verdict]++
    $decidingLayer[$decision.deciding_layer]++
    $layerStates.L1[$layer1.state]++
    $layerStates.L2[$layer2.state]++
    $layerStates.L3[$layer3.state]++
    $layerStates.L4[$layer4.state]++
    if ($decision.verdict -eq 'FAIL') {
        $rcKey = [string]$rootCause.code
        if ([string]::IsNullOrWhiteSpace($rcKey)) { $rcKey = 'RC_UNCLASSIFIED_FAIL' }
        if (-not $failRootCauseDistribution.ContainsKey($rcKey)) { $failRootCauseDistribution[$rcKey] = 0 }
        $failRootCauseDistribution[$rcKey]++
    }

    $referenceUrl = Get-ReferenceUrlForPolicyKey -Browser $Browser -PolicyKey $policyKey -CurrentReference ([string]$test.reference) -Test $test
    $riskGroup = Get-RiskGroup -Test $test -PolicyKey $policyKey
    $scenario = [string]$test.incident_scenario
    if ([string]::IsNullOrWhiteSpace($scenario)) {
        $scenario = Get-FallbackIncidentScenario -Test $test -RiskGroup $riskGroup
    }

    $testMethodOut = [string]$test.test_method
    if ([string]::IsNullOrWhiteSpace($testMethodOut)) {
        if (-not [string]::IsNullOrWhiteSpace($policyKey)) {
            $testMethodOut = "Policy key lookup ($policyKey) + layered evidence validation (L1/L2/L3)."
        } else {
            $testMethodOut = "Layered evidence validation (L1/L2/L3) + manual check guidance for $([string]$test.test_id)."
        }
    }

    $rationaleOut = [string]$test.rationale
    if ([string]::IsNullOrWhiteSpace($rationaleOut)) {
        $rationaleOut = "Bu kontrol $riskGroup alaninda is required to preserve the enterprise security baseline."
    }

    $testObj = $test | ConvertTo-Json -Depth 6 | ConvertFrom-Json
    $testObj | Add-Member -NotePropertyName 'policy_key'          -NotePropertyValue $policyKey            -Force
    $testObj | Add-Member -NotePropertyName 'policy_key_source'   -NotePropertyValue $policyKeySource      -Force
    $testObj | Add-Member -NotePropertyName 'policy_key_trusted'  -NotePropertyValue $policyKeyTrusted     -Force
    $testObj | Add-Member -NotePropertyName 'compliance_semantics' -NotePropertyValue $complianceSemantics -Force
    $testObj | Add-Member -NotePropertyName 'evidence_basis'      -NotePropertyValue $evidenceBasis        -Force
    $testObj | Add-Member -NotePropertyName 'expected_state'      -NotePropertyValue ([string]$expectedState) -Force
    $testObj | Add-Member -NotePropertyName 'expected_kind'       -NotePropertyValue ([string]$expectedMeta.kind) -Force
    $testObj | Add-Member -NotePropertyName 'expected_machine_value' -NotePropertyValue ([string]$expectedMeta.value) -Force
    $testObj | Add-Member -NotePropertyName 'layers'              -NotePropertyValue @{ L1 = $layer1; L2 = $layer2; L3 = $layer3; L4 = $layer4 } -Force
    $testObj | Add-Member -NotePropertyName 'policy_provenance'   -NotePropertyValue @{
        management_channel = $channelKey
        attribution        = [string]$provenance.attribution
        evidence_path      = [string]$provenance.evidence_path
        enforced           = [bool]$provenance.enforced
        scope              = [string]$provenance.scope
        candidate_channels = @($provenance.candidate_channels)
        notes              = [string]$provenance.notes
    } -Force
    $testObj | Add-Member -NotePropertyName 'verdict'             -NotePropertyValue $decision.verdict     -Force
    $testObj | Add-Member -NotePropertyName 'deciding_layer'      -NotePropertyValue $decision.deciding_layer -Force
    $testObj | Add-Member -NotePropertyName 'counts_in_score'     -NotePropertyValue $decision.counts_in_score -Force
    $testObj | Add-Member -NotePropertyName 'verdict_reasoning'   -NotePropertyValue $decision.reasoning   -Force
    $testObj | Add-Member -NotePropertyName 'root_cause_code'      -NotePropertyValue ([string]$rootCause.code) -Force
    $testObj | Add-Member -NotePropertyName 'root_cause_category'  -NotePropertyValue ([string]$rootCause.category) -Force
    $testObj | Add-Member -NotePropertyName 'root_cause_summary'   -NotePropertyValue ([string]$rootCause.summary) -Force
    $testObj | Add-Member -NotePropertyName 'root_cause_layer'     -NotePropertyValue ([string]$rootCause.evidence_layer) -Force
    $testObj | Add-Member -NotePropertyName 'behavioral_validation_level' -NotePropertyValue ([string]$behaviorValidation.level) -Force
    $testObj | Add-Member -NotePropertyName 'behavioral_validation_required' -NotePropertyValue ([bool]$behaviorValidation.required) -Force
    $testObj | Add-Member -NotePropertyName 'behavioral_validation_gap' -NotePropertyValue ([bool]$behaviorValidation.gap) -Force
    $testObj | Add-Member -NotePropertyName 'behavioral_validation_summary' -NotePropertyValue ([string]$behaviorValidation.summary) -Force
    $testObj | Add-Member -NotePropertyName 'drift_detected'      -NotePropertyValue $hasDriftSignal       -Force
    $testObj | Add-Member -NotePropertyName 'risk_group'          -NotePropertyValue $riskGroup            -Force
    $testObj | Add-Member -NotePropertyName 'mapping_class'       -NotePropertyValue $mappingClass          -Force
    $testObj | Add-Member -NotePropertyName 'test_method'         -NotePropertyValue $testMethodOut        -Force
    $testObj | Add-Member -NotePropertyName 'rationale'           -NotePropertyValue $rationaleOut         -Force
    $testObj | Add-Member -NotePropertyName 'reference_url'       -NotePropertyValue $referenceUrl         -Force
    if (-not [string]::IsNullOrWhiteSpace($referenceUrl)) {
        $testObj | Add-Member -NotePropertyName 'reference'       -NotePropertyValue $referenceUrl         -Force
    }
    $testObj | Add-Member -NotePropertyName 'incident_scenario'   -NotePropertyValue $scenario             -Force
    $testObj | Add-Member -NotePropertyName 'verification_timestamp' -NotePropertyValue (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -Force

    $testObj = Normalize-ResultNarrativeFields -TestObj $testObj -Decision $decision -Layer1 $layer1 -Layer2 $layer2 -Layer3 $layer3 -MappingClass $mappingClass -PolicyKey $policyKey

    $enriched += $testObj
}

$scored     = $verdictCounts.PASS + $verdictCounts.FAIL + $verdictCounts.PASS_NOT_ENFORCED
$scoreValue = if ($scored -gt 0) { [math]::Round(($verdictCounts.PASS / $scored) * 100, 1) } else { 0 }

$totalTests = [double]$allResults.Count
$assessedCoverage = if ($totalTests -gt 0) { [double]$scored / $totalTests } else { 0.0 }
$notAssessedRatio = if ($totalTests -gt 0) { [double]$verdictCounts.NOT_ASSESSED / $totalTests } else { 0.0 }

$directRatio = if ($totalTests -gt 0) { [double]$mappingStandardization.DIRECT / $totalTests } else { 0.0 }
$policyOnlyRatio = if ($totalTests -gt 0) { [double]$mappingStandardization.POLICY_ONLY / $totalTests } else { 0.0 }
$runtimeRatio = if ($totalTests -gt 0) { [double]$mappingStandardization.RUNTIME / $totalTests } else { 0.0 }
$manualRatio = if ($totalTests -gt 0) { [double]$mappingStandardization.MANUAL / $totalTests } else { 0.0 }
$unknownRatio = if ($totalTests -gt 0) { [double]$mappingStandardization.UNKNOWN / $totalTests } else { 0.0 }

# Evidence strength weights reflect confidence in machine-comparable, deterministic checks.
$evidenceStrength =
    ($directRatio * 1.00) +
    ($policyOnlyRatio * 0.60) +
    ($runtimeRatio * 0.75) +
    ($manualRatio * 0.35) +
    ($unknownRatio * 0.20)

$decisionConfidenceIndex = [math]::Round(($assessedCoverage * $evidenceStrength) * 100, 1)
$assessedCoveragePercent = [math]::Round($assessedCoverage * 100, 1)
$notAssessedPercent = [math]::Round($notAssessedRatio * 100, 1)
$evidenceStrengthPercent = [math]::Round($evidenceStrength * 100, 1)

Write-Host ""
Write-Host "PASS              : $($verdictCounts.PASS)"              -ForegroundColor Green
Write-Host "PASS_NOT_ENFORCED : $($verdictCounts.PASS_NOT_ENFORCED)" -ForegroundColor Yellow
Write-Host "FAIL              : $($verdictCounts.FAIL)"              -ForegroundColor Red
Write-Host "NOT_ASSESSED      : $($verdictCounts.NOT_ASSESSED)"      -ForegroundColor DarkGray
Write-Host "Compliance score  : $scoreValue% (PASS only, NOT_ASSESSED excluded)" -ForegroundColor Cyan
Write-Host "Decision confidence index: $decisionConfidenceIndex% (coverage x evidence strength)" -ForegroundColor Cyan
Write-Host "Fail root-cause classes: $($failRootCauseDistribution.Keys.Count) (standardized)" -ForegroundColor Cyan
Write-Host "Behavioral validation gaps: $behavioralGapCount" -ForegroundColor Yellow
Write-Host "L3 arbitrations   : $arbitrated" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Data quality - tests with no machine-comparable expectation: $noExpectation" -ForegroundColor Magenta
Write-Host "Data quality - tests with no resolvable policy key          : $noPolicyKey" -ForegroundColor Magenta
Write-Host ""

$enrichedReport = $report | ConvertTo-Json -Depth 3 | ConvertFrom-Json
$enrichedReport.results = $enriched

$enrichedReport | Add-Member -NotePropertyName 'verification_summary' -NotePropertyValue @{
    timestamp         = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    browser           = $Browser
    model             = 'Value-based comparison with evidence precedence (managed policy outranks user config)'
    total_tests       = $allResults.Count
    pass              = $verdictCounts.PASS
    pass_not_enforced = $verdictCounts.PASS_NOT_ENFORCED
    fail              = $verdictCounts.FAIL
    not_assessed      = $verdictCounts.NOT_ASSESSED
    compliance_score_percent = $scoreValue
    score_definition  = 'PASS / (PASS + PASS_NOT_ENFORCED + FAIL). NOT_ASSESSED is excluded.'
    decision_confidence_index_percent = $decisionConfidenceIndex
    decision_confidence_components = @{
        assessed_coverage_percent = $assessedCoveragePercent
        not_assessed_percent = $notAssessedPercent
        evidence_strength_percent = $evidenceStrengthPercent
        evidence_weights = @{
            DIRECT = 1.00
            POLICY_ONLY = 0.60
            RUNTIME = 0.75
            MANUAL = 0.35
            UNKNOWN = 0.20
        }
    }
    root_cause_standard = 'v2: RC_POLICY_NOT_DEPLOYED, RC_POLICY_VALUE_MISMATCH, RC_POLICY_ABSENT_USER_MISMATCH, RC_CONTROL_UNCONFIGURED, RC_RUNTIME_CONTRADICTION, RC_USER_VALUE_MISMATCH, RC_USER_SETTING_MISSING, RC_MANAGEMENT_CHANNEL_UNREADABLE, RC_UNCLASSIFIED_FAIL'
    fail_root_cause_distribution = $failRootCauseDistribution
    behavioral_validation_summary = @{
        policy_object_behavior_gap_count = $behavioralGapCount
        levels = @{
            STRONG = $behaviorValidationLevels.STRONG
            MODERATE = $behaviorValidationLevels.MODERATE
            LIMITED = $behaviorValidationLevels.LIMITED
            NONE = $behaviorValidationLevels.NONE
            NOT_REQUIRED = $behaviorValidationLevels.NOT_REQUIRED
        }
        policy = 'For policy-object or presence/configured controls, PASS is downgraded to PASS_NOT_ENFORCED when only weak/no behavioral evidence exists.'
    }
    enforcement_gap   = $verdictCounts.PASS_NOT_ENFORCED
    l3_arbitrations   = $arbitrated
} -Force

$enrichedReport | Add-Member -NotePropertyName 'data_quality' -NotePropertyValue @{
    tests_without_comparable_expectation  = $noExpectation
    tests_without_resolvable_policy_key   = $noPolicyKey
    no_machine_comparable_expectation     = $noExpectation
    no_resolvable_policy_key              = $noPolicyKey
    policy_key_source_distribution        = $policyKeySourceDistribution
    tests_with_inferred_policy_key        = $untrustedKeyCount
    evidence_basis_distribution           = $evidenceBasisDistribution
    evidence_basis_definition             = 'VALUE_COMPARISON: verdict rests on expected-vs-actual policy or preference values. RUNTIME_OBSERVATION: verdict rests on live process inspection. OBSERVATION: verdict rests on a deterministic filesystem or profile observation without a policy expectation. NONE: control was not assessed.'
    policy_key_source_definition          = 'RUNNER_DECLARED and CONTROL_MAP and REFERENCE_ANCHOR and STATIC_TABLE are verified mappings. INFERRED_FROM_TEXT is a heuristic guess taken from prose: it is shown for remediation context only and is never used as evidence.'
    note = 'These tests cannot support a value comparison at the user layer. Fix the test runner to emit expected_value so they can be scored instead of falling back to weaker evidence.'
} -Force

$enrichedReport | Add-Member -NotePropertyName 'mapping_standardization' -NotePropertyValue @{
    DIRECT       = $mappingStandardization.DIRECT
    POLICY_ONLY  = $mappingStandardization.POLICY_ONLY
    RUNTIME      = $mappingStandardization.RUNTIME
    MANUAL       = $mappingStandardization.MANUAL
    UNKNOWN      = $mappingStandardization.UNKNOWN
    note         = 'DIRECT means policy key + machine-comparable expectation exist. Chromium controls first use family-specific deterministic mapping (bool/enum/numeric) and only use present=true as last-resort fallback. POLICY_ONLY means a policy key exists but no deterministic comparison was emitted. RUNTIME means command-line/runtime evidence was used. MANUAL means the control is intentionally not machine-mapped.'
} -Force

$enrichedReport | Add-Member -NotePropertyName 'layer_evidence_summary' -NotePropertyValue @{
    L1 = @{ description = 'Managed policy (registry policy path - GPO / MDM ADMX ingestion / agent) - enforced'; states = $layerStates.L1 }
    L2 = @{ description = 'User-level configuration (Preferences / prefs.js) - user-revertible';                 states = $layerStates.L2 }
    L3 = @{ description = 'Runtime arbiter - invoked only on managed/user conflict';                             states = $layerStates.L3 }
    L4 = @{ description = 'MDM policy CSP store (PolicyManager) - enforced, device scope';                       states = $layerStates.L4 }
    deciding_layer_distribution = $decidingLayer
} -Force

$enrichedReport | Add-Member -NotePropertyName 'management_context' -NotePropertyValue @{
    hostname                = $mgmtProfile.hostname
    platform                = $mgmtProfile.platform
    platform_supported      = $mgmtProfile.platform_supported
    platform_note           = $mgmtProfile.platform_note
    elevated                = $mgmtProfile.elevated
    policy_store_access     = $mgmtProfile.policy_store_access
    domain_joined           = $mgmtProfile.domain_joined
    entra_joined            = $mgmtProfile.entra_joined
    entra_registered        = $mgmtProfile.entra_registered
    mdm_enrolled            = $mgmtProfile.mdm.enrolled
    mdm_provider            = $mgmtProfile.mdm.provider
    mdm_management_url      = $mgmtProfile.mdm.management_url
    admx_ingestion_present  = $mgmtProfile.admx_ingestion.present
    cloud_management        = $mgmtProfile.cloud_management
    detected_agents         = @($mgmtProfile.agents)
    active_channels         = $activeChannels
    readable_channels       = $mgmtProfile.readable_channels
    unreadable_channels     = @($mgmtProfile.unreadable_channels)
    evidence_coverage_complete = (-not $evidenceIncomplete)
    policy_channel_distribution = $channelDistribution
    mdm_sourced_controls    = $mdmSourcedControls
    fails_suppressed_by_channel_gap = $suppressedFails
    note = 'Enterprise browsers are managed through several channels. A value under a registry policy path is provably enforced, but the delivering channel (GPO, MDM ADMX ingestion, management agent) can only be attributed when a single channel is active. Ambiguity is reported, never guessed.'
} -Force

$enrichedReport | Add-Member -NotePropertyName 'roadmap' -NotePropertyValue @{
    note = 'L4 and L5 are additional evidence sources in the same precedence chain. They add no new verdict states, so no logic change is required when they are introduced.'
    L4_MDM   = @{ status = 'IMPLEMENTED'; rank = 'managed'; sources = @('MDM policy CSP store (PolicyManager)', 'MDM ADMX ingestion', 'Management agents') }
    L5_CLOUD = @{ status = 'DETECTED_NOT_READABLE'; rank = 'managed'; sources = @('Chrome Browser Cloud Management', 'Microsoft Edge management service'); handling = 'Enrollment is detected and reported. Values are not persisted on-box, so affected controls are returned NOT_ASSESSED instead of FAIL.' }
} -Force

$enrichedReport | ConvertTo-Json -Depth 12 | Out-File $OutputFile -Encoding UTF8
Write-Host "Saved: $OutputFile ($((Get-Item $OutputFile).Length) bytes)" -ForegroundColor Green

