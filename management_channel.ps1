<#
Management Channel Resolver

Purpose:
  Browser policy in an enterprise is not delivered only through Group Policy.
  The same registry value can originate from GPO, from an MDM (Intune ADMX
  ingestion / Settings Catalog), from a third-party agent (ManageEngine,
  Workspace ONE, ConfigMgr), or from a browser-native cloud management service
  (Chrome Browser Cloud Management / Microsoft Edge management service).

  A verification engine that only reads HKLM\SOFTWARE\Policies\... cannot tell
  these apart, and - worse - it reports FAIL for endpoints whose policy is
  delivered through a channel it never looked at. That is a false negative, and
  a false negative in a compliance report is worse than no report.

  This module provides:
    1. Device-level management profile (which channels are active).
    2. Policy-level evidence resolution across every readable channel, with
       provenance.
    3. An explicit list of ACTIVE BUT UNREADABLE channels, so the verdict engine
       can return NOT_ASSESSED instead of inventing a FAIL.

Design rule:
  Never claim a channel delivered a policy unless there is evidence for it.
  When attribution is ambiguous, say MANAGED_CHANNEL_AMBIGUOUS - not GPO.
#>

# ---------------------------------------------------------------------------
# Channel vocabulary
# ---------------------------------------------------------------------------
# MDM_CSP                    value read from the MDM PolicyManager CSP store
# MDM_ADMX_INGESTED          Policies path value, device is MDM enrolled with ADMX ingestion
# GPO_MACHINE                Policies path value on a domain-joined device, no MDM ADMX evidence
# GPO_MACHINE_WOW6432        same, 32-bit registry view
# GPO_USER                   HKCU Policies path
# MANAGED_CHANNEL_AMBIGUOUS  managed path value, but no channel can be proven
# LOCAL_OR_AGENT             managed path value on a device with no GPO and no MDM
# ENTERPRISE_FILE            Firefox distribution\policies.json
# CLOUD_UNREADABLE           browser-native cloud management is enrolled, values not on disk
# NONE                       not found in any readable channel

$script:BrowserPolicyRoots = @{
    Edge = @(
        @{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge';             channel = 'GPO_MACHINE';         enforced = $true;  scope = 'machine' }
        @{ path = 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Edge'; channel = 'GPO_MACHINE_WOW6432'; enforced = $true;  scope = 'machine' }
        @{ path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge';             channel = 'GPO_USER';            enforced = $true;  scope = 'user' }
    )
    Chrome = @(
        @{ path = 'HKLM:\SOFTWARE\Policies\Google\Chrome';             channel = 'GPO_MACHINE';         enforced = $true;  scope = 'machine' }
        @{ path = 'HKLM:\SOFTWARE\WOW6432Node\Policies\Google\Chrome'; channel = 'GPO_MACHINE_WOW6432'; enforced = $true;  scope = 'machine' }
        @{ path = 'HKCU:\SOFTWARE\Policies\Google\Chrome';             channel = 'GPO_USER';            enforced = $true;  scope = 'user' }
    )
    Firefox = @(
        @{ path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox';             channel = 'GPO_MACHINE';         enforced = $true; scope = 'machine' }
        @{ path = 'HKLM:\SOFTWARE\WOW6432Node\Policies\Mozilla\Firefox'; channel = 'GPO_MACHINE_WOW6432'; enforced = $true; scope = 'machine' }
        @{ path = 'HKCU:\SOFTWARE\Policies\Mozilla\Firefox';             channel = 'GPO_USER';            enforced = $true; scope = 'user' }
    )
}

# ADMX namespace fragments used as PolicyManager CSP area names.
$script:BrowserCspAreaPatterns = @{
    Edge    = @('microsoft_edge', 'microsoftedge')
    Chrome  = @('googlechrome', 'google~policy')
    Firefox = @('firefox', 'mozilla')
}

# Browser-native cloud management enrolment markers. Policy values delivered by
# these services are fetched at runtime and are NOT written to the registry.
$script:BrowserCloudMarkers = @{
    Edge = @(
        @{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge';     value = 'CloudManagementEnrollmentToken'; service = 'Microsoft Edge management service' }
        @{ path = 'HKLM:\SOFTWARE\Microsoft\Edge';              value = 'CloudManagementEnrollmentToken'; service = 'Microsoft Edge management service' }
    )
    Chrome = @(
        @{ path = 'HKLM:\SOFTWARE\Policies\Google\Chrome';      value = 'CloudManagementEnrollmentToken'; service = 'Chrome Browser Cloud Management' }
        @{ path = 'HKLM:\SOFTWARE\Google\Chrome\CloudManagement'; value = 'EnrollmentToken';              service = 'Chrome Browser Cloud Management' }
        @{ path = 'HKLM:\SOFTWARE\WOW6432Node\Google\Chrome\CloudManagement'; value = 'EnrollmentToken';  service = 'Chrome Browser Cloud Management' }
    )
    Firefox = @()
}

# Third-party configuration-management agents that write to the same registry
# paths as GPO. Their presence makes GPO attribution ambiguous.
$script:AgentMarkers = @(
    @{ name = 'Microsoft Configuration Manager'; path = 'HKLM:\SOFTWARE\Microsoft\CCM' }
    @{ name = 'ManageEngine';                    path = 'HKLM:\SOFTWARE\WOW6432Node\AdventNet' }
    @{ name = 'ManageEngine';                    path = 'HKLM:\SOFTWARE\AdventNet' }
    @{ name = 'VMware Workspace ONE';            path = 'HKLM:\SOFTWARE\AirWatch' }
    @{ name = 'VMware Workspace ONE';            path = 'HKLM:\SOFTWARE\WOW6432Node\AirWatch' }
    @{ name = 'Ivanti / LANDesk';                path = 'HKLM:\SOFTWARE\LANDesk' }
    @{ name = 'Tanium';                          path = 'HKLM:\SOFTWARE\Tanium' }
)

function Get-RegistryValueSafe {
    <#
      Registry value names are case-insensitive in Windows, but Get-ItemProperty
      -Name matches case-sensitively. Policy keys arriving from CIS text or from
      inference are frequently lower-cased, so an exact-name miss must fall back
      to a case-insensitive property scan before concluding "not configured".
    #>
    param([string]$Path, [string]$Name)

    $out = @{ found = $false; value = $null; type = ''; matched_name = '' }
    if (-not (Test-Path $Path)) { return $out }

    try {
        $item = Get-ItemProperty -Path $Path -ErrorAction Stop
        $property = $item.PSObject.Properties |
                    Where-Object { $_.Name -notlike 'PS*' -and $_.Name -eq $Name } |
                    Select-Object -First 1
        if (-not $property) {
            $property = $item.PSObject.Properties |
                        Where-Object { $_.Name -notlike 'PS*' -and $_.Name -ieq $Name } |
                        Select-Object -First 1
        }

        if ($property) {
            $out.found        = $true
            $out.value        = $property.Value
            $out.matched_name = $property.Name
            try {
                $out.type = [string](Get-Item -Path $Path -ErrorAction Stop).GetValueKind($property.Name)
            }
            catch {
                $out.type = 'Unknown'
            }
            return $out
        }
    }
    catch {
        $out.found = $false
    }

    if (-not $out.found) {
        # Chromium list policies are stored as a subkey with numbered values.
        $childPath = Join-Path $Path $Name
        if (Test-Path $childPath) {
            try {
                $child = Get-ItemProperty -Path $childPath -ErrorAction Stop
                $values = @($child.PSObject.Properties |
                            Where-Object { $_.Name -notlike 'PS*' } |
                            ForEach-Object { [string]$_.Value })
                if ($values.Count -gt 0) {
                    $out.found        = $true
                    $out.value        = $values
                    $out.type         = 'ListSubkey'
                    $out.matched_name = $Name
                }
            }
            catch {
                $out.found = $false
            }
        }
    }

    return $out
}

function Get-MdmEnrollmentState {
    <#
      Detects a real MDM enrollment. Windows ships several built-in placeholder
      enrollment GUIDs (Local Authority / Cloud Authority / Deploy Authority),
      so EnrollmentState=1 alone is NOT proof of MDM management.
      A genuine enrollment carries a discovery/management service URL.
    #>
    $state = @{
        enrolled       = $false
        provider       = ''
        management_url = ''
        upn            = ''
        enrollment_id  = ''
        evidence       = @()
    }

    $root = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    if (-not (Test-Path $root)) { return $state }

    foreach ($key in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
        $props = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
        if (-not $props) { continue }

        $url = [string]$props.DiscoveryServiceFullURL
        if ([string]::IsNullOrWhiteSpace($url)) { $url = [string]$props.ManagementServiceAddress }
        if ([string]::IsNullOrWhiteSpace($url)) { continue }

        $state.enrolled       = $true
        $state.provider       = [string]$props.ProviderID
        $state.management_url = $url
        $state.upn            = [string]$props.UPN
        $state.enrollment_id  = [string]$key.PSChildName
        $state.evidence      += "$($key.PSPath) DiscoveryServiceFullURL=$url"
        break
    }

    return $state
}
function Get-AdmxIngestionState {
    <#
      Intune "Administrative Templates" / imported ADMX policies are tracked under
      PolicyManager\AdmxInstalled and are written to the ADMX-defined registry
      path - i.e. the same HKLM\SOFTWARE\Policies\... location GPO uses.
      Presence of an ingested ADMX for a browser is what lets us attribute a
      Policies-path value to MDM rather than GPO.
    #>
    param([string]$Browser)

    $state = @{ present = $false; apps = @(); evidence = @() }

    $root = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled'
    if (-not (Test-Path $root)) { return $state }

    $patterns = $script:BrowserCspAreaPatterns[$Browser]
    if (-not $patterns) { $patterns = @() }

    foreach ($enrollment in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
        foreach ($app in (Get-ChildItem $enrollment.PSPath -ErrorAction SilentlyContinue)) {
            $name = [string]$app.PSChildName
            $state.apps += $name
            foreach ($pattern in $patterns) {
                if ($name -like "*$pattern*") {
                    $state.present   = $true
                    $state.evidence += $app.PSPath
                }
            }
        }
    }

    $state.apps = @($state.apps | Select-Object -Unique)
    return $state
}

function Get-CspPolicyEvidence {
    <#
      Reads the MDM CSP policy store. Values delivered through OMA-URI /
      Settings Catalog are mirrored here per enrollment.
    #>
    param([string]$Browser, [string]$PolicyKey)

    $out = @{ found = $false; value = $null; path = ''; area = '' }
    if ([string]::IsNullOrWhiteSpace($PolicyKey)) { return $out }

    $patterns = $script:BrowserCspAreaPatterns[$Browser]
    if (-not $patterns) { return $out }

    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device'
        'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\PolicyState'
    )
    foreach ($provider in (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\PolicyManager\providers' -ErrorAction SilentlyContinue)) {
        $roots += (Join-Path $provider.PSPath 'default\Device')
    }

    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($area in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
            $areaName = [string]$area.PSChildName
            $match = $false
            foreach ($pattern in $patterns) {
                if ($areaName -like "*$pattern*") { $match = $true }
            }
            if (-not $match) { continue }

            $lookup = Get-RegistryValueSafe -Path $area.PSPath -Name $PolicyKey
            if ($lookup.found) {
                $out.found = $true
                $out.value = $lookup.value
                $out.path  = "$($area.PSPath)\$PolicyKey"
                $out.area  = $areaName
                return $out
            }
        }
    }

    return $out
}

function Get-BrowserCloudManagementState {
    <#
      Cloud-managed browsers receive policy over the network. Nothing is written
      to the registry, so an on-box scanner CANNOT read those values. When this
      returns enrolled=$true, "policy not found" must never be reported as FAIL.
    #>
    param([string]$Browser)

    $state = @{ enrolled = $false; service = ''; evidence = @(); readable = $false }

    $markers = $script:BrowserCloudMarkers[$Browser]
    if (-not $markers) { return $state }

    foreach ($marker in $markers) {
        $lookup = Get-RegistryValueSafe -Path $marker.path -Name $marker.value
        if ($lookup.found -and -not [string]::IsNullOrWhiteSpace([string]$lookup.value)) {
            $state.enrolled  = $true
            $state.service   = $marker.service
            $state.evidence += "$($marker.path)\$($marker.value) is set"
        }
    }

    return $state
}

function Get-PlatformState {
    <#
      Collection is registry-based and therefore Windows-only. On any other
      platform the correct answer is "this endpoint was not assessed", not a set
      of failures produced by paths that cannot exist.
      $IsWindows only exists on PowerShell 6+, so its absence implies Windows.
    #>
    $state = @{ os = 'Windows'; supported = $true; reason = '' }

    if (Test-Path Variable:\IsWindows) {
        if (-not [bool](Get-Variable -Name IsWindows -ValueOnly)) {
            $state.supported = $false
            if (Test-Path Variable:\IsMacOS) {
                if ([bool](Get-Variable -Name IsMacOS -ValueOnly)) { $state.os = 'macOS' }
            }
            if ($state.os -eq 'Windows') { $state.os = 'Linux' }
            $state.reason = "Policy collection reads the Windows registry. On $($state.os) browser policy lives in configuration profiles or JSON policy files, which this collector does not read."
        }
    }

    return $state
}

function Test-PolicyStoreAccess {
    <#
      Distinguishes "the policy is not configured" from "this process may not read
      the policy store". Both look identical to Test-Path, and conflating them
      turns a permission problem into a wall of false failures.
    #>
    param([string]$Browser)

    $state = @{ readable = $true; denied_paths = @(); probed = @() }

    $roots = $script:BrowserPolicyRoots[$Browser]
    if (-not $roots) { return $state }

    $containers = @()
    foreach ($root in $roots) {
        $containers += (Split-Path -Path $root.path -Parent)
    }
    $containers += 'HKLM:\SOFTWARE\Microsoft\PolicyManager'
    $containers = @($containers | Select-Object -Unique)

    foreach ($container in $containers) {
        $state.probed += $container
        try {
            if (Test-Path $container) {
                Get-ChildItem -Path $container -ErrorAction Stop | Out-Null
            }
        }
        catch [System.Security.SecurityException] {
            $state.readable = $false
            $state.denied_paths += $container
        }
        catch [System.UnauthorizedAccessException] {
            $state.readable = $false
            $state.denied_paths += $container
        }
        catch {
            # Any other failure (missing key, provider error) is not a permission
            # problem and must not be reported as one.
            continue
        }
    }

    return $state
}

function Get-DeviceManagementProfile {
    <#
      One-shot description of every management channel that can deliver browser
      policy to this endpoint, and whether this scanner can read it.
    #>
    param([string]$Browser)

    $mgmt = @{
        hostname            = $env:COMPUTERNAME
        platform            = 'Windows'
        platform_supported  = $true
        platform_note       = ''
        elevated            = $false
        policy_store_access = @{ readable = $true; denied_paths = @() }
        domain_joined       = $false
        entra_joined        = $false
        entra_registered    = $false
        mdm                 = (Get-MdmEnrollmentState)
        admx_ingestion      = (Get-AdmxIngestionState -Browser $Browser)
        cloud_management    = (Get-BrowserCloudManagementState -Browser $Browser)
        agents              = @()
        readable_channels   = @()
        unreadable_channels = @()
        collected_at        = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    }

    $platform = Get-PlatformState
    $mgmt.platform           = $platform.os
    $mgmt.platform_supported = $platform.supported
    $mgmt.platform_note      = $platform.reason
    if (-not $platform.supported) {
        $mgmt.unreadable_channels += @{
            channel = 'UNSUPPORTED_PLATFORM'
            service = $platform.os
            reason  = $platform.reason
            impact  = 'No control can be decided from local evidence on this platform; every control is reported NOT_ASSESSED.'
        }
        return $mgmt
    }

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $mgmt.elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        $mgmt.elevated = $false
    }

    $access = Test-PolicyStoreAccess -Browser $Browser
    $mgmt.policy_store_access = @{ readable = $access.readable; denied_paths = @($access.denied_paths) }
    if (-not $access.readable) {
        $mgmt.unreadable_channels += @{
            channel = 'REGISTRY_ACCESS_DENIED'
            service = 'Windows registry policy store'
            reason  = "The current security context cannot enumerate: $(@($access.denied_paths) -join ', ')."
            impact  = 'Controls with no readable policy evidence are reported NOT_ASSESSED instead of FAIL. Re-run with sufficient privileges for a scored result.'
        }
    }

    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $mgmt.domain_joined = [bool]$cs.PartOfDomain
    }
    catch {
        $mgmt.domain_joined = $false
    }

    try {
        $dsreg = & dsregcmd.exe /status 2>$null
        foreach ($line in $dsreg) {
            if ($line -match '(?i)AzureAdJoined\s*:\s*YES')   { $mgmt.entra_joined = $true }
            if ($line -match '(?i)WorkplaceJoined\s*:\s*YES') { $mgmt.entra_registered = $true }
            if ($line -match '(?i)MdmUrl\s*:\s*\S+')          { $mgmt.mdm.enrolled = $true }
        }
    }
    catch {
        # dsregcmd is unavailable on non-domain SKUs; join state stays as detected.
    }

    foreach ($marker in $script:AgentMarkers) {
        if (Test-Path $marker.path) {
            $mgmt.agents += @{ name = $marker.name; evidence = $marker.path }
        }
    }

    $mgmt.readable_channels += 'REGISTRY_POLICIES (GPO / MDM ADMX ingestion / agent-written)'
    $mgmt.readable_channels += 'REGISTRY_CSP (MDM PolicyManager store)'
    $mgmt.readable_channels += 'USER_PREFERENCES (Preferences / prefs.js)'
    $mgmt.readable_channels += 'RUNTIME (process command line)'
    if ($Browser -eq 'Firefox') {
        $mgmt.readable_channels += 'ENTERPRISE_FILE (distribution\policies.json)'
    }

    if ($mgmt.cloud_management.enrolled) {
        $mgmt.unreadable_channels += @{
            channel = 'CLOUD_BROWSER_MANAGEMENT'
            service = $mgmt.cloud_management.service
            reason  = 'Policy is delivered over the network at runtime and is not persisted to the registry. On-box registry evidence is incomplete for this endpoint.'
            impact  = 'Controls with no local policy evidence are reported NOT_ASSESSED instead of FAIL.'
        }
    }

    return $mgmt
}

function Resolve-ManagedPolicyEvidence {
    <#
      Resolves a single policy key across every readable managed channel and
      returns the value together with its provenance.

      Precedence: MDM CSP store, then machine policy paths, then user policy path.
      Attribution is deliberately conservative - when several channels could have
      written the same Policies-path value, the channel is reported as ambiguous
      with the candidate list, rather than being guessed.
    #>
    param(
        [string]$Browser,
        [string]$PolicyKey,
        [hashtable]$ManagementProfile
    )

    $out = @{
        found              = $false
        value              = $null
        channel            = 'NONE'
        evidence_path      = ''
        enforced           = $false
        scope              = ''
        attribution        = 'NOT_FOUND'
        candidate_channels = @()
        notes              = ''
    }

    if ([string]::IsNullOrWhiteSpace($PolicyKey)) {
        $out.notes = 'No policy key resolved for this control; managed-channel lookup skipped.'
        return $out
    }

    $csp = Get-CspPolicyEvidence -Browser $Browser -PolicyKey $PolicyKey
    if ($csp.found) {
        $out.found         = $true
        $out.value         = $csp.value
        $out.channel       = 'MDM_CSP'
        $out.evidence_path = $csp.path
        $out.enforced      = $true
        $out.scope         = 'device'
        $out.attribution   = 'PROVEN'
        $out.notes         = "Delivered through the MDM policy CSP store (area: $($csp.area))."
        return $out
    }

    $roots = $script:BrowserPolicyRoots[$Browser]
    if (-not $roots) { return $out }

    foreach ($root in $roots) {
        $lookup = Get-RegistryValueSafe -Path $root.path -Name $PolicyKey
        if (-not $lookup.found) { continue }

        $out.found         = $true
        $out.value         = $lookup.value
        $out.evidence_path = "$($root.path)\$PolicyKey"
        $out.enforced      = $root.enforced
        $out.scope         = $root.scope

        $candidates = @()
        if ($ManagementProfile -and $ManagementProfile.mdm.enrolled -and $ManagementProfile.admx_ingestion.present) { $candidates += 'MDM_ADMX_INGESTED' }
        if ($ManagementProfile -and $ManagementProfile.domain_joined) { $candidates += 'GPO' }
        foreach ($agent in @($ManagementProfile.agents)) { $candidates += "AGENT:$($agent.name)" }

        $out.candidate_channels = @($candidates | Select-Object -Unique)

        if ($out.candidate_channels.Count -eq 1) {
            $out.channel     = $out.candidate_channels[0]
            $out.attribution = 'INFERRED_SINGLE_CHANNEL'
            $out.notes       = "Value found at a managed policy path; only one management channel is active on this device."
        }
        elseif ($out.candidate_channels.Count -gt 1) {
            $out.channel     = 'MANAGED_CHANNEL_AMBIGUOUS'
            $out.attribution = 'AMBIGUOUS'
            $out.notes       = "Value is enforced, but several channels can write this path: $($out.candidate_channels -join ', '). Enforcement is proven; the delivering channel is not."
        }
        else {
            $out.channel     = 'LOCAL_OR_AGENT'
            $out.attribution = 'INFERRED_LOCAL'
            $out.notes       = 'Value found at a managed policy path on a device with no detected domain or MDM management.'
        }

        return $out
    }

    $out.notes = 'Policy key not present in any readable managed channel (CSP store, machine policy paths, user policy path).'
    return $out
}

function Test-ManagedEvidenceIsIncomplete {
    <#
      True when the endpoint has an ACTIVE management channel this scanner cannot
      read. In that state "policy not found" is not proof of non-compliance, so
      the verdict engine must return NOT_ASSESSED instead of FAIL.
    #>
    param([hashtable]$ManagementProfile)

    if (-not $ManagementProfile) { return $false }
    $result = (@($ManagementProfile.unreadable_channels).Count -gt 0)
    return $result
}
