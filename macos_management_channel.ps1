function Get-MacOSBrowserDomains {
    param([string]$Browser)

    switch ($Browser) {
        'Chrome'  { return @('com.google.Chrome') }
        'Edge'    { return @('com.microsoft.Edge') }
        'Firefox' { return @('org.mozilla.firefox') }
        default   { return @() }
    }
}

function Get-MacOSPreferenceValue {
    param([string]$Path, [string]$Name)

    $result = @{ found = $false; value = $null }
    if (-not (Test-Path -LiteralPath $Path)) { return $result }

    try {
        $value = & /usr/bin/plutil -extract $Name raw -o - -- $Path 2>$null
        if ($LASTEXITCODE -eq 0) {
            $result.found = $true
            $result.value = [string]($value -join '')
        }
    }
    catch {
        Write-Verbose "plutil extract failed for '$Name' in '$Path': $($_.Exception.Message)"
    }

    return $result
}

function Get-MacOSEffectiveUid {
    try {
        $uid = & /usr/bin/id -u 2>$null
        if ($LASTEXITCODE -eq 0) { return [int]([string]$uid).Trim() }
    }
    catch {
        Write-Verbose "Effective uid lookup failed: $($_.Exception.Message)"
    }

    return -1
}

function Get-MacOSManagementProfile {
    param([string]$Browser)

    $managementProfile = @{
        hostname            = ''
        platform            = 'macOS'
        platform_supported  = $true
        platform_note       = 'macOS management evidence is collected from managed preferences and configuration profiles.'
        elevated            = $false
        policy_store_access = @{ readable = $true; denied_paths = @() }
        domain_joined       = $false
        entra_joined        = $false
        entra_registered    = $false
        mdm                 = @{ enrolled = $false; provider = ''; management_url = ''; upn = ''; enrollment_id = ''; evidence = @() }
        admx_ingestion      = @{ present = $false; apps = @(); evidence = @() }
        cloud_management    = @{ enrolled = $false; service = ''; evidence = @(); readable = $false }
        agents              = @()
        readable_channels   = @()
        unreadable_channels = @()
        collected_at        = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    }

    $uid = Get-MacOSEffectiveUid
    $managementProfile.elevated = ($uid -eq 0)
    $domains = @(Get-MacOSBrowserDomains -Browser $Browser)
    $managedPaths = @()
    $localPaths = @()
    $userPaths = @()
    $userHome = $HOME
    if ([string]::IsNullOrWhiteSpace([string]$userHome)) {
        $userHome = [Environment]::GetFolderPath('UserProfile')
    }

    foreach ($domain in $domains) {
        $managedPaths += Join-Path '/Library/Managed Preferences' "$domain.plist"
        $localPaths += Join-Path '/Library/Preferences' "$domain.plist"
        $userPaths += Join-Path $userHome "Library/Preferences/$domain.plist"
    }

    $managedRoot = '/Library/Managed Preferences'
    foreach ($userDirectory in @(Get-ChildItem -LiteralPath $managedRoot -Directory -ErrorAction SilentlyContinue)) {
        foreach ($domain in $domains) {
            $managedPaths += Join-Path $userDirectory.FullName "$domain.plist"
        }
    }

    $enforcedChannels = @()
    foreach ($path in $managedPaths) {
        if (Test-Path -LiteralPath $path) {
            if ($path -like '/Library/Managed Preferences/*/*') {
                $channel = 'MDM_MANAGED_PREFERENCES_USER'
            }
            else {
                $channel = 'MDM_MANAGED_PREFERENCES'
            }
            $managementProfile.readable_channels += $channel
            $enforcedChannels += $channel
        }
    }
    foreach ($path in $localPaths) {
        if (Test-Path -LiteralPath $path) { $managementProfile.readable_channels += 'LOCAL_ADMIN_PREFERENCE' }
    }
    foreach ($path in $userPaths) {
        if (Test-Path -LiteralPath $path) { $managementProfile.readable_channels += 'USER_PREFERENCE' }
    }

    $profilesCommand = Get-Command profiles -ErrorAction SilentlyContinue
    if (-not $managementProfile.elevated) {
        $managementProfile.unreadable_channels += @{
            channel = 'MDM_PROFILE_UNREADABLE'
            service = 'macOS Configuration Profiles'
            reason  = 'Configuration profile inventory requires an effective uid of 0.'
            impact  = 'Controls delivered through configuration profiles are reported NOT_ASSESSED until the inventory is readable.'
        }
    }
    elseif (-not $profilesCommand) {
        $managementProfile.unreadable_channels += @{
            channel = 'MDM_PROFILE_UNREADABLE'
            service = 'macOS Configuration Profiles'
            reason  = 'The macOS profiles command is unavailable.'
            impact  = 'Configuration profile evidence could not be collected.'
        }
    }
    else {
        try {
            $inventory = & $profilesCommand.Source -C -o stdout-xml 2>$null
            if ($LASTEXITCODE -ne 0) { throw 'profiles command failed' }
            if (-not [string]::IsNullOrWhiteSpace(($inventory -join ''))) {
                $managementProfile.readable_channels += 'MDM_PROFILE'
                $managementProfile.mdm.enrolled = $true
                $managementProfile.mdm.provider = 'macOS Configuration Profiles'
                $managementProfile.mdm.evidence = @('profiles -C -o stdout-xml')
            }
        }
        catch {
            $managementProfile.unreadable_channels += @{
                channel = 'MDM_PROFILE_UNREADABLE'
                service = 'macOS Configuration Profiles'
                reason  = 'The configuration profile inventory could not be read.'
                impact  = 'Configuration profile evidence could not be collected.'
            }
        }
    }

    $cloudTokenFound = $false
    foreach ($path in @($managedPaths + $localPaths + $userPaths)) {
        $token = Get-MacOSPreferenceValue -Path $path -Name 'CloudManagementEnrollmentToken'
        if ($token.found) { $cloudTokenFound = $true }
    }
    if ($cloudTokenFound) {
        $managementProfile.cloud_management.enrolled = $true
        $managementProfile.cloud_management.service = 'Chrome Browser Cloud Management'
        $managementProfile.cloud_management.evidence = @('com.google.Chrome:CloudManagementEnrollmentToken')
        $managementProfile.unreadable_channels += @{
            channel = 'CLOUD_MANAGED'
            service = 'Chrome Browser Cloud Management'
            reason  = 'Cloud management policy is delivered over the network and is not readable from local preference evidence.'
            impact  = 'Controls with no local policy evidence are reported NOT_ASSESSED instead of FAIL.'
        }
    }

    $enforcedChannels = @($enforcedChannels | Select-Object -Unique)
    if ($managementProfile.mdm.enrolled) { $enforcedChannels += 'MDM_PROFILE' }
    $enforcedChannels = @($enforcedChannels | Select-Object -Unique)
    if ($enforcedChannels.Count -gt 1) {
        $managementProfile.readable_channels += 'MANAGED_CHANNEL_AMBIGUOUS'
    }

    $managementProfile.readable_channels = @($managementProfile.readable_channels | Select-Object -Unique)
    return $managementProfile
}