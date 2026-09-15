# macOS evidence helpers shared by browser-specific collectors.
# PowerShell 7 only; functions remain loadable on non-macOS hosts.

function Get-MacEvidenceResult {
    param(
        [bool]$Found = $false,
        $Value = $null,
        [string]$SourcePath = '',
        [bool]$AccessDenied = $false
    )

    return @{
        found        = $Found
        value        = $Value
        source_path  = $SourcePath
        access_denied = $AccessDenied
    }
}

function Test-MacReadAccess {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $result = @{
        exists        = $false
        readable      = $false
        access_denied = $false
    }

    if ([string]::IsNullOrWhiteSpace($Path)) { return $result }

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $result.exists = $true

        if ($item.PSIsContainer) {
            Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop | Out-Null
            $result.readable = $true
            return $result
        }

        $stream = [System.IO.File]::Open($item.FullName, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $stream.Dispose()
        $result.readable = $true
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        return $result
    }
    catch [System.UnauthorizedAccessException] {
        $result.access_denied = $true
    }
    catch [System.IO.FileNotFoundException] {
        return $result
    }
    catch [System.IO.DirectoryNotFoundException] {
        return $result
    }
    catch [System.Security.SecurityException] {
        $result.access_denied = $true
    }
    catch [System.IO.IOException] {
        # An existing path that cannot be opened is unreadable, including TCC denial.
        $result.access_denied = $true
    }

    return $result
}

function ConvertFrom-MacPlistJson {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [string]$PlutilPath = '/usr/bin/plutil'
    )

    $access = Test-MacReadAccess -Path $Path
    if (-not $access.exists) {
        return @{ state = 'missing'; value = $null }
    }
    if (-not $access.readable) {
        return @{ state = 'access_denied'; value = $null }
    }

    $plutil = Get-Command -Name $PlutilPath -ErrorAction SilentlyContinue
    if (-not $plutil -and -not (Test-Path -LiteralPath $PlutilPath -PathType Leaf)) {
        return @{ state = 'unavailable'; value = $null }
    }

    try {
        $json = & $PlutilPath -convert json -o - -- $Path 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($json -join ''))) {
            return @{ state = 'unreadable'; value = $null }
        }
        return @{ state = 'read'; value = ($json -join "`n" | ConvertFrom-Json -ErrorAction Stop) }
    }
    catch [System.UnauthorizedAccessException] {
        return @{ state = 'access_denied'; value = $null }
    }
    catch {
        return @{ state = 'unreadable'; value = $null }
    }
}

function Get-MacPreferenceValue {
    param(
        [Parameter(Mandatory)]
        [string]$Domain,
        [Parameter(Mandatory)]
        [string]$Key,
        [Parameter(Mandatory)]
        [ValidateSet('Managed', 'System', 'User')]
        [string]$Scope,
        [string]$ManagedPreferencesRoot = '/Library/Managed Preferences',
        [string]$SystemPreferencesRoot = '/Library/Preferences',
        [string]$UserPreferencesRoot = '',
        [string]$PlutilPath = '/usr/bin/plutil'
    )

    $result = Get-MacEvidenceResult
    if ([string]::IsNullOrWhiteSpace($UserPreferencesRoot)) {
        $userHomePath = [Environment]::GetFolderPath('UserProfile')
        if ([string]::IsNullOrWhiteSpace($userHomePath)) { $userHomePath = $HOME }
        $UserPreferencesRoot = Join-Path $userHomePath 'Library/Preferences'
    }

    $roots = switch ($Scope) {
        'Managed' {
            @($ManagedPreferencesRoot) + @(
                Get-ChildItem -LiteralPath $ManagedPreferencesRoot -Directory -Force -ErrorAction SilentlyContinue |
                    ForEach-Object { $_.FullName }
            )
        }
        'System' { @($SystemPreferencesRoot) }
        'User'   { @($UserPreferencesRoot) }
    }

    $deniedPath = ''
    if ($Scope -eq 'Managed') {
        $managedAccess = Test-MacReadAccess -Path $ManagedPreferencesRoot
        if ($managedAccess.access_denied) { $deniedPath = $ManagedPreferencesRoot }
    }
    foreach ($root in ($roots | Select-Object -Unique)) {
        $path = Join-Path $root "$Domain.plist"
        $access = Test-MacReadAccess -Path $path
        if (-not $access.exists) { continue }
        if (-not $access.readable) {
            if ([string]::IsNullOrWhiteSpace($deniedPath)) { $deniedPath = $path }
            continue
        }

        $document = ConvertFrom-MacPlistJson -Path $path -PlutilPath $PlutilPath
        if ($document.state -eq 'access_denied') {
            if ([string]::IsNullOrWhiteSpace($deniedPath)) { $deniedPath = $path }
            continue
        }
        if ($document.state -eq 'unreadable' -and [string]::IsNullOrWhiteSpace($deniedPath)) {
            $deniedPath = $path
        }
        if ($document.state -ne 'read') { continue }

        $property = $document.value.PSObject.Properties |
            Where-Object { $_.Name -ieq $Key } |
            Select-Object -First 1
        if ($null -ne $property) {
            return Get-MacEvidenceResult -Found $true -Value $property.Value -SourcePath $path
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($deniedPath)) {
        return Get-MacEvidenceResult -SourcePath $deniedPath -AccessDenied $true
    }
    return $result
}

function Get-MacProcessArguments {
    param(
        [Parameter(Mandatory)]
        [string]$ProcessNamePattern,
        [string]$PsPath = '/bin/ps'
    )

    $arguments = @()
    $command = Get-Command -Name $PsPath -ErrorAction SilentlyContinue
    if (-not $command -and -not (Test-Path -LiteralPath $PsPath -PathType Leaf)) { return $arguments }

    try {
        $rows = & $PsPath -axo 'pid=,command=' 2>$null
        if ($LASTEXITCODE -ne 0) { return $arguments }
        foreach ($row in $rows) {
            $line = ([string]$row).Trim()
            if ($line -match '^\s*\d+\s+(.*)$' -and $Matches[1] -match $ProcessNamePattern) {
                $arguments += $Matches[1]
            }
        }
    }
    catch { return @() }

    return @($arguments)
}

function Get-MacAppVersion {
    param(
        [Parameter(Mandatory)]
        [string[]]$BundlePath,
        [string]$PlutilPath = '/usr/bin/plutil'
    )

    $deniedPath = ''
    foreach ($candidate in $BundlePath) {
        $plistCandidates = @(
            (Join-Path $candidate 'Contents/Info.plist'),
            (Join-Path $candidate 'Info.plist')
        )
        if ((Get-Item -LiteralPath $candidate -ErrorAction SilentlyContinue) -and
            ([IO.Path]::GetExtension($candidate) -ieq '.plist')) {
            $plistCandidates = @($candidate) + $plistCandidates
        }

        foreach ($plistPath in ($plistCandidates | Select-Object -Unique)) {
            $access = Test-MacReadAccess -Path $plistPath
            if (-not $access.exists) { continue }
            if (-not $access.readable) {
                if ([string]::IsNullOrWhiteSpace($deniedPath)) { $deniedPath = $plistPath }
                continue
            }

            $document = ConvertFrom-MacPlistJson -Path $plistPath -PlutilPath $PlutilPath
            if ($document.state -eq 'access_denied') {
                if ([string]::IsNullOrWhiteSpace($deniedPath)) { $deniedPath = $plistPath }
                continue
            }
            if ($document.state -eq 'unreadable' -and [string]::IsNullOrWhiteSpace($deniedPath)) {
                $deniedPath = $plistPath
            }
            if ($document.state -ne 'read') { continue }

            foreach ($key in @('CFBundleShortVersionString', 'CFBundleVersion')) {
                $property = $document.value.PSObject.Properties |
                    Where-Object { $_.Name -ieq $key } |
                    Select-Object -First 1
                if ($null -ne $property) {
                    return Get-MacEvidenceResult -Found $true -Value $property.Value -SourcePath $plistPath
                }
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($deniedPath)) {
        return Get-MacEvidenceResult -SourcePath $deniedPath -AccessDenied $true
    }
    return Get-MacEvidenceResult
}
