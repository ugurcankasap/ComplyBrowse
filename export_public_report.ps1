param(
    [Parameter(Mandatory = $true)][string]$InputJson,
    [string]$OutputJson = ""
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $InputJson)) {
    throw "Input file not found: $InputJson"
}

if ([string]::IsNullOrWhiteSpace($OutputJson)) {
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($InputJson)
    $dir = Join-Path $PSScriptRoot "reports/public"
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $OutputJson = Join-Path $dir ($baseName + "_public.json")
}

$sanitizer = Join-Path $PSScriptRoot "tools/sanitize_public_report.py"
if (-not (Test-Path $sanitizer)) {
    throw "Sanitizer script not found: $sanitizer"
}

function Test-PythonRuntime {
    param([string]$Executable, [string[]]$Prefix)

    if (-not (Get-Command $Executable -ErrorAction SilentlyContinue)) {
        return $false
    }

    # WindowsApps python stubs resolve as a command but fail to execute.
    try {
        & $Executable @Prefix -V *> $null
        return ($LASTEXITCODE -eq 0)
    }
    catch {
        return $false
    }
}

$runtime = $null
foreach ($candidate in @(
        @{ Exe = 'python'; Prefix = @() },
        @{ Exe = 'python3'; Prefix = @() },
        @{ Exe = 'py'; Prefix = @('-3') }
    )) {
    if (Test-PythonRuntime -Executable $candidate.Exe -Prefix $candidate.Prefix) {
        $runtime = $candidate
        break
    }
}

if ($null -eq $runtime) {
    throw "Python runtime not found or not executable. Install Python 3 to run report sanitization."
}

if (Test-Path $OutputJson) {
    Remove-Item $OutputJson -Force
}

$exe = [string]$runtime.Exe
$prefix = @($runtime.Prefix)
& $exe @prefix $sanitizer --input $InputJson --output $OutputJson
if ($LASTEXITCODE -ne 0) {
    throw "Sanitization failed (exit code $LASTEXITCODE). Public report was not created."
}

if (-not (Test-Path $OutputJson)) {
    throw "Sanitization reported success but produced no output file: $OutputJson"
}

Write-Host "Public report created: $OutputJson" -ForegroundColor Green
