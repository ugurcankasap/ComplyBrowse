param(
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot

$targets = @(
    @{ Path = Join-Path $root 'artifacts'; Type = 'Directory'; Reason = 'Local evidence artifacts' },
    @{ Path = Join-Path $root 'reports/raw'; Type = 'Directory'; Reason = 'Raw reports may contain private evidence' },
    @{ Path = Join-Path $root 'reports/private'; Type = 'Directory'; Reason = 'Private reports must not be published' },
    @{ Path = Join-Path $root 'reports/csv'; Type = 'Directory'; Reason = 'CSV exports contain actual endpoint findings' },
    @{ Path = Join-Path $root 'reports/public'; Type = 'Directory'; Reason = 'Public reports still contain findings/evidence narrative' },
    @{ Path = Join-Path $root '3LAYER_VERIFICATION_REPORT.md'; Type = 'File'; Reason = 'Contains findings summary and historical evidence narrative' },
    @{ Path = Join-Path $root 'MULTI_LAYER_VERIFICATION_REPORT.md'; Type = 'File'; Reason = 'Contains findings summary and historical evidence narrative' },
    @{ Path = Join-Path $root 'ENRICHMENT_REPORT.md'; Type = 'File'; Reason = 'Contains findings summary and historical evidence narrative' },
    @{ Path = Join-Path $root 'reports/turkish_test_lines.txt'; Type = 'File'; Reason = 'Test metadata with endpoint context' }
)

$patterns = @(
    '*_test_results.json',
    '*_test_results_*.json',
    '*_verified.json',
    '*_verified_*.json',
    'test_results.json',
    'chrome_test_*.json',
    'firefox_test_*.json',
    '*_raw_report.json',
    '_tmp*.json',
    '.coverage'
)

$removed = New-Object System.Collections.Generic.List[string]
$missing = New-Object System.Collections.Generic.List[string]

function Remove-Target {
    param(
        [string]$Path,
        [string]$Reason,
        [switch]$DryRun
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        $script:missing.Add("MISSING: $Path") | Out-Null
        return
    }

    if ($DryRun) {
        Write-Host "[DRY-RUN] Remove: $Path ($Reason)" -ForegroundColor Yellow
        return
    }

    Remove-Item -LiteralPath $Path -Recurse -Force
    $script:removed.Add("REMOVED: $Path ($Reason)") | Out-Null
}

foreach ($target in $targets) {
    Remove-Target -Path $target.Path -Reason $target.Reason -DryRun:$DryRun
}

$rootJson = Get-ChildItem -LiteralPath $root -File -Filter '*.json' -ErrorAction SilentlyContinue
foreach ($pattern in $patterns) {
    foreach ($file in ($rootJson | Where-Object { $_.Name -like $pattern })) {
        Remove-Target -Path $file.FullName -Reason "Pattern match: $pattern" -DryRun:$DryRun
    }
}

if (-not $DryRun) {
    # Recreate empty folders that tooling expects to exist.
    foreach ($path in @(
            (Join-Path $root 'artifacts'),
            (Join-Path $root 'reports/raw'),
            (Join-Path $root 'reports/private'),
            (Join-Path $root 'reports/public')
        )) {
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
}

Write-Host "" 
Write-Host "Publish safety cleanup summary" -ForegroundColor Cyan
if ($DryRun) {
    Write-Host "Mode: DRY-RUN" -ForegroundColor Cyan
}
else {
    Write-Host "Mode: APPLY" -ForegroundColor Cyan
}

if ($removed.Count -gt 0) {
    Write-Host "Removed items: $($removed.Count)" -ForegroundColor Green
    $removed | ForEach-Object { Write-Host "  $_" }
}
elseif (-not $DryRun) {
    Write-Host "Removed items: 0" -ForegroundColor Green
}

if ($missing.Count -gt 0) {
    Write-Host "Missing items (already clean): $($missing.Count)" -ForegroundColor DarkGray
}

Write-Host "" 
Write-Host "Next step: run a leak scan before publishing." -ForegroundColor Cyan
Write-Host "Suggested scan:" -ForegroundColor Cyan
Write-Host '  rg -n -i "REDACTED_HOST|PC-[A-Z0-9-]+|C:\\Users\\|evidence_path|evidence_output|finding_details" .' -ForegroundColor Cyan
