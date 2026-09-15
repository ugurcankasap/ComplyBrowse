param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'

$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$forbiddenPathPatterns = @(
    '^artifacts/',
    '^reports/(raw|private|csv|public)/',
    '(^|/).+_verified(?:_.+)?\.json$',
    '(^|/).+_test_results(?:_.+)?\.json$',
    '(^|/).+_raw_report\.json$',
    '(^|/)\.coverage$'
)
$evidencePatterns = @(
    '(?i)REDACTED_HOST',
    '(?i)PC-[A-Z0-9-]+',
    '[A-Za-z]:\\Users\\'
)
$patternDefinitionFiles = @(
    'prepare_publish_safe.ps1',
    'tools/check_publish_safety.ps1',
    'tools/sanitize_public_report.py'
)

Push-Location $root
try {
    $candidateFiles = @(
        (git ls-files --cached)
        (git ls-files --others --exclude-standard)
        (git ls-files --others --ignored --exclude-standard)
    ) | Where-Object {
        $_ -and $_ -notmatch '(^|/)(\.venv|\.ruff_cache|__pycache__)/'
    } | Sort-Object -Unique
}
finally {
    Pop-Location
}

$violations = New-Object System.Collections.Generic.List[string]
foreach ($path in $candidateFiles) {
    $normalizedPath = $path.Replace('\', '/')
    foreach ($pattern in $forbiddenPathPatterns) {
        if ($normalizedPath -match $pattern) {
            $violations.Add("Forbidden publish output: $normalizedPath") | Out-Null
            break
        }
    }

    $fullPath = Join-Path $root $path
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        continue
    }
    if ($normalizedPath -in $patternDefinitionFiles) {
        continue
    }

    foreach ($pattern in $evidencePatterns) {
        $patternMatches = Select-String -LiteralPath $fullPath -Pattern $pattern -AllMatches -ErrorAction Stop
        foreach ($match in $patternMatches) {
            $violations.Add("Potential private evidence in ${normalizedPath}:$($match.LineNumber)") | Out-Null
        }
    }
}

if ($violations.Count -gt 0) {
    Write-Error "Publish safety gate failed with $($violations.Count) violation(s):`n$($violations -join "`n")"
    exit 1
}

Write-Host "Publish safety gate passed: $($candidateFiles.Count) tracked or untracked publish candidates checked." -ForegroundColor Green