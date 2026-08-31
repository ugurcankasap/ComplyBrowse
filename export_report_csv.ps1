param(
    [Parameter(Mandatory = $true)][string]$InputJson,
    [string]$OutputCsv = ""
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $InputJson)) {
    throw "Input file not found: $InputJson"
}

if ([string]::IsNullOrWhiteSpace($OutputCsv)) {
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($InputJson)
    $dir = Join-Path $PSScriptRoot "reports/csv"
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $OutputCsv = Join-Path $dir ($baseName + ".csv")
}

$raw = Get-Content -Path $InputJson -Raw -Encoding UTF8
$report = $raw | ConvertFrom-Json

if ($null -eq $report) {
    throw "Input JSON could not be parsed."
}

if ($null -eq $report.results) {
    throw "Input JSON does not contain a 'results' array."
}

$results = @($report.results)
if ($results.Count -eq 0) {
    Write-Warning "No result rows found in $InputJson. Creating an empty CSV."
}

$rows = foreach ($r in $results) {
    $cisControls = ""
    if ($null -ne $r.cis_controls) {
        if ($r.cis_controls -is [System.Array]) {
            $cisControls = (($r.cis_controls | ForEach-Object { [string]$_ }) -join ';')
        } elseif (-not [string]::IsNullOrWhiteSpace([string]$r.cis_controls)) {
            $cisControls = [string]$r.cis_controls
        }
    }

    [pscustomobject]@{
        TestID                    = [string]$r.test_id
        TestName                  = [string]$r.test_name
        Status                    = [string]$r.status
        ManageEngineReference     = [string]$r.manageengine_reference_url
        Severity                  = [string]$r.severity
        Verdict                   = [string]$r.verdict
        DecidingLayer             = [string]$r.deciding_layer
        PolicyKey                 = [string]$r.policy_key
        CISControls               = $cisControls
        ExpectedValue             = [string]$r.expected_value
        ObservedValue             = [string]$r.observed_value
        Remediation               = [string]$r.remediation
        Browser                   = [string]$report.browser
        TestDate                  = [string]$report.test_date
        RunId                     = [string]$r.run_id
        IntuneReference           = [string]$r.intune_reference_url
    }
}

$rows | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
Write-Host "CSV report created: $OutputCsv" -ForegroundColor Green