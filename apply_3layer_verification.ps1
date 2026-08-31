<![CDATA[<#
.SYNOPSIS
DEPRECATED: Use apply_verification.ps1 instead.

.DESCRIPTION
This script is a compatibility shim. All functionality has been consolidated into
apply_verification.ps1, which uses the 4-verdict framework (PASS, PASS_NOT_ENFORCED, FAIL, NOT_ASSESSED).

This script will be removed in v1.1.0.

.PARAMETER InputFile
Path to raw test results JSON file.

.PARAMETER Browser
Target browser: Edge, Chrome, or Firefox.

.PARAMETER OutputFile
Optional output path for verified results JSON.
#>
]]>
param(
    [Parameter(Mandatory = $true)][string]$InputFile,
    [Parameter(Mandatory = $true)][ValidateSet('Edge', 'Chrome', 'Firefox')][string]$Browser = 'Edge',
    [string]$OutputFile
)

Write-Warning "apply_3layer_verification.ps1 is deprecated. Redirecting to apply_verification.ps1 (PASS | PASS_NOT_ENFORCED | FAIL | NOT_ASSESSED)."

$scriptPath = Join-Path $PSScriptRoot 'apply_verification.ps1'
if (-not (Test-Path $scriptPath)) {
    throw "Missing script: $scriptPath"
}

& $scriptPath -InputFile $InputFile -Browser $Browser -OutputFile $OutputFile
exit $LASTEXITCODE
