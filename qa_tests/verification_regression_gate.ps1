param(
    [string[]]$Browsers = @('edge', 'chrome', 'firefox'),
    [int]$EdgeMaxPolicyOnly = 0,
    [int]$EdgeMaxManual = 2,
    [int]$EdgeMaxNoPolicy = 2,
    [int]$EdgeMinDirect = 30,
    [int]$ChromeMaxPolicyOnly = 0,
    [int]$ChromeMaxManual = 0,
    [int]$ChromeMaxNoPolicy = 1,
    [int]$ChromeMinDirect = 100,
    [int]$FirefoxMaxPolicyOnly = 0,
    [int]$FirefoxMaxManual = 2,
    [int]$FirefoxMaxNoPolicy = 2,
    [int]$FirefoxMinDirect = 76
)

$ErrorActionPreference = 'Stop'

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

foreach ($browser in $Browsers) {
    $fileName = "${browser}_verified.json"
    Assert-True (Test-Path $fileName) "Missing verified output: $fileName"

    $json = Get-Content $fileName -Raw | ConvertFrom-Json

    Assert-True ($null -ne $json.results) "${fileName}: missing results"
    Assert-True ($null -ne $json.summary) "${fileName}: missing summary"
    Assert-True ($null -ne $json.verification_summary) "${fileName}: missing verification_summary"
    Assert-True ($null -ne $json.mapping_standardization) "${fileName}: missing mapping_standardization"

    $resultCount = @($json.results).Count
    Assert-True ($resultCount -gt 0) "${fileName}: empty results array"
    Assert-True ([int]$json.summary.total_tests -eq $resultCount) "${fileName}: summary.total_tests mismatch"
    Assert-True ([int]$json.verification_summary.total_tests -eq $resultCount) "${fileName}: verification_summary.total_tests mismatch"

    $unknownClass = [int]$json.mapping_standardization.UNKNOWN
    Assert-True ($unknownClass -eq 0) "${fileName}: mapping_standardization.UNKNOWN must be 0"

    $direct = [int]$json.mapping_standardization.DIRECT
    $policyOnly = [int]$json.mapping_standardization.POLICY_ONLY
    $manual = [int]$json.mapping_standardization.MANUAL
    $noPolicy = [int]$json.data_quality.no_resolvable_policy_key

    $missingClass = @($json.results | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.mapping_class) }).Count
    Assert-True ($missingClass -eq 0) "${fileName}: one or more results missing mapping_class"

    switch ($browser) {
        'edge' {
            Assert-True ($policyOnly -le $EdgeMaxPolicyOnly) "edge_verified.json: POLICY_ONLY regression ($policyOnly > $EdgeMaxPolicyOnly)"
            Assert-True ($manual -le $EdgeMaxManual) "edge_verified.json: MANUAL regression ($manual > $EdgeMaxManual)"
            Assert-True ($noPolicy -le $EdgeMaxNoPolicy) "edge_verified.json: no_resolvable_policy_key regression ($noPolicy > $EdgeMaxNoPolicy)"
            Assert-True ($direct -ge $EdgeMinDirect) "edge_verified.json: DIRECT regression ($direct < $EdgeMinDirect)"
        }
        'chrome' {
            Assert-True ($policyOnly -le $ChromeMaxPolicyOnly) "chrome_verified.json: POLICY_ONLY regression ($policyOnly > $ChromeMaxPolicyOnly)"
            Assert-True ($manual -le $ChromeMaxManual) "chrome_verified.json: MANUAL regression ($manual > $ChromeMaxManual)"
            Assert-True ($noPolicy -le $ChromeMaxNoPolicy) "chrome_verified.json: no_resolvable_policy_key regression ($noPolicy > $ChromeMaxNoPolicy)"
            Assert-True ($direct -ge $ChromeMinDirect) "chrome_verified.json: DIRECT regression ($direct < $ChromeMinDirect)"
        }
        'firefox' {
            Assert-True ($policyOnly -le $FirefoxMaxPolicyOnly) "firefox_verified.json: POLICY_ONLY regression ($policyOnly > $FirefoxMaxPolicyOnly)"
            Assert-True ($manual -le $FirefoxMaxManual) "firefox_verified.json: MANUAL regression ($manual > $FirefoxMaxManual)"
            Assert-True ($noPolicy -le $FirefoxMaxNoPolicy) "firefox_verified.json: no_resolvable_policy_key regression ($noPolicy > $FirefoxMaxNoPolicy)"
            Assert-True ($direct -ge $FirefoxMinDirect) "firefox_verified.json: DIRECT regression ($direct < $FirefoxMinDirect)"
        }
    }

    Write-Host ("[PASS] {0}: results={1}, DIRECT={2}, POLICY_ONLY={3}, RUNTIME={4}, MANUAL={5}, UNKNOWN={6}" -f
        $fileName,
        $resultCount,
        [int]$json.mapping_standardization.DIRECT,
        [int]$json.mapping_standardization.POLICY_ONLY,
        [int]$json.mapping_standardization.RUNTIME,
        [int]$json.mapping_standardization.MANUAL,
        [int]$json.mapping_standardization.UNKNOWN)
}

Write-Host "All verification regression gates passed."
