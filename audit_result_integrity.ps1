<#
Result Integrity Audit

Purpose:
  Before a compliance report is presented to management or published, it must be
  proven internally consistent. This script does not re-scan the endpoint. It
  audits a *_verified.json report for defects that silently corrupt findings:

    A1  A control was tagged with a CIS control id whose policy key contradicts
        the key the test itself says it checked. Wrong tag -> wrong key ->
        wrong remediation link -> wrong CIS attribution.
    A2  A verdict of PASS or FAIL was produced from a runner outcome that was
        not conclusive (UNKNOWN / ERROR / SKIPPED).
    A3  A PASS that no layer actually earned: no compliant value comparison and
        no managed policy evidence.
    A4  A control that counts towards the score without a machine-comparable
        expectation.
    A5  The published compliance score does not match a recomputation from the
        per-result verdicts.
    A6  Duplicate test ids, or verdicts outside the declared vocabulary.
    A7  Two different controls resolving to the same policy key with conflicting
        expectations.

Exit code 0 = report is internally consistent (publishable).
Exit code 1 = blocking defects found.
#>

param(
    [Parameter(Mandatory = $true)][string]$InputFile,
    [switch]$ShowAll
)

if (-not (Test-Path $InputFile)) {
    Write-Error "Report not found: $InputFile"
    exit 2
}

$report  = Get-Content $InputFile -Raw -Encoding UTF8 | ConvertFrom-Json
$results = @($report.results)

$validVerdicts = @('PASS', 'PASS_NOT_ENFORCED', 'FAIL', 'NOT_ASSESSED')
$findings = @()

# Controls that are legitimately satisfiable through more than one policy key
# must not be flagged as mismatches.
$aliasMap = @{}
$browserName = [string]$report.verification_summary.browser
$mapFile = switch ($browserName) {
    'Edge'    { 'edge_cis_policy_map.json' }
    'Chrome'  { 'chrome_cis_policy_map.json' }
    'Firefox' { 'firefox_cis_policy_map.json' }
    default   { $null }
}
if ($mapFile) {
    $mapPath = Join-Path $PSScriptRoot $mapFile
    if (Test-Path $mapPath) {
        foreach ($entry in (Get-Content $mapPath -Raw -Encoding UTF8 | ConvertFrom-Json)) {
            $aliases = @($entry.equivalent_policy_keys | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
            if ($entry.policy_key -and $aliases.Count -gt 0) {
                $primary = ([string]$entry.policy_key).ToLowerInvariant()
                $group = @($primary) + @($aliases | ForEach-Object { ([string]$_).ToLowerInvariant() })
                foreach ($member in $group) {
                    $aliasMap[$member] = $group
                }
            }
        }
    }
}

function Add-Finding {
    param([string]$Code, [string]$Severity, [string]$TestId, [string]$Detail)
    $script:findings += [pscustomobject]@{
        code     = $Code
        severity = $Severity
        test_id  = $TestId
        detail   = $Detail
    }
}

# ---------------------------------------------------------------------------
# A1 - policy key contradicts the key named in the test's own evidence text
# ---------------------------------------------------------------------------
foreach ($r in $results) {
    $declaredKey = [string]$r.policy_key
    if ([string]::IsNullOrWhiteSpace($declaredKey)) { continue }

    $evidenceText = "$($r.details) $($r.expected_value) $($r.remediation)"
    if ([string]::IsNullOrWhiteSpace($evidenceText)) { continue }

    # Keys named inside registry paths or expectation sentences. All-caps tokens
    # such as ENABLED or DISABLED are status words, not policy identifiers.
    $named = @()
    foreach ($m in [regex]::Matches($evidenceText, '\b([A-Z][a-z0-9]+(?:[A-Z][A-Za-z0-9]*)+)\b')) {
        $named += $m.Groups[1].Value
    }
    $named = @($named | Select-Object -Unique)
    if ($named.Count -eq 0) { continue }

    $exactHits = @($named | Where-Object { $_ -ieq $declaredKey })
    if ($exactHits.Count -gt 0) { continue }

    $declaredLower = $declaredKey.ToLowerInvariant()
    if ($aliasMap.ContainsKey($declaredLower)) {
        $group = $aliasMap[$declaredLower]
        $aliasHit = @($named | Where-Object { $group -contains $_.ToLowerInvariant() })
        if ($aliasHit.Count -gt 0) { continue }
    }

    # Only report when the evidence text clearly names a policy-style identifier.
    $policyStyle = @($named | Where-Object { $_ -match '(Enabled|Disabled|Availability|Restrictions|Mode|Allowed|Blocklist|Allowlist|Settings|Level|Policy)$' })
    if ($policyStyle.Count -eq 0) { continue }

    Add-Finding -Code 'A1_KEY_MISMATCH' -Severity 'BLOCKING' -TestId ([string]$r.test_id) `
        -Detail "Resolved policy key '$declaredKey' (source: $([string]$r.policy_key_source)) but the test evidence names '$($policyStyle -join ', ')'. CIS tag: $(@($r.cis_controls) -join ',')."
}

# ---------------------------------------------------------------------------
# A2 - conclusive verdict built on an inconclusive runner outcome
# ---------------------------------------------------------------------------
foreach ($r in $results) {
    $status = ([string]$r.status).ToUpperInvariant()
    if ($status -notin @('UNKNOWN', 'ERROR', 'SKIPPED', 'INCONCLUSIVE')) { continue }
    if ([string]$r.verdict -notin @('PASS', 'FAIL')) { continue }

    Add-Finding -Code 'A2_UNKNOWN_TO_VERDICT' -Severity 'BLOCKING' -TestId ([string]$r.test_id) `
        -Detail "Runner status '$status' was converted into verdict '$([string]$r.verdict)' (deciding layer $([string]$r.deciding_layer))."
}

# ---------------------------------------------------------------------------
# A3 - PASS with no earned evidence
# ---------------------------------------------------------------------------
foreach ($r in $results) {
    if ([string]$r.verdict -ne 'PASS') { continue }

    $l1 = [string]$r.layers.L1.state
    $l2 = [string]$r.layers.L2.state
    $l3 = [string]$r.layers.L3.state
    $channel = [string]$r.policy_provenance.management_channel

    $hasComparison  = ($l1 -eq 'COMPLIANT' -or $l2 -eq 'COMPLIANT')
    $hasRuntime     = ($l3 -eq 'COMPLIANT')
    $hasProvenance  = (-not [string]::IsNullOrWhiteSpace($channel) -and $channel -ne 'NONE')
    $runtimeScoped  = ([string]$r.mapping_class -eq 'RUNTIME')

    if ($hasProvenance) { continue }
    # A runtime-scoped control has no policy key by design; live process evidence
    # is its primary and correct evidence source.
    if ($hasRuntime -and $runtimeScoped) { continue }
    if ($hasComparison -and $hasRuntime) { continue }
    # Exception and bypass lists are compliant precisely because nothing is
    # configured, so absent managed evidence is the expected state for them.
    if ([string]$r.compliance_semantics -eq 'ABSENCE_IS_COMPLIANT') { continue }
    if ($hasComparison) {
        Add-Finding -Code 'A3_PASS_WITHOUT_PROVENANCE' -Severity 'WARNING' -TestId ([string]$r.test_id) `
            -Detail "PASS is based on a layer state ($l1/$l2) but no policy value was found in any readable managed channel. Verify the control is not passing on absence of configuration."
        continue
    }

    Add-Finding -Code 'A3_PASS_WITHOUT_EVIDENCE' -Severity 'BLOCKING' -TestId ([string]$r.test_id) `
        -Detail "PASS with no compliant value comparison (L1=$l1, L2=$l2, L3=$l3) and no managed policy evidence."
}

# ---------------------------------------------------------------------------
# A4 - scored control without a machine-comparable expectation
# ---------------------------------------------------------------------------
foreach ($r in $results) {
    if (-not [bool]$r.counts_in_score) { continue }
    if (-not [string]::IsNullOrWhiteSpace([string]$r.expected_kind)) { continue }
    if (-not [string]::IsNullOrWhiteSpace([string]$r.expected_state)) { continue }
    # Observational controls (filesystem scans, live process inspection) reach a
    # deterministic finding without a policy-value expectation. Their evidence
    # basis is reported separately rather than treated as a data gap.
    if ([string]$r.evidence_basis -in @('OBSERVATION', 'RUNTIME_OBSERVATION')) { continue }
    if ([string]$r.mapping_class -in @('RUNTIME')) { continue }
    if ([string]$r.compliance_semantics -eq 'ABSENCE_IS_COMPLIANT') { continue }

    Add-Finding -Code 'A4_SCORED_WITHOUT_EXPECTATION' -Severity 'WARNING' -TestId ([string]$r.test_id) `
        -Detail "Verdict '$([string]$r.verdict)' counts towards the score but the control has no machine-comparable expectation."
}

# ---------------------------------------------------------------------------
# A5 - score arithmetic
# ---------------------------------------------------------------------------
$counts = @{ PASS = 0; PASS_NOT_ENFORCED = 0; FAIL = 0; NOT_ASSESSED = 0 }
foreach ($r in $results) {
    $v = [string]$r.verdict
    if ($counts.ContainsKey($v)) { $counts[$v]++ }
}
$scored = $counts.PASS + $counts.PASS_NOT_ENFORCED + $counts.FAIL
$recomputed = 0
if ($scored -gt 0) { $recomputed = [math]::Round(($counts.PASS / $scored) * 100, 1) }

$published = [double]$report.verification_summary.compliance_score_percent
if ([math]::Abs($published - $recomputed) -gt 0.1) {
    Add-Finding -Code 'A5_SCORE_MISMATCH' -Severity 'BLOCKING' -TestId '(report)' `
        -Detail "Published score $published% does not match recomputation $recomputed% (PASS=$($counts.PASS), PNE=$($counts.PASS_NOT_ENFORCED), FAIL=$($counts.FAIL), NA=$($counts.NOT_ASSESSED))."
}

foreach ($key in @('pass', 'fail', 'not_assessed')) {
    $declared = [int]$report.verification_summary.$key
    $actual = switch ($key) {
        'pass'         { $counts.PASS }
        'fail'         { $counts.FAIL }
        'not_assessed' { $counts.NOT_ASSESSED }
    }
    if ($declared -ne $actual) {
        Add-Finding -Code 'A5_SUMMARY_MISMATCH' -Severity 'BLOCKING' -TestId '(report)' `
            -Detail "verification_summary.$key = $declared but the results array contains $actual."
    }
}

# ---------------------------------------------------------------------------
# A6 - structural integrity
# ---------------------------------------------------------------------------
$duplicateIds = @($results | Group-Object test_id | Where-Object { $_.Count -gt 1 })
foreach ($dup in $duplicateIds) {
    Add-Finding -Code 'A6_DUPLICATE_TEST_ID' -Severity 'BLOCKING' -TestId ([string]$dup.Name) `
        -Detail "test_id appears $($dup.Count) times; results cannot be uniquely referenced."
}

foreach ($r in $results) {
    if ([string]$r.verdict -notin $validVerdicts) {
        Add-Finding -Code 'A6_INVALID_VERDICT' -Severity 'BLOCKING' -TestId ([string]$r.test_id) `
            -Detail "Verdict '$([string]$r.verdict)' is outside the declared vocabulary."
    }
    if ([string]::IsNullOrWhiteSpace([string]$r.verdict_reasoning)) {
        Add-Finding -Code 'A6_NO_REASONING' -Severity 'WARNING' -TestId ([string]$r.test_id) `
            -Detail 'Verdict has no reasoning text; the finding cannot be defended in a review.'
    }
}

# ---------------------------------------------------------------------------
# A7 - conflicting expectations on the same policy key
# ---------------------------------------------------------------------------
$byKey = @{}
foreach ($r in $results) {
    $k = [string]$r.policy_key
    if ([string]::IsNullOrWhiteSpace($k)) { continue }
    if (-not [bool]$r.policy_key_trusted) { continue }
    $normalized = $k.ToLowerInvariant()
    if (-not $byKey.ContainsKey($normalized)) { $byKey[$normalized] = @() }
    $byKey[$normalized] += $r
}

foreach ($k in $byKey.Keys) {
    $group = @($byKey[$k])
    if ($group.Count -lt 2) { continue }

    # Only genuine contradictions matter. A vague expectation such as
    # 'configured' is weaker than a typed one, not opposed to it: two controls
    # conflict when they demand different values for the same key.
    $typed = @()
    foreach ($item in $group) {
        $kind  = ([string]$item.expected_kind).ToLowerInvariant()
        $value = ([string]$item.expected_machine_value).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        if ($value -in @('configured', 'present', 'enabled_or_configured')) { continue }

        $normalizedValue = switch ($value) {
            'true'  { '1' }
            'false' { '0' }
            default { $value }
        }
        $typed += [pscustomobject]@{ test_id = [string]$item.test_id; kind = $kind; value = $normalizedValue }
    }

    $distinctValues = @($typed | ForEach-Object { $_.value } | Select-Object -Unique)
    if ($distinctValues.Count -le 1) { continue }

    $detail = @($typed | ForEach-Object { "$($_.test_id): $($_.kind)=$($_.value)" }) -join ' | '
    Add-Finding -Code 'A7_CONFLICTING_EXPECTATION' -Severity 'BLOCKING' -TestId (@($typed | ForEach-Object { $_.test_id }) -join ', ') `
        -Detail "Policy key '$k' is required to hold different values by different controls: $detail. One of them is wrong."
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
$blocking = @($findings | Where-Object { $_.severity -eq 'BLOCKING' })
$warnings = @($findings | Where-Object { $_.severity -eq 'WARNING' })

Write-Host ''
Write-Host "Result integrity audit" -ForegroundColor Cyan
Write-Host "----------------------" -ForegroundColor Cyan
Write-Host "Report   : $InputFile"
Write-Host "Browser  : $([string]$report.verification_summary.browser)"
Write-Host "Controls : $($results.Count)"
Write-Host ''

if ($findings.Count -eq 0) {
    Write-Host 'No integrity defects found. Report is internally consistent.' -ForegroundColor Green
    exit 0
}

$grouped = $findings | Group-Object code | Sort-Object Name
foreach ($g in $grouped) {
    $severity = ($g.Group | Select-Object -First 1).severity
    $color = if ($severity -eq 'BLOCKING') { 'Red' } else { 'Yellow' }
    Write-Host ("[{0}] {1}  x{2}" -f $severity, $g.Name, $g.Count) -ForegroundColor $color

    $show = if ($ShowAll) { $g.Group } else { $g.Group | Select-Object -First 5 }
    foreach ($f in $show) {
        Write-Host ("    {0}: {1}" -f $f.test_id, $f.detail) -ForegroundColor DarkGray
    }
    if (-not $ShowAll -and $g.Count -gt 5) {
        Write-Host ("    ... {0} more (use -ShowAll)" -f ($g.Count - 5)) -ForegroundColor DarkGray
    }
    Write-Host ''
}

Write-Host ("Blocking defects : {0}" -f $blocking.Count) -ForegroundColor Red
Write-Host ("Warnings         : {0}" -f $warnings.Count) -ForegroundColor Yellow
Write-Host ''

if ($blocking.Count -gt 0) {
    Write-Host 'RESULT: report is NOT publishable until blocking defects are resolved.' -ForegroundColor Red
    exit 1
}

Write-Host 'RESULT: no blocking defects. Review the warnings before publishing.' -ForegroundColor Yellow
exit 0
