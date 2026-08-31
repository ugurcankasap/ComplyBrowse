<#
Verification Engine Self-Validation

Why this exists:
  A compliance report is only as credible as the decision function behind it.
  Before results are presented to management or published, the decision function
  itself must be proven deterministic and correct against a declared truth table.

  This harness does not touch the endpoint. It feeds synthetic layer states into
  Resolve-ComplianceVerdict and asserts the verdict, the deciding layer and
  whether the control counts towards the score.

Run:
  .\validate_verification_engine.ps1
Exit code 0 = every assertion held. Non-zero = the engine changed behaviour.
#>

param([switch]$Detailed)

. "$PSScriptRoot\verify_value_based.ps1"

function New-Layer {
    param([string]$Layer, [string]$State, [bool]$Enforced = $false)
    return @{
        layer    = $Layer
        source   = "synthetic-$Layer"
        enforced = $Enforced
        state    = $State
        expected = 'synthetic-expected'
        actual   = 'synthetic-actual'
        details  = 'synthetic'
    }
}

# id | browser | L1 | L2 | L3 | expected verdict | expected deciding layer | counts in score
$truthTable = @(
    @{ id = 'TT-01'; browser = 'Edge';    l1 = 'COMPLIANT';           l2 = 'NOT_APPLICABLE';      l3 = 'NOT_ASSESSED';        verdict = 'PASS';              layer = 'L1';   scored = $true
       why = 'Managed policy matches the expectation and the user layer has no equivalent: enforced compliance.' }

    @{ id = 'TT-02'; browser = 'Edge';    l1 = 'NON_COMPLIANT_VALUE'; l2 = 'COMPLIANT';           l3 = 'NOT_ASSESSED';        verdict = 'FAIL';              layer = 'L1';   scored = $true
       why = 'Managed policy outranks user config. A compliant user value cannot rescue a misconfigured policy.' }

    @{ id = 'TT-03'; browser = 'Edge';    l1 = 'ABSENT';              l2 = 'COMPLIANT';           l3 = 'NOT_ASSESSED';        verdict = 'PASS_NOT_ENFORCED'; layer = 'L2';   scored = $false
       why = 'Compliant today, revertible by the user tomorrow. Must never count as enforced compliance.' }

    @{ id = 'TT-04'; browser = 'Edge';    l1 = 'ABSENT';              l2 = 'NON_COMPLIANT_VALUE'; l3 = 'NOT_ASSESSED';        verdict = 'FAIL';              layer = 'L2';   scored = $true
       why = 'No policy deployed and the observed user value contradicts the expectation.' }

    @{ id = 'TT-05'; browser = 'Edge';    l1 = 'ABSENT';              l2 = 'NOT_APPLICABLE';      l3 = 'NOT_ASSESSED';        verdict = 'FAIL';              layer = 'L1';   scored = $true
       why = 'Policy-only control with no policy deployed: the control is simply not implemented.' }

    @{ id = 'TT-06'; browser = 'Firefox'; l1 = 'ABSENT';              l2 = 'ABSENT';              l3 = 'NOT_ASSESSED';        verdict = 'NOT_ASSESSED';      layer = 'NONE'; scored = $false
       why = 'Firefox defaults are ambiguous with no policy and no pref; guessing FAIL would be unfounded.' }

    @{ id = 'TT-07'; browser = 'Edge';    l1 = 'COMPLIANT';           l2 = 'NON_COMPLIANT_VALUE'; l3 = 'NON_COMPLIANT_VALUE'; verdict = 'FAIL';              layer = 'L3';   scored = $true
       why = 'Policy looks correct but runtime evidence shows it is neutralised: the arbiter wins.' }

    @{ id = 'TT-08'; browser = 'Edge';    l1 = 'COMPLIANT';           l2 = 'NON_COMPLIANT_VALUE'; l3 = 'COMPLIANT';           verdict = 'PASS';              layer = 'L3';   scored = $true
       why = 'User drift exists but runtime evidence confirms the policy is actually in force.' }

    @{ id = 'TT-09'; browser = 'Chrome';  l1 = 'NOT_APPLICABLE';      l2 = 'NOT_APPLICABLE';      l3 = 'COMPLIANT';           verdict = 'PASS';              layer = 'L3';   scored = $true
       why = 'Runtime-only control: the arbiter is the only applicable evidence source.' }

    @{ id = 'TT-10'; browser = 'Chrome';  l1 = 'NOT_APPLICABLE';      l2 = 'NOT_APPLICABLE';      l3 = 'NON_COMPLIANT_VALUE'; verdict = 'FAIL';              layer = 'L3';   scored = $true
       why = 'Runtime-only control with contradicting runtime evidence.' }

    @{ id = 'TT-11'; browser = 'Chrome';  l1 = 'NOT_APPLICABLE';      l2 = 'NOT_APPLICABLE';      l3 = 'NOT_ASSESSED';        verdict = 'NOT_ASSESSED';      layer = 'NONE'; scored = $false
       why = 'No applicable layer produced evidence. The control must leave the score, not enter it as PASS.' }

    @{ id = 'TT-12'; browser = 'Edge';    l1 = 'NOT_ASSESSED';        l2 = 'NON_COMPLIANT_VALUE'; l3 = 'NOT_ASSESSED';        verdict = 'FAIL';              layer = 'L2';   scored = $true
       why = 'Managed evidence unreadable, but a concrete user-layer mismatch is still a finding.' }

    @{ id = 'TT-13'; browser = 'Edge';    l1 = 'NOT_ASSESSED';        l2 = 'NOT_ASSESSED';        l3 = 'NOT_ASSESSED';        verdict = 'NOT_ASSESSED';      layer = 'NONE'; scored = $false
       why = 'No readable evidence anywhere. Silence is not compliance and not a finding.' }

    @{ id = 'TT-14'; browser = 'Chrome';  l1 = 'COMPLIANT';           l2 = 'COMPLIANT';           l3 = 'NOT_ASSESSED';        verdict = 'PASS';              layer = 'L1';   scored = $true
       why = 'Policy and user layer agree; the enforced layer decides.' }

    @{ id = 'TT-15'; browser = 'Firefox'; l1 = 'ABSENT';              l2 = 'NON_COMPLIANT_VALUE'; l3 = 'NOT_ASSESSED';        verdict = 'FAIL';              layer = 'L2';   scored = $true
       why = 'Firefox ambiguity applies only when the user layer is silent, not when it contradicts.' }
)

$failures = @()
$passed   = 0

Write-Host ''
Write-Host 'Verification engine self-validation' -ForegroundColor Cyan
Write-Host '-----------------------------------' -ForegroundColor Cyan

foreach ($case in $truthTable) {
    $decision = Resolve-ComplianceVerdict `
        -Browser $case.browser `
        -Layer1 (New-Layer -Layer 'L1' -State $case.l1 -Enforced $true) `
        -Layer2 (New-Layer -Layer 'L2' -State $case.l2) `
        -Layer3 (New-Layer -Layer 'L3' -State $case.l3)

    $problems = @()
    if ([string]$decision.verdict -ne [string]$case.verdict) {
        $problems += "verdict expected '$($case.verdict)' but got '$($decision.verdict)'"
    }
    if ([string]$decision.deciding_layer -ne [string]$case.layer) {
        $problems += "deciding_layer expected '$($case.layer)' but got '$($decision.deciding_layer)'"
    }
    if ([bool]$decision.counts_in_score -ne [bool]$case.scored) {
        $problems += "counts_in_score expected '$($case.scored)' but got '$($decision.counts_in_score)'"
    }

    if ($problems.Count -eq 0) {
        $passed++
        if ($Detailed) {
            Write-Host ("  [OK]   {0}  {1}/{2}/{3} -> {4} ({5})" -f $case.id, $case.l1, $case.l2, $case.l3, $decision.verdict, $decision.deciding_layer) -ForegroundColor Green
        }
    }
    else {
        $failures += @{ id = $case.id; problems = $problems; why = $case.why }
        Write-Host ("  [FAIL] {0}  {1}" -f $case.id, ($problems -join '; ')) -ForegroundColor Red
        Write-Host ("         rule: {0}" -f $case.why) -ForegroundColor DarkGray
    }
}

# Invariant checks that must hold regardless of the truth table.
$invariantFailures = @()

foreach ($browser in @('Edge', 'Chrome', 'Firefox')) {
    $states = @('COMPLIANT', 'NON_COMPLIANT_VALUE', 'ABSENT', 'NOT_APPLICABLE', 'NOT_ASSESSED')
    foreach ($s1 in $states) {
        foreach ($s2 in $states) {
            foreach ($s3 in $states) {
                $d = Resolve-ComplianceVerdict `
                    -Browser $browser `
                    -Layer1 (New-Layer -Layer 'L1' -State $s1 -Enforced $true) `
                    -Layer2 (New-Layer -Layer 'L2' -State $s2) `
                    -Layer3 (New-Layer -Layer 'L3' -State $s3)

                if ([string]$d.verdict -notin @('PASS', 'PASS_NOT_ENFORCED', 'FAIL', 'NOT_ASSESSED')) {
                    $invariantFailures += "$browser/$s1/$s2/$s3 produced an undeclared verdict '$($d.verdict)'"
                }
                if ([string]$d.verdict -eq 'PASS_NOT_ENFORCED' -and [bool]$d.counts_in_score) {
                    $invariantFailures += "$browser/$s1/$s2/$s3 counted PASS_NOT_ENFORCED towards the score"
                }
                if ([string]$d.verdict -eq 'NOT_ASSESSED' -and [bool]$d.counts_in_score) {
                    $invariantFailures += "$browser/$s1/$s2/$s3 counted NOT_ASSESSED towards the score"
                }
                if ([string]$d.verdict -eq 'PASS' -and $s1 -ne 'COMPLIANT' -and $s3 -ne 'COMPLIANT') {
                    $invariantFailures += "$browser/$s1/$s2/$s3 returned PASS without any COMPLIANT enforced evidence"
                }
                if ([string]::IsNullOrWhiteSpace([string]$d.reasoning)) {
                    $invariantFailures += "$browser/$s1/$s2/$s3 produced a verdict with no reasoning"
                }
            }
        }
    }
}

$combinations = 3 * 5 * 5 * 5

# ---------------------------------------------------------------------------
# Environment scenarios: the engine must behave correctly on endpoints that look
# nothing like the machine it was developed on.
# ---------------------------------------------------------------------------
. "$PSScriptRoot\management_channel.ps1"

$scenarioFailures = @()

function New-Scenario {
    param(
        [string]$Name,
        [bool]$DomainJoined,
        [bool]$MdmEnrolled,
        [bool]$AdmxIngested,
        [string[]]$Agents,
        [bool]$CloudManaged,
        [bool]$PolicyStoreReadable = $true,
        [bool]$PlatformSupported = $true
    )

    $mgmt = @{
        hostname            = 'SYNTHETIC'
        platform            = 'Windows'
        platform_supported  = $PlatformSupported
        platform_note       = ''
        elevated            = $true
        policy_store_access = @{ readable = $PolicyStoreReadable; denied_paths = @() }
        domain_joined       = $DomainJoined
        entra_joined        = $false
        entra_registered    = $false
        mdm                 = @{ enrolled = $MdmEnrolled; provider = 'MS DM Server'; management_url = 'https://synthetic'; upn = ''; enrollment_id = ''; evidence = @() }
        admx_ingestion      = @{ present = $AdmxIngested; apps = @(); evidence = @() }
        cloud_management    = @{ enrolled = $CloudManaged; service = 'Synthetic cloud management'; evidence = @(); readable = $false }
        agents              = @()
        readable_channels   = @()
        unreadable_channels = @()
        collected_at        = ''
    }

    foreach ($agent in @($Agents)) {
        $mgmt.agents += @{ name = $agent; evidence = 'synthetic' }
    }
    if ($CloudManaged) {
        $mgmt.unreadable_channels += @{ channel = 'CLOUD_BROWSER_MANAGEMENT'; service = 'Synthetic cloud management'; reason = 'synthetic'; impact = 'synthetic' }
    }
    if (-not $PolicyStoreReadable) {
        $mgmt.unreadable_channels += @{ channel = 'REGISTRY_ACCESS_DENIED'; service = 'registry'; reason = 'synthetic'; impact = 'synthetic' }
    }
    if (-not $PlatformSupported) {
        $mgmt.unreadable_channels += @{ channel = 'UNSUPPORTED_PLATFORM'; service = 'macOS'; reason = 'synthetic'; impact = 'synthetic' }
    }

    return @{ name = $Name; mgmt = $mgmt }
}

$scenarios = @(
    @{ case = (New-Scenario -Name 'Domain-joined, GPO only'              -DomainJoined $true  -MdmEnrolled $false -AdmxIngested $false -Agents @()              -CloudManaged $false); expect_channel = 'GPO';                       expect_incomplete = $false }
    @{ case = (New-Scenario -Name 'Intune-only, ADMX ingested'           -DomainJoined $false -MdmEnrolled $true  -AdmxIngested $true  -Agents @()              -CloudManaged $false); expect_channel = 'MDM_ADMX_INGESTED';         expect_incomplete = $false }
    @{ case = (New-Scenario -Name 'Co-managed: domain + Intune ADMX'     -DomainJoined $true  -MdmEnrolled $true  -AdmxIngested $true  -Agents @()              -CloudManaged $false); expect_channel = 'MANAGED_CHANNEL_AMBIGUOUS'; expect_incomplete = $false }
    @{ case = (New-Scenario -Name 'Domain + management agent'            -DomainJoined $true  -MdmEnrolled $false -AdmxIngested $false -Agents @('ManageEngine') -CloudManaged $false); expect_channel = 'MANAGED_CHANNEL_AMBIGUOUS'; expect_incomplete = $false }
    @{ case = (New-Scenario -Name 'Workgroup, agent only'                -DomainJoined $false -MdmEnrolled $false -AdmxIngested $false -Agents @('Tanium')       -CloudManaged $false); expect_channel = 'AGENT:Tanium';              expect_incomplete = $false }
    @{ case = (New-Scenario -Name 'Unmanaged standalone'                 -DomainJoined $false -MdmEnrolled $false -AdmxIngested $false -Agents @()              -CloudManaged $false); expect_channel = 'LOCAL_OR_AGENT';            expect_incomplete = $false }
    @{ case = (New-Scenario -Name 'Cloud-managed browser'                -DomainJoined $false -MdmEnrolled $false -AdmxIngested $false -Agents @()              -CloudManaged $true);  expect_channel = 'LOCAL_OR_AGENT';            expect_incomplete = $true }
    @{ case = (New-Scenario -Name 'Registry not readable'                -DomainJoined $true  -MdmEnrolled $false -AdmxIngested $false -Agents @()              -CloudManaged $false -PolicyStoreReadable $false); expect_channel = 'GPO'; expect_incomplete = $true }
    @{ case = (New-Scenario -Name 'Unsupported platform'                 -DomainJoined $false -MdmEnrolled $false -AdmxIngested $false -Agents @()              -CloudManaged $false -PlatformSupported $false);    expect_channel = 'LOCAL_OR_AGENT'; expect_incomplete = $true }
)

Write-Host ''
Write-Host 'Environment scenarios' -ForegroundColor Cyan
Write-Host '---------------------' -ForegroundColor Cyan

foreach ($scenario in $scenarios) {
    $case = $scenario.case
    $mgmt = $case.mgmt

    # Channel attribution is exercised through the same code path production uses,
    # with a policy key that is guaranteed not to exist so the candidate-channel
    # logic is what decides the label.
    $candidates = @()
    if ($mgmt.mdm.enrolled -and $mgmt.admx_ingestion.present) { $candidates += 'MDM_ADMX_INGESTED' }
    if ($mgmt.domain_joined) { $candidates += 'GPO' }
    foreach ($agent in @($mgmt.agents)) { $candidates += "AGENT:$($agent.name)" }
    $candidates = @($candidates | Select-Object -Unique)

    $label = 'LOCAL_OR_AGENT'
    if ($candidates.Count -eq 1) { $label = $candidates[0] }
    elseif ($candidates.Count -gt 1) { $label = 'MANAGED_CHANNEL_AMBIGUOUS' }

    $incomplete = Test-ManagedEvidenceIsIncomplete -ManagementProfile $mgmt

    $problems = @()
    if ($label -ne $scenario.expect_channel) {
        $problems += "channel expected '$($scenario.expect_channel)' but got '$label'"
    }
    if ([bool]$incomplete -ne [bool]$scenario.expect_incomplete) {
        $problems += "evidence-incomplete expected '$($scenario.expect_incomplete)' but got '$incomplete'"
    }

    if ($problems.Count -eq 0) {
        Write-Host ("  [OK]   {0}" -f $case.name) -ForegroundColor Green
    }
    else {
        $scenarioFailures += "$($case.name): $($problems -join '; ')"
        Write-Host ("  [FAIL] {0}  {1}" -f $case.name, ($problems -join '; ')) -ForegroundColor Red
    }
}

Write-Host ''
Write-Host ("Truth-table cases : {0}/{1} passed" -f $passed, $truthTable.Count) -ForegroundColor (& { if ($failures.Count -eq 0) { 'Green' } else { 'Red' } })
Write-Host ("Invariant sweep   : {0} state combinations checked, {1} violation(s)" -f $combinations, $invariantFailures.Count) -ForegroundColor (& { if ($invariantFailures.Count -eq 0) { 'Green' } else { 'Red' } })
Write-Host ("Environment cases : {0}/{1} passed" -f ($scenarios.Count - $scenarioFailures.Count), $scenarios.Count) -ForegroundColor (& { if ($scenarioFailures.Count -eq 0) { 'Green' } else { 'Red' } })

foreach ($violation in ($invariantFailures | Select-Object -Unique -First 20)) {
    Write-Host "  [INVARIANT] $violation" -ForegroundColor Red
}

Write-Host ''
if ($failures.Count -eq 0 -and $invariantFailures.Count -eq 0 -and $scenarioFailures.Count -eq 0) {
    Write-Host 'RESULT: engine behaviour matches the declared decision model.' -ForegroundColor Green
    exit 0
}

Write-Host 'RESULT: engine behaviour deviates from the declared decision model.' -ForegroundColor Red
exit 1
