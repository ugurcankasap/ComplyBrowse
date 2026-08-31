[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidDefaultValueSwitchParameter', '', Justification = 'False positive in editor diagnostics; no switch default is set in this script.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidAssignmentToAutomaticVariable', 'args', Justification = 'False positive in editor diagnostics; script does not assign to automatic variable $args.')]
param(
    [switch]$SkipPythonInstall,
    [switch]$DisableBreakSystemPackages,
    [string]$PythonPath = ""
)

$ErrorActionPreference = 'Stop'

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    Write-Host "" -ForegroundColor Gray
    Write-Host "=== $Name ===" -ForegroundColor Cyan
    & $Action
    Write-Host "[OK] $Name" -ForegroundColor Green
}

function Get-PythonCommand {
    $candidates = New-Object System.Collections.Generic.List[object]

    function Add-Candidate {
        param(
            [System.Collections.Generic.List[object]]$List,
            [string]$Executable,
            [string[]]$Prefix
        )

        $List.Add([pscustomobject]@{
            Exe = $Executable
            Prefix = $Prefix
        }) | Out-Null
    }

    if (-not [string]::IsNullOrWhiteSpace($PythonPath)) {
        Add-Candidate -List $candidates -Executable $PythonPath -Prefix @()
    }

    $localBin = Join-Path $HOME '.local/bin'
    if (Test-Path $localBin) {
        $localPythons = Get-ChildItem -Path $localBin -Filter 'python*.exe' -File -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending
        foreach ($item in $localPythons) {
            Add-Candidate -List $candidates -Executable $item.FullName -Prefix @()
        }
    }

    if (Get-Command python3 -ErrorAction SilentlyContinue) {
        Add-Candidate -List $candidates -Executable 'python3' -Prefix @()
    }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        Add-Candidate -List $candidates -Executable 'python' -Prefix @()
    }
    if (Get-Command py -ErrorAction SilentlyContinue) {
        Add-Candidate -List $candidates -Executable 'py' -Prefix @('-3')
    }

    foreach ($candidate in $candidates) {
        $exe = [string]$candidate.Exe
        $prefix = @($candidate.Prefix)
        try {
            & $exe @prefix -V *> $null
            if ($LASTEXITCODE -eq 0) {
                return @{ Exe = $exe; Prefix = $prefix }
            }
        }
        catch {
            continue
        }
    }

    throw 'Python runtime not found. Install Python 3 or py launcher.'
}

function Invoke-Python {
    param([string[]]$CommandParts)

    $py = Get-PythonCommand
    $exe = [string]$py.Exe
    $prefix = @($py.Prefix)

    & $exe @prefix @CommandParts
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed: $exe $($prefix + $CommandParts -join ' ')"
    }
}

function Invoke-ValidationScript {
    param(
        [string]$ScriptPath,
        [string[]]$ScriptArgs = @(),
        [string]$FailureMessage
    )

    powershell -ExecutionPolicy RemoteSigned -File $ScriptPath @ScriptArgs
    if ($LASTEXITCODE -ne 0) {
        throw $FailureMessage
    }
}

function Invoke-PipInstall {
    param([string[]]$CommandParts)

    $allowBreakSystemPackages = -not $DisableBreakSystemPackages

    try {
        Invoke-Python -CommandParts (@('-m', 'pip') + $CommandParts)
    }
    catch {
        if ($allowBreakSystemPackages -and -not ($CommandParts -contains '--break-system-packages')) {
            Write-Host 'Retrying pip command with --break-system-packages...' -ForegroundColor Yellow
            Invoke-Python -CommandParts (@('-m', 'pip') + $CommandParts + @('--break-system-packages'))
        }
        else {
            throw
        }
    }
}

Set-Location $PSScriptRoot

Invoke-Step -Name 'Python install dependencies' -Action {
    if ($SkipPythonInstall) {
        Write-Host 'Skipping pip install step by request.' -ForegroundColor Yellow
        return
    }

    Invoke-PipInstall -CommandParts @('install', '--upgrade', 'pip')
    Invoke-PipInstall -CommandParts @('install', '-r', 'requirements.txt')
}

Invoke-Step -Name 'Python syntax check' -Action {
    Invoke-Python -CommandParts @('-m', 'compileall', 'browser_security_agent.py', 'tests', 'qa_tests')
}

Invoke-Step -Name 'Python contract tests' -Action {
    Invoke-Python -CommandParts @('-m', 'unittest', 'discover', '-s', 'qa_tests', '-p', 'test_*.py', '-v')
}

Invoke-Step -Name 'Python coverage gate' -Action {
    Invoke-Python -CommandParts @('-m', 'coverage', 'run', '--source=browser_security_agent,tests', '-m', 'unittest', 'discover', '-s', 'qa_tests', '-p', 'test_*.py')
    Invoke-Python -CommandParts @('-m', 'coverage', 'report', '--fail-under=60')
}

Invoke-Step -Name 'Verification engine self-validation' -Action {
    Invoke-ValidationScript -ScriptPath '.\validate_verification_engine.ps1' `
        -FailureMessage 'Decision engine deviates from the declared truth table.'
}

Invoke-Step -Name 'Generate Edge results' -Action {
    Invoke-ValidationScript -ScriptPath '.\test_runner.ps1' `
        -ScriptArgs @('-OutputJSON', '-OutputFile', '.\edge_test_results.json') `
        -FailureMessage 'Edge result generation failed.'
}

Invoke-Step -Name 'Generate Chrome results' -Action {
    Invoke-ValidationScript -ScriptPath '.\chrome_test_runner.ps1' `
        -ScriptArgs @('-OutputJSON', '-OutputFile', '.\chrome_test_results.json') `
        -FailureMessage 'Chrome result generation failed.'
}

Invoke-Step -Name 'Generate Firefox results' -Action {
    Invoke-ValidationScript -ScriptPath '.\firefox_test_runner.ps1' `
        -ScriptArgs @('-OutputJSON', '-OutputFile', '.\firefox_test_results.json') `
        -FailureMessage 'Firefox result generation failed.'
}

Invoke-Step -Name 'Apply value verification (Edge)' -Action {
    Invoke-ValidationScript -ScriptPath '.\apply_verification.ps1' `
        -ScriptArgs @('-InputFile', '.\edge_test_results.json', '-Browser', 'edge', '-OutputFile', '.\edge_verified.json') `
        -FailureMessage 'Edge value verification failed.'
}

Invoke-Step -Name 'Apply value verification (Chrome)' -Action {
    Invoke-ValidationScript -ScriptPath '.\apply_verification.ps1' `
        -ScriptArgs @('-InputFile', '.\chrome_test_results.json', '-Browser', 'chrome', '-OutputFile', '.\chrome_verified.json') `
        -FailureMessage 'Chrome value verification failed.'
}

Invoke-Step -Name 'Apply value verification (Firefox)' -Action {
    Invoke-ValidationScript -ScriptPath '.\apply_verification.ps1' `
        -ScriptArgs @('-InputFile', '.\firefox_test_results.json', '-Browser', 'firefox', '-OutputFile', '.\firefox_verified.json') `
        -FailureMessage 'Firefox value verification failed.'
}

Invoke-Step -Name 'Result integrity audit (all browsers)' -Action {
    foreach ($report in @('.\edge_verified.json', '.\chrome_verified.json', '.\firefox_verified.json')) {
        Invoke-ValidationScript -ScriptPath '.\audit_result_integrity.ps1' `
            -ScriptArgs @('-InputFile', $report) `
            -FailureMessage "Blocking integrity defects found in $report; the report is not publishable."
    }
}

Invoke-Step -Name 'Verification regression gate' -Action {
    Invoke-ValidationScript -ScriptPath '.\qa_tests\verification_regression_gate.ps1' `
        -FailureMessage 'Verification regression gate failed; thresholds regressed.'
}

Write-Host "" -ForegroundColor Gray
Write-Host 'Local CI-equivalent validation completed successfully.' -ForegroundColor Green
