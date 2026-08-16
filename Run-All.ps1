param(
    [switch]$KeepLab,
    [switch]$SkipPathTests,
    [switch]$SkipManagedPolicyTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $repoRoot 'lib\Common.ps1')
. (Join-Path $repoRoot 'tests\PathTests.ps1')
. (Join-Path $repoRoot 'tests\ManagedPolicyTests.ps1')

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$resultDirectory = Join-Path $repoRoot ("results\$stamp")
$labRoot = Join-Path $env:TEMP ("claude-lab-$stamp-" + ([guid]::NewGuid().ToString('N').Substring(0,8)))
New-Item -ItemType Directory -Force -Path $resultDirectory,$labRoot | Out-Null

# Use a native PowerShell array for compatibility with Windows PowerShell 5.1.
$results = @()

function Add-AndPrintResult {
    param([Parameter(Mandatory)]$Result)
    $script:results += $Result
    Write-Host ("  {0,-24} {1}" -f $Result.Test, $Result.Status)
    if ($Result.Status -in @('ERROR','INCONCLUSIVE','SECURITY_FAIL')) {
        Write-Host ("    -> {0}" -f $Result.Observed) -ForegroundColor Yellow
        if ($Result.RawFile) { Write-Host ("    raw: {0}" -f (Join-Path $script:resultDirectory $Result.RawFile)) }
    }
}

try {
    $claude = Get-ClaudeExecutable
    $claudeVersion = (& $claude --version 2>&1 | Out-String).Trim()
    $windowsVersion = [System.Environment]::OSVersion.VersionString
    $psVersion = $PSVersionTable.PSVersion.ToString()

    Write-Host "Claude Lab" -ForegroundColor Cyan
    Write-Host "Claude Code: $claudeVersion"
    Write-Host "Lab root:    $labRoot"
    Write-Host "Results:     $resultDirectory"
    Write-Host ''

    if (-not $SkipPathTests) {
        Write-Host '[1/2] Windows path / Read deny tests...' -ForegroundColor Cyan
        try {
            foreach ($r in @(Invoke-ClaudeLabPathTests -LabRoot $labRoot -ResultDirectory $resultDirectory)) {
                Add-AndPrintResult -Result $r
            }
        }
        catch {
            Add-AndPrintResult -Result (New-ClaudeLabResult -Suite 'WindowsPathDenyRead' -Test 'SUITE' -Status 'ERROR' -Expected 'Path suite completes.' -Observed $_.Exception.Message)
        }
    }

    if (-not $SkipManagedPolicyTests) {
        Write-Host ''
        Write-Host '[2/2] Managed policy / project hook test...' -ForegroundColor Cyan
        try {
            foreach ($r in @(Invoke-ClaudeLabManagedPolicyTests -LabRoot $labRoot -ResultDirectory $resultDirectory)) {
                Add-AndPrintResult -Result $r
            }
        }
        catch {
            Add-AndPrintResult -Result (New-ClaudeLabResult -Suite 'ManagedPolicy' -Test 'SUITE' -Status 'ERROR' -Expected 'Managed policy suite completes.' -Observed $_.Exception.Message)
        }
    }

    $metadata = @{
        Generated = (Get-Date).ToString('o')
        ClaudeVersion = $claudeVersion
        WindowsVersion = $windowsVersion
        PowerShellVersion = $psVersion
        LabRoot = $labRoot
    }
    Write-ClaudeLabReports -Results $results -ResultDirectory $resultDirectory -Metadata $metadata

    $failures = @($results | Where-Object Status -eq 'SECURITY_FAIL')
    $errors = @($results | Where-Object Status -eq 'ERROR')
    $inconclusive = @($results | Where-Object Status -eq 'INCONCLUSIVE')

    Write-Host ''
    Write-Host 'Summary' -ForegroundColor Cyan
    Write-Host ("  PASS:          {0}" -f @($results | Where-Object Status -eq 'PASS').Count)
    Write-Host ("  SECURITY_FAIL: {0}" -f $failures.Count)
    Write-Host ("  INCONCLUSIVE:  {0}" -f $inconclusive.Count)
    Write-Host ("  SKIPPED:       {0}" -f @($results | Where-Object Status -eq 'SKIPPED').Count)
    Write-Host ("  ERROR:         {0}" -f $errors.Count)
    Write-Host ''
    Write-Host "Report: $(Join-Path $resultDirectory 'REPORT.md')"

    if ($failures.Count -gt 0) {
        Write-Host ''
        Write-Host 'Candidate security boundary failures detected. Preserve the raw result directory and re-run the specific case before reporting.' -ForegroundColor Yellow
    }
}
finally {
    if ($KeepLab) {
        Write-Host "Temporary lab preserved: $labRoot"
    }
    elseif (Test-Path -LiteralPath $labRoot) {
        try { Remove-Item -LiteralPath $labRoot -Recurse -Force -ErrorAction Stop }
        catch { Write-Warning "Could not remove temporary lab directory: $($_.Exception.Message)" }
    }
}
