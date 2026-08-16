Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ClaudeExecutable {
    $cmd = Get-Command claude -ErrorAction Stop
    return $cmd.Source
}

function New-ClaudeLabResult {
    param(
        [Parameter(Mandatory)][string]$Suite,
        [Parameter(Mandatory)][string]$Test,
        [Parameter(Mandatory)][ValidateSet('PASS','SECURITY_FAIL','INCONCLUSIVE','SKIPPED','ERROR')][string]$Status,
        [Parameter(Mandatory)][string]$Expected,
        [Parameter(Mandatory)][string]$Observed,
        [string]$Evidence = '',
        [string]$RawFile = ''
    )

    [pscustomobject]@{
        Timestamp = (Get-Date).ToString('o')
        Suite     = $Suite
        Test      = $Test
        Status    = $Status
        Expected  = $Expected
        Observed  = $Observed
        Evidence  = $Evidence
        RawFile   = $RawFile
    }
}

function Convert-ToClaudeAbsoluteRulePath {
    param([Parameter(Mandatory)][string]$Path)

    $full = [System.IO.Path]::GetFullPath($Path).Replace([char]92, [char]47)
    if ($full -match '^([A-Za-z]):/(.*)$') {
        return ('//{0}/{1}' -f $Matches[1].ToLowerInvariant(), $Matches[2])
    }
    throw "Expected a drive-letter Windows path, got: $Path"
}

function Invoke-ClaudeCaptured {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [Parameter(Mandatory)][string]$OutputFile
    )

    $claude = Get-ClaudeExecutable
    $old = Get-Location
    try {
        Set-Location -LiteralPath $WorkingDirectory
        $all = & $claude @Arguments 2>&1 | Out-String
        $exit = $LASTEXITCODE
    }
    catch {
        $all = ($_ | Out-String)
        $exit = -1
    }
    finally {
        Set-Location $old
    }

    Set-Content -LiteralPath $OutputFile -Value $all -Encoding UTF8
    [pscustomobject]@{
        ExitCode = $exit
        Output   = $all
    }
}

function Get-FreeSubstDriveLetter {
    $used = (Get-PSDrive -PSProvider FileSystem).Name
    foreach ($letter in [char[]]'ZYXWVUTSRQPONMLKJIHGFED') {
        $s = [string]$letter
        if ($used -notcontains $s) { return $s }
    }
    return $null
}

function Get-ShortPathNameSafe {
    param([Parameter(Mandatory)][string]$Path)

    if (-not ('ClaudeLab.NativeMethods' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
namespace ClaudeLab {
    public static class NativeMethods {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint GetShortPathName(string lpszLongPath, StringBuilder lpszShortPath, uint cchBuffer);
    }
}
'@
    }

    $sb = New-Object System.Text.StringBuilder 4096
    $n = [ClaudeLab.NativeMethods]::GetShortPathName($Path, $sb, $sb.Capacity)
    if ($n -eq 0) { return $null }
    $short = $sb.ToString()
    if ([string]::IsNullOrWhiteSpace($short) -or $short -eq $Path) { return $null }
    return $short
}

function Write-ClaudeLabReports {
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [Parameter(Mandatory)][string]$ResultDirectory,
        [Parameter(Mandatory)][hashtable]$Metadata
    )

    $jsonPath = Join-Path $ResultDirectory 'results.json'
    $csvPath = Join-Path $ResultDirectory 'results.csv'
    $mdPath = Join-Path $ResultDirectory 'REPORT.md'

    [pscustomobject]@{
        metadata = $Metadata
        results  = $Results
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

    $Results | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

    $counts = @{}
    foreach ($s in @('PASS','SECURITY_FAIL','INCONCLUSIVE','SKIPPED','ERROR')) {
        $counts[$s] = @($Results | Where-Object Status -eq $s).Count
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# Claude Lab Report')
    $lines.Add('')
    $lines.Add("- Generated: $($Metadata.Generated)")
    $lines.Add("- Claude Code: $($Metadata.ClaudeVersion)")
    $lines.Add("- Windows: $($Metadata.WindowsVersion)")
    $lines.Add("- PowerShell: $($Metadata.PowerShellVersion)")
    $lines.Add('')
    $lines.Add('## Summary')
    $lines.Add('')
    $lines.Add("- PASS: $($counts.PASS)")
    $lines.Add("- SECURITY_FAIL: $($counts.SECURITY_FAIL)")
    $lines.Add("- INCONCLUSIVE: $($counts.INCONCLUSIVE)")
    $lines.Add("- SKIPPED: $($counts.SKIPPED)")
    $lines.Add("- ERROR: $($counts.ERROR)")
    $lines.Add('')
    $lines.Add('## Results')
    $lines.Add('')
    $lines.Add('| Suite | Test | Status | Expected | Observed |')
    $lines.Add('|---|---|---|---|---|')
    foreach ($r in $Results) {
        $expected = ($r.Expected -replace '\|','\\|') -replace "`r?`n", ' '
        $observed = ($r.Observed -replace '\|','\\|') -replace "`r?`n", ' '
        $lines.Add("| $($r.Suite) | $($r.Test) | **$($r.Status)** | $expected | $observed |")
    }
    $lines.Add('')
    $lines.Add('A `SECURITY_FAIL` is a candidate finding, not proof by itself. Re-run it in a fresh lab directory and preserve the raw evidence.')

    Set-Content -LiteralPath $mdPath -Value $lines -Encoding UTF8
}
