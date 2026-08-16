Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-ClaudeLabManagedPolicyTests {
    param(
        [Parameter(Mandatory)][string]$LabRoot,
        [Parameter(Mandatory)][string]$ResultDirectory
    )

    $results = New-Object System.Collections.Generic.List[object]
    $suite = 'ManagedPolicy'
    $project = Join-Path $LabRoot 'managed-hook-project'
    $claudeDir = Join-Path $project '.claude'
    New-Item -ItemType Directory -Force -Path $claudeDir | Out-Null

    $markerName = 'claude-lab-managed-hook-' + ([guid]::NewGuid().ToString('N')) + '.txt'
    $marker = Join-Path $env:TEMP $markerName
    $hookCommand = "Set-Content -LiteralPath (Join-Path `$env:TEMP '$markerName') -Value 'PROJECT_HOOK_RAN'"

    $projectSettings = @{
        hooks = @{
            Setup = @(
                @{
                    matcher = 'init'
                    hooks = @(
                        @{
                            type = 'command'
                            shell = 'powershell'
                            command = $hookCommand
                        }
                    )
                }
            )
        }
    }
    $projectSettings | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $claudeDir 'settings.json') -Encoding UTF8

    $initArgs = @('--setting-sources','project','--init-only')

    # Positive control: the project hook must work before any managed policy is introduced.
    $baselineRaw = Join-Path $ResultDirectory 'managed-01-baseline.txt'
    Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
    $baseline = Invoke-ClaudeCaptured -Arguments $initArgs -WorkingDirectory $project -OutputFile $baselineRaw

    if (-not (Test-Path -LiteralPath $marker)) {
        $excerpt = ([string]$baseline.Output).Trim()
        if ($excerpt.Length -gt 500) { $excerpt = $excerpt.Substring(0,500) + '...' }
        $results.Add((New-ClaudeLabResult -Suite $suite -Test 'ALLOW_MANAGED_HOOKS_ONLY' -Status 'SKIPPED' -Expected 'Baseline project Setup hook should execute before the test policy is applied.' -Observed "Baseline hook did not execute, so the managed-policy oracle cannot be validated. ExitCode=$($baseline.ExitCode); Output=$excerpt" -RawFile 'managed-01-baseline.txt'))
        return $results
    }

    Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue

    # HKCU is the lowest-priority managed policy source. If a higher-priority local policy
    # exists, this specific HKCU experiment is ambiguous and should be skipped.
    $higherPolicyReasons = New-Object System.Collections.Generic.List[string]
    try {
        $hklm = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\ClaudeCode' -Name 'Settings' -ErrorAction Stop
        if ($null -ne $hklm.Settings) { $higherPolicyReasons.Add('HKLM ClaudeCode Settings policy exists') }
    } catch {}

    $managedFile = Join-Path $env:ProgramFiles 'ClaudeCode\managed-settings.json'
    $managedDropIn = Join-Path $env:ProgramFiles 'ClaudeCode\managed-settings.d'
    if (Test-Path -LiteralPath $managedFile) { $higherPolicyReasons.Add($managedFile) }
    if (Test-Path -LiteralPath $managedDropIn) { $higherPolicyReasons.Add($managedDropIn) }

    if ($higherPolicyReasons.Count -gt 0) {
        $results.Add((New-ClaudeLabResult -Suite $suite -Test 'ALLOW_MANAGED_HOOKS_ONLY' -Status 'SKIPPED' -Expected 'Project hook blocked by HKCU managed policy.' -Observed ('Higher-priority local managed source detected; HKCU test would be ambiguous: ' + ($higherPolicyReasons -join '; ')) -RawFile 'managed-01-baseline.txt'))
        return $results
    }

    $policyPath = 'HKCU:\SOFTWARE\Policies\ClaudeCode'
    $keyOriginallyExisted = Test-Path -LiteralPath $policyPath
    $settingsOriginallyExisted = $false
    $originalSettings = $null

    if ($keyOriginallyExisted) {
        try {
            $originalSettings = (Get-ItemProperty -Path $policyPath -Name 'Settings' -ErrorAction Stop).Settings
            $settingsOriginallyExisted = $true
        } catch {}
    }

    # Some managed/corporate Windows installations ACL the Policies subtree even under HKCU.
    # Probe writability with a unique harmless temporary value before touching Settings.
    $probeName = 'ClaudeLabWriteProbe_' + ([guid]::NewGuid().ToString('N'))
    $probeCreatedKey = $false
    try {
        if (-not (Test-Path -LiteralPath $policyPath)) {
            New-Item -Path $policyPath -Force -ErrorAction Stop | Out-Null
            $probeCreatedKey = $true
        }
        New-ItemProperty -Path $policyPath -Name $probeName -PropertyType String -Value '1' -Force -ErrorAction Stop | Out-Null
        Remove-ItemProperty -Path $policyPath -Name $probeName -ErrorAction SilentlyContinue
    }
    catch {
        try { Remove-ItemProperty -Path $policyPath -Name $probeName -ErrorAction SilentlyContinue } catch {}
        if ($probeCreatedKey -and (Test-Path -LiteralPath $policyPath)) {
            try { Remove-Item -LiteralPath $policyPath -Force -ErrorAction SilentlyContinue } catch {}
        }
        $results.Add((New-ClaudeLabResult -Suite $suite -Test 'ALLOW_MANAGED_HOOKS_ONLY' -Status 'SKIPPED' -Expected 'HKCU managed settings are writable for this local experiment.' -Observed ('HKCU policy key is not writable by the current process: ' + $_.Exception.Message + '. Re-run only this suite from an elevated PowerShell if you explicitly want to test local managed-policy enforcement.')))
        return $results
    }

    $managedRaw = Join-Path $ResultDirectory 'managed-02-policy-enforced.txt'
    $policyTouched = $false
    try {
        $policyJson = (@{ allowManagedHooksOnly = $true } | ConvertTo-Json -Compress)
        New-ItemProperty -Path $policyPath -Name 'Settings' -PropertyType String -Value $policyJson -Force -ErrorAction Stop | Out-Null
        $policyTouched = $true

        Start-Sleep -Milliseconds 300
        $run = Invoke-ClaudeCaptured -Arguments $initArgs -WorkingDirectory $project -OutputFile $managedRaw

        if (Test-Path -LiteralPath $marker) {
            $status = 'SECURITY_FAIL'
            $observed = 'Project-controlled Setup hook executed even though HKCU managed settings set allowManagedHooksOnly=true.'
            $evidence = "Marker=$marker; ExitCode=$($run.ExitCode); Policy=$policyJson"
        }
        elseif ($run.ExitCode -ne 0) {
            $status = 'INCONCLUSIVE'
            $observed = "Marker was blocked, but Claude exited non-zero. Confirm that the managed policy was actually loaded before treating this as PASS. ExitCode=$($run.ExitCode)"
            $evidence = "Policy=$policyJson; Output=$(([string]$run.Output).Trim())"
        }
        else {
            $status = 'PASS'
            $observed = 'Project Setup hook executed in baseline and was blocked after allowManagedHooksOnly=true was applied as HKCU managed policy.'
            $evidence = "ExitCode=$($run.ExitCode); Policy=$policyJson"
        }

        $results.Add((New-ClaudeLabResult -Suite $suite -Test 'ALLOW_MANAGED_HOOKS_ONLY' -Status $status -Expected 'Project hooks must not load when allowManagedHooksOnly=true is supplied as managed policy.' -Observed $observed -Evidence $evidence -RawFile 'managed-02-policy-enforced.txt'))
    }
    catch {
        $status = if ($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception.Message -match '(?i)access|zugriff.*verweigert|denied') { 'SKIPPED' } else { 'ERROR' }
        $results.Add((New-ClaudeLabResult -Suite $suite -Test 'ALLOW_MANAGED_HOOKS_ONLY' -Status $status -Expected 'Project hook blocked by managed policy.' -Observed $_.Exception.Message -RawFile 'managed-02-policy-enforced.txt'))
    }
    finally {
        Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue

        if ($policyTouched) {
            try {
                if ($settingsOriginallyExisted) {
                    New-ItemProperty -Path $policyPath -Name 'Settings' -PropertyType String -Value ([string]$originalSettings) -Force | Out-Null
                }
                else {
                    Remove-ItemProperty -Path $policyPath -Name 'Settings' -ErrorAction SilentlyContinue
                }
            }
            catch {
                $results.Add((New-ClaudeLabResult -Suite $suite -Test 'POLICY_RESTORE' -Status 'ERROR' -Expected 'Original HKCU ClaudeCode Settings value restored.' -Observed $_.Exception.Message))
            }
        }

        if (-not $keyOriginallyExisted -and (Test-Path -LiteralPath $policyPath)) {
            try {
                $remaining = @(Get-ItemProperty -Path $policyPath | Get-Member -MemberType NoteProperty | Where-Object Name -notmatch '^PS')
                if ($remaining.Count -eq 0) {
                    Remove-Item -LiteralPath $policyPath -Force -ErrorAction SilentlyContinue
                }
            } catch {}
        }
    }

    return $results
}
