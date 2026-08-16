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

    $baselineRaw = Join-Path $ResultDirectory 'managed-01-baseline.txt'
    Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
    $baseline = Invoke-ClaudeCaptured -Arguments @('--init-only') -WorkingDirectory $project -OutputFile $baselineRaw

    if (-not (Test-Path -LiteralPath $marker)) {
        $results.Add((New-ClaudeLabResult -Suite $suite -Test 'ALLOW_MANAGED_HOOKS_ONLY' -Status 'SKIPPED' -Expected 'Baseline project Setup hook should execute before policy is applied.' -Observed 'Baseline hook did not execute, so the managed-policy oracle cannot be validated.' -Evidence "ExitCode=$($baseline.ExitCode)" -RawFile 'managed-01-baseline.txt'))
        return $results
    }

    Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue

    # HKCU is the lowest-priority managed policy source. If a higher-priority
    # machine/file policy exists, Claude Code may ignore HKCU entirely, making
    # this specific test invalid rather than vulnerable.
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
        $results.Add((New-ClaudeLabResult -Suite $suite -Test 'ALLOW_MANAGED_HOOKS_ONLY' -Status 'SKIPPED' -Expected 'Project hook blocked by HKCU managed policy.' -Observed ('Higher-priority managed source detected; HKCU test would be ambiguous: ' + ($higherPolicyReasons -join '; ')) -RawFile 'managed-01-baseline.txt'))
        return $results
    }

    $policyPath = 'HKCU:\SOFTWARE\Policies\ClaudeCode'
    $keyOriginallyExisted = Test-Path -LiteralPath $policyPath
    $settingsOriginallyExisted = $false
    $originalSettings = $null

    if ($keyOriginallyExisted) {
        try {
            $originalSettings = (Get-ItemProperty -LiteralPath $policyPath -Name 'Settings' -ErrorAction Stop).Settings
            $settingsOriginallyExisted = $true
        } catch {}
    }

    $managedRaw = Join-Path $ResultDirectory 'managed-02-policy-enforced.txt'
    try {
        if (-not (Test-Path -LiteralPath $policyPath)) {
            New-Item -Path $policyPath -Force | Out-Null
        }

        $policyJson = (@{ allowManagedHooksOnly = $true } | ConvertTo-Json -Compress)
        New-ItemProperty -LiteralPath $policyPath -Name 'Settings' -PropertyType String -Value $policyJson -Force | Out-Null

        # Give registry notification/read paths a moment to settle before a new CLI process starts.
        Start-Sleep -Milliseconds 300

        $run = Invoke-ClaudeCaptured -Arguments @('--init-only') -WorkingDirectory $project -OutputFile $managedRaw

        if (Test-Path -LiteralPath $marker) {
            $status = 'SECURITY_FAIL'
            $observed = 'Project-controlled Setup hook executed even though HKCU managed settings set allowManagedHooksOnly=true.'
            $evidence = "Marker=$marker; ExitCode=$($run.ExitCode); Policy=$policyJson"
        }
        else {
            $status = 'PASS'
            $observed = 'Project Setup hook was blocked after allowManagedHooksOnly=true was applied as managed policy.'
            $evidence = "ExitCode=$($run.ExitCode); Policy=$policyJson"
        }

        $results.Add((New-ClaudeLabResult -Suite $suite -Test 'ALLOW_MANAGED_HOOKS_ONLY' -Status $status -Expected 'Project hooks must not load when allowManagedHooksOnly=true is supplied as managed policy.' -Observed $observed -Evidence $evidence -RawFile 'managed-02-policy-enforced.txt'))
    }
    catch {
        $results.Add((New-ClaudeLabResult -Suite $suite -Test 'ALLOW_MANAGED_HOOKS_ONLY' -Status 'ERROR' -Expected 'Project hook blocked by managed policy.' -Observed $_.Exception.Message -RawFile 'managed-02-policy-enforced.txt'))
    }
    finally {
        Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue

        try {
            if ($settingsOriginallyExisted) {
                New-ItemProperty -LiteralPath $policyPath -Name 'Settings' -PropertyType String -Value ([string]$originalSettings) -Force | Out-Null
            }
            elseif (Test-Path -LiteralPath $policyPath) {
                Remove-ItemProperty -LiteralPath $policyPath -Name 'Settings' -ErrorAction SilentlyContinue
            }

            if (-not $keyOriginallyExisted -and (Test-Path -LiteralPath $policyPath)) {
                $remaining = @(Get-ItemProperty -LiteralPath $policyPath | Get-Member -MemberType NoteProperty | Where-Object Name -notmatch '^PS')
                if ($remaining.Count -eq 0) {
                    Remove-Item -LiteralPath $policyPath -Force -ErrorAction SilentlyContinue
                }
            }
        }
        catch {
            $results.Add((New-ClaudeLabResult -Suite $suite -Test 'POLICY_RESTORE' -Status 'ERROR' -Expected 'Original HKCU ClaudeCode policy state restored.' -Observed $_.Exception.Message))
        }
    }

    return $results
}
