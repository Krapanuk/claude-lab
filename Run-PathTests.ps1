param([switch]$KeepLab)

$runner = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'Run-All.ps1'
& $runner -SkipManagedPolicyTests -KeepLab:$KeepLab
