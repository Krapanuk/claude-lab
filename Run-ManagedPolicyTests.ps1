param([switch]$KeepLab)

$runner = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'Run-All.ps1'
& $runner -SkipPathTests -KeepLab:$KeepLab
