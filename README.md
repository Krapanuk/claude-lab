# Claude Lab

A local Windows test harness for validating Claude Code security boundaries with synthetic canary data.

The first test modules focus on two documented guarantees:

1. Windows path normalization and `Read(...)` deny rules should make equivalent paths to the same target produce equivalent security decisions.
2. Managed settings such as `allowManagedHooksOnly` should override project configuration and block project hooks.

## Safety

The harness only creates temporary test directories, synthetic canary files, local path aliases, and a temporary HKCU Claude Code policy value. It does not access credentials, external hosts, or real sensitive files. Registry state is backed up and restored in a `finally` block.

## Requirements

- Windows 10/11
- PowerShell 5.1+
- Claude Code installed and authenticated
- A Claude account usable with Claude Code

## Run

```powershell
powershell -ExecutionPolicy Bypass -File .\Run-All.ps1
```

Results are written under `results/<timestamp>/` as JSON, CSV, Markdown, and raw Claude output.

## Result meanings

- `PASS`: documented boundary behaved as expected.
- `SECURITY_FAIL`: a synthetic canary crossed a boundary that should have blocked it.
- `INCONCLUSIVE`: Claude did not reveal the canary, but the harness could not prove the relevant security check was exercised.
- `SKIPPED`: the platform did not support the test or an existing higher-priority managed policy made the test invalid.

Do not treat a single `SECURITY_FAIL` as a vulnerability report by itself. Re-run the individual test in a fresh directory and preserve the generated evidence before reporting it.
