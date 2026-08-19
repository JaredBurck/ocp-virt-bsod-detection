# test_ps_export_remediation.ps1
# -----------------------------------------------------------------------------
# Offline unit-style regression test for Export-RemediationArtifact (Issue J,
# peer-review gitlab-issue-drafts-open-after-remediation.md) in
# scripts/lib/Export-RemediationArtifact.ps1, dot-sourced by
# scripts/collect-windows-guest-info.ps1's -Remediate -Export <fmt> path.
#
# This dot-sources the actual production file directly (same pattern as
# tests/test_ps_verdict.ps1 for Get-StreamDriverVerdict.ps1) rather than
# extracting the function body. Test-Path/Get-ItemProperty/Get-Service --
# the only seams that touch the OS -- are stubbed after dot-sourcing (same
# technique tests/test_ps_protect_guest_staging_dir.ps1 uses for
# Invoke-Icacls), so this can run on any platform pwsh supports, without a
# real Windows registry or service control manager.
#
# Usage: pwsh tests/test_ps_export_remediation.ps1
# Exit code: 0 if every scenario matches its expected result, else 1.
# -----------------------------------------------------------------------------
param()

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Split-Path -Parent $ScriptDir
$Target = Join-Path $RepoRoot 'scripts/lib/Export-RemediationArtifact.ps1'

if (-not (Test-Path $Target)) {
  Write-Host "FAIL: $Target not found"
  exit 1
}

. $Target

if (-not (Get-Command Export-RemediationArtifact -ErrorAction SilentlyContinue)) {
  Write-Host "FAIL: Export-RemediationArtifact did not source correctly"
  exit 1
}

$PassCount = 0
$FailCount = 0

function Test-Pass { param([string]$Name) Write-Host "PASS: $Name"; $script:PassCount++ }
function Test-Fail { param([string]$Name) Write-Host "FAIL: $Name"; $script:FailCount++ }

function New-ScratchDir {
  $d = Join-Path ([System.IO.Path]::GetTempPath()) ("bsod-export-test-" + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $d -Force | Out-Null
  return $d
}

# --- Stub state shared by every scenario, reset per-scenario ----------------
$script:MockServicePaths = @()   # HKLM service keys that "exist" (Test-Path true)
$script:MockRegValues = @{}      # "$Path|$Name" -> value, for Get-ItemProperty
$script:MockQgaService = $null   # $null = QEMU-GA service absent

function Reset-Mocks {
  param(
    [string[]]$ServicePaths = @(),
    [hashtable]$RegValues = @{},
    $QgaService = $null
  )
  $script:MockServicePaths = $ServicePaths
  $script:MockRegValues = $RegValues
  $script:MockQgaService = $QgaService
}

function Test-Path {
  param($Path)
  return $script:MockServicePaths -contains $Path
}

function Get-ItemProperty {
  param($Path, $Name, $ErrorAction)
  $key = "$Path|$Name"
  if ($script:MockRegValues.ContainsKey($key)) {
    return [PSCustomObject]@{ $Name = $script:MockRegValues[$key] }
  }
  return $null
}

function Get-Service {
  param($Name, $ErrorAction)
  return $script:MockQgaService
}

$IoRecommended = 180
$IoDefault = 60
$IoTarget = 300

# --- Scenario (a): everything already tuned -> NothingToExport, no files ---
$dirA = New-ScratchDir
Reset-Mocks -ServicePaths @('HKLM:\SYSTEM\CurrentControlSet\Services\viostor', 'HKLM:\SYSTEM\CurrentControlSet\Services\vioscsi') `
  -RegValues @{
    'HKLM:\SYSTEM\CurrentControlSet\Services\viostor\Parameters|IoTimeoutValue' = 300
    'HKLM:\SYSTEM\CurrentControlSet\Services\vioscsi\Parameters|IoTimeoutValue' = 300
    'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl|CrashDumpEnabled' = 7
  } `
  -QgaService ([PSCustomObject]@{ StartType = 'Automatic'; Status = 'Running' })
$resultA = Export-RemediationArtifact -OutDir $dirA -Format 'both' `
  -IoTimeoutRecommended $IoRecommended -IoTimeoutDefault $IoDefault -IoTimeoutTarget $IoTarget -PhantomDevices @()
if ($resultA.NothingToExport -and $resultA.ExportedFiles.Count -eq 0) {
  Test-Pass "(a) fully-tuned guest -> NothingToExport, no files written"
} else {
  Test-Fail "(a) expected NothingToExport, got: $($resultA | ConvertTo-Json -Compress)"
}
if (-not (Test-Path (Join-Path $dirA 'remediation-export.reg'))) {
  Test-Pass "(a) no .reg file created on the filesystem"
} else {
  Test-Fail "(a) .reg file should not exist when nothing needs fixing"
}
Remove-Item -Path $dirA -Recurse -Force -ErrorAction SilentlyContinue

# --- Scenario (b): untuned viostor + disabled CrashDump + stopped QGA + a
#     phantom device -> both artifacts written, correct content in each ---
$dirB = New-ScratchDir
Reset-Mocks -ServicePaths @('HKLM:\SYSTEM\CurrentControlSet\Services\viostor') `
  -RegValues @{
    'HKLM:\SYSTEM\CurrentControlSet\Services\viostor\Parameters|IoTimeoutValue' = 60
    'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl|CrashDumpEnabled' = 0
  } `
  -QgaService ([PSCustomObject]@{ StartType = 'Manual'; Status = 'Stopped' })
$phantom = @([PSCustomObject]@{ FriendlyName = 'VMware SVGA 3D'; InstanceId = 'PCI\VEN_15AD&DEV_0405\3&abc' })
$resultB = Export-RemediationArtifact -OutDir $dirB -Format 'both' `
  -IoTimeoutRecommended $IoRecommended -IoTimeoutDefault $IoDefault -IoTimeoutTarget $IoTarget -PhantomDevices $phantom

if (-not $resultB.NothingToExport) {
  Test-Pass "(b) untuned guest -> NothingToExport is false"
} else {
  Test-Fail "(b) expected findings, got NothingToExport=true"
}
if ($resultB.RegItemCount -eq 2) {
  Test-Pass "(b) exactly 2 registry items planned (viostor IoTimeoutValue + CrashDumpEnabled; vioscsi absent)"
} else {
  Test-Fail "(b) expected RegItemCount=2, got $($resultB.RegItemCount)"
}
if ($resultB.QgaNeedsFix -eq $true) {
  Test-Pass "(b) QGA service flagged as needing fix"
} else {
  Test-Fail "(b) expected QgaNeedsFix=true"
}
if ($resultB.PhantomCount -eq 1) {
  Test-Pass "(b) 1 phantom device counted"
} else {
  Test-Fail "(b) expected PhantomCount=1, got $($resultB.PhantomCount)"
}
if ($resultB.ExportedFiles.Count -eq 2) {
  Test-Pass "(b) both .reg and .yml artifacts written"
} else {
  Test-Fail "(b) expected 2 exported files, got $($resultB.ExportedFiles.Count)"
}

$regPath = Join-Path $dirB 'remediation-export.reg'
$ymlPath = Join-Path $dirB 'remediation-playbook.yml'
# [System.IO.File]::Exists, not Test-Path -- Test-Path itself is one of the
# functions this file overrides (mocking the guest registry probe above), so
# calling it here would check $script:MockServicePaths instead of the real
# filesystem and always report "missing".
if ([System.IO.File]::Exists($regPath) -and [System.IO.File]::Exists($ymlPath)) {
  Test-Pass "(b) both artifact files exist on disk"
} else {
  Test-Fail "(b) one or both artifact files missing on disk"
}

$regContent = Get-Content -Path $regPath -Raw
if ($regContent -match [regex]::Escape('[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\viostor\Parameters]') -and
    $regContent -match '"IoTimeoutValue"=dword:0000012c') {
  Test-Pass "(b) .reg file contains viostor IoTimeoutValue=300 (0x12c) in correct key"
} else {
  Test-Fail "(b) .reg file missing/incorrect viostor IoTimeoutValue entry: $regContent"
}
if ($regContent -match [regex]::Escape('[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl]') -and
    $regContent -match '"CrashDumpEnabled"=dword:00000007') {
  Test-Pass "(b) .reg file contains CrashDumpEnabled=7 (0x7) in correct key"
} else {
  Test-Fail "(b) .reg file missing/incorrect CrashDumpEnabled entry: $regContent"
}
if ($regContent -notmatch 'vioscsi') {
  Test-Pass "(b) .reg file does not mention vioscsi (service not installed in this scenario)"
} else {
  Test-Fail "(b) .reg file should not reference an uninstalled driver"
}
if ($regContent -match 'QEMU-GA' -and $regContent -match 'phantom VMware device') {
  Test-Pass "(b) .reg file documents the non-representable QGA + phantom-device follow-ups as comments"
} else {
  Test-Fail "(b) .reg file missing the QGA/phantom-device follow-up comments"
}

$ymlContent = Get-Content -Path $ymlPath -Raw
if ($ymlContent -match 'ansible\.windows\.win_regedit' -and $ymlContent -match 'ansible\.windows\.win_service') {
  Test-Pass "(b) playbook uses win_regedit and win_service tasks"
} else {
  Test-Fail "(b) playbook missing expected ansible.windows module tasks: $ymlContent"
}
if ($ymlContent -match [regex]::Escape('data: 300') -and $ymlContent -match [regex]::Escape('data: 7')) {
  Test-Pass "(b) playbook sets IoTimeoutValue=300 and CrashDumpEnabled=7"
} else {
  Test-Fail "(b) playbook missing expected data values"
}
if ($ymlContent -match [regex]::Escape('pnputil /remove-device')) {
  Test-Pass "(b) playbook documents phantom-device removal as a commented example, not a live task"
} else {
  Test-Fail "(b) playbook missing the commented phantom-device example"
}

# R-11 (this test file's own regression, found while writing it): an earlier
# draft left $item.Description unquoted in the YAML "name:" field. Every
# Description contains "(was: N)" -- an unquoted ": " inside a YAML plain
# scalar is parsed as a nested mapping key, not literal text. Assert the
# generated file actually parses as YAML-shaped content (matching quoted
# "- name: "..."" lines), not just that it contains the right substrings.
$quotedNameLines = [regex]::Matches($ymlContent, '(?m)^\s*-\s*name:\s*"[^"]*\(was:[^"]*\)"\s*$')
if ($quotedNameLines.Count -ge 2) {
  Test-Pass "(b) task 'name:' values containing '(was: ...)' are double-quoted (valid YAML)"
} else {
  Test-Fail "(b) expected >=2 double-quoted 'name: `"...(was: ...)`"' lines, found $($quotedNameLines.Count) in: $ymlContent"
}

Remove-Item -Path $dirB -Recurse -Force -ErrorAction SilentlyContinue

# --- Scenario (c): -Format 'reg' only writes the .reg file, not the playbook ---
$dirC = New-ScratchDir
Reset-Mocks -ServicePaths @('HKLM:\SYSTEM\CurrentControlSet\Services\viostor') `
  -RegValues @{ 'HKLM:\SYSTEM\CurrentControlSet\Services\viostor\Parameters|IoTimeoutValue' = 60 } `
  -QgaService ([PSCustomObject]@{ StartType = 'Automatic'; Status = 'Running' })
$resultC = Export-RemediationArtifact -OutDir $dirC -Format 'reg' `
  -IoTimeoutRecommended $IoRecommended -IoTimeoutDefault $IoDefault -IoTimeoutTarget $IoTarget -PhantomDevices @()
if ($resultC.ExportedFiles.Count -eq 1 -and $resultC.ExportedFiles[0] -like '*.reg') {
  Test-Pass "(c) -Format reg writes exactly one .reg file"
} else {
  Test-Fail "(c) expected exactly one .reg file, got: $($resultC.ExportedFiles -join ', ')"
}
Remove-Item -Path $dirC -Recurse -Force -ErrorAction SilentlyContinue

# --- Scenario (d): -Format 'ansible' only writes the playbook, not the .reg ---
$dirD = New-ScratchDir
Reset-Mocks -ServicePaths @('HKLM:\SYSTEM\CurrentControlSet\Services\viostor') `
  -RegValues @{ 'HKLM:\SYSTEM\CurrentControlSet\Services\viostor\Parameters|IoTimeoutValue' = 60 } `
  -QgaService ([PSCustomObject]@{ StartType = 'Automatic'; Status = 'Running' })
$resultD = Export-RemediationArtifact -OutDir $dirD -Format 'ansible' `
  -IoTimeoutRecommended $IoRecommended -IoTimeoutDefault $IoDefault -IoTimeoutTarget $IoTarget -PhantomDevices @()
if ($resultD.ExportedFiles.Count -eq 1 -and $resultD.ExportedFiles[0] -like '*.yml') {
  Test-Pass "(d) -Format ansible writes exactly one .yml file"
} else {
  Test-Fail "(d) expected exactly one .yml file, got: $($resultD.ExportedFiles -join ', ')"
}
Remove-Item -Path $dirD -Recurse -Force -ErrorAction SilentlyContinue

# --- Scenario (e): no Parameters key at all (driver installed, never tuned) ---
# -- same "service key present, Parameters absent" case R-1's in-place branch
# treats as untuned (M-11) -- Get-ItemProperty on the Parameters path returns
# $null (no mock entry), current is falsy, so this must still be planned.
$dirE = New-ScratchDir
Reset-Mocks -ServicePaths @('HKLM:\SYSTEM\CurrentControlSet\Services\viostor') `
  -RegValues @{ 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl|CrashDumpEnabled' = 7 } `
  -QgaService ([PSCustomObject]@{ StartType = 'Automatic'; Status = 'Running' })
$resultE = Export-RemediationArtifact -OutDir $dirE -Format 'both' `
  -IoTimeoutRecommended $IoRecommended -IoTimeoutDefault $IoDefault -IoTimeoutTarget $IoTarget -PhantomDevices @()
if ($resultE.RegItemCount -eq 1) {
  Test-Pass "(e) service present with no Parameters key is still planned as untuned (M-11 parity)"
} else {
  Test-Fail "(e) expected RegItemCount=1 for absent-Parameters case, got $($resultE.RegItemCount)"
}
# The "was: <label>" text only appears in the Ansible task name (the .reg
# file has no free-text comment per value, only "[key]"/"name"=dword:hex),
# so the absent-Parameters label is asserted against the playbook.
$ymlContentE = Get-Content -Path (Join-Path $dirE 'remediation-playbook.yml') -Raw
if ($ymlContentE -match 'default/60') {
  Test-Pass "(e) playbook task name labels the prior state as 'default/60', not a bogus current value"
} else {
  Test-Fail "(e) expected 'default/60' label in: $ymlContentE"
}
Remove-Item -Path $dirE -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=============================================="
Write-Host " test_ps_export_remediation.ps1: $PassCount passed, $FailCount failed"
Write-Host "=============================================="
if ($FailCount -gt 0) { exit 1 }
exit 0
