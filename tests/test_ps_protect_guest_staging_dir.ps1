# test_ps_protect_guest_staging_dir.ps1
# -----------------------------------------------------------------------------
# Offline unit-style regression test for Protect-GuestStagingDir (v0.16.0
# review #2 -- LPE fix) in scripts/lib/Protect-GuestStagingDir.ps1, dot-sourced
# by windows-exporter/install-windows-exporter.ps1.
#
# Mirrors tests/test_qga_harden_staging_dir.sh, which covers the equivalent
# bash+QGA function (harden_guest_staging_dir). Both functions must agree on
# the fail-closed contract: reclaim ownership, strip inherited ACEs, grant
# only SYSTEM + Administrators, then re-read the ACL and abort if any
# Users/Everyone/Authenticated Users ACE survives.
#
# This dot-sources the actual production file directly (same pattern as
# tests/test_ps_verdict.ps1 for Get-StreamDriverVerdict.ps1) rather than
# extracting the function body, since the file contains nothing but function
# definitions and has no top-level side effects. Invoke-Icacls -- the only
# seam that touches the OS -- is stubbed after dot-sourcing so this can run
# on any platform pwsh supports, without a real Windows ACL engine.
#
# Usage: pwsh tests/test_ps_protect_guest_staging_dir.ps1
# Exit code: 0 if every scenario matches its expected result, else 1.
# -----------------------------------------------------------------------------
param()

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Split-Path -Parent $ScriptDir
$Target = Join-Path $RepoRoot 'scripts/lib/Protect-GuestStagingDir.ps1'

if (-not (Test-Path $Target)) {
  Write-Host "FAIL: $Target not found"
  exit 1
}

. $Target

if (-not (Get-Command Protect-GuestStagingDir -ErrorAction SilentlyContinue)) {
  Write-Host "FAIL: Protect-GuestStagingDir did not source correctly"
  exit 1
}

$PassCount = 0
$FailCount = 0

function Test-Pass { param([string]$Name) Write-Host "PASS: $Name"; $script:PassCount++ }
function Test-Fail { param([string]$Name) Write-Host "FAIL: $Name"; $script:FailCount++ }

$script:CallLog = @()
$script:ReadBackOutput = @()

# Stub for Invoke-Icacls: records every invocation's argument list. The
# read-back call is the only one made with a single argument (just -Path);
# setowner/grant calls always pass additional flags.
function Invoke-Icacls {
  param([string[]]$Arguments)
  $script:CallLog += , ($Arguments -join ' ')
  if ($Arguments.Count -eq 1) {
    return $script:ReadBackOutput
  }
  return @('Successfully processed 1 files; Failed processing 0 files')
}

function Reset-Stubs {
  param([string[]]$ReadBack)
  $script:CallLog = @()
  $script:ReadBackOutput = $ReadBack
}

function New-ScratchDir {
  $d = Join-Path ([System.IO.Path]::GetTempPath()) ("bsod-pgsd-test-" + [guid]::NewGuid().ToString('N'))
  return $d
}

# --- Scenario (a): clean ACL after hardening -> no exception ---
$dirA = New-ScratchDir
Reset-Stubs -ReadBack @(
  "$dirA NT AUTHORITY\SYSTEM:(OI)(CI)(F)",
  "      BUILTIN\Administrators:(OI)(CI)(F)",
  "",
  "Successfully processed 1 files; Failed processing 0 files"
)
try {
  Protect-GuestStagingDir -Path $dirA
  Test-Pass "(a) clean ACL (SYSTEM + Administrators only) does not throw"
} catch {
  Test-Fail "(a) clean ACL should not throw, got: $($_.Exception.Message)"
}
if (Test-Path $dirA) {
  Test-Pass "(a) target directory was created"
} else {
  Test-Fail "(a) target directory was not created"
}
Remove-Item -Path $dirA -Recurse -Force -ErrorAction SilentlyContinue

# --- Scenario (b): leftover BUILTIN\Users ACE -> hard failure ---
$dirB = New-ScratchDir
Reset-Stubs -ReadBack @(
  "$dirB NT AUTHORITY\SYSTEM:(OI)(CI)(F)",
  "      BUILTIN\Administrators:(OI)(CI)(F)",
  "      BUILTIN\Users:(OI)(CI)(RX)"
)
try {
  Protect-GuestStagingDir -Path $dirB
  Test-Fail "(b) ACL still granting BUILTIN\Users should throw, did not"
} catch {
  Test-Pass "(b) ACL still granting BUILTIN\Users throws"
}
Remove-Item -Path $dirB -Recurse -Force -ErrorAction SilentlyContinue

# --- Scenario (b2): leftover Everyone ACE -> hard failure ---
$dirB2 = New-ScratchDir
Reset-Stubs -ReadBack @("$dirB2 Everyone:(OI)(CI)(F)")
try {
  Protect-GuestStagingDir -Path $dirB2
  Test-Fail "(b2) ACL still granting Everyone should throw, did not"
} catch {
  Test-Pass "(b2) ACL still granting Everyone throws"
}
Remove-Item -Path $dirB2 -Recurse -Force -ErrorAction SilentlyContinue

# --- Scenario (b3): leftover well-known SID (S-1-5-11, Authenticated Users) ---
$dirB3 = New-ScratchDir
Reset-Stubs -ReadBack @("$dirB3 S-1-5-11:(OI)(CI)(RX)")
try {
  Protect-GuestStagingDir -Path $dirB3
  Test-Fail "(b3) ACL still granting Authenticated Users SID should throw, did not"
} catch {
  Test-Pass "(b3) ACL still granting Authenticated Users SID throws"
}
Remove-Item -Path $dirB3 -Recurse -Force -ErrorAction SilentlyContinue

# --- Scenario (c): icacls read-back returns nothing -> fail closed ---
$dirC = New-ScratchDir
Reset-Stubs -ReadBack @()
try {
  Protect-GuestStagingDir -Path $dirC
  Test-Fail "(c) empty/unreadable ACL should fail closed (throw), did not"
} catch {
  Test-Pass "(c) empty/unreadable ACL fails closed (throws)"
}
Remove-Item -Path $dirC -Recurse -Force -ErrorAction SilentlyContinue

# --- Scenario (d): exact icacls argument lists are well-formed ---
$dirD = New-ScratchDir
Reset-Stubs -ReadBack @("$dirD NT AUTHORITY\SYSTEM:(OI)(CI)(F)")
try { Protect-GuestStagingDir -Path $dirD } catch { }

if ($script:CallLog -contains "$dirD /setowner *S-1-5-32-544 /T /C") {
  Test-Pass "(d) /setowner call reclaims ownership to BUILTIN\Administrators SID"
} else {
  Test-Fail "(d) /setowner call missing or malformed: $($script:CallLog -join ' | ')"
}

if ($script:CallLog -contains "$dirD /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F /grant:r *S-1-5-32-544:(OI)(CI)F /T /C") {
  Test-Pass "(d) /inheritance:r + /grant:r call grants only SYSTEM + Administrators SIDs"
} else {
  Test-Fail "(d) /inheritance:r + /grant:r call missing or malformed: $($script:CallLog -join ' | ')"
}
Remove-Item -Path $dirD -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=============================================="
Write-Host " test_ps_protect_guest_staging_dir.ps1: $PassCount passed, $FailCount failed"
Write-Host "=============================================="
if ($FailCount -gt 0) { exit 1 }
exit 0
