# Protect-GuestStagingDir.ps1 -- ACL hardening for a SYSTEM-executed staging
# directory on a Windows guest. Dot-sourced by:
#   - windows-exporter/install-windows-exporter.ps1 (production)
#   - tests/test_ps_protect_guest_staging_dir.ps1 (CI harness)
#
# v0.16.0 review #2: install-windows-exporter.ps1 creates
# C:\ProgramData\windows_exporter\{lib,textfile} and later runs a SYSTEM
# scheduled task out of that tree with no ACL hardening -- the same LPE class
# harden_guest_staging_dir() (scripts/cnv-qga-fleet-collect.sh) already fixed
# for C:\DebugInfo (L-9). Directories created under C:\ProgramData inherit an
# ACL that lets BUILTIN\Users create files, and a standard user who
# pre-creates the directory becomes its owner -- either way an unprivileged
# guest user could plant a payload that a SYSTEM scheduled task then executes.
#
# This installer runs directly on the guest as Administrator (not via QGA
# from the hypervisor side, unlike the bash sibling), so it calls icacls.exe
# directly rather than reusing the bash+QGA wrapper. Same fail-closed
# contract as the bash version: reclaim ownership first (an owner can
# rewrite any DACL we set), strip inherited ACEs, grant only SYSTEM and
# Administrators, then re-read the ACL and abort if any
# Users/Everyone/Authenticated Users ACE survives.
#
# Icacls.exe is invoked through Invoke-Icacls so tests can stub it without
# touching a real filesystem/ACL -- mirrors the qga_exec/qga_exec_capture
# stub seams tests/test_qga_harden_staging_dir.sh already uses for the bash
# version.

function Invoke-Icacls {
  [CmdletBinding()]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Icacls is the Windows program name (icacls.exe), not a pluralized noun.')]
  param(
    [Parameter(Mandatory)]
    [string[]]$Arguments
  )
  & icacls.exe @Arguments 2>&1
}

function Protect-GuestStagingDir {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Path
  )

  if (-not (Test-Path $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }

  # Reclaim ownership first: if a low-privileged user pre-created the
  # directory they own it, and an owner can rewrite any DACL we set. Uses
  # the well-known SID for BUILTIN\Administrators (*S-1-5-32-544) instead of
  # the localized name, which fails outright on a non-English Windows
  # install.
  Invoke-Icacls -Arguments @($Path, '/setowner', '*S-1-5-32-544', '/T', '/C') | Out-Null

  # /inheritance:r drops inherited ACEs from the parent (this is what
  # removes BUILTIN\Users); /grant:r replaces rather than adds, so re-running
  # is idempotent. (OI)(CI) propagates the grant to files and subdirectories,
  # including ones that already exist under -Path (/T).
  Invoke-Icacls -Arguments @(
    $Path, '/inheritance:r',
    '/grant:r', '*S-1-5-18:(OI)(CI)F',
    '/grant:r', '*S-1-5-32-544:(OI)(CI)F',
    '/T', '/C'
  ) | Out-Null

  # Fail closed. If the ACL cannot be verified we do not know who can write
  # to the directory a SYSTEM scheduled task is about to run out of, and
  # "probably fine" is not an acceptable basis for that.
  $aclLines = Invoke-Icacls -Arguments @($Path)
  $aclText = ($aclLines | Out-String)
  if ([string]::IsNullOrWhiteSpace($aclText)) {
    throw "Protect-GuestStagingDir: could not read ACL on '$Path' (icacls returned nothing) -- aborting install"
  }
  # Any remaining Users/Everyone/Authenticated Users ACE means inheritance
  # removal did not take. Matched by SID and by the common English names,
  # since icacls prints resolved names when it can (mirrors the bash
  # version's grep pattern exactly).
  if ($aclText -match '(?i)S-1-5-32-545|S-1-1-0|S-1-5-11|\\Users:|Everyone:|Authenticated Users:') {
    throw "Protect-GuestStagingDir: '$Path' still grants access to non-administrative users after hardening:`n$aclText"
  }
}
