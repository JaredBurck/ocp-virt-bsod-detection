<#
.SYNOPSIS
  Custom text_file collector for windows_exporter exposing BSOD-relevant metrics.

.DESCRIPTION
  Writes Prometheus text format metrics to the windows_exporter textfile collector
  directory. Runs as a scheduled task (every 5 minutes) alongside windows_exporter.

  Metrics exposed:
    - bsod_virtio_driver_version (gauge with version label)
    - bsod_virtio_package_version (gauge with version label)
    - bsod_virtio_driver_outdated (gauge: 1=outdated for OCP stream, 0=ok)
    - bsod_io_timeout_value (gauge per driver)
    - bsod_crashdump_enabled (gauge: 0=disabled, 1-7=dump type)
    - bsod_qga_service_running (gauge: 1=running, 0=not running)
    - bsod_pagefile_max_mb (gauge)

.PARAMETER TextfileDir
  Path to the windows_exporter textfile collector directory.
  Default: C:\ProgramData\windows_exporter\textfile

.PARAMETER OCPVersion
  Optional OCP major.minor (e.g. 4.18) for stream-aware outdated evaluation.
  Also read from env BSOD_OCP_VERSION or C:\ProgramData\windows_exporter\ocp-version.txt.

.PARAMETER ThresholdsPath
  Path to virtio-win-thresholds.json. Defaults to ProgramData then DebugInfo copies.

.NOTES
  Requires: PowerShell 5.1+, windows_exporter with --collectors.enabled=textfile
  KCS: 7141291, 7132512, 7128506
#>
param(
  [string]$TextfileDir = 'C:\ProgramData\windows_exporter\textfile',
  [string]$OCPVersion = '',
  [string]$ThresholdsPath = ''
)

# R-40 (v0.19.0 follow-up N-04): re-harden the textfile directory on EVERY run.
#
# This block used to be `if (-not (Test-Path)) { New-Item -Force }` and nothing
# else. `New-Item -Force` creates the directory with DEFAULT, INHERITED ACLs --
# on a stock Windows install that leaves BUILTIN\Users able to create and modify
# files in it. install-windows-exporter.ps1 calls Protect-GuestStagingDir once at
# install time, but this script runs as SYSTEM from a scheduled task every 5
# minutes, indefinitely: any run that finds the directory missing (deleted,
# cleaned, or never created) silently recreated it Users-writable and then wrote
# .prom files into it, reopening the exact window the Wave 2 hardening closed.
#
# windows_exporter reads this directory and exposes whatever it finds as
# metrics, so a writable textfile dir is a metric-injection surface, not merely
# untidy ACLs.
#
# Hardening runs UNCONDITIONALLY rather than only on the create branch --
# re-applying an already-correct ACL is a no-op paid once per 5-minute cycle,
# and it also repairs a directory whose ACL was weakened after install.
if (-not (Test-Path $TextfileDir)) {
  New-Item -ItemType Directory -Path $TextfileDir -Force | Out-Null
}

# Single source of truth for the ACL rules -- the same helper the installer and
# the bash/QGA side use. Deliberately NOT re-implemented here: a second copy of
# the rule set is exactly the drift this repo keeps finding.
$protectHelper = Join-Path $PSScriptRoot 'lib\Protect-GuestStagingDir.ps1'
if (Test-Path $protectHelper) {
  . $protectHelper
  Protect-GuestStagingDir -Path $TextfileDir   # _TEXTFILE_HARDEN_MARKER
} else {
  # Fail LOUD but continue. Failing closed here would trade a hardening gap for
  # a monitoring outage on every guest installed before this helper shipped,
  # leaving the operator blind rather than merely under-hardened -- and the
  # resulting posture is no worse than before this fix existed. The warning
  # surfaces in the scheduled task's output and the Windows event log.
  Write-Warning "ACL helper not found at $protectHelper -- $TextfileDir was NOT re-hardened this run. Re-run install-windows-exporter.ps1 to stage it."
}

# Escape a label value per the Prometheus text exposition format
# (https://prometheus.io/docs/instrumenting/exposition_formats/): backslash,
# double-quote, and newline are the only characters that must be escaped
# inside a quoted label value. Driver/registry-sourced strings (DriverVersion,
# package Version) are untrusted input as far as this exposition format is
# concerned -- an unescaped `"` or newline would corrupt the line and could
# break every metric parsed after it, not just this one.
function ConvertTo-EscapedPrometheusLabelValue {
  param([string]$Value)
  if ($null -eq $Value) { return '' }
  return $Value.Replace('\', '\\').Replace('"', '\"').Replace("`n", '\n')
}

# Resolve OCP version: param > env > file drop
if (-not $OCPVersion -and $env:BSOD_OCP_VERSION) {
  $OCPVersion = $env:BSOD_OCP_VERSION
}
if (-not $OCPVersion) {
  $ocpFile = 'C:\ProgramData\windows_exporter\ocp-version.txt'
  if (Test-Path $ocpFile) {
    $OCPVersion = (Get-Content $ocpFile -Raw -ErrorAction SilentlyContinue).Trim()
  }
}

# Resolve thresholds + verdict helper
$thresholdCandidates = @()
if ($ThresholdsPath) { $thresholdCandidates += $ThresholdsPath }
$thresholdCandidates += @(
  'C:\ProgramData\windows_exporter\virtio-win-thresholds.json',
  'C:\DebugInfo\virtio-win-thresholds.json',
  (Join-Path $PSScriptRoot 'virtio-win-thresholds.json')
)
$cfg = $null
foreach ($tp in $thresholdCandidates) {
  if ($tp -and (Test-Path $tp)) {
    try {
      $cfg = Get-Content $tp -Raw | ConvertFrom-Json
      break
    } catch {
      $cfg = $null
    }
  }
}

$verdictHelperCandidates = @(
  (Join-Path $PSScriptRoot 'Get-StreamDriverVerdict.ps1'),
  'C:\ProgramData\windows_exporter\lib\Get-StreamDriverVerdict.ps1',
  'C:\DebugInfo\lib\Get-StreamDriverVerdict.ps1'
)
$verdictLoaded = $false
foreach ($vh in $verdictHelperCandidates) {
  if (Test-Path $vh) {
    . $vh
    $verdictLoaded = $true
    break
  }
}

$Remediation = [version]'1.9.57'
$ToolingFloor = [version]'1.9.41'
$StreamFail = $null
$StreamWarn = $null
$StreamMax = $null
$StreamName = ''
if ($cfg) {
  try {
    if ($cfg.remediation_baseline) { $Remediation = [version]$cfg.remediation_baseline }
    if ($cfg.tooling_floor) { $ToolingFloor = [version]$cfg.tooling_floor }
  } catch {
    Write-Verbose "Could not parse remediation_baseline/tooling_floor from thresholds config: $($_.Exception.Message)"
  }
  if ($OCPVersion -and $cfg.streams) {
    $ocpMinor = ($OCPVersion -split '\.')[0..1] -join '.'
    $matchedStream = $cfg.streams.PSObject.Properties | Where-Object {
      $_.Value.ocp_versions -contains $ocpMinor
    } | Select-Object -First 1
    if ($matchedStream) {
      $StreamName = $matchedStream.Name
      if ($matchedStream.Value.fail) {
        try { $StreamFail = [version]$matchedStream.Value.fail } catch { $StreamFail = $null }
      }
      if ($matchedStream.Value.warn) {
        try { $StreamWarn = [version]$matchedStream.Value.warn } catch { $StreamWarn = $null }
      }
      if ($matchedStream.Value.max) {
        try { $StreamMax = [version]$matchedStream.Value.max } catch { $StreamMax = $null }
      }
    }
  }
}

# $Remediation/$StreamFail/$StreamWarn/$StreamMax are read by
# Get-StreamDriverVerdict below via PowerShell's dynamic scoping (see that
# file's header comment), not by name in this file, so PSScriptAnalyzer
# can't see the cross-file usage and flags them as unused
# (PSUseDeclaredVarsMoreThanAssignments). False positive, not dead code.
$null = $Remediation, $StreamFail, $StreamWarn, $StreamMax

$metrics = @()
$metrics += "# HELP bsod_virtio_driver_version VirtIO driver binary version (from Win32_PnPSignedDriver)"
$metrics += "# TYPE bsod_virtio_driver_version gauge"

$virtioDrivers = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
  Where-Object { $_.DeviceName -match 'VirtIO|Red Hat' -and $_.DriverVersion } |
  Sort-Object DriverVersion -Descending |
  Select-Object -First 1

if ($virtioDrivers) {
  $ver = ConvertTo-EscapedPrometheusLabelValue $virtioDrivers.DriverVersion
  $metrics += "bsod_virtio_driver_version{version=`"$ver`"} 1"
} else {
  $metrics += "bsod_virtio_driver_version{version=`"unknown`"} 0"
}

$metrics += "# HELP bsod_virtio_package_version VirtIO-Win package version from registry (1.9.x format)"
$metrics += "# TYPE bsod_virtio_package_version gauge"

# Registry-only. Do NOT fall back to Win32_PnPSignedDriver's DriverVersion here:
# that field is a binary build number (e.g. "100.85.104.20700" -- confirmed
# real-world via Red Hat Bugzilla #1998933 for the VirtIO SCSI driver), not the
# virtio-win *package* version (e.g. "1.9.57"). Mislabeling one as the other is
# exactly the identity-confusion bug this metric exists to avoid; if the
# registry key is absent, report "unknown" rather than a misleading value.
$pkgVer = "unknown"
$pkgVerFound = 0
$regPaths = @(
  'HKLM:\SOFTWARE\Red Hat\Virtio-Win',
  'HKLM:\SOFTWARE\WOW6432Node\Red Hat\Virtio-Win'
)
foreach ($rp in $regPaths) {
  $prop = Get-ItemProperty -Path $rp -Name 'Version' -ErrorAction SilentlyContinue
  if ($prop -and $prop.Version) { $pkgVer = $prop.Version; $pkgVerFound = 1; break }
}
$metrics += "bsod_virtio_package_version{version=`"$(ConvertTo-EscapedPrometheusLabelValue $pkgVer)`"} $pkgVerFound"

# Stream-aware outdated gauge (1 = outdated / at risk for this OCP stream)
$metrics += "# HELP bsod_virtio_driver_outdated VirtIO package outdated for OCP stream (1=outdated, 0=ok)"
$metrics += "# TYPE bsod_virtio_driver_outdated gauge"
$outdated = 0
$streamLabel = if ($StreamName) { $StreamName } else { 'unknown' }
$pkgParsed = $null
[void][version]::TryParse((($pkgVer -split '-')[0] -replace '[^0-9.]', ''), [ref]$pkgParsed)
if ($pkgParsed -and $verdictLoaded) {
  # Stream-aware: FAIL or WARN from shared verdict helper => outdated for alerting
  $verdict = Get-StreamDriverVerdict -DriverVersion $pkgParsed
  if ($verdict -eq 'FAIL' -or $verdict -eq 'WARN') { $outdated = 1 }
} elseif ($pkgParsed) {
  # Fallback when stream/helper unavailable: tooling floor (shared JSON 1.9.41)
  if ($pkgParsed -lt $ToolingFloor) { $outdated = 1 }
}
$metrics += "bsod_virtio_driver_outdated{version=`"$(ConvertTo-EscapedPrometheusLabelValue $pkgVer)`",stream=`"$(ConvertTo-EscapedPrometheusLabelValue $streamLabel)`"} $outdated"

$metrics += "# HELP bsod_io_timeout_value IoTimeoutValue registry setting per storage driver (seconds)"
$metrics += "# TYPE bsod_io_timeout_value gauge"

foreach ($driver in @('viostor', 'vioscsi')) {
  $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$driver\Parameters"
  $timeout = 0
  if (Test-Path $regPath) {
    $val = Get-ItemProperty -Path $regPath -Name 'IoTimeoutValue' -ErrorAction SilentlyContinue
    if ($val) { $timeout = $val.IoTimeoutValue }
  }
  if ($timeout -eq 0) { $timeout = 60 }
  $metrics += "bsod_io_timeout_value{driver=`"$driver`"} $timeout"
}

$metrics += "# HELP bsod_crashdump_enabled CrashDumpEnabled registry value (0=none, 1=complete, 2=kernel, 3=mini, 7=auto)"
$metrics += "# TYPE bsod_crashdump_enabled gauge"

$crashReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'CrashDumpEnabled' -ErrorAction SilentlyContinue
$crashVal = if ($crashReg) { $crashReg.CrashDumpEnabled } else { 0 }
$metrics += "bsod_crashdump_enabled $crashVal"

$metrics += "# HELP bsod_qga_service_running QEMU Guest Agent service status (1=running, 0=not)"
$metrics += "# TYPE bsod_qga_service_running gauge"

$qga = Get-Service -Name 'QEMU-GA' -ErrorAction SilentlyContinue
$qgaRunning = if ($qga -and $qga.Status -eq 'Running') { 1 } else { 0 }
$metrics += "bsod_qga_service_running $qgaRunning"

$metrics += "# HELP bsod_pagefile_max_mb Maximum pagefile size in MB"
$metrics += "# TYPE bsod_pagefile_max_mb gauge"

$pf = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue | Select-Object -First 1
$pfMax = if ($pf) { $pf.AllocatedBaseSize } else { 0 }
$metrics += "bsod_pagefile_max_mb $pfMax"

# Write via temp-file + rename so windows_exporter's textfile collector (which
# may scrape on its own schedule concurrently with this script) never reads a
# partially-written file -- Out-File directly to the final name is visible to
# readers mid-write. Move-Item within the same directory/volume is an atomic
# rename on NTFS, so the collector only ever sees the old complete file or the
# new complete file, never a truncated one.
$outPath = Join-Path $TextfileDir 'bsod_metrics.prom'
$tmpPath = Join-Path $TextfileDir "bsod_metrics.prom.tmp-$PID"
$metrics -join "`n" | Out-File -FilePath $tmpPath -Encoding ascii -Force
Move-Item -Path $tmpPath -Destination $outPath -Force
