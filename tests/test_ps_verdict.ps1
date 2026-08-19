# Cross-layer PowerShell verdict test harness (CR-1).
# Dot-sources Get-StreamDriverVerdict from scripts/lib/Get-StreamDriverVerdict.ps1
# and validates each shared test vector produces the expected verdict.
#
# Requirements: PowerShell 5.1+ or pwsh
# Usage: pwsh tests/test_ps_verdict.ps1
param()

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Split-Path -Parent $ScriptDir

$VectorsFile = Join-Path $RepoRoot 'shared/driver-verdict-test-vectors.json'
$ThresholdsFile = Join-Path $RepoRoot 'shared/virtio-win-thresholds.json'

if (-not (Test-Path $VectorsFile)) {
  Write-Host "SKIP: $VectorsFile not found"
  exit 0
}
if (-not (Test-Path $ThresholdsFile)) {
  Write-Host "SKIP: $ThresholdsFile not found"
  exit 0
}

$cfg = Get-Content $ThresholdsFile -Raw | ConvertFrom-Json
$Remediation = [version]$cfg.remediation_baseline
$ToolingFloor = [version]$cfg.tooling_floor

# Source the production verdict function (single source of truth).
. (Join-Path $RepoRoot 'scripts/lib/Get-StreamDriverVerdict.ps1')

$vectors = (Get-Content $VectorsFile -Raw | ConvertFrom-Json).vectors

$passCount = 0
$failCount = 0
$total = 0
$failures = @()

foreach ($v in $vectors) {
  $stream = $v.stream
  $expected = $v.expected
  $note = $v.note

  $streamData = $cfg.streams.PSObject.Properties | Where-Object { $_.Name -eq $stream } | Select-Object -First 1

  $StreamFail = $null
  $StreamWarn = $null
  $StreamMax = $null

  if ($streamData) {
    if ($streamData.Value.fail) { $StreamFail = [version]$streamData.Value.fail }
    if ($streamData.Value.warn) { $StreamWarn = [version]$streamData.Value.warn }
    if ($streamData.Value.max)  { $StreamMax  = [version]$streamData.Value.max }
  }

  # Clean/anchor the version the same way the production script does
  # (collect-windows-guest-info.ps1), via the shared ConvertTo-CleanDriverVersion
  # helper -- a raw [version] cast throws on inputs like "1.9.41-1" or
  # "1.9.57-2.el9" (real RPM NVR suffixes, which several test vectors
  # intentionally exercise), and a naive char-strip (this harness's own
  # previous inline copy) silently mis-grades a non-numeric-leading string
  # like "v1.9.20" instead of rejecting it as unparseable.
  $driverVersion = ConvertTo-CleanDriverVersion -VersionString $v.version

  $actual = Get-StreamDriverVerdict -DriverVersion $driverVersion

  $total++
  if ($actual -eq $expected) {
    $passCount++
    Write-Host "  PASS: version=$($v.version) stream=$stream -> $actual ($note)"
  } else {
    $failCount++
    $msg = "  FAIL: version=$($v.version) stream=$stream -> got $actual, expected $expected ($note)"
    $failures += $msg
    Write-Host $msg
  }
}

Write-Host ""
Write-Host "PowerShell verdict test results: $passCount/$total passed, $failCount failed"

# N-06 (Wave 7, R-47): os_compat_vectors -- guest-OS-support axis, a SEPARATE
# function (Get-GuestOSDriverCompatibility) from the stream-version axis
# tested above.
$OSSupportFile = Join-Path $RepoRoot 'shared/virtio-win-guest-os-support.json'
if (-not (Test-Path $OSSupportFile)) {
  Write-Host "SKIP: $OSSupportFile not found -- skipping os_compat_vectors"
} else {
  $osSupportConfig = Get-Content $OSSupportFile -Raw | ConvertFrom-Json
  $osCompatVectors = (Get-Content $VectorsFile -Raw | ConvertFrom-Json).os_compat_vectors

  foreach ($v in $osCompatVectors) {
    $osHint = $v.os_hint
    $verString = $v.version
    $expected = $v.expected
    $note = $v.note

    $osResult = Get-GuestOSDriverCompatibility -OSHint $osHint -DriverVersionString $verString -OSSupportConfig $osSupportConfig

    $total++
    if ($osResult.Verdict -eq $expected) {
      $passCount++
      Write-Host "  PASS: os_hint=$osHint version=$verString -> '$($osResult.Verdict)' ($note)"
    } else {
      $failCount++
      $msg = "  FAIL: os_hint=$osHint version=$verString -> got '$($osResult.Verdict)', expected '$expected' ($note)"
      $failures += $msg
      Write-Host $msg
    }
  }
}

Write-Host ""
Write-Host "Combined PowerShell verdict test results: $passCount/$total passed, $failCount failed"

if ($failCount -gt 0) {
  Write-Host ""
  Write-Host "Failures:"
  $failures | ForEach-Object { Write-Host $_ }
  exit 1
}
