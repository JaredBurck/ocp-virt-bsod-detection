# Get-StreamDriverVerdict.ps1 -- stream-aware driver version verdict logic.
# Single source of truth for the PowerShell layer. Dot-sourced by:
#   - scripts/collect-windows-guest-info.ps1 (production)
#   - tests/test_ps_verdict.ps1 (CI harness)
#
# Expects callers to set: $StreamMax, $StreamFail, $StreamWarn,
#   $ToolingFloor, $Remediation

# ConvertTo-CleanDriverVersion: R-01 (v0.19.0 unified review U-01) FORMAT
# ANCHOR, PowerShell layer. Strips a real RPM release/NVR suffix (the first
# '-' and everything after -- e.g. '1.9.57-2.el9' -> '1.9.57'), then requires
# the remaining upstream portion be STRICTLY dotted-numeric with 2+
# components before parsing it as a [version].
#
# Every caller of this function previously did the cleaning inline as
# `-replace '[^0-9.]', ''`, which SILENTLY STRIPS offending characters
# instead of rejecting the string outright. 'v1.9.20' cleaned to '1.9.20'
# and graded on that real (and, on el9_6, FAIL-range) value instead of being
# rejected as unparseable evidence -- caught live by
# shared/driver-verdict-test-vectors.json's cross-layer 'v1.9.20' -> WARN
# vector (bash's evaluate_driver_version_stream anchor already rejects it;
# only the two inline PowerShell copies of this cleaning step did not). A
# wrong-identity string that happens to reduce to a real PASS-range number
# after stripping would have graded a false PASS on this framework's single
# most important guest check -- the exact bug class R-01 exists to close.
#
# Returns a [version] or $null (never throws). Mirrors bash's format anchor
# in scripts/lib/driver-verdict.sh and Python's parse_version() in
# insights-rules/plugins/common.py -- keep all three in sync.
function ConvertTo-CleanDriverVersion {
  param([string]$VersionString)
  if ([string]::IsNullOrEmpty($VersionString)) { return $null }
  $upstream = ($VersionString -split '-')[0]
  # Anchor: only digits and dots, at least two dot-separated components (a
  # bare major like '2' or '100' has too little precision to grade against
  # an x.y.z threshold), no leading/trailing/doubled dots -- all rejected
  # implicitly by requiring >=1 repetition of '.<digits>' after the leading
  # digits.
  if ($upstream -notmatch '^[0-9]+(\.[0-9]+)+$') { return $null }
  $parsed = $null
  if (-not [version]::TryParse($upstream, [ref]$parsed)) { return $null }
  return $parsed
}

function Get-StreamDriverVerdict {
  param([version]$DriverVersion)
  if (-not $DriverVersion) { return 'WARN' }
  # Sanity guard: a Win32_PnPSignedDriver "binary" DriverVersion (e.g.
  # 100.85.104.20700 -- confirmed real-world via Red Hat Bugzilla #1998933 for
  # the VirtIO SCSI driver) is easy to mistake for the virtio-win *package*
  # version (e.g. 1.9.57): both are dotted-numeric strings. virtio-win package
  # majors are 1.x for the foreseeable future, so major > 50 unambiguously
  # signals the wrong identity was captured upstream. Never let this silently
  # evaluate as PASS (tuple/version comparison would otherwise treat 100.x as
  # "way above" any real threshold).
  if ($DriverVersion.Major -gt 50) { return 'WARN' }
  if ($StreamMax -and $DriverVersion -ge $StreamMax) { return 'WARN' }
  if ($StreamFail -and $DriverVersion -lt $StreamFail) { return 'FAIL' }
  if ($StreamWarn -and $DriverVersion -lt $StreamWarn) { return 'WARN' }
  if ($DriverVersion -lt $ToolingFloor) {
    # H-2: on capped streams where max < tooling floor, FAIL is unactionable
    if ($StreamMax -and $StreamMax -lt $ToolingFloor) { return 'WARN' }
    return 'FAIL'
  }
  if ($DriverVersion -lt $Remediation) { return 'WARN' }
  return 'PASS'
}

# Get-GuestOSDriverCompatibility: N-06 (Wave 7, R-47) -- a SEPARATE axis from
# Get-StreamDriverVerdict above, deliberately not fused into it. That
# function answers "is this driver version current for the host-stream
# running it"; this one answers "is this guest OS a Red Hat Certified
# OpenShift Virtualization guest at all (KCS 4234591 --
# https://access.redhat.com/articles/4234591), and does ANY virtio-win
# '1.9.x' package this framework tracks even claim to support it", which is
# independent of the specific version reported. Mirrors bash's
# evaluate_guest_os_driver_compatibility in scripts/lib/driver-verdict.sh --
# keep both in sync; see shared/virtio-win-guest-os-support.json for the
# single source of truth both consume.
#
# Params:
#   -OSHint               free-form os_hint string (vm.kubevirt.io/os
#                         annotation/label value, or template name)
#   -DriverVersionString  raw virtio-win package version string, or empty/
#                         $null if not collected (this function still fires
#                         for incompatible_with_any_tracked_version=true
#                         entries even with no version at all)
#   -OSSupportConfig      parsed shared/virtio-win-guest-os-support.json
#                         (ConvertFrom-Json output)
#
# Returns a PSCustomObject: Verdict ('INCOMPATIBLE' or ''), OSName, Ceiling.
function Get-GuestOSDriverCompatibility {
  param(
    [string]$OSHint,
    [string]$DriverVersionString,
    [Parameter(Mandatory = $true)][PSObject]$OSSupportConfig
  )
  $result = [PSCustomObject]@{
    Verdict = ''
    OSName  = ''
    Ceiling = ''
  }
  if ([string]::IsNullOrEmpty($OSHint)) { return $result }
  if (-not $OSSupportConfig) { return $result }

  $matchKey = $null
  foreach ($key in $OSSupportConfig._match_order) {
    $entry = $OSSupportConfig.os_support.$key
    if (-not $entry) { continue }
    if ([regex]::IsMatch($OSHint, $entry.match_pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
      $matchKey = $key
      break
    }
  }
  if (-not $matchKey) { return $result }

  $entry = $OSSupportConfig.os_support.$matchKey
  $result.OSName = $entry.display_name
  if ($entry.last_supported_package_version) { $result.Ceiling = $entry.last_supported_package_version }

  if ($entry.incompatible_with_any_tracked_version -eq $true) {
    $result.Verdict = 'INCOMPATIBLE'
    return $result
  }

  # Ceiling-based path: no os_support token carries a non-null
  # last_supported_package_version as of this writing (every entry is
  # incompatible_with_any_tracked_version=true per KCS 4234591 -- see the
  # shared JSON), so this branch is currently unreached in production.
  # Implemented now so a future OS added with a real ceiling only requires a
  # JSON change, not new code here.
  if ($entry.last_supported_package_version -and $DriverVersionString) {
    $parsedVersion = ConvertTo-CleanDriverVersion -VersionString $DriverVersionString
    if ($parsedVersion) {
      $ceilingVersion = [version]$entry.last_supported_package_version
      if ($parsedVersion -gt $ceilingVersion) {
        $result.Verdict = 'INCOMPATIBLE'
      }
    }
  }
  return $result
}
