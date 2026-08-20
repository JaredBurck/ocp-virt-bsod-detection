<#
.SYNOPSIS
  collect-windows-guest-info.ps1
  Guest-side companion to the OpenShift Virtualization BSOD runbook.

.DESCRIPTION
  Verifies the in-guest virtio-win driver version against Red Hat's baselines,
  then invokes the OFFICIAL Red Hat collection script (CollectSystemInfo.ps1)
  shipped on the virtio-win CD-ROM, per KCS 7128506.

  This wrapper does NOT replace the Red Hat script -- it gates on driver
  version first (so you catch the most common BSOD cause before collecting)
  and then optionally calls the official tool. MEMORY.DMP / Minidump collection
  requires an explicit -IncludeSensitiveData opt-in (default off).

  Baselines (loaded from shared/virtio-win-thresholds.json when available):
    - Remediation baseline : virtio-win >= 1.9.57   (KCS 7141291 [Master])
    - Collection tooling   : virtio-win >= 1.9.41-1  (KCS 7128506)

  Minimum PowerShell: 5.1 (Windows PowerShell).
  Compatible with PowerShell 7.x (pwsh) but NOT tested below 5.1.
  Uses: Get-CimInstance, Get-PnpDevice, Get-Counter, Get-HotFix, Get-Service.

.PARAMETER VirtioDrive
  Drive letter of the mounted virtio-win CD-ROM (e.g. D). If omitted, the
  script tries to auto-detect a volume whose FriendlyName starts 'virtio-win'.

.PARAMETER OutDir
  Where to stage collected data. Default C:\DebugInfo.

.PARAMETER IncludeSensitiveData
  Opt-in: pass -IncludeSensitiveData to CollectSystemInfo.ps1 (MEMORY.DMP /
  Minidumps). Default is off.

.PARAMETER Remediate
  Opt-in: apply safe remediations (IoTimeout, CrashDump, QGA, phantom devices).

.PARAMETER Export
  Peer-review Issue J: opt-in, requires -Remediate. Instead of mutating the
  guest, evaluates the SAME conditions the in-place path would act on and
  writes a reviewable artifact to -OutDir -- 'reg' for a .reg file (Windows
  Registry Editor Version 5.00), 'ansible' for an Ansible playbook using
  ansible.windows modules, or 'both'. Nothing on the guest is read-write
  except the artifact file itself: no registry key is created or modified, no
  reg export backup is taken (nothing to back up), and no device is removed.
  Intended for sites whose change-control process does not permit a
  diagnostic tool to mutate a production guest directly -- the artifact is
  handed to the Windows/SCCM/Intune team to review and apply through their
  own process instead.

.EXAMPLE
  PS> Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
  PS> .\collect-windows-guest-info.ps1 -VirtioDrive D
  PS> .\collect-windows-guest-info.ps1 -VirtioDrive D -IncludeSensitiveData
  PS> .\collect-windows-guest-info.ps1 -Remediate -Export reg
#>

[CmdletBinding()]
# This is an interactive operator-run diagnostic tool (see .EXAMPLE above);
# colorized Write-Host status output is the intended UX, not a script that
# feeds a pipeline. See Write-Status/the -ForegroundColor calls throughout.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive console tool: colorized status output is the intended UX.')]
param(
  [string]$VirtioDrive,
  [string]$OutDir = 'C:\DebugInfo',
  [string]$OCPVersion = '',
  [switch]$IncludeSensitiveData,
  [switch]$Remediate,
  [ValidateSet('', 'reg', 'ansible', 'both')]
  [string]$Export = ''
)

# Issue J: -Export is a mode switch on -Remediate, not an independent
# feature -- both layers (this script and cnv-qga-fleet-collect.sh) require
# -Remediate/--remediate to be present so a reader of either invocation sees
# the same "remediation is happening" signal whether it lands in-place or as
# an exported artifact. Fail loudly rather than silently ignoring -Export.
if ($Export -and -not $Remediate) {
  Write-Host "  [FAIL] -Export requires -Remediate (e.g. -Remediate -Export $Export)" -ForegroundColor Red
  exit 2
}

# M-7: IoTimeoutValue thresholds from shared/io-timeout-thresholds.json -- the
# same file insights-rules/plugins/bsod_storage_checks.py and the Prometheus
# recording rule read. Previously the remediation hardcoded 300 while the
# analyzer used 180 and the recording rule 60, with nothing binding them.
$IoTimeoutDefault     = 60
$IoTimeoutRecommended = 180
$IoTimeoutTarget      = 300
foreach ($ioPath in @(
    (Join-Path $PSScriptRoot '..\shared\io-timeout-thresholds.json'),
    'C:\DebugInfo\io-timeout-thresholds.json')) {
  if (Test-Path $ioPath) {
    try {
      $ioCfg = Get-Content $ioPath -Raw | ConvertFrom-Json
      if ($ioCfg.windows_default_seconds)    { $IoTimeoutDefault     = [int]$ioCfg.windows_default_seconds }
      if ($ioCfg.recommended_min_seconds)    { $IoTimeoutRecommended = [int]$ioCfg.recommended_min_seconds }
      if ($ioCfg.remediation_target_seconds) { $IoTimeoutTarget      = [int]$ioCfg.remediation_target_seconds }
    } catch {
      Write-Host "  WARNING: failed to parse $ioPath -- using IoTimeout defaults" -ForegroundColor Yellow
    }
    break
  }
}

# Load thresholds from shared config (single source of truth).
$SharedConfigPaths = @(
  (Join-Path $PSScriptRoot '..\shared\virtio-win-thresholds.json'),
  'C:\DebugInfo\virtio-win-thresholds.json'
)
$Remediation = [version]'1.9.57'
$ToolingFloor = [version]'1.9.41'
$StreamFail = $null
$StreamWarn = $null
$StreamMax = $null
$StreamName = ''
$cfg = $null
foreach ($cfgPath in $SharedConfigPaths) {
  if (Test-Path $cfgPath) {
    try {
      $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
      $Remediation = [version]$cfg.remediation_baseline
      $ToolingFloor = [version]$cfg.tooling_floor
      Write-Host "  Loaded thresholds from $cfgPath" -ForegroundColor DarkGray
    } catch {
      Write-Host "  WARNING: failed to parse $cfgPath -- using defaults" -ForegroundColor Yellow
      $cfg = $null
    }
    break
  }
}

# Stream-aware threshold resolution: map OCP version to RHEL stream for
# per-stream fail/warn gates (consistent with Python insights-rules layer).
if ($OCPVersion -and $cfg -and $cfg.streams) {
  $ocpMinor = ($OCPVersion -split '\.')[0..1] -join '.'
  $matchedStream = $cfg.streams.PSObject.Properties | Where-Object {
    $_.Value.ocp_versions -contains $ocpMinor
  } | Select-Object -First 1
  if ($matchedStream) {
    $StreamName = $matchedStream.Name
    if ($matchedStream.Value.fail) {
      $StreamFail = [version]$matchedStream.Value.fail
    }
    if ($matchedStream.Value.warn) {
      $StreamWarn = [version]$matchedStream.Value.warn
    }
    if ($matchedStream.Value.max) {
      $StreamMax = [version]$matchedStream.Value.max
    }
    Write-Host "  OCP $OCPVersion -> stream: $StreamName" -ForegroundColor DarkGray
  }
}

# $Remediation/$ToolingFloor/$StreamFail/$StreamWarn/$StreamMax are read by
# Get-StreamDriverVerdict below via PowerShell's dynamic scoping (see that
# file's header comment), not by name in this file, so PSScriptAnalyzer
# can't see the cross-file usage and flags them as unused (PSUseDeclaredVarsMoreThanAssignments).
# This is a false positive, not dead code -- keep this read reference.
$null = $Remediation, $ToolingFloor, $StreamFail, $StreamWarn, $StreamMax

# N-06 (Wave 7, R-47): guest-OS-support axis, loaded independently of the
# stream thresholds above. See shared/virtio-win-guest-os-support.json.
$OSSupportConfigPaths = @(
  (Join-Path $PSScriptRoot '..\shared\virtio-win-guest-os-support.json'),
  'C:\DebugInfo\virtio-win-guest-os-support.json'
)
$Script:OSSupportConfig = $null
foreach ($cfgPath in $OSSupportConfigPaths) {
  if (Test-Path $cfgPath) {
    try {
      $Script:OSSupportConfig = Get-Content $cfgPath -Raw | ConvertFrom-Json
    } catch {
      Write-Host "  WARNING: failed to parse $cfgPath -- guest-OS-support check will be skipped" -ForegroundColor Yellow
    }
    break
  }
}

# Source the shared driver verdict function (single source of truth for PowerShell).
. "$PSScriptRoot/lib/Get-StreamDriverVerdict.ps1"
# Issue J: shared -Remediate -Export <fmt> artifact writer (single source of
# truth for PowerShell; extracted so it can be unit-tested on non-Windows pwsh).
. "$PSScriptRoot/lib/Export-RemediationArtifact.ps1"

$Script:FailCount = 0
$Script:WarnCount = 0

function Write-Status($level, $msg) {
  $color = switch ($level) { 'OK' {'Green'} 'WARN' {'Yellow'} 'FAIL' {'Red'} default {'Gray'} }
  Write-Host ("  [{0}] {1}" -f $level, $msg) -ForegroundColor $color
  if ($level -eq 'FAIL') { $Script:FailCount++ }
  if ($level -eq 'WARN') { $Script:WarnCount++ }
}

Write-Host "=== OpenShift Virtualization Windows BSOD guest collection ===" -ForegroundColor Cyan

#Requires -Version 5.1
if ($PSVersionTable.PSVersion -lt [version]'5.1') {
  Write-Status 'FAIL' "PowerShell $($PSVersionTable.PSVersion) is below the minimum 5.1. Upgrade Windows PowerShell."
  exit 1
}
Write-Host "  PowerShell: $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))" -ForegroundColor DarkGray

# --- 1. Auto-detect the virtio-win CD-ROM if not supplied --------------------
# The CD is only required for step 13 (official Red Hat CollectSystemInfo.ps1).
# Steps 2-12 query Windows internals and run without the CD.
$HasVirtioDrive = $true
if (-not $VirtioDrive) {
  $vol = Get-Volume |
    Where-Object { $_.FriendlyName -like 'virtio-win*' } |
    Select-Object -First 1
  if ($vol) {
    $VirtioDrive = $vol.DriveLetter
    Write-Status 'OK' "Auto-detected virtio-win CD-ROM at ${VirtioDrive}: ($($vol.FriendlyName))"
  } else {
    $HasVirtioDrive = $false
    Write-Status 'WARN' "No virtio-win CD-ROM found. Steps 2-12 will proceed; step 13 (official collector) will be skipped."
    Write-Host "  See KCS 7128506 for attaching the virtio-win container disk to the VM."
  }
}

# --- 2. Gate on in-guest virtio-win driver version ---------------------------
# storage driver (viostor/vioscsi) is the most BSOD-relevant; check the netkvm
# and balloon too since the catalog ties several stop codes to virtio drivers.
#
# IMPORTANT (peer-review v0.7.0 P0-3): Win32_PnPSignedDriver.DriverVersion is a
# per-device *binary* build number (e.g. "100.85.104.20700" -- confirmed
# real-world via Red Hat Bugzilla #1998933 for the VirtIO SCSI driver), NOT the
# virtio-win *package* version (e.g. "1.9.57") that the stream thresholds in
# shared/virtio-win-thresholds.json are defined against. The two use unrelated
# numbering schemes with no reliable mapping in the guest. The stream verdict
# below is therefore evaluated against the registry-sourced package version
# (HKLM\SOFTWARE\Red Hat\Virtio-Win), matching bsod-textfile-collector.ps1.
# Per-device binary versions are still enumerated for informational display
# (confirms drivers are actually installed) but are NOT fed into the verdict.
Write-Host "-- virtio driver version gate --"
$drivers = Get-CimInstance Win32_PnPSignedDriver |
  Where-Object { $_.DeviceName -match 'Red Hat VirtIO|virtio|NetKVM|Balloon' } |
  Select-Object DeviceName, DriverVersion -Unique

if (-not $drivers) {
  Write-Status 'WARN' "No virtio drivers detected in guest. If this VM uses virtio buses it will not boot (0x7B)."
} else {
  foreach ($d in $drivers) {
    Write-Host ("       detected: {0} (binary build {1})" -f $d.DeviceName, $d.DriverVersion) -ForegroundColor DarkGray
  }
}

$Script:VirtioPackageVersion = $null
foreach ($rp in @('HKLM:\SOFTWARE\Red Hat\Virtio-Win', 'HKLM:\SOFTWARE\WOW6432Node\Red Hat\Virtio-Win')) {
  $prop = Get-ItemProperty -Path $rp -Name 'Version' -ErrorAction SilentlyContinue
  if ($prop -and $prop.Version) { $Script:VirtioPackageVersion = $prop.Version; break }
}

if (-not $Script:VirtioPackageVersion) {
  Write-Status 'WARN' "virtio-win package version not found in registry (HKLM\SOFTWARE\Red Hat\Virtio-Win) -- cannot verify stream threshold. Per-device binary build numbers above are NOT a substitute (different numbering scheme; KCS-7141291)."
} else {
  $pkgDv = ConvertTo-CleanDriverVersion -VersionString $Script:VirtioPackageVersion
  if ($null -eq $pkgDv) {
    Write-Status 'WARN' ("virtio-win package version unparseable: '{0}'" -f $Script:VirtioPackageVersion)
    # R-01 (v0.19.0 unified review U-01): do NOT export a value this script has
    # just declared unparseable. It was previously written to virtio_version.txt
    # anyway (the export below is guarded only on non-null), and the bash
    # consumer applied no format validation of its own -- so the framework
    # warned "unparseable" here and then printed "[ OK ] ... PASS" for the same
    # string in Gate 15. Clearing it makes Gate 15 report UNKNOWN, which is the
    # honest verdict: the version was collected but could not be interpreted.
    $Script:VirtioPackageVersion = $null
  } else {
    $verdict = Get-StreamDriverVerdict -DriverVersion $pkgDv
    $detail = if ($StreamName) { " [stream=$StreamName]" } else { '' }
    switch ($verdict) {
      'FAIL' { Write-Status 'FAIL' ("virtio-win package {0}{1} (below threshold; UPGRADE; KCS-7141291)" -f $pkgDv, $detail) }
      'WARN' {
        # F-03: 'below baseline; upgrade recommended' is WRONG for the
        # at-stream-max case -- the guest is already on the newest package its
        # OCP release ships, so there is nothing to upgrade to and the advice
        # sends an operator looking for a driver that does not exist. The only
        # remediation is an OCP upgrade.
        if ($script:StreamDriverVerdictReason -eq 'at_stream_max') {
          Write-Status 'WARN' ("virtio-win package {0}{1} is at the ceiling available for this OCP release -- the BSOD fixes above it are not shippable here, so no driver update can clear this. Remediation is an OCP upgrade (KCS-7141291)" -f $pkgDv, $detail)
        } elseif ($script:StreamDriverVerdictReason -eq 'below_tooling_floor') {
          # F-06: a collection-tooling limitation, cited to the utility article.
          Write-Status 'WARN' ("virtio-win package {0}{1} is below the floor this framework's collection tooling requires -- guest-side evidence may be incomplete (KCS-7128506)" -f $pkgDv, $detail)
        } else {
          Write-Status 'WARN' ("virtio-win package {0}{1} (below baseline; upgrade recommended; KCS-7141291)" -f $pkgDv, $detail)
        }
      }
      'PASS' { Write-Status 'OK' ("virtio-win package {0}{1} (>= baseline)" -f $pkgDv, $detail) }
    }
  }
}

# --- 3. WSL / nested-virt presence (HYPERVISOR_ERROR 0x20001 risk) -----------
Write-Host "-- WSL / nested Hyper-V check (0x20001 after VMware migration) --"
$wsl = Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue |
  Where-Object { $_.FeatureName -match 'Microsoft-Windows-Subsystem-Linux|VirtualMachinePlatform|Microsoft-Hyper-V' -and $_.State -eq 'Enabled' }
if ($wsl) {
  Write-Status 'WARN' "WSL / Hyper-V / VirtualMachinePlatform enabled -> nested virtualization needed on target node."
  $wsl | ForEach-Object { Write-Host ("       enabled: {0}" -f $_.FeatureName) }
} else {
  Write-Status 'OK' "No WSL/nested-Hyper-V features enabled."
}
$featuresPath = Join-Path $OutDir 'GuestFeatures.json'
$allFeatures = Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue |
  Where-Object { $_.State -eq 'Enabled' -and $_.FeatureName -match 'Hyper-V|VirtualMachine|Subsystem-Linux|Containers' } |
  ForEach-Object { $_.FeatureName }
if ($allFeatures) {
  @($allFeatures) | ConvertTo-Json -Depth 2 | Out-File -FilePath $featuresPath -Encoding utf8 -Force
} else {
  '[]' | Out-File -FilePath $featuresPath -Encoding utf8 -Force
}

# --- 4. Display adapter note (Virtio GPU => possible 'no dump') --------------
Write-Host "-- display adapter (virtio-gpu 'no memory dump' caveat) --"
$gpu = Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name
$gpu | ForEach-Object {
  if ($_ -match 'virtio|Red Hat') {
    Write-Status 'WARN' ("$_ -- with virtio graphics a crash may produce NO memory dump (per KCS 7141988). Fix: virtio-win >= 1.9.57")
  } else {
    Write-Status 'OK' "$_"
  }
}

# --- 5. Phantom device detection (VMware residue -> 0x20001, VIDEO_TDR) -----
Write-Host "-- phantom device detection (VMware migration residue) --"
$phantomDevices = @()
try {
  $allDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Unknown' -or $_.Status -eq 'Error' }
  $vmwarePhantoms = $allDevices | Where-Object {
    $_.FriendlyName -match 'VMware|vmxnet|SVGA|VMMemCtl|pvscsi' -or
    $_.Manufacturer -match 'VMware'
  }
  if ($vmwarePhantoms) {
    foreach ($pd in $vmwarePhantoms) {
      Write-Status 'FAIL' ("Phantom VMware device: $($pd.FriendlyName) (Class=$($pd.Class), Status=$($pd.Status))")
      $phantomDevices += $pd
    }
    Write-Host "  ACTION: Remove phantom VMware devices to prevent 0x20001/HYPERVISOR_ERROR (KCS-7132519)"
  } else {
    $otherPhantoms = $allDevices | Where-Object { $_.Class -match 'Net|Display|SCSIAdapter|System' }
    if ($otherPhantoms) {
      foreach ($pd in $otherPhantoms) {
        Write-Status 'WARN' ("Phantom device: $($pd.FriendlyName) (Class=$($pd.Class), Status=$($pd.Status))")
      }
    } else {
      Write-Status 'OK' "No phantom devices detected"
    }
  }
} catch {
  Write-Status 'WARN' "Could not enumerate phantom devices: $($_.Exception.Message)"
}

# --- 6. IoTimeoutValue registry audit (storage timeout BSOD risk) -----------
Write-Host "-- IoTimeoutValue registry audit (storage 0x1A/0x7A timeout risk) --"
$storageDrivers = @('viostor', 'vioscsi')
foreach ($drv in $storageDrivers) {
  $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$drv\Parameters"
  if (Test-Path $regPath) {
    $ioTimeout = (Get-ItemProperty -Path $regPath -Name 'IoTimeoutValue' -ErrorAction SilentlyContinue).IoTimeoutValue
    if ($null -eq $ioTimeout -or $ioTimeout -le $IoTimeoutDefault) {
      $displayVal = if ($null -ne $ioTimeout) { $ioTimeout } else { "default($IoTimeoutDefault)" }
      Write-Status 'WARN' ("$drv IoTimeoutValue=$displayVal -- increase to $IoTimeoutRecommended+ if storage latency spikes occur (KCS-7132512)")
    } elseif ($ioTimeout -ge $IoTimeoutRecommended) {
      Write-Status 'OK' ("$drv IoTimeoutValue=$ioTimeout (tuned)")
    } else {
      Write-Status 'WARN' ("$drv IoTimeoutValue=$ioTimeout (low; recommend >= $IoTimeoutRecommended)")
    }
  } else {
    $svcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$drv"
    if (Test-Path $svcPath) {
      Write-Status 'WARN' ("$drv service present but no Parameters key -- IoTimeoutValue defaults to ${IoTimeoutDefault}s")
    }
  }
}

# --- 7. I/O performance baseline (in-guest storage latency) -----------------
Write-Host "-- I/O performance baseline --"
try {
  $diskCounters = Get-Counter '\PhysicalDisk(*)\Avg. Disk sec/Read',
                              '\PhysicalDisk(*)\Avg. Disk sec/Write' -SampleInterval 1 -MaxSamples 3 -ErrorAction Stop
  $lastSample = $diskCounters[-1].CounterSamples | Where-Object { $_.InstanceName -ne '_total' }
  # Accumulate per-disk so read and write land on ONE record each. The counter
  # samples arrive as a flat list of (instance, counter) pairs, so a disk
  # appears twice -- once for Read, once for Write.
  $ioBaseline = @{}
  foreach ($cs in $lastSample) {
    $latMs = [math]::Round($cs.CookedValue * 1000, 2)
    $diskId = $cs.InstanceName
    $counterName = ($cs.Path -split '\\')[-1]
    if (-not $ioBaseline.ContainsKey($diskId)) {
      $ioBaseline[$diskId] = [ordered]@{
        disk_id = $diskId; read_latency_ms = 0; write_latency_ms = 0
        read_iops = 0; write_iops = 0; queue_length = 0
      }
    }
    if ($counterName -like '*Read*') {
      $ioBaseline[$diskId].read_latency_ms = $latMs
    } elseif ($counterName -like '*Write*') {
      $ioBaseline[$diskId].write_latency_ms = $latMs
    }
    if ($latMs -gt 500) {
      Write-Status 'FAIL' ("$diskId $counterName = ${latMs}ms (elevated I/O early-warning FAIL >= 500ms; not the 60s IoTimeoutValue scale)")
    } elseif ($latMs -gt 50) {
      Write-Status 'WARN' ("$diskId $counterName = ${latMs}ms (elevated I/O early-warning WARN >= 50ms)")
    } else {
      Write-Status 'OK' ("$diskId $counterName = ${latMs}ms")
    }
  }
  # F-01 follow-up (v0.27.0). Until now this section was the ONLY one in the
  # collector that produced no artifact -- it printed to the console and threw
  # the numbers away. insights-rules/parsers/io_limits.py and
  # bsod_storage_checks.check_storage_io_latency have always been able to
  # consume exactly this shape, but nothing ever wrote it, so that analyzer
  # path was dead on any real collection. Writing it here is the first of the
  # three links; cnv-qga-fleet-collect.sh must also retrieve the file and
  # analyze.py must look for it under guest/, or it still goes nowhere.
  #
  # Schema matches DiskIOBaseline's field names exactly so analyze.py's
  # JSON-list branch consumes it without a translation layer.
  $ioPath = Join-Path $OutDir 'io-limits.json'
  # -InputObject, NOT a pipe. Piping an array into ConvertTo-Json unrolls it,
  # so a single-disk VM (the common case) serialises as a bare {...} object
  # instead of [{...}] -- and analyze.py's parser only accepts a list, so the
  # file would be silently ignored. Caught on a live guest: the first real
  # io-limits.json this collector ever produced was an object.
  #
  # The file carries a UTF-8 BOM regardless: PS 5.1's Out-File -Encoding utf8
  # always emits one (the BOM-less UTF-8 encoding enum is PS 6+; see CLAUDE.md).
  # Readers must decode with utf-8-sig; analyze.py does.
  ConvertTo-Json -InputObject @($ioBaseline.Values) -Depth 3 |
    Out-File -FilePath $ioPath -Encoding utf8
  Write-Status 'OK' "I/O baseline written: $ioPath"
} catch {
  Write-Status 'WARN' "Could not collect I/O counters: $($_.Exception.Message)"
}

# --- 8. MTV firstboot log capture -------------------------------------------
Write-Host "-- MTV firstboot log (migration completeness check) --"
$firstbootPaths = @(
  'C:\Program Files\Guestfs\Firstboot\log.txt',
  'C:\Program Files\Red Hat\Firstboot\log.txt'
)
$firstbootFound = $false
foreach ($fbPath in $firstbootPaths) {
  if (Test-Path $fbPath) {
    $firstbootFound = $true
    $fbContent = Get-Content $fbPath -ErrorAction SilentlyContinue
    Write-Status 'OK' "MTV firstboot log found: $fbPath ($($fbContent.Count) lines)"
    $errors = $fbContent | Where-Object { $_ -match 'error|fail|exception' }
    if ($errors) {
      Write-Status 'WARN' "Firstboot log contains $($errors.Count) error/failure lines:"
      $errors | Select-Object -First 5 | ForEach-Object { Write-Host "    $_" }
    }
    if ($OutDir) {
      Copy-Item $fbPath -Destination (Join-Path $OutDir 'firstboot.log') -ErrorAction SilentlyContinue
    }
    break
  }
}
$hasMigrationMeta = $false
try {
  $forkliftReg = Test-Path 'HKLM:\SOFTWARE\Red Hat\Migration' -ErrorAction SilentlyContinue
  $hasMigrationMeta = $forkliftReg
} catch {
  Write-Verbose "Could not check for migration metadata registry key: $($_.Exception.Message)"
}
if (-not $firstbootFound) {
  if ($hasMigrationMeta) {
    Write-Status 'WARN' "Migration metadata present but no firstboot log found -- possible incomplete driver setup"
  } else {
    Write-Status 'OK' "No MTV firstboot log (VM was not migrated via MTV)"
  }
}

# --- 9. CrashDump configuration audit (memory dump readiness) ---------------
Write-Host "-- CrashDump configuration audit --"
$crashCtrlPath = 'HKLM:\System\CurrentControlSet\Control\CrashControl'
if (Test-Path $crashCtrlPath) {
  $crashDumpEnabled = (Get-ItemProperty -Path $crashCtrlPath -Name 'CrashDumpEnabled' -ErrorAction SilentlyContinue).CrashDumpEnabled
  switch ($crashDumpEnabled) {
    1 { Write-Status 'OK' "CrashDumpEnabled=1 (Complete memory dump)" }
    2 { Write-Status 'OK' "CrashDumpEnabled=2 (Kernel memory dump)" }
    3 { Write-Status 'WARN' "CrashDumpEnabled=3 (Small/Minidump only -- insufficient for BSOD root cause analysis)" }
    7 { Write-Status 'OK' "CrashDumpEnabled=7 (Automatic memory dump)" }
    0 { Write-Status 'FAIL' "CrashDumpEnabled=0 (Crash dumps DISABLED -- no MEMORY.DMP on BSOD)" }
    default { Write-Status 'WARN' "CrashDumpEnabled=$crashDumpEnabled (unexpected value)" }
  }
  $dumpFile = (Get-ItemProperty -Path $crashCtrlPath -Name 'DumpFile' -ErrorAction SilentlyContinue).DumpFile
  if ($dumpFile) { Write-Host "  DumpFile path: $dumpFile" }
} else {
  Write-Status 'WARN' "CrashControl registry key not found"
}
$pagefile = Get-CimInstance Win32_PageFileSetting -ErrorAction SilentlyContinue
$pagefileUsage = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue
if ($pagefile) {
  foreach ($pf in $pagefile) {
    Write-Host ("  Pagefile: {0} (InitialSize={1}MB, MaxSize={2}MB)" -f $pf.Name, $pf.InitialSize, $pf.MaximumSize)
    if ($pf.MaximumSize -gt 0 -and $pf.MaximumSize -lt 4096) {
      Write-Status 'WARN' "Pagefile max size < 4GB -- may be too small for kernel dump on large-RAM VMs"
    }
  }
} elseif ($pagefileUsage) {
  foreach ($pfu in $pagefileUsage) {
    Write-Host ("  Pagefile: {0} (Allocated={1}MB, CurrentUsage={2}MB) [system-managed]" -f $pfu.Name, $pfu.AllocatedBaseSize, $pfu.CurrentUsage)
  }
} else {
  Write-Host "  Pagefile: not detected"
}

# --- 10. Windows version and KB patch level ----------------------------------
Write-Host "-- Windows version and recent updates --"
$osInfo = Get-CimInstance Win32_OperatingSystem
Write-Host ("  OS: {0}" -f $osInfo.Caption)
Write-Host ("  Version: {0} (Build {1})" -f $osInfo.Version, $osInfo.BuildNumber)
Write-Host ("  Architecture: {0}" -f $osInfo.OSArchitecture)
Write-Host ("  Install Date: {0}" -f $osInfo.InstallDate)

# N-06 (Wave 7, R-47): guest-OS-support axis, evaluated here (not in the
# virtio driver version gate above) because $osInfo.Caption -- the only
# guest-local OS-hint string this script has -- isn't populated until this
# step. Fires even if $Script:VirtioPackageVersion is empty/unparseable (see
# Get-GuestOSDriverCompatibility's header comment): the incompatibility is
# intrinsic to the OS, not the reported driver number.
if ($Script:OSSupportConfig -and $osInfo -and $osInfo.Caption) {
  $osCompatResult = Get-GuestOSDriverCompatibility -OSHint $osInfo.Caption `
    -DriverVersionString $Script:VirtioPackageVersion -OSSupportConfig $Script:OSSupportConfig
  if ($osCompatResult.Verdict -eq 'INCOMPATIBLE') {
    $ceilingNote = if ($osCompatResult.Ceiling) { " (last known-supported package: $($osCompatResult.Ceiling))" } else { '' }
    Write-Status 'WARN' ("Guest OS '{0}' ({1}) is not a Red Hat Certified OpenShift Virtualization guest OS (KCS 4234591){2} -- a driver-version bump alone cannot fix BSODs here; this is a platform-migration conversation, not a driver-update one" -f $osInfo.Caption, $osCompatResult.OSName, $ceilingNote)
  }
} elseif (-not $Script:OSSupportConfig) {
  Write-Host "  (guest-OS-support config not found -- skipping platform-certification check; see shared/virtio-win-guest-os-support.json)" -ForegroundColor DarkGray
}

try {
  $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Select-Object -First 10
  if ($hotfixes) {
    Write-Host "  Last 10 installed updates:"
    foreach ($hf in $hotfixes) {
      Write-Host ("    {0}  {1}  ({2})" -f $hf.HotFixID, $hf.InstalledOn, $hf.Description)
    }
    $kbExport = $hotfixes | ForEach-Object {
      @{
        HotFixID    = $_.HotFixID
        InstalledOn = if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { '' }
        Description = $_.Description
      }
    }
    $kbJsonPath = Join-Path $OutDir 'InstalledKBs.json'
    @($kbExport) | ConvertTo-Json -Depth 3 | Out-File -FilePath $kbJsonPath -Encoding utf8 -Force
    Write-Status 'OK' "Exported KB history to InstalledKBs.json"
  } else {
    Write-Status 'WARN' "No hotfix information available"
  }
} catch {
  Write-Status 'WARN' "Could not enumerate hotfixes: $($_.Exception.Message)"
}

# --- 11. QEMU Guest Agent service check -------------------------------------
Write-Host "-- QEMU Guest Agent (QGA) service status --"
$qgaSvc = Get-Service -Name 'QEMU-GA' -ErrorAction SilentlyContinue
if (-not $qgaSvc) {
  $qgaSvc = Get-Service -DisplayName '*QEMU Guest Agent*' -ErrorAction SilentlyContinue
}
if ($qgaSvc) {
  if ($qgaSvc.Status -eq 'Running' -and $qgaSvc.StartType -eq 'Automatic') {
    Write-Status 'OK' ("QEMU Guest Agent: {0}, StartType={1}" -f $qgaSvc.Status, $qgaSvc.StartType)
  } elseif ($qgaSvc.Status -eq 'Running') {
    Write-Status 'WARN' ("QEMU Guest Agent is Running but StartType={0} (should be Automatic for reliability)" -f $qgaSvc.StartType)
  } else {
    Write-Status 'FAIL' ("QEMU Guest Agent: {0}, StartType={1} -- graceful shutdown, VSS snapshots, and memory ballooning will fail" -f $qgaSvc.Status, $qgaSvc.StartType)
  }
} else {
  Write-Status 'FAIL' "QEMU Guest Agent service NOT found -- install qemu-ga from the virtio-win package"
}

# --- 12. Export QGA-compatible artifacts for analyze.py pipeline ---------------
Write-Host "-- exporting QGA-compatible artifacts --"
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

if ($drivers) {
  $drvCsvPath = Join-Path $OutDir 'drv_list.csv'
  $drivers | Export-Csv -Path $drvCsvPath -NoTypeInformation -Force
  Write-Status 'OK' "Exported driver list: $drvCsvPath"
}

# N8: $drivers above is filtered to virtio/NetKVM/Balloon device names ONLY
# (step 2's Where-Object), so drv_list.csv structurally can never contain a
# VMware driver name -- check_vmware_leftover_drivers() (analyze.py) reads
# drv_list.csv and was therefore dead code against any real guest: the
# FAIL condition it exists to catch (KCS-7132519, active VMMemCtl after a
# VMware->KubeVirt migration) could never fire no matter what was actually
# installed in the guest. Collect a SECOND, separate snapshot restricted to
# a VMware-name allowlist -- same shape/pattern as the virtio-only filter
# above, so no additional sensitive data (arbitrary installed software) is
# captured, only the same short well-known driver-name list
# check_vmware_leftover_drivers() already matches against.
Write-Host "-- VMware leftover-driver residue check (KCS-7132519) --"
$vmwareDriverPattern = 'VMMemCtl|VMTools|VMware SVGA|vm3dmp|vmxnet|pvscsi|VMware Pointing|VMware VMCI'
$vmwareDrivers = Get-CimInstance Win32_PnPSignedDriver |
  Where-Object { $_.DeviceName -match $vmwareDriverPattern } |
  Select-Object DeviceName, DriverVersion -Unique

if ($vmwareDrivers) {
  Write-Status 'WARN' "Active VMware driver(s) detected -- see vmware_drv_list.csv (KCS-7132519)"
  foreach ($vd in $vmwareDrivers) {
    Write-Host ("       detected: {0}" -f $vd.DeviceName) -ForegroundColor DarkGray
  }
  $vmwareDrvCsvPath = Join-Path $OutDir 'vmware_drv_list.csv'
  $vmwareDrivers | Export-Csv -Path $vmwareDrvCsvPath -NoTypeInformation -Force
  Write-Status 'OK' "Exported VMware leftover-driver list: $vmwareDrvCsvPath"
} else {
  Write-Status 'OK' "No active VMware drivers detected"
  # Write a header-only CSV (rather than no file) so analyze.py can
  # distinguish "checked, none found" (PASS) from "collector predates this
  # check" (UNKNOWN, file absent entirely) -- unlike drv_list.csv, which is
  # only written when non-empty, PASS is itself meaningful evidence here.
  # Export-Csv on an empty collection writes nothing at all (not even a
  # header) in PS 5.1, so the header line is written directly.
  $vmwareDrvCsvPath = Join-Path $OutDir 'vmware_drv_list.csv'
  '"DeviceName","DriverVersion"' | Out-File -FilePath $vmwareDrvCsvPath -Encoding utf8 -Force
  Write-Status 'OK' "Exported VMware leftover-driver list (none found): $vmwareDrvCsvPath"
}

# Registry-sourced package version (see step 2) -- preferred by
# cnv-win-bsod-audit.sh Gate 15 over drv_list.csv's binary DriverVersion
# column, which is the wrong identity for stream-threshold evaluation.
if ($Script:VirtioPackageVersion) {
  $verPath = Join-Path $OutDir 'virtio_version.txt'
  $Script:VirtioPackageVersion | Out-File -FilePath $verPath -Encoding utf8 -Force -NoNewline
  Write-Status 'OK' "Exported virtio-win package version: $verPath ($Script:VirtioPackageVersion)"
}

$storageDrivers2 = @('viostor', 'vioscsi')
$virtioLines = @()
foreach ($drv2 in $storageDrivers2) {
  $regPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\$drv2\Parameters"
  if (Test-Path $regPath2) {
    $ioVal = (Get-ItemProperty -Path $regPath2 -Name 'IoTimeoutValue' -ErrorAction SilentlyContinue).IoTimeoutValue
    $displayVal2 = if ($null -ne $ioVal) { $ioVal } else { $IoTimeoutDefault }
    $virtioLines += "$drv2 Parameters:"
    $virtioLines += "IoTimeoutValue: $displayVal2"
    $virtioLines += ""
  }
}
if ($virtioLines.Count -gt 0) {
  $virtioLines | Out-File -FilePath (Join-Path $OutDir 'virtio_disk.txt') -Encoding UTF8 -Force
  Write-Status 'OK' "Exported virtio disk info: $(Join-Path $OutDir 'virtio_disk.txt')"
}

if ($phantomDevices.Count -gt 0) {
  $phantomCsvPath = Join-Path $OutDir 'PhantomDevices.csv'
  $phantomDevices | Select-Object FriendlyName, Class, Status, InstanceId |
    Export-Csv -Path $phantomCsvPath -NoTypeInformation -Force
  Write-Status 'OK' "Exported phantom devices: $phantomCsvPath"
}

try {
  $phantomNics = Get-PnpDevice -ErrorAction SilentlyContinue |
    Where-Object { ($_.Status -eq 'Unknown' -or $_.Status -eq 'Error') -and $_.Class -eq 'Net' }
  if ($phantomNics) {
    $phantomNicCsvPath = Join-Path $OutDir 'PhantomNICConfig.csv'
    $phantomNics | Select-Object FriendlyName, Class, Status, InstanceId |
      Export-Csv -Path $phantomNicCsvPath -NoTypeInformation -Force
    Write-Status 'OK' "Exported phantom NIC config: $phantomNicCsvPath"
  }
} catch {
  Write-Verbose "Could not enumerate phantom NICs: $($_.Exception.Message)"
}

$crashDumpVal = if ($null -ne $crashDumpEnabled) { $crashDumpEnabled } else { -1 }
$dumpFileVal = if ($null -ne $dumpFile) { $dumpFile } else { '' }
$pagefileList = @()
$pagefileManaged = $true
if ($pagefile) {
  $pagefileManaged = $false
  $pagefileList = @($pagefile | ForEach-Object {
    @{ Name = $_.Name; InitialSizeMB = $_.InitialSize; MaxSizeMB = $_.MaximumSize }
  })
} elseif ($pagefileUsage) {
  $pagefileList = @($pagefileUsage | ForEach-Object {
    @{ Name = $_.Name; AllocatedMB = $_.AllocatedBaseSize; CurrentUsageMB = $_.CurrentUsage; Managed = $true }
  })
}
$vmRamMB = 0
try {
  $vmRamMB = [math]::Floor((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB)
} catch {
  Write-Verbose "Could not determine VM RAM size: $($_.Exception.Message)"
}
$crashConfig = @{
  CrashDumpEnabled = $crashDumpVal
  DumpFile         = $dumpFileVal
  Pagefiles        = $pagefileList
  PagefileManaged  = $pagefileManaged
  VMRamMB          = $vmRamMB
  OSCaption        = if ($osInfo) { $osInfo.Caption } else { '' }
  OSVersion        = if ($osInfo) { $osInfo.Version } else { '' }
  OSBuild          = if ($osInfo) { "$($osInfo.BuildNumber)" } else { '' }
}
$crashConfigPath = Join-Path $OutDir 'CrashDumpConfig.json'
# Write BOM-free UTF-8: Set-Content -Encoding UTF8 emits a BOM on
# PowerShell 5.1, which breaks json.loads() on the Python side.
[System.IO.File]::WriteAllText($crashConfigPath, ($crashConfig | ConvertTo-Json -Depth 3), [System.Text.UTF8Encoding]::new($false))
Write-Status 'OK' "Exported crash dump config: $crashConfigPath"

# --- 13. Invoke the OFFICIAL Red Hat collector --------------------------------
Write-Host "-- invoking official Red Hat collector (KCS 7128506) --"
if (-not $HasVirtioDrive) {
  Write-Status 'WARN' "Skipping official Red Hat collector -- no virtio-win CD-ROM attached. Attach the CD and re-run to collect full diagnostics."
} else {
  $collector = Join-Path "${VirtioDrive}:" 'tools\debug\CollectSystemInfo.ps1'
  if (-not (Test-Path $collector)) {
    Write-Status 'FAIL' "CollectSystemInfo.ps1 not found at $collector"
    Write-Host  "  Confirm the virtio-win CD is mounted and contains tools\debug\. Refer to the CD README.md."
  } else {
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    Push-Location $OutDir
    try {
      if ($IncludeSensitiveData) {
        Write-Status 'OK' "Running CollectSystemInfo with -IncludeSensitiveData (MEMORY.DMP / Minidump -- handle with care)."
        & $collector -IncludeSensitiveData
      } else {
        Write-Status 'OK' "Running CollectSystemInfo without sensitive dumps (pass -IncludeSensitiveData to include MEMORY.DMP / Minidump)."
        & $collector
      }
      $folder = Get-ChildItem -Path $OutDir -Directory -Filter 'SystemInfo_*' |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
      if ($folder) {
        $zip = "$($folder.FullName).zip"
        Compress-Archive -Path $folder.FullName -DestinationPath $zip -Force
        Write-Status 'OK' "Collected and compressed: $zip"
        Write-Host  "  Upload this archive to the Red Hat case. If a Microsoft case exists, reference its number."
      } else {
        Write-Status 'WARN' "Collector ran but no SystemInfo_* folder found; check Collecting_Status.txt for an interrupted run."
      }
    } finally {
      Pop-Location
    }
  }
}

# --- 14. Auto-Remediation (optional, requires -Remediate) --------------------
$remediationLog = Join-Path $OutDir 'remediation.log'
$remediationCount = 0
$remediationFail = 0
$exportedFiles = @()

# --- 14a. Auto-Remediation Export (optional, requires -Remediate -Export <fmt>) ---
# Issue J (Gemini peer review): many sites' change-control process will not
# let a diagnostic tool mutate a production guest directly. This branch
# evaluates the EXACT SAME conditions the in-place branch below (14b) acts
# on, but instead of calling New-Item/Set-ItemProperty/Set-Service/pnputil,
# only READS current state and writes a reviewable artifact under -OutDir.
# No backup directory is created, no `reg export` runs, and nothing in the
# registry, service control manager, or device tree is modified -- there is
# nothing to roll back because nothing was changed.
if ($Remediate -and $Export) {
  Write-Host ""
  Write-Host "=== AUTO-REMEDIATION EXPORT MODE (read-only -- nothing on the guest is modified) ===" -ForegroundColor Yellow

  $exportResult = Export-RemediationArtifact -OutDir $OutDir -Format $Export `
    -IoTimeoutRecommended $IoTimeoutRecommended -IoTimeoutDefault $IoTimeoutDefault `
    -IoTimeoutTarget $IoTimeoutTarget -PhantomDevices $phantomDevices

  if ($exportResult.NothingToExport) {
    Write-Status 'OK' "Export: nothing to remediate -- guest already meets every checked baseline"
  } else {
    foreach ($f in $exportResult.ExportedFiles) {
      $extraNote = ''
      if ($f -like '*.yml') {
        if ($exportResult.QgaNeedsFix) { $extraNote += ' + QGA service task' }
        if ($exportResult.PhantomCount -gt 0) { $extraNote += ", $($exportResult.PhantomCount) phantom device(s) noted" }
        Write-Status 'OK' "EXPORTED: $f ($($exportResult.RegItemCount) registry task(s)$extraNote)"
      } else {
        Write-Status 'OK' "EXPORTED: $f ($($exportResult.RegItemCount) registry value(s))"
      }
      $exportedFiles += $f
    }
  }
}

# --- 14b. Auto-Remediation (in-place, requires -Remediate without -Export) ---
if ($Remediate -and (-not $Export)) {
  Write-Host ""
  Write-Host "=== AUTO-REMEDIATION MODE ===" -ForegroundColor Yellow
  Write-Host "  Backing up registry keys before modifications..."

  $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $backupDir = Join-Path $OutDir "remediation-backup-$timestamp"
  New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

  function Write-RemediationLog {
    param([string]$Action, [string]$Before, [string]$After, [string]$Result)
    $entry = "[{0}] {1} | before={2} | after={3} | result={4}" -f (Get-Date -Format 'o'), $Action, $Before, $After, $Result
    Add-Content -Path $remediationLog -Value $entry
  }

  # N12 (v0.16.0 #12): reg export / pnputil /export-pnpstate are the only
  # rollback path if a remediation step below turns out to be wrong for a
  # given guest. Both tools can exit non-zero (or, observed in the wild,
  # exit 0 while writing a truncated/empty file if the backup path is on a
  # read-only or full volume) without the caller noticing, since their
  # output is redirected to $null. Verify the backup file actually landed
  # and is non-empty before letting a caller proceed to mutate the registry
  # or remove a device -- "we could not back up" must block the mutation it
  # protects, not just log a warning after the fact.
  function Test-BackupSucceeded {
    param([string]$BackupPath, [int]$ToolExitCode)
    if ($ToolExitCode -ne 0) { return $false }
    $item = Get-Item -Path $BackupPath -ErrorAction SilentlyContinue
    return ($null -ne $item -and $item.Length -gt 0)
  }

  # R-1 (IoTimeoutValue) and R-2 (CrashDumpEnabled) are registry values read
  # once at boot by the storage driver / crash-dump subsystem respectively --
  # neither takes effect for the running session until the guest reboots.
  # Applying either without communicating that leaves an operator believing
  # the fix is already active (e.g. assuming the new IoTimeoutValue is
  # already protecting against a storage-latency BSOD) when it is not.
  $rebootRequiredFor = @()

  # R-1: IoTimeoutValue for viostor/vioscsi
  foreach ($driver in @('viostor', 'vioscsi')) {
    $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$driver"
    $regPath = "$servicePath\Parameters"
    # M-11: gate on the SERVICE key, not on Parameters. Parameters is optional
    # and frequently absent on a freshly installed virtio-win -- which is
    # precisely the untuned ${IoTimeoutDefault}s state that step 6 above flags
    # as an at-risk finding. Gating on Parameters meant -Remediate silently
    # skipped every VM in the exact condition it exists to fix, while still
    # exiting successfully. Gating on the service key keeps the original
    # safety property: never create Parameters for a driver that is not
    # installed, since a stray key would be inert at best and misleading to
    # the next person reading the registry at worst.
    if (Test-Path $servicePath) {
      try {
        $createdKey = $false
        $backupVerified = $true
        if (-not (Test-Path $regPath)) {
          New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
          $createdKey = $true
        } else {
          $paramsBackup = Join-Path $backupDir "$driver-params.reg"
          reg export "HKLM\SYSTEM\CurrentControlSet\Services\$driver\Parameters" $paramsBackup /y 2>$null | Out-Null
          $regExportExit = $LASTEXITCODE
          $backupVerified = Test-BackupSucceeded -BackupPath $paramsBackup -ToolExitCode $regExportExit
        }
        # N12 (v0.16.0 #12): abort just this driver's remediation -- not the
        # whole script -- if the pre-mutation backup didn't actually land.
        # Mutating IoTimeoutValue with no verified rollback path defeats the
        # purpose of backing it up in the first place.
        if (-not $backupVerified) {
          Write-Status 'FAIL' "REMEDIATION SKIPPED: $driver IoTimeoutValue -- backup (reg export) did not produce a valid backup file, refusing to mutate the registry without one"
          Write-RemediationLog "IoTimeoutValue.$driver" 'unknown' "$IoTimeoutTarget" 'FAILED: backup verification failed'
          $remediationFail++
          continue
        }
        $current = (Get-ItemProperty -Path $regPath -Name 'IoTimeoutValue' -ErrorAction SilentlyContinue).IoTimeoutValue
        if (-not $current -or $current -lt $IoTimeoutRecommended) {
          Set-ItemProperty -Path $regPath -Name 'IoTimeoutValue' -Value $IoTimeoutTarget -Type DWord
          $keyNote = if ($createdKey) { '; Parameters key created' } else { '' }
          $wasValue = if ($current) { $current } else { "default/$IoTimeoutDefault" }
          Write-Status 'OK' "REMEDIATED: $driver IoTimeoutValue set to $IoTimeoutTarget (was: $wasValue$keyNote) -- REBOOT REQUIRED to take effect"
          # M-11: distinguish "value was absent under an existing key" from
          # "the whole Parameters key was absent". Rollback differs: the former
          # restores from $driver-params.reg, the latter has no backup file
          # because there was nothing to export -- undo by deleting the key.
          $wasLog = if ($current) { $current } elseif ($createdKey) { 'absent(no-parameters-key)' } else { 'default' }
          # Result stays the exact literal "SUCCESS" -- insights-rules'
          # RemediationEntry.succeeded does an exact string match against
          # "SUCCESS" (parsers/remediation_log.py), so appending extra text
          # here would silently break BSOD_REMEDIATION_IO_TIMEOUT_FIXED's
          # PASS detection. Reboot-required is instead recorded as its own
          # dedicated log entry below and in the console banner.
          Write-RemediationLog "IoTimeoutValue.$driver" $wasLog "$IoTimeoutTarget" 'SUCCESS'
          $remediationCount++
          $rebootRequiredFor += "$driver IoTimeoutValue"
        }
      } catch {
        Write-Status 'FAIL' "REMEDIATION FAILED: $driver IoTimeoutValue -- $($_.Exception.Message)"
        Write-RemediationLog "IoTimeoutValue.$driver" 'unknown' "$IoTimeoutTarget" "FAILED: $($_.Exception.Message)"
        $remediationFail++
      }
    }
  }

  # R-2: CrashDumpEnabled (fix disabled=0 and minidump-only=3)
  try {
    $crashPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
    $crashBackup = Join-Path $backupDir 'CrashControl.reg'
    reg export 'HKLM\SYSTEM\CurrentControlSet\Control\CrashControl' $crashBackup /y 2>$null | Out-Null
    $crashRegExportExit = $LASTEXITCODE
    # N12 (v0.16.0 #12): this block is top-level inside `if ($Remediate)`, not
    # inside a function or loop, so `throw` (caught by the existing catch
    # below) is used to bail out of just this remediation step rather than
    # `return`, which would exit the whole script from this scope.
    if (-not (Test-BackupSucceeded -BackupPath $crashBackup -ToolExitCode $crashRegExportExit)) {
      throw 'backup (reg export) did not produce a valid backup file, refusing to mutate the registry without one'
    }
    $currentCrash = (Get-ItemProperty -Path $crashPath -Name 'CrashDumpEnabled' -ErrorAction SilentlyContinue).CrashDumpEnabled
    if ($currentCrash -eq 0 -or $currentCrash -eq 3) {
      $wasLabel = if ($currentCrash -eq 0) { '0/disabled' } else { '3/minidump' }
      Set-ItemProperty -Path $crashPath -Name 'CrashDumpEnabled' -Value 7 -Type DWord
      Write-Status 'OK' "REMEDIATED: CrashDumpEnabled set to 7/Automatic (was: $wasLabel) -- REBOOT REQUIRED to take effect"
      # Result stays the exact literal "SUCCESS" -- see the IoTimeoutValue
      # comment above for why (RemediationEntry.succeeded exact-matches it).
      Write-RemediationLog 'CrashDumpEnabled' "$currentCrash" '7' 'SUCCESS'
      $remediationCount++
      $rebootRequiredFor += 'CrashDumpEnabled'
    }
  } catch {
    Write-Status 'FAIL' "REMEDIATION FAILED: CrashDumpEnabled -- $($_.Exception.Message)"
    Write-RemediationLog 'CrashDumpEnabled' 'unknown' '7' "FAILED: $($_.Exception.Message)"
    $remediationFail++
  }

  # R-3: QGA service startup type
  try {
    $qgaSvc = Get-Service -Name 'QEMU-GA' -ErrorAction SilentlyContinue
    if ($qgaSvc) {
      if ($qgaSvc.StartType -ne 'Automatic') {
        Set-Service -Name 'QEMU-GA' -StartupType Automatic
        Write-Status 'OK' "REMEDIATED: QEMU-GA StartType set to Automatic (was: $($qgaSvc.StartType))"
        Write-RemediationLog 'QGA.StartType' $qgaSvc.StartType 'Automatic' 'SUCCESS'
        $remediationCount++
      }
      if ($qgaSvc.Status -ne 'Running') {
        Start-Service -Name 'QEMU-GA'
        Write-Status 'OK' "REMEDIATED: QEMU-GA service started"
        Write-RemediationLog 'QGA.Status' $qgaSvc.Status 'Running' 'SUCCESS'
        $remediationCount++
      }
    }
  } catch {
    Write-Status 'FAIL' "REMEDIATION FAILED: QGA service -- $($_.Exception.Message)"
    Write-RemediationLog 'QGA' 'unknown' 'Automatic+Running' "FAILED: $($_.Exception.Message)"
    $remediationFail++
  }

  # R-4: Remove phantom VMware devices (irreversible -- export device tree first)
  # Match detection: Unknown and Error status (parity with section 5 phantom scan)
  $phantomVmware = Get-PnpDevice -ErrorAction SilentlyContinue |
    Where-Object {
      ($_.Status -eq 'Unknown' -or $_.Status -eq 'Error') -and
      ($_.FriendlyName -match 'VMware|VMMemCtl|vmxnet|SVGA|pvscsi' -or $_.Manufacturer -match 'VMware')
    }
  if ($phantomVmware) {
    $pnpBackup = Join-Path $backupDir 'pnpstate-before.pnp'
    pnputil /export-pnpstate $pnpBackup 2>$null | Out-Null
    $pnpExportExit = $LASTEXITCODE
    # N12 (v0.16.0 #12): device removal is irreversible without a verified
    # pnpstate backup -- if the export didn't actually produce a usable file,
    # refuse to remove any of the phantom devices in this batch rather than
    # silently proceeding with no rollback path.
    if (-not (Test-BackupSucceeded -BackupPath $pnpBackup -ToolExitCode $pnpExportExit)) {
      foreach ($dev in $phantomVmware) {
        Write-Status 'FAIL' "REMEDIATION SKIPPED: Remove $($dev.InstanceId) -- pnputil /export-pnpstate did not produce a valid backup file, refusing to remove devices without one"
        Write-RemediationLog "PhantomDevice.$($dev.InstanceId)" 'present' 'removed' 'FAILED: backup verification failed'
        $remediationFail++
      }
    } else {
      foreach ($dev in $phantomVmware) {
        try {
          pnputil /remove-device $dev.InstanceId 2>$null | Out-Null
          if ($LASTEXITCODE -ne 0) {
            Write-Status 'FAIL' "REMEDIATION FAILED: Remove $($dev.InstanceId) -- pnputil exit $LASTEXITCODE"
            Write-RemediationLog "PhantomDevice.$($dev.InstanceId)" 'present' 'removed' "FAILED: pnputil exit $LASTEXITCODE"
            $remediationFail++
          } else {
            Write-Status 'OK' "REMEDIATED: Removed phantom device '$($dev.FriendlyName)' ($($dev.InstanceId))"
            Write-RemediationLog "PhantomDevice.$($dev.InstanceId)" 'present' 'removed' 'SUCCESS'
            $remediationCount++
          }
        } catch {
          Write-Status 'FAIL' "REMEDIATION FAILED: Remove $($dev.InstanceId) -- $($_.Exception.Message)"
          Write-RemediationLog "PhantomDevice.$($dev.InstanceId)" 'present' 'removed' "FAILED: $($_.Exception.Message)"
          $remediationFail++
        }
      }
    }
  }

  Write-Host ""
  Write-Host ("  Remediations applied: {0}, Failed: {1}" -f $remediationCount, $remediationFail) -ForegroundColor Cyan
  Write-Host "  Backup: $backupDir"
  Write-Host "  Log: $remediationLog"
  if ($rebootRequiredFor.Count -gt 0) {
    Write-Host ""
    Write-Host "  *** REBOOT REQUIRED ***" -ForegroundColor Yellow
    Write-Host "  The following remediation(s) are registry values read once at boot and do NOT take" -ForegroundColor Yellow
    Write-Host "  effect until the guest reboots -- until then, the underlying BSOD risk is NOT yet mitigated" -ForegroundColor Yellow
    Write-Host "  despite the successful REMEDIATED status above:" -ForegroundColor Yellow
    foreach ($item in $rebootRequiredFor) { Write-Host "    - $item" -ForegroundColor Yellow }
    Write-RemediationLog 'RebootRequired' 'n/a' ($rebootRequiredFor -join ', ') 'PENDING (guest not yet rebooted)'
  }
}

Write-Host ""
Write-Host ("=== Summary: {0} FAIL, {1} WARN ===" -f $Script:FailCount, $Script:WarnCount) -ForegroundColor Cyan
if ($Remediate -and $Export) {
  Write-Host ("  Export: {0} artifact(s) written, nothing on the guest was modified" -f $exportedFiles.Count) -ForegroundColor Cyan
  foreach ($f in $exportedFiles) { Write-Host "    - $f" -ForegroundColor Cyan }
} elseif ($Remediate) {
  Write-Host ("  Remediations: {0} applied, {1} failed" -f $remediationCount, $remediationFail) -ForegroundColor Cyan
}
if ($remediationFail -gt 0) {
  Write-Host "  Exit code 12: remediation failure(s)." -ForegroundColor Red
  exit 12
}
if ($Remediate -and $remediationCount -gt 0 -and $Script:FailCount -gt 0) {
  Write-Host "  Exit code 11: partial (remediations applied but findings remain)." -ForegroundColor Yellow
  exit 11
}
if ($Script:FailCount -gt 0) {
  Write-Host "  Exit code 10: one or more FAIL findings detected." -ForegroundColor Red
  exit 10
}
Write-Host "=== done ===" -ForegroundColor Cyan
