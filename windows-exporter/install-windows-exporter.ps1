<#
.SYNOPSIS
  Install and configure windows_exporter with BSOD textfile collector.

.DESCRIPTION
  Downloads and installs windows_exporter MSI, configures the textfile collector
  directory, adds a firewall rule for TCP 9182, and schedules the BSOD textfile
  collector to run every 5 minutes.

.PARAMETER MsiUrl
  URL to the windows_exporter MSI. Defaults to the latest GitHub release.

.PARAMETER TextfileDir
  Directory for textfile collector metrics.

.PARAMETER CollectorScript
  Path to bsod-textfile-collector.ps1 (copied to the guest beforehand).

.PARAMETER FirewallProfile
  Windows Firewall profile(s) the TCP 9182 inbound rule applies to. Defaults
  to Domain,Private (excludes Public) -- windows_exporter serves plaintext,
  unauthenticated metrics, so the rule should not be reachable from a Public
  profile. Pass 'Any' only if you have an explicit reason (e.g. -Profile Any
  was the pre-hardening default; scope -FirewallRemoteAddress instead if you
  need it).

.PARAMETER FirewallRemoteAddress
  Remote address scope(s) for the TCP 9182 inbound rule (CIDR or address).
  Defaults to 'Any' for zero-config installs, but production/customer-shared
  deployments should pass the cluster's pod/machine network CIDR(s) here --
  see the "Security Considerations" > firewall-scope-narrowing example in
  deploy-guide.md for how to obtain them via `oc get network.config cluster`.

.NOTES
  Run as Administrator. Requires internet access for MSI download.
#>
[CmdletBinding()]
# Interactive installer run manually by an operator; colorized/plain
# Write-Host status output is the intended UX, not a script that feeds
# a pipeline.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive installer: console status output is the intended UX.')]
param(
  [string]$MsiUrl = 'https://github.com/prometheus-community/windows_exporter/releases/download/v0.30.1/windows_exporter-0.30.1-amd64.msi',
  # SHA256 from https://github.com/prometheus-community/windows_exporter/releases/download/v0.30.1/sha256sums.txt
  [string]$MsiChecksum = 'fb43db2b2168dcbbf3f689697c0ef139ea08888a0c873f93b28ca33d76eb3bf2',
  [string]$TextfileDir = 'C:\ProgramData\windows_exporter\textfile',
  [string]$CollectorScript = 'C:\ProgramData\windows_exporter\bsod-textfile-collector.ps1',
  [string]$OCPVersion = '',
  [string]$ThresholdsSource = '',
  [string]$VerdictHelperSource = '',
  [string[]]$FirewallProfile = @('Domain', 'Private'),
  [string[]]$FirewallRemoteAddress = @('Any')
)

$ErrorActionPreference = 'Stop'

# v0.16.0 review #2: single source of truth for ACL hardening, shared with
# scripts/cnv-qga-fleet-collect.sh's harden_guest_staging_dir() (bash/QGA
# side). $ErrorActionPreference = 'Stop' above means an unhandled exception
# from Protect-GuestStagingDir aborts this whole install -- intentional
# fail-closed behavior, not an oversight.
. (Join-Path $PSScriptRoot '..\scripts\lib\Protect-GuestStagingDir.ps1')

Write-Host "=== windows_exporter Installation for BSOD Detection ==="

# Windows Server 2016 / older Windows 10 builds ship with TLS 1.2 supported
# by the OS but NOT enabled by default in .NET's ServicePointManager, so
# Invoke-WebRequest against GitHub (TLS 1.2-only) fails immediately with
# "Could not create SSL/TLS secure channel." Add (not replace) Tls12 to
# whatever the process default already is -- harmless no-op on newer
# Windows where it's already enabled.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# Download MSI
$msiPath = Join-Path $env:TEMP 'windows_exporter.msi'
Write-Host "Downloading windows_exporter v0.30.1 MSI..."
Invoke-WebRequest -Uri $MsiUrl -OutFile $msiPath -UseBasicParsing

$actualHash = (Get-FileHash -Path $msiPath -Algorithm SHA256).Hash.ToLowerInvariant()
$expectedHash = $MsiChecksum.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
  Write-Error ("MSI SHA256 mismatch: expected {0}, got {1}. Aborting install." -f $expectedHash, $actualHash)
  exit 1
}
Write-Host "MSI SHA256 verified: $actualHash"

# Install with textfile + pagefile collectors enabled
Write-Host "Installing windows_exporter..."
$installArgs = @(
  '/i', $msiPath,
  '/quiet',
  "ENABLED_COLLECTORS=cpu,cs,logical_disk,memory,net,os,pagefile,service,system,textfile",
  "TEXTFILE_DIR=$TextfileDir",
  "LISTEN_ADDR=0.0.0.0",
  "LISTEN_PORT=9182"
)
# F-08: msiexec's exit code MUST be captured and acted on.
#
# This was `Start-Process ... -Wait -NoNewWindow` with no -PassThru, so the
# exit code was discarded entirely. $ErrorActionPreference = 'Stop' does not
# cover it -- that governs PowerShell cmdlet errors, not a child process's
# exit status -- so a failed install fell through to the end of this script,
# which then exited 0.
#
# That 0 is authoritative downstream: cnv-windows-exporter-fleet-install.sh
# reads it as the installer's verdict, prints "[OK] <vm>: windows_exporter
# installed" and increments its SUCCESS counter. A whole fleet could report a
# clean rollout with no exporter running anywhere.
#
# Nothing else would have caught it. Guest CPU/memory saturation is
# alert-only by design (see the KNOWN LIMITATION note in
# alerts/bsod-risk-guest-alerts.yaml) with no analyzer counterpart, so the
# only symptom is alerts that never fire -- indistinguishable from a healthy
# fleet. Fail loudly here or the failure is invisible forever.
#
# 1618 (another install in progress) is the common real-world case: Windows
# Update holds the installer mutex and msiexec returns immediately.
# 3010 is success-with-reboot-required and must NOT be treated as a failure.
$msiProc = Start-Process msiexec.exe -ArgumentList $installArgs -Wait -NoNewWindow -PassThru
if ($msiProc.ExitCode -eq 3010) {
  Write-Host "msiexec returned 3010 (success; reboot required to complete)."
} elseif ($msiProc.ExitCode -ne 0) {
  $hint = switch ($msiProc.ExitCode) {
    1603 { ' (fatal error during installation -- check %TEMP%\MSI*.log)' }
    1618 { ' (another installation is already in progress -- retry once it completes)' }
    1619 { ' (installation package could not be opened)' }
    1625 { ' (install forbidden by system policy)' }
    default { '' }
  }
  Write-Error ("msiexec failed with exit code {0}{1}. windows_exporter is NOT installed. Aborting." -f $msiProc.ExitCode, $hint)
  exit 1
}
# Create config.yaml with textfile directory (MSI TEXTFILE_DIR may not propagate to service args)
$configDir = Join-Path $env:ProgramFiles 'windows_exporter'
$configPath = Join-Path $configDir 'config.yaml'
$configContent = @"
collector:
  textfile:
    directories: "$($TextfileDir -replace '\\', '/')"
"@
$configContent | Out-File -FilePath $configPath -Encoding ascii -Force

# Create textfile directory, plus the exporter's own ProgramData tree (lib/
# thresholds/verdict helper get staged into it below, and the SYSTEM
# scheduled task is run out of it further down) -- created together here so
# both can be hardened before anything is written into either.
if (-not (Test-Path $TextfileDir)) {
  New-Item -ItemType Directory -Path $TextfileDir -Force | Out-Null
}
$exporterRoot = 'C:\ProgramData\windows_exporter'
$libDir = Join-Path $exporterRoot 'lib'
if (-not (Test-Path $libDir)) { New-Item -ItemType Directory -Path $libDir -Force | Out-Null }

# v0.16.0 review #2 (LPE): C:\ProgramData inherits an ACL that lets
# BUILTIN\Users create files, and a standard user who pre-creates one of
# these directories becomes its owner. A SYSTEM scheduled task later runs
# the collector script out of $exporterRoot/$TextfileDir (see below), so an
# unprivileged guest user could otherwise plant a payload SYSTEM would
# execute. Harden both roots now, before any file is staged into either.
Write-Host "Hardening ACLs on $exporterRoot ..."
Protect-GuestStagingDir -Path $exporterRoot
if ($TextfileDir -ne $exporterRoot -and $TextfileDir -notlike "$exporterRoot\*") {
  Write-Host "Hardening ACLs on $TextfileDir ..."
  Protect-GuestStagingDir -Path $TextfileDir
}

# Add firewall rule for Prometheus scraping. windows_exporter has no
# authentication and serves plaintext HTTP, so the firewall rule -- scoped by
# profile and, ideally, -FirewallRemoteAddress -- is the actual security
# boundary here. Default profile excludes Public; RemoteAddress defaults to
# Any for zero-config installs but should be narrowed for production.
$fwRule = Get-NetFirewallRule -DisplayName 'windows_exporter (TCP 9182)' -ErrorAction SilentlyContinue
if (-not $fwRule) {
  Write-Host "Adding firewall rule for TCP 9182 (profile: $($FirewallProfile -join ','); remote: $($FirewallRemoteAddress -join ','))..."
  New-NetFirewallRule -DisplayName 'windows_exporter (TCP 9182)' `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9182 `
    -Profile $FirewallProfile -RemoteAddress $FirewallRemoteAddress `
    -Description 'Allow Prometheus to scrape windows_exporter metrics'
} else {
  # R-41 (v0.19.0 follow-up N-05): UPDATE the existing rule, do not skip it.
  #
  # This branch used to log "already exists -- leaving as-is" and return, which
  # meant an operator who deployed permissively (the zero-config default is
  # -FirewallRemoteAddress Any) and later re-ran the installer to NARROW it got
  # no error and no effect. The comment a few lines above this one calls the
  # firewall rule "the actual security boundary here" for a plaintext,
  # unauthenticated exporter -- so silently discarding a request to tighten that
  # boundary is the worst possible place for a no-op, and it fails in the
  # direction of leaving access open.
  #
  # Set-NetFirewallRule is idempotent, so re-running with unchanged values is a
  # no-op in the harmless direction. Before/after values are logged so an
  # operator can confirm the narrowing actually happened rather than trusting
  # that it did.
  $oldProfile = ($fwRule | Select-Object -ExpandProperty Profile) -join ','
  $oldRemote = (($fwRule | Get-NetFirewallAddressFilter).RemoteAddress) -join ','
  $newProfile = $FirewallProfile -join ','
  $newRemote = $FirewallRemoteAddress -join ','

  if ($oldProfile -eq $newProfile -and $oldRemote -eq $newRemote) {
    Write-Host "Firewall rule 'windows_exporter (TCP 9182)' already matches requested scope (profile: $newProfile; remote: $newRemote) -- no change."
  } else {
    Write-Host "Updating firewall rule 'windows_exporter (TCP 9182)':"
    Write-Host "    profile: $oldProfile -> $newProfile"
    Write-Host "    remote:  $oldRemote -> $newRemote"
    Set-NetFirewallRule -DisplayName 'windows_exporter (TCP 9182)' `
      -Profile $FirewallProfile -RemoteAddress $FirewallRemoteAddress
    Write-Host "  firewall rule updated in place."
  }
}

# Stage stream-aware thresholds + verdict helper for the textfile collector
# ($exporterRoot/$libDir created and hardened above, before any Copy-Item)
$thresholdDest = Join-Path $exporterRoot 'virtio-win-thresholds.json'
$thresholdCandidates = @()
if ($ThresholdsSource) { $thresholdCandidates += $ThresholdsSource }
$thresholdCandidates += @(
  (Join-Path $PSScriptRoot '..\shared\virtio-win-thresholds.json'),
  (Join-Path $PSScriptRoot 'virtio-win-thresholds.json'),
  'C:\DebugInfo\virtio-win-thresholds.json'
)
foreach ($ts in $thresholdCandidates) {
  if ($ts -and (Test-Path $ts)) {
    Copy-Item $ts $thresholdDest -Force
    Write-Host "Staged thresholds: $thresholdDest"
    break
  }
}

# R-40 (v0.19.0 follow-up N-04): the ACL helper must persist alongside the
# collector, not only exist in C:\Temp during the install. The scheduled task
# runs bsod-textfile-collector.ps1 from $exporterRoot every 5 minutes,
# indefinitely -- long after install-time scaffolding under C:\Temp may have
# been cleaned -- and that script now re-hardens $TextfileDir on every run.
$protectDest = Join-Path $libDir 'Protect-GuestStagingDir.ps1'
$protectSrc = Join-Path $PSScriptRoot '..\scripts\lib\Protect-GuestStagingDir.ps1'
if (Test-Path $protectSrc) {
  Copy-Item $protectSrc $protectDest -Force
  Write-Host "  staged ACL helper: $protectDest"
} else {
  Write-Warning "Protect-GuestStagingDir.ps1 not found at $protectSrc -- the textfile collector will not be able to re-harden its directory on each run."
}

$verdictDest = Join-Path $libDir 'Get-StreamDriverVerdict.ps1'
$verdictCandidates = @()
if ($VerdictHelperSource) { $verdictCandidates += $VerdictHelperSource }
$verdictCandidates += @(
  (Join-Path $PSScriptRoot '..\scripts\lib\Get-StreamDriverVerdict.ps1'),
  (Join-Path $PSScriptRoot 'Get-StreamDriverVerdict.ps1'),
  'C:\DebugInfo\lib\Get-StreamDriverVerdict.ps1'
)
foreach ($vs in $verdictCandidates) {
  if ($vs -and (Test-Path $vs)) {
    Copy-Item $vs $verdictDest -Force
    Write-Host "Staged verdict helper: $verdictDest"
    break
  }
}

if ($OCPVersion) {
  Set-Content -Path (Join-Path $exporterRoot 'ocp-version.txt') -Value $OCPVersion.Trim() -Encoding ascii
  Write-Host "Wrote OCP version $OCPVersion for stream-aware driver metrics"
} elseif ($env:BSOD_OCP_VERSION) {
  Set-Content -Path (Join-Path $exporterRoot 'ocp-version.txt') -Value $env:BSOD_OCP_VERSION.Trim() -Encoding ascii
}

# Schedule BSOD textfile collector (every 5 minutes)
if (Test-Path $CollectorScript) {
  Write-Host "Scheduling BSOD textfile collector..."
  $collectorArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$CollectorScript`" -TextfileDir `"$TextfileDir`""
  if ($OCPVersion) {
    $collectorArgs += " -OCPVersion `"$OCPVersion`""
  } elseif ($env:BSOD_OCP_VERSION) {
    $collectorArgs += " -OCPVersion `"$($env:BSOD_OCP_VERSION)`""
  }
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $collectorArgs
  $trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) `
    -Once -At (Get-Date)
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName 'BSOD-TextfileCollector' `
    -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

  # Run it once immediately
  Start-ScheduledTask -TaskName 'BSOD-TextfileCollector'
  Write-Host "BSOD textfile collector scheduled and running."
} else {
  Write-Warning "Collector script not found at $CollectorScript -- schedule manually."
}

# Verify service is running
Start-Sleep -Seconds 3
$svc = Get-Service -Name 'windows_exporter' -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
  Write-Host "SUCCESS: windows_exporter is running on port 9182."
  Write-Host "Verify: curl http://localhost:9182/metrics | findstr bsod_"
} else {
  # F-08: this is the last line of defence, and it must be a FAILURE, not a
  # warning. A Write-Warning still leaves $LASTEXITCODE at 0, so the fleet
  # installer recorded the VM as a success and moved on -- the exact silent
  # blindness described at the msiexec check above. An exporter that is not
  # running is an exporter that will never emit a metric, so there is nothing
  # partial about this outcome to report as a warning.
  $svcState = if ($svc) { $svc.Status } else { 'not installed' }
  Write-Error ("windows_exporter service is not running (state: {0}). The install did not complete successfully -- check Event Viewer and %TEMP%\MSI*.log." -f $svcState)
  exit 1
}

Write-Host "`n=== Next Steps ==="
Write-Host "1. Create a Service in OpenShift pointing to this VM's IP:9182"
Write-Host "2. Label the Service: bsod-detection/windows-exporter=true"
Write-Host "3. Deploy the ServiceMonitor: oc apply -f windows-exporter/servicemonitor-windows-vms.yaml"
Write-Host "4. Deploy guest alerts: oc apply -f alerts/bsod-risk-guest-alerts.yaml"
