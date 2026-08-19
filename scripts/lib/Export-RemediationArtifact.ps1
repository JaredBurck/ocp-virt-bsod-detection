# Export-RemediationArtifact.ps1 -- Issue J (Gemini peer review): emit a
# reviewable remediation artifact instead of mutating the guest.
#
# Single source of truth for the -Remediate -Export <fmt> code path. Dot-sourced by:
#   - scripts/collect-windows-guest-info.ps1 (production)
#   - tests/test_ps_export_remediation.ps1 (CI harness)
#
# Evaluates the EXACT SAME conditions collect-windows-guest-info.ps1's
# in-place remediation branch (R-1..R-4) acts on, but never calls
# New-Item/Set-ItemProperty/Set-Service/pnputil -- only Test-Path/
# Get-ItemProperty/Get-Service (read-only) plus Set-Content to write the
# artifact file(s) themselves. No backup directory, no `reg export`, no
# registry/service/device mutation of any kind happens here.
#
# Extracted into its own dot-sourceable file (matching Get-StreamDriverVerdict.ps1's
# precedent) specifically so it can be unit-tested on a non-Windows pwsh CI
# runner: Test-Path/Get-ItemProperty/Get-Service are overridden by the test
# harness AFTER dot-sourcing, in the same script scope -- the same technique
# tests/test_ps_protect_guest_staging_dir.ps1 uses for Invoke-Icacls.

# Export-RemediationArtifact: read current guest state for the same four
# remediation targets the in-place branch fixes, and if any of them would be
# touched, write a .reg file, an Ansible playbook, or both to -OutDir.
#
# Params:
#   -OutDir                Directory to write the artifact(s) to.
#   -Format                'reg', 'ansible', or 'both'.
#   -IoTimeoutRecommended  Threshold below which IoTimeoutValue is flagged
#                          (from shared/io-timeout-thresholds.json).
#   -IoTimeoutDefault      Label used when no IoTimeoutValue is set at all.
#   -IoTimeoutTarget       Value the artifact would set IoTimeoutValue to.
#   -PhantomDevices        Array of PnP device objects (FriendlyName,
#                          InstanceId) already detected as VMware residue by
#                          the caller's own phantom-device scan -- reused,
#                          not re-queried, so this function never calls
#                          Get-PnpDevice itself.
#
# Returns a PSCustomObject: RegItemCount, QgaNeedsFix, PhantomCount,
# NothingToExport, ExportedFiles (array of paths written).
function Export-RemediationArtifact {
  param(
    [Parameter(Mandatory = $true)][string]$OutDir,
    [Parameter(Mandatory = $true)][ValidateSet('reg', 'ansible', 'both')][string]$Format,
    [Parameter(Mandatory = $true)][int]$IoTimeoutRecommended,
    [Parameter(Mandatory = $true)][int]$IoTimeoutDefault,
    [Parameter(Mandatory = $true)][int]$IoTimeoutTarget,
    [array]$PhantomDevices = @()
  )

  # Same detection as R-1 (in-place branch): viostor/vioscsi IoTimeoutValue.
  $regItems = @()
  foreach ($driver in @('viostor', 'vioscsi')) {
    $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$driver"
    $regPathCheck = "$servicePath\Parameters"
    if (Test-Path $servicePath) {
      $current = (Get-ItemProperty -Path $regPathCheck -Name 'IoTimeoutValue' -ErrorAction SilentlyContinue).IoTimeoutValue
      if (-not $current -or $current -lt $IoTimeoutRecommended) {
        $wasLabel = if ($current) { "$current" } else { "default/$IoTimeoutDefault" }
        $regItems += [PSCustomObject]@{
          RegPathBackslash = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$driver\Parameters"
          AnsiblePath      = "HKLM:\SYSTEM\CurrentControlSet\Services\$driver\Parameters"
          Name             = 'IoTimeoutValue'
          Value            = $IoTimeoutTarget
          Description      = "$driver IoTimeoutValue -> $IoTimeoutTarget (was: $wasLabel)"
        }
      }
    }
  }

  # Same detection as R-2: CrashDumpEnabled.
  $exportCrashPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
  $currentCrash = (Get-ItemProperty -Path $exportCrashPath -Name 'CrashDumpEnabled' -ErrorAction SilentlyContinue).CrashDumpEnabled
  if ($currentCrash -eq 0 -or $currentCrash -eq 3) {
    $wasLabel = if ($currentCrash -eq 0) { '0/disabled' } else { '3/minidump' }
    $regItems += [PSCustomObject]@{
      RegPathBackslash = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl'
      AnsiblePath      = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
      Name             = 'CrashDumpEnabled'
      Value            = 7
      Description      = "CrashDumpEnabled -> 7/Automatic (was: $wasLabel)"
    }
  }

  # Same detection as R-3: QGA service. Not representable as a plain .reg
  # import (starting a service is not a registry effect), so this is
  # Ansible-only -- the .reg artifact documents it as a manual follow-up.
  $qgaSvc = Get-Service -Name 'QEMU-GA' -ErrorAction SilentlyContinue
  $qgaNeedsFix = $false
  if ($qgaSvc -and ($qgaSvc.StartType -ne 'Automatic' -or $qgaSvc.Status -ne 'Running')) {
    $qgaNeedsFix = $true
  }

  # Same population as R-4: caller's already-collected phantom-device list.
  # Listed for awareness only -- irreversible device removal is never
  # emitted as an unattended task in either artifact.
  $phantomList = @()
  if ($PhantomDevices) { $phantomList = $PhantomDevices }

  $result = [PSCustomObject]@{
    RegItemCount    = $regItems.Count
    QgaNeedsFix     = $qgaNeedsFix
    PhantomCount    = $phantomList.Count
    NothingToExport = $false
    ExportedFiles   = @()
  }

  $totalCount = $regItems.Count
  if ($qgaNeedsFix) { $totalCount++ }
  $totalCount += $phantomList.Count
  if ($totalCount -eq 0) {
    $result.NothingToExport = $true
    return $result
  }

  $genStamp = Get-Date -Format 'o'

  if ($Format -eq 'reg' -or $Format -eq 'both') {
    $regFilePath = Join-Path $OutDir 'remediation-export.reg'
    $lines = @()
    $lines += 'Windows Registry Editor Version 5.00'
    $lines += ''
    $lines += "; Generated by collect-windows-guest-info.ps1 -Remediate -Export reg on $genStamp"
    $lines += '; REVIEW BEFORE APPLYING. Apply with: reg import <this file> (run as Administrator).'
    $lines += '; Registry values below take effect only after the guest reboots.'
    $lines += ''
    foreach ($item in $regItems) {
      $hexValue = '{0:x8}' -f [int]$item.Value
      $lines += "[$($item.RegPathBackslash)]"
      $lines += "`"$($item.Name)`"=dword:$hexValue"
      $lines += ''
    }
    if ($qgaNeedsFix -or $phantomList.Count -gt 0) {
      $lines += '; NOT included above -- not representable as a .reg import:'
      if ($qgaNeedsFix) {
        $lines += ';   - QEMU-GA service startup/state. Apply with:'
        $lines += ';       sc.exe config QEMU-GA start= auto'
        $lines += ';       net start QEMU-GA'
      }
      if ($phantomList.Count -gt 0) {
        $lines += ";   - $($phantomList.Count) phantom VMware device(s) -- irreversible device removal, review"
        $lines += ';     and remove manually (Device Manager or pnputil /remove-device), or re-run'
        $lines += ';     collect-windows-guest-info.ps1 -Remediate (without -Export).'
      }
    }
    Set-Content -Path $regFilePath -Value $lines -Encoding ASCII
    $result.ExportedFiles += $regFilePath
  }

  if ($Format -eq 'ansible' -or $Format -eq 'both') {
    $ymlFilePath = Join-Path $OutDir 'remediation-playbook.yml'
    $lines = @()
    $lines += '---'
    $lines += "# Generated by collect-windows-guest-info.ps1 -Remediate -Export ansible on $genStamp"
    $lines += '# REVIEW BEFORE RUNNING. Requires the ansible.windows collection:'
    $lines += '#   ansible-galaxy collection install ansible.windows'
    $lines += '# and a WinRM-reachable inventory host for this VM in the "windows_vms" group.'
    $lines += '- name: BSOD risk remediation (exported by collect-windows-guest-info.ps1, not yet applied)'
    $lines += '  hosts: windows_vms'
    $lines += '  gather_facts: false'
    $lines += '  tasks:'
    foreach ($item in $regItems) {
      # Description always contains "(was: N)" -- an unquoted ": " inside a
      # YAML plain scalar is parsed as a nested mapping key, not literal
      # text (confirmed: PyYAML raises "mapping values are not allowed
      # here" on an earlier unquoted draft). Double-quote the scalar.
      $lines += "    - name: `"$($item.Description)`""
      $lines += '      ansible.windows.win_regedit:'
      $lines += "        path: $($item.AnsiblePath)"
      $lines += "        name: $($item.Name)"
      $lines += "        data: $($item.Value)"
      $lines += '        type: dword'
    }
    if ($qgaNeedsFix) {
      $lines += '    - name: Ensure QEMU-GA service is running and set to auto-start'
      $lines += '      ansible.windows.win_service:'
      $lines += '        name: QEMU-GA'
      $lines += '        start_mode: auto'
      $lines += '        state: started'
    }
    if ($phantomList.Count -gt 0) {
      $lines += "    # $($phantomList.Count) phantom VMware device(s) detected -- NOT included as a task above."
      $lines += '    # Device removal is irreversible; review each device before scripting it. Example:'
      foreach ($dev in $phantomList) {
        $lines += "    #   ansible.windows.win_shell: pnputil /remove-device `"$($dev.InstanceId)`"  # $($dev.FriendlyName)"
      }
    }
    if ($regItems.Count -gt 0) {
      $lines += '  # Registry changes above require a reboot of the guest to take effect. Uncomment to'
      $lines += '  # reboot automatically as part of this play (review your own maintenance-window policy'
      $lines += '  # first):'
      $lines += '  # - name: Reboot to apply registry changes'
      $lines += '  #   ansible.windows.win_reboot: {}'
    }
    Set-Content -Path $ymlFilePath -Value $lines -Encoding ASCII
    $result.ExportedFiles += $ymlFilePath
  }

  return $result
}
