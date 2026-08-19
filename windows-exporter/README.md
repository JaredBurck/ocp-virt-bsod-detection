# windows_exporter Deployment Guide for BSOD Detection

## Overview

This guide covers deploying `windows_exporter` inside Windows VMs on OpenShift Virtualization to enable guest-visible metrics in Prometheus. These metrics provide higher-fidelity BSOD risk detection than hypervisor-side metrics alone.

The deployment has two sides:

1. **Guest-side** -- install `windows_exporter` and the BSOD textfile collector inside each Windows VM
2. **Cluster-side** -- create per-VM Services, a ServiceMonitor, and guest alert rules so Prometheus scrapes the metrics

## Prerequisites

Before deploying, confirm:

- Windows VM running on OpenShift Virtualization (Windows Server 2019+ or Windows 10+; Server 2016 requires TLS 1.2 pre-configuration -- see Troubleshooting)
- Administrator access inside the Windows VM (or QEMU Guest Agent connectivity for zero-touch deployment)
- Network path from OpenShift worker nodes to the VM on TCP 9182 (see Network Requirements below)
- Prometheus/OpenShift monitoring stack operational
- `oc` CLI authenticated to the cluster with namespace admin privileges
- `jq` installed (required for QGA fleet deployment)

### Network Requirements

Prometheus must reach the Windows guest on TCP 9182. This requires L2/L3 reachability from the pod network to the VM's guest IP. Depending on your CNV network configuration:

- **Masquerade (default)**: Traffic routes through the pod network. A Service with pod selector works because `targetPort` hits the virt-launcher pod, which forwards to the guest via QEMU.
- **Bridge / Multus secondary**: Traffic goes directly to the VM's interface IP. Use a headless Service with explicit Endpoints pointing to the guest IP.

**Verify reachability:**

```bash
curl http://<vm-guest-ip>:9182/metrics
```

## Components

| File | Purpose |
|------|---------|
| `install-windows-exporter.ps1` | Automated installer (MSI + firewall + scheduled task) |
| `bsod-textfile-collector.ps1` | Custom collector exposing BSOD-specific metrics |
| `servicemonitor-windows-vms.yaml` | ServiceMonitor CR for Prometheus scraping |

## Metrics Exposed

| Metric | Type | Alert-Backed | Description |
|--------|------|:---:|-------------|
| `windows_logical_disk_read_seconds_total` | Built-in | Yes | Read time counter (rate-divided by `reads_total` yields avg latency) |
| `windows_logical_disk_reads_total` | Built-in | Yes | Read operations counter |
| `windows_pagefile_free_bytes` | Built-in | Yes | Current pagefile free space in bytes (utilization is derived as `(limit-free)/limit`) |
| `windows_pagefile_limit_bytes` | Built-in | Yes | Maximum pagefile capacity (utilization ratio > 0.9 fires alert) |
| `windows_service_state{name="QEMU-GA"}` | Built-in | -- | QGA service state (redundant with custom metric below) |
| `bsod_virtio_package_version` | Custom | Yes | VirtIO package version (label: `version`, e.g., `1.9.46`) |
| `bsod_virtio_driver_outdated` | Custom | Yes | Stream-aware outdated flag (`1`/`0`; labels: `version`, `stream`) |
| `bsod_virtio_driver_version` | Custom | -- | VirtIO binary driver version (label: `version`, e.g., `100.0.0.46000`) |
| `bsod_io_timeout_value` | Custom | -- | IoTimeoutValue per storage driver |
| `bsod_crashdump_enabled` | Custom | Yes | CrashDump registry setting (0=disabled, 7=automatic) |
| `bsod_qga_service_running` | Custom | Yes | QGA service running status (used by `BSODRisk_QGAServiceDown`) |
| `bsod_pagefile_max_mb` | Custom | -- | Maximum pagefile size in MB |

## Installation

### Method 1: Automated (Recommended)

1. Copy both scripts to the Windows VM (via QGA, RDP, or shared folder)
2. Place `bsod-textfile-collector.ps1` at `C:\ProgramData\windows_exporter\bsod-textfile-collector.ps1` (the installer expects it there)
3. Run the installer:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Pre-stage the collector script
New-Item -ItemType Directory -Force -Path 'C:\ProgramData\windows_exporter'
Copy-Item .\bsod-textfile-collector.ps1 'C:\ProgramData\windows_exporter\bsod-textfile-collector.ps1'

# Run the installer (downloads MSI, generates config.yaml, configures firewall, schedules collector)
# Pass -OCPVersion for stream-aware bsod_virtio_driver_outdated (also stages thresholds JSON)
.\install-windows-exporter.ps1 -OCPVersion 4.18

# Recommended for production: scope the firewall rule to the cluster's pod/machine network CIDR(s)
.\install-windows-exporter.ps1 -OCPVersion 4.18 -FirewallRemoteAddress '10.128.0.0/14','172.30.0.0/16'
```

**What the installer does:**
1. Downloads the `windows_exporter` v0.30.1 MSI from GitHub
2. Verifies SHA256 checksum against the pinned upstream `sha256sums.txt` (install aborts if the hash does not match)
3. Installs the MSI with configured collectors
4. Generates `config.yaml` (textfile directory with forward slashes)
5. Creates a Windows Firewall rule (defaults to `Domain,Private` profiles; `-FirewallProfile`/`-FirewallRemoteAddress` narrow it further)
6. Stages `virtio-win-thresholds.json` + verdict helper when available
7. Registers a scheduled task for the textfile collector

If the collector script is not pre-staged, the installer prints "Collector script not found -- schedule manually." and skips the scheduled task creation.

**After install:** The `windows_exporter` service requires a restart to pick up the `config.yaml` textfile directory. If `bsod_*` metrics are missing after install:

```powershell
Restart-Service windows_exporter
```

### Method 2: Manual

**Step 1:** Download and install windows_exporter MSI:

```powershell
msiexec /i windows_exporter-amd64.msi ENABLED_COLLECTORS="cpu,cs,logical_disk,memory,net,os,service,system,textfile,pagefile" TEXTFILE_DIR="C:\ProgramData\windows_exporter\textfile" LISTEN_PORT="9182" LISTEN_ADDR="0.0.0.0" /quiet
```

`LISTEN_ADDR=0.0.0.0` is required so Prometheus can reach the exporter from the pod network. The `pagefile` collector is required for `BSODRisk_PagefilePressure`.

**Step 2:** Create `config.yaml` for textfile collector directory (MSI `TEXTFILE_DIR` alone does not propagate to the service):

```powershell
@"
collector:
  textfile:
    directories: "C:/ProgramData/windows_exporter/textfile"
"@ | Out-File -FilePath "C:\Program Files\windows_exporter\config.yaml" -Encoding ascii
Restart-Service windows_exporter
```

**Important:** Use forward slashes in the YAML path. Backslash sequences like `\t` are interpreted as escape characters by the YAML parser.

**Step 3:** Open firewall:

```powershell
New-NetFirewallRule -DisplayName 'windows_exporter (TCP 9182)' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9182
```

**Step 4:** Deploy the BSOD textfile collector:

```powershell
Copy-Item bsod-textfile-collector.ps1 C:\ProgramData\windows_exporter\
# Create scheduled task to run every 5 minutes
schtasks /create /tn "BSOD-TextfileCollector" /tr "powershell -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\windows_exporter\bsod-textfile-collector.ps1" /sc minute /mo 5 /ru SYSTEM /f
```

### Method 3: Via QGA (Zero-Touch Fleet)

Deploy `windows_exporter` to all Windows VMs in a namespace without RDP, SSH, or console access. This uses the QEMU Guest Agent's `guest-file-write` and `guest-exec` APIs through the virt-launcher pod.

**Prerequisites:** All target VMs must have QGA installed and the `AgentConnected` condition set to `True`. Verify:

```bash
oc get vmi -n <namespace> -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .status.conditions[*]}{.type}={.status} {end}{"\n"}{end}' | grep AgentConnected
```

**Deployment steps per VM:**

```bash
NAMESPACE="my-vms"
VM_NAME="my-windows-vm"

# Find the virt-launcher pod
POD=$(oc get pods -n "$NAMESPACE" -l "kubevirt.io/domain=$VM_NAME" \
  --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')

# Get the libvirt domain name
DOMAIN=$(oc exec -n "$NAMESPACE" "$POD" -c compute -- \
  bash -c 'virsh list --name 2>/dev/null | grep -v "^$" | head -1')

# 1. Create target directories in the guest. install-windows-exporter.ps1 dot-sources
# ..\scripts\lib\Protect-GuestStagingDir.ps1 relative to its own location, so the guest
# layout must mirror the repo layout (windows-exporter/ and scripts/lib/ as siblings) --
# staging the installer alone at C:\Temp\install-windows-exporter.ps1 fails at startup
# with "The term 'C:\Temp\..\scripts\lib\Protect-GuestStagingDir.ps1' is not recognized".
oc exec -n "$NAMESPACE" "$POD" -c compute -- virsh qemu-agent-command "$DOMAIN" \
  '{"execute":"guest-exec","arguments":{"path":"C:\\Windows\\System32\\cmd.exe","arg":["/c","mkdir C:\\ProgramData\\windows_exporter 2>nul & mkdir C:\\Temp\\windows-exporter 2>nul & mkdir C:\\Temp\\scripts\\lib 2>nul"],"capture-output":true}}'

# 2. Upload scripts via guest-file-write (base64-encode, open/write/close). Stage:
#    bsod-textfile-collector.ps1        -> C:\ProgramData\windows_exporter\bsod-textfile-collector.ps1
#    install-windows-exporter.ps1       -> C:\Temp\windows-exporter\install-windows-exporter.ps1
#    scripts/lib/Protect-GuestStagingDir.ps1 -> C:\Temp\scripts\lib\Protect-GuestStagingDir.ps1  (required)
#    scripts/lib/Get-StreamDriverVerdict.ps1 -> C:\Temp\scripts\lib\Get-StreamDriverVerdict.ps1  (optional, enables stream-aware bsod_virtio_driver_outdated)
#    shared/virtio-win-thresholds.json  -> C:\Temp\shared\virtio-win-thresholds.json             (optional)
B64=$(base64 -w 0 < windows-exporter/bsod-textfile-collector.ps1)
HANDLE=$(oc exec -n "$NAMESPACE" "$POD" -c compute -- virsh qemu-agent-command "$DOMAIN" \
  '{"execute":"guest-file-open","arguments":{"path":"C:\\ProgramData\\windows_exporter\\bsod-textfile-collector.ps1","mode":"w"}}' | jq '.return')
oc exec -n "$NAMESPACE" "$POD" -c compute -- virsh qemu-agent-command "$DOMAIN" \
  "{\"execute\":\"guest-file-write\",\"arguments\":{\"handle\":$HANDLE,\"buf-b64\":\"$B64\"}}"
oc exec -n "$NAMESPACE" "$POD" -c compute -- virsh qemu-agent-command "$DOMAIN" \
  "{\"execute\":\"guest-file-close\",\"arguments\":{\"handle\":$HANDLE}}"

# Repeat the open/write/close sequence for the other files listed above, at their
# respective guest paths.

# 2b. IMPORTANT: files created via guest-file-open/write can come back with an empty
# (deny-all) DACL regardless of the parent directory's permissions -- observed live
# (bsod-textfile-collector.ps1 ended up with zero ACEs while a file staged the same way
# in a different directory did not). Directly grant SYSTEM + Administrators on EACH
# staged file (do not rely on install-windows-exporter.ps1's Protect-GuestStagingDir
# recursive /T re-grant to reach pre-existing files -- confirmed live that it does not
# always do so). Otherwise later execution fails with "Access to the path ... is
# denied" / CommandNotFoundException, even though `whoami` and `icacls <dir>` both show
# SYSTEM has full control on the containing directory.
#
# A bare `/grant:r` is NOT reliable by itself: confirmed live that it can silently
# no-op on a file whose DACL degraded to zero entries (icacls exits 0 but the ACL is
# unchanged, and Protect-GuestStagingDir's own later re-ACL attempt on the same file
# then fails with "Access is denied"). Reclaim ownership first with `/setowner`
# (SYSTEM always holds SeTakeOwnershipPrivilege, independent of the existing DACL) --
# owning the file is what grants the WRITE_DAC needed for `/grant:r` to actually take
# effect. This is the same two-step order harden_guest_staging_dir()
# (scripts/cnv-qga-fleet-collect.sh) and Protect-GuestStagingDir.ps1 already use.
for f in 'C:\ProgramData\windows_exporter\bsod-textfile-collector.ps1' \
         'C:\Temp\windows-exporter\install-windows-exporter.ps1' \
         'C:\Temp\scripts\lib\Protect-GuestStagingDir.ps1'; do
  CMD=$(printf '{"execute":"guest-exec","arguments":{"path":"C:\\\\Windows\\\\System32\\\\cmd.exe","arg":["/c","icacls \\"%s\\" /setowner *S-1-5-18 /C"],"capture-output":true}}' "$f")
  oc exec -n "$NAMESPACE" "$POD" -c compute -- virsh qemu-agent-command "$DOMAIN" "$CMD"
  CMD=$(printf '{"execute":"guest-exec","arguments":{"path":"C:\\\\Windows\\\\System32\\\\cmd.exe","arg":["/c","icacls \\"%s\\" /inheritance:r /grant:r *S-1-5-18:F /grant:r *S-1-5-32-544:F /C"],"capture-output":true}}' "$f")
  oc exec -n "$NAMESPACE" "$POD" -c compute -- virsh qemu-agent-command "$DOMAIN" "$CMD"
done

# 3. Execute the installer via guest-exec (note the path matches the mirrored layout)
oc exec -n "$NAMESPACE" "$POD" -c compute -- virsh qemu-agent-command "$DOMAIN" \
  '{"execute":"guest-exec","arguments":{"path":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","arg":["-NoProfile","-ExecutionPolicy","Bypass","-File","C:\\Temp\\windows-exporter\\install-windows-exporter.ps1"],"capture-output":true}}'

# 4. Poll guest-exec-status until exited=true (timeout ~300-500s; MSI download+install
# can occasionally take several minutes depending on guest link speed)

# 5. Run the textfile collector once and restart the service to load config.yaml
# (the scheduled task handles subsequent runs every 5 minutes)

# 6. Widen the firewall rule's profile so Prometheus can actually reach the
# guest -- masquerade-networked, non-domain-joined VMs report Public (not
# Private/Domain) via Get-NetConnectionProfile, so the installer's default
# Domain,Private rule never matches inbound scrapes from the pod network.
# Scope -RemoteAddress to the pod network CIDR to keep exposure bounded
# despite the broader profile (see "Security Considerations" below).
POD_CIDR=$(oc get network.config cluster -o jsonpath='{.spec.clusterNetwork[0].cidr}')
CMD=$(printf '{"execute":"guest-exec","arguments":{"path":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","arg":["-NoProfile","-Command","Set-NetFirewallRule -DisplayName '"'"'windows_exporter (TCP 9182)'"'"' -Profile Any -RemoteAddress '"'"'%s'"'"'"],"capture-output":true}}' "$POD_CIDR")
oc exec -n "$NAMESPACE" "$POD" -c compute -- virsh qemu-agent-command "$DOMAIN" "$CMD"
```

`scripts/cnv-windows-exporter-fleet-install.sh` automates this entire workflow (staging with the ACL fix, install, optional `--widen-firewall`) across a namespace or an explicit VM list -- prefer it over hand-rolling the steps above for real deployments:

```bash
# Discover Windows VMs automatically (structured OS metadata + name fallback,
# same contract as the other three Windows-VM-detection implementations)
scripts/cnv-windows-exporter-fleet-install.sh --namespace bsod-test --all-windows \
  --ocp-version 4.18 --widen-firewall --confirm-widen-firewall \
  --status-file /tmp/windows-exporter-fleet-status.tsv

# Or target one VM
scripts/cnv-windows-exporter-fleet-install.sh --namespace bsod-test --vm win2k22-good --ocp-version 4.18
```

It reuses the `qga_file_write`/`qga_exec` helper functions from `cnv-qga-fleet-collect.sh` -- note that script's own helpers do *not* apply the per-file ACL workaround in 2b nor the firewall-profile widening in step 6 by themselves; the fleet-install script layers both on top. For fleet-wide deployment via the manual steps above instead, loop over all VMs returned by `oc get vmi`.

**Air-gapped environments:** The guest needs internet access to download the MSI from GitHub. For air-gapped environments, pre-stage the `windows_exporter-0.30.1-amd64.msi` file via `guest-file-write`, then pass `-MsiUrl 'C:\Temp\windows_exporter.msi'` to the installer.

**Alternative access method:** `virtctl ssh` works if SSH/WinRM is configured inside the guest, but is not required. The QGA approach works without any guest-side networking configuration.

## OpenShift Configuration

### 1. Create a Service for Each Windows VM

Each VM needs a Service that the ServiceMonitor can discover. The file `servicemonitor-windows-vms.yaml` includes a Service **template** with `${VM_NAME}` and `${NAMESPACE}` placeholders -- substitute these before applying.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: bsod-windows-exporter-<vm-name>
  namespace: <namespace>
  labels:
    bsod-detection/windows-exporter: "true"
    vm.kubevirt.io/name: <vm-name>
spec:
  type: ClusterIP
  ports:
    - name: windows-exporter
      port: 9182
      targetPort: 9182
  selector:
    vm.kubevirt.io/name: <vm-name>
```

**How this works:** The selector matches the virt-launcher pod for the VM. With the default masquerade network, traffic to `targetPort: 9182` is forwarded through QEMU to the guest. For bridge/Multus configurations where the guest has a routable IP, create a headless Service with explicit Endpoints pointing to the guest IP instead.

**Example for a VM named `winweb01` in namespace `my-vms`:**

```bash
VM_NAME=winweb01 NAMESPACE=my-vms envsubst < windows-exporter/servicemonitor-windows-vms.yaml | oc apply -f -
```

### 2. Deploy ServiceMonitor

Deploy the ServiceMonitor once (it matches across all namespaces):

```bash
# Apply the ServiceMonitor
oc apply -f - <<'EOF'
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: bsod-windows-exporter
  namespace: openshift-cnv
  labels:
    app.kubernetes.io/component: bsod-detection
spec:
  endpoints:
    - port: windows-exporter
      interval: 60s
      path: /metrics
      relabelings:
        - sourceLabels: [__meta_kubernetes_pod_label_vm_kubevirt_io_name]
          targetLabel: vm_name
        - sourceLabels: [__meta_kubernetes_namespace]
          targetLabel: vm_namespace
  namespaceSelector:
    any: true
  selector:
    matchLabels:
      bsod-detection/windows-exporter: "true"
EOF
```

### 3. Deploy Guest Alerts

```bash
oc apply -f alerts/bsod-risk-guest-alerts.yaml
```

### 4. Verify Scraping

Query Prometheus directly with your user token:

```bash
TOKEN=$(oc whoami -t)
PROM_ROUTE=$(oc get route prometheus-k8s -n openshift-monitoring -o jsonpath='{.spec.host}')

# #6 (v0.16.0): this route is edge-terminated by the OpenShift router, so its
# certificate is signed by the cluster's INGRESS CA -- trust that bundle
# explicitly instead of `-k` skipping verification (see
# scripts/cnv-storage-latency-calibrate.sh for the same fix, verified
# against a live cluster).
INGRESS_CA=$(mktemp)
oc get configmap default-ingress-cert -n openshift-config-managed \
  -o jsonpath='{.data.ca-bundle\.crt}' > "$INGRESS_CA"

# Check bsod_virtio_driver_version across all VMs
curl -s --cacert "$INGRESS_CA" -H "Authorization: Bearer $TOKEN" \
  "https://${PROM_ROUTE}/api/v1/query?query=bsod_virtio_driver_version" | \
  jq -r '.data.result[] | "\(.metric.vm_name): version=\(.metric.version)"'

# Quick count of scraped VMs
curl -s --cacert "$INGRESS_CA" -H "Authorization: Bearer $TOKEN" \
  "https://${PROM_ROUTE}/api/v1/query?query=count(bsod_virtio_driver_version)" | \
  jq -r '.data.result[0].value[1]'

rm -f "$INGRESS_CA"
```

Or exec into Prometheus directly:

```bash
oc -n openshift-monitoring exec -c prometheus prometheus-k8s-0 -- \
  promtool query instant http://localhost:9090 'bsod_virtio_driver_version'
```

You see one result per VM with `windows_exporter` installed and running.

## Security Considerations

### No Authentication (By Design)

`windows_exporter` does not support authentication. TCP 9182 serves plaintext HTTP. Metrics exposed are system-level counters (CPU, memory, disk, pagefile, driver versions), not user data. The endpoint is unauthenticated and unencrypted -- **network-level scoping is the only control**.

### Listen Address

`install-windows-exporter.ps1` binds `LISTEN_ADDR=0.0.0.0:9182` so Prometheus can reach the exporter via the pod network. This is required for the default CNV masquerade networking model. If you run a sidecar proxy or node-local agent that can reach `127.0.0.1`, override `LISTEN_ADDR=127.0.0.1` in the MSI arguments.

### Firewall Rule (Primary Security Boundary)

`install-windows-exporter.ps1` defaults the rule's `-FirewallProfile` to `Domain,Private` (excludes Public). This is safer than the original `-Profile Any`, but the rule still allows inbound TCP 9182 from any reachable source by default.

**Narrow the rule for production deployments along two axes:**

**Profile:** Only widen to `-FirewallProfile Any` (or add `Public`) if the VM is directly NIC-bridged onto an untrusted network segment and you have a specific reason to.

> **Cloned/unjoined VMs on masquerade networking are classified `Public`, not
> `Private`/`Domain`, by Windows Network Location Awareness** -- confirmed
> live via `Get-NetConnectionProfile` on `bsod-test` VMs. This isn't about
> being NIC-bridged onto an untrusted segment; it's the default classification
> any fresh, non-domain-joined Windows guest gets on a virtio-net masquerade
> interface. Since `-FirewallProfile Domain,Private` therefore never matches
> on these VMs, the exporter is unreachable from Prometheus (scrapes fail with
> `context deadline exceeded`, not `connection refused`) until the rule is
> widened to `Any`. Compensate by scoping `-FirewallRemoteAddress` to the pod
> network CIDR (see below) so the practical exposure is still limited to
> cluster-internal traffic despite the broader profile match.

**Source scope (`-FirewallRemoteAddress`):** Restrict inbound TCP 9182 to the cluster's pod/machine network CIDR(s):

```bash
# From a system with oc access, find the pod/machine network CIDRs:
oc get network.config cluster -o jsonpath='{.status.clusterNetwork[*].cidr}{"\n"}{.status.networking.machineNetwork[*].cidr}'
```

```powershell
# Pass the CIDR(s) to the installer (use your cluster's actual output, not these examples):
.\install-windows-exporter.ps1 -OCPVersion 4.18 -FirewallRemoteAddress '10.128.0.0/14','172.30.0.0/16'

# To re-scope an already-installed rule without re-running the full installer:
Set-NetFirewallRule -DisplayName 'windows_exporter (TCP 9182)' -Profile Domain,Private -RemoteAddress '10.128.0.0/14','172.30.0.0/16'
```

With Multus/bridge networking (where Prometheus reaches the guest IP directly), scope `-FirewallRemoteAddress` to the relevant node/machine network CIDR instead.

### Defense in Depth

Scope reachability at the OpenShift Service/NetworkPolicy level too:
- Expose the exporter only via the per-VM Service the ServiceMonitor targets
- Apply the shipped `NetworkPolicy` in each namespace holding Windows VMs:

```bash
oc apply -n <vm-namespace> -f windows-exporter/networkpolicy-windows-exporter.yaml
```

It is a default-deny on ingress plus a single allow for TCP 9182 from the
platform (and user-workload) Prometheus pods. The deny rule is listed first so a
mistake in the allow selector fails **closed**.

> **Enrolment is required — the policy is inert until you label the VM.** Both
> policies select `bsod-detection/windows-exporter: "true"` **on the pod**, which
> means the label must live in the VM's `spec.template.metadata.labels`:
>
> ```bash
> oc patch vm <name> -n <ns> --type merge -p \
>   '{"spec":{"template":{"metadata":{"labels":{"bsod-detection/windows-exporter":"true"}}}}}'
> ```
>
> A VM's own `metadata.labels` will **not** work — KubeVirt propagates
> `spec.template.metadata.labels` to the virt-launcher pod, not the VM's
> top-level labels. (Verified live: a VM carrying `vm.kubevirt.io/os` in
> `metadata.labels` does not have it on its pod.)
>
> This is the same label `servicemonitor-windows-vms.yaml` already selects on, so
> enrolling a VM for scraping and for network policy is one action, not two.

**Why enrolment and not "all Windows VMs":** an earlier version of this manifest
selected `vm.kubevirt.io/name: Exists`, which KubeVirt sets on *every*
virt-launcher pod regardless of guest OS — so its deny-by-default would have cut
ingress to co-located **Linux** VMs. There is no OS label on a virt-launcher pod
to select on. Scoping to exporter enrolment is also simply more precise: a
Windows VM not running the exporter has no port 9182 to police.

> **Verify it is actually enforced.** A `NetworkPolicy` is inert unless the
> cluster network plugin enforces it -- `oc apply` succeeding proves nothing.
> Check with:
> ```bash
> oc get network.operator cluster -o jsonpath='{.spec.defaultNetwork.type}{"\n"}'
> ```
> OVN-Kubernetes (the OCP 4.12+ default) enforces policy.

> **Multus/bridge networking:** this policy governs *pod-network* ingress only.
> Where Prometheus reaches the guest IP directly it does not apply -- scope the
> in-guest firewall rule (`-FirewallRemoteAddress`) to the node/machine network
> instead, as the Firewall section above describes.

Until v0.19.0 this section recommended a `NetworkPolicy` without shipping one,
so the only durable boundary these docs identify had to be hand-authored by
every operator.

### Least Privilege

- The textfile collector runs as SYSTEM to read registry keys
- The exporter service runs as `LocalSystem` (the upstream MSI's default `ServiceAccount`; `install-windows-exporter.ps1` does not override it) -- confirmed live via `Get-CimInstance Win32_Service -Filter "Name='windows_exporter'"` on a `win-vms` VM. This is a corrected claim: earlier text here said "Local Service" (`NT AUTHORITY\LOCAL SERVICE`), which is a distinct, much lower-privileged account that cannot read a textfile-collector output file whose DACL happens to degrade to zero ACEs (see the Troubleshooting row on `bsod_*` metrics below) -- only SYSTEM/Administrators can

## Troubleshooting

| Issue | Resolution |
|-------|-----------|
| No metrics in Prometheus | Check Service selector matches VM pod labels. Verify firewall rule. Test `curl http://<vm-ip>:9182/metrics` from a debug pod in the same namespace. |
| `bsod_*` metrics missing but standard metrics work | Restart the `windows_exporter` service inside the guest (`Restart-Service windows_exporter`). Verify `C:\Program Files\windows_exporter\config.yaml` exists with `collector.textfile.directories` using forward slashes. If the config and service are fine, check the ACL on `bsod_metrics.prom` itself next (see the row below) -- confirmed live on a `cnv-windows-exporter-fleet-install.sh`-installed VM: `icacls C:\ProgramData\windows_exporter\textfile\bsod_metrics.prom` came back with **zero ACEs** (deny-all, not even SYSTEM/Administrators), even though the service (`LocalSystem`, see "Least Privilege" above) and the sibling `textfile\` directory's own inherited ACL were both fine. The file is written by `bsod-textfile-collector.ps1`'s own atomic per-PID-temp-file-then-`Move-Item` (not QGA `guest-file-write`), so this is the same DACL-degradation bug class documented elsewhere in this repo for QGA-staged files, just observed on a different write path -- cause still unconfirmed. Fix: `icacls <path> /setowner *S-1-5-18 /C` then `icacls <path> /inheritance:r /grant:r *S-1-5-18:F /grant:r *S-1-5-32-544:F /C` (same two-step reclaim-then-grant order as `harden_guest_staging_dir()`/`Protect-GuestStagingDir.ps1`). This may need repeating if the next scheduled collector run reproduces the same degraded write. |
| Textfile collector errors | Verify `C:\ProgramData\windows_exporter\textfile\bsod_metrics.prom` exists and contains valid Prometheus text format. |
| Service not matching pods | KubeVirt pod labels use `vm.kubevirt.io/name`. Verify with `oc get pods -l vm.kubevirt.io/name=<vm>`. |
| Scheduled task not running | Verify: `schtasks /query /tn BSOD-TextfileCollector`. Re-run installer or create manually. |
| Server 2016 install fails (`Could not create SSL/TLS secure channel`) | Fixed as of this writing: `install-windows-exporter.ps1` now forces `[Net.ServicePointManager]::SecurityProtocol` to include `Tls12` before downloading the MSI, since .NET on Windows Server 2016 (and some older Windows 10 builds) doesn't enable TLS 1.2 by default and GitHub's release CDN is TLS 1.2-only. If you're running an older copy of the script that lacks this, add the same one-liner before the `Invoke-WebRequest` call, or pre-stage the MSI via QGA `guest-file-write`. |
| Prometheus target shows `context deadline exceeded` (not `connection refused`) | The VM's `NetConnectionProfile` is `Public`, not `Private`/`Domain` -- check with `Get-NetConnectionProfile`. Cloned/unjoined VMs on masquerade networking are classified `Public` by Windows Network Location Awareness, so the installer's default `-FirewallProfile Domain,Private` rule silently doesn't apply and inbound scrapes are dropped with no RST. Widen the profile (ideally still scoped to the pod network via `-RemoteAddress`, see "Firewall Rule" below): `Set-NetFirewallRule -DisplayName 'windows_exporter (TCP 9182)' -Profile Any -RemoteAddress '<pod-network-CIDR>'`. |
| ServiceMonitor not being discovered | Verify the ServiceMonitor is in a namespace monitored by Prometheus (e.g., `openshift-cnv`). Check the `namespaceSelector` includes the target Service namespace. Run `oc get servicemonitor -n openshift-cnv bsod-windows-exporter`. |
| Grafana dashboard issues | See `dashboards/README.md` for Grafana Operator installation, datasource authentication, and dashboard troubleshooting. |

## Dependent Alerts

The `BSODRisk_GuestUnexpectedRestart` proxy alert in `alerts/bsod-risk-guest-alerts.yaml`
depends on windows_exporter being deployed. It uses the `up{job="bsod-windows-exporter"}`
metric to detect when a VM's exporter goes offline (potential crash/reboot), combined
with the native virt-controller metric
`kubevirt_vm_running_status_last_transition_timestamp_seconds` (no additional guest-side
dependency) to confirm the VM genuinely re-entered Running recently, rather than the
exporter simply being unreachable. Without windows_exporter deployed and the
ServiceMonitor active, this alert will not have data to evaluate.
