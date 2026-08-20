# BSOD Detection Framework -- Administrator Runbook

This runbook is for OpenShift administrators and platform teams who deploy
the **customer-facing** half of the framework: Prometheus alerts and the
bash migration gate. It is written for the public distribution at
[github.com/JaredBurck/ocp-virt-bsod-detection](https://github.com/JaredBurck/ocp-virt-bsod-detection).

This is **not a supported Red Hat product**. It is diagnostic tooling,
provided as-is, under Apache-2.0. It does not replace OpenShift
Virtualization, MTV, or a support case.

Red Hat support engineers have a separate internal runbook (must-gather
image and offline analysis). That path is not in this repository. If the
gate reports FAIL or WARN, open a Red Hat support case and attach the
gate `--json` output plus the git tag you ran.

## What this distribution contains

- Layer 4: `scripts/cnv-win-bsod-audit.sh` (21 gates) and the MTV
  plan/fleet wrappers
- Layer 3: PrometheusRule CRs (13 hypervisor alerts, 11 recording rules,
  9 guest alerts) plus ACM, dashboards, `windows-exporter`, fleet exporter,
  COO, and Tekton wrappers
- Shared threshold JSON under `shared/`

It does **not** ship Windows guest disk images. Point the gate at VirtualMachines
you already run. Live-cluster lab overlays and internal guest-disk registries
are not part of this distribution.

## Prerequisites

- OpenShift Container Platform 4.12+ with OpenShift Virtualization
- `oc` authenticated (`oc whoami`)
- `jq`
- For guest collection: PowerShell 5.1+ inside the Windows VM, or QEMU
  Guest Agent for `cnv-qga-fleet-collect.sh`
- Cluster-admin (or the RBAC in `tekton/rbac.yaml`) to deploy alerts and
  run the gate

This repository does not require Python, pytest, or an insights-rules
checkout to operate.

## Windows VMs (bring your own)

Run the gate against namespaces that already contain your Windows VMs:

```bash
./scripts/cnv-win-bsod-audit.sh <namespace>
./scripts/cnv-win-bsod-audit.sh <namespace> <vm-name>
```

MTV/Forklift-imported VMs are in scope. The gate does not provision guest
disks, DataVolumes, or `win-vms` lab images.

## Installation

### 1. PrometheusRule alerts and recording rules

Deploy recording rules first (storage-latency alerts depend on them):

```bash
oc apply -f alerts/bsod-risk-recording-rules.yaml
oc apply -f alerts/bsod-risk-prometheusrules.yaml
oc apply -f alerts/bsod-risk-guest-alerts.yaml   # needs windows_exporter
```

Full tables, `os` annotation dependency, AMD kube-state-metrics allowlist
(OCP &lt; 4.14), and `promtool` tests: [`alerts/README.md`](../alerts/README.md).

**`BSODRisk_GuestCrash` is a preview placeholder.** The
`kubevirt_vmi_guest_os_panic_total` metric is not in any shipping CNV
release. A quiet alert is not evidence of no crash. Use virt-launcher logs
(`GUEST_PANICKED` / `GUEST_CRASHLOADED`) and attach them to the support case.

### 2. Grafana dashboard (optional)

[`dashboards/README.md`](../dashboards/README.md). Canonical JSON is
`dashboards/bsod-risk-overview.json`.

### 3. Guest metrics with `windows_exporter` (optional)

Without this, the 9 guest-metric alerts show no data. Hypervisor alerts and
the bash gate still work.

[`windows-exporter/README.md`](../windows-exporter/README.md).

### 4. ACM, fleet exporter, COO, Tekton (optional)

- Multi-cluster: [`acm/README.md`](../acm/README.md)
- Evidence-completeness exporter: [`exporter/README.md`](../exporter/README.md)
- Cluster Observability Operator: [`coo/README.md`](../coo/README.md)
- Pipeline-as-code / MTV PreHook: [`tekton/README.md`](../tekton/README.md)

### Fleet evidence-completeness exporter

The `BSODRisk_FleetEvidenceIncomplete` / `BSODRisk_ExporterCollectionFailing`
alerts point here. Deploy the exporter from [`exporter/README.md`](../exporter/README.md)
and attach gate `--json` output when opening a case.

Build the gate image yourself (do not treat maintainer Quay tags as a
product registry):

```bash
podman build -t <your-registry>/tekton-bsod-gate:local -f Dockerfile.gate .
```

Point `tekton/bsod-gate-task.yaml` / PreHook Job at that image. Unattended
PreHook must stay **inform**, not enforce, and must pass `--fail-on-unknown`
(see `shared/audit-consumers.json`).

## Running the gate

```bash
# Namespace (Windows VMs only, default)
./scripts/cnv-win-bsod-audit.sh <namespace>

# One VM
./scripts/cnv-win-bsod-audit.sh <namespace> <vm-name>

# Promote migration-critical WARNs to FAIL
./scripts/cnv-win-bsod-audit.sh --strict <namespace>

# Machine-readable (attach this to a support case)
./scripts/cnv-win-bsod-audit.sh --json <namespace> > bsod-gate.json

# Unattended consumers: treat unassessed checks as blocking
./scripts/cnv-win-bsod-audit.sh --fail-on-unknown <namespace>
```

Guest evidence (Gate 15 driver version, Gate 16 VMware residue) needs
`collect-windows-guest-info.ps1` or `cnv-qga-fleet-collect.sh`. Set
`BSOD_GUEST_EVIDENCE_DIR` if the collect output is not `./bsod-qga-collect`.

MTV plan / fleet:

```bash
./scripts/cnv-mtv-plan-gate.sh <plan-namespace> <plan-name>
./scripts/cnv-mtv-fleet-readiness.sh <plan-namespace>
```

### Verdicts

| Output | Meaning |
|--------|---------|
| `[FAIL]` | Hard blocker. Process exit 1. |
| `[WARN]` | Advisory. Exit 0 unless `--strict` promotes it. |
| `[UNKN]` | Required evidence missing. Exit 0 unless `--fail-on-unknown`. |
| `[ OK ]` | That check passed. |

**Exit 0 is not migration-safe.** Review WARN and UNKN counts before a
migration wave. The gate is cluster-visible configuration plus guest files
you collected; it is not a substitute for production soak or a support
investigation.

## Gate checks (21 gates; 7 cluster-scoped + 15 per-VM)

Gates 8, 9, 12, 17, 18, 19, and 20 run once at the cluster level; gates 1-7,
9-11, 13-16, and 21 run per VM. Gate 9 runs at **both** scopes (cluster-wide
AMD node presence, then per-VM `arch-capabilities`), which is why the two
counts sum to 22 rather than 21.

| Gate | Check | BSOD Risk (Stop Code) | KCS |
|------|-------|-----------|-----|
| 1 | Boot disk bus (non-virtio) | INACCESSIBLE_BOOT_DEVICE (0x7B) | [7141237](https://access.redhat.com/solutions/7141237) |
| 2 | Machine type (i440FX) | INACCESSIBLE_BOOT_DEVICE (0x7B) on Q35 transition | [7141237](https://access.redhat.com/solutions/7141237) |
| 3 | NIC model (legacy e1000) | DRIVER_IRQL_NOT_LESS_OR_EQUAL (0xD1) | [263043](https://access.redhat.com/solutions/263043) |
| 4 | CPU model (host-passthrough / host-model / unset) | CLOCK_WATCHDOG_TIMEOUT (0x101) / KERNEL_MODE_EXCEPTION_NOT_HANDLED (0x9C) on live migration | -- |
| 5 | Hyper-V enlightenments | Clock/perf bugchecks | -- |
| 6 | Eviction strategy (None) | Dirty shutdown as BSOD (**always FAIL**) | -- |
| 7 | WSL/nested-virt annotation | HYPERVISOR_ERROR (0x20001) | [7132519](https://access.redhat.com/solutions/7132519) |
| 8 | AMD microcode (Family 1Ah only) | PFN_LIST_CORRUPT (0x4E) | [7132511](https://access.redhat.com/solutions/7132511) |
| 9 | arch-capabilities CPU feature (cluster + per-VM) | UNSUPPORTED_PROCESSOR (0x5D) | [7125237](https://access.redhat.com/solutions/7125237) |
| 10 | virtio-blk multiqueue | MEMORY_MANAGEMENT (0x1A) | [7136486](https://access.redhat.com/solutions/7136486) |
| 11 | Storage latency (Prometheus 1h mean; UNKNOWN if unreachable) | MEMORY_MANAGEMENT (0x1A) / KERNEL_DATA_INPAGE_ERROR (0x7A) / PAGE_FAULT_IN_NONPAGED_AREA (0x50) / CRITICAL_PROCESS_DIED (0xEF) | [7132512](https://access.redhat.com/solutions/7132512) |
| 12 | TSC frequency consistency (cluster) | CLOCK_WATCHDOG_TIMEOUT (0x101) | -- |
| 13 | QEMU Guest Agent health | Graceful shutdown failure | -- |
| 14 | CPU topology (socket count) | Windows Desktop licensing limit | -- |
| 15 | Guest virtio-win version (stream-aware) | Known BSOD triggers when outdated | [7141291](https://access.redhat.com/solutions/7141291) |
| 16 | Phantom NIC / VMware driver residue (guest evidence) | DRIVER_IRQL_NOT_LESS_OR_EQUAL (0xD1) | [263043](https://access.redhat.com/solutions/263043) |
| 17 | Legacy template compliance (cluster) | HYPERVISOR_ERROR (0x20001) / 0x7B | [7132519](https://access.redhat.com/solutions/7132519), [7141237](https://access.redhat.com/solutions/7141237) |
| 18 | InstanceType topology compliance (cluster) | MEMORY_MANAGEMENT (0x1A) | [7136486](https://access.redhat.com/solutions/7136486) |
| 19 | Preference compliance audit (cluster) | HYPERVISOR_ERROR (0x20001) / 0x7B / 0x5D | [7132519](https://access.redhat.com/solutions/7132519), [7141237](https://access.redhat.com/solutions/7141237), [7125237](https://access.redhat.com/solutions/7125237) |
| 20 | Prometheus alert coverage (cluster) | n/a -- reports alert blind spots | n/a |
| 21 | virtio-win driver source attached (containerDisk/CD-ROM) | INACCESSIBLE_BOOT_DEVICE (0x7B) | [7141291](https://access.redhat.com/solutions/7141291) |

## Gate behavior notes

- **Gate 6** (`evictionStrategy=None`) is always a hard **FAIL**.
- **`--strict` mode** promotes migration-critical warnings (gates 9, 10, 7)
  to hard failures.
- **Gate 8 (AMD Family 1Ah):** microcode probe uses `oc debug` (a short-lived
  privileged pod). Set `BSOD_SKIP_MICROCODE_PROBE=1` to skip (UNKNOWN, not a
  pass).
- **Gate 10:** confirm guest virtio-win &gt;= 1.9.53 via QGA/collector, not
  the cluster stream floor alone. [KCS-7136486](https://access.redhat.com/solutions/7136486).
  If the running queue count cannot be confirmed, the gate reports UNKNOWN
  (not a pass). Confirm with `oc exec -n <ns> virt-launcher-<pod> -c compute
  -- virsh dumpxml 1 | grep queues=`.
- **Gate 11** queries the in-cluster Thanos/Prometheus for the 1h worst-direction
  disk latency (`bsod:vmi_disk_latency:worst_1h`, falling back to raw KubeVirt
  counters). Absence of data is UNKNOWN, never a pass. Opt out with
  `BSOD_SKIP_PROM_QUERY=1`. Cross-check `BSODRisk_StorageLatency*`.
  [KCS-7132512](https://access.redhat.com/solutions/7132512).
- **Gates 15 and 16** evaluate guest evidence under `BSOD_GUEST_EVIDENCE_DIR`
  (default `./bsod-qga-collect`) via `scripts/lib/driver-verdict.sh` and the
  `PhantomNICConfig.csv` / `PhantomDevices.csv` artifacts
  `collect-windows-guest-info.ps1` writes. An absent CSV with an otherwise
  populated guest directory means "checked, found none," not "not assessed."
  Only a missing guest-evidence *directory* is UNKNOWN (`[UNKN]`). UNKNOWN is
  not a WARN: a WARN asserts a risk was found. UNKNOWNs are counted
  separately and block under `--fail-on-unknown`.
- **Gate 16** FAILs on active VMware drivers (`vmware_drv_list.csv`) and
  high-risk phantoms (`VMMemCtl` / `vmxnet` / `pvscsi` / `SVGA`). Other
  VMware phantoms WARN. Phantom NIC configs WARN.
  [KCS-7132519](https://access.redhat.com/solutions/7132519) /
  [KCS-263043](https://access.redhat.com/solutions/263043).
- **Gates 17-19** are shift-left cluster-scope audits of templates,
  instancetypes, and preferences. Gate 18 skips on OCP &lt; 4.14 (InstanceType
  API not GA). Gate 19 produces a hard FAIL if a Windows preference is
  completely missing `preferredHyperv`.
- **Gate 20** does not assess BSOD risk -- it assesses whether the alerting
  layer can see your VMs. `BSODRisk_MemoryPressure` and
  `BSODRisk_EvictionBlocked` select Windows VMs with
  `kubevirt_vmi_info{os=~"windows|win.*"}`; that `os` label comes from the
  VMI's `vm.kubevirt.io/os` annotation. VMs built from raw manifests,
  Terraform, or some MTV paths carry no `os` label and those two alerts
  **never fire for them**. Gate 20 reports "N of M Windows VMs are invisible"
  as a cluster-scope summary **and** on each affected VM's own verdict line.
  It also flags OCP older than 4.14, where kube-state-metrics does not export
  node labels by default. Pass `--suggest-annotate` to print (not execute) the
  `oc patch vm ... --type=merge` command for the nested annotation. Weighted
  in the lowest risk domain ("coverage") so this finding alone never moves a
  VM's tier.
- **Instancetype/preference resolution** (OCP 4.19+): VMs referencing
  instancetypes/preferences have sparse `spec.template.spec.domain`; the audit
  resolves the effective config from the running VMI (preferred) or the
  referenced preference (fallback).
- **Gate 21** is distinct from Gate 15 (grades an already-installed driver)
  and Gate 1 (grades the boot disk bus): it checks whether a virtio-win source
  was ever attached for a virtio/scsi-bus boot disk. It PASSes when guest
  evidence already confirms an installed driver, and does not apply to
  `sata`/`usb`-bus boot disks.

## Known limitations

These are deliberate, documented gaps -- not bugs. Plan around them.

### 1. Gate 4 WARNs on `host-model` / unset / `host-passthrough` without comparing per-node CPU feature sets

The gate WARNs whenever `cpu.model` is unset, explicitly `host-model`, or
`host-passthrough`. It does not inspect `cpu-feature.node.kubevirt.io/*`
labels across nodes, so it cannot tell a homogeneous cluster (false
positive) from a heterogeneous one (real 0x101 / 0x9C risk).

**Impact:** on a homogeneous cluster, triage the WARN against node labels. On
a heterogeneous cluster, take it at face value.

**Mitigation:** compare worker node CPU feature labels:

```bash
oc get nodes -l node-role.kubernetes.io/worker -o json |
  jq -r '.items[] | .metadata.name as $n | .metadata.labels
    | to_entries[] | select(.key | startswith("cpu-feature.node.kubevirt.io/"))
    | "\($n)\t\(.key)=\(.value)"'
```

If every schedulable virt worker exposes the same feature set, the WARN is
the conservative default. If features differ, pin `spec.template.spec.domain.cpu.model`
to a named model that all targets can provide. Attach gate `--json` to the
support case.

### 2. `BSODRisk_DriverVersionOutdated` fallback is not stream-aware

The alert's primary path uses the stream-aware `bsod_virtio_driver_outdated`
gauge and is correctly stream-aware. The fallback path (legacy textfile
collectors) uses a single universal floor. Details:
[`alerts/README.md`](../alerts/README.md) Limitations.

**Mitigation:** deploy the current `bsod-textfile-collector.ps1`. Confirm the
stream verdict with Gate 15 after guest collection.

### 3. Gate exit 0 does not mean "migration-safe"

`cnv-win-bsod-audit.sh` exits `0` when there are no `[FAIL]` gates. `[WARN]`
and `[UNKN]` are not reflected in the exit code unless you pass `--strict`
or `--fail-on-unknown`.

**Mitigation:** always review the printed WARN and UNKN counts before a
migration wave.

### 4. QGA sensitive-data retrieval is size-guarded

`--include-sensitive-data` produces a timestamped `SystemInfo_*.zip`. The
fleet script auto-retrieves it only when at or under `--max-dump-mb`
(default 200 MB). Larger bundles stay on the guest with a WARN. There is no
`oc cp` path -- the file lives inside the Windows guest disk. Delete the
guest-side copy after manual retrieval.

### 5. `BSODRisk_MemoryPressure` / `BSODRisk_EvictionBlocked` depend on `vm.kubevirt.io/os`

Both alerts filter on `kubevirt_vmi_info{os=~"windows|win.*"}`. That label
comes only from the `vm.kubevirt.io/os` annotation (common-template /
instancetype webhook). It is unrelated to QEMU Guest Agent.

**Pre-flight:**

```bash
oc get vm <vm-name> -n <namespace> \
  -o jsonpath='{.spec.template.metadata.annotations.vm\.kubevirt\.io/os}{"\n"}'
oc get vmi <vm-name> -n <namespace> \
  -o jsonpath='{.metadata.annotations.vm\.kubevirt\.io/os}{"\n"}'
```

Empty or non-matching output means those two alerts cannot fire. Gate 20
reports the same gap. Remediation:

```bash
oc patch vm <vm-name> -n <namespace> --type=merge \
  -p '{"spec":{"template":{"metadata":{"annotations":{"vm.kubevirt.io/os":"win2k22"}}}}}'
```

Restart the VM (stop/start, not live migration) so a fresh VMI picks up the
annotation. Use the guest's real OS id when known (`win10`, `win2k22`,
`win2k25`, ...); `windows` is a last-resort generic.

## virtio-win version matrix

The required virtio-win version depends on the OCP/RHEL stream. A universal
threshold does **not** work. Canonical numbers:
`shared/virtio-win-thresholds.json`.

| OCP Version | RHEL Stream | Max virtio-win | Key missing fixes |
|-------------|-------------|----------------|-------------------|
| 4.22+ | RHEL 10.1 | **1.9.57** | None (all fixes available) |
| 4.19-4.21 | RHEL 9.6 | **1.9.57** | None (all fixes available) |
| 4.16-4.18 | RHEL 9.4 | **1.9.46** | Multiqueue fix (1.9.53), VGA dump fix (1.9.57) |
| 4.13-4.15 | RHEL 9.2 | **1.9.34** | All major BSOD fixes |
| 4.12 | RHEL 8.6 | **1.9.24** | All major BSOD fixes |

For OCP &lt; 4.19, apply per-bug workarounds (disable multiqueue, tune
IoTimeoutValue, avoid VGA adapter) or upgrade to OCP 4.19+.

## Guest-side collector

`collect-windows-guest-info.ps1` runs inside Windows (PowerShell 5.1+).
Fleet equivalent: `cnv-qga-fleet-collect.sh` (no RDP).

```powershell
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
.\scripts\collect-windows-guest-info.ps1 -VirtioDrive D
```

```bash
./scripts/cnv-qga-fleet-collect.sh --namespace <ns> --all-windows --stage --output ./bsod-qga-collect
```

The collector:

1. Grades **VirtIO package version** against stream-aware baselines
   (`shared/virtio-win-thresholds.json`)
2. Detects **WSL / Hyper-V / VirtualMachinePlatform** (0x20001 risk)
3. Notes the **display adapter** (VirtIO GPU dump caveat,
   [KCS-7141988](https://access.redhat.com/solutions/7141988))
4. Enumerates **phantom VMware devices** (VMMemCtl, vmxnet, SVGA residue)
5. Audits **IoTimeoutValue** for viostor/vioscsi
6. Captures an **I/O performance baseline** via performance counters
7. Reads the **MTV firstboot log** for driver injection errors
8. Audits **CrashDump** configuration and pagefile sizing
9. Records **Windows version and KB** patch level
10. Checks **QEMU Guest Agent** service status and start type
11. Optionally invokes Red Hat **CollectSystemInfo.ps1** (`-IncludeSensitiveData`
    includes MEMORY.DMP; default off)
12. Exports QGA-compatible artifacts (`virtio_version.txt`,
    `PhantomDevices.csv`, `vmware_drv_list.csv`, `InstalledKBs.json`, …)
    for Gates 15/16
13. Optional **`-Remediate`**: IoTimeoutValue, CrashDumpEnabled, QGA
    service, phantom VMware device removal, with registry backup and
    `remediation.log`. `-Remediate -Export <reg|ansible|both>` writes a
    reviewable artifact instead of mutating the guest.

**Exit codes:** `0` = success, no findings; `10` = audit findings (no
remediation); `11` = partial remediation; `12` = remediation failures.

Sensitive dump collection is **opt-in**. Default collection does not pull
MEMORY.DMP or minidumps.

### Exit-code conventions (this distribution)

| Tool | Exit 0 | Other codes |
|------|--------|-------------|
| `collect-windows-guest-info.ps1` | Success, no findings | `10` findings / `11` partial remediation / `12` remediation failure(s) |
| `scripts/cnv-win-bsod-audit.sh` | No `[FAIL]` gates. **WARN and UNKN may still be present. Exit 0 is not migration-safe.** | `1` = one or more `[FAIL]` (or UNKNOWN under `--fail-on-unknown`) |

## Storage latency calibration

`BSODRisk_StorageLatencyElevated` / `High` / `Burst` / `Trending` use
thresholds from `shared/storage-latency-thresholds.json` (0.5s sustained
warning / 1.0s sustained critical / 5s burst). Calibration is **PARTIAL**.
See `_calibration_status` in that JSON for what the 2026-07-29 workshop
measurement did and did not establish.

Before fleet rollout, run `scripts/cnv-storage-latency-calibrate.sh` against
a cluster with real production Windows I/O and confirm healthy VMs sit well
below `sustained_warn_seconds`. Exit codes: `0` = within thresholds, `1` =
exceeds WARN/CRITICAL, `2` = calibration could not complete (re-run; do not
record). Adjust thresholds only in the JSON (never hardcode in alert YAML).

## Vendor routing (KCS-7129390)

Always open **both** a Red Hat case and a Microsoft case.

| Scenario | Contact first |
|----------|----------------|
| After VMware migration | Red Hat |
| After virtio-win driver update | Red Hat |
| After OCP/CNV platform upgrade | Red Hat |
| After Windows Update | Microsoft |
| Random one-off, no recent change | Microsoft |
| After Windows configuration change | Microsoft |

[KCS-7129390](https://access.redhat.com/solutions/7129390).

## Opening a support case

1. Note the git tag of this snapshot (GitHub release tag).
2. Attach `cnv-win-bsod-audit.sh --json` output.
3. If guest collection ran, attach the relevant CSVs (`vmware_drv_list.csv`,
   `PhantomDevices.csv`, `virtio_version.txt`) without MEMORY.DMP unless
   you opted into sensitive data collection.
4. Do not clone an internal GitLab URL. This GitHub repository is the
   customer distribution.
