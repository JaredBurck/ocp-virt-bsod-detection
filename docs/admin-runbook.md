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
- Layer 3: PrometheusRule CRs (hypervisor alerts, recording rules, guest
  alerts) plus ACM, dashboards, `windows-exporter`, fleet exporter, COO,
  and Tekton wrappers
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
release. A quiet alert is not evidence of no crash.

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

The `BSODRisk_EvidenceCompleteness` / `BSODRisk_FleetUnassessed` alerts
point here. Deploy the exporter from [`exporter/README.md`](../exporter/README.md)
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

### Gate notes operators hit in practice

- **Gate 11** does not measure storage latency. Use `BSODRisk_StorageLatency*`
  (Layer 3). Calibration of those alerts is PARTIAL. [KCS-VALIDATED]
  [KCS-7132512](https://access.redhat.com/solutions/7132512).
- **Gate 16** FAILs on active VMware drivers (`vmware_drv_list.csv`) and
  high-risk phantoms (`VMMemCtl` / `vmxnet` / `pvscsi` / `SVGA`). Other
  VMware phantoms WARN. Phantom NIC configs WARN. [KCS-VALIDATED]
  [KCS-7132519](https://access.redhat.com/solutions/7132519) /
  [KCS-263043](https://access.redhat.com/solutions/263043).
- **Gate 10:** confirm guest virtio-win &gt;= 1.9.53 via QGA/collector, not
  the cluster stream floor alone. [KCS-7136486](https://access.redhat.com/solutions/7136486).
- **Gate 8 (AMD Family 1Ah):** microcode probe uses `oc debug`. Set
  `BSOD_SKIP_MICROCODE_PROBE=1` to skip (WARN only).

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

Sensitive dump collection is **opt-in** (`-IncludeSensitiveData` /
`--include-sensitive-data`). Default collection does not pull MEMORY.DMP
or minidumps.
