# BSOD risk detection for OpenShift Virtualization

> **Not a supported Red Hat product.** Diagnostic tooling from Red Hat
> SBR-Virt, provided as-is under [Apache License 2.0](LICENSE). See
> [NOTICE](NOTICE).

Public snapshot of the **customer-runnable** layers:

- **Alerts (Layer 3)** -- PrometheusRule CRs, recording rules, optional
  ACM / Grafana / `windows_exporter` / fleet exporter / COO
- **Gates (Layer 4)** -- `cnv-win-bsod-audit.sh` (21 gates per VM) and MTV
  plan/fleet wrappers

Canonical development stays internal. This repository is a tag-aligned
distribution. Open [GitHub Issues](https://github.com/JaredBurck/ocp-virt-bsod-detection/issues)
for feedback; do not expect pull requests to merge here.

**This repo does not ship Windows guest images.** Run the gate against
VirtualMachines you already operate. Guest disks are not included in this
distribution.

Full operator steps: [docs/admin-runbook.md](docs/admin-runbook.md).

## Quick start

```bash
# Prerequisites: oc (logged in), jq
./scripts/cnv-win-bsod-audit.sh <namespace>
./scripts/cnv-win-bsod-audit.sh --json <namespace> > bsod-gate.json
```

Deploy alerts (recording rules first):

```bash
oc apply -f alerts/bsod-risk-recording-rules.yaml
oc apply -f alerts/bsod-risk-prometheusrules.yaml
```

Build the gate container yourself if you use Tekton/MTV PreHook:

```bash
podman build -t <your-registry>/tekton-bsod-gate:local -f Dockerfile.gate .
```

Maintainer `quay.io/jburck/*` tags are convenience builds, not a product
registry. Unattended PreHook: **inform**, not enforce; pass
`--fail-on-unknown`.

## What exit 0 means

`cnv-win-bsod-audit.sh` exits 0 when there are no `[FAIL]` lines. WARNs
and UNKNs may still be present. **Exit 0 is not migration-safe.**

`BSODRisk_GuestCrash` is a preview placeholder (metric not in shipping
CNV). Gate 11 does not measure I/O latency -- use `BSODRisk_StorageLatency*`.

## Vendor routing ([KCS-7129390](https://access.redhat.com/solutions/7129390))

Always open **both** Red Hat and Microsoft cases.

| Scenario | Contact first |
|----------|----------------|
| After VMware migration | Red Hat |
| After virtio-win driver update | Red Hat |
| After OCP/CNV platform upgrade | Red Hat |
| After Windows Update | Microsoft |
| Random one-off, no recent change | Microsoft |
| After Windows configuration change | Microsoft |

## Layout

| Path | Purpose |
|------|---------|
| `scripts/` | Gate pipeline, guest collector, CI validators |
| `shared/` | Thresholds and contracts |
| `alerts/` | PrometheusRule CRs |
| `windows-exporter/` | Guest metrics |
| `exporter/` | Fleet evidence-completeness exporter |
| `dashboards/` | Grafana JSON / ConfigMaps |
| `tekton/` | Task, Pipeline, MTV PreHook |
| `acm/` | ACM Policy |
| `coo/` | Optional Cluster Observability Operator |
| `docs/admin-runbook.md` | Install and operate |

## Confidence tiers

- **[KCS-VALIDATED]** -- Confirmed by a Red Hat KCS article (portal link)
- **[GENERAL-KNOWLEDGE]** -- Established virtualization practice
- **[UNVALIDATED]** -- Advisory only

KCS article **URLs** only (subscription may be required). This repository
does not redistribute KCS PDFs.
