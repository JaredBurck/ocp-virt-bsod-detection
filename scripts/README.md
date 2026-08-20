# Scripts

Gate pipeline, guest collection, and CI tooling for the BSOD Detection Framework.

## Operational Scripts

| Script | Language | Purpose | Requirements |
|--------|----------|---------|--------------|
| `cnv-win-bsod-audit.sh` | Bash | Per-VM BSOD risk audit (21 gates: 7 cluster-scoped + 15 per-VM; gate 9 runs at both scopes) against cluster-side configuration | `oc` (logged in), `jq` |
| `cnv-mtv-plan-gate.sh` | Bash | Run the audit across every VM in an MTV (Forklift) Plan with per-VM verdict | `oc`, `jq`, `cnv-win-bsod-audit.sh` |
| `cnv-mtv-fleet-readiness.sh` | Bash | Fleet-wide readiness report across all MTV Plans in a namespace | `oc`, `jq`, `cnv-mtv-plan-gate.sh` |
| `cnv-qga-fleet-collect.sh` | Bash | Zero-touch guest data collection via QEMU Guest Agent (no RDP required) | `oc`, `jq`, QGA running in guest |
| `collect-windows-guest-info.ps1` | PowerShell | Guest-side driver version check, evidence collection, and optional remediation | PowerShell 5.1+, run inside Windows VM |
| `pg-must-gather-cmd.sh` | Bash | Internal helper to assemble a multi-image `oc adm must-gather` command. **Not in the public GitHub snapshot.** | `oc` |
| `generate-dashboard-artifacts.sh` | Bash | Regenerate ConfigMap, GrafanaDashboard CR, and ACM policy from canonical dashboard JSON | `python3`, `yq` or `python3-yaml` |

## Shared Libraries (`lib/`)

| File | Language | Purpose | Consumers |
|------|----------|---------|-----------|
| `lib/driver-verdict.sh` | Bash | Stream-aware virtio-win driver version verdict logic | `cnv-win-bsod-audit.sh`, `tests/test_bash_verdict.sh` |
| `lib/Get-StreamDriverVerdict.ps1` | PowerShell | Stream-aware driver verdict logic (PowerShell equivalent) | `collect-windows-guest-info.ps1`, `tests/test_ps_verdict.ps1` |

Both libraries load thresholds from `shared/virtio-win-thresholds.json` and produce identical PASS/WARN/FAIL verdicts for the same version+stream input. Cross-layer consistency is validated by `tests/test_bash_verdict.sh` and `tests/test_ps_verdict.ps1`.

## CI Scripts (`ci/`)

| File | Language | Purpose | CI Job |
|------|----------|---------|--------|
| `ci/validate-acm-policy.py` | Python | Validate (or regenerate with `--update`) ACM policy embedded PrometheusRule specs against canonical sources | `validate-alerts` |
| `ci/validate-dashboard-configmap.py` | Python | Validate dashboard ConfigMap YAML embeds the same JSON as the standalone dashboard file | `validate-alerts` |
| `ci/generate-rules-only.py` | Python | Extract rule groups from PrometheusRule CRs into `_rules_only.yaml` for `promtool test rules` | `validate-alerts` |
| `ci/validate-metric-names.py` | Python | Validate all `windows_exporter`/textfile-collector metric names referenced in alerts/dashboards against the verified allowlist | `validate-alerts` |
| `ci/validate-doc-counts.py` | Python | Validate hardcoded gate/test/alert counts in shipped docs match reality | `test-python` |
| `ci/test_validate_acm_policy.py` | Python (pytest) | Regression tests for `validate-acm-policy.py`'s `--update` header-stripping -- asserts repeated runs are idempotent | `validate-acm` |
| `ci/test_validate_dashboard_configmap.py` | Python (pytest) | Regression tests for `validate-dashboard-configmap.py`'s windows_exporter label check | `validate-json` |

## Gate Pipeline Hierarchy

```
cnv-mtv-fleet-readiness.sh          (fleet: all Plans in a namespace)
  └─ cnv-mtv-plan-gate.sh           (plan: all VMs in one MTV Plan)
       └─ cnv-win-bsod-audit.sh     (VM: 21 gates per VirtualMachine)
            └─ lib/driver-verdict.sh (shared verdict logic)
```

Each layer delegates downward and aggregates results. All gate logic lives in `cnv-win-bsod-audit.sh`.

## Usage

### Single VM Audit

```bash
./scripts/cnv-win-bsod-audit.sh <namespace> [vm-name] [--strict]
```

### Multi-Namespace / Fleet-Wide Audit

```bash
# All namespaces (requires cluster-wide VM list RBAC)
./scripts/cnv-win-bsod-audit.sh --all-namespaces [--strict]

# Multiple explicit namespaces
./scripts/cnv-win-bsod-audit.sh --namespace prod --namespace staging --strict
```

### Stop-Code Filtering (Targeted Investigation)

```bash
# Only gates relevant to MEMORY_MANAGEMENT (0x1A) and PFN_LIST_CORRUPT (0x4E)
./scripts/cnv-win-bsod-audit.sh --stop-code 0x1A,0x4E <namespace>
```

### JSON Output

```bash
# Single JSON document
./scripts/cnv-win-bsod-audit.sh --json <namespace> | jq '.vms[].findings[]'

# NDJSON streaming (one finding per line, filterable)
./scripts/cnv-win-bsod-audit.sh -A --json=ndjson | jq 'select(.stop_code=="0x4E")'
```

### Label Selector

```bash
./scripts/cnv-win-bsod-audit.sh --selector app=migration-wave-1 <namespace>
```

### MTV Plan Gate

```bash
./scripts/cnv-mtv-plan-gate.sh <plan-namespace> <plan-name>
```

### Fleet Readiness Report

```bash
./scripts/cnv-mtv-fleet-readiness.sh <plan-namespace> [--csv combined.csv]
```

### Guest Collection via QGA

```bash
./scripts/cnv-qga-fleet-collect.sh --namespace <ns> --vm <vm> --stage --output ./bsod-qga-collect

# Opt-in MEMORY.DMP / Minidump collection (default off):
./scripts/cnv-qga-fleet-collect.sh --namespace <ns> --all-windows --include-sensitive-data
```

### Guest Collection + Remediation

```bash
# Inside Windows VM (as Administrator):
.\collect-windows-guest-info.ps1 -Remediate

# Fleet remediation via QGA (double opt-in):
./scripts/cnv-qga-fleet-collect.sh --namespace <ns> --all-windows \
  --remediate --confirm-remediate

# Or export a reviewable artifact instead of mutating the guest (Issue J --
# no --confirm-remediate needed, since nothing is modified):
./scripts/cnv-qga-fleet-collect.sh --namespace <ns> --all-windows \
  --remediate --export both
```

See the Guest-side collector section in
[`docs/admin-runbook.md`](../docs/admin-runbook.md) for `-Remediate -Export`
coverage (`.reg` / Ansible playbook).

### Regenerate Artifacts After Dashboard Changes

```bash
./scripts/generate-dashboard-artifacts.sh
```

### Regenerate ACM Policy After Alert Changes

```bash
python3 scripts/ci/validate-acm-policy.py --update
```

## Output Conventions

- Per-check status: `[FAIL]`, `[WARN]`, or `[ OK ]`
- ANSI colors: red = FAIL, amber = WARN, green = OK
- Exit code 0 = no hard failures; exit code 1 = at least one FAIL
- Gate scripts use `set -uo pipefail` but **not** `-e` (individual gates can fail without aborting)

## Related

- [`docs/admin-runbook.md`](../docs/admin-runbook.md) -- install, 21-gate table, known limitations, guest collector
- [`shared/virtio-win-thresholds.json`](../shared/virtio-win-thresholds.json) -- single source of truth for driver version thresholds
