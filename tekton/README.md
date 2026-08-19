# Tekton / Pipeline-as-Code Gate Integration

Run the BSOD risk gate as part of an automated migration pipeline using
Tekton Tasks or MTV PreHook Jobs.

## Prerequisites

1. OpenShift cluster with Tekton Pipelines installed (OpenShift Pipelines Operator)
2. `oc` CLI access to apply manifests
3. Gate container image built and pushed (see `Dockerfile.gate` in project root)

## Quick Start

```bash
# 1. Apply RBAC
oc apply -f tekton/rbac.yaml

# 2. Apply Tekton Task
oc apply -f tekton/bsod-gate-task.yaml

# 3. Run a TaskRun against an MTV Plan
cat <<EOF | oc create -f -
apiVersion: tekton.dev/v1
kind: TaskRun
metadata:
  generateName: bsod-gate-
  namespace: openshift-cnv
spec:
  taskRef:
    name: bsod-audit-gate
  params:
    - name: plan-name
      value: "my-migration-plan"
    - name: plan-namespace
      value: "openshift-mtv"
  serviceAccountName: bsod-gate-sa
EOF
```

## Components

| File | Description |
|------|-------------|
| `rbac.yaml` | ServiceAccount, ClusterRole, and ClusterRoleBinding |
| `bsod-gate-task.yaml` | Tekton Task (v1 API) with Results |
| `bsod-gate-pipeline.yaml` | Example Pipeline with `when` guard |
| `bsod-gate-prehook-job.yaml` | Kubernetes Job for MTV PreHook integration |

## RBAC

The `bsod-audit-gate` ClusterRole grants read-only access to all resources
queried by the gate scripts:

- `virtualmachines`, `virtualmachineinstances`, `kubevirts` (kubevirt.io)
- `nodes` (core)
- `hyperconvergeds` (hco.kubevirt.io)
- `templates` (template.openshift.io)
- `virtualmachineclusterinstancetypes`, `virtualmachineclusterpreferences` (instancetype.kubevirt.io)
- `plans` (forklift.konveyor.io)
- `clusterversions` (config.openshift.io)

All verbs are `get` and `list` only. No write operations.

## Tekton Task Results

The `bsod-audit-gate` Task exposes these Results for downstream pipeline logic:

| Result | Type | Description |
|--------|------|-------------|
| `verdict` | string | `PASS`, `WARN`, or `FAIL` |
| `fail-count` | string | Number of VMs with FAIL status |
| `warn-count` | string | Number of VMs with WARN status |
| `report-json` | string | Full JSON report from plan gate |

## Pipeline Integration

Use the `when` clause on subsequent tasks to block migration on FAIL:

```yaml
tasks:
  - name: bsod-gate
    taskRef:
      name: bsod-audit-gate
    params:
      - name: plan-name
        value: "$(params.plan-name)"
  - name: start-migration
    runAfter: [bsod-gate]
    when:
      - input: "$(tasks.bsod-gate.results.verdict)"
        operator: in
        values: ["PASS"]
    taskRef:
      name: your-migration-task
```

## MTV PreHook Integration

For Forklift/MTV Plans that use hook-based pre-migration checks:

```yaml
apiVersion: forklift.konveyor.io/v1beta1
kind: Plan
metadata:
  name: my-plan
spec:
  vms:
    - name: win-vm-1
      hooks:
        - hook:
            spec:
              preHook:
                apiVersion: batch/v1
                kind: Job
                metadata:
                  name: bsod-gate-prehook
                  namespace: openshift-cnv
```

Apply `tekton/bsod-gate-prehook-job.yaml` as a template; MTV will inject
VM-specific annotations that the Job script reads via downward API.

## Expected Runtime

- ~5-15 seconds per VM (dominated by `oc get` API calls)
- A 50-VM plan completes in ~5-10 minutes
- Task timeout is set to 30 minutes as safety margin

## Troubleshooting

- **RBAC errors:** Verify the ServiceAccount binding: `oc auth can-i get virtualmachines --as=system:serviceaccount:openshift-cnv:bsod-gate-sa`
- **Image pull errors:** Ensure the gate image is accessible from the cluster
- **Timeout:** Increase the step `timeout` in the Task if your plan has many VMs
- **Empty JSON output:** Check that `jq` is available in the image (it should be)
