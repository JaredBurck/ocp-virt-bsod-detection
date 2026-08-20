# dashboards — conventions

- **Dashboard VM variable has no `os` filter** — `kubevirt_vmi_info` is queried without `os` label because the KubeVirt `os` label is not reliably set across all cluster configurations
