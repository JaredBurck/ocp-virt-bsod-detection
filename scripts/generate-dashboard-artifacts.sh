#!/usr/bin/env bash
# Generate dashboard deployment artifacts from the canonical source JSON.
#
# Source of truth: dashboards/bsod-risk-overview.json
# Outputs:
#   1. dashboards/bsod-risk-dashboard-configmap.yaml  (direct oc apply to OCP console)
#   2. dashboards/bsod-risk-grafanadashboard-cr.yaml  (Grafana Operator CR)
#   3. Updates acm/bsod-risk-policy.yaml dashboard section (ACM enforcement)
#
# Also regenerates the fleet (multi-cluster) dashboard artifacts from
# dashboards/bsod-risk-fleet-overview.json (N10):
#   4. dashboards/bsod-risk-fleet-dashboard-configmap.yaml (MCO Grafana, byte-identical embed)
#   5. dashboards/bsod-risk-fleet-console-configmap.yaml (OCP console -- see NOTE below)
#
# NOTE on the fleet console ConfigMap: unlike every other artifact here, it is
# NOT a byte-identical embed of its source JSON. It deliberately converts three
# table panels (ids 9, 12, 13) to stat/bargauge for OCP console compatibility,
# so it cannot be regenerated as a straight copy. Instead, this script syncs
# only the panels whose `type` already matches between source and the console
# embed (which is every panel except the three intentional conversions) --
# this is exactly the class of drift that caused N10 (the storage-latency
# panel, id 15, has identical type/structure in both and silently drifted out
# of sync because nothing kept it in sync).
#
# Usage:
#   ./scripts/generate-dashboard-artifacts.sh
#
# Run this after editing dashboards/bsod-risk-overview.json or
# dashboards/bsod-risk-fleet-overview.json to keep all deployment mechanisms
# in sync.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DASHBOARD_JSON="$REPO_ROOT/dashboards/bsod-risk-overview.json"
OCP_CONFIGMAP="$REPO_ROOT/dashboards/bsod-risk-dashboard-configmap.yaml"
GRAFANA_CR="$REPO_ROOT/dashboards/bsod-risk-grafanadashboard-cr.yaml"
ACM_POLICY="$REPO_ROOT/acm/bsod-risk-policy.yaml"
FLEET_DASHBOARD_JSON="$REPO_ROOT/dashboards/bsod-risk-fleet-overview.json"
FLEET_MCO_CONFIGMAP="$REPO_ROOT/dashboards/bsod-risk-fleet-dashboard-configmap.yaml"
FLEET_CONSOLE_CONFIGMAP="$REPO_ROOT/dashboards/bsod-risk-fleet-console-configmap.yaml"

if [[ ! -f "$DASHBOARD_JSON" ]]; then
    echo "ERROR: $DASHBOARD_JSON not found" >&2
    exit 1
fi

if ! python3 -c "import json; json.load(open('$DASHBOARD_JSON'))" 2>/dev/null; then
    echo "ERROR: $DASHBOARD_JSON is not valid JSON" >&2
    exit 1
fi

echo "Source: $DASHBOARD_JSON ($(wc -c < "$DASHBOARD_JSON") bytes)"

python3 - "$DASHBOARD_JSON" "$OCP_CONFIGMAP" "$GRAFANA_CR" "$ACM_POLICY" <<'PYEOF'
import sys, json, yaml, re

src, ocp_dst, grafana_dst, acm_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

with open(src) as f:
    dashboard_json = f.read().rstrip("\n")

# Validate
json.loads(dashboard_json)

# --- Artifact 1: OCP Console ConfigMap ---
cm = {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {
        "name": "bsod-risk-grafana-dashboard",
        "namespace": "openshift-config-managed",
        "labels": {
            "console.openshift.io/dashboard": "true",
            "console.openshift.io/odc-dashboard": "true",
        },
    },
    "data": {"bsod-risk-overview.json": dashboard_json},
}

with open(ocp_dst, "w") as f:
    yaml.dump(cm, f, default_flow_style=False, allow_unicode=True, width=10000)
print(f"  Generated: {ocp_dst}")

# --- Artifact 2: GrafanaDashboard CR ---
cr = {
    "apiVersion": "grafana.integreatly.org/v1beta1",
    "kind": "GrafanaDashboard",
    "metadata": {
        "name": "bsod-risk-overview",
        "namespace": "grafana",
        "labels": {"app": "bsod-detection"},
    },
    "spec": {
        "instanceSelector": {"matchLabels": {"dashboards": "bsod-grafana"}},
        "json": dashboard_json,
    },
}

with open(grafana_dst, "w") as f:
    yaml.dump(cr, f, default_flow_style=False, allow_unicode=True, width=10000)
print(f"  Generated: {grafana_dst}")

# --- Artifact 3: ACM Policy dashboard section ---
with open(acm_path) as f:
    policy = f.read()

# Indent JSON for YAML block scalar (20 spaces = inside objectDefinition.data.key)
INDENT = "                    "  # 20 spaces
indented_json = "\n".join(INDENT + line for line in dashboard_json.splitlines())

new_section = """\
    - objectDefinition:
        apiVersion: policy.open-cluster-management.io/v1
        kind: ConfigurationPolicy
        metadata:
          name: bsod-risk-grafana-dashboard
          annotations:
            policy.open-cluster-management.io/hub-templates: "raw"
            policy.open-cluster-management.io/disable-templates: "true"
        spec:
          remediationAction: inform
          severity: low
          namespaceSelector:
            include:
              - openshift-cnv
          object-templates:
            - complianceType: musthave
              objectDefinition:
                apiVersion: v1
                kind: ConfigMap
                metadata:
                  name: bsod-risk-grafana-dashboard
                  namespace: openshift-cnv
                  labels:
                    grafana-dashboard: "true"
                    app.kubernetes.io/component: bsod-detection
                data:
                  bsod-risk-overview.json: |
""" + indented_json + "\n"

# Replace old dashboard section. Locate boundaries via the CP's `name:`
# field plus the stable "    - objectDefinition:\n" top-level list marker,
# rather than a literal regex over the CP's full internal content or a
# leading comment. Both of those are fragile: a comment-only marker can be
# silently dropped by validate-acm-policy.py's ruamel round-trip (this is
# exactly what happened here and let this section drift out of sync with the
# canonical JSON without any error being surfaced), and a content regex
# breaks whenever unrelated metadata (e.g. the hub-template annotations
# block) is added to the ConfigurationPolicy.
#
# IMPORTANT: do NOT prepend a leading comment line to new_section itself
# (e.g. a "generated by this script" note immediately above the
# "- objectDefinition:" marker). ruamel's round-trip loader in
# validate-acm-policy.py doesn't attach such a comment to this (the
# dashboard) list item -- it attaches it as a trailing comment on the
# *previous* policy-template's deeply-nested last scalar (e.g. the
# recording-rules PrometheusRule's last `expr:` block), which then makes
# that unrelated, otherwise-untouched section spuriously fail
# validate_groups()'s structural comparison against its own canonical
# source file. Keep any documentation about this generated block in this
# shell script's own comments (as here) instead.
OD_MARKER = "    - objectDefinition:\n"
NAME_MARKER = "          name: bsod-risk-grafana-dashboard\n"

try:
    name_idx = policy.index(NAME_MARKER)
except ValueError:
    print("  ERROR: Could not find ConfigurationPolicy 'bsod-risk-grafana-dashboard' in ACM policy", file=sys.stderr)
    sys.exit(1)

start_idx = policy.rfind(OD_MARKER, 0, name_idx)
if start_idx == -1:
    print("  ERROR: Could not find enclosing objectDefinition for dashboard CP", file=sys.stderr)
    sys.exit(1)

next_od_idx = policy.find(OD_MARKER, start_idx + len(OD_MARKER))
if next_od_idx == -1:
    print("  ERROR: Could not find end boundary (next objectDefinition) for dashboard section", file=sys.stderr)
    sys.exit(1)

policy_new = policy[:start_idx] + new_section + policy[next_od_idx:]

with open(acm_path, "w") as f:
    f.write(policy_new)
print(f"  Updated:   {acm_path}")
PYEOF

echo ""
echo "Done. Single-cluster artifacts are now in sync with $DASHBOARD_JSON"

# --- Fleet (multi-cluster) dashboard artifacts (N10) ---

if [[ ! -f "$FLEET_DASHBOARD_JSON" ]]; then
    echo "ERROR: $FLEET_DASHBOARD_JSON not found" >&2
    exit 1
fi

if ! python3 -c "import json; json.load(open('$FLEET_DASHBOARD_JSON'))" 2>/dev/null; then
    echo "ERROR: $FLEET_DASHBOARD_JSON is not valid JSON" >&2
    exit 1
fi

echo ""
echo "Source: $FLEET_DASHBOARD_JSON ($(wc -c < "$FLEET_DASHBOARD_JSON") bytes)"

python3 - "$FLEET_DASHBOARD_JSON" "$FLEET_MCO_CONFIGMAP" "$FLEET_CONSOLE_CONFIGMAP" <<'PYEOF'
import sys, json, yaml

src, mco_dst, console_dst = sys.argv[1], sys.argv[2], sys.argv[3]

with open(src) as f:
    dashboard_json = f.read().rstrip("\n")

json.loads(dashboard_json)  # validate

# --- Artifact 1: MCO Grafana ConfigMap (byte-identical embed, proven pattern) ---
with open(mco_dst) as f:
    mco_cm = yaml.safe_load(f)
mco_cm["data"]["bsod-risk-fleet-overview.json"] = dashboard_json
with open(mco_dst, "w") as f:
    yaml.dump(mco_cm, f, default_flow_style=False, allow_unicode=True, width=10000)
print(f"  Generated: {mco_dst}")

# --- Artifact 2: OCP Console ConfigMap (NOT byte-identical -- see script
# header NOTE). Sync only panels whose `type` already matches source; skip
# (and warn about) panels intentionally converted to a different type for
# console compatibility. ---
with open(console_dst) as f:
    console_cm = yaml.safe_load(f)
console_json = console_cm["data"]["bsod-risk-fleet-overview.json"]
console_doc = json.loads(console_json)
source_doc = json.loads(dashboard_json)

source_panels_by_id = {p["id"]: p for p in source_doc.get("panels", [])}
converted, synced = [], []
for i, panel in enumerate(console_doc.get("panels", [])):
    pid = panel.get("id")
    src_panel = source_panels_by_id.get(pid)
    if src_panel is None:
        continue
    if src_panel.get("type") != panel.get("type"):
        converted.append((pid, panel.get("type"), src_panel.get("type")))
        continue
    if src_panel != panel:
        console_doc["panels"][i] = src_panel
        synced.append(pid)

console_cm["data"]["bsod-risk-fleet-overview.json"] = json.dumps(console_doc)
with open(console_dst, "w") as f:
    yaml.dump(console_cm, f, default_flow_style=False, allow_unicode=True, width=10000)
print(f"  Generated: {console_dst}")
if synced:
    print(f"    Synced panel(s) from source (type matched, content drifted): {synced}")
if converted:
    print(f"    Skipped intentionally-converted panel(s) (console uses a different type "
          f"than source by design): {[(pid, f'{c}->{s}') for pid, c, s in converted]}")
PYEOF

echo ""
echo "Done. All artifacts (single-cluster + fleet) are now in sync with their source JSON."
echo ""
echo "Deploy options:"
echo "  Grafana Operator: oc apply -f dashboards/bsod-risk-grafanadashboard-cr.yaml"
echo "  OCP Console:      oc apply -f dashboards/bsod-risk-dashboard-configmap.yaml"
echo "  ACM (hub):        oc apply -f acm/bsod-risk-policy.yaml"
echo "  Fleet (MCO Grafana): oc apply -f dashboards/bsod-risk-fleet-dashboard-configmap.yaml"
echo "  Fleet (OCP Console): oc apply -f dashboards/bsod-risk-fleet-console-configmap.yaml"
