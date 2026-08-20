#!/usr/bin/env python3
"""Validate that all generated dashboard embeds match the canonical JSON.

Checks:
  1. dashboards/bsod-risk-dashboard-configmap.yaml (OCP console ConfigMap)
  2. dashboards/bsod-risk-grafanadashboard-cr.yaml (Grafana Operator CR)
  3. acm/bsod-risk-policy.yaml's embedded ConfigurationPolicy dashboard ConfigMap
  4. dashboards/bsod-risk-fleet-dashboard-configmap.yaml (MCO Grafana, fleet dashboard)
  5. dashboards/bsod-risk-fleet-console-configmap.yaml (OCP console, fleet dashboard --
     checked panel-by-panel since it deliberately converts three table panels to
     stat/bargauge; see scripts/generate-dashboard-artifacts.sh's NOTE)

Exits non-zero on any mismatch. This closes a gap where CI validated the
PrometheusRule objects embedded in the ACM policy (validate-acm-policy.py)
but never checked the dashboard ConfigMap embed, allowing it to drift from
the canonical JSON silently (see docs/info/peer-reviews/v0.7.0). N10 extended
this to the fleet dashboard after its storage-latency panel drifted out of
sync with its own source JSON (seconds treated as milliseconds) with nothing
catching it.

Usage:
    python3 scripts/ci/validate-dashboard-configmap.py
"""
import json
import re
import sys
import yaml


RECORDING_RULES_PATH = "alerts/bsod-risk-recording-rules.yaml"
STANDALONE_PATH = "dashboards/bsod-risk-overview.json"
CONFIGMAP_PATH = "dashboards/bsod-risk-dashboard-configmap.yaml"
GRAFANA_CR_PATH = "dashboards/bsod-risk-grafanadashboard-cr.yaml"
ACM_POLICY_PATH = "acm/bsod-risk-policy.yaml"
FLEET_STANDALONE_PATH = "dashboards/bsod-risk-fleet-overview.json"
FLEET_MCO_CONFIGMAP_PATH = "dashboards/bsod-risk-fleet-dashboard-configmap.yaml"
FLEET_CONSOLE_CONFIGMAP_PATH = "dashboards/bsod-risk-fleet-console-configmap.yaml"
FLEET_MCO_KEY = "bsod-risk-fleet-overview.json"


def _load_standalone():
    with open(STANDALONE_PATH) as f:
        return json.load(f)


def _canon(obj):
    return json.dumps(obj, sort_keys=True)


def check_configmap(standalone_canonical: str) -> int:
    with open(CONFIGMAP_PATH) as f:
        cm = yaml.safe_load(f)

    cm_json_str = cm.get("data", {}).get("bsod-risk-overview.json", "")
    if not cm_json_str:
        print(f"FAIL: no 'bsod-risk-overview.json' key in {CONFIGMAP_PATH} data")
        return 1

    try:
        embedded = json.loads(cm_json_str)
    except json.JSONDecodeError as exc:
        print(f"FAIL: invalid JSON in {CONFIGMAP_PATH}: {exc}")
        return 1

    if _canon(embedded) != standalone_canonical:
        print(f"FAIL: {STANDALONE_PATH} and {CONFIGMAP_PATH} dashboard JSON differ")
        print("Regenerate with: ./scripts/generate-dashboard-artifacts.sh")
        return 1

    print(f"OK: {CONFIGMAP_PATH} matches {STANDALONE_PATH}")
    return 0


def check_grafana_cr(standalone_canonical: str) -> int:
    with open(GRAFANA_CR_PATH) as f:
        cr = yaml.safe_load(f)

    cr_json_str = (cr.get("spec") or {}).get("json", "")
    if not cr_json_str:
        print(f"FAIL: no 'spec.json' key in {GRAFANA_CR_PATH}")
        return 1

    try:
        embedded = json.loads(cr_json_str)
    except json.JSONDecodeError as exc:
        print(f"FAIL: invalid JSON in {GRAFANA_CR_PATH}: {exc}")
        return 1

    if _canon(embedded) != standalone_canonical:
        print(f"FAIL: {STANDALONE_PATH} and {GRAFANA_CR_PATH} dashboard JSON differ")
        print("Regenerate with: ./scripts/generate-dashboard-artifacts.sh")
        return 1

    print(f"OK: {GRAFANA_CR_PATH} matches {STANDALONE_PATH}")
    return 0


def check_acm_policy(standalone_canonical: str) -> int:
    with open(ACM_POLICY_PATH) as f:
        policy = f.read()

    name_marker = "          name: bsod-risk-grafana-dashboard\n"
    od_marker = "    - objectDefinition:\n"

    name_idx = policy.find(name_marker)
    if name_idx == -1:
        print(f"FAIL: ConfigurationPolicy 'bsod-risk-grafana-dashboard' not found in {ACM_POLICY_PATH}")
        return 1

    start_idx = policy.rfind(od_marker, 0, name_idx)
    if start_idx == -1:
        print(f"FAIL: could not find enclosing objectDefinition for dashboard CP in {ACM_POLICY_PATH}")
        return 1

    next_idx = policy.find(od_marker, start_idx + len(od_marker))
    section = policy[start_idx:] if next_idx == -1 else policy[start_idx:next_idx]

    key = "bsod-risk-overview.json: |\n"
    key_idx = section.find(key)
    if key_idx == -1:
        print(f"FAIL: no 'bsod-risk-overview.json' block scalar in {ACM_POLICY_PATH} dashboard section")
        return 1

    json_lines = section[key_idx + len(key):].splitlines()
    # Block scalar is indented 20 spaces under `data: / bsod-risk-overview.json: |`
    dedented = "\n".join(
        line[20:] if len(line) >= 20 else line.strip() for line in json_lines
    )
    try:
        embedded = json.loads(dedented)
    except json.JSONDecodeError as exc:
        print(f"FAIL: invalid embedded JSON in {ACM_POLICY_PATH} dashboard section: {exc}")
        return 1

    if _canon(embedded) != standalone_canonical:
        print(f"FAIL: {ACM_POLICY_PATH} embedded dashboard JSON differs from {STANDALONE_PATH}")
        print("Regenerate with: ./scripts/generate-dashboard-artifacts.sh")
        return 1

    print(f"OK: {ACM_POLICY_PATH} embedded dashboard matches {STANDALONE_PATH}")
    return 0


# windows_exporter-sourced metrics never carry a "name"/"namespace" label --
# those come from kubevirt_vmi_info/ALERTS (native VM identity labels). VM
# identity on windows_exporter series is added by ServiceMonitor relabeling
# (windows-exporter/servicemonitor-windows-vms.yaml) as vm_name/vm_namespace.
# A table panel that queries one of these metrics but organizes/renames
# columns keyed on "name"/"namespace" will silently render blank VM/Namespace
# columns (peer-review v0.7.0 item 24: "VirtIO Driver Versions by VM" panel
# had exactly this bug against bsod_virtio_driver_version).
WINDOWS_EXPORTER_METRIC_PREFIXES = ("bsod_", "windows_")


def _panel_targets_windows_exporter_metric(panel: dict) -> bool:
    for target in panel.get("targets", []):
        expr = target.get("expr", "")
        if any(prefix in expr for prefix in WINDOWS_EXPORTER_METRIC_PREFIXES):
            return True
    return False


def check_windows_exporter_panels_use_vm_name_label(standalone: dict) -> int:
    rc = 0
    for panel in standalone.get("panels", []):
        if not _panel_targets_windows_exporter_metric(panel):
            continue
        for transform in panel.get("transformations", []):
            if transform.get("id") != "organize":
                continue
            options = transform.get("options", {})
            for field_map_name in ("indexByName", "renameByName"):
                keys = set(options.get(field_map_name, {}).keys())
                bad = keys & {"name", "namespace"}
                if bad:
                    print(
                        f"FAIL: panel '{panel.get('title', panel.get('id'))}' queries a "
                        f"windows_exporter metric but its '{field_map_name}' transform "
                        f"references {sorted(bad)} -- windows_exporter series use "
                        f"vm_name/vm_namespace (via ServiceMonitor relabeling), not "
                        f"name/namespace. Those columns will render blank."
                    )
                    rc = 1
    if rc == 0:
        print("OK: windows_exporter-sourced table panels use vm_name/vm_namespace, not name/namespace")
    return rc


# F10 (v0.17.0): structural guards independent of the byte-identical-embed
# checks above -- those catch drift *between* the standalone JSON and its
# generated embeds, but say nothing about whether the standalone JSON itself
# is internally well-formed. A panel with no query, a duplicate title (easy
# to introduce when copy-pasting a panel as a starting point), or a
# datasource uid/type that silently diverges from the rest of the dashboard
# (e.g. a hardcoded uid left over from panel-picker export instead of the
# `${datasource}` template variable every other panel uses) would pass every
# check above yet still render broken or inconsistently in Grafana/console.
#
# `row` panels are structural dividers with no query of their own -- Grafana
# never gives them a `datasource`/`targets`, so they are excluded from the
# per-target and datasource checks below, but still counted for title
# uniqueness (a row title colliding with a real panel's title is confusing
# either way).
ROW_PANEL_TYPE = "row"


def check_panel_structure(label: str, dashboard: dict) -> int:
    panels = dashboard.get("panels", [])
    rc = 0

    titles: dict[str, list] = {}
    datasources: dict[str, list] = {}
    for panel in panels:
        title = panel.get("title", "")
        ident = f"id={panel.get('id')}"
        titles.setdefault(title, []).append(ident)

        if panel.get("type") == ROW_PANEL_TYPE:
            continue

        targets = panel.get("targets") or []
        if not targets:
            print(f"FAIL: {label} panel {ident} ('{title}') has no targets[] "
                  f"-- a panel with no query renders empty in Grafana")
            rc = 1
        for target in targets:
            if not (target.get("expr") or "").strip():
                print(f"FAIL: {label} panel {ident} ('{title}') target "
                      f"refId={target.get('refId')} has an empty/missing "
                      f"'expr' -- it will render no data")
                rc = 1

        ds = panel.get("datasource")
        ds_key = json.dumps(ds, sort_keys=True) if ds is not None else "<missing>"
        datasources.setdefault(ds_key, []).append(ident)

    for title, idents in titles.items():
        if len(idents) > 1:
            print(f"FAIL: {label} has {len(idents)} panels titled '{title}' "
                  f"({', '.join(idents)}) -- panel titles must be unique "
                  f"within a dashboard")
            rc = 1

    if len(datasources) > 1:
        summary = "; ".join(f"{ds} -> {ids}" for ds, ids in datasources.items())
        print(f"FAIL: {label} panels use {len(datasources)} distinct "
              f"datasource uid/type combinations, expected exactly 1 "
              f"(all panels should share the same templated datasource): "
              f"{summary}")
        rc = 1

    if rc == 0:
        print(f"OK: {label} -- all panels have non-empty targets[].expr, "
              f"unique titles, and a single consistent datasource")
    return rc


# R-43 (v0.19.0 follow-up N-09): the fleet console ConfigMap's "Highest Risk
# VMs" panel (id 12) queried `bsod:vm_risk_factor_count:gauge` -- a recording
# rule defined `by (vm_name)` only -- with `legendFormat: "{{ name }}"`. No
# series this rule emits carries a `name` label, so every bar's legend
# rendered blank. check_fleet_console_configmap() above could not have caught
# this: panel 12 is one of the panels DELIBERATELY converted from table to
# bargauge for OCP console compatibility, so it is explicitly skipped by the
# "same type as source" byte-identical comparison. The drift was invisible to
# every existing check.
#
# This closes that gap generally, not just for panel 12: every panel target's
# `legendFormat` `{{ x }}` variables must be a subset of the labels the
# queried recording rule's OWN `by(...)` clause actually emits, cross-
# referenced directly against alerts/bsod-risk-recording-rules.yaml so the two
# artifacts cannot drift silently again.
#
# Scope: only targets whose expr references one of OUR OWN `bsod:` recording
# rules are checked. Native KubeVirt/ALERTS/kube-state-metrics queries (e.g.
# `ALERTS{alertname=~"BSODRisk_.*"}`, `kube_node_labels{...}`) are out of
# scope -- their label sets are not defined by anything in
# bsod-risk-recording-rules.yaml, so there is nothing in this repo to
# cross-reference them against.
#
# `cluster` is always allowed in addition to a rule's own by(...) labels: ACM's
# Thanos Querier/metrics-collector federation layer injects a `cluster` label
# onto every series it forwards from a managed cluster, external to and on top
# of whatever the recording rule itself groups by. The fleet dashboard's
# `{{ cluster }}` legends (e.g. "Cluster Risk Scores") are correct even though
# no recording rule's own expr groups by cluster.
FEDERATION_INJECTED_LABELS = {"cluster"}

_LEGEND_VAR_RE = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")
_BY_CLAUSE_RE = re.compile(r"\bby\s*\(([^)]*)\)")


def _load_recording_rule_labels(path: str = RECORDING_RULES_PATH) -> dict:
    """Map bsod: recording rule name -> frozenset of labels its OWN by(...)
    clause emits (empty frozenset if the rule aggregates away all labels,
    e.g. a bare sum(...)/count(...) with no by()).
    """
    with open(path) as f:
        doc = yaml.safe_load(f)

    rule_labels = {}
    for group in doc.get("spec", {}).get("groups", []):
        for rule in group.get("rules", []):
            name = rule.get("record")
            if not name:
                continue
            expr = rule.get("expr", "")
            by_matches = _BY_CLAUSE_RE.findall(expr)
            labels = set()
            for clause in by_matches:
                labels.update(label.strip() for label in clause.split(",") if label.strip())
            rule_labels[name] = frozenset(labels)
    return rule_labels


def _referenced_recording_rules(expr: str, known_rules) -> list:
    # Longest-name-first so a rule name that is a prefix of another (none
    # currently, but cheap insurance) can't shadow the more specific match.
    return [name for name in sorted(known_rules, key=len, reverse=True) if name in expr]


def check_legend_labels_match_recording_rules(label: str, dashboard: dict, rule_labels: dict) -> int:
    rc = 0
    checked = 0
    for panel in dashboard.get("panels", []):
        for target in panel.get("targets", []):
            expr = target.get("expr", "")
            referenced = _referenced_recording_rules(expr, rule_labels)
            if not referenced:
                continue  # out of scope: not one of our own bsod: recording rules

            legend = target.get("legendFormat", "")
            legend_vars = set(_LEGEND_VAR_RE.findall(legend))
            if not legend_vars:
                continue  # "__auto", a static string, or no legendFormat at all

            checked += 1
            allowed = FEDERATION_INJECTED_LABELS.copy()
            for rule_name in referenced:
                allowed |= rule_labels[rule_name]

            bad = legend_vars - allowed
            if bad:
                print(
                    f"FAIL: {label} panel '{panel.get('title', panel.get('id'))}' "
                    f"(refId={target.get('refId')}) legendFormat '{legend}' references "
                    f"{sorted(bad)}, which {' and '.join(referenced)} does not emit "
                    f"(by-clause labels: {sorted(allowed - FEDERATION_INJECTED_LABELS)}) "
                    f"-- this legend will render blank for {sorted(bad)}"
                )
                rc = 1

    if rc == 0:
        print(f"OK: {label} -- {checked} panel target(s) querying bsod: recording rules "
              f"have legendFormat labels the rule actually emits")
    return rc


def check_fleet_mco_configmap(fleet_canonical: str) -> int:
    """N10: the MCO Grafana fleet ConfigMap must be a byte-identical embed."""
    with open(FLEET_MCO_CONFIGMAP_PATH) as f:
        cm = yaml.safe_load(f)

    cm_json_str = cm.get("data", {}).get(FLEET_MCO_KEY, "")
    if not cm_json_str:
        print(f"FAIL: no '{FLEET_MCO_KEY}' key in {FLEET_MCO_CONFIGMAP_PATH} data")
        return 1

    try:
        embedded = json.loads(cm_json_str)
    except json.JSONDecodeError as exc:
        print(f"FAIL: invalid JSON in {FLEET_MCO_CONFIGMAP_PATH}: {exc}")
        return 1

    if _canon(embedded) != fleet_canonical:
        print(f"FAIL: {FLEET_STANDALONE_PATH} and {FLEET_MCO_CONFIGMAP_PATH} dashboard JSON differ")
        print("Regenerate with: ./scripts/generate-dashboard-artifacts.sh")
        return 1

    print(f"OK: {FLEET_MCO_CONFIGMAP_PATH} matches {FLEET_STANDALONE_PATH}")
    return 0


def check_fleet_console_configmap(fleet_source: dict) -> int:
    """N10: the OCP console fleet ConfigMap is NOT byte-identical to source --
    it deliberately converts 3 table panels (ids 9, 12, 13) to stat/bargauge
    for OCP console compatibility (see scripts/generate-dashboard-artifacts.sh's
    NOTE). Verify instead that every panel whose `type` already matches source
    is otherwise identical to source -- this is exactly the class of drift
    that caused N10 (a same-type panel, id 15, silently drifted).
    """
    with open(FLEET_CONSOLE_CONFIGMAP_PATH) as f:
        cm = yaml.safe_load(f)

    cm_json_str = cm.get("data", {}).get(FLEET_MCO_KEY, "")
    if not cm_json_str:
        print(f"FAIL: no '{FLEET_MCO_KEY}' key in {FLEET_CONSOLE_CONFIGMAP_PATH} data")
        return 1

    try:
        embedded = json.loads(cm_json_str)
    except json.JSONDecodeError as exc:
        print(f"FAIL: invalid JSON in {FLEET_CONSOLE_CONFIGMAP_PATH}: {exc}")
        return 1

    source_panels_by_id = {p["id"]: p for p in fleet_source.get("panels", [])}
    rc = 0
    checked = 0
    for panel in embedded.get("panels", []):
        pid = panel.get("id")
        src_panel = source_panels_by_id.get(pid)
        if src_panel is None:
            continue
        if src_panel.get("type") != panel.get("type"):
            continue  # intentional conversion (table -> stat/bargauge)
        checked += 1
        if src_panel != panel:
            print(
                f"FAIL: {FLEET_CONSOLE_CONFIGMAP_PATH} panel id={pid} "
                f"('{panel.get('title')}') has the same type as "
                f"{FLEET_STANDALONE_PATH}'s panel but differs in content -- "
                f"it should be identical since it was not intentionally converted."
            )
            rc = 1

    if rc == 0:
        print(f"OK: {FLEET_CONSOLE_CONFIGMAP_PATH}'s {checked} non-converted panel(s) "
              f"match {FLEET_STANDALONE_PATH}")
    else:
        print("Regenerate with: ./scripts/generate-dashboard-artifacts.sh")
    return rc


def main():
    standalone = _load_standalone()
    standalone_canonical = _canon(standalone)

    rc = 0
    rc |= check_configmap(standalone_canonical)
    rc |= check_grafana_cr(standalone_canonical)
    rc |= check_acm_policy(standalone_canonical)
    rc |= check_windows_exporter_panels_use_vm_name_label(standalone)
    rc |= check_panel_structure(STANDALONE_PATH, standalone)

    fleet_standalone = json.load(open(FLEET_STANDALONE_PATH))
    fleet_canonical = _canon(fleet_standalone)
    rc |= check_fleet_mco_configmap(fleet_canonical)
    rc |= check_fleet_console_configmap(fleet_standalone)
    rc |= check_panel_structure(FLEET_STANDALONE_PATH, fleet_standalone)

    # R-43: legend-vs-recording-rule-label cross-reference. Run against both
    # standalone dashboards AND the fleet console ConfigMap's embed
    # specifically -- that embed is the one artifact whose deliberately
    # converted panels (table -> stat/bargauge) are exempt from the
    # byte-identical checks above, which is exactly how N-09 hid.
    rule_labels = _load_recording_rule_labels()
    rc |= check_legend_labels_match_recording_rules(STANDALONE_PATH, standalone, rule_labels)
    rc |= check_legend_labels_match_recording_rules(FLEET_STANDALONE_PATH, fleet_standalone, rule_labels)
    with open(FLEET_CONSOLE_CONFIGMAP_PATH) as f:
        fleet_console_cm = yaml.safe_load(f)
    fleet_console_embedded = json.loads(fleet_console_cm.get("data", {}).get(FLEET_MCO_KEY, "{}"))
    rc |= check_legend_labels_match_recording_rules(
        FLEET_CONSOLE_CONFIGMAP_PATH, fleet_console_embedded, rule_labels
    )
    return rc


if __name__ == "__main__":
    sys.exit(main())
