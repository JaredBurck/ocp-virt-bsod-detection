#!/usr/bin/env python3
"""Validate (and optionally regenerate) ACM policy embedded PrometheusRule specs.

Preserves the dashboard ConfigMap section (managed by generate-dashboard-artifacts.sh).

Usage:
    python3 scripts/ci/validate-acm-policy.py
    python3 scripts/ci/validate-acm-policy.py --update
"""
from __future__ import annotations

import argparse
import copy
import sys
from pathlib import Path

from ruamel.yaml import YAML

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = REPO_ROOT / "acm" / "bsod-risk-policy.yaml"

RULE_SOURCES = {
    "bsod-risk-prometheusrule": (
        REPO_ROOT / "alerts" / "bsod-risk-prometheusrules.yaml",
        "bsod-risk-alerts",
    ),
    "bsod-risk-recording-rules": (
        REPO_ROOT / "alerts" / "bsod-risk-recording-rules.yaml",
        "bsod-risk-recording-rules",
    ),
    "bsod-risk-guest-alerts": (
        REPO_ROOT / "alerts" / "bsod-risk-guest-alerts.yaml",
        "bsod-risk-guest-alerts",
    ),
}

REQUIRED_CP_ANNOTATIONS = {
    "policy.open-cluster-management.io/hub-templates": "raw",
    "policy.open-cluster-management.io/disable-templates": "true",
}

PROMETHEUS_CP_NAMES = set(RULE_SOURCES.keys())

HEADER = (
    "# GENERATED from canonical sources -- regenerate with:\n"
    "#   python3 scripts/ci/validate-acm-policy.py --update\n"
    "# Canonical sources:\n"
    "#   alerts/bsod-risk-prometheusrules.yaml\n"
    "#   alerts/bsod-risk-recording-rules.yaml\n"
    "#   alerts/bsod-risk-guest-alerts.yaml\n"
    "#   dashboards/bsod-risk-dashboard-configmap.yaml "
    "(via generate-dashboard-artifacts.sh)\n"
)


def _yaml() -> YAML:
    y = YAML()
    y.preserve_quotes = True
    y.width = 120
    y.indent(mapping=2, sequence=4, offset=2)
    return y


def _load(path: Path):
    y = _yaml()
    with open(path) as f:
        return y.load(f)


def _strip_existing_headers(text: str) -> str:
    """Strip any leading '# GENERATED from canonical sources' comment block(s).

    ruamel's round-trip loader can re-attach a previously-written header as a
    leading comment on the document/first key, so a naive f.write(HEADER) +
    y.dump(data) on every --update run prepends a fresh header on top of the
    one already embedded in the round-tripped data -- headers accumulate
    without bound (observed: 4 stacked copies before this fix). Stripping any
    pre-existing header lines before writing the single canonical HEADER
    makes regeneration idempotent.
    """
    lines = text.splitlines(keepends=True)
    idx = 0
    while idx < len(lines) and lines[idx].startswith("#"):
        idx += 1
    return "".join(lines[idx:])


def _dump(path: Path, data) -> None:
    y = _yaml()
    from io import StringIO

    buf = StringIO()
    y.dump(data, buf)
    body = _strip_existing_headers(buf.getvalue())
    with open(path, "w") as f:
        f.write(HEADER)
        f.write(body)


def _find_configuration_policy(policy, name: str):
    for tmpl in policy.get("spec", {}).get("policy-templates", []) or []:
        obj = tmpl.get("objectDefinition", {})
        if (
            obj.get("kind") == "ConfigurationPolicy"
            and (obj.get("metadata") or {}).get("name") == name
        ):
            return obj
    return None


def _find_prometheus_rule_od(cp):
    for ot in (cp.get("spec") or {}).get("object-templates", []) or []:
        od = ot.get("objectDefinition", {})
        if od.get("kind") == "PrometheusRule":
            return od
    return None


def _groups_equal(a, b) -> bool:
    """Compare groups via round-trip dump for structural equality."""
    y = _yaml()
    from io import StringIO

    sa, sb = StringIO(), StringIO()
    y.dump(a, sa)
    y.dump(b, sb)
    return sa.getvalue() == sb.getvalue()


def validate_groups(policy, cp_name: str, canonical_path: Path) -> int:
    canonical = _load(canonical_path)
    canonical_groups = (canonical.get("spec") or {}).get("groups")
    if not canonical_groups:
        print(f"FAIL: no spec.groups in {canonical_path}")
        return 1

    cp = _find_configuration_policy(policy, cp_name)
    if cp is None:
        print(f"FAIL: ConfigurationPolicy {cp_name!r} not found in {POLICY_PATH}")
        return 1

    od = _find_prometheus_rule_od(cp)
    if od is None:
        print(f"FAIL: no PrometheusRule in ConfigurationPolicy {cp_name!r}")
        return 1

    policy_groups = (od.get("spec") or {}).get("groups")
    if policy_groups is None:
        print(f"FAIL: no spec.groups in ConfigurationPolicy {cp_name!r}")
        return 1

    if not _groups_equal(canonical_groups, policy_groups):
        print(f"FAIL: {cp_name} groups do not match {canonical_path}")
        return 1

    print(f"OK: ACM policy {cp_name} matches {canonical_path.relative_to(REPO_ROOT)}")
    return 0


def validate_annotations(policy) -> int:
    rc = 0
    for cp_name in sorted(PROMETHEUS_CP_NAMES):
        cp = _find_configuration_policy(policy, cp_name)
        if cp is None:
            print(f"FAIL: ConfigurationPolicy {cp_name!r} missing")
            rc = 1
            continue
        ann = (cp.get("metadata") or {}).get("annotations") or {}
        missing = False
        for key, expected in REQUIRED_CP_ANNOTATIONS.items():
            if ann.get(key) != expected:
                print(
                    f"FAIL: {cp_name} missing annotation {key}={expected!r} "
                    f"(have {ann.get(key)!r})"
                )
                rc = 1
                missing = True
        if not missing:
            print(f"OK: ACM policy {cp_name} has hub-template escape annotations")
    return rc


def update_policy() -> int:
    policy = _load(POLICY_PATH)

    for cp_name, (canonical_path, pr_name) in RULE_SOURCES.items():
        canonical = _load(canonical_path)
        cp = _find_configuration_policy(policy, cp_name)
        if cp is None:
            print(f"FAIL: ConfigurationPolicy {cp_name!r} not found; cannot update")
            return 1

        meta = cp.setdefault("metadata", {})
        ann = meta.setdefault("annotations", {})
        for key, val in REQUIRED_CP_ANNOTATIONS.items():
            ann[key] = val

        od = _find_prometheus_rule_od(cp)
        if od is None:
            print(f"FAIL: no PrometheusRule in {cp_name!r}")
            return 1

        # Sync PrometheusRule from canonical; keep ACM-enforced resource name
        new_od = _load(canonical_path)
        od.clear()
        for k, v in new_od.items():
            od[k] = copy.deepcopy(v)
        od["metadata"]["name"] = pr_name
        od["metadata"].setdefault("namespace", "openshift-cnv")

        print(f"Updated: {cp_name} <- {canonical_path.relative_to(REPO_ROOT)}")

    dash_cp = _find_configuration_policy(policy, "bsod-risk-grafana-dashboard")
    if dash_cp is not None:
        ann = dash_cp.setdefault("metadata", {}).setdefault("annotations", {})
        for key, val in REQUIRED_CP_ANNOTATIONS.items():
            ann[key] = val

    _dump(POLICY_PATH, policy)
    print(f"Wrote {POLICY_PATH.relative_to(REPO_ROOT)}")
    return 0


def validate_all() -> int:
    policy = _load(POLICY_PATH)
    rc = 0
    for cp_name, (canonical_path, _) in RULE_SOURCES.items():
        rc |= validate_groups(policy, cp_name, canonical_path)
    rc |= validate_annotations(policy)
    return rc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--update",
        action="store_true",
        help="Regenerate embedded PrometheusRule groups from canonical alert files",
    )
    args = parser.parse_args()

    if args.update:
        rc = update_policy()
        if rc != 0:
            return rc
        print("--- validating after update ---")
    return validate_all()


if __name__ == "__main__":
    sys.exit(main())
