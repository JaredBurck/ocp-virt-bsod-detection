#!/usr/bin/env python3
"""Fail CI if a recording rule's `by()`/`count by()` clause grows a new label.

F13 (v0.17.0 deep-dive review): `docs/info/e2e-validation-r9-r10.md` documents
a real cardinality risk for this framework's recording rules (section 5.8,
"Cardinality Check" -- < 500 series per cluster expected; a high-cardinality
label silently added to a `by()` clause is the failure mode it warns about),
but nothing in CI actually enforced it. A rule like
`bsod:vmi_disk_latency:avg_1h`'s `sum by (name, namespace, drive)` is
deliberately bounded (VM count x disk count, a few hundred series at most on
a large fleet); grouping by something unbounded instead -- `pod`, `instance`,
a raw UID, etc. -- would silently blow up Prometheus/Thanos cardinality with
no test catching it, since `promtool test rules` (alerts/tests.yaml) checks
PromQL *correctness*, not label-set cardinality risk.

This script parses every `by (...)`/`count by (...)` clause's label list out
of alerts/bsod-risk-recording-rules.yaml's `expr:` strings and fails if any
label is not in the reviewed ALLOWED_BY_LABELS allowlist below. Removing a
label, or adding one already in the allowlist, is always safe (lower or equal
cardinality) and passes silently -- only a genuinely NEW label name fails, so
a deliberate addition just needs one reviewed allowlist entry (with a comment
justifying why it's bounded) alongside the rule change, not a blanket
approval.

Usage:
    python3 scripts/ci/validate-recording-rule-cardinality.py
Exit: 0 clean, 1 violation (unreviewed label in a by()/count by() clause).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_FILE = REPO_ROOT / "alerts" / "bsod-risk-recording-rules.yaml"

# Every label name that may legitimately appear in a by()/count by() clause in
# this file, with a one-line justification for why it is cardinality-bounded.
# Add an entry here -- with a real justification, not just "needed it" -- in
# the SAME commit that adds a new label to a by() clause; that is the point
# of this guard.
ALLOWED_BY_LABELS: dict[str, str] = {
    "name": "VM name -- bounded by fleet size (the base per-VM cardinality "
            "budget every VM-scoped metric already carries)",
    "namespace": "bounded by namespace count, always <= VM count",
    "drive": "bounded by disk count per VM (typically 1-4)",
    "vm_name": "same identity as 'name' above; windows_exporter/textfile-"
               "collector-sourced metrics use this spelling instead",
    "label_cpu_feature_node_kubevirt_io_pcid": (
        "one value per WORKER NODE (not per VM) -- bounded by cluster size"
    ),
    "label_cpu_feature_node_kubevirt_io_invpcid": (
        "one value per worker node -- bounded by cluster size"
    ),
    "label_cpu_feature_node_kubevirt_io_pku": (
        "one value per worker node -- bounded by cluster size"
    ),
    "label_cpu_feature_node_kubevirt_io_erms": (
        "one value per worker node -- bounded by cluster size"
    ),
    "label_cpu_feature_node_kubevirt_io_amd_psfd": (
        "one value per worker node -- bounded by cluster size"
    ),
}

# Matches `by (a, b, c)` / `by(a,b,c)` preceded by any aggregation keyword
# (sum/count/min/max/avg/...); the aggregation keyword itself is irrelevant to
# cardinality, only the grouping labels are. `[^)]*` matches across newlines
# by default (character classes aren't newline-sensitive), so the multi-line
# `count by (\n  label1,\n  label2\n)` form is handled without re.DOTALL.
BY_CLAUSE_RE = re.compile(r"\bby\s*\(([^)]*)\)")


def extract_by_labels(expr: str) -> list[str]:
    labels: list[str] = []
    for match in BY_CLAUSE_RE.finditer(expr):
        for raw in match.group(1).split(","):
            label = raw.strip()
            if label:
                labels.append(label)
    return labels


def main() -> int:
    if not RULES_FILE.is_file():
        print(f"FAIL: {RULES_FILE} not found")
        return 1

    doc = yaml.safe_load(RULES_FILE.read_text())
    errors: list[str] = []
    checked = 0

    for group in (doc.get("spec", {}) or {}).get("groups", []) or []:
        for rule in group.get("rules", []) or []:
            record = rule.get("record")
            expr = rule.get("expr", "")
            if not record or not expr:
                continue
            for label in extract_by_labels(expr):
                checked += 1
                if label not in ALLOWED_BY_LABELS:
                    errors.append(
                        f"record '{record}' groups by unreviewed label "
                        f"'{label}' -- add it to ALLOWED_BY_LABELS in "
                        f"{Path(__file__).name} with a justification for why "
                        f"it is cardinality-bounded, or remove it if it was "
                        f"added by mistake"
                    )

    if errors:
        print("FAIL: recording-rule cardinality guard found unreviewed "
              "by()/count by() label(s):")
        for e in errors:
            print(f"  {e}")
        return 1

    print(f"OK: all {checked} by()/count by() label reference(s) across "
          f"{RULES_FILE.relative_to(REPO_ROOT)} are on the reviewed "
          f"allowlist")
    return 0


if __name__ == "__main__":
    sys.exit(main())
