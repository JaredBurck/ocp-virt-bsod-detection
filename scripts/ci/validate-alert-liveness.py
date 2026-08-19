#!/usr/bin/env python3
"""Fail CI if an alert's ability to FIRE ON A REAL CLUSTER is undeclared.

Peer-review finding F-02 (v0.25.0). `BSODRisk_HostCPUContention` divides CFS
throttle counters by CFS period counters across `virt-launcher-*` pods. Both
counters are populated by cAdvisor only when the cgroup carries a CPU bandwidth
quota -- i.e. only when a CPU *limit* is set. KubeVirt sets CPU *requests* on
virt-launcher by default and sets limits only under `dedicatedCpuPlacement` or
an explicit `resources.limits.cpu`. On a default cluster both sums are 0, the
expression evaluates 0/0 -> NaN, `NaN > 0.25` is false, and the alert is
silent at 100% node contention. Proven with promtool: flat-zero input series
produce no alert.

WHY THE EXISTING TEST SUITE CANNOT CATCH THIS. Every one of the 21 alerts
already has a promtool test asserting it fires. Those tests are correct and
worth keeping -- they prove the *expression arithmetic*. But the test author
supplies the input series, so a test can only ever prove "given these samples,
the alert fires". It cannot prove those samples occur on a real cluster.
`BSODRisk_HostCPUContention`'s firing test feeds non-zero CFS counters, an
input a default cluster never produces. The test passes; the alert is inert.

This is the THIRD instance of the class. `BSODRisk_GuestCrash` (its metric was
never released in any shipping HCO/CNV build) and `check_virtio_gpu_dump_
capability` (its API field does not exist) are both documented in CLAUDE.md as
"cannot fire on any currently shipping release". Both were found by hand, on a
live cluster, long after shipping.

WHAT THIS GUARD DOES. Whether a series exists on a real cluster is not
derivable from the repo -- it is domain knowledge. So this does not try to
compute it. It requires it to be WRITTEN DOWN, per alert, and reviewed:
`shared/alert-liveness.json` declares, for every alert, the base metrics it
depends on and the cluster precondition those metrics need. An alert whose
precondition is anything other than a stock cluster must say so explicitly.

That converts an unknowable into an enumerated list. Same doctrine as
`shared/audit-consumers.json`, which exists for exactly this reason: "A flag
default cannot prevent that; an enumeration can." Adding an alert fails CI
until its liveness is declared, which forces "can this actually fire?" to be
answered on the way in rather than discovered on a customer's cluster.

The declaration is cross-checked against the alert's real `expr` (resolved
through recording rules), so an expression that grows a new metric dependency
fails until the declaration is updated -- the declaration cannot silently rot.

Usage:
    python3 scripts/ci/validate-alert-liveness.py
Exit: 0 clean, 1 violation.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
ALERT_FILES = (
    REPO_ROOT / "alerts" / "bsod-risk-prometheusrules.yaml",
    REPO_ROOT / "alerts" / "bsod-risk-guest-alerts.yaml",
)
RECORDING_FILE = REPO_ROOT / "alerts" / "bsod-risk-recording-rules.yaml"
REGISTRY_FILE = REPO_ROOT / "shared" / "alert-liveness.json"

# Every value `status` may take, with the operational meaning that makes the
# distinction actionable. The point of the vocabulary is that "fires on a stock
# cluster" and "needs something the customer may not have" are DIFFERENT
# claims, and an alert must pick one deliberately.
VALID_STATUS = {
    "default-cluster":
        "Every base metric is present on a stock OCP + CNV cluster with the "
        "default monitoring stack. The alert can fire with no operator action.",
    "requires-optional-component":
        "Needs a component this framework ships but does not install by "
        "default (windows_exporter, the textfile collector, the fleet "
        "exporter). Documented as opt-in; silent until deployed.",
    "requires-nondefault-config":
        "Needs a cluster/VM configuration that is NOT the KubeVirt default "
        "(e.g. CPU limits set on virt-launcher). Silent on a default cluster "
        "even when the underlying risk is present -- this is the F-02 class.",
    "known-inert":
        "Cannot fire on any currently shipping release. Ships as a "
        "forward-looking placeholder only. Must never be presented to an "
        "operator as working detection.",
}

# Statuses that oblige the entry to carry a non-empty `precondition` naming
# exactly what is missing. "default-cluster" needs no such prose.
STATUS_REQUIRING_PRECONDITION = {
    "requires-optional-component",
    "requires-nondefault-config",
    "known-inert",
}

# PromQL keywords, aggregation operators and built-in functions -- tokens that
# look like identifiers but are never metric names.
_PROMQL_RESERVED = {
    "sum", "min", "max", "avg", "group", "stddev", "stdvar", "count",
    "count_values", "bottomk", "topk", "quantile",
    "by", "without", "on", "ignoring", "group_left", "group_right",
    "and", "or", "unless", "bool", "offset", "start", "end", "atan2",
    "abs", "absent", "absent_over_time", "ceil", "changes", "clamp",
    "clamp_max", "clamp_min", "day_of_month", "day_of_week", "day_of_year",
    "days_in_month", "delta", "deriv", "exp", "floor", "histogram_quantile",
    "holt_winters", "hour", "idelta", "increase", "irate", "label_join",
    "label_replace", "ln", "log2", "log10", "minute", "month", "predict_linear",
    "rate", "resets", "round", "scalar", "sgn", "sort", "sort_desc", "sqrt",
    "time", "timestamp", "vector", "year",
    "avg_over_time", "min_over_time", "max_over_time", "sum_over_time",
    "count_over_time", "quantile_over_time", "stddev_over_time",
    "stdvar_over_time", "last_over_time", "present_over_time", "mad_over_time",
}

_IDENT_RE = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")
_DURATION_RE = re.compile(r"\b\d+(?:\.\d+)?(?:ms|s|m|h|d|w|y)\b")


def _strip_non_metric_context(expr: str) -> str:
    """Remove every part of a PromQL expression that cannot hold a metric name.

    Label selectors (`{...}`), grouping clauses (`by (...)`, `on (...)`, ...),
    range/subquery brackets (`[5m]`, `[1h:5m]`) and quoted string arguments all
    contain identifiers that are LABEL names, not metric names. Counting
    `vm_name` or `label_cpu_vendor_node_kubevirt_io_amd` as a required series
    would make the declaration meaningless, so they are removed first.

    String literals matter specifically because of `label_replace()`, whose
    2nd-5th arguments are quoted label names -- BSODRisk_GuestUnexpectedRestart
    calls `label_replace(..., "name", "$1", "vm_name", "(.*)")` and would
    otherwise declare `name` and `vm_name` as required metrics.
    """
    expr = re.sub(r'"[^"]*"', " ", expr)        # string args (label_replace)
    expr = re.sub(r"'[^']*'", " ", expr)
    # Grouping clauses next -- their parenthesised label lists would otherwise
    # survive into the token stream.
    expr = re.sub(
        r"\b(?:by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)",
        " ", expr)
    expr = re.sub(r"\{[^}]*\}", " ", expr)      # label selectors
    expr = re.sub(r"\[[^\]]*\]", " ", expr)     # ranges and subqueries
    expr = _DURATION_RE.sub(" ", expr)
    return expr


def extract_metrics(expr: str, recording_rules: dict[str, str],
                    _depth: int = 0) -> set[str]:
    """Base metric names an expression depends on, resolved through recordings.

    A recording rule reference is replaced by the metrics ITS expression uses,
    so an alert built on `bsod:vmi_disk_latency:avg_1h` declares the KubeVirt
    counters underneath it. That is the level at which "does this exist on a
    real cluster?" is actually answerable -- the recording rule is only as
    live as its own inputs.
    """
    found: set[str] = set()
    for token in _IDENT_RE.findall(_strip_non_metric_context(expr)):
        if token in _PROMQL_RESERVED:
            continue
        if token in recording_rules:
            if _depth < 5:
                found |= extract_metrics(
                    recording_rules[token], recording_rules, _depth + 1)
            continue
        found.add(token)
    return found


def load_recording_rules() -> dict[str, str]:
    doc = yaml.safe_load(RECORDING_FILE.read_text())
    return {
        r["record"]: r["expr"]
        for g in doc["spec"]["groups"] for r in g["rules"] if "record" in r
    }


def load_alerts() -> dict[str, str]:
    """alert name -> expr, across every shipped alert CR."""
    alerts: dict[str, str] = {}
    for path in ALERT_FILES:
        doc = yaml.safe_load(path.read_text())
        for group in doc["spec"]["groups"]:
            for rule in group["rules"]:
                if "alert" in rule:
                    alerts[rule["alert"]] = rule["expr"]
    return alerts


def main() -> int:
    errors: list[str] = []

    if not REGISTRY_FILE.exists():
        print(f"FAIL: missing {REGISTRY_FILE.relative_to(REPO_ROOT)}")
        return 1

    try:
        registry = json.loads(REGISTRY_FILE.read_text())
    except ValueError as exc:
        print(f"FAIL: {REGISTRY_FILE.relative_to(REPO_ROOT)} is not valid "
              f"JSON ({exc})")
        return 1

    declared = registry.get("alerts", {})
    alerts = load_alerts()
    recording_rules = load_recording_rules()

    # 1. Every shipped alert must be declared, and nothing may be declared
    #    that is no longer shipped (a stale entry is a claim about an alert
    #    that no longer exists, which is worse than no claim).
    for name in sorted(set(alerts) - set(declared)):
        errors.append(
            f"{name}: shipped in an alert CR but absent from "
            f"{REGISTRY_FILE.name}. Declare its base metrics and the cluster "
            f"precondition they need -- i.e. answer 'can this actually fire "
            f"on a customer cluster?' before it ships, not after.")
    for name in sorted(set(declared) - set(alerts)):
        errors.append(
            f"{name}: declared in {REGISTRY_FILE.name} but no longer defined "
            f"in any alert CR -- remove the stale entry.")

    # 2. Each declaration must be internally well-formed.
    for name in sorted(set(declared) & set(alerts)):
        entry = declared[name]
        status = entry.get("status")
        if status not in VALID_STATUS:
            errors.append(
                f"{name}: status {status!r} is not one of "
                f"{sorted(VALID_STATUS)}")
            continue
        if status in STATUS_REQUIRING_PRECONDITION \
                and not str(entry.get("precondition", "")).strip():
            errors.append(
                f"{name}: status {status!r} requires a non-empty "
                f"'precondition' naming exactly what must be true for this "
                f"alert to fire. An alert that cannot fire on a stock cluster "
                f"must say so in words an operator can act on.")

        # 3. The declaration must match the expression it describes. This is
        #    what stops the registry rotting: change the expr, and the
        #    declared dependency set no longer matches.
        actual = extract_metrics(alerts[name], recording_rules)
        stated = set(entry.get("required_series", []))
        missing = actual - stated
        extra = stated - actual
        if missing:
            errors.append(
                f"{name}: expression depends on {sorted(missing)} but "
                f"'required_series' does not list them. Add them and "
                f"re-confirm the status still holds -- a new dependency can "
                f"change whether the alert fires on a default cluster.")
        if extra:
            errors.append(
                f"{name}: 'required_series' lists {sorted(extra)} which the "
                f"expression no longer uses -- remove them.")

    if errors:
        print("FAIL: alert-liveness declarations are incomplete or stale:")
        for e in errors:
            print(f"  {e}")
        return 1

    by_status: dict[str, list[str]] = {}
    for name, entry in declared.items():
        by_status.setdefault(entry["status"], []).append(name)

    print(f"OK: all {len(alerts)} alert(s) declare their firing preconditions "
          f"and match their expressions")
    for status in sorted(by_status):
        names = sorted(by_status[status])
        print(f"  {status:28s} {len(names):>2}  {', '.join(names)}")
    caveated = sum(len(v) for k, v in by_status.items() if k != "default-cluster")
    if caveated:
        print(f"\n  NOTE: {caveated} alert(s) cannot fire on a stock cluster "
              f"without the stated precondition. That is declared, not "
              f"accidental -- see {REGISTRY_FILE.name} for each rationale.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
