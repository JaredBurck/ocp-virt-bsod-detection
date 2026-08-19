#!/usr/bin/env python3
"""Bind hardcoded thresholds in non-programmable artifacts to shared/ configs.

Some consumers cannot load JSON at runtime -- PromQL recording rules and alert
expressions in particular. Their literals are therefore duplicated from
shared/*.json, and this check fails CI if the two drift apart.

Root cause it guards (M-7): IoTimeoutValue previously existed as four
uncoordinated magic numbers -- 60/180 in the Python analyzer, 300 in the
PowerShell remediation, and 60 again in the Prometheus recording rule. Nothing
bound them, so changing guidance meant edits in three languages and it was
possible (indeed likely) for them to diverge silently.

Usage:
    python3 scripts/ci/validate-shared-thresholds.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

FAILURES: list[str] = []


def _load(name: str) -> dict:
    path = REPO_ROOT / "shared" / name
    if not path.is_file():
        FAILURES.append(f"missing shared config: shared/{name}")
        return {}
    try:
        return json.loads(path.read_text())
    except ValueError as exc:
        FAILURES.append(f"shared/{name} is not valid JSON: {exc}")
        return {}


def check_io_timeout_recording_rule() -> None:
    """bsod:vm_risk_factor_count:gauge's IoTimeoutValue literal."""
    cfg = _load("io-timeout-thresholds.json")
    if not cfg:
        return
    expected = cfg.get("risk_factor_at_or_below_seconds")
    rules = REPO_ROOT / "alerts" / "bsod-risk-recording-rules.yaml"
    text = rules.read_text()
    m = re.search(r"min by \(vm_name\) \(bsod_io_timeout_value\) <= bool (\d+)", text)
    if not m:
        FAILURES.append(
            "alerts/bsod-risk-recording-rules.yaml: could not find the "
            "bsod_io_timeout_value threshold expression -- update this checker "
            "if the rule was intentionally restructured")
        return
    actual = int(m.group(1))
    if actual != expected:
        FAILURES.append(
            f"IoTimeoutValue risk-factor threshold drift: recording rule uses "
            f"{actual}, shared/io-timeout-thresholds.json says {expected} "
            f"(risk_factor_at_or_below_seconds)")


def check_storage_latency_alerts() -> None:
    """Storage-latency literals in the alert expressions (H-5).

    PromQL cannot read JSON, so these numbers are duplicated from
    shared/storage-latency-thresholds.json. Before H-5 the alert fired at an
    hourly MEAN of 30 s/op -- unreachable before the BSOD it predicted -- while
    the framework's own analyzer flagged the same quantity at 500ms. Keeping
    the two bound prevents that gap reopening silently.
    """
    cfg = _load("storage-latency-thresholds.json")
    if not cfg:
        return
    rules = (REPO_ROOT / "alerts" / "bsod-risk-prometheusrules.yaml").read_text()
    guest = (REPO_ROOT / "alerts" / "bsod-risk-guest-alerts.yaml").read_text()

    # F-01 (v0.25.0 peer review): these patterns used to disambiguate two
    # otherwise-identical `avg_1h >= N` expressions purely by the `for:`
    # duration that followed them, and `re.search` returns the FIRST match
    # anywhere in the file. That coupled this checker to an incidental
    # property of the alerts -- adding a second alert with the same `for:`,
    # or reordering them, would have silently made one pattern match the
    # wrong alert's threshold. Rewriting the storage exprs for the write path
    # broke all four patterns at once, which is what surfaced it.
    #
    # Each threshold is now located by scanning FORWARD FROM ITS OWN
    # `- alert: <Name>` anchor to that alert's `expr:` block, so a pattern can
    # only ever match inside the alert it names.
    def _alert_expr(text: str, alert: str) -> str | None:
        """The `expr:` block belonging to `alert`, or None if not found."""
        start = text.find(f"- alert: {alert}\n")
        if start == -1:
            return None
        expr_at = text.find("expr:", start)
        if expr_at == -1:
            return None
        # The expr block ends at whichever comes first: the alert's own `for:`
        # or `labels:` sibling key, or the start of the NEXT alert. The last
        # of those matters -- an alert with neither sibling (the shape the
        # synthetic fixtures in test_validate_shared_thresholds.py use) would
        # otherwise return None and silently skip the check, turning a guard
        # into a no-op.
        ends = [text.find(f"\n{' ' * 10}{k}", expr_at)
                for k in ("for:", "labels:")]
        ends.append(text.find("- alert: ", expr_at))
        ends = [e for e in ends if e != -1]
        return text[expr_at:min(ends)] if ends else text[expr_at:]

    checks = [
        (rules, "BSODRisk_StorageLatencyElevated", r">= ([\d.]+)",
         "sustained_warn_seconds"),
        (rules, "BSODRisk_StorageLatencyHigh", r">= ([\d.]+)",
         "sustained_critical_seconds"),
        (rules, "BSODRisk_StorageLatencyBurst", r"\) >= ([\d.]+)",
         "burst_seconds"),
        (guest, "BSODRisk_GuestDiskLatencyHigh", r"\) >= ([\d.]+)",
         "sustained_critical_seconds"),
    ]
    for text, alert, pattern, key in checks:
        expected = cfg.get(key)
        block = _alert_expr(text, alert)
        m = re.search(pattern, block) if block else None
        if not m:
            FAILURES.append(
                f"{alert}: could not locate its threshold expression -- update "
                f"this checker if the alert was intentionally restructured")
            continue
        if float(m.group(1)) != float(expected):
            FAILURES.append(
                f"{alert} threshold drift: expression uses {m.group(1)}, "
                f"shared/storage-latency-thresholds.json says {expected} ({key})")

    ratio = cfg.get("trend_ratio")
    trend_block = _alert_expr(rules, "BSODRisk_StorageLatencyTrending")
    m = re.search(r"worst_24h\) > ([\d.]+)", trend_block) if trend_block else None
    if m and float(m.group(1)) != float(ratio):
        FAILURES.append(
            f"BSODRisk_StorageLatencyTrending ratio drift: expression uses "
            f"{m.group(1)}, shared config says {ratio} (trend_ratio)")


def check_host_cpu_contention_alert() -> None:
    """CPU-contention threshold literals, for BOTH signals (R-45, F-02).

    PromQL cannot read JSON, so the 0.25 in each expression is duplicated from
    shared/host-contention-thresholds.json and must be kept in sync.

    F-02 (v0.25.0 peer review) split one alert into two, because the original
    BSODRisk_HostCPUContention measured CFS throttling -- a pod exceeding its
    OWN CPU limit -- which is not node contention and cannot even be observed
    on a default KubeVirt cluster (no limits set, so no CFS quota, so the
    counters stay flat at zero and the ratio is NaN). The CFS expression was
    kept under an honest name and PSI took over the contention signal. Both
    thresholds are bound here so neither can drift, and both lookups anchor on
    their own `- alert:` name rather than on incidental expression text --
    the same lesson as check_storage_latency_alerts().
    """
    cfg = _load("host-contention-thresholds.json")
    if not cfg:
        return
    rules = (REPO_ROOT / "alerts" / "bsod-risk-prometheusrules.yaml").read_text()

    def _expr_block(alert: str) -> str | None:
        start = rules.find(f"- alert: {alert}\n")
        if start == -1:
            return None
        expr_at = rules.find("expr:", start)
        if expr_at == -1:
            return None
        ends = [rules.find(f"\n{' ' * 10}{k}", expr_at) for k in ("for:", "labels:")]
        ends.append(rules.find("- alert: ", expr_at))
        ends = [e for e in ends if e != -1]
        return rules[expr_at:min(ends)] if ends else rules[expr_at:]

    for alert, key in (
        ("BSODRisk_VirtLauncherCPUThrottled", "throttle_ratio_warn"),
        ("BSODRisk_HostCPUContention", "runqueue_wait_per_cpu_warn"),
    ):
        expected = cfg.get(key)
        if expected is None:
            FAILURES.append(
                f"shared/host-contention-thresholds.json: missing {key!r}, "
                f"which {alert} depends on")
            continue
        block = _expr_block(alert)
        if block is None:
            FAILURES.append(
                f"alerts/bsod-risk-prometheusrules.yaml: could not find "
                f"{alert}'s expression -- update this checker if the alert was "
                f"intentionally restructured or renamed")
            continue
        # Both expressions contain MORE THAN ONE `> N` comparison: the real
        # threshold, plus a `> 0` denominator/scoping guard. Taking the first
        # match reads the guard on one alert and the threshold on the other,
        # and taking the last inverts that -- there is no positional rule that
        # works for both. So collect every comparison in the block and assert
        # the configured value is among them. Drift still fails (change 1.0 to
        # 2.0 and 1.0 is no longer present), while a guard constant cannot be
        # mistaken for the threshold.
        found = [float(x) for x in re.findall(r"[><]=? *([\d.]+)", block)]
        if not found:
            FAILURES.append(
                f"{alert}: expression has no comparison threshold to bind")
            continue
        if float(expected) not in found:
            FAILURES.append(
                f"{alert} threshold drift: shared/host-contention-thresholds."
                f"json says {expected} ({key}) but the expression compares "
                f"against {sorted(set(found))}")


def check_evidence_completeness_alert() -> None:
    """Issue K: BSODRisk_FleetEvidenceIncomplete's fleet_warn_below_pct literal.

    Mirrors check_host_cpu_contention_alert()'s binding discipline: PromQL
    cannot read JSON, so the alert's literal is duplicated from
    shared/evidence-completeness-thresholds.json and must be kept in sync the
    same way. The shared config stores fleet_warn_below_pct as a 0-100
    percent (for human readability); the recording rule it binds to
    (bsod:fleet_evidence_completeness:ratio) is a 0-1 ratio (checks-weighted
    sum()/sum(), not an unweighted percent average -- see the shared JSON's
    own _units field), so the alert's literal is expected to be that same
    value divided by 100, not the bare percent.
    """
    cfg = _load("evidence-completeness-thresholds.json")
    if not cfg:
        return
    expected = cfg.get("fleet_warn_below_pct")
    rules = (REPO_ROOT / "alerts" / "bsod-risk-prometheusrules.yaml").read_text()
    m = re.search(
        r"bsod:fleet_evidence_completeness:ratio\s*<\s*([\d.]+)", rules)
    if not m:
        FAILURES.append(
            "alerts/bsod-risk-prometheusrules.yaml: could not find "
            "BSODRisk_FleetEvidenceIncomplete's threshold expression -- "
            "update this checker if the alert was intentionally restructured")
        return
    actual = float(m.group(1))
    expected_ratio = float(expected) / 100.0
    if actual != expected_ratio:
        FAILURES.append(
            f"BSODRisk_FleetEvidenceIncomplete threshold drift: expression "
            f"uses {actual}, shared/evidence-completeness-thresholds.json "
            f"says {expected} (fleet_warn_below_pct) -> expected ratio "
            f"{expected_ratio}")


def check_risk_scoring_x100_parity() -> None:
    """The bash layer reads *_x100; drift from the float form breaks parity."""
    cfg = _load("risk-scoring.json")
    if not cfg:
        return
    for key in ("severity_weights", "domain_weights",
                "confidence_multipliers", "tier_thresholds"):
        floats, ints = cfg.get(key), cfg.get(f"{key}_x100")
        if floats is None or ints is None:
            FAILURES.append(f"shared/risk-scoring.json: missing {key} or {key}_x100")
            continue
        if set(floats) != set(ints):
            FAILURES.append(
                f"shared/risk-scoring.json: {key} and {key}_x100 have different keys")
            continue
        for k, v in floats.items():
            if int(round(v * 100)) != ints[k]:
                FAILURES.append(
                    f"shared/risk-scoring.json: {key}.{k} = {v} but "
                    f"{key}_x100.{k} = {ints[k]} (expected {int(round(v * 100))})")


def check_gate_domains_complete() -> None:
    """Every bash gate must map to a weighted domain, else it mis-scores."""
    cfg = _load("risk-scoring.json")
    if not cfg:
        return
    gate_domains = cfg.get("gate_domains", {})
    weights = cfg.get("domain_weights", {})
    audit = (REPO_ROOT / "scripts" / "cnv-win-bsod-audit.sh").read_text()
    gates = {m.group(1) for m in re.finditer(r"set_gate (\d+)", audit)}
    missing = sorted(gates - set(gate_domains), key=int)
    if missing:
        FAILURES.append(
            f"shared/risk-scoring.json gate_domains is missing gate(s): "
            f"{', '.join(missing)} -- they would silently fall back to 'config'")
    unknown = {d for d in gate_domains.values() if d not in weights}
    if unknown:
        FAILURES.append(
            f"shared/risk-scoring.json gate_domains references domains with no "
            f"weight: {', '.join(sorted(unknown))}")


def check_fail_upward_defaults_match() -> None:
    """N15: an unmapped domain/confidence must fail UPWARD (highest weight),
    and both scoring layers must agree on which literal tier that is.

    scripts/lib/risk-scoring.sh and insights-rules/plugins/risk_scoring.py
    each hardcode a fallback for "domain/confidence not found in the loaded
    config" (as opposed to "config loaded fine but doesn't map this gate/
    rule_id", which is check_gate_domains_complete()'s concern above). Before
    N15 these defaulted to the *lowest*-weighted tier in one or both layers,
    silently contradicting the documented "rounds UP toward higher risk"
    fail-safe contract. This check greps both layers' source for their
    literal fallback and fails CI if either drifts from the documented
    highest-weighted tier, or if the two layers disagree with each other.
    """
    bash_path = REPO_ROOT / "scripts" / "lib" / "risk-scoring.sh"
    python_path = REPO_ROOT / "insights-rules" / "plugins" / "risk_scoring.py"
    bash_src = bash_path.read_text()
    python_src = python_path.read_text() if python_path.is_file() else ""

    # Bash: local domain="${RS_GATE_DOMAIN[$gate]:-crash}"
    m = re.search(r'RS_GATE_DOMAIN\[\$gate\]:-(\w+)', bash_src)
    if not m:
        FAILURES.append(
            f"{bash_path}: could not find RS_GATE_DOMAIN's unmapped-gate "
            f"fallback -- update this checker if rs_score_finding() was "
            f"restructured")
    else:
        bash_domain_default = m.group(1)
        if bash_domain_default != "crash":
            FAILURES.append(
                f"{bash_path}: unmapped-gate domain fallback is "
                f"{bash_domain_default!r}, expected 'crash' (the "
                f"highest-weighted domain) per the documented fail-upward "
                f"contract")

    # Python: DOMAIN_WEIGHTS.get(domain, DOMAIN_WEIGHTS.get("crash", 3.0))
    # Layer 2 is absent from the public GitHub tree -- skip that half rather
    # than failing closed on a file the export deliberately does not ship.
    if python_src:
        m = re.search(
            r'DOMAIN_WEIGHTS\.get\(domain,\s*DOMAIN_WEIGHTS\.get\("(\w+)"', python_src)
        if not m:
            FAILURES.append(
                f"{python_path}: could not find score_finding()'s unmapped-domain "
                f"fallback -- update this checker if it was restructured")
        else:
            python_domain_default = m.group(1)
            if python_domain_default != "crash":
                FAILURES.append(
                    f"{python_path}: unmapped-domain fallback is "
                    f"{python_domain_default!r}, expected 'crash' -- must match "
                    f"scripts/lib/risk-scoring.sh's equivalent default")

    # Bash: local conf="${RS_CONFIDENCE[$conf_name]:-${RS_CONFIDENCE[KCS-VALIDATED]:-100}}"
    m = re.search(r'RS_CONFIDENCE\[\$conf_name\]:-\$\{RS_CONFIDENCE\[([\w-]+)\]', bash_src)
    if not m:
        FAILURES.append(
            f"{bash_path}: could not find RS_CONFIDENCE's unmapped-confidence "
            f"fallback -- update this checker if rs_score_finding() was "
            f"restructured")
    else:
        bash_conf_default = m.group(1)
        if bash_conf_default != "KCS-VALIDATED":
            FAILURES.append(
                f"{bash_path}: unmapped-confidence fallback is "
                f"{bash_conf_default!r}, expected 'KCS-VALIDATED' (the "
                f"highest-weighted confidence tier) per the documented "
                f"fail-upward contract")

    # Python: CONFIDENCE_MULTIPLIERS.get(result.confidence, CONFIDENCE_MULTIPLIERS.get("KCS-VALIDATED", 1.0))
    if python_src:
        m = re.search(
            r'CONFIDENCE_MULTIPLIERS\.get\(\s*result\.confidence,\s*'
            r'CONFIDENCE_MULTIPLIERS\.get\("([\w-]+)"', python_src)
        if not m:
            FAILURES.append(
                f"{python_path}: could not find score_finding()'s "
                f"unmapped-confidence fallback -- update this checker if it "
                f"was restructured")
        else:
            python_conf_default = m.group(1)
            if python_conf_default != "KCS-VALIDATED":
                FAILURES.append(
                    f"{python_path}: unmapped-confidence fallback is "
                    f"{python_conf_default!r}, expected 'KCS-VALIDATED' -- must "
                    f"match scripts/lib/risk-scoring.sh's equivalent default")


def check_dashboard_latency_thresholds():
    """M7: dashboard latency thresholds must match the shipped alert thresholds.

    The single-cluster dashboard's "VM Disk Read Latency" panel kept the
    pre-H-5 value: a red line at 30 s/op, described as "the 30s alert
    threshold", while the alerts this repo actually ships fire at 0.5 s and
    1.0 s. A customer shown that panel saw a graph reading comfortably green
    at a latency the alerting layer considers CRITICAL -- 30x less sensitive,
    and directly contradicting the alert it claimed to depict.

    N10 fixed the equivalent bug on the FLEET dashboard; this panel was the
    mirror image, and nothing bound EITHER dashboard's thresholds to
    shared/storage-latency-thresholds.json. This check does.
    """
    lat = _load("storage-latency-thresholds.json")
    warn = lat["sustained_warn_seconds"]
    crit = lat["sustained_critical_seconds"]

    for rel in ("dashboards/bsod-risk-overview.json",
                "dashboards/bsod-risk-fleet-overview.json"):
        path = REPO_ROOT / rel
        if not path.is_file():
            continue
        dash = json.loads(path.read_text())

        def _walk(panels):
            for panel in panels:
                title = panel.get("title") or ""
                # Only panels whose unit is seconds AND which plot latency.
                defaults = (panel.get("fieldConfig") or {}).get("defaults") or {}
                if defaults.get("unit") == "s" and "atency" in title:
                    steps = (defaults.get("thresholds") or {}).get("steps") or []
                    vals = [st.get("value") for st in steps
                            if st.get("value") is not None]
                    # Every threshold must be a RECOGNISED shared value, not
                    # the exact pair [warn, crit]. A panel that already filters
                    # to `> crit` (fleet "High Latency VMs Across Fleet",
                    # expr `bsod:vmi_disk_latency:avg_1h > 1`) legitimately
                    # carries only the crit step -- a warn band there would be
                    # meaningless, since every series shown is above crit by
                    # construction. Requiring the exact pair flagged that
                    # correct panel; the real defect is a value that appears
                    # in NEITHER the shared config nor the alerts (e.g. 30).
                    allowed = {warn, crit, lat.get("burst_seconds")}
                    stray = [v for v in vals if v not in allowed]
                    if stray:
                        FAILURES.append(
                            f"{rel}: panel {panel.get('id')} {title!r} "
                            f"threshold(s) {stray} appear in neither "
                            f"shared/storage-latency-thresholds.json "
                            f"(warn={warn}, crit={crit}, "
                            f"burst={lat.get('burst_seconds')}) nor the "
                            f"shipped alerts -- the panel would contradict "
                            f"the alerts it depicts"
                        )
                    desc = panel.get("description") or ""
                    for stale in ("30s alert", "30 s alert", "30s threshold"):
                        if stale in desc:
                            FAILURES.append(
                                f"{rel}: panel {panel.get('id')} {title!r} "
                                f"description still cites the pre-H-5 "
                                f"{stale!r}"
                            )
                _walk(panel.get("panels") or [])

        _walk(dash.get("panels") or [])


def check_calibration_status_drift() -> None:
    """#3 (v0.16.0): the storage-latency `_calibration_status` moved from
    "OUTSTANDING" to "PARTIAL" (a real calibration run on 2026-07-29 -- see
    the field itself for the measurement), but the copies of that status
    duplicated into shipped alert annotations, tests, and docs were not
    updated alongside it. This is the same "fixed at the source, missed
    propagating to siblings" pattern this file already guards several other
    values against.

    Rather than pin this check to whatever the CURRENT status string is
    (which would need editing every time calibration progresses further,
    e.g. PARTIAL -> COMPLETE), it asserts the general invariant: once the
    JSON source of truth no longer says "OUTSTANDING", no shipped
    alert/doc file may still claim it is. Case-insensitive, since the YAML
    annotations use "OUTSTANDING" but the prose docs use "outstanding".
    """
    cfg = _load("storage-latency-thresholds.json")
    if not cfg:
        return
    status = str(cfg.get("_calibration_status", ""))
    if "outstanding" in status.lower():
        return  # still outstanding at the source -- siblings may say so too

    shipped_files = (
        "alerts/bsod-risk-prometheusrules.yaml",
        "alerts/bsod-risk-guest-alerts.yaml",
        "alerts/README.md",
        "alerts/tests.yaml",
        "acm/bsod-risk-policy.yaml",
        "docs/operator-runbook.md",
    )
    for rel in shipped_files:
        path = REPO_ROOT / rel
        if not path.is_file():
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if "outstanding" in line.lower():
                FAILURES.append(
                    f"{rel}:{lineno}: still describes storage-latency "
                    f"calibration as outstanding, but "
                    f"shared/storage-latency-thresholds.json's "
                    f"_calibration_status no longer says OUTSTANDING "
                    f"(currently: {status.splitlines()[0]!r}) -- update this "
                    f"reference to match, or point at _calibration_status "
                    f"instead of restating it")


def _ver(s: str) -> tuple:
    """Parse a dotted virtio-win version into a comparable tuple.

    Only the upstream version is compared; any RPM release/dist suffix
    (`-0.el9_6`) is discarded, matching every other layer's behaviour.
    """
    return tuple(int(p) for p in str(s).split("-")[0].split(".") if p.isdigit())


def check_stream_threshold_ordering() -> None:
    """Per-stream FAIL floors may never regress below a documented fix baseline.

    Root cause it guards (v0.19.0 unified review R-05 / U-30): `el10_1.fail`
    shipped as 1.9.52 while `multiqueue_fix_baseline` is 1.9.53 (KCS-7136486,
    RHBA-2026:2280). virtio-win 1.9.52 therefore graded FAIL on OCP 4.19-4.21
    (el9_6) but only WARN on OCP 4.22 (el10_1) -- a severity REGRESSION
    triggered by a platform upgrade, which is the worst possible moment to
    lose a signal on a known-bad driver.

    The two values were authored in the same commit, but `multiqueue_fix_baseline`
    did not exist yet, so there was no invariant to violate at the time and
    nothing has re-checked them since. This closes the class: any stream whose
    FAIL floor is set below a baseline that documents a real BSOD fix now fails
    CI, whatever the stream.

    Note the upstream version is stream-independent -- a fix that landed in
    1.9.53 cannot be present in 1.9.52 for a different el stream -- so this is
    an invariant, not a heuristic.
    """
    cfg = _load("virtio-win-thresholds.json")
    if not cfg:
        return
    mq_baseline = cfg.get("multiqueue_fix_baseline")
    if not mq_baseline:
        FAILURES.append(
            "shared/virtio-win-thresholds.json: multiqueue_fix_baseline is "
            "missing -- the per-stream FAIL-floor invariant cannot be checked")
        return

    for name, stream in (cfg.get("streams") or {}).items():
        fail = stream.get("fail")
        warn = stream.get("warn")
        if fail and _ver(fail) < _ver(mq_baseline):
            FAILURES.append(
                f"stream {name}: fail={fail} is BELOW multiqueue_fix_baseline="
                f"{mq_baseline} (KCS-7136486) -- a driver missing the multiqueue "
                f"fix would grade WARN on this stream while grading FAIL on "
                f"others. Raise fail to >= {mq_baseline}, or document an "
                f"explicit exception with KCS rationale.")
        if fail and warn and _ver(warn) < _ver(fail):
            FAILURES.append(
                f"stream {name}: warn={warn} is below fail={fail} -- the WARN "
                f"threshold must be at or above the FAIL threshold, otherwise "
                f"the WARN band is unreachable.")


def main() -> int:
    check_io_timeout_recording_rule()
    check_storage_latency_alerts()
    check_host_cpu_contention_alert()
    check_evidence_completeness_alert()
    check_risk_scoring_x100_parity()
    check_gate_domains_complete()
    check_fail_upward_defaults_match()
    check_dashboard_latency_thresholds()
    check_calibration_status_drift()
    check_stream_threshold_ordering()

    if FAILURES:
        print("Shared-threshold consistency check FAILED:\n")
        for f in FAILURES:
            print(f"  - {f}")
        print("\nUpdate the shared/*.json config and every duplicated literal "
              "together, in the same commit.")
        return 1
    print("OK: all duplicated thresholds match their shared/ source of truth")
    return 0


if __name__ == "__main__":
    sys.exit(main())
