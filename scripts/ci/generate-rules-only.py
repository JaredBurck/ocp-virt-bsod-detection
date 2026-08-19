#!/usr/bin/env python3
"""Generate _rules_only.yaml from the alert and recording rule PrometheusRule
CRs, stripping Kubernetes metadata so promtool can parse them directly.

Usage:
    python3 scripts/ci/generate-rules-only.py [output-path]
    # Default output: alerts/_rules_only.yaml
"""
import sys
import yaml
from pathlib import Path


def main():
    output = sys.argv[1] if len(sys.argv) > 1 else "alerts/_rules_only.yaml"
    alert_dir = Path("alerts")

    sources = [
        alert_dir / "bsod-risk-prometheusrules.yaml",
        alert_dir / "bsod-risk-recording-rules.yaml",
        alert_dir / "bsod-risk-guest-alerts.yaml",
    ]

    groups = []
    for path in sources:
        if not path.exists():
            continue
        with open(path) as f:
            doc = yaml.safe_load(f)
        groups.extend(doc.get("spec", {}).get("groups", []))

    if not groups:
        print("FAIL: no rule groups found", file=sys.stderr)
        return 1

    with open(output, "w") as f:
        yaml.dump({"groups": groups}, f)

    print(f"OK: wrote {len(groups)} group(s) to {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
