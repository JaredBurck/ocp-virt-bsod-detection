#!/usr/bin/env python3
"""Reject a bare `rules:` key in the ACM observability allowlist ConfigMap.

R-38 (v0.19.0 follow-up N-02). `acm/observability-metrics-custom-allowlist.yaml`
declared its recording rule under `rules:`. RHACM's `metrics_list.yaml` schema
names that key **`recording_rules:`** -- verified against the published schema
for 2.13, 2.15, 2.16 and 2.17, so this is not version-conditional.

The failure mode is the dangerous kind: the MCO parses the document
successfully, silently ignores the unrecognised block, and reports nothing.
`bsod:cluster_alert_count:gauge` therefore never becomes a series on the hub,
and the fleet-dashboard panel that consumes it renders empty with no error
anywhere in the chain to explain why. Nothing in CI or at deploy time would have
caught it -- `oc apply` succeeds, the ConfigMap exists, the YAML is valid.

WHY THIS IS NOT A `grep -c 'rules:'`
------------------------------------
`rules:` is a perfectly legitimate key elsewhere in `acm/` -- `bsod-risk-policy.yaml`
embeds PrometheusRule CRs whose `spec.groups[].rules` is exactly right. Banning
the string outright would flag three correct usages to catch one wrong one, and a
validator that cries wolf gets disabled.

This check is therefore SHAPE-AWARE: it inspects only the embedded YAML bodies of
`metrics_list.yaml` / `uwl_metrics_list.yaml` inside the allowlist ConfigMap's
`data:`, and flags a `rules:` key only where it sits as a sibling of `names:` --
the specific shape RHACM's allowlist schema defines. A `rules:` key anywhere
else, in any other document shape, is ignored.

Usage:
    python3 scripts/ci/validate-acm-observability-allowlist.py
Exit: 0 clean, 1 violation found.
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    print("PyYAML is required: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

REPO_ROOT = Path(__file__).resolve().parents[2]
ALLOWLIST = REPO_ROOT / "acm" / "observability-metrics-custom-allowlist.yaml"

# The embedded documents RHACM's allowlist schema governs.
ALLOWLIST_KEYS = ("metrics_list.yaml", "uwl_metrics_list.yaml")

CORRECT_KEY = "recording_rules"
WRONG_KEY = "rules"

FAILURES: list[str] = []


def _check_recording_rule_quoting(rel: Path, key: str, inner: dict) -> None:
    """Reject double quotes inside a `recording_rules:` expr.

    R-48. Fixing the key name (R-38) made the MCO read the block at last, which
    exposed a second defect one layer down. The MCO passes each rule to the
    managed cluster's metrics-collector as a JSON-encoded flag::

        --recordingrule={"name":"<record>","query":"<expr>"}

    and the custom-allowlist path does not escape double quotes inside <expr>.
    A matcher written ``{alertname=~"BSODRisk_.*"}`` therefore closes the JSON
    string early, and the collector discards the entire rule with::

        msg="Input error" err="invalid character 'B' after object key:value pair"

    Confirmed live on RHACM 2.17: the rule failed on every 5-minute cycle for
    31 hours. The only symptom anywhere is a `level=warn` line in the
    collector's own log -- the hub surfaces nothing, `oc apply` succeeds, the
    ConfigMap reads correctly, and the series just never appears.

    PromQL parses 'single' and "double" quoted literals identically, so single
    quotes cost nothing semantically and survive the unescaped encoding.
    """
    for rule in inner.get(CORRECT_KEY) or []:
        if not isinstance(rule, dict):
            continue
        expr = rule.get("expr")
        record = rule.get("record", "<unnamed>")
        if isinstance(expr, str) and '"' in expr:
            FAILURES.append(
                f'{rel}: data.{key} recording rule `{record}` has a double '
                f'quote in its expr. The MCO does not escape it when building '
                f'--recordingrule={{...}} JSON, so the collector rejects the '
                f'whole rule every scrape ("invalid character ... after object '
                f"key:value pair\") and the series never reaches the hub. Use "
                f"single quotes -- PromQL treats them identically."
            )


def check_allowlist(path: Path) -> None:
    if not path.is_file():
        FAILURES.append(f"{path.relative_to(REPO_ROOT)} not found")
        return
    try:
        docs = [d for d in yaml.safe_load_all(path.read_text()) if d]
    except yaml.YAMLError as exc:
        FAILURES.append(f"{path.relative_to(REPO_ROOT)}: unparseable YAML: {exc}")
        return

    rel = path.relative_to(REPO_ROOT)
    seen_any = False

    for doc in docs:
        if not isinstance(doc, dict) or doc.get("kind") != "ConfigMap":
            continue
        for key, body in (doc.get("data") or {}).items():
            if key not in ALLOWLIST_KEYS or not isinstance(body, str):
                continue
            seen_any = True
            try:
                inner = yaml.safe_load(body)
            except yaml.YAMLError as exc:
                FAILURES.append(f"{rel}: data.{key} is not valid YAML: {exc}")
                continue
            if not isinstance(inner, dict):
                continue

            # The shape that matters: a rules-ish key alongside `names:`.
            if WRONG_KEY in inner:
                FAILURES.append(
                    f"{rel}: data.{key} declares `{WRONG_KEY}:` -- RHACM's "
                    f"allowlist schema calls this `{CORRECT_KEY}:`. The MCO "
                    f"parses the document, silently ignores the block, and "
                    f"reports nothing; the recording rule never becomes a "
                    f"series on the hub."
                )
            if CORRECT_KEY in inner and "names" not in inner:
                FAILURES.append(
                    f"{rel}: data.{key} has `{CORRECT_KEY}:` but no `names:` -- "
                    f"the allowlist schema expects both; check the document shape."
                )

            _check_recording_rule_quoting(rel, key, inner)

    if not seen_any:
        FAILURES.append(
            f"{rel}: no {' or '.join(ALLOWLIST_KEYS)} body found under any "
            f"ConfigMap's data:. If the file was restructured, update this "
            f"checker -- silently finding nothing to check is how this class "
            f"of bug survives."
        )


def main() -> int:
    check_allowlist(ALLOWLIST)

    if FAILURES:
        print("ACM observability allowlist check FAILED:\n")
        for f in FAILURES:
            print(f"  - {f}")
        # Two distinct failure classes reach here and they have opposite fixes,
        # so key the hint off what actually failed rather than printing the
        # R-38 advice unconditionally.
        if any("double quote" in f for f in FAILURES):
            print(
                "\nFor the quoting failures: rewrite the expr's label matchers "
                "with single quotes. PromQL parses 'x' and \"x\" identically, "
                "and the MCO does not escape double quotes when it JSON-encodes "
                "the rule onto the collector's command line."
            )
        if any(f"`{WRONG_KEY}:`" in f for f in FAILURES):
            print(
                f"\nFor the key failures: rename the key to `{CORRECT_KEY}:`. "
                f"Verified against RHACM's published metrics_list.yaml schema "
                f"for 2.13/2.15/2.16/2.17 -- it is stable across the "
                f"currently-supported range."
            )
        return 1
    print(
        f"OK: ACM observability allowlist uses `{CORRECT_KEY}:` "
        f"(a bare `{WRONG_KEY}:` would be silently ignored by the MCO)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
