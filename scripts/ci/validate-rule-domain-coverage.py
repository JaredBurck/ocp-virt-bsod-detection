#!/usr/bin/env python3
"""Validate that every rule_id the plugins emit maps to a known scoring domain.

F-05. `risk_scoring.py::_detect_domain()` resolves a rule_id to a scoring
domain, and `score_finding()` deliberately fails UPWARD (highest weight) for a
domain it does not recognise. `validate-shared-thresholds.py` already pins that
fallback DIRECTION -- but nothing pinned its COVERAGE. So a new rule whose
prefix nobody taught `_detect_domain` about would score at the maximum weight,
silently inflating a VM's risk tier with no test objecting.

That gap matters more here than it would elsewhere, because `_detect_domain`
falls through to SUBSTRING matching, and this repo has already been bitten by
that three separate times, each recorded in that function's own comments:

  N6   BSOD_RESOURCE_CPU_OVERCOMMIT   caught by "CPU"     -> cpu (2.0x), not resource (1.0x)
  N6   BSOD_MIGRATION_PHANTOM_NIC     caught by "NIC"     -> driver, not migration
  F-03 BSOD_PLATFORM_DRIVER_STREAM_*  caught by "DRIVER"  -> driver (1.5x), not platform (0.0x)

Each was fixed by adding an explicit prefix check AHEAD of the substring rules.
This validator is the other half of that fix: it proves no rule_id is currently
relying on a substring accident or falling through to UNMAPPED at all.

Two independent properties are checked:

  1. COVERAGE   -- every emitted rule_id resolves to a domain that exists in
                   DOMAIN_WEIGHTS. This is what closes F-05.
  2. WEIGHT SET -- every domain `_detect_domain` can return has a weight, and
                   every weight defined is reachable. A weight for a domain
                   nothing maps to is dead config; a domain with no weight is
                   the unmapped path.

Exit 0 = contract holds, 1 = violation (matches the other scripts/ci
validators).
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PLUGINS = REPO / "insights-rules" / "plugins"

sys.path.insert(0, str(REPO / "insights-rules"))
from plugins.risk_scoring import (  # noqa: E402
    DOMAIN_WEIGHTS, UNMAPPED_DOMAIN, _detect_domain,
)

# rule_id="BSOD_LITERAL_FORM"
LITERAL_RE = re.compile(r'rule_id\s*=\s*"([A-Z0-9_]+)"')
# RULE_PREFIX* = "BSOD_SOMETHING"
PREFIX_DEF_RE = re.compile(r'^(RULE_PREFIX[A-Z_]*)\s*=\s*"([A-Z0-9_]+)"', re.M)
# rule_id=f"{RULE_PREFIX}_SUFFIX"
FSTRING_RE = re.compile(r'rule_id\s*=\s*f"\{(RULE_PREFIX[A-Z_]*)\}([A-Z0-9_]*)"')


def collect_rule_ids():
    """Every rule_id the plugins can emit, with the file that emits it.

    Both spellings must be followed. Literal-only extraction would miss the
    f-string form that BSOD_DRIVER_* and BSOD_PLATFORM_* use -- and
    BSOD_PLATFORM_DRIVER_STREAM_CAPPED is precisely the rule whose domain
    misattribution (F-03) motivated this check.
    """
    found = {}
    for path in sorted(PLUGINS.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(REPO)
        for rid in LITERAL_RE.findall(text):
            found.setdefault(rid, rel)
        prefixes = dict(PREFIX_DEF_RE.findall(text))
        for var, suffix in FSTRING_RE.findall(text):
            if var in prefixes:
                found.setdefault(prefixes[var] + suffix, rel)
    return found


def check_coverage(errors: list) -> int:
    rule_ids = collect_rule_ids()
    if not rule_ids:
        errors.append(
            "no rule_ids were extracted from insights-rules/plugins/ -- the "
            "extractor has broken, and a validator that checks nothing while "
            "printing OK is worse than no validator at all."
        )
        return 0
    for rid, src in sorted(rule_ids.items()):
        domain = _detect_domain(rid)
        if domain == UNMAPPED_DOMAIN or domain not in DOMAIN_WEIGHTS:
            errors.append(
                f"{src}: rule_id {rid} resolves to '{domain}', which has no "
                f"weight in DOMAIN_WEIGHTS. score_finding() fails upward, so "
                f"this would silently score at the HIGHEST weight and inflate "
                f"the VM's risk tier. Add an explicit prefix branch to "
                f"_detect_domain() -- ahead of the substring rules, per N6/F-03."
            )
    return len(rule_ids)


def check_weight_set(errors: list, rule_ids: dict) -> None:
    reachable = {_detect_domain(r) for r in rule_ids}
    reachable.discard(UNMAPPED_DOMAIN)
    for dead in sorted(set(DOMAIN_WEIGHTS) - reachable):
        errors.append(
            f"DOMAIN_WEIGHTS defines '{dead}' but no emitted rule_id maps to "
            f"it. Either a rule was removed and its weight left behind, or a "
            f"rule that should map there is being claimed by a substring rule "
            f"first (the N6/F-03 failure mode)."
        )


def main() -> int:
    errors: list = []
    n = check_coverage(errors)
    if n:
        check_weight_set(errors, collect_rule_ids())

    if errors:
        print("FAIL: rule-domain coverage violated:\n", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    domains = sorted({_detect_domain(r) for r in collect_rule_ids()})
    print(
        f"OK: all {n} emitted rule_id(s) map to a weighted scoring domain "
        f"({len(domains)} domains in use, all {len(DOMAIN_WEIGHTS)} weights reachable)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
