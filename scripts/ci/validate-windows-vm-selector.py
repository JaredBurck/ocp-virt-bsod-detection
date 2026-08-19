#!/usr/bin/env python3
"""Hold every Windows-VM selector implementation to one definition.

R-10 (v0.19.0 unified review U-09). `CLAUDE.md` has always stated that four
implementations "must agree" on which VMs are Windows VMs, but agreement rested
on human diligence: the only automated check
(`tests/test_windows_vm_name_regex.sh`) compared the trailing NAME regex and
never the OR-clause SET around it. Three drifts existed simultaneously at
v0.19.0:

  1. `scripts/cnv-qga-fleet-collect.sh`'s standalone fallback omitted the
     `.metadata.labels["vm.kubevirt.io/template"]` clause -> silent
     under-collection.
  2. `scripts/cnv-windows-exporter-fleet-install.sh`'s fallback had NO Windows
     filter at all (`jsonpath={.items[*].metadata.name}` returns every VM in the
     namespace) -> it would attempt a Windows MSI install inside Linux guests.
  3. `insights-rules/parsers/vm_spec.py` derived `os_hint` from 2 of the 6
     clauses -> the analyzer and the gate script audited different VM
     populations, making their findings incomparable.

Only #1 and #3 were reported by the peer reviews; #2 and the fact that all
three coexisted came out of the synthesis pass. Catching the CLASS is the
point -- a fourth instance is otherwise only a matter of time.

WHAT IS CHECKED
---------------
* Every bash/jq `select(...)` body in the repo is byte-identical to what
  `scripts/lib/windows-vm-selector.sh` generates from
  `shared/windows-vm-selector.json`.
* The Python name/os-hint regexes equal the JSON's patterns.
* The Python `os_hint` derivation reads every field in `os_hint_fields`.

WHY EMBEDDED COPIES ARE ALLOWED AT ALL
--------------------------------------
`cnv-qga-fleet-collect.sh` and `cnv-windows-exporter-fleet-install.sh` are
documented as customer-shareable SINGLE FILES and must work with neither the
shared library nor the shared JSON present. The duplication is therefore
deliberate; this validator makes it machine-checked instead of merely
commented.

Usage:
    python3 scripts/ci/validate-windows-vm-selector.py
Exit: 0 clean, 1 drift found.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG = REPO_ROOT / "shared" / "windows-vm-selector.json"
LIB = REPO_ROOT / "scripts" / "lib" / "windows-vm-selector.sh"

# Files expected to carry a jq `select(...)` copy of the canonical selector.
JQ_CONSUMERS = (
    "scripts/cnv-win-bsod-audit.sh",
    "scripts/cnv-qga-fleet-collect.sh",
    "scripts/cnv-windows-exporter-fleet-install.sh",
    "must-gather/collection-scripts/common_bsod.sh",
)

# Layer 1 -- present on GitLab, absent from the public GitHub tree. Missing
# here is skipped (not a FAIL); missing a public consumer is still a FAIL.
INTERNAL_JQ_CONSUMERS = frozenset({
    "must-gather/collection-scripts/common_bsod.sh",
})

FAILURES: list[str] = []


def _canonical_selector() -> str | None:
    """Generate the selector via the shared library -- the same path the
    scripts use at runtime, so this validates the generator too."""
    # wvs_build_selector's own contract ("Requires: jq") returns rc=1 with
    # zero stdout when jq is simply absent -- identical, from this script's
    # point of view, to a genuine selector-logic drift. A CI environment
    # missing jq entirely (confirmed live: this job's before_script never
    # installed it) got the generic "produced no selector" FAILURES message
    # below, which reads exactly like a real drift finding. Check for the
    # missing-tool case first so the two failure modes are never conflated.
    if shutil.which("jq") is None:
        FAILURES.append(
            "jq is not installed -- cannot run wvs_build_selector to generate "
            "the canonical selector. This is an environment/CI setup gap, not "
            "a selector drift; install jq before re-running this validator.")
        return None
    try:
        out = subprocess.run(
            ["bash", "-c", f"source '{LIB}'; wvs_build_selector"],
            capture_output=True, text=True, cwd=REPO_ROOT, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        FAILURES.append(f"could not run {LIB.name}: {exc}")
        return None
    if out.returncode != 0 or not out.stdout.strip():
        FAILURES.append(
            f"{LIB.name} produced no selector (rc={out.returncode}). A selector "
            f"that matches nothing would report a clean fleet -- the exact "
            f"false all-clear this framework exists to prevent.")
        return None
    return out.stdout.rstrip("\n")


def _normalise(block: str) -> str:
    """Compare structure, not indentation: the same selector is embedded at
    different nesting depths in different files."""
    return "\n".join(line.strip() for line in block.strip().split("\n") if line.strip())


def _extract_selects(text: str) -> list[str]:
    """Pull every `select( ... )` body whose contents mention vm.kubevirt.io --
    i.e. the Windows-VM selectors, not unrelated jq selects."""
    found = []
    for m in re.finditer(r"select\(\s*\n", text):
        start = m.start()
        # Start the depth scan ON the '(' of select( -- not at the end of the
        # match (a newline), which would make the first clause's own parens
        # close the scan and truncate the block after one line.
        depth, i = 0, text.index("(", start)
        while i < len(text):
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        block = text[start:i + 1]
        if "vm.kubevirt.io" in block or "metadata.name | test" in block:
            found.append(block)
    return found


def check_jq_consumers(canonical: str) -> None:
    want = _normalise(canonical)
    for rel in JQ_CONSUMERS:
        path = REPO_ROOT / rel
        if not path.is_file():
            if rel in INTERNAL_JQ_CONSUMERS:
                continue
            FAILURES.append(f"{rel}: expected Windows-selector consumer is missing")
            continue
        blocks = _extract_selects(path.read_text())
        if not blocks:
            FAILURES.append(
                f"{rel}: no Windows-VM `select(...)` found. If this file no "
                f"longer selects Windows VMs, remove it from JQ_CONSUMERS; if it "
                f"selects them some other way, that is exactly the drift this "
                f"check exists to prevent.")
            continue
        for n, block in enumerate(blocks, 1):
            if _normalise(block) != want:
                FAILURES.append(
                    f"{rel}: Windows-VM selector #{n} differs from "
                    f"shared/windows-vm-selector.json.\n"
                    f"      Regenerate with: "
                    f"bash -c \"source scripts/lib/windows-vm-selector.sh; wvs_build_selector\"")


# R-10 follow-up (found during Wave 2): a Windows-VM list can also be built
# WITHOUT a jq select() at all --
#     oc get vm -n "$ns" -o jsonpath='{.items[*].metadata.name}'
# returns every VM in the namespace, and the select()-matching check above has
# nothing to find. Two such branches existed in
# cnv-windows-exporter-fleet-install.sh, which installs and EXECUTES a Windows
# MSI inside each returned guest. Catching the select() drift but not this one
# left the worse instance uncovered, so the class is closed from both directions.
_UNFILTERED_RE = re.compile(
    r"oc\s+get\s+vm\b[^\n|]*jsonpath=['\"]\{\.items\[\*\]\.metadata\.name\}")


def check_no_unfiltered_vm_listing() -> None:
    for rel in JQ_CONSUMERS:
        path = REPO_ROOT / rel
        if not path.is_file():
            continue
        for n, line in enumerate(path.read_text().split("\n"), 1):
            if line.lstrip().startswith("#"):
                continue      # documented history, not live code
            if _UNFILTERED_RE.search(line):
                FAILURES.append(
                    f"{rel}:{n}: builds a VM list with an UNFILTERED "
                    f"`oc get vm ... jsonpath={{.items[*].metadata.name}}` -- this returns "
                    f"every VM in the namespace, Windows or not. Use get_windows_vms() or "
                    f"the canonical selector from shared/windows-vm-selector.json.")


def check_python_patterns(cfg: dict) -> None:
    path = REPO_ROOT / "insights-rules" / "plugins" / "bsod_cpu_checks.py"
    if not path.is_file():
        return  # Layer 2 -- absent from the public GitHub tree
    text = path.read_text()
    for const, key in (("_WIN_NAME_RE", "name_fallback_pattern"),
                       ("_WIN_OS_HINT_RE", "os_hint_pattern")):
        m = re.search(rf'{const}\s*=\s*re\.compile\(\s*r?"([^"]*)"', text)
        if not m:
            FAILURES.append(f"bsod_cpu_checks.py: could not find {const}")
            continue
        if m.group(1) != cfg[key]:
            FAILURES.append(
                f"bsod_cpu_checks.py: {const} does not match "
                f"shared/windows-vm-selector.json's {key}\n"
                f"      python: {m.group(1)}\n"
                f"      shared: {cfg[key]}")


def check_python_os_hint(cfg: dict) -> None:
    """os_hint must consult every structured field the jq selector does."""
    path = REPO_ROOT / "insights-rules" / "parsers" / "vm_spec.py"
    if not path.is_file():
        return  # Layer 2 -- absent from the public GitHub tree
    text = path.read_text()
    # Non-greedy to the first ")\n" would stop at the first .get(...) call --
    # match the whole parenthesised expression by depth instead.
    anchor = text.find("os_hint = (")
    m = None
    if anchor != -1:
        depth, i = 0, text.index("(", anchor)
        while i < len(text):
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        m = re.match(r"(?s)(.*)", text[text.index("(", anchor) + 1:i])
    if not m:
        FAILURES.append("vm_spec.py: could not find the os_hint derivation")
        return
    block = m.group(1)
    for field in cfg["os_hint_fields"]:
        key = field.split('"')[1]                    # vm.kubevirt.io/os | .../template
        scope = "tmeta" if field.startswith(".spec.template") else "meta"
        kind = "annotations" if "annotations" in field else "labels"
        if not re.search(rf'{scope}\.get\("{kind}",\s*{{}}\)\.get\("{re.escape(key)}"', block):
            FAILURES.append(
                f"vm_spec.py: os_hint does not read {scope}.{kind}[\"{key}\"], which "
                f"shared/windows-vm-selector.json lists in os_hint_fields. A VM "
                f"classifiable as Windows only by that field is invisible to the "
                f"analyzer while the gate script sees it.")


def main() -> int:
    if not CONFIG.is_file():
        print(f"FAIL: {CONFIG.relative_to(REPO_ROOT)} not found")
        return 1
    cfg = json.loads(CONFIG.read_text())

    canonical = _canonical_selector()
    if canonical:
        check_jq_consumers(canonical)
    check_no_unfiltered_vm_listing()
    check_python_patterns(cfg)
    check_python_os_hint(cfg)

    if FAILURES:
        print("Windows-VM selector contract check FAILED:\n")
        for f in FAILURES:
            print(f"  - {f}")
        print("\nAll implementations must derive from "
              "shared/windows-vm-selector.json. See CLAUDE.md's "
              '"Windows-VM Detection (single contract)".')
        return 1
    print(f"OK: Windows-VM selector identical across {len(JQ_CONSUMERS)} jq "
          f"consumer(s) + the Python predicate and os_hint derivation; "
          f"no unfiltered VM listings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
