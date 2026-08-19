#!/usr/bin/env python3
"""Validate the inert, prepared AlertManager inhibit rule (F14).

alerts/bsod-alertmanager-inhibit-rules.yaml holds the `VMNonRecoverableOSPanic`
<-> `BSODRisk_GuestCrash` deconfliction design from
docs/design/roadmap-v1.0.md:510-517 (retired doc, kept for history), deliberately
YAML-commented out (see that
file's header for why -- the metric both alerts depend on hasn't shipped in
any released HCO/CNV build). "Commented out" must not mean "untested": this
script extracts the commented block, strips the comment markers, and confirms
the result is both structurally correct AND (when `amtool` is available)
a genuinely valid AlertManager `inhibit_rules` entry -- so activating it later
is a mechanical uncomment of already-proven-valid YAML, not a leap of faith.

Usage:
    python3 scripts/ci/validate-inhibit-rules.py [--amtool /path/to/amtool]
Exit: 0 clean (amtool check is skipped with a warning if amtool is not
      found -- this script never requires installing amtool for local/basic
      structural validation), 1 on any structural or amtool failure.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
INHIBIT_FILE = REPO_ROOT / "alerts" / "bsod-alertmanager-inhibit-rules.yaml"

BEGIN_MARKER = "# BEGIN inhibit_rules"
END_MARKER = "# END inhibit_rules"

EXPECTED_SOURCE_ALERT = "BSODRisk_GuestCrash"
EXPECTED_TARGET_ALERT = "VMNonRecoverableOSPanic"
EXPECTED_EQUAL_LABELS = ["name", "namespace"]


def extract_commented_yaml(text: str) -> str:
    """Pull the BEGIN/END-delimited block out and strip its '# ' comment prefix.

    Deliberately marker-delimited rather than "every '#' line in the file":
    the file's long explanatory header is also all '#'-prefixed, and treating
    that as YAML-to-be-uncommented would be wrong (and would fail to parse).
    """
    lines = text.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.strip() == BEGIN_MARKER)
        end = next(i for i, l in enumerate(lines) if l.strip() == END_MARKER)
    except StopIteration:
        raise ValueError(
            f"could not find {BEGIN_MARKER!r}/{END_MARKER!r} markers in "
            f"{INHIBIT_FILE.name}"
        )
    if end <= start:
        raise ValueError("END marker appears before BEGIN marker")

    stripped = []
    for line in lines[start + 1:end]:
        if line == "#":
            stripped.append("")
        elif line.startswith("# "):
            stripped.append(line[2:])
        else:
            raise ValueError(
                f"line inside the inhibit_rules block is not a '# '-prefixed "
                f"comment (cannot mechanically uncomment): {line!r}"
            )
    return "\n".join(stripped)


def check_structure(rule_doc: dict) -> list[str]:
    errors = []
    rules = rule_doc.get("inhibit_rules")
    if not isinstance(rules, list) or not rules:
        return ["'inhibit_rules' key is missing or not a non-empty list"]

    rule = rules[0]
    source = rule.get("source_matchers") or []
    target = rule.get("target_matchers") or []
    equal = rule.get("equal") or []

    if not any(EXPECTED_SOURCE_ALERT in m for m in source):
        errors.append(
            f"source_matchers does not reference alertname = "
            f"\"{EXPECTED_SOURCE_ALERT}\": {source!r}"
        )
    if not any(EXPECTED_TARGET_ALERT in m for m in target):
        errors.append(
            f"target_matchers does not reference alertname = "
            f"\"{EXPECTED_TARGET_ALERT}\": {target!r}"
        )
    if list(equal) != EXPECTED_EQUAL_LABELS:
        errors.append(
            f"equal list is {equal!r}, expected {EXPECTED_EQUAL_LABELS!r} "
            f"(inhibiting across VM identity requires both name AND "
            f"namespace -- 'name' alone could inhibit an unrelated VM with "
            f"the same name in a different namespace)"
        )
    return errors


def run_amtool_check(rules_yaml: str, amtool_path: str) -> tuple[bool, str]:
    """Wrap the fragment in a minimal valid AlertManager config and amtool-check it."""
    full_config = (
        "route:\n"
        "  receiver: default\n"
        "receivers:\n"
        "  - name: default\n"
        + rules_yaml.rstrip() + "\n"
    )
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as tf:
        tf.write(full_config)
        tf_name = tf.name
    try:
        result = subprocess.run(
            [amtool_path, "check-config", tf_name],
            capture_output=True, text=True,
        )
        return result.returncode == 0, (result.stdout + result.stderr)
    finally:
        Path(tf_name).unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--amtool", default=None,
        help="Path to amtool binary. Defaults to searching PATH; if not "
             "found anywhere, the amtool check is skipped (not failed).",
    )
    args = parser.parse_args()

    if not INHIBIT_FILE.is_file():
        print(f"FAIL: {INHIBIT_FILE} not found")
        return 1

    try:
        rules_yaml = extract_commented_yaml(INHIBIT_FILE.read_text())
    except ValueError as exc:
        print(f"FAIL: {exc}")
        return 1

    try:
        rule_doc = yaml.safe_load(rules_yaml)
    except yaml.YAMLError as exc:
        print(f"FAIL: extracted inhibit_rules block is not valid YAML: {exc}")
        return 1

    errors = check_structure(rule_doc)
    if errors:
        print("FAIL: extracted inhibit_rules block failed structural checks:")
        for e in errors:
            print(f"  {e}")
        return 1
    print("OK: extracted inhibit_rules block is structurally correct "
          f"({EXPECTED_SOURCE_ALERT} -> {EXPECTED_TARGET_ALERT}, "
          f"equal={EXPECTED_EQUAL_LABELS})")

    amtool_path = args.amtool or shutil.which("amtool")
    if not amtool_path:
        print("WARN: amtool not found on PATH -- skipping live AlertManager "
              "config validation (structural check above still passed). "
              "CI installs amtool and always runs this check.")
        return 0

    ok, output = run_amtool_check(rules_yaml, amtool_path)
    if not ok:
        print("FAIL: amtool check-config rejected the (uncommented) "
              "inhibit_rules block:")
        print(output)
        return 1
    print(f"OK: amtool ({amtool_path}) validated the inhibit_rules block as "
          f"a syntactically correct AlertManager config")
    return 0


if __name__ == "__main__":
    sys.exit(main())
