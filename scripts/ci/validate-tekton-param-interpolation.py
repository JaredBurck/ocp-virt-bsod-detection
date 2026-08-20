#!/usr/bin/env python3
"""Reject Tekton `$(params.*)` interpolation inside `script:` bodies (CWE-78).

R-04 (v0.19.0 unified review U-12). `tekton/bsod-gate-task.yaml` built its
gate invocation as:

    script: |
      if [ "$(params.strict)" = "true" ]; then ...
      /scripts/cnv-mtv-plan-gate.sh \
        "$(params.plan-name)" \
        "$(params.plan-namespace)" \

Tekton performs `$(params.*)` substitution on the script TEXT before the
container's shell ever parses it. The double quotes in this YAML are therefore
inert -- they are part of the string being generated, not protection applied to
a value. A PipelineRun with:

    plan-name: "a'; id; #"

produced a script whose quoting was broken by the injected text, executing
arbitrary shell in the gate pod. The task ServiceAccount is read-only
(`get`/`list`, no Secrets, no writes), which bounds the blast radius, but it is
CLUSTER-scoped over VMs/VMIs/nodes/HyperConverged/templates/plans -- so a
namespaced PipelineRun could read the whole fleet's topology and exfiltrate it.

THE SAFE FORM -- already used by `tekton/bsod-gate-prehook-job.yaml`, which is
why that file was never vulnerable:

    env:
      - name: PLAN_NAME
        value: "$(params.plan-name)"
    script: |
      /scripts/cnv-mtv-plan-gate.sh "$PLAN_NAME"

An env-var VALUE is delivered to the process out of band. It is never re-parsed
as shell syntax, so metacharacters in it are inert.

WHY A VALIDATOR AND NOT JUST THE FIX
------------------------------------
This is the same bug CLASS `scripts/ci/validate-shell-safety.py` already closes
for `bash -c "...$var..."` in shell scripts (its H1 docstring records the same
"fixed in two of three siblings, missed in the third" history). That validator
scans only `.sh` files, so Tekton YAML sat outside its scope entirely -- and the
Task was vulnerable while the Job next to it was not. This closes the YAML half.

WHAT IS DELIBERATELY ALLOWED
----------------------------
Only `$(params.*)` is user-controlled. Tekton's own `$(results.*.path)`,
`$(workspaces.*.path)` and `$(context.*)` expand to platform-generated paths and
identifiers, not to PipelineRun input, so they are not injection sinks and are
not flagged. `$(params.*)` inside an `env:` `value:` is the prescribed fix and
is likewise not flagged -- this check targets `script:` bodies only.

Usage:
    python3 scripts/ci/validate-tekton-param-interpolation.py
Exit: 0 clean, 1 violation found.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    print("PyYAML is required: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

REPO_ROOT = Path(__file__).resolve().parents[2]
TEKTON_DIR = REPO_ROOT / "tekton"

PARAM_RE = re.compile(r"\$\(params\.[^)]*\)")


def _walk(node, path, hits):
    """Collect (path, matches) for every `script:` string containing a param."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "script" and isinstance(value, str):
                found = PARAM_RE.findall(value)
                if found:
                    hits.append((f"{path}/script", sorted(set(found))))
            _walk(value, f"{path}/{key}", hits)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            _walk(value, f"{path}[{i}]", hits)


def main() -> int:
    if not TEKTON_DIR.is_dir():
        print(f"OK: no {TEKTON_DIR.relative_to(REPO_ROOT)} directory to scan")
        return 0

    violations: list[str] = []
    scanned = 0

    for path in sorted(TEKTON_DIR.glob("*.yaml")):
        try:
            docs = list(yaml.safe_load_all(path.read_text()))
        except yaml.YAMLError as exc:
            violations.append(f"{path.relative_to(REPO_ROOT)}: unparseable YAML: {exc}")
            continue
        scanned += 1
        for doc in docs:
            if not doc:
                continue
            hits: list = []
            _walk(doc, "", hits)
            for where, matches in hits:
                violations.append(
                    f"{path.relative_to(REPO_ROOT)}{where}: "
                    f"{', '.join(matches)}")

    if violations:
        print("Tekton param-interpolation check FAILED:\n")
        for v in violations:
            print(f"  - {v}")
        print(
            "\n$(params.*) is substituted into the script TEXT before bash parses "
            "it, so quoting in the YAML does not protect against metacharacters "
            "in a PipelineRun's input (CWE-78).\n"
            "\nPass the value as an env var instead and reference it as a shell "
            "variable:\n"
            "\n    env:\n"
            "      - name: PLAN_NAME\n"
            "        value: \"$(params.plan-name)\"\n"
            "    script: |\n"
            "      ... \"$PLAN_NAME\" ...\n"
            "\nSee tekton/bsod-gate-prehook-job.yaml for the reference pattern.")
        return 1

    print(f"OK: no $(params.*) interpolation inside script: bodies "
          f"({scanned} Tekton file(s) scanned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
