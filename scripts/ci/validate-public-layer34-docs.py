#!/usr/bin/env python3
"""Fail closed if customer-facing Layer 3/4 docs drift from the public tree.

The GitLab README.md is overlay-replaced by docs/public/README.md on export.
Operator detail belongs in docs/admin-runbook.md, which IS exported. This
guard closes the class that shipped v0.27.0-v0.28.3: the public snapshot
could run 21 gates and the guest collector but had no gate table, no
behavior notes, no known-limitations catalog, and markdown that 404'd on
docs/operator-runbook.md / insights-rules/.

Usage:
    python3 scripts/ci/validate-public-layer34-docs.py
Exit: 0 clean, 1 findings.
"""
from __future__ import annotations

import importlib.util
import re
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE_SCRIPT = REPO_ROOT / "scripts" / "cnv-win-bsod-audit.sh"
ADMIN_RUNBOOK_REL = "docs/admin-runbook.md"

_VCE_PATH = Path(__file__).resolve().parent / "validate-customer-export.py"
_SPEC = importlib.util.spec_from_file_location("validate_customer_export", _VCE_PATH)
vce = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(vce)

# Paths that exist on GitLab and are denied from the public snapshot.
# Markdown pointers 404 for a GitHub user. YAML comments are developer notes;
# only non-comment YAML is scanned, because those strings appear in the
# OpenShift alert UI. "must-gather" as a word is allowed; a Layer 1 repo
# path is not.
FORBIDDEN_MD_RES = (
    re.compile(r"docs/operator-runbook\.md"),
    re.compile(r"insights-rules/"),
    re.compile(r"must-gather/(README|collection-scripts|Dockerfile)"),
    re.compile(r"docs/design/"),
    re.compile(r"(?<![A-Za-z0-9_-])CLAUDE\.md"),
    re.compile(r"python3\s+insights-rules/analyze\.py"),
)
FORBIDDEN_YAML_VALUE_RES = (
    re.compile(r"docs/operator-runbook\.md"),
    re.compile(r"insights-rules/"),
    re.compile(r"python3\s+insights-rules/analyze\.py"),
)

STALE_GATE11_RE = re.compile(
    r"Gate 11 does not measure", re.IGNORECASE,
)

REQUIRED_HEADING_RES = (
    re.compile(r"^## Gate checks\b", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^## Gate behavior notes\b", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^## Known limitations\b", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^## virtio-win version matrix\b", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^## Guest-side collector\b", re.IGNORECASE | re.MULTILINE),
)

GATE_TABLE_ROW_RE = re.compile(r"^\|\s*(\d+)\s*\|", re.MULTILINE)

# Markdown inline/reference links whose target is a relative path.
MD_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")

SCAN_SUFFIXES = {".md", ".yaml", ".yml"}
SCAN_SKIP_PREFIXES = (
    "scripts/ci/",
    "shared/customer-export-manifest.json",
)

def gate_numbers_from_script(script: Path = GATE_SCRIPT) -> set[int]:
    text = script.read_text()
    numbers = {int(n) for n in re.findall(r'(?:echo|info) "-- Gate (\d+)', text)}
    if not numbers:
        raise RuntimeError(f"no Gate N statements in {script}")
    return numbers


def is_gitlab_source_tree(root: Path) -> bool:
    return (root / "docs" / "public" / "README.md").is_file() and (
        root / "insights-rules" / "analyze.py"
    ).is_file()


def materialize_public_tree(root: Path) -> tuple[Path, bool]:
    """Return (tree_to_scan, owns_tree). owns_tree => caller must rmtree."""
    if not is_gitlab_source_tree(root):
        return root, False
    manifest = vce.load_manifest()
    dest = Path(tempfile.mkdtemp(prefix="bsod-public-docs-"))
    vce.export_tree(dest, manifest, repo=root)
    return dest, True


def should_scan(rel: str) -> bool:
    if any(rel.startswith(p) or rel == p.rstrip("/") for p in SCAN_SKIP_PREFIXES):
        return False
    if Path(rel).name == "CLAUDE.md":
        return False
    return Path(rel).suffix in SCAN_SUFFIXES


def check_forbidden_paths(tree: Path) -> list[str]:
    errors: list[str] = []
    for path in vce._iter_files(tree):
        rel = path.relative_to(tree).as_posix()
        if not should_scan(rel):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        suffix = path.suffix
        for lineno, line in enumerate(text.splitlines(), start=1):
            if STALE_GATE11_RE.search(line):
                errors.append(
                    f"{rel}:{lineno}: stale Gate 11 claim (F-05 / v0.28.0 "
                    f"queries Prometheus): {line.strip()!r}"
                )
            if suffix == ".md":
                patterns = FORBIDDEN_MD_RES
            elif suffix in {".yaml", ".yml"}:
                if line.lstrip().startswith("#"):
                    continue
                patterns = FORBIDDEN_YAML_VALUE_RES
            else:
                continue
            for cre in patterns:
                if cre.search(line):
                    errors.append(
                        f"{rel}:{lineno}: public Layer 3/4 doc points at a "
                        f"GitLab-only path ({cre.pattern}): {line.strip()!r}"
                    )
    return errors


def check_markdown_links(tree: Path) -> list[str]:
    """Relative markdown links in exported *.md must resolve inside the tree."""
    errors: list[str] = []
    for path in vce._iter_files(tree):
        rel = path.relative_to(tree).as_posix()
        if path.suffix != ".md":
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for m in MD_LINK_RE.finditer(line):
                target = m.group(1).strip()
                if not target or target.startswith("#"):
                    continue
                if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.IGNORECASE):
                    continue  # http:, mailto:, etc.
                path_part = target.split("#", 1)[0].split("?", 1)[0]
                if not path_part:
                    continue
                resolved = (path.parent / path_part).resolve()
                try:
                    resolved.relative_to(tree.resolve())
                except ValueError:
                    errors.append(
                        f"{rel}:{lineno}: markdown link escapes the public "
                        f"tree: {target!r}"
                    )
                    continue
                if not resolved.exists():
                    errors.append(
                        f"{rel}:{lineno}: markdown link 404 in the public "
                        f"tree: {target!r}"
                    )
    return errors


def check_admin_runbook(tree: Path, expected_gates: set[int]) -> list[str]:
    errors: list[str] = []
    runbook = tree / ADMIN_RUNBOOK_REL
    if not runbook.is_file():
        return [f"missing {ADMIN_RUNBOOK_REL} in the public tree"]
    text = runbook.read_text()
    for cre in REQUIRED_HEADING_RES:
        if not cre.search(text):
            errors.append(
                f"{ADMIN_RUNBOOK_REL}: missing required heading matching "
                f"{cre.pattern}"
            )
    found = {int(n) for n in GATE_TABLE_ROW_RE.findall(text)}
    missing = expected_gates - found
    extra = found - expected_gates
    if missing:
        errors.append(
            f"{ADMIN_RUNBOOK_REL}: gate table missing Gate "
            f"{sorted(missing)} (script has {sorted(expected_gates)})"
        )
    if extra:
        errors.append(
            f"{ADMIN_RUNBOOK_REL}: gate table has unknown Gate "
            f"{sorted(extra)} (script has {sorted(expected_gates)})"
        )
    return errors


def check_gate_script_customer_strings(tree: Path) -> list[str]:
    """Layer 4 stdout must not tell a public-tree user to run analyze.py."""
    errors: list[str] = []
    script = tree / "scripts" / "cnv-win-bsod-audit.sh"
    if not script.is_file():
        return ["missing scripts/cnv-win-bsod-audit.sh in the public tree"]
    text = script.read_text()
    if "insights-rules/analyze.py" in text:
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if "insights-rules/analyze.py" in line:
                errors.append(
                    f"scripts/cnv-win-bsod-audit.sh:{lineno}: customer-visible "
                    f"string points at insights-rules/analyze.py: {line.strip()!r}"
                )
    return errors


def check_public_readme_points_at_runbook(tree: Path) -> list[str]:
    readme = tree / "README.md"
    if not readme.is_file():
        return ["missing README.md in the public tree"]
    text = readme.read_text()
    if "docs/admin-runbook.md" not in text:
        return ["public README.md must point at docs/admin-runbook.md"]
    return []


def run_checks(tree: Path) -> list[str]:
    expected = gate_numbers_from_script()
    errors: list[str] = []
    errors.extend(check_admin_runbook(tree, expected))
    errors.extend(check_forbidden_paths(tree))
    errors.extend(check_markdown_links(tree))
    errors.extend(check_gate_script_customer_strings(tree))
    errors.extend(check_public_readme_points_at_runbook(tree))
    return errors


def main() -> int:
    tree, owns = materialize_public_tree(REPO_ROOT)
    try:
        errors = run_checks(tree)
    finally:
        if owns:
            shutil.rmtree(tree, ignore_errors=True)

    if errors:
        print("FAIL: public Layer 3/4 documentation does not match the "
              "customer-facing tree:")
        for e in errors:
            print(f"  {e}")
        print(
            "\nPort operator detail to docs/admin-runbook.md. Do not link "
            "docs/operator-runbook.md, insights-rules/, or must-gather/ from "
            "files that ship in the public GitHub snapshot."
        )
        return 1
    print("OK: public Layer 3/4 docs match the exported tree "
          f"({len(gate_numbers_from_script())} gates, no GitLab-only path leaks)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
