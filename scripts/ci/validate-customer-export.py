#!/usr/bin/env python3
"""Allowlist + deny-scan for the public GitHub export.

Reads shared/customer-export-manifest.json.

  validate (default): every file under allowlist_prefixes is either
  exported (trees_full / files) or explicitly excluded. Undeclared files
  fail CI.

  --export DEST: copy the public tree into DEST, overlay docs/public/,
  then deny-scan the result.

  --list: print the relative paths that would be exported (no overlay).

Exit: 0 clean, 1 violation.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "shared" / "customer-export-manifest.json"
SKIP_DIR_NAMES = {".git", "__pycache__", ".pytest_cache"}


def git_exportable_relpaths(repo: Path) -> set[str] | None:
    """Tracked + untracked-not-ignored paths, or None if git is unavailable.

    trees_full must not copy gitignored artifacts (alerts/_rules_only.yaml)
    but MUST include newly added files that have not been committed yet.

    If `repo` is merely a subdirectory of some other git worktree (the
    public-export dest lives at .public-export/ inside the GitLab clone),
    return None so we do not apply the parent index to the wrong tree.
    """
    try:
        top = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=False, timeout=30,
        )
        if top.returncode != 0:
            return None
        if Path(top.stdout.strip()).resolve() != repo.resolve():
            return None
        tracked = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "-z"],
            capture_output=True, check=False, timeout=60,
        )
        others = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "-z",
             "--others", "--exclude-standard"],
            capture_output=True, check=False, timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if tracked.returncode != 0 or others.returncode != 0:
        return None
    paths = set()
    for blob in (tracked.stdout, others.stdout):
        paths.update(p for p in blob.decode().split("\0") if p)
    return paths


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text())


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(p in SKIP_DIR_NAMES for p in path.parts):
            continue
        yield path


def exported_relpaths(manifest: dict, repo: Path = REPO_ROOT) -> list[str]:
    """Relative POSIX paths that belong in the public tree (pre-overlay)."""
    excluded = {p.rstrip("/") for p in manifest.get("exclude_files", [])}
    tracked = git_exportable_relpaths(repo)
    found: set[str] = set()

    for tree in manifest.get("trees_full", []):
        tree_path = repo / tree.rstrip("/")
        if not tree_path.is_dir():
            continue
        for path in _iter_files(tree_path):
            rel = path.relative_to(repo).as_posix()
            if rel in excluded:
                continue
            if tracked is not None and rel not in tracked:
                continue
            found.add(rel)

    for rel in manifest.get("files", []):
        if rel in excluded:
            continue
        path = repo / rel
        if path.is_file():
            found.add(rel)

    overlay = manifest.get("overlay_dir", "docs/public")
    overlay_path = repo / overlay
    if overlay_path.is_dir():
        for path in _iter_files(overlay_path):
            rel = path.relative_to(repo).as_posix()
            found.add(rel)

    return sorted(found)


def _is_excluded(rel: str, excluded_files: set[str], excluded_prefixes: tuple[str, ...]) -> bool:
    if rel in excluded_files:
        return True
    for prefix in excluded_prefixes:
        p = prefix.rstrip("/")
        if rel == p or rel.startswith(p + "/"):
            return True
    return False


def undeclared_under_allowlist(manifest: dict, repo: Path = REPO_ROOT) -> list[str]:
    exported = set(exported_relpaths(manifest, repo))
    excluded_files = {p.rstrip("/") for p in manifest.get("exclude_files", [])}
    excluded_prefixes = tuple(manifest.get("exclude_prefixes", []))
    overlay = manifest.get("overlay_dir", "docs/public").rstrip("/") + "/"
    bad: list[str] = []
    for prefix in manifest.get("allowlist_prefixes", []):
        prefix_path = repo / prefix.rstrip("/")
        if not prefix_path.is_dir():
            continue
        for path in _iter_files(prefix_path):
            rel = path.relative_to(repo).as_posix()
            if rel.startswith(overlay):
                continue
            if rel in exported or _is_excluded(rel, excluded_files, excluded_prefixes):
                continue
            bad.append(rel)
    return sorted(bad)


def deny_scan(tree: Path, manifest: dict) -> list[str]:
    errors: list[str] = []
    for rel in manifest.get("deny_paths", []):
        target = tree / rel.rstrip("/")
        if target.exists():
            errors.append(f"deny_paths: {rel} exists in export tree")

    needles = manifest.get("deny_substrings", [])
    exceptions = set(manifest.get("deny_substring_exceptions", []))
    for path in _iter_files(tree):
        rel = path.relative_to(tree).as_posix()
        if rel in exceptions:
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for needle in needles:
            if needle in text:
                errors.append(f"{rel}: contains forbidden substring {needle!r}")
    return errors


def export_tree(dest: Path, manifest: dict, repo: Path = REPO_ROOT) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    overlay_prefix = manifest.get("overlay_dir", "docs/public").rstrip("/") + "/"
    for rel in exported_relpaths(manifest, repo):
        if rel.startswith(overlay_prefix):
            continue
        src = repo / rel
        if not src.is_file():
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)

    overlay = repo / manifest.get("overlay_dir", "docs/public")
    if overlay.is_dir():
        for path in _iter_files(overlay):
            rel_in_overlay = path.relative_to(overlay).as_posix()
            target = dest / rel_in_overlay
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export", metavar="DEST", help="materialize the public tree")
    parser.add_argument("--list", action="store_true", help="print export paths")
    parser.add_argument(
        "--scan-dir",
        metavar="DIR",
        help="deny-scan an already-exported tree (default: validate this repo)",
    )
    args = parser.parse_args()

    if not MANIFEST.is_file():
        print(f"FAIL: missing {MANIFEST}")
        return 1
    manifest = load_manifest()
    errors: list[str] = []

    if args.list:
        for rel in exported_relpaths(manifest):
            print(rel)
        return 0

    if args.export:
        dest = Path(args.export).resolve()
        export_tree(dest, manifest)
        errors.extend(deny_scan(dest, manifest))
        if errors:
            print("FAIL: export deny-scan:")
            for e in errors:
                print(f"  {e}")
            return 1
        print(f"OK: exported public tree to {dest}")
        return 0

    if args.scan_dir:
        errors.extend(deny_scan(Path(args.scan_dir), manifest))
        if errors:
            print("FAIL: export deny-scan:")
            for e in errors:
                print(f"  {e}")
            return 1
        print(f"OK: deny-scan clean for {args.scan_dir}")
        return 0

    for tree in manifest.get("trees_full", []):
        if not (REPO_ROOT / tree.rstrip("/")).is_dir():
            errors.append(f"trees_full entry missing: {tree}")
    for rel in manifest.get("files", []):
        if not (REPO_ROOT / rel).is_file():
            errors.append(f"files entry missing: {rel}")
    errors.extend(
        f"UNDECLARED under allowlist prefix: {rel}"
        for rel in undeclared_under_allowlist(manifest)
    )

    n_export = len(exported_relpaths(manifest))
    print(f"Customer export: {n_export} paths in allowlist")
    if errors:
        print("\nFAIL:")
        for e in errors:
            print(f"  {e}")
        return 1
    print("OK: every allowlist-prefix file is classified; manifest paths exist")
    return 0


if __name__ == "__main__":
    sys.exit(main())
