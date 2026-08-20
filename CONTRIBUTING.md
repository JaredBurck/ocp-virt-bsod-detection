# Contributing

This GitHub repository is a **one-way customer distribution**. Canonical
development is internal. Pull requests opened here will not be merged
into this remote.

## Feedback

Open a [GitHub Issue](https://github.com/JaredBurck/ocp-virt-bsod-detection/issues)
with:

- The git tag you ran (`git describe --tags`)
- `cnv-win-bsod-audit.sh --json` output (redact cluster names if needed)
- What you expected vs what you saw

Maintainers may cherry-pick a fix internally and publish it on the next
export tag.

## Do not

- Open PRs that add must-gather collectors, Python analyzers, or
  Windows guest disk image URLs -- those stay out of this tree
- Treat a green gate exit code as a migration approval
- Paste KCS article bodies into issues (link the portal URL instead)
