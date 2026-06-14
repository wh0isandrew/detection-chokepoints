#!/usr/bin/env python3
"""Weekly refresh of the masq-infra trend from local hunt intel.

The infra-malware-delivery-hunter skill writes one validated intel JSON per
hunt to ~/de-intel-pipeline/hunts/. transform_intel_hunts.py turns that folder
into _data/masq_infra_hunts.yml. This script wraps the two so a scheduled task
can keep the trends page current:

    1. regenerate the data file from the hunts folder
    2. decide whether anything REAL changed (ignoring the generated: timestamp)
    3. if so, open a review PR; otherwise do nothing

It runs LOCALLY (the hunts live outside this repo, so GitHub Actions can't see
them). Default is detect-only; pass --open-pr for the unattended weekly job.

Why the git care: run unattended, this must never disturb whatever branch/edits
you have checked out. It records the current branch, stashes dirty state, does
all work on a throwaway branch cut from origin/main, then restores you exactly.

Usage:
    python scripts/refresh_masq_infra.py            # detect + report only
    python scripts/refresh_masq_infra.py --open-pr  # open a PR if data changed
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DATA = REPO / "_data" / "masq_infra_hunts.yml"
TRANSFORM = REPO / "scripts" / "transform_intel_hunts.py"


def git(*args: str, check: bool = True) -> str:
    r = subprocess.run(["git", "-C", str(REPO), *args],
                       capture_output=True, text=True)
    if check and r.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed:\n{r.stderr}")
    return r.stdout.strip()


def data_changed(committed: str, regenerated: str) -> bool:
    """True if anything but the generated: timestamp differs."""
    def strip(text: str) -> list[str]:
        return [ln for ln in text.splitlines() if not ln.lstrip().startswith("generated:")]
    return strip(committed) != strip(regenerated)


def run_transform() -> str:
    subprocess.run([sys.executable, str(TRANSFORM)], check=True)
    return DATA.read_text(encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--open-pr", action="store_true",
                    help="open a PR when real hunt data changed (for the weekly job)")
    args = ap.parse_args()

    committed = git("show", "origin/main:_data/masq_infra_hunts.yml", check=False) or \
        DATA.read_text(encoding="utf-8")

    if not args.open_pr:
        # detect-only: regenerate in place, report, leave the file for manual review
        regenerated = run_transform()
        if data_changed(committed, regenerated):
            print("NEW hunt data detected — _data/masq_infra_hunts.yml updated. "
                  "Review and commit, or re-run with --open-pr.")
            return 0
        git("checkout", "--", "_data/masq_infra_hunts.yml")  # discard timestamp-only churn
        print("No new hunt data since last publish.")
        return 0

    # --- unattended PR mode: preserve the user's working state throughout ----
    original_branch = git("rev-parse", "--abbrev-ref", "HEAD")
    dirty = bool(git("status", "--porcelain"))
    if dirty:
        git("stash", "push", "-u", "-m", "refresh_masq_infra autostash")
    try:
        git("fetch", "origin", "main")
        branch = f"chore/masq-infra-refresh-{date.today():%Y-%m-%d}"
        git("switch", "-C", branch, "origin/main")
        regenerated = run_transform()
        if not data_changed(committed, regenerated):
            print("No new hunt data since last publish — no PR opened.")
            git("checkout", "--", "_data/masq_infra_hunts.yml")
            return 0
        git("add", "_data/masq_infra_hunts.yml")
        git("commit", "-m", f"chore(trends): refresh masq-infra hunts ({date.today():%Y-%m-%d})")
        git("push", "-u", "origin", branch, "--force-with-lease")
        pr = subprocess.run(
            ["gh", "pr", "create", "--title",
             f"chore(trends): refresh masq-infra hunts ({date.today():%Y-%m-%d})",
             "--body", "Automated weekly refresh of the masq-infra trend from "
             "de-intel-pipeline hunts. Review the diff before merging.",
             "--base", "main"],
            cwd=str(REPO), capture_output=True, text=True)
        print(pr.stdout.strip() or pr.stderr.strip())
        return 0
    finally:
        git("switch", original_branch, check=False)
        if dirty:
            git("stash", "pop", check=False)


if __name__ == "__main__":
    sys.exit(main())
