"""Shared utility functions used across all Streamlit tab components."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

# Repo root: app/utils/helpers.py → app/utils/ → app/ → repo_root/
REPO_ROOT = Path(__file__).parent.parent.parent

# Mapping from short key names to environment variable names
_KEY_MAP: dict[str, str] = {
    "urlscan":   "URLSCAN_API_KEY",
    "shodan":    "SHODAN_API_KEY",
    "mb":        "MB_API_KEY",
    "threatfox": "THREATFOX_API_KEY",
    "urlhaus":   "URLHAUS_API_KEY",
    "validin":   "VALIDIN_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "vt":        "VT_API_KEY",
    "github":    "GH_TOKEN",
}


def load_secrets() -> dict:
    """Load API keys from st.secrets with fallback to os.environ.

    Never raises on missing keys — returns empty string for any absent key.
    Returns dict with keys: urlscan, shodan, mb, threatfox, urlhaus, validin,
    anthropic.
    """
    result: dict[str, str] = {}
    for key, env_var in _KEY_MAP.items():
        val = ""
        try:
            import streamlit as st  # noqa: PLC0415
            val = st.secrets.get(env_var, "") or ""
        except Exception:  # noqa: BLE001 — FileNotFoundError, KeyError, etc.
            pass
        if not val:
            val = os.environ.get(env_var, "")
        result[key] = val
    return result


def load_records(path: str) -> list[dict]:
    """Read a JSON array from path.

    Returns empty list if file is missing or malformed.
    """
    p = Path(path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception as exc:  # noqa: BLE001
        print(f"[WARN] Failed to parse {p}: {exc}", file=sys.stderr)
        return []


def load_campaigns(path: str) -> list[dict]:
    """Read a JSON array of campaign records from path.

    Returns empty list if file is missing or malformed.
    """
    return load_records(path)


def confidence_badge(score: int) -> str:
    """Return an HTML <span> badge coloured by confidence score.

    score >= 70 → green / HIGH
    score >= 40 → amber / MEDIUM
    else        → red   / LOW
    """
    if score >= 70:
        bg, label = "#16a34a", "HIGH"
    elif score >= 40:
        bg, label = "#d97706", "MEDIUM"
    else:
        bg, label = "#dc2626", "LOW"
    style = (
        f"background:{bg}; color:#fff; "
        "padding:2px 8px; border-radius:4px; "
        "font-size:0.75rem; font-weight:600; "
        "display:inline-block"
    )
    return f'<span style="{style}">{label}</span>'


def payload_class_color(cls: str) -> str:
    """Return the hex color string for a payload class."""
    return {
        "stealer": "#ef4444",
        "c2":      "#f97316",
        "rmm":     "#8b5cf6",
        "loader":  "#06b6d4",
        "unknown": "#6b7280",
    }.get(cls, "#6b7280")


def format_chain(chain: list) -> str:
    """Return a readable string representation of a redirect chain.

    Format: role1(domain1) → role2(domain2) → ...
    Returns "not observed" if chain is None or empty.
    """
    if not chain:
        return "not observed"
    return " → ".join(
        f"{n.get('role', '?')}({n.get('domain', '?')})"
        for n in chain
    )


def run_script(script_path: str, env: dict) -> tuple[int, str, str]:
    """Run a Python script as a subprocess with merged environment variables.

    Args:
        script_path: Absolute path to the .py script.
        env: Dict of extra env vars to inject (typically API keys).

    Returns:
        Tuple of (returncode, stdout, stderr).
    """
    merged_env = {**os.environ, **env}
    result = subprocess.run(
        [sys.executable, script_path],
        capture_output=True,
        text=True,
        env=merged_env,
        cwd=str(REPO_ROOT),
    )
    return result.returncode, result.stdout, result.stderr


# ---------------------------------------------------------------------------
# GitHub data persistence — commit collected data back to the repo via API
# ---------------------------------------------------------------------------

_GITHUB_API = "https://api.github.com"


def _get_repo_slug() -> str | None:
    """Derive 'owner/repo' from the git remote origin URL.

    Falls back to the GITHUB_REPOSITORY env var (set on Streamlit Cloud
    when the app is linked to a repo).
    """
    slug = os.environ.get("GITHUB_REPOSITORY", "")
    if slug:
        return slug
    # Try parsing from git remote
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        url = result.stdout.strip()
        # Handle both HTTPS and SSH URLs
        if "github.com" in url:
            # https://github.com/owner/repo.git or git@github.com:owner/repo.git
            import re  # noqa: PLC0415
            m = re.search(r"github\.com[:/](.+?)(?:\.git)?$", url)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def github_commit_data(
    token: str,
    files: dict[str, str],
    message: str,
    branch: str | None = None,
) -> dict:
    """Commit one or more files to the repo via the GitHub API.

    This is the persistence mechanism for Streamlit Cloud: since the filesystem
    is ephemeral, collected data must be pushed back to the repo so GitHub Pages
    can serve it.

    Args:
        token: GitHub personal access token (GH_TOKEN from st.secrets).
        files: Mapping of repo-relative paths to file contents.
        message: Commit message.
        branch: Target branch (defaults to repo default branch).

    Returns:
        Dict with 'ok' bool and either 'sha' or 'error' string.
    """
    import base64 as b64  # noqa: PLC0415

    slug = _get_repo_slug()
    if not slug:
        return {"ok": False, "error": "Could not determine GitHub repo slug"}

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
    }

    import requests as req  # noqa: PLC0415

    # Resolve default branch if none specified
    if not branch:
        r = req.get(f"{_GITHUB_API}/repos/{slug}", headers=headers, timeout=15)
        if r.status_code != 200:
            return {"ok": False, "error": f"Cannot fetch repo info: {r.status_code}"}
        branch = r.json().get("default_branch", "main")

    # Get the latest commit SHA on the target branch
    r = req.get(
        f"{_GITHUB_API}/repos/{slug}/git/ref/heads/{branch}",
        headers=headers, timeout=15,
    )
    if r.status_code != 200:
        return {"ok": False, "error": f"Cannot resolve branch '{branch}': {r.status_code}"}
    base_sha = r.json()["object"]["sha"]

    # Get the tree SHA of that commit
    r = req.get(
        f"{_GITHUB_API}/repos/{slug}/git/commits/{base_sha}",
        headers=headers, timeout=15,
    )
    if r.status_code != 200:
        return {"ok": False, "error": f"Cannot fetch commit: {r.status_code}"}
    base_tree_sha = r.json()["tree"]["sha"]

    # Create blobs for each file
    tree_entries = []
    for path, content in files.items():
        r = req.post(
            f"{_GITHUB_API}/repos/{slug}/git/blobs",
            headers=headers, timeout=30,
            json={"content": b64.b64encode(content.encode()).decode(), "encoding": "base64"},
        )
        if r.status_code != 201:
            return {"ok": False, "error": f"Cannot create blob for {path}: {r.status_code}"}
        blob_sha = r.json()["sha"]
        tree_entries.append({
            "path": path, "mode": "100644", "type": "blob", "sha": blob_sha,
        })

    # Create a new tree
    r = req.post(
        f"{_GITHUB_API}/repos/{slug}/git/trees",
        headers=headers, timeout=30,
        json={"base_tree": base_tree_sha, "tree": tree_entries},
    )
    if r.status_code != 201:
        return {"ok": False, "error": f"Cannot create tree: {r.status_code}"}
    new_tree_sha = r.json()["sha"]

    # Create commit
    r = req.post(
        f"{_GITHUB_API}/repos/{slug}/git/commits",
        headers=headers, timeout=30,
        json={
            "message": message,
            "tree": new_tree_sha,
            "parents": [base_sha],
        },
    )
    if r.status_code != 201:
        return {"ok": False, "error": f"Cannot create commit: {r.status_code}"}
    new_commit_sha = r.json()["sha"]

    # Update branch reference
    r = req.patch(
        f"{_GITHUB_API}/repos/{slug}/git/refs/heads/{branch}",
        headers=headers, timeout=15,
        json={"sha": new_commit_sha},
    )
    if r.status_code != 200:
        return {"ok": False, "error": f"Cannot update ref: {r.status_code}"}

    return {"ok": True, "sha": new_commit_sha}


def github_create_pr(
    token: str,
    head_branch: str,
    base_branch: str = "main",
    title: str = "",
    body: str = "",
) -> dict:
    """Create a pull request via the GitHub API.

    Returns dict with 'ok' bool and either 'url' or 'error'.
    """
    import requests as req  # noqa: PLC0415

    slug = _get_repo_slug()
    if not slug:
        return {"ok": False, "error": "Could not determine GitHub repo slug"}

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
    }

    r = req.post(
        f"{_GITHUB_API}/repos/{slug}/pulls",
        headers=headers, timeout=30,
        json={
            "title": title,
            "body": body,
            "head": head_branch,
            "base": base_branch,
        },
    )
    if r.status_code == 201:
        return {"ok": True, "url": r.json().get("html_url", "")}
    if r.status_code == 422:
        # PR already exists
        return {"ok": True, "url": "(PR already exists for this branch)"}
    return {"ok": False, "error": f"PR creation failed: {r.status_code} {r.text[:500]}"}
