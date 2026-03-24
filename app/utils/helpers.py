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
    except Exception:  # noqa: BLE001
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
