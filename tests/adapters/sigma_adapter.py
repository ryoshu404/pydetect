"""Sigma rule adapter"""

from __future__ import annotations

from pathlib import Path


def run_sigma_rule(rule_path: Path, event: dict) -> bool:
    """Return True if the event matches the Sigma rule, False otherwise."""
    raise NotImplementedError(
        "Sigma adapter not yet implemented; will be filled in with rule #1."
    )
