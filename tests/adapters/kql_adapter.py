"""KQL rule adapter (synthetic Python interpreter, bounded operator surface)."""

from __future__ import annotations

from pathlib import Path


def run_kql_rule(rule_path: Path, event: dict) -> bool:
    """Return True if the KQL signature query matches the event, False otherwise."""
    raise NotImplementedError(
        "KQL adapter not yet implemented; synthetic interpreter coming with rule #1."
    )
