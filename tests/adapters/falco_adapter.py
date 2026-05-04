"""Falco rule adapter (synthetic evaluator)."""

from __future__ import annotations

from pathlib import Path


def run_falco_rule(rule_path: Path, event: dict) -> bool:
    """Return True if the rule's condition matches the event, False otherwise."""
    raise NotImplementedError(
        "Falco adapter not yet implemented; will be filled in with rule #1."
    )
