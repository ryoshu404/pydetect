"""Tests for Sigma rules: rule fires on exactly the labeled attack events, no more, no less."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.adapters.sigma_adapter import run_sigma_rule
from tests.conftest import discover_rules, load_dataset


@pytest.mark.parametrize("rule_path,labels", discover_rules(), ids=lambda x: x.stem if isinstance(x, Path) else "")
def test_rule_matches_exactly_labeled_events(rule_path: Path, labels: dict) -> None:
    ...
