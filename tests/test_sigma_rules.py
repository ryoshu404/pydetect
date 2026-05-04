"""Tests for Sigma rules: positive fixtures match, negative fixtures don't."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.adapters.sigma_adapter import run_sigma_rule
from tests.conftest import FRAMEWORKS, load_fixture

SIGMA_DIR = Path(__file__).parent.parent / "sigma"
SIGMA_RULES = sorted(SIGMA_DIR.glob(FRAMEWORKS["sigma"]))

@pytest.mark.parametrize("rule_path", SIGMA_RULES, ids=lambda p: p.stem)
def test_sigma_rule_matches_positive(rule_path: Path) -> None:
    fixture = load_fixture(rule_path.stem, "positive")
    assert run_sigma_rule(rule_path, fixture) is True, (
        f"{rule_path.stem}: expected positive returned negative"
    )

@pytest.mark.parametrize("rule_path", SIGMA_RULES, ids=lambda p: p.stem)
def test_sigma_rule_rejects_negative(rule_path: Path) -> None:
    fixture = load_fixture(rule_path.stem, "negative")
    assert run_sigma_rule(rule_path, fixture) is False, (
        f"{rule_path.stem}: negative fixture incorrectly matched rule"
    )
