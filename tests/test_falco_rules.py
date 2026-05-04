"""Tests for Falco rules: positive fixtures match, negative fixtures don't."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.adapters.falco_adapter import run_falco_rule
from tests.conftest import FRAMEWORKS, load_fixture

FALCO_DIR = Path(__file__).parent.parent / "falco"
FALCO_RULES = sorted(FALCO_DIR.glob(FRAMEWORKS["falco"]))

@pytest.mark.parametrize("rule_path", FALCO_RULES, ids=lambda p: p.stem)
def test_falco_rule_matches_positive(rule_path: Path) -> None:
    fixture = load_fixture(rule_path.stem, "positive")
    assert run_falco_rule(rule_path, fixture) is True, (
        f"{rule_path.stem}: expected positive returned negative"
    )

@pytest.mark.parametrize("rule_path", FALCO_RULES, ids=lambda p: p.stem)
def test_falco_rule_rejects_negative(rule_path: Path) -> None:
    fixture = load_fixture(rule_path.stem, "negative")
    assert run_falco_rule(rule_path, fixture) is False, (
        f"{rule_path.stem}: negative fixture incorrectly matched rule"
    )
