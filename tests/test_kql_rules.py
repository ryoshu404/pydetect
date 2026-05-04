"""Tests for KQL rules: positive fixtures match, negative fixtures don't."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.adapters.kql_adapter import run_kql_rule
from tests.conftest import FRAMEWORKS, load_fixture

KQL_DIR = Path(__file__).parent.parent / "kql"
KQL_RULES = sorted(KQL_DIR.glob(FRAMEWORKS["kql"]))

@pytest.mark.parametrize("rule_path", KQL_RULES, ids=lambda p: p.stem)
def test_kql_rule_matches_positive(rule_path: Path) -> None:
    fixture = load_fixture(rule_path.stem, "positive")
    assert run_kql_rule(rule_path, fixture) is True, (
        f"{rule_path.stem}: expected positive returned negative"
    )

@pytest.mark.parametrize("rule_path", KQL_RULES, ids=lambda p: p.stem)
def test_kql_rule_rejects_negative(rule_path: Path) -> None:
    fixture = load_fixture(rule_path.stem, "negative")
    assert run_kql_rule(rule_path, fixture) is False, (
        f"{rule_path.stem}: negative fixture incorrectly matched rule"
    )
