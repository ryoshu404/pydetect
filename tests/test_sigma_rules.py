"""Tests for Sigma rules: rule fires on exactly the labeled attack events, no more, no less."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.adapters.sigma import run_sigma_rule
from tests.conftest import discover_rules, load_dataset


_rules = discover_rules()
@pytest.mark.parametrize("rule_path, labels", _rules, ids=[r[0].stem for r in _rules])
def test_rule_matches_exactly_labeled_events(rule_path: Path, labels: dict) -> None:
    mismatches = []
    for entry in labels["datasets"]:
        events = load_dataset(entry["file"])
        actual = set()
        for idx, event in enumerate(events):
            if run_sigma_rule(rule_path, event):
                actual.add(idx)
        expected = set(entry["attack_event_indices"])
        if actual != expected:
            mismatches.append(format_mismatch(rule_path.stem, entry, actual ,expected))

    assert not mismatches, "\n".join(mismatches)

def format_mismatch(rule_name: str, entry: dict, actual: set[int], expected: set[int]) -> str:
    false_negatives = expected - actual
    false_positives = actual - expected

    lines = [f"{rule_name} / {entry['file']}"]
    if false_negatives:
        lines.append(f" - False negatives (rule missed): {false_negatives}")
    if false_positives:
        lines.append(f" - False positives (rule over-fired): {false_positives}")
    return "\n".join(lines)
