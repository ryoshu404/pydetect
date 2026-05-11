"""Sigma rule adapter.

Entry point for evaluating Sigma rules against event dicts. Coordinates
YAML loading, detection block walking, modifier dispatch, and condition
evaluation. Returns True if the event matches the rule, False otherwise.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from tests.adapters.sigma.condition import evaluate_condition
from tests.adapters.sigma.modifiers import match_field


def run_sigma_rule(rule_path: Path, event: dict) -> bool:
    """Return True if the event matches the Sigma rule, False otherwise.

    Loads the rule YAML from disk, walks the detection block, evaluates
    each search-identifier against the event, and combines results per
    the condition expression.

    Raises:
        FileNotFoundError: if the rule file does not exist
        yaml.YAMLError: if the rule file is not valid YAML
        ValueError: if the rule is missing required keys or uses unsupported features
    """
    rule = _load_rule(rule_path)
    if "detection" not in rule:
        raise ValueError(f"Rule {rule_path.name} missing detection block")
    detection = rule["detection"]
    if "condition" not in detection:
        raise ValueError(f"Rule {rule_path.name} missing condition in detection block")
    condition = detection["condition"]
    if isinstance(condition, list):
        raise ValueError(f"Rule {rule_path.name}: list-form condition expressions are out of scope for v1")
    selection_results = {}
    for name, value in detection.items():
        if name == "condition":
            continue
        selection_results[name] = _evaluate_search_identifier(value, event)
    return evaluate_condition(condition, selection_results)


def _load_rule(rule_path: Path) -> dict:
    with rule_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _evaluate_search_identifier(identifier_value: dict | list, event: dict) -> bool:
    """Evaluate a single search-identifier against an event.

    Maps are AND'd across field criteria; lists of maps are OR'd across items.
    """
    if isinstance(identifier_value, dict):
        return all(
            _evaluate_field_criteria(field_spec, expected, event)
            for field_spec, expected in identifier_value.items()
            )
    elif isinstance(identifier_value, list):
        if identifier_value and not isinstance(identifier_value[0], dict):
            raise ValueError("Expected list of dicts; keyword search lists are out of scope")
        return any(
            _evaluate_search_identifier(item, event)
            for item in identifier_value
            )
    else:
        raise ValueError(f"Search-identifier value must be a dict or list of dicts, got {type(identifier_value).__name__}")



def _evaluate_field_criteria(field_spec: str, expected_value: object, event: dict) -> bool:
    """Evaluate a single field criterion against an event.

    expected_value may be a scalar value or list of values
    (OR'd by default; AND'd if 'all' modifier is in the field_spec).
    """
    parts = field_spec.split("|")
    field_name = parts[0]
    modifiers = parts[1:]
    if field_name not in event:
        return False
    field_value = event[field_name]
    if not isinstance(expected_value, list):
        return match_field(modifiers, field_value, expected_value)
    combine = all if "all" in modifiers else any
    return combine(match_field(modifiers, field_value, v) for v in expected_value)
