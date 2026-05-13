"""pytest configuration and shared helpers for pydetect."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
FIXTURE_ROOT = Path(__file__).parent / "fixtures"
DATASETS_DIR = FIXTURE_ROOT / "_datasets"


def load_dataset(dataset_filename: str) -> list[dict]:
    """Load a dataset JSON file from tests/fixtures/_datasets/.

    Supports both JSON array format and NDJSON (one JSON object per line).
    """
    dataset_path = DATASETS_DIR / dataset_filename
    if not dataset_path.is_file():
        raise FileNotFoundError(f"{dataset_path} not found")
    with open(dataset_path, "r", encoding="utf-8") as f:
        content = f.read()
    try:
        dataset = json.loads(content)
    except json.JSONDecodeError:
        # Try NDJSON: one JSON object per line
        dataset = [json.loads(line) for line in content.splitlines() if line.strip()]
    if not isinstance(dataset, list):
        raise ValueError(f"Expected list, received {type(dataset).__name__}")
    if not dataset:
        return dataset
    if not isinstance(dataset[0], dict):
        raise ValueError(f"Expected list of dicts, received list of {type(dataset[0]).__name__}")
    return dataset


def load_labels(rule_name: str) -> dict:
    """Load a labels file from tests/fixtures/<rule_name>/labels.json."""
    labels_path = FIXTURE_ROOT / rule_name / "labels.json"
    if not labels_path.is_file():
        raise FileNotFoundError(f"{labels_path} not found")
    with open (labels_path, "r", encoding="utf-8") as f:
        labels = json.load(f)
    return labels


def discover_rules() -> list[tuple[Path, dict]]:
    """Discover rule directories under tests/fixtures/."""
    rules = []
    for directory in sorted(FIXTURE_ROOT.iterdir(), key=lambda p: p.name):
        if not directory.is_dir():
            continue
        if directory.name.startswith("_"):
            continue

        rule_name = directory.name
        rule_file = REPO_ROOT / "sigma" / f"{rule_name}.yml"
        labels = load_labels(rule_name)
        rules.append((rule_file, labels))

    return rules

def _validate_fixtures() -> None:
    """Collect all fixture validation problems at collection time; raise pytest.UsageError if any."""
    problems = []
    for directory in FIXTURE_ROOT.iterdir():
        if not directory.is_dir():
            continue
        if directory.name.startswith("_"):
            continue

        rule_name = directory.name
        rule_file = REPO_ROOT / "sigma" / f"{rule_name}.yml"
        if not rule_file.is_file():
            problems.append(f"{rule_name}: rule file missing at {rule_file}")
            continue

        labels_path = directory / "labels.json"
        if not labels_path.is_file():
            problems.append(f"{rule_name}: missing labels.json at {labels_path}")
            continue

        labels = load_labels(rule_name)
        if "rule_name" not in labels:
            problems.append(f"{rule_name}: labels.json missing required key 'rule_name'")
        elif labels["rule_name"] != rule_name:
            problems.append(f"{rule_name}: declared rule_name='{labels['rule_name']}' doesn't match directory name")

        if "datasets" not in labels:
            problems.append(f"{rule_name}: labels.json missing required key 'datasets'")
            continue
        elif not isinstance(labels["datasets"], list):
            problems.append(f"{rule_name}: datasets is not a list")
            continue
        elif not labels["datasets"]:
            problems.append(f"{rule_name}: datasets is empty")
            continue

        for entry_idx, dataset_entry in enumerate(labels["datasets"]):
            if "file" not in dataset_entry:
                problems.append(f"{rule_name}: datasets[{entry_idx}] missing 'file' key")
                continue

            dataset_file = dataset_entry["file"]
            dataset_path = DATASETS_DIR / dataset_file
            if not dataset_path.is_file():
                problems.append(f"{rule_name}: datasets[{entry_idx}] references missing dataset {dataset_file}")
                continue
            if "attack_event_indices" not in dataset_entry:
                problems.append(f"{rule_name}: datasets[{entry_idx}] missing 'attack_event_indices' key")
                continue

            dataset = load_dataset(dataset_file)
            for idx in dataset_entry["attack_event_indices"]:
                if not isinstance(idx, int):
                    problems.append(
                        f"{rule_name}: datasets[{entry_idx}] attack_event_indices contains non-int {idx!r}"
                        )
                elif idx < 0 or idx >= len(dataset):
                    problems.append(
                        f"{rule_name}: datasets[{entry_idx}] index {idx} out of range "
                        f"for dataset of length {len(dataset)}"
                        )

    if problems:
        raise pytest.UsageError(
            "Following problems found:\n - "
            +"\n - ".join(problems)
            )

_validate_fixtures()
