"""pytest configuration and shared helpers for pydetect.

Provides:
- load_fixture(): helper for loading JSON event fixtures from disk
- _validate_fixtures(): collection-time fail-fast that ensures every
rule has both positive.json and negative.json before tests run
"""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
FIXTURE_ROOT = Path(__file__).parent / "fixtures"
FRAMEWORKS: dict[str, str] = {
    "sigma": "*.yml",
    "falco": "*.yaml",
    "kql": "*.kql",
}
REQUIRED_FIXTURE_KINDS = ("positive", "negative")

def load_fixture(rule_name: str, kind: str) -> dict:
    """Load a JSON event fixture from tests/fixtures/<rule_name>/<kind>.json."""
    if kind not in REQUIRED_FIXTURE_KINDS:
        raise ValueError(
            f"Invalid fixture kind: {kind!r}. Must be one of {REQUIRED_FIXTURE_KINDS}."
            )
    fixture_path = FIXTURE_ROOT / rule_name / f"{kind}.json"
    return json.loads(fixture_path.read_text(encoding="utf-8"))

def _validate_fixtures() -> None:
    """Fail-fast at collection time if any rule lacks required fixtures."""
    missing = []
    for framework, glob in FRAMEWORKS.items():
        framework_dir = REPO_ROOT / framework
        if not framework_dir.exists():
            continue
        for rule_path in sorted(framework_dir.glob(glob)):
            for kind in REQUIRED_FIXTURE_KINDS:
                fixture_path = FIXTURE_ROOT / rule_path.stem / f"{kind}.json"
                if not fixture_path.exists():
                    missing.append(
                        f"{framework}/{rule_path.name} -> tests/fixtures/{rule_path.stem}/{kind}.json"
                    )
    if missing:
        raise AssertionError(
            "Missing required fixtures for the following rules:\n "
            + "\n ".join(missing)
        )

_validate_fixtures()
