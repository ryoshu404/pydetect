# pydetect ![tests](https://github.com/ryoshu404/pydetect/actions/workflows/test.yml/badge.svg)

pydetect is a Python repository for authoring and testing Sigma detection rules. Rules ship with per-rule decision documentation, a pytest harness that validates them against real captured attack telemetry, and GitHub Actions CI that blocks merges without passing tests.

---

# What It Is

pydetect treats detection rules as production code:

- Sigma rules authored from public threat research
- A pytest harness that runs rules against real captured attack telemetry from the [OTRF Security Datasets project](https://securitydatasets.com/)
- Per-rule decision docs covering threat model, modality choice, FP considerations, environmental assumptions, and source/validation provenance
- Collection-time fixture validation that fails CI before any test runs if rules are missing labels
- GitHub Actions CI gating every push and pull request

Rules are organized into TTP-cluster batches — each batch covers an attacker behavior with one or more rules sharing a threat-research foundation. v1 batches: Cobalt Strike default named pipes (T1071.002), LSASS credential access (T1003.001), AWS EC2 instance role credential abuse (T1078.004), and AWS S3 object download by assumed role (T1530).

---

# Methodology

Rules begin with a documented attacker behavior, typically from a credible threat-research source: Mandiant, Microsoft Threat Intelligence, Unit 42, The DFIR Report, WithSecure Labs, and similar. The threat model section of each decision document captures the behavior at field-level detail and cites the source. Rule logic is then tested against captured attack telemetry from OTRF Security Datasets to verify the rule fires on the documented behavior and doesn't fire on benign or adjacent malicious activity.

Every rule ships with a decision doc covering the threat model, modality choice, FP considerations, environmental assumptions, and source/validation provenance. The doc lives alongside the rule, so the reasoning is preserved at the same level as the implementation.

Synthetic fixtures aren't used. Every fixture is derived from real captured events. This avoids the closed-loop problem where the same engineer who writes the rule also writes the events the rule is tested against — the test only validates self-consistency, not rule behavior under real data.

---

# Validation

Rules are validated against three corpora, all derived from a single OTRF dataset per rule:

1. **Documented attack events** — events extracted from the OTRF dataset documenting the target attack behavior (named in the rule's `labels.json`). The rule must fire on every such event.

2. **Baseline corpus** — non-attack events captured alongside the attack on the same host during the dataset's recording window. These are real benign Windows or AWS events, not synthetic. The rule must not fire on any baseline event.

3. **Sibling-rule discrimination** — attack events meant for other v1 rules. The rule must not fire on events labeled as another rule's positives. This catches over-broad matching (e.g., a Cobalt Strike named-pipe rule should not fire on Mimikatz LSASS events).

All three checks are enforced by a single assertion: rule fires on exactly the labeled event indices in the dataset, no more, no less. The labels file per rule expresses the engineering judgment about what the rule is detecting; the harness enforces it against the entire dataset.

## Validation source policy

v1 uses OTRF Security Datasets exclusively as the validation source. Single-source validation keeps the methodology demonstration clean and ensures every rule has consistent, ATT&CK-mapped, contributor-attributable provenance.

## Limitations

What dataset-validated rules don't demonstrate:

- Rules are validated against captured telemetry, not deployed in production. Real-world FP rate measurement requires production telemetry distribution, which isn't in scope for a public detection-as-code repository. Rules are demonstrably correct against their validation corpora; deployment in any specific environment would still require local validation.
- The validation surface is bounded by what OTRF captures. Behaviors not represented in OTRF datasets can't be validated this way and are deferred to v1.1 or out of scope.
- AWS coverage is intentionally narrow in v1 (one OTRF attack chain — the AWS Cloud Bank Breach scenario). Broader AWS coverage is v1.1 work.
- The pydetect Sigma adapter implements field-level matching and condition evaluation. It does **not** translate Sigma logsource categories into event-type filters.
    - In pydetect's test harness, the adapter is run against every event in the dataset, regardless of EventID. The rule's field criteria implicitly filter the matches. Events without the required fields (e.g., events without `PipeName`) will never match a rule that filters on those fields. This works correctly for rules where the field criteria are sufficient to distinguish target events from non-target events.
    - If a rule's correctness depends on EventID-based filtering that isn't expressible in field criteria alone, the rule must include explicit EventID matching in its detection block. Most v1 rules do not require this, but it is a known constraint for future rule authoring.
    - This is a known gap. Production Sigma deployments do not have this limitation because the SIEM backend handles logsource translation.
- The adapter interprets `.` in field names as nested-object traversal (e.g., `userIdentity.type` looks up `event["userIdentity"]["type"]`). This supports nested telemetry formats like AWS CloudTrail. Events with literal dotted keys (e.g., `event["data.point"]`) are not currently supported.
- Field-missing and field-is-None are treated identically by the adapter — both produce a non-match. Rules requiring strict distinction between these cases would need adapter changes.

## Adapter scope

The Sigma adapter implements a documented subset of the DSL covering signature-shape rules:

- Generic modifiers: `startswith`, `endswith`, `contains`, `all`, `cased`
- Regex matching via `re` (with `i`, `m`, `s` sub-modifiers)
- Boolean conditions: `and`, `or`, `not`, brackets, operator precedence per spec
- Search-identifier patterns: `1 of selection_*`, `all of selection_*`

Out of scope:

- Encoding modifiers (`base64`, `base64offset`, `utf16`, `wide`)
- Numeric (`lt`, `lte`, `gt`, `gte`) and time (`minute`, `hour`, etc.) modifiers
- IP modifiers (`cidr`)
- `fieldref`, `expand`, `windash`, `exists`, `neq`, `null` matching
- Keyword-only search identifiers
- Correlation rules and aggregation queries

When the adapter encounters an unsupported feature, it raises `ValueError` naming the unsupported construct. The full Sigma DSL is supported by [pysigma](https://github.com/SigmaHQ/pySigma); this adapter is purpose-built for evaluating signature rules against event dicts, which pysigma isn't optimized for.

---

# Repository Structure

```
pydetect/
├── sigma/                           # Sigma rule files (.yml)
├── tests/
│   ├── conftest.py                  # fixture loaders + collection-time validation
│   ├── adapters/
│   │   └── sigma/
│   │       ├── __init__.py
│   │       ├── adapter.py
│   │       ├── modifiers.py
│   │       └── condition.py
│   ├── fixtures/
│   │   ├── _datasets/
│   │   │   └── <dataset-name>.json  # full OTRF event capture, shared across rules
│   │   └── <rule-name>/
│   │       └── labels.json          # which event indices are this rule's attack
│   └── test_sigma_rules.py          # parametrized over discovered rules
├── docs/
│   └── <rule-name>.md               # per-rule decision doc
├── requirements.txt
└── .github/workflows/
    └── test.yml                     # CI: pytest on push and PR
```

Each rule shipped to the repository produces three artifacts on disk: the rule file, a labels file describing which events in a referenced OTRF dataset are the documented attack, and the decision doc. The parametrized test cases are generated automatically by the harness from the labels files.

---

# Frameworks

## Sigma

SIEM-agnostic detection rules in YAML. Compiles to backend-specific queries (Splunk, Elastic, Sentinel KQL) at deploy time. pydetect's v1 Sigma scope is endpoint and log-based detection: Windows process creation, Sysmon events, PowerShell script block logging, AWS CloudTrail. Rules follow SigmaHQ field conventions where applicable.

---

# Testing Harness

The harness is built on pytest. Three pieces enforce rule-test coupling structurally rather than by convention.

The Sigma adapter exposes a single function:

```python
def run_sigma_rule(rule_path: Path, event: dict) -> bool:
    """Returns True if the event matches the rule, False otherwise."""
```

Tests call the adapter against every event in the dataset; the adapter handles Sigma evaluation internally. The same contract will apply to the KQL adapter when it lands in v1.1.

The Sigma test file uses `pytest.parametrize` over rules discovered on disk. Adding a new rule to `sigma/` with a corresponding `tests/fixtures/<rule-name>/labels.json` automatically produces a new test case with no test-file edits required.

Before any test runs, `conftest.py` walks every rule directory under `tests/fixtures/`, verifies each rule has a labels file, and verifies each labels entry references an existing dataset and uses indices in valid range. Missing or invalid labels fail pytest collection with explicit errors. This makes it structurally impossible to ship a rule without its fixture metadata — the failure surfaces in CI, not as a silent gap.

---

# Decision Documentation

Every rule ships with a decision doc at `docs/<rule-name>.md`. Each doc covers five sections:

- **Threat Model** — what behavior the rule detects, what attacker goal it serves, ATT&CK technique mapping
- **Modality Choice** — why this telemetry source
- **FP Considerations** — what real-environment activity could trigger this rule, alternative rule shapes considered, tuning posture
- **Environmental Assumptions** — what log source, sensor, or pipeline is assumed
- **Source / Validation** — research provenance for the threat behavior plus dataset provenance for rule testing (positive count, baseline result, sibling-rule discrimination outcome)

---

# Design Decisions

## Sigma-only for v1

v1 ships Sigma rules only. Sigma is the standard format for SIEM-agnostic detection rules, with broad legibility for non-specialist reviewers and a clean deployment story (compiles to Splunk, Elastic, Sentinel KQL, etc. at deploy time). Other framework adapters are deferred to keep v1 scope bounded — the methodology is better demonstrated when one framework's harness is fully exercised against real captured telemetry than when multiple frameworks each have a single rule.

## Per-rule decision documentation

Each rule's decision doc captures the reasoning behind the rule's shape — why this telemetry source, what FP envelope is anticipated, what alternatives were considered, and where the threat model came from. The doc lives alongside the rule.

## Labels-based fixture organization

Per-rule fixture directories contain a `labels.json` file specifying which event indices in a referenced OTRF dataset are the rule's documented attack. The dataset itself is the source of truth; labels are metadata over it. This means:

- No data duplication. The same dataset's events are used as both positives (labeled indices) and negatives (everything else) without copying events into separate fixture files.
- Sibling-rule discrimination is structural rather than orchestrated. A rule's labeled indices are its positives; everything else in the dataset, including other rules' labeled indices, is a negative for this rule.
- Engineering judgment becomes a reviewable artifact. The labels file is the load-bearing claim about what the rule is detecting and where the boundaries are.

## Tests generated from rule discovery, not hand-written

`pytest.parametrize` over discovered rules generates tests automatically. The alternative — hand-writing one test function per rule — relies on author discipline to remember to wire each rule's tests. With generated tests, that discipline becomes structural: rules can't be added without tests because the tests are derived from rule files on disk.

## Filesystem as source of truth

No database, no lockfile, no central registry. Rules live as files. Datasets live as files. Labels live as files. Decision docs live as files. The presence of `tests/fixtures/<rule_name>/labels.json` is what tells the harness the rule's fixtures exist. Appropriate for a rules repository at v1 scale.

---

# Current State

**v1.0 released.** Sigma adapter, labels-based test harness, and GitHub Actions CI are in place and operational.

### Rules Released:
- Cobalt Strike default named pipes (T1071.002)
- LSASS credential access (T1003.001)
- AWS EC2 instance role credential abuse (T1078.004)
- AWS S3 object download by assumed role (T1530). 

---

# Roadmap

## v1.0 (released)

- Sigma adapter with documented operator subset
- Labels-based test harness with collection-time fixture validation
- pytest integration with parametrized rule discovery
- GitHub Actions CI workflow
- Methodology README (this document)

## v1.1

- **KQL adapter and sample rules.** Microsoft Defender XDR detection queries against published Defender table schemas, with a synthetic Python interpreter covering a bounded operator surface for filter-shape signatures.
- **Expanded validation sources.** flaws.cloud (organic-attacker-traffic CloudTrail), invictus-ir/aws_dataset (Stratus Red Team simulations), and others where appropriate per behavior.


# Related Projects

Part of a larger security tooling portfolio.

### [statica](https://github.com/ryoshu404/statica) (v1.0)
Modular static analysis pipeline written in Python. Extracts file hashes, printable strings, and IOCs from arbitrary files.

### [macollect](https://github.com/ryoshu404/macollect) (v1.0)
Modular macOS forensic artifact collector written in Python. Collects persistence mechanisms, process snapshots, code signing metadata, TCC permissions, and Unified Log activity across eight independent collection modules.

---

# Author

R. Santos
GitHub: https://github.com/ryoshu404

---

# License

MIT
