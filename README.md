# pydetect ![tests](https://github.com/ryoshu404/pydetect/actions/workflows/test.yml/badge.svg)

> **Note: This README is not final. The project is in active build.**

pydetect is a detection-as-code repository written in Python that authors and tests Sigma detection rules with per-rule decision documentation. The goal of pydetect is to demonstrate detection engineering as a software discipline — rules in version control, tests that validate rule logic against captured attack telemetry, decision documentation that captures reasoning, and continuous integration that enforces it all.

The repository contains Sigma rules backed by a Python pytest harness, fixture validation at test collection time, and GitHub Actions CI that blocks merges without passing tests. Falco, Panther, and KQL framework adapters are deferred to v1.1.

---

# What It Is

pydetect implements detection engineering as a structured engineering practice:

- Sigma detection rules authored from public threat research
- A pytest harness that validates rules against real captured attack telemetry from the [OTRF Security Datasets project](https://securitydatasets.com/)
- Per-rule decision documentation covering threat model, modality choice, FP considerations, environmental assumptions, and source/validation provenance
- Collection-time fixture validation that fails CI before any test runs if rules lack their fixture labels
- GitHub Actions CI gating every push and pull request

Rules are organized into TTP-cluster batches — each batch covers an attacker behavior with one or more rules sharing a threat-research foundation. v1 batches: Cobalt Strike default profile, LSASS credential access, lateral movement via service creation, and AWS attack patterns.

---

# Methodology

pydetect treats detection rules as production code. Three principles drive the structure:

**Rules authored from research, validated against captured telemetry.** Rules begin with a documented attacker behavior — typically from a credible threat-research source (Mandiant, Microsoft Threat Intelligence, Unit 42, The DFIR Report, WithSecure Labs, etc.). The threat model section of each decision document captures the behavior at field-level detail, citing the source. Rule logic is then tested against captured attack telemetry from OTRF Security Datasets to validate that the rule fires on the documented behavior and does not fire on benign or adjacent malicious activity.

**Decision documentation as a first-class artifact.** Every rule ships with a decision doc covering the threat model, modality choice, FP considerations, environmental assumptions, and source/validation provenance. The decision docs make the reasoning behind each rule legible. They demonstrate the judgment behind each rule, not just the rule itself.

**Synthetic fixtures aren't used.** Every fixture is derived from real captured events. This avoids the closed-loop problem where the same engineer who writes the rule also writes the synthetic events the rule is tested against — the test only validates self-consistency, not rule behavior under real data.

---

# Validation

Rules are validated against three corpora, all derived from a single OTRF dataset per rule:

1. **Documented attack events** — events extracted from the OTRF dataset documenting the target attack behavior (named in the rule's `labels.json`). The rule must fire on every such event.

2. **Baseline corpus** — non-attack events captured alongside the attack on the same host during the dataset's recording window. These are real benign Windows or AWS events from a real host, not synthetic. The rule must not fire on any baseline event.

3. **Sibling-rule discrimination** — attack events meant for other v1 rules. The rule must not fire on events labeled as another rule's positives. This catches over-broad matching (e.g., a Cobalt Strike named-pipe rule should not fire on Mimikatz LSASS events).

Mechanically, all three checks are enforced by a single assertion: rule fires on exactly the labeled event indices in the dataset, no more, no less. The labels file per rule expresses the engineering judgment about what the rule is detecting; the harness enforces it against the entire dataset.

## Validation source policy

v1 uses OTRF Security Datasets exclusively as the validation source. This is a deliberate constraint — single-source validation simplifies the methodology demonstration and ensures every rule has consistent, ATT&CK-mapped, contributor-attributable provenance.

v1.1 will expand to additional sources: organic-attacker-traffic CloudTrail captures (e.g., flaws.cloud), Stratus Red Team simulations, and others. These broaden the validation surface but require more manual labeling work and are scope expansion for post-v1 work.

## Limitations

The author is forthright about what dataset-validated rules do and don't demonstrate:

- Rules are validated against captured telemetry, not deployed in production. Real-world FP rate measurement requires production telemetry distribution, which is not in scope for a public detection-as-code repository. Rules are demonstrably correct against their validation corpora; deployment in any specific environment would still require local validation.
- The validation surface is bounded by what OTRF captures. Behaviors not represented in OTRF datasets cannot be validated this way and are deferred to v1.1 or out of scope.
- AWS coverage is intentionally narrow in v1 (one OTRF attack chain — the AWS Cloud Bank Breach scenario). Broader AWS coverage is v1.1 work.

---

# Repository Structure

```
pydetect/
├── sigma/                           # Sigma rule files (.yml)
├── tests/
│   ├── conftest.py                  # fixture loaders + collection-time validation
│   ├── adapters/
│   │   └── sigma_adapter.py         # Sigma rule evaluator
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

## Falco (v1.1)

Runtime security rules for Linux syscalls and Kubernetes audit events. Falco rules and adapter will be added in v1.1.

## Panther (v1.1)

Cloud and SaaS audit log detection rules in Python (CloudTrail, Okta, GitHub audit, Google Workspace). Panther rules and adapter will be added in v1.1.

## KQL (v1.1)

Microsoft Defender XDR detection queries against the published Defender table schemas. KQL rules and adapter will be added in v1.1. The author's production KQL detection authorship at the AF Cyber Defense Operations team operates separately from this repository.

---

# Testing Harness

The harness is built on pytest with three design decisions that enforce rule-test coupling structurally rather than by convention.

**Adapter contract.** The Sigma adapter exposes a single function:

```python
def run_sigma_rule(rule_path: Path, event: dict) -> bool:
    """Returns True if the event matches the rule, False otherwise."""
```

Tests call the adapter against every event in the dataset; the adapter handles Sigma evaluation internally. The same contract will apply to Falco, Panther, and KQL adapters when those land in v1.1.

**Tests generated from rule discovery.** The Sigma test file uses `pytest.parametrize` over rules discovered on disk. Adding a new rule to `sigma/` with a corresponding `tests/fixtures/<rule-name>/labels.json` automatically produces a new test case with no test-file edits required.

**Collection-time fixture validation.** Before any test runs, `conftest.py` walks every rule directory under `tests/fixtures/`, verifies each rule has a labels file, and verifies each labels entry references an existing dataset and uses indices in valid range. Missing or invalid labels fail pytest collection with explicit errors. This makes it structurally impossible to ship a rule without its fixture metadata — the failure surfaces in CI, not as a silent gap.

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

## Sigma-only for v1, additional frameworks in v1.1

v1 ships Sigma rules only. Sigma is the SIEM-agnostic lingua franca of detection-as-code, with the broadest immediate legibility for non-specialist reviewers and the cleanest deployment story (compiles to Splunk, Elastic, Sentinel KQL, etc. at deploy time). Falco, Panther, and KQL adapters are deferred to v1.1 to keep v1's scope bounded — the methodology is best demonstrated when one framework's harness is fully exercised against real captured telemetry rather than three frameworks each having a single rule.

## Per-Rule Decision Documentation

Each rule's decision doc captures the reasoning behind the rule's shape — why this telemetry source, what FP envelope is anticipated, what alternatives were considered, and where the threat model came from. The doc lives alongside the rule, so the reasoning is preserved at the same level as the implementation.

## Labels-Based Fixture Organization

Per-rule fixture directories contain a `labels.json` file specifying which event indices in a referenced OTRF dataset are the rule's documented attack. The dataset itself is the source of truth; labels are metadata over it. This means:

- No data duplication. The same dataset's events are used as both positives (labeled indices) and negatives (everything else) without copying events into separate fixture files.
- Sibling-rule discrimination is structural rather than orchestrated. A rule's labeled indices are its positives; everything else in the dataset, including other rules' labeled indices, is a negative for this rule.
- Engineering judgment becomes a reviewable artifact. The labels file is the load-bearing claim about what the rule is detecting and where the boundaries are.

## Tests Generated from Rule Discovery, Not Hand-Written

`pytest.parametrize` over discovered rules generates tests automatically. The alternative — hand-writing one test function per rule — relies on author discipline to remember to wire each rule's tests. With generated tests, that discipline becomes structural: rules cannot be added without tests because the tests are derived from rule files on disk.

## Filesystem as Source of Truth

There is no database, no lockfile, no central registry. Rules live as files. Datasets live as files. Labels live as files. Decision docs live as files. The presence of `tests/fixtures/<rule_name>/labels.json` is what tells the harness the rule's fixtures exist. This is appropriate for a rules repository at v1 scale.

---

# Current State

**Harness in transition.** The pytest harness is being restructured from per-rule positive/negative fixtures to labels-based fixtures over shared OTRF datasets. The Sigma adapter is the next implementation step.

**Rules in progress.** Rule authorship is the active workstream. The first batch (Cobalt Strike default profile, validated against the APT Simulator OTRF dataset) is in research and labeling.

**Target ship: late May 2026.**

**Work-side application.** Sigma's harness pattern is being applied privately to a subset of the author's production KQL detections at the AF Cyber Defense Operations team. The public pydetect repository demonstrates the methodology; the private work-side rollout backs the production-use claim.

---

# Roadmap

## v1.0

- 4-6 Sigma rules across 4-5 TTP-cluster batches
- Per-rule decision docs with research-sourced provenance and OTRF dataset validation
- Green CI with full rule coverage
- Methodology README (this document)
- Work-side KQL rollout in progress at the AF

## v1.1 (cloud-environment extension)

- **Falco adapter and rules.** Linux syscall and Kubernetes audit event detection following the same harness pattern as Sigma. Rules cover cloud-native deployment behavior — container runtime, K8s audit, sensitive file access from system processes.
- **Panther adapter and rules.** Cloud audit log detection in Python — CloudTrail, Okta System Log, GitHub audit, Google Workspace admin audit. Continues the cloud-environment theme from v1's AWS Sigma rules.
- **KQL adapter and sample rules.** Microsoft Defender XDR detection queries against published Defender table schemas, with a synthetic Python interpreter covering a bounded operator surface for filter-shape signatures.
- **Expanded validation sources.** flaws.cloud (organic-attacker-traffic CloudTrail), invictus-ir/aws_dataset (Stratus Red Team simulations), and others where appropriate per behavior.
- **One upstream rule submission.** Opportunistic — pick the strongest rule from the v1 batches, conform to SigmaHQ style conventions, and submit a single PR for review. Best-effort rather than hard commitment.

## v2 (post-application)

- Full Falco runtime testing via `.scap` capture playback in CI
- Kustainer-based real KQL evaluation if the v1.1 synthetic interpreter's operator surface proves insufficient
- Continued upstream rule submissions
- Framework expansion if the target set shifts (YARA-L for Chronicle, Splunk SPL, etc.)

---

# Related Projects

This project is part of a larger security tooling portfolio.

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
